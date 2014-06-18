/* module-verify-sig.c: module signature checker
 *
 * Copyright (C) 2004 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 * - Derived from GregKH's RSA module signer
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/elf.h>
#include <linux/crypto/ksign.h>
#include <linux/modsign.h>
#include "module-verify.h"

#undef MODSIGN_DEBUG

int modsign_debug;
core_param(modsign_debug, modsign_debug, bool, 0644);

#define _debug(FMT, ...)			    \
	do {					    \
		if (unlikely(modsign_debug))	    \
			printk(FMT, ##__VA_ARGS__); \
	} while(0)

#ifdef MODSIGN_DEBUG
#define count_and_csum(C, __p, __n)			\
do {							\
	int __loop;					\
	for (__loop = 0; __loop < __n; __loop++) {	\
		(C)->csum += __p[__loop];		\
		(C)->xcsum += __p[__loop];		\
	}						\
	(C)->signed_size += __n;			\
} while (0)
#else
#define count_and_csum(C, __p, __n)		\
do {						\
	(C)->signed_size += __n;		\
} while (0)
#endif

#define crypto_digest_update_data(C, PTR, N)			\
do {								\
	uint8_t *__p = (uint8_t *)(PTR);			\
	size_t __n = (N);					\
	count_and_csum((C), __p, __n);				\
	crypto_shash_update((C)->hash, __p, __n);		\
} while (0)

#define crypto_digest_update_val(C, VAL)			\
do {								\
	uint8_t *__p = (uint8_t *)&(VAL);			\
	size_t __n = sizeof(VAL);				\
	count_and_csum((C), __p, __n);				\
	crypto_shash_update((C)->hash, __p, __n);		\
} while (0)

static int module_verify_canonicalise(struct module_verify_data *mvdata);

static int extract_elf_rela(struct module_verify_data *mvdata,
			    int secix,
			    const Elf_Rela *relatab, size_t nrels,
			    const char *sh_name);

static int extract_elf_rel(struct module_verify_data *mvdata,
			   int secix,
			   const Elf_Rel *reltab, size_t nrels,
			   const char *sh_name);

#ifdef CONFIG_MODULE_SIG_FORCE
static int signedonly = 1;
#else
static int signedonly;
#endif

static int __init sign_setup(char *str)
{
	signedonly = 1;
	return 0;
}
__setup("enforcemodulesig", sign_setup);

static const char modsign_note_name[] = ELFNOTE_NAME(MODSIGN_NOTE_NAME);
static const char modsign_note_section[] = ELFNOTE_SECTION(MODSIGN_NOTE_NAME);

/*
 * verify a module's signature
 */
int module_verify_signature(struct module_verify_data *mvdata,
			    int *_gpgsig_ok)
{
	const struct elf_note *note;
	struct crypto_shash *tfm;
	const Elf_Shdr *sechdrs = mvdata->sections;
	const char *secstrings = mvdata->secstrings;
	const char *sig;
	unsigned note_size, sig_size, note_namesz;
	int loop, ret;

	_debug("looking for sig section '%s'\n", modsign_note_section);

	for (loop = 1; loop < mvdata->nsects; loop++) {
		switch (sechdrs[loop].sh_type) {
		case SHT_NOTE:
			if (strcmp(mvdata->secstrings + sechdrs[loop].sh_name,
				   modsign_note_section) == 0)
				mvdata->sig_index = loop;
			break;
		}
	}

	if (mvdata->sig_index <= 0)
		goto no_signature;

	note = mvdata->buffer + sechdrs[mvdata->sig_index].sh_offset;
	note_size = sechdrs[mvdata->sig_index].sh_size;

	/* there should be one note of the appropriate type */
	if (note_size < sizeof(*note) + 2 * 4)
		goto format_error_no_free;
	note_namesz = note->n_namesz;
	sig_size = note->n_descsz;
	if (note_namesz != sizeof(modsign_note_name))
		goto format_error_no_free;
	if (note->n_type != MODSIGN_NOTE_TYPE)
		goto format_error_no_free;
	if (memcmp(note + 1, modsign_note_name, note_namesz) != 0)
		goto format_error_no_free;
	sig = (void *)(note + 1) + roundup(note_namesz, 4);

	_debug("sig in section %d (size %d)\n",
	       mvdata->sig_index, sig_size);
	_debug("%02x%02x%02x%02x%02x%02x%02x%02x\n",
	       sig[0], sig[1], sig[2], sig[3],
	       sig[4], sig[5], sig[6], sig[7]);

	/* produce a canonicalisation map for the sections */
	ret = module_verify_canonicalise(mvdata);
	if (ret < 0)
		return ret;

	/* grab an SHA1 transformation context
	 * - !!! if this tries to load the sha1.ko module, we will deadlock!!!
	 */
	tfm = crypto_alloc_shash("sha1", 0, 0);
	if (!tfm) {
		printk(KERN_ERR
		       "Couldn't load module - SHA1 transform unavailable\n");
		return -EPERM;
	}

	mvdata->hash = kmalloc(sizeof(*mvdata->hash) +
			       crypto_shash_descsize(tfm),
			       GFP_KERNEL);
	if (!mvdata->hash) {
		crypto_free_shash(tfm);
		return -ENOMEM;
	}

	mvdata->hash->tfm = tfm;
	mvdata->hash->flags = CRYPTO_TFM_REQ_MAY_SLEEP;
	ret = crypto_shash_init(mvdata->hash);
	if (ret < 0) {
		crypto_free_shash(mvdata->hash->tfm);
		kfree(mvdata->hash);
		return -ENOMEM;
	}

#ifdef MODSIGN_DEBUG
	mvdata->xcsum = 0;
#endif

	/* load data from each relevant section into the digest */
	for (loop = 0; loop < mvdata->ncanon; loop++) {
		int sect = mvdata->canonlist[loop];
		unsigned long sh_type = sechdrs[sect].sh_type;
		unsigned long sh_info = sechdrs[sect].sh_info;
		unsigned long sh_size = sechdrs[sect].sh_size;
		unsigned long sh_flags = sechdrs[sect].sh_flags;
		const char *sh_name = secstrings + sechdrs[sect].sh_name;
		const void *data = mvdata->buffer + sechdrs[sect].sh_offset;

#ifdef MODSIGN_DEBUG
		mvdata->csum = 0;
#endif

		/* it would be nice to include relocation sections, but the act
		 * of adding a signature to the module seems changes their
		 * contents, because the symtab gets changed when sections are
		 * added or removed */
		if (sh_type == SHT_REL || sh_type == SHT_RELA) {
			uint32_t xsh_info = mvdata->canonmap[sh_info];

			crypto_digest_update_data(mvdata, sh_name, strlen(sh_name));
			crypto_digest_update_val(mvdata, sechdrs[sect].sh_type);
			crypto_digest_update_val(mvdata, sechdrs[sect].sh_flags);
			crypto_digest_update_val(mvdata, sechdrs[sect].sh_size);
			crypto_digest_update_val(mvdata, sechdrs[sect].sh_addralign);
			crypto_digest_update_val(mvdata, xsh_info);

			if (sh_type == SHT_RELA)
				ret = extract_elf_rela(
					mvdata, sect,
					data,
					sh_size / sizeof(Elf_Rela),
					sh_name);
			else
				ret = extract_elf_rel(
					mvdata, sect,
					data,
					sh_size / sizeof(Elf_Rel),
					sh_name);

			if (ret < 0)
				goto format_error;
			continue;
		}

		/* include the headers of BSS sections */
		if (sh_type == SHT_NOBITS && sh_flags & SHF_ALLOC) {
			crypto_digest_update_data(mvdata, sh_name, strlen(sh_name));
			crypto_digest_update_val(mvdata, sechdrs[sect].sh_type);
			crypto_digest_update_val(mvdata, sechdrs[sect].sh_flags);
			crypto_digest_update_val(mvdata, sechdrs[sect].sh_size);
			crypto_digest_update_val(mvdata, sechdrs[sect].sh_addralign);
			goto digested;
		}

		/* include allocatable loadable sections */
		if (sh_type != SHT_NOBITS && sh_flags & SHF_ALLOC)
			goto include_section;

		continue;

	include_section:
		crypto_digest_update_data(mvdata, sh_name, strlen(sh_name));
		crypto_digest_update_val(mvdata, sechdrs[sect].sh_type);
		crypto_digest_update_val(mvdata, sechdrs[sect].sh_flags);
		crypto_digest_update_val(mvdata, sechdrs[sect].sh_size);
		crypto_digest_update_val(mvdata, sechdrs[sect].sh_addralign);

		crypto_digest_update_data(mvdata, data, sh_size);

	digested:
		_debug("%08zx %02x digested the %s section, size %ld\n",
		       mvdata->signed_size, mvdata->csum, sh_name, sh_size);
	}

	_debug("Contributed %zu bytes to the digest (csum 0x%02x)\n",
	       mvdata->signed_size, mvdata->xcsum);

	/* do the actual signature verification */
	ret = ksign_verify_signature(sig, sig_size, mvdata->hash);

	crypto_free_shash(mvdata->hash->tfm);
	kfree(mvdata->hash);

	_debug("verify-sig : %d\n", ret);

	switch (ret) {
	case 0:			/* good signature */
		*_gpgsig_ok = 1;
		break;
	case -EKEYREJECTED:	/* signature mismatch or number format error */
		printk(KERN_ERR "Module signature verification failed\n");
		break;
	case -ENOKEY:		/* signed, but we don't have the public key */
		printk(KERN_ERR "Module signed with unknown public key\n");
		break;
	default:		/* other error (probably ENOMEM) */
		break;
	}

	return ret;

format_error:
	crypto_free_shash(mvdata->hash->tfm);
	kfree(mvdata->hash);
format_error_no_free:
	printk(KERN_ERR "Module format error encountered\n");
	return -ELIBBAD;

	/* deal with the case of an unsigned module */
no_signature:
	_debug("no signature found\n");
	if (!signedonly)
		return 0;
	printk(KERN_ERR "An attempt to load unsigned module was rejected\n");
	return -EKEYREJECTED;
}

/*
 * canonicalise the section table index numbers
 */
static int module_verify_canonicalise(struct module_verify_data *mvdata)
{
	int canon, loop, changed, tmp;

	/* produce a list of index numbers of sections that contribute
	 * to the kernel's module image
	 */
	mvdata->canonlist =
		kmalloc(sizeof(int) * mvdata->nsects * 2, GFP_KERNEL);
	if (!mvdata->canonlist)
		return -ENOMEM;

	mvdata->canonmap = mvdata->canonlist + mvdata->nsects;
	canon = 0;

	for (loop = 1; loop < mvdata->nsects; loop++) {
		const Elf_Shdr *section = mvdata->sections + loop;

		if (loop == mvdata->sig_index)
			continue;

		/* we only need to canonicalise allocatable sections */
		if (section->sh_flags & SHF_ALLOC)
			mvdata->canonlist[canon++] = loop;
		else if ((section->sh_type == SHT_REL ||
			  section->sh_type == SHT_RELA) &&
			 mvdata->sections[section->sh_info].sh_flags & SHF_ALLOC)
			mvdata->canonlist[canon++] = loop;
	}

	/* canonicalise the index numbers of the contributing section */
	do {
		changed = 0;

		for (loop = 0; loop < canon - 1; loop++) {
			const char *x, *y;

			x = mvdata->secstrings +
				mvdata->sections[mvdata->canonlist[loop + 0]].sh_name;
			y = mvdata->secstrings +
				mvdata->sections[mvdata->canonlist[loop + 1]].sh_name;

			if (strcmp(x, y) > 0) {
				tmp = mvdata->canonlist[loop + 0];
				mvdata->canonlist[loop + 0] =
					mvdata->canonlist[loop + 1];
				mvdata->canonlist[loop + 1] = tmp;
				changed = 1;
			}
		}

	} while (changed);

	for (loop = 0; loop < canon; loop++)
		mvdata->canonmap[mvdata->canonlist[loop]] = loop + 1;
	mvdata->ncanon = canon;
	return 0;
}

/*
 * extract an ELF RELA table
 * - need to canonicalise the entries in case section addition/removal has
 *   rearranged the symbol table and the section table
 */
static int extract_elf_rela(struct module_verify_data *mvdata,
			    int secix,
			    const Elf_Rela *relatab, size_t nrels,
			    const char *sh_name)
{
	struct {
#if defined(MODULES_ARE_ELF32)
		uint32_t	r_offset;
		uint32_t	r_addend;
		uint32_t	st_value;
		uint32_t	st_size;
		uint16_t	st_shndx;
		uint8_t		r_type;
		uint8_t		st_info;
		uint8_t		st_other;
#elif defined(MODULES_ARE_ELF64)
		uint64_t	r_offset;
		uint64_t	r_addend;
		uint64_t	st_value;
		uint64_t	st_size;
		uint32_t	r_type;
		uint16_t	st_shndx;
		uint8_t		st_info;
		uint8_t		st_other;
#else
#error unsupported module type
#endif
	} __attribute__((packed)) relocation;

	const Elf_Rela *reloc;
	const Elf_Sym *symbol;
	size_t loop;

	/* contribute the relevant bits from a join of { RELA, SYMBOL, SECTION } */
	for (loop = 0; loop < nrels; loop++) {
		int st_shndx;

		reloc = &relatab[loop];

		/* decode the relocation */
		relocation.r_offset = reloc->r_offset;
		relocation.r_addend = reloc->r_addend;
		relocation.r_type = ELF_R_TYPE(reloc->r_info);

		/* decode the symbol referenced by the relocation */
		symbol = &mvdata->symbols[ELF_R_SYM(reloc->r_info)];
		relocation.st_info = symbol->st_info;
		relocation.st_other = symbol->st_other;
		relocation.st_value = symbol->st_value;
		relocation.st_size = symbol->st_size;
		relocation.st_shndx = symbol->st_shndx;
		st_shndx = symbol->st_shndx;

		/* canonicalise the section used by the symbol */
		if (st_shndx > SHN_UNDEF && st_shndx < mvdata->nsects)
			relocation.st_shndx = mvdata->canonmap[st_shndx];

		crypto_digest_update_val(mvdata, relocation);

		/* undefined symbols must be named if referenced */
		if (st_shndx == SHN_UNDEF) {
			const char *name = mvdata->strings + symbol->st_name;
			crypto_digest_update_data(mvdata,
						  name, strlen(name) + 1);
		}
	}

	_debug("%08zx %02x digested the %s section, nrels %zu\n",
	       mvdata->signed_size, mvdata->csum, sh_name, nrels);

	return 0;
}

/*
 * extract an ELF REL table
 * - need to canonicalise the entries in case section addition/removal has
 *   rearranged the symbol table and the section table
 */
static int extract_elf_rel(struct module_verify_data *mvdata,
			   int secix,
			   const Elf_Rel *reltab, size_t nrels,
			   const char *sh_name)
{
	struct {
#if defined(MODULES_ARE_ELF32)
		uint32_t	r_offset;
		uint32_t	st_value;
		uint32_t	st_size;
		uint16_t	st_shndx;
		uint8_t		r_type;
		uint8_t		st_info;
		uint8_t		st_other;
#elif defined(MODULES_ARE_ELF64)
		uint64_t	r_offset;
		uint64_t	st_value;
		uint64_t	st_size;
		uint32_t	r_type;
		uint16_t	st_shndx;
		uint8_t		st_info;
		uint8_t		st_other;
#else
#error unsupported module type
#endif
	} __attribute__((packed)) relocation;

	const Elf_Rel *reloc;
	const Elf_Sym *symbol;
	size_t loop;

	/* contribute the relevant bits from a join of { RELA, SYMBOL, SECTION } */
	for (loop = 0; loop < nrels; loop++) {
		int st_shndx;

		reloc = &reltab[loop];

		/* decode the relocation */
		relocation.r_offset = reloc->r_offset;
		relocation.r_type = ELF_R_TYPE(reloc->r_info);

		/* decode the symbol referenced by the relocation */
		symbol = &mvdata->symbols[ELF_R_SYM(reloc->r_info)];
		relocation.st_info = symbol->st_info;
		relocation.st_other = symbol->st_other;
		relocation.st_value = symbol->st_value;
		relocation.st_size = symbol->st_size;
		relocation.st_shndx = symbol->st_shndx;
		st_shndx = symbol->st_shndx;

		/* canonicalise the section used by the symbol */
		if (st_shndx > SHN_UNDEF && st_shndx < mvdata->nsects)
			relocation.st_shndx = mvdata->canonmap[st_shndx];

		crypto_digest_update_val(mvdata, relocation);

		/* undefined symbols must be named if referenced */
		if (st_shndx == SHN_UNDEF) {
			const char *name = mvdata->strings + symbol->st_name;
			crypto_digest_update_data(mvdata,
						  name, strlen(name) + 1);
		}
	}

	_debug("%08zx %02x digested the %s section, nrels %zu\n",
	       mvdata->signed_size, mvdata->csum, sh_name, nrels);

	return 0;
}

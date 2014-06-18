/* module-verify.h: module verification definitions
 *
 * Copyright (C) 2004 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/types.h>
#include <crypto/hash.h>
#include <asm/module.h>

#ifdef CONFIG_MODULE_VERIFY
struct module_verify_data {
	struct shash_desc	*hash;		/* module signature digest (SHA1) */
	const void		*buffer;	/* module buffer */
	const Elf_Ehdr		*hdr;		/* ELF header */
	const Elf_Shdr		*sections;	/* ELF section table */
	const Elf_Sym		*symbols;	/* ELF symbol table */
	const char		*secstrings;	/* ELF section string table */
	const char		*strings;	/* ELF string table */
	size_t			*secsizes;	/* section size list */
	size_t			size;		/* module object size */
	size_t			nsects;		/* number of sections */
	size_t			nsyms;		/* number of symbols */
	size_t			nstrings;	/* size of strings section */
	size_t			signed_size;	/* count of bytes contributed to digest */
	int			*canonlist;	/* list of canonicalised sections */
	int			*canonmap;	/* section canonicalisation map */
	int			ncanon;		/* number of canonicalised sections */
	int			sig_index;	/* module signature section index */
	uint8_t			xcsum;		/* checksum of bytes contributed to digest */
	uint8_t			csum;		/* checksum of bytes representing a section */
};

/*
 * module-verify.c
 */
extern int module_verify(const Elf_Ehdr *hdr, size_t size, int *_gpgsig_ok);

/*
 * module-verify-elf.c
 */
#ifdef CONFIG_MODULE_VERIFY_ELF
extern int module_verify_elf(struct module_verify_data *mvdata);
#else
#define module_verify_elf(m) (0)
#endif

/*
 * module-verify-sig.c
 */
#ifdef CONFIG_MODULE_SIG
extern int module_verify_signature(struct module_verify_data *mvdata,
				   int *_gpgsig_ok);
#else
#define module_verify_signature(m, g) (0)
#endif

#else
#define module_verify(h, s, g) (0)
#endif

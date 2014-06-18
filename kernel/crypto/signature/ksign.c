/* ksign.c: signature checker
 *
 * Copyright (C) 2004 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <asm/errno.h>
#include "local.h"

int ksign_debug;
core_param(ksign_debug, ksign_debug, bool, 0644);

#define _debug(FMT, ...)					\
	do {							\
		if (unlikely(ksign_debug))			\
			printk(KERN_DEBUG FMT, ##__VA_ARGS__);	\
	} while(0)

/*
 * check the signature which is contained in SIG.
 */
static int ksign_signature_check(const struct ksign_signature *sig,
				 struct shash_desc *digest)
{
	struct ksign_public_key *pk;
	uint8_t sha1[SHA1_DIGEST_SIZE];
	MPI result = NULL;
	int rc = 0;

	pk = ksign_get_public_key(sig->keyid);
	if (!pk) {
		printk("ksign: module signed with unknown public key\n");
		printk("- signature keyid: %08x%08x ver=%u\n",
		       sig->keyid[0], sig->keyid[1], sig->version);
		return -ENOKEY;
	}

	if (pk->timestamp > sig->timestamp)
		printk("ksign:"
		       " public key is %lu seconds newer than the signature"
		       " [%lx < %lx]\n",
		       pk->timestamp - sig->timestamp,
		       pk->timestamp, sig->timestamp);

	/* complete the digest */
	if (sig->version >= 4)
		SHA1_putc(digest, sig->version);
	SHA1_putc(digest, sig->sig_class);

	if (sig->version < 4) {
		u32 a = sig->timestamp;
		SHA1_putc(digest, (a >> 24) & 0xff);
		SHA1_putc(digest, (a >> 16) & 0xff);
		SHA1_putc(digest, (a >>  8) & 0xff);
		SHA1_putc(digest, (a >>  0) & 0xff);
	}
	else {
		uint8_t buf[6];
		size_t n;
		SHA1_putc(digest, PUBKEY_ALGO_DSA);
		SHA1_putc(digest, DIGEST_ALGO_SHA1);
		if (sig->hashed_data) {
			n = (sig->hashed_data[0] << 8) | sig->hashed_data[1];
			SHA1_write(digest, sig->hashed_data, n + 2);
			n += 6;
		}
		else {
			n = 6;
		}

		/* add some magic */
		buf[0] = sig->version;
		buf[1] = 0xff;
		buf[2] = n >> 24;
		buf[3] = n >> 16;
		buf[4] = n >>  8;
		buf[5] = n;
		SHA1_write(digest, buf, 6);
	}

	crypto_shash_final(digest, sha1);

	rc = -ENOMEM;
	result = mpi_alloc((SHA1_DIGEST_SIZE + BYTES_PER_MPI_LIMB - 1) /
			   BYTES_PER_MPI_LIMB);
	if (!result)
		goto cleanup;

	rc = mpi_set_buffer(result, sha1, SHA1_DIGEST_SIZE, 0);
	if (rc < 0)
		goto cleanup;

	rc = DSA_verify(result, sig->data, pk->pkey);

 cleanup:
	mpi_free(result);
	ksign_put_public_key(pk);

	return rc;
}

/*
 * examine the signatures that are parsed out of the signature data - we keep
 * the first one that's appropriate and ignore the rest
 * - return 0 if signature of interest (sig not freed by caller)
 * - return 1 if no interest (caller frees)
 */
static int ksign_grab_signature(struct ksign_signature *sig, void *fnxdata)
{
	struct ksign_signature **_sig = fnxdata;

	if (sig->sig_class != 0x00) {
		_debug("ksign: standalone signature of class 0x%02x\n",
		       sig->sig_class);
		return 1;
	}

	if (*_sig)
		return 1;

	*_sig = sig;
	return 0;
}

/*
 * verify the signature of some data with one of the kernel's known public keys
 * - the SHA1 digest supplied should have the data to be checked already loaded
 *   in to it
 */
int ksign_verify_signature(const char *sigdata, unsigned sig_size,
			   struct shash_desc *partial_digest)
{
	struct ksign_signature *sig = NULL;
	struct shash_desc *digest = NULL;
	uint8_t sha1[SHA1_DIGEST_SIZE];
	void *export_buf = NULL;
	int retval, loop;

	/* copy the current state of the digest, something that we have to do
	 * by exporting the old state and importing into the new state
	 */
	export_buf = kmalloc(crypto_shash_statesize(partial_digest->tfm),
			     GFP_KERNEL);
	if (!export_buf)
		return -ENOMEM;

	retval = crypto_shash_export(partial_digest, export_buf);
	if (retval < 0)
		goto cleanup;

	retval = -ENOMEM;
	digest = kmalloc(sizeof(*partial_digest) +
			 crypto_shash_descsize(partial_digest->tfm),
			 GFP_KERNEL);
	if (!digest)
		goto cleanup;

	digest->tfm = partial_digest->tfm;
	digest->flags = CRYPTO_TFM_REQ_MAY_SLEEP;

	if (ksign_debug) {
		/* print the partial digest for debugging purposes */
		retval = crypto_shash_import(digest, export_buf);
		if (retval < 0)
			goto cleanup;

		crypto_shash_final(digest, sha1);
		printk(KERN_WARNING "Modsign digest: ");
		for (loop = 0; loop < sizeof(sha1); loop++)
			printk("%02x", sha1[loop]);
		printk("\n");
	}

	retval = crypto_shash_import(digest, export_buf);
	if (retval < 0)
		goto cleanup;

	kfree(export_buf);
	export_buf = NULL;

	/* parse the signature data to get the actual signature */
	retval = ksign_parse_packets(sigdata, sig_size,
				     &ksign_grab_signature, NULL, NULL,
				     &sig);
	if (retval < 0)
		goto cleanup;

	if (!sig) {
		printk(KERN_NOTICE
		       "Couldn't find valid DSA signature in module\n");
		retval = -ENOENT;
		goto cleanup;
	}

	_debug("signature keyid: %08x%08x ver=%u\n",
	       sig->keyid[0], sig->keyid[1], sig->version);

	/* check the data SHA1 transformation against the public key */
	retval = ksign_signature_check(sig, digest);
	switch (retval) {
	case 0:
		_debug("ksign: Signature check succeeded\n");
		break;
	case -ENOMEM:
		_debug("ksign: Signature check ENOMEM\n");
		break;
	default:
		_debug("ksign: Signature check failed: %d\n", retval);
		if (retval != -ENOKEY)
			retval = -EKEYREJECTED;
		break;
	}

cleanup:
	if (sig)
		ksign_free_signature(sig);
	kfree(export_buf);
	kfree(digest);
	return retval;
}

/* module-verify.c: module verifier
 *
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fips.h>
#include "module-verify.h"

/*
 * verify a module's integrity
 * - check the ELF is viable
 * - check the module's signature
 */
int module_verify(const Elf_Ehdr *hdr, size_t size, int *_gpgsig_ok)
{
	struct module_verify_data mvdata;
	int ret;

	memset(&mvdata, 0, sizeof(mvdata));
	mvdata.buffer	= hdr;
	mvdata.hdr	= hdr;
	mvdata.size	= size;

	ret = module_verify_elf(&mvdata);
	if (ret < 0) {
		if (ret == -ELIBBAD)
			printk("Module failed ELF checks\n");
		goto error;
	}

	ret = module_verify_signature(&mvdata, _gpgsig_ok);
#ifdef CONFIG_CRYPTO_FIPS
	if (ret < 0 && fips_enabled)
		panic("Module verification failed with error %d in FIPS mode\n",
		      ret);
#endif

error:
	kfree(mvdata.secsizes);
	kfree(mvdata.canonlist);
	return ret;
}

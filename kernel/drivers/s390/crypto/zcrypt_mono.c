/*
 *  linux/drivers/s390/crypto/zcrypt_mono.c
 *
 *  zcrypt 2.1.0
 *
 *  Copyright (C)  2001, 2006 IBM Corporation
 *  Author(s): Robert Burroughs
 *	       Eric Rossman (edrossma@us.ibm.com)
 *
 *  Hotplug & misc device support: Jochen Roehrig (roehrig@de.ibm.com)
 *  Major cleanup & driver split: Martin Schwidefsky <schwidefsky@de.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/compat.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>

#include "ap_bus.h"
#include "zcrypt_api.h"
#include "zcrypt_pcica.h"
#include "zcrypt_pcicc.h"
#include "zcrypt_pcixcc.h"
#include "zcrypt_cex2a.h"
#include "zcrypt_msgtype6.h"
#include "zcrypt_msgtype50.h"
#include "zcrypt_cex4.h"

/**
 * The module initialization code.
 */
static int __init zcrypt_init(void)
{
	int rc;

	rc = ap_module_init();
	if (rc)
		goto out;
	rc = zcrypt_api_init();
	if (rc)
		goto out_ap;
	rc = zcrypt_msgtype6_init();
	if (rc)
		goto out_api;
	rc = zcrypt_msgtype50_init();
	if (rc)
		goto out_msgtype6;
	rc = zcrypt_pcica_init();
	if (rc)
		goto out_msgtype50;
	rc = zcrypt_pcicc_init();
	if (rc)
		goto out_pcica;
	rc = zcrypt_pcixcc_init();
	if (rc)
		goto out_pcicc;
	rc = zcrypt_cex2a_init();
	if (rc)
		goto out_pcixcc;
	rc = zcrypt_cex4_init();
	if (rc)
		goto out_cex2a;
	return 0;

out_cex2a:
	zcrypt_cex2a_exit();
out_pcixcc:
	zcrypt_pcixcc_exit();
out_pcicc:
	zcrypt_pcicc_exit();
out_pcica:
	zcrypt_pcica_exit();
out_msgtype50:
	zcrypt_msgtype50_exit();
out_msgtype6:
	zcrypt_msgtype6_exit();
out_api:
	zcrypt_api_exit();
out_ap:
	ap_module_exit();
out:
	return rc;
}

/**
 * The module termination code.
 */
static void __exit zcrypt_exit(void)
{
	zcrypt_cex4_exit();
	zcrypt_cex2a_exit();
	zcrypt_pcixcc_exit();
	zcrypt_pcicc_exit();
	zcrypt_pcica_exit();
	zcrypt_msgtype50_exit();
	zcrypt_msgtype6_exit();
	zcrypt_api_exit();
	ap_module_exit();
}

module_init(zcrypt_init);
module_exit(zcrypt_exit);

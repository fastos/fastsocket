/****************************************************************************
 * Driver for Solarflare network controllers
 *           (including support for SFE4001 10GBT NIC)
 *
 * Copyright 2005-2006: Fen Systems Ltd.
 * Copyright 2006-2010: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Initially developed by Michael Brown <mbrown@fensystems.co.uk>
 * Maintained by Solarflare Communications <linux-net-drivers@solarflare.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

#ifndef EFX_IOCTL_H
#define EFX_IOCTL_H

#include <linux/if.h>
#include <linux/sockios.h>
#include <linux/types.h>

/* Efx private ioctl number */
/* We do not use the first 3 private ioctls because some utilities expect
 * them to be the old MDIO ioctls. */
#define SIOCEFX (SIOCDEVPRIVATE + 3)

/*
 * Efx private ioctls
 */

/* For talking MCDI to siena ************************************************/
#define EFX_MCDI_REQUEST 0xef0c
struct efx_mcdi_request {
	__u32 payload[63];
	__u8 cmd;
	__u8 len; /* In and out */
	__u8 rc;
};

/* Reset selected components, like ETHTOOL_RESET ****************************/
#define EFX_RESET_FLAGS 0xef0d
struct efx_reset_flags {
	__u32 flags;
};

/* Efx private ioctl command structures *************************************/

union efx_ioctl_data {
	struct efx_mcdi_request mcdi_request;
	struct efx_reset_flags reset_flags;
};

struct efx_sock_ioctl {
	/* Command to run */
	__u16 cmd;
	__u16 reserved;
	/* Parameters */
	union efx_ioctl_data u;
} __attribute__ ((packed));

extern int efx_private_ioctl(struct efx_nic *efx, u16 cmd,
			     union efx_ioctl_data __user *data);

#endif /* EFX_IOCTL_H */

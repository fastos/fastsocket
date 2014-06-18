/****************************************************************************
 * Driver for Solarflare network controllers
 *           (including support for SFE4001 10GBT NIC)
 *
 * Copyright 2005-2006: Fen Systems Ltd.
 * Copyright 2005-2010: Solarflare Communications Inc,
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
#include "net_driver.h"
#include "efx.h"
#include "efx_ioctl.h"
#include "nic.h"
#include "mcdi.h"
#include "mcdi_pcol.h"

static int efx_ioctl_do_mcdi(struct efx_nic *efx, union efx_ioctl_data *data)
{
	struct efx_mcdi_request *req = &data->mcdi_request;
	size_t outlen;
	int rc;

	if (req->len > sizeof(req->payload) || req->len & 3) {
		netif_err(efx, drv, efx->net_dev, "inlen is too long");
		return -EINVAL;
	}

	if (efx_nic_rev(efx) < EFX_REV_SIENA_A0) {
		netif_err(efx, drv, efx->net_dev,
			  "error: NIC has no MC for MCDI\n");
		return -ENOTSUPP;
	}

	rc = efx_mcdi_rpc(efx, req->cmd, (const u8 *)req->payload,
			  req->len, (u8 *)req->payload,
			  sizeof(req->payload), &outlen);

	/* efx_mcdi_rpc() will not schedule a reset if MC_CMD_PAYLOAD causes
	 * a reboot. But from the user's POV, they're triggering a reboot
	 * 'externally', and want both ports to recover. So schedule the
	 * reset here
	 */
	if (req->cmd == MC_CMD_REBOOT && rc == -EIO) {
		netif_err(efx, drv, efx->net_dev, "MC fatal error %d\n", -rc);
		efx_schedule_reset(efx, RESET_TYPE_MC_FAILURE);
	}

	/* No distinction is made between RPC failures (driver timeouts) and
	 * MCDI failures (timeouts, reboots etc)
	 */
	req->rc = -rc;
	req->len = (__u8)outlen;
	return 0;
}

static int
efx_ioctl_reset_flags(struct efx_nic *efx, union efx_ioctl_data *data)
{
	return efx_ethtool_reset(efx->net_dev, &data->reset_flags.flags);
}

/*****************************************************************************/

int efx_private_ioctl(struct efx_nic *efx, u16 cmd,
		      union efx_ioctl_data __user *user_data)
{
	int (*op)(struct efx_nic *, union efx_ioctl_data *);
	union efx_ioctl_data data;
	size_t size;
	int rc;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	switch (cmd) {
	case EFX_MCDI_REQUEST:
		size = sizeof(data.mcdi_request);
		op = efx_ioctl_do_mcdi;
		break;
	case EFX_RESET_FLAGS:
		size = sizeof(data.reset_flags);
		op = efx_ioctl_reset_flags;
		break;
	default:
		netif_err(efx, drv, efx->net_dev,
			  "unknown private ioctl cmd %x\n", cmd);
		return -EOPNOTSUPP;
	}

	if (copy_from_user(&data, user_data, size))
		return -EFAULT;
	rc = op(efx, &data);
	if (rc)
		return rc;
	if (copy_to_user(user_data, &data, size))
		return -EFAULT;
	return 0;
}

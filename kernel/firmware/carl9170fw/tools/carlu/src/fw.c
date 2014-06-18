/*
 * carlu - userspace testing utility for ar9170 devices
 *
 * Firmware parsers
 *
 * Copyright 2009-2011 Christian Lamparter <chunkeey@googlemail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "libusb.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "carlu.h"
#include "usb.h"
#include "debug.h"

int carlu_fw_check(struct carlu *ar)
{
	struct carl9170fw_otus_desc *otus_desc;

	otus_desc = carlfw_find_desc(ar->fw, (uint8_t *) OTUS_MAGIC,
				     sizeof(*otus_desc),
				     CARL9170FW_OTUS_DESC_CUR_VER);

	if (!otus_desc) {
		err("No valid OTUS descriptor found.\n");
		return -EINVAL;
	}

	if (!carl9170fw_supports(otus_desc->feature_set, CARL9170FW_DUMMY_FEATURE)) {
		err("Invalid Firmware Descriptor.\n");
		return -EIO;
	}

	if (carl9170fw_supports(otus_desc->feature_set, CARL9170FW_UNUSABLE))
		dbg("Firmware is marked as unuseable.\n");

	info("Firmware Version: %d.\n", otus_desc->api_ver);

	return 0;
}

int carlusb_fw_check(struct carlu *ar)
{
	struct carl9170fw_otus_desc *otus_desc;

	otus_desc = carlfw_find_desc(ar->fw, (uint8_t *) OTUS_MAGIC,
				     sizeof(*otus_desc),
				     CARL9170FW_OTUS_DESC_CUR_VER);

	if (!otus_desc) {
		err("No valid USB descriptor found.\n");
		return -ENODATA;
	}

	if (!carl9170fw_supports(otus_desc->feature_set, CARL9170FW_DUMMY_FEATURE)) {
		err("Invalid Firmware Descriptor.\n");
		return -EINVAL;
	}

	if (!carl9170fw_supports(otus_desc->feature_set, CARL9170FW_USB_INIT_FIRMWARE)) {
		err("Firmware does not know how to initialize USB core.\n");
		return -EOPNOTSUPP;
	}

	if (carl9170fw_supports(otus_desc->feature_set, CARL9170FW_USB_DOWN_STREAM)) {
		dbg("Enabled tx stream mode.\n");
		ar->tx_stream = true;
		ar->extra_headroom = sizeof(struct ar9170_stream);
	}

	if (carl9170fw_supports(otus_desc->feature_set, CARL9170FW_USB_UP_STREAM)) {
		dbg("Enabled rx stream mode.\n");
		ar->rx_stream = true;
	}

	if (carl9170fw_supports(otus_desc->feature_set, CARL9170FW_USB_RESP_EP2))
		dbg("Firmware sends traps over EP2.\n");

	ar->dma_chunk_size = le16_to_cpu(otus_desc->tx_frag_len);
	ar->dma_chunks = otus_desc->tx_descs;
	ar->rx_max = le16_to_cpu(otus_desc->rx_max_frame_len);

	if (carl9170fw_supports(otus_desc->feature_set, CARL9170FW_MINIBOOT))
		ar->miniboot_size = le16_to_cpu(otus_desc->miniboot_size);

	return 0;
}

void carlu_fw_info(struct carlu *ar)
{
	struct carl9170fw_motd_desc *motd_desc;
	unsigned int fw_date;

	motd_desc = carlfw_find_desc(ar->fw, (uint8_t *) MOTD_MAGIC,
				     sizeof(*motd_desc),
				     CARL9170FW_MOTD_DESC_CUR_VER);

	if (motd_desc) {
		fw_date = le32_to_cpu(motd_desc->fw_year_month_day);

		info("Firmware Date: 2%.3d-%.2d-%.2d\n",
		     CARL9170FW_GET_YEAR(fw_date), CARL9170FW_GET_MONTH(fw_date),
		     CARL9170FW_GET_DAY(fw_date));
	}
}

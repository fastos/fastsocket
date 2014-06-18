/*
 * carl9170 firmware - used by the ar9170 wireless device
 *
 * Firmware definition
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

#ifndef __CARL9170FW_FWDSC_H
#define __CARL9170FW_FWDSC_H

#include "config.h"
#include "compiler.h"
#include "types.h"
#include "fwdesc.h"

struct carl9170_firmware_descriptor {
	struct carl9170fw_otus_desc otus;
	struct carl9170fw_txsq_desc txsq;
#ifdef CONFIG_CARL9170FW_WOL
	struct carl9170fw_wol_desc  wol;
#endif /* CONFIG_CARL9170FW_WOL */
	struct carl9170fw_motd_desc motd;
	struct carl9170fw_dbg_desc  dbg;
	struct carl9170fw_last_desc last;
} __packed;

extern const struct carl9170_firmware_descriptor carl9170fw_desc;

static inline void __check_fw(void)
{
	BUILD_BUG_ON(sizeof(carl9170fw_desc) & 0x3);
	BUILD_BUG_ON(sizeof(carl9170fw_desc) > CARL9170FW_DESC_MAX_LENGTH);
}

#endif /* __CARL9170FW_FWDSC_H */

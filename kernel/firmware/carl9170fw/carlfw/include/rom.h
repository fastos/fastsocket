/*
 * carl9170 firmware - used by the ar9170 wireless device
 *
 * ROM layout
 *
 * Copyright (c) 2000-2005 ZyDAS Technology Corporation
 * Copyright (c) 2007-2009 Atheros Communications, Inc.
 * Copyright	2009	Johannes Berg <johannes@sipsolutions.net>
 * Copyright 2009-2011	Christian Lamparter <chunkeey@googlemail.com>
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

#ifndef __CARL9170FW_ROM_H
#define __CARL9170FW_ROM_H

#include "types.h"
#include "config.h"
#include "compiler.h"
#include "usb.h"
#include "eeprom.h"

struct ar9170_hwtype {
	/* 0x00001370 */
	uint8_t data[4];

	/* 0x00001374 */
	struct ar9170_led_mode led_mode[AR9170_NUM_LEDS];

	/* 0x00001378 */
	uint8_t nulldata[2];

	struct {
		/* 0x0000137a */
		struct usb_device_descriptor device_desc;

		/* 0x0000138c */
		uint8_t string0_desc[4];

		/* 0x00001390 */
		uint8_t string1_desc[32];

		/* 0x000013b0 */
		uint8_t string2_desc[48];

		/* 0x000013e0 */
		uint8_t string3_desc[32];
	} usb;
} __packed;

struct ar9170_rom {
	/* 0x00000000 */
	uint32_t *irq_table[2];

	/* 0x00000008 */
	uint8_t bootcode[4968];

	/* 0x00001370 */
	struct ar9170_hwtype hw;

	/* 0x00001400 */
	uint8_t data[512];

	/* eeprom */
	struct ar9170_eeprom sys;
} __packed;

static const struct ar9170_rom rom __section(eeprom);

#endif /* __CARL9170FW_ROM_H */

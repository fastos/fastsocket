/*
 * carl9170 firmware - used by the ar9170 wireless device
 *
 * Copyright (c) 2000-2005  ZyDAS Technology Corporation
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

#include "carl9170.h"
#include "printf.h"
#include "rom.h"
#include "usb_fifo.h"

/* TODO / TOTEST */
#ifdef CONFIG_CARL9170FW_USB_MODESWITCH
static inline void usb_ep_map(const uint8_t ep, const uint8_t map)
{
	setb(AR9170_USB_REG_EP_MAP + (ep - 1), map);
}

static inline void usb_fifo_map(const uint8_t fifo, const uint8_t map)
{
	setb(AR9170_USB_REG_FIFO_MAP + (fifo - 1), map);
}

static inline void usb_fifo_config(const uint8_t fifo, const uint8_t cfg)
{
	setb(AR9170_USB_REG_FIFO_CONFIG + (fifo - 1), cfg);
}

static inline void usb_ep_packet_size_hi(const uint8_t ep, const uint8_t dir,
			     const uint16_t size)
{
	setb(AR9170_USB_REG_EP_IN_MAX_SIZE_HIGH + (((dir * 0x20) + ep) << 1),
	     (size >> 8) & 0xf);
}

static inline void usb_ep_packet_size_lo(const uint8_t ep, const uint8_t dir,
			    const uint16_t size)
{
	setb(AR9170_USB_REG_EP_IN_MAX_SIZE_LOW + (((dir * 0x20) + ep) << 1),
	     size & 0xff);
}

static void usb_ep_in_highbandset(const uint8_t ep, const uint8_t dir,
				const uint16_t size)
{
	andb(AR9170_USB_REG_EP_IN_MAX_SIZE_HIGH + (ep << 1), ~(BIT(6) | BIT(5)));

	switch (dir) {
	case DIRECTION_IN:
		setb(AR9170_USB_REG_EP_IN_MAX_SIZE_HIGH + (ep << 1),
		     ((size >> 11) + 1) << 5);
		break;
	case DIRECTION_OUT:
	default:
		break;
	}
}

/*
 *      vUsbFIFO_EPxCfg_HS(void)
 *      Description:
 *          1. Configure the FIFO and EPx map
 *      input: none
 *      output: none
 */

void usb_init_highspeed_fifo_cfg(void)
{
	int i;

	/* EP 1 */
	usb_ep_map(1, HS_C1_I0_A0_EP1_MAP);
	usb_fifo_map(HS_C1_I0_A0_EP1_FIFO_START, HS_C1_I0_A0_EP1_FIFO_MAP);
	usb_fifo_config(HS_C1_I0_A0_EP1_FIFO_START, HS_C1_I0_A0_EP1_FIFO_CONFIG);

	for (i = HS_C1_I0_A0_EP1_FIFO_START + 1;
	     i < HS_C1_I0_A0_EP1_FIFO_START + HS_C1_I0_A0_EP1_FIFO_NO; i++) {
		usb_fifo_config(i, (HS_C1_I0_A0_EP1_FIFO_CONFIG & (~BIT(7))));
	}

	usb_ep_packet_size_hi(1, HS_C1_I0_A0_EP1_DIRECTION, (HS_C1_I0_A0_EP1_MAX_PACKET & 0x7ff));
	usb_ep_packet_size_lo(1, HS_C1_I0_A0_EP1_DIRECTION, (HS_C1_I0_A0_EP1_MAX_PACKET & 0x7ff));
	usb_ep_in_highbandset(1, HS_C1_I0_A0_EP1_DIRECTION, HS_C1_I0_A0_EP1_MAX_PACKET);

	/* EP 2 */
	usb_ep_map(2, HS_C1_I0_A0_EP2_MAP);
	usb_fifo_map(HS_C1_I0_A0_EP2_FIFO_START, HS_C1_I0_A0_EP2_FIFO_MAP);
	usb_fifo_config(HS_C1_I0_A0_EP2_FIFO_START, HS_C1_I0_A0_EP2_FIFO_CONFIG);

	for (i = HS_C1_I0_A0_EP2_FIFO_START + 1;
	     i < HS_C1_I0_A0_EP2_FIFO_START + HS_C1_I0_A0_EP2_FIFO_NO; i++) {
		usb_fifo_config(i, (HS_C1_I0_A0_EP2_FIFO_CONFIG & (~BIT(7))));
	}

	usb_ep_packet_size_hi(2, HS_C1_I0_A0_EP2_DIRECTION, (HS_C1_I0_A0_EP2_MAX_PACKET & 0x7ff));
	usb_ep_packet_size_lo(2, HS_C1_I0_A0_EP2_DIRECTION, (HS_C1_I0_A0_EP2_MAX_PACKET & 0x7ff));
	usb_ep_in_highbandset(2, HS_C1_I0_A0_EP2_DIRECTION, HS_C1_I0_A0_EP2_MAX_PACKET);

	/* EP 3 */
	usb_ep_map(3, HS_C1_I0_A0_EP3_MAP);
	usb_fifo_map(HS_C1_I0_A0_EP3_FIFO_START, HS_C1_I0_A0_EP3_FIFO_MAP);
	usb_fifo_config(HS_C1_I0_A0_EP3_FIFO_START, HS_C1_I0_A0_EP3_FIFO_CONFIG);

	for (i = HS_C1_I0_A0_EP3_FIFO_START + 1;
	     i < HS_C1_I0_A0_EP3_FIFO_START + HS_C1_I0_A0_EP3_FIFO_NO; i++) {
		usb_fifo_config(i, (HS_C1_I0_A0_EP3_FIFO_CONFIG & (~BIT(7))));
	}

	usb_ep_packet_size_hi(3, HS_C1_I0_A0_EP3_DIRECTION, (HS_C1_I0_A0_EP3_MAX_PACKET & 0x7ff));
	usb_ep_packet_size_lo(3, HS_C1_I0_A0_EP3_DIRECTION, (HS_C1_I0_A0_EP3_MAX_PACKET & 0x7ff));
	usb_ep_in_highbandset(3, HS_C1_I0_A0_EP3_DIRECTION, HS_C1_I0_A0_EP3_MAX_PACKET);

	/* EP 4 */
	usb_ep_map(4, HS_C1_I0_A0_EP4_MAP);
	usb_fifo_map(HS_C1_I0_A0_EP4_FIFO_START, HS_C1_I0_A0_EP4_FIFO_MAP);
	usb_fifo_config(HS_C1_I0_A0_EP4_FIFO_START, HS_C1_I0_A0_EP4_FIFO_CONFIG);

	for (i = HS_C1_I0_A0_EP4_FIFO_START + 1;
	     i < HS_C1_I0_A0_EP4_FIFO_START + HS_C1_I0_A0_EP4_FIFO_NO; i++) {
		usb_fifo_config(i, (HS_C1_I0_A0_EP4_FIFO_CONFIG & (~BIT(7))));
	}

	usb_ep_packet_size_hi(4, HS_C1_I0_A0_EP4_DIRECTION, (HS_C1_I0_A0_EP4_MAX_PACKET & 0x7ff));
	usb_ep_packet_size_lo(4, HS_C1_I0_A0_EP4_DIRECTION, (HS_C1_I0_A0_EP4_MAX_PACKET & 0x7ff));
	usb_ep_in_highbandset(4, HS_C1_I0_A0_EP4_DIRECTION, HS_C1_I0_A0_EP4_MAX_PACKET);
}

void usb_init_fullspeed_fifo_cfg(void)
{
	int i;

	/* EP 1 */
	usb_ep_map(1, FS_C1_I0_A0_EP1_MAP);
	usb_fifo_map(FS_C1_I0_A0_EP1_FIFO_START, FS_C1_I0_A0_EP1_FIFO_MAP);
	usb_fifo_config(FS_C1_I0_A0_EP1_FIFO_START, FS_C1_I0_A0_EP1_FIFO_CONFIG);

	for (i = FS_C1_I0_A0_EP1_FIFO_START + 1;
	     i < FS_C1_I0_A0_EP1_FIFO_START + FS_C1_I0_A0_EP1_FIFO_NO; i++) {
		usb_fifo_config(i, (FS_C1_I0_A0_EP1_FIFO_CONFIG & (~BIT(7))));
	}

	usb_ep_packet_size_hi(1, FS_C1_I0_A0_EP1_DIRECTION, (FS_C1_I0_A0_EP1_MAX_PACKET & 0x7ff));
	usb_ep_packet_size_lo(1, FS_C1_I0_A0_EP1_DIRECTION, (FS_C1_I0_A0_EP1_MAX_PACKET & 0x7ff));
	/* ``.JWEI 2003/04/29 */
	usb_ep_in_highbandset(1, FS_C1_I0_A0_EP1_DIRECTION, FS_C1_I0_A0_EP1_MAX_PACKET);

	/* EP 2 */
	usb_ep_map(2, FS_C1_I0_A0_EP2_MAP);
	usb_fifo_map(FS_C1_I0_A0_EP2_FIFO_START, FS_C1_I0_A0_EP2_FIFO_MAP);
	usb_fifo_config(FS_C1_I0_A0_EP2_FIFO_START, FS_C1_I0_A0_EP2_FIFO_CONFIG);

	for (i = FS_C1_I0_A0_EP2_FIFO_START + 1;
	     i < FS_C1_I0_A0_EP2_FIFO_START + FS_C1_I0_A0_EP2_FIFO_NO; i++) {
		usb_fifo_config(i, (FS_C1_I0_A0_EP2_FIFO_CONFIG & (~BIT(7))));
	}

	usb_ep_packet_size_hi(2, FS_C1_I0_A0_EP2_DIRECTION, (FS_C1_I0_A0_EP2_MAX_PACKET & 0x7ff));
	usb_ep_packet_size_lo(2, FS_C1_I0_A0_EP2_DIRECTION, (FS_C1_I0_A0_EP2_MAX_PACKET & 0x7ff));
	usb_ep_in_highbandset(2, FS_C1_I0_A0_EP2_DIRECTION, FS_C1_I0_A0_EP2_MAX_PACKET);

	/* EP 3 */
	usb_ep_map(3, FS_C1_I0_A0_EP3_MAP);
	usb_fifo_map(FS_C1_I0_A0_EP3_FIFO_START, FS_C1_I0_A0_EP3_FIFO_MAP);
	usb_fifo_config(FS_C1_I0_A0_EP3_FIFO_START, FS_C1_I0_A0_EP3_FIFO_CONFIG);

	for (i = FS_C1_I0_A0_EP3_FIFO_START + 1;
	     i < FS_C1_I0_A0_EP3_FIFO_START + FS_C1_I0_A0_EP3_FIFO_NO; i++) {
		usb_fifo_config(i, (FS_C1_I0_A0_EP3_FIFO_CONFIG & (~BIT(7))));
	}

	usb_ep_packet_size_hi(3, FS_C1_I0_A0_EP3_DIRECTION, (FS_C1_I0_A0_EP3_MAX_PACKET & 0x7ff));
	usb_ep_packet_size_lo(3, FS_C1_I0_A0_EP3_DIRECTION, (FS_C1_I0_A0_EP3_MAX_PACKET & 0x7ff));
	usb_ep_in_highbandset(3, FS_C1_I0_A0_EP3_DIRECTION, FS_C1_I0_A0_EP3_MAX_PACKET);

	/* EP 4 */
	usb_ep_map(4, FS_C1_I0_A0_EP4_MAP);
	usb_fifo_map(FS_C1_I0_A0_EP4_FIFO_START, FS_C1_I0_A0_EP4_FIFO_MAP);
	usb_fifo_config(FS_C1_I0_A0_EP4_FIFO_START, FS_C1_I0_A0_EP4_FIFO_CONFIG);

	for (i = FS_C1_I0_A0_EP4_FIFO_START + 1;
	     i < FS_C1_I0_A0_EP4_FIFO_START + FS_C1_I0_A0_EP4_FIFO_NO; i++) {
		usb_fifo_config(i, (FS_C1_I0_A0_EP4_FIFO_CONFIG & (~BIT(7))));
	}

	usb_ep_packet_size_hi(4, FS_C1_I0_A0_EP4_DIRECTION, (FS_C1_I0_A0_EP4_MAX_PACKET & 0x7ff));
	usb_ep_packet_size_lo(4, FS_C1_I0_A0_EP4_DIRECTION, (FS_C1_I0_A0_EP4_MAX_PACKET & 0x7ff));
	usb_ep_in_highbandset(4, FS_C1_I0_A0_EP4_DIRECTION, FS_C1_I0_A0_EP4_MAX_PACKET);
}
#endif /* CONFIG_CARL9170FW_USB_MODESWITCH */

/*
 * carl9170 firmware - used by the ar9170 wireless device
 *
 * USB definitions
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

#ifndef __CARL9170FW_USB_H
#define __CARL9170FW_USB_H

#include "config.h"
#include "types.h"
#include "io.h"
#include "hw.h"
#include "ch9.h"

struct ar9170_usb_config {
	struct usb_config_descriptor cfg;
	struct usb_interface_descriptor intf;
	struct usb_endpoint_descriptor ep[AR9170_USB_NUM_EXTRA_EP];
} __packed;

static inline __inline bool usb_detect_highspeed(void)
{
	return !!(getb(AR9170_USB_REG_MAIN_CTRL) &
		  AR9170_USB_MAIN_CTRL_HIGHSPEED);
}

static inline __inline bool usb_configured(void)
{
	return !!(getb(AR9170_USB_REG_DEVICE_ADDRESS) &
		  AR9170_USB_DEVICE_ADDRESS_CONFIGURE);
}

static inline __inline void usb_enable_remote_wakeup(void)
{
	orb(AR9170_USB_REG_MAIN_CTRL, AR9170_USB_MAIN_CTRL_REMOTE_WAKEUP);
}

static inline __inline void usb_disable_remote_wakeup(void)
{
	andb(AR9170_USB_REG_MAIN_CTRL, ~AR9170_USB_MAIN_CTRL_REMOTE_WAKEUP);
}

static inline __inline void usb_enable_global_int(void)
{
	orb(AR9170_USB_REG_MAIN_CTRL, AR9170_USB_MAIN_CTRL_ENABLE_GLOBAL_INT);
}

static inline __inline void usb_trigger_out(void)
{
	andb(AR9170_USB_REG_INTR_MASK_BYTE_4,
		(uint8_t) ~AR9170_USB_INTR_DISABLE_OUT_INT);
}

static inline __inline void usb_reset_out(void)
{
	orb(AR9170_USB_REG_INTR_MASK_BYTE_4, AR9170_USB_INTR_DISABLE_OUT_INT);
}

static inline __inline void usb_trigger_in(void)
{
	andb(AR9170_USB_REG_INTR_MASK_BYTE_6, ~AR9170_USB_INTR_DISABLE_IN_INT);
}

static inline __inline void usb_reset_in(void)
{
	orb(AR9170_USB_REG_INTR_MASK_BYTE_6, AR9170_USB_INTR_DISABLE_IN_INT);
}

static inline __inline void usb_ep3_xfer_done(void)
{
	orb(AR9170_USB_REG_EP3_BYTE_COUNT_HIGH, 0x08);
}

static inline __inline void usb_suspend_ack(void)
{
	/*
	 * uP must do-over everything it should handle
	 * and do before into the suspend mode
	 */
	andb(AR9170_USB_REG_INTR_SOURCE_7, ~BIT(2));
}

static inline __inline void usb_resume_ack(void)
{
	/*
	 * uP must do-over everything it should handle
	 * and do before into the suspend mode
	 */

	andb(AR9170_USB_REG_INTR_SOURCE_7, ~BIT(3));
}

static inline __inline void usb_reset_ack(void)
{
	andb(AR9170_USB_REG_INTR_SOURCE_7, ~BIT(1));
}

static inline __inline void usb_data_out0Byte(void)
{
	andb(AR9170_USB_REG_INTR_SOURCE_7, (uint8_t) ~BIT(7));
}

static inline __inline void usb_data_in0Byte(void)
{
	andb(AR9170_USB_REG_INTR_SOURCE_7, ~BIT(6));
}

static inline __inline void usb_stop_down_queue(void)
{
	andl(AR9170_USB_REG_DMA_CTL, ~AR9170_USB_DMA_CTL_ENABLE_TO_DEVICE);
}

static inline __inline void usb_start_down_queue(void)
{
	orl(AR9170_USB_REG_DMA_CTL, AR9170_USB_DMA_CTL_ENABLE_TO_DEVICE);
}

static inline __inline void usb_clear_input_ep_toggle(unsigned int ep)
{
	andl(AR9170_USB_REG_EP_IN_MAX_SIZE_HIGH + (ep << 1),
	     ~AR9170_USB_EP_IN_TOGGLE);
}

static inline __inline void usb_set_input_ep_toggle(unsigned int ep)
{
	orl(AR9170_USB_REG_EP_IN_MAX_SIZE_HIGH + (ep << 1),
	    AR9170_USB_EP_IN_TOGGLE);
}

static inline __inline void usb_clear_output_ep_toggle(unsigned int ep)
{
	andl(AR9170_USB_REG_EP_OUT_MAX_SIZE_HIGH + (ep << 1),
	     ~AR9170_USB_EP_OUT_TOGGLE);
}

static inline __inline void usb_set_output_ep_toggle(unsigned int ep)
{
	orl(AR9170_USB_REG_EP_OUT_MAX_SIZE_HIGH + (ep << 1),
	    AR9170_USB_EP_OUT_TOGGLE);
}

static inline void usb_structure_check(void)
{
	BUILD_BUG_ON(sizeof(struct usb_config_descriptor) != USB_DT_CONFIG_SIZE);
	BUILD_BUG_ON(sizeof(struct usb_device_descriptor) != USB_DT_DEVICE_SIZE);
	BUILD_BUG_ON(sizeof(struct usb_endpoint_descriptor) != USB_DT_ENDPOINT_SIZE);
	BUILD_BUG_ON(sizeof(struct usb_interface_descriptor) != USB_DT_INTERFACE_SIZE);
}

void __noreturn jump_to_bootcode(void);

void send_cmd_to_host(const uint8_t len, const uint8_t type,
		      const uint8_t ext, const uint8_t *body);

void usb_init(void);
void usb_ep0rx(void);
void usb_ep0tx(void);
void usb_ep0setup(void);
void handle_usb(void);

void usb_timer(void);
void usb_putc(const char c);
void usb_print_hex_dump(const void *buf, int len);

void usb_init_highspeed_fifo_cfg(void);
void usb_init_fullspeed_fifo_cfg(void);

void __noreturn start(void);
void __noreturn reboot(void);

#endif /* __CARL9170FW_USB_H */

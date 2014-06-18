/*
 * carlu - userspace testing utility for ar9170 devices
 *
 * USB back-end API declaration
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

#ifndef __CARL9170USER_USB_H
#define __CARL9170USER_USB_H

#include "SDL.h"
#include "SDL_thread.h"
#include "libusb.h"
#include "frame.h"
#include "list.h"

#include "fwcmd.h"
#include <unistd.h>
#include "carlu.h"

#define AR9170_RX_BULK_BUFS		16
#define AR9170_RX_BULK_BUF_SIZE		8192
#define AR9170_RX_BULK_IRQ_SIZE		64

/* endpoints */
#define AR9170_EP_TX				(LIBUSB_ENDPOINT_OUT | AR9170_USB_EP_TX)
#define AR9170_EP_RX				(LIBUSB_ENDPOINT_IN  | AR9170_USB_EP_RX)
#define AR9170_EP_IRQ				(LIBUSB_ENDPOINT_IN  | AR9170_USB_EP_IRQ)
#define AR9170_EP_CMD				(LIBUSB_ENDPOINT_OUT | AR9170_USB_EP_CMD)

#define AR9170_TX_MAX_ACTIVE_URBS		8

#define CARL9170_FIRMWARE_FILE (CARLU_PATH "/../../carlfw/carl9170.fw")

struct carlu;

void carlusb_reset_txep(struct carlu *ar);

int usb_init(void);
void usb_exit(void);

struct carlu *carlusb_probe(void);
void carlusb_close(struct carlu *ar);

void carlusb_tx(struct carlu *ar, struct frame *frame);
int carlusb_fw_check(struct carlu *ar);

int carlusb_cmd(struct carlu *_ar, uint8_t oid, uint8_t *cmd, size_t clen,
		uint8_t *rsp, size_t rlen);

int carlusb_print_known_devices(void);

#endif /* __CARL9170USER_USB_H */

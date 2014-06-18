/*
 * carlu - userspace testing utility for ar9170 devices
 *
 * RX data processing
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

#include "carlu.h"
#include "debug.h"
#include "frame.h"
#include "ieee80211.h"
#include "wlan.h"

static void carlu_handle_data(struct carlu *ar, void *buf,
			       unsigned int len)
{
	if (ar->rx_cb) {
		ar->rx_cb(ar, buf, len);
	} else {
		dbg("unhandled data:\n");
		print_hex_dump_bytes(VERBOSE, "DATA:", buf, len);
	}
}

void carlu_handle_command(struct carlu *ar, void *buf,
			  unsigned int len)
{
	struct carl9170_rsp *cmd;
	int ret = 0;

	cmd = (void *) buf;

	if ((cmd->hdr.cmd & CARL9170_RSP_FLAG) != CARL9170_RSP_FLAG) {
		if ((cmd->hdr.cmd & CARL9170_CMD_ASYNC_FLAG))
			return;

		SDL_mutexP(ar->resp_lock);
		if (ar->resp_buf && ar->resp_len && ar->resp_len >= (len - 4)) {
			memcpy(ar->resp_buf, buf + 4, len - 4);
			ar->resp_buf = NULL;
		} else {
			warn("spurious command response (%d / %d)\n",
			     (int) len - 4, (int) ar->resp_len);
			print_hex_dump_bytes(WARNING, "RSP:", buf, len);
		}
		SDL_mutexV(ar->resp_lock);

		SDL_CondSignal(ar->resp_pend);
		return;
	}

	if (ar->cmd_cb)
		ret = ar->cmd_cb(ar, cmd, buf, len);

	if (ret) {
		switch (cmd->hdr.cmd) {
		case CARL9170_RSP_TXCOMP:
			carlu_tx_feedback(ar, cmd);
			break;

		case CARL9170_RSP_TEXT:
			info("carl9170 FW: %.*s\n", (int)len - 4, (char *)buf + 4);
			break;

		case CARL9170_RSP_HEXDUMP:
			info("carl9170 FW: hexdump\n");
			print_hex_dump_bytes(INFO, "HEX:", (char *)buf + 4, len - 4);
			break;

		case CARL9170_RSP_WATCHDOG:
			err("Woof Woof! Watchdog notification.\n");
			break;

		case CARL9170_RSP_GPIO:
			info("GPIO Interrupt => GPIO state %.8x\n",
			    le32_to_cpu(cmd->gpio.gpio));
			break;

		case CARL9170_RSP_RADAR:
			info("RADAR Interrupt");
			break;

		default:
			warn("received unhandled event 0x%x\n", cmd->hdr.cmd);
			print_hex_dump_bytes(WARNING, "RSP:", (char *)buf + 4, len - 4);
			break;
		}
	}
}

static void __carlu_rx(struct carlu *ar, uint8_t *buf, unsigned int len)
{
	unsigned int i;

	i = 0;

	/* weird thing, but this is the same in the original driver */
	while (len > 2 && i < 12 && buf[0] == 0xff && buf[1] == 0xff) {
		i += 2;
		len -= 2;
		buf += 2;
	}

	if (i == 12) {
		struct carl9170_rsp *cmd;
		i = 0;

		while (i < len) {
			cmd = (void *) &buf[i];

			carlu_handle_command(ar, cmd, cmd->hdr.len + 4);
			i += cmd->hdr.len + 4;
		}
	} else {
		carlu_handle_data(ar, buf, len);
	}
}

static void carlu_rx_stream(struct carlu *ar, struct frame *frame)
{
	void *buf = frame->data;
	unsigned int len = frame->len;

	while (len >= 4) {
		struct ar9170_stream *rx_stream;
		unsigned int resplen, elen;

		rx_stream = (void *) buf;
		resplen = le16_to_cpu(rx_stream->length);
		elen = roundup(resplen + 4, 4);

		if (rx_stream->tag != cpu_to_le16(0x4e00)) {
			warn("frame has no tag %p %u %x.\n",
			      buf, (int) len, rx_stream->tag);
			print_hex_dump_bytes(WARNING, "FRAME:", frame->data, frame->len);

			__carlu_rx(ar, buf, len);
			return;
		}

		__carlu_rx(ar, rx_stream->payload, resplen);

		len -= elen;
		buf += elen;
	}
}

void carlu_rx(struct carlu *ar, struct frame *frame)
{
	if (ar->rx_stream)
		carlu_rx_stream(ar, frame);
	else
		__carlu_rx(ar, frame->data, frame->len);
}

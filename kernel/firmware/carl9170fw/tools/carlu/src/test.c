/*
 * carlu - userspace testing utility for ar9170 devices
 *
 * Various tests
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
#include "SDL.h"

#include "carlu.h"
#include "debug.h"
#include "frame.h"
#include "usb.h"
#include "cmd.h"

void debug_test(void)
{
	err("This is an error.\n");
	warn("This is a warnig.\n");
	info("This is an informative message.\n");
	dbg("This is just utter useless babble.\n");
}

void carlu_frame_test(struct carlu *ar)
{
	struct frame *frame;

	frame = carlu_alloc_frame(ar, 0x40);
	frame_reserve(frame, 0x10);

	memset(frame_put(frame, 0x10), 0x11, 0x10);
	memset(frame_put(frame, 0x10), 0x22, 0x10);
	memset(frame_push(frame, 0x10), 0x33, 0x10);
	memset(frame_put(frame, 0x10), 0x44, 0x10);

	print_hex_dump_bytes(INFO, "DATA:", frame->data, frame->len);

	print_hex_dump_bytes(INFO, "PAYLOAD:", frame->payload, frame->alloced);

	frame_free(frame);
}

static void carlu_loopback_tx_cb(struct carlu *ar __unused,
				    struct frame *frame __unused)
{
}

static int carlu_loopback_cmd(struct carlu *ar __unused,
			      struct carl9170_rsp *cmd, void *buf __unused,
			      unsigned int len __unused)
{
	unsigned int i, n;

	switch (cmd->hdr.cmd) {
	case CARL9170_RSP_TXCOMP:
		n = cmd->hdr.ext;
		dbg("received tx feedback (%d).\n", n);

		for (i = 0; i < n; i++) {
			dbg("cookie:%x info:%x\n",
				cmd->_tx_status[i].cookie,
				cmd->_tx_status[i].info);
		}
		return -1;

	default:
		return -1;
	}
}

static void carlu_loopback_rx(struct carlu *ar,
				void *buf __unused, unsigned int len)
{
	ar->rxed++;
	ar->rx_octets += len;
}

static void carlu_loopback_mark_tx_frames(struct frame *frame)
{
	unsigned int i;

	for (i = 0; i < frame->len; i++)
		frame->data[i] = (uint8_t) i;
}

void carlu_loopback_test(struct carlu *ar, const unsigned int total_runs,
			  const unsigned int interval, const unsigned int min_len, const unsigned int max_len)
{
	struct frame *frame;
	uint32_t start_time, total_time = 0;
	float moctets, dtime;
	unsigned int runs = 0, i = 0, j = 0, len;
	int ret;

	if (min_len > max_len) {
		err("stresstest: invalid parameters => min_len:%d > max_len:%d",
		    min_len, max_len);
		return;
	}

	if (min_len < 4) {
		err("stresstest: invalid parameters => min_len is smaller than 4");
		return;
	}

	len = min_len;
	frame = carlu_alloc_frame(ar, len);
	frame_put(frame, len);

	carlu_loopback_mark_tx_frames(frame);

	ar->rx_cb = carlu_loopback_rx;
	ar->cmd_cb = carlu_loopback_cmd;
	ar->tx_cb = carlu_loopback_tx_cb;

	start_time = SDL_GetTicks();
	while (runs <= total_runs) {
		if (frame && carlu_tx(ar, frame) == 0) {
			len = min_len;
			i++;
		} else {
			frame_free(frame);
		}

		frame = NULL;

		frame = carlu_alloc_frame(ar, len);
		frame_put(frame, len);

		carlu_loopback_mark_tx_frames(frame);
		j++;

		total_time = SDL_GetTicks() - start_time;

		if (total_time >= interval) {
			moctets = ((float)ar->tx_octets) / (1024.0f * 1024.0f);
			dtime = ((float)total_time) / 1000;
			info("%d: tx %d of %d => %.2f MiB in %.2f secs => %.4f MBits/s\n",
				runs, i, j, moctets, dtime, (moctets * 8.0f) / dtime);

			moctets = ((float)ar->rx_octets) / (1024.0f * 1024.0f);
			info("%d: rx %d of %d => %.2f MiB in %.2f secs => %.4f MBits/s\n",
				runs, ar->rxed, i, moctets, dtime, (moctets * 8.0f) / dtime);

			if ((ar->rxed == 0 && i) || !i) {
				ret = carlu_cmd_echo(ar, 0xdeadbeef);
				if (ret)
					warn("firmware crashed... echo_cmd: (%d)\n", ret);
			}

			total_time = 0;
			i = 0;
			j = 0;
			ar->rxed = 0;
			ar->txed = 0;
			ar->rx_octets = 0;
			ar->tx_octets = 0;
			runs++;
			start_time = SDL_GetTicks();
		}
	}

	ar->rx_cb = NULL;
	ar->cmd_cb = NULL;
	ar->tx_cb = NULL;
}

int carlu_gpio_test(struct carlu *ar)
{
	uint32_t gpio;

#define CHK(cmd)				\
	do {					\
		int __err = cmd;		\
		if ((__err))			\
			return __err;		\
	} while (0)

	CHK(carlu_cmd_read_mem(ar, AR9170_GPIO_REG_PORT_DATA, &gpio));
	info("GPIO state:%x\n", gpio);

	/* turn both LEDs on */
	CHK(carlu_cmd_write_mem(ar, AR9170_GPIO_REG_PORT_DATA,
	    AR9170_GPIO_PORT_LED_0 | AR9170_GPIO_PORT_LED_1));

	SDL_Delay(700);

	CHK(carlu_cmd_read_mem(ar, AR9170_GPIO_REG_PORT_DATA, &gpio));
	info("GPIO state:%x\n", gpio);

	/* turn LEDs off everything */
	CHK(carlu_cmd_write_mem(ar, AR9170_GPIO_REG_PORT_DATA, 0));

	CHK(carlu_cmd_read_mem(ar, AR9170_GPIO_REG_PORT_DATA, &gpio));
	info("GPIO state:%x\n", gpio);
}

int carlu_random_test(struct carlu *ar)
{
	uint32_t buf[4096];
	int err, i;

	err = carlu_cmd_mem_watch(ar, AR9170_RAND_REG_NUM, sizeof(buf), buf);
	if (err)
		return err;

	for (i = 0; i < ARRAY_SIZE(buf); i++)
		info("%.2x %.2x ", buf[i] & 0xff, buf[i] >> 8);

	info("\n");
}

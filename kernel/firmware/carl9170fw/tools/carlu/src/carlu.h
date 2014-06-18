/*
 * carlu - userspace testing utility for ar9170 devices
 *
 * common API declaration
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

#ifndef __CARL9170USER_H
#define __CARL9170USER_H

#include "SDL.h"
#include "SDL_thread.h"

#include "carlfw.h"

#include "debug.h"
#include "hw.h"
#include "fwcmd.h"
#include "frame.h"
#include "eeprom.h"
#include "ieee80211.h"
#include "wlan.h"
#include "usb.h"

struct carlu {
	libusb_device_handle *dev;
	libusb_context *ctx;

	SDL_Thread *event_thread;
	bool stop_event_polling;

	struct libusb_transfer *rx_ring[AR9170_RX_BULK_BUFS];

	struct libusb_transfer *rx_interrupt;
	unsigned char irq_buf[AR9170_RX_BULK_IRQ_SIZE];

	union {
		unsigned char buf[CARL9170_MAX_CMD_LEN];
		uint32_t buf4[CARL9170_MAX_CMD_LEN / sizeof(uint32_t)];
		struct carl9170_cmd cmd;
		struct carl9170_rsp rsp;
	} cmd;

	struct list_head tx_queue;
	SDL_mutex *tx_queue_lock;
	unsigned int tx_queue_len;

	struct list_head dev_list;
	unsigned int idx;

	unsigned int miniboot_size;
	unsigned int rx_max;

	int event_pipe[2];

	SDL_cond *resp_pend;
	SDL_mutex *resp_lock;
	uint8_t *resp_buf;
	size_t resp_len;

	int tx_pending;
	uint8_t cookie;

	void (*tx_cb)(struct carlu *, struct frame *);
	void (*tx_fb_cb)(struct carlu *, struct frame *);
	void (*rx_cb)(struct carlu *, void *, unsigned int);
	int (*cmd_cb)(struct carlu *, struct carl9170_rsp *,
		      void *, unsigned int);

	struct carlfw *fw;

	struct ar9170_eeprom eeprom;

	struct frame_queue tx_sent_queue[__AR9170_NUM_TXQ];

	SDL_mutex *mem_lock;
	unsigned int dma_chunks;
	unsigned int dma_chunk_size;
	unsigned int used_dma_chunks;

	unsigned int extra_headroom;
	bool tx_stream;
	bool rx_stream;

	/* statistics */
	unsigned int rxed;
	unsigned int txed;

	unsigned long tx_octets;
	unsigned long rx_octets;
};

struct carlu_rate {
	int8_t rix;
	int8_t cnt;
	uint8_t flags;
};

struct carlu_tx_info_tx {
	unsigned int key;
};

struct carlu_tx_info {
	uint32_t flags;

	struct carlu_rate rates[CARL9170_TX_MAX_RATES];

	union {
		struct carlu_tx_info_tx tx;
	};
};

static inline struct carlu_tx_info *get_tx_info(struct frame *frame)
{
	return (void *) frame->cb;
}

void *carlu_alloc_driver(size_t size);
void carlu_free_driver(struct carlu *ar);

int carlu_fw_check(struct carlu *ar);
void carlu_fw_info(struct carlu *ar);

void carlu_rx(struct carlu *ar, struct frame *frame);
int carlu_tx(struct carlu *ar, struct frame *frame);
void carlu_tx_feedback(struct carlu *ar,
			  struct carl9170_rsp *cmd);
void carlu_handle_command(struct carlu *ar, void *buf, unsigned int len);

struct frame *carlu_alloc_frame(struct carlu *ar, unsigned int size);
void carlu_free_frame(struct carlu *ar, struct frame *frame);
#endif /* __CARL9170USER_H */

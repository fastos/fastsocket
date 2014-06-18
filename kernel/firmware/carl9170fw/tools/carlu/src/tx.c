/*
 * carlu - userspace testing utility for ar9170 devices
 *
 * xmit - related functions
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
#include "usb.h"
#include "ieee80211.h"
#include "wlan.h"

struct frame *carlu_alloc_frame(struct carlu *ar, unsigned int size)
{
	struct frame *tmp;
	unsigned int total_len;

	total_len = ar->extra_headroom + sizeof(struct _carl9170_tx_superframe) + size;

	tmp = frame_alloc(total_len);
	if (!tmp)
		return NULL;

	frame_reserve(tmp, sizeof(struct _carl9170_tx_superframe) + ar->extra_headroom);

	tmp->queue = 2;

	return tmp;
}

static int carlu_alloc_dev_mem(struct carlu *ar,
				struct frame *frame)
{
	struct _carl9170_tx_superframe *txp = (void *)frame->data;
	unsigned int len, chunks;

	len = roundup(frame->len, ar->dma_chunk_size);
	chunks = len / ar->dma_chunk_size;

	SDL_mutexP(ar->mem_lock);
	if (ar->tx_pending >= ar->dma_chunks ||
	    ar->used_dma_chunks + chunks >= ar->dma_chunks) {
		SDL_mutexV(ar->mem_lock);
		return -ENOSPC;
	}

	ar->used_dma_chunks += chunks;
	ar->tx_pending++;
	txp->s.cookie = ar->cookie++;
	SDL_mutexV(ar->mem_lock);

	return 0;
}

static void carlu_free_dev_mem(struct carlu *ar,
				 struct frame *frame)
{
	struct _carl9170_tx_superframe *txp = (void *)frame->data;
	unsigned int len, chunks;

	len = roundup(frame->len, ar->dma_chunk_size);
	chunks = len / ar->dma_chunk_size;

	SDL_mutexP(ar->mem_lock);
	ar->used_dma_chunks -= chunks;
	ar->tx_pending--;
	SDL_mutexV(ar->mem_lock);
}

void carlu_free_frame(struct carlu *ar __unused,
			 struct frame *frame)
{
	frame_free(frame);
}

static struct frame *carlu_find_frame(struct carlu *ar,
					 unsigned int queue, uint8_t cookie)
{
	struct frame *frame = NULL;

	BUG_ON(queue >= __AR9170_NUM_TXQ);
	BUG_ON(SDL_mutexP(ar->tx_sent_queue[queue].lock) != 0);
	FRAME_WALK(frame, &ar->tx_sent_queue[queue]) {
		struct _carl9170_tx_superframe *super;

		super = (void *) frame->data;
		if (super->s.cookie == cookie) {
			__frame_unlink(&ar->tx_sent_queue[queue], frame);
			SDL_mutexV(ar->tx_sent_queue[queue].lock);
			return frame;
		}
	}
	SDL_mutexV(ar->tx_sent_queue[queue].lock);

	return NULL;
}

static void carlu_tx_fb_cb(struct carlu *ar,
			      struct frame *frame)
{
	if (ar->tx_fb_cb)
		ar->tx_fb_cb(ar, frame);
	else
		carlu_free_frame(ar, frame);

}

void carlu_tx_feedback(struct carlu *ar,
		       struct carl9170_rsp *cmd)
{
	unsigned int i, n, k, q;
	struct frame *frame;
	struct carlu_tx_info *tx_info;

	n = cmd->hdr.ext;

	for (i = 0; i < n; i++) {
		q = (cmd->_tx_status[i].info >> CARL9170_TX_STATUS_QUEUE_S) &
		    CARL9170_TX_STATUS_QUEUE;
		frame = carlu_find_frame(ar, q, cmd->_tx_status[i].cookie);
		if (frame) {
			carlu_free_dev_mem(ar, frame);
			tx_info = get_tx_info(frame);

			k = (cmd->_tx_status[i].info >> CARL9170_TX_STATUS_RIX)
			    & CARL9170_TX_STATUS_RIX_S;
			tx_info->rates[k].cnt = (cmd->_tx_status[i].info >>
						 CARL9170_TX_STATUS_TRIES_S) &
						CARL9170_TX_STATUS_TRIES;
			for (k++; k < CARL9170_TX_MAX_RATES; k++) {
				tx_info->rates[k].rix = -1;
				tx_info->rates[k].cnt = -1;
			}

			carlu_tx_fb_cb(ar, frame);
		} else {
			err("Found no frame for cookie %d.\n",
			    cmd->_tx_status[i].cookie);
		}
	}
}

int carlu_tx(struct carlu *ar, struct frame *frame)
{
	struct _carl9170_tx_superframe *txp;
	unsigned int len, queue;
	int cookie, err;

	len = frame->len;

	txp = (void *) frame_push(frame, sizeof(struct _carl9170_tx_superframe));

	if (txp->s.rix)
		goto err_out;

	err = carlu_alloc_dev_mem(ar, frame);
	if (err)
		goto err_out;

	txp->s.len = cpu_to_le16(frame->len);

	queue = (frame->queue % __AR9170_NUM_TXQ);

	SET_VAL(CARL9170_TX_SUPER_MISC_QUEUE, txp->s.misc, queue);

	txp->f.length = len + FCS_LEN; /* + I(C)V_LEN */

	txp->f.mac_control = cpu_to_le16(AR9170_TX_MAC_HW_DURATION |
					 AR9170_TX_MAC_BACKOFF);
	txp->f.mac_control |= cpu_to_le16(queue << AR9170_TX_MAC_QOS_S);

	txp->f.phy_control = cpu_to_le32(AR9170_TX_PHY_MOD_CCK | AR9170_TX_PHY_BW_20MHZ |
					 ((17 * 2) << AR9170_TX_PHY_TX_PWR_S) |
					 (AR9170_TX_PHY_TXCHAIN_1 << AR9170_TX_PHY_TXCHAIN_S) |
					 (11 << AR9170_TX_PHY_MCS_S));

	frame_queue_tail(&ar->tx_sent_queue[queue], frame);
	carlusb_tx(ar, frame);
	return 0;

err_out:
	frame_pull(frame, sizeof(struct _carl9170_tx_superframe));
	return err;
}

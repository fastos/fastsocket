/*
 * carl9170 firmware - used by the ar9170 wireless device
 *
 * DMA descriptor handling functions
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

#include "carl9170.h"
#include "wl.h"
#include "printf.h"

struct ar9170_dma_memory dma_mem __section(sram);

static void copy_dma_desc(struct dma_desc *dst,
			  struct dma_desc *src)
{
	memcpy(dst, src, sizeof(struct dma_desc));
}

static void clear_descriptor(struct dma_desc *d)
{
	d->status = AR9170_OWN_BITS_SW;
	d->ctrl = 0;
	d->dataSize = 0;
	d->totalLen = 0;
	d->lastAddr = d;
	d->dataAddr = NULL;
	d->nextAddr = d;
}

static void fill_descriptor(struct dma_desc *d, uint16_t size, uint8_t *data)
{
	d->status = AR9170_OWN_BITS_SW;
	d->ctrl = 0;
	d->dataSize = size;
	d->totalLen = 0;
	d->lastAddr = d;
	d->dataAddr = data;
	d->nextAddr = NULL;
}

static void init_queue(struct dma_queue *q, struct dma_desc *d)
{
	q->head = q->terminator = d;
}

/*
 *  - Init up_queue, down_queue, tx_queue[5], rx_queue.
 *  - Setup descriptors and data buffer address.
 *  - Ring descriptors rx_queue and down_queue by dma_reclaim().
 *
 * NOTE: LastAddr tempary point (same) to nextAddr after initialize.
 *	 Because LastAddr is don't care in function dma_reclaim().
 */
void dma_init_descriptors(void)
{
	unsigned int i, j;

	for (i = 0; i < ARRAY_SIZE(dma_mem.terminator); i++)
		clear_descriptor(&dma_mem.terminator[i]);

	/* Assign terminators to DMA queues */
	i = 0;
	init_queue(&fw.pta.up_queue, &dma_mem.terminator[i++]);
	init_queue(&fw.pta.down_queue, &dma_mem.terminator[i++]);
	for (j = 0; j < __AR9170_NUM_TX_QUEUES; j++)
		init_queue(&fw.wlan.tx_queue[j], &dma_mem.terminator[i++]);
	init_queue(&fw.wlan.tx_retry, &dma_mem.terminator[i++]);
	init_queue(&fw.wlan.rx_queue, &dma_mem.terminator[i++]);
	fw.usb.int_desc = &dma_mem.terminator[i++];
	fw.wlan.fw_desc = &dma_mem.terminator[i++];

#ifdef CONFIG_CARL9170FW_CAB_QUEUE
	for (j = 0; j < CARL9170_INTF_NUM; j++)
		init_queue(&fw.wlan.cab_queue[j], &dma_mem.terminator[i++]);
#endif /* CONFIG_CARL9170FW_CAB_QUEUE */

	BUG_ON(AR9170_TERMINATOR_NUMBER != i);

	DBG("Blocks:%d [tx:%d, rx:%d] Terminators:%d/%d\n",
	    AR9170_BLOCK_NUMBER, AR9170_TX_BLOCK_NUMBER,
	    AR9170_RX_BLOCK_NUMBER, AR9170_TERMINATOR_NUMBER, i);

	/* Init descriptors and memory blocks */
	for (i = 0; i < AR9170_BLOCK_NUMBER; i++) {
		fill_descriptor(&dma_mem.block[i], AR9170_BLOCK_SIZE, dma_mem.data[i].data);

		if (i < AR9170_TX_BLOCK_NUMBER)
			dma_reclaim(&fw.pta.down_queue, &dma_mem.block[i]);
		else
			dma_reclaim(&fw.wlan.rx_queue, &dma_mem.block[i]);
	}

	/* Set DMA address registers */
	set(AR9170_PTA_REG_DN_DMA_ADDRH, (uint32_t) fw.pta.down_queue.head >> 16);
	set(AR9170_PTA_REG_DN_DMA_ADDRL, (uint32_t) fw.pta.down_queue.head & 0xffff);
	set(AR9170_PTA_REG_UP_DMA_ADDRH, (uint32_t) fw.pta.up_queue.head >> 16);
	set(AR9170_PTA_REG_UP_DMA_ADDRL, (uint32_t) fw.pta.up_queue.head & 0xffff);

	for (i = 0; i < __AR9170_NUM_TX_QUEUES; i++)
		set_wlan_txq_dma_addr(i, (uint32_t) fw.wlan.tx_queue[i].head);

	set(AR9170_MAC_REG_DMA_RXQ_ADDR, (uint32_t) fw.wlan.rx_queue.head);
	fw.usb.int_desc->dataSize = AR9170_BLOCK_SIZE;
	fw.usb.int_desc->dataAddr = (void *) &dma_mem.reserved.rsp;

	memset(DESC_PAYLOAD(fw.usb.int_desc), 0xff,
	       AR9170_INT_MAGIC_HEADER_SIZE);
	memset(DESC_PAYLOAD_OFF(fw.usb.int_desc, AR9170_INT_MAGIC_HEADER_SIZE),
	       0, AR9170_BLOCK_SIZE - AR9170_INT_MAGIC_HEADER_SIZE);

	/* rsp is now available for use */
	fw.usb.int_desc_available = 1;

	memset(DESC_PAYLOAD(fw.wlan.fw_desc), 0, 128);
	fw.wlan.fw_desc_available = 1;
}

/*
 * Free descriptor.
 *
 * Exchange the terminator and the first descriptor of the packet
 * for hardware ascy...
 */
void dma_reclaim(struct dma_queue *q, struct dma_desc *desc)
{
	struct dma_desc *tmpDesc, *last;
	struct dma_desc tdesc;

	/* 1. Set OWN bit to HW for all TDs to be added, clear ctrl and size */
	tmpDesc = desc;
	last = desc->lastAddr;

	while (1) {
		tmpDesc->status = AR9170_OWN_BITS_HW;
		tmpDesc->ctrl = 0;
		tmpDesc->totalLen = 0;
		tmpDesc->dataSize = AR9170_BLOCK_SIZE;

		/* TODO : Exception handle */

		tmpDesc->lastAddr = tmpDesc;

		if (tmpDesc == last)
			break;

		tmpDesc = tmpDesc->nextAddr;
	}

	/* 2. Next address of Last TD to be added = first TD */
	tmpDesc->nextAddr = desc;

	/* Link first TD to self */
	desc->lastAddr = q->terminator;

	/* 3. Copy first TD to be added to TTD */
	copy_dma_desc(&tdesc, desc);

	/* 4. Initialize new terminator */
	clear_descriptor(desc);

	/* 5. Copy TTD to last TD */
	tdesc.status = 0;
	copy_dma_desc((void *)q->terminator, (void *)&tdesc);
	q->terminator->status |= AR9170_OWN_BITS_HW;

	/* Update terminator pointer */
	q->terminator = desc;
}

/*
 * Put a complete packet into the tail of the Queue q.
 * Exchange the terminator and the first descriptor of the packet
 * for hardware ascy...
 */
void dma_put(struct dma_queue *q, struct dma_desc *desc)
{
	struct dma_desc *tmpDesc;
	struct dma_desc tdesc;

	tmpDesc = desc;

	while (1) {
		/* update totalLen */
		tmpDesc->totalLen = desc->totalLen;

		/* 1. Set OWN bit to HW for all TDs to be added */
		tmpDesc->status = AR9170_OWN_BITS_HW;
		/* TODO : Exception handle */

		tmpDesc->lastAddr = desc->lastAddr;

		if (desc->lastAddr == tmpDesc)
			break;

		tmpDesc = tmpDesc->nextAddr;
	}

	/* 2. Next address of Last TD to be added = first TD */
	desc->lastAddr->nextAddr = desc;

	/* If there is only one descriptor, update pointer of last descriptor */
	if (desc->lastAddr == desc)
		desc->lastAddr = q->terminator;

	/* 3. Copy first TD to be added to TTD */
	copy_dma_desc(&tdesc, desc);

	/* 4. Initialize new terminator */
	clear_descriptor(desc);

	/* 5. Copy TTD to last TD */
	tdesc.status &= (~AR9170_OWN_BITS);
	copy_dma_desc((void *)q->terminator, (void *)&tdesc);
	q->terminator->status |= AR9170_OWN_BITS_HW;

	/* Update terminator pointer */
	q->terminator = desc;
}

struct dma_desc *dma_unlink_head(struct dma_queue *queue)
{
	struct dma_desc *desc;

	if (queue_empty(queue))
		return NULL;

	desc = queue->head;

	queue->head = desc->lastAddr->nextAddr;

	/* poison nextAddr address */
	desc->lastAddr->nextAddr = desc->lastAddr;
	desc->lastAddr->lastAddr = desc->lastAddr;

	return desc;
}

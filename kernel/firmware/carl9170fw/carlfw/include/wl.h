/*
 * carl9170 firmware - used by the ar9170 wireless device
 *
 * WLAN
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

#ifndef __CARL9170FW_WLAN_H
#define __CARL9170FW_WLAN_H

#include "config.h"
#include "carl9170.h"
#include "io.h"

struct ieee80211_hdr;

static inline __inline void set_wlan_txq_dma_addr(const unsigned int q, const uint32_t v)
{
	set(AR9170_MAC_REG_DMA_TXQ_ADDR + (q << 3), v);
}

static inline __inline void set_wlan_txq_dma_curr_addr(const unsigned int q, const uint32_t v)
{
	set(AR9170_MAC_REG_DMA_TXQ_CURR_ADDR + (q << 3), v);
}

static inline __inline volatile struct dma_desc *get_wlan_txq_dma_addr(const unsigned int q)
{
	return getp(AR9170_MAC_REG_DMA_TXQ_ADDR + (q << 3));
}

static inline __inline volatile struct dma_desc *get_wlan_txq_addr(const unsigned int q)
{
	return getp(AR9170_MAC_REG_DMA_TXQ_CURR_ADDR + (q << 3));
}

static inline __inline volatile struct dma_desc *get_wlan_txq_last_addr(const unsigned int q)
{
	return getp(AR9170_MAC_REG_DMA_TXQ_LAST_ADDR + (q << 2));
}

static inline __inline void wlan_trigger(const uint32_t queue_bit)
{
	set(AR9170_MAC_REG_DMA_TRIGGER, queue_bit);
}

static inline __inline uint8_t ar9170_get_rx_macstatus_status(struct dma_desc *desc)
{
	return *((uint8_t *) DESC_PAYLOAD_OFF(desc->lastAddr,
		(unsigned int) desc->lastAddr->dataSize - 1));
}

static inline __inline uint8_t ar9170_get_rx_macstatus_error(struct dma_desc *desc)
{
	unsigned int offset;

	if (desc->lastAddr->dataSize == 1) {
		while (desc->lastAddr != desc->nextAddr)
			desc = desc->nextAddr;

		offset = (unsigned int) (desc->dataSize - 1);
	} else {
		desc = desc->lastAddr;
		offset = desc->dataSize -
			(sizeof(struct ar9170_rx_macstatus) -
			 offsetof(struct ar9170_rx_macstatus, error));
	}

	return *((uint8_t *) DESC_PAYLOAD_OFF(desc, offset));
}

static inline __inline struct ieee80211_hdr *ar9170_get_rx_i3e(struct dma_desc *desc)
{
	if (!((ar9170_get_rx_macstatus_status(desc) &
		AR9170_RX_STATUS_MPDU) & AR9170_RX_STATUS_MPDU_LAST)) {
		return (void *)(DESC_PAYLOAD_OFF(desc,
			offsetof(struct ar9170_rx_frame_head, i3e)));
	} else {
		return (void *)(DESC_PAYLOAD_OFF(desc,
			offsetof(struct ar9170_rx_frame_tail, i3e)));
	}
}

static inline __inline struct ar9170_rx_head *ar9170_get_rx_head(struct dma_desc *desc)
{
	if (!((ar9170_get_rx_macstatus_status(desc) &
		AR9170_RX_STATUS_MPDU) & AR9170_RX_STATUS_MPDU_LAST)) {
		return (void *)((uint8_t *)DESC_PAYLOAD(desc) +
			offsetof(struct ar9170_rx_frame_head, phy_head));
	} else {
		return (void *) NULL;
	}
}

static inline __inline uint32_t ar9170_rx_to_phy(struct dma_desc *rx)
{
	struct ar9170_tx_hw_phy_control phy;
	struct ar9170_rx_head *head;
	uint8_t mac_status;

	phy.set = 0;

	head = ar9170_get_rx_head(rx);
	if (!head)
		return le32_to_cpu(phy.set);

	mac_status = ar9170_get_rx_macstatus_status(rx);

	phy.modulation = mac_status & AR9170_RX_STATUS_MODULATION;
	phy.chains = AR9170_TX_PHY_TXCHAIN_1;

	switch (phy.modulation) {
	case AR9170_RX_STATUS_MODULATION_CCK:
		if (mac_status & AR9170_RX_STATUS_SHORT_PREAMBLE)
			phy.preamble = 1;

		switch (head->plcp[0]) {
		case AR9170_RX_PHY_RATE_CCK_2M:
			phy.mcs = AR9170_TX_PHY_RATE_CCK_2M;
			break;

		case AR9170_RX_PHY_RATE_CCK_5M:
			phy.mcs = AR9170_TX_PHY_RATE_CCK_5M;
			break;

		case AR9170_RX_PHY_RATE_CCK_11M:
			phy.mcs = AR9170_TX_PHY_RATE_CCK_11M;
			break;

		case AR9170_RX_PHY_RATE_CCK_1M:
		default:
			phy.mcs = AR9170_TX_PHY_RATE_CCK_1M;
			break;

		}
		break;

	case AR9170_RX_STATUS_MODULATION_DUPOFDM:
	case AR9170_RX_STATUS_MODULATION_OFDM:
		phy.mcs = head->plcp[0] & 0xf;
		break;

	case AR9170_RX_STATUS_MODULATION_HT:
		if (head->plcp[3] & 0x80)
			phy.bandwidth = 2;

		if (head->plcp[6] & 0x80)
			phy.short_gi = 1;

		/* TODO: Enable both chains for MCS > 7 */
		phy.mcs = head->plcp[6] & 0x7;
		break;
	}

	return le32_to_cpu(phy.set);
}

static inline __inline unsigned int ar9170_get_rx_mpdu_len(struct dma_desc *desc)
{
	/*
	 * WARNING: you have to check the error bits in macstatus first!
	 */

	unsigned int mpdu_len = desc->totalLen;

	mpdu_len -= sizeof(struct ar9170_rx_macstatus);

	switch (ar9170_get_rx_macstatus_status(desc) & AR9170_RX_STATUS_MPDU) {
	case AR9170_RX_STATUS_MPDU_LAST:
		mpdu_len -= sizeof(struct ar9170_rx_phystatus);
		break;

	case AR9170_RX_STATUS_MPDU_SINGLE:
		mpdu_len -= sizeof(struct ar9170_rx_phystatus);

	case AR9170_RX_STATUS_MPDU_FIRST:
		mpdu_len -= sizeof(struct ar9170_rx_head);
		break;

	case AR9170_RX_STATUS_MPDU_MIDDLE:
	default:
		break;
	}

	return mpdu_len;
}

static inline __inline bool ar9170_tx_length_check(const uint16_t len)
{
	return len > (sizeof(struct carl9170_tx_superframe) + 24 +
			 FCS_LEN);
}

static inline __inline struct carl9170_tx_superframe *get_super(struct dma_desc *desc)
{
	return container_of(DESC_PAYLOAD(desc), struct carl9170_tx_superframe,
			    f);
}

static inline __inline struct carl9170_tx_superframe *__get_super(struct dma_desc *desc)
{
	return DESC_PAYLOAD(desc);
}

static inline __inline void hide_super(struct dma_desc *desc)
{
	desc->dataAddr = (uint8_t *)
		(((unsigned long)(DESC_PAYLOAD(desc)) +
		offsetof(struct carl9170_tx_superframe, f)));

	desc->dataSize -= sizeof(struct carl9170_tx_superdesc);
	desc->totalLen -= sizeof(struct carl9170_tx_superdesc);
}

static inline __inline void unhide_super(struct dma_desc *desc)
{
	desc->dataAddr = (uint8_t *) get_super(desc);
	desc->dataSize += sizeof(struct carl9170_tx_superdesc);
	desc->totalLen += sizeof(struct carl9170_tx_superdesc);
}

static inline __inline __hot void read_tsf(uint32_t *tsf)
{
	/*
	 * "According to the [hardware] documentation:
	 *  > when TSF_LOW is read, TSF_HI is automatically concurrently
	 *  > copied into a temporary register so that an immediate read
	 *  > of TSF_HI will get the value that was present when TSF_LOW
	 *  > was read. "
	 *
	 * (David H. Lynch Jr. - mail from 2010-05-22)
	 * http://permalink.gmane.org/gmane.linux.kernel.wireless.general/51249
	 */

	tsf[0] = get(AR9170_MAC_REG_TSF_L);
	tsf[1] = get(AR9170_MAC_REG_TSF_H);
}

/* This function will only work on uint32_t-aligned pointers! */
static inline bool compare_ether_address(const void *_d0, const void *_d1)
{
	const uint32_t *d0 = _d0;
	const uint32_t *d1 = _d1;

	/* BUG_ON((unsigned long)d0 & 3 || (unsigned long)d1 & 3)) */
	return !((d0[0] ^ d1[0]) | (unsigned short)(d0[1] ^ d1[1]));
}

void wlan_tx(struct dma_desc *desc);
void wlan_tx_fw(struct carl9170_tx_superdesc *super, fw_desc_callback_t cb);
void wlan_timer(void);
void handle_wlan(void);

void wlan_cab_flush_queue(const unsigned int vif);
void wlan_modify_beacon(const unsigned int vif,
			const unsigned int bcn_addr,
			const unsigned int bcn_len);

void wlan_tx_complete(struct carl9170_tx_superframe *super, bool txs);
void wlan_prepare_wol(void);

static inline void __check_wlantx(void)
{
	BUILD_BUG_ON(CARL9170_TX_SUPERDESC_LEN & 3);
	BUILD_BUG_ON(sizeof(struct carl9170_tx_superdesc) != CARL9170_TX_SUPERDESC_LEN);
	BUILD_BUG_ON(sizeof(struct _carl9170_tx_superdesc) != CARL9170_TX_SUPERDESC_LEN);
	BUILD_BUG_ON(sizeof(struct _carl9170_tx_superframe) != CARL9170_TX_SUPERFRAME_LEN);
	BUILD_BUG_ON((offsetof(struct carl9170_tx_superframe, f) & 3) != 0);
	BUILD_BUG_ON(offsetof(struct _carl9170_tx_superframe, f) !=
		     (offsetof(struct _carl9170_tx_superframe, f)));
	BUILD_BUG_ON(sizeof(struct ar9170_tx_hwdesc) != AR9170_TX_HWDESC_LEN);
	BUILD_BUG_ON(sizeof(struct _ar9170_tx_hwdesc) != AR9170_TX_HWDESC_LEN);
	BUILD_BUG_ON(sizeof(struct ar9170_rx_head) != AR9170_RX_HEAD_LEN);
	BUILD_BUG_ON(sizeof(struct ar9170_rx_phystatus) != AR9170_RX_PHYSTATUS_LEN);
	BUILD_BUG_ON(sizeof(struct ar9170_rx_macstatus) != AR9170_RX_MACSTATUS_LEN);
}

#endif /* __CARL9170FW_WLAN_H */

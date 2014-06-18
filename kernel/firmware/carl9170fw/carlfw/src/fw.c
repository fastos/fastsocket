/*
 * carl9170 firmware - used by the ar9170 wireless device
 *
 * Firmware descriptor
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
#include "carl9170.h"
#include "fwdsc.h"

#define FILL(small, big, more...)					\
	.small = {							\
		CARL9170FW_FILL_DESC(big##_MAGIC,			\
			sizeof(struct carl9170fw_## small##_desc),	\
			CARL9170FW_## big##_DESC_MIN_VER,		\
			CARL9170FW_## big##_DESC_CUR_VER),		\
		more							\
	}

const struct carl9170_firmware_descriptor __section(fwdsc) carl9170fw_desc = {
	FILL(otus, OTUS,
	     .feature_set = cpu_to_le32(BIT(CARL9170FW_DUMMY_FEATURE) |
					BIT(CARL9170FW_USB_RESP_EP2) |
					BIT(CARL9170FW_HANDLE_BACK_REQ) |
					BIT(CARL9170FW_RX_FILTER) |
					BIT(CARL9170FW_HW_COUNTERS) |
					BIT(CARL9170FW_RX_BA_FILTER) |
					BIT(CARL9170FW_USB_INIT_FIRMWARE) |
#ifdef CONFIG_CARL9170FW_USB_UP_STREAM
					BIT(CARL9170FW_USB_UP_STREAM) |
#endif /* CONFIG_CARL9170FW_USB_UP_STREAM */
#ifdef CONFIG_CARL9170FW_USB_DOWN_STREAM
					BIT(CARL9170FW_USB_DOWN_STREAM) |
#endif /* CONFIG_CARL9170FW_USB_DOWN_STREAM */
#ifdef CONFIG_CARL9170FW_RADIO_FUNCTIONS
					BIT(CARL9170FW_COMMAND_PHY) |
					BIT(CARL9170FW_PSM) |
					BIT(CARL9170FW_FIXED_5GHZ_PSM) |
#endif /* CONFIG_CARL9170FW_RADIO_FUNCTIONS */
#ifdef CONFIG_CARL9170FW_SECURITY_ENGINE
					BIT(CARL9170FW_COMMAND_CAM) |
#endif /* CONFIG_CARL9170FW_SECURITY_ENGINE */
#ifdef CONFIG_CARL9170FW_CAB_QUEUE
					BIT(CARL9170FW_WLANTX_CAB) |
#endif /* CONFIG_CARL9170FW_CAB_QUEUE */
#ifdef CONFIG_CARL9170FW_UNUSABLE
					BIT(CARL9170FW_UNUSABLE) |
#endif /* CONFIG_CARL9170FW_UNUSABLE */
#ifdef CONFIG_CARL9170FW_GPIO_INTERRUPT
					BIT(CARL9170FW_GPIO_INTERRUPT) |
#endif /* CONFIG_CARL9170FW_GPIO_INTERRUPT */
#ifdef CONFIG_CARL9170FW_WOL
					BIT(CARL9170FW_WOL) |
#endif /* CONFIG_CARL9170FW_WOL */
					(0)),

	     .miniboot_size = cpu_to_le16(0),
	     .tx_descs = AR9170_TX_BLOCK_NUMBER,
	     .cmd_bufs = CARL9170_INT_RQ_CACHES,
	     .rx_max_frame_len = cpu_to_le16(CONFIG_CARL9170FW_RX_FRAME_LEN),
	     .tx_frag_len = cpu_to_le16(AR9170_BLOCK_SIZE),
	     .fw_address = cpu_to_le32(AR9170_PRAM_OFFSET),
	     .bcn_addr = (__le32) cpu_to_le32(&dma_mem.reserved.bcn),
	     .bcn_len = (__le16) cpu_to_le16(sizeof(dma_mem.reserved.bcn)),
	     .vif_num = CARL9170_INTF_NUM,
	     .api_ver = CONFIG_CARL9170FW_RELEASE_VERSION,
	),

	FILL(txsq, TXSQ,
	     .seq_table_addr = cpu_to_le32(&fw.wlan.sequence),
	),

#ifdef CONFIG_CARL9170FW_WOL
	FILL(wol, WOL,
	     .supported_triggers = BIT(CARL9170_WOL_DISCONNECT) |
				   BIT(CARL9170_WOL_MAGIC_PKT),
	),
#endif /* CONFIG_CARL9170FW_WOL */


	FILL(motd, MOTD,
	     .fw_year_month_day = cpu_to_le32(
			CARL9170FW_SET_DAY(CARL9170FW_VERSION_DAY) +
			CARL9170FW_SET_MONTH(CARL9170FW_VERSION_MONTH) +
			CARL9170FW_SET_YEAR(CARL9170FW_VERSION_YEAR)),
	     .desc = "Community AR9170 Linux",
	     .release = CARL9170FW_VERSION_GIT),

	FILL(dbg, DBG,
	     .bogoclock_addr = cpu_to_le32(0),
	     .counter_addr = cpu_to_le32(&fw.counter),
	     .rx_total_addr = cpu_to_le32(0),
	     .rx_overrun_addr = cpu_to_le32(0),
	     .rx_filter = cpu_to_le32(&fw.wlan.rx_filter),
	),

	FILL(last, LAST),
};

#undef FILL

struct firmware_context_struct fw;

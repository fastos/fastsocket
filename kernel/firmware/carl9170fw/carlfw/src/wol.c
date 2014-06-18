/*
 * carl9170 firmware - used by the ar9170 wireless device
 *
 * WakeUp on WLAN functions
 *
 * Copyright 2011	Christian Lamparter <chunkeey@googlemail.com>
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
#include "shared/phy.h"
#include "timer.h"
#include "wl.h"
#include "printf.h"
#include "rf.h"
#include "wol.h"
#include "linux/ieee80211.h"

#ifdef CONFIG_CARL9170FW_WOL

void wol_cmd(const struct carl9170_wol_cmd *cmd)
{
	memcpy(&fw.wol.cmd, cmd, sizeof(cmd));
}

void wol_prepare(void)
{
	/* set MAC filter */
	memcpy((void *)AR9170_MAC_REG_MAC_ADDR_L, fw.wol.cmd.mac, 6);
	memcpy((void *)AR9170_MAC_REG_BSSID_L, fw.wol.cmd.bssid, 6);
	set(AR9170_MAC_REG_RX_CONTROL, AR9170_MAC_RX_CTRL_DEAGG);

	/* set filter policy to: discard everything */
	fw.wlan.rx_filter = CARL9170_RX_FILTER_EVERYTHING;

	/* reenable rx dma */
	wlan_trigger(AR9170_DMA_TRIGGER_RXQ);

	/* initialize the last_beacon timer */
	fw.wol.last_null = fw.wol.last_beacon = get_clock_counter();
}

#ifdef CONFIG_CARL9170FW_WOL_NL80211_TRIGGERS
static bool wlan_rx_wol_magic_packet(const struct ieee80211_hdr *hdr, const unsigned int len)
{
	const unsigned char *data, *end, *mac;
	unsigned int found = 0;

	/*
	 * LIMITATION:
	 * We can only scan the first AR9170_BLOCK_SIZE [=~320] bytes
	 * for MAGIC patterns!
	 */

	mac = (const unsigned char *) AR9170_MAC_REG_MAC_ADDR_L;

	data = (u8 *)((unsigned long)hdr + ieee80211_hdrlen(hdr->frame_control));
	end = (u8 *)((unsigned long)hdr + len);

	/*
	 * scan for standard WOL Magic frame
	 *
	 * "A physical WakeOnLAN (Magic Packet) will look like this:
	 * ---------------------------------------------------------------
	 * | Synchronization Stream | Target MAC |  Password (optional)	 |
	 * |	6 octets	    | 96 octets  |   0, 4 or 6		 |
	 * ---------------------------------------------------------------
	 *
	 * The Synchronization Stream is defined as 6 bytes of FFh.
	 * The Target MAC block contains 16 duplications of the IEEEaddress
	 * of the target, with no breaks or interruptions.
	 *
	 * The Password field is optional, but if present, contains either
	 * 4 bytes or 6 bytes. The WakeOnLAN dissector was implemented to
	 * dissect the password, if present, according to the command-line
	 * format that ether-wake uses, therefore, if a 4-byte password is
	 * present, it will be dissected as an IPv4 address and if a 6-byte
	 * password is present, it will be dissected as an Ethernet address.
	 *
	 * <http://wiki.wireshark.org/WakeOnLAN>
	 */

	while (data < end) {
		if (found >= 6) {
			if (*data == mac[found % 6])
				found++;
			else
				found = 0;
		}

		/* previous check might reset found counter */
		if (found < 6) {
			if (*data == 0xff)
				found++;
			else
				found = 0;
		}

		if (found == (6 + 16 * 6))
			return true;

		data++;
	}

	return false;
}

static void wlan_wol_connect_callback(void __unused *dummy, bool success)
{
	if (success)
		fw.wol.lost_null = 0;
	else
		fw.wol.lost_null++;
}

static void wlan_wol_connection_monitor(void)
{
	struct carl9170_tx_null_superframe *nullf = &dma_mem.reserved.cmd.null;
	struct ieee80211_hdr *null = (struct ieee80211_hdr *) &nullf->f.null;

	if (!fw.wlan.fw_desc_available)
		return;

	memset(nullf, 0, sizeof(*nullf));

	nullf->s.len = sizeof(struct carl9170_tx_superdesc) +
		     sizeof(struct ar9170_tx_hwdesc) +
		     sizeof(struct ieee80211_hdr);
	nullf->s.ri[0].tries = 3;
	nullf->s.assign_seq = true;
	nullf->s.queue = AR9170_TXQ_VO;
	nullf->f.hdr.length = sizeof(struct ieee80211_hdr) + FCS_LEN;

	nullf->f.hdr.mac.backoff = 1;
	nullf->f.hdr.mac.hw_duration = 1;
	nullf->f.hdr.mac.erp_prot = AR9170_TX_MAC_PROT_RTS;

	nullf->f.hdr.phy.modulation = AR9170_TX_PHY_MOD_OFDM;
	nullf->f.hdr.phy.bandwidth = AR9170_TX_PHY_BW_20MHZ;
	nullf->f.hdr.phy.chains = AR9170_TX_PHY_TXCHAIN_2;
	nullf->f.hdr.phy.tx_power = 29; /* 14.5 dBm */
	nullf->f.hdr.phy.mcs = AR9170_TXRX_PHY_RATE_OFDM_6M;

	/* format outgoing nullfunc */
	null->frame_control = cpu_to_le16(IEEE80211_FTYPE_DATA |
		IEEE80211_STYPE_NULLFUNC | IEEE80211_FCTL_TODS);

	memcpy(null->addr1, fw.wol.cmd.bssid, 6);
	memcpy(null->addr2, fw.wol.cmd.mac, 6);
	memcpy(null->addr3, fw.wol.cmd.bssid, 6);

	wlan_tx_fw(&nullf->s, wlan_wol_connect_callback);
}

static bool wlan_rx_wol_disconnect(const unsigned int rx_filter,
				   const struct ieee80211_hdr *hdr,
				   const unsigned int __unused len)
{
	const unsigned char *bssid;
	bssid = (const unsigned char *) AR9170_MAC_REG_BSSID_L;

	/* should catch both broadcast and unicast MLMEs */
	if (!(rx_filter & CARL9170_RX_FILTER_OTHER_RA)) {
		if (ieee80211_is_deauth(hdr->frame_control) ||
		    ieee80211_is_disassoc(hdr->frame_control))
			return true;
	}

	if (ieee80211_is_beacon(hdr->frame_control) &&
	    compare_ether_address(hdr->addr3, bssid)) {
		fw.wol.last_beacon = get_clock_counter();
	}

	return false;
}

#endif /* CARL9170FW_WOL_NL80211_TRIGGERS */

#ifdef CONFIG_CARL9170FW_WOL_PROBE_REQUEST

/*
 * Note: CONFIG_CARL9170FW_WOL_PROBE_REQUEST_SSID is not a real
 * string. We have to be careful not to add a \0 at the end.
 */
static const struct {
	u8 ssid_ie;
	u8 ssid_len;
	u8 ssid[sizeof(CONFIG_CARL9170FW_WOL_PROBE_REQUEST_SSID) - 1];
} __packed probe_req = {
	.ssid_ie = WLAN_EID_SSID,
	.ssid_len = sizeof(CONFIG_CARL9170FW_WOL_PROBE_REQUEST_SSID) - 1,
	.ssid = CONFIG_CARL9170FW_WOL_PROBE_REQUEST_SSID,
};

static bool wlan_rx_wol_probe_ssid(const struct ieee80211_hdr *hdr, const unsigned int len)
{
	const unsigned char *data, *end, *scan = (void *) &probe_req;

	/*
	 * IEEE 802.11-2007 7.3.2.1 specifies that the SSID is no
	 * longer than 32 octets.
	 */
	BUILD_BUG_ON((sizeof(CONFIG_CARL9170FW_WOL_PROBE_REQUEST_SSID) - 1) > 32);

	if (ieee80211_is_probe_req(hdr->frame_control)) {
		unsigned int i;
		end = (u8 *)((unsigned long)hdr + len);

		/*
		 * The position of the SSID information element inside
		 * a probe request frame is more or less "fixed".
		 */
		data = (u8 *)((struct ieee80211_mgmt *)hdr)->u.probe_req.variable;
		for (i = 0; i < (unsigned int)(probe_req.ssid_len + 1); i++) {
			if (data > end || scan[i] != data[i])
				return false;
		}

		return true;
	}

	return false;
}
#endif /* CONFIG_CARL9170FW_WOL_PROBE_REQUEST */

void wol_rx(const unsigned int rx_filter __unused, const struct ieee80211_hdr *hdr __unused, const unsigned int len __unused)
{
#ifdef CONFIG_CARL9170FW_WOL_NL80211_TRIGGERS
	/* Disconnect is always enabled */
	if (fw.wol.cmd.flags & CARL9170_WOL_DISCONNECT &&
	    rx_filter & CARL9170_RX_FILTER_MGMT)
		fw.wol.wake_up |= wlan_rx_wol_disconnect(rx_filter, hdr, len);

	if (fw.wol.cmd.flags & CARL9170_WOL_MAGIC_PKT &&
	    rx_filter & CARL9170_RX_FILTER_DATA)
		fw.wol.wake_up |= wlan_rx_wol_magic_packet(hdr, len);
#endif /* CONFIG_CARL9170FW_WOL_NL80211_TRIGGERS */

#ifdef CONFIG_CARL9170FW_WOL_PROBE_REQUEST
	if (rx_filter & CARL9170_RX_FILTER_MGMT)
		fw.wol.wake_up |= wlan_rx_wol_probe_ssid(hdr, len);
#endif /* CONFIG_CARL9170FW_WOL_PROBE_REQUEST */
}

void wol_janitor(void)
{
	if (unlikely(fw.suspend_mode == CARL9170_HOST_SUSPENDED)) {
#ifdef CONFIG_CARL9170FW_WOL_NL80211_TRIGGERS
		if (fw.wol.cmd.flags & CARL9170_WOL_DISCONNECT) {
			/*
			 * connection lost after 10sec without receiving
			 * a beacon
			  */
			if (is_after_msecs(fw.wol.last_beacon, 10000))
				fw.wol.wake_up |= true;

			if (fw.wol.cmd.null_interval &&
			    is_after_msecs(fw.wol.last_null, fw.wol.cmd.null_interval))
				wlan_wol_connection_monitor();

			if (fw.wol.lost_null >= 5)
				fw.wol.wake_up |= true;
		}
#endif /* CONFIG_CARL9170FW_WOL_NL80211_TRIGGERS */

		if (fw.wol.wake_up) {
			fw.suspend_mode = CARL9170_AWAKE_HOST;
			set(AR9170_USB_REG_WAKE_UP, AR9170_USB_WAKE_UP_WAKE);
		}
	}
}
#else

#endif /* CONFIG_CARL9170FW_WOL */

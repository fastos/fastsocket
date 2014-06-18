/*
 * carl9170 firmware - used by the ar9170 wireless device
 *
 * Firmware command interface definition
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

#ifndef __CARL9170FW_CMD_H
#define __CARL9170FW_CMD_H

#include "config.h"
#include "compiler.h"
#include "types.h"

#include "fwcmd.h"

static inline void __check(void)
{
	BUILD_BUG_ON(sizeof(struct carl9170_cmd) != CARL9170_MAX_CMD_LEN);
	BUILD_BUG_ON(sizeof(struct carl9170_rsp) != CARL9170_MAX_CMD_LEN);
	BUILD_BUG_ON(sizeof(struct carl9170_set_key_cmd) != CARL9170_SET_KEY_CMD_SIZE);
	BUILD_BUG_ON(sizeof(struct carl9170_disable_key_cmd) != CARL9170_DISABLE_KEY_CMD_SIZE);
	BUILD_BUG_ON(sizeof(struct carl9170_rf_init) != CARL9170_RF_INIT_SIZE);
	BUILD_BUG_ON(sizeof(struct carl9170_rf_init_result) != CARL9170_RF_INIT_RESULT_SIZE);
	BUILD_BUG_ON(sizeof(struct carl9170_psm) != CARL9170_PSM_SIZE);
	BUILD_BUG_ON(sizeof(struct carl9170_tsf_rsp) != CARL9170_TSF_RSP_SIZE);
	BUILD_BUG_ON(sizeof(struct carl9170_bcn_ctrl_cmd) != CARL9170_BCN_CTRL_CMD_SIZE);
	BUILD_BUG_ON(sizeof(struct carl9170_tx_status) != CARL9170_TX_STATUS_SIZE);
	BUILD_BUG_ON(sizeof(struct _carl9170_tx_status) != CARL9170_TX_STATUS_SIZE);
	BUILD_BUG_ON(sizeof(struct carl9170_gpio) != CARL9170_GPIO_SIZE);
	BUILD_BUG_ON(sizeof(struct carl9170_rx_filter_cmd) != CARL9170_RX_FILTER_CMD_SIZE);
	BUILD_BUG_ON(sizeof(struct carl9170_wol_cmd) != CARL9170_WOL_CMD_SIZE);
}

void handle_cmd(struct carl9170_rsp *resp);

#endif /* __CARL9170FW_CMD_H */

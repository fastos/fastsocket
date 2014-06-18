/*
 * carl9170 firmware - used by the ar9170 wireless device
 *
 * RF routine definitions
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

#ifndef __CARL9170FW_RF_H
#define __CARL9170FW_RF_H

#include "config.h"

#ifdef CONFIG_CARL9170FW_RADIO_FUNCTIONS
void rf_notify_set_channel(void);
void rf_cmd(const struct carl9170_cmd *cmd, struct carl9170_rsp *resp);
void rf_psm(void);
#endif /* CONFIG_CARL9170FW_RADIO_FUNCTIONS */

#endif /* __CARL9170FW_RF_H */

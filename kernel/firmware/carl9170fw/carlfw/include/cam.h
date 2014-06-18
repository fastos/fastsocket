/*
 * carl9170 firmware - used by the ar9170 wireless device
 *
 * CAM (Security Engine) definitions
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

#ifndef __CARL9170FW_CAM_H
#define __CARL9170FW_CAM_H

#include "config.h"
#include "cmd.h"

#ifdef CONFIG_CARL9170FW_SECURITY_ENGINE

#define ENCRY_TYPE_START_ADDR	24
#define DEFAULT_ENCRY_TYPE	26
#define KEY_START_ADDR		27
#define STA_KEY_START_ADDR	155
#define COUNTER_START_ADDR      163
#define STA_COUNTER_START_ADDR	165

/* CAM */
#define MIC_FINISH			0x1

void set_key(const struct carl9170_set_key_cmd *key);
void disable_key(const struct carl9170_disable_key_cmd *key);

#endif /* CONFIG_CARL9170FW_SECURITY_ENGINE */

#endif /* __CARL9170FW_CAM_H */

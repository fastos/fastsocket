/*
 * carl9170 firmware - used by the ar9170 wireless device
 *
 * HostIF definition
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

#ifndef __CARL9170FW_HOSTIF_H
#define __CARL9170FW_HOSTIF_H

#include "config.h"
#include "compiler.h"
#include "types.h"
#include "hw.h"
#include "io.h"

static inline __inline void down_trigger(void)
{
	set(AR9170_PTA_REG_DN_DMA_TRIGGER, 1);
}

static inline __inline void up_trigger(void)
{
	set(AR9170_PTA_REG_UP_DMA_TRIGGER, 1);
}

void handle_host_interface(void);

#endif /* __CARL9170FW_HOSTIF_H */

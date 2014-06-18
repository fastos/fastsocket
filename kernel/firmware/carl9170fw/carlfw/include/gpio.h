/*
 * carl9170 firmware - used by the ar9170 wireless device
 *
 * GPIO definitions
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

#ifndef __CARL9170FW_GPIO_H
#define __CARL9170FW_GPIO_H

#include "config.h"
#include "hw.h"
#include "io.h"

static inline __inline void led_init(void)
{
	set(AR9170_GPIO_REG_PORT_TYPE, 3);
}

static inline __inline void led_set(const unsigned int ledstate)
{
	set(AR9170_GPIO_REG_PORT_DATA, ledstate);
}

#ifdef CONFIG_CARL9170FW_GPIO_INTERRUPT

void gpio_timer(void);

#endif /* CONFIG_CARL9170FW_GPIO_INTERRUPT */
#endif /* __CARL9170FW_GPIO_H */

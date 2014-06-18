/*
 * carl9170 firmware - used by the ar9170 wireless device
 *
 * GPIO interrupt service
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
#include "gpio.h"

#ifdef CONFIG_CARL9170FW_GPIO_INTERRUPT
void gpio_timer(void)
{
	uint32_t cur;

	cur = get(AR9170_GPIO_REG_PORT_DATA) & CARL9170_GPIO_MASK;

	if (cur != fw.cached_gpio_state.gpio) {
		fw.cached_gpio_state.gpio = cur;

		send_cmd_to_host(sizeof(struct carl9170_gpio),
				 CARL9170_RSP_GPIO, 0x00,
				 (uint8_t *)&fw.cached_gpio_state);

# ifdef CONFIG_CARL9170FW_WATCHDOG_BUTTON
		for (;;) {
			/*
			 * Loop forever... Until the watchdog triggers.
			 */
		}
# endif /* CONFIG_CARL9170FW_WATCHDOG_BUTTON */
	}
}
#endif /* CONFIG_CARL9170FW_GPIO_INTERRUPT */

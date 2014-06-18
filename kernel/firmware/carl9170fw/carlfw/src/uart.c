/*
 * carl9170 firmware - used by the ar9170 wireless device
 *
 * UART debug interface functions.
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
#include "uart.h"
#include "io.h"

#ifdef CONFIG_CARL9170FW_DEBUG_UART
void uart_putc(const char c)
{
	set(AR9170_UART_REG_TX_HOLDING, c);

	while (get(AR9170_UART_REG_LINE_STATUS) &
	       AR9170_UART_LINE_STS_TX_FIFO_ALMOST_EMPTY) {
		/*
		 * wait until the byte has made it
		 */
	}
}

void uart_print_hex_dump(const void *buf, const int len)
{
	unsigned int offset = 0;

	uart_putc('H');
	uart_putc('D');
	uart_putc(':');

	while (len > 0) {
		uart_putc(*((uint8_t *) buf + offset));
		offset++;
	}
}

void uart_init(void)
{
	unsigned int timeout = 0;

#ifdef CONFIG_CARL9170FW_UART_CLOCK_25M
	set(AR9170_UART_REG_DIVISOR_LSB, 0xc);
#elif CONFIG_CARL9170FW_UART_CLOCK_40M
	set(AR9170_UART_REG_DIVISOR_LSB, 0x14);	/* 40 MHz */
	set(AR9170_UART_REG_REMAINDER, 0xb38e);
#else
#error "Unsupported UART clock"
#endif /* CARL9170FW_UART_CLOCK_25M */

	while (get(AR9170_UART_REG_LINE_STATUS) &
	       AR9170_UART_LINE_STS_TRANSMITTER_EMPTY) {
		if (timeout++ >= 10000)
			break;
	}
}
#endif /* CONFIG_CARL9170FW_DEBUG_UART */

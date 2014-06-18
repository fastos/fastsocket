/*
 * carl9170 firmware - used by the ar9170 wireless device
 *
 * printf and his friends...
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

#ifndef __CARL9170FW_PRINTF_H
#define __CARL9170FW_PRINTF_H

#include <stdarg.h>
#include <string.h>
#include "config.h"
#include "carl9170.h"
#include "uart.h"
#include "fwcmd.h"

#ifdef CONFIG_CARL9170FW_PRINTF
void __attribute__((format (printf, 1, 2))) tfp_printf(const char *fmt, ...);

#define printf tfp_printf

#else
void __attribute__((format (printf, 1, 2))) min_printf(const char *fmt, ...);

#define printf min_printf
#endif /* CONFIG_CARL9170FW_PRINTF */

#define PRINT(fmt, args...)						\
	do {								\
		printf(fmt, ## args);					\
	} while (0)

#define INFO(fmt, args...)	PRINT(fmt, ## args)

#define ERR(fmt, args...)	PRINT(CARL9170_ERR_MAGIC fmt, ## args)

#ifdef CONFIG_CARL9170FW_DEBUG
#define DBG(fmt, args...)	PRINT(fmt, ## args)
#else
#define DBG(...)		do { } while (0);
#endif

/*
 * NB: even though the MACRO is called "stall". It isn't supposed
 * to stall since this will render the device unresponsive, until
 * someone pulls the plug.
 */
#define STALL()

#define BUG(fmt, args...)						\
	do {								\
		PRINT(CARL9170_BUG_MAGIC" %s()@%d \"" fmt "\"" ,	\
		      __func__, __LINE__, ## args);			\
		STALL()							\
	} while (0);

#define BUG_ON(condition)						\
	({								\
		int __ret = !!(condition);				\
		if (unlikely(!!(__ret)))				\
			BUG(#condition);				\
		(__ret);						\
	})

static inline __inline void putcharacter(const char c __unused)
{
#ifdef CONFIG_CARL9170FW_DEBUG_USB
	usb_putc(c);
#endif /* CONFIG_CARL9170FW_DEBUG_USB */

#ifdef CONFIG_CARL9170FW_DEBUG_UART
	uart_putc(c);
#endif /* CONFIG_CARL9170FW_DEBUG_UART */
}

static inline __inline void print_hex_dump(const void *buf __unused, int len __unused)
{
#ifdef CONFIG_CARL9170FW_DEBUG_USB
	usb_print_hex_dump(buf, len);
#endif /* CONFIG_CARL9170FW_DEBUG_USB */

#ifdef CONFIG_CARL9170FW_DEBUG_UART
	uart_print_hex_dump(buf, len);
#endif /* CONFIG_CARL9170FW_DEBUG_UART */
}

#endif /* __CARL9170FW_PRINTF_H */


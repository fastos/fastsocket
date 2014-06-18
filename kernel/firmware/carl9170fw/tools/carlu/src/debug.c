/*
 * carlu - userspace testing utility for ar9170 devices
 *
 * Random assortment of debug stuff
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "debug.h"

bool print_message_debug_level;
enum debug_level_t debug_level;
FILE *_stdout;
FILE *_stddbg;
FILE *_stderr;

void init_debug()
{
	debug_level = VERBOSE;
	debug_level = INFO;
	print_message_debug_level = false;

	_stdout = stdout;
	_stddbg = stdout;
	_stderr = stderr;
}

FILE *dbg_lvl_to_fh(const enum debug_level_t lvl)
{
	switch (lvl) {
	case ERROR:
	case WARNING:
		return _stderr;
	case INFO:
		return _stdout;
	case VERBOSE:
		return _stddbg;
	default:
		BUG_ON(1);
	}
}

void print_hex_dump_bytes(const enum debug_level_t lvl, const char *pre,
			  const void *buf, size_t len)
{
	char line[58];
	char str[17] = { 0 };
	const unsigned char *tmp = (void *) buf;
	char *pbuf = line;
	size_t i, j;

	for (i = 0; i < len; i++) {
		if (i % 16 == 0) {
			if (pbuf != line) {
				__fprintf(lvl, "%s%s: %s\n", pre, line, str);
				pbuf = line;
			}

			pbuf += sprintf(pbuf, "0x%04lx: ", (unsigned long)i);
		}

		pbuf += sprintf(pbuf, "%.2x ", tmp[i]);
		str[i % 16] = (isprint(tmp[i]) && isascii(tmp[i])) ? tmp[i] : '.';
	}
	if (pbuf != line) {
		if ((i % 16)) {
			str[i % 16] = '\0';

			for (j = 0; j < (16 - (i % 16)); j++)
				pbuf += sprintf(pbuf, "   ");
		}

		__fprintf(lvl, "%s%s: %s\n", pre, line, str);
	}
}

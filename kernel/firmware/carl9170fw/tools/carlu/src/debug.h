/*
 * carlu - userspace testing utility for ar9170 devices
 *
 * Debug API definition
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

#ifndef __CARL9170USER_DEBUG_H
#define __CARL9170USER_DEBUG_H

#include <stdio.h>
#include "compiler.h"

enum debug_level_t {
	SILENT,
	ERROR,
	WARNING,
	INFO,
	VERBOSE,

	/* KEEP LAST */
	ALL,
};

extern bool print_message_debug_level;
extern enum debug_level_t debug_level;

#define __fprintf(lvl, fmt, args...)		do {						\
		if (lvl <= debug_level) {							\
			if (print_message_debug_level)						\
				fprintf(dbg_lvl_to_fh(lvl), "<%d>:" fmt, lvl, ##args);		\
			else									\
				fprintf(dbg_lvl_to_fh(lvl), fmt, ##args);			\
		}										\
	} while (0);

#define dbg(fmt, args...) __fprintf(VERBOSE, fmt, ##args)
#define info(fmt, args...) __fprintf(INFO, fmt, ##args)
#define warn(fmt, args...) __fprintf(WARNING, fmt, ##args)
#define err(fmt, args...) __fprintf(ERROR, fmt, ##args)

#define BUG_ON(a)										\
	do {											\
		if (a) {									\
			__fprintf(ERROR, "!!!=>BUG IN function \"%s\" at line %d<=!!! %s\n",	\
				 __func__, __LINE__, #a);					\
			fflush(stderr);								\
			abort();								\
		}										\
	} while (0)

FILE *dbg_lvl_to_fh(const enum debug_level_t lvl);
void init_debug(void);
void print_hex_dump_bytes(const enum debug_level_t lvl, const char *prefix,
			  const void *buf, size_t len);

#endif /* __CARL9170USER_DEBUG_H */

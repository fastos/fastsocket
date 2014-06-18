/*
 * carlu - userspace testing utility for ar9170 devices
 *
 * register/memory/command access functions
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

#ifndef __CARL9170USER_CMD_H
#define __CARL9170USER_CMD_H

#include "carlu.h"

int carlu_cmd_echo(struct carlu *ar, const uint32_t message);
int carlu_cmd_reboot(struct carlu *ar);
int carlu_cmd_read_eeprom(struct carlu *ar);
int carlu_cmd_mem_dump(struct carlu *ar, const uint32_t start,
			const unsigned int len, void *_buf);
int carlu_cmd_write_mem(struct carlu *ar, const uint32_t addr,
			const uint32_t val);
int carlu_cmd_mem_watch(struct carlu *ar, const uint32_t mem,
			const unsigned int len, void *_buf);

struct carl9170_cmd *carlu_cmd_buf(struct carlu *ar,
	const enum carl9170_cmd_oids cmd, const unsigned int len);

#define PAYLOAD_MAX	(CARL9170_MAX_CMD_LEN / 4 - 1)
/*
 * Macros to facilitate writing multiple registers in a single
 * write-combining USB command. Note that when the first group
 * fails the whole thing will fail without any others attempted,
 * but you won't know which write in the group failed.
 */
#define carlu_regwrite_begin(ar)					\
do {									\
	struct carlu *__ar = ar;					\
	unsigned int __nreg = 0;					\
	int __err = 0;							\
	uint32_t __dummy;

#define carlu_regwrite_flush()						\
	if (__nreg) {							\
		__err = carlusb_cmd(__ar, CARL9170_CMD_WREG,		\
			(u8 *)&__ar->cmd.cmd.data, 8 * __nreg,		\
			(u8 *)&__dummy, sizeof(__dummy));		\
		__nreg = 0;						\
		if (__err)						\
			goto __regwrite_out;				\
	}

#define carlu_regwrite(r, v) do {					\
	__ar->cmd.buf4[2 * __nreg + 1] = cpu_to_le32(r);		\
	__ar->cmd.buf4[2 * __nreg + 2] = cpu_to_le32(v);		\
	__nreg++;							\
	if ((__nreg >= PAYLOAD_MAX / 2)) {				\
		__err = carlusb_cmd(__ar, CARL9170_CMD_WREG,		\
			(u8 *)&__ar->cmd.cmd.data, 8 * __nreg,		\
			(u8 *)&__dummy, sizeof(__dummy));		\
									\
		__nreg = 0;						\
		if (__err)						\
			goto __regwrite_out;				\
	}								\
} while (0)

#define carlu_regwrite_finish()						\
__regwrite_out :							\
	if (__err == 0 && __nreg)					\
		carlu_regwrite_flush();

#define carlu_regwrite_result()						\
	__err;								\
} while (0);


#define carlu_async_get_buf()						\
do {									\
	__cmd = carlu_cmd_buf(__carl, CARL9170_CMD_WREG_ASYNC,		\
				 CARL9170_MAX_CMD_PAYLOAD_LEN);		\
	if (IS_ERR_OR_NULL(__cmd)) {					\
		__err = __cmd ? PTR_ERR(__cmd) : -ENOMEM;		\
		goto __async_regwrite_out;				\
	}								\
} while (0);

#define carlu_async_regwrite_begin(carl)				\
do {									\
	int __nreg = 0, __err = 0;					\
	struct carlu *__carl = carl;					\
	struct carl9170_cmd *__cmd;					\
	carlu_async_get_buf();						\

#define carlu_async_regwrite_flush()					\
	if (__nreg) {							\
		__cmd->hdr.len = 8 * __nreg;				\
		__err = carlusb_cmd_async(__carl, __cmd, true);		\
		__nreg = 0;						\
		if (__err)						\
			goto __async_regwrite_out;			\
		__cmd = NULL;						\
		carlu_async_get_buf();					\
	}

#define carlu_async_regwrite(r, v) do {					\
	__cmd->wreg.regs[__nreg].addr = cpu_to_le32(r);			\
	__cmd->wreg.regs[__nreg].val = cpu_to_le32(v);			\
	__nreg++;							\
	if ((__nreg >= PAYLOAD_MAX / 2))				\
		carlu_async_regwrite_flush();				\
} while (0)

#define carlu_async_regwrite_finish()					\
__async_regwrite_out :							\
	if (__err == 0 && __nreg)					\
		carlu_async_regwrite_flush();

#define carlu_async_regwrite_result()					\
	__err;								\
} while (0);

#endif /* __CARL9170USER_CMD_H */

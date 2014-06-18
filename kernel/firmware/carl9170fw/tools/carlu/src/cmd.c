/*
 * carlu - userspace testing utility for ar9170 devices
 *
 * Abstraction Layer for FW/HW command interface
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
#include "libusb.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "carlu.h"
#include "usb.h"
#include "debug.h"
#include "fwcmd.h"
#include "eeprom.h"
#include "cmd.h"

int carlu_cmd_echo(struct carlu *ar, const uint32_t message)
{
	uint32_t _message;
	int ret;

	ret = carlusb_cmd(ar, CARL9170_CMD_ECHO,
			     (uint8_t *)&message, sizeof(message),
			     (uint8_t *)&_message, sizeof(_message));

	if (ret == 0)
		ret = (message == _message) ? 0 : -EIO;

	return ret;
}

struct carl9170_cmd *carlu_cmd_buf(struct carlu *ar,
	const enum carl9170_cmd_oids cmd, const unsigned int len)
{
	struct carl9170_cmd *tmp;

	if (len % 4 || (sizeof(struct carl9170_cmd_head) + len > 64))
		return ERR_PTR(-EINVAL);

	tmp = malloc(sizeof(struct carl9170_cmd_head) + len);
	if (tmp) {
		tmp->hdr.cmd = cmd;
		tmp->hdr.len = len;
	}
	return tmp;
}

int carlu_cmd_reboot(struct carlu *ar)
{
	struct carl9170_cmd *reboot;
	int err;

	/* sure, we could put the struct on the stack too. */
	reboot = carlu_cmd_buf(ar, CARL9170_CMD_REBOOT_ASYNC, 0);
	if (IS_ERR_OR_NULL(reboot))
		return reboot ? PTR_ERR(reboot) : -ENOMEM;

	err = carlusb_cmd_async(ar, reboot, true);
	return err;
}

int carlu_cmd_mem_dump(struct carlu *ar, const uint32_t start,
			const unsigned int len, void *_buf)
{
#define RW	8	/* number of words to read at once */
#define RB	(sizeof(uint32_t) * RW)
	uint8_t *buf = _buf;
	unsigned int i, j, block;
	int err;
	__le32 offsets[RW];

	for (i = 0; i < (len + RB - 1) / RB; i++) {
		block = min_t(unsigned int, (len - RB * i) / sizeof(uint32_t), RW);
		for (j = 0; j < block; j++)
			offsets[j] = cpu_to_le32(start + RB * i + 4 * j);

		err = carlusb_cmd(ar, CARL9170_CMD_RREG,
				    (void *) &offsets, block * sizeof(uint32_t),
				    (void *) buf + RB * i, RB);

		if (err)
			return err;
	}

#undef RW
#undef RB

	return 0;
}

int carlu_cmd_mem_watch(struct carlu *ar, const uint32_t mem,
			const unsigned int len, void *_buf)
{
#define RW	8	/* number of words to read at once */
#define RB	(sizeof(uint32_t) * RW)
	uint8_t *buf = _buf;
	unsigned int i, j, block;
	int err;
	__le32 offsets[RW];

	for (i = 0; i < (len + RB - 1) / RB; i++) {
		block = min_t(unsigned int, (len - RB * i) / sizeof(uint32_t), RW);
		for (j = 0; j < block; j++)
			offsets[j] = cpu_to_le32(mem);

		err = carlusb_cmd(ar, CARL9170_CMD_RREG,
				    (void *) &offsets, block * sizeof(uint32_t),
				    (void *) buf + RB * i, RB);

		if (err)
			return err;
	}

#undef RW
#undef RB

	return 0;
}

int carlu_cmd_write_mem(struct carlu *ar, const uint32_t addr,
			const uint32_t val)
{
	int err;
	__le32 msg, block[2] = { cpu_to_le32(addr), cpu_to_le32(val) };

	err = carlusb_cmd(ar, CARL9170_CMD_WREG,
			  (void *) &block, sizeof(block),
			  (void *) &msg, sizeof(msg));
	return err;
}

int carlu_cmd_read_mem(struct carlu *ar, const uint32_t _addr,
		       uint32_t *val)
{
	int err;
	__le32 msg, addr = { cpu_to_le32(_addr) };
	err = carlusb_cmd(ar, CARL9170_CMD_RREG, (void *) &addr, sizeof(addr),
			  (void *) &msg, sizeof(msg));

	*val = le32_to_cpu(msg);
	return err;
}

int carlu_cmd_read_eeprom(struct carlu *ar)
{

	int err;

	err = carlu_cmd_mem_dump(ar, AR9170_EEPROM_START, sizeof(ar->eeprom),
				  &ar->eeprom);

#ifndef __CHECKER__
	/* don't want to handle trailing remains */
	BUILD_BUG_ON(sizeof(ar->eeprom) % 8);
#endif

	if (ar->eeprom.length == cpu_to_le16(0xffff))
		return -ENODATA;

	return 0;
}

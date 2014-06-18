/*
 * Copyright 2010-2011 Christian Lamparter <chunkeey@googlemail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation version 2 of the License.
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

#include <stdlib.h>
#include <stdio.h>
#include <error.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "carlfw.h"

#include "compiler.h"

static int get_val(char *str, unsigned int *val)
{
	int err;

	err = sscanf(str, "%8x", val);
	if (err != 1)
		return -EINVAL;

	return 0;
}

static int get_addr(char *str, unsigned int *val)
{
	int err;

	err = get_val(str, val);
	if (*val & 3) {
		fprintf(stderr, "Address 0x%.8x is not a multiple of 4.\n",
			*val);

		return -EINVAL;
	}

	return err;
}

static int
new_fix_entry(struct carlfw *fw, struct carl9170fw_fix_entry *fix_entry)
{
	struct carl9170fw_fix_desc *fix;
	unsigned int len;

	len = sizeof(*fix) + sizeof(*fix_entry);
	fix = malloc(len);
	if (!fix)
		return -ENOMEM;

	carl9170fw_fill_desc(&fix->head, (uint8_t *) FIX_MAGIC,
			      cpu_to_le16(len),
			      CARL9170FW_FIX_DESC_MIN_VER,
			      CARL9170FW_FIX_DESC_CUR_VER);

	memcpy(&fix->data[0], fix_entry, sizeof(*fix_entry));

	return carlfw_desc_add_tail(fw, &fix->head);
}

static struct carl9170fw_fix_entry *
scan_for_similar_fix(struct carl9170fw_fix_desc *fix, __le32 address)
{
	unsigned int i, entries;

	entries = (le16_to_cpu(fix->head.length) - sizeof(*fix)) /
		   sizeof(struct carl9170fw_fix_entry);

	for (i = 0; i < entries; i++) {
		if (address == fix->data[i].address)
			return &fix->data[i];
	}

	return NULL;
}

static int
add_another_fix_entry(struct carlfw *fw, struct carl9170fw_fix_desc *fix,
		 struct carl9170fw_fix_entry *fix_entry)
{
	unsigned int entry;

	fix = carlfw_desc_mod_len(fw, &fix->head, sizeof(*fix_entry));
	if (IS_ERR_OR_NULL(fix))
		return (int) PTR_ERR(fix);

	entry = (le16_to_cpu(fix->head.length) - sizeof(*fix)) /
		sizeof(*fix_entry) - 1;

	memcpy(&fix->data[entry], fix_entry, sizeof(*fix_entry));
	return 0;
}

static int
update_entry(char option, struct carl9170fw_fix_entry *entry,
	     struct carl9170fw_fix_entry *fix)
{
	switch (option) {
	case '=':
		entry->mask = fix->mask;
		entry->value = fix->value;
		break;

	case 'O':
		entry->mask |= fix->mask;
		entry->value |= fix->value;
		break;

	case 'A':
		entry->mask &= fix->mask;
		entry->value &= fix->value;
		break;

	default:
		fprintf(stderr, "Unknown option: '%c'\n", option);
		return -EINVAL;
	}

	return 0;
}

static void user_education(void)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\teeprom_fix FW-FILE SWITCH [ADDRESS [VALUE MASK]]\n");

	fprintf(stderr, "\nDescription:\n");
	fprintf(stderr, "\tThis utility manage a set of overrides which "
			"commands the driver\n\tto load customized EEPROM' "
			"data for all specified addresses.\n");

	fprintf(stderr, "\nParameters:\n");
	fprintf(stderr, "\t'FW-FILE'  = firmware file [basename]\n");
	fprintf(stderr, "\t'SWITCH'   = [=|d|D]\n");
	fprintf(stderr, "\t | '='       => add/set value for address\n");
	fprintf(stderr, "\t | 'D'       => removes all EEPROM overrides\n");
	fprintf(stderr, "\t * 'd'       => removed override for 'address'\n");
	fprintf(stderr, "\n\t'ADDRESS'  = location of the EEPROM override\n");
	fprintf(stderr, "\t\t     NB: must be a multiple of 4.\n");
	fprintf(stderr, "\t\t     an address map can be found in eeprom.h.\n");
	fprintf(stderr, "\n\t'VALUE'    = replacement value\n");
	fprintf(stderr, "\t'MASK'     = mask for the value placement.\n\n");

	exit(EXIT_FAILURE);
}

static int
set_fix(struct carlfw *fw, struct carl9170fw_fix_desc *fix,
	char __unused option, int __unused argc, char *args[])
{
	struct carl9170fw_fix_entry fix_entry, *entry = NULL;
	unsigned int address, value, mask;
	int err;

	err = get_addr(args[3], &address);
	if (err)
		return err;

	err = get_val(args[4], &value);
	if (err)
		return err;

	err = get_val(args[5], &mask);
	if (err)
		return err;

	fix_entry.address = cpu_to_le32(address);
	fix_entry.value = cpu_to_le32(value);
	fix_entry.mask = cpu_to_le32(mask);

	if (!fix) {
		err = new_fix_entry(fw, &fix_entry);
	} else {
		entry = scan_for_similar_fix(fix, fix_entry.address);
		if (entry) {
			err = update_entry(option, entry, &fix_entry);
			if (err)
				fprintf(stdout, "Overwrite old entry.\n");
		} else {
			err = add_another_fix_entry(fw, fix, &fix_entry);
		}
	}

	return err;
}

static int
del_fix(struct carlfw *fw, struct carl9170fw_fix_desc *fix,
	char __unused option, int __unused argc, char *args[])
{
	struct carl9170fw_fix_entry *entry = NULL;
	unsigned int address;
	unsigned long off;
	unsigned int rem_len;
	int err;

	err = get_addr(args[3], &address);
	if (err)
		return err;

	if (fix)
		entry = scan_for_similar_fix(fix, cpu_to_le32(address));

	if (!entry) {
		fprintf(stderr, "Entry for 0x%.8x not found\n", address);
		return -EINVAL;
	}

	off = (unsigned long) entry - (unsigned long) fix->data;
	rem_len = le16_to_cpu(fix->head.length) - off;

	if (rem_len) {
		unsigned long cont;
		cont = (unsigned long) entry + sizeof(*entry);
		memmove(entry, (void *)cont, rem_len);
	}

	fix = carlfw_desc_mod_len(fw, &fix->head, -sizeof(*entry));
	err = IS_ERR_OR_NULL(fix);
	return err;
}

static int del_all(struct carlfw *fw, struct carl9170fw_fix_desc *fix,
	char __unused option, int __unused argc, char __unused *args[])
{
	if (!fix)
		return 0;

	carlfw_desc_del(fw, &fix->head);
	return 0;
}

static const struct {
	char option;
	int argc;
	int (*func)(struct carlfw *, struct carl9170fw_fix_desc *,
		    char, int, char **);
} programm_function[] = {
	{ '=', 6, set_fix },
	{ 'O', 6, set_fix },
	{ 'A', 6, set_fix },
	{ 'd', 4, del_fix },
	{ 'D', 3, del_all },
};

int main(int argc, char *args[])
{
	struct carl9170fw_fix_desc *fix;
	struct carlfw *fw = NULL;
	unsigned int i;
	int err = 0;
	char option;

	if (argc < 3 || argc > 6) {
		err = -EINVAL;
		goto out;
	}

	fw = carlfw_load(args[1]);
	if (IS_ERR_OR_NULL(fw)) {
		err = PTR_ERR(fw);
		fprintf(stderr, "Failed to open file \"%s\" (%d).\n",
			args[1], err);
		goto out;
	}

	fix = carlfw_find_desc(fw, (uint8_t *)FIX_MAGIC, sizeof(*fix),
			       CARL9170FW_FIX_DESC_CUR_VER);

	option = args[2][0];
	for (i = 0; i < ARRAY_SIZE(programm_function); i++) {
		if (programm_function[i].option != option)
			continue;

		if (argc != programm_function[i].argc) {
			err = -EINVAL;
			goto out;
		}

		err = programm_function[i].func(fw, fix, option, argc, args);
		if (err)
			goto out;

		break;
	}
	if (i == ARRAY_SIZE(programm_function)) {
		fprintf(stderr, "Unknown option: '%c'\n",
			args[2][0]);
		goto out;
	}

	err = carlfw_store(fw);
	if (err) {
		fprintf(stderr, "Failed to apply changes (%d).\n", err);
		goto out;
	}

out:
	carlfw_release(fw);

	if (err) {
		if (err == -EINVAL)
			user_education();
		else
			fprintf(stderr, "%s\n", strerror(err));
	}

	return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

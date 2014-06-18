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

static void mini_help(void)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\tminiboot ACTION FW-FILE [MB-FILE]\n");

	fprintf(stderr, "\nDescription:\n");
	fprintf(stderr, "\tFirmware concatenation utility.\n");

	fprintf(stderr, "\nParameteres:\n");
	fprintf(stderr, "\t'ACTION'	= [a|d]\n");
	fprintf(stderr, "\t | 'a'	= Add miniboot firmware.\n");
	fprintf(stderr, "\t * 'd'	= remove miniboot firmware.\n");
	fprintf(stderr, "\t'FW-FILE'	= destination for the package.\n");
	fprintf(stderr, "\t'MB-FILE'	= extra firmware image.\n");
}

static int add_mini(struct carlfw *fw, const char *mini)
{
	struct stat file_stat;
	struct carl9170fw_otus_desc *otus_desc = NULL;
	FILE *m = NULL;
	char *buf = NULL;
	size_t extra;
	int err;

	m = fopen(mini, "r");
	if (m == NULL) {
		fprintf(stderr, "Failed to open file %s (%d).\n",
			mini, errno);
		err = -errno;
		goto fail;
	}

	err = fstat(fileno(m), &file_stat);
	if (err) {
		fprintf(stderr, "Failed to query file infos from "
				"\"%s\" (%d).\n", mini, errno);
		err = -errno;
		goto fail;
	}
	extra = file_stat.st_size;

	otus_desc = carlfw_find_desc(fw, (uint8_t *) OTUS_MAGIC,
				     sizeof(*otus_desc),
				     CARL9170FW_OTUS_DESC_CUR_VER);
	if (!otus_desc) {
		fprintf(stderr, "No OTUS descriptor found\n");
		goto fail;
	}

	if (carl9170fw_supports(otus_desc->feature_set, CARL9170FW_MINIBOOT)) {
		fprintf(stderr, "Firmware has already a miniboot image.\n");
		goto fail;
	}

	otus_desc->feature_set |= cpu_to_le32(BIT(CARL9170FW_MINIBOOT));
	otus_desc->miniboot_size = cpu_to_le16(extra);

	buf = carlfw_mod_headroom(fw, extra);
	if (IS_ERR_OR_NULL(buf)) {
		fprintf(stderr, "Unable to add miniboot image.\n");
		goto fail;
	}

	err = fread(buf, extra, 1, m);
	if (err != 1) {
		fprintf(stderr, "Unable to load miniboot.\n");
		goto fail;
	}

	carlfw_store(fw);
	fclose(m);

	return 0;

fail:
	if (m)
		fclose(m);

	return err;
}

static int del_mini(struct carlfw *fw)
{
	struct carl9170fw_otus_desc *otus_desc = NULL;
	void *buf;
	int cut;

	otus_desc = carlfw_find_desc(fw, (uint8_t *) OTUS_MAGIC,
				     sizeof(*otus_desc),
				     CARL9170FW_OTUS_DESC_CUR_VER);
	if (!otus_desc) {
		fprintf(stderr, "Firmware is not for USB devices.\n");
		return -ENODATA;
	}

	if (!carl9170fw_supports(otus_desc->feature_set, CARL9170FW_MINIBOOT)) {
		fprintf(stderr, "Firmware has no miniboot image.\n");
		return -EINVAL;
	}

	cut = le16_to_cpu(otus_desc->miniboot_size);

	buf = carlfw_mod_headroom(fw, -cut);
	if (IS_ERR_OR_NULL(buf)) {
		fprintf(stderr, "Unable to remove miniboot.\n");
		return PTR_ERR(buf);
	}

	otus_desc->feature_set &= cpu_to_le32(~BIT(CARL9170FW_MINIBOOT));
	otus_desc->miniboot_size = cpu_to_le16(0);

	carlfw_store(fw);
	return 0;
}

int main(int argc, char *args[])
{
	struct carlfw *fw = NULL;
	int err;

	if (argc < 3 || argc > 4) {
		err = -EINVAL;
		goto err_param;
	}

	switch (args[1][0]) {
	case 'a':
		if (argc != 4)
			goto err_param;

		fw = carlfw_load(args[2]);
		if (IS_ERR_OR_NULL(fw)) {
			err = PTR_ERR(fw);
			goto err_out;
		}

		err = add_mini(fw, args[3]);
		break;
	case 'd':
		if (argc != 3)
			goto err_param;

		fw = carlfw_load(args[2]);
		if (IS_ERR_OR_NULL(fw)) {
			err = PTR_ERR(fw);
			goto err_out;
		}

		err = del_mini(fw);
		break;

	default:
		goto err_param;
		break;
	}

	carlfw_release(fw);
	return EXIT_SUCCESS;

err_out:
	carlfw_release(fw);
	fprintf(stderr, "miniboot action failed (%d).\n", err);
	return EXIT_FAILURE;

err_param:
	carlfw_release(fw);
	mini_help();
	return EXIT_FAILURE;
}

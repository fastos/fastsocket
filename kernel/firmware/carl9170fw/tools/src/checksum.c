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

static void checksum_help(void)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\tchecksum FW-FILE\n");

	fprintf(stderr, "\nDescription:\n");
	fprintf(stderr, "\tThis simple utility adds/updates various "
			"checksums.\n");

	fprintf(stderr, "\nParameteres:\n");
	fprintf(stderr, "\t 'FW-FILE'	= firmware name\n");
	fprintf(stderr, "\n");
}

int main(int argc, char *args[])
{
	struct carlfw *fw = NULL;
	int err = 0;

	if (argc != 2) {
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

	/*
	 * No magic here, The checksum descriptor is added/update
	 * automatically in a subroutine of carlfw_store().
	 *
	 * This tools serves as a skeleton/example.
	 */
	err = carlfw_store(fw);
	if (err) {
		fprintf(stderr, "Failed to apply checksum (%d).\n", err);
		goto out;
	}

out:
	switch (err) {
	case 0:
		fprintf(stdout, "checksum applied.\n");
		break;
	case -EINVAL:
		checksum_help();
		break;
	default:
		break;
	}

	carlfw_release(fw);
	return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

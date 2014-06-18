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

struct carlfw_file {
	char *name;
	size_t len;
	char *data;
};

struct carlfw {
	struct carlfw_file fw;
	struct carlfw_file hdr;

	struct list_head desc_list;
	unsigned int desc_list_entries,
		     desc_list_len;
};

#define carlfw_walk_descs(iter, fw)					\
	list_for_each_entry(iter, &fw->desc_list, h.list)

struct carlfw_list_entry_head {
	struct list_head list;
};

struct carlfw_list_entry {
	struct carlfw_list_entry_head h;
	union {
		struct carl9170fw_desc_head head;
		uint32_t data[0];
		char text[0];
	};
};

static inline struct carlfw_list_entry *carlfw_desc_to_entry(struct carl9170fw_desc_head *head)
{
	return container_of(head, struct carlfw_list_entry, head);
}

static inline struct carl9170fw_desc_head *carlfw_entry_to_desc(struct carlfw_list_entry *entry)
{
	return &entry->head;
}

static void carlfw_entry_unlink(struct carlfw *fw,
	struct carlfw_list_entry *entry)
{
	fw->desc_list_entries--;
	fw->desc_list_len -= le16_to_cpu(entry->head.length);
	list_del(&entry->h.list);
}

static void carlfw_entry_del(struct carlfw *fw,
	struct carlfw_list_entry *entry)
{
	carlfw_entry_unlink(fw, entry);
	free(entry);
}

static struct carlfw_list_entry *carlfw_find_entry(struct carlfw *fw,
						   const uint8_t descid[4],
						   unsigned int len,
						   uint8_t compatible_revision)
{
	struct carlfw_list_entry *iter;

	carlfw_walk_descs(iter, fw) {
		if (carl9170fw_desc_cmp(&iter->head, descid, len,
					 compatible_revision))
			return (void *)iter;
	}

	return NULL;
}

static struct carlfw_list_entry *__carlfw_entry_add_prepare(struct carlfw *fw,
	const struct carl9170fw_desc_head *desc)
{
	struct carlfw_list_entry *tmp;
	unsigned int len;

	len = le16_to_cpu(desc->length);

	if (len < sizeof(struct carl9170fw_desc_head))
		return ERR_PTR(-EINVAL);

	tmp = malloc(sizeof(*tmp) + len);
	if (!tmp)
		return ERR_PTR(-ENOMEM);

	fw->desc_list_entries++;
	fw->desc_list_len += len;

	memcpy(tmp->data, desc, len);
	return tmp;
}

static void __carlfw_release(struct carlfw_file *f)
{
	f->len = 0;
	if (f->name)
		free(f->name);
	f->name = NULL;

	if (f->data)
		free(f->data);
	f->data = NULL;
}

void carlfw_release(struct carlfw *fw)
{
	struct carlfw_list_entry *entry;

	if (!IS_ERR_OR_NULL(fw)) {
		while (!list_empty(&fw->desc_list)) {
			entry = list_entry(fw->desc_list.next,
					   struct carlfw_list_entry, h.list);
			carlfw_entry_del(fw, entry);
		}

		__carlfw_release(&fw->fw);
		__carlfw_release(&fw->hdr);
		free(fw);
	}
}

static int __carlfw_load(struct carlfw_file *file, const char *name, const char *mode)
{
	struct stat file_stat;
	FILE *fh;
	int err;

	fh = fopen(name, mode);
	if (fh == NULL)
		return errno ? -errno : -1;

	err = fstat(fileno(fh), &file_stat);
	if (err)
		return errno ? -errno : -1;

	file->len = file_stat.st_size;
	file->data = malloc(file->len);
	if (file->data == NULL)
		return -ENOMEM;

	err = fread(file->data, file->len, 1, fh);
	if (err != 1)
		return -ferror(fh);

	file->name = strdup(name);
	fclose(fh);

	if (!file->name)
		return -ENOMEM;

	return 0;
}

static void *__carlfw_find_desc(struct carlfw_file *file,
				uint8_t descid[4],
				unsigned int len,
				uint8_t compatible_revision)
{
	int scan = file->len, found = 0;
	struct carl9170fw_desc_head *tmp = NULL;

	while (scan >= 0) {
		if (file->data[scan] == descid[CARL9170FW_MAGIC_SIZE - found - 1])
			found++;
		else
			found = 0;

		if (found == CARL9170FW_MAGIC_SIZE)
			break;

		scan--;
	}

	if (found == CARL9170FW_MAGIC_SIZE) {
		tmp = (void *) &file->data[scan];

		if (!CHECK_HDR_VERSION(tmp, compatible_revision) &&
		    (le16_to_cpu(tmp->length) >= len))
			return tmp;
	}

	return NULL;
}

void *carlfw_find_desc(struct carlfw *fw,
		       const uint8_t descid[4],
		       const unsigned int len,
		       const uint8_t compatible_revision)
{
	struct carlfw_list_entry *tmp;

	tmp = carlfw_find_entry(fw, descid, len, compatible_revision);

	return tmp ? carlfw_entry_to_desc(tmp) : NULL;
}

int carlfw_desc_add_tail(struct carlfw *fw,
	const struct carl9170fw_desc_head *desc)
{
	struct carlfw_list_entry *tmp;

	tmp = __carlfw_entry_add_prepare(fw, desc);
	if (IS_ERR(tmp))
		return PTR_ERR(tmp);

	list_add_tail(&tmp->h.list, &fw->desc_list);
	return 0;
}

int carlfw_desc_add(struct carlfw *fw,
		    const struct carl9170fw_desc_head *desc,
		    struct carl9170fw_desc_head *prev,
		    struct carl9170fw_desc_head *next)
{
	struct carlfw_list_entry *tmp;

	tmp = __carlfw_entry_add_prepare(fw, desc);
	if (IS_ERR(tmp))
		return PTR_ERR(tmp);

	list_add(&tmp->h.list, &((carlfw_desc_to_entry(prev))->h.list),
		 &((carlfw_desc_to_entry(next))->h.list));
	return 0;
}

int carlfw_desc_add_before(struct carlfw *fw,
			   const struct carl9170fw_desc_head *desc,
			   struct carl9170fw_desc_head *pos)
{
	struct carl9170fw_desc_head *prev;
	struct carlfw_list_entry *prev_entry;

	prev_entry = carlfw_desc_to_entry(pos);

	prev = carlfw_entry_to_desc((struct carlfw_list_entry *) prev_entry->h.list.prev);

	return carlfw_desc_add(fw, desc, prev, pos);
}

void carlfw_desc_unlink(struct carlfw *fw,
	struct carl9170fw_desc_head *desc)
{
	carlfw_entry_unlink(fw, carlfw_desc_to_entry(desc));
}

void carlfw_desc_del(struct carlfw *fw,
	struct carl9170fw_desc_head *desc)
{
	carlfw_entry_del(fw, carlfw_desc_to_entry(desc));
}

void *carlfw_desc_mod_len(struct carlfw *fw __unused,
	struct carl9170fw_desc_head *desc, size_t len)
{
	struct carlfw_list_entry *obj, tmp;
	int new_len = le16_to_cpu(desc->length) + len;

	if (new_len < (int)sizeof(*desc))
		return ERR_PTR(-EINVAL);

	if (new_len > CARL9170FW_DESC_MAX_LENGTH)
		return ERR_PTR(-E2BIG);

	obj = carlfw_desc_to_entry(desc);

	memcpy(&tmp, obj, sizeof(tmp));
	obj = realloc(obj, new_len + sizeof(struct carlfw_list_entry_head));
	if (obj == NULL)
		return ERR_PTR(-ENOMEM);

	list_replace(&tmp.h.list, &obj->h.list);

	desc = carlfw_entry_to_desc(obj);
	desc->length = le16_to_cpu(new_len);
	fw->desc_list_len += len;

	return desc;
}

void *carlfw_desc_next(struct carlfw *fw,
		       struct carl9170fw_desc_head *pos)
{
	struct carlfw_list_entry *entry;

	if (!pos)
		entry = (struct carlfw_list_entry *) &fw->desc_list;
	else
		entry = carlfw_desc_to_entry(pos);

	if (list_at_tail(entry, &fw->desc_list, h.list))
		return NULL;

	entry = (struct carlfw_list_entry *) entry->h.list.next;

	return carlfw_entry_to_desc(entry);
}

static int carlfw_parse_descs(struct carlfw *fw,
			      struct carl9170fw_otus_desc *otus_desc)
{
	const struct carl9170fw_desc_head *iter = NULL;
	int err;

	carl9170fw_for_each_hdr(iter, &otus_desc->head) {
		err = carlfw_desc_add_tail(fw, iter);
		if (err)
			return err;
	}
	/* LAST is added automatically by carlfw_store */

	return err;
}

#if BYTE_ORDER == LITTLE_ENDIAN
#define CRCPOLY_LE 0xedb88320

/* copied from the linux kernel  */
static uint32_t crc32_le(uint32_t crc, unsigned char const *p, size_t len)
{
	int i;
	while (len--) {
		crc ^= *p++;
		for (i = 0; i < 8; i++)
			crc = (crc >> 1) ^ ((crc & 1) ? CRCPOLY_LE : 0);
	}
	return crc;
}
#else
#error "this tool does not work with a big endian host yet!"
#endif

static int carlfw_check_crc32s(struct carlfw *fw)
{
	struct carl9170fw_chk_desc *chk_desc;
	struct carlfw_list_entry *iter;
	unsigned int elen;
	uint32_t crc32;

	chk_desc = carlfw_find_desc(fw, (uint8_t *) CHK_MAGIC,
				    sizeof(*chk_desc),
				    CARL9170FW_CHK_DESC_CUR_VER);
	if (!chk_desc)
		return -ENODATA;

	crc32 = crc32_le(~0, (void *) fw->fw.data, fw->fw.len);
	if (crc32 != le32_to_cpu(chk_desc->fw_crc32))
		return -EINVAL;

	carlfw_walk_descs(iter, fw) {
		elen = le16_to_cpu(iter->head.length);

		if (carl9170fw_desc_cmp(&iter->head, (uint8_t *) CHK_MAGIC,
					sizeof(*chk_desc),
					CARL9170FW_CHK_DESC_CUR_VER))
			continue;

		crc32 = crc32_le(crc32, (void *) &iter->head, elen);
	}

	if (crc32 != le32_to_cpu(chk_desc->hdr_crc32))
		return -EINVAL;

	return 0;
}

struct carlfw *carlfw_load(const char *basename)
{
	char filename[256];
	struct carlfw *fw;
	struct carl9170fw_otus_desc *otus_desc;
	struct carl9170fw_last_desc *last_desc;
	struct carlfw_file *hdr_file;
	unsigned long fin, diff, off, rem;
	int err;

	fw = calloc(1, sizeof(*fw));
	if (!fw)
		return ERR_PTR(-ENOMEM);

	init_list_head(&fw->desc_list);

	err = __carlfw_load(&fw->fw, basename, "r");
	if (err)
		goto err_out;

	if (fw->hdr.name)
		hdr_file = &fw->hdr;
	else
		hdr_file = &fw->fw;

	otus_desc = __carlfw_find_desc(hdr_file, (uint8_t *) OTUS_MAGIC,
				       sizeof(*otus_desc),
				       CARL9170FW_OTUS_DESC_CUR_VER);
	last_desc = __carlfw_find_desc(hdr_file, (uint8_t *) LAST_MAGIC,
				       sizeof(*last_desc),
				       CARL9170FW_LAST_DESC_CUR_VER);

	if (!otus_desc || !last_desc ||
	    (unsigned long) otus_desc > (unsigned long) last_desc) {
		err = -ENODATA;
		goto err_out;
	}

	err = carlfw_parse_descs(fw, otus_desc);
	if (err)
		goto err_out;

	fin = (unsigned long)last_desc + sizeof(*last_desc);
	diff = fin - (unsigned long)otus_desc;
	rem = hdr_file->len - (fin - (unsigned long) hdr_file->data);

	if (rem) {
		off = (unsigned long)otus_desc - (unsigned long)hdr_file->data;
		memmove(&hdr_file->data[off],
			((uint8_t *)last_desc) + sizeof(*last_desc), rem);
	}

	hdr_file->len -= diff;
	hdr_file->data = realloc(hdr_file->data, hdr_file->len);
	if (!hdr_file->data && hdr_file->len) {
		err = -ENOMEM;
		goto err_out;
	}

	err = carlfw_check_crc32s(fw);
	if (err && err != -ENODATA)
		goto err_out;

	return fw;

err_out:
	carlfw_release(fw);
	return ERR_PTR(err);
}

static int carlfw_apply_checksums(struct carlfw *fw)
{
	struct carlfw_list_entry *iter;
	struct carl9170fw_chk_desc tmp = {
		CARL9170FW_FILL_DESC(CHK_MAGIC, sizeof(tmp),
				      CARL9170FW_CHK_DESC_MIN_VER,
				      CARL9170FW_CHK_DESC_CUR_VER) };
	struct carl9170fw_chk_desc *chk_desc = NULL;
	int err = 0;
	unsigned int len = 0, elen, max_len;
	uint32_t crc32;

	chk_desc = carlfw_find_desc(fw, (uint8_t *) CHK_MAGIC,
				    sizeof(*chk_desc),
				    CARL9170FW_CHK_DESC_CUR_VER);
	if (chk_desc) {
		carlfw_desc_del(fw, &chk_desc->head);
		chk_desc = NULL;
	}

	max_len = fw->desc_list_len;

	crc32 = crc32_le(~0, (void *) fw->fw.data, fw->fw.len);
	tmp.fw_crc32 = cpu_to_le32(crc32);

	/*
	 * NOTE:
	 *
	 * The descriptor checksum is seeded with the firmware's crc32.
	 * This neat trick ensures that the driver can check whenever
	 * descriptor actually belongs to the firmware, or not.
	 */

	carlfw_walk_descs(iter, fw) {
		elen = le16_to_cpu(iter->head.length);

		if (max_len < len + elen)
			return -EMSGSIZE;

		crc32 = crc32_le(crc32, (void *) &iter->head, elen);
		len += elen;
	}

	tmp.hdr_crc32 = cpu_to_le32(crc32);

	err = carlfw_desc_add_tail(fw, &tmp.head);

	return err;
}

int carlfw_store(struct carlfw *fw)
{
	struct carl9170fw_last_desc last_desc = {
		CARL9170FW_FILL_DESC(LAST_MAGIC, sizeof(last_desc),
			CARL9170FW_LAST_DESC_MIN_VER,
			CARL9170FW_LAST_DESC_CUR_VER) };

	struct carlfw_list_entry *iter;
	FILE *fh;
	int err, elen;

	err = carlfw_apply_checksums(fw);
	if (err)
		return err;

	fh = fopen(fw->fw.name, "w");
	if (!fh)
		return -errno;

	err = fwrite(fw->fw.data, fw->fw.len, 1, fh);
	if (err != 1) {
		err = -errno;
		goto close_out;
	}

	if (fw->hdr.name) {
		fclose(fh);

		fh = fopen(fw->hdr.name, "w");
	}

	carlfw_walk_descs(iter, fw) {
		elen = le16_to_cpu(iter->head.length);

		if (elen > CARL9170FW_DESC_MAX_LENGTH) {
			err = -E2BIG;
			goto close_out;
		}

		err = fwrite(iter->data, elen, 1, fh);
		if (err != 1) {
			err = -ferror(fh);
			goto close_out;
		}
	}

	err = fwrite(&last_desc, sizeof(last_desc), 1, fh);
	if (err != 1) {
		err = -ferror(fh);
		goto close_out;
	}

	err = 0;

close_out:
	fclose(fh);
	return err;
}

void *carlfw_mod_tailroom(struct carlfw *fw, ssize_t len)
{
	size_t new_len;
	void *buf;

	new_len = fw->fw.len + len;

	if (!carl9170fw_size_check(new_len))
		return ERR_PTR(-EINVAL);

	buf = realloc(fw->fw.data, new_len);
	if (buf == NULL)
		return ERR_PTR(-ENOMEM);

	fw->fw.len = new_len;
	fw->fw.data = buf;
	return &fw->fw.data[new_len - len];
}

void *carlfw_mod_headroom(struct carlfw *fw, ssize_t len)
{
	size_t new_len;
	void *ptr;

	new_len = fw->fw.len + len;
	if (!carl9170fw_size_check(new_len))
		return ERR_PTR(-EINVAL);

	if (len < 0)
		memmove(fw->fw.data, &fw->fw.data[len], new_len);

	ptr = carlfw_mod_tailroom(fw, len);
	if (IS_ERR_OR_NULL(ptr))
		return ptr;

	if (len > 0)
		memmove(&fw->fw.data[len], &fw->fw.data[0], new_len - len);

	return fw->fw.data;
}

void *carlfw_get_fw(struct carlfw *fw, size_t *len)
{
	*len = fw->fw.len;
	return fw->fw.data;
}

unsigned int carlfw_get_descs_num(struct carlfw *fw)
{
	return fw->desc_list_entries;
}

unsigned int carlfw_get_descs_size(struct carlfw *fw)
{
	return fw->desc_list_len;
}

/* ksign-keyring.c: public key cache
 *
 * Copyright (C) 2001 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This file is derived from part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <linux/rwsem.h>
#include "local.h"

static LIST_HEAD(keyring);
static DECLARE_RWSEM(keyring_sem);

/*
 * handle a public key element parsed from the keyring blob
 */
static int add_keyblock_key(struct ksign_public_key *pk, void *data)
{
	printk("- Added public key %X%X\n", pk->keyid[0], pk->keyid[1]);

	if (pk->expiredate && pk->expiredate < get_seconds())
		printk("  - public key has expired\n");

	if (pk->timestamp > get_seconds())
		printk("  - key was been created %lu seconds in future\n",
		       pk->timestamp - get_seconds());

	atomic_inc(&pk->count);

	down_write(&keyring_sem);
	list_add_tail(&pk->link, &keyring);
	up_write(&keyring_sem);

	return 0;
}

/*
 * handle a user ID element parsed from the keyring blob
 */
static int add_keyblock_uid(struct ksign_user_id *uid, void *data)
{
	printk("- User ID: %s\n", uid->name);
	return 1;
}

/*
 * add the keys from a ASN.1 encoded blob into the keyring
 */
int ksign_load_keyring_from_buffer(const void *buffer, size_t size)
{
    printk("Loading keyring\n");

    return ksign_parse_packets((const uint8_t *) buffer,
			       size,
			       NULL,
			       add_keyblock_key,
			       add_keyblock_uid,
			       NULL);
}

/*
 * find a public key by ID
 */
struct ksign_public_key *ksign_get_public_key(const uint32_t *keyid)
{
	struct ksign_public_key *pk;

	down_read(&keyring_sem);

	list_for_each_entry(pk, &keyring, link) {
		if (memcmp(pk->keyid, keyid, sizeof(pk->keyid)) == 0) {
			atomic_inc(&pk->count);
			goto found;
		}
	}

	pk = NULL;

found:
	up_read(&keyring_sem);
	return pk;
}

/*
 * clear the public-key keyring
 */
void ksign_clear_keyring(void)
{
	struct ksign_public_key *pk;

	down_write(&keyring_sem);

	while (!list_empty(&keyring)) {
		pk = list_entry(keyring.next, struct ksign_public_key, link);
		list_del(&pk->link);

		ksign_put_public_key(pk);
	}

	up_write(&keyring_sem);
}

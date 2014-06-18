/* local.h: kernel signature checker internal defs
 *
 * Copyright (C) 2004 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 * - Derived from GnuPG packet.h - packet definitions
 *   - Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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

#include <linux/list.h>
#include <linux/scatterlist.h>
#include <linux/crypto.h>
#include <linux/crypto/ksign.h>
#include <linux/crypto/mpi.h>
#include <asm/atomic.h>

#define SHA1_DIGEST_SIZE	20

#define PUBKEY_USAGE_SIG	1	    /* key is good for signatures */
#define PUBKEY_USAGE_ENC	2	    /* key is good for encryption */

#define PUBKEY_ALGO_DSA		17
#define DSA_NPKEY		4	/* number of MPI's in DSA public key */
#define DSA_NSIG		2	/* number of MPI's in DSA signature */

#define DIGEST_ALGO_SHA1	2

typedef enum {
	PKT_NONE			= 0,
	PKT_SIGNATURE			= 2,	/* secret key encrypted packet */
	PKT_PUBLIC_KEY			= 6,	/* public key */
	PKT_USER_ID			= 13,	/* user id packet */
} pkttype_t;

typedef enum {
	SIGSUBPKT_TEST_CRITICAL		= -3,
	SIGSUBPKT_NONE			= 0,
	SIGSUBPKT_SIG_CREATED		= 2,	/* signature creation time */
	SIGSUBPKT_SIG_EXPIRE		= 3,	/* signature expiration time */
	SIGSUBPKT_EXPORTABLE		= 4,	/* exportable */
	SIGSUBPKT_TRUST			= 5,	/* trust signature */
	SIGSUBPKT_REGEXP		= 6,	/* regular expression */
	SIGSUBPKT_REVOCABLE		= 7,	/* revocable */
	SIGSUBPKT_KEY_EXPIRE		= 9,	/* key expiration time */
	SIGSUBPKT_ARR			= 10,	/* additional recipient request */
	SIGSUBPKT_PREF_SYM		= 11,	/* preferred symmetric algorithms */
	SIGSUBPKT_REV_KEY		= 12,	/* revocation key */
	SIGSUBPKT_ISSUER		= 16,	/* issuer key ID */
	SIGSUBPKT_NOTATION		= 20,	/* notation data */
	SIGSUBPKT_PREF_HASH		= 21,	/* preferred hash algorithms */
	SIGSUBPKT_PREF_COMPR		= 22,	/* preferred compression algorithms */
	SIGSUBPKT_KS_FLAGS		= 23,	/* key server preferences */
	SIGSUBPKT_PREF_KS		= 24,	/* preferred key server */
	SIGSUBPKT_PRIMARY_UID		= 25,	/* primary user id */
	SIGSUBPKT_POLICY		= 26,	/* policy URL */
	SIGSUBPKT_KEY_FLAGS		= 27,	/* key flags */
	SIGSUBPKT_SIGNERS_UID		= 28,	/* signer's user id */
	SIGSUBPKT_REVOC_REASON		= 29,	/* reason for revocation */
	SIGSUBPKT_PRIV_VERIFY_CACHE	= 101,	/* cache verification result */

	SIGSUBPKT_FLAG_CRITICAL		= 128
} sigsubpkttype_t;

/*
 * signature record
 */
struct ksign_signature {
	uint32_t	have;			/* list of bits found */
#define KSIGN_HAVE_KEYID	0x01
#define KSIGN_HAVE_TIMESTAMP	0x02
	uint32_t	keyid[2];		/* 64 bit keyid */
	time_t		timestamp;		/* signature made */
	uint8_t		version;
	uint8_t		sig_class;		/* sig classification, append for MD calculation*/
	uint8_t		*hashed_data;		/* all subpackets with hashed  data (v4 only) */
	uint8_t		*unhashed_data;		/* ditto for unhashed data */
	uint8_t		digest_start[2];	/* first 2 uint8_ts of the digest */
	MPI		data[DSA_NSIG];
};

extern void ksign_free_signature(struct ksign_signature *sig);

/*
 * public key record
 */
struct ksign_public_key {
	struct list_head link;
	atomic_t	count;			/* ref count */
	time_t		timestamp;		/* key made */
	time_t		expiredate;		/* expires at this date or 0 if not at all */
	uint8_t		hdrbytes;		/* number of header bytes */
	uint8_t		version;
	int		is_valid;		/* key (especially subkey) is valid */
	unsigned long	local_id;		/* internal use, valid if > 0 */
	uint32_t	main_keyid[2];		/* keyid of the primary key */
	uint32_t	keyid[2];		/* calculated by keyid_from_pk() */
	MPI		pkey[DSA_NPKEY];
};

extern void ksign_free_public_key(struct ksign_public_key *pk);

static inline void ksign_put_public_key(struct ksign_public_key *pk)
{
	if (atomic_dec_and_test(&pk->count))
		ksign_free_public_key(pk);
}

extern int ksign_load_keyring_from_buffer(const void *buffer, size_t size);

extern struct ksign_public_key *ksign_get_public_key(const uint32_t *keyid);

/*
 * user ID record
 */
struct ksign_user_id {
	int		len;			/* length of the name */
	char		name[0];
};

extern void ksign_free_user_id(struct ksign_user_id *uid);

/*
 *
 */
typedef int (*ksign_signature_actor_t)(struct ksign_signature *, void *fnxdata);
typedef int (*ksign_public_key_actor_t)(struct ksign_public_key *, void *fnxdata);
typedef int (*ksign_user_id_actor_t)(struct ksign_user_id *, void *fnxdata);

extern int ksign_parse_packets(const uint8_t *buf,
			       size_t size,
			       ksign_signature_actor_t sigfnx,
			       ksign_public_key_actor_t pkfnx,
			       ksign_user_id_actor_t uidfnx,
			       void *data);

extern int DSA_verify(const MPI datahash, const MPI sig[], const MPI pkey[]);

/*
 * fast access to the digest
 * - we _know_ the data is locked into kernel memory, so we don't want to have
 *   to kmap() it
 */
static inline void SHA1_putc(struct shash_desc *digest, uint8_t ch)
{
	crypto_shash_update(digest, &ch, 1);
}

static inline void SHA1_write(struct shash_desc *digest, const void *s, size_t n)
{
	crypto_shash_update(digest, s, n);
}

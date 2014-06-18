/*
 * Copyright (C) 2005-2009 Red Hat, Inc. All rights reserved.
 *
 * Module Author: Heinz Mauelshagen <heinzm@redhat.com>
 *
 * This file is released under the GPL.
 *
 *
 * Linux 2.6 Device Mapper RAID4 and RAID5 target.
 *
 * Tested-by: Intel; Marcin.Labun@intel.com, krzysztof.wojcik@intel.com
 *
 *
 * Supports the following ATARAID vendor solutions (and SNIA DDF):
 *
 * 	Adaptec HostRAID ASR
 * 	SNIA DDF1
 * 	Hiphpoint 37x
 * 	Hiphpoint 45x
 *	Intel IMSM
 *	Jmicron ATARAID
 *	LSI Logic MegaRAID
 *	NVidia RAID
 *	Promise FastTrack
 *	Silicon Image Medley
 *	VIA Software RAID
 *
 * via the dmraid application.
 *
 *
 * Features:
 *
 *	o RAID4 with dedicated and selectable parity device
 *	o RAID5 with rotating parity (left+right, symmetric+asymmetric)
 *	o recovery of out of sync device for initial
 *	  RAID set creation or after dead drive replacement
 *	o run time optimization of xor algorithm used to calculate parity
 *
 *
 * Thanks to MD for:
 *    o the raid address calculation algorithm
 *    o the base of the biovec <-> page list copier.
 *
 *
 * Uses region hash to keep track of how many writes are in flight to
 * regions in order to use dirty log to keep state of regions to recover:
 *
 *    o clean regions (those which are synchronized
 * 	and don't have write io in flight)
 *    o dirty regions (those with write io in flight)
 *
 *
 * On startup, any dirty regions are migrated to the
 * 'nosync' state and are subject to recovery by the daemon.
 *
 * See raid_ctr() for table definition.
 *
 * ANALYZEME: recovery bandwidth
 */

static const char *version = "v0.2597k";

#include "dm.h"
#include "dm-memcache.h"
#include "dm-raid45.h"

#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/raid/xor.h>

#include <linux/bio.h>
#include <linux/dm-io.h>
#include <linux/dm-dirty-log.h>
#include <linux/dm-region-hash.h>


/*
 * Configurable parameters
 */

/* Minimum/maximum and default # of selectable stripes. */
#define	STRIPES_MIN		8
#define	STRIPES_MAX		16384
#define	STRIPES_DEFAULT		80

/* Maximum and default chunk size in sectors if not set in constructor. */
#define	CHUNK_SIZE_MIN		8
#define	CHUNK_SIZE_MAX		16384
#define	CHUNK_SIZE_DEFAULT	64

/* Default io size in sectors if not set in constructor. */
#define	IO_SIZE_MIN		CHUNK_SIZE_MIN
#define	IO_SIZE_DEFAULT		IO_SIZE_MIN

/* Recover io size default in sectors. */
#define	RECOVER_IO_SIZE_MIN		64
#define	RECOVER_IO_SIZE_DEFAULT		256

/* Default, minimum and maximum percentage of recover io bandwidth. */
#define	BANDWIDTH_DEFAULT	10
#define	BANDWIDTH_MIN		1
#define	BANDWIDTH_MAX		100

/* # of parallel recovered regions */
#define RECOVERY_STRIPES_MIN	1
#define RECOVERY_STRIPES_MAX	64
#define RECOVERY_STRIPES_DEFAULT	RECOVERY_STRIPES_MIN
/*
 * END Configurable parameters
 */

#define	TARGET	"dm-raid45"
#define	DAEMON	"kraid45d"
#define	DM_MSG_PREFIX	TARGET

#define	SECTORS_PER_PAGE	(PAGE_SIZE >> SECTOR_SHIFT)

/* Amount/size for __xor(). */
#define	XOR_SIZE	PAGE_SIZE

/* Ticks to run xor_speed() test for. */
#define	XOR_SPEED_TICKS	5

/* Check value in range. */
#define	range_ok(i, min, max)	(i >= min && i <= max)

/* Structure access macros. */
/* Derive raid_set from stripe_cache pointer. */
#define	RS(x)	container_of(x, struct raid_set, sc)

/* Page reference. */
#define PAGE(stripe, p)  ((stripe)->obj[p].pl->page)

/* Stripe chunk reference. */
#define CHUNK(stripe, p) ((stripe)->chunk + p)

/* Bio list reference. */
#define	BL(stripe, p, rw)	(stripe->chunk[p].bl + rw)
#define	BL_CHUNK(chunk, rw)	(chunk->bl + rw)

/* Page list reference. */
#define	PL(stripe, p)		(stripe->obj[p].pl)
/* END: structure access macros. */

/* Factor out to dm-bio-list.h */
static inline void bio_list_push(struct bio_list *bl, struct bio *bio)
{
	bio->bi_next = bl->head;
	bl->head = bio;

	if (!bl->tail)
		bl->tail = bio;
}

/* Factor out to dm.h */
#define TI_ERR_RET(str, ret) \
	do { ti->error = str; return ret; } while (0);
#define TI_ERR(str)     TI_ERR_RET(str, -EINVAL)

/* Macro to define access IO flags access inline functions. */
#define	BITOPS(name, what, var, flag) \
static inline int TestClear ## name ## what(struct var *v) \
{ return test_and_clear_bit(flag, &v->io.flags); } \
static inline int TestSet ## name ## what(struct var *v) \
{ return test_and_set_bit(flag, &v->io.flags); } \
static inline void Clear ## name ## what(struct var *v) \
{ clear_bit(flag, &v->io.flags); } \
static inline void Set ## name ## what(struct var *v) \
{ set_bit(flag, &v->io.flags); } \
static inline int name ## what(struct var *v) \
{ return test_bit(flag, &v->io.flags); }

/*-----------------------------------------------------------------
 * Stripe cache
 *
 * Cache for all reads and writes to raid sets (operational or degraded)
 *
 * We need to run all data to and from a RAID set through this cache,
 * because parity chunks need to get calculated from data chunks
 * or, in the degraded/resynchronization case, missing chunks need
 * to be reconstructed using the other chunks of the stripe.
 *---------------------------------------------------------------*/
/* Unique kmem cache name suffix # counter. */
static atomic_t _stripe_sc_nr = ATOMIC_INIT(-1); /* kmem cache # counter. */

/* A chunk within a stripe (holds bios hanging off). */
/* IO status flags for chunks of a stripe. */
enum chunk_flags {
	CHUNK_DIRTY,		/* Pages of chunk dirty; need writing. */
	CHUNK_ERROR,		/* IO error on any chunk page. */
	CHUNK_IO,		/* Allow/prohibit IO on chunk pages. */
	CHUNK_LOCKED,		/* Chunk pages locked during IO. */
	CHUNK_MUST_IO,		/* Chunk must io. */
	CHUNK_UNLOCK,		/* Enforce chunk unlock. */
	CHUNK_UPTODATE,		/* Chunk pages are uptodate. */
};

#if READ != 0 || WRITE != 1
#error dm-raid45: READ/WRITE != 0/1 used as index!!!
#endif

enum bl_type {
	WRITE_QUEUED = WRITE + 1,
	WRITE_MERGED,
	NR_BL_TYPES,	/* Must be last one! */
};
struct stripe_chunk {
	atomic_t cnt;		/* Reference count. */
	struct stripe *stripe;	/* Backpointer to stripe for endio(). */
	/* Bio lists for reads, writes, and writes merged. */
	struct bio_list bl[NR_BL_TYPES];
	struct {
		unsigned long flags; /* IO status flags. */
	} io;
};

/* Define chunk bit operations. */
BITOPS(Chunk, Dirty,	 stripe_chunk, CHUNK_DIRTY)
BITOPS(Chunk, Error,	 stripe_chunk, CHUNK_ERROR)
BITOPS(Chunk, Io,	 stripe_chunk, CHUNK_IO)
BITOPS(Chunk, Locked,	 stripe_chunk, CHUNK_LOCKED)
BITOPS(Chunk, MustIo,	 stripe_chunk, CHUNK_MUST_IO)
BITOPS(Chunk, Unlock,	 stripe_chunk, CHUNK_UNLOCK)
BITOPS(Chunk, Uptodate,	 stripe_chunk, CHUNK_UPTODATE)

/*
 * Stripe linked list indexes. Keep order, because the stripe
 * and the stripe cache rely on the first 3!
 */
enum list_types {
	LIST_FLUSH,	/* Stripes to flush for io. */
	LIST_ENDIO,	/* Stripes to endio. */
	LIST_LRU,	/* Least recently used stripes. */
	SC_NR_LISTS,	/* # of lists in stripe cache. */
	LIST_HASH = SC_NR_LISTS,	/* Hashed stripes. */
	LIST_RECOVER = LIST_HASH, /* For recovery type stripes only. */
	STRIPE_NR_LISTS,/* To size array in struct stripe. */
};

/* Adressing region recovery. */
struct recover_addr {
	struct dm_region *reg;	/* Actual region to recover. */
	sector_t pos;	/* Position within region to recover. */
	sector_t end;	/* End of region to recover. */
};

/* A stripe: the io object to handle all reads and writes to a RAID set. */
struct stripe {
	atomic_t cnt;			/* Reference count. */
	struct stripe_cache *sc;	/* Backpointer to stripe cache. */

	/*
	 * 4 linked lists:
	 *   o io list to flush io
	 *   o endio list
	 *   o LRU list to put stripes w/o reference count on
	 *   o stripe cache hash
	 */
	struct list_head lists[STRIPE_NR_LISTS];

	sector_t key;	 /* Hash key. */
	region_t region; /* Region stripe is mapped to. */

	struct {
		unsigned long flags;	/* Stripe state flags (see below). */

		/*
		 * Pending ios in flight:
		 *
		 * used to control move of stripe to endio list
		 */
		atomic_t pending;

		/* Sectors to read and write for multi page stripe sets. */
		unsigned size;
	} io;

	/* Address region recovery. */
	struct recover_addr *recover;

	/* Lock on stripe (Future: for clustering). */
	void *lock;

	struct {
		unsigned short parity;	/* Parity chunk index. */
		short recover;		/* Recovery chunk index. */
	} idx;

	/*
	 * This stripe's memory cache object (dm-mem-cache);
	 * i.e. the io chunk pages.
	 */
	struct dm_mem_cache_object *obj;

	/* Array of stripe sets (dynamically allocated). */
	struct stripe_chunk chunk[0];
};

/* States stripes can be in (flags field). */
enum stripe_states {
	STRIPE_ERROR,		/* io error on stripe. */
	STRIPE_MERGED,		/* Writes got merged to be written. */
	STRIPE_RBW,		/* Read-before-write stripe. */
	STRIPE_RECONSTRUCT,	/* Reconstruct of a missing chunk required. */
	STRIPE_RECONSTRUCTED,	/* Reconstructed of a missing chunk. */
	STRIPE_RECOVER,		/* Stripe used for RAID set recovery. */
};

/* Define stripe bit operations. */
BITOPS(Stripe, Error,	      stripe, STRIPE_ERROR)
BITOPS(Stripe, Merged,        stripe, STRIPE_MERGED)
BITOPS(Stripe, RBW,	      stripe, STRIPE_RBW)
BITOPS(Stripe, Reconstruct,   stripe, STRIPE_RECONSTRUCT)
BITOPS(Stripe, Reconstructed, stripe, STRIPE_RECONSTRUCTED)
BITOPS(Stripe, Recover,	      stripe, STRIPE_RECOVER)

/* A stripe hash. */
struct stripe_hash {
	struct list_head *hash;
	unsigned buckets;
	unsigned mask;
	unsigned prime;
	unsigned shift;
};

enum sc_lock_types {
	LOCK_ENDIO,	/* Protect endio list. */
	NR_LOCKS,       /* To size array in struct stripe_cache. */
};

/* A stripe cache. */
struct stripe_cache {
	/* Stripe hash. */
	struct stripe_hash hash;

	spinlock_t locks[NR_LOCKS];	/* Locks to protect lists. */

	/* Stripes with io to flush, stripes to endio and LRU lists. */
	struct list_head lists[SC_NR_LISTS];

	/* Slab cache to allocate stripes from. */
	struct {
		struct kmem_cache *cache;	/* Cache itself. */
		char name[32];	/* Unique name. */
	} kc;

	struct dm_io_client *dm_io_client; /* dm-io client resource context. */

	/* dm-mem-cache client resource context. */
	struct dm_mem_cache_client *mem_cache_client;

	int stripes_parm;	    /* # stripes parameter from constructor. */
	atomic_t stripes;	    /* actual # of stripes in cache. */
	atomic_t stripes_to_set;    /* # of stripes to resize cache to. */
	atomic_t stripes_last;	    /* last # of stripes in cache. */
	atomic_t active_stripes;    /* actual # of active stripes in cache. */

	/* REMOVEME: */
	atomic_t active_stripes_max; /* actual # of active stripes in cache. */
};

/* Flag specs for raid_dev */ ;
enum raid_dev_flags {
	DEV_FAILED,	/* Device failed. */
	DEV_IO_QUEUED,	/* Io got queued to device. */
};

/* The raid device in a set. */
struct raid_dev {
	struct dm_dev *dev;
	sector_t start;		/* Offset to map to. */
	struct {	/* Using struct to be able to BITOPS(). */
		unsigned long flags;	/* raid_dev_flags. */
	} io;
};

BITOPS(Dev, Failed,   raid_dev, DEV_FAILED)
BITOPS(Dev, IoQueued, raid_dev, DEV_IO_QUEUED)

/* Flags spec for raid_set. */
enum raid_set_flags {
	RS_CHECK_OVERWRITE,	/* Check for chunk overwrites. */
	RS_DEAD,		/* RAID set inoperational. */
	RS_DEAD_ENDIO_MESSAGE,	/* RAID set dead endio one-off message. */
	RS_DEGRADED,		/* Io errors on RAID device. */
	RS_DEVEL_STATS,		/* REMOVEME: display status information. */
	RS_ENFORCE_PARITY_CREATION,/* Enforce parity creation. */
	RS_PROHIBIT_WRITES,	/* Prohibit writes on device failure. */
	RS_RECOVER,		/* Do recovery. */
	RS_RECOVERY_BANDWIDTH,	/* Allow recovery bandwidth (delayed bios). */
	RS_SC_BUSY,		/* Stripe cache busy -> send an event. */
	RS_SUSPEND,		/* Suspend RAID set. */
};

/* REMOVEME: devel stats counters. */
enum stats_types {
	S_BIOS_READ,
	S_BIOS_ADDED_READ,
	S_BIOS_ENDIO_READ,
	S_BIOS_WRITE,
	S_BIOS_ADDED_WRITE,
	S_BIOS_ENDIO_WRITE,
	S_CAN_MERGE,
	S_CANT_MERGE,
	S_CONGESTED,
	S_DM_IO_READ,
	S_DM_IO_WRITE,
	S_BANDWIDTH,
	S_BARRIER,
	S_BIO_COPY_PL_NEXT,
	S_DEGRADED,
	S_DELAYED_BIOS,
	S_FLUSHS,
	S_HITS_1ST,
	S_IOS_POST,
	S_INSCACHE,
	S_MAX_LOOKUP,
	S_CHUNK_LOCKED,
	S_NO_BANDWIDTH,
	S_NOT_CONGESTED,
	S_NO_RW,
	S_NOSYNC,
	S_OVERWRITE,
	S_PROHIBITCHUNKIO,
	S_RECONSTRUCT_EI,
	S_RECONSTRUCT_DEV,
	S_RECONSTRUCT_SET,
	S_RECONSTRUCTED,
	S_REQUEUE,
	S_STRIPE_ERROR,
	S_SUM_DELAYED_BIOS,
	S_XORS,
	S_NR_STATS,	/* # of stats counters. Must be last! */
};

/* Status type -> string mappings. */
struct stats_map {
	const enum stats_types type;
	const char *str;
};

static struct stats_map stats_map[] = {
	{ S_BIOS_READ, "r=" },
	{ S_BIOS_ADDED_READ, "/" },
	{ S_BIOS_ENDIO_READ, "/" },
	{ S_BIOS_WRITE, " w=" },
	{ S_BIOS_ADDED_WRITE, "/" },
	{ S_BIOS_ENDIO_WRITE, "/" },
	{ S_DM_IO_READ, " rc=" },
	{ S_DM_IO_WRITE, " wc=" },
	{ S_BANDWIDTH, "\nbw=" },
	{ S_NO_BANDWIDTH, " no_bw=" },
	{ S_BARRIER, "\nbarrier=" },
	{ S_BIO_COPY_PL_NEXT, "\nbio_cp_next=" },
	{ S_CAN_MERGE, "\nmerge=" },
	{ S_CANT_MERGE, "/no_merge=" },
	{ S_CHUNK_LOCKED, "\nchunk_locked=" },
	{ S_CONGESTED, "\ncgst=" },
	{ S_NOT_CONGESTED, "/not_cgst=" },
	{ S_DEGRADED, "\ndegraded=" },
	{ S_DELAYED_BIOS, "\ndel_bios=" },
	{ S_SUM_DELAYED_BIOS, "/sum_del_bios=" },
	{ S_FLUSHS, "\nflushs=" },
	{ S_HITS_1ST, "\nhits_1st=" },
	{ S_IOS_POST, " ios_post=" },
	{ S_INSCACHE, " inscache=" },
	{ S_MAX_LOOKUP, " maxlookup=" },
	{ S_NO_RW, "\nno_rw=" },
	{ S_NOSYNC, " nosync=" },
	{ S_OVERWRITE, " ovr=" },
	{ S_PROHIBITCHUNKIO, " prhbt_io=" },
	{ S_RECONSTRUCT_EI, "\nrec_ei=" },
	{ S_RECONSTRUCT_DEV, " rec_dev=" },
	{ S_RECONSTRUCT_SET, " rec_set=" },
	{ S_RECONSTRUCTED, " rec=" },
	{ S_REQUEUE, " requeue=" },
	{ S_STRIPE_ERROR, " stripe_err=" },
	{ S_XORS, " xors=" },
};

/*
 * A RAID set.
 */
#define	dm_rh_client	dm_region_hash
enum count_type { IO_WORK = 0, IO_RECOVER, IO_NR_COUNT };
typedef void (*xor_function_t)(unsigned count, unsigned long **data);
struct raid_set {
	struct dm_target *ti;	/* Target pointer. */

	struct {
		unsigned long flags;	/* State flags. */
		struct mutex in_lock;	/* Protects central input list below. */
		struct mutex xor_lock;	/* Protects xor algorithm set. */
		struct bio_list in;	/* Pending ios (central input list). */
		struct bio_list work;	/* ios work set. */
		wait_queue_head_t suspendq;	/* suspend synchronization. */
		atomic_t in_process;	/* counter of queued bios (suspendq). */
		atomic_t in_process_max;/* counter of queued bios max. */

		/* io work. */
		struct workqueue_struct *wq;
		struct delayed_work dws_do_raid;	/* For main worker. */
		struct work_struct ws_do_table_event;	/* For event worker. */
	} io;

	/* Stripe locking abstraction. */
	struct dm_raid45_locking_type *locking;

	struct stripe_cache sc;	/* Stripe cache for this set. */

	/* Xor optimization. */
	struct {
		struct xor_func *f;
		unsigned chunks;
		unsigned speed;
	} xor;

	/* Recovery parameters. */
	struct recover {
		struct dm_dirty_log *dl;	/* Dirty log. */
		struct dm_rh_client *rh;	/* Region hash. */

		struct dm_io_client *dm_io_client; /* recovery dm-io client. */
		/* dm-mem-cache client resource context for recovery stripes. */
		struct dm_mem_cache_client *mem_cache_client;

		struct list_head stripes;	/* List of recovery stripes. */

		region_t nr_regions;
		region_t nr_regions_to_recover;
		region_t nr_regions_recovered;
		unsigned long start_jiffies;
		unsigned long end_jiffies;

		unsigned bandwidth;	 /* Recovery bandwidth [%]. */
		unsigned bandwidth_work; /* Recovery bandwidth [factor]. */
		unsigned bandwidth_parm; /*  " constructor parm. */
		unsigned io_size;        /* recovery io size <= region size. */
		unsigned io_size_parm;   /* recovery io size ctr parameter. */
		unsigned recovery;	 /* Recovery allowed/prohibited. */
		unsigned recovery_stripes; /* # of parallel recovery stripes. */

		/* recovery io throttling. */
		atomic_t io_count[IO_NR_COUNT];	/* counter recover/regular io.*/
		unsigned long last_jiffies;
	} recover;

	/* RAID set parameters. */
	struct {
		struct raid_type *raid_type;	/* RAID type (eg, RAID4). */
		unsigned raid_parms;	/* # variable raid parameters. */

		unsigned chunk_size;	/* Sectors per chunk. */
		unsigned chunk_size_parm;
		unsigned chunk_shift;	/* rsector chunk size shift. */

		unsigned io_size;	/* Sectors per io. */
		unsigned io_size_parm;
		unsigned io_mask;	/* Mask for bio_copy_page_list(). */
		unsigned io_inv_mask;	/* Mask for raid_address(). */

		sector_t sectors_per_dev;	/* Sectors per device. */

		atomic_t failed_devs;		/* Amount of devices failed. */

		/* Index of device to initialize. */
		int dev_to_init;
		int dev_to_init_parm;

		/* Raid devices dynamically allocated. */
		unsigned raid_devs;	/* # of RAID devices below. */
		unsigned data_devs;	/* # of RAID data devices. */

		int ei;		/* index of failed RAID device. */

		/* Index of dedicated parity device (i.e. RAID4). */
		int pi;
		int pi_parm;	/* constructor parm for status output. */
	} set;

	/* REMOVEME: devel stats counters. */
	atomic_t stats[S_NR_STATS];

	/* Dynamically allocated temporary pointers for xor(). */
	unsigned long **data;

	/* Dynamically allocated RAID devices. Alignment? */
	struct raid_dev dev[0];
};

/* Define RAID set bit operations. */
BITOPS(RS, Bandwidth, raid_set, RS_RECOVERY_BANDWIDTH)
BITOPS(RS, CheckOverwrite, raid_set, RS_CHECK_OVERWRITE)
BITOPS(RS, Dead, raid_set, RS_DEAD)
BITOPS(RS, DeadEndioMessage, raid_set, RS_DEAD_ENDIO_MESSAGE)
BITOPS(RS, Degraded, raid_set, RS_DEGRADED)
BITOPS(RS, DevelStats, raid_set, RS_DEVEL_STATS)
BITOPS(RS, EnforceParityCreation, raid_set, RS_ENFORCE_PARITY_CREATION)
BITOPS(RS, ProhibitWrites, raid_set, RS_PROHIBIT_WRITES)
BITOPS(RS, Recover, raid_set, RS_RECOVER)
BITOPS(RS, ScBusy, raid_set, RS_SC_BUSY)
BITOPS(RS, Suspend, raid_set, RS_SUSPEND)
#undef BITOPS

/*-----------------------------------------------------------------
 * Raid-4/5 set structures.
 *---------------------------------------------------------------*/
/* RAID level definitions. */
enum raid_level {
	raid4,
	raid5,
};

/* Symmetric/Asymmetric, Left/Right parity rotating algorithms. */
enum raid_algorithm {
	none,
	left_asym,
	right_asym,
	left_sym,
	right_sym,
};

struct raid_type {
	const char *name;		/* RAID algorithm. */
	const char *descr;		/* Descriptor text for logging. */
	const unsigned parity_devs;	/* # of parity devices. */
	const unsigned minimal_devs;	/* minimal # of devices in set. */
	const enum raid_level level;		/* RAID level. */
	const enum raid_algorithm algorithm;	/* RAID algorithm. */
};

/* Supported raid types and properties. */
static struct raid_type raid_types[] = {
	{"raid4",    "RAID4 (dedicated parity disk)", 1, 3, raid4, none},
	{"raid5_la", "RAID5 (left asymmetric)",       1, 3, raid5, left_asym},
	{"raid5_ra", "RAID5 (right asymmetric)",      1, 3, raid5, right_asym},
	{"raid5_ls", "RAID5 (left symmetric)",        1, 3, raid5, left_sym},
	{"raid5_rs", "RAID5 (right symmetric)",       1, 3, raid5, right_sym},
};

/* Address as calculated by raid_address(). */
struct raid_address {
	sector_t key;		/* Hash key (address of stripe % chunk_size). */
	unsigned di, pi;	/* Data and parity disks index. */
};

/* REMOVEME: reset statistics counters. */
static void stats_reset(struct raid_set *rs)
{
	unsigned s = S_NR_STATS;

	while (s--)
		atomic_set(rs->stats + s, 0);
}

/*----------------------------------------------------------------
 * RAID set management routines.
 *--------------------------------------------------------------*/
/*
 * Begin small helper functions.
 */
/* No need to be called from region hash indirectly at dm_rh_dec(). */
static void wake_dummy(void *context) {}

/* Return # of io reference. */
static int io_ref(struct raid_set *rs)
{
	return atomic_read(&rs->io.in_process);
}

/* Get an io reference. */
static void io_get(struct raid_set *rs)
{
	int p = atomic_inc_return(&rs->io.in_process);

	if (p > atomic_read(&rs->io.in_process_max))
		atomic_set(&rs->io.in_process_max, p); /* REMOVEME: max. */
}

/* Put the io reference and conditionally wake io waiters. */
static void io_put(struct raid_set *rs)
{
	/* Intel: rebuild data corrupter? */
	if (atomic_dec_and_test(&rs->io.in_process))
		wake_up(&rs->io.suspendq);
	else
		BUG_ON(io_ref(rs) < 0);
}

/* Wait until all io has been processed. */
static void wait_ios(struct raid_set *rs)
{
	wait_event(rs->io.suspendq, !io_ref(rs));
}

/* Queue (optionally delayed) io work. */
static void wake_do_raid_delayed(struct raid_set *rs, unsigned long delay)
{
	queue_delayed_work(rs->io.wq, &rs->io.dws_do_raid, delay);
}

/* Queue io work immediately (called from region hash too). */
static void wake_do_raid(void *context)
{
	struct raid_set *rs = context;

	queue_work(rs->io.wq, &rs->io.dws_do_raid.work);
}

/* Calculate device sector offset. */
static sector_t _sector(struct raid_set *rs, struct bio *bio)
{
	sector_t sector = bio->bi_sector;

	sector_div(sector, rs->set.data_devs);
	return sector;
}

/* Return # of active stripes in stripe cache. */
static int sc_active(struct stripe_cache *sc)
{
	return atomic_read(&sc->active_stripes);
}

/* Stripe cache busy indicator. */
static int sc_busy(struct raid_set *rs)
{
	return sc_active(&rs->sc) >
	       atomic_read(&rs->sc.stripes) - (STRIPES_MIN / 2);
}

/* Set chunks states. */
enum chunk_dirty_type { CLEAN, DIRTY, ERROR };
static void chunk_set(struct stripe_chunk *chunk, enum chunk_dirty_type type)
{
	switch (type) {
	case CLEAN:
		ClearChunkDirty(chunk);
		break;
	case DIRTY:
		SetChunkDirty(chunk);
		break;
	case ERROR:
		SetChunkError(chunk);
		SetStripeError(chunk->stripe);
		return;
	default:
		BUG();
	}

	SetChunkUptodate(chunk);
	SetChunkIo(chunk);
	ClearChunkError(chunk);
}

/* Return region state for a sector. */
static int region_state(struct raid_set *rs, sector_t sector,
			enum dm_rh_region_states state)
{
	struct dm_rh_client *rh = rs->recover.rh;
	region_t region = dm_rh_sector_to_region(rh, sector);

	return !!(dm_rh_get_state(rh, region, 1) & state);
}

/*
 * Return true in case a chunk should be read/written
 *
 * Conditions to read/write:
 *	o chunk not uptodate
 *	o chunk dirty
 *
 * Conditios to avoid io:
 *	o io already ongoing on chunk
 *	o io explitely prohibited
 */
static int chunk_io(struct stripe_chunk *chunk)
{
	/* 2nd run optimization (flag set below on first run). */
	if (TestClearChunkMustIo(chunk))
		return 1;

	/* Avoid io if prohibited or a locked chunk. */
	if (!ChunkIo(chunk) || ChunkLocked(chunk))
		return 0;

	if (!ChunkUptodate(chunk) || ChunkDirty(chunk)) {
		SetChunkMustIo(chunk); /* 2nd run optimization. */
		return 1;
	}

	return 0;
}

/* Call a function on each chunk needing io unless device failed. */
static unsigned for_each_io_dev(struct stripe *stripe,
			        void (*f_io)(struct stripe *stripe, unsigned p))
{
	struct raid_set *rs = RS(stripe->sc);
	unsigned p, r = 0;

	for (p = 0; p < rs->set.raid_devs; p++) {
		if (chunk_io(CHUNK(stripe, p)) && !DevFailed(rs->dev + p)) {
			f_io(stripe, p);
			r++;
		}
	}

	return r;
}

/*
 * Index of device to calculate parity on.
 *
 * Either the parity device index *or* the selected
 * device to init after a spare replacement.
 */
static int dev_for_parity(struct stripe *stripe, int *sync)
{
	struct raid_set *rs = RS(stripe->sc);
	int r = region_state(rs, stripe->key, DM_RH_NOSYNC | DM_RH_RECOVERING);

	*sync = !r;

	/* Reconstruct a particular device ?. */
	if (r && rs->set.dev_to_init > -1)
		return rs->set.dev_to_init;
	else if (rs->set.raid_type->level == raid4)
		return rs->set.pi;
	else if (!StripeRecover(stripe))
		return stripe->idx.parity;
	else
		return -1;
}

/* RAID set congested function. */
static int rs_congested(void *congested_data, int bdi_bits)
{
	int r;
	unsigned p;
	struct raid_set *rs = congested_data;

	if (sc_busy(rs) || RSSuspend(rs) || RSProhibitWrites(rs))
		r = 1;
	else for (r = 0, p = rs->set.raid_devs; !r && p--; ) {
		/* If any of our component devices are overloaded. */
		struct request_queue *q = bdev_get_queue(rs->dev[p].dev->bdev);

		r |= bdi_congested(&q->backing_dev_info, bdi_bits);
	}

	/* REMOVEME: statistics. */
	atomic_inc(rs->stats + (r ? S_CONGESTED : S_NOT_CONGESTED));
	return r;
}

/* RAID device degrade check. */
static void rs_check_degrade_dev(struct raid_set *rs,
				 struct stripe *stripe, unsigned p)
{
	if (TestSetDevFailed(rs->dev + p))
		return;

	/* Through an event in case of member device errors. */
	if ((atomic_inc_return(&rs->set.failed_devs) >
	     rs->set.raid_type->parity_devs) &&
	     !TestSetRSDead(rs)) {
		/* Display RAID set dead message once. */
		unsigned p;
		char buf[BDEVNAME_SIZE];

		DMERR("FATAL: too many devices failed -> RAID set broken");
		for (p = 0; p < rs->set.raid_devs; p++) {
			if (DevFailed(rs->dev + p))
				DMERR("device /dev/%s failed",
				      bdevname(rs->dev[p].dev->bdev, buf));
		}
	}

	/* Only log the first member error. */
	if (!TestSetRSDegraded(rs)) {
		char buf[BDEVNAME_SIZE];

		/* Store index for recovery. */
		rs->set.ei = p;
		DMERR("CRITICAL: %sio error on device /dev/%s "
		      "in region=%llu; DEGRADING RAID set\n",
		      stripe ? "" : "FAKED ",
		      bdevname(rs->dev[p].dev->bdev, buf),
		      (unsigned long long) (stripe ? stripe->key : 0));
		DMERR("further device error messages suppressed");
	}

	/* Prohibit further writes to allow for userpace to update metadata. */
	SetRSProhibitWrites(rs);
	schedule_work(&rs->io.ws_do_table_event);
}

/* RAID set degrade check. */
static void rs_check_degrade(struct stripe *stripe)
{
	struct raid_set *rs = RS(stripe->sc);
	unsigned p = rs->set.raid_devs;

	while (p--) {
		if (ChunkError(CHUNK(stripe, p)))
			rs_check_degrade_dev(rs, stripe, p);
	}
}

/* Lookup a RAID device by name or by major:minor number. */
static int raid_dev_lookup(struct raid_set *rs, struct raid_dev *dev_lookup)
{
	unsigned p;
	struct raid_dev *dev;

	/*
	 * Must be an incremental loop, because the device array
	 * can have empty slots still on calls from raid_ctr()
	 */
	for (dev = rs->dev, p = 0;
	     dev->dev && p < rs->set.raid_devs;
	     dev++, p++) {
		if (dev_lookup->dev->bdev->bd_dev == dev->dev->bdev->bd_dev)
			return p;
	}

	return -ENODEV;
}
/*
 * End small helper functions.
 */

/*
 * Stripe hash functions
 */
/* Initialize/destroy stripe hash. */
static int hash_init(struct stripe_hash *hash, unsigned stripes)
{
	unsigned buckets = roundup_pow_of_two(stripes >> 1);
	static unsigned hash_primes[] = {
		/* Table of primes for hash_fn/table size optimization. */
		1, 2, 3, 7, 13, 27, 53, 97, 193, 389, 769,
		1543, 3079, 6151, 12289, 24593, 49157, 98317,
	};

	/* Allocate stripe hash buckets. */
	hash->hash = vmalloc(buckets * sizeof(*hash->hash));
	if (!hash->hash)
		return -ENOMEM;

	hash->buckets = buckets;
	hash->mask = buckets - 1;
	hash->shift = ffs(buckets);
	if (hash->shift > ARRAY_SIZE(hash_primes))
		hash->shift = ARRAY_SIZE(hash_primes) - 1;

	BUG_ON(hash->shift < 2);
	hash->prime = hash_primes[hash->shift];

	/* Initialize buckets. */
	while (buckets--)
		INIT_LIST_HEAD(hash->hash + buckets);
	return 0;
}

static void hash_exit(struct stripe_hash *hash)
{
	if (hash->hash) {
		vfree(hash->hash);
		hash->hash = NULL;
	}
}

static unsigned hash_fn(struct stripe_hash *hash, sector_t key)
{
	return (unsigned) (((key * hash->prime) >> hash->shift) & hash->mask);
}

static struct list_head *hash_bucket(struct stripe_hash *hash, sector_t key)
{
	return hash->hash + hash_fn(hash, key);
}

/* Insert an entry into a hash. */
static void stripe_insert(struct stripe_hash *hash, struct stripe *stripe)
{
	list_add(stripe->lists + LIST_HASH, hash_bucket(hash, stripe->key));
}

/* Lookup an entry in the stripe hash. */
static struct stripe *stripe_lookup(struct stripe_cache *sc, sector_t key)
{
	unsigned look = 0;
	struct stripe *stripe;
	struct list_head *bucket = hash_bucket(&sc->hash, key);

	list_for_each_entry(stripe, bucket, lists[LIST_HASH]) {
		look++;

		if (stripe->key == key) {
			/* REMOVEME: statisics. */
			if (look > atomic_read(RS(sc)->stats + S_MAX_LOOKUP))
				atomic_set(RS(sc)->stats + S_MAX_LOOKUP, look);
			return stripe;
		}
	}

	return NULL;
}

/* Resize the stripe cache hash on size changes. */
static int sc_hash_resize(struct stripe_cache *sc)
{
	/* Resize indicated ? */
	if (atomic_read(&sc->stripes) != atomic_read(&sc->stripes_last)) {
		int r;
		struct stripe_hash hash;

		r = hash_init(&hash, atomic_read(&sc->stripes));
		if (r)
			return r;

		if (sc->hash.hash) {
			unsigned b = sc->hash.buckets;
			struct list_head *pos, *tmp;

			/* Walk old buckets and insert into new. */
			while (b--) {
				list_for_each_safe(pos, tmp, sc->hash.hash + b)
				    stripe_insert(&hash,
						  list_entry(pos, struct stripe,
							     lists[LIST_HASH]));
			}

		}

		hash_exit(&sc->hash);
		memcpy(&sc->hash, &hash, sizeof(sc->hash));
		atomic_set(&sc->stripes_last, atomic_read(&sc->stripes));
	}

	return 0;
}
/* End hash stripe hash function. */

/* List add, delete, push and pop functions. */
/* Add stripe to flush list. */
#define	DEL_LIST(lh) \
	if (!list_empty(lh)) \
		list_del_init(lh);

/* Delete stripe from hash. */
static void stripe_hash_del(struct stripe *stripe)
{
	DEL_LIST(stripe->lists + LIST_HASH);
}

/* Return stripe reference count. */
static inline int stripe_ref(struct stripe *stripe)
{
	return atomic_read(&stripe->cnt);
}

static void stripe_flush_add(struct stripe *stripe)
{
	struct stripe_cache *sc = stripe->sc;
	struct list_head *lh = stripe->lists + LIST_FLUSH;

	if (!StripeReconstruct(stripe) && list_empty(lh))
		list_add_tail(lh, sc->lists + LIST_FLUSH);
}

/*
 * Add stripe to LRU (inactive) list.
 *
 * Need lock, because of concurrent access from message interface.
 */
static void stripe_lru_add(struct stripe *stripe)
{
	if (!StripeRecover(stripe)) {
		struct list_head *lh = stripe->lists + LIST_LRU;

		if (list_empty(lh))
			list_add_tail(lh, stripe->sc->lists + LIST_LRU);
	}
}

#define POP_LIST(list) \
	do { \
		if (list_empty(sc->lists + (list))) \
			stripe = NULL; \
		else { \
			stripe = list_first_entry(sc->lists + (list), \
						  struct stripe, \
						  lists[(list)]); \
			list_del_init(stripe->lists + (list)); \
		} \
	} while (0);

/* Pop an available stripe off the LRU list. */
static struct stripe *stripe_lru_pop(struct stripe_cache *sc)
{
	struct stripe *stripe;

	POP_LIST(LIST_LRU);
	return stripe;
}

/* Pop an available stripe off the io list. */
static struct stripe *stripe_io_pop(struct stripe_cache *sc)
{
	struct stripe *stripe;

	POP_LIST(LIST_FLUSH);
	return stripe;
}

/* Push a stripe safely onto the endio list to be handled by do_endios(). */
static void stripe_endio_push(struct stripe *stripe)
{
	unsigned long flags;
	struct stripe_cache *sc = stripe->sc;
	struct list_head *stripe_list = stripe->lists + LIST_ENDIO,
			 *sc_list = sc->lists + LIST_ENDIO;
	spinlock_t *lock = sc->locks + LOCK_ENDIO;

	/* This runs in parallel with do_endios(). */
	spin_lock_irqsave(lock, flags);
	if (list_empty(stripe_list))
		list_add_tail(stripe_list, sc_list);
	spin_unlock_irqrestore(lock, flags);

	wake_do_raid(RS(sc)); /* Wake myself. */
}

/* Pop a stripe off safely off the endio list. */
static struct stripe *stripe_endio_pop(struct stripe_cache *sc)
{
	struct stripe *stripe;
	spinlock_t *lock = sc->locks + LOCK_ENDIO;

	/* This runs in parallel with endio(). */
	spin_lock_irq(lock);
	POP_LIST(LIST_ENDIO)
	spin_unlock_irq(lock);
	return stripe;
}
#undef POP_LIST

/*
 * Stripe cache locking functions
 */
/* Dummy lock function for single host RAID4+5. */
static void *no_lock(sector_t key, enum dm_lock_type type)
{
	return &no_lock;
}

/* Dummy unlock function for single host RAID4+5. */
static void no_unlock(void *lock_handle)
{
}

/* No locking (for single host RAID 4+5). */
static struct dm_raid45_locking_type locking_none = {
	.lock = no_lock,
	.unlock = no_unlock,
};

/* Lock a stripe (for clustering). */
static int
stripe_lock(struct stripe *stripe, int rw, sector_t key)
{
	stripe->lock = RS(stripe->sc)->locking->lock(key, rw == READ ? DM_RAID45_SHARED : DM_RAID45_EX);
	return stripe->lock ? 0 : -EPERM;
}

/* Unlock a stripe (for clustering). */
static void stripe_unlock(struct stripe *stripe)
{
	RS(stripe->sc)->locking->unlock(stripe->lock);
	stripe->lock = NULL;
}

/* Test io pending on stripe. */
static int stripe_io_ref(struct stripe *stripe)
{
	return atomic_read(&stripe->io.pending);
}

static void stripe_io_get(struct stripe *stripe)
{
	if (atomic_inc_return(&stripe->io.pending) == 1)
		/* REMOVEME: statistics */
		atomic_inc(&stripe->sc->active_stripes);
	else
		BUG_ON(stripe_io_ref(stripe) < 0);
}

static void stripe_io_put(struct stripe *stripe)
{
	if (atomic_dec_and_test(&stripe->io.pending)) {
		if (unlikely(StripeRecover(stripe)))
			/* Don't put recovery stripe on endio list. */
			wake_do_raid(RS(stripe->sc));
		else
			/* Add regular stripe to endio list and wake daemon. */
			stripe_endio_push(stripe);

		/* REMOVEME: statistics */
		atomic_dec(&stripe->sc->active_stripes);
	} else
		BUG_ON(stripe_io_ref(stripe) < 0);
}

/* Take stripe reference out. */
static int stripe_get(struct stripe *stripe)
{
	int r;
	struct list_head *lh = stripe->lists + LIST_LRU;

	/* Delete stripe from LRU (inactive) list if on. */
	DEL_LIST(lh);
	BUG_ON(stripe_ref(stripe) < 0);

	/* Lock stripe on first reference */
	r = (atomic_inc_return(&stripe->cnt) == 1) ?
	    stripe_lock(stripe, WRITE, stripe->key) : 0;

	return r;
}
#undef DEL_LIST

/* Return references on a chunk. */
static int chunk_ref(struct stripe_chunk *chunk)
{
	return atomic_read(&chunk->cnt);
}

/* Take out reference on a chunk. */
static int chunk_get(struct stripe_chunk *chunk)
{
	return atomic_inc_return(&chunk->cnt);
}

/* Drop reference on a chunk. */
static void chunk_put(struct stripe_chunk *chunk)
{
	BUG_ON(atomic_dec_return(&chunk->cnt) < 0);
}

/*
 * Drop reference on a stripe.
 *
 * Move it to list of LRU stripes if zero.
 */
static void stripe_put(struct stripe *stripe)
{
	if (atomic_dec_and_test(&stripe->cnt)) {
		BUG_ON(stripe_io_ref(stripe));
		stripe_unlock(stripe);
	} else
		BUG_ON(stripe_ref(stripe) < 0);
}

/* Helper needed by for_each_io_dev(). */
static void stripe_get_references(struct stripe *stripe, unsigned p)
{

	/*
	 * Another one to reference the stripe in
	 * order to protect vs. LRU list moves.
	 */
	io_get(RS(stripe->sc));	/* Global io references. */
	stripe_get(stripe);
	stripe_io_get(stripe);	/* One for each chunk io. */
}

/* Helper for endio() to put all take references. */
static void stripe_put_references(struct stripe *stripe)
{
	stripe_io_put(stripe);	/* One for each chunk io. */
	stripe_put(stripe);
	io_put(RS(stripe->sc));
}

/*
 * Stripe cache functions.
 */
/*
 * Invalidate all chunks (i.e. their pages)  of a stripe.
 *
 * I only keep state for the whole chunk.
 */
static inline void stripe_chunk_invalidate(struct stripe_chunk *chunk)
{
	chunk->io.flags = 0;
}

static void
stripe_chunks_invalidate(struct stripe *stripe)
{
	unsigned p = RS(stripe->sc)->set.raid_devs;

	while (p--)
		stripe_chunk_invalidate(CHUNK(stripe, p));
}

/* Prepare stripe for (re)use. */
static void stripe_invalidate(struct stripe *stripe)
{
	stripe->io.flags = 0;
	stripe->idx.parity = stripe->idx.recover = -1;
	stripe_chunks_invalidate(stripe);
}

/*
 * Allow io on all chunks of a stripe.
 * If not set, IO will not occur; i.e. it's prohibited.
 *
 * Actual IO submission for allowed chunks depends
 * on their !uptodate or dirty state.
 */
static void stripe_allow_io(struct stripe *stripe)
{
	unsigned p = RS(stripe->sc)->set.raid_devs;

	while (p--)
		SetChunkIo(CHUNK(stripe, p));
}

/* Initialize a stripe. */
static void stripe_init(struct stripe_cache *sc, struct stripe *stripe)
{
	unsigned i, p = RS(sc)->set.raid_devs;

	/* Work all io chunks. */
	while (p--) {
		struct stripe_chunk *chunk = CHUNK(stripe, p);

		atomic_set(&chunk->cnt, 0);
		chunk->stripe = stripe;
		i = ARRAY_SIZE(chunk->bl);
		while (i--)
			bio_list_init(chunk->bl + i);
	}

	stripe->sc = sc;

	i = ARRAY_SIZE(stripe->lists);
	while (i--)
		INIT_LIST_HEAD(stripe->lists + i);

	stripe->io.size = RS(sc)->set.io_size;
	atomic_set(&stripe->cnt, 0);
	atomic_set(&stripe->io.pending, 0);
	stripe_invalidate(stripe);
}

/* Number of pages per chunk. */
static inline unsigned chunk_pages(unsigned sectors)
{
	return dm_div_up(sectors, SECTORS_PER_PAGE);
}

/* Number of pages per stripe. */
static inline unsigned stripe_pages(struct raid_set *rs, unsigned io_size)
{
	return chunk_pages(io_size) * rs->set.raid_devs;
}

/* Initialize part of page_list (recovery). */
static void stripe_zero_pl_part(struct stripe *stripe, int p,
				unsigned start, unsigned count)
{
	unsigned o = start / SECTORS_PER_PAGE, pages = chunk_pages(count);
	/* Get offset into the page_list. */
	struct page_list *pl = pl_elem(PL(stripe, p), o);

	BUG_ON(!pl);
	while (pl && pages--) {
		BUG_ON(!pl->page);
		memset(page_address(pl->page), 0, PAGE_SIZE);
		pl = pl->next;
	}
}

/* Initialize parity chunk of stripe. */
static void stripe_zero_chunk(struct stripe *stripe, int p)
{
	if (p > -1)
		stripe_zero_pl_part(stripe, p, 0, stripe->io.size);
}

/* Return dynamic stripe structure size. */
static size_t stripe_size(struct raid_set *rs)
{
	return sizeof(struct stripe) +
		      rs->set.raid_devs * sizeof(struct stripe_chunk);
}

/* Allocate a stripe and its memory object. */
/* XXX adjust to cope with stripe cache and recovery stripe caches. */
enum grow { SC_GROW, SC_KEEP };
static struct stripe *stripe_alloc(struct stripe_cache *sc,
				   struct dm_mem_cache_client *mc,
				   enum grow grow)
{
	int r;
	struct stripe *stripe;

	stripe = kmem_cache_zalloc(sc->kc.cache, GFP_KERNEL);
	if (stripe) {
		/* Grow the dm-mem-cache by one object. */
		if (grow == SC_GROW) {
			r = dm_mem_cache_grow(mc, 1);
			if (r)
				goto err_free;
		}

		stripe->obj = dm_mem_cache_alloc(mc);
		if (IS_ERR(stripe->obj))
			goto err_shrink;

		stripe_init(sc, stripe);
	}

	return stripe;

err_shrink:
	if (grow == SC_GROW)
		dm_mem_cache_shrink(mc, 1);
err_free:
	kmem_cache_free(sc->kc.cache, stripe);
	return NULL;
}

/*
 * Free a stripes memory object, shrink the
 * memory cache and free the stripe itself.
 */
static void stripe_free(struct stripe *stripe, struct dm_mem_cache_client *mc)
{
	dm_mem_cache_free(mc, stripe->obj);
	dm_mem_cache_shrink(mc, 1);
	kmem_cache_free(stripe->sc->kc.cache, stripe);
}

/* Free the recovery stripe. */
static void stripe_recover_free(struct raid_set *rs)
{
	struct recover *rec = &rs->recover;
	struct dm_mem_cache_client *mc;

	mc = rec->mem_cache_client;
	rec->mem_cache_client = NULL;
	if (mc && !IS_ERR(mc)) {
		struct stripe *stripe;

		while (!list_empty(&rec->stripes)) {
			stripe = list_first_entry(&rec->stripes, struct stripe,
						  lists[LIST_RECOVER]);
			list_del(stripe->lists + LIST_RECOVER);
			kfree(stripe->recover);
			stripe_free(stripe, mc);
		}

		dm_mem_cache_client_destroy(mc);

		if (rec->dm_io_client && !IS_ERR(rec->dm_io_client)) {
			dm_io_client_destroy(rec->dm_io_client);
			rec->dm_io_client = NULL;
		}
	}
}

/* Grow stripe cache. */
static int sc_grow(struct stripe_cache *sc, unsigned stripes, enum grow grow)
{
	int r = 0;

	/* Try to allocate this many (additional) stripes. */
	while (stripes--) {
		struct stripe *stripe =
			stripe_alloc(sc, sc->mem_cache_client, grow);

		if (likely(stripe)) {
			stripe_lru_add(stripe);
			atomic_inc(&sc->stripes);
		} else {
			r = -ENOMEM;
			break;
		}
	}

	return r ? r : sc_hash_resize(sc);
}

/* Shrink stripe cache. */
static int sc_shrink(struct stripe_cache *sc, unsigned stripes)
{
	int r = 0;

	/* Try to get unused stripe from LRU list. */
	while (stripes--) {
		struct stripe *stripe;

		stripe = stripe_lru_pop(sc);
		if (stripe) {
			/* An LRU stripe may never have ios pending! */
			BUG_ON(stripe_io_ref(stripe));
			BUG_ON(stripe_ref(stripe));
			atomic_dec(&sc->stripes);
			/* Remove from hash if on before deletion. */
			stripe_hash_del(stripe);
			stripe_free(stripe, sc->mem_cache_client);
		} else {
			r = -ENOENT;
			break;
		}
	}

	/* Check if stats are still sane. */
	if (atomic_read(&sc->active_stripes_max) >
	    atomic_read(&sc->stripes))
		atomic_set(&sc->active_stripes_max, 0);

	if (r)
		return r;

	return atomic_read(&sc->stripes) ? sc_hash_resize(sc) : 0;
}

/* Create stripe cache and recovery. */
static int sc_init(struct raid_set *rs, unsigned stripes)
{
	unsigned i, r, rstripes;
	struct stripe_cache *sc = &rs->sc;
	struct stripe *stripe;
	struct recover *rec = &rs->recover;
	struct mapped_device *md;
	struct gendisk *disk;


	/* Initialize lists and locks. */
	i = ARRAY_SIZE(sc->lists);
	while (i--)
		INIT_LIST_HEAD(sc->lists + i);

	INIT_LIST_HEAD(&rec->stripes);

	/* Initialize endio and LRU list locks. */
	i = NR_LOCKS;
	while (i--)
		spin_lock_init(sc->locks + i);

	/* Initialize atomic variables. */
	atomic_set(&sc->stripes, 0);
	atomic_set(&sc->stripes_to_set, 0);
	atomic_set(&sc->active_stripes, 0);
	atomic_set(&sc->active_stripes_max, 0);	/* REMOVEME: statistics. */

	/*
	 * We need a runtime unique # to suffix the kmem cache name
	 * because we'll have one for each active RAID set.
	 */
	md = dm_table_get_md(rs->ti->table);
	disk = dm_disk(md);
	snprintf(sc->kc.name, sizeof(sc->kc.name), "%s-%d.%d", TARGET,
		 disk->first_minor, atomic_inc_return(&_stripe_sc_nr));
	dm_put(md);
	sc->kc.cache = kmem_cache_create(sc->kc.name, stripe_size(rs),
					 0, 0, NULL);
	if (!sc->kc.cache)
		return -ENOMEM;

	/* Create memory cache client context for RAID stripe cache. */
	sc->mem_cache_client =
		dm_mem_cache_client_create(stripes, rs->set.raid_devs,
					   chunk_pages(rs->set.io_size));
	if (IS_ERR(sc->mem_cache_client))
		return PTR_ERR(sc->mem_cache_client);

	/* Create memory cache client context for RAID recovery stripe(s). */
	rstripes = rec->recovery_stripes;
	rec->mem_cache_client =
		dm_mem_cache_client_create(rstripes, rs->set.raid_devs,
					   chunk_pages(rec->io_size));
	if (IS_ERR(rec->mem_cache_client))
		return PTR_ERR(rec->mem_cache_client);

	/* Create dm-io client context for IO stripes. */
	sc->dm_io_client = dm_io_client_create();
	if (IS_ERR(sc->dm_io_client))
		return PTR_ERR(sc->dm_io_client);

	/* FIXME: intermingeled with stripe cache initialization. */
	/* Create dm-io client context for recovery stripes. */
	rec->dm_io_client = dm_io_client_create();
	if (IS_ERR(rec->dm_io_client))
		return PTR_ERR(rec->dm_io_client);

	/* Allocate stripes for set recovery. */
	while (rstripes--) {
		stripe = stripe_alloc(sc, rec->mem_cache_client, SC_KEEP);
		if (!stripe)
			return -ENOMEM;

		stripe->recover = kzalloc(sizeof(*stripe->recover), GFP_KERNEL);
		if (!stripe->recover) {
			stripe_free(stripe, rec->mem_cache_client);
			return -ENOMEM;
		}

		SetStripeRecover(stripe);
		stripe->io.size = rec->io_size;
		list_add_tail(stripe->lists + LIST_RECOVER, &rec->stripes);
		/* Don't add recovery stripes to LRU list! */
	}

	/*
	 * Allocate the stripe objetcs from the
	 * cache and add them to the LRU list.
	 */
	r = sc_grow(sc, stripes, SC_KEEP);
	if (!r)
		atomic_set(&sc->stripes_last, stripes);

	return r;
}

/* Destroy the stripe cache. */
static void sc_exit(struct stripe_cache *sc)
{
	struct raid_set *rs = RS(sc);

	if (sc->kc.cache) {
		stripe_recover_free(rs);
		BUG_ON(sc_shrink(sc, atomic_read(&sc->stripes)));
		kmem_cache_destroy(sc->kc.cache);
		sc->kc.cache = NULL;

		if (sc->mem_cache_client && !IS_ERR(sc->mem_cache_client))
			dm_mem_cache_client_destroy(sc->mem_cache_client);

		if (sc->dm_io_client && !IS_ERR(sc->dm_io_client))
			dm_io_client_destroy(sc->dm_io_client);

		hash_exit(&sc->hash);
	}
}

/*
 * Calculate RAID address
 *
 * Delivers tuple with the index of the data disk holding the chunk
 * in the set, the parity disks index and the start of the stripe
 * within the address space of the set (used as the stripe cache hash key).
 */
/* thx MD. */
static struct raid_address *raid_address(struct raid_set *rs, sector_t sector,
					 struct raid_address *addr)
{
	sector_t stripe, tmp;

	/*
	 * chunk_number = sector / chunk_size
	 * stripe_number = chunk_number / data_devs
	 * di = stripe % data_devs;
	 */
	stripe = sector >> rs->set.chunk_shift;
	addr->di = sector_div(stripe, rs->set.data_devs);

	switch (rs->set.raid_type->level) {
	case raid4:
		addr->pi = rs->set.pi;
		goto check_shift_di;
	case raid5:
		tmp = stripe;
		addr->pi = sector_div(tmp, rs->set.raid_devs);

		switch (rs->set.raid_type->algorithm) {
		case left_asym:		/* Left asymmetric. */
			addr->pi = rs->set.data_devs - addr->pi;
		case right_asym:	/* Right asymmetric. */
check_shift_di:
			if (addr->di >= addr->pi)
				addr->di++;
			break;
		case left_sym:		/* Left symmetric. */
			addr->pi = rs->set.data_devs - addr->pi;
		case right_sym:		/* Right symmetric. */
			addr->di = (addr->pi + addr->di + 1) %
				   rs->set.raid_devs;
			break;
		case none: /* Ain't happen: RAID4 algorithm placeholder. */
			BUG();
		}
	}

	/*
	 * Start offset of the stripes chunk on any single device of the RAID
	 * set, adjusted in case io size differs from chunk size.
	 */
	addr->key = (stripe << rs->set.chunk_shift) +
		    (sector & rs->set.io_inv_mask);
	return addr;
}

/*
 * Copy data across between stripe pages and bio vectors.
 *
 * Pay attention to data alignment in stripe and bio pages.
 */
static void bio_copy_page_list(int rw, struct stripe *stripe,
			       struct page_list *pl, struct bio *bio)
{
	unsigned i, page_offset;
	void *page_addr;
	struct raid_set *rs = RS(stripe->sc);
	struct bio_vec *bv;

	/* Get start page in page list for this sector. */
	i = (bio->bi_sector & rs->set.io_mask) / SECTORS_PER_PAGE;
	pl = pl_elem(pl, i);
	BUG_ON(!pl);
	BUG_ON(!pl->page);

	page_addr = page_address(pl->page);
	page_offset = to_bytes(bio->bi_sector & (SECTORS_PER_PAGE - 1));

	/* Walk all segments and copy data across between bio_vecs and pages. */
	bio_for_each_segment(bv, bio, i) {
		int len = bv->bv_len, size;
		unsigned bio_offset = 0;
		void *bio_addr = __bio_kmap_atomic(bio, i, KM_USER0);
redo:
		size = (page_offset + len > PAGE_SIZE) ?
		       PAGE_SIZE - page_offset : len;

		if (rw == READ)
			memcpy(bio_addr + bio_offset,
			       page_addr + page_offset, size);
		else
			memcpy(page_addr + page_offset,
			       bio_addr + bio_offset, size);

		page_offset += size;
		if (page_offset == PAGE_SIZE) {
			/*
			 * We reached the end of the chunk page ->
			 * need to refer to the next one to copy more data.
			 */
			len -= size;
			if (len) {
				/* Get next page. */
				pl = pl->next;
				BUG_ON(!pl);
				BUG_ON(!pl->page);
				page_addr = page_address(pl->page);
				page_offset = 0;
				bio_offset += size;
				/* REMOVEME: statistics. */
				atomic_inc(rs->stats + S_BIO_COPY_PL_NEXT);
				goto redo;
			}
		}

		__bio_kunmap_atomic(bio_addr, KM_USER0);
	}
}

/*
 * Xor optimization macros.
 */
/* Xor data pointer declaration and initialization macros. */
#define DECLARE_2	unsigned long *d0 = data[0], *d1 = data[1]
#define DECLARE_3	DECLARE_2, *d2 = data[2]
#define DECLARE_4	DECLARE_3, *d3 = data[3]
#define DECLARE_5	DECLARE_4, *d4 = data[4]
#define DECLARE_6	DECLARE_5, *d5 = data[5]
#define DECLARE_7	DECLARE_6, *d6 = data[6]
#define DECLARE_8	DECLARE_7, *d7 = data[7]

/* Xor unrole macros. */
#define D2(n)	d0[n] = d0[n] ^ d1[n]
#define D3(n)	D2(n) ^ d2[n]
#define D4(n)	D3(n) ^ d3[n]
#define D5(n)	D4(n) ^ d4[n]
#define D6(n)	D5(n) ^ d5[n]
#define D7(n)	D6(n) ^ d6[n]
#define D8(n)	D7(n) ^ d7[n]

#define	X_2(macro, offset)	macro(offset); macro(offset + 1);
#define	X_4(macro, offset)	X_2(macro, offset); X_2(macro, offset + 2);
#define	X_8(macro, offset)	X_4(macro, offset); X_4(macro, offset + 4);
#define	X_16(macro, offset)	X_8(macro, offset); X_8(macro, offset + 8);
#define	X_32(macro, offset)	X_16(macro, offset); X_16(macro, offset + 16);
#define	X_64(macro, offset)	X_32(macro, offset); X_32(macro, offset + 32);

/* Define a _xor_#chunks_#xors_per_run() function. */
#define	_XOR(chunks, xors_per_run) \
static void _xor ## chunks ## _ ## xors_per_run(unsigned long **data) \
{ \
	unsigned end = XOR_SIZE / sizeof(data[0]), i; \
	DECLARE_ ## chunks; \
\
	for (i = 0; i < end; i += xors_per_run) { \
		X_ ## xors_per_run(D ## chunks, i); \
	} \
}

/* Define xor functions for 2 - 8 chunks and xors per run. */
#define	MAKE_XOR_PER_RUN(xors_per_run) \
	_XOR(2, xors_per_run); _XOR(3, xors_per_run); \
	_XOR(4, xors_per_run); _XOR(5, xors_per_run); \
	_XOR(6, xors_per_run); _XOR(7, xors_per_run); \
	_XOR(8, xors_per_run);

MAKE_XOR_PER_RUN(8)	/* Define _xor_*_8() functions. */
MAKE_XOR_PER_RUN(16)	/* Define _xor_*_16() functions. */
MAKE_XOR_PER_RUN(32)	/* Define _xor_*_32() functions. */
MAKE_XOR_PER_RUN(64)	/* Define _xor_*_64() functions. */

#define MAKE_XOR(xors_per_run) \
struct { \
	void (*f)(unsigned long **); \
} static xor_funcs ## xors_per_run[] = { \
	{ NULL }, /* NULL pointers to optimize indexing in xor(). */ \
	{ NULL }, \
	{ _xor2_ ## xors_per_run }, \
	{ _xor3_ ## xors_per_run }, \
	{ _xor4_ ## xors_per_run }, \
	{ _xor5_ ## xors_per_run }, \
	{ _xor6_ ## xors_per_run }, \
	{ _xor7_ ## xors_per_run }, \
	{ _xor8_ ## xors_per_run }, \
}; \
\
static void xor_ ## xors_per_run(unsigned n, unsigned long **data) \
{ \
	/* Call respective function for amount of chunks. */ \
	xor_funcs ## xors_per_run[n].f(data); \
}

/* Define xor_8() - xor_64 functions. */
MAKE_XOR(8)
MAKE_XOR(16)
MAKE_XOR(32)
MAKE_XOR(64)
/*
 * END xor optimization macros.
 */

/* Maximum number of chunks, which can be xor'ed in one go. */
#define	XOR_CHUNKS_MAX	(ARRAY_SIZE(xor_funcs8) - 1)

/* xor_blocks wrapper to allow for using that crypto library function. */
static void xor_blocks_wrapper(unsigned n, unsigned long **data)
{
	BUG_ON(n < 2 || n > MAX_XOR_BLOCKS + 1);
	xor_blocks(n - 1, XOR_SIZE, (void *) data[0], (void **) data + 1);
}

struct xor_func {
	xor_function_t f;
	const char *name;
} static xor_funcs[] = {
	{ xor_64,  "xor_64" },
	{ xor_32,  "xor_32" },
	{ xor_16,  "xor_16" },
	{ xor_8,   "xor_8"  },
	{ xor_blocks_wrapper, "xor_blocks" },
};

/*
 * Check, if chunk has to be xored in/out:
 *
 * o if writes are queued
 * o if writes are merged
 * o if stripe is to be reconstructed
 * o if recovery stripe
 */
static inline int chunk_must_xor(struct stripe_chunk *chunk)
{
	if (ChunkUptodate(chunk)) {
		BUG_ON(!bio_list_empty(BL_CHUNK(chunk, WRITE_QUEUED)) &&
		       !bio_list_empty(BL_CHUNK(chunk, WRITE_MERGED)));

		if (!bio_list_empty(BL_CHUNK(chunk, WRITE_QUEUED)) ||
		    !bio_list_empty(BL_CHUNK(chunk, WRITE_MERGED)))
			return 1;

		if (StripeReconstruct(chunk->stripe) ||
		    StripeRecover(chunk->stripe))
			return 1;
	}

	return 0;
}

/*
 * Calculate crc.
 *
 * This indexes into the chunks of a stripe and their pages.
 *
 * All chunks will be xored into the indexed (@pi)
 * chunk in maximum groups of xor.chunks.
 *
 */
static void xor(struct stripe *stripe, unsigned pi, unsigned sector)
{
	struct raid_set *rs = RS(stripe->sc);
	unsigned max_chunks = rs->xor.chunks, n = 1,
		 o = sector / SECTORS_PER_PAGE, /* Offset into the page_list. */
		 p = rs->set.raid_devs;
	unsigned long **d = rs->data;
	xor_function_t xor_f = rs->xor.f->f;

	BUG_ON(sector > stripe->io.size);

	/* Address of parity page to xor into. */
	d[0] = page_address(pl_elem(PL(stripe, pi), o)->page);

	while (p--) {
		/* Preset pointers to data pages. */
		if (p != pi && chunk_must_xor(CHUNK(stripe, p)))
			d[n++] = page_address(pl_elem(PL(stripe, p), o)->page);

		/* If max chunks -> xor. */
		if (n == max_chunks) {
			mutex_lock(&rs->io.xor_lock);
			xor_f(n, d);
			mutex_unlock(&rs->io.xor_lock);
			n = 1;
		}
	}

	/* If chunks -> xor. */
	if (n > 1) {
		mutex_lock(&rs->io.xor_lock);
		xor_f(n, d);
		mutex_unlock(&rs->io.xor_lock);
	}
}

/* Common xor loop through all stripe page lists. */
static void common_xor(struct stripe *stripe, sector_t count,
		       unsigned off, unsigned pi)
{
	unsigned sector;

	BUG_ON(!count);
	for (sector = off; sector < count; sector += SECTORS_PER_PAGE)
		xor(stripe, pi, sector);

	/* Set parity page uptodate and clean. */
	chunk_set(CHUNK(stripe, pi), CLEAN);
	atomic_inc(RS(stripe->sc)->stats + S_XORS); /* REMOVEME: statistics. */
}

/*
 * Calculate parity sectors on intact stripes.
 *
 * Need to calculate raid address for recover stripe, because its
 * chunk sizes differs and is typically larger than io chunk size.
 */
static void parity_xor(struct stripe *stripe)
{
	struct raid_set *rs = RS(stripe->sc);
	int size_differs = stripe->io.size != rs->set.io_size;
	unsigned chunk_size = rs->set.chunk_size, io_size = stripe->io.size,
		 xor_size = chunk_size > io_size ? io_size : chunk_size;
	sector_t off;

	/* This can be the recover stripe with a larger io size. */
	for (off = 0; off < io_size; off += xor_size) {
		/*
		 * Recover stripe is likely bigger than regular io
		 * ones and has no precalculated parity disk index ->
		 * need to calculate RAID address.
		 */
		if (unlikely(size_differs)) {
			struct raid_address addr;

			raid_address(rs, (stripe->key + off) *
					 rs->set.data_devs, &addr);
			stripe->idx.parity = addr.pi;
			stripe_zero_pl_part(stripe, addr.pi, off, xor_size);
		}

		common_xor(stripe, xor_size, off, stripe->idx.parity);
		chunk_set(CHUNK(stripe, stripe->idx.parity), DIRTY);
	}
}

/* Reconstruct missing chunk. */
static void stripe_reconstruct(struct stripe *stripe)
{
	struct raid_set *rs = RS(stripe->sc);
	int p = rs->set.raid_devs, pr = stripe->idx.recover;

	BUG_ON(pr < 0);

	/* Check if all but the chunk to be reconstructed are uptodate. */
	while (p--)
		BUG_ON(p != pr && !ChunkUptodate(CHUNK(stripe, p)));

	/* REMOVEME: statistics. */
	atomic_inc(rs->stats + (RSDegraded(rs) ? S_RECONSTRUCT_EI :
						 S_RECONSTRUCT_DEV));
	/* Zero chunk to be reconstructed. */
	stripe_zero_chunk(stripe, pr);
	common_xor(stripe, stripe->io.size, 0, pr);
}

/*
 * Recovery io throttling
 */
/* Conditionally reset io counters. */
static int recover_io_reset(struct raid_set *rs)
{
	unsigned long j = jiffies;

	/* Pay attention to jiffies overflows. */
	if (j > rs->recover.last_jiffies + HZ ||
	    j < rs->recover.last_jiffies) {
		atomic_set(rs->recover.io_count + IO_WORK, 0);
		atomic_set(rs->recover.io_count + IO_RECOVER, 0);
		rs->recover.last_jiffies = j;
		return 1;
	}

	return 0;
}

/* Count ios. */
static void recover_io_count(struct stripe *stripe)
{
	struct raid_set *rs = RS(stripe->sc);

	atomic_inc(rs->recover.io_count +
		   (StripeRecover(stripe) ? IO_RECOVER : IO_WORK));
}

/* Try getting a stripe either from the hash or from the LRU list. */
static struct stripe *stripe_find(struct raid_set *rs,
				  struct raid_address *addr)
{
	int r;
	struct stripe_cache *sc = &rs->sc;
	struct stripe *stripe;

	/* Try stripe from hash. */
	stripe = stripe_lookup(sc, addr->key);
	if (stripe) {
		r = stripe_get(stripe);
		if (r)
			goto get_lock_failed;

		atomic_inc(rs->stats + S_HITS_1ST); /* REMOVEME: statistics. */
	} else {
		/* Not in hash -> try to get an LRU stripe. */
		stripe = stripe_lru_pop(sc);
		if (stripe) {
			/*
			 * An LRU stripe may not be referenced
			 * and may never have ios pending!
			 */
			BUG_ON(stripe_ref(stripe));
			BUG_ON(stripe_io_ref(stripe));

			/* Remove from hash if on before reuse. */
			stripe_hash_del(stripe);

			/* Invalidate before reinserting with changed key. */
			stripe_invalidate(stripe);

			stripe->key = addr->key;
			stripe->region = dm_rh_sector_to_region(rs->recover.rh,
								addr->key);
			stripe->idx.parity = addr->pi;
			r = stripe_get(stripe);
			if (r)
				goto get_lock_failed;

			/* Insert stripe into the stripe hash. */
			stripe_insert(&sc->hash, stripe);
			/* REMOVEME: statistics. */
			atomic_inc(rs->stats + S_INSCACHE);
		}
	}

	return stripe;

get_lock_failed:
	stripe_put(stripe);
	return NULL;
}

/*
 * Process end io
 *
 * I need to do it here because I can't in interrupt
 */
/* End io all bios on a bio list. */
static void bio_list_endio(struct stripe *stripe, struct bio_list *bl,
			   int p, int error)
{
	struct raid_set *rs = RS(stripe->sc);
	struct bio *bio;
	struct page_list *pl = PL(stripe, p);
	struct stripe_chunk *chunk = CHUNK(stripe, p);

	/* Update region counters. */
	while ((bio = bio_list_pop(bl))) {
		if (bio_data_dir(bio) == WRITE)
			/* Drop io pending count for any writes. */
			dm_rh_dec(rs->recover.rh, stripe->region);
		else if (!error)
			/* Copy data accross. */
			bio_copy_page_list(READ, stripe, pl, bio);

		bio_endio(bio, error);

		/* REMOVEME: statistics. */
		atomic_inc(rs->stats + (bio_data_dir(bio) == READ ?
			   S_BIOS_ENDIO_READ : S_BIOS_ENDIO_WRITE));

		chunk_put(chunk);
		stripe_put(stripe);
		io_put(rs);	/* Wake any suspend waiters on last bio. */
	}
}

/*
 * End io all reads/writes on a stripe copying
 * read data accross from stripe to bios and
 * decrementing region counters for writes.
 *
 * Processing of ios depeding on state:
 * o no chunk error -> endio ok
 * o degraded:
 *   - chunk error and read -> ignore to be requeued
 *   - chunk error and write -> endio ok
 * o dead (more than parity_devs failed) and chunk_error-> endio failed
 */
static void stripe_endio(int rw, struct stripe *stripe)
{
	struct raid_set *rs = RS(stripe->sc);
	unsigned p = rs->set.raid_devs;
	int write = (rw != READ);

	while (p--) {
		struct stripe_chunk *chunk = CHUNK(stripe, p);
		struct bio_list *bl;

		BUG_ON(ChunkLocked(chunk));

		bl = BL_CHUNK(chunk, rw);
		if (bio_list_empty(bl))
			continue;

		if (unlikely(ChunkError(chunk) || !ChunkUptodate(chunk))) {
			/* RAID set dead. */
			if (unlikely(RSDead(rs)))
				bio_list_endio(stripe, bl, p, -EIO);
			/* RAID set degraded. */
			else if (write)
				bio_list_endio(stripe, bl, p, 0);
		} else {
			BUG_ON(!RSDegraded(rs) && ChunkDirty(chunk));
			bio_list_endio(stripe, bl, p, 0);
		}
	}
}

/* Fail all ios hanging off all bio lists of a stripe. */
static void stripe_fail_io(struct stripe *stripe)
{
	struct raid_set *rs = RS(stripe->sc);
	unsigned p = rs->set.raid_devs;

	while (p--) {
		struct stripe_chunk *chunk = CHUNK(stripe, p);
		int i = ARRAY_SIZE(chunk->bl);

		/* Fail all bios on all bio lists of the stripe. */
		while (i--) {
			struct bio_list *bl = chunk->bl + i;

			if (!bio_list_empty(bl))
				bio_list_endio(stripe, bl, p, -EIO);
		}
	}

	/* Put stripe on LRU list. */
	BUG_ON(stripe_io_ref(stripe));
	BUG_ON(stripe_ref(stripe));
}

/* Unlock all required chunks. */
static void stripe_chunks_unlock(struct stripe *stripe)
{
	unsigned p = RS(stripe->sc)->set.raid_devs;
	struct stripe_chunk *chunk;

	while (p--) {
		chunk = CHUNK(stripe, p);

		if (TestClearChunkUnlock(chunk))
			ClearChunkLocked(chunk);
	}
}

/*
 * Queue reads and writes to a stripe by hanging
 * their bios off the stripesets read/write lists.
 */
static int stripe_queue_bio(struct raid_set *rs, struct bio *bio,
			    struct bio_list *reject)
{
	struct raid_address addr;
	struct stripe *stripe;

	stripe = stripe_find(rs, raid_address(rs, bio->bi_sector, &addr));
	if (stripe) {
		int r = 0, rw = bio_data_dir(bio);

		/* Distinguish reads and writes. */
		bio_list_add(BL(stripe, addr.di, rw), bio);

		if (rw == READ)
			/* REMOVEME: statistics. */
			atomic_inc(rs->stats + S_BIOS_ADDED_READ);
		else {
			/* Inrement pending write count on region. */
			dm_rh_inc(rs->recover.rh, stripe->region);
			r = 1;

			/* REMOVEME: statistics. */
			atomic_inc(rs->stats + S_BIOS_ADDED_WRITE);
		}

		/*
		 * Put on io (flush) list in case of
		 * initial bio queued to chunk.
		 */
		if (chunk_get(CHUNK(stripe, addr.di)) == 1)
			stripe_flush_add(stripe);

		return r;
	}

	/* Got no stripe from cache or failed to lock it -> reject bio. */
	bio_list_add(reject, bio);
	atomic_inc(rs->stats + S_IOS_POST); /* REMOVEME: statistics. */
	return 0;
}

/*
 * Handle all stripes by handing them to the daemon, because we can't
 * map their chunk pages to copy the data in interrupt context.
 *
 * We don't want to handle them here either, while interrupts are disabled.
 */

/* Read/write endio function for dm-io (interrupt context). */
static void endio(unsigned long error, void *context)
{
	struct stripe_chunk *chunk = context;

	if (unlikely(error)) {
		chunk_set(chunk, ERROR);
		/* REMOVEME: statistics. */
		atomic_inc(RS(chunk->stripe->sc)->stats + S_STRIPE_ERROR);
	} else
		chunk_set(chunk, CLEAN);

	/*
	 * For recovery stripes, I need to reset locked locked
	 * here, because those aren't processed in do_endios().
	 */
	if (unlikely(StripeRecover(chunk->stripe)))
		ClearChunkLocked(chunk);
	else
		SetChunkUnlock(chunk);

	/* Indirectly puts stripe on cache's endio list via stripe_io_put(). */
	stripe_put_references(chunk->stripe);
}

/* Read/Write a chunk asynchronously. */
static void stripe_chunk_rw(struct stripe *stripe, unsigned p)
{
	struct stripe_cache *sc = stripe->sc;
	struct raid_set *rs = RS(sc);
	struct dm_mem_cache_object *obj = stripe->obj + p;
	struct page_list *pl = obj->pl;
	struct stripe_chunk *chunk = CHUNK(stripe, p);
	struct raid_dev *dev = rs->dev + p;
	struct dm_io_region io = {
		.bdev = dev->dev->bdev,
		.sector = stripe->key,
		.count = stripe->io.size,
	};
	struct dm_io_request control = {
		.bi_rw = ChunkDirty(chunk) ? WRITE : READ,
		.mem = {
			.type = DM_IO_PAGE_LIST,
			.ptr.pl = pl,
			.offset = 0,
		},
		.notify = {
			.fn = endio,
			.context = chunk,
		},
		.client = StripeRecover(stripe) ? rs->recover.dm_io_client :
						  sc->dm_io_client,
	};

	BUG_ON(ChunkLocked(chunk));
	BUG_ON(!ChunkUptodate(chunk) && ChunkDirty(chunk));
	BUG_ON(ChunkUptodate(chunk) && !ChunkDirty(chunk));

	/*
	 * Don't rw past end of device, which can happen, because
	 * typically sectors_per_dev isn't divisible by io_size.
	 */
	if (unlikely(io.sector + io.count > rs->set.sectors_per_dev))
		io.count = rs->set.sectors_per_dev - io.sector;

	BUG_ON(!io.count);
	io.sector += dev->start;	/* Add <offset>. */
	if (RSRecover(rs))
		recover_io_count(stripe);	/* Recovery io accounting. */

	/* REMOVEME: statistics. */
	atomic_inc(rs->stats + (ChunkDirty(chunk) ? S_DM_IO_WRITE :
						    S_DM_IO_READ));
	SetChunkLocked(chunk);
	SetDevIoQueued(dev);
	BUG_ON(dm_io(&control, 1, &io, NULL));
}

/*
 * Write dirty or read not uptodate page lists of a stripe.
 */
static int stripe_chunks_rw(struct stripe *stripe)
{
	int r;
	struct raid_set *rs = RS(stripe->sc);

	/*
	 * Increment the pending count on the stripe
	 * first, so that we don't race in endio().
	 *
	 * An inc (IO) is needed for any chunk unless !ChunkIo(chunk):
	 *
	 * o not uptodate
	 * o dirtied by writes merged
	 * o dirtied by parity calculations
	 */
	r = for_each_io_dev(stripe, stripe_get_references);
	if (r) {
		/* Io needed: chunks are either not uptodate or dirty. */
		int max;	/* REMOVEME: */
		struct stripe_cache *sc = &rs->sc;

		/* Submit actual io. */
		for_each_io_dev(stripe, stripe_chunk_rw);

		/* REMOVEME: statistics */
		max = sc_active(sc);
		if (atomic_read(&sc->active_stripes_max) < max)
			atomic_set(&sc->active_stripes_max, max);

		atomic_inc(rs->stats + S_FLUSHS);
		/* END REMOVEME: statistics */
	}

	return r;
}

/* Merge in all writes hence dirtying respective chunks. */
static void stripe_merge_writes(struct stripe *stripe)
{
	unsigned p = RS(stripe->sc)->set.raid_devs;

	while (p--) {
		struct stripe_chunk *chunk = CHUNK(stripe, p);
		struct bio_list *write = BL_CHUNK(chunk, WRITE_QUEUED);

		if (!bio_list_empty(write)) {
			struct bio *bio;
			struct page_list *pl = stripe->obj[p].pl;

			/*
			 * We can play with the lists without holding a lock,
			 * because it is just us accessing them anyway.
			 */
			bio_list_for_each(bio, write)
				bio_copy_page_list(WRITE, stripe, pl, bio);

			bio_list_merge(BL_CHUNK(chunk, WRITE_MERGED), write);
			bio_list_init(write);
			chunk_set(chunk, DIRTY);
		}
	}
}

/* Queue all writes to get merged. */
static int stripe_queue_writes(struct stripe *stripe)
{
	int r = 0;
	unsigned p = RS(stripe->sc)->set.raid_devs;

	while (p--) {
		struct stripe_chunk *chunk = CHUNK(stripe, p);
		struct bio_list *write = BL_CHUNK(chunk, WRITE);

		if (!bio_list_empty(write)) {
			bio_list_merge(BL_CHUNK(chunk, WRITE_QUEUED), write);
			bio_list_init(write);
SetChunkIo(chunk);
			r = 1;
		}
	}

	return r;
}


/* Check, if a chunk gets completely overwritten. */
static int stripe_check_chunk_overwrite(struct stripe *stripe, unsigned p)
{
	unsigned sectors = 0;
	struct bio *bio;
	struct bio_list *bl = BL(stripe, p, WRITE_QUEUED);

	bio_list_for_each(bio, bl)
		sectors += bio_sectors(bio);

	BUG_ON(sectors > RS(stripe->sc)->set.io_size);
	return sectors == RS(stripe->sc)->set.io_size;
}

/*
 * Avoid io on broken/reconstructed drive in order to
 * reconstruct date on endio.
 *
 * (*1*) We set StripeReconstruct() in here, so that _do_endios()
 *	 will trigger a reconstruct call before resetting it.
 */
static int stripe_chunk_set_io_flags(struct stripe *stripe, int pr)
{
	struct stripe_chunk *chunk = CHUNK(stripe, pr);

	/*
	 * Allow io on all chunks but the indexed one,
	 * because we're either degraded or prohibit it
	 * on the one for later reconstruction.
	 */
	/* Includes ClearChunkIo(), ClearChunkUptodate(). */
	stripe_chunk_invalidate(chunk);
	stripe->idx.recover = pr;
	SetStripeReconstruct(stripe);

	/* REMOVEME: statistics. */
	atomic_inc(RS(stripe->sc)->stats + S_PROHIBITCHUNKIO);
	return -EPERM;
}

/* Chunk locked/uptodate and device failed tests. */
static struct stripe_chunk *
stripe_chunk_check(struct stripe *stripe, unsigned p, unsigned *chunks_uptodate)
{
	struct raid_set *rs = RS(stripe->sc);
	struct stripe_chunk *chunk = CHUNK(stripe, p);

	/* Can't access active chunks. */
	if (ChunkLocked(chunk)) {
		/* REMOVEME: statistics. */
		atomic_inc(rs->stats + S_CHUNK_LOCKED);
		return NULL;
	}

	/* Can't access broken devive. */
	if (ChunkError(chunk) || DevFailed(rs->dev + p))
		return NULL;

	/* Can access uptodate chunks. */
	if (ChunkUptodate(chunk)) {
		(*chunks_uptodate)++;
		return NULL;
	}

	return chunk;
}

/*
 * Degraded/reconstruction mode.
 *
 * Check stripe state to figure which chunks don't need IO.
 *
 * Returns 0 for fully operational, -EPERM for degraded/resynchronizing.
 */
static int stripe_check_reconstruct(struct stripe *stripe)
{
	struct raid_set *rs = RS(stripe->sc);

	if (RSDead(rs)) {
		ClearStripeReconstruct(stripe);
		ClearStripeReconstructed(stripe);
		stripe_allow_io(stripe);
		return 0;
	}

	/* Avoid further reconstruction setting, when already set. */
	if (StripeReconstruct(stripe)) {
		/* REMOVEME: statistics. */
		atomic_inc(rs->stats + S_RECONSTRUCT_SET);
		return -EBUSY;
	}

	/* Initially allow io on all chunks. */
	stripe_allow_io(stripe);

	/* Return if stripe is already reconstructed. */
	if (StripeReconstructed(stripe)) {
		atomic_inc(rs->stats + S_RECONSTRUCTED);
		return 0;
	}

	/*
	 * Degraded/reconstruction mode (device failed) ->
	 * avoid io on the failed device.
	 */
	if (unlikely(RSDegraded(rs))) {
		/* REMOVEME: statistics. */
		atomic_inc(rs->stats + S_DEGRADED);
		/* Allow IO on all devices but the dead one. */
		BUG_ON(rs->set.ei < 0);
		return stripe_chunk_set_io_flags(stripe, rs->set.ei);
	} else {
		int sync, pi = dev_for_parity(stripe, &sync);

		/*
		 * Reconstruction mode (ie. a particular (replaced) device or
		 * some (rotating) parity chunk is being resynchronized) ->
		 *   o make sure all needed chunks are read in
		 *   o cope with 3/4 disk array special case where it
		 *     doesn't make a difference to read in parity
		 *     to xor data in/out
		 */
		if (RSEnforceParityCreation(rs) || !sync) {
			/* REMOVEME: statistics. */
			atomic_inc(rs->stats + S_NOSYNC);
			/* Allow IO on all devs but the one to reconstruct. */
			return stripe_chunk_set_io_flags(stripe, pi);
		}
	}

	return 0;
}

/*
 * Check, if stripe is ready to merge writes.
 * I.e. if all chunks present to allow to merge bios.
 *
 * We prohibit io on:
 *
 * o chunks without bios
 * o chunks which get completely written over
 */
static int stripe_merge_possible(struct stripe *stripe, int nosync)
{
	struct raid_set *rs = RS(stripe->sc);
	unsigned chunks_overwrite = 0, chunks_prohibited = 0,
		 chunks_uptodate = 0, p = rs->set.raid_devs;

	/* Walk all chunks. */
	while (p--) {
		struct stripe_chunk *chunk;

		/* Prohibit io on broken devices. */
		if (DevFailed(rs->dev + p)) {
			chunk = CHUNK(stripe, p);
			goto prohibit_io;
		}

		/* We can't optimize any further if no chunk. */
		chunk = stripe_chunk_check(stripe, p, &chunks_uptodate);
		if (!chunk || nosync)
			continue;

		/*
		 * We have a chunk, which is not uptodate.
		 *
		 * If this is not parity and we don't have
		 * reads queued, we can optimize further.
		 */
		if (p != stripe->idx.parity &&
		    bio_list_empty(BL_CHUNK(chunk, READ)) &&
		    bio_list_empty(BL_CHUNK(chunk, WRITE_MERGED))) {
			if (bio_list_empty(BL_CHUNK(chunk, WRITE_QUEUED)))
				goto prohibit_io;
			else if (RSCheckOverwrite(rs) &&
				 stripe_check_chunk_overwrite(stripe, p))
				/* Completely overwritten chunk. */
				chunks_overwrite++;
		}

		/* Allow io for chunks with bios and overwritten ones. */
		SetChunkIo(chunk);
		continue;

prohibit_io:
		/* No io for broken devices or for chunks w/o bios. */
		ClearChunkIo(chunk);
		chunks_prohibited++;
		/* REMOVEME: statistics. */
		atomic_inc(RS(stripe->sc)->stats + S_PROHIBITCHUNKIO);
	}

	/* All data chunks will get written over. */
	if (chunks_overwrite == rs->set.data_devs)
		atomic_inc(rs->stats + S_OVERWRITE); /* REMOVEME: statistics.*/
	else if (chunks_uptodate + chunks_prohibited < rs->set.raid_devs) {
		/* We don't have enough chunks to merge. */
		atomic_inc(rs->stats + S_CANT_MERGE); /* REMOVEME: statistics.*/
		return -EPERM;
	}

	/*
	 * If we have all chunks up to date or overwrite them, we
	 * just zero the parity chunk and let stripe_rw() recreate it.
	 */
	if (chunks_uptodate == rs->set.raid_devs ||
	    chunks_overwrite == rs->set.data_devs) {
		stripe_zero_chunk(stripe, stripe->idx.parity);
		BUG_ON(StripeReconstruct(stripe));
		SetStripeReconstruct(stripe);	/* Enforce xor in caller. */
	} else {
		/*
		 * With less chunks, we xor parity out.
		 *
		 * (*4*) We rely on !StripeReconstruct() in chunk_must_xor(),
		 *	 so that only chunks with queued or merged writes
		 *	 are being xored.
		 */
		parity_xor(stripe);
	}

	/*
	 * We do have enough chunks to merge.
	 * All chunks are uptodate or get written over.
	 */
	atomic_inc(rs->stats + S_CAN_MERGE); /* REMOVEME: statistics. */
	return 0;
}

/*
 * Avoid reading chunks in case we're fully operational.
 *
 * We prohibit io on any chunks without bios but the parity chunk.
 */
static void stripe_avoid_reads(struct stripe *stripe)
{
	struct raid_set *rs = RS(stripe->sc);
	unsigned dummy = 0, p = rs->set.raid_devs;

	/* Walk all chunks. */
	while (p--) {
		struct stripe_chunk *chunk =
			stripe_chunk_check(stripe, p, &dummy);

		if (!chunk)
			continue;

		/* If parity or any bios pending -> allow io. */
		if (chunk_ref(chunk) || p == stripe->idx.parity)
			SetChunkIo(chunk);
		else {
			ClearChunkIo(chunk);
			/* REMOVEME: statistics. */
			atomic_inc(RS(stripe->sc)->stats + S_PROHIBITCHUNKIO);
		}
	}
}

/*
 * Read/write a stripe.
 *
 * All stripe read/write activity goes through this function
 * unless recovery, which has to call stripe_chunk_rw() directly.
 *
 * Make sure we don't try already merged stripes in order
 * to avoid data corruption.
 *
 * Check the state of the RAID set and if degraded (or
 * resynchronizing for reads), read in all other chunks but
 * the one on the dead/resynchronizing device in order to be
 * able to reconstruct the missing one in _do_endios().
 *
 * Can be called on active stripes in order
 * to dispatch new io on inactive chunks.
 *
 * States to cover:
 *   o stripe to read and/or write
 *   o stripe with error to reconstruct
 */
static int stripe_rw(struct stripe *stripe)
{
	int nosync, r;
	struct raid_set *rs = RS(stripe->sc);

	/*
 	 * Check, if a chunk needs to be reconstructed
 	 * because of a degraded set or a region out of sync.
 	 */
	nosync = stripe_check_reconstruct(stripe);
	switch (nosync) {
	case -EBUSY:
		return 0; /* Wait for stripe reconstruction to finish. */
	case -EPERM:
		goto io;
	}

	/*
	 * If we don't have merged writes pending, we can schedule
	 * queued writes to be merged next without corrupting data.
	 */
	if (!StripeMerged(stripe)) {
		r = stripe_queue_writes(stripe);
		if (r)
			/* Writes got queued -> flag RBW. */
			SetStripeRBW(stripe);
	}

	/*
	 * Merge all writes hanging off uptodate/overwritten
	 * chunks of the stripe.
	 */
	if (StripeRBW(stripe)) {
		r = stripe_merge_possible(stripe, nosync);
		if (!r) { /* Merge possible. */
			struct stripe_chunk *chunk;

			/*
			 * I rely on valid parity in order
			 * to xor a fraction of chunks out
			 * of parity and back in.
			 */
			stripe_merge_writes(stripe);	/* Merge writes in. */
			parity_xor(stripe);		/* Update parity. */
			ClearStripeReconstruct(stripe);	/* Reset xor enforce. */
			SetStripeMerged(stripe);	/* Writes merged. */
			ClearStripeRBW(stripe);		/* Disable RBW. */

			/*
			 * REMOVEME: sanity check on parity chunk
			 * 	     states after writes got merged.
			 */
			chunk = CHUNK(stripe, stripe->idx.parity);
			BUG_ON(ChunkLocked(chunk));
			BUG_ON(!ChunkUptodate(chunk));
			BUG_ON(!ChunkDirty(chunk));
			BUG_ON(!ChunkIo(chunk));
		}
	} else if (!nosync && !StripeMerged(stripe))
		/* Read avoidance if not degraded/resynchronizing/merged. */
		stripe_avoid_reads(stripe);

io:
	/* Now submit any reads/writes for non-uptodate or dirty chunks. */
	r = stripe_chunks_rw(stripe);
	if (!r) {
		/*
		 * No io submitted because of chunk io
		 * prohibited or locked chunks/failed devices
		 * -> push to end io list for processing.
		 */
		stripe_endio_push(stripe);
		atomic_inc(rs->stats + S_NO_RW); /* REMOVEME: statistics. */
	}

	return r;
}

/*
 * Recovery functions
 */
/* Read a stripe off a raid set for recovery. */
static int stripe_recover_read(struct stripe *stripe, int pi)
{
	BUG_ON(stripe_io_ref(stripe));

	/* Invalidate all chunks so that they get read in. */
	stripe_chunks_invalidate(stripe);
	stripe_allow_io(stripe); /* Allow io on all recovery chunks. */

	/*
	 * If we are reconstructing a perticular device, we can avoid
	 * reading the respective chunk in, because we're going to
	 * reconstruct it anyway.
	 *
	 * We can't do that for resynchronization of rotating parity,
	 * because the recovery stripe chunk size is typically larger
	 * than the sets chunk size.
	 */
	if (pi > -1)
		ClearChunkIo(CHUNK(stripe, pi));

	return stripe_chunks_rw(stripe);
}

/* Write a stripe to a raid set for recovery. */
static int stripe_recover_write(struct stripe *stripe, int pi)
{
	BUG_ON(stripe_io_ref(stripe));

	/*
	 * If this is a reconstruct of a particular device, then
	 * reconstruct the respective chunk, else create parity chunk.
	 */
	if (pi > -1) {
		stripe_zero_chunk(stripe, pi);
		common_xor(stripe, stripe->io.size, 0, pi);
		chunk_set(CHUNK(stripe, pi), DIRTY);
	} else
		parity_xor(stripe);

	return stripe_chunks_rw(stripe);
}

/* Read/write a recovery stripe. */
static int stripe_recover_rw(struct stripe *stripe)
{
	int r = 0, sync = 0;

	/* Read/write flip-flop. */
	if (TestClearStripeRBW(stripe)) {
		SetStripeMerged(stripe);
		stripe->key = stripe->recover->pos;
		r = stripe_recover_read(stripe, dev_for_parity(stripe, &sync));
		BUG_ON(!r);
	} else if (TestClearStripeMerged(stripe)) {
		r = stripe_recover_write(stripe, dev_for_parity(stripe, &sync));
		BUG_ON(!r);
	}

	BUG_ON(sync);
	return r;
}

/* Recover bandwidth available ?. */
static int recover_bandwidth(struct raid_set *rs)
{
	int r, work;

	/* On reset or when bios delayed -> allow recovery. */
	r = recover_io_reset(rs);
	if (r || RSBandwidth(rs))
		goto out;

	work = atomic_read(rs->recover.io_count + IO_WORK);
	if (work) {
		/* Pay attention to larger recover stripe size. */
		int recover = atomic_read(rs->recover.io_count + IO_RECOVER) *
					  rs->recover.io_size / rs->set.io_size;

		/*
		 * Don't use more than given bandwidth
		 * of the work io for recovery.
		 */
		if (recover > work / rs->recover.bandwidth_work) {
			/* REMOVEME: statistics. */
			atomic_inc(rs->stats + S_NO_BANDWIDTH);
			return 0;
		}
	}

out:
	atomic_inc(rs->stats + S_BANDWIDTH);	/* REMOVEME: statistics. */
	return 1;
}

/* Try to get a region to recover. */
static int stripe_recover_get_region(struct stripe *stripe)
{
	struct raid_set *rs = RS(stripe->sc);
	struct recover *rec = &rs->recover;
	struct recover_addr *addr = stripe->recover;
	struct dm_dirty_log *dl = rec->dl;
	struct dm_rh_client *rh = rec->rh;

	BUG_ON(!dl);
	BUG_ON(!rh);

	/* Return, that we have region first to finish it during suspension. */
	if (addr->reg)
		return 1;

	if (RSSuspend(rs))
		return -EPERM;

	if (dl->type->get_sync_count(dl) >= rec->nr_regions)
		return -ENOENT;

	/* If we don't have enough bandwidth, we don't proceed recovering. */
	if (!recover_bandwidth(rs))
		return -EAGAIN;

	/* Start quiescing a region. */
	dm_rh_recovery_prepare(rh);
	addr->reg = dm_rh_recovery_start(rh);
	if (!addr->reg)
		return -EAGAIN;

	addr->pos = dm_rh_region_to_sector(rh, dm_rh_get_region_key(addr->reg));
	addr->end = addr->pos + dm_rh_get_region_size(rh);

	/*
	 * Take one global io reference out for the
	 * whole region, which is going to be released
	 * when the region is completely done with.
	 */
	io_get(rs);
	return 0;
}

/* Update region hash state. */
enum recover_type { REC_FAILURE = 0, REC_SUCCESS = 1 };
static void recover_rh_update(struct stripe *stripe, enum recover_type success)
{
	struct recover_addr *addr = stripe->recover;
	struct raid_set *rs = RS(stripe->sc);
	struct recover *rec = &rs->recover;

	if (!addr->reg) {
		DMERR("%s- Called w/o region", __func__);
		return;
	}

	dm_rh_recovery_end(addr->reg, success);
	if (success)
		rec->nr_regions_recovered++;

	addr->reg = NULL;

	/*
	 * Completely done with this region ->
	 * release the 1st io reference.
	 */
	io_put(rs);
}

/* Set start of recovery state. */
static void set_start_recovery(struct raid_set *rs)
{
	/* Initialize recovery. */
	rs->recover.start_jiffies = jiffies;
	rs->recover.end_jiffies = 0;
}

/* Set end of recovery state. */
static void set_end_recovery(struct raid_set *rs)
{
	ClearRSRecover(rs);
/* Achtung: nicht mehr zurück setzten -> 'i' belibt in status output und userpace könnte sich darauf verlassen, das es verschiwndet!!!! */
	rs->set.dev_to_init = -1;

	/* Check for jiffies overrun. */
	rs->recover.end_jiffies = jiffies;
	if (rs->recover.end_jiffies < rs->recover.start_jiffies)
		rs->recover.end_jiffies = ~0;
}

/* Handle recovery on one recovery stripe. */
static int _do_recovery(struct stripe *stripe)
{
	int r;
	struct raid_set *rs = RS(stripe->sc);
	struct recover_addr *addr = stripe->recover;

	/* If recovery is active -> return. */
	if (stripe_io_ref(stripe))
		return 1;

	/* IO error is fatal for recovery -> stop it. */
	if (unlikely(StripeError(stripe)))
		goto err;

	/* Recovery end required. */
	if (unlikely(RSDegraded(rs)))
		goto err;

	/* Get a region to recover. */
	r = stripe_recover_get_region(stripe);
	switch (r) {
	case 0:	/* Got a new region: flag initial read before write. */
		SetStripeRBW(stripe);
	case 1:	/* Have a region in the works. */
		break;
	case -EAGAIN:
		/* No bandwidth/quiesced region yet, try later. */
		if (!io_ref(rs))
			wake_do_raid_delayed(rs, HZ / 4);
	case -EPERM:
		/* Suspend. */
		return 1;
	case -ENOENT:	/* No more regions to recover. */
		schedule_work(&rs->io.ws_do_table_event);
		return 0;
	default:
		BUG();
	}

	/* Read/write a recover stripe. */
	r = stripe_recover_rw(stripe);
	if (r)
		/* IO initiated. */
		return 1;

	/* Read and write finished-> update recovery position within region. */
	addr->pos += stripe->io.size;

	/* If we're at end of region, update region hash. */
	if (addr->pos >= addr->end ||
	    addr->pos >= rs->set.sectors_per_dev)
		recover_rh_update(stripe, REC_SUCCESS);
	else
		/* Prepare to read next region segment. */
		SetStripeRBW(stripe);

	/* Schedule myself for another round... */
	wake_do_raid(rs);
	return 1;

err:
	/* FIXME: rather try recovering other regions on error? */
	rs_check_degrade(stripe);
	recover_rh_update(stripe, REC_FAILURE);

	/* Check state of partially recovered array. */
	if (RSDegraded(rs) && !RSDead(rs) &&
	    rs->set.dev_to_init != -1 &&
	    rs->set.ei != rs->set.dev_to_init) {
		/* Broken drive != drive to recover -> FATAL. */
		SetRSDead(rs);
		DMERR("FATAL: failed device != device to initialize -> "
		      "RAID set broken");
	}

	if (StripeError(stripe) || RSDegraded(rs)) {
		char buf[BDEVNAME_SIZE];

		DMERR("stopping recovery due to "
		      "ERROR on /dev/%s, stripe at offset %llu",
		      bdevname(rs->dev[rs->set.ei].dev->bdev, buf),
		      (unsigned long long) stripe->key);

	}

	/* Make sure, that all quiesced regions get released. */
	while (addr->reg) {
		dm_rh_recovery_end(addr->reg, -EIO);
		addr->reg = dm_rh_recovery_start(rs->recover.rh);
	}

	return 0;
}

/* Called by main io daemon to recover regions. */
static int do_recovery(struct raid_set *rs)
{
	if (RSRecover(rs)) {
		int r = 0;
		struct stripe *stripe;

		list_for_each_entry(stripe, &rs->recover.stripes,
				    lists[LIST_RECOVER])
			r += _do_recovery(stripe);

		if (r)
			return r;

		set_end_recovery(rs);
		stripe_recover_free(rs);
	}

	return 0;
}

/*
 * END recovery functions
 */

/* End io process all stripes handed in by endio() callback. */
static void _do_endios(struct raid_set *rs, struct stripe *stripe,
		       struct list_head *flush_list)
{
	/* First unlock all required chunks. */
	stripe_chunks_unlock(stripe);

	/*
	 * If an io error on a stripe occured, degrade the RAID set
	 * and try to endio as many bios as possible. If any bios can't
	 * be endio processed, requeue the stripe (stripe_ref() != 0).
	 */
	if (TestClearStripeError(stripe)) {
		/*
		 * FIXME: if read, rewrite the failed chunk after reconstruction
		 *        in order to trigger disk bad sector relocation.
		 */
		rs_check_degrade(stripe); /* Resets ChunkError(). */
		ClearStripeReconstruct(stripe);
		ClearStripeReconstructed(stripe);

		/*
 		 * FIXME: if write, don't endio writes in flight and don't
 		 *	  allow for new writes until userspace has updated
 		 *	  its metadata.
 		 */
	}

	/* Got to reconstruct a missing chunk. */
	if (StripeReconstruct(stripe)) {
		/*
		 * (*2*) We use StripeReconstruct() to allow for
		 *	 all chunks to be xored into the reconstructed
		 *	 one (see chunk_must_xor()).
		 */
		stripe_reconstruct(stripe);

		/*
		 * (*3*) Now we reset StripeReconstruct() and flag
		 * 	 StripeReconstructed() to show to stripe_rw(),
		 * 	 that we have reconstructed a missing chunk.
		 */
		ClearStripeReconstruct(stripe);
		SetStripeReconstructed(stripe);

		/* FIXME: reschedule to be written in case of read. */
		/* if (!RSDead && RSDegraded(rs) !StripeRBW(stripe)) {
			chunk_set(CHUNK(stripe, stripe->idx.recover), DIRTY);
			stripe_chunks_rw(stripe);
		} */

		stripe->idx.recover = -1;
	}

	/*
	 * Now that we eventually got a complete stripe, we
	 * can process the rest of the end ios on reads.
	 */
	stripe_endio(READ, stripe);

	/* End io all merged writes if not prohibited. */
	if (!RSProhibitWrites(rs) && StripeMerged(stripe)) {
		ClearStripeMerged(stripe);
		stripe_endio(WRITE_MERGED, stripe);
	}

	/* If RAID set is dead -> fail any ios to dead drives. */
	if (RSDead(rs)) {
		if (!TestSetRSDeadEndioMessage(rs))
			DMERR("RAID set dead: failing ios to dead devices");

		stripe_fail_io(stripe);
	}

	/*
	 * We have stripe references still,
	 * beacuse of read before writes or IO errors ->
	 * got to put on flush list for processing.
	 */
	if (stripe_ref(stripe)) {
		BUG_ON(!list_empty(stripe->lists + LIST_LRU));
		list_add_tail(stripe->lists + LIST_FLUSH, flush_list);
		atomic_inc(rs->stats + S_REQUEUE); /* REMOVEME: statistics. */
	} else
		stripe_lru_add(stripe);
}

/* Pop any endio stripes off of the endio list and belabour them. */
static void do_endios(struct raid_set *rs)
{
	struct stripe_cache *sc = &rs->sc;
	struct stripe *stripe;
	/* IO flush list for sorted requeued stripes. */
	struct list_head flush_list;

	INIT_LIST_HEAD(&flush_list);

	while ((stripe = stripe_endio_pop(sc))) {
		/* Avoid endio on stripes with newly io'ed chunks. */
		if (!stripe_io_ref(stripe))
			_do_endios(rs, stripe, &flush_list);
	}

	/*
	 * Insert any requeued stripes in the proper
	 * order at the beginning of the io (flush) list.
	 */
	list_splice(&flush_list, sc->lists + LIST_FLUSH);
}

/* Flush any stripes on the io list. */
static int do_flush(struct raid_set *rs)
{
	int r = 0;
	struct stripe *stripe;

	while ((stripe = stripe_io_pop(&rs->sc)))
		r += stripe_rw(stripe); /* Read/write stripe. */

	return r;
}

/* Stripe cache resizing. */
static void do_sc_resize(struct raid_set *rs)
{
	unsigned set = atomic_read(&rs->sc.stripes_to_set);

	if (set) {
		unsigned cur = atomic_read(&rs->sc.stripes);
		int r = (set > cur) ? sc_grow(&rs->sc, set - cur, SC_GROW) :
				      sc_shrink(&rs->sc, cur - set);

		/* Flag end of resizeing if ok. */
		if (!r)
			atomic_set(&rs->sc.stripes_to_set, 0);
	}
}

/*
 * Process all ios
 *
 * We do different things with the io depending
 * on the state of the region that it is in:
 *
 * o reads: hang off stripe cache or postpone if full
 *
 * o writes:
 *
 *  CLEAN/DIRTY/NOSYNC:	increment pending and hang io off stripe's stripe set.
 *			In case stripe cache is full or busy, postpone the io.
 *
 *  RECOVERING:		delay the io until recovery of the region completes.
 *
 */
static void do_ios(struct raid_set *rs, struct bio_list *ios)
{
	int r;
	unsigned flush = 0, delay = 0;
	sector_t sector;
	struct dm_rh_client *rh = rs->recover.rh;
	struct bio *bio;
	struct bio_list reject;

	bio_list_init(&reject);

	/*
	 * Classify each io:
	 *    o delay writes to recovering regions (let reads go through)
	 *    o queue io to all other regions
	 */
	while ((bio = bio_list_pop(ios))) {
		/*
		 * In case we get a barrier bio, push it back onto
		 * the input queue unless all work queues are empty
		 * and the stripe cache is inactive.
		 */
		if (unlikely(bio_empty_barrier(bio))) {
			/* REMOVEME: statistics. */
			atomic_inc(rs->stats + S_BARRIER);
			if (delay ||
			    !list_empty(rs->sc.lists + LIST_FLUSH) ||
			    !bio_list_empty(&reject) ||
			    sc_active(&rs->sc)) {
				bio_list_push(ios, bio);
				break;
			}
		}

		/* If writes prohibited because of failures -> postpone. */
		if (RSProhibitWrites(rs) && bio_data_dir(bio) == WRITE) {
			bio_list_add(&reject, bio);
			continue;
		}

		/* Check for recovering regions. */
		sector = _sector(rs, bio);
		r = region_state(rs, sector, DM_RH_RECOVERING);
		if (unlikely(r)) {
			delay++;
			/* Wait writing to recovering regions. */
			dm_rh_delay_by_region(rh, bio,
					      dm_rh_sector_to_region(rh,
								     sector));
			/* REMOVEME: statistics.*/
			atomic_inc(rs->stats + S_DELAYED_BIOS);
			atomic_inc(rs->stats + S_SUM_DELAYED_BIOS);

			/* Force bandwidth tests in recovery. */
			SetRSBandwidth(rs);
		} else {
			/*
			 * Process ios to non-recovering regions by queueing
			 * them to stripes (does dm_rh_inc()) for writes).
			 */
			flush += stripe_queue_bio(rs, bio, &reject);
		}
	}

	if (flush) {
		/* FIXME: better error handling. */
		r = dm_rh_flush(rh); /* Writes got queued -> flush dirty log. */
		if (r)
			DMERR_LIMIT("dirty log flush");
	}

	/* Merge any rejected bios back to the head of the input list. */
	bio_list_merge_head(ios, &reject);
}

/* Unplug: let any queued io role on the sets devices. */
static void do_unplug(struct raid_set *rs)
{
	struct raid_dev *dev = rs->dev + rs->set.raid_devs;

	while (dev-- > rs->dev) {
		/* Only call any device unplug function, if io got queued. */
		if (TestClearDevIoQueued(dev))
			blk_unplug(bdev_get_queue(dev->dev->bdev));
	}
}

/* Send an event in case we're getting too busy. */
static void do_busy_event(struct raid_set *rs)
{
	if (sc_busy(rs)) {
		if (!TestSetRSScBusy(rs))
			schedule_work(&rs->io.ws_do_table_event);
	} else
		ClearRSScBusy(rs);
}

/* Throw an event. */
static void do_table_event(struct work_struct *ws)
{
	struct raid_set *rs = container_of(ws, struct raid_set,
					   io.ws_do_table_event);
	dm_table_event(rs->ti->table);
}


/*-----------------------------------------------------------------
 * RAID daemon
 *---------------------------------------------------------------*/
/*
 * o belabour all end ios
 * o update the region hash states
 * o optionally shrink the stripe cache
 * o optionally do recovery
 * o unplug any component raid devices with queued bios
 * o grab the input queue
 * o work an all requeued or new ios and perform stripe cache flushs
 * o unplug any component raid devices with queued bios
 * o check, if the stripe cache gets too busy and throw an event if so
 */
static void do_raid(struct work_struct *ws)
{
	int r;
	struct raid_set *rs = container_of(ws, struct raid_set,
					   io.dws_do_raid.work);
	struct bio_list *ios = &rs->io.work, *ios_in = &rs->io.in;

	/*
	 * We always need to end io, so that ios can get errored in
	 * case the set failed and the region counters get decremented
	 * before we update region hash states and go any further.
	 */
	do_endios(rs);
	dm_rh_update_states(rs->recover.rh, 1);

	/*
	 * Now that we've end io'd, which may have put stripes on the LRU list
	 * to allow for shrinking, we resize the stripe cache if requested.
	 */
	do_sc_resize(rs);

	/* Try to recover regions. */
	r = do_recovery(rs);
	if (r)
		do_unplug(rs);	/* Unplug the sets device queues. */

	/* Quickly grab all new ios queued and add them to the work list. */
	mutex_lock(&rs->io.in_lock);
	bio_list_merge(ios, ios_in);
	bio_list_init(ios_in);
	mutex_unlock(&rs->io.in_lock);

	if (!bio_list_empty(ios))
		do_ios(rs, ios); /* Got ios to work into the cache. */

	r = do_flush(rs);		/* Flush any stripes on io list. */
	if (r)
		do_unplug(rs);		/* Unplug the sets device queues. */

	do_busy_event(rs);	/* Check if we got too busy. */
}

/*
 * Callback for region hash to dispatch
 * delayed bios queued to recovered regions
 * (gets called via dm_rh_update_states()).
 */
static void dispatch_delayed_bios(void *context, struct bio_list *bl)
{
	struct raid_set *rs = context;
	struct bio *bio;

	/* REMOVEME: statistics; decrement pending delayed bios counter. */
	bio_list_for_each(bio, bl)
		atomic_dec(rs->stats + S_DELAYED_BIOS);

	/* Merge region hash private list to work list. */
	bio_list_merge_head(&rs->io.work, bl);
	bio_list_init(bl);
	ClearRSBandwidth(rs);
}

/*************************************************************
 * Constructor helpers
 *************************************************************/
/* Calculate MB/sec. */
static unsigned mbpers(struct raid_set *rs, unsigned io_size)
{
	return to_bytes((rs->xor.speed * rs->set.data_devs *
			 io_size * HZ / XOR_SPEED_TICKS) >> 10) >> 10;
}

/*
 * Discover fastest xor algorithm and # of chunks combination.
 */
/* Calculate speed of particular algorithm and # of chunks. */
static unsigned xor_speed(struct stripe *stripe)
{
	int ticks = XOR_SPEED_TICKS;
	unsigned p = RS(stripe->sc)->set.raid_devs, r = 0;
	unsigned long j;

	/* Set uptodate so that common_xor()->xor() will belabour chunks. */
	while (p--)
		SetChunkUptodate(CHUNK(stripe, p));

	/* Wait for next tick. */
	for (j = jiffies; j == jiffies; );

	/* Do xors for a few ticks. */
	while (ticks--) {
		unsigned xors = 0;

		for (j = jiffies; j == jiffies; ) {
			mb();
			common_xor(stripe, stripe->io.size, 0, 0);
			mb();
			xors++;
			mb();
		}

		if (xors > r)
			r = xors;
	}

	return r;
}

/* Define for xor multi recovery stripe optimization runs. */
#define DMRAID45_XOR_TEST

/* Optimize xor algorithm for this RAID set. */
static unsigned xor_optimize(struct raid_set *rs)
{
	unsigned chunks_max = 2, speed_max = 0;
	struct xor_func *f = ARRAY_END(xor_funcs), *f_max = NULL;
	struct stripe *stripe;
	unsigned io_size, speed_hm = 0, speed_min = ~0, speed_xor_blocks = 0;

	BUG_ON(list_empty(&rs->recover.stripes));
#ifndef DMRAID45_XOR_TEST
	stripe = list_first_entry(&rs->recover.stripes, struct stripe,
				  lists[LIST_RECOVER]);
#endif

	/* Try all xor functions. */
	while (f-- > xor_funcs) {
		unsigned speed;

#ifdef DMRAID45_XOR_TEST
		list_for_each_entry(stripe, &rs->recover.stripes,
				    lists[LIST_RECOVER]) {
			io_size = stripe->io.size;
#endif

			/* Set actual xor function for common_xor(). */
			rs->xor.f = f;
			rs->xor.chunks = (f->f == xor_blocks_wrapper ?
					  (MAX_XOR_BLOCKS + 1) :
					  XOR_CHUNKS_MAX);
			if (rs->xor.chunks > rs->set.raid_devs)
				rs->xor.chunks = rs->set.raid_devs;

			for ( ; rs->xor.chunks > 1; rs->xor.chunks--) {
				speed = xor_speed(stripe);

#ifdef DMRAID45_XOR_TEST
				if (f->f == xor_blocks_wrapper) {
					if (speed > speed_xor_blocks)
						speed_xor_blocks = speed;
				} else if (speed > speed_hm)
					speed_hm = speed;

				if (speed < speed_min)
					speed_min = speed;
#endif

				if (speed > speed_max) {
					speed_max = speed;
					chunks_max = rs->xor.chunks;
					f_max = f;
				}
			}
#ifdef DMRAID45_XOR_TEST
		}
#endif
	}

	/* Memorize optimal parameters. */
	rs->xor.f = f_max;
	rs->xor.chunks = chunks_max;
#ifdef DMRAID45_XOR_TEST
	DMINFO("%s stripes=%u/size=%u min=%u xor_blocks=%u hm=%u max=%u",
	       speed_max == speed_hm ? "HM" : "NB",
	       rs->recover.recovery_stripes, io_size, speed_min,
	       speed_xor_blocks, speed_hm, speed_max);
#endif
	return speed_max;
}

/*
 * Allocate a RAID context (a RAID set)
 */
/* Structure for variable RAID parameters. */
struct variable_parms {
	int bandwidth;
	int bandwidth_parm;
	int chunk_size;
	int chunk_size_parm;
	int io_size;
	int io_size_parm;
	int stripes;
	int stripes_parm;
	int recover_io_size;
	int recover_io_size_parm;
	int raid_parms;
	int recovery;
	int recovery_stripes;
	int recovery_stripes_parm;
};

static struct raid_set *
context_alloc(struct raid_type *raid_type, struct variable_parms *p,
	      unsigned raid_devs, sector_t sectors_per_dev,
	      struct dm_target *ti, unsigned dl_parms, char **argv)
{
	int r;
	size_t len;
	sector_t region_size, ti_len;
	struct raid_set *rs = NULL;
	struct dm_dirty_log *dl;
	struct recover *rec;

	/*
	 * Create the dirty log
	 *
	 * We need to change length for the dirty log constructor,
	 * because we want an amount of regions for all stripes derived
	 * from the single device size, so that we can keep region
	 * size = 2^^n independant of the number of devices
	 */
	ti_len = ti->len;
	ti->len = sectors_per_dev;
	dl = dm_dirty_log_create(argv[0], ti, NULL, dl_parms, argv + 2);
	ti->len = ti_len;
	if (!dl)
		goto bad_dirty_log;

	/* Chunk size *must* be smaller than region size. */
	region_size = dl->type->get_region_size(dl);
	if (p->chunk_size > region_size)
		goto bad_chunk_size;

	/* Recover io size *must* be smaller than region size as well. */
	if (p->recover_io_size > region_size)
		goto bad_recover_io_size;

	/* Size and allocate the RAID set structure. */
	len = sizeof(*rs->data) + sizeof(*rs->dev);
	if (dm_array_too_big(sizeof(*rs), len, raid_devs))
		goto bad_array;

	len = sizeof(*rs) + raid_devs * len;
	rs = kzalloc(len, GFP_KERNEL);
	if (!rs)
		goto bad_alloc;

	rec = &rs->recover;
	atomic_set(&rs->io.in_process, 0);
	atomic_set(&rs->io.in_process_max, 0);
	rec->io_size = p->recover_io_size;

	/* Pointer to data array. */
	rs->data = (unsigned long **)
		   ((void *) rs->dev + raid_devs * sizeof(*rs->dev));
	rec->dl = dl;
	rs->set.raid_devs = raid_devs;
	rs->set.data_devs = raid_devs - raid_type->parity_devs;
	rs->set.raid_type = raid_type;

	rs->set.raid_parms = p->raid_parms;
	rs->set.chunk_size_parm = p->chunk_size_parm;
	rs->set.io_size_parm = p->io_size_parm;
	rs->sc.stripes_parm = p->stripes_parm;
	rec->io_size_parm = p->recover_io_size_parm;
	rec->bandwidth_parm = p->bandwidth_parm;
	rec->recovery = p->recovery;
	rec->recovery_stripes = p->recovery_stripes;

	/*
	 * Set chunk and io size and respective shifts
	 * (used to avoid divisions)
	 */
	rs->set.chunk_size = p->chunk_size;
	rs->set.chunk_shift = ffs(p->chunk_size) - 1;

	rs->set.io_size = p->io_size;
	rs->set.io_mask = p->io_size - 1;
	/* Mask to adjust address key in case io_size != chunk_size. */
	rs->set.io_inv_mask = (p->chunk_size - 1) & ~rs->set.io_mask;

	rs->set.sectors_per_dev = sectors_per_dev;

	rs->set.ei = -1;	/* Indicate no failed device. */
	atomic_set(&rs->set.failed_devs, 0);

	rs->ti = ti;

	atomic_set(rec->io_count + IO_WORK, 0);
	atomic_set(rec->io_count + IO_RECOVER, 0);

	/* Initialize io lock and queues. */
	mutex_init(&rs->io.in_lock);
	mutex_init(&rs->io.xor_lock);
	bio_list_init(&rs->io.in);
	bio_list_init(&rs->io.work);

	init_waitqueue_head(&rs->io.suspendq);	/* Suspend waiters (dm-io). */

	rec->nr_regions = dm_sector_div_up(sectors_per_dev, region_size);
	rec->rh = dm_region_hash_create(rs, dispatch_delayed_bios,
			wake_dummy, wake_do_raid, 0, p->recovery_stripes,
			dl, region_size, rec->nr_regions);
	if (IS_ERR(rec->rh))
		goto bad_rh;

	/* Initialize stripe cache. */
	r = sc_init(rs, p->stripes);
	if (r)
		goto bad_sc;

	/* REMOVEME: statistics. */
	stats_reset(rs);
	ClearRSDevelStats(rs);	/* Disnable development status. */
	return rs;

bad_dirty_log:
	TI_ERR_RET("Error creating dirty log", ERR_PTR(-ENOMEM));

bad_chunk_size:
	dm_dirty_log_destroy(dl);
	TI_ERR_RET("Chunk size larger than region size", ERR_PTR(-EINVAL));

bad_recover_io_size:
	dm_dirty_log_destroy(dl);
	TI_ERR_RET("Recover stripe io size larger than region size",
			ERR_PTR(-EINVAL));

bad_array:
	dm_dirty_log_destroy(dl);
	TI_ERR_RET("Arry too big", ERR_PTR(-EINVAL));

bad_alloc:
	dm_dirty_log_destroy(dl);
	TI_ERR_RET("Cannot allocate raid context", ERR_PTR(-ENOMEM));

bad_rh:
	dm_dirty_log_destroy(dl);
	ti->error = DM_MSG_PREFIX "Error creating dirty region hash";
	goto free_rs;

bad_sc:
	dm_region_hash_destroy(rec->rh); /* Destroys dirty log too. */
	sc_exit(&rs->sc);
	ti->error = DM_MSG_PREFIX "Error creating stripe cache";
free_rs:
	kfree(rs);
	return ERR_PTR(-ENOMEM);
}

/* Free a RAID context (a RAID set). */
static void context_free(struct raid_set *rs, unsigned p)
{
	while (p--)
		dm_put_device(rs->ti, rs->dev[p].dev);

	sc_exit(&rs->sc);
	dm_region_hash_destroy(rs->recover.rh); /* Destroys dirty log too. */
	kfree(rs);
}

/* Create work queue and initialize delayed work. */
static int rs_workqueue_init(struct raid_set *rs)
{
	struct dm_target *ti = rs->ti;

	rs->io.wq = create_singlethread_workqueue(DAEMON);
	if (!rs->io.wq)
		TI_ERR_RET("failed to create " DAEMON, -ENOMEM);

	INIT_DELAYED_WORK(&rs->io.dws_do_raid, do_raid);
	INIT_WORK(&rs->io.ws_do_table_event, do_table_event);
	return 0;
}

/* Return pointer to raid_type structure for raid name. */
static struct raid_type *get_raid_type(char *name)
{
	struct raid_type *r = ARRAY_END(raid_types);

	while (r-- > raid_types) {
		if (!strcmp(r->name, name))
			return r;
	}

	return NULL;
}

/* FIXME: factor out to dm core. */
static int multiple(sector_t a, sector_t b, sector_t *n)
{
	sector_t r = a;

	sector_div(r, b);
	*n = r;
	return a == r * b;
}

/* Log RAID set information to kernel log. */
static void rs_log(struct raid_set *rs, unsigned io_size)
{
	unsigned p;
	char buf[BDEVNAME_SIZE];

	for (p = 0; p < rs->set.raid_devs; p++)
		DMINFO("/dev/%s is raid disk %u%s",
				bdevname(rs->dev[p].dev->bdev, buf), p,
				(p == rs->set.pi) ? " (parity)" : "");

	DMINFO("%d/%d/%d sectors chunk/io/recovery size, %u stripes\n"
	       "algorithm \"%s\", %u chunks with %uMB/s\n"
	       "%s set with net %u/%u devices",
	       rs->set.chunk_size, rs->set.io_size, rs->recover.io_size,
	       atomic_read(&rs->sc.stripes),
	       rs->xor.f->name, rs->xor.chunks, mbpers(rs, io_size),
	       rs->set.raid_type->descr, rs->set.data_devs, rs->set.raid_devs);
}

/* Get all devices and offsets. */
static int dev_parms(struct raid_set *rs, char **argv, int *p)
{
	struct dm_target *ti = rs->ti;

DMINFO("rs->set.sectors_per_dev=%llu", (unsigned long long) rs->set.sectors_per_dev);
	for (*p = 0; *p < rs->set.raid_devs; (*p)++, argv += 2) {
		int r;
		unsigned long long tmp;
		struct raid_dev *dev = rs->dev + *p;

		/* Get offset and device. */
		if (sscanf(argv[1], "%llu", &tmp) != 1 ||
		    tmp > rs->set.sectors_per_dev)
			TI_ERR("Invalid RAID device offset parameter");

		dev->start = tmp;
		r = dm_get_device(ti, argv[0],
				  dm_table_get_mode(ti->table), &dev->dev);
		if (r)
			TI_ERR_RET("RAID device lookup failure", r);

		r = raid_dev_lookup(rs, dev);
		if (r != -ENODEV && r < *p) {
			(*p)++;	/* Ensure dm_put_device() on actual device. */
			TI_ERR_RET("Duplicate RAID device", -ENXIO);
		}
	}

	return 0;
}

/* Set recovery bandwidth. */
static void
recover_set_bandwidth(struct raid_set *rs, unsigned bandwidth)
{
	rs->recover.bandwidth = bandwidth;
	rs->recover.bandwidth_work = 100 / bandwidth;
}

/* Handle variable number of RAID parameters. */
static int get_raid_variable_parms(struct dm_target *ti, char **argv,
				   struct variable_parms *vp)
{
	int p, value;
	struct {
		int action; /* -1: skip, 0: no power2 check, 1: power2 check */
		char *errmsg;
		int min, max;
		int *var, *var2, *var3;
	} argctr[] = {
		{ 1,
		  "Invalid chunk size; must be -1 or 2^^n and <= 16384",
 		  IO_SIZE_MIN, CHUNK_SIZE_MAX,
		  &vp->chunk_size_parm, &vp->chunk_size, &vp->io_size },
		{ 0,
		  "Invalid number of stripes: must be -1 or >= 8 and <= 16384",
		  STRIPES_MIN, STRIPES_MAX,
		  &vp->stripes_parm, &vp->stripes, NULL },
		{ 1,
		  "Invalid io size; must -1 or >= 8, 2^^n and less equal "
		  "min(BIO_MAX_SECTORS/2, chunk size)",
		  IO_SIZE_MIN, 0, /* Needs to be updated in loop below. */
		  &vp->io_size_parm, &vp->io_size, NULL },
		{ 1,
		  "Invalid recovery io size; must be -1 or "
		  "2^^n and less equal BIO_MAX_SECTORS/2",
		  RECOVER_IO_SIZE_MIN, BIO_MAX_SECTORS / 2,
		  &vp->recover_io_size_parm, &vp->recover_io_size, NULL },
		{ 0,
		  "Invalid recovery bandwidth percentage; "
		  "must be -1 or > 0 and <= 100",
		  BANDWIDTH_MIN, BANDWIDTH_MAX,
		  &vp->bandwidth_parm, &vp->bandwidth, NULL },
		/* Handle sync argument seperately in loop. */
		{ -1,
		  "Invalid recovery switch; must be \"sync\" or \"nosync\"" },
		{ 0,
		  "Invalid number of recovery stripes;"
		  "must be -1, > 0 and <= 64",
		  RECOVERY_STRIPES_MIN, RECOVERY_STRIPES_MAX,
		  &vp->recovery_stripes_parm, &vp->recovery_stripes, NULL },
	}, *varp;

	/* Fetch # of variable raid parameters. */
	if (sscanf(*(argv++), "%d", &vp->raid_parms) != 1 ||
	    !range_ok(vp->raid_parms, 0, 7))
		TI_ERR("Bad variable raid parameters number");

	/* Preset variable RAID parameters. */
	vp->chunk_size = CHUNK_SIZE_DEFAULT;
	vp->io_size = IO_SIZE_DEFAULT;
	vp->stripes = STRIPES_DEFAULT;
	vp->recover_io_size = RECOVER_IO_SIZE_DEFAULT;
	vp->bandwidth = BANDWIDTH_DEFAULT;
	vp->recovery = 1;
	vp->recovery_stripes = RECOVERY_STRIPES_DEFAULT;

	/* Walk the array of argument constraints for all given ones. */
	for (p = 0, varp = argctr; p < vp->raid_parms; p++, varp++) {
	     	BUG_ON(varp >= ARRAY_END(argctr));

		/* Special case for "[no]sync" string argument. */
		if (varp->action < 0) {
			if (!strcmp(*argv, "sync"))
				;
			else if (!strcmp(*argv, "nosync"))
				vp->recovery = 0;
			else
				TI_ERR(varp->errmsg);

			argv++;
			continue;
		}

		/*
		 * Special case for io_size depending
		 * on previously set chunk size.
		 */
		if (p == 2)
			varp->max = min(BIO_MAX_SECTORS / 2, vp->chunk_size);

		if (sscanf(*(argv++), "%d", &value) != 1 ||
		    (value != -1 &&
		     ((varp->action && !is_power_of_2(value)) ||
		      !range_ok(value, varp->min, varp->max))))
			TI_ERR(varp->errmsg);

		*varp->var = value;
		if (value != -1) {
			if (varp->var2)
				*varp->var2 = value;
			if (varp->var3)
				*varp->var3 = value;
		}
	}

	return 0;
}

/* Parse optional locking parameters. */
static int get_raid_locking_parms(struct dm_target *ti, char **argv,
				  int *locking_parms,
				  struct dm_raid45_locking_type **locking_type)
{
	if (!strnicmp(argv[0], "locking", strlen(argv[0]))) {
		char *lckstr = argv[1];
		size_t lcksz = strlen(lckstr);

		if (!strnicmp(lckstr, "none", lcksz)) {
			*locking_type = &locking_none;
			*locking_parms = 2;
		} else if (!strnicmp(lckstr, "cluster", lcksz)) {
			DMERR("locking type \"%s\" not yet implemented",
			      lckstr);
			return -EINVAL;
		} else {
			DMERR("unknown locking type \"%s\"", lckstr);
			return -EINVAL;
		}
	}

	*locking_parms = 0;
	*locking_type = &locking_none;
	return 0;
}

/* Set backing device read ahead properties of RAID set. */
static void rs_set_read_ahead(struct raid_set *rs,
			      unsigned sectors, unsigned stripes)
{
	unsigned ra_pages = dm_div_up(sectors, SECTORS_PER_PAGE);
	struct mapped_device *md = dm_table_get_md(rs->ti->table);
	struct backing_dev_info *bdi = &dm_disk(md)->queue->backing_dev_info;

	/* Set read-ahead for the RAID set and the component devices. */
	if (ra_pages) {
		unsigned p = rs->set.raid_devs;

		bdi->ra_pages = stripes * ra_pages * rs->set.data_devs;

		while (p--) {
			struct request_queue *q =
				bdev_get_queue(rs->dev[p].dev->bdev);

			q->backing_dev_info.ra_pages = ra_pages;
		}
	}

	dm_put(md);
}

/* Set congested function. */
static void rs_set_congested_fn(struct raid_set *rs)
{
	struct mapped_device *md = dm_table_get_md(rs->ti->table);
	struct backing_dev_info *bdi = &dm_disk(md)->queue->backing_dev_info;

	/* Set congested function and data. */
	bdi->congested_fn = rs_congested;
	bdi->congested_data = rs;
	dm_put(md);
}

/*
 * Construct a RAID4/5 mapping:
 *
 * log_type #log_params <log_params> \
 * raid_type [#parity_dev] #raid_variable_params <raid_params> \
 * [locking "none"/"cluster"]
 * #raid_devs #dev_to_initialize [<dev_path> <offset>]{3,}
 *
 * log_type = "core"/"disk",
 * #log_params = 1-3 (1-2 for core dirty log type, 3 for disk dirty log only)
 * log_params = [dirty_log_path] region_size [[no]sync])
 *
 * raid_type = "raid4", "raid5_la", "raid5_ra", "raid5_ls", "raid5_rs"
 *
 * #parity_dev = N if raid_type = "raid4"
 * o N = -1: pick default = last device
 * o N >= 0 and < #raid_devs: parity device index
 *
 * #raid_variable_params = 0-7; raid_params (-1 = default):
 *   [chunk_size [#stripes [io_size [recover_io_size \
 *    [%recovery_bandwidth [recovery_switch [#recovery_stripes]]]]]]]
 *   o chunk_size (unit to calculate drive addresses; must be 2^^n, > 8
 *     and <= CHUNK_SIZE_MAX)
 *   o #stripes is number of stripes allocated to stripe cache
 *     (must be > 1 and < STRIPES_MAX)
 *   o io_size (io unit size per device in sectors; must be 2^^n and > 8)
 *   o recover_io_size (io unit size per device for recovery in sectors;
 must be 2^^n, > SECTORS_PER_PAGE and <= region_size)
 *   o %recovery_bandwith is the maximum amount spend for recovery during
 *     application io (1-100%)
 *   o recovery switch = [sync|nosync]
 *   o #recovery_stripes is the number of recovery stripes used for
 *     parallel recovery of the RAID set
 * If raid_variable_params = 0, defaults will be used.
 * Any raid_variable_param can be set to -1 to apply a default
 *
 * #raid_devs = N (N >= 3)
 *
 * #dev_to_initialize = N
 * -1: initialize parity on all devices
 * >= 0 and < #raid_devs: initialize raid_path; used to force reconstruction
 * of a failed devices content after replacement
 *
 * <dev_path> = device_path (eg, /dev/sdd1)
 * <offset>   = begin at offset on <dev_path>
 *
 */
#define	MIN_PARMS	13
static int raid_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	int dev_to_init, dl_parms, i, locking_parms,
	    parity_parm, pi = -1, r, raid_devs;
	sector_t tmp, sectors_per_dev;
	struct dm_raid45_locking_type *locking;
	struct raid_set *rs;
	struct raid_type *raid_type;
	struct variable_parms parms;

	/* Ensure minimum number of parameters. */
	if (argc < MIN_PARMS)
		TI_ERR("Not enough parameters");

	/* Fetch # of dirty log parameters. */
	if (sscanf(argv[1], "%d", &dl_parms) != 1 ||
	    !range_ok(dl_parms, 1, 4711)) /* ;-) */
		TI_ERR("Bad dirty log parameters number");

	/* Check raid_type. */
	raid_type = get_raid_type(argv[dl_parms + 2]);
	if (!raid_type)
		TI_ERR("Bad raid type");

	/* In case of RAID4, parity drive is selectable. */
	parity_parm = !!(raid_type->level == raid4);

	/* Handle variable number of RAID parameters. */
	r = get_raid_variable_parms(ti, argv + dl_parms + parity_parm + 3,
				    &parms);
	if (r)
		return r;

	/* Handle any locking parameters. */
	r = get_raid_locking_parms(ti,
				   argv + dl_parms + parity_parm +
				   parms.raid_parms + 4,
				   &locking_parms, &locking);
	if (r)
		return r;

	/* # of raid devices. */
	i = dl_parms + parity_parm + parms.raid_parms + locking_parms + 4;
	if (sscanf(argv[i], "%d", &raid_devs) != 1 ||
	    raid_devs < raid_type->minimal_devs)
		TI_ERR("Invalid number of raid devices");

	/* In case of RAID4, check parity drive index is in limits. */
	if (raid_type->level == raid4) {
		/* Fetch index of parity device. */
		if (sscanf(argv[dl_parms + 3], "%d", &pi) != 1 ||
		    (pi != -1 && !range_ok(pi, 0, raid_devs - 1)))
			TI_ERR("Invalid RAID4 parity device index");
	}

	/*
	 * Index of device to initialize starts at 0
	 *
	 * o -1 -> don't initialize a selected device;
	 *         initialize parity conforming to algorithm
	 * o 0..raid_devs-1 -> initialize respective device
	 *   (used for reconstruction of a replaced device)
	 */
	if (sscanf(argv[dl_parms + parity_parm + parms.raid_parms +
		   locking_parms + 5], "%d", &dev_to_init) != 1 ||
	    !range_ok(dev_to_init, -1, raid_devs - 1))
		TI_ERR("Invalid number for raid device to initialize");

	/* Check # of raid device arguments. */
	if (argc - dl_parms - parity_parm - parms.raid_parms - 6 !=
	    2 * raid_devs)
		TI_ERR("Wrong number of raid device/offset arguments");

	/*
	 * Check that the table length is devisable
	 * w/o rest by (raid_devs - parity_devs)
	 */
	if (!multiple(ti->len, raid_devs - raid_type->parity_devs,
		      &sectors_per_dev))
		TI_ERR("Target length not divisible by number of data devices");

	/*
	 * Check that the device size is
	 * devisable w/o rest by chunk size
	 */
	if (!multiple(sectors_per_dev, parms.chunk_size, &tmp))
		TI_ERR("Device length not divisible by chunk_size");

	/****************************************************************
	 * Now that we checked the constructor arguments ->
	 * let's allocate the RAID set
	 ****************************************************************/
	rs = context_alloc(raid_type, &parms, raid_devs, sectors_per_dev,
			   ti, dl_parms, argv);
	if (IS_ERR(rs))
		return PTR_ERR(rs);


	rs->set.dev_to_init = rs->set.dev_to_init_parm = dev_to_init;
	rs->set.pi = rs->set.pi_parm = pi;

	/* Set RAID4 parity drive index. */
	if (raid_type->level == raid4)
		rs->set.pi = (pi == -1) ? rs->set.data_devs : pi;

	recover_set_bandwidth(rs, parms.bandwidth);

	/* Use locking type to lock stripe access. */
	rs->locking = locking;

	/* Get the device/offset tupels. */
	argv += dl_parms + 6 + parity_parm + parms.raid_parms;
	r = dev_parms(rs, argv, &i);
	if (r)
		goto err;

	/* Set backing device information (eg. read ahead). */
	rs_set_read_ahead(rs, 2 * rs->set.chunk_size /* sectors per device */,
			      2 /* # of stripes */);
	rs_set_congested_fn(rs); /* Set congested function. */
	SetRSCheckOverwrite(rs); /* Allow chunk overwrite checks. */
	rs->xor.speed = xor_optimize(rs); /* Select best xor algorithm. */

	/* Set for recovery of any nosync regions. */
	if (parms.recovery)
		SetRSRecover(rs);
	else {
		/*
		 * Need to free recovery stripe(s) here in case
		 * of nosync, because xor_optimize uses one.
		 */
		set_start_recovery(rs);
		set_end_recovery(rs);
		stripe_recover_free(rs);
	}

	/*
	 * Enable parity chunk creation enformcement for
	 * little numbers of array members where it doesn'ti
	 * gain us performance to xor parity out and back in as
	 * with larger array member numbers.
	 */
	if (rs->set.raid_devs <= rs->set.raid_type->minimal_devs + 1)
		SetRSEnforceParityCreation(rs);

	/*
	 * Make sure that dm core only hands maximum io size
	 * length down and pays attention to io boundaries.
	 */
	r = dm_set_target_max_io_len(ti, rs->set.io_size);
	if (r)
		goto err;

	ti->private = rs;

	/* Initialize work queue to handle this RAID set's io. */
	r = rs_workqueue_init(rs);
	if (r)
		goto err;

	rs_log(rs, rs->recover.io_size); /* Log information about RAID set. */
	return 0;

err:
	context_free(rs, i);
	return r;
}

/*
 * Destruct a raid mapping
 */
static void raid_dtr(struct dm_target *ti)
{
	struct raid_set *rs = ti->private;

	destroy_workqueue(rs->io.wq);
	context_free(rs, rs->set.raid_devs);
}

/* Raid mapping function. */
static int raid_map(struct dm_target *ti, struct bio *bio,
		    union map_info *map_context)
{
	/* I don't want to waste stripe cache capacity. */
	if (bio_rw(bio) == READA)
		return -EIO;
	else {
		struct raid_set *rs = ti->private;

		/*
		 * Get io reference to be waiting for to drop
		 * to zero on device suspension/destruction.
		 */
		io_get(rs);
		bio->bi_sector -= ti->begin;	/* Remap sector. */

		/* Queue io to RAID set. */
		mutex_lock(&rs->io.in_lock);
		bio_list_add(&rs->io.in, bio);
		mutex_unlock(&rs->io.in_lock);

		/* Wake daemon to process input list. */
		wake_do_raid(rs);

		/* REMOVEME: statistics. */
		atomic_inc(rs->stats + (bio_data_dir(bio) == READ ?
				        S_BIOS_READ : S_BIOS_WRITE));
		return DM_MAPIO_SUBMITTED;	/* Handle later. */
	}
}

/* Device suspend. */
static void raid_presuspend(struct dm_target *ti)
{
	struct raid_set *rs = ti->private;
	struct dm_dirty_log *dl = rs->recover.dl;

	SetRSSuspend(rs);

	if (RSRecover(rs))
		dm_rh_stop_recovery(rs->recover.rh);

	cancel_delayed_work(&rs->io.dws_do_raid);
	flush_workqueue(rs->io.wq);
	wait_ios(rs);	/* Wait for completion of all ios being processed. */

	if (dl->type->presuspend && dl->type->presuspend(dl))
		/* FIXME: need better error handling. */
		DMWARN("log presuspend failed");
}

static void raid_postsuspend(struct dm_target *ti)
{
	struct raid_set *rs = ti->private;
	struct dm_dirty_log *dl = rs->recover.dl;

	if (dl->type->postsuspend && dl->type->postsuspend(dl))
		/* FIXME: need better error handling. */
		DMWARN("log postsuspend failed");

}

/* Device resume. */
static void raid_resume(struct dm_target *ti)
{
	struct raid_set *rs = ti->private;
	struct recover *rec = &rs->recover;
	struct dm_dirty_log *dl = rec->dl;

DMINFO("%s...", __func__);
	if (dl->type->resume && dl->type->resume(dl))
		/* Resume dirty log. */
		/* FIXME: need better error handling. */
		DMWARN("log resume failed");

	rec->nr_regions_to_recover =
		rec->nr_regions - dl->type->get_sync_count(dl);

	/* Restart any unfinished recovery. */
	if (RSRecover(rs)) {
		set_start_recovery(rs);
		dm_rh_start_recovery(rec->rh);
	}

	ClearRSSuspend(rs);
}

/* Return stripe cache size. */
static unsigned sc_size(struct raid_set *rs)
{
	return to_sector(atomic_read(&rs->sc.stripes) *
			 (sizeof(struct stripe) +
			  (sizeof(struct stripe_chunk) +
			   (sizeof(struct page_list) +
			    to_bytes(rs->set.io_size) *
			    rs->set.raid_devs)) +
			  (rs->recover.end_jiffies ?
			   0 : rs->recover.recovery_stripes *
			   to_bytes(rs->set.raid_devs * rs->recover.io_size))));
}

/* REMOVEME: status output for development. */
static void raid_devel_stats(struct dm_target *ti, char *result,
			     unsigned *size, unsigned maxlen)
{
	unsigned sz = *size;
	unsigned long j;
	char buf[BDEVNAME_SIZE], *p;
	struct stats_map *sm;
	struct raid_set *rs = ti->private;
	struct recover *rec = &rs->recover;
	struct timespec ts;

	DMEMIT("%s %s=%u bw=%u\n",
	       version, rs->xor.f->name, rs->xor.chunks, rs->recover.bandwidth);
	DMEMIT("act_ios=%d ", io_ref(rs));
	DMEMIT("act_ios_max=%d\n", atomic_read(&rs->io.in_process_max));
	DMEMIT("act_stripes=%d ", sc_active(&rs->sc));
	DMEMIT("act_stripes_max=%d\n",
	       atomic_read(&rs->sc.active_stripes_max));

	for (sm = stats_map; sm < ARRAY_END(stats_map); sm++)
		DMEMIT("%s%d", sm->str, atomic_read(rs->stats + sm->type));

	DMEMIT(" checkovr=%s\n", RSCheckOverwrite(rs) ? "on" : "off");
	DMEMIT("sc=%u/%u/%u/%u/%u/%u/%u\n", rs->set.chunk_size,
	       atomic_read(&rs->sc.stripes), rs->set.io_size,
	       rec->recovery_stripes, rec->io_size, rs->sc.hash.buckets,
	       sc_size(rs));

	j = (rec->end_jiffies ? rec->end_jiffies : jiffies) -
	    rec->start_jiffies;
	jiffies_to_timespec(j, &ts);
	sprintf(buf, "%ld.%ld", ts.tv_sec, ts.tv_nsec);
	p = strchr(buf, '.');
	p[3] = 0;

	DMEMIT("rg=%llu/%llu/%llu/%u %s\n",
	       (unsigned long long) rec->nr_regions_recovered,
	       (unsigned long long) rec->nr_regions_to_recover,
	       (unsigned long long) rec->nr_regions, rec->bandwidth, buf);

	*size = sz;
}

static int raid_status(struct dm_target *ti, status_type_t type,
		       char *result, unsigned maxlen)
{
	unsigned p, sz = 0;
	char buf[BDEVNAME_SIZE];
	struct raid_set *rs = ti->private;
	struct dm_dirty_log *dl = rs->recover.dl;
	int raid_parms[] = {
		rs->set.chunk_size_parm,
		rs->sc.stripes_parm,
		rs->set.io_size_parm,
		rs->recover.io_size_parm,
		rs->recover.bandwidth_parm,
		-2,
		rs->recover.recovery_stripes,
	};

	switch (type) {
	case STATUSTYPE_INFO:
		/* REMOVEME: statistics. */
		if (RSDevelStats(rs))
			raid_devel_stats(ti, result, &sz, maxlen);

		DMEMIT("%u ", rs->set.raid_devs);

		for (p = 0; p < rs->set.raid_devs; p++)
			DMEMIT("%s ",
			       format_dev_t(buf, rs->dev[p].dev->bdev->bd_dev));

		DMEMIT("2 ");
		for (p = 0; p < rs->set.raid_devs; p++) {
			DMEMIT("%c", !DevFailed(rs->dev + p) ? 'A' : 'D');

			if (p == rs->set.pi)
				DMEMIT("p");

			if (p == rs->set.dev_to_init)
				DMEMIT("i");
		}

		DMEMIT(" %llu/%llu ",
		      (unsigned long long) dl->type->get_sync_count(dl),
		      (unsigned long long) rs->recover.nr_regions);

		sz += dl->type->status(dl, type, result+sz, maxlen-sz);
		break;
	case STATUSTYPE_TABLE:
		sz = rs->recover.dl->type->status(rs->recover.dl, type,
						  result, maxlen);
		DMEMIT("%s %u ", rs->set.raid_type->name, rs->set.raid_parms);

		for (p = 0; p < rs->set.raid_parms; p++) {
			if (raid_parms[p] > -2)
				DMEMIT("%d ", raid_parms[p]);
			else
				DMEMIT("%s ", rs->recover.recovery ?
					      "sync" : "nosync");
		}

		DMEMIT("%u %d ", rs->set.raid_devs, rs->set.dev_to_init);

		for (p = 0; p < rs->set.raid_devs; p++)
			DMEMIT("%s %llu ",
			       format_dev_t(buf, rs->dev[p].dev->bdev->bd_dev),
			       (unsigned long long) rs->dev[p].start);
	}

	return 0;
}

/*
 * Message interface
 */
/* Turn a delta into an absolute value. */
static int _absolute(char *action, int act, int r)
{
	size_t len = strlen(action);

	if (len < 2)
		len = 2;

	/* Make delta absolute. */
	if (!strncmp("set", action, len))
		;
	else if (!strncmp("grow", action, len))
		r += act;
	else if (!strncmp("shrink", action, len))
		r = act - r;
	else
		r = -EINVAL;

	return r;
}

 /* Change recovery io bandwidth. */
static int bandwidth_change(struct raid_set *rs, int argc, char **argv,
			    enum raid_set_flags flag)
{
	int act = rs->recover.bandwidth, bandwidth;

	if (argc != 2)
		return -EINVAL;

	if (sscanf(argv[1], "%d", &bandwidth) == 1 &&
	    range_ok(bandwidth, BANDWIDTH_MIN, BANDWIDTH_MAX)) {
		/* Make delta bandwidth absolute. */
		bandwidth = _absolute(argv[0], act, bandwidth);

		/* Check range. */
		if (range_ok(bandwidth, BANDWIDTH_MIN, BANDWIDTH_MAX)) {
			recover_set_bandwidth(rs, bandwidth);
			return 0;
		}
	}

	return -EINVAL;
}

/* Set/reset development feature flags. */
static int devel_flags(struct raid_set *rs, int argc, char **argv,
		       enum raid_set_flags flag)
{
	size_t len;

	if (argc != 1)
		return -EINVAL;

	len = strlen(argv[0]);
	if (len < 2)
		len = 2;

	if (!strncmp(argv[0], "on", len))
		return test_and_set_bit(flag, &rs->io.flags) ? -EPERM : 0;
	else if (!strncmp(argv[0], "off", len))
		return test_and_clear_bit(flag, &rs->io.flags) ? 0 : -EPERM;
	else if (!strncmp(argv[0], "reset", len)) {
		if (flag == RS_DEVEL_STATS) {
			if  (test_bit(flag, &rs->io.flags)) {
				stats_reset(rs);
				return 0;
			} else
				return -EPERM;
		} else  {
			set_bit(flag, &rs->io.flags);
			return 0;
		}
	}

	return -EINVAL;
}

/* Resize the stripe cache. */
static int sc_resize(struct raid_set *rs, int argc, char **argv,
		     enum raid_set_flags flag)
{
	int act, stripes;

	if (argc != 2)
		return -EINVAL;

	/* Deny permission in case the daemon is still resizing!. */
	if (atomic_read(&rs->sc.stripes_to_set))
		return -EPERM;

	if (sscanf(argv[1], "%d", &stripes) == 1 &&
	    stripes > 0) {
		act = atomic_read(&rs->sc.stripes);

		/* Make delta stripes absolute. */
		stripes = _absolute(argv[0], act, stripes);

		/*
		 * Check range and that the # of stripes changes.
		 * We leave the resizing to the wroker.
		 */
		if (range_ok(stripes, STRIPES_MIN, STRIPES_MAX) &&
		    stripes != atomic_read(&rs->sc.stripes)) {
			atomic_set(&rs->sc.stripes_to_set, stripes);
			wake_do_raid(rs);
			return 0;
		}
	}

	return -EINVAL;
}

/* Change xor algorithm and number of chunks. */
static int xor_set(struct raid_set *rs, int argc, char **argv,
		   enum raid_set_flags flag)
{
	if (argc == 2) {
		int chunks;
		char *algorithm = argv[0];
		struct xor_func *f = ARRAY_END(xor_funcs);

		if (sscanf(argv[1], "%d", &chunks) == 1 &&
		    range_ok(chunks, 2, XOR_CHUNKS_MAX) &&
		    chunks <= rs->set.raid_devs) {
			while (f-- > xor_funcs) {
				if (!strcmp(algorithm, f->name)) {
					unsigned io_size = 0;
					struct stripe *stripe = stripe_alloc(&rs->sc, rs->sc.mem_cache_client, SC_GROW);

					DMINFO("xor: %s", f->name);
					if (f->f == xor_blocks_wrapper &&
					    chunks > MAX_XOR_BLOCKS + 1) {
						DMERR("chunks > MAX_XOR_BLOCKS"
						      " + 1");
						break;
					}

					mutex_lock(&rs->io.xor_lock);
					rs->xor.f = f;
					rs->xor.chunks = chunks;
					rs->xor.speed = 0;
					mutex_unlock(&rs->io.xor_lock);

					if (stripe) {
						rs->xor.speed = xor_speed(stripe);
						io_size = stripe->io.size;
						stripe_free(stripe, rs->sc.mem_cache_client);
					}

					rs_log(rs, io_size);
					return 0;
				}
			}
		}
	}

	return -EINVAL;
}

/*
 * Allow writes after they got prohibited because of a device failure.
 *
 * This needs to be called after userspace updated metadata state
 * based on an event being thrown during device failure processing.
 */
static int allow_writes(struct raid_set *rs, int argc, char **argv,
			enum raid_set_flags flag)
{
	if (TestClearRSProhibitWrites(rs)) {
DMINFO("%s waking", __func__);
		wake_do_raid(rs);
		return 0;
	}

	return -EPERM;
}

/* Parse the RAID message. */
/*
 * 'all[ow_writes]'
 * 'ba[ndwidth] {se[t],g[row],sh[rink]} #'	# e.g 'ba se 50'
 * "o[verwrite]  {on,of[f],r[eset]}'		# e.g. 'o of'
 * 'sta[tistics] {on,of[f],r[eset]}'		# e.g. 'stat of'
 * 'str[ipecache] {se[t],g[row],sh[rink]} #'	# e.g. 'stripe set 1024'
 * 'xor algorithm #chunks'			# e.g. 'xor xor_8 5'
 *
 */
static int raid_message(struct dm_target *ti, unsigned argc, char **argv)
{
	if (argc) {
		size_t len = strlen(argv[0]);
		struct raid_set *rs = ti->private;
		struct {
			const char *name;
			int (*f) (struct raid_set *rs, int argc, char **argv,
				  enum raid_set_flags flag);
			enum raid_set_flags flag;
		} msg_descr[] = {
			{ "allow_writes", allow_writes, 0 },
			{ "bandwidth", bandwidth_change, 0 },
			{ "overwrite", devel_flags, RS_CHECK_OVERWRITE },
			{ "statistics", devel_flags, RS_DEVEL_STATS },
			{ "stripe_cache", sc_resize, 0 },
			{ "xor", xor_set, 0 },
		}, *m = ARRAY_END(msg_descr);

		if (len < 3)
			len = 3;

		while (m-- > msg_descr) {
			if (!strncmp(argv[0], m->name, len))
				return m->f(rs, argc - 1, argv + 1, m->flag);
		}

	}

	return -EINVAL;
}
/*
 * END message interface
 */

/* Provide io hints. */
static void raid_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct raid_set *rs = ti->private;

	blk_limits_io_min(limits, rs->set.chunk_size);
	blk_limits_io_opt(limits, rs->set.chunk_size * rs->set.data_devs);
}

/* Check device limits. */
static int raid_iterate_devices(struct dm_target *ti,
				iterate_devices_callout_fn fn, void *data)
{
	int ret;
	struct raid_set *rs = ti->private;
	struct raid_dev *dev;
	sector_t sectors_per_dev = rs->set.sectors_per_dev;

	for (dev = rs->dev, ret = 0;
	     !ret && dev < rs->dev + rs->set.raid_devs; dev++)
		ret = fn(ti, dev->dev, dev->start, sectors_per_dev, data);

	return ret;
}

static struct target_type raid_target = {
	.name = "raid45",
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.ctr = raid_ctr,
	.dtr = raid_dtr,
	.map = raid_map,
	.presuspend = raid_presuspend,
	.postsuspend = raid_postsuspend,
	.resume = raid_resume,
	.status = raid_status,
	.message = raid_message,
	.io_hints = raid_io_hints,
	.iterate_devices = raid_iterate_devices,
};

static void init_exit(const char *bad_msg, const char *good_msg, int r)
{
	if (r)
		DMERR("Failed to %sregister target [%d]", bad_msg, r);
	else
		DMINFO("%s %s", good_msg, version);
}

static int __init dm_raid_init(void)
{
	int r = dm_register_target(&raid_target);

	init_exit("", "initialized", r);
	return r;
}

static void __exit dm_raid_exit(void)
{
	dm_unregister_target(&raid_target);
	init_exit("un", "exit", 0);
}

/* Module hooks. */
module_init(dm_raid_init);
module_exit(dm_raid_exit);

MODULE_DESCRIPTION(DM_NAME " raid4/5 target");
MODULE_AUTHOR("Heinz Mauelshagen <heinzm@redhat.com>");
MODULE_LICENSE("GPL");
MODULE_ALIAS("dm-raid4");
MODULE_ALIAS("dm-raid5");

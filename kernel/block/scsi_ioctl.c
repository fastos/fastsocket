/*
 * Copyright (C) 2001 Jens Axboe <axboe@suse.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public Licens
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-
 *
 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/capability.h>
#include <linux/completion.h>
#include <linux/cdrom.h>
#include <linux/slab.h>
#include <linux/times.h>
#include <asm/uaccess.h>

#include <scsi/scsi.h>
#include <scsi/scsi_ioctl.h>
#include <scsi/scsi_cmnd.h>

struct blk_cmd_filter {
	u32 read_ok[BLK_SCSI_MAX_CMDS];
	u32 write_ok[BLK_SCSI_MAX_CMDS];
} blk_default_cmd_filter;

/* Command group 3 is reserved and should never be used.  */
const unsigned char scsi_command_size_tbl[8] =
{
	6, 10, 10, 12,
	16, 12, 10, 10
};
EXPORT_SYMBOL(scsi_command_size_tbl);

#include <scsi/sg.h>

static int sg_get_version(int __user *p)
{
	static const int sg_version_num = 30527;
	return put_user(sg_version_num, p);
}

static int scsi_get_idlun(struct request_queue *q, int __user *p)
{
	return put_user(0, p);
}

static int scsi_get_bus(struct request_queue *q, int __user *p)
{
	return put_user(0, p);
}

static int sg_get_timeout(struct request_queue *q)
{
	return jiffies_to_clock_t(q->sg_timeout);
}

static int sg_set_timeout(struct request_queue *q, int __user *p)
{
	int timeout, err = get_user(timeout, p);

	if (!err)
		q->sg_timeout = clock_t_to_jiffies(timeout);

	return err;
}

static int sg_get_reserved_size(struct request_queue *q, int __user *p)
{
	unsigned val = min(q->sg_reserved_size, queue_max_sectors(q) << 9);

	return put_user(val, p);
}

static int sg_set_reserved_size(struct request_queue *q, int __user *p)
{
	int size, err = get_user(size, p);

	if (err)
		return err;

	if (size < 0)
		return -EINVAL;
	if (size > (queue_max_sectors(q) << 9))
		size = queue_max_sectors(q) << 9;

	q->sg_reserved_size = size;
	return 0;
}

/*
 * will always return that we are ATAPI even for a real SCSI drive, I'm not
 * so sure this is worth doing anything about (why would you care??)
 */
static int sg_emulated_host(struct request_queue *q, int __user *p)
{
	return put_user(1, p);
}

static void blk_set_cmd_filter_defaults(struct blk_cmd_filter *filter)
{
#define sgio_bitmap_set(cmd, mask, rw) \
	filter->rw##_ok[(cmd)] |= (mask);

#define D (1u << TYPE_DISK)           /* Direct Access Block Device (SBC-3) */
#define T (1u << TYPE_TAPE)           /* Sequential Access Device (SSC-3) */
#define L (1u << TYPE_PRINTER)        /* Printer Device (SSC) */
#define P (1u << TYPE_PROCESSOR)      /* Processor Device (SPC-2) */
#define W (1u << TYPE_WORM)           /* Write Once Block Device (SBC) */
#define R (1u << TYPE_ROM)            /* C/DVD Device (MMC-6) */
#define S (1u << TYPE_SCANNER)        /* Scanner device (obsolete) */
#define O (1u << TYPE_MOD)            /* Optical Memory Block Device (SBC) */
#define M (1u << TYPE_MEDIUM_CHANGER) /* Media Changer Device (SMC-3) */
#define C (1u << TYPE_COMM)           /* Communication devices (obsolete) */
#define A (1u << TYPE_RAID)           /* Storage Array Device (SCC-2) */
#define E (1u << TYPE_ENCLOSURE)      /* SCSI Enclosure Services device (SES-2) */
#define B (1u << TYPE_RBC)            /* Simplified Direct-Access (Reduced Block) device (RBC) */
#define K (1u << 0x0f)                /* Optical Card Reader/Writer device (OCRW) */
#define V (1u << 0x10)                /* Automation/Device Interface device (ADC-2) */
#define F (1u << TYPE_OSD)            /* Object-based Storage Device (OSD-2) */

	/* control, universal except possibly RBC, read */

	sgio_bitmap_set(0x00, -1                             , read);  // TEST UNIT READY
	sgio_bitmap_set(0x03, -1                             , read);  // REQUEST SENSE
	sgio_bitmap_set(0x12, -1                             , read);  // INQUIRY
	sgio_bitmap_set(0x1A, -1                             , read);  // MODE SENSE(6)
	sgio_bitmap_set(0x1C,                    ~B          , read);  // RECEIVE DIAGNOSTIC RESULTS
	sgio_bitmap_set(0x4D, -1                             , read);  // LOG SENSE
	sgio_bitmap_set(0x5A, -1                             , read);  // MODE SENSE(10)
	sgio_bitmap_set(0x9E, -1                             , read);  // SERVICE ACTION IN(16)
	sgio_bitmap_set(0xA0, -1                             , read);  // REPORT LUNS

	/* control, universal, write */

	sgio_bitmap_set(0x4C, -1                             , write); // LOG SELECT
	sgio_bitmap_set(0x15, -1                             , write); // MODE SELECT(6)
	sgio_bitmap_set(0x55, -1                             , write); // MODE SELECT(10)

	/* control, write */

	sgio_bitmap_set(0x1B, D|      W|R|O|  A|  B|K|  F    , write); // START STOP UNIT
	sgio_bitmap_set(0x1E, D|T|    W|R|O|M|      K|  F    , write); // PREVENT ALLOW MEDIUM REMOVAL

	/* input */

	sgio_bitmap_set(0x08, D|T|    W|  O                  , read);  // READ(6)
	sgio_bitmap_set(0x25, D|      W|R|O|      B|K        , read);  // READ CAPACITY(10)
	sgio_bitmap_set(0x28, D|      W|R|O|      B|K        , read);  // READ(10)
	sgio_bitmap_set(0x29, D|      W|R|O                  , read);  // READ GENERATION
	sgio_bitmap_set(0x2D,             O                  , read);  // READ UPDATED BLOCK
	sgio_bitmap_set(0x37, D|          O                  , read);  // READ DEFECT DATA(10)
	sgio_bitmap_set(0x3E, D|      W|  O                  , read);  // READ LONG(10)
	sgio_bitmap_set(0x88, D|T|    W|  O|      B          , read);  // READ(16)
	sgio_bitmap_set(0x8F, D|T|    W|  O|      B          , read);  // VERIFY(16)
	sgio_bitmap_set(0x90, D|      W|  O|      B          , read);  // PRE-FETCH(16)
	sgio_bitmap_set(0xA8, D|      W|R|O                  , read);  // READ(12)
	sgio_bitmap_set(0xAF, D|      W|  O                  , read);  // VERIFY(12)
	sgio_bitmap_set(0xB7, D|          O                  , read);  // READ DEFECT DATA(12)

	/* write */

	sgio_bitmap_set(0x04, D|        R|O                  , write); // FORMAT UNIT
	sgio_bitmap_set(0x07, D|      W|  O                  , write); // REASSIGN BLOCKS
	sgio_bitmap_set(0x0A, D|T|    W|  O                  , write); // WRITE(6)
	sgio_bitmap_set(0x2A, D|      W|R|O|      B|K        , write); // WRITE(10)
	sgio_bitmap_set(0x2C, D|        R|O                  , write); // ERASE(10)
	sgio_bitmap_set(0x2E, D|      W|R|O|      B|K        , write); // WRITE AND VERIFY(10)
	sgio_bitmap_set(0x2F, D|      W|R|O                  , write); // VERIFY(10)
	sgio_bitmap_set(0x34, D|      W|  O|        K        , write); // PRE-FETCH(10)
	sgio_bitmap_set(0x35, D|      W|R|O|      B|K        , write); // SYNCHRONIZE CACHE(10)
	sgio_bitmap_set(0x38,         W|  O|        K        , write); // MEDIUM SCAN
	sgio_bitmap_set(0x3D,             O                  , write); // UPDATE BLOCK
	sgio_bitmap_set(0x3F, D|      W|  O                  , write); // WRITE LONG(10)
	sgio_bitmap_set(0x41, D                              , write); // WRITE SAME(10)
	sgio_bitmap_set(0x42, D                              , write); // UNMAP
	sgio_bitmap_set(0x48, D|                  B          , write); // SANITIZE
	sgio_bitmap_set(0x51, D                              , write); // XPWRITE(10)
	sgio_bitmap_set(0x53, D                              , write); // XDWRITEREAD(10)
	sgio_bitmap_set(0x89, D                              , write); // COMPARE AND WRITE
	sgio_bitmap_set(0x8B, D                              , write); // ORWRITE
	sgio_bitmap_set(0x85, D|                  B          , write); // ATA PASS-THROUGH(16)
	sgio_bitmap_set(0x8A, D|T|    W|  O|      B          , write); // WRITE(16)
	sgio_bitmap_set(0x8E, D|      W|  O|      B          , write); // WRITE AND VERIFY(16)
	sgio_bitmap_set(0x91, D|      W|  O|      B          , write); // SYNCHRONIZE CACHE(16)
	sgio_bitmap_set(0x93, D                              , write); // WRITE SAME(16)
	sgio_bitmap_set(0xA1, D|                  B          , write); // ATA PASS-THROUGH(12)
	sgio_bitmap_set(0xAA, D|      W|R|O                  , write); // WRITE(12)
	sgio_bitmap_set(0xAC,             O                  , write); // ERASE(12)
	sgio_bitmap_set(0xAE, D|      W|  O                  , write); // WRITE AND VERIFY(12)

	/* processor device */

	sgio_bitmap_set(0x08,       P                        , read);  // RECEIVE
	sgio_bitmap_set(0x0A,       P                        , write); // SEND(6)

	/* printer */

	sgio_bitmap_set(0x04,     L                          , write); // FORMAT
	sgio_bitmap_set(0x0A,     L                          , write); // PRINT
	sgio_bitmap_set(0x0B,     L                          , write); // SLEW AND PRINT
	sgio_bitmap_set(0x10,     L                          , write); // SYNCHRONIZE BUFFER
	sgio_bitmap_set(0x1B,     L                          , write); // STOP PRINT

	/* media changer */

	sgio_bitmap_set(0x07,               M                , write); // INITIALIZE ELEMENT STATUS
	sgio_bitmap_set(0x1B,               M                , write); // OPEN/CLOSE IMPORT/EXPORT ELEMENT
	sgio_bitmap_set(0x2B,               M                , write); // POSITION TO ELEMENT
	sgio_bitmap_set(0x37,               M                , write); // INITIALIZE ELEMENT STATUS WITH RANGE
	sgio_bitmap_set(0xA6,               M                , write); // EXCHANGE MEDIUM
	sgio_bitmap_set(0xB5,               M                , write); // REQUEST VOLUME ELEMENT ADDRESS
	sgio_bitmap_set(0xB6,               M                , write); // SEND VOLUME TAG

	/* (mostly) MMC */

	sgio_bitmap_set(0x23,           R                    , read);  // READ FORMAT CAPACITIES
	sgio_bitmap_set(0x42,           R                    , read);  // READ SUB-CHANNEL
	sgio_bitmap_set(0x43,           R                    , read);  // READ TOC/PMA/ATIP
	sgio_bitmap_set(0x44,           R                    , read);  // READ HEADER
	sgio_bitmap_set(0x45,           R                    , read);  // PLAY AUDIO(10)
	sgio_bitmap_set(0x46,           R                    , read);  // GET CONFIGURATION
	sgio_bitmap_set(0x47,           R                    , read);  // PLAY AUDIO MSF
	sgio_bitmap_set(0x4A,           R                    , read);  // GET EVENT STATUS NOTIFICATION
	sgio_bitmap_set(0x4B,           R                    , read);  // PAUSE/RESUME
	sgio_bitmap_set(0x4E,           R                    , read);  // STOP PLAY/SCAN
	sgio_bitmap_set(0x51,           R                    , read);  // READ DISC INFORMATION
	sgio_bitmap_set(0x52,           R                    , read);  // READ TRACK INFORMATION
	sgio_bitmap_set(0x5C,           R                    , read);  // READ BUFFER CAPACITY
	sgio_bitmap_set(0xA4,           R                    , read);  // REPORT KEY
	sgio_bitmap_set(0xA5,           R                    , read);  // PLAY AUDIO(12)
	sgio_bitmap_set(0xAB,           R|            V      , read);  // SERVICE ACTION IN(12)
	sgio_bitmap_set(0xAC,           R                    , read);  // GET PERFORMANCE
	sgio_bitmap_set(0xAD,           R                    , read);  // READ DVD STRUCTURE
	sgio_bitmap_set(0xB9,           R                    , read);  // READ CD MSF
	sgio_bitmap_set(0xBA,           R                    , read);  // SCAN
	sgio_bitmap_set(0xBD,           R                    , read);  // MECHANISM STATUS
	sgio_bitmap_set(0xBE,           R                    , read);  // READ CD

	sgio_bitmap_set(0xB6,           R                    , write); // SET STREAMING
	sgio_bitmap_set(0x53,           R                    , write); // RESERVE TRACK
	sgio_bitmap_set(0x54,           R                    , write); // SEND OPC INFORMATION
	sgio_bitmap_set(0x58,           R                    , write); // REPAIR TRACK
	sgio_bitmap_set(0x5B,           R                    , write); // CLOSE TRACK/SESSION
	sgio_bitmap_set(0x5D,           R                    , write); // SEND CUE SHEET
	sgio_bitmap_set(0xA1,           R                    , write); // BLANK
	sgio_bitmap_set(0xA2,           R                    , write); // SEND EVENT
	sgio_bitmap_set(0xA3,           R                    , write); // SEND KEY
	sgio_bitmap_set(0xA6,           R                    , write); // LOAD/UNLOAD C/DVD
	sgio_bitmap_set(0xA7,           R                    , write); // SET READ AHEAD
	sgio_bitmap_set(0xBB,           R                    , write); // SET CD SPEED
	sgio_bitmap_set(0xBF,           R                    , write); // SEND DVD STRUCTURE

	/* (mostly) tape */

	sgio_bitmap_set(0x01,   T                            , read);  // REWIND
	sgio_bitmap_set(0x05,   T                            , read);  // READ BLOCK LIMITS
	sgio_bitmap_set(0x0F,   T                            , read);  // READ REVERSE(6)
	sgio_bitmap_set(0x13,   T                            , read);  // VERIFY(6)
	sgio_bitmap_set(0x2B,   T                            , read);  // LOCATE(10)
	sgio_bitmap_set(0x34,   T                            , read);  // READ POSITION
	sgio_bitmap_set(0x44,   T|                    V      , read);  // REPORT DENSITY SUPPORT
	sgio_bitmap_set(0x81,   T                            , read);  // READ REVERSE(16)
	sgio_bitmap_set(0x92,   T                            , read);  // LOCATE(16)

	sgio_bitmap_set(0x04,   T                            , write); // FORMAT MEDIUM
	sgio_bitmap_set(0x0B,   T                            , write); // SET CAPACITY
	sgio_bitmap_set(0x10,   T                            , write); // WRITE FILEMARKS(6)
	sgio_bitmap_set(0x11,   T                            , write); // SPACE(6)
	sgio_bitmap_set(0x14,   T|L                          , write); // RECOVER BUFFERED DATA
	sgio_bitmap_set(0x19,   T                            , write); // ERASE(6)
	sgio_bitmap_set(0x1B,   T|                    V      , write); // LOAD UNLOAD
	sgio_bitmap_set(0x80,   T                            , write); // WRITE FILEMARKS(16)
	sgio_bitmap_set(0x82,   T                            , write); // ALLOW OVERWRITE
	sgio_bitmap_set(0x91,   T                            , write); // SPACE(16)
	sgio_bitmap_set(0x93,   T                            , write); // ERASE(16)

	/* various obsolete */

	sgio_bitmap_set(0x0B, D|      W|R|O                  , read);  // SEEK(6)
	sgio_bitmap_set(0x2B, D|      W|R|O|        K        , read);  // SEEK(10)
	sgio_bitmap_set(0x30, D|      W|R|O                  , read);  // SEARCH DATA HIGH(10)
	sgio_bitmap_set(0x31, D|      W|R|O                  , read);  // SEARCH DATA EQUAL(10)
	sgio_bitmap_set(0x32, D|      W|R|O                  , read);  // SEARCH DATA LOW(10)
	sgio_bitmap_set(0x39, D|T|L|P|W|R|O|        K        , read);  // COMPARE
	sgio_bitmap_set(0x52, D                              , read);  // XDREAD(10)
	sgio_bitmap_set(0xB0,         W|R|O                  , read);  // SEARCH DATA HIGH(12)
	sgio_bitmap_set(0xB1,         W|R|O                  , read);  // SEARCH DATA EQUAL(12)
	sgio_bitmap_set(0xB2,         W|R|O                  , read);  // SEARCH DATA LOW(12)
	sgio_bitmap_set(0xB4, D|T|    W|R|O                  , read);  // READ ELEMENT STATUS ATTACHED
	sgio_bitmap_set(0xB8,   T|    W|R|O|M                , read);  // READ ELEMENT STATUS

	sgio_bitmap_set(0x01, D|      W|R|O|M                , write); // REZERO UNIT
	sgio_bitmap_set(0x18, D|T|L|P|W|R|O|        K        , write); // COPY
	sgio_bitmap_set(0x3A, D|T|L|P|W|R|O|        K        , write); // COPY AND VERIFY
	sgio_bitmap_set(0x50, D                              , write); // XDWRITE(10)
	sgio_bitmap_set(0x80, D                              , write); // XDWRITE EXTENDED(16)

	/* communication devices (obsolete) */

	sgio_bitmap_set(0x08,                             C  , write); // GET MESSAGE(6)
	sgio_bitmap_set(0x0A,                             C  , write); // SEND MESSAGE(6)
	sgio_bitmap_set(0x28,                             C  , write); // GET MESSAGE(10)
	sgio_bitmap_set(0x2A,                             C  , write); // SEND MESSAGE(10)
	sgio_bitmap_set(0xA8,                             C  , write); // GET MESSAGE(12)
	sgio_bitmap_set(0xAA,                             C  , write); // SEND MESSAGE(12)

	/* scanners (obsolete) */

	sgio_bitmap_set(0x1B,                               S, write); // SCAN
	sgio_bitmap_set(0x24,                               S, write); // SET WINDOW
	sgio_bitmap_set(0x25,                               S, write); // GET WINDOW
	sgio_bitmap_set(0x2A,                               S, write); // SEND(10)
	sgio_bitmap_set(0x31,                               S, write); // OBJECT POSITION
	sgio_bitmap_set(0x34,                               S, write); // GET DATA BUFFER STATUS

#if 0
	/*
	 * Starting from here are commands that are always privileged.
	 * I'm listing them anyway, as a reference to the version of
	 * the command list that I used.
	 */

	/* control, privileged, universal except possibly RBC */

	sgio_bitmap_set(0x1D,                    ~B          , write); // SEND DIAGNOSTIC
	sgio_bitmap_set(0x3B, -1                             , write); // WRITE BUFFER
	sgio_bitmap_set(0x3C,                    ~B          , write); // READ BUFFER

	/* control, privileged */

	sgio_bitmap_set(0x5E, D|T|L|P|W|  O|M|A|E|      F    , write); // PERSISTENT RESERVE IN
	sgio_bitmap_set(0x5F, D|T|L|P|W|  O|M|A|E|      F    , write); // PERSISTENT RESERVE OUT
	sgio_bitmap_set(0x83, D|T|L|P|W|  O|        K|V      , write); // Third-party Copy OUT
	sgio_bitmap_set(0x84, D|T|L|P|W|  O|        K|V      , write); // Third-party Copy IN
	sgio_bitmap_set(0x86, D|T|  P|W|  O|M|A|E|B|K|V      , write); // ACCESS CONTROL IN
	sgio_bitmap_set(0x87, D|T|  P|W|  O|M|A|E|B|K|V      , write); // ACCESS CONTROL OUT
	sgio_bitmap_set(0x8C, D|T|    W|  O|M|    B|  V      , write); // READ ATTRIBUTE
	sgio_bitmap_set(0x8D, D|T|    W|  O|M|    B|  V      , write); // WRITE ATTRIBUTE
	sgio_bitmap_set(0xA2, D|T|      R|            V      , write); // SECURITY PROTOCOL IN
	sgio_bitmap_set(0xA3, D|T|L|  W|  O|M|A|E|B|K|V      , write); // MAINTENANCE IN
	sgio_bitmap_set(0xA4, D|T|L|  W|  O|M|A|E|B|K|V      , write); // MAINTENANCE OUT
	sgio_bitmap_set(0xA9,                         V      , write); // SERVICE ACTION OUT(12)
	sgio_bitmap_set(0xB5, D|T|      R|            V      , write); // SECURITY PROTOCOL OUT
	sgio_bitmap_set(0xBA, D|      W|  O|M|A|E            , write); // REDUNDANCY GROUP (IN)
	sgio_bitmap_set(0xBB, D|      W|  O|M|A|E            , write); // REDUNDANCY GROUP (OUT)
	sgio_bitmap_set(0xBC, D|      W|  O|M|A|E            , write); // SPARE (IN)
	sgio_bitmap_set(0xBD, D|      W|  O|M|A|E            , write); // SPARE (OUT)
	sgio_bitmap_set(0xBE, D|      W|  O|M|A|E            , write); // VOLUME SET (IN)
	sgio_bitmap_set(0xBF, D|      W|  O|M|A|E            , write); // VOLUME SET (OUT)

	/* control, privileged, obsolete */

	sgio_bitmap_set(0x16, D|T|L|P|W|  O|M|A|E|  K        , write); // RESERVE(6)
	sgio_bitmap_set(0x16,               M                , write); // RESERVE ELEMENT(6)
	sgio_bitmap_set(0x17, D|T|L|P|W|  O|M|A|E|  K        , write); // RELEASE(6)
	sgio_bitmap_set(0x17,               M                , write); // RELEASE ELEMENT(6)
	sgio_bitmap_set(0x33, D|      W|R|O                  , write); // SET LIMITS(10)
	sgio_bitmap_set(0x36, D|      W|  O|        K        , write); // LOCK UNLOCK CACHE(10)
	sgio_bitmap_set(0x40, D|T|L|P|W|R|O|M                , write); // CHANGE DEFINITION
	sgio_bitmap_set(0x56, D|T|L|P|W|  O|M|A|E            , write); // RESERVE(10)
	sgio_bitmap_set(0x56,               M                , write); // RESERVE ELEMENT(10)
	sgio_bitmap_set(0x57, D|T|L|P|W|  O|M|A|E            , write); // RELEASE(10)
	sgio_bitmap_set(0x57,               M                , write); // RELEASE ELEMENT(10)
	sgio_bitmap_set(0x81, D                              , write); // REBUILD(16)
	sgio_bitmap_set(0x82, D                              , write); // REGENERATE(16)
	sgio_bitmap_set(0x92, D|      W|  O                  , write); // LOCK UNLOCK CACHE(16)
	sgio_bitmap_set(0xA5,   T|    W|  O|M                , write); // MOVE MEDIUM
	sgio_bitmap_set(0xA7, D|T|    W|  O                  , write); // MOVE MEDIUM ATTACHED
	sgio_bitmap_set(0xB3, D|      W|R|O                  , write); // SET LIMITS(12)

	/* others: multiplexed */

	sgio_bitmap_set(0x7E, D|T|      R|  M|A|E|B|  V      , write); // extended CDB
	sgio_bitmap_set(0x7F, D|                        F    , write); // variable length CDB
	sgio_bitmap_set(0x9F,                         V      , write); // SERVICE ACTION OUT(16)

	/* others: vendor specific */

	sgio_bitmap_set(0x01,     L                          , write);
	sgio_bitmap_set(0x02, D|T|L|P|W|R|  M                , write);
	sgio_bitmap_set(0x05, D|  L|P|W|R|  M                , write);
	sgio_bitmap_set(0x06, D|T|L|P|W|R|  M                , write);
	sgio_bitmap_set(0x07,   T|L                          , write);
	sgio_bitmap_set(0x08,     L|        M                , write);
	sgio_bitmap_set(0x09, D|T|L|P|W|R|  M                , write);
	sgio_bitmap_set(0x0A,               M                , write);
	sgio_bitmap_set(0x0B,               M                , write);
	sgio_bitmap_set(0x0C, D|T|L|P|W|R|  M                , write);
	sgio_bitmap_set(0x0D, D|T|L|P|W|R|  M                , write);
	sgio_bitmap_set(0x0E, D|T|L|P|W|R|  M                , write);
	sgio_bitmap_set(0x0F, D|  L|P|W|R|  M                , write);
	sgio_bitmap_set(0x10, D|    P|W|R                    , write);
	sgio_bitmap_set(0x11, D|  L|P|W|R                    , write);
	sgio_bitmap_set(0x13, D|  L|P|W|R                    , write);
	sgio_bitmap_set(0x14, D|    P|W|R                    , write);
	sgio_bitmap_set(0x19, D|  L|P|W|R                    , write);
	sgio_bitmap_set(0x20, D|      W|R|O|        K        , write);
	sgio_bitmap_set(0x21, D|      W|R|O|        K        , write);
	sgio_bitmap_set(0x22, D|      W|R|O|        K        , write);
	sgio_bitmap_set(0x23, D|      W|  O|        K        , write);
	sgio_bitmap_set(0x24, D|      W|R                    , write);
	sgio_bitmap_set(0x26, D|      W|R                    , write);
	sgio_bitmap_set(0x27, D|      W|R                    , write);
	sgio_bitmap_set(0x2D, D                              , write);

	/* others: reserved */

	sgio_bitmap_set(0x1F, 0                              , write);
	sgio_bitmap_set(0x49, 0                              , write);
	sgio_bitmap_set(0x4F, 0                              , write);
	sgio_bitmap_set(0x59, 0                              , write);
	sgio_bitmap_set(0x98, 0                              , write);
	sgio_bitmap_set(0x99, 0                              , write);
	sgio_bitmap_set(0x9A, 0                              , write);
	sgio_bitmap_set(0x9B, 0                              , write);
	sgio_bitmap_set(0x9C, 0                              , write);
	sgio_bitmap_set(0x9D, 0                              , write); //       SERVICE ACTION BIDIRECTIONAL
#endif

#undef D
#undef T
#undef L
#undef P
#undef W
#undef R
#undef S
#undef O
#undef M
#undef C
#undef A
#undef E
#undef B
#undef K
#undef V
#undef F
#undef sgio_bitmap_set
}

int blk_verify_command(struct request_queue *q,
		       unsigned char *cmd, fmode_t has_write_perm)
{
	struct blk_cmd_filter *filter = &blk_default_cmd_filter;

	/* root can do any command. */
	if (capable(CAP_SYS_RAWIO) || blk_queue_unpriv_sgio(q))
		return 0;

	/* Anybody who can open the device can do a read-safe command */
	if (filter->read_ok[cmd[0]] & (1 << q->sgio_type))
		return 0;

	/* Write-safe commands require a writable open */
	if (has_write_perm && filter->write_ok[cmd[0]] & (1 << q->sgio_type))
		return 0;

	return -EPERM;
}
EXPORT_SYMBOL(blk_verify_command);

static int blk_fill_sghdr_rq(struct request_queue *q, struct request *rq,
			     struct sg_io_hdr *hdr, fmode_t mode)
{
	if (copy_from_user(rq->cmd, hdr->cmdp, hdr->cmd_len))
		return -EFAULT;
	if (blk_verify_command(q, rq->cmd, mode & FMODE_WRITE))
		return -EPERM;

	/*
	 * fill in request structure
	 */
	rq->cmd_len = hdr->cmd_len;
	rq->cmd_type = REQ_TYPE_BLOCK_PC;

	rq->timeout = msecs_to_jiffies(hdr->timeout);
	if (!rq->timeout)
		rq->timeout = q->sg_timeout;
	if (!rq->timeout)
		rq->timeout = BLK_DEFAULT_SG_TIMEOUT;
	if (rq->timeout < BLK_MIN_SG_TIMEOUT)
		rq->timeout = BLK_MIN_SG_TIMEOUT;

	return 0;
}

static int blk_complete_sghdr_rq(struct request *rq, struct sg_io_hdr *hdr,
				 struct bio *bio)
{
	int r, ret = 0;

	/*
	 * fill in all the output members
	 */
	hdr->status = rq->errors & 0xff;
	hdr->masked_status = status_byte(rq->errors);
	hdr->msg_status = msg_byte(rq->errors);
	hdr->host_status = host_byte(rq->errors);
	hdr->driver_status = driver_byte(rq->errors);
	hdr->info = 0;
	if (hdr->masked_status || hdr->host_status || hdr->driver_status)
		hdr->info |= SG_INFO_CHECK;
	hdr->resid = rq->resid_len;
	hdr->sb_len_wr = 0;

	if (rq->sense_len && hdr->sbp) {
		int len = min((unsigned int) hdr->mx_sb_len, rq->sense_len);

		if (!copy_to_user(hdr->sbp, rq->sense, len))
			hdr->sb_len_wr = len;
		else
			ret = -EFAULT;
	}

	r = blk_rq_unmap_user(bio);
	if (!ret)
		ret = r;
	blk_put_request(rq);

	return ret;
}

static int sg_io(struct request_queue *q, struct gendisk *bd_disk,
		struct sg_io_hdr *hdr, fmode_t mode)
{
	unsigned long start_time;
	int writing = 0, ret = 0;
	struct request *rq;
	char sense[SCSI_SENSE_BUFFERSIZE];
	struct bio *bio;

	if (hdr->interface_id != 'S')
		return -EINVAL;
	if (hdr->cmd_len > BLK_MAX_CDB)
		return -EINVAL;

	if (hdr->dxfer_len > (queue_max_hw_sectors(q) << 9))
		return -EIO;

	if (hdr->dxfer_len)
		switch (hdr->dxfer_direction) {
		default:
			return -EINVAL;
		case SG_DXFER_TO_DEV:
			writing = 1;
			break;
		case SG_DXFER_TO_FROM_DEV:
		case SG_DXFER_FROM_DEV:
			break;
		}

	rq = blk_get_request(q, writing ? WRITE : READ, GFP_KERNEL);
	if (!rq)
		return -ENODEV;

	if (blk_fill_sghdr_rq(q, rq, hdr, mode)) {
		blk_put_request(rq);
		return -EFAULT;
	}

	if (hdr->iovec_count) {
		const int size = sizeof(struct sg_iovec) * hdr->iovec_count;
		size_t iov_data_len;
		struct sg_iovec *iov;

		iov = kmalloc(size, GFP_KERNEL);
		if (!iov) {
			ret = -ENOMEM;
			goto out;
		}

		if (copy_from_user(iov, hdr->dxferp, size)) {
			kfree(iov);
			ret = -EFAULT;
			goto out;
		}

		/* SG_IO howto says that the shorter of the two wins */
		iov_data_len = iov_length((struct iovec *)iov,
					  hdr->iovec_count);
		if (hdr->dxfer_len < iov_data_len) {
			hdr->iovec_count = iov_shorten((struct iovec *)iov,
						       hdr->iovec_count,
						       hdr->dxfer_len);
			iov_data_len = hdr->dxfer_len;
		}

		ret = blk_rq_map_user_iov(q, rq, NULL, iov, hdr->iovec_count,
					  iov_data_len, GFP_KERNEL);
		kfree(iov);
	} else if (hdr->dxfer_len)
		ret = blk_rq_map_user(q, rq, NULL, hdr->dxferp, hdr->dxfer_len,
				      GFP_KERNEL);

	if (ret)
		goto out;

	bio = rq->bio;
	memset(sense, 0, sizeof(sense));
	rq->sense = sense;
	rq->sense_len = 0;
	rq->retries = 0;

	start_time = jiffies;

	/* ignore return value. All information is passed back to caller
	 * (if he doesn't check that is his problem).
	 * N.B. a non-zero SCSI status is _not_ necessarily an error.
	 */
	blk_execute_rq(q, bd_disk, rq, 0);

	hdr->duration = jiffies_to_msecs(jiffies - start_time);

	return blk_complete_sghdr_rq(rq, hdr, bio);
out:
	blk_put_request(rq);
	return ret;
}

/**
 * sg_scsi_ioctl  --  handle deprecated SCSI_IOCTL_SEND_COMMAND ioctl
 * @file:	file this ioctl operates on (optional)
 * @q:		request queue to send scsi commands down
 * @disk:	gendisk to operate on (option)
 * @sic:	userspace structure describing the command to perform
 *
 * Send down the scsi command described by @sic to the device below
 * the request queue @q.  If @file is non-NULL it's used to perform
 * fine-grained permission checks that allow users to send down
 * non-destructive SCSI commands.  If the caller has a struct gendisk
 * available it should be passed in as @disk to allow the low level
 * driver to use the information contained in it.  A non-NULL @disk
 * is only allowed if the caller knows that the low level driver doesn't
 * need it (e.g. in the scsi subsystem).
 *
 * Notes:
 *   -  This interface is deprecated - users should use the SG_IO
 *      interface instead, as this is a more flexible approach to
 *      performing SCSI commands on a device.
 *   -  The SCSI command length is determined by examining the 1st byte
 *      of the given command. There is no way to override this.
 *   -  Data transfers are limited to PAGE_SIZE
 *   -  The length (x + y) must be at least OMAX_SB_LEN bytes long to
 *      accommodate the sense buffer when an error occurs.
 *      The sense buffer is truncated to OMAX_SB_LEN (16) bytes so that
 *      old code will not be surprised.
 *   -  If a Unix error occurs (e.g. ENOMEM) then the user will receive
 *      a negative return and the Unix error code in 'errno'.
 *      If the SCSI command succeeds then 0 is returned.
 *      Positive numbers returned are the compacted SCSI error codes (4
 *      bytes in one int) where the lowest byte is the SCSI status.
 */
#define OMAX_SB_LEN 16          /* For backward compatibility */
int sg_scsi_ioctl(struct request_queue *q, struct gendisk *disk, fmode_t mode,
		struct scsi_ioctl_command __user *sic)
{
	struct request *rq;
	int err;
	unsigned int in_len, out_len, bytes, opcode, cmdlen;
	char *buffer = NULL, sense[SCSI_SENSE_BUFFERSIZE];

	if (!sic)
		return -EINVAL;

	/*
	 * get in an out lengths, verify they don't exceed a page worth of data
	 */
	if (get_user(in_len, &sic->inlen))
		return -EFAULT;
	if (get_user(out_len, &sic->outlen))
		return -EFAULT;
	if (in_len > PAGE_SIZE || out_len > PAGE_SIZE)
		return -EINVAL;
	if (get_user(opcode, sic->data))
		return -EFAULT;

	bytes = max(in_len, out_len);
	if (bytes) {
		buffer = kzalloc(bytes, q->bounce_gfp | GFP_USER| __GFP_NOWARN);
		if (!buffer)
			return -ENOMEM;

	}

	rq = blk_get_request(q, in_len ? WRITE : READ, __GFP_WAIT);
	if (!rq) {
		kfree(buffer);
		return -ENODEV;
	}

	cmdlen = COMMAND_SIZE(opcode);

	/*
	 * get command and data to send to device, if any
	 */
	err = -EFAULT;
	rq->cmd_len = cmdlen;
	if (copy_from_user(rq->cmd, sic->data, cmdlen))
		goto error;

	if (in_len && copy_from_user(buffer, sic->data + cmdlen, in_len))
		goto error;

	err = blk_verify_command(q, rq->cmd, mode & FMODE_WRITE);
	if (err)
		goto error;

	/* default.  possible overriden later */
	rq->retries = 5;

	switch (opcode) {
	case SEND_DIAGNOSTIC:
	case FORMAT_UNIT:
		rq->timeout = FORMAT_UNIT_TIMEOUT;
		rq->retries = 1;
		break;
	case START_STOP:
		rq->timeout = START_STOP_TIMEOUT;
		break;
	case MOVE_MEDIUM:
		rq->timeout = MOVE_MEDIUM_TIMEOUT;
		break;
	case READ_ELEMENT_STATUS:
		rq->timeout = READ_ELEMENT_STATUS_TIMEOUT;
		break;
	case READ_DEFECT_DATA:
		rq->timeout = READ_DEFECT_DATA_TIMEOUT;
		rq->retries = 1;
		break;
	default:
		rq->timeout = BLK_DEFAULT_SG_TIMEOUT;
		break;
	}

	if (bytes && blk_rq_map_kern(q, rq, buffer, bytes, __GFP_WAIT)) {
		err = DRIVER_ERROR << 24;
		goto out;
	}

	memset(sense, 0, sizeof(sense));
	rq->sense = sense;
	rq->sense_len = 0;
	rq->cmd_type = REQ_TYPE_BLOCK_PC;

	blk_execute_rq(q, disk, rq, 0);

out:
	err = rq->errors & 0xff;	/* only 8 bit SCSI status */
	if (err) {
		if (rq->sense_len && rq->sense) {
			bytes = (OMAX_SB_LEN > rq->sense_len) ?
				rq->sense_len : OMAX_SB_LEN;
			if (copy_to_user(sic->data, rq->sense, bytes))
				err = -EFAULT;
		}
	} else {
		if (copy_to_user(sic->data, buffer, out_len))
			err = -EFAULT;
	}
	
error:
	kfree(buffer);
	blk_put_request(rq);
	return err;
}
EXPORT_SYMBOL_GPL(sg_scsi_ioctl);

/* Send basic block requests */
static int __blk_send_generic(struct request_queue *q, struct gendisk *bd_disk,
			      int cmd, int data)
{
	struct request *rq;
	int err;

	rq = blk_get_request(q, WRITE, __GFP_WAIT);
	if (!rq)
		return -ENODEV;
	rq->cmd_type = REQ_TYPE_BLOCK_PC;
	rq->timeout = BLK_DEFAULT_SG_TIMEOUT;
	rq->cmd[0] = cmd;
	rq->cmd[4] = data;
	rq->cmd_len = 6;
	err = blk_execute_rq(q, bd_disk, rq, 0);
	blk_put_request(rq);

	return err;
}

static inline int blk_send_start_stop(struct request_queue *q,
				      struct gendisk *bd_disk, int data)
{
	return __blk_send_generic(q, bd_disk, GPCMD_START_STOP_UNIT, data);
}

int scsi_cmd_ioctl(struct request_queue *q, struct gendisk *bd_disk, fmode_t mode,
		   unsigned int cmd, void __user *arg)
{
	int err;

	if (!q)
		return -ENXIO;

	switch (cmd) {
		/*
		 * new sgv3 interface
		 */
		case SG_GET_VERSION_NUM:
			err = sg_get_version(arg);
			break;
		case SCSI_IOCTL_GET_IDLUN:
			err = scsi_get_idlun(q, arg);
			break;
		case SCSI_IOCTL_GET_BUS_NUMBER:
			err = scsi_get_bus(q, arg);
			break;
		case SG_SET_TIMEOUT:
			err = sg_set_timeout(q, arg);
			break;
		case SG_GET_TIMEOUT:
			err = sg_get_timeout(q);
			break;
		case SG_GET_RESERVED_SIZE:
			err = sg_get_reserved_size(q, arg);
			break;
		case SG_SET_RESERVED_SIZE:
			err = sg_set_reserved_size(q, arg);
			break;
		case SG_EMULATED_HOST:
			err = sg_emulated_host(q, arg);
			break;
		case SG_IO: {
			struct sg_io_hdr hdr;

			err = -EFAULT;
			if (copy_from_user(&hdr, arg, sizeof(hdr)))
				break;
			err = sg_io(q, bd_disk, &hdr, mode);
			if (err == -EFAULT)
				break;

			if (copy_to_user(arg, &hdr, sizeof(hdr)))
				err = -EFAULT;
			break;
		}
		case CDROM_SEND_PACKET: {
			struct cdrom_generic_command cgc;
			struct sg_io_hdr hdr;

			err = -EFAULT;
			if (copy_from_user(&cgc, arg, sizeof(cgc)))
				break;
			cgc.timeout = clock_t_to_jiffies(cgc.timeout);
			memset(&hdr, 0, sizeof(hdr));
			hdr.interface_id = 'S';
			hdr.cmd_len = sizeof(cgc.cmd);
			hdr.dxfer_len = cgc.buflen;
			err = 0;
			switch (cgc.data_direction) {
				case CGC_DATA_UNKNOWN:
					hdr.dxfer_direction = SG_DXFER_UNKNOWN;
					break;
				case CGC_DATA_WRITE:
					hdr.dxfer_direction = SG_DXFER_TO_DEV;
					break;
				case CGC_DATA_READ:
					hdr.dxfer_direction = SG_DXFER_FROM_DEV;
					break;
				case CGC_DATA_NONE:
					hdr.dxfer_direction = SG_DXFER_NONE;
					break;
				default:
					err = -EINVAL;
			}
			if (err)
				break;

			hdr.dxferp = cgc.buffer;
			hdr.sbp = cgc.sense;
			if (hdr.sbp)
				hdr.mx_sb_len = sizeof(struct request_sense);
			hdr.timeout = jiffies_to_msecs(cgc.timeout);
			hdr.cmdp = ((struct cdrom_generic_command __user*) arg)->cmd;
			hdr.cmd_len = sizeof(cgc.cmd);

			err = sg_io(q, bd_disk, &hdr, mode);
			if (err == -EFAULT)
				break;

			if (hdr.status)
				err = -EIO;

			cgc.stat = err;
			cgc.buflen = hdr.resid;
			if (copy_to_user(arg, &cgc, sizeof(cgc)))
				err = -EFAULT;

			break;
		}

		/*
		 * old junk scsi send command ioctl
		 */
		case SCSI_IOCTL_SEND_COMMAND:
			printk(KERN_WARNING "program %s is using a deprecated SCSI ioctl, please convert it to SG_IO\n", current->comm);
			err = -EINVAL;
			if (!arg)
				break;

			err = sg_scsi_ioctl(q, bd_disk, mode, arg);
			break;
		case CDROMCLOSETRAY:
			err = blk_send_start_stop(q, bd_disk, 0x03);
			break;
		case CDROMEJECT:
			err = blk_send_start_stop(q, bd_disk, 0x02);
			break;
		default:
			err = -ENOTTY;
	}

	return err;
}
EXPORT_SYMBOL(scsi_cmd_ioctl);

int scsi_verify_blk_ioctl(struct block_device *bd, unsigned int cmd)
{
	if (bd && bd == bd->bd_contains)
		return 0;

	/* Actually none of this is particularly useful on a partition
	 * device, but let's play it safe.
	 */
	switch (cmd) {
	case SCSI_IOCTL_GET_IDLUN:
	case SCSI_IOCTL_GET_BUS_NUMBER:
	case SCSI_IOCTL_GET_PCI:
	case SCSI_IOCTL_PROBE_HOST:
	case SG_GET_VERSION_NUM:
	case SG_SET_TIMEOUT:
	case SG_GET_TIMEOUT:
	case SG_GET_RESERVED_SIZE:
	case SG_SET_RESERVED_SIZE:
	case SG_EMULATED_HOST:
		return 0;
	default:
		break;
	}
	/* In particular, rule out all resets and host-specific ioctls.  */
	return -ENOTTY;
}
EXPORT_SYMBOL(scsi_verify_blk_ioctl);

int scsi_cmd_blk_ioctl(struct block_device *bd, fmode_t mode,
		       unsigned int cmd, void __user *arg)
{
	int ret;

	ret = scsi_verify_blk_ioctl(bd, cmd);
	if (ret < 0)
		return ret;

	return scsi_cmd_ioctl(bd->bd_disk->queue, bd->bd_disk, mode, cmd, arg);
}
EXPORT_SYMBOL(scsi_cmd_blk_ioctl);

int __init blk_scsi_ioctl_init(void)
{
	blk_set_cmd_filter_defaults(&blk_default_cmd_filter);
	return 0;
}
fs_initcall(blk_scsi_ioctl_init);

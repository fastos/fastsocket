/*
 * carl9170 firmware - used by the ar9170 wireless device
 *
 * USB definitions
 *
 * Copyright (c) 2000-2005 ZyDAS Technology Corporation
 * Copyright (c) 2007-2009 Atheros Communications, Inc.
 * Copyright	2009	Johannes Berg <johannes@sipsolutions.net>
 * Copyright 2009-2011	Christian Lamparter <chunkeey@googlemail.com>
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

#ifndef __CARL9170FW_USB_FIFO_H
#define __CARL9170FW_USB_FIFO_H

#include "config.h"

#define MASK_F0             0xf0

/* Block Size define */
#define BLK512BYTE      1
#define BLK1024BYTE     2

#define BLK64BYTE       1
#define BLK128BYTE      2

/* Block toggle number define */
#define SINGLE_BLK      1
#define DOUBLE_BLK      2
#define TRIBLE_BLK      3

/* Endpoint transfer type */
#define TF_TYPE_ISOCHRONOUS     1
#define TF_TYPE_BULK            2
#define TF_TYPE_INTERRUPT       3

/* Endpoint or FIFO direction define */
#define DIRECTION_IN    0
#define DIRECTION_OUT   1

#define HS_C1_I0_A0_EP1_MAX_PACKET              512
#define HS_C1_I0_A0_EP1_bInterval               0

#define HS_C1_I0_A0_EP_NUMBER                   0x04
#define HS_C1_I0_A0_EP_LENGTH                   (EP_LENGTH * HS_C1_I0_A0_EP_NUMBER)
#define HS_C1_I0_ALT_LENGTH                     (HS_C1_I0_A0_EP_LENGTH)
#define HS_C1_INTERFACE_LENGTH                  (HS_C1_I0_ALT_LENGTH)

#define HS_C1_CONFIG_TOTAL_LENGTH               (CONFIG_LENGTH + INTERFACE_LENGTH +  HS_C1_INTERFACE_LENGTH)
#define FS_C1_CONFIG_TOTAL_LENGTH               (CONFIG_LENGTH + INTERFACE_LENGTH +  FS_C1_INTERFACE_LENGTH)

#define FS_C1_I0_A0_EP1_MAX_PACKET              64
/* #define FS_C1_I0_A0_EP1_bInterval               HS_C1_I0_A0_EP1_bInterval */

#define HS_CONFIGURATION_NUMBER                 1
#define FS_CONFIGURATION_NUMBER                 1

#define fDOUBLE_BUF                             1
#define fDOUBLE_BUF_IN                          0

#define fFLASH_DISK                             0
#define fENABLE_ISO                             0

#define HS_C1_INTERFACE_NUMBER  0x01
#define HS_C1                   0x01
#define HS_C1_iConfiguration    0x00
#define HS_C1_bmAttribute       0x80

#define HS_C1_iMaxPower         0xFA

/* Interface 0 */
#define HS_C1_I0_ALT_NUMBER    0X01
/* AlternateSetting 0 */
#define HS_C1_I0_A0_bInterfaceNumber	0x00
#define HS_C1_I0_A0_bAlternateSetting	0x00
/* JWEI 2003/07/14 */
#define HS_C1_I0_A0_EP_NUMBER		0x04
#define HS_C1_I0_A0_bInterfaceClass	0xff
#define HS_C1_I0_A0_bInterfaceSubClass	0x00
#define HS_C1_I0_A0_bInterfaceProtocol	0x00
#define HS_C1_I0_A0_iInterface		0x00

/* EP 1 */
#define HS_C1_I0_A0_EP1_BLKSIZE    512
#define HS_C1_I0_A0_EP1_BLKNO      DOUBLE_BLK
#define HS_C1_I0_A0_EP1_DIRECTION  DIRECTION_OUT
#define HS_C1_I0_A0_EP1_TYPE       TF_TYPE_BULK

#define HS_C1_I0_A0_EP1_MAX_PACKET 512
#define HS_C1_I0_A0_EP1_bInterval  0

/* EP 2 */
#define HS_C1_I0_A0_EP2_BLKSIZE    512
/* JWEI 2003/08/20 */
#define HS_C1_I0_A0_EP2_BLKNO      SINGLE_BLK
#define HS_C1_I0_A0_EP2_DIRECTION  DIRECTION_IN
#define HS_C1_I0_A0_EP2_TYPE       TF_TYPE_BULK
#define HS_C1_I0_A0_EP2_MAX_PACKET 512
#define HS_C1_I0_A0_EP2_bInterval  0

/* EP 3 */
#define HS_C1_I0_A0_EP3_BLKSIZE    64
#define HS_C1_I0_A0_EP3_BLKNO      SINGLE_BLK
#define HS_C1_I0_A0_EP3_DIRECTION  DIRECTION_IN
#define HS_C1_I0_A0_EP3_TYPE       TF_TYPE_INTERRUPT
#define HS_C1_I0_A0_EP3_MAX_PACKET 0x0040
#define HS_C1_I0_A0_EP3_bInterval  01

/*
 * Note: HS Bulk type require max pkt size = 512
 *       ==> must use Interrupt type for max pkt size = 64
 */

/* EP 4 */
#define HS_C1_I0_A0_EP4_BLKSIZE    64
#define HS_C1_I0_A0_EP4_BLKNO      SINGLE_BLK
#define HS_C1_I0_A0_EP4_DIRECTION  DIRECTION_OUT
#define HS_C1_I0_A0_EP4_TYPE       TF_TYPE_INTERRUPT
#define HS_C1_I0_A0_EP4_MAX_PACKET 0x0040
#define HS_C1_I0_A0_EP4_bInterval  01

#define HS_C1_I0_A0_EP_LENGTH           (EP_LENGTH * HS_C1_I0_A0_EP_NUMBER)
/* EP 1 */
#define HS_C1_I0_A0_EP1_FIFO_START  0
#define HS_C1_I0_A0_EP1_FIFO_NO     (HS_C1_I0_A0_EP1_BLKNO * HS_C1_I0_A0_EP1_BLKSIZE)
#define HS_C1_I0_A0_EP1_FIFO_CONFIG (uint8_t)(0x80 | ((HS_C1_I0_A0_EP1_BLKSIZE - 1) << 4) | ((HS_C1_I0_A0_EP1_BLKNO - 1) << 2) | HS_C1_I0_A0_EP1_TYPE)
#define HS_C1_I0_A0_EP1_FIFO_MAP    (((1 - HS_C1_I0_A0_EP1_DIRECTION) << 4) | 1)
#define HS_C1_I0_A0_EP1_MAP         (HS_C1_I0_A0_EP1_FIFO_START |   (HS_C1_I0_A0_EP1_FIFO_START << 4)   | (MASK_F0 >> (4*HS_C1_I0_A0_EP1_DIRECTION)))

/* EP 2 */
#define HS_C1_I0_A0_EP2_FIFO_START  (uint8_t)(HS_C1_I0_A0_EP1_FIFO_START + HS_C1_I0_A0_EP1_FIFO_NO)
#define HS_C1_I0_A0_EP2_FIFO_NO     (uint8_t)(HS_C1_I0_A0_EP2_BLKNO * HS_C1_I0_A0_EP2_BLKSIZE)
#define HS_C1_I0_A0_EP2_FIFO_CONFIG (uint8_t)(0x80 | ((HS_C1_I0_A0_EP2_BLKSIZE - 1) << 4) | ((HS_C1_I0_A0_EP2_BLKNO - 1) << 2) | HS_C1_I0_A0_EP2_TYPE)
#define HS_C1_I0_A0_EP2_FIFO_MAP    (uint8_t)(((1 - HS_C1_I0_A0_EP2_DIRECTION) << 4) | 2)
#define HS_C1_I0_A0_EP2_MAP         (uint8_t)(HS_C1_I0_A0_EP2_FIFO_START |   (HS_C1_I0_A0_EP2_FIFO_START << 4)   | (MASK_F0 >> (4*HS_C1_I0_A0_EP2_DIRECTION)))

/* EP 3 */
#define HS_C1_I0_A0_EP3_FIFO_START  14
#define HS_C1_I0_A0_EP3_FIFO_NO     (HS_C1_I0_A0_EP3_BLKNO * HS_C1_I0_A0_EP3_BLKSIZE)
#define HS_C1_I0_A0_EP3_FIFO_CONFIG (uint8_t)(0x80 | ((HS_C1_I0_A0_EP3_BLKSIZE - 1) << 4) | ((HS_C1_I0_A0_EP3_BLKNO - 1) << 2) | HS_C1_I0_A0_EP3_TYPE)
#define HS_C1_I0_A0_EP3_FIFO_MAP    (uint8_t)(((1 - HS_C1_I0_A0_EP3_DIRECTION) << 4) | 3)
#define HS_C1_I0_A0_EP3_MAP         (uint8_t)(HS_C1_I0_A0_EP3_FIFO_START |   (HS_C1_I0_A0_EP3_FIFO_START << 4)   | (MASK_F0 >> (4*HS_C1_I0_A0_EP3_DIRECTION)))

/* EP 4 */
#define HS_C1_I0_A0_EP4_FIFO_START  (HS_C1_I0_A0_EP3_FIFO_START + HS_C1_I0_A0_EP3_FIFO_NO)
#define HS_C1_I0_A0_EP4_FIFO_NO     (HS_C1_I0_A0_EP4_BLKNO * HS_C1_I0_A0_EP4_BLKSIZE)
#define HS_C1_I0_A0_EP4_FIFO_CONFIG (uint8_t)(0x80 | ((HS_C1_I0_A0_EP4_BLKSIZE - 1) << 4) | ((HS_C1_I0_A0_EP4_BLKNO - 1) << 2) | HS_C1_I0_A0_EP4_TYPE)
#define HS_C1_I0_A0_EP4_FIFO_MAP    (((1 - HS_C1_I0_A0_EP4_DIRECTION) << 4) | 4)
#define HS_C1_I0_A0_EP4_MAP         (uint8_t)(HS_C1_I0_A0_EP4_FIFO_START |   (HS_C1_I0_A0_EP4_FIFO_START << 4)   | (MASK_F0 >> (4*HS_C1_I0_A0_EP4_DIRECTION)))

/* Configuration 1 */
#define FS_C1_INTERFACE_NUMBER		0x01
#define FS_C1				0x01
#define FS_C1_iConfiguration		0x00
#define FS_C1_bmAttribute		0x80
#define FS_C1_iMaxPower			0xfa

/* Interface 0 */
#define FS_C1_I0_ALT_NUMBER		0x01
/* AlternateSetting 0x00 */
#define FS_C1_I0_A0_bInterfaceNumber	0x00
#define FS_C1_I0_A0_bAlternateSetting	0x00
#define FS_C1_I0_A0_EP_NUMBER		0x04
#define FS_C1_I0_A0_bInterfaceClass	0xff
#define FS_C1_I0_A0_bInterfaceSubClass	0x00
#define FS_C1_I0_A0_bInterfaceProtocol	0x00

/* EP 1 */
#define FS_C1_I0_A0_EP1_BLKSIZE    512
/* JWEI 2003/05/19 */
#define FS_C1_I0_A0_EP1_BLKNO      DOUBLE_BLK
#define FS_C1_I0_A0_EP1_DIRECTION  DIRECTION_OUT
#define FS_C1_I0_A0_EP1_TYPE       TF_TYPE_BULK
#define FS_C1_I0_A0_EP1_MAX_PACKET 64
#define FS_C1_I0_A0_EP1_bInterval  0

/* EP 2 */
#define FS_C1_I0_A0_EP2_BLKSIZE    512
/* JWEI 2003/08/20 */
#define FS_C1_I0_A0_EP2_BLKNO      SINGLE_BLK
#define FS_C1_I0_A0_EP2_DIRECTION  DIRECTION_IN
#define FS_C1_I0_A0_EP2_TYPE       TF_TYPE_BULK
#define FS_C1_I0_A0_EP2_MAX_PACKET 64
#define FS_C1_I0_A0_EP2_bInterval  0

/* EP 3 */
#define FS_C1_I0_A0_EP3_BLKSIZE    64
#define FS_C1_I0_A0_EP3_BLKNO      SINGLE_BLK
#define FS_C1_I0_A0_EP3_DIRECTION  DIRECTION_IN
#define FS_C1_I0_A0_EP3_TYPE       TF_TYPE_INTERRUPT
#define FS_C1_I0_A0_EP3_MAX_PACKET 0x0040
#define FS_C1_I0_A0_EP3_bInterval  1

/* EP 4 */
#define FS_C1_I0_A0_EP4_BLKSIZE    64
#define FS_C1_I0_A0_EP4_BLKNO      SINGLE_BLK
#define FS_C1_I0_A0_EP4_DIRECTION  DIRECTION_OUT
#define FS_C1_I0_A0_EP4_TYPE       TF_TYPE_BULK
#define FS_C1_I0_A0_EP4_MAX_PACKET 0x0040
#define FS_C1_I0_A0_EP4_bInterval  0

#define FS_C1_I0_A0_EP_LENGTH           (EP_LENGTH * FS_C1_I0_A0_EP_NUMBER)
/* EP 1 */
#define FS_C1_I0_A0_EP1_FIFO_START  0
#define FS_C1_I0_A0_EP1_FIFO_NO     (uint8_t)(FS_C1_I0_A0_EP1_BLKNO * FS_C1_I0_A0_EP1_BLKSIZE)
#define FS_C1_I0_A0_EP1_FIFO_CONFIG (uint8_t)(0x80 | ((FS_C1_I0_A0_EP1_BLKSIZE - 1) << 4) | ((FS_C1_I0_A0_EP1_BLKNO - 1) << 2) | FS_C1_I0_A0_EP1_TYPE)
#define FS_C1_I0_A0_EP1_FIFO_MAP    (uint8_t)(((1 - FS_C1_I0_A0_EP1_DIRECTION) << 4) | 1)
#define FS_C1_I0_A0_EP1_MAP         (uint8_t)(FS_C1_I0_A0_EP1_FIFO_START |   (FS_C1_I0_A0_EP1_FIFO_START << 4)   | (MASK_F0 >> (4*FS_C1_I0_A0_EP1_DIRECTION)))

/* EP 2 */
#define FS_C1_I0_A0_EP2_FIFO_START  (uint8_t)(FS_C1_I0_A0_EP1_FIFO_START + FS_C1_I0_A0_EP1_FIFO_NO)
#define FS_C1_I0_A0_EP2_FIFO_NO     (uint8_t)(FS_C1_I0_A0_EP2_BLKNO * FS_C1_I0_A0_EP2_BLKSIZE)
#define FS_C1_I0_A0_EP2_FIFO_CONFIG (uint8_t)(0x80 | ((FS_C1_I0_A0_EP2_BLKSIZE - 1) << 4) | ((FS_C1_I0_A0_EP2_BLKNO - 1) << 2) | FS_C1_I0_A0_EP2_TYPE)
#define FS_C1_I0_A0_EP2_FIFO_MAP    (uint8_t)(((1 - FS_C1_I0_A0_EP2_DIRECTION) << 4) | 2)
#define FS_C1_I0_A0_EP2_MAP         (uint8_t)(FS_C1_I0_A0_EP2_FIFO_START |   (FS_C1_I0_A0_EP2_FIFO_START << 4)   | (MASK_F0 >> (4*FS_C1_I0_A0_EP2_DIRECTION)))

/* EP 3 */
#define FS_C1_I0_A0_EP3_FIFO_START  14
#define FS_C1_I0_A0_EP3_FIFO_NO     (uint8_t)(FS_C1_I0_A0_EP3_BLKNO * FS_C1_I0_A0_EP3_BLKSIZE)
#define FS_C1_I0_A0_EP3_FIFO_CONFIG (uint8_t)(0x80 | ((FS_C1_I0_A0_EP3_BLKSIZE - 1) << 4) | ((FS_C1_I0_A0_EP3_BLKNO - 1) << 2) | FS_C1_I0_A0_EP3_TYPE)
#define FS_C1_I0_A0_EP3_FIFO_MAP    (uint8_t)(((1 - FS_C1_I0_A0_EP3_DIRECTION) << 4) | 3)
#define FS_C1_I0_A0_EP3_MAP         (uint8_t)(FS_C1_I0_A0_EP3_FIFO_START |   (FS_C1_I0_A0_EP3_FIFO_START << 4)   | (MASK_F0 >> (4*FS_C1_I0_A0_EP3_DIRECTION)))

/* EP 4 */
#define FS_C1_I0_A0_EP4_FIFO_START  (uint8_t)(FS_C1_I0_A0_EP3_FIFO_START + FS_C1_I0_A0_EP3_FIFO_NO)
#define FS_C1_I0_A0_EP4_FIFO_NO     (uint8_t)(FS_C1_I0_A0_EP4_BLKNO * FS_C1_I0_A0_EP4_BLKSIZE)
#define FS_C1_I0_A0_EP4_FIFO_CONFIG (uint8_t)(0x80 | ((FS_C1_I0_A0_EP4_BLKSIZE - 1) << 4) | ((FS_C1_I0_A0_EP4_BLKNO - 1) << 2) | FS_C1_I0_A0_EP4_TYPE)
#define FS_C1_I0_A0_EP4_FIFO_MAP    (uint8_t)(((1 - FS_C1_I0_A0_EP4_DIRECTION) << 4) | 4)
#define FS_C1_I0_A0_EP4_MAP         (uint8_t)(FS_C1_I0_A0_EP4_FIFO_START |   (FS_C1_I0_A0_EP4_FIFO_START << 4)   | (MASK_F0 >> (4*FS_C1_I0_A0_EP4_DIRECTION)))

#endif /* __CARL9170FW_USB_FIFO_H */

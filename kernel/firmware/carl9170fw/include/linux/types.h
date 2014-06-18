/*
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

#ifndef __LINUX_TYPES_H
#define __LINUX_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/param.h>

#if BYTE_ORDER == BIG_ENDIAN
#error	"big endian is not supported by target"
#endif

typedef uint16_t	__le16;
typedef uint32_t	__le32;
typedef uint64_t	__le64;

typedef uint8_t		u8;
typedef uint8_t		__u8;
typedef uint16_t	u16;
typedef uint16_t	__u16;
typedef uint32_t	u32;
typedef uint32_t	__u32;
typedef uint64_t	u64;
typedef uint64_t	__u64;
typedef int8_t		s8;
typedef int8_t		__s8;
typedef int16_t		s16;
typedef int16_t		__s16;
typedef int32_t		s32;
typedef int32_t		__s32;
typedef int64_t		s64;
typedef int64_t		__s64;

#define cpu_to_le16(x) ((__le16)(uint16_t)(x))
#define le16_to_cpu(x) ((uint16_t)(__le16)(x))
#define cpu_to_le32(x) ((__le32)(uint32_t)(x))
#define le32_to_cpu(x) ((uint32_t)(__le32)(x))
#define cpu_to_le64(x) ((__le64)(uint64_t)(x))
#define le64_to_cpu(x) ((uint64_t)(__le64)(x))

typedef uint16_t	__be16;
typedef uint32_t	__be32;
typedef uint64_t	__be64;

#endif /* __LINUX_TYPES_H */

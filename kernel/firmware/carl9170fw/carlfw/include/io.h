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

#ifndef __CARL9170FW_IO_H
#define __CARL9170FW_IO_H

#include "config.h"
#include "types.h"
#include "compiler.h"

static inline __inline uint8_t readb(const volatile void *addr)
{
	return *(const volatile uint8_t *) addr;
}

static inline __inline uint16_t readw(const volatile void *addr)
{
	return *(const volatile uint16_t *) addr;
}

static inline __inline volatile void *readp(const volatile void *addr)
{
	return *(volatile void **) addr;
}

static inline __inline uint32_t readl(const volatile void *addr)
{
	return *(const volatile unsigned int *) addr;
}

static inline __inline void writeb(volatile void *addr, const volatile uint8_t val)
{
	*(volatile uint8_t *) addr = val;
}

static inline __inline void writew(volatile void *addr, const volatile uint16_t val)
{
	*(volatile uint16_t *) addr = val;
}

static inline __inline void writel(volatile void *addr, const volatile uint32_t val)
{
	*(volatile uint32_t *) addr = val;
}

static inline __inline void __orl(volatile void *addr, const volatile uint32_t val)
{
	*(volatile uint32_t *) addr |= val;
}

static inline __inline void __andl(volatile void *addr, const volatile uint32_t val)
{
	*(volatile uint32_t *) addr &= val;
}

static inline __inline void __xorl(volatile void *addr, const volatile uint32_t val)
{
	*(volatile uint32_t *) addr ^= val;
}

static inline __inline void __incl(volatile void *addr)
{
	(*(volatile uint32_t *)addr)++;
}

static inline __inline uint32_t readl_async(const volatile void *addr)
{
	uint32_t i = 0, read, tmp;

	read = readl(addr);
	do {
		tmp = read;
		tmp = readl(addr);
		i++;
	} while (tmp != read && i <= 10);

	return read;
}

static inline __inline void set(const volatile uint32_t addr, const volatile uint32_t val)
{
	writel((volatile void *) addr, val);
}

static inline __inline void orl(volatile uint32_t addr, const volatile uint32_t val)
{
	__orl((volatile void *) addr, val);
}

static inline __inline void xorl(const volatile uint32_t addr, const volatile uint32_t val)
{
	__xorl((volatile void *) addr, val);
}

static inline __inline void andl(const volatile uint32_t addr, const volatile uint32_t val)
{
	__andl((volatile void *) addr, val);
}

static inline __inline void incl(const volatile uint32_t addr)
{
	__incl((volatile void *) addr);
}

static inline __inline uint32_t get(const volatile uint32_t addr)
{
	return readl((volatile void *) addr);
}

static inline __inline volatile void *getp(const volatile uint32_t addr)
{
	return readp((const volatile void *) addr);
}

static inline __inline uint32_t get_async(const volatile uint32_t addr)
{
	return readl_async((const volatile void *) addr);
}

static inline __inline void setb(const volatile uint32_t addr, const volatile uint8_t val)
{
	writeb((volatile void *) addr, val);
}

static inline __inline uint8_t getb(const volatile uint32_t addr)
{
	return readb((const volatile void *) addr);
}

static inline __inline void andb(const volatile uint32_t addr, const volatile uint8_t val)
{
	setb(addr, getb(addr) & val);
}

static inline __inline void orb(const volatile uint32_t addr, const volatile uint32_t val)
{
	setb(addr, getb(addr) | val);
}

#endif /* __CARL9170FW_IO_H */

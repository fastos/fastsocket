#ifndef _ASM_GENERIC_BITOPS_LE_H_
#define _ASM_GENERIC_BITOPS_LE_H_

#include <asm/types.h>
#include <asm/byteorder.h>

#define BITOP_WORD(nr)		((nr) / BITS_PER_LONG)
#if defined(__LITTLE_ENDIAN)

#define BITOP_LE_SWIZZLE	0

#define generic_test_le_bit(nr, addr) test_bit(nr, addr)
#define generic___set_le_bit(nr, addr) __set_bit(nr, addr)
#define generic___clear_le_bit(nr, addr) __clear_bit(nr, addr)

#define generic_test_and_set_le_bit(nr, addr) test_and_set_bit(nr, addr)
#define generic_test_and_clear_le_bit(nr, addr) test_and_clear_bit(nr, addr)

#define generic___test_and_set_le_bit(nr, addr) __test_and_set_bit(nr, addr)
#define generic___test_and_clear_le_bit(nr, addr) __test_and_clear_bit(nr, addr)

#define generic_find_next_zero_le_bit(addr, size, offset) find_next_zero_bit(addr, size, offset)
#define generic_find_next_le_bit(addr, size, offset) \
			find_next_bit(addr, size, offset)

#elif defined(__BIG_ENDIAN)

#define BITOP_LE_SWIZZLE	((BITS_PER_LONG-1) & ~0x7)

#define generic_test_le_bit(nr, addr) \
	test_bit((nr) ^ BITOP_LE_SWIZZLE, (addr))
#define generic___set_le_bit(nr, addr) \
	__set_bit((nr) ^ BITOP_LE_SWIZZLE, (addr))
#define generic___clear_le_bit(nr, addr) \
	__clear_bit((nr) ^ BITOP_LE_SWIZZLE, (addr))

#define generic_test_and_set_le_bit(nr, addr) \
	test_and_set_bit((nr) ^ BITOP_LE_SWIZZLE, (addr))
#define generic_test_and_clear_le_bit(nr, addr) \
	test_and_clear_bit((nr) ^ BITOP_LE_SWIZZLE, (addr))

#define generic___test_and_set_le_bit(nr, addr) \
	__test_and_set_bit((nr) ^ BITOP_LE_SWIZZLE, (addr))
#define generic___test_and_clear_le_bit(nr, addr) \
	__test_and_clear_bit((nr) ^ BITOP_LE_SWIZZLE, (addr))

extern unsigned long generic_find_next_zero_le_bit(const unsigned long *addr,
		unsigned long size, unsigned long offset);
extern unsigned long generic_find_next_le_bit(const unsigned long *addr,
		unsigned long size, unsigned long offset);

#else
#error "Please fix <asm/byteorder.h>"
#endif

#define generic_find_first_zero_le_bit(addr, size) \
        generic_find_next_zero_le_bit((addr), (size), 0)

/* Compat macros for RHEL6 */
#define find_next_zero_bit_le(addr, size, offset) \
			generic_find_next_zero_le_bit(addr, size, offset)
#define find_next_bit_le(addr, size, offset) \
			generic_find_next_le_bit(addr, size, offset)
#define __set_bit_le(nr, addr) \
	generic___set_le_bit(nr, addr)
#define __clear_bit_le(nr, addr) \
	generic___clear_le_bit(nr, addr)

#define test_bit_le(nr, addr) \
	generic_test_le_bit(nr, addr)
#define set_bit_le(nr, addr) \
	set_bit((nr) ^ BITOP_LE_SWIZZLE, (addr))
#define clear_bit_le(nr, addr) \
	clear_bit((nr) ^ BITOP_LE_SWIZZLE, (addr))

#define test_and_set_bit_le(nr, addr) \
	generic_test_and_set_le_bit(nr, addr)
#define test_and_clear_bit_le(nr, addr) \
	generic_test_and_clear_le_bit(nr, addr)

#define __test_and_set_bit_le(nr, addr) \
	generic___test_and_set_le_bit(nr, addr)
#define __test_and_clear_bit_le(nr, addr) \
	generic___test_and_clear_le_bit(nr, addr)

#endif /* _ASM_GENERIC_BITOPS_LE_H_ */

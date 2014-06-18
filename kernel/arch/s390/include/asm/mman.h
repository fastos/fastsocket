/*
 *  include/asm-s390/mman.h
 *
 *  S390 version
 *
 *  Derived from "include/asm-i386/mman.h"
 */

#ifndef __S390_MMAN_H__
#define __S390_MMAN_H__

#include <asm-generic/mman.h>

#if defined(__KERNEL__) && !defined(__ASSEMBLY__) && defined(CONFIG_64BIT)
int s390_mmap_check(unsigned long addr, unsigned long len, unsigned long flags);
#define arch_mmap_check(addr, len, flags) s390_mmap_check(addr, len, flags)
#endif

#endif /* __S390_MMAN_H__ */

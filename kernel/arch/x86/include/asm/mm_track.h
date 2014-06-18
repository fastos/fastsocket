/*
 * Routines and structures for building a bitmap of
 * dirty pages in a live system.  For use in memory mirroring
 * or migration applications.
 *
 * Copyright (C) 2006, 2010 Stratus Technologies Bermuda Ltd.
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#ifndef __X86_64_MMTRACK_H__
#define __X86_64_MMTRACK_H__

#ifndef CONFIG_TRACK_DIRTY_PAGES

static inline void mm_track_pte(pte_t *ptep)	{}
static inline void mm_track_pmd(pmd_t *pmdp)	{}
static inline void mm_track_pud(pud_t *pudp)	{}
static inline void mm_track_pgd(pgd_t *pgdp) 	{}
static inline void mm_track_phys(void *physp)	{}

#else

#include <asm/page.h>
#include <asm/atomic.h>
 /*
  * For memory-tracking purposes, if active is true (non-zero), the other
  * elements of the structure are available for use.  Each time mm_track_pte
  * is called, it increments count and sets a bit in the bitvector table.
  * Each bit in the bitvector represents a physical page in memory.
  *
  * This is declared in arch/x86_64/mm/track.c.
  *
  * The in_use element is used in the code which drives the memory tracking
  * environment.  When tracking is complete, the vector may be freed, but
  * only after the active flag is set to zero and the in_use count goes to
  * zero.
  *
  * The count element indicates how many pages have been stored in the
  * bitvector.  This is an optimization to avoid counting the bits in the
  * vector between harvest operations.
  */
struct mm_tracker {
	int active;		/* non-zero if this structure in use */
	atomic_t count;		/* number of pages tracked by mm_track() */
	unsigned long *vector;	/* bit vector of modified pages */
	unsigned long bitcnt;	/* number of bits in vector */
};
extern struct mm_tracker mm_tracking_struct;

extern void do_mm_track_pte(void *);
extern void do_mm_track_pmd(void *);
extern void do_mm_track_pud(void *);
extern void do_mm_track_pgd(void *);
extern void do_mm_track_phys(void *);

/*
 * The mm_track routine is needed by macros in pgtable.h
 */
static inline void mm_track_pte(pte_t *ptep)
{
	if (unlikely(mm_tracking_struct.active))
		do_mm_track_pte(ptep);
}
static inline void mm_track_pmd(pmd_t *pmdp)
{
	if (unlikely(mm_tracking_struct.active))
		do_mm_track_pmd(pmdp);
}
static inline void mm_track_pud(pud_t *pudp)
{
	if (unlikely(mm_tracking_struct.active))
		do_mm_track_pud(pudp);
}
static inline void mm_track_pgd(pgd_t *pgdp)
{
	if (unlikely(mm_tracking_struct.active))
		do_mm_track_pgd(pgdp);
}
static inline void mm_track_phys(void *physp)
{
	if (unlikely(mm_tracking_struct.active))
		do_mm_track_phys(physp);
}
#endif /* CONFIG_TRACK_DIRTY_PAGES */

#endif /* __X86_64_MMTRACK_H__ */

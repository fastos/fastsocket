#ifndef _ASM_I386_CRASH_H
#define _ASM_I386_CRASH_H

/*
 * linux/include/asm-i386/crash.h
 *
 * Copyright (c) 2004 Red Hat, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifdef __KERNEL__

#include <linux/mm.h>
#include <linux/highmem.h>
#include <asm/mmzone.h>

#ifdef __i386__
#include <xen/xen.h>
#include <asm/xen/page.h>
#endif

extern int page_is_ram(unsigned long);

static inline void *
map_virtual(u64 offset, struct page **pp)
{
	struct page *page;
	unsigned long pfn;
	void *vaddr;

	pfn = (unsigned long)(offset >> PAGE_SHIFT);

	if (!page_is_ram(pfn)) {
		printk(KERN_INFO
		    "crash memory driver: !page_is_ram(pfn: %lx)\n", pfn);
		return NULL;
	}

	if (!pfn_valid(pfn)) {
		printk(KERN_INFO
		    "crash memory driver: invalid pfn: %lx )\n", pfn);
		return NULL;
	}

#ifdef __i386__
	if (xen_pv_domain() && !phys_to_machine_mapping_valid(pfn)) {
		printk(KERN_INFO "crash memory driver: "
		       "no machine mapping for pfn: %lx\n", pfn);
		return NULL;
	}
#endif

	page = pfn_to_page(pfn);

	vaddr = kmap(page);
	if (!vaddr) {
		printk(KERN_INFO
		    "crash memory driver: pfn: %lx kmap(page: %lx) failed\n", 
			pfn, (unsigned long)page);
		return NULL;
	}

	*pp = page;
	return (vaddr + (offset & (PAGE_SIZE-1)));
}

static inline void unmap_virtual(struct page *page) 
{ 
	kunmap(page);
}

#endif /* __KERNEL__ */

#endif /* _ASM_I386_CRASH_H */

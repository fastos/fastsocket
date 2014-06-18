#ifndef _ASM_IA64_CRASH_H
#define _ASM_IA64_CRASH_H

/*
 * linux/include/asm-ia64/crash.h
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

#include <linux/efi.h>
#include <linux/mm.h>
#include <asm/mmzone.h>

static inline void *
map_virtual(u64 offset, struct page **pp)
{
	struct page *page;
	unsigned long pfn;
	u32 type;

	if (REGION_NUMBER(offset) == 5) {
		char byte;

		if (__get_user(byte, (char *)offset) == 0)
			return (void *)offset;
		else
			return NULL;
	}

	switch (type = efi_mem_type(offset)) 
	{
	case EFI_LOADER_CODE:
	case EFI_LOADER_DATA:
	case EFI_BOOT_SERVICES_CODE:
	case EFI_BOOT_SERVICES_DATA:
	case EFI_CONVENTIONAL_MEMORY:
		break;

	default:
		printk(KERN_INFO
		    "crash memory driver: invalid memory type for %lx: %d\n", 
			offset, type);
		return NULL;
	}

	pfn = offset >> PAGE_SHIFT;

	if (!pfn_valid(pfn)) {
		printk(KERN_INFO
			"crash memory driver: invalid pfn: %lx )\n", pfn);
		return NULL;
	}

	page = pfn_to_page(pfn);

	if (!page->virtual) {
		printk(KERN_INFO
		    "crash memory driver: offset: %lx page: %lx page->virtual: NULL\n", 
			offset, (unsigned long)page);
		return NULL;
	}

	return (page->virtual + (offset & (PAGE_SIZE-1)));
}

static inline void unmap_virtual(struct page *page) 
{ 
	return;
}

#endif /* __KERNEL__ */

#endif /* _ASM_IA64_CRASH_H */

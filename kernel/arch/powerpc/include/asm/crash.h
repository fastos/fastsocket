#ifndef _PPC64_CRASH_H
#define _PPC64_CRASH_H

#ifdef __KERNEL__

#include <linux/mm.h>
#include <linux/highmem.h>


static inline void *map_virtual(u64 offset, struct page **pp)
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

	page = pfn_to_page(pfn);

	vaddr = kmap(page);
	if (!vaddr) {
		printk(KERN_INFO
		    "crash memory driver: pfn: %lx kmap(page: %lx) failed\n",
			pfn, (unsigned long) page);
		return NULL;
	}

	*pp = page;
	return (vaddr + (offset & (PAGE_SIZE - 1)));
}

static inline void unmap_virtual(struct page *page)
{
	kunmap(page);
}

#endif /* __KERNEL__ */

#endif /* _PPC64_CRASH_H */

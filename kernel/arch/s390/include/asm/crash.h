#ifndef _S390_CRASH_H
#define _S390_CRASH_H

#ifdef __KERNEL__

#include <linux/mm.h>
#include <linux/highmem.h>


/*
 * For swapped prefix pages get bounce buffer using xlate_dev_mem_ptr()
 */
static inline void *map_virtual(u64 offset, struct page **pp)
{
	struct page *page;
	unsigned long pfn;
	void *vaddr;

	vaddr = xlate_dev_mem_ptr(offset);
	pfn = ((unsigned long) vaddr) >> PAGE_SHIFT;
	if ((unsigned long) vaddr != offset)
		page = pfn_to_page(pfn);
	else
		page = NULL;

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

	*pp = page;
	return vaddr;
}

/*
 * Free bounce buffer if necessary
 */
static inline void unmap_virtual(struct page *page)
{
	void *vaddr;

	if (page) {
		/*
		 * Because for bounce buffers vaddr will never be 0
		 * unxlate_dev_mem_ptr() will always free the bounce buffer.
		 */
		vaddr = (void *)(page_to_pfn(page) << PAGE_SHIFT);
		unxlate_dev_mem_ptr(0, vaddr);
	}
}

#endif /* __KERNEL__ */

#endif /* _S390_CRASH_H */

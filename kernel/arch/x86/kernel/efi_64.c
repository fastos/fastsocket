/*
 * x86_64 specific EFI support functions
 * Based on Extensible Firmware Interface Specification version 1.0
 *
 * Copyright (C) 2005-2008 Intel Co.
 *	Fenghua Yu <fenghua.yu@intel.com>
 *	Bibo Mao <bibo.mao@intel.com>
 *	Chandramouli Narayanan <mouli@linux.intel.com>
 *	Huang Ying <ying.huang@intel.com>
 *
 * Code to convert EFI to E820 map has been implemented in elilo bootloader
 * based on a EFI patch by Edgar Hucek. Based on the E820 map, the page table
 * is setup appropriately for EFI runtime code.
 * - mouli 06/14/2007.
 *
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/bootmem.h>
#include <linux/ioport.h>
#include <linux/module.h>
#include <linux/efi.h>
#include <linux/dmi.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/reboot.h>
#include <linux/memory.h>

#include <asm/setup.h>
#include <asm/page.h>
#include <asm/e820.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/proto.h>
#include <asm/efi.h>
#include <asm/cacheflush.h>
#include <asm/fixmap.h>

static pgd_t save_pgd __initdata;
static DEFINE_PER_CPU(unsigned long, efi_flags);
static DEFINE_PER_CPU(unsigned long, save_cr3);
static pgd_t efi_pgd[PTRS_PER_PGD] __page_aligned_bss;

static void __init early_code_mapping_set_exec(int executable)
{
	efi_memory_desc_t *md;
	void *p;

	if (!(__supported_pte_mask & _PAGE_NX))
		return;

	/* Make EFI runtime service code area executable */
	for (p = memmap.map; p < memmap.map_end; p += memmap.desc_size) {
		md = p;
		if (md->type == EFI_RUNTIME_SERVICES_CODE ||
		    md->type == EFI_BOOT_SERVICES_CODE) {
			efi_set_executable(md, executable);
		}
	}
}

void __init efi_call_phys_prelog(void)
{
	unsigned long vaddress;

	early_code_mapping_set_exec(1);
	local_irq_save(get_cpu_var(efi_flags));
	vaddress = (unsigned long)__va(0x0UL);
	save_pgd = *pgd_offset_k(0x0UL);
	set_pgd(pgd_offset_k(0x0UL), *pgd_offset_k(vaddress));
	__flush_tlb_all();
}

void __init efi_call_phys_epilog(void)
{
	/*
	 * After the lock is released, the original page table is restored.
	 */
	set_pgd(pgd_offset_k(0x0UL), save_pgd);
	__flush_tlb_all();
	local_irq_restore(get_cpu_var(efi_flags));
	early_code_mapping_set_exec(0);
}

void efi_call_phys_prelog_in_physmode(void)
{
	local_irq_save(get_cpu_var(efi_flags));
	get_cpu_var(save_cr3)= read_cr3();
	write_cr3(virt_to_phys(efi_pgd));
}

void efi_call_phys_epilog_in_physmode(void)
{
	write_cr3(get_cpu_var(save_cr3));
	local_irq_restore(get_cpu_var(efi_flags));
}

void __iomem *__init efi_ioremap(unsigned long phys_addr, unsigned long size,
				 u32 type)
{
	unsigned long last_map_pfn;

	if (type == EFI_MEMORY_MAPPED_IO)
		return ioremap(phys_addr, size);

	last_map_pfn = init_memory_mapping(phys_addr, phys_addr + size);
	if ((last_map_pfn << PAGE_SHIFT) < phys_addr + size) {
		unsigned long top = last_map_pfn << PAGE_SHIFT;
		efi_ioremap(top, size - (top - phys_addr), type);
	}

	return (void __iomem *)__va(phys_addr);
}

static pud_t *fill_pud(pgd_t *pgd, unsigned long vaddr)
{
	if (pgd_none(*pgd)) {
		pud_t *pud = (pud_t *)get_zeroed_page(GFP_ATOMIC);
		set_pgd(pgd, __pgd(_PAGE_TABLE | __pa(pud)));
		if (pud != pud_offset(pgd, 0))
			printk(KERN_ERR "EFI PAGETABLE BUG #00! %p <-> %p\n",
			       pud, pud_offset(pgd, 0));
	}
	return pud_offset(pgd, vaddr);
}

static pmd_t *fill_pmd(pud_t *pud, unsigned long vaddr)
{
	if (pud_none(*pud)) {
		pmd_t *pmd = (pmd_t *)get_zeroed_page(GFP_ATOMIC);
		set_pud(pud, __pud(_PAGE_TABLE | __pa(pmd)));
		if (pmd != pmd_offset(pud, 0))
			printk(KERN_ERR "EFI PAGETABLE BUG #01! %p <-> %p\n",
			       pmd, pmd_offset(pud, 0));
	}
	return pmd_offset(pud, vaddr);
}

static pte_t *fill_pte(pmd_t *pmd, unsigned long vaddr)
{
	if (pmd_none(*pmd)) {
		pte_t *pte = (pte_t *)get_zeroed_page(GFP_ATOMIC);
		set_pmd(pmd, __pmd(_PAGE_TABLE | __pa(pte)));
		if (pte != pte_offset_kernel(pmd, 0))
			printk(KERN_ERR "EFI PAGETABLE BUG #02!\n");
	}
	return pte_offset_kernel(pmd, vaddr);
}

static int __init dell_efi_quirk(const struct dmi_system_id *d)
{
	u64 vaddr;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	/*
	* Some UEFI run time implementations (DELL) require physical page
	* zero to be mapped. This location is used during EfiResetSystem
	* when ResetType is EfiResetWarm (reboot=warm). UEFI writes to
	* a BIOS physical address of 0x472 for the reboot mode. The reason
	* for this hasn't been revealed by the UEFI developers.
	*/
	printk(KERN_INFO
	       "%s series board detected. Applying quirk for"
	       " page 0 UEFI firmware access.\n", d->ident);
	vaddr = 0UL;
	pgd = efi_pgd + pgd_index(vaddr);
	pud = fill_pud(pgd, vaddr);
	pmd = fill_pmd(pud, vaddr);
	pte = fill_pte(pmd, vaddr);
	set_pte(pte, pfn_pte(0UL, PAGE_KERNEL));
	return 0;
}

static struct dmi_system_id __initdata efi_quirk_table[] = {
	{	/* Dell systems in EFI mode need special handling for resets */
		.callback = dell_efi_quirk,
		.ident = "Dell PowerEdge",
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc"),
		},
	},
	{ }
};

#define EFI_CALLBACK_PRI	3	/* lower than node and SLAB */
#ifdef CONFIG_MEMORY_HOTPLUG
static int efi_memory_callback(struct notifier_block *self,
			       unsigned long action, void *arg)
{
	switch (action) {
		case MEM_GOING_ONLINE: /* fall through */
		case MEM_GOING_OFFLINE:
			clone_pgd_range(efi_pgd + KERNEL_PGD_BOUNDARY,
					swapper_pg_dir + KERNEL_PGD_BOUNDARY, KERNEL_PGD_PTRS);
			break;
		default:
			break;
	}

	return NOTIFY_OK;
}
#endif

void __init efi_pagetable_init(void)
{
	efi_memory_desc_t *md;
	unsigned long size;
	u64 start_pfn, end_pfn, pfn, vaddr;
	void *p;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	memset(efi_pgd, 0, sizeof(efi_pgd));

	dmi_check_system(efi_quirk_table);

	for (p = memmap.map; p < memmap.map_end; p += memmap.desc_size) {
		md = p;
		if (!(md->attribute & EFI_MEMORY_RUNTIME))
			continue;

		start_pfn = md->phys_addr >> PAGE_SHIFT;
		size = md->num_pages << EFI_PAGE_SHIFT;
		end_pfn = PFN_UP(md->phys_addr + size);

		for (pfn = start_pfn; pfn <= end_pfn; pfn++) {
			unsigned long val;

			vaddr = pfn << PAGE_SHIFT;
			pgd = efi_pgd + pgd_index(vaddr);
			pud = fill_pud(pgd, vaddr);
			pmd = fill_pmd(pud, vaddr);
			pte = fill_pte(pmd, vaddr);
			if (md->type == EFI_RUNTIME_SERVICES_CODE)
				val = __PAGE_KERNEL_EXEC;
			else
				val = __PAGE_KERNEL;

			if (!(md->attribute & EFI_MEMORY_WB))
				val |= _PAGE_CACHE_UC_MINUS;
			set_pte(pte, pfn_pte(pfn, __pgprot(val)));
		}
	}
	clone_pgd_range(efi_pgd + KERNEL_PGD_BOUNDARY,
	                swapper_pg_dir + KERNEL_PGD_BOUNDARY, KERNEL_PGD_PTRS);
	hotplug_memory_notifier(efi_memory_callback, EFI_CALLBACK_PRI);
}

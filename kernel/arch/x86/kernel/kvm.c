/*
 * KVM paravirt_ops implementation
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
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) 2007, Red Hat, Inc., Ingo Molnar <mingo@redhat.com>
 * Copyright IBM Corporation, 2007
 *   Authors: Anthony Liguori <aliguori@us.ibm.com>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kvm_para.h>
#include <linux/cpu.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/hardirq.h>
#include <linux/notifier.h>
#include <linux/reboot.h>
#include <asm/timer.h>
#include <asm/cpu.h>
#include <asm/apic.h>
#include <asm/apicdef.h>
#include <asm/hypervisor.h>

#define MMU_QUEUE_SIZE 1024

struct kvm_para_state {
	u8 mmu_queue[MMU_QUEUE_SIZE];
	int mmu_queue_len;
};

static DEFINE_PER_CPU(struct kvm_para_state, para_state);

static struct kvm_para_state *kvm_para_state(void)
{
	return &per_cpu(para_state, raw_smp_processor_id());
}

static DEFINE_PER_CPU(struct kvm_steal_time, steal_time) __aligned(64);
static int has_steal_clock = 0;

/*
 * No need for any "IO delay" on KVM
 */
static void kvm_io_delay(void)
{
}

static void kvm_mmu_op(void *buffer, unsigned len)
{
	int r;
	unsigned long a1, a2;

	do {
		a1 = __pa(buffer);
		a2 = 0;   /* on i386 __pa() always returns <4G */
		r = kvm_hypercall3(KVM_HC_MMU_OP, len, a1, a2);
		buffer += r;
		len -= r;
	} while (len);
}

static void mmu_queue_flush(struct kvm_para_state *state)
{
	if (state->mmu_queue_len) {
		kvm_mmu_op(state->mmu_queue, state->mmu_queue_len);
		state->mmu_queue_len = 0;
	}
}

static void kvm_deferred_mmu_op(void *buffer, int len)
{
	struct kvm_para_state *state = kvm_para_state();

	if (paravirt_get_lazy_mode() != PARAVIRT_LAZY_MMU) {
		kvm_mmu_op(buffer, len);
		return;
	}
	if (state->mmu_queue_len + len > sizeof state->mmu_queue)
		mmu_queue_flush(state);
	memcpy(state->mmu_queue + state->mmu_queue_len, buffer, len);
	state->mmu_queue_len += len;
}

static void kvm_mmu_write(void *dest, u64 val)
{
	__u64 pte_phys;
	struct kvm_mmu_op_write_pte wpte;

#ifdef CONFIG_HIGHPTE
	struct page *page;
	unsigned long dst = (unsigned long) dest;

	page = kmap_atomic_to_page(dest);
	pte_phys = page_to_pfn(page);
	pte_phys <<= PAGE_SHIFT;
	pte_phys += (dst & ~(PAGE_MASK));
#else
	pte_phys = (unsigned long)__pa(dest);
#endif
	wpte.header.op = KVM_MMU_OP_WRITE_PTE;
	wpte.pte_val = val;
	wpte.pte_phys = pte_phys;

	kvm_deferred_mmu_op(&wpte, sizeof wpte);
}

/*
 * We only need to hook operations that are MMU writes.  We hook these so that
 * we can use lazy MMU mode to batch these operations.  We could probably
 * improve the performance of the host code if we used some of the information
 * here to simplify processing of batched writes.
 */
static void kvm_set_pte(pte_t *ptep, pte_t pte)
{
	kvm_mmu_write(ptep, pte_val(pte));
}

static void kvm_set_pte_at(struct mm_struct *mm, unsigned long addr,
			   pte_t *ptep, pte_t pte)
{
	kvm_mmu_write(ptep, pte_val(pte));
}

static void kvm_set_pmd(pmd_t *pmdp, pmd_t pmd)
{
	kvm_mmu_write(pmdp, pmd_val(pmd));
}

#if PAGETABLE_LEVELS >= 3
#ifdef CONFIG_X86_PAE
static void kvm_set_pte_atomic(pte_t *ptep, pte_t pte)
{
	kvm_mmu_write(ptep, pte_val(pte));
}

static void kvm_pte_clear(struct mm_struct *mm,
			  unsigned long addr, pte_t *ptep)
{
	kvm_mmu_write(ptep, 0);
}

static void kvm_pmd_clear(pmd_t *pmdp)
{
	kvm_mmu_write(pmdp, 0);
}
#endif

static void kvm_set_pud(pud_t *pudp, pud_t pud)
{
	kvm_mmu_write(pudp, pud_val(pud));
}

#if PAGETABLE_LEVELS == 4
static void kvm_set_pgd(pgd_t *pgdp, pgd_t pgd)
{
	kvm_mmu_write(pgdp, pgd_val(pgd));
}
#endif
#endif /* PAGETABLE_LEVELS >= 3 */

static void kvm_flush_tlb(void)
{
	struct kvm_mmu_op_flush_tlb ftlb = {
		.header.op = KVM_MMU_OP_FLUSH_TLB,
	};

	kvm_deferred_mmu_op(&ftlb, sizeof ftlb);
}

static void kvm_release_pt(unsigned long pfn)
{
	struct kvm_mmu_op_release_pt rpt = {
		.header.op = KVM_MMU_OP_RELEASE_PT,
		.pt_phys = (u64)pfn << PAGE_SHIFT,
	};

	kvm_mmu_op(&rpt, sizeof rpt);
}

static void kvm_enter_lazy_mmu(void)
{
	paravirt_enter_lazy_mmu();
}

static void kvm_leave_lazy_mmu(void)
{
	struct kvm_para_state *state = kvm_para_state();

	mmu_queue_flush(state);
	paravirt_leave_lazy_mmu();
}

static DEFINE_PER_CPU(unsigned long, kvm_apic_eoi) = KVM_PV_EOI_DISABLED;

static void kvm_guest_apic_eoi_write(u32 reg, u32 val)
{
	/**
	 * This relies on __test_and_clear_bit to modify the memory
	 * in a way that is atomic with respect to the local CPU.
	 * The hypervisor only accesses this memory from the local CPU so
	 * there's no need for lock or memory barriers.
	 * An optimization barrier is implied in apic write.
	 */
	if (__test_and_clear_bit(KVM_PV_EOI_BIT, &__get_cpu_var(kvm_apic_eoi)))
		return;
	apic_write(APIC_EOI, APIC_EOI_ACK);
}

static void __init paravirt_ops_setup(void)
{
	pv_info.name = "KVM";
	pv_info.paravirt_enabled = 1;

	if (kvm_para_has_feature(KVM_FEATURE_NOP_IO_DELAY))
		pv_cpu_ops.io_delay = kvm_io_delay;

	if (kvm_para_has_feature(KVM_FEATURE_MMU_OP)) {
		pv_mmu_ops.set_pte = kvm_set_pte;
		pv_mmu_ops.set_pte_at = kvm_set_pte_at;
		pv_mmu_ops.set_pmd = kvm_set_pmd;
#if PAGETABLE_LEVELS >= 3
#ifdef CONFIG_X86_PAE
		pv_mmu_ops.set_pte_atomic = kvm_set_pte_atomic;
		pv_mmu_ops.pte_clear = kvm_pte_clear;
		pv_mmu_ops.pmd_clear = kvm_pmd_clear;
#endif
		pv_mmu_ops.set_pud = kvm_set_pud;
#if PAGETABLE_LEVELS == 4
		pv_mmu_ops.set_pgd = kvm_set_pgd;
#endif
#endif
		pv_mmu_ops.flush_tlb_user = kvm_flush_tlb;
		pv_mmu_ops.release_pte = kvm_release_pt;
		pv_mmu_ops.release_pmd = kvm_release_pt;
		pv_mmu_ops.release_pud = kvm_release_pt;

		pv_mmu_ops.lazy_mode.enter = kvm_enter_lazy_mmu;
		pv_mmu_ops.lazy_mode.leave = kvm_leave_lazy_mmu;
	}
#ifdef CONFIG_X86_IO_APIC
	no_timer_check = 1;
#endif
}

static void kvm_register_steal_time(void)
{
	int cpu = smp_processor_id();
	struct kvm_steal_time *st = &per_cpu(steal_time, cpu);

	if (!has_steal_clock)
		return;

	memset(st, 0, sizeof(*st));

	wrmsrl(MSR_KVM_STEAL_TIME, (__pa(st) | KVM_MSR_ENABLED));
	printk(KERN_INFO "kvm-stealtime: cpu %d, msr %lx\n",
		cpu, __pa(st));
}

void __cpuinit kvm_guest_cpu_init(void)
{
	if (!kvm_para_available())
		return;

	if (kvm_para_has_feature(KVM_FEATURE_PV_EOI)) {
		unsigned long pa;
		/* Size alignment is implied but just to make it explicit. */
		BUILD_BUG_ON(__alignof__(per_cpu_var(kvm_apic_eoi)) < 4);
		__get_cpu_var(kvm_apic_eoi) = 0;
		pa = __pa(&__get_cpu_var(kvm_apic_eoi)) | KVM_MSR_ENABLED;
		wrmsrl(MSR_KVM_PV_EOI_EN, pa);
	}
	if (has_steal_clock)
		kvm_register_steal_time();
}

static void kvm_pv_guest_cpu_reboot(void *unused)
{
	/*
	 * We disable PV EOI before we load a new kernel by kexec,
	 * since MSR_KVM_PV_EOI_EN stores a pointer into old kernel's memory.
	 * New kernel can re-enable when it boots.
	 */
	if (kvm_para_has_feature(KVM_FEATURE_PV_EOI))
		wrmsrl(MSR_KVM_PV_EOI_EN, 0);
}

static int kvm_pv_reboot_notify(struct notifier_block *nb,
				unsigned long code, void *unused)
{
	if (code == SYS_RESTART)
		on_each_cpu(kvm_pv_guest_cpu_reboot, NULL, 1);
	return NOTIFY_DONE;
}

static struct notifier_block kvm_pv_reboot_nb = {
	.notifier_call = kvm_pv_reboot_notify,
};

static u64 kvm_steal_clock(int cpu)
{
	u64 steal;
	struct kvm_steal_time *src;
	int version;

	src = &per_cpu(steal_time, cpu);
	do {
		version = src->version;
		rmb();
		steal = src->steal;
		rmb();
	} while ((version & 1) || (version != src->version));

	return steal;
}

void kvm_disable_steal_time(void)
{
	if (!has_steal_clock)
		return;

	wrmsr(MSR_KVM_STEAL_TIME, 0, 0);
}

#ifdef CONFIG_SMP
static void __init kvm_smp_prepare_boot_cpu(void)
{
#ifdef CONFIG_KVM_CLOCK
	WARN_ON(kvm_register_clock("primary cpu clock"));
#endif
	kvm_guest_cpu_init();
	native_smp_prepare_boot_cpu();
}

static void __cpuinit kvm_guest_cpu_online(void *dummy)
{
	kvm_guest_cpu_init();
}

static void kvm_guest_cpu_offline(void *dummy)
{
	kvm_disable_steal_time();
	if (kvm_para_has_feature(KVM_FEATURE_PV_EOI))
		wrmsrl(MSR_KVM_PV_EOI_EN, 0);
}

static int __cpuinit kvm_cpu_notify(struct notifier_block *self,
				    unsigned long action, void *hcpu)
{
	int cpu = (unsigned long)hcpu;
	switch (action) {
	case CPU_ONLINE:
	case CPU_DOWN_FAILED:
	case CPU_ONLINE_FROZEN:
		smp_call_function_single(cpu, kvm_guest_cpu_online, NULL, 0);
		break;
	case CPU_DOWN_PREPARE:
	case CPU_DOWN_PREPARE_FROZEN:
		smp_call_function_single(cpu, kvm_guest_cpu_offline, NULL, 1);
		break;
	default:
		break;
	}
	return NOTIFY_OK;
}

static struct notifier_block __cpuinitdata kvm_cpu_notifier = {
        .notifier_call  = kvm_cpu_notify,
};
#endif

static bool __init kvm_detect(void)
{
	if (!kvm_para_available())
		return false;
	return true;
}

static bool __init kvm_x2apic_available(void)
{
	return kvm_para_available();
}

const struct hypervisor_x86 x86_hyper_kvm __refconst = {
	.name                   = "KVM",
	.detect                 = kvm_detect,
	.x2apic_available	= kvm_x2apic_available,
};
EXPORT_SYMBOL_GPL(x86_hyper_kvm);

void __init kvm_guest_init(void)
{
	if (!kvm_para_available())
		return;

	paravirt_ops_setup();
	register_reboot_notifier(&kvm_pv_reboot_nb);

	if (kvm_para_has_feature(KVM_FEATURE_STEAL_TIME)) {
		has_steal_clock = 1;
		pv_time_ops.steal_clock = kvm_steal_clock;
		paravirt_steal_enabled = true;
	}

	if (kvm_para_has_feature(KVM_FEATURE_PV_EOI))
		apic_set_eoi_write(kvm_guest_apic_eoi_write);

#ifdef CONFIG_SMP
	smp_ops.smp_prepare_boot_cpu = kvm_smp_prepare_boot_cpu;
	register_cpu_notifier(&kvm_cpu_notifier);
#else
	kvm_guest_cpu_init();
#endif
}

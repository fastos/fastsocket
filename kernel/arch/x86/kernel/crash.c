/*
 * Architecture specific (i386/x86_64) functions for kexec based crash dumps.
 *
 * Created by: Hariprasad Nellitheertha (hari@in.ibm.com)
 *
 * Copyright (C) IBM Corporation, 2004. All rights reserved.
 *
 */

#include <linux/init.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/smp.h>
#include <linux/reboot.h>
#include <linux/kexec.h>
#include <linux/delay.h>
#include <linux/elf.h>
#include <linux/elfcore.h>
#include <linux/pci.h>
#include <linux/module.h>

#include <asm/processor.h>
#include <asm/hardirq.h>
#include <asm/nmi.h>
#include <asm/hw_irq.h>
#include <asm/apic.h>
#include <asm/hpet.h>
#include <linux/kdebug.h>
#include <asm/cpu.h>
#include <asm/reboot.h>
#include <asm/virtext.h>
#include <asm/iommu.h>


int in_crash_kexec;

/*
 * This is used to VMCLEAR all VMCSs loaded on the
 * processor. And when loading kvm_intel module, the
 * callback function pointer will be assigned.
 *
 * protected by rcu.
 */
crash_vmclear_fn __rcu *crash_vmclear_loaded_vmcss = NULL;
EXPORT_SYMBOL_GPL(crash_vmclear_loaded_vmcss);

static inline void cpu_crash_vmclear_loaded_vmcss(void)
{
	crash_vmclear_fn *do_vmclear_operation = NULL;

	rcu_read_lock();
	do_vmclear_operation = rcu_dereference(crash_vmclear_loaded_vmcss);
	if (do_vmclear_operation)
		do_vmclear_operation();
	rcu_read_unlock();
}

#if defined(CONFIG_SMP) && defined(CONFIG_X86_LOCAL_APIC)

static void kdump_nmi_callback(int cpu, struct die_args *args)
{
	struct pt_regs *regs;
#ifdef CONFIG_X86_32
	struct pt_regs fixed_regs;
#endif

	regs = args->regs;

#ifdef CONFIG_X86_32
	if (!user_mode_vm(regs)) {
		crash_fixup_ss_esp(&fixed_regs, regs);
		regs = &fixed_regs;
	}
#endif
	crash_save_cpu(regs, cpu);

	/*
	 * VMCLEAR VMCSs loaded on all cpus if needed.
	 */
	cpu_crash_vmclear_loaded_vmcss();

	/* Disable VMX or SVM if needed.
	 *
	 * We need to disable virtualization on all CPUs.
	 * Having VMX or SVM enabled on any CPU may break rebooting
	 * after the kdump kernel has finished its task.
	 */
	cpu_emergency_vmxoff();
	cpu_emergency_svm_disable();

	disable_local_APIC();
}

static void kdump_nmi_shootdown_cpus(void)
{
	in_crash_kexec = 1;
	nmi_shootdown_cpus(kdump_nmi_callback);

	disable_local_APIC();
}

#else
static void kdump_nmi_shootdown_cpus(void)
{
	/* There are no cpus to shootdown */
}
#endif

extern struct pci_dev *mcp55_rewrite;
void native_machine_crash_shutdown(struct pt_regs *regs)
{
	/* This function is only called after the system
	 * has panicked or is otherwise in a critical state.
	 * The minimum amount of code to allow a kexec'd kernel
	 * to run successfully needs to happen here.
	 *
	 * In practice this means shooting down the other cpus in
	 * an SMP system.
	 */
	/* The kernel is broken so disable interrupts */
	local_irq_disable();

	kdump_nmi_shootdown_cpus();

	/*
	 * VMCLEAR VMCSs loaded on this cpu if needed.
	 */
	cpu_crash_vmclear_loaded_vmcss();

	/* Booting kdump kernel with VMX or SVM enabled won't work,
	 * because (among other limitations) we can't disable paging
	 * with the virt flags.
	 */
	cpu_emergency_vmxoff();
	cpu_emergency_svm_disable();

	lapic_shutdown();
#if defined(CONFIG_X86_IO_APIC)
	disable_IO_APIC(1);
#endif
	if (mcp55_rewrite) {
		u32 cfg;
		printk(KERN_CRIT "REWRITING MCP55 CFG REG\n");
		/*
		 * We have a mcp55 chip on board which has been
		 * flagged as only sending legacy interrupts
		 * to the BSP, and we are crashing on an AP
		 * This is obviously bad, and we need to
		 * fix it up.  To do this we write to the
		 * flagged device, to the register at offset 0x74
		 * and we make sure that bit 2 and bit 15 are clear
		 * This forces legacy interrupts to be broadcast
		 * to all cpus
		 */
		pci_read_config_dword(mcp55_rewrite, 0x74, &cfg);
		cfg &= ~((1 << 2) | (1 << 15));
		printk(KERN_CRIT "CFG = %x\n", cfg);
		pci_write_config_dword(mcp55_rewrite, 0x74, cfg);
	}

#ifdef CONFIG_HPET_TIMER
	hpet_disable();
#endif

	crash_save_cpu(regs, safe_smp_processor_id());
}

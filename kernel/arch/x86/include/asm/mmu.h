#ifndef _ASM_X86_MMU_H
#define _ASM_X86_MMU_H

#include <linux/spinlock.h>
#include <linux/mutex.h>

/*
 * The x86 doesn't have a mmu context, but
 * we put the segment information here.
 *
 * exec_limit is used to track the range PROT_EXEC
 * mappings span.
 */
typedef struct {
	void *ldt;
	int size;
	struct mutex lock;
	void *vdso;
#ifdef CONFIG_X86_32
	struct desc_struct user_cs;
	unsigned long exec_limit;
#endif
} mm_context_t;

#ifdef CONFIG_SMP
void leave_mm(int cpu);
#else
static inline void leave_mm(int cpu)
{
}
#endif

#endif /* _ASM_X86_MMU_H */

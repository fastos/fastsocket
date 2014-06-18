/*
 * The current implementation of RH's KABI only protects functions.  There are
 * some cases where we would like to protect a struct.  In order to protect
 * a struct it must be included as a parameter to a function.
 *
 * Every release we will add the appropriate rh_kabi_* struct to the kabi
 * whitelists.
 *
 * I don't care if this file gets cluttered with #ifdef CONFIG_ARCHes
 * which prevents us from having to have a rh_kabi.c in each arch directory.
 */
#include <linux/kernel.h>
#include <linux/module.h>

#ifdef CONFIG_X86
#include <asm/alternative.h>
#endif

struct rh_kabi_structs_6_2 {
	int pad; /* avoid an empty struct */
#ifdef CONFIG_X86
	struct alt_instr *alt_instr;
#endif
};

struct rh_kabi_structs_6_3 {
	int pad; /* avoid an empty struct */
#ifdef CONFIG_PARAVIRT
	struct paravirt_patch_template *paravirt_patch_template;
#endif
};

void rh_kabi_6_2(struct rh_kabi_structs_6_2 *rh_kabi_structs_6_2)
{
	/* No one should ever call this function */
	panic("Problem exists between keyboard and your seat.");
}
EXPORT_SYMBOL_GPL(rh_kabi_6_2);

void rh_kabi_6_3(struct rh_kabi_structs_6_3 *rh_kabi_structs_6_3)
{
	/* No need to duplicate the string above :) */
	rh_kabi_6_2(NULL);
}
EXPORT_SYMBOL_GPL(rh_kabi_6_3);

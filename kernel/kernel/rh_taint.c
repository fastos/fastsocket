/*
 * This can be used throughout hardware code to indicate that the hardware
 * is unsupported in RHEL6.
 */
#include <linux/kernel.h>
#include <linux/module.h>

void mark_hardware_unsupported(const char *msg)
{
	printk(KERN_CRIT "UNSUPPORTED HARDWARE DEVICE: %s\n", msg);
	WARN_TAINT(1, TAINT_HARDWARE_UNSUPPORTED,
		   "Your hardware is unsupported.  Please do not report "
		   "bugs, panics, oopses, etc., on this hardware.\n");
}
EXPORT_SYMBOL(mark_hardware_unsupported);

/* Mark parts of the kernel as 'Tech Preview', to make it clear to our 
 * support organization and customers what we do not fully support yet.
 * NOTE: this will TAINT the kernel to signify the machine is running
 * code that is not fully supported.  Use with caution.
 */
void mark_tech_preview(const char *msg, struct module *mod)
{
	const char *str = NULL;

	if (msg)
		str = msg;
	else if (mod && mod->name)
		str = mod->name;
	
	pr_warning("TECH PREVIEW: %s may not be fully supported.\n"
		   "Please review provided documentation for limitations.\n",
		   (str ? str : "kernel"));
	add_taint(TAINT_TECH_PREVIEW);
	if (mod)
        	mod->taints |= (1U << TAINT_TECH_PREVIEW);
}
EXPORT_SYMBOL(mark_tech_preview);

/* You've been bitten by a zombie.  There's nothing we can do for you. */
static int bitten_by_zombie(char *str)
{
	WARN_TAINT(1, TAINT_BIT_BY_ZOMBIE, "... ... ... BRAAAAIIIINNNNSSSSS\n");
	return 1;
}
__setup("OMGZOMBIES", bitten_by_zombie);

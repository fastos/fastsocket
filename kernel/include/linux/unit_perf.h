#ifndef UNIT_PERF_H_
#define UNIT_PERF_H_

/*
Usage:
When you want to find the bottleneck in you codes, you could use the monitor point to check it.
1. Use up_add_monitor to add the monitor point name;
ATTENSION: It should be invoked in process/thread context. Because it will allocate memory with GFP_KERNEL
2. Invoke the up_start_monitor when reach the monitor point;
3. Invoke the up_end_monitor when reach the monitor point;
ATTENTION: The monitor name is the index of unit perf.
4. Check the result:
cat /proc/unit_perf/top_list;
5. Reset the result if necessary
cat /proc/unit_perf/reset_result
6. Use up_remove_monitor to remove the monitor point name.

When you want to check the performance of fixed codes, you could use up_func_once to get it.
1. Create one function whose signature is like up_test_func;
2. Invoke the up_func_once(_preempt/bh/irq) according to your requirement.
3. Check the result by dmesg

*/

typedef void (*up_test_func) (void *);

#ifdef CONFIG_UNIT_PERF
extern int up_add_monitor(const char *name);
extern void up_remove_monitor(const char *name);
extern void up_start_monitor(const char *name);
extern void up_end_monitor(const char *name);

/* Invoke the func directly */
extern void up_func_once(const char *name, up_test_func cb, void *data);
/* Disable the preempt and enable again */
extern void up_func_once_preempt(const char *name, up_test_func cb, void *data);
/* Disable the softirq and enable again */
extern void up_func_once_bh(const char *name, up_test_func cb, void *data);
/* Disable the interrutp and enable again */
extern void up_func_once_irq(const char *name, up_test_func cb, void *data);
#else

static inline int up_add_monitor(const char *name) 
{
	return 0;
}

static inline void up_remove_monitor(const char *name)
{
}

static inline void up_start_monitor(const char *name)
{
	
}

static inline void up_end_monitor(const char *name)
{
}

static inline void up_func_once(const char *name, up_test_func cb, void *data)
{
}
static inline void up_func_once_preempt(const char *name, up_test_func cb, void *data)
{
}
static inline void up_func_once_bh(const char *name, up_test_func cb, void *data)
{
}
static void up_func_once_irq(const char *name, up_test_func cb, void *data)
{
}

#endif

#define UP_AUTO_START_FUNC_MONITOR()				up_start_monitor(__FUNCTION__)
#define UP_AUTO_END_FUNC_MONITOR()					up_end_monitor(__FUNCTION__)

#endif



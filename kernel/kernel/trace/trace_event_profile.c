/*
 * trace event based perf counter profiling
 *
 * Copyright (C) 2009 Red Hat Inc, Peter Zijlstra <pzijlstr@redhat.com>
 *
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include "trace.h"


char *trace_profile_buf;
EXPORT_SYMBOL_GPL(trace_profile_buf);

char *trace_profile_buf_nmi;
EXPORT_SYMBOL_GPL(trace_profile_buf_nmi);

typedef typeof(char [FTRACE_MAX_PROFILE_SIZE]) perf_trace_t ;

/* Count the events in use (per event id, not per instance) */
static int	total_profile_count;

static int ftrace_profile_enable_event(struct ftrace_event_call *event)
{
	char *buf;
	int ret = -ENOMEM;

	if (atomic_inc_return(&event->profile_count))
		return 0;

	if (!total_profile_count) {
		buf = (char *)alloc_percpu(perf_trace_t);
		if (!buf)
			goto fail_buf;

		rcu_assign_pointer(trace_profile_buf, buf);

		buf = (char *)alloc_percpu(perf_trace_t);
		if (!buf)
			goto fail_buf_nmi;

		rcu_assign_pointer(trace_profile_buf_nmi, buf);
	}

	ret = event->profile_enable(event);
	if (!ret) {
		total_profile_count++;
		return 0;
	}

fail_buf_nmi:
	if (!total_profile_count) {
		free_percpu(trace_profile_buf_nmi);
		free_percpu(trace_profile_buf);
		trace_profile_buf_nmi = NULL;
		trace_profile_buf = NULL;
	}
fail_buf:
	atomic_dec(&event->profile_count);

	return ret;
}

int ftrace_profile_enable(int event_id)
{
	struct ftrace_event_call *event;
	int ret = -EINVAL;

	mutex_lock(&event_mutex);
	list_for_each_entry(event, &ftrace_events, list) {
		if (event->id == event_id && event->profile_enable &&
		    try_module_get(event->mod)) {
			ret = ftrace_profile_enable_event(event);
			break;
		}
	}
	mutex_unlock(&event_mutex);

	return ret;
}

static void ftrace_profile_disable_event(struct ftrace_event_call *event)
{
	char *buf, *nmi_buf;

	if (!atomic_add_negative(-1, &event->profile_count))
		return;

	event->profile_disable(event);

	if (!--total_profile_count) {
		buf = trace_profile_buf;
		rcu_assign_pointer(trace_profile_buf, NULL);

		nmi_buf = trace_profile_buf_nmi;
		rcu_assign_pointer(trace_profile_buf_nmi, NULL);

		/*
		 * Ensure every events in profiling have finished before
		 * releasing the buffers
		 */
		synchronize_sched();

		free_percpu(buf);
		free_percpu(nmi_buf);
	}
}

void ftrace_profile_disable(int event_id)
{
	struct ftrace_event_call *event;

	mutex_lock(&event_mutex);
	list_for_each_entry(event, &ftrace_events, list) {
		if (event->id == event_id) {
			ftrace_profile_disable_event(event);
			module_put(event->mod);
			break;
		}
	}
	mutex_unlock(&event_mutex);
}

__kprobes void *ftrace_perf_buf_prepare(int size, unsigned short type,
					int *rctxp, unsigned long *irq_flags)
{
	struct trace_entry *entry;
	char *trace_buf, *raw_data;
	int pc, cpu;

	pc = preempt_count();

	/* Protect the per cpu buffer, begin the rcu read side */
	local_irq_save(*irq_flags);

	*rctxp = perf_swevent_get_recursion_context();
	if (*rctxp < 0)
		goto err_recursion;

	cpu = smp_processor_id();

	if (in_nmi())
		trace_buf = rcu_dereference(trace_profile_buf_nmi);
	else
		trace_buf = rcu_dereference(trace_profile_buf);

	if (!trace_buf)
		goto err;

	raw_data = per_cpu_ptr(trace_buf, cpu);

	/* zero the dead bytes from align to not leak stack to user */
	*(u64 *)(&raw_data[size - sizeof(u64)]) = 0ULL;

	entry = (struct trace_entry *)raw_data;
	tracing_generic_entry_update(entry, *irq_flags, pc);
	entry->type = type;

	return raw_data;
err:
	perf_swevent_put_recursion_context(*rctxp);
err_recursion:
	local_irq_restore(*irq_flags);
	return NULL;
}
EXPORT_SYMBOL_GPL(ftrace_perf_buf_prepare);

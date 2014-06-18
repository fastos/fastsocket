/*
 * linux/kernel/ptrace.c
 *
 * (C) Copyright 1999 Linus Torvalds
 *
 * Common interfaces for "ptrace()" which we do not want
 * to continually duplicate across every architecture.
 */

#include <linux/capability.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/smp_lock.h>
#include <linux/ptrace.h>
#include <linux/utrace.h>
#include <linux/security.h>
#include <linux/signal.h>
#include <linux/audit.h>
#include <linux/pid_namespace.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>

/*
 * ptrace a task: make the debugger its new parent and
 * move it to the ptrace list.
 *
 * Must be called with the tasklist lock write-held.
 */
void __ptrace_link(struct task_struct *child, struct task_struct *new_parent)
{
	BUG_ON(!list_empty(&child->ptrace_entry));
	list_add(&child->ptrace_entry, &new_parent->ptraced);
	child->parent = new_parent;
}

/*
 * unptrace a task: move it back to its original parent and
 * remove it from the ptrace list.
 *
 * Must be called with the tasklist lock write-held.
 */
void __ptrace_unlink(struct task_struct *child)
{
	BUG_ON(!child->ptrace);

	child->ptrace = 0;
	child->parent = child->real_parent;
	list_del_init(&child->ptrace_entry);

	arch_ptrace_untrace(child);
}

struct ptrace_context {
	int				options;

	int				signr;
	siginfo_t			*siginfo;

	int				stop_code;
	unsigned long			eventmsg;

	enum utrace_resume_action	resume;
};

#define PT_UTRACED			0x00001000

#define PTRACE_O_SYSEMU			0x100
#define PTRACE_O_DETACHED		0x200

#define PTRACE_EVENT_SYSCALL		(1 << 16)
#define PTRACE_EVENT_SIGTRAP		(2 << 16)
#define PTRACE_EVENT_SIGNAL		(3 << 16)
/* events visible to user-space */
#define PTRACE_EVENT_MASK		0xFFFF

static inline bool ptrace_event_pending(struct ptrace_context *ctx)
{
	return ctx->stop_code != 0;
}

static inline int get_stop_event(struct ptrace_context *ctx)
{
	return ctx->stop_code >> 8;
}

static inline void set_stop_code(struct ptrace_context *ctx, int event)
{
	ctx->stop_code = (event << 8) | SIGTRAP;
}

static inline struct ptrace_context *
ptrace_context(struct utrace_engine *engine)
{
	return engine->data;
}

static const struct utrace_engine_ops ptrace_utrace_ops; /* forward decl */

static struct utrace_engine *ptrace_lookup_engine(struct task_struct *tracee)
{
	return utrace_attach_task(tracee, UTRACE_ATTACH_MATCH_OPS,
					&ptrace_utrace_ops, NULL);
}

static int utrace_barrier_uninterruptible(struct task_struct *target,
					struct utrace_engine *engine)
{
	for (;;) {
		int err = utrace_barrier(target, engine);

		if (err != -ERESTARTSYS)
			return err;

		schedule_timeout_uninterruptible(1);
	}
}

static struct utrace_engine *
ptrace_reuse_engine(struct task_struct *tracee)
{
	struct utrace_engine *engine;
	struct ptrace_context *ctx;
	int err = -EPERM;

	engine = ptrace_lookup_engine(tracee);
	if (IS_ERR(engine))
		return engine;

	ctx = ptrace_context(engine);
	if (unlikely(ctx->options == PTRACE_O_DETACHED)) {
		/*
		 * Try to reuse this self-detaching engine.
		 * The only caller which can hit this case is ptrace_attach(),
		 * it holds ->cred_guard_mutex.
		 */
		ctx->options = 0;
		ctx->eventmsg = 0;

		/* make sure we don't get unwanted reports */
		err = utrace_set_events(tracee, engine, UTRACE_EVENT(QUIESCE));
		if (!err || err == -EINPROGRESS) {
			ctx->resume = UTRACE_RESUME;
			/* synchronize with ptrace_report_signal() */
			err = utrace_barrier_uninterruptible(tracee, engine);
		}

		if (!err) {
			WARN_ON(engine->ops != &ptrace_utrace_ops &&
				!tracee->exit_state);
			return engine;
		}

		WARN_ON(engine->ops == &ptrace_utrace_ops);
	}

	utrace_engine_put(engine);
	return ERR_PTR(err);
}

static struct utrace_engine *
ptrace_attach_engine(struct task_struct *tracee)
{
	struct utrace_engine *engine;
	struct ptrace_context *ctx;

	if (unlikely(task_utrace_flags(tracee))) {
		engine = ptrace_reuse_engine(tracee);
		if (!IS_ERR(engine) || IS_ERR(engine) == -EPERM)
			return engine;
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (unlikely(!ctx))
		return ERR_PTR(-ENOMEM);

	ctx->resume = UTRACE_RESUME;

	engine = utrace_attach_task(tracee, UTRACE_ATTACH_CREATE |
						UTRACE_ATTACH_EXCLUSIVE |
						UTRACE_ATTACH_MATCH_OPS,
						&ptrace_utrace_ops, ctx);
	if (unlikely(IS_ERR(engine))) {
		if (engine != ERR_PTR(-ESRCH) &&
		    engine != ERR_PTR(-ERESTARTNOINTR))
			engine = ERR_PTR(-EPERM);
		kfree(ctx);
	}

	return engine;
}

static inline int ptrace_set_events(struct task_struct *target,
					struct utrace_engine *engine,
					unsigned long options)
{
	struct ptrace_context *ctx = ptrace_context(engine);
	/*
	 * We need QUIESCE for resume handling, CLONE to check
	 * for CLONE_PTRACE, other events are always reported.
	 */
	unsigned long events = UTRACE_EVENT(QUIESCE) | UTRACE_EVENT(CLONE) |
			       UTRACE_EVENT(EXEC) | UTRACE_EVENT_SIGNAL_ALL;

	ctx->options = options;
	if (options & PTRACE_O_TRACEEXIT)
		events |= UTRACE_EVENT(EXIT);

	return utrace_set_events(target, engine, events);
}

/*
 * Attach a utrace engine for ptrace and set up its event mask.
 * Returns error code or 0 on success.
 */
static int ptrace_attach_task(struct task_struct *tracee, int options)
{
	struct utrace_engine *engine;
	int err;

	engine = ptrace_attach_engine(tracee);
	if (IS_ERR(engine))
		return PTR_ERR(engine);
	/*
	 * It can fail only if the tracee is dead, the caller
	 * must notice this before setting PT_UTRACED.
	 */
	err = ptrace_set_events(tracee, engine, options);
	WARN_ON(err && !tracee->exit_state);
	utrace_engine_put(engine);
	return 0;
}

static int ptrace_wake_up(struct task_struct *tracee,
				struct utrace_engine *engine,
				enum utrace_resume_action action,
				bool force_wakeup)
{
	if (force_wakeup) {
		unsigned long flags;
		/*
		 * Preserve the compatibility bug. Historically ptrace
		 * wakes up the tracee even if it should not. Clear
		 * SIGNAL_STOP_STOPPED for utrace_wakeup().
		 */
		if (lock_task_sighand(tracee, &flags)) {
			tracee->signal->flags &= ~SIGNAL_STOP_STOPPED;
			unlock_task_sighand(tracee, &flags);
		}
	}

	if (action != UTRACE_REPORT)
		ptrace_context(engine)->stop_code = 0;

	return utrace_control(tracee, engine, action);
}

static void ptrace_detach_task(struct task_struct *tracee, int sig)
{
	/*
	 * If true, the caller is PTRACE_DETACH, otherwise
	 * the tracer detaches implicitly during exit.
	 */
	bool explicit = (sig >= 0);
	struct utrace_engine *engine = ptrace_lookup_engine(tracee);
	enum utrace_resume_action action = UTRACE_DETACH;
	struct ptrace_context *ctx;

	if (unlikely(IS_ERR(engine)))
		return;

	ctx = ptrace_context(engine);

	if (!explicit) {
		int err;

		/*
		 * We are going to detach, the tracee can be running.
		 * Ensure ptrace_report_signal() won't report a signal.
		 */
		ctx->resume = UTRACE_DETACH;
		err = utrace_barrier_uninterruptible(tracee, engine);

		if (!err && ctx->siginfo) {
			/*
			 * The tracee has already reported a signal
			 * before utrace_barrier().
			 *
			 * Resume it like we do in PTRACE_EVENT_SIGNAL
			 * case below. The difference is that we can race
			 * with ptrace_report_signal() if the tracee is
			 * running but this doesn't matter. In any case
			 * UTRACE_SIGNAL_REPORT must be pending and it
			 * can return nothing but UTRACE_DETACH.
			 */
			action = UTRACE_RESUME;
		}

	} else if (sig) {
		switch (get_stop_event(ctx)) {
		case PTRACE_EVENT_SYSCALL:
			send_sig_info(sig, SEND_SIG_PRIV, tracee);
			break;

		case PTRACE_EVENT_SIGNAL:
			ctx->signr = sig;
			ctx->resume = UTRACE_DETACH;
			action = UTRACE_RESUME;
			break;
		}
	}

	ptrace_wake_up(tracee, engine, action, explicit);

	if (action != UTRACE_DETACH)
		ctx->options = PTRACE_O_DETACHED;

	utrace_engine_put(engine);
}

static void ptrace_abort_attach(struct task_struct *tracee)
{
	ptrace_detach_task(tracee, 0);
}

static u32 ptrace_report_exit(u32 action, struct utrace_engine *engine,
			      long orig_code, long *code)
{
	struct ptrace_context *ctx = ptrace_context(engine);

	WARN_ON(ptrace_event_pending(ctx) &&
		!signal_group_exit(current->signal));

	set_stop_code(ctx, PTRACE_EVENT_EXIT);
	ctx->eventmsg = *code;

	return UTRACE_STOP;
}

static void ptrace_clone_attach(struct task_struct *child,
				int options)
{
	struct task_struct *parent = current;
	struct task_struct *tracer;
	bool abort = true;

	if (unlikely(ptrace_attach_task(child, options))) {
		WARN_ON(1);
		return;
	}

	write_lock_irq(&tasklist_lock);
	tracer = parent->parent;
	if (!(tracer->flags & PF_EXITING) && parent->ptrace) {
		child->ptrace = parent->ptrace;
		__ptrace_link(child, tracer);
		abort = false;
	}
	write_unlock_irq(&tasklist_lock);
	if (unlikely(abort)) {
		ptrace_abort_attach(child);
		return;
	}

	sigaddset(&child->pending.signal, SIGSTOP);
	set_tsk_thread_flag(child, TIF_SIGPENDING);
}

static u32 ptrace_report_clone(u32 action, struct utrace_engine *engine,
			       unsigned long clone_flags,
			       struct task_struct *child)
{
	struct ptrace_context *ctx = ptrace_context(engine);
	int event = 0;

	WARN_ON(ptrace_event_pending(ctx));

	if (clone_flags & CLONE_UNTRACED) {
		/* no events reported */
	} else if (clone_flags & CLONE_VFORK) {
		if (ctx->options & PTRACE_O_TRACEVFORK)
			event = PTRACE_EVENT_VFORK;
		else if (ctx->options & PTRACE_O_TRACEVFORKDONE)
			event = PTRACE_EVENT_VFORK_DONE;
	} else if ((clone_flags & CSIGNAL) != SIGCHLD) {
		if (ctx->options & PTRACE_O_TRACECLONE)
			event = PTRACE_EVENT_CLONE;
	} else if (ctx->options & PTRACE_O_TRACEFORK) {
		event = PTRACE_EVENT_FORK;
	}
	/*
	 * Any of these reports implies auto-attaching the new child.
	 * So does CLONE_PTRACE, even with no event to report.
	 */
	if ((event && event != PTRACE_EVENT_VFORK_DONE) ||
				(clone_flags & CLONE_PTRACE))
		ptrace_clone_attach(child, ctx->options);

	if (!event)
		return UTRACE_RESUME;

	set_stop_code(ctx, event);
	ctx->eventmsg = task_pid_vnr(child);
	/*
	 * We shouldn't stop now, inside the do_fork() path.
	 * We will stop later, before return to user-mode.
	 */
	if (event == PTRACE_EVENT_VFORK_DONE)
		return UTRACE_REPORT;
	else
		return UTRACE_STOP;
}

static inline void set_syscall_code(struct ptrace_context *ctx)
{
	set_stop_code(ctx, PTRACE_EVENT_SYSCALL);
	if (ctx->options & PTRACE_O_TRACESYSGOOD)
		ctx->stop_code |= 0x80;
}

static u32 ptrace_report_syscall_entry(u32 action, struct utrace_engine *engine,
				       struct pt_regs *regs)
{
	struct ptrace_context *ctx = ptrace_context(engine);

	if (action & UTRACE_SYSCALL_RESUMED) {
		/*
		 * We already reported the first time.
		 * Nothing more to do now.
		 */
		if (unlikely(ctx->options & PTRACE_O_SYSEMU))
			return UTRACE_SYSCALL_ABORT | UTRACE_REPORT;
		return utrace_syscall_action(action) | UTRACE_RESUME;
	}

	WARN_ON(ptrace_event_pending(ctx));

	set_syscall_code(ctx);

	if (unlikely(ctx->options & PTRACE_O_SYSEMU))
		return UTRACE_SYSCALL_ABORT | UTRACE_REPORT;
	/*
	 * Stop now to report.  We will get another callback after
	 * we resume, with the UTRACE_SYSCALL_RESUMED flag set.
	 */
	return UTRACE_SYSCALL_RUN | UTRACE_STOP;
}

static inline bool is_step_resume(enum utrace_resume_action resume)
{
	return resume == UTRACE_BLOCKSTEP || resume == UTRACE_SINGLESTEP;
}

static u32 ptrace_report_syscall_exit(u32 action, struct utrace_engine *engine,
				      struct pt_regs *regs)
{
	struct ptrace_context *ctx = ptrace_context(engine);

	if (ptrace_event_pending(ctx))
		return UTRACE_STOP;

	if (is_step_resume(ctx->resume)) {
		ctx->signr = SIGTRAP;
		return UTRACE_INTERRUPT;
	}

	set_syscall_code(ctx);
	return UTRACE_STOP;
}

static u32 ptrace_report_exec(u32 action, struct utrace_engine *engine,
			      const struct linux_binfmt *fmt,
			      const struct linux_binprm *bprm,
			      struct pt_regs *regs)
{
	struct ptrace_context *ctx = ptrace_context(engine);

	WARN_ON(ptrace_event_pending(ctx));

	if (!(ctx->options & PTRACE_O_TRACEEXEC)) {
		/*
		 * Old-fashioned ptrace'd exec just posts a plain signal.
		 */
		send_sig(SIGTRAP, current, 0);
		return UTRACE_RESUME;
	}

	set_stop_code(ctx, PTRACE_EVENT_EXEC);
	return UTRACE_STOP;
}

static enum utrace_signal_action resume_signal(struct ptrace_context *ctx,
					       struct k_sigaction *return_ka)
{
	siginfo_t *info = ctx->siginfo;
	int signr = ctx->signr;

	ctx->siginfo = NULL;
	ctx->signr = 0;

	/* Did the debugger cancel the sig? */
	if (!signr)
		return UTRACE_SIGNAL_IGN;
	/*
	 * Update the siginfo structure if the signal has changed.
	 * If the debugger wanted something specific in the siginfo
	 * then it should have updated *info via PTRACE_SETSIGINFO.
	 */
	if (info->si_signo != signr) {
		info->si_signo = signr;
		info->si_errno = 0;
		info->si_code = SI_USER;
		info->si_pid = task_pid_vnr(current->parent);
		info->si_uid = task_uid(current->parent);
	}

	/* If the (new) signal is now blocked, requeue it. */
	if (sigismember(&current->blocked, signr)) {
		send_sig_info(signr, info, current);
		return UTRACE_SIGNAL_IGN;
	}

	spin_lock_irq(&current->sighand->siglock);
	*return_ka = current->sighand->action[signr - 1];
	spin_unlock_irq(&current->sighand->siglock);

	return UTRACE_SIGNAL_DELIVER;
}

static u32 ptrace_report_signal(u32 action, struct utrace_engine *engine,
				struct pt_regs *regs,
				siginfo_t *info,
				const struct k_sigaction *orig_ka,
				struct k_sigaction *return_ka)
{
	struct ptrace_context *ctx = ptrace_context(engine);
	enum utrace_resume_action resume = ctx->resume;

	if (ptrace_event_pending(ctx)) {
		action = utrace_signal_action(action);
		WARN_ON(action != UTRACE_SIGNAL_REPORT);
		return action | UTRACE_STOP;
	}

	switch (utrace_signal_action(action)) {
	case UTRACE_SIGNAL_HANDLER:
		if (WARN_ON(ctx->siginfo))
			ctx->siginfo = NULL;

		if (is_step_resume(resume)) {
			set_stop_code(ctx, PTRACE_EVENT_SIGTRAP);
			return UTRACE_STOP | UTRACE_SIGNAL_IGN;
		}

	case UTRACE_SIGNAL_REPORT:
		if (!ctx->siginfo) {
			if (ctx->signr) {
				/* set by ptrace_resume(SYSCALL_EXIT) */
				WARN_ON(ctx->signr != SIGTRAP);
				user_single_step_siginfo(current, regs, info);
				force_sig_info(SIGTRAP, info, current);
			}

			return resume | UTRACE_SIGNAL_IGN;
		}

		if (WARN_ON(ctx->siginfo != info))
			return resume | UTRACE_SIGNAL_IGN;

		return resume | resume_signal(ctx, return_ka);

	default:
		break;
	}

	WARN_ON(ctx->siginfo);

	/* Raced with the exiting tracer ? */
	if (resume == UTRACE_DETACH)
		return action;

	ctx->siginfo = info;
	/*
	 * ctx->siginfo points to the caller's stack.
	 * Make sure the subsequent UTRACE_SIGNAL_REPORT clears
	 * ->siginfo before return from get_signal_to_deliver().
	 */
	if (utrace_control(current, engine, UTRACE_INTERRUPT))
		WARN_ON(1);

	ctx->signr = info->si_signo;
	ctx->stop_code = (PTRACE_EVENT_SIGNAL << 8) | ctx->signr;

	return UTRACE_STOP | UTRACE_SIGNAL_IGN;
}

static u32 ptrace_report_quiesce(u32 action, struct utrace_engine *engine,
				 unsigned long event)
{
	struct ptrace_context *ctx = ptrace_context(engine);

	if (ptrace_event_pending(ctx))
		return UTRACE_STOP;

	return event ? UTRACE_RESUME : ctx->resume;
}

static void ptrace_release(void *data)
{
	kfree(data);
}

static const struct utrace_engine_ops ptrace_utrace_ops = {
	.report_signal = ptrace_report_signal,
	.report_quiesce = ptrace_report_quiesce,
	.report_exec = ptrace_report_exec,
	.report_exit = ptrace_report_exit,
	.report_clone = ptrace_report_clone,
	.report_syscall_entry = ptrace_report_syscall_entry,
	.report_syscall_exit = ptrace_report_syscall_exit,
	.release = ptrace_release,
};

int ptrace_check_attach(struct task_struct *child, int kill)
{
	struct utrace_engine *engine;
	struct utrace_examiner exam;
	int ret = -ESRCH;

	engine = ptrace_lookup_engine(child);
	if (IS_ERR(engine))
		return ret;

	if (child->parent != current)
		goto out;

	if (unlikely(kill))
		ret = 0;

	if (!task_is_stopped_or_traced(child))
		goto out;
	/*
	 * Make sure our engine has already stopped the child.
	 * Then wait for it to be off the CPU.
	 */
	utrace_freeze_stop(child);
	if (!utrace_control(child, engine, UTRACE_STOP) &&
	    !utrace_prepare_examine(child, engine, &exam))
		ret = 0;
	else
		utrace_unfreeze_stop(child);

out:
	utrace_engine_put(engine);
	return ret;
}

int ptrace_attach(struct task_struct *task)
{
	int retval;

	audit_ptrace(task);

	retval = -EPERM;
	if (unlikely(task->flags & PF_KTHREAD))
		goto out;
	if (same_thread_group(task, current))
		goto out;

	/*
	 * Protect exec's credential calculations against our interference;
	 * interference; SUID, SGID and LSM creds get determined differently
	 * under ptrace.
	 */
	retval = -ERESTARTNOINTR;
	if (mutex_lock_interruptible(&task->cred_guard_mutex))
		goto out;

	task_lock(task);
	retval = __ptrace_may_access(task, PTRACE_MODE_ATTACH);
	task_unlock(task);
	if (retval)
		goto unlock_creds;

	retval = ptrace_attach_task(task, 0);
	if (unlikely(retval))
		goto unlock_creds;

	write_lock_irq(&tasklist_lock);
	retval = -EPERM;
	if (unlikely(task->exit_state))
		goto unlock_tasklist;

	BUG_ON(task->ptrace);
	task->ptrace = PT_UTRACED;
	if (capable(CAP_SYS_PTRACE))
		task->ptrace |= PT_PTRACE_CAP;

	__ptrace_link(task, current);
	send_sig_info(SIGSTOP, SEND_SIG_FORCED, task);

	retval = 0;
unlock_tasklist:
	write_unlock_irq(&tasklist_lock);
unlock_creds:
	mutex_unlock(&task->cred_guard_mutex);
out:
	return retval;
}

/*
 * Performs checks and sets PT_UTRACED.
 * Should be used by all ptrace implementations for PTRACE_TRACEME.
 */
int ptrace_traceme(void)
{
	bool detach = true;
	int ret = ptrace_attach_task(current, 0);

	if (unlikely(ret))
		return ret;

	ret = -EPERM;
	write_lock_irq(&tasklist_lock);
	BUG_ON(current->ptrace);
	ret = security_ptrace_traceme(current->parent);
	/*
	 * Check PF_EXITING to ensure ->real_parent has not passed
	 * exit_ptrace(). Otherwise we don't report the error but
	 * pretend ->real_parent untraces us right after return.
	 */
	if (!ret && !(current->real_parent->flags & PF_EXITING)) {
		current->ptrace = PT_UTRACED;
		__ptrace_link(current, current->real_parent);
		detach = false;
	}
	write_unlock_irq(&tasklist_lock);

	if (detach)
		ptrace_abort_attach(current);
	return ret;
}

static void ptrace_do_detach(struct task_struct *tracee, unsigned int data)
{
	bool detach, release;

	write_lock_irq(&tasklist_lock);
	/*
	 * This tracee can be already killed. Make sure de_thread() or
	 * our sub-thread doing do_wait() didn't do release_task() yet.
	 */
	detach = tracee->ptrace != 0;
	release = false;
	if (likely(detach))
		release = __ptrace_detach(current, tracee);
	write_unlock_irq(&tasklist_lock);

	if (unlikely(release))
		release_task(tracee);
	else if (likely(detach))
		ptrace_detach_task(tracee, data);
}

int ptrace_detach(struct task_struct *child, unsigned int data)
{
	utrace_unfreeze_stop(child);

	if (!valid_signal(data))
		return -EIO;

	ptrace_do_detach(child, data);

	return 0;
}

/*
 * Detach all tasks we were using ptrace on.
 */
void exit_ptrace(struct task_struct *tracer)
{
	for (;;) {
		struct task_struct *tracee = NULL;

		read_lock(&tasklist_lock);
		if (!list_empty(&tracer->ptraced)) {
			tracee = list_first_entry(&tracer->ptraced,
					struct task_struct, ptrace_entry);
			get_task_struct(tracee);
		}
		read_unlock(&tasklist_lock);
		if (!tracee)
			break;

		ptrace_do_detach(tracee, -1);
		put_task_struct(tracee);
	}
}

static int ptrace_set_options(struct task_struct *tracee,
				struct utrace_engine *engine, long data)
{
	BUILD_BUG_ON(PTRACE_O_MASK & (PTRACE_O_SYSEMU | PTRACE_O_DETACHED));

	ptrace_set_events(tracee, engine, data & PTRACE_O_MASK);
	return (data & ~PTRACE_O_MASK) ? -EINVAL : 0;
}

static int ptrace_rw_siginfo(struct task_struct *tracee,
				struct ptrace_context *ctx,
				siginfo_t *info, bool write)
{
	unsigned long flags;
	int err;

	switch (get_stop_event(ctx)) {
	case 0: /* jctl stop */
		return -EINVAL;

	case PTRACE_EVENT_SIGNAL:
		err = -ESRCH;
		if (lock_task_sighand(tracee, &flags)) {
			if (likely(task_is_traced(tracee))) {
				if (write)
					*ctx->siginfo = *info;
				else
					*info = *ctx->siginfo;
				err = 0;
			}
			unlock_task_sighand(tracee, &flags);
		}

		return err;

	default:
		if (!write) {
			memset(info, 0, sizeof(*info));
			info->si_signo = SIGTRAP;
			info->si_code = ctx->stop_code & PTRACE_EVENT_MASK;
			info->si_pid = task_pid_vnr(tracee);
			info->si_uid = task_uid(tracee);
		}

		return 0;
	}
}

static void do_ptrace_notify_stop(struct ptrace_context *ctx,
					struct task_struct *tracee)
{
	/*
	 * This can race with SIGKILL, but we borrow this race from
	 * the old ptrace implementation. ->exit_code is only needed
	 * for wait_task_stopped()->task_stopped_code(), we should
	 * change it to use ptrace_context.
	 */
	tracee->exit_code = ctx->stop_code & PTRACE_EVENT_MASK;
	WARN_ON(!tracee->exit_code);

	read_lock(&tasklist_lock);
	/*
	 * Don't want to allow preemption here, because
	 * sys_ptrace() needs this task to be inactive.
	 */
	preempt_disable();
	/*
	 * It can be killed and then released by our subthread,
	 * or ptrace_attach() has not completed yet.
	 */
	if (task_ptrace(tracee))
		do_notify_parent_cldstop(tracee, CLD_TRAPPED);
	read_unlock(&tasklist_lock);
	preempt_enable_no_resched();
}

void ptrace_notify_stop(struct task_struct *tracee)
{
	struct utrace_engine *engine = ptrace_lookup_engine(tracee);

	if (IS_ERR(engine))
		return;

	do_ptrace_notify_stop(ptrace_context(engine), tracee);
	utrace_engine_put(engine);
}

static int ptrace_resume_action(struct task_struct *tracee,
				struct utrace_engine *engine, long request)
{
	struct ptrace_context *ctx = ptrace_context(engine);
	unsigned long events;
	int action;

	ctx->options &= ~PTRACE_O_SYSEMU;
	events = engine->flags & ~UTRACE_EVENT_SYSCALL;
	action = UTRACE_RESUME;

	switch (request) {
#ifdef PTRACE_SINGLEBLOCK
	case PTRACE_SINGLEBLOCK:
		if (unlikely(!arch_has_block_step()))
			return -EIO;
		action = UTRACE_BLOCKSTEP;
		events |= UTRACE_EVENT(SYSCALL_EXIT);
		break;
#endif

#ifdef PTRACE_SINGLESTEP
	case PTRACE_SINGLESTEP:
		if (unlikely(!arch_has_single_step()))
			return -EIO;
		action = UTRACE_SINGLESTEP;
		events |= UTRACE_EVENT(SYSCALL_EXIT);
		break;
#endif

#ifdef PTRACE_SYSEMU
	case PTRACE_SYSEMU_SINGLESTEP:
		if (unlikely(!arch_has_single_step()))
			return -EIO;
		action = UTRACE_SINGLESTEP;
	case PTRACE_SYSEMU:
		ctx->options |= PTRACE_O_SYSEMU;
		events |= UTRACE_EVENT(SYSCALL_ENTRY);
		break;
#endif

	case PTRACE_SYSCALL:
		events |= UTRACE_EVENT_SYSCALL;
		break;

	case PTRACE_CONT:
		break;
	default:
		return -EIO;
	}

	if (events != engine->flags &&
	    utrace_set_events(tracee, engine, events))
		return -ESRCH;

	return action;
}

static int ptrace_resume(struct task_struct *tracee,
				struct utrace_engine *engine,
				long request, long data)
{
	struct ptrace_context *ctx = ptrace_context(engine);
	int action;

	if (!valid_signal(data))
		return -EIO;

	action = ptrace_resume_action(tracee, engine, request);
	if (action < 0)
		return action;

	switch (get_stop_event(ctx)) {
	case PTRACE_EVENT_VFORK:
		if (ctx->options & PTRACE_O_TRACEVFORKDONE) {
			set_stop_code(ctx, PTRACE_EVENT_VFORK_DONE);
			action = UTRACE_REPORT;
		}
		break;

	case PTRACE_EVENT_EXEC:
	case PTRACE_EVENT_FORK:
	case PTRACE_EVENT_CLONE:
	case PTRACE_EVENT_VFORK_DONE:
		if (request == PTRACE_SYSCALL) {
			set_syscall_code(ctx);
			do_ptrace_notify_stop(ctx, tracee);
			return 0;
		}

		if (action != UTRACE_RESUME) {
			/*
			 * single-stepping. UTRACE_SIGNAL_REPORT will
			 * synthesize a trap to follow the syscall insn.
			*/
			ctx->signr = SIGTRAP;
			action = UTRACE_INTERRUPT;
		}
		break;

	case PTRACE_EVENT_SYSCALL:
		if (data)
			send_sig_info(data, SEND_SIG_PRIV, tracee);
		break;

	case PTRACE_EVENT_SIGNAL:
		ctx->signr = data;
		break;
	}

	ctx->resume = action;
	ptrace_wake_up(tracee, engine, action, true);
	return 0;
}

extern int ptrace_regset(struct task_struct *task, int req, unsigned int type,
			 struct iovec *kiov);

int ptrace_request(struct task_struct *child, long request,
		   long addr, long data)
{
	struct utrace_engine *engine = ptrace_lookup_engine(child);
	siginfo_t siginfo;
	int ret;

	if (unlikely(IS_ERR(engine)))
		return -ESRCH;

	switch (request) {
	case PTRACE_PEEKTEXT:
	case PTRACE_PEEKDATA:
		ret = generic_ptrace_peekdata(child, addr, data);
		break;
	case PTRACE_POKETEXT:
	case PTRACE_POKEDATA:
		ret = generic_ptrace_pokedata(child, addr, data);
		break;

#ifdef PTRACE_OLDSETOPTIONS
	case PTRACE_OLDSETOPTIONS:
#endif
	case PTRACE_SETOPTIONS:
		ret = ptrace_set_options(child, engine, data);
		break;
	case PTRACE_GETEVENTMSG:
		ret = put_user(ptrace_context(engine)->eventmsg,
				(unsigned long __user *) data);
		break;

	case PTRACE_GETSIGINFO:
		ret = ptrace_rw_siginfo(child, ptrace_context(engine),
					&siginfo, false);
		if (!ret)
			ret = copy_siginfo_to_user((siginfo_t __user *) data,
						   &siginfo);
		break;

	case PTRACE_SETSIGINFO:
		if (copy_from_user(&siginfo, (siginfo_t __user *) data,
				   sizeof siginfo))
			ret = -EFAULT;
		else
			ret = ptrace_rw_siginfo(child, ptrace_context(engine),
						&siginfo, true);
		break;

	case PTRACE_DETACH:	 /* detach a process that was attached. */
		ret = ptrace_detach(child, data);
		break;

	case PTRACE_KILL:
		/* Ugly historical behaviour. */
		if (task_is_traced(child))
			ptrace_resume(child, engine, PTRACE_CONT, SIGKILL);
		ret = 0;
		break;

	case PTRACE_GETREGSET:
	case PTRACE_SETREGSET:
	{
		struct iovec kiov;
		struct iovec __user *uiov = (struct iovec __user *) data;

		if (!access_ok(VERIFY_WRITE, uiov, sizeof(*uiov)))
			return -EFAULT;

		if (__get_user(kiov.iov_base, &uiov->iov_base) ||
		    __get_user(kiov.iov_len, &uiov->iov_len))
			return -EFAULT;

		ret = ptrace_regset(child, request, addr, &kiov);
		if (!ret)
			ret = __put_user(kiov.iov_len, &uiov->iov_len);
		break;
	}

	default:
		ret = ptrace_resume(child, engine, request, data);
		break;
	}

	utrace_engine_put(engine);
	return ret;
}

#if defined CONFIG_COMPAT
#include <linux/compat.h>

int compat_ptrace_request(struct task_struct *child, compat_long_t request,
			  compat_ulong_t addr, compat_ulong_t data)
{
	struct utrace_engine *engine = ptrace_lookup_engine(child);
	compat_ulong_t __user *datap = compat_ptr(data);
	compat_ulong_t word;
	siginfo_t siginfo;
	int ret;

	if (unlikely(IS_ERR(engine)))
		return -ESRCH;

	switch (request) {
	case PTRACE_PEEKTEXT:
	case PTRACE_PEEKDATA:
		ret = access_process_vm(child, addr, &word, sizeof(word), 0);
		if (ret != sizeof(word))
			ret = -EIO;
		else
			ret = put_user(word, datap);
		break;

	case PTRACE_POKETEXT:
	case PTRACE_POKEDATA:
		ret = access_process_vm(child, addr, &data, sizeof(data), 1);
		ret = (ret != sizeof(data) ? -EIO : 0);
		break;

	case PTRACE_GETEVENTMSG:
		ret = put_user((compat_ulong_t)ptrace_context(engine)->eventmsg,
				datap);
		break;

	case PTRACE_GETSIGINFO:
		ret = ptrace_rw_siginfo(child, ptrace_context(engine),
					&siginfo, false);
		if (!ret)
			ret = copy_siginfo_to_user32(
				(struct compat_siginfo __user *) datap,
				&siginfo);
		break;

	case PTRACE_SETSIGINFO:
		memset(&siginfo, 0, sizeof siginfo);
		if (copy_siginfo_from_user32(
			    &siginfo, (struct compat_siginfo __user *) datap))
			ret = -EFAULT;
		else
			ret = ptrace_rw_siginfo(child, ptrace_context(engine),
						&siginfo, true);
		break;

	case PTRACE_GETREGSET:
	case PTRACE_SETREGSET:
	{
		struct iovec kiov;
		struct compat_iovec __user *uiov =
			(struct compat_iovec __user *) datap;
		compat_uptr_t ptr;
		compat_size_t len;

		if (!access_ok(VERIFY_WRITE, uiov, sizeof(*uiov)))
			return -EFAULT;

		if (__get_user(ptr, &uiov->iov_base) ||
		    __get_user(len, &uiov->iov_len))
			return -EFAULT;

		kiov.iov_base = compat_ptr(ptr);
		kiov.iov_len = len;

		ret = ptrace_regset(child, request, addr, &kiov);
		if (!ret)
			ret = __put_user(kiov.iov_len, &uiov->iov_len);
		break;
	}

	default:
		ret = ptrace_request(child, request, addr, data);
	}

	utrace_engine_put(engine);
	return ret;
}
#endif	/* CONFIG_COMPAT */

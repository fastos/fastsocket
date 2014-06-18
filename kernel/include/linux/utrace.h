/*
 * utrace infrastructure interface for debugging user processes
 *
 * Copyright (C) 2006-2009 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 *
 * Red Hat Author: Roland McGrath.
 *
 * This interface allows for notification of interesting events in a
 * thread.  It also mediates access to thread state such as registers.
 * Multiple unrelated users can be associated with a single thread.
 * We call each of these a tracing engine.
 *
 * A tracing engine starts by calling utrace_attach_task() or
 * utrace_attach_pid() on the chosen thread, passing in a set of hooks
 * (&struct utrace_engine_ops), and some associated data.  This produces a
 * &struct utrace_engine, which is the handle used for all other
 * operations.  An attached engine has its ops vector, its data, and an
 * event mask controlled by utrace_set_events().
 *
 * For each event bit that is set, that engine will get the
 * appropriate ops->report_*() callback when the event occurs.  The
 * &struct utrace_engine_ops need not provide callbacks for an event
 * unless the engine sets one of the associated event bits.
 */

#ifndef _LINUX_UTRACE_H
#define _LINUX_UTRACE_H	1

#include <linux/list.h>
#include <linux/kref.h>
#include <linux/signal.h>
#include <linux/sched.h>

struct linux_binprm;
struct pt_regs;
struct utrace;
struct user_regset;
struct user_regset_view;

/*
 * Event bits passed to utrace_set_events().
 * These appear in &struct task_struct.@utrace_flags
 * and &struct utrace_engine.@flags.
 */
enum utrace_events {
	_UTRACE_EVENT_QUIESCE,	/* Thread is available for examination.  */
	_UTRACE_EVENT_REAP,  	/* Zombie reaped, no more tracing possible.  */
	_UTRACE_EVENT_CLONE,	/* Successful clone/fork/vfork just done.  */
	_UTRACE_EVENT_EXEC,	/* Successful execve just completed.  */
	_UTRACE_EVENT_EXIT,	/* Thread exit in progress.  */
	_UTRACE_EVENT_DEATH,	/* Thread has died.  */
	_UTRACE_EVENT_SYSCALL_ENTRY, /* User entered kernel for system call. */
	_UTRACE_EVENT_SYSCALL_EXIT, /* Returning to user after system call.  */
	_UTRACE_EVENT_SIGNAL,	/* Signal delivery will run a user handler.  */
	_UTRACE_EVENT_SIGNAL_IGN, /* No-op signal to be delivered.  */
	_UTRACE_EVENT_SIGNAL_STOP, /* Signal delivery will suspend.  */
	_UTRACE_EVENT_SIGNAL_TERM, /* Signal delivery will terminate.  */
	_UTRACE_EVENT_SIGNAL_CORE, /* Signal delivery will dump core.  */
	_UTRACE_EVENT_JCTL,	/* Job control stop or continue completed.  */
	_UTRACE_NEVENTS
};
#define UTRACE_EVENT(type)	(1UL << _UTRACE_EVENT_##type)

/*
 * All the kinds of signal events.
 * These all use the @report_signal() callback.
 */
#define UTRACE_EVENT_SIGNAL_ALL	(UTRACE_EVENT(SIGNAL) \
				 | UTRACE_EVENT(SIGNAL_IGN) \
				 | UTRACE_EVENT(SIGNAL_STOP) \
				 | UTRACE_EVENT(SIGNAL_TERM) \
				 | UTRACE_EVENT(SIGNAL_CORE))
/*
 * Both kinds of syscall events; these call the @report_syscall_entry()
 * and @report_syscall_exit() callbacks, respectively.
 */
#define UTRACE_EVENT_SYSCALL	\
	(UTRACE_EVENT(SYSCALL_ENTRY) | UTRACE_EVENT(SYSCALL_EXIT))

/*
 * The event reports triggered synchronously by task death.
 */
#define _UTRACE_DEATH_EVENTS (UTRACE_EVENT(DEATH) | UTRACE_EVENT(QUIESCE))

/*
 * Hooks in <linux/tracehook.h> call these entry points to the utrace dispatch.
 */
void utrace_free_task(struct task_struct *);
bool utrace_interrupt_pending(void);
void utrace_resume(struct task_struct *, struct pt_regs *);
void utrace_finish_stop(void);
void utrace_maybe_reap(struct task_struct *, struct utrace *, bool);
int utrace_get_signal(struct task_struct *, struct pt_regs *,
		      siginfo_t *, struct k_sigaction *);
void utrace_report_clone(unsigned long, struct task_struct *);
void utrace_finish_vfork(struct task_struct *);
void utrace_report_exit(long *exit_code);
void utrace_report_death(struct task_struct *, struct utrace *, bool, int);
void utrace_report_jctl(int notify, int type);
void utrace_report_exec(struct linux_binfmt *, struct linux_binprm *,
			struct pt_regs *regs);
bool utrace_report_syscall_entry(struct pt_regs *);
void utrace_report_syscall_exit(struct pt_regs *);
void utrace_signal_handler(struct task_struct *, int);

#ifndef CONFIG_UTRACE

/*
 * <linux/tracehook.h> uses these accessors to avoid #ifdef CONFIG_UTRACE.
 */
static inline unsigned long task_utrace_flags(struct task_struct *task)
{
	return 0;
}
static inline struct utrace *task_utrace_struct(struct task_struct *task)
{
	return NULL;
}
static inline void utrace_init_task(struct task_struct *child)
{
}

static inline void task_utrace_proc_status(struct seq_file *m,
					   struct task_struct *p)
{
}

static inline void utrace_freeze_stop(struct task_struct *task)
{
}
static inline void utrace_unfreeze_stop(struct task_struct *task)
{
}

#else  /* CONFIG_UTRACE */

static inline unsigned long task_utrace_flags(struct task_struct *task)
{
	return task->utrace_flags;
}

static inline struct utrace *task_utrace_struct(struct task_struct *task)
{
	struct utrace *utrace;

	/*
	 * This barrier ensures that any prior load of task->utrace_flags
	 * is ordered before this load of task->utrace.  We use those
	 * utrace_flags checks in the hot path to decide to call into
	 * the utrace code.  The first attach installs task->utrace before
	 * setting task->utrace_flags nonzero with implicit barrier in
	 * between, see utrace_add_engine().
	 */
	smp_rmb();
	utrace = task->utrace;

	smp_read_barrier_depends(); /* See utrace_task_alloc().  */
	return utrace;
}

static inline void utrace_init_task(struct task_struct *task)
{
	task->utrace_flags = 0;
	task->utrace = NULL;
}

void task_utrace_proc_status(struct seq_file *m, struct task_struct *p);


/*
 * Version number of the API defined in this file.  This will change
 * whenever a tracing engine's code would need some updates to keep
 * working.  We maintain this here for the benefit of tracing engine code
 * that is developed concurrently with utrace API improvements before they
 * are merged into the kernel, making LINUX_VERSION_CODE checks unwieldy.
 */
#define UTRACE_API_VERSION	20091216

/**
 * enum utrace_resume_action - engine's choice of action for a traced task
 * @UTRACE_STOP:		Stay quiescent after callbacks.
 * @UTRACE_INTERRUPT:		Make @report_signal() callback soon.
 * @UTRACE_REPORT:		Make some callback soon.
 * @UTRACE_SINGLESTEP:		Resume in user mode for one instruction.
 * @UTRACE_BLOCKSTEP:		Resume in user mode until next branch.
 * @UTRACE_RESUME:		Resume normally in user mode.
 * @UTRACE_DETACH:		Detach my engine (implies %UTRACE_RESUME).
 *
 * See utrace_control() for detailed descriptions of each action.  This is
 * encoded in the @action argument and the return value for every callback
 * with a &u32 return value.
 *
 * The order of these is important.  When there is more than one engine,
 * each supplies its choice and the smallest value prevails.
 */
enum utrace_resume_action {
	UTRACE_STOP,
	UTRACE_INTERRUPT,
	UTRACE_REPORT,
	UTRACE_SINGLESTEP,
	UTRACE_BLOCKSTEP,
	UTRACE_RESUME,
	UTRACE_DETACH,
	UTRACE_RESUME_MAX
};
#define UTRACE_RESUME_BITS	(ilog2(UTRACE_RESUME_MAX) + 1)
#define UTRACE_RESUME_MASK	((1 << UTRACE_RESUME_BITS) - 1)

/**
 * utrace_resume_action - &enum utrace_resume_action from callback action
 * @action:		&u32 callback @action argument or return value
 *
 * This extracts the &enum utrace_resume_action from @action,
 * which is the @action argument to a &struct utrace_engine_ops
 * callback or the return value from one.
 */
static inline enum utrace_resume_action utrace_resume_action(u32 action)
{
	return action & UTRACE_RESUME_MASK;
}

/**
 * enum utrace_signal_action - disposition of signal
 * @UTRACE_SIGNAL_DELIVER:	Deliver according to sigaction.
 * @UTRACE_SIGNAL_IGN:		Ignore the signal.
 * @UTRACE_SIGNAL_TERM:		Terminate the process.
 * @UTRACE_SIGNAL_CORE:		Terminate with core dump.
 * @UTRACE_SIGNAL_STOP:		Deliver as absolute stop.
 * @UTRACE_SIGNAL_TSTP:		Deliver as job control stop.
 * @UTRACE_SIGNAL_REPORT:	Reporting before pending signals.
 * @UTRACE_SIGNAL_HANDLER:	Reporting after signal handler setup.
 *
 * This is encoded in the @action argument and the return value for
 * a @report_signal() callback.  It says what will happen to the
 * signal described by the &siginfo_t parameter to the callback.
 *
 * The %UTRACE_SIGNAL_REPORT value is used in an @action argument when
 * a tracing report is being made before dequeuing any pending signal.
 * If this is immediately after a signal handler has been set up, then
 * %UTRACE_SIGNAL_HANDLER is used instead.  A @report_signal callback
 * that uses %UTRACE_SIGNAL_DELIVER|%UTRACE_SINGLESTEP will ensure
 * it sees a %UTRACE_SIGNAL_HANDLER report.
 */
enum utrace_signal_action {
	UTRACE_SIGNAL_DELIVER	= 0x00,
	UTRACE_SIGNAL_IGN	= 0x10,
	UTRACE_SIGNAL_TERM	= 0x20,
	UTRACE_SIGNAL_CORE	= 0x30,
	UTRACE_SIGNAL_STOP	= 0x40,
	UTRACE_SIGNAL_TSTP	= 0x50,
	UTRACE_SIGNAL_REPORT	= 0x60,
	UTRACE_SIGNAL_HANDLER	= 0x70
};
#define	UTRACE_SIGNAL_MASK	0xf0
#define UTRACE_SIGNAL_HOLD	0x100 /* Flag, push signal back on queue.  */

/**
 * utrace_signal_action - &enum utrace_signal_action from callback action
 * @action:		@report_signal callback @action argument or return value
 *
 * This extracts the &enum utrace_signal_action from @action, which
 * is the @action argument to a @report_signal callback or the
 * return value from one.
 */
static inline enum utrace_signal_action utrace_signal_action(u32 action)
{
	return action & UTRACE_SIGNAL_MASK;
}

/**
 * enum utrace_syscall_action - disposition of system call attempt
 * @UTRACE_SYSCALL_RUN:		Run the system call.
 * @UTRACE_SYSCALL_ABORT:	Don't run the system call.
 *
 * This is encoded in the @action argument and the return value for
 * a @report_syscall_entry callback.
 */
enum utrace_syscall_action {
	UTRACE_SYSCALL_RUN	= 0x00,
	UTRACE_SYSCALL_ABORT	= 0x10
};
#define	UTRACE_SYSCALL_MASK	0xf0
#define	UTRACE_SYSCALL_RESUMED	0x100 /* Flag, report_syscall_entry() repeats */

/**
 * utrace_syscall_action - &enum utrace_syscall_action from callback action
 * @action:		@report_syscall_entry callback @action or return value
 *
 * This extracts the &enum utrace_syscall_action from @action, which
 * is the @action argument to a @report_syscall_entry callback or the
 * return value from one.
 */
static inline enum utrace_syscall_action utrace_syscall_action(u32 action)
{
	return action & UTRACE_SYSCALL_MASK;
}

/*
 * Flags for utrace_attach_task() and utrace_attach_pid().
 */
#define UTRACE_ATTACH_MATCH_OPS		0x0001 /* Match engines on ops.  */
#define UTRACE_ATTACH_MATCH_DATA	0x0002 /* Match engines on data.  */
#define UTRACE_ATTACH_MATCH_MASK	0x000f
#define UTRACE_ATTACH_CREATE		0x0010 /* Attach a new engine.  */
#define UTRACE_ATTACH_EXCLUSIVE		0x0020 /* Refuse if existing match.  */

/**
 * struct utrace_engine - per-engine structure
 * @ops:	&struct utrace_engine_ops pointer passed to utrace_attach_task()
 * @data:	engine-private &void * passed to utrace_attach_task()
 * @flags:	event mask set by utrace_set_events() plus internal flag bits
 *
 * The task itself never has to worry about engines detaching while
 * it's doing event callbacks.  These structures are removed from the
 * task's active list only when it's stopped, or by the task itself.
 *
 * utrace_engine_get() and utrace_engine_put() maintain a reference count.
 * When it drops to zero, the structure is freed.  One reference is held
 * implicitly while the engine is attached to its task.
 */
struct utrace_engine {
/* private: */
	struct kref kref;
	void (*release)(void *);
	struct list_head entry;

/* public: */
	const struct utrace_engine_ops *ops;
	void *data;

	unsigned long flags;
};

/**
 * utrace_engine_get - acquire a reference on a &struct utrace_engine
 * @engine:	&struct utrace_engine pointer
 *
 * You must hold a reference on @engine, and you get another.
 */
static inline void utrace_engine_get(struct utrace_engine *engine)
{
	kref_get(&engine->kref);
}

void __utrace_engine_release(struct kref *);

/**
 * utrace_engine_put - release a reference on a &struct utrace_engine
 * @engine:	&struct utrace_engine pointer
 *
 * You must hold a reference on @engine, and you lose that reference.
 * If it was the last one, @engine becomes an invalid pointer.
 */
static inline void utrace_engine_put(struct utrace_engine *engine)
{
	kref_put(&engine->kref, __utrace_engine_release);
}

/**
 * struct utrace_engine_ops - tracing engine callbacks
 *
 * Each @report_*() callback corresponds to an %UTRACE_EVENT(*) bit.
 * utrace_set_events() calls on @engine choose which callbacks will
 * be made to @engine from @task.
 *
 * Most callbacks take an @action argument, giving the resume action
 * chosen by other tracing engines.  All callbacks take an @engine
 * argument.  The @report_reap callback takes a @task argument that
 * might or might not be @current.  All other @report_* callbacks
 * report an event in the @current task.
 *
 * For some calls, @action also includes bits specific to that event
 * and utrace_resume_action() is used to extract the resume action.
 * This shows what would happen if @engine wasn't there, or will if
 * the callback's return value uses %UTRACE_RESUME.  This always
 * starts as %UTRACE_RESUME when no other tracing is being done on
 * this task.
 *
 * All return values contain &enum utrace_resume_action bits.  For
 * some calls, other bits specific to that kind of event are added to
 * the resume action bits with OR.  These are the same bits used in
 * the @action argument.  The resume action returned by a callback
 * does not override previous engines' choices, it only says what
 * @engine wants done.  What @current actually does is the action that's
 * most constrained among the choices made by all attached engines.
 * See utrace_control() for more information on the actions.
 *
 * When %UTRACE_STOP is used in @report_syscall_entry, then @current
 * stops before attempting the system call.  In this case, another
 * @report_syscall_entry callback will follow after @current resumes if
 * %UTRACE_REPORT or %UTRACE_INTERRUPT was returned by some callback
 * or passed to utrace_control().  In a second or later callback,
 * %UTRACE_SYSCALL_RESUMED is set in the @action argument to indicate
 * a repeat callback still waiting to attempt the same system call
 * invocation.  This repeat callback gives each engine an opportunity
 * to reexamine registers another engine might have changed while
 * @current was held in %UTRACE_STOP.
 *
 * In other cases, the resume action does not take effect until @current
 * is ready to check for signals and return to user mode.  If there
 * are more callbacks to be made, the last round of calls determines
 * the final action.  A @report_quiesce callback with @event zero, or
 * a @report_signal callback, will always be the last one made before
 * @current resumes.  Only %UTRACE_STOP is "sticky"--if @engine returned
 * %UTRACE_STOP then @current stays stopped unless @engine returns
 * different from a following callback.
 *
 * The report_death() and report_reap() callbacks do not take @action
 * arguments, and only %UTRACE_DETACH is meaningful in the return value
 * from a report_death() callback.  None of the resume actions applies
 * to a dead thread.
 *
 * All @report_*() hooks are called with no locks held, in a generally
 * safe environment when we will be returning to user mode soon (or just
 * entered the kernel).  It is fine to block for memory allocation and
 * the like, but all hooks are asynchronous and must not block on
 * external events!  If you want the thread to block, use %UTRACE_STOP
 * in your hook's return value; then later wake it up with utrace_control().
 *
 * @report_quiesce:
 *	Requested by %UTRACE_EVENT(%QUIESCE).
 *	This does not indicate any event, but just that @current is in a
 *	safe place for examination.  This call is made before each specific
 *	event callback, except for @report_reap.  The @event argument gives
 *	the %UTRACE_EVENT(@which) value for the event occurring.  This
 *	callback might be made for events @engine has not requested, if
 *	some other engine is tracing the event; calling utrace_set_events()
 *	call here can request the immediate callback for this occurrence of
 *	@event.  @event is zero when there is no other event, @current is
 *	now ready to check for signals and return to user mode, and some
 *	engine has used %UTRACE_REPORT or %UTRACE_INTERRUPT to request this
 *	callback.  For this case, if @report_signal is not %NULL, the
 *	@report_quiesce callback may be replaced with a @report_signal
 *	callback passing %UTRACE_SIGNAL_REPORT in its @action argument,
 *	whenever @current is entering the signal-check path anyway.
 *
 * @report_signal:
 *	Requested by %UTRACE_EVENT(%SIGNAL_*) or %UTRACE_EVENT(%QUIESCE).
 *	Use utrace_signal_action() and utrace_resume_action() on @action.
 *	The signal action is %UTRACE_SIGNAL_REPORT when some engine has
 *	used %UTRACE_REPORT or %UTRACE_INTERRUPT; the callback can choose
 *	to stop or to deliver an artificial signal, before pending signals.
 *	It's %UTRACE_SIGNAL_HANDLER instead when signal handler setup just
 *	finished (after a previous %UTRACE_SIGNAL_DELIVER return); this
 *	serves in lieu of any %UTRACE_SIGNAL_REPORT callback requested by
 *	%UTRACE_REPORT or %UTRACE_INTERRUPT, and is also implicitly
 *	requested by %UTRACE_SINGLESTEP or %UTRACE_BLOCKSTEP into the
 *	signal delivery.  The other signal actions indicate a signal about
 *	to be delivered; the previous engine's return value sets the signal
 *	action seen by the the following engine's callback.  The @info data
 *	can be changed at will, including @info->si_signo.  The settings in
 *	@return_ka determines what %UTRACE_SIGNAL_DELIVER does.  @orig_ka
 *	is what was in force before other tracing engines intervened, and
 *	it's %NULL when this report began as %UTRACE_SIGNAL_REPORT or
 *	%UTRACE_SIGNAL_HANDLER.  For a report without a new signal, @info
 *	is left uninitialized and must be set completely by an engine that
 *	chooses to deliver a signal; if there was a previous @report_signal
 *	callback ending in %UTRACE_STOP and it was just resumed using
 *	%UTRACE_REPORT or %UTRACE_INTERRUPT, then @info is left unchanged
 *	from the previous callback.  In this way, the original signal can
 *	be left in @info while returning %UTRACE_STOP|%UTRACE_SIGNAL_IGN
 *	and then found again when resuming with %UTRACE_INTERRUPT.
 *	The %UTRACE_SIGNAL_HOLD flag bit can be OR'd into the return value,
 *	and might be in @action if the previous engine returned it.  This
 *	flag asks that the signal in @info be pushed back on @current's queue
 *	so that it will be seen again after whatever action is taken now.
 *
 * @report_clone:
 *	Requested by %UTRACE_EVENT(%CLONE).
 *	Event reported for parent, before the new task @child might run.
 *	@clone_flags gives the flags used in the clone system call, or
 *	equivalent flags for a fork() or vfork() system call.  This
 *	function can use utrace_attach_task() on @child.  Then passing
 *	%UTRACE_STOP to utrace_control() on @child here keeps the child
 *	stopped before it ever runs in user mode, %UTRACE_REPORT or
 *	%UTRACE_INTERRUPT ensures a callback from @child before it
 *	starts in user mode.
 *
 * @report_jctl:
 *	Requested by %UTRACE_EVENT(%JCTL).
 *	Job control event; @type is %CLD_STOPPED or %CLD_CONTINUED,
 *	indicating whether we are stopping or resuming now.  If @notify
 *	is nonzero, @current is the last thread to stop and so will send
 *	%SIGCHLD to its parent after this callback; @notify reflects
 *	what the parent's %SIGCHLD has in @si_code, which can sometimes
 *	be %CLD_STOPPED even when @type is %CLD_CONTINUED.
 *
 * @report_exec:
 *	Requested by %UTRACE_EVENT(%EXEC).
 *	An execve system call has succeeded and the new program is about to
 *	start running.  The initial user register state is handy to be tweaked
 *	directly in @regs.  @fmt and @bprm gives the details of this exec.
 *
 * @report_syscall_entry:
 *	Requested by %UTRACE_EVENT(%SYSCALL_ENTRY).
 *	Thread has entered the kernel to request a system call.
 *	The user register state is handy to be tweaked directly in @regs.
 *	The @action argument contains an &enum utrace_syscall_action,
 *	use utrace_syscall_action() to extract it.  The return value
 *	overrides the last engine's action for the system call.
 *	If the final action is %UTRACE_SYSCALL_ABORT, no system call
 *	is made.  The details of the system call being attempted can
 *	be fetched here with syscall_get_nr() and syscall_get_arguments().
 *	The parameter registers can be changed with syscall_set_arguments().
 *	See above about the %UTRACE_SYSCALL_RESUMED flag in @action.
 *	Use %UTRACE_REPORT in the return value to guarantee you get
 *	another callback (with %UTRACE_SYSCALL_RESUMED flag) in case
 *	@current stops with %UTRACE_STOP before attempting the system call.
 *
 * @report_syscall_exit:
 *	Requested by %UTRACE_EVENT(%SYSCALL_EXIT).
 *	Thread is about to leave the kernel after a system call request.
 *	The user register state is handy to be tweaked directly in @regs.
 *	The results of the system call attempt can be examined here using
 *	syscall_get_error() and syscall_get_return_value().  It is safe
 *	here to call syscall_set_return_value() or syscall_rollback().
 *
 * @report_exit:
 *	Requested by %UTRACE_EVENT(%EXIT).
 *	Thread is exiting and cannot be prevented from doing so,
 *	but all its state is still live.  The @code value will be
 *	the wait result seen by the parent, and can be changed by
 *	this engine or others.  The @orig_code value is the real
 *	status, not changed by any tracing engine.  Returning %UTRACE_STOP
 *	here keeps @current stopped before it cleans up its state and dies,
 *	so it can be examined by other processes.  When @current is allowed
 *	to run, it will die and get to the @report_death callback.
 *
 * @report_death:
 *	Requested by %UTRACE_EVENT(%DEATH).
 *	Thread is really dead now.  It might be reaped by its parent at
 *	any time, or self-reap immediately.  Though the actual reaping
 *	may happen in parallel, a report_reap() callback will always be
 *	ordered after a report_death() callback.
 *
 * @report_reap:
 *	Requested by %UTRACE_EVENT(%REAP).
 *	Called when someone reaps the dead task (parent, init, or self).
 *	This means the parent called wait, or else this was a detached
 *	thread or a process whose parent ignores SIGCHLD.
 *	No more callbacks are made after this one.
 *	The engine is always detached.
 *	There is nothing more a tracing engine can do about this thread.
 *	After this callback, the @engine pointer will become invalid.
 *	The @task pointer may become invalid if get_task_struct() hasn't
 *	been used to keep it alive.
 *	An engine should always request this callback if it stores the
 *	@engine pointer or stores any pointer in @engine->data, so it
 *	can clean up its data structures.
 *	Unlike other callbacks, this can be called from the parent's context
 *	rather than from the traced thread itself--it must not delay the
 *	parent by blocking.
 *
 * @release:
 *	If not %NULL, this is called after the last utrace_engine_put()
 *	call for a &struct utrace_engine, which could be implicit after
 *	a %UTRACE_DETACH return from another callback.  Its argument is
 *	the engine's @data member.
 */
struct utrace_engine_ops {
	u32 (*report_quiesce)(u32 action, struct utrace_engine *engine,
			      unsigned long event);
	u32 (*report_signal)(u32 action, struct utrace_engine *engine,
			     struct pt_regs *regs,
			     siginfo_t *info,
			     const struct k_sigaction *orig_ka,
			     struct k_sigaction *return_ka);
	u32 (*report_clone)(u32 action, struct utrace_engine *engine,
			    unsigned long clone_flags,
			    struct task_struct *child);
	u32 (*report_jctl)(u32 action, struct utrace_engine *engine,
			   int type, int notify);
	u32 (*report_exec)(u32 action, struct utrace_engine *engine,
			   const struct linux_binfmt *fmt,
			   const struct linux_binprm *bprm,
			   struct pt_regs *regs);
	u32 (*report_syscall_entry)(u32 action, struct utrace_engine *engine,
				    struct pt_regs *regs);
	u32 (*report_syscall_exit)(u32 action, struct utrace_engine *engine,
				   struct pt_regs *regs);
	u32 (*report_exit)(u32 action, struct utrace_engine *engine,
			   long orig_code, long *code);
	u32 (*report_death)(struct utrace_engine *engine,
			    bool group_dead, int signal);
	void (*report_reap)(struct utrace_engine *engine,
			    struct task_struct *task);
	void (*release)(void *data);
};

/**
 * struct utrace_examiner - private state for using utrace_prepare_examine()
 *
 * The members of &struct utrace_examiner are private to the implementation.
 * This data type holds the state from a call to utrace_prepare_examine()
 * to be used by a call to utrace_finish_examine().
 */
struct utrace_examiner {
/* private: */
	long state;
	unsigned long ncsw;
};

/*
 * These are the exported entry points for tracing engines to use.
 * See kernel/utrace.c for their kerneldoc comments with interface details.
 */
struct utrace_engine *utrace_attach_task(struct task_struct *, int,
					 const struct utrace_engine_ops *,
					 void *);
struct utrace_engine *utrace_attach_pid(struct pid *, int,
					const struct utrace_engine_ops *,
					void *);
int __must_check utrace_control(struct task_struct *,
				struct utrace_engine *,
				enum utrace_resume_action);
int __must_check utrace_set_events(struct task_struct *,
				   struct utrace_engine *,
				   unsigned long eventmask);
int __must_check utrace_barrier(struct task_struct *,
				struct utrace_engine *);
int __must_check utrace_prepare_examine(struct task_struct *,
					struct utrace_engine *,
					struct utrace_examiner *);
int __must_check utrace_finish_examine(struct task_struct *,
				       struct utrace_engine *,
				       struct utrace_examiner *);

void utrace_freeze_stop(struct task_struct *task);
void utrace_unfreeze_stop(struct task_struct *task);

/**
 * utrace_control_pid - control a thread being traced by a tracing engine
 * @pid:		thread to affect
 * @engine:		attached engine to affect
 * @action:		&enum utrace_resume_action for thread to do
 *
 * This is the same as utrace_control(), but takes a &struct pid
 * pointer rather than a &struct task_struct pointer.  The caller must
 * hold a ref on @pid, but does not need to worry about the task
 * staying valid.  If it's been reaped so that @pid points nowhere,
 * then this call returns -%ESRCH.
 */
static inline __must_check int utrace_control_pid(
	struct pid *pid, struct utrace_engine *engine,
	enum utrace_resume_action action)
{
	/*
	 * We don't bother with rcu_read_lock() here to protect the
	 * task_struct pointer, because utrace_control will return
	 * -ESRCH without looking at that pointer if the engine is
	 * already detached.  A task_struct pointer can't die before
	 * all the engines are detached in release_task() first.
	 */
	struct task_struct *task = pid_task(pid, PIDTYPE_PID);
	return unlikely(!task) ? -ESRCH : utrace_control(task, engine, action);
}

/**
 * utrace_set_events_pid - choose which event reports a tracing engine gets
 * @pid:		thread to affect
 * @engine:		attached engine to affect
 * @eventmask:		new event mask
 *
 * This is the same as utrace_set_events(), but takes a &struct pid
 * pointer rather than a &struct task_struct pointer.  The caller must
 * hold a ref on @pid, but does not need to worry about the task
 * staying valid.  If it's been reaped so that @pid points nowhere,
 * then this call returns -%ESRCH.
 */
static inline __must_check int utrace_set_events_pid(
	struct pid *pid, struct utrace_engine *engine, unsigned long eventmask)
{
	struct task_struct *task = pid_task(pid, PIDTYPE_PID);
	return unlikely(!task) ? -ESRCH :
		utrace_set_events(task, engine, eventmask);
}

/**
 * utrace_barrier_pid - synchronize with simultaneous tracing callbacks
 * @pid:		thread to affect
 * @engine:		engine to affect (can be detached)
 *
 * This is the same as utrace_barrier(), but takes a &struct pid
 * pointer rather than a &struct task_struct pointer.  The caller must
 * hold a ref on @pid, but does not need to worry about the task
 * staying valid.  If it's been reaped so that @pid points nowhere,
 * then this call returns -%ESRCH.
 */
static inline __must_check int utrace_barrier_pid(struct pid *pid,
						  struct utrace_engine *engine)
{
	struct task_struct *task = pid_task(pid, PIDTYPE_PID);
	return unlikely(!task) ? -ESRCH : utrace_barrier(task, engine);
}

#endif	/* CONFIG_UTRACE */

#endif	/* linux/utrace.h */

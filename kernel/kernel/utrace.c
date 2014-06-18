/*
 * utrace infrastructure interface for debugging user processes
 *
 * Copyright (C) 2006-2010 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 *
 * Red Hat Author: Roland McGrath.
 */

#include <linux/utrace.h>
#include <linux/tracehook.h>
#include <linux/regset.h>
#include <asm/syscall.h>
#include <linux/ptrace.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/freezer.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/seq_file.h>


/*
 * Per-thread structure private to utrace implementation.
 * If task_struct.utrace_flags is nonzero, task_struct.utrace
 * has always been allocated first.  Once allocated, it is
 * never freed until free_task().
 *
 * The common event reporting loops are done by the task making the
 * report without ever taking any locks.  To facilitate this, the two
 * lists @attached and @attaching work together for smooth asynchronous
 * attaching with low overhead.  Modifying either list requires @lock.
 * The @attaching list can be modified any time while holding @lock.
 * New engines being attached always go on this list.
 *
 * The @attached list is what the task itself uses for its reporting
 * loops.  When the task itself is not quiescent, it can use the
 * @attached list without taking any lock.  Nobody may modify the list
 * when the task is not quiescent.  When it is quiescent, that means
 * that it won't run again without taking @lock itself before using
 * the list.
 *
 * At each place where we know the task is quiescent (or it's current),
 * while holding @lock, we call splice_attaching(), below.  This moves
 * the @attaching list members on to the end of the @attached list.
 * Since this happens at the start of any reporting pass, any new
 * engines attached asynchronously go on the stable @attached list
 * in time to have their callbacks seen.
 */
struct utrace {
	spinlock_t lock;
	struct list_head attached, attaching;

	struct task_struct *cloning;

	struct utrace_engine *reporting;

	enum utrace_resume_action resume:UTRACE_RESUME_BITS;
	unsigned int signal_handler:1;
	unsigned int vfork_stop:1; /* need utrace_stop() before vfork wait */
	unsigned int death:1;	/* in utrace_report_death() now */
	unsigned int reap:1;	/* release_task() has run */
	unsigned int pending_attach:1; /* need splice_attaching() */

	bool freeze_stop;
};

static struct kmem_cache *utrace_cachep;
static struct kmem_cache *utrace_engine_cachep;
static const struct utrace_engine_ops utrace_detached_ops; /* forward decl */

static int __init utrace_init(void)
{
	utrace_cachep = KMEM_CACHE(utrace, SLAB_PANIC);
	utrace_engine_cachep = KMEM_CACHE(utrace_engine, SLAB_PANIC);
	return 0;
}
module_init(utrace_init);

/*
 * Set up @task.utrace for the first time.  We can have races
 * between two utrace_attach_task() calls here.  The task_lock()
 * governs installing the new pointer.  If another one got in first,
 * we just punt the new one we allocated.
 *
 * This returns false only in case of a memory allocation failure.
 */
static bool utrace_task_alloc(struct task_struct *task)
{
	struct utrace *utrace = kmem_cache_zalloc(utrace_cachep, GFP_KERNEL);
	if (unlikely(!utrace))
		return false;
	spin_lock_init(&utrace->lock);
	INIT_LIST_HEAD(&utrace->attached);
	INIT_LIST_HEAD(&utrace->attaching);
	utrace->resume = UTRACE_RESUME;
	task_lock(task);
	if (likely(!task->utrace)) {
		/*
		 * This barrier makes sure the initialization of the struct
		 * precedes the installation of the pointer.  This pairs
		 * with smp_read_barrier_depends() in task_utrace_struct().
		 */
		smp_wmb();
		task->utrace = utrace;
	}
	task_unlock(task);

	if (unlikely(task->utrace != utrace))
		kmem_cache_free(utrace_cachep, utrace);
	return true;
}

/*
 * This is called via tracehook_free_task() from free_task()
 * when @task is being deallocated.
 */
void utrace_free_task(struct task_struct *task)
{
	kmem_cache_free(utrace_cachep, task->utrace);
}

/*
 * This is calledwhen the task is safely quiescent, i.e. it won't consult
 * utrace->attached without the lock.  Move any engines attached
 * asynchronously from @utrace->attaching onto the @utrace->attached list.
 */
static void splice_attaching(struct utrace *utrace)
{
	lockdep_assert_held(&utrace->lock);
	list_splice_tail_init(&utrace->attaching, &utrace->attached);
	utrace->pending_attach = 0;
}

/*
 * This is the exported function used by the utrace_engine_put() inline.
 */
void __utrace_engine_release(struct kref *kref)
{
	struct utrace_engine *engine = container_of(kref, struct utrace_engine,
						    kref);
	BUG_ON(!list_empty(&engine->entry));
	if (engine->release)
		(*engine->release)(engine->data);
	kmem_cache_free(utrace_engine_cachep, engine);
}
EXPORT_SYMBOL_GPL(__utrace_engine_release);

static bool engine_matches(struct utrace_engine *engine, int flags,
			   const struct utrace_engine_ops *ops, void *data)
{
	if ((flags & UTRACE_ATTACH_MATCH_OPS) && engine->ops != ops)
		return false;
	if ((flags & UTRACE_ATTACH_MATCH_DATA) && engine->data != data)
		return false;
	return engine->ops && engine->ops != &utrace_detached_ops;
}

static struct utrace_engine *find_matching_engine(
	struct utrace *utrace, int flags,
	const struct utrace_engine_ops *ops, void *data)
{
	struct utrace_engine *engine;
	list_for_each_entry(engine, &utrace->attached, entry)
		if (engine_matches(engine, flags, ops, data))
			return engine;
	list_for_each_entry(engine, &utrace->attaching, entry)
		if (engine_matches(engine, flags, ops, data))
			return engine;
	return NULL;
}

/*
 * Enqueue @engine, or maybe don't if UTRACE_ATTACH_EXCLUSIVE.
 */
static int utrace_add_engine(struct task_struct *target,
			     struct utrace *utrace,
			     struct utrace_engine *engine,
			     int flags,
			     const struct utrace_engine_ops *ops,
			     void *data)
{
	int ret;

	spin_lock(&utrace->lock);

	ret = -EEXIST;
	if ((flags & UTRACE_ATTACH_EXCLUSIVE) &&
	     unlikely(find_matching_engine(utrace, flags, ops, data)))
		goto unlock;

	/*
	 * In case we had no engines before, make sure that
	 * utrace_flags is not zero. Since we did unlock+lock
	 * at least once after utrace_task_alloc() installed
	 * ->utrace, we have the necessary barrier which pairs
	 * with rmb() in task_utrace_struct().
	 */
	ret = -ESRCH;
	if (!target->utrace_flags) {
		target->utrace_flags = UTRACE_EVENT(REAP);
		/*
		 * If we race with tracehook_prepare_release_task()
		 * make sure that either it sees utrace_flags != 0
		 * or we see exit_state == EXIT_DEAD.
		 */
		smp_mb();
		if (unlikely(target->exit_state == EXIT_DEAD)) {
			target->utrace_flags = 0;
			goto unlock;
		}
	}

	/*
	 * Put the new engine on the pending ->attaching list.
	 * Make sure it gets onto the ->attached list by the next
	 * time it's examined.  Setting ->pending_attach ensures
	 * that start_report() takes the lock and splices the lists
	 * before the next new reporting pass.
	 *
	 * When target == current, it would be safe just to call
	 * splice_attaching() right here.  But if we're inside a
	 * callback, that would mean the new engine also gets
	 * notified about the event that precipitated its own
	 * creation.  This is not what the user wants.
	 */
	list_add_tail(&engine->entry, &utrace->attaching);
	utrace->pending_attach = 1;
	ret = 0;
unlock:
	spin_unlock(&utrace->lock);

	return ret;
}

/**
 * utrace_attach_task - attach new engine, or look up an attached engine
 * @target:	thread to attach to
 * @flags:	flag bits combined with OR, see below
 * @ops:	callback table for new engine
 * @data:	engine private data pointer
 *
 * The caller must ensure that the @target thread does not get freed,
 * i.e. hold a ref or be its parent.  It is always safe to call this
 * on @current, or on the @child pointer in a @report_clone callback.
 * For most other cases, it's easier to use utrace_attach_pid() instead.
 *
 * UTRACE_ATTACH_CREATE:
 * Create a new engine.  If %UTRACE_ATTACH_CREATE is not specified, you
 * only look up an existing engine already attached to the thread.
 *
 * UTRACE_ATTACH_EXCLUSIVE:
 * Attempting to attach a second (matching) engine fails with -%EEXIST.
 *
 * UTRACE_ATTACH_MATCH_OPS: Only consider engines matching @ops.
 * UTRACE_ATTACH_MATCH_DATA: Only consider engines matching @data.
 *
 * Calls with neither %UTRACE_ATTACH_MATCH_OPS nor %UTRACE_ATTACH_MATCH_DATA
 * match the first among any engines attached to @target.  That means that
 * %UTRACE_ATTACH_EXCLUSIVE in such a call fails with -%EEXIST if there
 * are any engines on @target at all.
 */
struct utrace_engine *utrace_attach_task(
	struct task_struct *target, int flags,
	const struct utrace_engine_ops *ops, void *data)
{
	struct utrace *utrace = task_utrace_struct(target);
	struct utrace_engine *engine;
	int ret;

	if (!(flags & UTRACE_ATTACH_CREATE)) {
		if (unlikely(!utrace))
			return ERR_PTR(-ENOENT);
		spin_lock(&utrace->lock);
		engine = find_matching_engine(utrace, flags, ops, data);
		if (engine)
			utrace_engine_get(engine);
		spin_unlock(&utrace->lock);
		return engine ?: ERR_PTR(-ENOENT);
	}

	if (unlikely(!ops) || unlikely(ops == &utrace_detached_ops))
		return ERR_PTR(-EINVAL);

	if (unlikely(target->flags & PF_KTHREAD))
		/*
		 * Silly kernel, utrace is for users!
		 */
		return ERR_PTR(-EPERM);

	if (!utrace) {
		if (unlikely(!utrace_task_alloc(target)))
			return ERR_PTR(-ENOMEM);
		utrace = task_utrace_struct(target);
	}

	engine = kmem_cache_alloc(utrace_engine_cachep, GFP_KERNEL);
	if (unlikely(!engine))
		return ERR_PTR(-ENOMEM);

	/*
	 * Initialize the new engine structure.  It starts out with two
	 * refs: one ref to return, and one ref for being attached.
	 */
	kref_set(&engine->kref, 2);
	engine->flags = 0;
	engine->ops = ops;
	engine->data = data;
	engine->release = ops->release;

	ret = utrace_add_engine(target, utrace, engine, flags, ops, data);

	if (unlikely(ret)) {
		kmem_cache_free(utrace_engine_cachep, engine);
		engine = ERR_PTR(ret);
	}

	return engine;
}
EXPORT_SYMBOL_GPL(utrace_attach_task);

/**
 * utrace_attach_pid - attach new engine, or look up an attached engine
 * @pid:	&struct pid pointer representing thread to attach to
 * @flags:	flag bits combined with OR, see utrace_attach_task()
 * @ops:	callback table for new engine
 * @data:	engine private data pointer
 *
 * This is the same as utrace_attach_task(), but takes a &struct pid
 * pointer rather than a &struct task_struct pointer.  The caller must
 * hold a ref on @pid, but does not need to worry about the task
 * staying valid.  If it's been reaped so that @pid points nowhere,
 * then this call returns -%ESRCH.
 */
struct utrace_engine *utrace_attach_pid(
	struct pid *pid, int flags,
	const struct utrace_engine_ops *ops, void *data)
{
	struct utrace_engine *engine = ERR_PTR(-ESRCH);
	struct task_struct *task = get_pid_task(pid, PIDTYPE_PID);
	if (task) {
		engine = utrace_attach_task(task, flags, ops, data);
		put_task_struct(task);
	}
	return engine;
}
EXPORT_SYMBOL_GPL(utrace_attach_pid);

/*
 * When an engine is detached, the target thread may still see it and
 * make callbacks until it quiesces.  We install a special ops vector
 * with these two callbacks.  When the target thread quiesces, it can
 * safely free the engine itself.  For any event we will always get
 * the report_quiesce() callback first, so we only need this one
 * pointer to be set.  The only exception is report_reap(), so we
 * supply that callback too.
 */
static u32 utrace_detached_quiesce(u32 action, struct utrace_engine *engine,
				   unsigned long event)
{
	return UTRACE_DETACH;
}

static void utrace_detached_reap(struct utrace_engine *engine,
				 struct task_struct *task)
{
}

static const struct utrace_engine_ops utrace_detached_ops = {
	.report_quiesce = &utrace_detached_quiesce,
	.report_reap = &utrace_detached_reap
};

/*
 * The caller has to hold a ref on the engine.  If the attached flag is
 * true (all but utrace_barrier() calls), the engine is supposed to be
 * attached.  If the attached flag is false (utrace_barrier() only),
 * then return -ERESTARTSYS for an engine marked for detach but not yet
 * fully detached.  The task pointer can be invalid if the engine is
 * detached.
 *
 * Get the utrace lock for the target task.
 * Returns the struct if locked, or ERR_PTR(-errno).
 *
 * This has to be robust against races with:
 *	utrace_control(target, UTRACE_DETACH) calls
 *	UTRACE_DETACH after reports
 *	utrace_report_death
 *	utrace_release_task
 */
static struct utrace *get_utrace_lock(struct task_struct *target,
				      struct utrace_engine *engine,
				      bool attached)
	__acquires(utrace->lock)
{
	struct utrace *utrace;

	rcu_read_lock();

	/*
	 * If this engine was already detached, bail out before we look at
	 * the task_struct pointer at all.  If it's detached after this
	 * check, then RCU is still keeping this task_struct pointer valid.
	 *
	 * The ops pointer is NULL when the engine is fully detached.
	 * It's &utrace_detached_ops when it's marked detached but still
	 * on the list.  In the latter case, utrace_barrier() still works,
	 * since the target might be in the middle of an old callback.
	 */
	if (unlikely(!engine->ops)) {
		rcu_read_unlock();
		return ERR_PTR(-ESRCH);
	}

	if (unlikely(engine->ops == &utrace_detached_ops)) {
		rcu_read_unlock();
		return attached ? ERR_PTR(-ESRCH) : ERR_PTR(-ERESTARTSYS);
	}

	utrace = task_utrace_struct(target);
	spin_lock(&utrace->lock);
	if (unlikely(!engine->ops) ||
	    unlikely(engine->ops == &utrace_detached_ops)) {
		/*
		 * By the time we got the utrace lock,
		 * it had been reaped or detached already.
		 */
		spin_unlock(&utrace->lock);
		utrace = ERR_PTR(-ESRCH);
		if (!attached && engine->ops == &utrace_detached_ops)
			utrace = ERR_PTR(-ERESTARTSYS);
	}
	rcu_read_unlock();

	return utrace;
}

/*
 * Now that we don't hold any locks, run through any
 * detached engines and free their references.  Each
 * engine had one implicit ref while it was attached.
 */
static void put_detached_list(struct list_head *list)
{
	struct utrace_engine *engine, *next;
	list_for_each_entry_safe(engine, next, list, entry) {
		list_del_init(&engine->entry);
		utrace_engine_put(engine);
	}
}

/*
 * We use an extra bit in utrace_engine.flags past the event bits,
 * to record whether the engine is keeping the target thread stopped.
 *
 * This bit is set in task_struct.utrace_flags whenever it is set in any
 * engine's flags.  Only utrace_reset() resets it in utrace_flags.
 */
#define ENGINE_STOP		(1UL << _UTRACE_NEVENTS)

static void mark_engine_wants_stop(struct task_struct *task,
				   struct utrace_engine *engine)
{
	engine->flags |= ENGINE_STOP;
	task->utrace_flags |= ENGINE_STOP;
}

static void clear_engine_wants_stop(struct utrace_engine *engine)
{
	engine->flags &= ~ENGINE_STOP;
}

static bool engine_wants_stop(struct utrace_engine *engine)
{
	return (engine->flags & ENGINE_STOP) != 0;
}

/**
 * utrace_set_events - choose which event reports a tracing engine gets
 * @target:		thread to affect
 * @engine:		attached engine to affect
 * @events:		new event mask
 *
 * This changes the set of events for which @engine wants callbacks made.
 *
 * This fails with -%EALREADY and does nothing if you try to clear
 * %UTRACE_EVENT(%DEATH) when the @report_death callback may already have
 * begun, if you try to clear %UTRACE_EVENT(%REAP) when the @report_reap
 * callback may already have begun, or if you try to newly set
 * %UTRACE_EVENT(%DEATH) or %UTRACE_EVENT(%QUIESCE) when @target is
 * already dead or dying.
 *
 * This can fail with -%ESRCH when @target has already been detached,
 * including forcible detach on reaping.
 *
 * If @target was stopped before the call, then after a successful call,
 * no event callbacks not requested in @events will be made; if
 * %UTRACE_EVENT(%QUIESCE) is included in @events, then a
 * @report_quiesce callback will be made when @target resumes.
 *
 * If @target was not stopped and @events excludes some bits that were
 * set before, this can return -%EINPROGRESS to indicate that @target
 * may have been making some callback to @engine.  When this returns
 * zero, you can be sure that no event callbacks you've disabled in
 * @events can be made.  If @events only sets new bits that were not set
 * before on @engine, then -%EINPROGRESS will never be returned.
 *
 * To synchronize after an -%EINPROGRESS return, see utrace_barrier().
 *
 * When @target is @current, -%EINPROGRESS is not returned.  But note
 * that a newly-created engine will not receive any callbacks related to
 * an event notification already in progress.  This call enables @events
 * callbacks to be made as soon as @engine becomes eligible for any
 * callbacks, see utrace_attach_task().
 *
 * These rules provide for coherent synchronization based on %UTRACE_STOP,
 * even when %SIGKILL is breaking its normal simple rules.
 */
int utrace_set_events(struct task_struct *target,
		      struct utrace_engine *engine,
		      unsigned long events)
{
	struct utrace *utrace;
	unsigned long old_flags, old_utrace_flags;
	int ret;

	/*
	 * We just ignore the internal bit, so callers can use
	 * engine->flags to seed bitwise ops for our argument.
	 */
	events &= ~ENGINE_STOP;

	utrace = get_utrace_lock(target, engine, true);
	if (unlikely(IS_ERR(utrace)))
		return PTR_ERR(utrace);

	old_utrace_flags = target->utrace_flags;
	old_flags = engine->flags & ~ENGINE_STOP;

	if (target->exit_state &&
	    (((events & ~old_flags) & _UTRACE_DEATH_EVENTS) ||
	     (utrace->death &&
	      ((old_flags & ~events) & _UTRACE_DEATH_EVENTS)) ||
	     (utrace->reap && ((old_flags & ~events) & UTRACE_EVENT(REAP))))) {
		spin_unlock(&utrace->lock);
		return -EALREADY;
	}

	/*
	 * When setting these flags, it's essential that we really
	 * synchronize with exit_notify().  They cannot be set after
	 * exit_notify() takes the tasklist_lock.  By holding the read
	 * lock here while setting the flags, we ensure that the calls
	 * to tracehook_notify_death() and tracehook_report_death() will
	 * see the new flags.  This ensures that utrace_release_task()
	 * knows positively that utrace_report_death() will be called or
	 * that it won't.
	 */
	if ((events & ~old_utrace_flags) & _UTRACE_DEATH_EVENTS) {
		read_lock(&tasklist_lock);
		if (unlikely(target->exit_state)) {
			read_unlock(&tasklist_lock);
			spin_unlock(&utrace->lock);
			return -EALREADY;
		}
		target->utrace_flags |= events;
		read_unlock(&tasklist_lock);
	}

	engine->flags = events | (engine->flags & ENGINE_STOP);
	target->utrace_flags |= events;

	if ((events & UTRACE_EVENT_SYSCALL) &&
	    !(old_utrace_flags & UTRACE_EVENT_SYSCALL))
		set_tsk_thread_flag(target, TIF_SYSCALL_TRACE);

	ret = 0;
	if ((old_flags & ~events) && target != current &&
	    !task_is_stopped_or_traced(target) && !target->exit_state) {
		/*
		 * This barrier ensures that our engine->flags changes
		 * have hit before we examine utrace->reporting,
		 * pairing with the barrier in start_callback().  If
		 * @target has not yet hit finish_callback() to clear
		 * utrace->reporting, we might be in the middle of a
		 * callback to @engine.
		 */
		smp_mb();
		if (utrace->reporting == engine)
			ret = -EINPROGRESS;
	}

	spin_unlock(&utrace->lock);

	return ret;
}
EXPORT_SYMBOL_GPL(utrace_set_events);

/*
 * Asynchronously mark an engine as being detached.
 *
 * This must work while the target thread races with us doing
 * start_callback(), defined below.  It uses smp_rmb() between checking
 * @engine->flags and using @engine->ops.  Here we change @engine->ops
 * first, then use smp_wmb() before changing @engine->flags.  This ensures
 * it can check the old flags before using the old ops, or check the old
 * flags before using the new ops, or check the new flags before using the
 * new ops, but can never check the new flags before using the old ops.
 * Hence, utrace_detached_ops might be used with any old flags in place.
 * It has report_quiesce() and report_reap() callbacks to handle all cases.
 */
static void mark_engine_detached(struct utrace_engine *engine)
{
	engine->ops = &utrace_detached_ops;
	smp_wmb();
	engine->flags = UTRACE_EVENT(QUIESCE);
}

/*
 * Get @target to stop and return true if it is already stopped now.
 * If we return false, it will make some event callback soonish.
 * Called with @utrace locked.
 */
static bool utrace_do_stop(struct task_struct *target, struct utrace *utrace)
{
	if (task_is_stopped(target)) {
		/*
		 * Stopped is considered quiescent; when it wakes up, it will
		 * go through utrace_finish_stop() before doing anything else.
		 */
		spin_lock_irq(&target->sighand->siglock);
		if (likely(task_is_stopped(target)))
			__set_task_state(target, TASK_TRACED);
		spin_unlock_irq(&target->sighand->siglock);
	} else if (utrace->resume > UTRACE_REPORT) {
		utrace->resume = UTRACE_REPORT;
		set_notify_resume(target);
	}

	return task_is_traced(target);
}

/*
 * If the target is not dead it should not be in tracing
 * stop any more.  Wake it unless it's in job control stop.
 */
static void utrace_wakeup(struct task_struct *target, struct utrace *utrace)
{
	lockdep_assert_held(&utrace->lock);
	spin_lock_irq(&target->sighand->siglock);
	if (target->signal->flags & SIGNAL_STOP_STOPPED ||
	    target->signal->group_stop_count)
		target->state = TASK_STOPPED;
	else
		wake_up_state(target, __TASK_TRACED);
	spin_unlock_irq(&target->sighand->siglock);
}

/*
 * This is called when there might be some detached engines on the list or
 * some stale bits in @task->utrace_flags.  Clean them up and recompute the
 * flags.  Returns true if we're now fully detached.
 *
 * Called with @utrace->lock held, returns with it released.
 * After this returns, @utrace might be freed if everything detached.
 */
static bool utrace_reset(struct task_struct *task, struct utrace *utrace)
	__releases(utrace->lock)
{
	struct utrace_engine *engine, *next;
	unsigned long flags = 0;
	LIST_HEAD(detached);

	splice_attaching(utrace);

	/*
	 * Update the set of events of interest from the union
	 * of the interests of the remaining tracing engines.
	 * For any engine marked detached, remove it from the list.
	 * We'll collect them on the detached list.
	 */
	list_for_each_entry_safe(engine, next, &utrace->attached, entry) {
		if (engine->ops == &utrace_detached_ops) {
			engine->ops = NULL;
			list_move(&engine->entry, &detached);
		} else {
			flags |= engine->flags | UTRACE_EVENT(REAP);
		}
	}

	if (task->exit_state) {
		/*
		 * Once it's already dead, we never install any flags
		 * except REAP.  When ->exit_state is set and events
		 * like DEATH are not set, then they never can be set.
		 * This ensures that utrace_release_task() knows
		 * positively that utrace_report_death() can never run.
		 */
		BUG_ON(utrace->death);
		flags &= UTRACE_EVENT(REAP);
	} else if (!(flags & UTRACE_EVENT_SYSCALL) &&
		   test_tsk_thread_flag(task, TIF_SYSCALL_TRACE)) {
		clear_tsk_thread_flag(task, TIF_SYSCALL_TRACE);
	}

	if (!flags) {
		/*
		 * No more engines, cleared out the utrace.
		 */
		utrace->resume = UTRACE_RESUME;
		utrace->signal_handler = 0;
	}

	/*
	 * If no more engines want it stopped, wake it up.
	 */
	if (task_is_traced(task) && !(flags & ENGINE_STOP)) {
		/*
		 * It just resumes, so make sure single-step
		 * is not left set.
		 */
		if (utrace->resume == UTRACE_RESUME)
			user_disable_single_step(task);
		utrace_wakeup(task, utrace);
	}

	/*
	 * In theory spin_lock() doesn't imply rcu_read_lock().
	 * Once we clear ->utrace_flags this task_struct can go away
	 * because tracehook_prepare_release_task() path does not take
	 * utrace->lock when ->utrace_flags == 0.
	 */
	rcu_read_lock();
	task->utrace_flags = flags;
	spin_unlock(&utrace->lock);
	rcu_read_unlock();

	put_detached_list(&detached);

	return !flags;
}

void utrace_freeze_stop(struct task_struct *task)
{
	struct utrace *utrace = task_utrace_struct(task);

	WARN_ON(utrace->freeze_stop);
	utrace->freeze_stop = true;
}

void utrace_unfreeze_stop(struct task_struct *task)
{
	task_utrace_struct(task)->freeze_stop = false;
}

void utrace_finish_stop(void)
{
	/*
	 * If we were task_is_traced() and then SIGKILL'ed, make
	 * sure we do nothing until the tracer drops utrace->lock.
	 */
	if (unlikely(__fatal_signal_pending(current))) {
		struct utrace *utrace = task_utrace_struct(current);
		spin_unlock_wait(&utrace->lock);
		/*
		 * Make sure we do not return to the low-level code if the
		 * tracer plays with our registers/etc, see the upstream
		 * 9899d11f commit/changelog.
		 *
		 * Note that ptrace_check_attach() does utrace_freeze_stop()
		 * before utrace_prepare_examine()->wait_task_inactive() which
		 * acts as a barrier, we can not miss ->freeze_stop if the
		 * tracee was killed after wait_task_inactive() succeeds.
		 */
		while (utrace->freeze_stop)
			schedule_timeout_uninterruptible(1);
	}
}

/*
 * Perform %UTRACE_STOP, i.e. block in TASK_TRACED until woken up.
 * @task == current, @utrace == current->utrace, which is not locked.
 * Return true if we were woken up by SIGKILL even though some utrace
 * engine may still want us to stay stopped.
 */
static void utrace_stop(struct task_struct *task, struct utrace *utrace,
			enum utrace_resume_action action)
{
relock:
	spin_lock(&utrace->lock);

	if (action < utrace->resume) {
		/*
		 * Ensure a reporting pass when we're resumed.
		 */
		utrace->resume = action;
		if (action == UTRACE_INTERRUPT)
			set_thread_flag(TIF_SIGPENDING);
		else
			set_thread_flag(TIF_NOTIFY_RESUME);
	}

	/*
	 * If the ENGINE_STOP bit is clear in utrace_flags, that means
	 * utrace_reset() ran after we processed some UTRACE_STOP return
	 * values from callbacks to get here.  If all engines have detached
	 * or resumed us, we don't stop.  This check doesn't require
	 * siglock, but it should follow the interrupt/report bookkeeping
	 * steps (this can matter for UTRACE_RESUME but not UTRACE_DETACH).
	 */
	if (unlikely(!(task->utrace_flags & ENGINE_STOP))) {
		utrace_reset(task, utrace);
		if (task->utrace_flags & ENGINE_STOP)
			goto relock;
		return;
	}

	/*
	 * The siglock protects us against signals.  As well as SIGKILL
	 * waking us up, we must synchronize with the signal bookkeeping
	 * for stop signals and SIGCONT.
	 */
	spin_lock_irq(&task->sighand->siglock);

	if (unlikely(__fatal_signal_pending(task))) {
		spin_unlock_irq(&task->sighand->siglock);
		spin_unlock(&utrace->lock);
		return;
	}

	__set_current_state(TASK_TRACED);

	/*
	 * If there is a group stop in progress,
	 * we must participate in the bookkeeping.
	 */
	if (unlikely(task->signal->group_stop_count) &&
			!--task->signal->group_stop_count)
		task->signal->flags = SIGNAL_STOP_STOPPED;

	spin_unlock_irq(&task->sighand->siglock);
	spin_unlock(&utrace->lock);

	/*
	 * If ptrace is among the reasons for this stop, do its
	 * notification now.  This could not just be done in
	 * ptrace's own event report callbacks because it has to
	 * be done after we are in TASK_TRACED.  This makes the
	 * synchronization with ptrace_do_wait() work right.
	 *
	 * It's only because of the bad old overloading of the do_wait()
	 * logic for handling ptrace stops that we need this special case
	 * here.  One day we will clean up ptrace so it does not need to
	 * work this way.  New things that are designed sensibly don't need
	 * a wakeup that synchronizes with tasklist_lock and ->state, so
	 * the proper utrace API does not try to support this weirdness.
	 */
	ptrace_notify_stop(task);

	schedule();

	utrace_finish_stop();

	/*
	 * While in TASK_TRACED, we were considered "frozen enough".
	 * Now that we woke up, it's crucial if we're supposed to be
	 * frozen that we freeze now before running anything substantial.
	 */
	try_to_freeze();

	/*
	 * While we were in TASK_TRACED, complete_signal() considered
	 * us "uninterested" in signal wakeups.  Now make sure our
	 * TIF_SIGPENDING state is correct for normal running.
	 */
	spin_lock_irq(&task->sighand->siglock);
	recalc_sigpending();
	spin_unlock_irq(&task->sighand->siglock);
}

/*
 * Called by release_task() with @reap set to true.
 * Called by utrace_report_death() with @reap set to false.
 * On reap, make report_reap callbacks and clean out @utrace
 * unless still making callbacks.  On death, update bookkeeping
 * and handle the reap work if release_task() came in first.
 */
void utrace_maybe_reap(struct task_struct *target, struct utrace *utrace,
		       bool reap)
{
	struct utrace_engine *engine, *next;
	struct list_head attached;

	spin_lock(&utrace->lock);

	if (reap) {
		/*
		 * If the target will do some final callbacks but hasn't
		 * finished them yet, we know because it clears these event
		 * bits after it's done.  Instead of cleaning up here and
		 * requiring utrace_report_death() to cope with it, we
		 * delay the REAP report and the teardown until after the
		 * target finishes its death reports.
		 */
		utrace->reap = 1;

		if (target->utrace_flags & _UTRACE_DEATH_EVENTS) {
			spin_unlock(&utrace->lock);
			return;
		}
	} else {
		/*
		 * After we unlock with this flag clear, any competing
		 * utrace_control/utrace_set_events calls know that we've
		 * finished our callbacks and any detach bookkeeping.
		 */
		utrace->death = 0;

		if (!utrace->reap) {
			/*
			 * We're just dead, not reaped yet.  This will
			 * reset @target->utrace_flags so the later call
			 * with @reap set won't hit the check above.
			 */
			utrace_reset(target, utrace);
			return;
		}
	}

	/*
	 * utrace_add_engine() checks ->utrace_flags != 0.  Since
	 * @utrace->reap is set, nobody can set or clear UTRACE_EVENT(REAP)
	 * in @engine->flags or change @engine->ops and nobody can change
	 * @utrace->attached after we drop the lock.
	 */
	target->utrace_flags = 0;

	/*
	 * We clear out @utrace->attached before we drop the lock so
	 * that find_matching_engine() can't come across any old engine
	 * while we are busy tearing it down.
	 */
	list_replace_init(&utrace->attached, &attached);
	list_splice_tail_init(&utrace->attaching, &attached);

	spin_unlock(&utrace->lock);

	list_for_each_entry_safe(engine, next, &attached, entry) {
		if (engine->flags & UTRACE_EVENT(REAP))
			engine->ops->report_reap(engine, target);

		engine->ops = NULL;
		engine->flags = 0;
		list_del_init(&engine->entry);

		utrace_engine_put(engine);
	}
}

/*
 * You can't do anything to a dead task but detach it.
 * If release_task() has been called, you can't do that.
 *
 * On the exit path, DEATH and QUIESCE event bits are set only
 * before utrace_report_death() has taken the lock.  At that point,
 * the death report will come soon, so disallow detach until it's
 * done.  This prevents us from racing with it detaching itself.
 *
 * Called only when @target->exit_state is nonzero.
 */
static inline int utrace_control_dead(struct task_struct *target,
				      struct utrace *utrace,
				      enum utrace_resume_action action)
{
	lockdep_assert_held(&utrace->lock);

	if (action != UTRACE_DETACH || unlikely(utrace->reap))
		return -ESRCH;

	if (unlikely(utrace->death))
		/*
		 * We have already started the death report.  We can't
		 * prevent the report_death and report_reap callbacks,
		 * so tell the caller they will happen.
		 */
		return -EALREADY;

	return 0;
}

/**
 * utrace_control - control a thread being traced by a tracing engine
 * @target:		thread to affect
 * @engine:		attached engine to affect
 * @action:		&enum utrace_resume_action for thread to do
 *
 * This is how a tracing engine asks a traced thread to do something.
 * This call is controlled by the @action argument, which has the
 * same meaning as the &enum utrace_resume_action value returned by
 * event reporting callbacks.
 *
 * If @target is already dead (@target->exit_state nonzero),
 * all actions except %UTRACE_DETACH fail with -%ESRCH.
 *
 * The following sections describe each option for the @action argument.
 *
 * UTRACE_DETACH:
 *
 * After this, the @engine data structure is no longer accessible,
 * and the thread might be reaped.  The thread will start running
 * again if it was stopped and no longer has any attached engines
 * that want it stopped.
 *
 * If the @report_reap callback may already have begun, this fails
 * with -%ESRCH.  If the @report_death callback may already have
 * begun, this fails with -%EALREADY.
 *
 * If @target is not already stopped, then a callback to this engine
 * might be in progress or about to start on another CPU.  If so,
 * then this returns -%EINPROGRESS; the detach happens as soon as
 * the pending callback is finished.  To synchronize after an
 * -%EINPROGRESS return, see utrace_barrier().
 *
 * If @target is properly stopped before utrace_control() is called,
 * then after successful return it's guaranteed that no more callbacks
 * to the @engine->ops vector will be made.
 *
 * The only exception is %SIGKILL (and exec or group-exit by another
 * thread in the group), which can cause asynchronous @report_death
 * and/or @report_reap callbacks even when %UTRACE_STOP was used.
 * (In that event, this fails with -%ESRCH or -%EALREADY, see above.)
 *
 * UTRACE_STOP:
 *
 * This asks that @target stop running.  This returns 0 only if
 * @target is already stopped, either for tracing or for job
 * control.  Then @target will remain stopped until another
 * utrace_control() call is made on @engine; @target can be woken
 * only by %SIGKILL (or equivalent, such as exec or termination by
 * another thread in the same thread group).
 *
 * This returns -%EINPROGRESS if @target is not already stopped.
 * Then the effect is like %UTRACE_REPORT.  A @report_quiesce or
 * @report_signal callback will be made soon.  Your callback can
 * then return %UTRACE_STOP to keep @target stopped.
 *
 * This does not interrupt system calls in progress, including ones
 * that sleep for a long time.  For that, use %UTRACE_INTERRUPT.
 * To interrupt system calls and then keep @target stopped, your
 * @report_signal callback can return %UTRACE_STOP.
 *
 * UTRACE_RESUME:
 *
 * Just let @target continue running normally, reversing the effect
 * of a previous %UTRACE_STOP.  If another engine is keeping @target
 * stopped, then it remains stopped until all engines let it resume.
 * If @target was not stopped, this has no effect.
 *
 * UTRACE_REPORT:
 *
 * This is like %UTRACE_RESUME, but also ensures that there will be
 * a @report_quiesce or @report_signal callback made soon.  If
 * @target had been stopped, then there will be a callback before it
 * resumes running normally.  If another engine is keeping @target
 * stopped, then there might be no callbacks until all engines let
 * it resume.
 *
 * Since this is meaningless unless @report_quiesce callbacks will
 * be made, it returns -%EINVAL if @engine lacks %UTRACE_EVENT(%QUIESCE).
 *
 * UTRACE_INTERRUPT:
 *
 * This is like %UTRACE_REPORT, but ensures that @target will make a
 * @report_signal callback before it resumes or delivers signals.
 * If @target was in a system call or about to enter one, work in
 * progress will be interrupted as if by %SIGSTOP.  If another
 * engine is keeping @target stopped, then there might be no
 * callbacks until all engines let it resume.
 *
 * This gives @engine an opportunity to introduce a forced signal
 * disposition via its @report_signal callback.
 *
 * UTRACE_SINGLESTEP:
 *
 * It's invalid to use this unless arch_has_single_step() returned true.
 * This is like %UTRACE_RESUME, but resumes for one user instruction only.
 *
 * Note that passing %UTRACE_SINGLESTEP or %UTRACE_BLOCKSTEP to
 * utrace_control() or returning it from an event callback alone does
 * not necessarily ensure that stepping will be enabled.  If there are
 * more callbacks made to any engine before returning to user mode,
 * then the resume action is chosen only by the last set of callbacks.
 * To be sure, enable %UTRACE_EVENT(%QUIESCE) and look for the
 * @report_quiesce callback with a zero event mask, or the
 * @report_signal callback with %UTRACE_SIGNAL_REPORT.
 *
 * Since this is not robust unless @report_quiesce callbacks will
 * be made, it returns -%EINVAL if @engine lacks %UTRACE_EVENT(%QUIESCE).
 *
 * UTRACE_BLOCKSTEP:
 *
 * It's invalid to use this unless arch_has_block_step() returned true.
 * This is like %UTRACE_SINGLESTEP, but resumes for one whole basic
 * block of user instructions.
 *
 * Since this is not robust unless @report_quiesce callbacks will
 * be made, it returns -%EINVAL if @engine lacks %UTRACE_EVENT(%QUIESCE).
 *
 * %UTRACE_BLOCKSTEP devolves to %UTRACE_SINGLESTEP when another
 * tracing engine is using %UTRACE_SINGLESTEP at the same time.
 */
int utrace_control(struct task_struct *target,
		   struct utrace_engine *engine,
		   enum utrace_resume_action action)
{
	struct utrace *utrace;
	bool reset;
	int ret;

	if (unlikely(action >= UTRACE_RESUME_MAX)) {
		WARN(1, "invalid action argument to utrace_control()!");
		return -EINVAL;
	}

	/*
	 * This is a sanity check for a programming error in the caller.
	 * Their request can only work properly in all cases by relying on
	 * a follow-up callback, but they didn't set one up!  This check
	 * doesn't do locking, but it shouldn't matter.  The caller has to
	 * be synchronously sure the callback is set up to be operating the
	 * interface properly.
	 */
	if (action >= UTRACE_REPORT && action < UTRACE_RESUME &&
	    unlikely(!(engine->flags & UTRACE_EVENT(QUIESCE)))) {
		WARN(1, "utrace_control() with no QUIESCE callback in place!");
		return -EINVAL;
	}

	utrace = get_utrace_lock(target, engine, true);
	if (unlikely(IS_ERR(utrace)))
		return PTR_ERR(utrace);

	reset = task_is_traced(target);
	ret = 0;

	/*
	 * ->exit_state can change under us, this doesn't matter.
	 * We do not care about ->exit_state in fact, but we do
	 * care about ->reap and ->death. If either flag is set,
	 * we must also see ->exit_state != 0.
	 */
	if (unlikely(target->exit_state)) {
		ret = utrace_control_dead(target, utrace, action);
		if (ret) {
			spin_unlock(&utrace->lock);
			return ret;
		}
		reset = true;
	}

	switch (action) {
	case UTRACE_STOP:
		mark_engine_wants_stop(target, engine);
		if (!reset && !utrace_do_stop(target, utrace))
			ret = -EINPROGRESS;
		reset = false;
		break;

	case UTRACE_DETACH:
		if (engine_wants_stop(engine))
			target->utrace_flags &= ~ENGINE_STOP;
		mark_engine_detached(engine);
		reset = reset || utrace_do_stop(target, utrace);
		if (!reset) {
			/*
			 * As in utrace_set_events(), this barrier ensures
			 * that our engine->flags changes have hit before we
			 * examine utrace->reporting, pairing with the barrier
			 * in start_callback().  If @target has not yet hit
			 * finish_callback() to clear utrace->reporting, we
			 * might be in the middle of a callback to @engine.
			 */
			smp_mb();
			if (utrace->reporting == engine)
				ret = -EINPROGRESS;
		}
		break;

	case UTRACE_RESUME:
		clear_engine_wants_stop(engine);
		break;

	case UTRACE_BLOCKSTEP:
		/*
		 * Resume from stopped, step one block.
		 * We fall through to treat it like UTRACE_SINGLESTEP.
		 */
		if (unlikely(!arch_has_block_step())) {
			WARN(1, "UTRACE_BLOCKSTEP when !arch_has_block_step()");
			action = UTRACE_SINGLESTEP;
		}

	case UTRACE_SINGLESTEP:
		/*
		 * Resume from stopped, step one instruction.
		 * We fall through to the UTRACE_REPORT case.
		 */
		if (unlikely(!arch_has_single_step())) {
			WARN(1,
			     "UTRACE_SINGLESTEP when !arch_has_single_step()");
			reset = false;
			ret = -EOPNOTSUPP;
			break;
		}

	case UTRACE_REPORT:
		/*
		 * Make the thread call tracehook_notify_resume() soon.
		 * But don't bother if it's already been interrupted.
		 * In that case, utrace_get_signal() will be reporting soon.
		 */
		clear_engine_wants_stop(engine);
		if (action < utrace->resume) {
			utrace->resume = action;
			set_notify_resume(target);
		}
		break;

	case UTRACE_INTERRUPT:
		/*
		 * Make the thread call tracehook_get_signal() soon.
		 */
		clear_engine_wants_stop(engine);
		if (utrace->resume == UTRACE_INTERRUPT)
			break;
		utrace->resume = UTRACE_INTERRUPT;

		/*
		 * If it's not already stopped, interrupt it now.  We need
		 * the siglock here in case it calls recalc_sigpending()
		 * and clears its own TIF_SIGPENDING.  By taking the lock,
		 * we've serialized any later recalc_sigpending() after our
		 * setting of utrace->resume to force it on.
		 */
		if (reset) {
			/*
			 * This is really just to keep the invariant that
			 * TIF_SIGPENDING is set with UTRACE_INTERRUPT.
			 * When it's stopped, we know it's always going
			 * through utrace_get_signal() and will recalculate.
			 */
			set_tsk_thread_flag(target, TIF_SIGPENDING);
		} else {
			struct sighand_struct *sighand;
			unsigned long irqflags;
			sighand = lock_task_sighand(target, &irqflags);
			if (likely(sighand)) {
				signal_wake_up(target, 0);
				unlock_task_sighand(target, &irqflags);
			}
		}
		break;

	default:
		BUG();		/* We checked it on entry.  */
	}

	/*
	 * Let the thread resume running.  If it's not stopped now,
	 * there is nothing more we need to do.
	 */
	if (reset)
		utrace_reset(target, utrace);
	else
		spin_unlock(&utrace->lock);

	return ret;
}
EXPORT_SYMBOL_GPL(utrace_control);

/**
 * utrace_barrier - synchronize with simultaneous tracing callbacks
 * @target:		thread to affect
 * @engine:		engine to affect (can be detached)
 *
 * This blocks while @target might be in the midst of making a callback to
 * @engine.  It can be interrupted by signals and will return -%ERESTARTSYS.
 * A return value of zero means no callback from @target to @engine was
 * in progress.  Any effect of its return value (such as %UTRACE_STOP) has
 * already been applied to @engine.
 *
 * It's not necessary to keep the @target pointer alive for this call.
 * It's only necessary to hold a ref on @engine.  This will return
 * safely even if @target has been reaped and has no task refs.
 *
 * A successful return from utrace_barrier() guarantees its ordering
 * with respect to utrace_set_events() and utrace_control() calls.  If
 * @target was not properly stopped, event callbacks just disabled might
 * still be in progress; utrace_barrier() waits until there is no chance
 * an unwanted callback can be in progress.
 */
int utrace_barrier(struct task_struct *target, struct utrace_engine *engine)
{
	struct utrace *utrace;
	int ret = -ERESTARTSYS;

	if (unlikely(target == current))
		return 0;

	do {
		utrace = get_utrace_lock(target, engine, false);
		if (unlikely(IS_ERR(utrace))) {
			ret = PTR_ERR(utrace);
			if (ret != -ERESTARTSYS)
				break;
		} else {
			/*
			 * All engine state changes are done while
			 * holding the lock, i.e. before we get here.
			 * Since we have the lock, we only need to
			 * worry about @target making a callback.
			 * When it has entered start_callback() but
			 * not yet gotten to finish_callback(), we
			 * will see utrace->reporting == @engine.
			 * When @target doesn't take the lock, it uses
			 * barriers to order setting utrace->reporting
			 * before it examines the engine state.
			 */
			if (utrace->reporting != engine)
				ret = 0;
			spin_unlock(&utrace->lock);
			if (!ret)
				break;
		}
		schedule_timeout_interruptible(1);
	} while (!signal_pending(current));

	return ret;
}
EXPORT_SYMBOL_GPL(utrace_barrier);

/*
 * This is local state used for reporting loops, perhaps optimized away.
 */
struct utrace_report {
	u32 result;
	enum utrace_resume_action action;
	enum utrace_resume_action resume_action;
	bool detaches;
	bool spurious;
};

#define INIT_REPORT(var)			\
	struct utrace_report var = {		\
		.action = UTRACE_RESUME,	\
		.resume_action = UTRACE_RESUME,	\
		.spurious = true 		\
	}

/*
 * We are now making the report, so clear the flag saying we need one.
 * When there is a new attach, ->pending_attach is set just so we will
 * know to do splice_attaching() here before the callback loop.
 */
static enum utrace_resume_action start_report(struct utrace *utrace)
{
	enum utrace_resume_action resume = utrace->resume;
	if (utrace->pending_attach ||
	    (resume > UTRACE_INTERRUPT && resume < UTRACE_RESUME)) {
		spin_lock(&utrace->lock);
		splice_attaching(utrace);
		resume = utrace->resume;
		if (resume > UTRACE_INTERRUPT)
			utrace->resume = UTRACE_RESUME;
		spin_unlock(&utrace->lock);
	}
	return resume;
}

static inline void finish_report_reset(struct task_struct *task,
				       struct utrace *utrace,
				       struct utrace_report *report)
{
	if (unlikely(report->spurious || report->detaches)) {
		spin_lock(&utrace->lock);
		if (utrace_reset(task, utrace))
			report->action = UTRACE_RESUME;
	}
}

/*
 * Complete a normal reporting pass, pairing with a start_report() call.
 * This handles any UTRACE_DETACH or UTRACE_REPORT or UTRACE_INTERRUPT
 * returns from engine callbacks.  If @will_not_stop is true and any
 * engine's last callback used UTRACE_STOP, we do UTRACE_REPORT here to
 * ensure we stop before user mode.  If there were no callbacks made, it
 * will recompute @task->utrace_flags to avoid another false-positive.
 */
static void finish_report(struct task_struct *task, struct utrace *utrace,
			  struct utrace_report *report, bool will_not_stop)
{
	enum utrace_resume_action resume = report->action;

	if (resume == UTRACE_STOP)
		resume = will_not_stop ? UTRACE_REPORT : UTRACE_RESUME;

	if (resume < utrace->resume) {
		spin_lock(&utrace->lock);
		utrace->resume = resume;
		if (resume == UTRACE_INTERRUPT)
			set_tsk_thread_flag(task, TIF_SIGPENDING);
		else
			set_tsk_thread_flag(task, TIF_NOTIFY_RESUME);
		spin_unlock(&utrace->lock);
	}

	finish_report_reset(task, utrace, report);
}

static void finish_callback_report(struct task_struct *task,
				   struct utrace *utrace,
				   struct utrace_report *report,
				   struct utrace_engine *engine,
				   enum utrace_resume_action action)
{
	if (action == UTRACE_DETACH) {
		/*
		 * By holding the lock here, we make sure that
		 * utrace_barrier() (really get_utrace_lock()) sees the
		 * effect of this detach.  Otherwise utrace_barrier() could
		 * return 0 after this callback had returned UTRACE_DETACH.
		 * This way, a 0 return is an unambiguous indicator that any
		 * callback returning UTRACE_DETACH has indeed caused detach.
		 */
		spin_lock(&utrace->lock);
		engine->ops = &utrace_detached_ops;
		spin_unlock(&utrace->lock);
	}

	/*
	 * If utrace_control() was used, treat that like UTRACE_DETACH here.
	 */
	if (engine->ops == &utrace_detached_ops) {
		report->detaches = true;
		return;
	}

	if (action < report->action)
		report->action = action;

	if (action != UTRACE_STOP) {
		if (action < report->resume_action)
			report->resume_action = action;

		if (engine_wants_stop(engine)) {
			spin_lock(&utrace->lock);
			clear_engine_wants_stop(engine);
			spin_unlock(&utrace->lock);
		}

		return;
	}

	if (!engine_wants_stop(engine)) {
		spin_lock(&utrace->lock);
		/*
		 * If utrace_control() came in and detached us
		 * before we got the lock, we must not stop now.
		 */
		if (unlikely(engine->ops == &utrace_detached_ops))
			report->detaches = true;
		else
			mark_engine_wants_stop(task, engine);
		spin_unlock(&utrace->lock);
	}
}

/*
 * Apply the return value of one engine callback to @report.
 * Returns true if @engine detached and should not get any more callbacks.
 */
static bool finish_callback(struct task_struct *task, struct utrace *utrace,
			    struct utrace_report *report,
			    struct utrace_engine *engine,
			    u32 ret)
{
	report->result = ret & ~UTRACE_RESUME_MASK;
	finish_callback_report(task, utrace, report, engine,
			       utrace_resume_action(ret));

	/*
	 * Now that we have applied the effect of the return value,
	 * clear this so that utrace_barrier() can stop waiting.
	 * A subsequent utrace_control() can stop or resume @engine
	 * and know this was ordered after its callback's action.
	 *
	 * We don't need any barriers here because utrace_barrier()
	 * takes utrace->lock.  If we touched engine->flags above,
	 * the lock guaranteed this change was before utrace_barrier()
	 * examined utrace->reporting.
	 */
	utrace->reporting = NULL;

	/*
	 * We've just done an engine callback.  These are allowed to sleep,
	 * though all well-behaved ones restrict that to blocking kalloc()
	 * or quickly-acquired mutex_lock() and the like.  This is a good
	 * place to make sure tracing engines don't introduce too much
	 * latency under voluntary preemption.
	 */
	might_sleep();

	return engine->ops == &utrace_detached_ops;
}

/*
 * Start the callbacks for @engine to consider @event (a bit mask).
 * This makes the report_quiesce() callback first.  If @engine wants
 * a specific callback for @event, we return the ops vector to use.
 * If not, we return NULL.  The return value from the ops->callback
 * function called should be passed to finish_callback().
 */
static const struct utrace_engine_ops *start_callback(
	struct utrace *utrace, struct utrace_report *report,
	struct utrace_engine *engine, struct task_struct *task,
	unsigned long event)
{
	const struct utrace_engine_ops *ops;
	unsigned long want;

	/*
	 * This barrier ensures that we've set utrace->reporting before
	 * we examine engine->flags or engine->ops.  utrace_barrier()
	 * relies on this ordering to indicate that the effect of any
	 * utrace_control() and utrace_set_events() calls is in place
	 * by the time utrace->reporting can be seen to be NULL.
	 */
	utrace->reporting = engine;
	smp_mb();

	/*
	 * This pairs with the barrier in mark_engine_detached().
	 * It makes sure that we never see the old ops vector with
	 * the new flags, in case the original vector had no report_quiesce.
	 */
	want = engine->flags;
	smp_rmb();
	ops = engine->ops;

	if (want & UTRACE_EVENT(QUIESCE)) {
		if (finish_callback(task, utrace, report, engine,
				    (*ops->report_quiesce)(report->action,
							   engine, event)))
			return NULL;

		/*
		 * finish_callback() reset utrace->reporting after the
		 * quiesce callback.  Now we set it again (as above)
		 * before re-examining engine->flags, which could have
		 * been changed synchronously by ->report_quiesce or
		 * asynchronously by utrace_control() or utrace_set_events().
		 */
		utrace->reporting = engine;
		smp_mb();
		want = engine->flags;
	}

	if (want & ENGINE_STOP)
		report->action = UTRACE_STOP;

	if (want & event) {
		report->spurious = false;
		return ops;
	}

	utrace->reporting = NULL;
	return NULL;
}

/*
 * Do a normal reporting pass for engines interested in @event.
 * @callback is the name of the member in the ops vector, and remaining
 * args are the extras it takes after the standard three args.
 */
#define REPORT_CALLBACKS(rev, task, utrace, report, event, callback, ...)     \
	do {								      \
		struct utrace_engine *engine;				      \
		const struct utrace_engine_ops *ops;			      \
		list_for_each_entry##rev(engine, &utrace->attached, entry) {  \
			ops = start_callback(utrace, report, engine, task,    \
					     event);			      \
			if (!ops)					      \
				continue;				      \
			finish_callback(task, utrace, report, engine,	      \
					(*ops->callback)(__VA_ARGS__));	      \
		}							      \
	} while (0)
#define REPORT(task, utrace, report, event, callback, ...)		      \
	do {								      \
		start_report(utrace);					      \
		REPORT_CALLBACKS(, task, utrace, report, event, callback,     \
				 (report)->action, engine, ## __VA_ARGS__);   \
		finish_report(task, utrace, report, true);		      \
	} while (0)

/*
 * Called iff UTRACE_EVENT(EXEC) flag is set.
 */
void utrace_report_exec(struct linux_binfmt *fmt, struct linux_binprm *bprm,
			struct pt_regs *regs)
{
	struct task_struct *task = current;
	struct utrace *utrace = task_utrace_struct(task);
	INIT_REPORT(report);

	REPORT(task, utrace, &report, UTRACE_EVENT(EXEC),
	       report_exec, fmt, bprm, regs);
}

static u32 do_report_syscall_entry(struct pt_regs *regs,
				   struct task_struct *task,
				   struct utrace *utrace,
				   struct utrace_report *report,
				   u32 resume_report)
{
	start_report(utrace);
	REPORT_CALLBACKS(_reverse, task, utrace, report,
			 UTRACE_EVENT(SYSCALL_ENTRY), report_syscall_entry,
			 resume_report | report->result | report->action,
			 engine, regs);
	finish_report(task, utrace, report, false);

	if (report->action != UTRACE_STOP)
		return 0;

	utrace_stop(task, utrace, report->resume_action);

	if (fatal_signal_pending(task)) {
		/*
		 * We are continuing despite UTRACE_STOP because of a
		 * SIGKILL.  Don't let the system call actually proceed.
		 */
		report->result = UTRACE_SYSCALL_ABORT;
	} else if (utrace->resume <= UTRACE_REPORT) {
		/*
		 * If we've been asked for another report after our stop,
		 * go back to report (and maybe stop) again before we run
		 * the system call.  The second (and later) reports are
		 * marked with the UTRACE_SYSCALL_RESUMED flag so that
		 * engines know this is a second report at the same
		 * entry.  This gives them the chance to examine the
		 * registers anew after they might have been changed
		 * while we were stopped.
		 */
		report->detaches = false;
		report->spurious = true;
		report->action = report->resume_action = UTRACE_RESUME;
		return UTRACE_SYSCALL_RESUMED;
	}

	return 0;
}

/*
 * Called iff UTRACE_EVENT(SYSCALL_ENTRY) flag is set.
 * Return true to prevent the system call.
 */
bool utrace_report_syscall_entry(struct pt_regs *regs)
{
	struct task_struct *task = current;
	struct utrace *utrace = task_utrace_struct(task);
	INIT_REPORT(report);
	u32 resume_report = 0;

	do {
		resume_report = do_report_syscall_entry(regs, task, utrace,
							&report, resume_report);
	} while (resume_report);

	return utrace_syscall_action(report.result) == UTRACE_SYSCALL_ABORT;
}

/*
 * Called iff UTRACE_EVENT(SYSCALL_EXIT) flag is set.
 */
void utrace_report_syscall_exit(struct pt_regs *regs)
{
	struct task_struct *task = current;
	struct utrace *utrace = task_utrace_struct(task);
	INIT_REPORT(report);

	REPORT(task, utrace, &report, UTRACE_EVENT(SYSCALL_EXIT),
	       report_syscall_exit, regs);
}

/*
 * Called iff UTRACE_EVENT(CLONE) flag is set.
 * This notification call blocks the wake_up_new_task call on the child.
 * So we must not quiesce here.  tracehook_report_clone_complete will do
 * a quiescence check momentarily.
 */
void utrace_report_clone(unsigned long clone_flags, struct task_struct *child)
{
	struct task_struct *task = current;
	struct utrace *utrace = task_utrace_struct(task);
	INIT_REPORT(report);

	/*
	 * We don't use the REPORT() macro here, because we need
	 * to clear utrace->cloning before finish_report().
	 * After finish_report(), utrace can be a stale pointer
	 * in cases when report.action is still UTRACE_RESUME.
	 */
	start_report(utrace);
	utrace->cloning = child;

	REPORT_CALLBACKS(, task, utrace, &report,
			 UTRACE_EVENT(CLONE), report_clone,
			 report.action, engine, clone_flags, child);

	utrace->cloning = NULL;
	finish_report(task, utrace, &report, !(clone_flags & CLONE_VFORK));

	/*
	 * For a vfork, we will go into an uninterruptible block waiting
	 * for the child.  We need UTRACE_STOP to happen before this, not
	 * after.  For CLONE_VFORK, utrace_finish_vfork() will be called.
	 */
	if (report.action == UTRACE_STOP && (clone_flags & CLONE_VFORK)) {
		spin_lock(&utrace->lock);
		utrace->vfork_stop = 1;
		spin_unlock(&utrace->lock);
	}
}

/*
 * We're called after utrace_report_clone() for a CLONE_VFORK.
 * If UTRACE_STOP was left from the clone report, we stop here.
 * After this, we'll enter the uninterruptible wait_for_completion()
 * waiting for the child.
 */
void utrace_finish_vfork(struct task_struct *task)
{
	struct utrace *utrace = task_utrace_struct(task);

	if (utrace->vfork_stop) {
		spin_lock(&utrace->lock);
		utrace->vfork_stop = 0;
		spin_unlock(&utrace->lock);
		utrace_stop(task, utrace, UTRACE_RESUME); /* XXX */
	}
}

/*
 * Called iff UTRACE_EVENT(JCTL) flag is set.
 *
 * Called with siglock held.
 */
void utrace_report_jctl(int notify, int what)
{
	struct task_struct *task = current;
	struct utrace *utrace = task_utrace_struct(task);
	INIT_REPORT(report);

	spin_unlock_irq(&task->sighand->siglock);

	REPORT(task, utrace, &report, UTRACE_EVENT(JCTL),
	       report_jctl, what, notify);

	spin_lock_irq(&task->sighand->siglock);
}

/*
 * Called iff UTRACE_EVENT(EXIT) flag is set.
 */
void utrace_report_exit(long *exit_code)
{
	struct task_struct *task = current;
	struct utrace *utrace = task_utrace_struct(task);
	INIT_REPORT(report);
	long orig_code = *exit_code;

	REPORT(task, utrace, &report, UTRACE_EVENT(EXIT),
	       report_exit, orig_code, exit_code);

	if (report.action == UTRACE_STOP)
		utrace_stop(task, utrace, report.resume_action);
}

/*
 * Called iff UTRACE_EVENT(DEATH) or UTRACE_EVENT(QUIESCE) flag is set.
 *
 * It is always possible that we are racing with utrace_release_task here.
 * For this reason, utrace_release_task checks for the event bits that get
 * us here, and delays its cleanup for us to do.
 */
void utrace_report_death(struct task_struct *task, struct utrace *utrace,
			 bool group_dead, int signal)
{
	INIT_REPORT(report);

	BUG_ON(!task->exit_state);

	/*
	 * We are presently considered "quiescent"--which is accurate
	 * inasmuch as we won't run any more user instructions ever again.
	 * But for utrace_control and utrace_set_events to be robust, they
	 * must be sure whether or not we will run any more callbacks.  If
	 * a call comes in before we do, taking the lock here synchronizes
	 * us so we don't run any callbacks just disabled.  Calls that come
	 * in while we're running the callbacks will see the exit.death
	 * flag and know that we are not yet fully quiescent for purposes
	 * of detach bookkeeping.
	 */
	spin_lock(&utrace->lock);
	BUG_ON(utrace->death);
	utrace->death = 1;
	utrace->resume = UTRACE_RESUME;
	splice_attaching(utrace);
	spin_unlock(&utrace->lock);

	REPORT_CALLBACKS(, task, utrace, &report, UTRACE_EVENT(DEATH),
			 report_death, engine, group_dead, signal);

	utrace_maybe_reap(task, utrace, false);
}

/*
 * Finish the last reporting pass before returning to user mode.
 */
static void finish_resume_report(struct task_struct *task,
				 struct utrace *utrace,
				 struct utrace_report *report)
{
	finish_report_reset(task, utrace, report);

	switch (report->action) {
	case UTRACE_STOP:
		utrace_stop(task, utrace, report->resume_action);
		break;

	case UTRACE_INTERRUPT:
		if (!signal_pending(task))
			set_tsk_thread_flag(task, TIF_SIGPENDING);
		break;

	case UTRACE_BLOCKSTEP:
		if (likely(arch_has_block_step())) {
			user_enable_block_step(task);
			break;
		}

		/*
		 * This means some callback is to blame for failing
		 * to check arch_has_block_step() itself.  Warn and
		 * then fall through to treat it as SINGLESTEP.
		 */
		WARN(1, "UTRACE_BLOCKSTEP when !arch_has_block_step()");

	case UTRACE_SINGLESTEP:
		if (likely(arch_has_single_step())) {
			user_enable_single_step(task);
		} else {
			/*
			 * This means some callback is to blame for failing
			 * to check arch_has_single_step() itself.  Spew
			 * about it so the loser will fix his module.
			 */
			WARN(1,
			     "UTRACE_SINGLESTEP when !arch_has_single_step()");
		}
		break;

	case UTRACE_REPORT:
	case UTRACE_RESUME:
	default:
		user_disable_single_step(task);
		break;
	}
}

/*
 * This is called when TIF_NOTIFY_RESUME had been set (and is now clear).
 * We are close to user mode, and this is the place to report or stop.
 * When we return, we're going to user mode or into the signals code.
 */
void utrace_resume(struct task_struct *task, struct pt_regs *regs)
{
	struct utrace *utrace = task_utrace_struct(task);
	INIT_REPORT(report);
	struct utrace_engine *engine;

	/*
	 * Some machines get here with interrupts disabled.  The same arch
	 * code path leads to calling into get_signal_to_deliver(), which
	 * implicitly reenables them by virtue of spin_unlock_irq.
	 */
	local_irq_enable();

	/*
	 * If this flag is still set it's because there was a signal
	 * handler setup done but no report_signal following it.  Clear
	 * the flag before we get to user so it doesn't confuse us later.
	 */
	if (unlikely(utrace->signal_handler)) {
		spin_lock(&utrace->lock);
		utrace->signal_handler = 0;
		spin_unlock(&utrace->lock);
	}

	/*
	 * Update our bookkeeping even if there are no callbacks made here.
	 */
	report.action = start_report(utrace);

	switch (report.action) {
	case UTRACE_RESUME:
		/*
		 * Anything we might have done was already handled by
		 * utrace_get_signal(), or this is an entirely spurious
		 * call.  (The arch might use TIF_NOTIFY_RESUME for other
		 * purposes as well as calling us.)
		 */
		return;
	case UTRACE_REPORT:
		if (unlikely(!(task->utrace_flags & UTRACE_EVENT(QUIESCE))))
			break;
		/*
		 * Do a simple reporting pass, with no specific
		 * callback after report_quiesce.
		 */
		report.action = UTRACE_RESUME;
		list_for_each_entry(engine, &utrace->attached, entry)
			start_callback(utrace, &report, engine, task, 0);
		break;
	default:
		/*
		 * Even if this report was truly spurious, there is no need
		 * for utrace_reset() now.  TIF_NOTIFY_RESUME was already
		 * cleared--it doesn't stay spuriously set.
		 */
		report.spurious = false;
		break;
	}

	/*
	 * Finish the report and either stop or get ready to resume.
	 * If utrace->resume was not UTRACE_REPORT, this applies its
	 * effect now (i.e. step or interrupt).
	 */
	finish_resume_report(task, utrace, &report);
}

/*
 * Return true if current has forced signal_pending().
 *
 * This is called only when current->utrace_flags is nonzero, so we know
 * that current->utrace must be set.  It's not inlined in tracehook.h
 * just so that struct utrace can stay opaque outside this file.
 */
bool utrace_interrupt_pending(void)
{
	return task_utrace_struct(current)->resume == UTRACE_INTERRUPT;
}

/*
 * Take the siglock and push @info back on our queue.
 * Returns with @task->sighand->siglock held.
 */
static void push_back_signal(struct task_struct *task, siginfo_t *info)
	__acquires(task->sighand->siglock)
{
	struct sigqueue *q;

	if (unlikely(!info->si_signo)) { /* Oh, a wise guy! */
		spin_lock_irq(&task->sighand->siglock);
		return;
	}

	q = sigqueue_alloc();
	if (likely(q)) {
		q->flags = 0;
		copy_siginfo(&q->info, info);
	}

	spin_lock_irq(&task->sighand->siglock);

	sigaddset(&task->pending.signal, info->si_signo);
	if (likely(q))
		list_add(&q->list, &task->pending.list);

	set_tsk_thread_flag(task, TIF_SIGPENDING);
}

/*
 * This is the hook from the signals code, called with the siglock held.
 * Here is the ideal place to stop.  We also dequeue and intercept signals.
 */
int utrace_get_signal(struct task_struct *task, struct pt_regs *regs,
		      siginfo_t *info, struct k_sigaction *return_ka)
	__releases(task->sighand->siglock)
	__acquires(task->sighand->siglock)
{
	struct utrace *utrace;
	struct k_sigaction *ka;
	INIT_REPORT(report);
	struct utrace_engine *engine;
	const struct utrace_engine_ops *ops;
	unsigned long event, want;
	u32 ret;
	int signr;

	utrace = task_utrace_struct(task);
	if (utrace->resume < UTRACE_RESUME ||
	    utrace->pending_attach || utrace->signal_handler) {
		enum utrace_resume_action resume;

		/*
		 * We've been asked for an explicit report before we
		 * even check for pending signals.
		 */

		spin_unlock_irq(&task->sighand->siglock);

		spin_lock(&utrace->lock);

		splice_attaching(utrace);

		report.result = utrace->signal_handler ?
			UTRACE_SIGNAL_HANDLER : UTRACE_SIGNAL_REPORT;
		utrace->signal_handler = 0;

		resume = utrace->resume;
		utrace->resume = UTRACE_RESUME;

		spin_unlock(&utrace->lock);

		/*
		 * Make sure signal_pending() only returns true
		 * if there are real signals pending.
		 */
		if (signal_pending(task)) {
			spin_lock_irq(&task->sighand->siglock);
			recalc_sigpending();
			spin_unlock_irq(&task->sighand->siglock);
		}

		if (resume > UTRACE_REPORT) {
			/*
			 * We only got here to process utrace->resume.
			 * Despite no callbacks, this report is not spurious.
			 */
			report.action = resume;
			report.spurious = false;
			finish_resume_report(task, utrace, &report);
			return -1;
		} else if (!(task->utrace_flags & UTRACE_EVENT(QUIESCE))) {
			/*
			 * We only got here to clear utrace->signal_handler.
			 */
			return -1;
		}

		/*
		 * Do a reporting pass for no signal, just for EVENT(QUIESCE).
		 * The engine callbacks can fill in *info and *return_ka.
		 * We'll pass NULL for the @orig_ka argument to indicate
		 * that there was no original signal.
		 */
		event = 0;
		ka = NULL;
		memset(return_ka, 0, sizeof *return_ka);
	} else if (!(task->utrace_flags & UTRACE_EVENT_SIGNAL_ALL) ||
		   unlikely(task->signal->group_stop_count)) {
		/*
		 * If no engine is interested in intercepting signals or
		 * we must stop, let the caller just dequeue them normally
		 * or participate in group-stop.
		 */
		return 0;
	} else {
		/*
		 * Steal the next signal so we can let tracing engines
		 * examine it.  From the signal number and sigaction,
		 * determine what normal delivery would do.  If no
		 * engine perturbs it, we'll do that by returning the
		 * signal number after setting *return_ka.
		 */
		signr = dequeue_signal(task, &task->blocked, info);
		if (signr == 0)
			return signr;
		BUG_ON(signr != info->si_signo);

		ka = &task->sighand->action[signr - 1];
		*return_ka = *ka;

		/*
		 * We are never allowed to interfere with SIGKILL.
		 * Just punt after filling in *return_ka for our caller.
		 */
		if (signr == SIGKILL)
			return signr;

		if (ka->sa.sa_handler == SIG_IGN) {
			event = UTRACE_EVENT(SIGNAL_IGN);
			report.result = UTRACE_SIGNAL_IGN;
		} else if (ka->sa.sa_handler != SIG_DFL) {
			event = UTRACE_EVENT(SIGNAL);
			report.result = UTRACE_SIGNAL_DELIVER;
		} else if (sig_kernel_coredump(signr)) {
			event = UTRACE_EVENT(SIGNAL_CORE);
			report.result = UTRACE_SIGNAL_CORE;
		} else if (sig_kernel_ignore(signr)) {
			event = UTRACE_EVENT(SIGNAL_IGN);
			report.result = UTRACE_SIGNAL_IGN;
		} else if (signr == SIGSTOP) {
			event = UTRACE_EVENT(SIGNAL_STOP);
			report.result = UTRACE_SIGNAL_STOP;
		} else if (sig_kernel_stop(signr)) {
			event = UTRACE_EVENT(SIGNAL_STOP);
			report.result = UTRACE_SIGNAL_TSTP;
		} else {
			event = UTRACE_EVENT(SIGNAL_TERM);
			report.result = UTRACE_SIGNAL_TERM;
		}

		/*
		 * Now that we know what event type this signal is, we
		 * can short-circuit if no engines care about those.
		 */
		if ((task->utrace_flags & (event | UTRACE_EVENT(QUIESCE))) == 0)
			return signr;

		/*
		 * We have some interested engines, so tell them about
		 * the signal and let them change its disposition.
		 */
		spin_unlock_irq(&task->sighand->siglock);
	}

	/*
	 * This reporting pass chooses what signal disposition we'll act on.
	 */
	list_for_each_entry(engine, &utrace->attached, entry) {
		/*
		 * See start_callback() comment about this barrier.
		 */
		utrace->reporting = engine;
		smp_mb();

		/*
		 * This pairs with the barrier in mark_engine_detached(),
		 * see start_callback() comments.
		 */
		want = engine->flags;
		smp_rmb();
		ops = engine->ops;

		if ((want & (event | UTRACE_EVENT(QUIESCE))) == 0) {
			utrace->reporting = NULL;
			continue;
		}

		if (ops->report_signal)
			ret = (*ops->report_signal)(
				report.result | report.action, engine,
				regs, info, ka, return_ka);
		else
			ret = (report.result | (*ops->report_quiesce)(
				       report.action, engine, event));

		/*
		 * Avoid a tight loop reporting again and again if some
		 * engine is too stupid.
		 */
		switch (utrace_resume_action(ret)) {
		default:
			break;
		case UTRACE_INTERRUPT:
		case UTRACE_REPORT:
			ret = (ret & ~UTRACE_RESUME_MASK) | UTRACE_RESUME;
			break;
		}

		finish_callback(task, utrace, &report, engine, ret);
	}

	/*
	 * We express the chosen action to the signals code in terms
	 * of a representative signal whose default action does it.
	 * Our caller uses our return value (signr) to decide what to
	 * do, but uses info->si_signo as the signal number to report.
	 */
	switch (utrace_signal_action(report.result)) {
	case UTRACE_SIGNAL_TERM:
		signr = SIGTERM;
		break;

	case UTRACE_SIGNAL_CORE:
		signr = SIGQUIT;
		break;

	case UTRACE_SIGNAL_STOP:
		signr = SIGSTOP;
		break;

	case UTRACE_SIGNAL_TSTP:
		signr = SIGTSTP;
		break;

	case UTRACE_SIGNAL_DELIVER:
		signr = info->si_signo;

		if (return_ka->sa.sa_handler == SIG_DFL) {
			/*
			 * We'll do signr's normal default action.
			 * For ignore, we'll fall through below.
			 * For stop/death, break locks and returns it.
			 */
			if (likely(signr) && !sig_kernel_ignore(signr))
				break;
		} else if (return_ka->sa.sa_handler != SIG_IGN &&
			   likely(signr)) {
			/*
			 * Complete the bookkeeping after the report.
			 * The handler will run.  If an engine wanted to
			 * stop or step, then make sure we do another
			 * report after signal handler setup.
			 */
			if (report.action != UTRACE_RESUME)
				report.action = UTRACE_INTERRUPT;
			finish_report(task, utrace, &report, true);

			if (unlikely(report.result & UTRACE_SIGNAL_HOLD))
				push_back_signal(task, info);
			else
				spin_lock_irq(&task->sighand->siglock);

			/*
			 * We do the SA_ONESHOT work here since the
			 * normal path will only touch *return_ka now.
			 */
			if (unlikely(return_ka->sa.sa_flags & SA_ONESHOT)) {
				return_ka->sa.sa_flags &= ~SA_ONESHOT;
				if (likely(valid_signal(signr))) {
					ka = &task->sighand->action[signr - 1];
					ka->sa.sa_handler = SIG_DFL;
				}
			}

			return signr;
		}

		/* Fall through for an ignored signal.  */

	case UTRACE_SIGNAL_IGN:
	case UTRACE_SIGNAL_REPORT:
	default:
		/*
		 * If the signal is being ignored, then we are on the way
		 * directly back to user mode.  We can stop here, or step,
		 * as in utrace_resume(), above.  After we've dealt with that,
		 * our caller will relock and come back through here.
		 */
		finish_resume_report(task, utrace, &report);

		if (unlikely(fatal_signal_pending(task))) {
			/*
			 * The only reason we woke up now was because of a
			 * SIGKILL.  Don't do normal dequeuing in case it
			 * might get a signal other than SIGKILL.  That would
			 * perturb the death state so it might differ from
			 * what the debugger would have allowed to happen.
			 * Instead, pluck out just the SIGKILL to be sure
			 * we'll die immediately with nothing else different
			 * from the quiescent state the debugger wanted us in.
			 */
			sigset_t sigkill_only;
			siginitsetinv(&sigkill_only, sigmask(SIGKILL));
			spin_lock_irq(&task->sighand->siglock);
			signr = dequeue_signal(task, &sigkill_only, info);
			BUG_ON(signr != SIGKILL);
			*return_ka = task->sighand->action[SIGKILL - 1];
			return signr;
		}

		if (unlikely(report.result & UTRACE_SIGNAL_HOLD)) {
			push_back_signal(task, info);
			spin_unlock_irq(&task->sighand->siglock);
		}

		return -1;
	}

	/*
	 * Complete the bookkeeping after the report.
	 * This sets utrace->resume if UTRACE_STOP was used.
	 */
	finish_report(task, utrace, &report, true);

	return_ka->sa.sa_handler = SIG_DFL;

	/*
	 * If this signal is fatal, si_signo gets through as exit_code.
	 * We can't allow a completely bogus value there or else core
	 * kernel code can freak out.  (If an engine wants to control
	 * the exit_code value exactly, it can do so in report_exit.)
	 * We'll produce a big complaint in dmesg, but won't crash.
	 * That's nicer for debugging your utrace engine.
	 */
	if (unlikely(info->si_signo & 0x80)) {
		WARN(1, "utrace engine left bogus si_signo value!");
		info->si_signo = SIGTRAP;
	}

	if (unlikely(report.result & UTRACE_SIGNAL_HOLD))
		push_back_signal(task, info);
	else
		spin_lock_irq(&task->sighand->siglock);

	if (sig_kernel_stop(signr))
		task->signal->flags |= SIGNAL_STOP_DEQUEUED;

	return signr;
}

/*
 * This gets called after a signal handler has been set up.
 * We set a flag so the next report knows it happened.
 * If we're already stepping, make sure we do a report_signal.
 * If not, make sure we get into utrace_resume() where we can
 * clear the signal_handler flag before resuming.
 */
void utrace_signal_handler(struct task_struct *task, int stepping)
{
	struct utrace *utrace = task_utrace_struct(task);

	spin_lock(&utrace->lock);

	utrace->signal_handler = 1;
	if (utrace->resume > UTRACE_INTERRUPT) {
		if (stepping) {
			utrace->resume = UTRACE_INTERRUPT;
			set_tsk_thread_flag(task, TIF_SIGPENDING);
		} else if (utrace->resume == UTRACE_RESUME) {
			set_tsk_thread_flag(task, TIF_NOTIFY_RESUME);
		}
	}

	spin_unlock(&utrace->lock);
}

/**
 * utrace_prepare_examine - prepare to examine thread state
 * @target:		thread of interest, a &struct task_struct pointer
 * @engine:		engine pointer returned by utrace_attach_task()
 * @exam:		temporary state, a &struct utrace_examiner pointer
 *
 * This call prepares to safely examine the thread @target using
 * &struct user_regset calls, or direct access to thread-synchronous fields.
 *
 * When @target is current, this call is superfluous.  When @target is
 * another thread, it must be held stopped via %UTRACE_STOP by @engine.
 *
 * This call may block the caller until @target stays stopped, so it must
 * be called only after the caller is sure @target is about to unschedule.
 * This means a zero return from a utrace_control() call on @engine giving
 * %UTRACE_STOP, or a report_quiesce() or report_signal() callback to
 * @engine that used %UTRACE_STOP in its return value.
 *
 * Returns -%ESRCH if @target is dead or -%EINVAL if %UTRACE_STOP was
 * not used.  If @target has started running again despite %UTRACE_STOP
 * (for %SIGKILL or a spurious wakeup), this call returns -%EAGAIN.
 *
 * When this call returns zero, it's safe to use &struct user_regset
 * calls and task_user_regset_view() on @target and to examine some of
 * its fields directly.  When the examination is complete, a
 * utrace_finish_examine() call must follow to check whether it was
 * completed safely.
 */
int utrace_prepare_examine(struct task_struct *target,
			   struct utrace_engine *engine,
			   struct utrace_examiner *exam)
{
	int ret = 0;

	if (unlikely(target == current))
		return 0;

	rcu_read_lock();
	if (unlikely(!engine_wants_stop(engine)))
		ret = -EINVAL;
	else if (unlikely(target->exit_state))
		ret = -ESRCH;
	else {
		exam->state = target->state;
		if (unlikely(exam->state == TASK_RUNNING))
			ret = -EAGAIN;
		else
			get_task_struct(target);
	}
	rcu_read_unlock();

	if (likely(!ret)) {
		exam->ncsw = wait_task_inactive(target, exam->state);
		put_task_struct(target);
		if (unlikely(!exam->ncsw))
			ret = -EAGAIN;
	}

	return ret;
}
EXPORT_SYMBOL_GPL(utrace_prepare_examine);

/**
 * utrace_finish_examine - complete an examination of thread state
 * @target:		thread of interest, a &struct task_struct pointer
 * @engine:		engine pointer returned by utrace_attach_task()
 * @exam:		pointer passed to utrace_prepare_examine() call
 *
 * This call completes an examination on the thread @target begun by a
 * paired utrace_prepare_examine() call with the same arguments that
 * returned success (zero).
 *
 * When @target is current, this call is superfluous.  When @target is
 * another thread, this returns zero if @target has remained unscheduled
 * since the paired utrace_prepare_examine() call returned zero.
 *
 * When this returns an error, any examination done since the paired
 * utrace_prepare_examine() call is unreliable and the data extracted
 * should be discarded.  The error is -%EINVAL if @engine is not
 * keeping @target stopped, or -%EAGAIN if @target woke up unexpectedly.
 */
int utrace_finish_examine(struct task_struct *target,
			  struct utrace_engine *engine,
			  struct utrace_examiner *exam)
{
	int ret = 0;

	if (unlikely(target == current))
		return 0;

	rcu_read_lock();
	if (unlikely(!engine_wants_stop(engine)))
		ret = -EINVAL;
	else if (unlikely(target->state != exam->state))
		ret = -EAGAIN;
	else
		get_task_struct(target);
	rcu_read_unlock();

	if (likely(!ret)) {
		unsigned long ncsw = wait_task_inactive(target, exam->state);
		if (unlikely(ncsw != exam->ncsw))
			ret = -EAGAIN;
		put_task_struct(target);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(utrace_finish_examine);

/*
 * This is declared in linux/regset.h and defined in machine-dependent
 * code.  We put the export here to ensure no machine forgets it.
 */
EXPORT_SYMBOL_GPL(task_user_regset_view);

/*
 * Called with rcu_read_lock() held.
 */
void task_utrace_proc_status(struct seq_file *m, struct task_struct *p)
{
	seq_printf(m, "Utrace:\t%lx\n", p->utrace_flags);
}

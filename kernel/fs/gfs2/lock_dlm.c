/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2009 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

#include <linux/fs.h>
#include <linux/dlm.h>
#include <linux/types.h>
#include <linux/gfs2_ondisk.h>

#include "incore.h"
#include "glock.h"
#include "util.h"
#include "trace_gfs2.h"

/**
 * gfs2_update_stats - Update time based stats
 * @mv: Pointer to mean/variance structure to update
 * @sample: New data to include
 *
 * @delta is the difference between the current rtt sample and the
 * running average srtt. We add 1/8 of that to the srtt in order to
 * update the current srtt estimate. The varience estimate is a bit
 * more complicated. We subtract the abs value of the @delta from
 * the current variance estimate and add 1/4 of that to the running
 * total.
 *
 * Note that the index points at the array entry containing the smoothed
 * mean value, and the variance is always in the following entry
 *
 * Reference: TCP/IP Illustrated, vol 2, p. 831,832
 * All times are in units of integer nanoseconds. Unlike the TCP/IP case,
 * they are not scaled fixed point.
 */

static inline void gfs2_update_stats(struct gfs2_lkstats *s, unsigned index,
				     s64 sample)
{
	s64 delta = sample - s->stats[index];
	s->stats[index] += (delta >> 3);
	index++;
	s->stats[index] += ((abs64(delta) - s->stats[index]) >> 2);
}

/**
 * gfs2_update_reply_times - Update locking statistics
 * @gl: The glock to update
 *
 * This assumes that gl->gl_dstamp has been set earlier.
 *
 * The rtt (lock round trip time) is an estimate of the time
 * taken to perform a dlm lock request. We update it on each
 * reply from the dlm.
 *
 * The blocking flag is set on the glock for all dlm requests
 * which may potentially block due to lock requests from other nodes.
 * DLM requests where the current lock state is exclusive, the
 * requested state is null (or unlocked) or where the TRY or
 * TRY_1CB flags are set are classified as non-blocking. All
 * other DLM requests are counted as (potentially) blocking.
 */
static inline void gfs2_update_reply_times(struct gfs2_glock *gl)
{
	struct gfs2_pcpu_lkstats *lks;
	const unsigned gltype = gl->gl_name.ln_type;
	unsigned index = test_bit(GLF_BLOCKING, &gl->gl_flags) ?
			 GFS2_LKS_SRTTB : GFS2_LKS_SRTT;
	s64 rtt;

	preempt_disable();
	rtt = ktime_to_ns(ktime_sub(ktime_get_real(), gl->gl_dstamp));
	lks = this_cpu_ptr(gl->gl_sbd->sd_lkstats);
	gfs2_update_stats(&gl->gl_stats, index, rtt);		/* Local */
	gfs2_update_stats(&lks->lkstats[gltype], index, rtt);	/* Global */
	preempt_enable();

	trace_gfs2_glock_lock_time(gl, rtt);
}

/**
 * gfs2_update_request_times - Update locking statistics
 * @gl: The glock to update
 *
 * The irt (lock inter-request times) measures the average time
 * between requests to the dlm. It is updated immediately before
 * each dlm call.
 */

static inline void gfs2_update_request_times(struct gfs2_glock *gl)
{
	struct gfs2_pcpu_lkstats *lks;
	const unsigned gltype = gl->gl_name.ln_type;
	ktime_t dstamp;
	s64 irt;

	preempt_disable();
	dstamp = gl->gl_dstamp;
	gl->gl_dstamp = ktime_get_real();
	irt = ktime_to_ns(ktime_sub(gl->gl_dstamp, dstamp));
	lks = this_cpu_ptr(gl->gl_sbd->sd_lkstats);
	gfs2_update_stats(&gl->gl_stats, GFS2_LKS_SIRT, irt);		/* Local */
	gfs2_update_stats(&lks->lkstats[gltype], GFS2_LKS_SIRT, irt);	/* Global */
	preempt_enable();
}

static void gdlm_ast(void *arg)
{
	struct gfs2_glock *gl = arg;
	unsigned ret = gl->gl_state;

	gfs2_update_reply_times(gl);
	BUG_ON(gl->gl_lksb.sb_flags & DLM_SBF_DEMOTED);

	if (gl->gl_lksb.sb_flags & DLM_SBF_VALNOTVALID)
		memset(gl->gl_lvb, 0, GDLM_LVB_SIZE);

	switch (gl->gl_lksb.sb_status) {
	case -DLM_EUNLOCK: /* Unlocked, so glock can be freed */
		gfs2_glock_free(gl);
		return;
	case -DLM_ECANCEL: /* Cancel while getting lock */
		ret |= LM_OUT_CANCELED;
		goto out;
	case -EAGAIN: /* Try lock fails */
	case -EDEADLK: /* Deadlock detected */
		goto out;
	case -ETIMEDOUT: /* Canceled due to timeout */
		ret |= LM_OUT_ERROR;
		goto out;
	case 0: /* Success */
		break;
	default: /* Something unexpected */
		BUG();
	}

	ret = gl->gl_req;
	if (gl->gl_lksb.sb_flags & DLM_SBF_ALTMODE) {
		if (gl->gl_req == LM_ST_SHARED)
			ret = LM_ST_DEFERRED;
		else if (gl->gl_req == LM_ST_DEFERRED)
			ret = LM_ST_SHARED;
		else
			BUG();
	}

	set_bit(GLF_INITIAL, &gl->gl_flags);
	gfs2_glock_complete(gl, ret);
	return;
out:
	if (!test_bit(GLF_INITIAL, &gl->gl_flags))
		gl->gl_lksb.sb_lkid = 0;
	gfs2_glock_complete(gl, ret);
}

static void gdlm_bast(void *arg, int mode)
{
	struct gfs2_glock *gl = arg;

	switch (mode) {
	case DLM_LOCK_EX:
		gfs2_glock_cb(gl, LM_ST_UNLOCKED);
		break;
	case DLM_LOCK_CW:
		gfs2_glock_cb(gl, LM_ST_DEFERRED);
		break;
	case DLM_LOCK_PR:
		gfs2_glock_cb(gl, LM_ST_SHARED);
		break;
	default:
		printk(KERN_ERR "unknown bast mode %d", mode);
		BUG();
	}
}

/* convert gfs lock-state to dlm lock-mode */

static int make_mode(const unsigned int lmstate)
{
	switch (lmstate) {
	case LM_ST_UNLOCKED:
		return DLM_LOCK_NL;
	case LM_ST_EXCLUSIVE:
		return DLM_LOCK_EX;
	case LM_ST_DEFERRED:
		return DLM_LOCK_CW;
	case LM_ST_SHARED:
		return DLM_LOCK_PR;
	}
	printk(KERN_ERR "unknown LM state %d", lmstate);
	BUG();
	return -1;
}

static u32 make_flags(struct gfs2_glock *gl, const unsigned int gfs_flags,
		      const int req)
{
	u32 lkf = DLM_LKF_VALBLK;
	u32 lkid = gl->gl_lksb.sb_lkid;

	if (gfs_flags & LM_FLAG_TRY)
		lkf |= DLM_LKF_NOQUEUE;

	if (gfs_flags & LM_FLAG_TRY_1CB) {
		lkf |= DLM_LKF_NOQUEUE;
		lkf |= DLM_LKF_NOQUEUEBAST;
	}

	if (gfs_flags & LM_FLAG_PRIORITY) {
		lkf |= DLM_LKF_NOORDER;
		lkf |= DLM_LKF_HEADQUE;
	}

	if (gfs_flags & LM_FLAG_ANY) {
		if (req == DLM_LOCK_PR)
			lkf |= DLM_LKF_ALTCW;
		else if (req == DLM_LOCK_CW)
			lkf |= DLM_LKF_ALTPR;
		else
			BUG();
	}

	if (lkid != 0) {
		lkf |= DLM_LKF_CONVERT;
		if (test_bit(GLF_BLOCKING, &gl->gl_flags))
			lkf |= DLM_LKF_QUECVT;
	}

	return lkf;
}

static void gfs2_reverse_hex(char *c, u64 value)
{
	*c = '0';
	while (value) {
		*c-- = hex_asc[value & 0x0f];
		value >>= 4;
	}
}

static unsigned int gdlm_lock(struct gfs2_glock *gl, unsigned int req_state,
		     unsigned int flags)
{
	struct lm_lockstruct *ls = &gl->gl_sbd->sd_lockstruct;
	int error;
	int req;
	u32 lkf;
	char strname[GDLM_STRNAME_BYTES] = "";

	req = make_mode(req_state);
	lkf = make_flags(gl, flags, req);
	gfs2_glstats_inc(gl, GFS2_LKS_DCOUNT);
	gfs2_sbstats_inc(gl, GFS2_LKS_DCOUNT);
	if (gl->gl_lksb.sb_lkid) {
		gfs2_update_request_times(gl);
	} else {
		memset(strname, ' ', GDLM_STRNAME_BYTES - 1);
		strname[GDLM_STRNAME_BYTES - 1] = '\0';
		gfs2_reverse_hex(strname + 7, gl->gl_name.ln_type);
		gfs2_reverse_hex(strname + 23, gl->gl_name.ln_number);
		gl->gl_dstamp = ktime_get_real();
	}
	/*
	 * Submit the actual lock request.
	 */

	error = dlm_lock(ls->ls_dlm, req, &gl->gl_lksb, lkf, strname,
			 GDLM_STRNAME_BYTES - 1, 0, gdlm_ast, gl, gdlm_bast);
	if (error == -EAGAIN)
		return 0;
	if (error)
		return LM_OUT_ERROR;
	return LM_OUT_ASYNC;
}

static void gdlm_put_lock(struct gfs2_glock *gl)
{
	struct gfs2_sbd *sdp = gl->gl_sbd;
	struct lm_lockstruct *ls = &sdp->sd_lockstruct;
	int error;

	if (gl->gl_lksb.sb_lkid == 0) {
		gfs2_glock_free(gl);
		return;
	}

	clear_bit(GLF_BLOCKING, &gl->gl_flags);
	gfs2_glstats_inc(gl, GFS2_LKS_DCOUNT);
	gfs2_sbstats_inc(gl, GFS2_LKS_DCOUNT);
	gfs2_update_request_times(gl);
	error = dlm_unlock(ls->ls_dlm, gl->gl_lksb.sb_lkid, DLM_LKF_VALBLK,
			   NULL, gl);
	if (error) {
		printk(KERN_ERR "gdlm_unlock %x,%llx err=%d\n",
		       gl->gl_name.ln_type,
		       (unsigned long long)gl->gl_name.ln_number, error);
		return;
	}
}

static void gdlm_cancel(struct gfs2_glock *gl)
{
	struct lm_lockstruct *ls = &gl->gl_sbd->sd_lockstruct;
	dlm_unlock(ls->ls_dlm, gl->gl_lksb.sb_lkid, DLM_LKF_CANCEL, NULL, gl);
}

static int gdlm_mount(struct gfs2_sbd *sdp, const char *fsname)
{
	struct lm_lockstruct *ls = &sdp->sd_lockstruct;
	int error;

	if (fsname == NULL) {
		fs_info(sdp, "no fsname found\n");
		return -EINVAL;
	}

	error = dlm_new_lockspace(fsname, strlen(fsname), &ls->ls_dlm,
				  DLM_LSFL_FS | DLM_LSFL_NEWEXCL |
				  (ls->ls_nodir ? DLM_LSFL_NODIR : 0),
				  GDLM_LVB_SIZE);
	if (error)
		printk(KERN_ERR "dlm_new_lockspace error %d", error);

	return error;
}

static void gdlm_unmount(struct gfs2_sbd *sdp)
{
	struct lm_lockstruct *ls = &sdp->sd_lockstruct;

	if (ls->ls_dlm) {
		dlm_release_lockspace(ls->ls_dlm, 2);
		ls->ls_dlm = NULL;
	}
}

static const match_table_t dlm_tokens = {
	{ Opt_jid, "jid=%d"},
	{ Opt_id, "id=%d"},
	{ Opt_first, "first=%d"},
	{ Opt_nodir, "nodir=%d"},
	{ Opt_err, NULL },
};

const struct lm_lockops gfs2_dlm_ops = {
	.lm_proto_name = "lock_dlm",
	.lm_mount = gdlm_mount,
	.lm_unmount = gdlm_unmount,
	.lm_put_lock = gdlm_put_lock,
	.lm_lock = gdlm_lock,
	.lm_cancel = gdlm_cancel,
	.lm_tokens = &dlm_tokens,
};


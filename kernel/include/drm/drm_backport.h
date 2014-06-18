/*
 * Copyright (C) 2013 Red Hat
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License v2. See the file COPYING in the main directory of this archive for
 * more details.
 */

#ifndef DRM_BACKPORT_H_
#define DRM_BACKPORT_H_

#include <linux/console.h>

#define in_dbg_master() (0)

static inline void console_lock(void)
{
	acquire_console_sem();
}

static inline void console_unlock(void)
{
	release_console_sem();
}

static inline int console_trylock(void)
{
	return try_acquire_console_sem();
}

static inline struct inode *file_inode(struct file *f)
{
	return f->f_path.dentry->d_inode;
}

#define SIZE_MAX ULONG_MAX

#endif /* DRM_BACKPORT_H_ */


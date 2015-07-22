/*
 * net/fastsocket/fastsocket.c
 *
 * Copyright (C) SINA Corporation
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/fs.h>
#include <linux/file.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_sock.h>
#include <net/inet_common.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/nsproxy.h>
#include <linux/file.h>
#include <linux/net.h>
#include <linux/eventpoll.h>
#include <linux/list.h>
#include <linux/cred.h>
#include <linux/fdtable.h>
#include <linux/mount.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/fsnotify.h>
#include <linux/netdevice.h>

#include "fastsocket.h"

#define DISABLE_LISTEN_SPAWN					0
#define ENABLE_LISTEN_SPAWN_REQUIRED_AFFINITY	1
#define ENABLE_LISTEN_SPAWN_AUTOSET_AFFINITY	2



#define FSOCKET_MEM_POOL_BACKLOG_MAX_LIMIT			(16)

enum {
	FSOCKET_STATS_SOCK_ALLOC_FROM_SLAB,
	FSOCKET_STATS_SOCK_FREE_TO_SLAB,
	FSOCKET_STATS_SOCK_ALLOC_FROM_POOL,
	FSOCKET_STATS_SOCK_FREE_TO_POOL,
	FSOCKET_STATS_SOCK_IN_POOL,
	FSOCKET_STATS_SOCK_POOL_LOCK,
	FSOCKET_STATS_SOCK_ACCEPT_CONNS,

	FSOCKET_STATS_NR
};

struct fsocket_stats {
	u32 stats[FSOCKET_STATS_NR];
};

struct fsocket_pool {
	struct list_head free_list;
	struct list_head backlog_list;
	spinlock_t backlog_lock;
	int free_cnt;
	int backlog_cnt;
};

struct fsocket_alloc {
	struct socket_alloc sock_alloc;
	struct list_head next;
	int cpu_id;
};

extern struct kmem_cache *dentry_cache;
extern int inet_create(struct net *net, struct socket *sock, int protocol, int kern);

extern unsigned int sock_poll(struct file *file, poll_table *wait);
extern ssize_t sock_sendpage(struct file *file, struct page *page,
		int offset, size_t size, loff_t *ppos, int more);
extern ssize_t generic_splice_sendpage(struct pipe_inode_info *pipe,
		struct file *out, loff_t *ppos, size_t len, unsigned int flags);
extern ssize_t sock_splice_read(struct file *file, loff_t *ppos,
		struct pipe_inode_info *pipe, size_t len, unsigned int flags);
extern ssize_t sock_aio_read(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos);
extern ssize_t sock_aio_write(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos);

static DEFINE_PER_CPU(struct fsocket_stats, fsocket_stats);
static DEFINE_PER_CPU(struct fsocket_pool, fsocket_pool);
static DEFINE_PER_CPU(unsigned int, global_spawn_accept) = 0;
static struct kmem_cache *fsocket_cachep;
static struct kmem_cache *fsocket_pool_cachep;

/*****************************************************************************************************/
#define FSOCKET_INC_STATS(stats_type) \
	do { \
		struct fsocket_stats *fstats = &__get_cpu_var(fsocket_stats); \
		++fstats->stats[stats_type]; \
	} while (0)
#define FSOCKET_DEC_STATS(stats_type) \
	do { \
		struct fsocket_stats *fstats = &__get_cpu_var(fsocket_stats); \
		--fstats->stats[stats_type]; \
	} while (0)
#define FSOCKET_GET_STATS(stats_type) (__get_cpu_var(fsocket_stats).stats[stats_type])

#define FSOCKET_INC_CPU_STATS(cpu, stats_type) \
	do { \
		struct fsocket_stats *fstats = &per_cpu(fsocket_stats, cpu); \
		++fstats->stats[stats_type]; \
	} while (0)
#define FSOCKET_DEC_CPU_STATS(cpu, stats_type) \
	do { \
		struct fsocket_stats *fstats = &per_cpu(fsocket_stats, cpu); \
		--fstats->stats[stats_type]; \
	} while (0)
#define FSOCKET_GET_CPU_STATS(cpu, stats_type) \
	(per_cpu(fsocket_stats, cpu).stats[stats_type])
	

static inline void fsock_release_sock(struct socket *sock)
{
	if (sock->ops) {
		DPRINTK(DEBUG, "Release inode socket 0x%p\n", SOCK_INODE(sock));
		sock->ops->release(sock);
		sock->ops = NULL;
	}
}

static struct socket_alloc *fsocket_alloc_socket_mem(void)
{
	struct socket_alloc *socket;

	if (enable_socket_pool_size) {
		struct fsocket_pool *fsock_pool = &__get_cpu_var(fsocket_pool);
		struct fsocket_alloc *fsock_alloc = NULL;

		preempt_disable();
		if (fsock_pool->free_cnt) {
			fsock_alloc = list_first_entry(&fsock_pool->free_list, struct fsocket_alloc, next);
			list_del(&fsock_alloc->next);
			fsock_pool->free_cnt--;
		}
		preempt_enable_no_resched();

		if (likely(fsock_alloc)) {
			goto alloc_from_pool;
		}

		if (fsock_pool->backlog_cnt) {			
			spin_lock(&fsock_pool->backlog_lock);
			FSOCKET_INC_STATS(FSOCKET_STATS_SOCK_POOL_LOCK);
			if (fsock_pool->backlog_cnt) {
				list_splice_init(&fsock_pool->backlog_list, &fsock_pool->free_list);
				fsock_pool->free_cnt = fsock_pool->backlog_cnt;
				fsock_pool->backlog_cnt = 0;
				
				fsock_alloc = list_first_entry(&fsock_pool->free_list, struct fsocket_alloc, next);
				list_del(&fsock_alloc->next);
				fsock_pool->free_cnt--;
			}
			spin_unlock(&fsock_pool->backlog_lock);
		}

		if (fsock_alloc) {
			goto alloc_from_pool;
		}

		fsock_alloc = kmem_cache_alloc(fsocket_pool_cachep, GFP_KERNEL);
		if (likely(fsock_alloc)) {
			fsock_alloc->cpu_id = smp_processor_id();
			FSOCKET_INC_STATS(FSOCKET_STATS_SOCK_ALLOC_FROM_SLAB);
			return &fsock_alloc->sock_alloc;
		}

		return NULL;

alloc_from_pool:
		FSOCKET_INC_STATS(FSOCKET_STATS_SOCK_ALLOC_FROM_POOL);
		FSOCKET_DEC_STATS(FSOCKET_STATS_SOCK_IN_POOL);
		return &fsock_alloc->sock_alloc;
	} else {
		socket = kmem_cache_alloc(fsocket_cachep, GFP_KERNEL);
		if (likely(socket)) {
			FSOCKET_INC_STATS(FSOCKET_STATS_SOCK_ALLOC_FROM_SLAB);
		}
		
		return socket;
	}
}


static inline void fsocket_move_socket_mem(struct fsocket_pool *src_pool, struct fsocket_pool *dst_pool, u32 cpu_id, int move_cnt)
{
	struct fsocket_alloc *pos, *next;
	int i = 0;

	list_for_each_entry_safe(pos, next, &src_pool->free_list, next) {
		list_del(&pos->next);
		src_pool->free_cnt--;
		FSOCKET_DEC_STATS(FSOCKET_STATS_SOCK_IN_POOL);

		// Change CPU ID
		pos->cpu_id = cpu_id;
		list_add(&pos->next, &dst_pool->free_list);
		dst_pool->free_cnt++;
		FSOCKET_INC_CPU_STATS(cpu_id, FSOCKET_STATS_SOCK_IN_POOL);

		++i;
		if (i >= move_cnt) {
			break;
		}
	}
}

static inline void fsocket_free_socket_mem(struct socket_alloc *sock_alloc)
{
	if (enable_socket_pool_size) {
		struct fsocket_alloc *fsock = (struct fsocket_alloc *)sock_alloc;
		struct fsocket_pool *fsock_pool = &per_cpu(fsocket_pool, fsock->cpu_id);
		struct fsocket_pool *cur_fsock_pool = &__get_cpu_var(fsocket_pool);
		int cpu = smp_processor_id();

		if (fsock_pool->free_cnt+fsock_pool->backlog_cnt >= enable_socket_pool_size) {
			kmem_cache_free(fsocket_pool_cachep, fsock);
			FSOCKET_INC_STATS(FSOCKET_STATS_SOCK_FREE_TO_SLAB);
			if (fsock_pool->backlog_cnt > FSOCKET_MEM_POOL_BACKLOG_MAX_LIMIT) {
            	spin_lock(&fsock_pool->backlog_lock);
            	if (fsock_pool->backlog_cnt > FSOCKET_MEM_POOL_BACKLOG_MAX_LIMIT)  {
                	list_splice_init(&fsock_pool->backlog_list, &fsock_pool->free_list);
                	fsock_pool->free_cnt += fsock_pool->backlog_cnt;
                	fsock_pool->backlog_cnt = 0;

            	}
            	spin_unlock(&fsock_pool->backlog_lock);
			}
		} else {
			if (fsock->cpu_id == cpu) {
				FSOCKET_INC_STATS(FSOCKET_STATS_SOCK_FREE_TO_POOL);
				FSOCKET_INC_STATS(FSOCKET_STATS_SOCK_IN_POOL);
				preempt_disable();
				list_add(&fsock->next, &fsock_pool->free_list);
				fsock_pool->free_cnt++;
				preempt_enable_no_resched();
			} else {				
				FSOCKET_INC_STATS(FSOCKET_STATS_SOCK_POOL_LOCK);
				spin_lock(&fsock_pool->backlog_lock);
				list_add(&fsock->next, &fsock_pool->backlog_list);
				fsock_pool->backlog_cnt++;
				FSOCKET_INC_CPU_STATS(fsock->cpu_id, FSOCKET_STATS_SOCK_FREE_TO_POOL);
				FSOCKET_INC_CPU_STATS(fsock->cpu_id, FSOCKET_STATS_SOCK_IN_POOL);

				/*
				The cur CPU has less socket mem load than that CPU.
				So we move the socket mem to the master worker CPU.
				*/
				if (FSOCKET_GET_STATS(FSOCKET_STATS_SOCK_ALLOC_FROM_POOL) * 4 < FSOCKET_GET_CPU_STATS(fsock->cpu_id, FSOCKET_STATS_SOCK_ALLOC_FROM_POOL)) {
					int move_cnt = cur_fsock_pool->free_cnt-fsock_pool->free_cnt;
					if (move_cnt > 0) {
						DPRINTK(INFO, "CPU(%u) move %d socket mem to CPU(%d)",
							cpu, move_cnt, fsock->cpu_id);
						preempt_disable();
						fsocket_move_socket_mem(cur_fsock_pool, fsock_pool, fsock->cpu_id, move_cnt);
						preempt_enable();
					}
				}
				spin_unlock(&fsock_pool->backlog_lock);
			}
		}			
	} else {		
		kmem_cache_free(fsocket_cachep, sock_alloc);
		
		FSOCKET_INC_STATS(FSOCKET_STATS_SOCK_FREE_TO_SLAB);
	}

	module_put(THIS_MODULE);
}

static int __fsocket_filp_close(struct file *file)
{
	struct dentry *dentry = file->f_path.dentry;

	if (atomic_long_dec_and_test(&file->f_count)) {

		eventpoll_release(file);

		file->private_data = NULL;
		file->f_path.dentry = NULL;
		file->f_path.mnt = NULL;

		put_empty_filp(file);

		DPRINTK(DEBUG, "Free file 0x%p[%ld]\n", file, atomic_long_read(&file->f_count));

		if (dentry) {
			DPRINTK(DEBUG, "Release dentry 0x%p[%d]\n", dentry, atomic_read(&dentry->d_count));
			DPRINTK(DEBUG, "Release inode 0x%p[%d]\n", dentry->d_inode, atomic_read(&dentry->d_inode->i_count));
		} else {
			EPRINTK_LIMIT(ERR, "No dentry for file 0x%p\n", file);
			return 1;
		}

		dput(dentry);
		return 0;

	} else {
		DPRINTK(DEBUG, "Next time to release file 0x%p[%ld]\n", file, atomic_long_read(&file->f_count));
		return 1;
	}
}

static inline int fsocket_filp_close(struct file *file)
{
	struct file *sfile, *ofile;
	int retval;

	sfile = file->sub_file;
	ofile = file->old_file;

	DPRINTK(DEBUG, "Close file 0x%p\n", file);

	retval = __fsocket_filp_close(file);

	//FIXME: To close sub file and old file after close file successfully? Or the other way around.

	if (sfile && !retval) {
		DPRINTK(DEBUG, "Close sub file 0x%p\n", sfile);
		__fsocket_filp_close(sfile);
	}

	//Close old file when we don't need the socket fd, so it's safe to install the ofile back when spawn failed
	if (ofile && !retval) {
		DPRINTK(DEBUG, "Close old file 0x%p\n", ofile);
		__fsocket_filp_close(ofile);
	}

	return 0;
}

static inline int fsock_close(struct inode *i_node, struct file *file)
{
	DPRINTK(DEBUG, "Enter fsock_close, inode(%p) file(%p)\n", i_node, file);

	return fsocket_filp_close(file);
}

static int fsock_no_open(struct inode *irrelevant, struct file *dontcare)
{
	return -ENXIO;
}

static long fsock_ioctl(struct file *file, unsigned cmd, unsigned long arg)
{
   DPRINTK(INFO, "Do!\n");
   return -EINVAL;
}

#ifdef CONFIG_COMPAT
static long compat_fsock_ioctl(struct file *file, unsigned cmd, unsigned long arg)
{
   DPRINTK(INFO, "Do!\n");
   return -EINVAL;
}
#endif

static int fsock_mmap(struct file *file, struct vm_area_struct *vma)
{
	DPRINTK(INFO, "Do!\n");
	return -EINVAL;
}

static int fsock_fasync(int fd, struct file *filp, int on)
{
	DPRINTK(INFO, "Do!\n");
	return -EINVAL;
}

static const struct file_operations fsocket_file_ops = {
	.owner = 	THIS_MODULE,
	.llseek =	no_llseek,
	.aio_read = 	sock_aio_read,
	.aio_write =	sock_aio_write,
	.poll =		sock_poll,
	.unlocked_ioctl = fsock_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = compat_fsock_ioctl,
#endif
	.mmap =		fsock_mmap,
	.open =		fsock_no_open,	/* special open code to disallow open via /proc */
	.release =	fsock_close,
	.fasync =	fsock_fasync,
	.sendpage =	sock_sendpage,
	.splice_write = generic_splice_sendpage,
	.splice_read =	sock_splice_read,
};

static char *fastsockfs_dynamic_dname(struct dentry *dentry, char *buffer, int buflen,
			const char *fmt, ...)
{
	va_list args;
	char temp[64];
	int sz;

	va_start(args, fmt);
	sz = vsnprintf(temp, sizeof(temp), fmt, args) + 1;
	va_end(args);

	if (sz > sizeof(temp) || sz > buflen)
		return ERR_PTR(-ENAMETOOLONG);

	buffer += buflen - sz;
	return memcpy(buffer, temp, sz);
}

static char *fastsockfs_dname(struct dentry *dentry, char *buffer, int buflen)
{
	return fastsockfs_dynamic_dname(dentry, buffer, buflen, "socket:[%lu]",
				dentry->d_inode->i_ino);
}

static const struct dentry_operations fastsockfs_dentry_operations = {
	.d_dname  = fastsockfs_dname,
};

static void __put_unused_fd(struct files_struct *files, unsigned int fd)
{
	struct fdtable *fdt = files_fdtable(files);
	__FD_CLR(fd, fdt->open_fds);
	if (fd < files->next_fd)
		files->next_fd = fd;
}

#define DNAME_INLINE_LEN (sizeof(struct dentry)-offsetof(struct dentry,d_iname))

static void fsock_d_free(struct dentry *dentry)
{
    if (dname_external(dentry))
        kfree(dentry->d_name.name);

	kmem_cache_free(dentry_cache, dentry);
}

static struct dentry *fsock_d_alloc(struct socket *sock, struct dentry *parent, const struct qstr *name)
{
	struct dentry *dentry;
	char *dname;
	struct inode *inode;

	dentry = kmem_cache_alloc(dentry_cache, GFP_KERNEL);
	if (!dentry)
		return NULL;

	DPRINTK(DEBUG, "\tAllocat dentry 0x%p\n", dentry);

	if (name->len > DNAME_INLINE_LEN-1) {
		dname = kmalloc(name->len + 1, GFP_KERNEL);
		if (!dname) {
			kmem_cache_free(dentry_cache, dentry);
			return NULL;
		}
	} else {
		dname = dentry->d_iname;
	}

	dentry->d_name.name = dname;

	dentry->d_name.len = name->len;
	dentry->d_name.hash = name->hash;
	memcpy(dname, name->name, name->len);
	dname[name->len] = 0;

	atomic_set(&dentry->d_count, 1);
	dentry->d_flags = DCACHE_UNHASHED;
	spin_lock_init(&dentry->d_lock);
	dentry->d_inode = NULL;
	dentry->d_parent = NULL;
	dentry->d_sb = NULL;
	dentry->d_op = NULL;
	dentry->d_fsdata = NULL;
	INIT_HLIST_NODE(&dentry->d_hash);
	INIT_LIST_HEAD(&dentry->d_lru);
	INIT_LIST_HEAD(&dentry->d_subdirs);
	INIT_LIST_HEAD(&dentry->d_alias);

	INIT_LIST_HEAD(&dentry->d_u.d_child);

	inode = SOCK_INODE(sock);

	dentry->d_sb = inode->i_sb;
	dentry->d_parent = NULL;
	dentry->d_flags |= DCACHE_FASTSOCKET | DCACHE_DISCONNECTED;
	dentry->d_inode = inode;

	dentry->d_op = &fastsockfs_dentry_operations;

	return dentry;
}

static int fsock_alloc_file(struct socket *sock, struct file **f, int flags)
{
	int fd;
	struct qstr name = { .name = "" };
	struct path path;
	struct file *file;

	fd = get_unused_fd_flags(flags);

	if (unlikely(fd < 0)) {
		EPRINTK_LIMIT(ERR, "Socket 0x%p get unused fd failed\n", sock);
		return fd;
	}

	path.dentry = fsock_d_alloc(sock, NULL, &name);
	if (unlikely(!path.dentry)) {
		EPRINTK_LIMIT(ERR, "Socket 0x%p allocate dentry failed\n", sock);
		put_unused_fd(fd);
		return -ENOMEM;
	}

	path.mnt = fastsocket_mnt;

	SOCK_INODE(sock)->i_fop = &fsocket_file_ops;

	file = get_empty_filp();
	if (unlikely(!file)) {
		EPRINTK_LIMIT(ERR, "Socket 0x%p allocate empty file failed\n", sock);
		fsock_d_free(path.dentry);
		put_unused_fd(fd);
		return -ENFILE;
	}

	DPRINTK(DEBUG, "Allocate file 0x%p\n", file);

	file->f_path = path;
	file->f_mapping = path.dentry->d_inode->i_mapping;
	file->f_mode = FMODE_READ | FMODE_WRITE | FMODE_FASTSOCKET;
	if (enable_fast_epoll)
		file->f_mode |= FMODE_BIND_EPI;
	file->f_op = &fsocket_file_ops;

	sock->file = file;

	file->f_flags = O_RDWR | (flags & O_NONBLOCK);
	file->f_pos = 0;
	file->private_data = sock;

	file->sub_file = NULL;
	file->f_epi = NULL;

	*f = file;

	DPRINTK(DEBUG, "fsock_alloc_file: file(%p) dentry(%p)", file, file->f_path.dentry);

	return fd;
}

static int fsock_map_fd(struct socket *sock, int flags)
{
	struct file *newfile;

	int fd = fsock_alloc_file(sock, &newfile, flags);
	if (likely(fd >= 0))
		fd_install(fd, newfile);

	return fd;
}

static struct socket *fsocket_alloc_socket(void)
{
#define FSOCKET_INODE_START	( 1 << 12 )

	static const struct inode_operations empty_iops;
	static const struct file_operations empty_fops;
	struct socket *sock;
	//FIXME: Just guess this inode number is not something really matters.
	static unsigned int last_ino = FSOCKET_INODE_START;
	struct inode *inode = NULL;	

	sock = (struct socket *)fsocket_alloc_socket_mem();
	if (!sock) {
		DPRINTK(ERR, "Fail to allocate sock\n");
		goto err1;
	}
	
	__module_get(THIS_MODULE);
	
	if (security_inode_alloc(SOCK_INODE(sock))) {
		goto err2;
	}
	
	init_waitqueue_head(&sock->wait);
	
	sock->fasync_list = NULL;
	sock->state = SS_UNCONNECTED;
	sock->flags = 0;
	sock->ops = NULL;
	sock->sk = NULL;
	sock->file = NULL;
	
	sock->type = 0;
	
	inode = SOCK_INODE(sock);
	
	inode->i_op = &empty_iops;
	inode->i_fop = &empty_fops;
	inode->i_sb = fastsocket_mnt->mnt_sb;
	atomic_set(&inode->i_count, 1);
	
	INIT_LIST_HEAD(&inode->i_list);
	INIT_LIST_HEAD(&inode->i_sb_list);
	
	inode->i_ino = ++last_ino;
	inode->i_state = 0;
	
	kmemcheck_annotate_bitfield(sock, type);
	inode->i_mode = S_IFSOCK | S_IRWXUGO;
	inode->i_uid = current_fsuid();
	inode->i_gid = current_fsgid();

	
	
	DPRINTK(DEBUG, "Allocat inode 0x%p\n", inode);

	return sock;
	
err2:
	module_put(THIS_MODULE);
	fsocket_free_socket_mem((struct socket_alloc*)sock);
err1:
	return NULL;
}


static void fsocket_init_socket(struct socket *sock)
{
	if (enable_direct_tcp) {
		sock_set_flag(sock->sk, SOCK_DIRECT_TCP);
		DPRINTK(DEBUG, "Socket 0x%p is set with DIRECT_TCP\n", sock->sk);
	}
	if (enable_receive_cpu_selection) {
		sock_set_flag(sock->sk, SOCK_AFFINITY);
		sock->sk->sk_affinity = smp_processor_id();
		DPRINTK(DEBUG, "Socket 0x%p is set with RCS\n", sock->sk);
	}
}

static void fsocket_copy_socket(struct socket *oldsock, struct socket *newsock)
{
	//TODO: Check if all these copy works.

	/* General sk flags */
	newsock->sk->sk_flags = oldsock->sk->sk_flags;
	/* Non-Block */

	/* REUSEADDR (Verified) */
	newsock->sk->sk_reuse = oldsock->sk->sk_reuse;
	/* LINGER */
	newsock->sk->sk_lingertime = oldsock->sk->sk_lingertime;
	/* TPROXY - IP_TRANSPARENT and IP_FREEBIND */
	inet_sk(newsock->sk)->freebind = inet_sk(oldsock->sk)->freebind;
	inet_sk(newsock->sk)->transparent = inet_sk(oldsock->sk)->transparent;
	/* TCP_MAXSEG */
	tcp_sk(newsock->sk)->rx_opt.user_mss = tcp_sk(oldsock->sk)->rx_opt.user_mss;
	/* TCP_DEFER_ACCEPT */
	inet_csk(newsock->sk)->icsk_accept_queue.rskq_defer_accept =
		inet_csk(oldsock->sk)->icsk_accept_queue.rskq_defer_accept;
	/* TCP_QUICKACK */
	inet_csk(newsock->sk)->icsk_ack.pingpong = inet_csk(oldsock->sk)->icsk_ack.pingpong;

	//TODO: Other attibutes that need to be copied
}

static int fsocket_spawn_clone(int fd, struct socket *oldsock, struct socket **newsock)
{
	struct socket *sock;
	struct file *ofile, *nfile, *sfile;
	struct qstr name = { .name = "" };
	struct path path;

	int err = 0;

	ofile = oldsock->file;

	/*
	 * Allocate file for local spawned listen socket.
	*/

	DPRINTK(DEBUG, "Spawn inode 0x%p\n", SOCK_INODE(oldsock));

	sfile = get_empty_filp();
	if (sfile == NULL) {
		err = -ENOMEM;
		EPRINTK_LIMIT(ERR, "Spawn sub listen socket alloc file failed\n");
		goto out;
	}

	DPRINTK(DEBUG, "Allocate sub listen socket file 0x%p\n", sfile);

	sock = fsocket_alloc_socket();
	if (sock == NULL) {
		EPRINTK_LIMIT(ERR, "Allocate New Socket failed\n");
		err = -ENOMEM;
		put_empty_filp(sfile);
		goto out;
	}

	sock->type = oldsock->type;

	err = inet_create(current->nsproxy->net_ns, sock, 0, 0);
	if (err < 0) {
		EPRINTK_LIMIT(ERR, "Initialize Inet Socket failed\n");
		put_empty_filp(sfile);
		fsocket_free_socket_mem((struct socket_alloc*)sock);
		goto out;
	}

	err = security_socket_post_create(sock, PF_INET, SOCK_STREAM, IPPROTO_TCP, 0);
	if (err) {
		EPRINTK_LIMIT(ERR, "security_socket_post_create failed\n");
		put_empty_filp(sfile);
		fsock_release_sock(sock);
		fsocket_free_socket_mem((struct socket_alloc*)sock);
		goto out;
	}

	sock->sk->sk_local = -1;

	fsocket_copy_socket(oldsock, sock);

	path.dentry = fsock_d_alloc(sock, NULL, &name);
	if (unlikely(!path.dentry)) {
		err = -ENOMEM;
		EPRINTK_LIMIT(ERR, "Spawn listen socket alloc dentry failed\n");
		put_empty_filp(sfile);
		fsock_release_sock(sock);
		fsocket_free_socket_mem((struct socket_alloc*)sock);
		goto out;
	}

	path.mnt = fastsocket_mnt;

	SOCK_INODE(sock)->i_fop = &fsocket_file_ops;

	sfile->f_path = path;
	sfile->f_mapping = NULL;
	sfile->f_mode = ofile->f_mode;
	/* For spawned listen socket, set bind-epi and reset single-wakeup */
	if (enable_fast_epoll) {
		sfile->f_mode &= ~FMODE_SINGLE_WAKEUP;
		sfile->f_mode |= FMODE_BIND_EPI;
	}
	sfile->f_op = ofile->f_op;
	sfile->f_flags = ofile->f_flags;
	sfile->f_pos = ofile->f_pos;
	sfile->private_data = sock;

	sfile->sub_file = NULL;
	sfile->f_epi = NULL;

	sock->file = sfile;

	/*
	 * Allocate file copy for global listen socket.
	*/

	nfile = get_empty_filp();
	if (nfile == NULL) {
		err = -ENOMEM;
		EPRINTK_LIMIT(ERR, "Spawn global listen socket alloc file failed\n");
		__fsocket_filp_close(sfile);		
		goto out;
	}

	DPRINTK(DEBUG, "Allocate new listen socket file 0x%p\n", nfile);

	path.dentry = fsock_d_alloc(oldsock, NULL, &name);
	if (unlikely(!path.dentry)) {
		err = -ENOMEM;
		EPRINTK_LIMIT(ERR, "Spawn listen socket alloc dentry failed\n");
		put_empty_filp(nfile);
		__fsocket_filp_close(sfile);		
		goto out;
	}

	path.mnt = fastsocket_mnt;

	nfile->f_path = path;
	nfile->f_mapping = path.dentry->d_inode->i_mapping;
	nfile->f_mode = sfile->f_mode;
	nfile->f_op = sfile->f_op;
	nfile->f_flags = sfile->f_flags;
	nfile->f_pos = sfile->f_pos;
	nfile->private_data = oldsock;

	nfile->sub_file = sfile;
	nfile->f_epi = NULL;

	//Add i_count for this socket inode.
	atomic_inc(&SOCK_INODE(oldsock)->i_count);

	fd_reinstall(fd, nfile);

	//Save ofile in case that spawn failed and the listen fd can be restored back right before the spawn
	nfile->old_file = ofile;

	DPRINTK(DEBUG, "Clone new socket %d\n", err);

	*newsock = sock;

	goto out;

out:
	return err;
}


#if 0
extern int is_file_epoll_export(struct file *f);
extern void clear_tfile_check_list(void);
extern int ep_loop_check(struct eventpoll *ep, struct file *file);
extern struct mutex epmutex;

static int fsocket_epoll_ctl(struct eventpoll *ep, struct file *tfile, int fd,  int op,  struct __user epoll_event *ev)
{
	int error = -EINVAL;
	int full_check = 0;
	struct eventpoll *tep = NULL;

	struct epitem *epi;
	struct epoll_event epds;

	struct file *sfile;

	if (copy_from_user(&epds, ev, sizeof(struct epoll_event)))
		return -EFAULT;

	//FIXME: Do more sanity check.

	/**
	 * sub_file is used to record the spawned listeners only. If tfile is an
	 * epoll file, its sub_file must then be null. Thus there is no need to
	 * involve sub_file in the checking.
	 */
	mutex_lock(&ep->mtx);
	if (op == EPOLL_CTL_ADD) {
		if (!list_empty(&tfile->f_ep_links) ||
			is_file_epoll_export(tfile)) {
			full_check = 1;
			WARN(1, "Why do fastsocket need nested ep?!\n");
			mutex_unlock(&ep->mtx);
			mutex_lock(&epmutex);
			goto error_loop_check;
			if (is_file_epoll_export(tfile)) {
				error = -ELOOP;
				if (ep_loop_check(ep, tfile) != 0) {
					clear_tfile_check_list();
					goto error_loop_check;
				}
			}
			mutex_lock(&ep->mtx);
			if (is_file_epoll_export(tfile)) {
				tep = tfile->private_data;
				mutex_lock(&tep->mtx);
			}
		}
	}
	if (op == EPOLL_CTL_DEL && is_file_epoll_export(tfile)) {
		tep = tfile->private_data;
		mutex_lock(&tep->mtx);
	}

	if (tfile->f_mode & FMODE_BIND_EPI) {
		DPRINTK(DEBUG, "File 0x%p binds epi\n", tfile);
		epi = tfile->f_epi;
	}
	else {
		DPRINTK(DEBUG, "File 0x%p binds NO epi\n", tfile);
		epi = ep_find(ep, tfile, fd);
	}

	DPRINTK(DEBUG, "OP %d EPI 0x%p\n", op, epi);

	sfile = tfile->sub_file;

	switch (op) {
	case EPOLL_CTL_ADD:
		if (!epi) {
			epds.events |= POLLERR | POLLHUP;
			DPRINTK(DEBUG, "Insert common socket %d\n", fd);
			error = ep_insert(ep, &epds, tfile, fd, full_check);
			if (sfile && !error) {
				DPRINTK(DEBUG, "Insert spawned listen socket %d\n", fd);
				error = ep_insert(ep, &epds, sfile, fd, full_check);
				if (error < 0)
					EPRINTK_LIMIT(ERR, "Insert sub socket %d to epoll failed\n", fd);
					//FIXME: Rollback the epoll opertation of the original file.
			}
		} else
			error = -EEXIST;
		clear_tfile_check_list();
		if (full_check)
			clear_tfile_check_list();
		break;
	case EPOLL_CTL_DEL:
		if (epi) {
			DPRINTK(DEBUG, "Remove common socket %d\n", fd);
			error = ep_remove(ep, epi);
			if (sfile && !error) {
				struct epitem *sepi;
				error = -ENOENT;

				DPRINTK(DEBUG, "Remove spawned listen socket %d\n", fd);
				if (sfile->f_mode & FMODE_BIND_EPI) {
					DPRINTK(DEBUG, "Subfile 0x%p binds epi 0x%p\n", sfile, sfile->f_epi);
					sepi = sfile->f_epi;
				} else {
					DPRINTK(DEBUG, "Subfile 0x%p binds NO epi\n", sfile);
					sepi = ep_find(ep, sfile, fd);
				}
				if (sepi) {
					error = ep_remove(ep, sepi);
					if (error < 0)
						EPRINTK_LIMIT(ERR, "Remove sub socket %d from epoll failed\n", fd);
						//FIXME: Rollback the epoll opertation of the original file.
				} else {
					EPRINTK_LIMIT(ERR, "No sub epoll item for socket %d\n", fd);
				}
			}
		} else
			error = -ENOENT;
		break;
	case EPOLL_CTL_MOD:
		if (epi) {
			epds.events |= POLLERR | POLLHUP;
			DPRINTK(DEBUG, "Modify common socket %d\n", fd);
			error = ep_modify(ep, epi, &epds);
			if (sfile && !error) {
				struct epitem *sepi;
				error = -ENOENT;

				DPRINTK(DEBUG, "Modify spawned listen socket %d\n", fd);

				if (sfile->f_mode & FMODE_BIND_EPI) {
					DPRINTK(DEBUG, "Subfile 0x%p binds epi 0x%p\n", sfile, sfile->f_epi);
					sepi = sfile->f_epi;
				} else {
					DPRINTK(DEBUG, "Subfile 0x%p binds NO epi\n", sfile);
					sepi = ep_find(ep, sfile, fd);
				}

				if (sepi) {
					error = ep_modify(ep, epi, &epds);
					if (error < 0)
						EPRINTK_LIMIT(ERR, "Modify sub socket %d in epoll failed\n", fd);
						//FIXME: Rollback the epoll opertation of the original file.
				} else {
					EPRINTK_LIMIT(ERR, "No sub epoll item for socket %d\n", fd);
				}
			}
		} else
			error = -ENOENT;
		break;
	}
	if (tep != NULL)
		mutex_unlock(&tep->mtx);
	mutex_unlock(&ep->mtx);

error_loop_check:
	if (full_check)
		mutex_unlock(&epmutex);

	return error;
}
#endif

static void fsocket_process_affinity_set(int cpu)
{
	struct cpumask mask;

	cpumask_clear(&mask);
	cpumask_set_cpu(cpu, &mask);
	sched_setaffinity(current->pid, &mask);
}

static void fsocket_process_affinity_restore(int cpu)
{
	cpu_clear(cpu, fastsocket_spawn_cpuset);
	fastsocket_spawn_cpu--;
}

/* Currently, user required CPU affinity is not supported. However, the feature 
 * function suppport is kept for future complete implementation. */

static int fsocket_process_affinity_check(int rcpu)
{
	int ccpu, ncpu, cpu;
	int tcpu = -1;
	cpumask_var_t omask;
	//struct socket *sock;

	if (enable_listen_spawn == DISABLE_LISTEN_SPAWN) {
		EPRINTK_LIMIT(ERR, "Module para disable listen-spawn feature\n");
		return -EPERM;
	}

	if ((rcpu >= 0) && (rcpu > num_active_cpus())) {
		EPRINTK_LIMIT(ERR, "Requested CPU %d is greater than system available CPU core %d\n", rcpu, num_active_cpus());
		return -EINVAL;
	}

	/* Respect the choice of user */

	if (rcpu >= 0)
		return rcpu;

	if (!alloc_cpumask_var(&omask, GFP_KERNEL))
		return -ENOMEM;

	sched_getaffinity(current->pid, omask);
	ccpu = cpumask_first(omask);
	ncpu = cpumask_next(ccpu, omask);
	free_cpumask_var(omask);

	DPRINTK(DEBUG, "Current process ccpu(%d) ncpu(%d)\n", ccpu, ncpu);

	if (ccpu >= nr_cpu_ids) {
		DPRINTK(DEBUG, "Current process affinity is messed up\n");
		return -EINVAL;
	}

	if (ncpu >= nr_cpu_ids) {
		DPRINTK(INFO, "Current process already binds to CPU %d\n", ccpu);
		return ccpu;
	}

	if (enable_listen_spawn != ENABLE_LISTEN_SPAWN_AUTOSET_AFFINITY) {
		EPRINTK_LIMIT(ERR, "Module para disable autoset affinity for listen-spawn\n");
		return -EPERM;
	}

	/* Choose a unused CPU core to bind this process */	

	for (cpu = fastsocket_spawn_cpu; cpu < num_active_cpus(); cpu++) {
		if (!cpu_isset(cpu, fastsocket_spawn_cpuset)) {
			DPRINTK(INFO, "CPU %d is available for process affinity\n", cpu);
			tcpu = cpu;
			break;
		}
	}

	if (tcpu >= 0) {
		cpu_set(cpu, fastsocket_spawn_cpuset);
		fastsocket_spawn_cpu++;
	} else {
		EPRINTK_LIMIT(ERR, "Process number is more than CPU number\n");
		return -EINVAL;
	}

	DPRINTK(INFO, "Target process affinity: %d\n", tcpu);

	return tcpu;
}

static void fsocket_sk_affinity_set(struct socket *sock, int cpu)
{
	sock_set_flag(sock->sk, SOCK_LOCAL);
	sock->sk->sk_local = cpu;

	DPRINTK(DEBUG, "Bind this listen socket to CPU %d", cpu);
}

static void fsocket_sk_affinity_release(struct socket *sock)
{
	sock->sk->sk_local = -1;
}

static void fsocket_filp_close_spawn(int fd)
{
	int fput_needed;
	struct file *nfile, *ofile, *sfile;

	nfile = fget_light(fd, &fput_needed);

	ofile = nfile->old_file;
	sfile = nfile->sub_file;

	fd_reinstall(fd, ofile);

	DPRINTK(DEBUG, "Close sub file 0x%p\n", sfile);
	__fsocket_filp_close(sfile);
	DPRINTK(DEBUG, "Close new file 0x%p\n", nfile);
	__fsocket_filp_close(nfile);

	fput_light(nfile, fput_needed);
}

static void fsocket_set_bind_cap(kernel_cap_t *p)
{
	kernel_cap_t pE, pI, pP, pN;
	struct cred *new;

	cap_capget(current, &pE, &pI, &pP);
	pN = pE;

	cap_raise(pN, CAP_NET_BIND_SERVICE);

	//TODO: Ugly hack.
	new = (struct cred *)current_cred();
	new->cap_effective = pN;

	*p = pE;
}

static void fsocket_reset_bind_cap(kernel_cap_t *p)
{
	struct cred *old;

	old = (struct cred *)current_cred();
	old->cap_effective = *p;
}


DECLARE_PER_CPU(struct inet_hash_stats, hash_stats);

static inline int fsocket_common_accept(struct socket *sock, struct socket *newsock, int flags)
{
	int ret;

	ret =  sock->ops->accept(sock, newsock, flags);
	if (!ret)
		__get_cpu_var(hash_stats).common_accept++;
	//else {
	//	if (ret != -EAGAIN)
	//		__get_cpu_var(hash_stats).common_accept_failed++;
	//	else
	//		__get_cpu_var(hash_stats).common_accept_again++;
	//}
	return ret;
}

static inline int fsocket_local_accept(struct socket *sock, struct socket *newsock, int flags)
{
	int ret;

	ret = sock->ops->accept(sock, newsock, flags);
	if (!ret) {
		if (sock->sk->sk_local == smp_processor_id())
			__get_cpu_var(hash_stats).local_accept++;
		else
			__get_cpu_var(hash_stats).remote_accept++;
	}
	//else {
	//	if (unlikely(ret != -EAGAIN))
	//		__get_cpu_var(hash_stats).local_accept_failed++;
	//	else
	//		__get_cpu_var(hash_stats).local_accept_again++;
	//}
	return ret;
}

static inline int fsocket_need_global_accept(void)
{
	return percpu_read(global_spawn_accept) & 0x1;
}

static inline int fsocket_global_accept(struct socket *sock, struct socket *newsock, int flags)
{
	int ret;

	percpu_add(global_spawn_accept, 1);

	//TODO: Is the policy good?
	if (fsocket_need_global_accept()) {
		ret = sock->ops->accept(sock, newsock, flags);
		if (!ret)
			__get_cpu_var(hash_stats).global_accept++;
		//else {
		//	if (ret != -EAGAIN)
		//		__get_cpu_var(hash_stats).global_accept_failed++;
		//	else
		//		__get_cpu_var(hash_stats).global_accept_again++;
		//}
		return ret;
	}
	return -EAGAIN;
}

static void init_once(void *foo)
{
	struct socket_alloc *ei = (struct socket_alloc *)foo;

	inode_init_once(&ei->vfs_inode);
}

DECLARE_PER_CPU(struct netif_deliver_stats, deliver_stats);

static int process_rcs_rps(struct sk_buff *skb)
{
	struct iphdr *iph = (struct iphdr *)skb->data;
	int iphl = iph->ihl;
	struct netif_deliver_stats *stat;

	if (pskb_may_pull(skb, (iphl * 4) + sizeof(struct tcphdr))) {
		struct sock *sk;
		struct tcphdr *th = (struct tcphdr *)(skb->data + (iphl * 4));
		int cur_cpu = smp_processor_id();

		if (!skb->peek_sk) {
			sk = __inet_lookup(&init_net, &tcp_hashinfo, iph->saddr, th->source, iph->daddr, th->dest, skb->dev->ifindex);;
			skb->peek_sk = sk;
		} else
			sk = skb->peek_sk;

		stat = &get_cpu_var(deliver_stats);

		if (likely(sk)) {
			if ((sk->sk_state != TCP_TIME_WAIT) && 
					sock_flag(sk, SOCK_AFFINITY) && sk->sk_affinity >= 0) {
				stat->steer++;

				if (sk->sk_affinity != cur_cpu) {
					stat->steer_done++;
					return sk->sk_affinity;
				} else {
					stat->steer_save++;
					return -1;
				}
			} else {
				stat->pass++;
				return -1;
			}
		}
	}

	return -1;
}

static struct netif_rps_entry rcs_rps_entry = {
	.proto		= IPPROTO_TCP,
	.flags		= RPS_STOP,
	.rps_process	= process_rcs_rps,
	.rps_init	= NULL,
	.rps_uninit	= NULL,
	.list		= LIST_HEAD_INIT(rcs_rps_entry.list),
};

static int process_direct_tcp_rps(struct sk_buff *skb)
{
	struct iphdr *iph = (struct iphdr *)skb->data;
	int iphl = iph->ihl;

	if (pskb_may_pull(skb, (iphl * 4) + sizeof(struct tcphdr))) {
		struct sock *sk;
		struct tcphdr *th = (struct tcphdr *)(skb->data + (iphl * 4));

		if (!skb->peek_sk) {
			sk = __inet_lookup(&init_net, &tcp_hashinfo, iph->saddr, th->source, iph->daddr, th->dest, skb->dev->ifindex);;
			skb->peek_sk = sk;
		} else
			sk = skb->peek_sk;

		if (likely(sk)) {
			if ((sk->sk_state != TCP_TIME_WAIT) && sock_flag(sk, SOCK_DIRECT_TCP)) {
				//DPRINTK(DEBUG, "Skb 0x%p[:%u] hit DIRECT_TCP socket 0x%p[:%u]\n", skb, ntohs(th->dest), sk, inet_sk(sk)->num);
				if(sk->sk_rcv_dst) {
					skb_dst_set(skb, sk->sk_rcv_dst);
					skb->sock_dst = sk->sk_rcv_dst;
					//DPRINTK(DEBUG, "Direct TCP socket 0x%p has dst record 0x%p[%u]\n", sk, sk->sk_rcv_dst, atomic_read(&sk->sk_rcv_dst->__refcnt));a
				}
				//} else {
				//	DPRINTK(DEBUG, "Direct TCP socket 0x%p has not dst record\n", sk);
				//}

			//} else {
			//	if (ntohs(th->dest) != 22)
			//		DPRINTK(DEBUG, "Skb 0x%p[:%u] hit common socket 0x%p[:%u]\n", skb,ntohs(th->dest), sk, inet_sk(sk)->num);
			}
		}
	}

	return -1;
}

static struct netif_rps_entry direct_tcp_rps_entry = {
	.proto		= IPPROTO_TCP,
	.flags		= RPS_CONTINUE,
	.rps_process	= process_direct_tcp_rps,
	.rps_init	= NULL,
	.rps_uninit	= NULL,
	.list		= LIST_HEAD_INIT(direct_tcp_rps_entry.list),
};

static int fsocket_stats_show(struct seq_file *s, void *v)
{
	struct fsocket_stats *stats;
	int cpu;

	seq_printf(s, "CPU    s_alloc_slab    s_free_slab    s_alloc_pool    s_free_pool    s_pool    s_lock    accept_conns\n");

	for_each_online_cpu(cpu) {
		stats = &per_cpu(fsocket_stats, cpu);

		seq_printf(s, "%3d    %12d    %11d    %12d    %11d    %6d    %6d    %12d\n", 
				cpu, 
				stats->stats[FSOCKET_STATS_SOCK_ALLOC_FROM_SLAB],
				stats->stats[FSOCKET_STATS_SOCK_FREE_TO_SLAB],
				stats->stats[FSOCKET_STATS_SOCK_ALLOC_FROM_POOL],
				stats->stats[FSOCKET_STATS_SOCK_FREE_TO_POOL],
				stats->stats[FSOCKET_STATS_SOCK_IN_POOL], 
				stats->stats[FSOCKET_STATS_SOCK_POOL_LOCK],
				stats->stats[FSOCKET_STATS_SOCK_ACCEPT_CONNS]);
	}

	return 0;
}

static void *fsocket_stats_start(struct seq_file *m, loff_t *pos)
{
    return *pos < 1 ? (void *)1 : NULL;
}

static void *fsocket_stats_next(struct seq_file *m, void *v, loff_t *pos)
{
    ++*pos;
    return NULL;
}

static void fsocket_stats_stop(struct seq_file *m, void *v)
{

}

static const struct seq_operations fsocket_seq_ops = {
    .start  = fsocket_stats_start,
    .next   = fsocket_stats_next,
    .stop   = fsocket_stats_stop,
    .show   = fsocket_stats_show,
};

static int fsocket_seq_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &fsocket_seq_ops);
}

static const struct file_operations fsocket_seq_fops = {
    .owner   = THIS_MODULE,
    .open    = fsocket_seq_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = seq_release,
};

static void fsocket_fini_sock_pool(void)
{
	int cpu;

	for_each_online_cpu(cpu) {
		struct fsocket_pool *sock_pool = &per_cpu(fsocket_pool, cpu);
		struct fsocket_alloc *pos, *n;

		list_for_each_entry_safe(pos, n, &sock_pool->free_list, next) {
			kmem_cache_free(fsocket_pool_cachep, pos);
		}

		list_for_each_entry_safe(pos, n, &sock_pool->backlog_list, next) {
			kmem_cache_free(fsocket_pool_cachep, pos);
		}
	}

	kmem_cache_destroy(fsocket_pool_cachep);
}

static int fsocket_init_sock_pool(void)
{
	int cpu, i;

	/* Makesure the percpu sock pool is initialized */
	for_each_online_cpu(cpu) {		
		struct fsocket_pool *sock_pool = &per_cpu(fsocket_pool, cpu);

		INIT_LIST_HEAD(&sock_pool->free_list);
		INIT_LIST_HEAD(&sock_pool->backlog_list);
		spin_lock_init(&sock_pool->backlog_lock);
	}

	for_each_online_cpu(cpu) {
		struct fsocket_pool *sock_pool = &per_cpu(fsocket_pool, cpu);
		struct fsocket_alloc *fsock;

		for (i = 0; i < enable_socket_pool_size; ++i) {
			fsock = kmem_cache_alloc_node(fsocket_pool_cachep, GFP_KERNEL, cpu_to_node(cpu));
			if (fsock) {				
				fsock->cpu_id = cpu;
				list_add(&fsock->next, &sock_pool->free_list);
				sock_pool->free_cnt++;
				FSOCKET_INC_CPU_STATS(cpu, FSOCKET_STATS_SOCK_IN_POOL);
			} else {
				goto error;
			}
		}
	}	

	return 0;

error:
	fsocket_fini_sock_pool();
	return -ENOMEM;
}

int fsocket_init(void)
{
	int ret;

	fsocket_cachep = kmem_cache_create("fsocket_socket_cache", sizeof(struct socket_alloc), 0,
			SLAB_HWCACHE_ALIGN | SLAB_RECLAIM_ACCOUNT |
			SLAB_MEM_SPREAD | SLAB_PANIC, init_once);
	if (!fsocket_cachep) {
		EPRINTK_LIMIT(ERR, "Allocate fsocket cachep failed\n");
		ret = -ENOMEM;
		goto err1;
	}
	
	if (!proc_net_fops_create(&init_net, "fsocket_stats", S_IRUGO, &fsocket_seq_fops)) {
		goto err2;
	}
	
	if (enable_listen_spawn)
		printk(KERN_INFO "Fastsocket: Enable Listen Spawn[Mode-%d]\n", enable_listen_spawn);
	if (enable_receive_flow_deliver)
		printk(KERN_INFO "Fastsocket: Enable Recieve Flow Deliver\n");
	if (enable_fast_epoll)
		printk(KERN_INFO "Fastsocket: Enable Fast Epoll\n");
	if (enable_direct_tcp) {
		enable_rps_framework = 1;
		rps_register(&direct_tcp_rps_entry);
		printk(KERN_INFO "Fastsocket: Enable Direct TCP\n");
	}
	if (enable_skb_pool)
		printk(KERN_INFO "Fastsocket: Enable Skb Pool[Mode-%d]\n", enable_skb_pool);
		
	if (enable_receive_cpu_selection) {
		enable_rps_framework = 1;
		rps_register(&rcs_rps_entry);
		printk(KERN_INFO "Fastsocket: Enable Receive CPU Selection\n");
	}

	if (enable_socket_pool_size) {		
		fsocket_pool_cachep = kmem_cache_create("fsocket_pool_cache", sizeof(struct fsocket_alloc), 0,
				SLAB_HWCACHE_ALIGN | SLAB_RECLAIM_ACCOUNT |
				SLAB_MEM_SPREAD | SLAB_PANIC, init_once);
		if (!fsocket_pool_cachep) {
			EPRINTK_LIMIT(ERR, "Allocate fsocket pool cachep failed\n");
			ret = -ENOMEM;
			goto err3;
		}
		
		ret = fsocket_init_sock_pool();
		if (ret) {
			EPRINTK_LIMIT(ERR, "Fail to init sock pool\n");
			goto err4;
		}
	
		printk(KERN_INFO "Fastsocket: Enable socket pool[Size-%d]\n", enable_socket_pool_size);
	}

	return 0;

err4:
	fsocket_fini_sock_pool();
err3:
	proc_net_remove(&init_net, "fsocket_stats");
err2:
	kmem_cache_destroy(fsocket_cachep);
err1:
	return ret;
}

void fsocket_exit(void)
{
	if (enable_receive_flow_deliver) {
		enable_receive_flow_deliver = 0;
		printk(KERN_INFO "Fastsocket: Disable Recieve Flow Deliver\n");
	}
	if (enable_direct_tcp) {
		enable_rps_framework = 0;
		rps_unregister(&direct_tcp_rps_entry);
		enable_direct_tcp = 0;
		printk(KERN_INFO "Fastsocket: Disable Direct TCP\n");
	}
	if (enable_skb_pool) {
		enable_skb_pool = 0;
		printk(KERN_INFO "Fastsocket: Disable Skb Pool\n");
	}
	if (enable_receive_cpu_selection) {
		enable_rps_framework = 0;
		rps_unregister(&rcs_rps_entry);
		enable_receive_cpu_selection = 0;
		printk(KERN_INFO "Fastsocket: Disable CPU Selection\n");
	}

	proc_net_remove(&init_net, "fsocket_stats");

	kmem_cache_destroy(fsocket_cachep);

	if (enable_socket_pool_size) {
		fsocket_fini_sock_pool();
	}

}

int fsocket_socket(int flags)
{
	struct socket *sock;
	int fd;

	int err = 0;

	if (flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK)) {
		EPRINTK_LIMIT(ERR, "Unsupported Socket Flags For Fastsocket\n");
		err = -EINVAL;
		goto out;
	}

	sock = fsocket_alloc_socket();
	if (sock == NULL) {
		EPRINTK_LIMIT(ERR, "Allocate New Socket failed\n");
		err = -ENOMEM;
		goto out;
	}

	sock->type = SOCK_STREAM;

	err = inet_create(current->nsproxy->net_ns, sock, 0, 0);
	if (err < 0) {
		EPRINTK_LIMIT(ERR, "Initialize Inet Socket failed\n");
		goto free_sock;
	}

	fsocket_init_socket(sock);

	fd = fsock_map_fd(sock, flags);
	if (fd < 0) {
		err = fd;
		EPRINTK_LIMIT(ERR, "Map Socket FD failed\n");
		goto release_sock;
	}

	err = security_socket_post_create(sock, PF_INET, SOCK_STREAM, IPPROTO_TCP, 0);
	if (err) {
		EPRINTK_LIMIT(ERR, "security_socket_post_create failed\n");
		fsocket_close(fd);
		return err;
	}

	return fd;

release_sock:
	fsock_release_sock(sock);
free_sock:
	fsocket_free_socket_mem((struct socket_alloc*)sock);
out:
	return err;
}

int fsocket_listen(struct file *file, int backlog)
{
	struct socket *sock, *lsock;
	struct file *sfile;
	int ret = 0;
	int old_backlog;

	sock = (struct socket *)file->private_data;
	if (sock) {
		ret = sock->ops->listen(sock, backlog);
		if (ret < 0)
			goto out;
	} else {
		ret = -EBADF;
		goto out;
	}

	sfile = file->sub_file;
	if (sfile) {
		old_backlog = sock->sk->sk_max_ack_backlog;
		lsock = (struct socket *)file->private_data;
		if (lsock) {
			ret = sock->ops->listen(lsock, backlog);
			if (ret < 0)
				goto restore_out;
		} else {
			ret = -EBADF;
			goto restore_out;
		}
	}

	goto out;

restore_out:
	sock->sk->sk_max_ack_backlog = old_backlog;
out:
	return ret;
}

int fsocket_spawn(struct file *filp, int fd, int tcpu)
{
	int ret = 0, backlog;
	int cpu;
	struct socket *sock, *newsock;
	struct sockaddr_in addr;
	kernel_cap_t p;

	DPRINTK(INFO, "Listen spawn listen fd %d on CPU %d\n", fd, tcpu);

	mutex_lock(&fastsocket_spawn_mutex);

	if (filp->sub_file) {
		EPRINTK_LIMIT(ERR, "Spawn on a already spawned file 0x%p\n", filp);
		ret = -EEXIST;
		goto out;
	}

	sock  = (struct socket *)filp->private_data;

	if (sock->sk->sk_state != TCP_LISTEN) {
		EPRINTK_LIMIT(ERR, "Spawn on a non-listen socket[%d-%d] file 0x%p\n", fd, sock->sk->sk_state, filp);
		ret = -EINVAL;
		goto out;
	}

	ret = fsocket_process_affinity_check(tcpu);
	if (ret < 0) {
		EPRINTK_LIMIT(ERR, "Set CPU affinity for process failed\n");
		goto out;
	}

	cpu = ret;
	newsock = NULL;
	ret = fsocket_spawn_clone(fd, sock, &newsock);
	if (ret < 0) {
		EPRINTK_LIMIT(ERR, "Clone listen socket failed[%d]\n", ret);
		goto restore;
	}

	fsocket_sk_affinity_set(newsock, cpu);

	fsocket_set_bind_cap(&p);

	addr.sin_family = AF_INET;
	addr.sin_port = inet_sk(sock->sk)->sport;
	addr.sin_addr.s_addr = inet_sk(sock->sk)->saddr;

	ret = newsock->ops->bind(newsock, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0)
	{
		EPRINTK_LIMIT(ERR, "Bind spawned socket %d failed[%d]\n", fd, ret);
		goto release;
	}

	fsocket_reset_bind_cap(&p);

	backlog = sock->sk->sk_max_ack_backlog;

	ret = newsock->ops->listen(newsock, backlog);
	if (ret < 0)
	{
		EPRINTK_LIMIT(ERR, "Listen spawned socket %d failed[%d]\n", fd, ret);
		goto release;
	}

	fsocket_process_affinity_set(cpu);

	goto out;

release:
	fsocket_sk_affinity_release(newsock);
	fsocket_filp_close_spawn(fd);
restore:
	fsocket_process_affinity_restore(cpu);
out:
	mutex_unlock(&fastsocket_spawn_mutex);

	DPRINTK(DEBUG, "fsocket_spawn return value is %d\n", ret);	

	return ret;
}


int fsocket_accept(struct file *file , struct sockaddr __user *upeer_sockaddr,
		int __user *upeer_addrlen, int flags)
{
	int err = 0, newfd, len;
	struct socket *sock, *newsock, *lsock;
	struct sockaddr_storage address;
	struct file *newfile;
	struct inet_connection_sock *icsk;

	//FIXME: Maybe unsafe for CLOEXEC flag
	if (flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK)) {
		EPRINTK_LIMIT(ERR, "Unsupported flags for file 0x%p\n", file);
		err = -EINVAL;
		goto out;
	}

	sock = (struct socket *)file->private_data;
	if (!sock) {
		EPRINTK_LIMIT(ERR, "No socket for file 0x%p\n", file);
		err = -EBADF;
		goto out;
	}

	DPRINTK(DEBUG, "Accept file 0x%p\n", file);

	if (!(newsock = fsocket_alloc_socket())) {
		EPRINTK_LIMIT(ERR, "Allocate empty socket failed\n");
		err = -ENOMEM;
		goto out;
	}

	newsock->type = SOCK_STREAM;
	newsock->ops = sock->ops;

	newfd = fsock_alloc_file(newsock, &newfile, O_NONBLOCK | flags);
	if (unlikely(newfd < 0)) {
		EPRINTK_LIMIT(ERR, "Allocate file for new socket failed\n");
		err = newfd;
		fsocket_free_socket_mem((struct socket_alloc*)newsock);
		goto out;
	}

	err = security_socket_accept(sock, newsock);
	if (err) {	
		EPRINTK_LIMIT(ERR, "security_socket_accept failed\n");
		goto out_fd;
	}

	if (!file->sub_file) {
		DPRINTK(DEBUG, "File 0x%p has no sub file, Do common accept\n", file);
		err = fsocket_common_accept(sock, newsock, O_NONBLOCK);
	} else {
		DPRINTK(DEBUG, "File 0x%p has sub file 0x%p, Do spawn accept\n", file, file->sub_file);
		icsk = inet_csk(sock->sk);
		lsock = (struct socket *)file->sub_file->private_data;
		if (!lsock) {
			EPRINTK_LIMIT(ERR, "No socket for sub file\n");
			err = -EBADF;
			goto out_fd;
		}

		if (unlikely(!reqsk_queue_empty(&icsk->icsk_accept_queue))) {
			DPRINTK(DEBUG, "Accept global listen socket 0x%p\n", sock);
			err = fsocket_global_accept(sock, newsock, O_NONBLOCK);
			if (err < 0) {
				DPRINTK(DEBUG, "Check local listen socket 0x%p again\n", lsock);
				err = fsocket_local_accept(lsock, newsock, O_NONBLOCK);
			}
		} else {
			DPRINTK(DEBUG, "Accept local listen socket 0x%p\n", lsock);
			err = fsocket_local_accept(lsock, newsock, O_NONBLOCK);
		}
	}

	if (err < 0) {
		if (err != -EAGAIN)
			EPRINTK_LIMIT(ERR, "Accept failed [%d]\n", err);
		goto out_fd;
	}

	/* Accepted socket flags are copied from listen socket */

	if (upeer_sockaddr) {
		if (newsock->ops->getname(newsock, (struct sockaddr *)&address, &len, 2) < 0) {
			EPRINTK_LIMIT(ERR, "Getname failed for accepted socket\n");
			err = -ECONNABORTED;
			goto out_fd;
		}

		err = move_addr_to_user((struct sockaddr *)&address, len, upeer_sockaddr, upeer_addrlen);
		if (err < 0)
			goto out_fd;
	}

	fd_install(newfd, newfile);
	err = newfd;

	DPRINTK(DEBUG, "Accept file 0x%p new fd %d\n", file, newfd);
	FSOCKET_INC_STATS(FSOCKET_STATS_SOCK_ACCEPT_CONNS);

	goto out;

out_fd:
	__fsocket_filp_close(newfile);
	put_unused_fd(newfd);
out:
	return err;
}

int fsocket_shutdown_listen(struct file *file, int how)
{
	struct socket *sock;
	int err;

	sock = file->private_data;
	if (sock->sk->sk_state == TCP_LISTEN) {
		struct file *sfile = file->sub_file;

		err = sock->ops->shutdown(sock, how);
		if (!err && sfile && sfile->private_data) {
			struct socket *ssock;

			ssock = sfile->private_data;
			err = ssock->ops->shutdown(ssock, how);
		}
	} else {
		err = sock->ops->shutdown(sock, how);
	}

	return err;
}

int fsocket_close(unsigned int fd)
{
	struct file *filp;
	struct files_struct *files = current->files;
	struct fdtable *fdt;
	int retval = 0;

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	if (fd >= fdt->max_fds)
		goto out_unlock;
	filp = fdt->fd[fd];
	if (!filp)
		goto out_unlock;
	rcu_assign_pointer(fdt->fd[fd], NULL);
	FD_CLR(fd, fdt->close_on_exec);
	__put_unused_fd(files, fd);
	spin_unlock(&files->file_lock);

	retval = fsocket_filp_close(filp);

	return retval;

out_unlock:
	spin_unlock(&files->file_lock);
	return -EBADF;
}

struct inode *fsocket_alloc_inode(struct super_block *sb)
{
	struct socket_alloc *ei;

	ei = fsocket_alloc_socket_mem();
	if (!ei)
		return NULL;

	if (security_inode_alloc(&ei->vfs_inode)) {
		fsocket_free_socket_mem(ei);
		return NULL;
	}

	init_waitqueue_head(&ei->socket.wait);

	ei->socket.fasync_list = NULL;
	ei->socket.state = SS_UNCONNECTED;
	ei->socket.flags = 0;
	ei->socket.ops = NULL;
	ei->socket.sk = NULL;
	ei->socket.file = NULL;

	DPRINTK(DEBUG, "Allocate inode 0x%p\n", &ei->vfs_inode);

	return &ei->vfs_inode;
}

void fsocket_destroy_inode(struct inode *inode)
{
	DPRINTK(DEBUG, "Free inode 0x%p\n", inode);

	if (S_ISSOCK(inode->i_mode)) {
		security_inode_free(inode);
	}
	fsock_release_sock(SOCKET_I(inode));
	fsocket_free_socket_mem((struct socket_alloc*)(SOCKET_I(inode)));
}


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
#include <linux/miscdevice.h>
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
#include <linux/syscalls.h>
#include <linux/cred.h>
#include <linux/fdtable.h>
#include <linux/mount.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/fsnotify.h>
#include <linux/netdevice.h>

#include "fastsocket.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Xiaofeng Lin <sina.com.cn>");
MODULE_VERSION("1.0.0");
MODULE_DESCRIPTION("Fastsocket which provides scalable and thus high kernel performance for socket applications");

int enable_fastsocket_debug = 3;
static int enable_listen_spawn = 2;
extern int enable_receive_flow_deliver;
static int enable_fast_epoll = 1;
extern int enable_skb_pool;
extern int enable_rps_framework;
int enable_receive_cpu_selection = 0;
int enable_direct_tcp = 0;

module_param(enable_fastsocket_debug,int, 0);
module_param(enable_listen_spawn, int, 0);
module_param(enable_receive_flow_deliver, int, 0);
module_param(enable_fast_epoll, int, 0);
module_param(enable_direct_tcp, int, 0);
module_param(enable_skb_pool, int, 0);
module_param(enable_receive_cpu_selection, int, 0);

MODULE_PARM_DESC(enable_fastsocket_debug, " Debug level [Default: 3]" );
MODULE_PARM_DESC(enable_listen_spawn, " Control Listen-Spawn: 0 = Disabled, 1 = Process affinity required, 2 = Autoset process affinity[Default]");
MODULE_PARM_DESC(enable_receive_flow_deliver, " Control Receive-Flow-Deliver: 0 = Disabled[Default], 1 = Enabled");
MODULE_PARM_DESC(enable_fast_epoll, " Control Fast-Epoll: 0 = Disabled, 1 = Enabled[Default]");
MODULE_PARM_DESC(enable_direct_tcp, " Control Direct-TCP: 0 = Disbale[Default], 1 = Enabled");
MODULE_PARM_DESC(enable_skb_pool, " Control Skb-Pool: 0 = Disbale[Default], 1 = Receive skb pool, 2 = Send skb pool,  3 = Both skb pool");
MODULE_PARM_DESC(enable_receive_cpu_selection, " Control RCS: 0 = Disabled[Default], 1 = Enabled");

#define DISABLE_LISTEN_SPAWN			0
#define ENABLE_LISTEN_SPAWN_REQUIRED_AFFINITY	1
#define ENABLE_LISTEN_SPAWN_AUTOSET_AFFINITY	2

static struct kmem_cache *socket_cachep;
extern struct kmem_cache *dentry_cache;

static struct vfsmount *sock_mnt;

static DEFINE_PER_CPU(int, fastsockets_in_use) = 0;
static DEFINE_PER_CPU(unsigned int, global_spawn_accept) = 0;

extern int inet_create(struct net *net, struct socket *sock, int protocol, int kern);

static inline int fsocket_filp_close(struct file *file);

static inline void fsock_release_sock(struct socket *sock)
{
	if (sock->ops) {
		DPRINTK(DEBUG, "Release inode socket 0x%p\n", SOCK_INODE(sock));
		sock->ops->release(sock);
		sock->ops = NULL;
	}
}

static inline void fsock_free_sock(struct socket *sock)
{
	kmem_cache_free(socket_cachep, sock);
	percpu_sub(fastsockets_in_use, 1);

	module_put(THIS_MODULE);
}

static void fastsock_destroy_inode(struct inode *inode)
{
	DPRINTK(DEBUG, "Free inode 0x%p\n", inode);

	security_inode_free(inode);
	fsock_release_sock(INODE_SOCKET(inode));
	fsock_free_sock(INODE_SOCKET(inode));
}

static struct inode *fastsock_alloc_inode(struct super_block *sb)
{
	struct fsocket_alloc *ei;

	ei = kmem_cache_alloc(socket_cachep, GFP_KERNEL);
	if (!ei)
		return NULL;

	if (security_inode_alloc(&ei->vfs_inode)) {
		kmem_cache_free(socket_cachep, ei);
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

static const struct super_operations fastsockfs_ops = {
	.alloc_inode = fastsock_alloc_inode,
	.destroy_inode = fastsock_destroy_inode,
	.statfs = simple_statfs,
};

static int fastsockfs_get_sb(struct file_system_type *fs_type,
			 int flags, const char *dev_name, void *data,
			 struct vfsmount *mnt)
{
	//FIXME: How about MAGIC Number
	return get_sb_pseudo(fs_type, "fastsocket:", &fastsockfs_ops, 0x534F434C,
			     mnt);
}

static struct file_system_type fastsock_fs_type = {
	.name = "fastsockfs",
	.get_sb = fastsockfs_get_sb,
	.kill_sb = kill_anon_super,
};

static inline unsigned int fast_sock_poll(struct file *file, poll_table *wait)
{
	struct socket *sock;

	sock = (struct socket *)file->private_data;
	if (sock && sock->ops && sock->ops->poll)
		return sock->ops->poll(file, sock, wait);

	return -EINVAL;
}

static inline int fast_sock_close(struct inode *i_node, struct file *file)
{
	return fsocket_filp_close(file);
}

loff_t fast_sock_llseek(struct file *file, loff_t offset, int origin)
{
	return -ESPIPE;
}

static int fast_sock_open(struct inode *irrelevant, struct file *dontcare)
{
	return -ENXIO;
}

extern ssize_t sock_aio_read(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos);

extern ssize_t sock_aio_write(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos);

static inline ssize_t fast_sock_read(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos)
{
	ssize_t ret;
	ret = sock_aio_read(iocb, iov, nr_segs, pos);
	DPRINTK(DEBUG, "Read %ld\n", ret);
	return ret;
}

static inline ssize_t fast_sock_write(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos)
{
	ssize_t ret;
	ret = sock_aio_write(iocb, iov, nr_segs, pos);
	DPRINTK(DEBUG, "Write %ld\n", ret);
	return ret;
}

static inline long fast_sock_ioctl(struct file *file, unsigned cmd, unsigned long arg)
{
	DPRINTK(INFO, "Do!\n");
	return -EINVAL;
}

#ifdef CONFIG_COMPAT
static inline long fast_compate_sock_ioctl(struct file *file, unsigned cmd, unsigned long arg)
{
	DPRINTK(INFO, "Do!\n");
	return -EINVAL;
}
#endif

static inline int fast_sock_mmap(struct file *file, struct vm_area_struct *vma)
{
	DPRINTK(INFO, "Do!\n");
	return -EINVAL;
}

static inline int fast_sock_fasync(int fd, struct file *filp, int on)
{
	DPRINTK(INFO, "Do!\n");
	return -EINVAL;
}

extern ssize_t sock_sendpage(struct file *file, struct page *page,
		int offset, size_t size, loff_t *ppos, int more);

static inline ssize_t fast_sock_sendpage(struct file *file, struct page *page,
		int offset, size_t size, loff_t *ppos, int more)
{
	ssize_t ret;
	ret = sock_sendpage(file, page, offset, size, ppos, more);
	DPRINTK(DEBUG, "Send page %ld\n", ret);
	return ret;
}

extern ssize_t generic_splice_sendpage(struct pipe_inode_info *pipe,
		struct file *out, loff_t *ppos, size_t len, unsigned int flags);
extern ssize_t sock_splice_read(struct file *file, loff_t *ppos,
		struct pipe_inode_info *pipe, size_t len, unsigned int flags);

static inline ssize_t fast_sock_splice_write(struct pipe_inode_info *pipe,
		struct file *out, loff_t *ppos, size_t len, unsigned int flags)
{
	ssize_t ret;
	ret = generic_splice_sendpage(pipe, out, ppos, len, flags);
	DPRINTK(DEBUG, "Splice wirte %ld\n", ret);
	return ret;
}

static inline ssize_t fast_sock_splice_read(struct file *file, loff_t *ppos,
		struct pipe_inode_info *pipe, size_t len, unsigned int flags)
{
	ssize_t ret;
	ret = sock_splice_read(file, ppos, pipe, len, flags);
	DPRINTK(DEBUG, "Splice read %ld\n", ret);
	return ret;
}

static const struct file_operations socket_file_ops = {
	.owner = 	THIS_MODULE,
	.llseek =	fast_sock_llseek,
	.aio_read = 	fast_sock_read,
	.aio_write =	fast_sock_write,
	.poll =		fast_sock_poll,
	.unlocked_ioctl = fast_sock_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = fast_compate_sock_ioctl,
#endif
	.mmap =		fast_sock_mmap,
	.open =		fast_sock_open,	/* special open code to disallow open via /proc */
	.release =	fast_sock_close,
	.fasync =	fast_sock_fasync,
	.sendpage =	fast_sock_sendpage,
	.splice_write = fast_sock_splice_write,
	.splice_read =	fast_sock_splice_read,
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

static int fsocket_close(unsigned int fd)
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

#define FSOCKET_INODE_START	( 1 << 12 )

static struct socket *fsocket_alloc_socket(void)
{
	static const struct inode_operations empty_iops;
	static const struct file_operations empty_fops;
	struct socket *sock;
	//FIXME: Just guess this inode number is not something really matters.
	static unsigned int last_ino = FSOCKET_INODE_START;
	struct inode *inode = NULL;	

	sock = (struct socket *)kmem_cache_alloc(socket_cachep, GFP_KERNEL);
	if (!sock) {
		DPRINTK(ERR, "Fail to allocate sock\n");
		goto err1;
	}
	
	if(!try_module_get(THIS_MODULE)) {
		goto err2;
	}
	
	if (security_inode_alloc(SOCK_INODE(sock))) {
		goto err3;
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
	inode->i_sb = sock_mnt->mnt_sb;
	atomic_set(&inode->i_count, 1);
	
	INIT_LIST_HEAD(&inode->i_list);
	INIT_LIST_HEAD(&inode->i_sb_list);
	
	inode->i_ino = ++last_ino;
	inode->i_state = 0;
	
	kmemcheck_annotate_bitfield(sock, type);
	inode->i_mode = S_IFSOCK | S_IRWXUGO;
	inode->i_uid = current_fsuid();
	inode->i_gid = current_fsgid();
	
	percpu_add(fastsockets_in_use, 1);
	
	DPRINTK(DEBUG, "Allocat inode 0x%p\n", inode);

	return sock;
	
err3:
	module_put(THIS_MODULE);
err2:
	kmem_cache_free(socket_cachep, sock);
err1:
	return NULL;
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

	path.mnt = sock_mnt;

	SOCK_INODE(sock)->i_fop = &socket_file_ops;

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
	file->f_op = &socket_file_ops;

	sock->file = file;

	file->f_flags = O_RDWR | (flags & O_NONBLOCK);
	file->f_pos = 0;
	file->private_data = sock;

	file->sub_file = NULL;
	file->f_epi = NULL;

	*f = file;

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
		fsock_free_sock(sock);
		goto out;
	}

	err = security_socket_post_create(sock, PF_INET, SOCK_STREAM, IPPROTO_TCP, 0);
	if (err) {
		EPRINTK_LIMIT(ERR, "security_socket_post_create failed\n");
		put_empty_filp(sfile);
		fsock_free_sock(sock);
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
		fsock_free_sock(sock);
		goto out;
	}

	path.mnt = sock_mnt;

	SOCK_INODE(sock)->i_fop = &socket_file_ops;

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

	path.mnt = sock_mnt;

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

static int fsocket_socket(int flags)
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
		goto release_sock;
	}

	return fd;

release_sock:
	fsock_release_sock(sock);
free_sock:
	fsock_free_sock(sock);
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

cpumask_t spawn_cpuset;
int spawn_cpu;
static DEFINE_MUTEX(spawn_mutex);

static void fsocket_process_affinity_set(int cpu)
{
	struct cpumask mask;

	cpumask_clear(&mask);
	cpumask_set_cpu(cpu, &mask);
	sched_setaffinity(current->pid, &mask);
}

static void fsocket_process_affinity_restore(int cpu)
{
	cpu_clear(cpu, spawn_cpuset);
	spawn_cpu--;
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

	for (cpu = spawn_cpu; cpu < num_active_cpus(); cpu++) {
		if (!cpu_isset(cpu, spawn_cpuset)) {
			DPRINTK(INFO, "CPU %d is available for process affinity\n", cpu);
			tcpu = cpu;
			break;
		}
	}

	if (tcpu >= 0) {
		cpu_set(cpu, spawn_cpuset);
		spawn_cpu++;
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

static int fsocket_spawn(struct file *filp, int fd, int tcpu)
{
	int ret = 0, backlog;
	int cpu;
	struct socket *sock, *newsock;
	struct sockaddr_in addr;
	kernel_cap_t p;

	DPRINTK(INFO, "Listen spawn listen fd %d on CPU %d\n", fd, tcpu);

	mutex_lock(&spawn_mutex);

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
	mutex_unlock(&spawn_mutex);

	return ret;
}

static int fastsocket_spawn_listen(struct fsocket_ioctl_arg *arg)
{
	struct file *tfile;
	int fd, tcpu, ret, fput_needed;

	DPRINTK(DEBUG, "Listen spawn listen fd %d\n", arg->fd);

	fd = arg->fd;
	tcpu = arg->op.spawn_op.cpu;

	tfile = fget_light(fd, &fput_needed);
	if (tfile == NULL) {
		EPRINTK_LIMIT(ERR, "fd [%d] doesn't exist!\n", fd);
		return -EINVAL;
	}

	if (tfile->f_mode & FMODE_FASTSOCKET)
		ret = fsocket_spawn(tfile, fd, tcpu);
	else {
		DPRINTK(INFO, "Spawn non fastsocket\n");
		return -EINVAL;
	}

	fput_light(tfile, fput_needed);

	return ret;
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

static int fsocket_accept(struct file *file , struct sockaddr __user *upeer_sockaddr,
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
		fsock_free_sock(newsock);
		goto out;
	}

	err = security_socket_accept(sock, newsock);
	if (err)
		goto out;

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

	goto out;

out_fd:
	__fsocket_filp_close(newfile);
	put_unused_fd(newfd);
out:
	return err;
}

int fastsocket_accept(struct fsocket_ioctl_arg *arg)
{
	int ret;
	struct file *tfile;
	int fput_need;

	tfile =	fget_light(arg->fd, &fput_need);
	if (tfile == NULL) {
		EPRINTK_LIMIT(ERR, "Accept file don't exist!\n");
		return -ENOENT;
	}

	if (tfile->f_mode & FMODE_FASTSOCKET) {
		DPRINTK(DEBUG, "Accept fastsocket %d\n", arg->fd);
		ret = fsocket_accept(tfile, arg->op.accept_op.sockaddr,
				arg->op.accept_op.sockaddr_len, arg->op.accept_op.flags);
	} else {
		DPRINTK(INFO, "Accept non-fastsocket %d\n", arg->fd);
		ret = sys_accept(arg->fd, arg->op.accept_op.sockaddr, arg->op.accept_op.sockaddr_len);
	}
	fput_light(tfile, fput_need);

	return ret;
}

static int fsocket_listen(struct file *file, int backlog)
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

static int fastsocket_listen(struct fsocket_ioctl_arg *arg)
{
	struct file *tfile;
	int fd, backlog, ret, fput_needed;

	fd = arg->fd;
	backlog = arg->backlog;

	tfile = fget_light(fd, &fput_needed);
	if (tfile == NULL) {
		EPRINTK_LIMIT(ERR, "fd [%d] file doesn't exist!\n", fd);
		return -EINVAL;
	}

	if (tfile->f_mode & FMODE_FASTSOCKET) {
		DPRINTK(DEBUG,"Listen fastsocket %d\n", fd);
		if (enable_fast_epoll) {
			/* For listen fastsocket, set single-wakeup and reset bind-epi */
			tfile->f_mode |= FMODE_SINGLE_WAKEUP;
			tfile->f_mode &= ~FMODE_BIND_EPI;
		}
		ret = fsocket_listen(tfile, backlog);
	} else {
		DPRINTK(INFO, "Listen non-fastsocket %d\n", fd);
		ret = sys_listen(fd, backlog);
	}

	fput_light(tfile, fput_needed);

	return ret;
}

static int fastsocket_socket(struct fsocket_ioctl_arg *arg)
{
	int family, type, protocol, fd;

	DPRINTK(DEBUG,"Try to create fastsocket\n");

	family = arg->op.socket_op.family;
	type = arg->op.socket_op.type;
	protocol = arg->op.socket_op.protocol;

	if (( family == AF_INET ) &&
		((type & SOCK_TYPE_MASK) == SOCK_STREAM )) {
		fd = fsocket_socket(type & ~SOCK_TYPE_MASK);
		DPRINTK(DEBUG,"Create fastsocket %d\n", fd);
		return fd;
	} else {
		fd = sys_socket(family, type, protocol);
		DPRINTK(INFO, "Create non fastsocket %d\n", fd);
		return fd;
	}
}

static int fastsocket_close(struct fsocket_ioctl_arg * arg)
{
	int error;
	struct file *tfile;
	int fput_need;

	DPRINTK(DEBUG,"Close fastsocket %d\n", arg->fd);

	tfile = fget_light(arg->fd, &fput_need);
	if (tfile == NULL) {
		EPRINTK_LIMIT(ERR, "Close file don't exist!\n");
		return -EINVAL;
	}

	if (tfile->f_mode & FMODE_FASTSOCKET) {
		fput_light(tfile, fput_need);
		error = fsocket_close(arg->fd);
	} else {
		fput_light(tfile, fput_need);
		DPRINTK(INFO, "Close non fastsocket %d\n", arg->fd);
		error = sys_close(arg->fd);
	}

	return error;
}

static int fsocket_shutdown_listen(struct file *file, int how)
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

static int fastsocket_shutdown_listen(struct fsocket_ioctl_arg *arg)
{
	int ret;
	struct file *tfile;
	int fput_need;

	tfile =	fget_light(arg->fd, &fput_need);
	if (tfile == NULL) {
		EPRINTK_LIMIT(ERR, "Accept file don't exist!\n");
		return -ENOENT;
	}

	if (tfile->f_mode & FMODE_FASTSOCKET) {
		DPRINTK(DEBUG, "Shutdown fastsocket %d\n", arg->fd);
		ret = fsocket_shutdown_listen(tfile, arg->op.shutdown_op.how);
	} else {
		DPRINTK(INFO, "Shutdown non-fastsocket %d\n", arg->fd);
		ret = sys_shutdown(arg->fd, arg->op.shutdown_op.how);
	}
	fput_light(tfile, fput_need);

	return ret;
}

#if 0
static int fastsocket_epoll_ctl(struct fsocket_ioctl_arg *u_arg)
{
	struct fsocket_ioctl_arg arg;
	struct file *efile, *tfile;
	struct eventpoll *ep;
	int e_fput_need, t_fput_need, ret;

	if (copy_from_user(&arg, u_arg, sizeof(arg))) {
		EPRINTK_LIMIT(ERR, "copy ioctl parameter from user space to kernel failed\n");
		return -EFAULT;
	}

	DPRINTK(DEBUG, "Epoll_ctl socket %d[%d]\n", arg.fd, arg.op.epoll_op.ep_ctl_cmd);

	/* Only use module epoll_ctl when listen spawn is enabled,
	 * fastepoll is taken care of by kernel source.
	 */
	if (!enable_listen_spawn) {
		DPRINTK(DEBUG, "Fastsocket epoll is disabled\n");
		ret = sys_epoll_ctl(arg.op.epoll_op.epoll_fd, arg.op.epoll_op.ep_ctl_cmd,
				arg.fd, arg.op.epoll_op.ev);
		return ret;
	}

	efile = fget_light(arg.op.epoll_op.epoll_fd, &e_fput_need);
	if (efile == NULL) {
		EPRINTK_LIMIT(ERR, "epoll file don't exist!\n");
		return -EINVAL;
	}

	ep = (struct eventpoll *)efile->private_data;

	tfile = fget_light(arg.fd, &t_fput_need);
	if (tfile == NULL) {
		fput_light(efile, e_fput_need);
		EPRINTK_LIMIT(ERR, "target file don't exist!\n");
		return -EINVAL;
	}

	if (tfile->f_mode & FMODE_FASTSOCKET) {
		ret = fsocket_epoll_ctl(ep, tfile, arg.fd, arg.op.epoll_op.ep_ctl_cmd,
				arg.op.epoll_op.ev);
	} else {
		DPRINTK(INFO, "Target socket %d is Not Fastsocket\n", arg.fd);
		ret = sys_epoll_ctl(arg.op.epoll_op.epoll_fd, arg.op.epoll_op.ep_ctl_cmd,
				arg.fd, arg.op.epoll_op.ev);
	}

	fput_light(tfile, t_fput_need);
	fput_light(efile, e_fput_need);

	return ret;
}
#endif

static long fastsocket_ioctl(struct file *filp, unsigned int cmd, unsigned long __user u_arg)
{
	struct fsocket_ioctl_arg k_arg;

	if (copy_from_user(&k_arg, (struct fsocket_ioctl_arg *)u_arg, sizeof(k_arg))) {
		EPRINTK_LIMIT(ERR, "copy ioctl parameter from user space to kernel failed\n");
		return -EFAULT;
	}

	switch (cmd) {
	case FSOCKET_IOC_SOCKET:
		return fastsocket_socket(&k_arg);
	case FSOCKET_IOC_LISTEN:
		return fastsocket_listen(&k_arg);
	case FSOCKET_IOC_SPAWN_LISTEN:
		return fastsocket_spawn_listen(&k_arg);
	case FSOCKET_IOC_ACCEPT:
		return fastsocket_accept(&k_arg);
	case FSOCKET_IOC_CLOSE:
		return fastsocket_close(&k_arg);
	case FSOCKET_IOC_SHUTDOWN_LISTEN:
		return fastsocket_shutdown_listen(&k_arg);
	//case FSOCKET_IOC_EPOLL_CTL:
	//	return fastsocket_epoll_ctl((struct fsocket_ioctl_arg *)arg);
	default:
		EPRINTK_LIMIT(ERR, "ioctl [%d] operation not support\n", cmd);
		break;
	}
	return -EINVAL;
}

static int fsocket_open(struct inode *inode, struct file *filp)
{
	if (!try_module_get(THIS_MODULE)) {
		EPRINTK_LIMIT(ERR, "Add reference to fastsocket module failed\n");
		return -EINVAL;
	}

	DPRINTK(INFO, "Hold module reference\n");

	cpus_clear(spawn_cpuset);
	spawn_cpu = 0;

	return 0;
}

static int fsocket_release(struct inode *inode, struct file *filp)
{
	module_put(THIS_MODULE);

	DPRINTK(INFO, "Release module reference\n");

	return 0;
}

static const struct file_operations fastsocket_fops = {
	.open = fsocket_open,
	.release = fsocket_release,
	.unlocked_ioctl = fastsocket_ioctl,
};

static struct miscdevice fastsocket_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "fastsocket",
	.fops = &fastsocket_fops ,
	.mode = S_IRUGO,
};

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

static int __init  fastsocket_init(void)
{
	int ret = 0;

	DPRINTK(INFO, "CPU number: online %d possible %d present %d active %d\n",
			num_online_cpus(), num_possible_cpus(),
			num_present_cpus(), num_active_cpus());

	ret = misc_register(&fastsocket_dev);

	if (ret < 0) {
		EPRINTK_LIMIT(ERR, "Register fastsocket channel device failed\n");
		goto err1;
	}

	socket_cachep = kmem_cache_create("fastsocket_socket_cache", sizeof(struct fsocket_alloc), 0,
			SLAB_HWCACHE_ALIGN | SLAB_RECLAIM_ACCOUNT |
			SLAB_MEM_SPREAD | SLAB_PANIC, init_once);
	if (!socket_cachep) {
		EPRINTK_LIMIT(ERR, "Allocate fastsocket cachep failed\n");
		ret = -ENOMEM;
		goto err2;
	}

	ret = register_filesystem(&fastsock_fs_type);
	if (ret) {
		EPRINTK_LIMIT(ERR, "Register fastsocket filesystem failed\n");
		goto err3;
	}

	sock_mnt = kern_mount(&fastsock_fs_type);
	DPRINTK(DEBUG, "Fastsocket super block 0x%p ops 0x%p\n", sock_mnt->mnt_sb, sock_mnt->mnt_sb->s_op);

	if (IS_ERR(sock_mnt)) {
		EPRINTK_LIMIT(ERR, "Mount fastsocket filesystem failed\n");
		ret = PTR_ERR(sock_mnt);
		goto err4;
	}

	printk(KERN_INFO "Fastsocket: Load Module\n");

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

	return ret;

err4:
	unregister_filesystem(&fastsock_fs_type);
err3:
	kmem_cache_destroy(socket_cachep);	
err2:
	misc_deregister(&fastsocket_dev);
err1:
	return ret;
}

static void __exit fastsocket_exit(void)
{
	misc_deregister(&fastsocket_dev);

	DPRINTK(DEBUG, "Fastsocket super block 0x%p ops 0x%p\n", sock_mnt->mnt_sb, sock_mnt->mnt_sb->s_op);
	mntput(sock_mnt);

	unregister_filesystem(&fastsock_fs_type);

	kmem_cache_destroy(socket_cachep);

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

	printk(KERN_INFO "Fastsocket: Remove Module\n");
}

module_init(fastsocket_init)
module_exit(fastsocket_exit)

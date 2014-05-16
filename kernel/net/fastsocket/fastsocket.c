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

#include "fastsocket.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Xiaofeng Lin <sina.com.cn>");
MODULE_VERSION("1.0.0");
MODULE_DESCRIPTION("Fastsocket which provides scalable and thus high kernel performance for socket application");

static int enable_fastsocket_debug = 3;

module_param(enable_fastsocket_debug,int, 0);

MODULE_PARM_DESC(enable_fastsocket_debug, " Debug level [Default: 3]" );

int inline fsocket_get_dbg_level(void)
{
	return enable_fastsocket_debug;
}

static struct kmem_cache *socket_cachep;
extern struct kmem_cache *dentry_cache;

static struct vfsmount *sock_mnt;

static DEFINE_PER_CPU(int, fastsockets_in_use) = 0;

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

	fsock_release_sock(INODE_SOCKET(inode));
	fsock_free_sock(INODE_SOCKET(inode));
}

static struct inode *fastsock_alloc_inode(struct super_block *sb)
{
	struct fsocket_alloc *ei;

	ei = kmem_cache_alloc(socket_cachep, GFP_KERNEL);
	if (!ei)
		return NULL;

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
	int retval;

	DPRINTK(DEBUG, "Close file 0x%p\n", file);

	retval = __fsocket_filp_close(file);

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
	struct socket *sock;
	struct inode *inode = NULL;

	//FIXME: Just guess this inode number is not something really matters.
	static unsigned int last_ino = FSOCKET_INODE_START;

	sock = (struct socket *)kmem_cache_alloc(socket_cachep, GFP_KERNEL);
	if (sock != NULL) {
		static const struct inode_operations empty_iops;
		static const struct file_operations empty_fops;

		if(!try_module_get(THIS_MODULE)) {
			kmem_cache_free(socket_cachep, sock);
			return NULL;
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
	}
	return sock;
}

#define DNAME_INLINE_LEN (sizeof(struct dentry)-offsetof(struct dentry,d_iname))

static void fsock_d_free(struct dentry *dentry)
{
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
		if (!dname)
			return NULL;
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
	file->f_op = &socket_file_ops;

	sock->file = file;

	file->f_flags = O_RDWR | (flags & O_NONBLOCK);
	file->f_pos = 0;
	file->private_data = sock;

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

static int fsocket_socket(int flags)
{
	struct socket *sock;

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

	err = fsock_map_fd(sock, flags);
	if (err < 0) {
		EPRINTK_LIMIT(ERR, "Map Socket FD failed\n");
		goto release_sock;
	}

	goto out;

release_sock:
	fsock_release_sock(sock);
free_sock:
	fsock_free_sock(sock);
out:
	return err;
}

static int fastsocket_spawn(struct fsocket_ioctl_arg *u_arg)
{
	return -ENOSYS;
}

static inline int fsocket_common_accept(struct socket *sock, struct socket *newsock, int flags)
{
	int ret;

	ret =  sock->ops->accept(sock, newsock, flags);
	return ret;
}

static int fsocket_spawn_accept(struct file *file , struct sockaddr __user *upeer_sockaddr,
		int __user *upeer_addrlen, int flags)
{
	int err = 0, newfd, len;
	struct socket *sock, *newsock;
	struct sockaddr_storage address;
	struct file *newfile;

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

	err = fsocket_common_accept(sock, newsock, O_NONBLOCK);

	if (err < 0) {
		if (err != -EAGAIN)
			EPRINTK_LIMIT(ERR, "Accept failed [%d]\n", err);
		goto out_fd;
	}

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

int fastsocket_accept(struct fsocket_ioctl_arg *u_arg)
{
	int ret;
	struct fsocket_ioctl_arg arg;
	struct file *tfile;
	int fput_need;

	if (copy_from_user(&arg, u_arg, sizeof(arg))) {
		EPRINTK_LIMIT(ERR, "copy ioctl parameter from user space to kernel failed\n");
		return -EFAULT;
	}

	tfile =	fget_light(arg.fd, &fput_need);
	if (tfile == NULL) {
		EPRINTK_LIMIT(ERR, "Accept file don't exist!\n");
		return -ENOENT;
	}

	if (tfile->f_mode & FMODE_FASTSOCKET) {
		DPRINTK(DEBUG, "Accept fastsocket %d\n", arg.fd);
		ret = fsocket_spawn_accept(tfile, arg.op.accept_op.sockaddr,
				arg.op.accept_op.sockaddr_len, arg.op.accept_op.flags);
	} else {
		DPRINTK(INFO, "Accept non-fastsocket %d\n", arg.fd);
		ret = sys_accept(arg.fd, arg.op.accept_op.sockaddr, arg.op.accept_op.sockaddr_len);
	}
	fput_light(tfile, fput_need);

	return ret;
}

static int fastsocket_listen(struct fsocket_ioctl_arg *u_arg)
{
	struct fsocket_ioctl_arg arg;
	struct file *tfile;
	int fd, backlog, ret, fput_needed;

	if (copy_from_user(&arg, u_arg, sizeof(arg))) {
		EPRINTK_LIMIT(ERR, "copy ioctl parameter from user space to kernel failed\n");
		return -EFAULT;
	}

	fd = arg.fd;
	backlog = arg.backlog;

	tfile = fget_light(fd, &fput_needed);
	if (tfile == NULL) {
		EPRINTK_LIMIT(ERR, "fd [%d] file doesn't exist!\n", fd);
		return -EINVAL;
	}

	ret = sys_listen(fd, backlog);

	fput_light(tfile, fput_needed);

	return ret;
}

static int fastsocket_socket(struct fsocket_ioctl_arg *u_arg)
{
	struct fsocket_ioctl_arg arg;
	int family, type, protocol, fd;

	DPRINTK(DEBUG,"Try to create fastsocket\n");

	if (copy_from_user(&arg, u_arg, sizeof(arg))) {
		EPRINTK_LIMIT(ERR, "copy ioctl parameter from user space to kernel failed\n");
		return -EFAULT;
	}

	family = arg.op.socket_op.family;
	type = arg.op.socket_op.type;
	protocol = arg.op.socket_op.protocol;

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

static int fastsocket_close(struct fsocket_ioctl_arg * u_arg)
{
	int error;
	struct file *tfile;
	struct fsocket_ioctl_arg arg;
	int fput_need;

	if (copy_from_user(&arg, u_arg, sizeof(arg))) {
		EPRINTK_LIMIT(ERR, "copy ioctl parameter from user space to kernel failed\n");
		return -EFAULT;
	}

	DPRINTK(DEBUG,"Close fastsocket %d\n", arg.fd);

	tfile = fget_light(arg.fd, &fput_need);
	if (tfile == NULL) {
		EPRINTK_LIMIT(ERR, "Close file don't exist!\n");
		return -EINVAL;
	}

	if (tfile->f_mode & FMODE_FASTSOCKET) {
		fput_light(tfile, fput_need);
		error = fsocket_close(arg.fd);
	} else {
		fput_light(tfile, fput_need);
		DPRINTK(INFO, "Close non fastsocket %d\n", arg.fd);
		error = sys_close(arg.fd);
	}

	return error;
}

static int fastsocket_epoll_ctl(struct fsocket_ioctl_arg *u_arg)
{
	struct fsocket_ioctl_arg arg;
	int ret;

	if (copy_from_user(&arg, u_arg, sizeof(arg))) {
		EPRINTK_LIMIT(ERR, "copy ioctl parameter from user space to kernel failed\n");
		return -EFAULT;
	}

	DPRINTK(DEBUG, "Epoll_ctl socket %d[%d]\n", arg.fd, arg.op.epoll_op.ep_ctl_cmd);

	ret = sys_epoll_ctl(arg.op.epoll_op.epoll_fd, arg.op.epoll_op.ep_ctl_cmd,
			    arg.fd, arg.op.epoll_op.ev);
	return ret;
}

static long fastsocket_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case FSOCKET_IOC_SOCKET:
		return fastsocket_socket((struct fsocket_ioctl_arg *) arg);
	case FSOCKET_IOC_LISTEN:
		return fastsocket_listen((struct fsocket_ioctl_arg *) arg);
	case FSOCKET_IOC_SPAWN:
		return fastsocket_spawn((struct fsocket_ioctl_arg *) arg);
	case FSOCKET_IOC_ACCEPT:
		return fastsocket_accept((struct fsocket_ioctl_arg *)arg);
	case FSOCKET_IOC_CLOSE:
		return fastsocket_close((struct fsocket_ioctl_arg *) arg);
	case FSOCKET_IOC_EPOLL_CTL:
		return fastsocket_epoll_ctl((struct fsocket_ioctl_arg *)arg);
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

static int __init  fastsocket_init(void)
{
	int ret = 0;

	DPRINTK(INFO, "CPU number: online %d possible %d present %d active %d\n",
			num_online_cpus(), num_possible_cpus(),
			num_present_cpus(), num_active_cpus());

	ret = misc_register(&fastsocket_dev);
	if (ret < 0) {
		EPRINTK_LIMIT(ERR, "Register fastsocket channel device failed\n");
		return -ENOMEM;
	}

	socket_cachep = kmem_cache_create("fastsocket_socket_cache", sizeof(struct fsocket_alloc), 0,
			SLAB_HWCACHE_ALIGN | SLAB_RECLAIM_ACCOUNT |
			SLAB_MEM_SPREAD | SLAB_PANIC, init_once);

	ret = register_filesystem(&fastsock_fs_type);
	if (ret) {
		misc_deregister(&fastsocket_dev);
		EPRINTK_LIMIT(ERR, "Register fastsocket filesystem failed\n");
		return ret;
	}

	sock_mnt = kern_mount(&fastsock_fs_type);
	DPRINTK(DEBUG, "Fastsocket super block 0x%p ops 0x%p\n", sock_mnt->mnt_sb, sock_mnt->mnt_sb->s_op);

	if (IS_ERR(sock_mnt)) {
		EPRINTK_LIMIT(ERR, "Mount fastsocket filesystem failed\n");
		ret = PTR_ERR(sock_mnt);
		misc_deregister(&fastsocket_dev);
		unregister_filesystem(&fastsock_fs_type);
		return ret;
	}

	printk(KERN_INFO "Fastsocket: Load Module\n");

	return ret;
}

static void __exit fastsocket_exit(void)
{
	misc_deregister(&fastsocket_dev);

	DPRINTK(DEBUG, "Fastsocket super block 0x%p ops 0x%p\n", sock_mnt->mnt_sb, sock_mnt->mnt_sb->s_op);
	mntput(sock_mnt);

	unregister_filesystem(&fastsock_fs_type);

	kmem_cache_destroy(socket_cachep);

	printk(KERN_INFO "Fastsocket: Remove Module\n");
}

module_init(fastsocket_init)
module_exit(fastsocket_exit)

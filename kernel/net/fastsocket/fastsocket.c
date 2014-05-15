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

static struct vfsmount *sock_mnt;

static DEFINE_PER_CPU(int, fastsockets_in_use) = 0;

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

static int fastsocket_spawn(struct fsocket_ioctl_arg *u_arg)
{
	return -ENOSYS;
}

int fastsocket_accept(struct fsocket_ioctl_arg *u_arg)
{
	return -ENOSYS;
}

static int fastsocket_listen(struct fsocket_ioctl_arg *u_arg)
{
	return -ENOSYS;
}

static int fastsocket_socket(struct fsocket_ioctl_arg *u_arg)
{
	return -ENOSYS;
}

static int fastsocket_close(struct fsocket_ioctl_arg * u_arg)
{
	return -ENOSYS;
}

static int fastsocket_epoll_ctl(struct fsocket_ioctl_arg *u_arg)
{
	return -ENOSYS;
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

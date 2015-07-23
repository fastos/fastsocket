#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <net/tcp_states.h>
#include <linux/miscdevice.h>
#include <linux/mount.h>

#include "fastsocket.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Xiaofeng Lin <sina.com.cn>");
MODULE_AUTHOR("Feng Gao <gfree.wind@gmail.com>");

MODULE_VERSION("1.0.0");
MODULE_DESCRIPTION("Fastsocket which provides scalable and thus high kernel performance for socket applications");

int enable_fastsocket_debug = 3;
/* Fastsocket feature switches */
int enable_listen_spawn = 2;
int enable_receive_flow_deliver;
int enable_fast_epoll = 1;
int enable_skb_pool;
int enable_rps_framework;
int enable_receive_cpu_selection = 0;
int enable_direct_tcp = 0;
int enable_socket_pool_size = 0;

module_param(enable_fastsocket_debug,int, 0);
module_param(enable_listen_spawn, int, 0);
module_param(enable_receive_flow_deliver, int, 0);
module_param(enable_fast_epoll, int, 0);
module_param(enable_direct_tcp, int, 0);
module_param(enable_skb_pool, int, 0);
module_param(enable_receive_cpu_selection, int, 0);
module_param(enable_socket_pool_size, int, 0);

MODULE_PARM_DESC(enable_fastsocket_debug, " Debug level [Default: 3]" );
MODULE_PARM_DESC(enable_listen_spawn, " Control Listen-Spawn: 0 = Disabled, 1 = Process affinity required, 2 = Autoset process affinity[Default]");
MODULE_PARM_DESC(enable_receive_flow_deliver, " Control Receive-Flow-Deliver: 0 = Disabled[Default], 1 = Enabled");
MODULE_PARM_DESC(enable_fast_epoll, " Control Fast-Epoll: 0 = Disabled, 1 = Enabled[Default]");
MODULE_PARM_DESC(enable_direct_tcp, " Control Direct-TCP: 0 = Disbale[Default], 1 = Enabled");
MODULE_PARM_DESC(enable_skb_pool, " Control Skb-Pool: 0 = Disbale[Default], 1 = Receive skb pool, 2 = Send skb pool,  3 = Both skb pool");
MODULE_PARM_DESC(enable_receive_cpu_selection, " Control RCS: 0 = Disabled[Default], 1 = Enabled");
MODULE_PARM_DESC(enable_socket_pool_size, "Control socket pool size: 0 = Disabled[Default], other are the pool size");

DEFINE_RATELIMIT_STATE(fastsocket_ratelimit_state, 5 * HZ, 10);

cpumask_t fastsocket_spawn_cpuset;
int fastsocket_spawn_cpu;
DEFINE_MUTEX(fastsocket_spawn_mutex);

struct vfsmount *fastsocket_mnt;

/**************************************************************************************************/
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

static int fastsocket_spawn_all_listen(void)
{
	struct files_struct *files = current->files;
	struct fdtable *fdt;
	struct file *file;
	unsigned int i;
	int ret = 0;

	DPRINTK(DEBUG, "Spawn all listen socket of pid(%u)\n", current->pid);

	rcu_read_lock();
	fdt = files_fdtable(files);

	for (i = 0; i < fdt->max_fds; ++i) {
		if (FD_ISSET(i, fdt->open_fds)) {
			file = rcu_dereference(fdt->fd[i]);
			if (file && file->f_mode & FMODE_FASTSOCKET) {
				struct socket * sock = file->private_data;

				DPRINTK(DEBUG, "fd(%d) is fastsocket fd, sock state(%d) subfile(%p)\n", 
					i, sock->sk->sk_state, file->sub_file);

				if (sock->sk->sk_state == TCP_LISTEN) {
					if (file->sub_file) {
						// The parent process has already spawn, we need to free the old one.
						fscoket_spawn_restore(sock, i);
						// Need to get the file again;
						file = rcu_dereference(fdt->fd[i]);
					}
					ret += fsocket_spawn(file, i, -1);
				}
			}

			rcu_read_unlock();
		}
	}
	rcu_read_unlock();

	return ret;
}

static int fastsocket_accept(struct fsocket_ioctl_arg *arg)
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
	case FSOCKET_IOC_SPAWN_ALL_LISTEN:
		EPRINTK_LIMIT(DEBUG, "ioctl [%d] receive spawn all listen socket", cmd);
		return fastsocket_spawn_all_listen();
	default:
		EPRINTK_LIMIT(ERR, "ioctl [%d] operation not support\n", cmd);
		break;
	}
	return -EINVAL;
}

static const struct super_operations fastsockfs_ops = {
	.alloc_inode = fsocket_alloc_inode,
	.destroy_inode = fsocket_destroy_inode,
	.statfs = simple_statfs,
};

static int fastsocket_open(struct inode *inode, struct file *filp)
{
	if (!try_module_get(THIS_MODULE)) {
		EPRINTK_LIMIT(ERR, "Add reference to fastsocket module failed\n");
		return -EINVAL;
	}

	DPRINTK(INFO, "Hold module reference\n");

	cpus_clear(fastsocket_spawn_cpuset);
	fastsocket_spawn_cpu = 0;

	return 0;
}

static int fastsocket_release(struct inode *inode, struct file *filp)
{
	DPRINTK(DEBUG, "Enter fsocket_release. inode(%p) file(%p) dentry(%p)", 
		inode, filp, filp->f_path.dentry);

	if (filp->f_path.dentry->d_flags & DCACHE_FASTSOCKET) {
		DPRINTK(INFO, "dentry memleak happens!!!\n");
	}

	module_put(THIS_MODULE);

	DPRINTK(INFO, "Release module reference\n");

	return 0;
}


static const struct file_operations fastsocket_fops = {
	.open = fastsocket_open,
	.release = fastsocket_release,
	.unlocked_ioctl = fastsocket_ioctl,
};

static struct miscdevice fastsocket_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "fastsocket",
	.fops = &fastsocket_fops ,
	.mode = S_IRUGO,
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


static int __init  fastsocket_init(void)
{
	int ret = 0;
	
	printk(KERN_INFO "Fastsocket: Load Module\n");

	DPRINTK(INFO, "CPU number: online %d possible %d present %d active %d\n",
			num_online_cpus(), num_possible_cpus(),
			num_present_cpus(), num_active_cpus());

	ret = misc_register(&fastsocket_dev);
	if (ret < 0) {
		EPRINTK_LIMIT(ERR, "Register fastsocket channel device failed\n");
		goto err1;
	}

	ret = fsocket_init();
	if (ret) {
		EPRINTK_LIMIT(ERR, "fsocket_init failed\n");
		goto err2;
	}
	
	ret = register_filesystem(&fastsock_fs_type);
	if (ret) {
		EPRINTK_LIMIT(ERR, "Register fastsocket filesystem failed\n");
		goto err3;
	}

	fastsocket_mnt = kern_mount(&fastsock_fs_type);
	DPRINTK(DEBUG, "Fastsocket super block 0x%p ops 0x%p\n", fastsocket_mnt->mnt_sb, fastsocket_mnt->mnt_sb->s_op);

	if (IS_ERR(fastsocket_mnt)) {
		EPRINTK_LIMIT(ERR, "Mount fastsocket filesystem failed\n");
		ret = PTR_ERR(fastsocket_mnt);
		goto err4;
	}
	
	return ret;

err4:
	unregister_filesystem(&fastsock_fs_type);
err3:
	fsocket_exit();
err2:
	misc_deregister(&fastsocket_dev);
err1:
	return ret;
}

static void __exit fastsocket_exit(void)
{	
	misc_deregister(&fastsocket_dev);

	DPRINTK(DEBUG, "Fastsocket super block 0x%p ops 0x%p\n", fastsocket_mnt->mnt_sb, fastsocket_mnt->mnt_sb->s_op);
	mntput(fastsocket_mnt);

	unregister_filesystem(&fastsock_fs_type);

	fsocket_exit();
	
	printk(KERN_INFO "Fastsocket: Remove Module\n");
}

module_init(fastsocket_init)
module_exit(fastsocket_exit)


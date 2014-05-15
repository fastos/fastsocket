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

	return ret;
}

static void __exit fastsocket_exit(void)
{
	misc_deregister(&fastsocket_dev);

	printk(KERN_INFO "Fastsocket: Remove Module\n");
}

module_init(fastsocket_init)
module_exit(fastsocket_exit)

/*
 * net/fastsocket/fastsocket.h
 *
 * Copyright (C) SINA Corporation
 */

#ifndef _LINUX_FASTSOCKET_H
#define _LINUX_FASTSOCKET_H

#include <linux/ratelimit.h>
#include <linux/fs.h>
#include <linux/net.h>
#include <linux/ioctl.h>
#include <net/sock.h>

#define IOC_ID 0xf5

#define FSOCKET_IOC_SOCKET _IO(IOC_ID, 0x01)
#define FSOCKET_IOC_LISTEN _IO(IOC_ID, 0x02)
#define FSOCKET_IOC_ACCEPT _IO(IOC_ID, 0x03)
#define FSOCKET_IOC_CLOSE _IO(IOC_ID, 0x04)
//#define FSOCKET_IOC_EPOLL_CTL _IO(IOC_ID, 0x05)
#define FSOCKET_IOC_SPAWN_LISTEN _IO(IOC_ID, 0x06)
#define FSOCKET_IOC_SHUTDOWN_LISTEN _IO(IOC_ID, 0x07)
#define FSOCKET_IOC_SPAWN_ALL_LISTEN _IO(IOC_ID, 0x08)

#define ALERT 0x00
#define ERR 0x01
#define WARNING 0x02
#define INFO 0x03
#define DEBUG 0x04

static int inline fastsocket_dbg_level(void)
{
	//Declare the global variable inside this function to hide this varaible
	extern int enable_fastsocket_debug;
	
	return enable_fastsocket_debug;
}


static inline int fastsocket_limit(void)
{
	//Declare the global variable inside this function to hide this varaible
	extern struct ratelimit_state fastsocket_ratelimit_state;
	
	return __ratelimit(&fastsocket_ratelimit_state);
}


#ifndef DPRINTK
#define DPRINTK(level, msg, args...) ({\
	if (level < fastsocket_dbg_level()) \
		printk(KERN_DEBUG "Fastsocket [CPU%d][PID-%d][%s] %s:%d\t" msg, smp_processor_id(), current->pid, current->comm, __FUNCTION__, __LINE__, ## args); \
	})
#endif

#define EPRINTK_LIMIT(level, msg, args...) ({\
	if (fastsocket_limit() && level < fastsocket_dbg_level()) \
		printk(KERN_DEBUG "Fastsocket [CPU%d][PID-%d][%s] %s:%d\t" msg, smp_processor_id(), current->pid, current->comm, __FUNCTION__, __LINE__, ## args); \
	})


struct fsocket_ioctl_arg {
	u32 fd;
	u32 backlog;
	union ops_arg {
		struct socket_accept_op_t {
			void *sockaddr;
			int *sockaddr_len;
			int flags;
		}accept_op;

		struct spawn_op_t {
			int cpu;
		}spawn_op;

		struct io_op_t {
			char *buf;
			u32 buf_len;
		}io_op;

		struct socket_op_t {
			u32 family;
			u32 type;
			u32 protocol;
		}socket_op;

		struct shutdown_op_t {
			int how;
		}shutdown_op;

		struct epoll_op_t {
			u32 epoll_fd;
			u32 size;
			u32 ep_ctl_cmd;
			u32 time_out;
			struct epoll_event *ev;
		}epoll_op;
	}op;
};

/*
Fastsocket global variable
*/
extern struct vfsmount *fastsocket_mnt;
/* Fastsocket feature switches */
extern int enable_listen_spawn;
extern int enable_receive_flow_deliver;
extern int enable_fast_epoll;
extern int enable_skb_pool;
extern int enable_rps_framework;
extern int enable_receive_cpu_selection;
extern int enable_direct_tcp;
extern int enable_socket_pool_size;

/* Fastsocket spawn cpu */
extern cpumask_t fastsocket_spawn_cpuset;
extern int fastsocket_spawn_cpu;
extern struct mutex fastsocket_spawn_mutex;

/*
Fastsocket core functions
*/
extern int fsocket_init(void);
extern void fsocket_exit(void);

extern int fsocket_socket(int flags);
extern int fsocket_listen(struct file *file, int backlog);
extern int fsocket_spawn(struct file *filp, int fd, int tcpu);
extern void fscoket_spawn_restore(struct socket *sock, int fd);
extern int fsocket_accept(struct file *file , struct sockaddr __user *upeer_sockaddr,
		int __user *upeer_addrlen, int flags);
extern int fsocket_shutdown_listen(struct file *file, int how);
extern int fsocket_close(unsigned int fd);

extern struct inode *fsocket_alloc_inode(struct super_block *sb);
extern void fsocket_destroy_inode(struct inode *inode);

#endif

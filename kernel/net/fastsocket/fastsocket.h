/*
 * net/fastsocket/fastsocket.h
 *
 * Copyright (C) SINA Corporation
 */

#ifndef _LINUX_FASTSOCKET_H
#define _LINUX_FASTSOCKET_H

#include <linux/ioctl.h>

#define IOC_ID 0xf5

#define FSOCKET_IOC_SOCKET _IO(IOC_ID, 0x01)
#define FSOCKET_IOC_LISTEN _IO(IOC_ID, 0x02)
#define FSOCKET_IOC_ACCEPT _IO(IOC_ID, 0x03)
#define FSOCKET_IOC_CLOSE _IO(IOC_ID, 0x04)
//#define FSOCKET_IOC_EPOLL_CTL _IO(IOC_ID, 0x05)
#define FSOCKET_IOC_SPAWN_LISTEN _IO(IOC_ID, 0x06)
#define FSOCKET_IOC_SHUTDOWN_LISTEN _IO(IOC_ID, 0x07)

#define ALERT 0x00
#define ERR 0x01
#define WARNING 0x02
#define INFO 0x03
#define DEBUG 0x04

static int inline fsocket_get_dbg_level(void)
{
	//Declare the global variable inside this function to hide this varaible
	extern int enable_fastsocket_debug;
	
	return enable_fastsocket_debug;
}

DEFINE_RATELIMIT_STATE(fastsocket_ratelimit_state, 5 * HZ, 10);

static inline int fastsocket_limit(void)
{
	return __ratelimit(&fastsocket_ratelimit_state);
}


#ifndef DPRINTK
#define DPRINTK(level, msg, args...) ({\
	if (level < fsocket_get_dbg_level()) \
		printk(KERN_DEBUG "Fastsocket [CPU%d][PID-%d] %s:%d\t" msg, smp_processor_id(), current->pid, __FUNCTION__, __LINE__, ## args); \
	})
#endif

#define EPRINTK_LIMIT(level, msg, args...) ({\
	if (fastsocket_limit() && level < fsocket_get_dbg_level()) \
		printk(KERN_DEBUG "Fastsocket [CPU%d][PID-%d] %s:%d\t" msg, smp_processor_id(), current->pid, __FUNCTION__, __LINE__, ## args); \
	})

struct fsocket_alloc {
	struct socket socket;
	struct inode vfs_inode;
};

static inline struct inode *SOCKET_INODE(struct socket *socket)
{
	return &container_of(socket, struct fsocket_alloc, socket)->vfs_inode;
}

static inline struct socket *INODE_SOCKET(struct inode *inode)
{
	return &container_of(inode, struct socket_alloc, vfs_inode)->socket;
}

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

#endif

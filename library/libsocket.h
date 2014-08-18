/*
 * libsocket.h
 *
 * Copyright (C) SINA Corporation
 */

#ifndef _LINUX_FASTSOCKET_LIB_H
#define _LINUX_FASTSOCKET_LIB_H

#include <linux/ioctl.h>

typedef unsigned int u32;

#define IOC_ID 0xf5

#define FSOCKET_IOC_SOCKET _IO(IOC_ID, 0x01)
#define FSOCKET_IOC_LISTEN _IO(IOC_ID, 0x02)
#define FSOCKET_IOC_ACCEPT _IO(IOC_ID, 0x03)
#define FSOCKET_IOC_CLOSE _IO(IOC_ID, 0x04)
//#define FSOCKET_IOC_EPOLL_CTL _IO(IOC_ID, 0x05)
#define FSOCKET_IOC_SPAWN_LISTEN _IO(IOC_ID, 0x06)
#define FSOCKET_IOC_SHUTDOWN_LISTEN _IO(IOC_ID, 0x07)

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

/*
 * libsocket.c
 *
 * Copyright (C) SINA Corporation
 */

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <linux/eventpoll.h>
//#include <fcntl.h>

#define __USE_GNU
#include <sched.h>
#include <dlfcn.h>

#include "libsocket.h"

static int fsocket_channel_fd = -1;

#define FSOCKET_ERR(msg, ...)
//#define FSOCKET_ERR(msg, ...) \
//do {\
//	fprintf(stderr, "Fastsocket Library:" msg, ##__VA_ARGS__);\
//}while(0)

#define INIT_FDSET_NUM	65536

/* fsocket_fd_set is useed to check listen fd to spawn listen
 * socket "automatically" without changing applications' code.
 * This automation is definitely not accurate. However, it's
 * serving Haproxy and Nginx fine in the test environment and
 * the production enviroment */

//TODO: To support multi-thread programme

static int *fsocket_fd_set;
static int fsocket_fd_num;

inline int get_cpus()
{
        return sysconf(_SC_NPROCESSORS_ONLN);
}

__attribute__((constructor))
void fastsocket_init(void)
{
	int ret = 0;
	int i;
	cpu_set_t cmask;

	ret = open("/dev/fastsocket", O_RDONLY);
	if (ret < 0) {
		FSOCKET_ERR("Open fastsocket channel failed, please CHECK\n");
		/* Just exit for safty*/
		exit(-1);
	}
	fsocket_channel_fd = ret;

	fsocket_fd_set = calloc(INIT_FDSET_NUM, sizeof(int));
	if (!fsocket_fd_set) {
		FSOCKET_ERR("Allocate memory for listen fd set failed\n");
		exit(-1);
	}

	fsocket_fd_num = INIT_FDSET_NUM;

        CPU_ZERO(&cmask);

	for (i = 0; i < get_cpus(); i++)
		CPU_SET(i, &cmask);

        ret = sched_setaffinity(0, get_cpus(), &cmask);
	if (ret < 0) {
		FSOCKET_ERR("Clear process CPU affinity failed\n");
		exit(-1);
	}

	return;
}

__attribute__((destructor))
void fastsocket_uninit(void)
{
	close(fsocket_channel_fd);
	free(fsocket_fd_set);

	return;
}

int fastsocket_expand_fdset(int fd)
{
	int *old_fd_set = fsocket_fd_set;
	int ret = fd;
	struct fsocket_ioctl_arg arg;

	if (fd >= fsocket_fd_num) {
		fsocket_fd_set = calloc(fsocket_fd_num + INIT_FDSET_NUM, sizeof(int));
		if (!fsocket_fd_set) {
			FSOCKET_ERR("Re allocate memory for listen fd set failed\n");
			arg.fd = fd;
			ioctl(fsocket_channel_fd, FSOCKET_IOC_CLOSE, &arg);
			//FIXME: Is it a appropriate errno here?
			errno = EMFILE;
			ret = -1;
		} else {
			memcpy(fsocket_fd_set, old_fd_set, fsocket_fd_num * sizeof(int));
			free(old_fd_set);
			fsocket_fd_num += INIT_FDSET_NUM;
		}
	}
	return ret;
}

int socket(int family, int type, int protocol)
{
	static int (*real_socket)(int, int, int) = NULL;
	int fd = -1;
	struct fsocket_ioctl_arg arg;

	if (fsocket_channel_fd >= 0) {
		arg.op.socket_op.family = family;
		arg.op.socket_op.type = type;
		arg.op.socket_op.protocol = protocol;

		fd = ioctl(fsocket_channel_fd, FSOCKET_IOC_SOCKET, &arg);
		if (fd < 0)
			FSOCKET_ERR("FSOCKET:create light socket failed!\n");
		else
			fd = fastsocket_expand_fdset(fd);
	} else {
		if (!real_socket)
			real_socket = dlsym(RTLD_NEXT, "socket");

		fd =  real_socket(family, type, protocol);
	}

	return fd;
}

int listen(int fd, int backlog)
{
	static int (*real_listen)(int, int) = NULL;
	int ret = 0;
	struct fsocket_ioctl_arg arg;

	if (!real_listen)
		real_listen = dlsym(RTLD_NEXT, "listen");

	if (fsocket_channel_fd >= 0) {
		arg.fd = fd;
		arg.backlog = backlog;

		if (!fsocket_fd_set[fd])
			fsocket_fd_set[fd] = 1;

		ret = ioctl(fsocket_channel_fd, FSOCKET_IOC_LISTEN, &arg);
		if (ret < 0) {
			FSOCKET_ERR("FSOCKET:Listen failed!\n");
			fsocket_fd_set[fd] = 0;
		}

	} else {
		ret =  real_listen(fd, backlog);
	}

	return ret;
}

int accept(int fd, struct sockaddr *addr, socklen_t *addr_len)
{
	static int (*real_accept)(int, struct sockaddr *, socklen_t *) = NULL;
	int ret = 0;
	struct fsocket_ioctl_arg arg;

	if (fsocket_channel_fd >= 0) {
		arg.fd = fd;
		arg.op.accept_op.sockaddr = addr;
		arg.op.accept_op.sockaddr_len = addr_len;
		arg.op.accept_op.flags = 0;

		ret = ioctl(fsocket_channel_fd, FSOCKET_IOC_ACCEPT, &arg);
		if (ret < 0) {
			if (errno != EAGAIN)
				FSOCKET_ERR("FSOCKET:Accept failed!\n");
		} else {
			ret = fastsocket_expand_fdset(ret);
		}
	} else {
		if (!real_accept)
			real_accept = dlsym(RTLD_NEXT, "accept");
		ret = real_accept(fd, addr, addr_len);
	}

	return ret;
}

int accept4(int fd, struct sockaddr *addr, socklen_t *addr_len, int flags)
{
	static int (*real_accept)(int, struct sockaddr *, socklen_t *) = NULL;
	int ret = 0;
	struct fsocket_ioctl_arg arg;

	if (fsocket_channel_fd >= 0) {
		arg.fd = fd;
		arg.op.accept_op.sockaddr = addr;
		arg.op.accept_op.sockaddr_len = addr_len;
		arg.op.accept_op.flags = flags;

		ret = ioctl(fsocket_channel_fd, FSOCKET_IOC_ACCEPT, &arg);
		if (ret < 0) {
			if(errno != EAGAIN)
				FSOCKET_ERR("FSOCKET:Accept failed!\n");
		} else {
			ret = fastsocket_expand_fdset(ret);
		}
	} else {
		if (!real_accept)
			real_accept = dlsym(RTLD_NEXT, "accept4");
		ret = real_accept(fd, addr, addr_len);
	}

	return ret;
}

int close(int fd)
{
	static int (*real_close)(int) = NULL;
	int ret;
	struct fsocket_ioctl_arg arg;

	if (fsocket_channel_fd >= 0) {
		arg.fd = fd;

		if (fsocket_fd_set[fd])
			fsocket_fd_set[fd] = 0;

		ret = ioctl(fsocket_channel_fd, FSOCKET_IOC_CLOSE, &arg);
		if (ret < 0) {
			FSOCKET_ERR("FSOCKET:Close failed!\n");
		}
	} else {
		if (!real_close)
			real_close = dlsym(RTLD_NEXT, "close");
		ret = real_close(fd);
	}

	return ret;
}

int shutdown(int fd, int how)
{
	static int (*real_shutdown)(int, int) = NULL;
	int ret;
	struct fsocket_ioctl_arg arg;

	if ((fsocket_channel_fd >= 0) && fsocket_fd_set[fd]) {
		arg.fd = fd;
		arg.op.shutdown_op.how = how;

		ret = ioctl(fsocket_channel_fd, FSOCKET_IOC_SHUTDOWN_LISTEN, &arg);
		if (ret < 0) {
			FSOCKET_ERR("FSOCKET:Close failed!\n");
		}
	} else {
		if (!real_shutdown)
			real_shutdown = dlsym(RTLD_NEXT, "shutdown");
		ret = real_shutdown(fd, how);
	}

	return ret;
}


int epoll_ctl(int efd, int cmd, int fd, struct epoll_event *ev)
{
	static int (*real_epoll_ctl)(int, int, int, struct epoll_event *) = NULL;
	int ret;
	struct fsocket_ioctl_arg arg;

	if (fsocket_channel_fd >= 0) {
		arg.fd = fd;
		arg.op.spawn_op.cpu = -1;

		/* "Automatically" do the spawn */
		if (fsocket_fd_set[fd] && cmd == EPOLL_CTL_ADD) {
			ret = ioctl(fsocket_channel_fd, FSOCKET_IOC_SPAWN_LISTEN, &arg);
			if (ret < 0) {
				FSOCKET_ERR("FSOCKET: spawn failed!\n");
			}
		}

		arg.op.epoll_op.epoll_fd = efd;
		arg.op.epoll_op.ep_ctl_cmd = cmd;
		arg.op.epoll_op.ev = ev;

		ret = ioctl(fsocket_channel_fd, FSOCKET_IOC_EPOLL_CTL, &arg);
		if (ret < 0) {
			FSOCKET_ERR("FSOCKET: epoll_ctl failed!\n");
			return ret;
		}
	} else {
		if (!real_epoll_ctl)
			real_epoll_ctl = dlsym(RTLD_NEXT, "epoll_ctl");
		ret = real_epoll_ctl(efd, cmd, fd, ev);
	}

	return ret;
}

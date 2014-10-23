/*
 * server.h
 *
 * Copyright (C) SINA Corporation
 *
 */

#ifndef SERVER_H
#define SERVER_H

#define MAX_CONNS_PER_WORKER    8192
#define MAX_BUFSIZE        2048

#define EVENTS_PER_BATCH	64
#define ACCEPT_PER_LISTEN_EVENT	1

#define MAX_LISTEN_ADDRESS	32
#define MAX_PROXY_ADDRESS	32

struct worker_data {
	pid_t process;
	uint64_t trancnt;
	uint64_t trancnt_prev;
	int cpu_id;
	uint64_t polls_max;
	uint64_t polls_min;
	uint64_t polls_avg;
	uint64_t polls_cnt;
	uint64_t polls_sum;
	uint64_t polls_mpt;
	uint64_t polls_lst;
	uint64_t accept_cnt;
	uint64_t read_cnt;
	uint64_t write_cnt;
};

#define PROXY_BACKEND_EVENT	0x01

struct context_pool {
	int total;
	int allocated;
	int next_idx;
	struct conn_context {
		int fd;
		int fd_added;
		int end_fd;
		int end_fd_added;
		int flags;
		int ep_fd;
		int cpu_id;
		void (*handler)(struct conn_context *);
		int events;
		int data_len;
		struct context_pool *pool;
		int next_idx;
		char buf[MAX_BUFSIZE];
	} *arr;
};

struct listen_addr {
	int param_port;
	struct in_addr listenip;
	char param_ip[32];
	int listen_fd;
};

struct proxy_addr {
	int param_port;
	struct in_addr proxyip;
	char param_ip[32];
};

void init_log(void);
void init_server(void);
void init_signal(void);
void init_timer(void);
void init_workers(void);
void init_threads(void);
void init_processes(void);
void *process_clients(void *arg);
void do_stats(void);
void exit_cleanup(void);
void stop_threads(void);
void stop_workers(void);

#endif


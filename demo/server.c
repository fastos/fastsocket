/*
 * Simple HTTP server that can be used in web server mode
 * and proxy server mode.
 * It is used to test short TCP connection performance.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sched.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "server.h"

struct worker_data *wdata;

int num_workers;
int start_cpu = 0;
int enable_verbose = 0;
int enable_proxy = 0;
int enable_keepalive = 0;

int process_mode = 0;

struct listen_addr la[MAX_LISTEN_ADDRESS];
struct proxy_addr pa[MAX_PROXY_ADDRESS];
int la_num;
int pa_num;

static void process_read(struct conn_context *ctx);
static void process_write(struct conn_context *ctx);
static void process_read_backend(struct conn_context *ctx);
static void process_write_backend(struct conn_context *ctx);
static void process_read_frontend(struct conn_context *ctx);
static void process_write_frontend(struct conn_context *ctx);

int get_cpu_num()
{
	return sysconf(_SC_NPROCESSORS_ONLN);
}

int bind_process_cpu(int cpu)
{
	cpu_set_t cmask;
	size_t n;
	int ret;

	n = get_cpu_num();

	if (cpu < 0 || cpu >= (int)n) {
		errno = EINVAL;
		return -1;
	}

	CPU_ZERO(&cmask);
	CPU_SET(cpu, &cmask);

	ret = sched_setaffinity(0, n, &cmask);

	CPU_ZERO(&cmask);

	return ret;
}

int main(int argc, char *argv[])
{

	printf("Usage: %s [-k] [-d] [-c] [start_cpu] [-w] [worker_num] [-a] [ip:port ...] [-x] [ip:port ...]\n",
	       argv[0]);
	printf("   -c: specify the first cpu to bind each worker\n	   [default is 0]\n");
	printf("   -w: specify worker number\n	   [default is the available cpu core number]\n");
	printf("   -a: specify frontend listen address\n	   [default is 0.0.0.0:80]\n");
	printf("   -x: enable proxy mode and specify backend listen address\n	   [default is off]\n");
	printf("   -k: enable HTTP keepalive\n	   [default is off]\n");
	printf("   -v: enable verbose mode\n	   [default is off]\n");
	printf("\n");

again:

	if (argc >= 2 && strcmp(argv[1], "-v") == 0) {
		enable_verbose = 1;
		argv++;
		argc--;
		goto again;
	}

	if (argc >= 2 && strcmp(argv[1], "-k") == 0) {
		enable_keepalive = 1;
		argv++;
		argc--;
		goto again;
	}

	if (argc >= 3 && strcmp(argv[1], "-c") == 0) {
		start_cpu = atoi(argv[2]);

		argv += 2;
		argc -= 2;
		goto again;
	}

	if (argc >= 3 && strcmp(argv[1], "-w") == 0) {
		process_mode = 1;
		num_workers = atoi(argv[2]);

		argv += 2;
		argc -= 2;
		goto again;
	}

	if (argc >= 3 && strcmp(argv[1], "-a") == 0) {
		int i ;

		for (i = 0; i < MAX_LISTEN_ADDRESS && argv[2]; i++) {
			char *sep = strchr(argv[2], ':');

			if (sep) {
				*sep = 0;
				strncpy(la[i].param_ip, argv[2], 32);
				inet_aton(la[i].param_ip, &la[i].listenip);
				sscanf(++sep, "%d", &la[i].param_port);
			} else
				break;
			argv++;
			argc--;
			la_num++;
		}

		argv++;
		argc--;
		goto again;
	}

	if (argc >= 3 && strcmp(argv[1], "-x") == 0) {
		int i ;

		enable_proxy = 1;

		for (i = 0; i < MAX_PROXY_ADDRESS && argv[2]; i++) {
			char *sep = strchr(argv[2], ':');

			if (sep) {
				*sep = 0;
				strncpy(pa[i].param_ip, argv[2], 32);
				inet_aton(pa[i].param_ip, &pa[i].proxyip);
				sscanf(++sep, "%d", &pa[i].param_port);
			} else
				break;

			argv++;
			argc--;
			pa_num++;
		}

		argv++;
		argc--;
		goto again;
	}

	if (!process_mode)
		process_mode = 1;
	if (!num_workers)
		num_workers = get_cpu_num();

	assert(num_workers >= 1 && num_workers <= get_cpu_num());

	if (la_num) {
		int i;

		for (i = 0; i < la_num; i++) {
			printf("Specified listen address %s:%d\n",
			       la[i].param_ip, la[i].param_port);
		}
	} else {
		la_num = 1;
		strncpy(la[0].param_ip, "0.0.0.0", 32);
		inet_aton(la[0].param_ip, &la[0].listenip);
		la[0].param_port = 80;
		printf("Default listen address %s:%d\n",
		       la[0].param_ip, la[0].param_port);
	}
	printf("\n");

	if (pa_num) {
		int i;

		printf("Proxy mode is enabled\n\n");
		enable_keepalive = 0;
		printf("HTTP keepalive is not supported in the proxy mode so far and therefore is disabled\n\n");

		for (i = 0; i < pa_num; i++) {
			printf("Back-End address %s:%d\n",
			       pa[i].param_ip, pa[i].param_port);
		}
		printf("\n");
	}

	if (enable_keepalive)
		printf("HTTP keepalive is enabled\n\n");

	if (process_mode)
		printf("Process Mode is enable with %d workers\n\n", num_workers);

	init_server();
	init_signal();

	init_workers();

	init_timer();
	do_stats();

	return 0;
}

void init_signal(void) {
	sigset_t siglist;

	if(sigemptyset(&siglist) == -1) {
		perror("Unable to initialize signal list");
		exit_cleanup();
	}

	if(sigaddset(&siglist, SIGALRM) == -1) {
		perror("Unable to add SIGALRM signal to signal list");
		exit_cleanup();
	}

	if(sigaddset(&siglist, SIGINT) == -1) {
		perror("Unable to add SIGINT signal to signal list");
		exit_cleanup();
	}

	if(pthread_sigmask(SIG_BLOCK, &siglist, NULL) != 0) {
		perror("Unable to change signal mask");
		exit_cleanup();
	}
}

void init_timer(void) {
	struct itimerval interval;

	interval.it_interval.tv_sec = 1;
	interval.it_interval.tv_usec = 0;
	interval.it_value.tv_sec = 1;
	interval.it_value.tv_usec = 0;

	if(setitimer(ITIMER_REAL, &interval, NULL) != 0) {
		perror("Unable to set interval timer");
		exit_cleanup();
	}
}

int init_single_server(struct in_addr ip, uint16_t port)
{
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	int serverfd, flags, value;

	if((serverfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("Unable to open socket");
		exit_cleanup();
	}

	flags = fcntl(serverfd, F_GETFL, 0);
	flags |= O_NONBLOCK;
	fcntl(serverfd, F_SETFL, flags);

	value = 1;
	if(setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) ==
	   -1) {
		perror("Unable to set socket reuseaddr option");
		exit_cleanup();
	}

	memset(&addr, 0, addrlen);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr = ip;

	if(bind(serverfd, (struct sockaddr *)&addr, addrlen) == -1) {
		perror("Unable to bind socket");
		exit_cleanup();
	}

	if(listen(serverfd, 8192) != 0) {
		perror("Cannot listen for client connections");
		exit_cleanup();
	}

	return serverfd;
}

int init_server(void)
{
	int ret = 0;
	int i;

	for (i = 0; i < la_num; i++){
		struct in_addr ip;
		uint16_t port;

		ip = la[i].listenip;
		port = la[i].param_port;

		la[i].listen_fd = init_single_server(ip, port);
	}

	return ret;
}

void init_processes(void)
{
	int i, pid;

	wdata = mmap(NULL, num_workers * sizeof(struct worker_data),
		     PROT_READ|PROT_WRITE,
		     MAP_ANON|MAP_SHARED,
		     -1, 0);

	memset(wdata, 0, num_workers * sizeof(struct worker_data));

	if (wdata == NULL) {
		perror("Unable to mmap shared global wdata");
		exit_cleanup();
	}

	for(i = 0; i < num_workers; i++) {
		wdata[i].trancnt = 0;
		wdata[i].cpu_id = i + start_cpu;

		if ( (pid = fork()) < 0) {
			perror("Unable to fork child process");
			exit_cleanup();
		} else if( pid == 0) {
			wdata[i].process = pid;
			process_clients((void *)&(wdata[i]));
			exit(0);
		}
	}
}

void init_workers(void)
{
	if (process_mode)
		init_processes();
}

struct context_pool *init_pool(int size)
{
	struct context_pool *ret;
	int i;

	assert(size > 0);

	ret = malloc(sizeof(struct context_pool));
	assert(ret);

	ret->arr = malloc(sizeof(struct conn_context) * size);
	assert(ret->arr);

	ret->total = size;
	ret->allocated = 0;
	ret->next_idx = 0;

	for (i = 0; i < size - 1; i++)
		ret->arr[i].next_idx = i + 1;

	ret->arr[size - 1].next_idx = -1;

	return ret;
}

struct conn_context *alloc_context(struct context_pool *pool)
{
	struct conn_context *ret;

	assert(pool->allocated < pool->total);
	pool->allocated++;

	ret = &pool->arr[pool->next_idx];
	pool->next_idx = pool->arr[pool->next_idx].next_idx;

	ret->fd = 0;
	ret->end_fd = 0;
	ret->next_idx = -1;

	ret->pool = pool;

	return ret;
}

void free_context(struct conn_context *context)
{
	struct context_pool *pool = context->pool;

	assert(pool->allocated > 0);
	pool->allocated--;

	context->next_idx = pool->next_idx;
	pool->next_idx = context - pool->arr;
}

char *http_200="HTTP/1.0 200 OK\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>200 OK</h1>\nEverything is fine.\n</body></html>\n";

char *http_200_keepalive="HTTP/1.0 200 OK\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: keep-alive\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>200 OK</h1>\nEverything is fine.\n</body></html>\n";

char *http_response;
int http_response_len;

static void process_close(struct conn_context *client_ctx)
{
	int fd, end_fd, ep_fd, ret;
	struct epoll_event evt;

	ep_fd = client_ctx->ep_fd;
	fd = client_ctx->fd;
	end_fd = client_ctx->end_fd;

	evt.events = EPOLLHUP | EPOLLERR;
	evt.data.ptr = client_ctx;

	ret = epoll_ctl(ep_fd, EPOLL_CTL_DEL, fd, &evt);
	if (ret < 0)
		perror("Unable to delete client socket from epoll");

	close(fd);
	if (end_fd) {
		ret = epoll_ctl(ep_fd, EPOLL_CTL_DEL, end_fd, &evt);
		if (ret < 0)
			perror("Unable to delete client socket from epoll");
		close(end_fd);
	}
}

static void process_write_backend(struct conn_context *ctx)
{
	int ep_fd, end_fd;
	int events = ctx->events;
	char *buf;
	int data_len;
	int ret;

	ep_fd = ctx->ep_fd;
	end_fd = ctx->end_fd;
	buf = ctx->buf;
	data_len = ctx->data_len;

	print_d("Process write event[%02x] on back-end socket %d\n", events, end_fd);

	if (events & (EPOLLHUP | EPOLLERR)) {
		printf("process_write_backend() with events HUP or ERR 0x%x\n", events);
		goto free_back;
	}

	struct epoll_event evt;

	if (!(ctx->flags & PROXY_BACKEND_EVENT))
	{
		printf("Write to back-end socket while back end socket not enabled\n");
		goto free_back;
	}

	ret = write(end_fd, buf, data_len);
	if (ret < 0) {
		perror("process_write() can't write back end socket");
		goto free_back;
	}

	print_d("Write %d to back-end socket %d\n", ret, end_fd);

	ctx->handler = process_read_backend;
	ctx->flags |= PROXY_BACKEND_EVENT;

	evt.events = EPOLLIN | EPOLLHUP | EPOLLERR;
	evt.data.ptr = ctx;

	ret = epoll_ctl(ep_fd, EPOLL_CTL_MOD, end_fd, &evt);
	if (ret < 0) {
		perror("Unable to add client socket read event to epoll");
		goto free_back;
	}

	goto back;

free_back:

	process_close(ctx);
	free_context(ctx);

back:

	return;
}

static void process_write_frontend(struct conn_context *ctx)
{
	int front_fd;
	char *buf;
	int data_len;
	int cpu_id;
	int ret;

	cpu_id = ctx->cpu_id;
	front_fd = ctx->fd;
	buf = ctx->buf;
	data_len = ctx->data_len;

	if (ctx->flags & PROXY_BACKEND_EVENT) {
		printf("Write to front end socket while back end socket enabled\n");
		goto free_back;
	}

	ret = write(front_fd, buf, data_len);
	if (ret < 0) {
		perror("Can't write front-end socket");
		goto free_back;
	}

	print_d("Write %d to front end socket %d\n", data_len, front_fd);

	wdata[cpu_id].trancnt++;

free_back:

	process_close(ctx);
	free_context(ctx);

	return;
}

static void process_read_backend(struct conn_context *ctx)
{
	int front_fd, end_fd, ep_fd;
	char *buf;
	int cpu_id;
	struct epoll_event evt;
	int ret;

	cpu_id = ctx->cpu_id;
	ep_fd = ctx->ep_fd;
	end_fd = ctx->end_fd;
	front_fd = ctx->fd;

	buf = ctx->buf;

	if (!(ctx->flags & PROXY_BACKEND_EVENT)) {
		printf("Process back end read while backend socket not enable\n");
		goto free_back;
	}

	ret = read(end_fd, buf, MAX_BUFSIZE);
	if (ret < 0) {
		wdata[cpu_id].read_cnt++;
		perror("process_read_backend() can't read client socket");
		goto free_back;
	}

	print_d("Read %d from back end socket %d\n", ret, end_fd);

	ctx->handler = process_write_frontend;
	ctx->flags &= ~PROXY_BACKEND_EVENT;
	ctx->data_len = ret;

	evt.events = EPOLLOUT | EPOLLHUP | EPOLLERR;
	evt.data.ptr = ctx;

	ret = epoll_ctl(ep_fd, EPOLL_CTL_MOD, front_fd, &evt);
	if (ret < 0) {
		perror("Unable to add client socket read event to epoll");
		goto free_back;
	}

	evt.events = EPOLLHUP | EPOLLERR;
	evt.data.ptr = ctx;

	//FIXME: Why monitor end fd?
	ret = epoll_ctl(ep_fd, EPOLL_CTL_MOD, end_fd, &evt);
	if (ret < 0)
	{
		perror("Unable to add client socket read event to epoll");
		goto free_back;
	}

	goto back;

free_back:

	process_close(ctx);
	free_context(ctx);

back:

	return;
}

static void select_backend(struct sockaddr_in *addr)
{
	static int last;

	addr->sin_family = AF_INET;
	addr->sin_port = htons(pa[last].param_port);
	addr->sin_addr = pa[last].proxyip;

	print_d("Select Back-end server %s:%d\n", pa[last].param_ip,
		pa[last].param_port);

	last++;

	if (last == pa_num)
		last = 0;
}

static void process_read_frontend(struct conn_context *ctx)
{
	int ep_fd, front_fd, end_fd;
	char *buf = ctx->buf;
	int events = ctx->events;
	struct epoll_event evt;
	struct sockaddr_in addr_in;
	int ret;
	int cpu_id = ctx->cpu_id;

	ep_fd = ctx->ep_fd;
	front_fd = ctx->fd;

	//FIXME: What else should I do.
	if (events & (EPOLLHUP | EPOLLERR)) {
		printf("process_read_frontend() with events HUP or ERR\n");
		goto free_back;
	}

	print_d("Process read event[%02x] on front-end socket %d\n", events, front_fd);

	ret = read(front_fd, buf, MAX_BUFSIZE);
	if (ret < 0)
	{
		wdata[cpu_id].read_cnt++;
		perror("process_read_frontend() can't read client socket");
		goto free_back;
	}

	ctx->data_len = ret;

	print_d("Read %d from front-end socket %d\n", ret, front_fd);

	//Remove interested read event for front-end socket
	evt.events = EPOLLHUP | EPOLLERR;
	evt.data.ptr = ctx;

	ret = epoll_ctl(ep_fd, EPOLL_CTL_MOD, front_fd, &evt);
	if (ret < 0) {
		perror("Unable to add client socket read event to epoll");
		goto free_back;
	}

	int flags;

	ret = socket(AF_INET, SOCK_STREAM, 0);
	if (ret < 0) {
		perror("Unable to create new socket for backend");
		goto free_back;
	}

	flags = fcntl(ret, F_GETFL, 0);
	flags |= O_NONBLOCK;
	fcntl(ret, F_SETFL, flags);

	end_fd = ret;

	select_backend(&addr_in);

	ret = connect(end_fd, (struct sockaddr *)&addr_in, sizeof(struct sockaddr));
	if (ret < 0) {
		if (errno != EINPROGRESS) {
			perror("Unable to connect to back end server");
			goto free_back;
		}
	}

	ctx->end_fd = end_fd;
	ctx->handler = process_write_backend;
	ctx->flags |= PROXY_BACKEND_EVENT;

	evt.events = EPOLLOUT | EPOLLHUP | EPOLLERR;
	evt.data.ptr = ctx;

	ret = epoll_ctl(ep_fd, EPOLL_CTL_ADD, end_fd, &evt);
	if (ret < 0) {
		perror("Unable to add client socket read event to epoll");
		goto free_back;
	}

	print_d("Add back-end socket %d to epoll\n", end_fd);

	goto back;

free_back:

	print_d("cpu[%d] close socket %d\n", cpu_id, ctx->fd);

	process_close(ctx);
	free_context(ctx);

back:
	return;
}

static void process_write(struct conn_context *client_ctx)
{
	int ep_fd, fd;
	int events = client_ctx->events;
	int cpu_id = client_ctx->cpu_id;
	char *buf;
	int len, ret;
	struct epoll_event evt;

	ep_fd = client_ctx->ep_fd;
	fd = client_ctx->fd;
	buf = client_ctx->buf;
	len = client_ctx->data_len;

	print_d("Process write event[%02x]\n", events);

	if (events & (EPOLLHUP | EPOLLERR)) {
		printf("process_write() with events HUP or ERR\n");
		goto free_back;
	}

	ret = write(fd, http_response, http_response_len);
	if (ret < 0) {
		wdata[cpu_id].write_cnt++;
		perror("process_write() can't write client socket");
		goto free_back;
	}

	print_d("Write %d to socket %d\n", ret, fd);

	wdata[cpu_id].trancnt++;

	if (!enable_keepalive)
		goto free_back;

	client_ctx->handler = process_read;

	evt.events = EPOLLIN | EPOLLHUP | EPOLLERR;
	evt.data.ptr = client_ctx;

	ret = epoll_ctl(ep_fd, EPOLL_CTL_MOD, fd, &evt);
	if (ret < 0) {
		perror("Unable to add client socket read event to epoll");
		goto free_back;
	}

	goto back;

free_back:

	process_close(client_ctx);
	free_context(client_ctx);
back:

	return;
}

static void process_read(struct conn_context *client_ctx)
{
	int ep_fd, fd;
	int events = client_ctx->events;
	struct epoll_event evt;
	int ret;
	char *buf = client_ctx->buf;
	int cpu_id = client_ctx->cpu_id;

	ep_fd = client_ctx->ep_fd;
	fd = client_ctx->fd;

	//FIXME: What else should I do.
	if (events & EPOLLHUP) {
		print_d("process_read() with events HUP\n");
		goto free_back;
	}
	if (events & EPOLLERR) {
		print_d("process_read() with events ERR\n");
		goto free_back;
	}

	print_d("Process read event[%02x] on socket %d\n", events, fd);

	ret = read(fd, buf, MAX_BUFSIZE);
	if (ret < 0) {
		wdata[cpu_id].read_cnt++;
		perror("process_read() can't read client socket");
		goto free_back;
	} else if (ret == 0) {
		goto free_back;
		print_d("Socket %d is closed\n", fd);
	}

	client_ctx->data_len = ret;

	print_d("Read %d from socket %d\n", ret, fd);

	client_ctx->handler = process_write;

	evt.events = EPOLLOUT | EPOLLHUP | EPOLLERR;
	evt.data.ptr = client_ctx;

	ret = epoll_ctl(ep_fd, EPOLL_CTL_MOD, fd, &evt);
	if (ret < 0) {
		perror("Unable to add client socket read event to epoll");
		goto free_back;
	}

	goto back;


free_back:

	print_d("cpu[%d] close socket %d\n", cpu_id, client_ctx->fd);

	process_close(client_ctx);
	free_context(client_ctx);

back:
	return;
}

static void process_accept(struct conn_context * listen_ctx)
{
	int client_fd, listen_fd;
	int events = listen_ctx->events;
	struct epoll_event evt;

	struct context_pool *pool;
	struct conn_context *client_ctx;

	int cpu_id = listen_ctx->cpu_id;
	int ret = 0;
	int i;

	listen_fd = listen_ctx->fd;

	//TODO: What else should I do.
	if (events & (EPOLLHUP | EPOLLERR))
		return;

	for (i = 0; i < ACCEPT_PER_LISTEN_EVENT; i++) {
		int flags;

		client_fd = accept(listen_fd, NULL, NULL);
		if (client_fd < 0) {
			wdata[cpu_id].accept_cnt++;
			goto back;
		}

		flags = fcntl(client_fd, F_GETFL, 0);
		flags |= O_NONBLOCK;
		fcntl(client_fd, F_SETFL, flags);

		print_d("Accept LWD %d from %d\n", client_fd, listen_fd);
	}

	pool = listen_ctx->pool;
	client_ctx = alloc_context(pool);
	assert(client_ctx);

	client_ctx->fd = client_fd;

	if (enable_proxy)
		client_ctx->handler = process_read_frontend;
	else
		client_ctx->handler = process_read;

	client_ctx->cpu_id = listen_ctx->cpu_id;
	client_ctx->ep_fd = listen_ctx->ep_fd;

	evt.events = EPOLLIN | EPOLLHUP | EPOLLERR;
	evt.data.ptr = client_ctx;

	ret = epoll_ctl(client_ctx->ep_fd, EPOLL_CTL_ADD, client_ctx->fd, &evt);
	if (ret < 0) {
		perror("Unable to add client socket read event to epoll");
		goto free_back;
	}

	goto back;

free_back:

	print_d("cpu[%d] close socket %d\n", cpu_id, client_ctx->fd);

	process_close(client_ctx);
	free_context(client_ctx);
back:
	return;
}

void *process_clients(void *arg)
{
	int ret;
	struct worker_data *mydata = (struct worker_data *)arg;
	struct context_pool *pool;

	struct epoll_event evt;
	struct epoll_event evts[EVENTS_PER_BATCH];

	int cpu_id;
	int ep_fd;
	int i;

	struct conn_context *ctx;

	if (enable_keepalive)
		http_response = http_200_keepalive;
	else
		http_response = http_200;

	http_response_len = strlen(http_response);

	ret = bind_process_cpu(mydata->cpu_id);
	if (ret < 0) {
		perror("Unable to Bind worker on CPU");
		exit_cleanup();
	}

	pool = init_pool(MAX_CONNS_PER_WORKER);

	if ((ep_fd = epoll_create(MAX_CONNS_PER_WORKER)) < 0) {
		perror("Unable to create epoll FD");
		exit_cleanup();
	}

	for (i = 0; i < la_num; i++) {
		ctx = alloc_context(pool);

		ctx->fd = la[i].listen_fd;
		ctx->handler = process_accept;
		cpu_id = mydata->cpu_id;
		ctx->cpu_id = cpu_id;
		ctx->ep_fd = ep_fd;

		evt.events = EPOLLIN | EPOLLHUP | EPOLLERR;
		evt.data.ptr = ctx;

		if (epoll_ctl(ctx->ep_fd, EPOLL_CTL_ADD, ctx->fd, &evt) < 0) {
			perror("Unable to add Listen Socket to epoll");
			exit_cleanup();
		}
	}

	wdata[cpu_id].polls_min = EVENTS_PER_BATCH;

	while (1) {
		int num_events;
		int i;
		int events;

		num_events = epoll_wait(ep_fd, evts, EVENTS_PER_BATCH, -1);
		if (num_events < 0) {
			if (errno == EINTR)
				continue;
			perror("epoll_wait() error");
		}
		if (!num_events)
			wdata[cpu_id].polls_mpt++;
		else if (num_events < wdata[cpu_id].polls_min)
			wdata[cpu_id].polls_min = num_events;
		if (num_events > wdata[cpu_id].polls_max)
			wdata[cpu_id].polls_max = num_events;

		wdata[cpu_id].polls_sum += num_events;
		wdata[cpu_id].polls_cnt++;
		wdata[cpu_id].polls_avg = wdata[cpu_id].polls_sum / wdata[cpu_id].polls_cnt;
		wdata[cpu_id].polls_lst = num_events;

		for (i = 0 ; i < num_events; i++) {
			int active_fd;

			events = evts[i].events;
			ctx = evts[i].data.ptr;
			ctx->events = events;

			if (ctx->flags & PROXY_BACKEND_EVENT)
				active_fd = ctx->end_fd;
			else
				active_fd = ctx->fd;

			print_d("%dth event[0x%x] at fd %d\n", i, events, active_fd);

			ctx->handler(ctx);
		}
	}
	return NULL;
}

void do_stats(void) {
	sigset_t siglist;
	int signum;
	int i;

	if(sigemptyset(&siglist) == -1) {
		perror("Unable to initalize stats signal list");
		exit_cleanup();
	}

	if(sigaddset(&siglist, SIGALRM) == -1) {
		perror("Unable to add SIGALRM signal to stats signal list");
		exit_cleanup();
	}


	if(sigaddset(&siglist, SIGINT) == -1) {
		perror("Unable to add SIGINT signal to stats signal list");
		exit_cleanup();
	}

	while(1) {
		if(sigwait(&siglist, &signum) != 0) {
			perror("Error waiting for signal");
			exit_cleanup();
		}

		if(signum == SIGALRM) {
			uint64_t trancnt = 0;

			for(i = 0; i < num_workers; i++)
			{
				trancnt += wdata[i].trancnt - wdata[i].trancnt_prev;
				if (enable_verbose)
					fprintf(stderr, "%lu[%lu-%lu-%lu-%lu-%lu-%lu-%lu-%lu]  ",
						wdata[i].trancnt - wdata[i].trancnt_prev, wdata[i].polls_mpt,
						wdata[i].polls_lst, wdata[i].polls_min, wdata[i].polls_max,
						wdata[i].polls_avg, wdata[i].accept_cnt, wdata[i].read_cnt,
						wdata[i].write_cnt);
				wdata[i].trancnt_prev = wdata[i].trancnt;
			}

			fprintf(stderr, "\tTotal %8lu\n", trancnt);

		} else if(signum == SIGINT) {
			printf("\nExiting...\n");
			stop_workers();
			break;
		}
	}
}

void exit_cleanup(void) {
	stop_workers();
	exit(EXIT_FAILURE);
}

void stop_processes(void)
{
	int i;

	for(i = 0; i < num_workers; i++)
		kill(wdata[i].process, SIGTERM);
}

void stop_workers(void)
{
	if (process_mode)
		stop_processes();
}

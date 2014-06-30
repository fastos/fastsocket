## INTRODUCTION ##

This is a simple TCP server and is used to benchmark and profile 
the performace of the network stack of Linux Kernel. It can also 
be used to demonstrate the scalability and performance improvement 
of Fastsocket over the base Linux kernel.

The demo server uses epoll and non-blocking IO to process network 
connections. It works only in multi-process mode. Each process is 
bound to a different CPU core starting from CPU core 0 and accepts 
connections individually. 

The demo server has two working modes: server mode and proxy mode. 
* **Server Mode**: The server will respond with a HTTP 200 OK once 
it receives anything.
* **Proxy Mode**: When the server receives something, it forwards 
that to a backend server. And the server delivers the reponse from 
the backend server back to the client.

As you can see, It is a simple and stupid TCP server. Please make 
sure that each message, including the request from client and 
the response from the backend server, only takes one packet. 
Otherwise, the demo server will get confused.

## BUILD ##

Demo server can be built by the following command:

`[root@localhost fastsocket]# cd demo && make`

## USAGE ##

Execute the following simple command and the demo server is started 
with default settings.

`[root@localhost demo]# ./server`

All the parameters are listed below:
- -w worker_num: Specify worker process number to process connections.
	- Default is the available CPU core number.
- -c start_core: Specify the first CPU core to start to bind each 
worker process.
	- Default is 0.
- -o log_file: Specify log file.
	- Default is ./demo.log
- -a listen_address: Specify the listen address[ip:port]. Multiple 
listen addresses can be added.
	- Default is 0.0.0.0:80
- -x backend_address: Enable proxy mode and specify backend server 
address[ip:port]. Multiple backend addresses can be added.
	- Default is disabled.
- -v: Enable verbose statistics output.
	- Default is disabled.
- -d: Enable debug mode. Debug message will be loged into log file.
	- Default is disbaled.
- -k: Enable HTTP keepalive. Currently it only works in the server 
mode.
	- Default is disabled.
 
## EXAMPLES ##

There are two important notes before running the demo server:

- To fully load CPUs on the demo server machine, make sure the client 
and the backend server are not the bottleneck. Two possible solutions:
	- Provide enough machines acting as the clients and the backend servers.
	- Or use Fastsocekt on the client and backend server(recommended to save machines).
- Configure NIC properly. If you have no idea what to do, then use the [script](../scripts/README.md "Script") provided in this repo.

### SERVER MODE EXAMPLE ###

In the server mode, two hosts are needed if a single client can generate enough load:

- Host A acts as a client to generate HTTP request work load 
- Host B acts as a simple web server

Assume each machine has 12 CPU cores and your network is configured in the following way:


	+--------------------+     +--------------------+
	|       Host A       |     |       Host B       |
	|                    |     |                    |
	|        10.0.0.1/24 |-----| 10.0.0.2/24        |
	|                    |     |                    |
	+--------------------+     +--------------------+


To run the demo, here are the steps on each of two hosts.

**Host B**:

- Run the demo server in the default server mode with 12 workers(equal to CPU core number).

	`[root@localhost demo]# ./server -w 12 -a 10.0.0.2:80`

- Or run the demo server with Fastsocket.

	`[root@localhost demo]# LD_PRELOAD=../library/libfsocket.so ./server -w 12 -a 10.0.0.2:80`

**Host A**:

- Run the work load generator(using ab as an example) to stress the demo server.

	`[root@localhost ~]# ab -n 1000000 -c 100 http://10.0.0.2:80/`

- To saturate the server, multiple ab instances may be required, which 
can be launched by the following command (12 instances in the example).

	`[root@localhost ~]# N=12; for i in $(seq 1 $N); do ab -n 1000000 -c 100 http://10.0.0.2:80/ > /dev/null 2>&1; done`


### PROXY MODE EXAMPLE ###

In the proxy mode, three hosts are needed, if one host for each client and backend server is enough:

- Host A acts as a client to generate HTTP request work load 
- Host B acts as a proxy server
- Host C acts as a backend server

Assume each machine has 12 CPU cores and your network is configured in the following way:


	+--------------------+     +--------------------+     +--------------------+
	|       Host A       |     |       Host B       |     |       Host C       |
	|                    |     |                    |     |                    |
	|    10.0.0.1/24     |     |    10.0.0.2/24     |     |     10.0.0.3/24    |
	+---------+----------+     +---------+----------+     +----------+---------+
              |                          |                           |
	+---------+--------------------------+---------------------------+---------+
	|                                 switch                                   |
	+--------------------------------------------------------------------------+



To run the demo, here are the steps on each of three hosts.

**Host B**:

- Run the demo server in proxy mode with 12 workers.

	`[root@localhost demo]# ./server -w 12 -a 10.0.0.2:80 -x 10.0.0.3:80`

- Or run the demo server in proxy mode with Fastsocket.

	`[root@localhost demo]# LD_PRELOAD=../library/libsocket.so ./server -w 12 -a 10.0.0.2:80 -x 10.0.0.3:80`

**Host C**:

- Any web server is fine to act as a backend server. Here we just use the demo server 
again. 

	`[root@localhost demo]# ./server -w 12 -a 10.0.0.3:80`

**Host A**:

- Run the work load generator(again with 12 ab instances).

	`[root@localhost ~]# N=12; for i in $(seq 1 $N); do ab -n 1000000 -c 100 http://10.0.0.2:80/ > /dev/null 2>&1; done`


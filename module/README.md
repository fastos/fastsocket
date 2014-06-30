 README for FASTSOCKET Kernel Module
========================================================================

## TABLE OF CONTENT ##
* [Introduction](#introduction)
* [VFS Optimizations](#vfs-optimizations)
* [Kernel Module Parameters](#kernel-module-parameters)
  * [enable_listen_spawn](#enable_listen_spawn)
  * [enable_fast_epoll](#enable_fast_epoll)
  * [enable_receive_flow_deliver](#enable_receive_flow_deliver)

## INTRODUCTION ##

Fastsocket kernel module (fastsocket.ko) provides various options to turn on/off
different features individually.

## VFS OPTIMIZATIONS ##

In the kernel from CentOS 6.5, lock contentions are common in VFS, leading to
poor scalability no matter what optimizations are done to the TCP/IP protocol
stack. The most severely contended locks include inode\_lock and dcache\_lock
which are unnecessary for pseudo file systems like sockfs. Fastsocket solves
these issues by providing a fastpath for sockfs during the initialization of VFS
structures, just in the same way as has been done in the following two commits
from the vanilla kernel.

a209dfc vfs: dont chain pipe/anon/socket on superblock s_inodes list
4b93688 fs: improve scalability of pseudo filesystems

All sockets created by Fastsocket pass the fastpaths. No option is provided to
disable this optimization.

## KERNEL MODULE PARAMETERS ##

### enable_listen_spawn ###

Fastsocket creates one local listen socket table for each CPU core. With this 
feature, application process can decide to process new connections from a specific CPU 
core. It is done by copying the original listen socket and inserting the copy 
into the local listen socket table. When there is a new connection on one CPU 
core, kernel tries to match a listen socket in the local listen table of 
that CPU core and inserts the connection into the accept queue of the local 
listen socket if there is match. Later, the process can accept the connection 
from the local listen socket exclusively. This way each network softirq has its own 
local socket to queue new connection and each process has its own local 
listen socket to pull new connection out. When the process is bound with the CPU
core specified, then connections delivered to that CPU core by NIC are entirely 
processed by the same CPU core with in all stages, including hardirp, softirq, 
syscall and user process. As a result, connections are processed without contension 
across all CPU cores, which achieves passive connection locality.

This feature is mostly suitable to cases in which:
  * there are as many NIC rx queues as CPU cores, and that
  * application workers are statically pinned to each CPU.

To satisfy the first condition, RPS can be used when the number of Rx queues is 
less then CPU cores. The second condition can be satisfied in two ways:
  * The application has a CPU affiity configuration to bind each worker to a 
different CPU core when worker starts.
  * Allow Fastsocket to set the CPU affinity for each worker automatically. 

As a result, enable_listen_spawn is a tristate option:

  * enable_listen_spawn=0: disable this feature completely
  * enable_listen_spawn=1: enable this feature and require the application to set
 worker process CPU affinity itself.
  * enable_listen_spawn=2 (default): enable this feature and allow Fastsocket to
    bind each application worker with a CPU core sequentially.

### enable_fast_epoll ###

When enabled, this feature caches the mapping from files to epitems by using an
additional field in the file structure. This avoids overhead from epitem lookup
in the epoll rbtree when epoll_ctl is invoked.

This optimization actually changes epoll semantic a little to benefit socket.
Fast_epoll requires one socket(not including listen socket) is added only to one 
epoll instance, which is true for most socket applications. Disable this feature
if the condition dose not hold for your application.

Enable_fast_epoll is a boolean option:

  * enable_fast_epoll=0: disable fast-epoll
  * enable_fast_epoll=1 (default): enable fast-epoll

### enable_receive_flow_deliver ###

Instead of randomly choosing a source port for newly-created active connections,
RFD (Receive Flow Deliver) encodes the ID of CPU core on which this connection is
created into the port number. When packets are received on active connections,
RFD decodes the CPU core ID out of the destination port and steers the packet to 
the CPU core accordingly. This feature guarantees the locality of the active 
connections. Together with Listen_spawn, a complete connection locality is achieved.

Enable_receive_flow is a boolean option:

  * enable_receive_flow=0 (default): disable RFD
  * enable_receive_flow=1: enable RFD

Note: 
  * When enabled, under current implementation, RFD overrides RPS completely 
and makes RPS policies noneffective. Disable this feature when you are using RPS. 
  * As RFD is only beneficial to applications with active connections such as proxies, 
we suggest disabling this feature when you work on web servers.

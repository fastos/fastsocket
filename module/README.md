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

When enabled, this feature spawns a local (i.e. CPU-pinned) listen socket each
time a listen socket is added to epoll by a worker. Each local listen socket
monitors incoming connections on that core using its own queues. When an
application worker asks for new connections, the local listen socket is checked
at first. Thus under normal conditions, each worker will only accept connections
established on the same core, which achieves connection locality.

This feature is mostly suitable to cases in which:
  * there are as many Rx queues as CPU cores, and that
  * application workers are statically pinned to each CPU.

To satisfy the first condition, RPS is enabled when the number of Rx queues and
cores are not equal. The second condition can be satisfied by either setting CPU
affinity of each worker manually or allow Fastsocket to set the parameters
automatically. As a result, enable_listen_spawn is a tristate option:

  * enable_listen_spawn=0: disable this feature completely
  * enable_listen_spawn=1: enable this feature and require the user to set CPU
    affinity of application processes.
  * enable_listen_spawn=2 (default): enable this feature and allow Fastsocket to
    set CPU affinities automatically in a round-robin way

Note: When there are less Rx queues than cores, this feature relies on RPS to
steers incoming packets evenly (the configuration script will take care of
configuring RPS). It is recommended to disable
[RFD](#enable_receive_flow_deliver) under such circumstances.

### enable_fast_epoll ###

When enabled, this feature caches the mapping from files to epitems by using an
additional field in the file structure. This avoids overhead from epitem lookup
and reduces the critical section of the per-epoll mutex.

Enable_fast_epoll is a boolean option:

  * enable_fast_epoll=0: disable fast-epoll
  * enable_fast_epoll=1 (default): enable fast-epoll

### enable_receive_flow_deliver ###

Instead of randomly choosing a source port for newly-created active connections,
RFD (Receive Flow Deliver) encodes the ID of CPU on which this connection is
created into the port number. When packets are received on active connections,
RFD overrides RPS hashing function and steers the packet to the core according
to its destination port. This feature guarantees locality of active connections
without modifications to the clients.

Enable_receive_flow is a boolean option:

  * enable_receive_flow=0 (default): disable RFD
  * enable_receive_flow=1: enable RFD

Note: When enabled, RFD overrides RPS completely and makes RPS policies
noneffective. As RFD is only beneficial to applications with active connections
such as proxies, we suggest disabling this feature when you work on web servers.
Please enable this feature with care.

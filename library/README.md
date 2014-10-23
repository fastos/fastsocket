## INTRODUCTION ##

Libfsocket is a library for applications to use Fastsocket. It 
serves two main purposes: maintainability and compatibility.

* **Maintainability**: Fastsocket optimizes the implementations of 
some socket system calls to improve kernel network stack efficiency.
Rather than modify these systemwide system calls, we carry out the
implementation in Fastsocket kernel module and provide a new ioctl 
interface for applications to replace these system calls.

* **Compatibility**: Applications have to modify their codes to adapt
the new interface and that would make it infeasible in the real world.
To address the that problem, libfsocket is used to intercept the these 
system calls and replace them with the new interface. Therefore, 
with libfsocket, Fastsocket is compatible with BSD socket interface and
applications can use Fastsocket directly without changing any code.

## BUILD ##

Enter the library directory and make:

	[root@localhost fastsocket]# cd library
	[root@localhost library]# make

After that, libfsocket.so is created in the same directory.

## USAGE ##

LD_PRELOAD libfsocket.so and start the application that wants to use Fastsocket.

For example, ngnix can be started with Fastsocket by:

	[root@localhost fastsocket]# cd library
	[root@localhost library]# LD_PRELOAD=./libfsocket.so nginx

If a rollback is needed, just restart nginx without libfsocket.so:

	[root@localhost library]# nginx

Notes: 

* Make sure fastsocket.ko is already loaded. 
* Fastsocket only takes effect on the application starting with libfsocket.so


## INTERNALS ##

As descripted in the introduction, most of the work is to intercept 
socket syscalls and replace them with Fastsocket ioctl interface.

There is an extra work:

To use Percore-Listen-Table feature of Fastsocket, after forking from 
the parent process and before doing the event loop processing, the 
application worker needs to invoke a listen_spawn function to copy the 
global listen socket and insert the copy into the local listen table. 

To keep the codes of application unchanged, libfsocket tries to do 
the listien_spawn in place of application in the following way:

* Libfsocket tracks all the listen socket fds.
* Libfsocket intercepts the epoll_ctl system call.
* When libfsocket notices that application calls epoll_ctl to add the 
listen socket fd into epoll, libfsocket will make listen_spawn the call.

This solution is definitely not accurate for all the applications, but 
it works fine with nginx, haproxy and lighttpd. Be carefull when 
you want to use Percore-Listen-Table feature on other applications.

## INTRODUCTION ##

Libfsocket is a library for applications to use Fastsocket. It 
serves two main pupposes: maintainability and compatibility.

* **Maintainability**: Fastsocket optimizes the implementations of 
some socket system calls to improve kernel network stack efficiency.
Rather than modify these systemwide system calls, we carry out the
implementation in Fastsocket kernel module and provide a new ioctl 
interface for applications to replace these system calls.

* **Compatibility**: Applications have to modify their codes to adapt
the new interface and that would make it infeasible in the real world.
Here, libfsocket is used to intercept the these system calls and 
replace them with the new interfaces. Therefore, Fastsocket is 
compatible with BSD socket interface with libfsocket.

## BUILD ##

Enter the library directory and make:

	[root@localhost fastsocket]# cd library
	[root@localhost library]# make

After that, libfsocket.so is created in the same directory.

## USAGE ##

Start the application that wants to use Fastsocekt with preload of 
libfsocket.so.

Notes: 

* Make sure fastsocket.ko is already loaded. 
* Fastsocket only takes effect on the application starting with libfsocket.so

For example, ngnix can be started with Fastsocket by:

	[root@localhost fastsocket]# cd library
	[root@localhost library]# LD_PRELOAD=./libfsocket.so nginx

If a rollback is needed, just restart nginx without preloading libfsocket.so:

	[root@localhost library]# nginx

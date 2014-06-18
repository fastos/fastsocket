#include <linux/workqueue.h>
#include <linux/rtnetlink.h>
#include <linux/cache.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/idr.h>
#include <linux/rculist.h>
#include <linux/nsproxy.h>
#include <linux/proc_fs.h>
#include <linux/file.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

/*
 *	Our network namespace constructor/destructor lists
 */

static LIST_HEAD(pernet_list);
static struct list_head *first_device = &pernet_list;
static DEFINE_MUTEX(net_mutex);

LIST_HEAD(net_namespace_list);
EXPORT_SYMBOL_GPL(net_namespace_list);

struct net init_net = {
	.dev_base_head = LIST_HEAD_INIT(init_net.dev_base_head),
};
EXPORT_SYMBOL(init_net);

#define INITIAL_NET_GEN_PTRS	13 /* +1 for len +2 for rcu_head */

static unsigned int max_gen_ptrs = INITIAL_NET_GEN_PTRS;

static struct net_generic *net_alloc_generic(void)
{
	struct net_generic *ng;
	size_t generic_size = offsetof(struct net_generic, ptr[max_gen_ptrs]);

	ng = kzalloc(generic_size, GFP_KERNEL);
	if (ng)
		ng->len = max_gen_ptrs;

	return ng;
}

/*
 * setup_net runs the initializers for the network namespace object.
 */
static __net_init int setup_net(struct net *net)
{
	/* Must be called with net_mutex held */
	struct pernet_operations *ops;
	int error = 0;

	atomic_set(&net->count, 1);

#ifdef NETNS_REFCNT_DEBUG
	atomic_set(&net->use_count, 0);
#endif

	list_for_each_entry(ops, &pernet_list, list) {
		if (ops->init) {
			error = ops->init(net);
			if (error < 0)
				goto out_undo;
		}
	}
out:
	return error;

out_undo:
	/* Walk through the list backwards calling the exit functions
	 * for the pernet modules whose init functions did not fail.
	 */
	list_for_each_entry_continue_reverse(ops, &pernet_list, list) {
		if (ops->exit)
			ops->exit(net);
	}

	rcu_barrier();
	goto out;
}


#ifdef CONFIG_NET_NS
static struct kmem_cache *net_cachep;
static struct workqueue_struct *netns_wq;

static struct net *net_alloc(void)
{
	struct net *net = NULL;
	struct net_generic *ng;

	ng = net_alloc_generic();
	if (!ng)
		goto out;

	net = kmem_cache_zalloc(net_cachep, GFP_KERNEL);
	if (!net)
		goto out_free;

	rcu_assign_pointer(net->gen, ng);
out:
	return net;

out_free:
	kfree(ng);
	goto out;
}

static void net_free(struct net *net)
{
#ifdef NETNS_REFCNT_DEBUG
	if (unlikely(atomic_read(&net->use_count) != 0)) {
		printk(KERN_EMERG "network namespace not free! Usage: %d\n",
			atomic_read(&net->use_count));
		return;
	}
#endif
	kfree(net->gen);
	kmem_cache_free(net_cachep, net);
}

static struct net *net_create(void)
{
	struct net *net;
	int rv;

	net = net_alloc();
	if (!net)
		return ERR_PTR(-ENOMEM);
	mutex_lock(&net_mutex);
	rv = setup_net(net);
	if (rv == 0) {
		rtnl_lock();
		list_add_tail_rcu(&net->list, &net_namespace_list);
		rtnl_unlock();
	}
	mutex_unlock(&net_mutex);
	if (rv < 0) {
		net_free(net);
		return ERR_PTR(rv);
	}
	return net;
}

struct net *copy_net_ns(unsigned long flags, struct net *old_net)
{
	if (!(flags & CLONE_NEWNET))
		return get_net(old_net);
	return net_create();
}

static void cleanup_net(struct work_struct *work)
{
	struct pernet_operations *ops;
	struct net *net;

	net = container_of(work, struct net, work);

	mutex_lock(&net_mutex);

	/* Don't let anyone else find us. */
	rtnl_lock();
	list_del_rcu(&net->list);
	rtnl_unlock();

	/*
	 * Another CPU might be rcu-iterating the list, wait for it.
	 * This needs to be before calling the exit() notifiers, so
	 * the rcu_barrier() below isn't sufficient alone.
	 */
	synchronize_rcu();

	/* Run all of the network namespace exit methods */
	list_for_each_entry_reverse(ops, &pernet_list, list) {
		if (ops->exit)
			ops->exit(net);
	}

	mutex_unlock(&net_mutex);

	/* Ensure there are no outstanding rcu callbacks using this
	 * network namespace.
	 */
	rcu_barrier();

	/* Finally it is safe to free my network namespace structure */
	net_free(net);
}

void __put_net(struct net *net)
{
	/* Cleanup the network namespace in process context */
	INIT_WORK(&net->work, cleanup_net);
	queue_work(netns_wq, &net->work);
}
EXPORT_SYMBOL_GPL(__put_net);

struct net *get_net_ns_by_fd(int fd)
{
	struct proc_inode *ei;
	struct file *file;
	struct net *net;

	file = proc_ns_fget(fd);
	if (IS_ERR(file))
		return ERR_CAST(file);

	ei = PROC_I(file->f_dentry->d_inode);
	if (ei->ns_ops == &netns_operations)
		net = get_net(ei->ns);
	else
		net = ERR_PTR(-EINVAL);

	fput(file);
	return net;
}

#else
struct net *copy_net_ns(unsigned long flags, struct net *old_net)
{
	if (flags & CLONE_NEWNET)
		return ERR_PTR(-EINVAL);
	return old_net;
}

struct net *get_net_ns_by_fd(int fd)
{
	return ERR_PTR(-EINVAL);
}
#endif

struct net *get_net_ns_by_pid(pid_t pid)
{
	struct task_struct *tsk;
	struct net *net;

	/* Lookup the network namespace */
	net = ERR_PTR(-ESRCH);
	rcu_read_lock();
	tsk = find_task_by_vpid(pid);
	if (tsk) {
		struct nsproxy *nsproxy;
		nsproxy = task_nsproxy(tsk);
		if (nsproxy)
			net = get_net(nsproxy->net_ns);
	}
	rcu_read_unlock();
	return net;
}
EXPORT_SYMBOL_GPL(get_net_ns_by_pid);

static __net_init int net_ns_net_init(struct net *net)
{
	return proc_alloc_inum(&net->proc_inum);
}

static __net_exit void net_ns_net_exit(struct net *net)
{
	proc_free_inum(net->proc_inum);
}

static struct pernet_operations __net_initdata net_ns_ops = {
	.init = net_ns_net_init,
	.exit = net_ns_net_exit,
};

static int __init net_ns_init(void)
{
	struct net_generic *ng;

#ifdef CONFIG_NET_NS
	net_cachep = kmem_cache_create("net_namespace", sizeof(struct net),
					SMP_CACHE_BYTES,
					SLAB_PANIC, NULL);

	/* Create workqueue for cleanup */
	netns_wq = create_singlethread_workqueue("netns");
	if (!netns_wq)
		panic("Could not create netns workq");
#endif

	ng = net_alloc_generic();
	if (!ng)
		panic("Could not allocate generic netns");

	rcu_assign_pointer(init_net.gen, ng);

	mutex_lock(&net_mutex);
	if (setup_net(&init_net))
		panic("Could not setup the initial network namespace");

	rtnl_lock();
	list_add_tail_rcu(&init_net.list, &net_namespace_list);
	rtnl_unlock();

	mutex_unlock(&net_mutex);

	register_pernet_subsys(&net_ns_ops);

	return 0;
}

pure_initcall(net_ns_init);

#ifdef CONFIG_NET_NS
static int register_pernet_operations(struct list_head *list,
				      struct pernet_operations *ops)
{
	struct net *net, *undo_net;
	int error;

	list_add_tail(&ops->list, list);
	if (ops->init) {
		for_each_net(net) {
			error = ops->init(net);
			if (error)
				goto out_undo;
		}
	}
	return 0;

out_undo:
	/* If I have an error cleanup all namespaces I initialized */
	list_del(&ops->list);
	if (ops->exit) {
		for_each_net(undo_net) {
			if (undo_net == net)
				goto undone;
			ops->exit(undo_net);
		}
	}
undone:
	return error;
}

static void unregister_pernet_operations(struct pernet_operations *ops)
{
	struct net *net;

	list_del(&ops->list);
	if (ops->exit)
		for_each_net(net)
			ops->exit(net);
}

#else

static int register_pernet_operations(struct list_head *list,
				      struct pernet_operations *ops)
{
	if (ops->init == NULL)
		return 0;
	return ops->init(&init_net);
}

static void unregister_pernet_operations(struct pernet_operations *ops)
{
	if (ops->exit)
		ops->exit(&init_net);
}
#endif

static DEFINE_IDA(net_generic_ids);

/**
 *      register_pernet_subsys - register a network namespace subsystem
 *	@ops:  pernet operations structure for the subsystem
 *
 *	Register a subsystem which has init and exit functions
 *	that are called when network namespaces are created and
 *	destroyed respectively.
 *
 *	When registered all network namespace init functions are
 *	called for every existing network namespace.  Allowing kernel
 *	modules to have a race free view of the set of network namespaces.
 *
 *	When a new network namespace is created all of the init
 *	methods are called in the order in which they were registered.
 *
 *	When a network namespace is destroyed all of the exit methods
 *	are called in the reverse of the order with which they were
 *	registered.
 */
int register_pernet_subsys(struct pernet_operations *ops)
{
	int error;
	mutex_lock(&net_mutex);
	error =  register_pernet_operations(first_device, ops);
	mutex_unlock(&net_mutex);
	return error;
}
EXPORT_SYMBOL_GPL(register_pernet_subsys);

/**
 *      unregister_pernet_subsys - unregister a network namespace subsystem
 *	@ops: pernet operations structure to manipulate
 *
 *	Remove the pernet operations structure from the list to be
 *	used when network namespaces are created or destroyed.  In
 *	addition run the exit method for all existing network
 *	namespaces.
 */
void unregister_pernet_subsys(struct pernet_operations *module)
{
	mutex_lock(&net_mutex);
	unregister_pernet_operations(module);
	mutex_unlock(&net_mutex);
}
EXPORT_SYMBOL_GPL(unregister_pernet_subsys);

int register_pernet_gen_subsys(int *id, struct pernet_operations *ops)
{
	int rv;

	mutex_lock(&net_mutex);
again:
	rv = ida_get_new_above(&net_generic_ids, 1, id);
	if (rv < 0) {
		if (rv == -EAGAIN) {
			ida_pre_get(&net_generic_ids, GFP_KERNEL);
			goto again;
		}
		goto out;
	}
	rv = register_pernet_operations(first_device, ops);
	if (rv < 0)
		ida_remove(&net_generic_ids, *id);
out:
	mutex_unlock(&net_mutex);
	return rv;
}
EXPORT_SYMBOL_GPL(register_pernet_gen_subsys);

void unregister_pernet_gen_subsys(int id, struct pernet_operations *ops)
{
	mutex_lock(&net_mutex);
	unregister_pernet_operations(ops);
	ida_remove(&net_generic_ids, id);
	mutex_unlock(&net_mutex);
}
EXPORT_SYMBOL_GPL(unregister_pernet_gen_subsys);

/**
 *      register_pernet_device - register a network namespace device
 *	@ops:  pernet operations structure for the subsystem
 *
 *	Register a device which has init and exit functions
 *	that are called when network namespaces are created and
 *	destroyed respectively.
 *
 *	When registered all network namespace init functions are
 *	called for every existing network namespace.  Allowing kernel
 *	modules to have a race free view of the set of network namespaces.
 *
 *	When a new network namespace is created all of the init
 *	methods are called in the order in which they were registered.
 *
 *	When a network namespace is destroyed all of the exit methods
 *	are called in the reverse of the order with which they were
 *	registered.
 */
int register_pernet_device(struct pernet_operations *ops)
{
	int error;
	mutex_lock(&net_mutex);
	error = register_pernet_operations(&pernet_list, ops);
	if (!error && (first_device == &pernet_list))
		first_device = &ops->list;
	mutex_unlock(&net_mutex);
	return error;
}
EXPORT_SYMBOL_GPL(register_pernet_device);

int register_pernet_gen_device(int *id, struct pernet_operations *ops)
{
	int error;
	mutex_lock(&net_mutex);
again:
	error = ida_get_new_above(&net_generic_ids, 1, id);
	if (error) {
		if (error == -EAGAIN) {
			ida_pre_get(&net_generic_ids, GFP_KERNEL);
			goto again;
		}
		goto out;
	}
	max_gen_ptrs = max_t(unsigned int, max_gen_ptrs, *id);
	error = register_pernet_operations(&pernet_list, ops);
	if (error)
		ida_remove(&net_generic_ids, *id);
	else if (first_device == &pernet_list)
		first_device = &ops->list;
out:
	mutex_unlock(&net_mutex);
	return error;
}
EXPORT_SYMBOL_GPL(register_pernet_gen_device);

/**
 *      unregister_pernet_device - unregister a network namespace netdevice
 *	@ops: pernet operations structure to manipulate
 *
 *	Remove the pernet operations structure from the list to be
 *	used when network namespaces are created or destroyed.  In
 *	addition run the exit method for all existing network
 *	namespaces.
 */
void unregister_pernet_device(struct pernet_operations *ops)
{
	mutex_lock(&net_mutex);
	if (&ops->list == first_device)
		first_device = first_device->next;
	unregister_pernet_operations(ops);
	mutex_unlock(&net_mutex);
}
EXPORT_SYMBOL_GPL(unregister_pernet_device);

void unregister_pernet_gen_device(int id, struct pernet_operations *ops)
{
	mutex_lock(&net_mutex);
	if (&ops->list == first_device)
		first_device = first_device->next;
	unregister_pernet_operations(ops);
	ida_remove(&net_generic_ids, id);
	mutex_unlock(&net_mutex);
}
EXPORT_SYMBOL_GPL(unregister_pernet_gen_device);

static void net_generic_release(struct rcu_head *rcu)
{
	struct net_generic *ng;

	ng = container_of(rcu, struct net_generic, rcu);
	kfree(ng);
}

int net_assign_generic(struct net *net, int id, void *data)
{
	struct net_generic *ng, *old_ng;

	BUG_ON(!mutex_is_locked(&net_mutex));
	BUG_ON(id == 0);

	ng = old_ng = net->gen;
	if (old_ng->len >= id)
		goto assign;

	ng = net_alloc_generic();
	if (ng == NULL)
		return -ENOMEM;

	/*
	 * Some synchronisation notes:
	 *
	 * The net_generic explores the net->gen array inside rcu
	 * read section. Besides once set the net->gen->ptr[x]
	 * pointer never changes (see rules in netns/generic.h).
	 *
	 * That said, we simply duplicate this array and schedule
	 * the old copy for kfree after a grace period.
	 */

	memcpy(&ng->ptr, &old_ng->ptr, old_ng->len * sizeof(void*));

	rcu_assign_pointer(net->gen, ng);
	call_rcu(&old_ng->rcu, net_generic_release);
assign:
	ng->ptr[id - 1] = data;
	return 0;
}
EXPORT_SYMBOL_GPL(net_assign_generic);

#ifdef CONFIG_NET_NS
static void *netns_get(struct task_struct *task)
{
	struct net *net = NULL;
	struct nsproxy *nsproxy;

	rcu_read_lock();
	nsproxy = task_nsproxy(task);
	if (nsproxy)
		net = get_net(nsproxy->net_ns);
	rcu_read_unlock();

	return net;
}

static void netns_put(void *ns)
{
	put_net(ns);
}

static int netns_install(struct nsproxy *nsproxy, void *ns)
{
	put_net(nsproxy->net_ns);
	nsproxy->net_ns = get_net(ns);
	return 0;
}

static unsigned int netns_inum(void *ns)
{
	struct net *net = ns;
	return net->proc_inum;
}

const struct proc_ns_operations netns_operations = {
	.name		= "net",
	.type		= CLONE_NEWNET,
	.get		= netns_get,
	.put		= netns_put,
	.install	= netns_install,
	.inum		= netns_inum,
};
#endif

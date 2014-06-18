#include <linux/err.h>
#include <linux/igmp.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/rculist.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <net/netlink.h>
#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
#include <net/ipv6.h>
#endif

#include "br_private.h"

static int br_rports_fill_info(struct sk_buff *skb, struct netlink_callback *cb,
			       struct net_device *dev)
{
	struct net_bridge *br = netdev_priv(dev);
	struct net_bridge_port *p;
	struct hlist_node *n;
	struct nlattr *nest;
	int ret = 0;

	spin_lock_bh(&br->multicast_lock);
	if (!br->multicast_router || hlist_empty(&br->router_list))
		goto unlock;

	nest = nla_nest_start(skb, MDBA_ROUTER);
	if (nest == NULL) {
		ret = -EMSGSIZE;
		goto unlock;
	}

	hlist_for_each_entry(p, n, &br->router_list, rlist) {
		if (p && nla_put_u32(skb, MDBA_ROUTER_PORT, p->dev->ifindex))
			goto fail;
	}

	nla_nest_end(skb, nest);
unlock:
	spin_unlock_bh(&br->multicast_lock);
	return ret;
fail:
	nla_nest_cancel(skb, nest);
	ret = -EMSGSIZE;
	goto unlock;
}

static int br_mdb_fill_info(struct sk_buff *skb, struct netlink_callback *cb,
			    struct net_device *dev)
{
	struct net_bridge *br = netdev_priv(dev);
	struct net_bridge_mdb_htable *mdb;
	struct nlattr *nest, *nest2;
	int i, err = 0;
	int idx = 0, s_idx = cb->args[1];

	spin_lock_bh(&br->multicast_lock);
	if (br->multicast_disabled)
		goto unlock;

	mdb = br->mdb;
	if (!mdb)
		goto unlock;

	nest = nla_nest_start(skb, MDBA_MDB);
	if (nest == NULL) {
		err = -EMSGSIZE;
		goto unlock;
	}

	for (i = 0; i < mdb->max; i++) {
		struct hlist_node *h;
		struct net_bridge_mdb_entry *mp;
		struct net_bridge_port_group *p, **pp;
		struct net_bridge_port *port;

		hlist_for_each_entry(mp, h, &mdb->mhash[i], hlist[mdb->ver]) {
			if (idx < s_idx)
				goto skip;

			nest2 = nla_nest_start(skb, MDBA_MDB_ENTRY);
			if (nest2 == NULL) {
				err = -EMSGSIZE;
				goto out;
			}

			for (pp = &mp->ports;
			     (p = *pp);
			      pp = &p->next) {
				port = p->port;
				if (port) {
					struct br_mdb_entry e;
					e.ifindex = port->dev->ifindex;
					if (p->addr.proto == htons(ETH_P_IP))
						e.addr.u.ip4 = p->addr.u.ip4;
#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
					if (p->addr.proto == htons(ETH_P_IPV6))
						e.addr.u.ip6 = p->addr.u.ip6;
#endif
					e.addr.proto = p->addr.proto;
					if (nla_put(skb, MDBA_MDB_ENTRY_INFO, sizeof(e), &e)) {
						nla_nest_cancel(skb, nest2);
						err = -EMSGSIZE;
						goto out;
					}
				}
			}
			nla_nest_end(skb, nest2);
		skip:
			idx++;
		}
	}

out:
	cb->args[1] = idx;
	nla_nest_end(skb, nest);
unlock:
	spin_unlock_bh(&br->multicast_lock);
	return err;
}

static int br_mdb_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct net_device *dev;
	struct net *net = sock_net(skb->sk);
	struct nlmsghdr *nlh = NULL;
	int idx = 0, s_idx;

	s_idx = cb->args[0];

	for_each_netdev(net, dev) {
		if (dev->priv_flags & IFF_EBRIDGE) {
			struct br_port_msg *bpm;

			if (idx < s_idx)
				goto skip;

			nlh = nlmsg_put(skb, NETLINK_CB(cb->skb).pid,
					cb->nlh->nlmsg_seq, RTM_GETMDB,
					sizeof(*bpm), NLM_F_MULTI);
			if (nlh == NULL)
				break;

			bpm = nlmsg_data(nlh);
			bpm->ifindex = dev->ifindex;
			if (br_mdb_fill_info(skb, cb, dev) < 0)
				goto out;
			if (br_rports_fill_info(skb, cb, dev) < 0)
				goto out;

			cb->args[1] = 0;
			nlmsg_end(skb, nlh);
		skip:
			idx++;
		}
	}

out:
	if (nlh)
		nlmsg_end(skb, nlh);
	cb->args[0] = idx;
	return skb->len;
}

void br_mdb_init(void)
{
	rtnl_register(PF_BRIDGE, RTM_GETMDB, NULL, br_mdb_dump, NULL);
}

void br_mdb_uninit(void)
{
	rtnl_unregister(PF_BRIDGE, RTM_GETMDB);
}

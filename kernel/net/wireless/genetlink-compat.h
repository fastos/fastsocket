#ifndef GENETLINK_COMPAT_H
#define GENETLINK_COMPAT_H

#include <net/genetlink.h>

struct compat_genl_info {
	struct genl_info *info;

	u32 snd_seq;
	u32 snd_pid;
	struct genlmsghdr *genlhdr;
	struct nlattr **attrs;
	void *user_ptr[2];
};
#define genl_info compat_genl_info

struct compat_genl_ops {
	struct genl_ops ops;

	u8 cmd;
	u8 internal_flags;
	unsigned int flags;
	const struct nla_policy *policy;

	int (*doit)(struct sk_buff *skb, struct genl_info *info);
	int (*dumpit)(struct sk_buff *skb, struct netlink_callback *cb);
	int (*done)(struct netlink_callback *cb);
};
#define genl_ops compat_genl_ops

struct compat_genl_family {
	struct genl_family family;

	struct list_head list;

	unsigned int id, hdrsize, version, maxattr;
	const char *name;
	bool netnsok;

	struct nlattr **attrbuf;

	int (*pre_doit)(struct genl_ops *ops, struct sk_buff *skb,
			struct genl_info *info);

	void (*post_doit)(struct genl_ops *ops, struct sk_buff *skb,
			  struct genl_info *info);
};

#define genl_family compat_genl_family

#define genl_register_family_with_ops compat_genl_register_family_with_ops

int genl_register_family_with_ops(struct genl_family *family,
				  struct genl_ops *ops, size_t n_ops);

#define genl_unregister_family compat_genl_unregister_family

int genl_unregister_family(struct genl_family *family);

#define genl_info_net(_info) genl_info_net((_info)->info)

#define genlmsg_reply(_msg, _info) genlmsg_reply(_msg, (_info)->info)
#define genlmsg_put(_skb, _pid, _seq, _fam, _flags, _cmd) genlmsg_put(_skb, _pid, _seq, &(_fam)->family, _flags, _cmd)
#define genl_register_mc_group(_fam, _grp) genl_register_mc_group(&(_fam)->family, _grp)
#define genl_unregister_mc_group(_fam, _grp) genl_unregister_mc_group(&(_fam)->family, _grp)
#define genl_dump_check_consistent(cb, user_hdr, _fam) genl_dump_check_consistent(cb, user_hdr, &(_fam)->family)

#endif /* GENETLINK_COMPAT_H */

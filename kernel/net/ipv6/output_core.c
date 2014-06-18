/*
 * IPv6 library code, needed by static components when full IPv6 support is
 * not configured or static.  These functions are needed by GSO/GRO implementation.
 */
#include <linux/export.h>
#include <net/ipv6.h>
#include <net/ip6_fib.h>

static u32 hashidentrnd __read_mostly;
#define FID_HASH_SZ 16
static u32 ipv6_fragmentation_id[FID_HASH_SZ];

void __init initialize_hashidentrnd(void)
{
	get_random_bytes(&hashidentrnd, sizeof(hashidentrnd));
}

static u32 __ipv6_select_ident(const struct in6_addr *addr)
{
	u32 newid, oldid, hash = jhash2((u32 *)addr, 4, hashidentrnd);
	u32 *pid = &ipv6_fragmentation_id[hash % FID_HASH_SZ];

	do {
		oldid = *pid;
		newid = oldid + 1;
		if (!(hash + newid))
			newid++;
	} while (cmpxchg(pid, oldid, newid) != oldid);

	return hash + newid;
}

void ipv6_select_ident(struct frag_hdr *fhdr, struct in6_addr *addr)
{
	fhdr->identification = htonl(__ipv6_select_ident(addr));
}
EXPORT_SYMBOL(ipv6_select_ident);

int ip6_find_1stfragopt(struct sk_buff *skb, u8 **nexthdr)
{
	u16 offset = sizeof(struct ipv6hdr);
	struct ipv6_opt_hdr *exthdr =
				(struct ipv6_opt_hdr *)(ipv6_hdr(skb) + 1);
	unsigned int packet_len = skb->tail - skb->network_header;
	int found_rhdr = 0;
	*nexthdr = &ipv6_hdr(skb)->nexthdr;

	while (offset + 1 <= packet_len) {

		switch (**nexthdr) {

		case NEXTHDR_HOP:
			break;
		case NEXTHDR_ROUTING:
			found_rhdr = 1;
			break;
		case NEXTHDR_DEST:
#if defined(CONFIG_IPV6_MIP6) || defined(CONFIG_IPV6_MIP6_MODULE)
			if (ipv6_find_tlv(skb, offset, IPV6_TLV_HAO) >= 0)
				break;
#endif
			if (found_rhdr)
				return offset;
			break;
		default :
			return offset;
		}

		offset += ipv6_optlen(exthdr);
		*nexthdr = &exthdr->nexthdr;
		exthdr = (struct ipv6_opt_hdr *)(skb_network_header(skb) +
						 offset);
	}

	return offset;
}
EXPORT_SYMBOL(ip6_find_1stfragopt);

#pragma once

struct frag_key {
	__be32 saddr;
	__be32 daddr;
	__be32 ipid;
};

struct frag_info {
	__u64	timeout;
	size_t	len;
	size_t	tot_len;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct frag_key);
	__type(value, struct frag_info);
	__uint(max_entries, 1000);
} fw_frag_list SEC(".maps");

#define IP_FLAG_MF 0x2000
#define IP_FRAG_OFFSET 0x1FFF
static __always_inline int fw_packet_is_fragment(const struct iphdr *iph)
{
	if (iph->frag_off & bpf_htons(IP_FLAG_MF | IP_FRAG_OFFSET))
		return 1;
	return 0;
}

static __always_inline int fw_ip_fragment(struct xbuf *xbuf, int *action)
{
	struct iphdr *iph = xbuf_ip_hdr(xbuf);
	struct frag_key fk;
	struct frag_info *fi;
	int frag_len;

	if (!fw_packet_is_fragment(iph))
		return 0;

	if ((iph->frag_off & bpf_htons(IP_FRAG_OFFSET)) == 0) {
		xbuf->flags |= XBUF_FLAG_IP_FRAG;
		return 0;
	}

	*action = FW_DROP;
	fk.saddr = iph->saddr;
	fk.daddr = iph->daddr;
	fk.ipid = iph->id;
	fi = bpf_map_lookup_elem(&fw_frag_list, &fk);
	/* If no entry is found, the packet is dropped */
	if (!fi) {
		return 1;
	}
	if (fi->timeout < bpf_jiffies64()) {
		return 1;
	}
	if ((fi->tot_len && fi->len >= fi->tot_len) || fi->len > 65515) {
		return 1;
	}
	
	frag_len = bpf_ntohs(iph->tot_len) - iph->ihl * 4;
	__sync_fetch_and_add(&fi->len, frag_len);
	pr_dbg("Fragment list len %d <= tot_len %d\n", fi->len, fi->tot_len);
	if ((iph->frag_off & bpf_htons(IP_FLAG_MF)) == 0) {
		int offset = bpf_ntohs(iph->frag_off) & IP_FRAG_OFFSET;
		offset *= 8;
		fi->tot_len = offset + frag_len;
		pr_dbg("Last fragment tot_len set to %d, current len %d\n", fi->tot_len, fi->len);
	} 

	*action = FW_PASS;
	return 1;
}

/* An entry is created if the first fragment is allowed. The remaining 
 * fragments will be allowed based on this entry
 */
static __always_inline void fw_ip_fragment_finish(const struct xbuf *xbuf)
{
	struct iphdr *iph = xbuf_ip_hdr(xbuf);
	struct frag_key fk;
	struct frag_info fi;

	if (!(xbuf->flags & XBUF_FLAG_IP_FRAG))
		return;
	fk.saddr = iph->saddr;
	fk.daddr = iph->daddr;
	fk.ipid = iph->id;
	fi.len = bpf_ntohs(iph->tot_len) - iph->ihl * 4;
	fi.tot_len = 0;
	fi.timeout = bpf_jiffies64() + 30 * HZ;
	pr_dbg("create new fi %x -> %x, ipid %x\n", iph->saddr, iph->daddr, iph->id);
	bpf_map_update_elem(&fw_frag_list, &fk, &fi, BPF_ANY);
}


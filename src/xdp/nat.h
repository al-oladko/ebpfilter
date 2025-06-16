// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2025 Aleksei Oladko <aleks.oladko@gmail.com>
#pragma once

#include "fw_nat.h"
#include "progtable.h"

#define NAT_TIMEOUT 300

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct fw_nat_rule);
	__uint(max_entries, 1);
} fw_nat SEC(".maps");

struct fw_nat_entry {
	__be32	orig_ip;
	__be16	orig_port;;
	__u64	timeout;
};

struct fw4_nat_tuple {
	__be32 addr;
	union {
		struct {
			__be16 sport;
			__be16 dport;
		};
		struct {
			__u8 icmp_type;
			__u8 icmp_code;
			__be16 icmp_id;
		};
	};
	__be32 l4protocol; /* 32bit bound for map keys */
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct fw4_nat_tuple);
	__type(value, struct fw_nat_entry);
	__uint(max_entries, FW_CT_MAX);
} fw_nat_table SEC(".maps");

static __always_inline __u16 csum_fold(__wsum csum) {
	csum = (csum & 0xffff) + (csum >> 16);
	csum += (csum >> 16);
	return ~csum;
}

static __always_inline __u32 csum_add(__u32 csum, __u32 delta) {
    csum += delta;
    return csum + (csum < delta);
}

static __always_inline bool fw_nat_is_expired(const struct fw_nat_entry *nat)
{
	return nat->timeout < bpf_jiffies64();
}

static __always_inline int fw_nat_input(struct xbuf *xbuf,
					struct fw4_tuple *key)
{
	struct iphdr *iph = xbuf_ip_hdr(xbuf);
	struct fw_nat_rule *rnat;
	struct fw4_tuple invert_key;
	struct fw4_nat_tuple *nat_key;
	struct fw_nat_entry *nat_entry;
	int rkey = 0;
	__wsum csum;

	if (!xbuf_is_rx(xbuf))
		return 0;

	rnat = bpf_map_lookup_elem(&fw_nat, &rkey);
	if (!rnat || rnat->to_addr == 0 || iph->daddr != rnat->to_addr)
		return 0;

	get_invert_tuple(key, &invert_key);
	nat_key = (struct fw4_nat_tuple *)&invert_key.daddr;
	nat_entry = bpf_map_lookup_elem(&fw_nat_table, nat_key);
	if (!nat_entry)
		return 0;

	/* let the linux kernel stack deal with this packet */
	if (fw_nat_is_expired(nat_entry))
		return 0;
	
	csum = bpf_csum_diff(&iph->daddr, sizeof(iph->daddr), &nat_entry->orig_ip, sizeof(nat_entry->orig_ip), (__u32)~iph->check);
	iph->daddr = nat_entry->orig_ip;
	iph->check = csum_fold(csum);
	if (key->l4protocol == IPPROTO_TCP) {
		struct tcphdr *tcph = xbuf_tcp_hdr(xbuf);

		if (!xbuf_check_access(xbuf, tcph, sizeof(*tcph)))
			return -1;
		csum = bpf_csum_diff(&rnat->to_addr, sizeof(rnat->to_addr), &nat_entry->orig_ip, sizeof(nat_entry->orig_ip), (__u32)~tcph->check);
		tcph->check = csum_fold(csum);
	}
	if (key->l4protocol == IPPROTO_UDP) {
		struct udphdr *udph = xbuf_udp_hdr(xbuf);

		if (!xbuf_check_access(xbuf, udph, sizeof(*udph)))
			return -1;
		csum = bpf_csum_diff(&rnat->to_addr, sizeof(rnat->to_addr), &nat_entry->orig_ip, sizeof(nat_entry->orig_ip), (__u32)~udph->check);
		udph->check = csum_fold(csum);
	}

	return 0;
}

static __always_inline int fw_do_nat_output(struct xbuf *xbuf,
					 const struct fw4_tuple *key)
{
	struct iphdr *iph = xbuf_ip_hdr(xbuf);
	struct fw_nat_rule *rnat;
	struct fw_nat_entry *nat_entry;
	struct fw4_nat_tuple *nat_key;
	int rkey = 0;
	__u64 timeout;
	bool expired;
	int ret;

	if (!xbuf_is_tx(xbuf))
		return 0;

	rnat = bpf_map_lookup_elem(&fw_nat, &rkey);
	if (!rnat || rnat->to_addr == 0)
		return 0;

	nat_key = (struct fw4_nat_tuple *)&key->daddr;
	nat_entry = bpf_map_lookup_elem(&fw_nat_table, nat_key);
	if (!nat_entry) {
		int ret;
		struct fw_nat_entry nat;
		nat_entry = &nat;
		nat_entry->orig_port = 0;
		nat_entry->orig_ip = iph->saddr;
		nat_entry->timeout = bpf_jiffies64() + NAT_TIMEOUT * HZ;
		ret = bpf_map_update_elem(&fw_nat_table, nat_key, nat_entry, BPF_NOEXIST);
		/* TODO change source port/echo id and create a new record */
		if (ret < 0)
			return ret;
	} else {
		expired = fw_nat_is_expired(nat_entry);
		if (nat_entry->orig_ip != iph->saddr && !expired)
			/* TODO change source port/echo id and create a new record */
			return -1;

		timeout = bpf_jiffies64() + NAT_TIMEOUT * HZ;
		if (expired) {
			__u64 old = nat_entry->timeout;
			__u64 res = atomic64_cmpxchg(&nat_entry->timeout, old, timeout);
			if (old != res)
				/* TODO change source port/echo id and create a new record */
				return -1;
		} else {
			/* update timeout */
			nat_entry->timeout = timeout;
		}
	}

	iph->saddr = rnat->to_addr;
	ret = bpf_l3_csum_replace(xbuf->skb, xbuf_get_offset(xbuf, &iph->check), nat_entry->orig_ip, rnat->to_addr, 4);
	if (ret < 0)
		return ret;
	if (key->l4protocol == IPPROTO_TCP) {
		struct tcphdr *tcph = xbuf_tcp_hdr(xbuf);
		if (!xbuf_check_access(xbuf, tcph, sizeof(*tcph)))
			return -1;
		bpf_l4_csum_replace(xbuf->skb, xbuf_get_offset(xbuf, &tcph->check), nat_entry->orig_ip, rnat->to_addr, BPF_F_PSEUDO_HDR | 4);
	}
	if (key->l4protocol == IPPROTO_UDP) {
		struct udphdr *udph = xbuf_udp_hdr(xbuf);
		if (!xbuf_check_access(xbuf, udph, sizeof(*udph)))
			return -1;
		bpf_l4_csum_replace(xbuf->skb, xbuf_get_offset(xbuf, &udph->check),
				    nat_entry->orig_ip, rnat->to_addr,
				    BPF_F_PSEUDO_HDR | 4);
	}
	return 0;
}

SEC("tc")
int tc_nat(struct __sk_buff *skb)
{
	struct xbuf xbuf;
	struct fw4_tuple key;
	int ret;

	xbuf_skb_init(skb, &xbuf);
	ret = fw_ip_rcv_fast(&xbuf);
	if (ret == XDP_DROP)
		return TC_ACT_SHOT;

	fill_fw4_tuple(&xbuf, &key);
	ret = fw_do_nat_output(&xbuf, &key);
	if (ret < 0)
		return TC_ACT_SHOT;
	return TC_ACT_OK;
}

static __always_inline int fw_nat_output(const struct xbuf *xbuf)
{
	if (xbuf_is_tx(xbuf))
		return fw_bpf_goto(xbuf->skb, FW_PROG_TC_NAT);
	return XDP_PASS;
}

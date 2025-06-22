// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2025 Aleksei Oladko <aleks.oladko@gmail.com>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/types.h>
#include <stddef.h>
#include <stdbool.h>
#include <assert.h>

#include "fw_config.h"
#include "debug.h"
#include "atomic.h"
#include "xbuf.h"
#include "tuple.h"
#include "fw_rule.h"
#include "fragment.h"
#include "packet.h"
#include "connection.h"
#include "dpi.h"
#include "nat.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, int);
	__type(value, struct fw_rule_set);
} fw_rules_table SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} fw_table_generation SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct fw_rule_stats);
	__uint(max_entries, FW_MAX_RULES * 2);
} fw_stats SEC(".maps");

static __always_inline int get_fw_id(void)
{
	int key = 0;
	int *gen_id;

	gen_id = bpf_map_lookup_elem(&fw_table_generation, &key);
	if (!gen_id)
		return 0;
	return *gen_id;
}

static __always_inline bool fw_tuple_match(const struct fw_rule *rule, const struct fw4_tuple *key)
{
	if ((rule->smask & key->saddr) != rule->saddr) {
		return false;
	}
	if ((rule->dmask & key->daddr) != rule->daddr) {
		return false;
	}
	if (!rule->protocol)
		return true;
	if (rule->protocol != key->l4protocol) {
		return false;
	}
	if (key->l4protocol == IPPROTO_TCP || key->l4protocol == IPPROTO_UDP) {
		if (rule->sport && rule->sport != key->sport)
			return false;
		if (rule->dport && rule->dport != key->dport)
			return false;
	}
	if (key->l4protocol == IPPROTO_ICMP) {
		if (rule->icmp_type && rule->icmp_type != key->icmp_type) {
			return false;
		}
	}
	return true;
}

static __always_inline void fw_do_stat(struct xbuf *xbuf, int tid, int rule_num)
{
	struct fw_rule_stats *stat;
	int index = rule_num + tid * FW_MAX_RULES;

	stat = bpf_map_lookup_elem(&fw_stats, &index);
	if (!stat)
		return;
	stat->packets++;
	stat->bytes += xbuf->pkt_len;
}

static __always_inline bool fw_rule_l7_protocol(struct fw_conn *ct,
						struct fw_param *param,
						int action)
{
	struct rule_l7 *r = (struct rule_l7 *)param;

	/* TODO error message */
	static_assert(sizeof(struct rule_l7) <= sizeof(struct fw_param), "error");

	if (ct->dpi.protocol == r->protocol) {
		return true;
	}
	if (ct->dpi.excluded_protocols & (1 << r->protocol)) {
		return false;
	}
	ct->need_recheck = 1;
	if (action == FW_DROP) {
		return false;
	}
	return true;
}

static __always_inline bool fw_rule_connlimit(struct fw_conn *ct,
					      struct fw_param *param,
					      int action)
{
	struct connlimit *cl = (struct connlimit *)param;
	int need = cl->ct_cost;
	__u64 jiffies, old_jiffies, extra_ticks;
	int extra_budget = 0;

	static_assert(sizeof(struct connlimit) <= sizeof(struct fw_param), "error");

	if (ct->status == FW_CT_ESTABLISHED)
		return true;

	if (atomic_read(&cl->budget) >= cl->ct_cost) {
		/* another thread might have decremented the budget */
		if (atomic64_sub_return(&cl->budget, cl->ct_cost) >= 0) {
			return true;
		}
		/* money back */
		atomic64_add_return(&cl->budget, cl->ct_cost);
	}

	jiffies = bpf_jiffies64();
	if (cl->jiffies == 0)
		cl->jiffies = jiffies;
	old_jiffies = cl->jiffies;
	if (jiffies > old_jiffies &&
	    (jiffies - old_jiffies) * cl->tick_cost + cl->budget >= cl->ct_cost) {
		jiffies += cl->credit;
		extra_ticks = atomic64_cmpxchg((__s64 *)&cl->jiffies, old_jiffies, jiffies);
		extra_ticks = jiffies - extra_ticks;

		if (extra_ticks) {
			/* be greedy, spend the budget on yourself */
			extra_budget = extra_ticks * cl->tick_cost;
			if (extra_budget > cl->max_budget) {
				extra_budget = cl->max_budget;
			}

			if (extra_budget >= cl->ct_cost) {
				extra_budget -= cl->ct_cost;
				if (cl->max_budget - cl->budget < extra_budget)
					extra_budget = cl->max_budget - cl->budget;
				atomic64_add_return(&cl->budget, extra_budget);
				return true;
			}
			need = cl->ct_cost - extra_budget;
		}
	}

	if (atomic_read(&cl->budget) < need) {
		if (extra_budget)
			atomic64_add_return(&cl->budget, extra_budget);

		return false;
	}

	/* another thread increased the budget */
	if (atomic64_sub_return(&cl->budget, need) < 0) {
		/* return need + extra_budget,
		 * but this is exactly ct->ct_coss
		 */
		atomic64_add_return(&cl->budget, cl->ct_cost);
		return false;
	}

	return true;
}

static __always_inline bool fw_rule_check_params(struct fw_conn *ct, 
						 struct fw_rule *rule)
{
	int i;
	bool ret;

	for (i = 0; i < FW_RULE_MAX_PARAMS; i++) {
		struct fw_param *param = &rule->params[i];

		switch (param->type) {
		case FW_RULE_PARAM_NONE:
			return true;
		case FW_RULE_PARAM_L7_PROTOCOL:
			ret = fw_rule_l7_protocol(ct, param, rule->action);
			if (!ret)
				return false;
		case FW_RULE_PARAM_CONNLIMIT:
			ret = fw_rule_connlimit(ct, param, rule->action);
			if (!ret)
				return false;
		default:
			break;
		}
	}
	return true;
}

static __always_inline int fw_do_filter(struct xbuf *xbuf, struct fw_conn *ct, const struct fw4_tuple *key)
{
	int i;
	int table_index;
	int gen_id;
	struct fw_rule_set *fw_table;
	struct fw_rule *rule;

	gen_id = get_fw_id();
	if (ct->status == FW_CT_ESTABLISHED && ct->fw_table_genid == gen_id && 
	    ct->need_recheck == 0) {
		pr_dbg("Apply action to established connection %d, ct gen id %d, fw genid %d\n", 
							ct->fw_action, ct->fw_table_genid, gen_id);
		return ct->fw_action;
	}

	table_index = gen_id & 1;
	fw_table = bpf_map_lookup_elem(&fw_rules_table, &table_index);
	if (!fw_table)
		return 0;
	/* TODO fw_table DPI_RULES flag */
	if ((ct->status == FW_CT_NEW /*&& fw_table->flags & DPI_RULES */) ||
	    (ct->status == FW_CT_ESTABLISHED && ct->need_recheck)) {
		pr_dbg("Start DPI processing\n");
		fw_dpi(xbuf, ct);
		if (ct->status == FW_CT_ESTABLISHED && ct->dpi.status == DPI_IN_PROGRESS) {
			return ct->fw_action;
		}
	}
	ct->need_recheck = 0;

	for (i = 0; i < FW_MAX_RULES; i++) {
		rule = &fw_table->rules[i];

		if (!fw_tuple_match(rule, key))
			continue;
		if (!fw_rule_check_params(ct, rule))
			continue;

		pr_dbg("Rules: gen_id %d, table_index %d, rule %d\n", gen_id, table_index, i);
		ct->fw_action = rule->action;
		ct->fw_table_genid = gen_id;
		ct->fw_rule_num = i;
		return rule->action;
	}
	return 0;
}

static __always_inline int fw_packet_filter(struct xbuf *xbuf)
{
	struct fw_conn *ct;
	struct fw4_tuple key;
	int ret;
	int action;
	__u32 frag_l4;

	if (fw_ip_fragment(xbuf, &action, &frag_l4)) {
		/* TODO Add statistics for fragments */
		if (action == FW_DROP)
			return XDP_DROP;
		return fw_nat_fragment(xbuf, frag_l4);
	}

	ret = fill_fw4_tuple(xbuf, &key);
	if (ret) {
		if (ret < 0)
			return XDP_DROP;
		return XDP_PASS;
	}

	ret = fw_nat_input(xbuf, &key, false);
	if (ret < 0)
		return XDP_DROP;

	ct = fw_conn_get(xbuf, &key);
	if (!ct)
		return XDP_DROP;

	action = fw_do_filter(xbuf, ct, &key);
	fw_do_stat(xbuf, ct->fw_table_genid & 1, ct->fw_rule_num);
	if (action == FW_DROP) {
		ct->need_recheck = 0;
		return XDP_DROP;
	}

	fw_ip_fragment_finish(xbuf, &key);
	fw_conn_put(ct, &key);

	return fw_nat_output(xbuf);
}

static __always_inline bool fw_check_supported_l4proto(const struct iphdr *ip)
{
	return ip->protocol == IPPROTO_TCP ||
		ip->protocol == IPPROTO_UDP ||
		ip->protocol == IPPROTO_ICMP;
}

static __always_inline int fw_ip_rcv(struct xbuf *xbuf)
{
	struct iphdr *ip;
	unsigned int ip_len;
	int ret;

	ret = fw_l2_input(xbuf);
	if (ret == XDP_DROP)
		return ret;

	if (xbuf->l3proto != bpf_htons(ETH_P_IP)) 
		return XDP_PASS;

	ip = xbuf_ip_hdr(xbuf);
	if (!xbuf_check_access(xbuf, ip, sizeof(*ip)))
		return XDP_DROP;

	if (ip->version != 4)
		return XDP_DROP;
	if (ip->ihl < 5)
		return XDP_DROP;

	if (!xbuf_check_access(xbuf, ip, ip->ihl * 4))
		return XDP_DROP;

	ip_len = bpf_ntohs(ip->tot_len);
	if (ip_len > xbuf_network_packet_len(xbuf))
		return XDP_DROP;
	if (ip_len < xbuf_network_packet_len(xbuf))
		xbuf_set_len(xbuf, xbuf_network_hdr_offset(xbuf) + ip_len);
	if (ip->ihl * 4 > ip_len)
		return XDP_DROP;

	xbuf_set_transport_hdr(xbuf, ip->ihl * 4);

	if (!fw_check_supported_l4proto(ip))
		return XDP_PASS;

	return fw_packet_filter(xbuf);
}

SEC("xdp")
int xdp_rcv(struct xdp_md *ctx)
{
	struct xbuf xbuf;

	xbuf_xdp_init(ctx, &xbuf);
	return fw_ip_rcv(&xbuf);
}

SEC("tc")
int tc_rcv(struct __sk_buff *skb)
{
	struct xbuf xbuf;
	int ret;

	xbuf_skb_init(skb, &xbuf);
	ret = fw_ip_rcv(&xbuf);
	if (ret == XDP_DROP)
		return TC_ACT_SHOT;
	return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";

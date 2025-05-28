// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2025 Aleksei Oladko <aleks.oladko@gmail.com>
#pragma once

#include "fw_connection.h"
#include "fw_config.h"
#include "debug.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct fw4_tuple);
	__type(value, struct fw_conn);
	__uint(max_entries, FW_CT_MAX);
} fw_conn_tracker SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct fw_conn);
	__uint(max_entries, 1);
} fw_conn_tmpl SEC(".maps");

static __always_inline void fw_conn_init(struct fw_conn *ct)
{
	__builtin_memset(ct, 0, sizeof(*ct));
	ct->status = FW_CT_NEW;
}

static __always_inline struct fw_conn *fw_conn_create(void)
{
	struct fw_conn *ct;
	int i = 0;

	ct = bpf_map_lookup_elem(&fw_conn_tmpl, &i);
	if (!ct)
		return ct;
	fw_conn_init(ct);
	return ct;
}

static __always_inline void fw_conn_delete(const struct fw4_tuple *key)
{
	bpf_map_delete_elem(&fw_conn_tracker, key);
}

/* timeout in sec */
static __always_inline void fw_conn_set_timeout(struct fw_conn *ct, int sec)
{
	ct->timeout = bpf_jiffies64() + sec * HZ;
}

static __always_inline bool fw_conn_is_expired(const struct fw_conn *ct)
{
	return ct->timeout < bpf_jiffies64();
}

#define TCP_STATE_NONE		0
#define TCP_STATE_HANDSHAKE_1	1
#define TCP_STATE_HANDSHAKE_2	2
//#define TCP_STATE_HANDSHAKE_3	3
#define TCP_STATE_ESTABLISHED	4
#define TCP_STATE_FIN1		5
#define TCP_STATE_FIN2		6
#define TCP_STATE_FIN		7
#define TCP_STATE_CLOSED	8
#define TCP_STATE_INVALID	9
#define TCP_STATE_REOPEN	10

#define TCP_PACKET_SYN		1
#define TCP_PACKET_SYNACK	2
#define TCP_PACKET_ACK		3
//#define TCP_PACKET_ACK_DATA	4
#define TCP_PACKET_FIN		5
#define TCP_PACKET_RST		6
#define TCP_PACKET_INVALID	7

static __always_inline __u8 fw_tcp_flags(const struct tcphdr *tcph)
{
	__u8 *ptr = (__u8 *)&tcph->ack_seq;
	return *(ptr + sizeof(tcph->ack_seq) + 1);
}

//#define TCP_FLAG_FIN 0X01
#define TCP_FLAG_SYN 0x02
//#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_ECE 0x40
#define TCP_FLAG_CWR 0x80
static __always_inline __u8 fw_tcp_type(const struct tcphdr *tcph)
{
	__u8 flags = fw_tcp_flags(tcph);

	if (!flags)
		return TCP_PACKET_INVALID;

	if (tcph->syn) {
		flags &= ~(TCP_FLAG_PSH|TCP_FLAG_ECE|TCP_FLAG_CWR);
		if (TCP_FLAG_SYN == flags) {
			return TCP_PACKET_SYN;
		}
		if (flags == (TCP_FLAG_SYN | TCP_FLAG_ACK)) {
			return TCP_PACKET_SYNACK;
		}
		return TCP_PACKET_INVALID;
	}
	if (tcph->rst)
		return TCP_PACKET_RST;
	if (tcph->fin)
		return TCP_PACKET_FIN;

	if (!tcph->ack)
		return TCP_PACKET_INVALID;

	return TCP_PACKET_ACK;
}

static __always_inline __u8 fw_tcp_state(const struct xbuf *xbuf,
					 struct fw_conn *ct,
					 const __u8 packet_type)
{
	switch (packet_type) {
	case TCP_PACKET_SYN:
		if (xbuf->payload_len != 0) {
			ct->tcp_state = TCP_STATE_INVALID;
			break;
		}
		if (ct->tcp_state == TCP_STATE_NONE) {
			ct->tcp_state = TCP_STATE_HANDSHAKE_1;
			break;
		}
		/* retransmit */
		if (xbuf->ct_dir == FWCT_DIR_FORWARD &&
		    ct->tcp_state <= TCP_STATE_HANDSHAKE_2) {
			break;
		}
		if (ct->tcp_state == TCP_STATE_FIN ||
		    ct->tcp_state == TCP_STATE_CLOSED) {
			ct->tcp_state = TCP_STATE_REOPEN;
			break;
		}
		ct->tcp_state = TCP_STATE_INVALID;
		break;
	case TCP_PACKET_SYNACK:
		/* synack in the same way that syn before */
		if (xbuf->ct_dir == FWCT_DIR_FORWARD) {
			ct->tcp_state = TCP_STATE_INVALID;
			break;
		}
		/* syn -> synack */
		if (ct->tcp_state == TCP_STATE_HANDSHAKE_1) {
			ct->tcp_state = TCP_STATE_HANDSHAKE_2;
			break;
		}
		if (ct->tcp_state > TCP_STATE_FIN2) {
			ct->tcp_state = TCP_STATE_INVALID;
		}
		break;
	case TCP_PACKET_ACK:
		if (ct->tcp_state < TCP_STATE_ESTABLISHED) {
			if (xbuf->ct_dir == FWCT_DIR_FORWARD &&
			    xbuf->payload_len == 0) {
				/* last ack */
				ct->tcp_state = TCP_STATE_ESTABLISHED;
			} else {
				/* haven't seen synack yet */
				ct->tcp_state = TCP_STATE_INVALID;
			}
		}
		break;
	case TCP_PACKET_FIN:
		/* fin before handshake was finished */
		if (ct->tcp_state < TCP_STATE_ESTABLISHED) {
			ct->tcp_state = TCP_STATE_INVALID;
			break;
		}
		if (xbuf->ct_dir == FWCT_DIR_FORWARD) {
			if (ct->tcp_state == TCP_STATE_FIN2)
				ct->tcp_state = TCP_STATE_FIN;
			else
				ct->tcp_state = TCP_STATE_FIN1;
		} else {
			if (ct->tcp_state == TCP_STATE_FIN1)
				ct->tcp_state = TCP_STATE_FIN;
			else
				ct->tcp_state = TCP_STATE_FIN2;
		}
		break;
	case TCP_PACKET_RST:
		ct->tcp_state = TCP_STATE_CLOSED;
		break;
	default:
		ct->tcp_state = TCP_STATE_INVALID;
		break;
	}
	return ct->tcp_state;
}

static __always_inline int fw_tcp_process(struct xbuf *xbuf, struct fw_conn *ct)
{
	struct tcphdr *tcph = xbuf_tcp_hdr(xbuf);
	size_t tcph_len;
	__u8 packet_type;
	__u8 state;

	if (!xbuf_check_access(xbuf, tcph, sizeof(struct tcphdr)))
		return -1;

	tcph_len = tcph->doff * 4;
	/* sanity checks */
	if (tcph_len < sizeof(*tcph))
		return -1;
	if (tcph_len > sizeof(*tcph)) {
		/* malwormed tcp packet */
		if (!xbuf_check_access(xbuf, tcph, tcph_len))
			return -1;
	}
	xbuf_set_payload(xbuf, (unsigned char *)tcph + tcph->doff * 4);
/*
	syn [o] -> syn+ack [r] -> ack [o] -> data (established) [b] -> fin [b] -> fin [b]
	rst at any time in both direction
*/
	packet_type = fw_tcp_type(tcph);
	if (packet_type == TCP_PACKET_INVALID) {
		pr_dbg("TCP invalid packet\n");
	}
	state = fw_tcp_state(xbuf, ct, packet_type);
	pr_dbg("TCP state: %d\n", state);
	if (state == TCP_STATE_REOPEN) {
		pr_dbg("TCP reopen!!!: %d\n", state);
		fw_conn_init(ct);
		state = TCP_STATE_HANDSHAKE_1;
		ct->tcp_state = state;
		if (xbuf->ct_dir == FWCT_DIR_REPLY) {
			ct->revert_dir = 1;
			xbuf->ct_dir = FWCT_DIR_FORWARD;
		}
	}
	/* timeout */
	if (state < TCP_STATE_ESTABLISHED) {
		fw_conn_set_timeout(ct, 120);
	} else if (state == TCP_STATE_ESTABLISHED) {
		fw_conn_set_timeout(ct, 300);
	} else {
		fw_conn_set_timeout(ct, 60);
	}
	return 0;
}

static __always_inline int fw_udp_process(struct xbuf *xbuf, struct fw_conn *ct)
{
	struct udphdr *udph = xbuf_udp_hdr(xbuf);

	if (bpf_ntohs(udph->len) < sizeof(*udph))
		return -1;
	xbuf_set_payload(xbuf, (unsigned char *)xbuf_udp_hdr(xbuf) + sizeof(struct udphdr));
	/* TODO check fragment
	if (bpf_ntohs(udph->len) > xbuf->payload_len && not fragment)
		return -1;
	*/
	fw_conn_set_timeout(ct, 120);
	return 0;
}

static __always_inline int fw_icmp_process(struct xbuf *xbuf, struct fw_conn *ct)
{
	(void)xbuf;
	/* TODO: extract encapsulated IP + TCP/UDP headers from ICMP message
	 * and associate them with the corresponding ct
	 */
	fw_conn_set_timeout(ct, 30);
	return 0;
}

static __always_inline struct fw_conn *fw_conn_lookup(struct xbuf *xbuf, const struct fw4_tuple *key)
{
	struct fw4_tuple invert_key;
	struct fw_conn *ct;

	xbuf->ct_dir = FWCT_DIR_FORWARD;
	ct = bpf_map_lookup_elem(&fw_conn_tracker, key);
	if (ct) {
		if (fw_conn_is_expired(ct)) {
			fw_conn_init(ct);
		}
		return ct;
	}
	get_invert_tuple(key, &invert_key);
	ct = bpf_map_lookup_elem(&fw_conn_tracker, &invert_key);
	if (ct) {
		if (fw_conn_is_expired(ct)) {
			fw_conn_delete(key);
			goto out;
		} else {
			xbuf->ct_dir = FWCT_DIR_REPLY;
		}
		return ct;
	}
out:
	return fw_conn_create();
}


static __always_inline struct fw_conn *fw_conn_get(struct xbuf *xbuf, const struct fw4_tuple *key)
{
	struct fw_conn *ct;
	int ret;

	ct = fw_conn_lookup(xbuf, key);
	if (!ct)
		return ct;
	ct->ppc++;

	switch (key->l4protocol) {
	case IPPROTO_TCP:
		if (ct->revert_dir)
			xbuf->ct_dir ^= ct->revert_dir;
		ret = fw_tcp_process(xbuf, ct);
		if (ret < 0)
			return NULL;
		break;
	case IPPROTO_UDP:
		fw_udp_process(xbuf, ct);
		break;
	case IPPROTO_ICMP:
		fw_icmp_process(xbuf, ct);
		break;
	default:
		break;
	}

	return ct;
}

static __always_inline void fw_conn_put(struct fw_conn *ct, const struct fw4_tuple *key)
{
	if (ct->status == FW_CT_NEW) {
		ct->status = FW_CT_ESTABLISHED;
		bpf_map_update_elem(&fw_conn_tracker, key, ct, BPF_NOEXIST);
	}
}

// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2025 Aleksei Oladko <aleks.oladko@gmail.com>
#pragma once

struct fw4_tuple {
	__be32 saddr;
	__be32 daddr;
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
	//__u8 l4protocol;
	__be32 l4protocol; /* 32bit bound for map keys */
};

static __always_inline void get_invert_tuple(const struct fw4_tuple *key,
					     struct fw4_tuple *invert_key)
{
	invert_key->saddr = key->daddr;
	invert_key->daddr = key->saddr;
	invert_key->l4protocol = key->l4protocol;
	if (key->l4protocol == IPPROTO_ICMP) {
		invert_key->icmp_type = 0;
		invert_key->icmp_code = 0;
		if (key->icmp_type == ICMP_ECHO)
			invert_key->icmp_type = ICMP_ECHOREPLY;
		if (key->icmp_type == ICMP_ECHOREPLY)
			invert_key->icmp_type = ICMP_ECHO;
		invert_key->icmp_id = key->icmp_id;
		return;
	}
	invert_key->sport = key->dport;
	invert_key->dport = key->sport;
}

static __always_inline int fill_fw4_tuple(const struct xbuf *xbuf,
					   struct fw4_tuple *tuple)
{
	struct iphdr *iph = xbuf_ip_hdr(xbuf);
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct icmphdr *icmph;

	tuple->saddr = iph->saddr;
	tuple->daddr = iph->daddr;
	tuple->l4protocol = iph->protocol;

	switch (iph->protocol) {
		case IPPROTO_TCP:
			tcph = xbuf_tcp_hdr(xbuf);

			if (!xbuf_check_access(xbuf, tcph, sizeof(struct tcphdr)))
				return -1;
			tuple->sport = tcph->source;
			tuple->dport = tcph->dest;
			break;
		case IPPROTO_UDP:
			udph = xbuf_udp_hdr(xbuf);

			if (!xbuf_check_access(xbuf, udph, sizeof(struct udphdr)))
				return -1;
			tuple->sport = udph->source;
			tuple->dport = udph->dest;
			break;
		case IPPROTO_ICMP:
			icmph = xbuf_icmp_hdr(xbuf);

			if (!xbuf_check_access(xbuf, icmph, sizeof(struct icmphdr)))
				return -1;
			tuple->icmp_type = icmph->type;
			tuple->icmp_code = icmph->code;
			tuple->icmp_id = 0;
			if (icmph->type == ICMP_ECHO || icmph->type == ICMP_ECHOREPLY)
				tuple->icmp_id = icmph->un.echo.id;
			break;
		default:
			return 1;
	}
	return 0;
}

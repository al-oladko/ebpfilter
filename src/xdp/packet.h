// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2025 Aleksei Oladko <aleks.oladko@gmail.com>
#pragma once

#define VLAN_HLEN 4

struct vlan_hdr {
	__be16 h_vlan_tci;
	__be16 h_vlan_encap_proto;
};

static __always_inline int fw_l2_input(struct xbuf *xbuf)
{
	struct ethhdr *eth = xbuf_ethhdr(xbuf);
	__be16 proto = eth->h_proto;
	__u16 l3_offset = ETH_HLEN;

	if (!xbuf_check_access(xbuf, xbuf_ethhdr(xbuf), ETH_HLEN))
		return XDP_DROP;

	if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vlan = (struct vlan_hdr *)(xbuf_packet_data(xbuf) + ETH_HLEN);

		if (!xbuf_check_access(xbuf, vlan, sizeof(*vlan)))
			return XDP_DROP;

		proto = vlan->h_vlan_encap_proto;
		l3_offset += sizeof(*vlan);
	}

	xbuf->l3proto = proto;
	xbuf_set_network_hdr(xbuf, l3_offset);
	return XDP_PASS;
}

static __always_inline int fw_ip_rcv_fast(struct xbuf *xbuf)
{
	struct iphdr *ip;
	int ret;

	ret = fw_l2_input(xbuf);
	if (ret == XDP_DROP)
		return ret;

	ip = xbuf_ip_hdr(xbuf);
	if (!xbuf_check_access(xbuf, ip, sizeof(*ip)))
		return XDP_DROP;

	xbuf_set_transport_hdr(xbuf, ip->ihl * 4);

	return XDP_PASS;
}

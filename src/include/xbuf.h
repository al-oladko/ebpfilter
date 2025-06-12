// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2025 Aleksei Oladko <aleks.oladko@gmail.com>
#pragma once

#define XBUF_FLAG_IP_FRAG	0x01
struct xbuf {
	struct xdp_md		*ctx;
	struct __sk_buff	*skb;
	unsigned char		*data;
	unsigned char		*data_end;
	unsigned int		pkt_len;
	unsigned int		len;
#ifdef XBUF_USE_OFFSET
	__u16			network_hdr_offset;
	__u16			transport_hdr_offset;
#else
	unsigned char		*network_hdr;
	unsigned char		*transport_hdr;
#endif
	unsigned char		*payload;
	__u16			l3proto;
	__u16			payload_len;
	__u8			ct_dir;
	__u8			dpi_processed;
	int			flags;
};

static __always_inline void xbuf_set_len(struct xbuf *xbuf, int pkt_len)
{
	xbuf->pkt_len = pkt_len;
}

static __always_inline void xbuf_init(struct xbuf *xbuf,
				      unsigned char *data,
				      unsigned char *data_end)
{
	unsigned int pkt_len = data_end - data;
	xbuf->data = data;
	xbuf->data_end = data_end;
	xbuf->pkt_len = xbuf->len = pkt_len;
	xbuf->payload = xbuf->data;
	xbuf->payload_len = 0;
	xbuf->dpi_processed = 0;
	xbuf->flags = 0;
}

static __always_inline void xbuf_xdp_init(struct xdp_md *ctx, struct xbuf *xbuf)
{
	unsigned char *data_end = (unsigned char *)(long)ctx->data_end;
	unsigned char *data = (unsigned char *)(long)ctx->data;
	xbuf->ctx = ctx;
	xbuf->skb = NULL;
	xbuf_init(xbuf, data, data_end);
}

static __always_inline void xbuf_skb_init(struct __sk_buff *skb, struct xbuf *xbuf)
{
	unsigned char *data_end = (unsigned char *)(long)skb->data_end;
	unsigned char *data = (unsigned char *)(long)skb->data;
	xbuf->skb = skb;
	xbuf->ctx = NULL;
	xbuf_init(xbuf, data, data_end);
	xbuf_set_len(xbuf, skb->len);
}

static __always_inline unsigned char *xbuf_packet_data(const struct xbuf *xbuf)
{
	return (unsigned char *)(long)xbuf->data;
}

static __always_inline bool xbuf_check_access(const struct xbuf *xbuf,
					      const void *ptr,
					      const int len)
{
	return (unsigned char *)ptr + len <= (unsigned char *)(long)xbuf->data_end;
}

static __always_inline struct ethhdr *xbuf_ethhdr(const struct xbuf *xbuf)
{
	return (struct ethhdr *)xbuf->data;
}

static __always_inline unsigned int xbuf_tail_len(const struct xbuf *xbuf,
						  const unsigned char *tail)
{
	return xbuf->pkt_len - (tail - xbuf->data);
}

static __always_inline void xbuf_set_payload(struct xbuf *xbuf, unsigned char *data)
{
	__u16 payload_len;

	payload_len = xbuf_tail_len(xbuf, data); 
	if (payload_len > 0) {
		xbuf->payload_len = payload_len;
		xbuf->payload = data; 
	}
}

static __always_inline unsigned char *xbuf_get_payload(const struct xbuf *xbuf)
{
	if (xbuf->payload_len > 0)
		return xbuf->payload;
	return NULL;
}

static __always_inline unsigned char *xbuf_get_tail(const struct xbuf *xbuf, int rlen)
{
	void *data     = (void *)(long)xbuf->data;
	void *data_end = (void *)(long)xbuf->data_end;
	__u32 offset;
	void *p = data + rlen;

	if (p > data_end)
		return NULL;

	offset = data_end - p;

	/* to make the verifier happy */
	if (offset > 65530)
		return NULL;

	p = data + offset;
	if ((p + rlen) > data_end)
		return NULL;

	if (!xbuf_check_access(xbuf, p, rlen))
		return NULL;

	return (unsigned char *)p;
}

#ifdef XBUF_USE_OFFSET
static __always_inline struct iphdr *xbuf_ip_hdr(const struct xbuf *xbuf)
{
	return (struct iphdr *)(xbuf->data + xbuf->network_hdr_offset);
}

static __always_inline void xbuf_set_network_hdr(struct xbuf *xbuf, const unsigned int offset)
{
	xbuf->network_hdr_offset = offset;
}

static __always_inline int xbuf_network_hdr_offset(const struct xbuf *xbuf)
{
	return xbuf->network_hdr_offset;
}

static __always_inline unsigned int xbuf_network_packet_len(const struct xbuf *xbuf)
{
	return xbuf->pkt_len - xbuf_network_hdr_offset(xbuf);;
}

static __always_inline void xbuf_set_transport_hdr(struct xbuf *xbuf, const unsigned int offset)
{
	xbuf->transport_hdr_offset = xbuf->network_hdr_offset + offset;
}

static __always_inline struct tcphdr *xbuf_tcp_hdr(const struct xbuf *xbuf)
{
	return (struct tcphdr *)(xbuf->data + xbuf->transport_hdr_offset);
}

static __always_inline struct udphdr *xbuf_udp_hdr(const struct xbuf *xbuf)
{
	return (struct udphdr *)(xbuf->data + xbuf->transport_hdr_offset);
}

static __always_inline struct icmphdr *xbuf_icmp_hdr(const struct xbuf *xbuf)
{
	return (struct icmphdr *)(xbuf->data + xbuf->transport_hdr_offset);
}

#else
static __always_inline struct iphdr *xbuf_ip_hdr(const struct xbuf *xbuf)
{
	return (struct iphdr *)xbuf->network_hdr;
}

static __always_inline void xbuf_set_network_hdr(struct xbuf *xbuf, const unsigned int offset)
{
	xbuf->network_hdr = xbuf->data + offset;
}

static __always_inline unsigned int xbuf_network_packet_len(const struct xbuf *xbuf)
{
	return xbuf_tail_len(xbuf, xbuf->network_hdr);
}

static __always_inline int xbuf_network_hdr_offset(const struct xbuf *xbuf)
{
	return xbuf->network_hdr - xbuf->data;
}

static __always_inline void xbuf_set_transport_hdr(struct xbuf *xbuf, const unsigned int offset)
{
	xbuf->transport_hdr = xbuf->network_hdr + offset;
}
static __always_inline struct tcphdr *xbuf_tcp_hdr(const struct xbuf *xbuf)
{
	return (struct tcphdr *)xbuf->transport_hdr;
}

static __always_inline struct udphdr *xbuf_udp_hdr(const struct xbuf *xbuf)
{
	return (struct udphdr *)xbuf->transport_hdr;
}

static __always_inline struct icmphdr *xbuf_icmp_hdr(const struct xbuf *xbuf)
{
	return (struct icmphdr *)xbuf->transport_hdr;
}
#endif


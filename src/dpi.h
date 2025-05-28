#pragma once

#include "fw_dpi.h"
#include "debug.h"

#define DPI_DETECTED		0
#define DPI_NEXT_DECODER	1
static __always_inline int dpi_dns_check_domain(const struct xbuf *xbuf,
						const __u8 *query)
{
	int i;
	__u8 label = 0;

	if (!xbuf_check_access(xbuf, query, 32))
		return 0;

	for (i = 0; i < 32; i++) {
		if (!label) {
			label = query[i];
			if (!label)
				break;
			if (label > 63)
				return 0;
		} else {
			char s;
			int res = 1;
			label--;
			s = query[i];
			if ((s >= 'a' && s <= 'z') ||
			    (s >= '0' && s <= '9') ||
			    s == '-')
				res = 0;
			if (res)
				return 1;
		}
	}

	if (i == 0)
		return 0;

	return 1;
}

static __always_inline int dpi_dns_handler(const struct xbuf *xbuf, struct fw_conn *ct)
{
	struct dns_header {
		__u16 id;
		__u16 flags;
		__u16 qcount; /* query */
		__u16 acount; /* answers */
		__u16 nscount; /* authority ns */
		__u16 arcount; /* additional records */
	} *dnsh = (struct dns_header *)xbuf_get_payload(xbuf);
	struct dns_query_tailer {
		__u16 type;
		__u16 class;
	} *dnst;
	__u8 label;

	if (xbuf->payload_len < sizeof(*dnsh) + 
	    7 + /* shortest domain: 0x02 aa 0x02 in 0x00 */
	    4 /* type + class */ ||
	    !xbuf_check_access(xbuf, dnsh, sizeof(*dnsh) + 1)) { /* +1 to read first label */
		return DPI_NEXT_DECODER;
	}

	label = *((__u8 *)dnsh + sizeof(*dnsh));
	dnst = (struct dns_query_tailer *)xbuf_get_tail(xbuf, sizeof(*dnst));
	if (!dnst)
		return DPI_NEXT_DECODER;

	if ((dnsh->flags == 0 ||  /* standard query */
	     dnsh->flags == __constant_htons(0x0100) || /* standard query + recursion needed */
	     /* dig sets AD bit */
	     dnsh->flags == __constant_htons(0x0020) || /* standard query + AD */
	     dnsh->flags == __constant_htons(0x0120)) && /* standard query + rr + ad */
	    dnsh->qcount == __constant_htons(1) && /* 1 query */
	    dnsh->acount == 0 &&
	    dnsh->nscount == 0 &&
	    label && label <= 63 && /* first label is always in range 1-63 */
	    ((dnsh->arcount == 0 &&
	      dnst->class == __constant_htons(0x01) && /* class IN */
	      bpf_ntohs(dnst->type) <= 0x42) ||
	     (dnsh->arcount == __constant_htons(1) &&
	      xbuf->payload_len >= sizeof(*dnsh) + 32 &&
	      dpi_dns_check_domain(xbuf, (__u8 *)dnsh + sizeof(*dnsh))))) {
		pr_dbg("DNS detected!!!\n");
		ct->dpi.protocol = DPI_PROTO_DNS;
		ct->dpi.status = DPI_FINISHED;
		return DPI_DETECTED;
	}
	ct->dpi.excluded_protocols |= (1 << DPI_PROTO_DNS);
	return DPI_NEXT_DECODER;
}

static __always_inline int dpi_ssh_handler(const struct xbuf *xbuf, struct fw_conn *ct)
{
	__u8 *data = xbuf_get_payload(xbuf);
	if (!xbuf_check_access(xbuf, data, 4))
		return DPI_NEXT_DECODER;
	if (__builtin_memcmp(data, "SSH-", 4) == 0) {
		pr_dbg("SSH detected!!!\n");
		ct->dpi.protocol = DPI_PROTO_SSH;
		ct->dpi.status = DPI_FINISHED;
		return DPI_DETECTED;
	}
	return DPI_NEXT_DECODER;
}

static __always_inline int dpi_ssl_handler(const struct xbuf *xbuf, struct fw_conn *ct)
{
	__u8 *data = xbuf_get_payload(xbuf);
	__u16 header_len, client_hello_len;

	if (xbuf->payload_len < 11 || !xbuf_check_access(xbuf, data, 11)) {
		return DPI_NEXT_DECODER;
	}

	header_len = (data[3] << 8) | data[4];
	client_hello_len = (data[7] << 8) | data[8];

	if (data[0] == 0x16 && /* tls handshake */
	    data[1] == 0x03 && data[2] <= 0x03 && /* ver TLS1.0-TLS1.3 */
	    data[5] == 0x01 && /* client hello */
	    data[6] == 0x00 &&
	    header_len > 48 && /* minimum client hello len */
	    header_len <= 0x0400 && /*maximum client hello len */
	    header_len == client_hello_len + 4 &&
	    data[9] == 0x03 && data[10] <= 0x03 /* version in client hello */) {
		pr_dbg("TLS detected!!!\n");
		ct->dpi.protocol = DPI_PROTO_TLS;
		ct->dpi.status = DPI_FINISHED;
		return DPI_DETECTED;
	}
	return DPI_NEXT_DECODER;
}

static __always_inline int dpi_http_handler(const struct xbuf *xbuf, struct fw_conn *ct)
{
	__u8 *data = xbuf_get_payload(xbuf);

	if (!xbuf_check_access(xbuf, data, 5))
		return DPI_NEXT_DECODER;
	/* simple detector, only 3 methods */
	if (__builtin_memcmp(data, "GET ", 4)  == 0 ||
	    (data[4] == ' ' && (
	    __builtin_memcmp(data, "POST", 4) == 0 ||
	    __builtin_memcmp(data, "HEAD", 4) == 0))) {
		pr_dbg("HTTP detected!!!\n");
		ct->dpi.protocol = DPI_PROTO_HTTP;
		ct->dpi.status = DPI_FINISHED;
		return DPI_DETECTED;
	}

	return DPI_NEXT_DECODER;
}

typedef int (*dpi_func)(const struct xbuf *xbuf, struct fw_conn *ct);
static __always_inline int fw_dpi(const struct xbuf *xbuf, struct fw_conn *ct)
{
	struct iphdr *iph = xbuf_ip_hdr(xbuf);
	int ret;
	unsigned int i;

	dpi_func dpi_udp_handlers[] = {
		dpi_dns_handler,
	};
	dpi_func dpi_tcp_handlers[] = {
		dpi_ssh_handler,
		dpi_ssl_handler,
		dpi_http_handler,
	};

	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
		return 0;
	if (ct->dpi.status == DPI_FINISHED) {
		return 0;
	}

	ct->dpi.status = DPI_IN_PROGRESS;
	if (xbuf->payload_len == 0)
		return 0;

	if (iph->protocol == IPPROTO_UDP) {
		for (i = 0; i < sizeof(dpi_udp_handlers) / sizeof(dpi_udp_handlers[0]); i++) {
			ret = dpi_udp_handlers[i](xbuf, ct);
			if (ret == DPI_DETECTED)
				break;
		}
	} else if (iph->protocol == IPPROTO_TCP) {
		for (i = 0; i < sizeof(dpi_tcp_handlers) / sizeof(dpi_tcp_handlers[0]); i++) {
			ret = dpi_tcp_handlers[i](xbuf, ct);
			if (ret == DPI_DETECTED)
				break;
		}
	}
	ct->dpi.status = DPI_FINISHED;

	return 0;
}

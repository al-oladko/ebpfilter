// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2025 Aleksei Oladko <aleks.oladko@gmail.com>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <linux/if_link.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#ifdef HAVE_LIBXDP
#include <xdp/libxdp.h>
#endif

#include "ebpfilter.h"
#include "lib.h"

char *protos[IPPROTO_RAW] = {
	[IPPROTO_IP]	= "any",
	[IPPROTO_ICMP]	= "icmp",
	[IPPROTO_TCP]	= "tcp",
	[IPPROTO_UDP]	= "udp",
};

int fwlib_file_line_parse(FILE *f, void *ctx, int (*cb)(void *, int, char **))
{
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	char *argv[MAX_RULE_WORDS];
	int argc = 0;
	int ret;

	while ((read = getline(&line, &len, f)) != -1) {
		int j;
		int word = 0;
		int q = 0;

		if (line[0] == '#')
			continue;
		argc = 0;
		for (j = 0; j < read; j++) {
			if (line[j] == '"') {
				if (q) {
					q = 0;
					line[j] = 0;
					continue;
				}
				q = 1;
				word = 1;
				if (argc >= MAX_RULE_WORDS) {
					fprintf(stderr, "Error: malformed input file\n");
					return -1;
				}
				argv[argc++] = &line[j+1];
				continue;
			}
			if (q)
				continue;
			if (line[j] == '\n') {
				line[j] = 0;
			}
			if (line[j] == ' ') {
				line[j] = 0;
				word = 0;
				continue;
			}
			if (!word) {
				if (argc >= MAX_RULE_WORDS) {
					fprintf(stderr, "Error: malformed input file\n");
					return -1;
				}
				argv[argc++] = &line[j];
			}
			word = 1;
		}

		ret = cb(ctx, argc, argv);
		if (ret < 0)
			goto out;
		if (ret == 1) {
			ret = 0;
			goto out;
		}
	}

	ret = 0;
	if (read == -1)
		ret = -1;
out:
	free(line);
	return ret;
}

#ifdef HAVE_LIBXDP
static int fw_prog_is_attached(int ifindex)
{
	int ret = 0;
	struct xdp_multiprog *mp;
	struct xdp_program *prog = NULL;

	mp = xdp_multiprog__get_from_ifindex(ifindex);
	if (libbpf_get_error(mp))
		return 0;

	if (xdp_multiprog__is_legacy(mp)) {
		prog = xdp_multiprog__main_prog(mp);
		if (prog && strcmp(xdp_program__name(prog), cfg.xdp_prog_name) == 0)
			ret = 1;

		goto out;
	}

	while ((prog = xdp_multiprog__next_prog(prog, mp))) {
		if (strcmp(xdp_program__name(prog), cfg.xdp_prog_name) == 0) {
			ret = 1;
			break;
		}
	}
out:
	xdp_multiprog__close(mp);
	return ret;
}
#else
static int fw_prog_is_attached(int ifindex)
{
	int ret, fd;
	__u32 prog_id;
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);

#ifdef HAVE_BPF_XDP_ATTACH
	ret = bpf_xdp_query_id(ifindex, 0, &prog_id);
#else
	ret = bpf_get_link_xdp_id(ifindex, &prog_id, 0);
#endif
	if (ret < 0 || prog_id == 0)
		return 0;

	fd = bpf_prog_get_fd_by_id(prog_id);
	if (fd < 0)
		return 0;

	ret = bpf_obj_get_info_by_fd(fd, &info, &len);
	if (ret)
		return 0;

	if (strcmp(info.name, cfg.xdp_prog_name) == 0)
		return 1;
	return 0;
}
#endif

int fw_for_each_dev(int (*f)(struct if_nameindex *, int))
{
	struct if_nameindex *ifs, *iface;
	int ret = -1;

	ifs = if_nameindex();
	if (!ifs)
		return -1;
	for (iface = ifs; iface->if_name; iface++) {
		int attached = fw_prog_is_attached(iface->if_index);
		ret = f(iface, attached);
		if (ret < 0)
			break;;
	}

	if_freenameindex(ifs);
	return ret;
}

static int fw_detect_dev(struct if_nameindex *iface, int attached)
{
	if (!attached)
		return 0;
	if (opts.ifindex > 0)
		return -1;
	opts.ifindex = iface->if_index;
	memcpy(opts.iface, iface->if_name, IFNAMSIZ);
	return 0;
}

int fw_opts_check_and_get_dev(void)
{
	if (opts.ifindex > 0)
		return 0;
	if (fw_for_each_dev(fw_detect_dev) < 0) {
		fprintf(stderr, "Not enough information: 'dev' argument is required\n");
		return -1;
	}
	if (opts.ifindex < 0) {
		printf("Prog is not attached to any iface\n");
		return -1;
	}
	return 0;
}

int parse_dev(char *iface)
{
	size_t len = strlen(iface) + 1;

	if (len > IFNAMSIZ)
		return -1;
	memcpy(opts.iface, iface, len);

	opts.ifindex = if_nametoindex(opts.iface);
	if (!opts.ifindex) {
		fprintf(stderr, "Cannot find device \"%s\": %s\n", opts.iface, strerror(errno));
		return -1;
	}
	return 0;
}

int fw_try_set_dev(int argc, char **argv)
{
	int ret;

	if (argc > 0) {
		if (argc != 2 || strcmp("dev", *argv))
			return -1;
		argv++;
		ret = parse_dev(*argv);
		if (ret < 0)
			return -1;
	}
	if (fw_opts_check_and_get_dev() < 0) {
		return -1;
	}
	return 0;
}

char *fw_ip_str(__be32 addr, __be32 mask)
{
	static char str[32];

	if (addr) {
		int mask_len = __builtin_popcount(mask);
		struct in_addr in = {
			.s_addr = addr,
		};
		if (mask_len && mask_len < 32) 
			snprintf(str, sizeof(str), "%s/%d", inet_ntoa(in), mask_len);
		else
			snprintf(str, sizeof(str), "%s", inet_ntoa(in));
		return str;
	}
	return "any";
}

void fw_print_ip(__be32 addr, __be32 mask, int width)
{
	char format[8];

	snprintf(format, sizeof(format), "%%%ds", width);
	printf(format, fw_ip_str(addr, mask));
}


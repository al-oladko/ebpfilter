// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2025 Aleksei Oladko <aleks.oladko@gmail.com>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <linux/limits.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <linux/icmp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#ifdef HAVE_LIBXDP
#include <xdp/libxdp.h>
#endif
#include <sys/ioctl.h>

#include "ebpfilter.h"
#include "lib.h"
#include "map.h"
#include "nat.h"

#include "fw_progtable.h"
#include "fw_nat.h"

static int fw_dev_get_ip(char *iface, __be32 *ip)
{
	int fd;
	struct ifreq ifr;
	int ret;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "Internal error. Please try again.\n");
		if (opts.verbose) {
			fprintf(stderr, "socket error: %s.\n", strerror(errno));
		}
		return -1;
	}

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);

	ret = ioctl(fd, SIOCGIFADDR, &ifr);
	if (ret < 0) {
		fprintf(stderr, "Internal error. Please try again.\n");
		if (opts.verbose) {
			fprintf(stderr, "ioctl error: %s.\n", strerror(errno));
		}
		return -1;
	}

	close(fd);
	*ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

	return 0;
}

static int fw_snat_enable(void)
{
	int map_fd, prog_fd, prog_id;
	int key, ret;

	map_fd = fw_map_get(FW_MAP_PROG_TABLE);
	if (map_fd < 0)
		return map_fd;

	key = FW_PROG_TC_NAT * 2 + 1;
	ret = bpf_map_lookup_elem(map_fd, &key, &prog_id);
	if (ret < 0) {
		return -1;
	}
	prog_fd = bpf_prog_get_fd_by_id(prog_id);
	key = FW_PROG_TC_NAT * 2;
	ret = bpf_map_update_elem(map_fd, &key, &prog_fd, BPF_ANY);
	return 0;
}

static int fw_snat_disable(void)
{
	int map_fd, prog_fd = 0;
	int key;

	map_fd = fw_map_get(FW_MAP_PROG_TABLE);
	if (map_fd < 0)
		return map_fd;

	key = FW_PROG_TC_NAT * 2;
	bpf_map_update_elem(map_fd, &key, &prog_fd, BPF_ANY);
	return 0;
}

#define FW_NAT_SOURCE	1
static int fw_do_nat_add(int argc, char **argv, int nat_type)
{
	struct fw_nat_rule rule;
	int key = 0, nat_fd;
	int autodetect = 0;
	int ret;

	memset(&rule, 0, sizeof(rule));
	while (argc > 0) {
		if (strcmp("set-ip", *argv) == 0) {
			struct in_addr in;
			argv++;
			argc--;
			if (nat_type == 0) {
				fprintf(stderr, "Error: NAT type has not been specifiedn");
				return -1;
			}
			if (autodetect) {
				fprintf(stderr, "Error: the 'set-ip IP' and 'auto' options cannot be used together\n");
				return -1;
			}
			if (rule.to_addr) {
				fprintf(stderr, "Error: the 'set-ip IP' and 'auto' options cannot be used together\n");
				return -1;
			}

			if (argc <= 0) {
				fprintf(stderr, "Option 'set-ip' requires an argument\n");
				return -1;
			}
			if (strcmp("auto", *argv) == 0) {
				autodetect = 1;
				goto next;
			}
			ret = inet_aton(*argv, &in);
			if (!ret) {
				fprintf(stderr, "Invalid host/subnet '%s'\n", *argv);
				return -1;
			}

			rule.to_addr = in.s_addr;
			if ((rule.to_addr & htonl(0xff000000)) == htonl(0x7f000000)) {
				fprintf(stderr, "Loopback address is forbidden '%s'\n", *argv);
				return -1;
			}
			if (IN_MULTICAST(rule.to_addr)) {
				fprintf(stderr, "Multicast address is forbidden '%s'\n", *argv);
				return -1;
			}
			if (IN_BADCLASS(rule.to_addr)) {
				fprintf(stderr, "Reserved address is forbidden '%s'\n", *argv);
				return -1;
			}
			if (rule.to_addr == INADDR_BROADCAST) {
				fprintf(stderr, "Broadcast address is forbidden '%s'\n", *argv);
				return -1;
			}
			if ((rule.to_addr & htonl(0xff000000)) == htonl(0x00000000)) {
				fprintf(stderr, "Zeronet address is forbidden '%s'\n", *argv);
				return -1;
			}
			goto next;
		}
		if (strcmp("dev", *argv) == 0) {
			argc--;
			if (argc <= 0) {
				fprintf(stderr, "Option 'dev' requires an argument\n");
				return -1;
			}
			argv++;
			ret = parse_dev(*argv);
			if (ret < 0) {
				return -1;
			}
			goto next;
		}
		if (strcmp("src-translation", *argv) == 0) {
			if (nat_type) {
				fprintf(stderr, "Error: the nat type parameter has already been specified\n");
				return -1;
			}
			nat_type = 1;
			goto next;
		}
next:
		argc--;
		argv++;
	}
	if (fw_opts_check_and_get_dev() < 0)
		return -1;

	if (autodetect) {
		ret = fw_dev_get_ip(opts.iface, &rule.to_addr);
		if (ret < 0)
			return -1;
	}
	if (!rule.to_addr) {
		fprintf(stderr, "Error: the parameter 'set-ip' must be specified\n");
		return -1;
	}
	nat_fd = fw_map_get(FW_MAP_NAT);
	if (nat_fd < 0) {
		return -1;
	}
	bpf_map_update_elem(nat_fd, &key, &rule, BPF_ANY);
	fw_snat_enable();
	return 0;
}

static int fw_nat_add(int argc, char **argv)
{
	return fw_do_nat_add(argc, argv, 0);
}

static int fw_snat_add(int argc, char **argv)
{
	return fw_do_nat_add(argc, argv, FW_NAT_SOURCE);
}

static int fw_nat_show_dev(void)
{
	struct in_addr in;
	int ret, key = 0;
	int nat_fd;
	struct fw_nat_rule rule;

	nat_fd = fw_map_get(FW_MAP_NAT);
	if (nat_fd < 0)
		return -1;
	ret = bpf_map_lookup_elem(nat_fd, &key, &rule);
	if (ret < 0) {
		printf("%s\n", RED_TEXT("failed to get information"));
		return 0;
	}
	if (rule.to_addr == htonl(INADDR_ANY)) {
		printf("%s: NAT rules are not configured\n", opts.iface);
	} else {
		in.s_addr = rule.to_addr;
		printf("%s: source translation to %s\n", opts.iface, inet_ntoa(in));
	}
	return 0;
}

static int fw_nat_show_all(struct if_nameindex *iface, int attached)
{
	if (!attached)
		return 0;
	opts.ifindex = iface->if_index;
	memcpy(opts.iface, iface->if_name, IFNAMSIZ);

	return fw_nat_show_dev();
}

static int fw_nat_show(int argc, char **argv)
{
	int ret;

	ret = fw_try_set_dev(argc, argv);
	if (ret < 0)
		return -1;

	if (opts.ifindex < 0)
		return fw_for_each_dev(fw_nat_show_all);
	return fw_nat_show_dev();
}

static int fw_nat_flush(int argc, char **argv)
{
	int ret, key = 0;
	int nat_fd;
	struct fw_nat_rule rule;

	memset(&rule, 0, sizeof(rule));
	ret = fw_try_set_dev(argc, argv);
	if (ret < 0)
		return -1;

	nat_fd = fw_map_get(FW_MAP_NAT);
	if (nat_fd < 0)
		return -1;

	bpf_map_update_elem(nat_fd, &key, &rule, BPF_ANY);
	fw_snat_disable();

	return 0;
}

static int fw_nat_help(__unused int argc, __unused char **argv)
{
	printf("Usage: %s nat show [dev IFNAME]\n"
	       "       %s nat add rule-options [dev IFNAME]\n"
	       "       %s nat flush [dev IFNAME]\n"
	       " If the XDP program is attached to only one interface, the dev parameter may\n"
	       " be omitted.\n\n"
	       "Commands       Description\n"
	       " show           Show rules in the policy\n"
	       " add            Add a nat rule to the policy\n"
	       " flush          Delete all NAT rules\n"
	       "rule-options:\n"
	       "  src-translation    source address translation{auto|to ip-address}\n"
	       "  set-ip IP|auto     Creates rules for source IP address translation. The source\n"
	       "                     IP address is either set to the value specified by the IP\n"
	       "                     option, or automatically determined as the interface IP\n"
	       "                     addressif the auto option is used.\n",
	       opts.argv[0], opts.argv[0], opts.argv[0]);
	return 0;
}

static struct cmd nat_cmds[] = {
	{ "show", fw_nat_show },
	{ "help", fw_nat_help },
	{ "add", fw_nat_add },
	{ "delete", fw_nat_flush },
	{ "flush", fw_nat_flush },
	{ NULL, fw_nat_help },
};

int fw_prog_nat(int argc, char **argv)
{
	return fw_run_cmd(nat_cmds, argc, argv);
}

static struct cmd snat_cmds[] = {
	{ "help", fw_nat_help },
	{ "add", fw_snat_add },
	{ NULL, fw_nat_help },
};

int fw_prog_snat(int argc, char **argv)
{
	return fw_run_cmd(snat_cmds, argc, argv);
}


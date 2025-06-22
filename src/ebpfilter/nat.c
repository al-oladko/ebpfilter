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
#include <yaml.h>

#include "ebpfilter.h"
#include "lib.h"
#include "map.h"
#include "nat.h"
#include "policy.h"

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

static int nat_prog_ids[] = { FW_PROG_TC_NAT, FW_PROG_TC_NAT_FRAGMENT };
static int fw_snat_enable(void)
{
	int map_fd, prog_fd, prog_id;
	int key, ret;
	unsigned int i;

	map_fd = fw_map_get(FW_MAP_PROG_TABLE);
	if (map_fd < 0)
		return map_fd;

	for (i = 0; i < sizeof(nat_prog_ids)/sizeof(nat_prog_ids[0]); i++) {
		key = i * 2 + 1;
		ret = bpf_map_lookup_elem(map_fd, &key, &prog_id);
		if (ret < 0) {
			return -1;
		}
		prog_fd = bpf_prog_get_fd_by_id(prog_id);
		key = i * 2;
		ret = bpf_map_update_elem(map_fd, &key, &prog_fd, BPF_ANY);
	}

	return 0;
}

static int fw_snat_disable(void)
{
	int map_fd, prog_fd = 0;
	int key;
	unsigned int i;

	map_fd = fw_map_get(FW_MAP_PROG_TABLE);
	if (map_fd < 0)
		return map_fd;

	for (i = 0; i < sizeof(nat_prog_ids)/sizeof(nat_prog_ids[0]); i++) {
		key = i * 2;
		bpf_map_update_elem(map_fd, &key, &prog_fd, BPF_ANY);
	}

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

int fw_snat_get_rule(struct fw_nat_rule *rule)
{
	int ret, key = 0;
	int nat_fd;

	memset(rule, 0, sizeof(*rule));
	nat_fd = fw_map_get(FW_MAP_NAT);
	if (nat_fd < 0)
		return -1;
	ret = bpf_map_lookup_elem(nat_fd, &key, rule);
	if (ret < 0) {
		printf("%s\n", RED_TEXT("failed to get information"));
	}
	close(nat_fd);
	return ret;
}

static int fw_nat_show_dev(void)
{
	struct in_addr in;
	struct fw_nat_rule rule;
	int ret;

	ret = fw_snat_get_rule(&rule);
	if (ret < 0) {
		fprintf(stderr, "Internal error. Please try again.\n");
		return ret;
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

static int fw_nat_add_cb(__unused void *ctx, int argc, char **argv)
{
	if (argc < 2)
		return -1;
	if (strcmp(argv[0], "snat"))
		return -1;
	if (strcmp(argv[1], "empty") == 0)
		return 1;
	argv += 1;
	argc -= 1;
	fw_snat_add(argc, argv);
	return 1;
}

static int fw_nat_txt_to_policy_apply(void *ctx)
{
	FILE *f = (FILE *)ctx;
	return fwlib_file_line_parse(f, NULL, fw_nat_add_cb);
}

static int fw_nat_txt_to_policy_show(void *ctx)
{
	FILE *f = (FILE *)ctx;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	read = getline(&line, &len, f);
	if (read < 0)
		return read;
	printf("%s\n", line);

	free(line);
	return 0;
}

static int fw_nat_policy_to_txt(void *ctx)
{
	FILE *f = (FILE *)ctx;
	struct in_addr in;
	struct fw_nat_rule rule;
	int ret;

	ret = fw_snat_get_rule(&rule);
	if (ret < 0) {
		fprintf(stderr, "Internal error. Please try again.\n");
		return ret;
	}
	if (rule.to_addr == htonl(INADDR_ANY)) {
		fprintf(f, "snat empty\n");
	} else {
		in.s_addr = rule.to_addr;
		fprintf(f, "snat set-ip %s\n", inet_ntoa(in));
	}
	return 0;
}

struct config_ops nat_config_txt = {
	.apply = fw_nat_txt_to_policy_apply,
	.show = fw_nat_txt_to_policy_show,
	.save = fw_nat_policy_to_txt,
};

int fw_yaml_write(yaml_emitter_t *emitter,
			 char *key,
			 char *value);
static int fw_nat_policy_to_yaml(void *ctx)
{
	yaml_emitter_t *emitter = (yaml_emitter_t *)ctx;
	yaml_event_t event;
	struct fw_nat_rule rule;
	struct in_addr in;
	int ret;

	fw_yaml_write(emitter, "nat", NULL);
	yaml_sequence_start_event_initialize(&event, NULL, (yaml_char_t *)YAML_SEQ_TAG,
			1, YAML_ANY_SEQUENCE_STYLE);
	if (!yaml_emitter_emit(emitter, &event)) goto error;

	yaml_mapping_start_event_initialize(&event, NULL, (yaml_char_t *)YAML_MAP_TAG,
			1, YAML_ANY_MAPPING_STYLE);
	if (!yaml_emitter_emit(emitter, &event)) goto error;

	fw_yaml_write(emitter, "snat", "");

	ret = fw_snat_get_rule(&rule);
	if (ret < 0) {
		fprintf(stderr, "Internal error. Please try again.\n");
		return ret;
	}
	if (rule.to_addr != htonl(INADDR_ANY)) {
		in.s_addr = rule.to_addr;
		fw_yaml_write(emitter, "set-ip", inet_ntoa(in));
	}

	yaml_mapping_end_event_initialize(&event);
	if (!yaml_emitter_emit(emitter, &event)) goto error;

	yaml_sequence_end_event_initialize(&event);
	if (!yaml_emitter_emit(emitter, &event)) goto error;

	ret = 0;
out:
	return ret;
error:
	fprintf(stderr, "Failed to emit event %d: %s\n", event.type, emitter->problem);
	ret = -1;
	goto out;
}

#define  FWNAT_CMD_CONFIG_APPLY	0
#define  FWNAT_CMD_CONFIG_SHOW	1
static int fw_nat_yaml_to_policy_parse(void *ctx, int command)
{
	yaml_parser_t *parser = (yaml_parser_t *)ctx;
	yaml_event_t event;
	char *argv[MAX_RULE_WORDS];
	char snat_key[] = "set-ip";
	char *current_value;
	int argc = 0;
	int stop = 0;
	int ret = 0;
	int nat_type;

	while (stop == 0) {
		if (!yaml_parser_parse(parser, &event)) {
			fprintf(stderr, "Parse error: %s\n", parser->problem);
			return 1;
		}

		switch (event.type) {
		case YAML_SEQUENCE_END_EVENT:
			stop = 1;
			ret = 0;
			break;
		case YAML_MAPPING_START_EVENT:
			nat_type = 0;
			argc = 0;
			argv[1] = NULL;
			break;
		case YAML_MAPPING_END_EVENT:
			if (nat_type == 0)
				break;
			if (nat_type == 1 && argc == 2) {
				if (command == FWNAT_CMD_CONFIG_SHOW)
					printf("snat set-ip %s\n", argv[1]);
				if (command == FWNAT_CMD_CONFIG_APPLY)
					fw_snat_add(argc, argv);
			}
			if (argv[1])
				free(argv[1]);
			break;
		case YAML_SCALAR_EVENT:
			current_value = (char *)event.data.scalar.value;
			if (nat_type == 0) {
				if (strcmp(current_value, "snat") == 0) {
					nat_type = 1;
					break;
				}
				fprintf(stderr, "Unknown keyword \"%s\"\n", current_value);
				stop = 1;
				ret = -1;
				break;
			}
			if (nat_type == 1) {
				if (argc == 1) {
					argv[argc] = malloc(event.data.scalar.length + 1);
					if (!argv[argc]) {
						fprintf(stderr, "Error: cannot allocate memory\n");
						stop = 1;
						ret = -1;
						break;
					}
					strncpy(argv[argc], current_value, event.data.scalar.length + 1);
					argc++;
				}
				if (argc == 0) {
					if (strcmp(current_value, "set-ip") == 0)
						argv[argc++] = snat_key;
				}
				break;
			}
			break;
		default:
			break;
		}
		yaml_event_delete(&event);
	}
	return ret;
}

static int fw_nat_yaml_to_policy_apply(void *ctx)
{
	return fw_nat_yaml_to_policy_parse(ctx, FWNAT_CMD_CONFIG_APPLY);
}

static int fw_nat_yaml_to_policy_show(void *ctx)
{
	return fw_nat_yaml_to_policy_parse(ctx, FWNAT_CMD_CONFIG_SHOW);
}

struct config_ops nat_config_yaml = {
	.apply = fw_nat_yaml_to_policy_apply,
	.show = fw_nat_yaml_to_policy_show,
	.save = fw_nat_policy_to_yaml,
};

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


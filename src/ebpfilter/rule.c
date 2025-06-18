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

#include "ebpfilter.h"
#include "lib.h"
#include "map.h"
#include "rule.h"

#include "fw_rule.h"
#include "fw_dpi.h"
#include "fw_config.h"

static void fw_stats_update(int gen_id)
{
	int i, ncpus;
	struct fw_rule_stats *stats;
	int set_id = gen_id & 1, stat_fd;

	ncpus = libbpf_num_possible_cpus();
	if (ncpus < 0)
		return;
	stats = calloc(ncpus, sizeof(*stats));
	if (!stats)
		return;
	stat_fd = fw_map_get(FW_MAP_STATS);
	if (stat_fd < 0) {
		return;
	}
	for (i = 0; i < FW_MAX_RULES; i++) {
		gen_id = set_id * FW_MAX_RULES + i;
		bpf_map_update_elem(stat_fd, &gen_id, stats, BPF_ANY);
	}
	close(stat_fd);
}

static int fw_policy_set(const struct fw_rule_set *set, int *cur_gen_id)
{
	int set_fd, gen_fd;
	int ret = -1;
	int gen_id, set_id = 0;

	gen_fd = fw_map_get(FW_MAP_GENID);
	if (gen_fd < 0) {
		return ret;
	}

	ret = bpf_map_lookup_elem(gen_fd, &set_id, &gen_id);
	if (ret < 0)
		goto out_close_gen;

	if (cur_gen_id && *cur_gen_id != gen_id) {
		fprintf(stderr, "Policy update error. The policy may have been updated by another process. Please try again.\n");
		return -1;
	}
	gen_id++;
	set_id = gen_id % 2;
	ret = -1;

	set_fd = fw_map_get(FW_MAP_RULES);
	if (set_fd < 0) {
		goto out_close_gen;
	}

	if (bpf_map_update_elem(set_fd, &set_id, set, BPF_ANY) < 0) {
		fprintf(stderr, "Update policy failed: %s\n", strerror(errno));
		goto out_close_set;
	}

	fw_stats_update(gen_id);
	set_id = 0;
	bpf_map_update_elem(gen_fd, &set_id, &gen_id, BPF_ANY);
	ret = 0;
out_close_set:
	close(set_fd);
out_close_gen:
	close(gen_fd);
	return ret;
}

static int fw_policy_get(struct fw_rule_set *set, int *gen_id)
{
	int set_fd, gen_fd;
	int key = 0;
	int ret;
	int set_id;

	gen_fd = fw_map_get(FW_MAP_GENID);
	if (gen_fd < 0) {
		return -1;
	}

	ret = bpf_map_lookup_elem(gen_fd, &key, gen_id);
	if (ret < 0)
		goto out_close_gen;

	ret = -1;
	set_id = (*gen_id) % 2;
	set_fd = fw_map_get(FW_MAP_RULES);
	if (set_fd < 0) {
		goto out_close_gen;
	}
	ret = bpf_map_lookup_elem(set_fd, &set_id, set);
	if (ret < 0) {
		fprintf(stderr, "Error while getting policy\n");
	}

	close(set_fd);
out_close_gen:
	close(gen_fd);
	return ret;
}

static int fw_convert_rule(struct rule *rule, struct fw_rule *frule)
{
	memset(frule, 0, sizeof(*frule));
	if (rule->src.ip) {
		frule->saddr = rule->src.ip;
		frule->smask = rule->src.mask;
	}
	if (rule->dst.ip) {
		frule->daddr = rule->dst.ip;
		frule->dmask = rule->dst.mask;
	}
	if (rule->protocol) {
		frule->protocol = rule->protocol;
		frule->sport = rule->sport;
		frule->dport = rule->dport;
	}
	if (rule->l7protocol) {
		struct rule_l7 *drule = (struct rule_l7 *)&frule->params[0];

		drule->type = FW_RULE_PARAM_L7_PROTOCOL;
		drule->protocol = rule->l7protocol;
	}
	if (rule->ct_cost) {
		int j;
		struct connlimit *cl = NULL;

		for (j = 0; j < FW_RULE_MAX_PARAMS; j++) {
			if (frule->params[j].type == FW_RULE_PARAM_NONE) {
				cl = (struct connlimit *)&frule->params[j];
				break;
			}
		}
		if (!cl) {
			fprintf(stderr, "Error: the limit on the maximum number of parameters in the rule has been reached\n");
			return -1;
		}
		cl->ct_cost = rule->ct_cost;
		cl->tick_cost = rule->tick_cost;
		cl->budget = cl->max_budget = rule->connlimit_budget;
		if (cl->tick_cost / cl->ct_cost > 10) {
			cl->credit = HZ / 25;
		}
		cl->type = FW_RULE_PARAM_CONNLIMIT;
	}
	frule->action = rule->action;

	return 0;
}

static int fw_rule_set_add(struct fw_rule_set *set, struct rule *rule)
{
	struct fw_rule frule;
	int ret, i;

	if (rule->rule_num) {
		/* index in array */
		rule->rule_num--;
		if (rule->rule_num > set->num) {
			fprintf(stderr, "Index of insertion too big. Maximum allowed value is %d\n", set->num);
			return -1;
		}
	} else {
		/* add the rule to the buttom */
		rule->rule_num = set->num;
	}
	if (set->num + 1 >= FW_MAX_RULES) {
		fprintf(stderr, "Maximum number of rules reached.\n");
		return -1;
	}
	set->num++;

	ret = fw_convert_rule(rule, &frule);
	if (ret < 0)
		return ret;

	for (i = set->num; i > rule->rule_num; i--) {
		set->rules[i] = set->rules[i - 1];
	}
	set->rules[rule->rule_num] = frule;

	return 0;
}

static int fw_policy_update(struct rule *rule)
{
	struct fw_rule_set set;
	int ret, gen_id;

	ret = fw_policy_get(&set, &gen_id);
	if (ret < 0)
		return ret;

	ret = fw_rule_set_add(&set, rule);
	if (ret < 0)
		return ret;

	fw_policy_set(&set, &gen_id);

	return 0;
}

static int fw_get_ip(struct ip_addr *ip, char *arg)
{
	struct in_addr in;
	char *mask_str;
	int mask_len = 0;
	uint32_t mask = 0xFFFFFFFF;
	int ret;

	if (strcmp(arg, "any") == 0) {
		return 0;
	}
	mask_str = strchr(arg, '/');
	if (mask_str) {
		mask_str++;
		mask_len = atoi(mask_str);
		if (mask_len <= 0 || mask_len > 32) {
			fprintf(stderr, "Invalid host/subnet '%s'\n", arg);
			return -1;
		}
		mask_str--;
		*mask_str = 0;
		if (mask_len < 32)
			mask = ((1U << mask_len) - 1) << (32 - mask_len);
	}
	ret = inet_aton(arg, &in);
	if (!ret) {
		fprintf(stderr, "Invalid host/subnet '%s'\n", arg);
		return -1;
	}

	ip->mask = htonl(mask);
	ip->ip = in.s_addr & ip->mask;
	return 0;
}

static bool is_number(const char *str)
{
	while (*str) {
		if (*str >= '0' && *str <= '9')
			str++;
		else
			break;
	}
	return *str == 0;
}

static char *srv_list[DPI_PROTO_MAX] = {
	"-", "ssh", "http", "dns", "tls", "unk"
};
static int fw_build_rule(struct rule *rule, int argc, char **argv)
{
	int ret;
	int rule_num, action_f = 0;

	memset(rule, 0, sizeof(*rule));
	rule_num = atoi(*argv);
	if (rule_num < 0 || rule_num > FW_MAX_RULES) {
		fprintf(stderr, "Rule number must be positive and not exceed %d\n", FW_MAX_RULES);
		return -1;
	}
	if (rule_num) {
		rule->rule_num = rule_num;
		argv++;
		argc--;
	}
	while (argc > 0) {
		if (strcmp("name", *argv) == 0) {
			argv++;
			argc--;
			if (argc <= 0) {
				fprintf(stderr, "Option 'name' requires an argument\n");
				return -1;
			}
			strncpy(rule->name, *argv, RULE_NAME_LEN - 1);
			rule->name[RULE_NAME_LEN - 1] = 0;
			goto next;
		}
		if (strcmp("src", *argv) == 0) {
			argv++;
			argc--;
			if (argc <= 0) {
				fprintf(stderr, "Option 'src' requires an argument\n");
				return -1;
			}
			ret = fw_get_ip(&rule->src, *argv);
			if (ret < 0)
				return -1;
			goto next;
		}
		if (strcmp("dst", *argv) == 0) {
			argv++;
			argc--;
			if (argc <= 0) {
				fprintf(stderr, "Option 'dst' requires an argument\n");
				return -1;
			}
			ret = fw_get_ip(&rule->dst, *argv);
			if (ret < 0)
				return -1;
			goto next;
		}
		if (strcmp("action", *argv) == 0) {
			argv++;
			argc--;
			if (argc <= 0) {
				fprintf(stderr, "Option 'action' requires an argument\n");
				return -1;
			}
			action_f = 1;
			if (strcmp("drop", *argv) == 0) {
				rule->action = FW_DROP;
				goto next;
			} else 
			if (strcmp("accept", *argv) == 0) {
				rule->action = FW_PASS;
				goto next;
			}
		}
		if (strcmp("icmp", *argv) == 0) {
			rule->protocol = IPPROTO_ICMP;
			goto next;
		}
		if (strcmp("tcp", *argv) == 0) {
			rule->protocol = IPPROTO_TCP;
			goto next;
		}
		if (strcmp("udp", *argv) == 0) {
			rule->protocol = IPPROTO_UDP;
			goto next;
		}
		if (strcmp("port", *argv) == 0) {
			if (rule->dport) {
				fprintf(stderr, "Only one 'port' allower.\n");
				return -1;
			}
			if (rule->protocol != IPPROTO_TCP && rule->protocol != IPPROTO_UDP) {
				fprintf(stderr, "Port number can only be specified if TCP or UDP protocol is selected.\n");
				return -1;
			}
			argv++;
			argc--;
			if (argc <= 0) {
				fprintf(stderr, "Option 'port' requires an argument\n");
				return -1;
			}
			ret = atoi(*argv);
			if (!ret || ret > 65535) {
				fprintf(stderr, "Invalid port number '%s'.\n", *argv);
				return -1;
			}
			rule->dport = htons(ret);
			goto next;
		}
		if (strcmp("src-port", *argv) == 0) {
			if (rule->sport) {
				fprintf(stderr, "Only one 'src-port' allower.\n");
				return -1;
			}
			if (rule->protocol != IPPROTO_TCP && rule->protocol != IPPROTO_UDP) {
				fprintf(stderr, "Port number can only be specified if TCP or UDP protocol is selected.\n");
				return -1;
			}
			argv++;
			argc--;
			if (argc <= 0) {
				fprintf(stderr, "Option 'src-port' requires an argument\n");
				return -1;
			}
			ret = atoi(*argv);
			if (!ret || ret > 65535) {
				fprintf(stderr, "Invalid port number '%s'.\n", *argv);
				return -1;
			}
			rule->sport = htons(ret);
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
		if (strcmp("service", *argv) == 0) {
			argv++;
			argc--;
			if (argc <= 0) {
				fprintf(stderr, "Option 'service' requires an argument\n");
				return -1;
			}
			if (strcmp("ping", *argv) == 0) {
				if (rule->protocol && rule->protocol != IPPROTO_ICMP) {
					fprintf(stderr, "Ping service cannot be specified when TCP or UDP protocol is selected.\n");
					return -1;
				}
				rule->protocol = IPPROTO_ICMP;
				rule->icmp_type = ICMP_ECHO;
			} else
			if (strcmp("tls", *argv) == 0) {
				rule->l7protocol = DPI_PROTO_TLS;
			} else
			if (strcmp("ssh", *argv) == 0) {
				rule->l7protocol = DPI_PROTO_SSH;
			} else
			if (strcmp("http", *argv) == 0) {
				rule->l7protocol = DPI_PROTO_HTTP;
			} else
			if (strcmp("dns", *argv) == 0) {
				rule->l7protocol = DPI_PROTO_DNS;
			} else {
				int j, smax = DPI_PROTO_MAX - 1;
				fprintf(stderr, "Unknown or unsupported service: %s\n", *argv);
				fprintf(stderr, "Currently, only the following protocols are supported: ");
				for (j = 1; j < smax; j++) {
					fprintf(stderr, "%s%s", srv_list[j], j == smax - 1 ? "\n" : ", ");
				}
				return -1;
			}
			goto next;
		}
		if (strcmp("connlimit", *argv) == 0) {
			char *sl;
			unsigned int ct_limit, time_limit;
			int m = 1;
			int ct_cost = 1, tick_cost = 1;
			argv++;
			argc--;
			if (argc <= 0) {
				fprintf(stderr, "Option 'connlimit' requires an argument\n");
				return -1;
			}
			sl = strchr(*argv, '/');
			if (!sl) {
				fprintf(stderr, "Error: Invalid connection limit format %s\n", *argv);
				return -1;
			}
			*sl = 0;
			sl++;
			if (!is_number(*argv)) {
				fprintf(stderr, "Error: Invalid connection limit format %s\n", *argv);
				return -1;
			}
			ct_limit = atoi(*argv);
			if (ct_limit <= 0) {
				fprintf(stderr, "Error: Invalid connection limit format %s\n", *argv);
				return -1;
			}
			if (sl[strlen(sl) - 1] == 'h') {
				m = 60 * 60;
			} else if (sl[strlen(sl) - 1] == 'm') {
				m = 60;
			} else if (sl[strlen(sl) - 1] != 's') {
				fprintf(stderr, "Error: Invalid connection limit format %s\n", sl);
				return -1;
			}
			sl[strlen(sl) - 1] = 0;
			if (!is_number(sl)) {
				fprintf(stderr, "Error: Invalid connection limit format %s\n", sl);
				return -1;
			}
			time_limit = atoi(sl);
			if (time_limit <= 0) {
				fprintf(stderr, "Error: Invalid connection limit format %s\n", sl);
				return -1;
			}
			time_limit *= m * HZ;
			if (time_limit == ct_limit) {
			} else if (time_limit > ct_limit) {
				int add;
				ct_cost = time_limit / ct_limit;
				add = ((time_limit % ct_limit) * 10) / ct_limit;
				if (add) {
					ct_cost = ct_cost * 10 + add;
					tick_cost = 10;
				}
			} else if (time_limit < ct_limit) {
				int add;
				tick_cost = ct_limit / time_limit;
				add = ((ct_limit % time_limit) * 10) / time_limit;
				if (add) {
					tick_cost = tick_cost * 10 + add;
					ct_cost = 10;
				}
			}
			if (ct_cost > UINT16_MAX) {
				fprintf(stderr, "Error: the specified rate is too small and is not currently supported\n");
				return -1;
			}
			if (ct_cost * ct_limit > INT32_MAX) {
				fprintf(stderr, "Error: the specified rate is too high and is not supported\n");
				return -1;
			}
			rule->ct_cost = ct_cost;
			rule->tick_cost = tick_cost;
			rule->connlimit_budget = ct_cost * ct_limit;
			goto next;
		}
		fprintf(stderr,"Unknown option '%s'\n", *argv);
		return -1;
next:
		argc--;
		argv++;
	}

	if (!action_f) {
		fprintf(stderr, "Not enough information: 'action' argument is required\n");
		return -1;
	}

	return 0;
}

static int fw_rule_add(int argc, char **argv)
{
	struct rule rule;

	if (!argc) {
		fprintf(stderr, "Command 'rule add' requires arguments\n");
		return -1;
	}

	if (fw_build_rule(&rule, argc, argv) < 0)
		return -1;
	if (fw_opts_check_and_get_dev() < 0) {
		return -1;
	}

	return fw_policy_update(&rule);
}

static int fw_rule_help(__unused int argc, __unused char **argv)
{
	printf("Usage: %s rule show [dev IFNAME]\n"
	       "       %s rule add rulenum rule-options [dev IFNAME]\n"
	       "       %s rule delete rulenum [dev IFNAME]\n"
	       "       %s rule flush [dev IFNAME]\n"
	       "       %s rule set default [accept|drop] [dev IFNAME]\n"
	       " If the XDP program is attached to only one interface, the dev parameter may be omitted.\n\n"
	       "Commands       Description\n"
	       " show           Show rules in the policy\n"
	       " add            Add a rule to the policy at position rulenum, or to the end\n"
	       " delete         Delete rule rulenum from the policy\n"
	       " flush          Reset all rules and set the default rule to 'accept'\n"
	       " set default    Set the default rule in the policy\n\n"
	       "rule-options:\n"
	       "  src any|address[/mask]    source ip-address or network\n"
	       "  dst any|address[/mask]    destination ip-address or network\n"
	       "  tcp|udp|icmp              protocol\n"
	       "  port NUM                  destination port for TCP or UDP\n"
	       "  src-port NUM              source port for TCP or UDP\n"
	       "  service [ssh|tls|dns|http|ping]\n"
	       "                            protocol detected by DPI\n"
	       " connlimit connections_per_period/period\n"
	       "                            limit of new connections for the rule.. The format is\n"
	       "                            [connections per period]/[period], where the period\n"
	       "                            is specified in seconds, minutes, or hours, and must\n"
	       "                            be indicated with the suffixes s, m, or h, respectively\n",
	       opts.argv[0], opts.argv[0], opts.argv[0], opts.argv[0], opts.argv[0]);
	return 0;
}

static int fw_rule_set_default(int argc, char **argv)
{
	struct fw_rule_set set;
	int gen_id, action, ret;

	if (argc < 2 || strcmp("default", *argv)) {
		fprintf(stderr, "usage: set default [accept|drop]\n");
		return -1;
	}
	argv++;
	if (strcmp("accept", *argv) == 0) {
		action = FW_PASS;
	} else
	if (strcmp("drop", *argv) == 0) {
		action = FW_DROP;
	} else {
		fprintf(stderr, "usage: set default [accept|drop]\n");
		return -1;
	}

	argc -= 2;
	argv += 1;
	ret = fw_try_set_dev(argc, argv);
	if (ret < 0) {
		return -1;
	}

	ret = fw_policy_get(&set, &gen_id);
	if (ret < 0)
		return ret;

	set.rules[set.num].action = action;
	fw_policy_set(&set, &gen_id);

	return 0;
}

static int fw_rule_flush(int argc, char **argv)
{
	struct fw_rule_set set;
	int ret;

	ret = fw_try_set_dev(argc, argv);
	if (ret < 0) {
		fw_rule_help(0, NULL);
		return -1;
	}

	memset(&set, 0, sizeof(set));	
	set.rules[0].action = FW_PASS;
	fw_policy_set(&set, NULL);

	return 0;
}

static int fw_rule_delete(int argc, char **argv)
{
	int rule_num;
	struct fw_rule_set set;
	int ret, gen_id, i;

	if (!argc)
		return -1;

	rule_num = atoi(*argv);
	if (rule_num <= 0 || rule_num > FW_MAX_RULES) {
		fprintf(stderr, "Rule number must be positive and not exceed %d.\n", FW_MAX_RULES);
		return -1;
	}
	argc--;
	argv++;

	ret = fw_try_set_dev(argc, argv);
	if (ret < 0) {
		fw_rule_help(0, NULL);
		return -1;
	}

	ret = fw_policy_get(&set, &gen_id);
	if (ret < 0)
		return ret;

	if (rule_num > set.num) {
		fprintf(stderr, "Rule number too large. Maximum allowed value is %d.\n", set.num);
		return -1;
	}

	rule_num--;
	for (i = rule_num; i < set.num; i++) {
		set.rules[i] = set.rules[i + 1];
	}

	set.num--;
	fw_policy_set(&set, &gen_id);

	return 0;
}

static void fw_print_stat(uint64_t value)
{
	int sp = 0;
	char *dim[] = {"", "k", "M", "G", "T", NULL};
	char str[8];

	while (value > 1000 && dim[sp+1]) {
		/* round */
		value += 500;
		value /= 1000;
		sp++;
	}
	snprintf(str, sizeof(str), "%ld%s", value, dim[sp]);
	printf("%6s", str);
}

static int fw_rule_set_show(const struct fw_rule_set *set, int set_id, bool show_stats)
{
	int stat_fd;
	int ret;
	int gen_id;
	int i;
	struct fw_rule_stats *stats;
	int ncpus;
	char *actions[] = {
		[FW_PASS] = "accept",
		[FW_DROP] = "drop",
	};

	if (show_stats) {
		ret = -1;
		ncpus = libbpf_num_possible_cpus();
		if (ncpus < 0) {
			fprintf(stderr, "Internal error. Please try again.\n");
			return ncpus;
		}
		stats = malloc(sizeof(*stats) * ncpus);
		if (!stats) {
			fprintf(stderr, "Internal error. Please try again.\n");
			return -1;
		}

		stat_fd = fw_map_get(FW_MAP_STATS);
		if (stat_fd < 0) {
			free(stats);
			return -1;
		}
	}

	if (show_stats)
	printf("   name                 src                dst proto   l7  action  pkts bytes  additional params\n");
	else
	printf("   name                 src                dst proto   l7  action  additional params\n");
	for (i = 0; i < set->num+1; i++) {
		const struct fw_rule *rule = &set->rules[i];
		unsigned int l7 = 0;
		int j;

		if (i == set->num)
			printf("default:");
		else
			printf("%2d rule:", i + 1);

		fw_print_ip(rule->saddr, rule->smask, 19);
		fw_print_ip(rule->daddr, rule->dmask, 19);

		ret = -1;
		if (print_array_index(protos, rule->protocol, 6) < 0) {
			goto out;
		}
		for (j = 0; j < FW_RULE_MAX_PARAMS; j++) {
			if (rule->params[j].type == FW_RULE_PARAM_L7_PROTOCOL) {
				struct rule_l7 *drule = (struct rule_l7 *)&rule->params[j];
				l7 = drule->protocol;
			}
		}
		if (print_array_index(srv_list, l7, 5) < 0) {
			goto out;
		}
		if (print_array_index(actions, rule->action, 8) < 0) {
			goto out;
		}

		if (show_stats) {
			gen_id = set_id * FW_MAX_RULES + i;
			ret = bpf_map_lookup_elem(stat_fd, &gen_id, stats);
			if (ret == 0) {
				int j;
				struct fw_rule_stats s = {0, 0};

				for (j = 0; j < ncpus; j++) {
					s.packets += stats[j].packets;
					s.bytes += stats[j].bytes;
				}
				fw_print_stat(s.packets);
				fw_print_stat(s.bytes);
			}
		}

		if (rule->protocol == IPPROTO_ICMP) {
			if (rule->icmp_type == ICMP_ECHO) {
				printf(" ping");
			}
		} else if (rule->sport)
			printf(" sport %d", ntohs(rule->sport));
		if (rule->dport)
			printf(" dport %d", ntohs(rule->dport));
		for (j = 0; j < FW_RULE_MAX_PARAMS; j++) {
			if (rule->params[j].type == FW_RULE_PARAM_CONNLIMIT) {
				struct connlimit *cl = (struct connlimit *)&rule->params[j];
				int ct_limit, time_limit;
				char t[] = {'s', 'm', 'h'};
				unsigned char ind = 0;
				ct_limit = cl->max_budget / cl->ct_cost;
				time_limit = cl->max_budget / (cl->tick_cost * HZ);
				if (time_limit >= 60 && time_limit % 60 == 0) {
					time_limit /= 60;
					ind++;
					if (time_limit >= 60 && time_limit % 60 == 0) {
						time_limit /= 60;
						ind++;
					}
				}
				printf(" connlimit %d/%d%c", ct_limit, time_limit, t[ind]);
			}
		}

		printf("\n");
	}

	ret = 0;
out:
	if (show_stats) {
		close(stat_fd);
		free(stats);
	}
	return ret;
}

static int fw_rule_show(int argc, char **argv)
{
	struct fw_rule_set set;
	int ret;
	int gen_id;

	ret = fw_try_set_dev(argc, argv);
	if (ret < 0) {
		fw_rule_help(0, NULL);
		return -1;
	}

	ret = fw_policy_get(&set, &gen_id);
	if (ret < 0) {
		fprintf(stderr, "Error while getting policy.\n");
		return ret;
	}

	return fw_rule_set_show(&set, gen_id % 2, true);
}

static struct cmd rule_cmds[] = {
	{ "show", fw_rule_show },
	{ "add", fw_rule_add },
	{ "delete", fw_rule_delete },
	{ "flush", fw_rule_flush },
	{ "set", fw_rule_set_default },
	{ "help", fw_rule_help },
	{ NULL, fw_rule_help },
};

int fw_prog_rule(int argc, char **argv)
{
	return fw_run_cmd(rule_cmds, argc, argv);
}


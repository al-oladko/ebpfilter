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
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#define LOCK_FILE "/var/run/ebpfilter.lock"


#include "fw_rule.h"
#include "fw_dpi.h"

#define __unused __attribute__((__unused__))

enum {
	FW_MAP_RULES = 0,
	FW_MAP_GENID,
	FW_MAP_STATS,
	FW_MAP_MAX,
};
char *maps_to_pin[] = {
	[FW_MAP_RULES] = "fw_rules_table",
	[FW_MAP_GENID] = "fw_table_generation",
	[FW_MAP_STATS] = "fw_stats",
	[FW_MAP_MAX]   = "",
};

struct {
	char prog_dir_path[PATH_MAX];
	char prog_file_name[NAME_MAX];
	char prog_name[NAME_MAX];
	char pinned_maps_dir[PATH_MAX];
} cfg = {
	.prog_dir_path = "/lib/bpf",
	.prog_file_name = "ebpfilter.xdp.o",
	.prog_name = "xdp_rcv",
	.pinned_maps_dir = "/sys/fs/bpf",
};

struct cmd {
	char *cmd;
	int (*handler)(int argc, char **argv);
};

#define XDP_MODE_NATIVE 1
#define XDP_MODE_LIBXDP 2
struct {
	char iface[IFNAMSIZ];
	int ifindex;
	int mode;
	int need_to_pin;
	int argc;
	char **argv;
	int verbose;
} opts = {
	.ifindex = -1,
	.mode = XDP_MODE_NATIVE,
};

#define print_verbose(format, ...)			\
({							\
	if (opts.verbose)				\
		printf((format), ##__VA_ARGS__);	\
})

int configure(void)
{
	struct stat s;
	char xdp_prog_filename[PATH_MAX];

	snprintf(xdp_prog_filename, sizeof(xdp_prog_filename), "%s/%s", cfg.prog_dir_path, cfg.prog_file_name);
	if (stat(xdp_prog_filename, &s) == 0)
		return 0;
	print_verbose("File not found %s\n", xdp_prog_filename);
	
	if (getcwd(cfg.prog_dir_path, sizeof(cfg.prog_dir_path)) == NULL) {
		fprintf(stderr, "Internal error. Please try again.\n");
		return -1;
	}
	
	snprintf(xdp_prog_filename, sizeof(xdp_prog_filename), "%s/%s", cfg.prog_dir_path, cfg.prog_file_name);
	if (stat(xdp_prog_filename, &s) == 0)
		return 0;
	print_verbose("File not found %s\n", xdp_prog_filename);
	fprintf(stderr, "XDP program not found. Try reinstalling the program.\n");
	return -1;
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

#ifdef HAVE_LIBXDP
#define IS_ERR(ptr)  ((uintptr_t)(ptr) >= (uintptr_t)-4095)
#define IS_ERR_OR_NULL(ptr) (!(ptr) || IS_ERR(ptr))
int fw_prog_is_attached(int ifindex)
{
	int ret = 0;
	struct xdp_multiprog *mp;
	struct xdp_program *prog = NULL;

	mp = xdp_multiprog__get_from_ifindex(ifindex);
	if (IS_ERR_OR_NULL(mp))
		return 0;

	if (xdp_multiprog__is_legacy(mp)) {
		prog = xdp_multiprog__main_prog(mp);
		if (prog && strcmp(xdp_program__name(prog), cfg.prog_name) == 0)
			ret = 1;

		goto out;
	}

	while ((prog = xdp_multiprog__next_prog(prog, mp))) {
		if (strcmp(xdp_program__name(prog), cfg.prog_name) == 0) {
			ret = 1;
			break;
		}
	}
out:
	xdp_multiprog__close(mp);
	return ret;
}
#else
int fw_prog_is_attached(int ifindex)
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

	if (strcmp(info.name, cfg.prog_name) == 0)
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

int fw_detect_dev(struct if_nameindex *iface, int attached)
{
	if (!attached)
		return 0;
	if (opts.ifindex > 0)
		return -1;
	opts.ifindex = iface->if_index;
	memcpy(opts.iface, iface->if_name, IFNAMSIZ);
	return 0;
}

char *fw_map_name(uint8_t map_id)
{
	if (map_id > FW_MAP_MAX)
		map_id = FW_MAP_MAX;;
	return maps_to_pin[map_id];
}

char *fw_map_path(uint8_t map_id)
{
	static char pinned_map_path[PATH_MAX];

	snprintf(pinned_map_path, sizeof(pinned_map_path), "%s/%s_%s", cfg.pinned_maps_dir, fw_map_name(map_id), opts.iface);
	return pinned_map_path;
}

int fw_do_map_get(uint8_t map_id, bool silence)
{
	char *pinned_map_path;
	int fd;

	pinned_map_path = fw_map_path(map_id);
	fd = bpf_obj_get(pinned_map_path);
	if (!silence && fd < 0)
		fprintf(stderr, "Error while opening %s: %s\n", pinned_map_path, strerror(errno));

	return fd;
}

int fw_map_get(uint8_t map_id)
{
	return fw_do_map_get(map_id, false);
}

int fw_map_try_get(uint8_t map_id)
{
	return fw_do_map_get(map_id, true);
}

int fw_map_reuse(struct bpf_object *obj, uint8_t map_id)
{
	int pinned_map_fd;
	struct bpf_map *map;
	int ret;

	map = bpf_object__find_map_by_name(obj, fw_map_name(map_id));
	if (!map)
		return -1;

	pinned_map_fd = fw_map_try_get(map_id);
	if (pinned_map_fd >= 0) {
		ret = bpf_map__reuse_fd(map, pinned_map_fd);
		print_verbose("Reuse pinned map: %s\n", fw_map_name(map_id));
		return ret;
	}
	return 1;
}

int fw_maps_reuse(struct bpf_object *obj)
{
	int i, ret;

	for (i = 0; i < FW_MAP_MAX; i++) {
		ret = fw_map_reuse(obj, i);
		if (ret < 0) {
			return ret;
		}
		if (ret == 1) {
			opts.need_to_pin = 1;
			break;
		}
	}

	return 0;
}

int fw_map_pin(struct bpf_object *obj, uint8_t map_id)
{
	struct bpf_map *map;
	char *pinned_map_path;
	int ret;

	map = bpf_object__find_map_by_name(obj, fw_map_name(map_id));
	if (!map)
		return -1;

	pinned_map_path = fw_map_path(map_id);
	ret = bpf_map__pin(map, pinned_map_path);
	print_verbose("Will pin map: %s to %s, ret %d\n", fw_map_name(map_id), pinned_map_path, ret);
	return ret;
}

int fw_maps_pin(struct bpf_object *obj)
{
	int i, ret;

	if (!opts.need_to_pin)
		return 0;
	for (i = 0; i < FW_MAP_MAX; i++) {
		ret = fw_map_pin(obj, i);
		if (ret < 0) {
			return ret;
		}
	}
	return 0;
}

void fw_maps_unpin(void);
int fw_prog_native_load(void)
{
	char xdp_prog_filename[PATH_MAX];
	struct bpf_object *obj = NULL;
	struct bpf_program *prog = NULL;
	int ret = -1;

	snprintf(xdp_prog_filename, sizeof(xdp_prog_filename), "%s/%s", cfg.prog_dir_path, cfg.prog_file_name);

	obj = bpf_object__open_file(xdp_prog_filename, NULL);
	if (!obj) {
		fprintf(stderr, "Error while opening %s\n", xdp_prog_filename);
		return -1;
	}

	ret = fw_maps_reuse(obj);
	if (ret < 0) {
		goto out;
	}

	ret = bpf_object__load(obj);
	if (ret) {
		fprintf(stderr, "Error while loading: %s\n", strerror(-ret));
		goto out;
	}

	prog = bpf_object__find_program_by_name(obj, cfg.prog_name);
	if (!prog) {
		fprintf(stderr, "Prog \"%s\" not found in %s\n", cfg.prog_name, xdp_prog_filename);
		ret = -1;
		goto out;
	}

	ret = fw_maps_pin(obj);
	if (ret < 0) {
		goto out;
	}
	//TODO default table

#ifdef HAVE_BPF_XDP_ATTACH
        ret = bpf_xdp_attach(opts.ifindex, bpf_program__fd(prog), XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
#else
        ret = bpf_set_link_xdp_fd(opts.ifindex, bpf_program__fd(prog), XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST);
#endif
	if (ret < 0) {
		fprintf(stderr, "Failed to attach program to %s: %s\n", cfg.prog_name, strerror(-ret));
		goto unpin_maps;
	}

out:
	bpf_object__close(obj);
	return ret;
unpin_maps:
	fw_maps_unpin();
	goto out;
}

#ifdef HAVE_LIBXDP
int fw_prog_libxdp_load(void)
{
	struct xdp_program *prog;
	struct bpf_object *obj;
	char xdp_prog_filename[PATH_MAX];
	int ret;

	snprintf(xdp_prog_filename, sizeof(xdp_prog_filename), "%s/%s", cfg.prog_dir_path, cfg.prog_file_name);
	prog = xdp_program__open_file(xdp_prog_filename, cfg.prog_name, NULL);
	if (!prog) {
		fprintf(stderr, "Error opening object %s: No such file or directory\n", xdp_prog_filename);
		return 1;
	}

	obj = xdp_program__bpf_obj(prog);
	ret = fw_maps_reuse(obj);
	if (ret < 0) {
		bpf_object__close(obj);
		return ret;
	}

	ret = xdp_program__attach(prog, opts.ifindex, XDP_MODE_NATIVE, 0);
	if (ret == -EOPNOTSUPP) {
		ret = xdp_program__attach(prog, opts.ifindex, XDP_MODE_SKB, 0);
	}
	if (ret < 0) {
		fprintf(stderr, "Can not attach XDP to %s\n", opts.iface);
		bpf_object__close(obj);
		return ret;
	}

	ret = fw_maps_pin(obj);
	if (ret < 0) {
		bpf_object__close(obj);
		return ret;
	}
	//TODO default table
	return 0;
}
#else
int fw_prog_libxdp_load(void)
{
	return -EOPNOTSUPP;
}
#endif

int fw_load_parse_opts(int argc, char **argv)
{
	int ret;

	while (argc > 0) {
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
		if (strcmp("mode", *argv) == 0) {
			argc--;
			if (argc <= 0) {
				return -1;
			}
			argv++;
			if(strcmp("native", *argv) == 0) {
				opts.mode = XDP_MODE_NATIVE;
				goto next;
			}
			if(strcmp("libxdp", *argv) == 0) {
				opts.mode = XDP_MODE_LIBXDP;
				goto next;
			}
			fprintf(stderr, "Invalid mode \"%s\"\n", *argv);
			return -1;
		}
		fprintf(stderr,"Unknown option '%s'\n", *argv);
		return -1;
next:
		argc--;
		argv++;
	}

	return 0;
}

int fw_prog_load(int argc, char **argv)
{
	int ret;

	ret = fw_load_parse_opts(argc, argv);
	if (ret < 0)
		return ret;

	if (opts.ifindex < 0) {
		fprintf(stderr, "Not enough information: 'dev' argument is required\n");
		return -1;
	}
	if (opts.mode == XDP_MODE_LIBXDP)
		return fw_prog_libxdp_load();
	return fw_prog_native_load();
}

void fw_maps_unpin(void)
{
	char *pinned_map_path;
	int i;

	for (i = 0; i < FW_MAP_MAX; i++) {
		pinned_map_path = fw_map_path(i);
		unlink(pinned_map_path);
	}
}
#ifdef HAVE_LIBXDP
int fw_prog_do_unload(void)
{
	int ret = 0;
	struct xdp_multiprog *mp;
	struct xdp_program *prog = NULL;

	mp = xdp_multiprog__get_from_ifindex(opts.ifindex);
	if (IS_ERR_OR_NULL(mp))
#ifdef HAVE_BPF_XDP_ATTACH
		return bpf_xdp_detach(opts.ifindex, XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
#else
		return bpf_set_link_xdp_fd(opts.ifindex, -1, XDP_FLAGS_UPDATE_IF_NOEXIST);
#endif

	if (xdp_multiprog__is_legacy(mp)) {
		prog = xdp_multiprog__main_prog(mp);
		if (!prog)
			goto out;
		if (strcmp(xdp_program__name(prog), cfg.prog_name)) {
			fprintf(stderr, "Prog \"%s\" has not been loaded, current prog %s\n", cfg.prog_name, xdp_program__name(prog));
			ret = -1;
			goto out;
		}

		xdp_multiprog__detach(mp);
		goto out;
	}

	while ((prog = xdp_multiprog__next_prog(prog, mp))) {
		if (strcmp(xdp_program__name(prog), cfg.prog_name) == 0) {
			enum xdp_attach_mode mode = xdp_multiprog__attach_mode(mp);
			xdp_program__detach(prog, opts.ifindex, mode, 0);
			break;
		}
	}
out:
	xdp_multiprog__close(mp);
	return ret;
}
#else
int fw_prog_do_unload(void)
{
	if (opts.mode == XDP_MODE_LIBXDP)
		return -EOPNOTSUPP;
#ifdef HAVE_BPF_XDP_ATTACH
	return bpf_xdp_detach(opts.ifindex, XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
#else
	return bpf_set_link_xdp_fd(opts.ifindex, -1, XDP_FLAGS_UPDATE_IF_NOEXIST);
#endif
}
#endif

int fw_do_unload(struct if_nameindex *iface, int attached)
{
	int ret;

	if (!attached)
		return 0;
	
	if (iface) {
		opts.ifindex = iface->if_index;
		memcpy(opts.iface, iface->if_name, IFNAMSIZ);
	}
	
	ret = fw_prog_do_unload();
	fw_maps_unpin();
	return ret;
}

int fw_prog_unload(int argc, char **argv)
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

	if (opts.ifindex < 0)
		return fw_for_each_dev(fw_do_unload);

	return fw_do_unload(NULL, 1);
}

struct ip_addr {
	uint32_t ip;
	uint32_t mask;
};

#define RULE_NAME_LEN 32
struct rule {
	char name[RULE_NAME_LEN];
	int rule_num;
	struct ip_addr src;
	struct ip_addr dst;
	union {
		struct {
		uint16_t sport;
		uint16_t dport;
		};
		struct {
			uint8_t icmp_type;
			uint8_t icmp_code;
			uint16_t icmp_id;
		};
	};
	uint8_t protocol;
	uint8_t l7protocol;
	int action;
};

void fw_stats_update(int gen_id)
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

int fw_policy_set(const struct fw_rule_set *set, int *cur_gen_id)
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

int fw_policy_get(struct fw_rule_set *set, int *gen_id)
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

int fw_policy_update(struct rule *rule)
{
	struct fw_rule_set set;
	struct fw_rule frule;
	int ret, gen_id, i;

	ret = fw_policy_get(&set, &gen_id);
	if (ret < 0)
		return ret;
	if (rule->rule_num) {
		/* index in array */
		rule->rule_num--;
		if (rule->rule_num > set.num) {
			fprintf(stderr, "Index of insertion too big. Maximum allowed value is %d\n", set.num);
			return -1;
		}
	} else {
		/* add the rule to the buttom */
		rule->rule_num = set.num;
	}
	if (set.num + 1 >= FW_MAX_RULES) {
		fprintf(stderr, "Maximum number of rules reached.\n");
		return -1;
	}
	set.num++;
	memset(&frule, 0, sizeof(frule));
	if (rule->src.ip) {
		frule.saddr = rule->src.ip;
		frule.smask = rule->src.mask;
	}
	if (rule->dst.ip) {
		frule.daddr = rule->dst.ip;
		frule.dmask = rule->dst.mask;
	}
	if (rule->protocol) {
		frule.protocol = rule->protocol;
		frule.sport = rule->sport;
		frule.dport = rule->dport;
	}
	if (rule->l7protocol) {
		struct rule_l7 *drule = (struct rule_l7 *)&frule.params[0];
		/* TODO struct */
		drule->type = FW_RULE_PARAM_L7_PROTOCOL;
		drule->protocol = rule->l7protocol;
	}
	frule.action = rule->action;

	for (i = set.num; i > rule->rule_num; i--) {
		set.rules[i] = set.rules[i - 1];
	}
	set.rules[rule->rule_num] = frule;
	fw_policy_set(&set, &gen_id);

	return 0;
}

int fw_get_ip(struct ip_addr *ip, char *arg)
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

char *srv_list[DPI_PROTO_MAX] = {
	"-", "ssh", "http", "dns", "tls", "unk"
};
int fw_rule_add(int argc, char **argv)
{
	int ret;
	int rule_num, next_port, action_f = 0;
	struct rule rule;

	if (!argc)
		return -1;
	memset(&rule, 0, sizeof(rule));
	rule_num = atoi(*argv);
	if (rule_num < 0 || rule_num > FW_MAX_RULES) {
		fprintf(stderr, "Rule number must be positive and not exceed %d\n", FW_MAX_RULES);
		return -1;
	}
	if (rule_num) {
		rule.rule_num = rule_num;
		argv++;
		argc--;
	}
	while (argc > 0) {
		if (strcmp("name", *argv) == 0) {
			argv++;
			argc--;
			strncpy(rule.name, *argv, RULE_NAME_LEN - 1);
			rule.name[RULE_NAME_LEN - 1] = 0;
			goto next;
		}
		if (strcmp("src", *argv) == 0) {
			argv++;
			argc--;
			ret = fw_get_ip(&rule.src, *argv);
			if (ret < 0)
				break;
			goto next;
		}
		if (strcmp("dst", *argv) == 0) {
			argv++;
			argc--;
			ret = fw_get_ip(&rule.dst, *argv);
			if (ret < 0)
				break;
			goto next;
		}
		if (strcmp("action", *argv) == 0) {
			argv++;
			argc--;
			action_f = 1;
			if (strcmp("drop", *argv) == 0) {
				rule.action = FW_DROP;
				goto next;
			} else 
			if (strcmp("accept", *argv) == 0) {
				rule.action = FW_PASS;
				goto next;
			}
		}
		if (strcmp("icmp", *argv) == 0) {
			rule.protocol = IPPROTO_ICMP;
			goto next;
		}
		if (strcmp("tcp", *argv) == 0) {
			rule.protocol = IPPROTO_TCP;
			next_port = 1;
			goto next_port;
		}
		if (strcmp("udp", *argv) == 0) {
			rule.protocol = IPPROTO_UDP;
			next_port = 1;
			goto next_port;
		}
		if (strcmp("port", *argv) == 0) {
			if (!next_port || rule.dport) {
				fprintf(stderr, "Port number can only be specified if TCP or UDP protocol is selected.\n");
				return -1;
			}
			argv++;
			argc--;
			ret = atoi(*argv);
			if (!ret || ret > 65535) {
				fprintf(stderr, "Invalid port number '%s'.\n", *argv);
				return -1;
			}
			rule.dport = htons(ret);
			goto next_port;
		}
		if (strcmp("src-port", *argv) == 0) {
			if (!next_port || rule.sport) {
				fprintf(stderr, "Port number can only be specified if TCP or UDP protocol is selected.\n");
				return -1;
			}
			argv++;
			argc--;
			ret = atoi(*argv);
			if (!ret || ret > 65535) {
				fprintf(stderr, "Invalid port number '%s'.\n", *argv);
				return -1;
			}
			rule.sport = htons(ret);
			goto next_port;
		}
		if (strcmp("service", *argv) == 0) {
			argv++;
			argc--;
			if (strcmp("ping", *argv) == 0) {
				if (rule.protocol && rule.protocol != IPPROTO_ICMP) {
					fprintf(stderr, "Ping service cannot be specified when TCP or UDP protocol is selected.\n");
					return -1;
				}
				rule.protocol = IPPROTO_ICMP;
				rule.icmp_type = ICMP_ECHO;
			} else
			if (strcmp("tls", *argv) == 0) {
				rule.l7protocol = DPI_PROTO_TLS;
			} else
			if (strcmp("ssh", *argv) == 0) {
				rule.l7protocol = DPI_PROTO_SSH;
			} else
			if (strcmp("http", *argv) == 0) {
				rule.l7protocol = DPI_PROTO_HTTP;
			} else
			if (strcmp("dns", *argv) == 0) {
				rule.l7protocol = DPI_PROTO_DNS;
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
		fprintf(stderr,"Unknown option '%s'\n", *argv);
		return -1;
next:
		next_port = 0;
next_port:
		argc--;
		argv++;
	}

	if (!action_f) {
		fprintf(stderr, "Not enough information: 'action' argument is required\n");
		return -1;
	}

	if (fw_opts_check_and_get_dev() < 0) {
		return -1;
	}

	return fw_policy_update(&rule);
}

int fw_rule_help(__unused int argc, __unused char **argv)
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
	       "                            protocol detected by DPI\n",
	       opts.argv[0], opts.argv[0], opts.argv[0], opts.argv[0], opts.argv[0]);
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

int fw_rule_set_default(int argc, char **argv)
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

int fw_rule_flush(int argc, char **argv)
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

int fw_rule_delete(int argc, char **argv)
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

void fw_print_ip(__be32 addr, __be32 mask)
{
	char str[32] = "any";
	if (addr) {
		int mask_len = __builtin_popcount(mask);
		struct in_addr in = {
			.s_addr = addr,
		};
		if (mask_len && mask_len < 32) 
			snprintf(str, sizeof(str), "%s/%d", inet_ntoa(in), mask_len);
		else
			snprintf(str, sizeof(str), "%s", inet_ntoa(in));
	}
	printf("%19s", str);
}

void fw_print_stat(uint64_t value)
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

#define check_array_index(array, index) ((index) < (sizeof(array) / sizeof(array[0])))
#define print_array_index(array, index, width)				\
({									\
	int __ret = -1;							\
	if (check_array_index((array), (index))) {			\
		__ret = 0;						\
		printf("%" #width "s", (array)[(index)]);		\
	} else								\
		printf("\nInvalid rule. " #index " %d\n", (index));	\
	__ret;								\
})
int fw_rule_show(int argc, char **argv)
{
	int stat_fd;
	struct fw_rule_set set;
	int ret;
	int gen_id, set_id;
	int i;
	struct fw_rule_stats *stats;
	int ncpus;
	char *protos[] = {
		[IPPROTO_IP]	= "any",
		[IPPROTO_ICMP]	= "icmp",
		[IPPROTO_TCP]	= "tcp",
		[IPPROTO_UDP]	= "udp",
	};
	char *actions[] = {
		[FW_PASS] = "accept",
		[FW_DROP] = "drop",
	};

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
	set_id = gen_id % 2;

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

	printf("   name                 src                dst proto   l7  action  pkts bytes  additional params\n");
	for (i = 0; i < set.num+1; i++) {
		struct fw_rule *rule = &set.rules[i];
		unsigned int l7 = 0;

		if (i == set.num)
			printf("default:");
		else
			printf("%2d rule:", i + 1);

		fw_print_ip(rule->saddr, rule->smask);
		fw_print_ip(rule->daddr, rule->dmask);

		ret = -1;
		if (print_array_index(protos, rule->protocol, 6) < 0) {
			goto out;
		}
		if (rule->params[0].type == FW_RULE_PARAM_L7_PROTOCOL) {
			struct rule_l7 *drule = (struct rule_l7 *)&rule->params[0];
			l7 = drule->protocol;
		}
		if (print_array_index(srv_list, l7, 5) < 0) {
			goto out;
		}
		if (print_array_index(actions, rule->action, 8) < 0) {
			goto out;
		}

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

		if (rule->protocol == IPPROTO_ICMP) {
			if (rule->icmp_type == ICMP_ECHO) {
				printf(" ping");
			}
		} else if (rule->sport)
			printf(" sport %d", ntohs(rule->sport));
		if (rule->dport)
			printf(" dport %d", ntohs(rule->dport));

		printf("\n");
	}

	ret = 0;
out:
	close(stat_fd);
	free(stats);
	return ret;
}

bool fw_cmd_eq(const char *str, const char *cmd)
{
	while (*str && *str == *cmd) {
		str++;
		cmd++;
	}
	return *str == 0;
}

int fw_run_cmd(const struct cmd *cmd, int argc, char **argv)
{
	int i;

	if (!argc)
		return cmd[0].handler(0, NULL);

	for (i = 0; cmd[i].cmd; i++) {
		if (fw_cmd_eq(argv[0], cmd[i].cmd)) {
			return cmd[i].handler(argc - 1, argv + 1);
		}
	}
	return cmd[i].handler(0, NULL);
}

struct cmd rule_cmds[] = {
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

#define RED_TEXT(text)		"\033[1;31m" text "\033[0m"
#define GREEN_TEXT(text)	"\033[1;32m" text "\033[0m"
#define GET_STR2(s) #s
#define GET_STR(s) GET_STR2(s)
int fw_print_status(struct if_nameindex *iface, int attached)
{
	printf("%d: %-" GET_STR(IFNAMSIZ) "s %s\n", iface->if_index, iface->if_name, 
			attached ? GREEN_TEXT("running") : RED_TEXT("not attached"));
	
	return 0;
}

int fw_prog_status(__unused int argc, __unused char **argv)
{
	return fw_for_each_dev(fw_print_status);
}

int fw_prog_do_reload(void)
{
	int ret;

	ret = fw_prog_do_unload();
	if (ret < 0)
		return ret;

	if (opts.mode == XDP_MODE_LIBXDP)
		return fw_prog_libxdp_load();
	return fw_prog_native_load();
}

int fw_prog_reload_all(struct if_nameindex *iface, int attached)
{
	if (!attached)
		return 0;
	opts.ifindex = iface->if_index;
	memcpy(opts.iface, iface->if_name, IFNAMSIZ);
	
	return fw_prog_do_reload();
}

int fw_prog_reload(int argc, char **argv)
{
	int ret;

	ret = fw_load_parse_opts(argc, argv);
	if (ret < 0)
		return ret;

	if (opts.ifindex < 0)
		return fw_for_each_dev(fw_prog_reload_all);

	return fw_prog_do_reload();
}

int fw_prog_help(__unused int argc, __unused char **argv)
{
	printf("Usage: %s OBJECT { COMMAND | help }\n"
	       "where  OBJECT := { load | unload | rule | status | help }\n\n"
	       " %s load dev IFNAME      Load an XDP program for a interface IFNAME\n"
	       " %s unload [dev IFNAME]  Unload the XDP program from interface IFNAME,\n"
	       "                         or from all interfaces if IFNAME is not specified\n"
	       " %s status               List interfaces where the XDP program is running\n"
	       " %s reload               Reattaching the XDP program while preserving the loaded rule set\n",
		opts.argv[0], opts.argv[0], opts.argv[0], opts.argv[0], opts.argv[0]);
	return 0;
}

struct cmd cmds[] = {
	{ "help", fw_prog_help },
	{ "status", fw_prog_status },
	{ "load", fw_prog_load },
	{ "unload", fw_prog_unload },
	{ "rule", fw_prog_rule },
	{ "reload", fw_prog_reload },
	{ NULL, fw_prog_help },
};

int main(int argc, char **argv)
{
	int fd;

	opts.argc = argc;
	opts.argv = argv;

	if (argc > 1) {
		if (strcmp("-v", argv[1]) == 0 || strcmp("--verbose", argv[1]) == 0) {
			opts.verbose = 1;
			argc--;
			argv++;
		}
	}

	if (configure())
		return 0;

	fd = open(LOCK_FILE, O_RDWR | O_CREAT, 0640);
	if (fd < 0) {
		fprintf(stderr, "Internal error. Please try again.\n");
		exit(EXIT_FAILURE);
	}
	if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
		fprintf(stderr, "Another instance is already running");
		close(fd);
		exit(EXIT_FAILURE);
	}
	argc--;
	argv++;
	fw_run_cmd(cmds, argc, argv);

	close(fd);

	return 0;
}

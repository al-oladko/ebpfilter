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
#include <sys/sysinfo.h>
#include <sys/ioctl.h>
#include <time.h>

#include "ebpfilter.h"
#include "lib.h"
#include "rule.h"
#include "map.h"
#include "nat.h"
#include "policy.h"

#include "fw_rule.h"
#include "fw_dpi.h"
#include "fw_tuple.h"
#include "fw_connection.h"
#include "fw_progtable.h"
#include "fw_nat.h"

struct cfg cfg = {
	.conf_dir = "/etc/ebpfilter",
	.prog_dir_path = "/lib/bpf",
	.prog_file_name = "ebpfilter.xdp.o",
	.xdp_prog_name = "xdp_rcv",
	.tc_prog_name = "tc_rcv",
	.pinned_maps_dir = "/sys/fs/bpf",
};

struct opts opts = {
	.ifindex = -1,
	.mode = XDP_MODE_NATIVE,
};

static int configure(void)
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

static int fw_tc_prog_deattach(void)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = opts.ifindex,
			    .attach_point = BPF_TC_EGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);

	return bpf_tc_detach(&tc_hook, &tc_opts);
}

static int fw_tc_prog_attach(struct bpf_object *obj)
{
	struct bpf_program *tc_prog = NULL;
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = opts.ifindex,
			    .attach_point = BPF_TC_EGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);
	int ret;

	tc_prog = bpf_object__find_program_by_name(obj, cfg.tc_prog_name);
	if (!tc_prog) {
		fprintf(stderr, "Prog \"%s\" not found\n", cfg.tc_prog_name);
		return -1;
	}
	tc_opts.prog_fd = bpf_program__fd(tc_prog);
	ret = bpf_tc_hook_create(&tc_hook);
	if (ret && ret != -EEXIST) {
		fprintf(stderr, "Failed to create TC hook: %s\n", strerror(-ret));
		return ret;
	}

	ret = bpf_tc_attach(&tc_hook, &tc_opts);
	if (ret) {
		fprintf(stderr, "Failed to create TC hook: %s\n", strerror(-ret));
		return ret;
	}

	return 0;
}

static char *fw_prog_table_names[] = {
	[FW_PROG_TC_NAT] = "tc_nat",
	[FW_PROG_TC_NAT_FRAGMENT] = "tc_nat_fragment",
};
static int fw_call_table_init(struct bpf_object *obj)
{
	struct bpf_program *prog;
	int map_fd, prog_fd;
	int key, i;

	map_fd = fw_map_get(FW_MAP_PROG_TABLE);
	if (map_fd < 0)
		return map_fd;

	for (i = FW_PROG_CALL_START; i < FW_PROG_CALL_END; i++) {
		prog = bpf_object__find_program_by_name(obj, fw_prog_table_names[i]);
		if (!prog) {
			fprintf(stderr, "Prog \"%s\" not found in %s\n", fw_prog_table_names[i], bpf_object__name(obj));
			return -1;
		}

		key = i * 2 + 1;
		prog_fd = bpf_program__fd(prog);
		bpf_map_update_elem(map_fd, &key, &prog_fd, BPF_ANY);
	}

	return 0;
}

static int fw_prog_native_load(void)
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

	prog = bpf_object__find_program_by_name(obj, cfg.xdp_prog_name);
	if (!prog) {
		fprintf(stderr, "Prog \"%s\" not found in %s\n", cfg.xdp_prog_name, xdp_prog_filename);
		ret = -1;
		goto out;
	}

	ret = fw_maps_pin(obj);
	if (ret < 0) {
		goto out;
	}
	//TODO default table

	ret = fw_call_table_init(obj);
	if (ret < 0) {
		goto out;
	}

#ifdef HAVE_BPF_XDP_ATTACH
        ret = bpf_xdp_attach(opts.ifindex, bpf_program__fd(prog), XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
#else
        ret = bpf_set_link_xdp_fd(opts.ifindex, bpf_program__fd(prog), XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST);
#endif
	if (ret < 0) {
		fprintf(stderr, "Failed to attach program to %s: %s\n", cfg.xdp_prog_name, strerror(-ret));
		goto unpin_maps;
	}

	ret = fw_tc_prog_attach(obj);
	if (ret < 0)
		goto unload_xdp_prog;
out:
	bpf_object__close(obj);
	return ret;
unload_xdp_prog:
#ifdef HAVE_BPF_XDP_ATTACH
		return bpf_xdp_detach(opts.ifindex, XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
#else
		return bpf_set_link_xdp_fd(opts.ifindex, -1, XDP_FLAGS_UPDATE_IF_NOEXIST);
#endif
unpin_maps:
	fw_maps_unpin();
	goto out;
}

#ifdef HAVE_LIBXDP
static int fw_prog_libxdp_load(void)
{
	struct xdp_program *prog;
	struct bpf_object *obj;
	char xdp_prog_filename[PATH_MAX];
	int ret;
	enum xdp_attach_mode mode = XDP_MODE_NATIVE;

	snprintf(xdp_prog_filename, sizeof(xdp_prog_filename), "%s/%s", cfg.prog_dir_path, cfg.prog_file_name);
	prog = xdp_program__open_file(xdp_prog_filename, cfg.xdp_prog_name, NULL);
	if (!prog) {
		fprintf(stderr, "Error opening object %s: No such file or directory\n", xdp_prog_filename);
		return -1;
	}

	obj = xdp_program__bpf_obj(prog);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "Failed to load prog: %ld\n", libbpf_get_error(obj));
		return -1;
	}

	ret = fw_maps_reuse(obj);
	if (ret < 0) {
		goto out;
	}

	ret = xdp_program__attach(prog, opts.ifindex, mode, 0);
	if (ret == -EOPNOTSUPP) {
		mode = XDP_MODE_SKB;
		ret = xdp_program__attach(prog, opts.ifindex, mode, 0);
	}
	if (ret < 0) {
		fprintf(stderr, "Can not attach XDP to %s\n", opts.iface);
		goto out;
	}

	ret = fw_call_table_init(obj);
	if (ret < 0) {
		goto xdp_detach;
	}

	ret = fw_tc_prog_attach(obj);
	if (ret < 0) {
		goto xdp_detach;
	}

	ret = fw_maps_pin(obj);
	if (ret < 0) {
		goto xdp_detach;
	}
	//TODO default table
out:
	return ret;
xdp_detach:
	xdp_program__detach(prog, opts.ifindex, mode, 0);
	goto out;
}
#else
static int fw_prog_libxdp_load(void)
{
	return -EOPNOTSUPP;
}
#endif

static int fw_load_parse_opts(int argc, char **argv)
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

static int fw_prog_load(int argc, char **argv)
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

#ifdef HAVE_LIBXDP
static int fw_prog_do_unload(void)
{
	int ret = 0;
	struct xdp_multiprog *mp;
	struct xdp_program *prog = NULL;

	fw_tc_prog_deattach();

	mp = xdp_multiprog__get_from_ifindex(opts.ifindex);
	if (libbpf_get_error(mp))
#ifdef HAVE_BPF_XDP_ATTACH
		return bpf_xdp_detach(opts.ifindex, XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
#else
		return bpf_set_link_xdp_fd(opts.ifindex, -1, XDP_FLAGS_UPDATE_IF_NOEXIST);
#endif

	if (xdp_multiprog__is_legacy(mp)) {
		prog = xdp_multiprog__main_prog(mp);
		if (!prog)
			goto out;
		if (strcmp(xdp_program__name(prog), cfg.xdp_prog_name)) {
			fprintf(stderr, "Prog \"%s\" has not been loaded, current prog %s\n", cfg.xdp_prog_name, xdp_program__name(prog));
			ret = -1;
			goto out;
		}

		xdp_multiprog__detach(mp);
		goto out;
	}

	while ((prog = xdp_multiprog__next_prog(prog, mp))) {
		if (strcmp(xdp_program__name(prog), cfg.xdp_prog_name) == 0) {
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
static int fw_prog_do_unload(void)
{
	if (opts.mode == XDP_MODE_LIBXDP)
		return -EOPNOTSUPP;
	fw_tc_prog_deattach();
#ifdef HAVE_BPF_XDP_ATTACH
	return bpf_xdp_detach(opts.ifindex, XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
#else
	return bpf_set_link_xdp_fd(opts.ifindex, -1, XDP_FLAGS_UPDATE_IF_NOEXIST);
#endif
}
#endif

static int fw_do_unload(struct if_nameindex *iface, int attached)
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

static int fw_prog_unload(int argc, char **argv)
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

static bool fw_cmd_eq(const char *str, const char *cmd)
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
	fprintf(stderr, "Error: unknown command '%s'\n", *argv);
	if (cmd[i].handler)
		return cmd[i].handler(0, NULL);
	return -1;
}

static int fw_print_status(struct if_nameindex *iface, int attached)
{
	printf("%d: %-" GET_STR(IFNAMSIZ) "s %s\n", iface->if_index, iface->if_name, 
			attached ? GREEN_TEXT("running") : RED_TEXT("not attached"));
	
	return 0;
}

static int fw_prog_status(__unused int argc, __unused char **argv)
{
	return fw_for_each_dev(fw_print_status);
}

static int fw_prog_do_reload(void)
{
	int ret;

	ret = fw_prog_do_unload();
	if (ret < 0)
		return ret;

	if (opts.mode == XDP_MODE_LIBXDP)
		return fw_prog_libxdp_load();
	return fw_prog_native_load();
}

static int fw_prog_reload_all(struct if_nameindex *iface, int attached)
{
	if (!attached)
		return 0;
	opts.ifindex = iface->if_index;
	memcpy(opts.iface, iface->if_name, IFNAMSIZ);
	
	return fw_prog_do_reload();
}

static int fw_prog_reload(int argc, char **argv)
{
	int ret;

	ret = fw_load_parse_opts(argc, argv);
	if (ret < 0)
		return ret;

	if (opts.ifindex < 0)
		return fw_for_each_dev(fw_prog_reload_all);

	return fw_prog_do_reload();
}

#define MAP_IDS_NUM 16
static int fw_prog_connection(int argc, char **argv)
{
	int ret;
	int fd;
	__u32 prog_id;
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);
	__u32 map_ids[MAP_IDS_NUM];
	unsigned int i;
	int ct_map_fd = -1;
	struct fw4_tuple key, *prev_key = NULL;
	struct fw_conn ct;
	struct sysinfo sinfo;

	if (argc > 0) {
		if (argc != 2 || strcmp("dev", *argv))
			return -1;
		argv++;
		ret = parse_dev(*argv);
		if (ret < 0)
			return -1;
	}

	if (fw_opts_check_and_get_dev() < 0)
		return -1;

#ifdef HAVE_BPF_XDP_ATTACH
	ret = bpf_xdp_query_id(opts.ifindex, 0, &prog_id);
#else
	ret = bpf_get_link_xdp_id(iopts.findex, &prog_id, 0);
#endif
	if (ret < 0 || prog_id == 0) {
		fprintf(stderr, "Prog is not attached to %s.\n", opts.iface);
		return -1;
	}

	fd = bpf_prog_get_fd_by_id(prog_id);
	if (fd < 0) {
		fprintf(stderr, "Internal error. Please try again.\n");
		return -1;
	}

	info.nr_map_ids = MAP_IDS_NUM;
        info.map_ids = (__u64)(unsigned long)map_ids;
	ret = bpf_obj_get_info_by_fd(fd, &info, &len);
	if (ret) {
		fprintf(stderr, "Internal error. Please try again.\n");
		return -1;
	}

	for (i = 0; i < info.nr_map_ids; i++) {
		int map_fd = bpf_map_get_fd_by_id(map_ids[i]);
		struct bpf_map_info map_info = {};
		__u32 map_info_len = sizeof(map_info);

		if (map_fd < 0)
			continue;

		ret = bpf_obj_get_info_by_fd(map_fd, &map_info, &map_info_len);
		if (ret == 0) {
			if (strcmp(map_info.name, "fw_conn_tracker") == 0) {
				ct_map_fd = map_fd;
				break;
			}
		}
	}
	if (ct_map_fd < 0) {
		fprintf(stderr, "Internal error. Please try again.\n");
		return -1;
	}

	if (sysinfo(&sinfo) < 0) {
		fprintf(stderr, "Internal error. Please try again.\n");
		return -1;
	}

	if (opts.verbose)
	printf("            src             dst proto ports        info                        status\n");
	else
	printf("            src             dst proto ports        info    status\n");
	while (bpf_map_get_next_key(ct_map_fd, prev_key, &key) == 0) {
		time_t timeout;
		if (bpf_map_lookup_elem(ct_map_fd, &key, &ct) != 0) {
			continue;
		}
		timeout = (ct.timeout - (4294967295 - (300 * HZ))) / HZ;
		fw_print_ip(key.saddr, 0, 15);
		fw_print_ip(key.daddr, 0, 16);
		print_array_index(protos, key.l4protocol, 6);
		if (key.l4protocol == IPPROTO_TCP || key.l4protocol == IPPROTO_UDP) {
			char str[16];
			snprintf(str, sizeof(str), "%d->%d", ntohs(key.sport), ntohs(key.dport));
			printf(" %-12s", str);
		} else {
				printf("             ");
		}
		printf(" %18s", timeout - sinfo.uptime < 0 ? RED_TEXT("expired") : GREEN_TEXT("active"));
		if (opts.verbose) {
			if (timeout - sinfo.uptime < 0) {
				int pr = 0;
				int len = 0;
				char format[32];

				timeout = sinfo.uptime - timeout;
				printf(" ");
				if (timeout > 24 * 3600) {
					len = printf("%ldd:", timeout / 24 * 3600);
					pr++;
					timeout %= (24 * 3600);
				}
				if (pr || timeout > 3600) {
					len += printf("%02ldh:", timeout / 3600);
					pr++;
					timeout %= 3600;
				}
				if (pr || timeout > 60) {
					len += printf("%02ldm:", timeout / 60);
					timeout %= 60;
				}
				len += printf("%02lds", timeout);
				snprintf(format, sizeof(format), "%%-%ds", 19 - len < 4 ? 4 : 19 - len);
				printf(format, " ago");
			} else {
				char str[32];
				snprintf(str, sizeof(str)," expired in %lds", timeout - sinfo.uptime);
				printf("%-20s", str);
			}
		}
		printf(" %s by rule %d\n", ct.fw_action == FW_DROP ? RED_TEXT(" dropped") : GREEN_TEXT("accepted"), ct.fw_rule_num + 1);
		prev_key = &key;
	}
	return 0;
}

static int fw_prog_help(__unused int argc, __unused char **argv)
{
	printf("Usage: %s OBJECT { COMMAND | help }\n"
	       "where  OBJECT := { load | unload | rule | nat | policy | status | help }\n\n"
	       " %s load dev IFNAME      Load an XDP program for a interface IFNAME\n"
	       " %s unload [dev IFNAME]  Unload the XDP program from interface IFNAME,\n"
	       "                                or from all interfaces if IFNAME is not specified\n"
	       " %s rule ...             firewall rule managment. see '%s rule help' for more\n"
	       "                                information\n"
	       " %s nat ...              nat rule managment. see '%s nat help' for more information\n"
	       " %s status               List interfaces where the XDP program is running\n"
	       " %s connection           View connection tracking table\n"
	       " %s reload               Reattaching the XDP program while preserving the loaded rule set\n"
	       " %s policy               firewall policy management\n",
		opts.argv[0], opts.argv[0], opts.argv[0], opts.argv[0], opts.argv[0], opts.argv[0],
		opts.argv[0], opts.argv[0], opts.argv[0], opts.argv[0], opts.argv[0]);
	return 0;
}

static struct cmd cmds[] = {
	{ "help", fw_prog_help },
	{ "status", fw_prog_status },
	{ "load", fw_prog_load },
	{ "unload", fw_prog_unload },
	{ "rule", fw_prog_rule },
	{ "reload", fw_prog_reload },
	{ "connection", fw_prog_connection },
	{ "nat", fw_prog_nat },
	{ "snat", fw_prog_snat },
	{ "policy", fw_prog_policy },
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

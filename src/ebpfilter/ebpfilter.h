// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2025 Aleksei Oladko <aleks.oladko@gmail.com>
#pragma once

#include <linux/limits.h>
#include <net/if.h>

#define LOCK_FILE "/var/run/ebpfilter.lock"
#define __unused __attribute__((__unused__))

struct cfg {
	char conf_dir[PATH_MAX];
	char prog_dir_path[PATH_MAX];
	char prog_file_name[NAME_MAX];
	char xdp_prog_name[NAME_MAX];
	char tc_prog_name[NAME_MAX];
	char pinned_maps_dir[PATH_MAX];
};

extern struct cfg cfg;

struct cmd {
	char *cmd;
	int (*handler)(int argc, char **argv);
};

#define XDP_MODE_NATIVE 1
#define XDP_MODE_LIBXDP 2
struct opts {
	char iface[IFNAMSIZ];
	int ifindex;
	int mode;
	int need_to_pin;
	int argc;
	char **argv;
	char *rules_file;
	int verbose;
};

extern struct opts opts;

int fw_run_cmd(const struct cmd *cmd, int argc, char **argv);

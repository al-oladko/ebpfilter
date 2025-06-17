// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2025 Aleksei Oladko <aleks.oladko@gmail.com>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "ebpfilter.h"
#include "lib.h"
#include "map.h"

char *maps_to_pin[] = {
	[FW_MAP_RULES] = "fw_rules_table",
	[FW_MAP_GENID] = "fw_table_generation",
	[FW_MAP_STATS] = "fw_stats",
	[FW_MAP_NAT]   = "fw_nat",
	[FW_MAP_PROG_TABLE] = "fw_prog_table",
	[FW_MAP_MAX]   = "",
};

static char *fw_map_name(uint8_t map_id)
{
	if (map_id > FW_MAP_MAX)
		map_id = FW_MAP_MAX;;
	return maps_to_pin[map_id];
}

static char *fw_map_path(uint8_t map_id)
{
	static char pinned_map_path[PATH_MAX];

	snprintf(pinned_map_path, sizeof(pinned_map_path), "%s/%s_%s", cfg.pinned_maps_dir, fw_map_name(map_id), opts.iface);
	return pinned_map_path;
}

static int fw_do_map_get(uint8_t map_id, bool silence)
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

static int fw_map_try_get(uint8_t map_id)
{
	return fw_do_map_get(map_id, true);
}

static int fw_map_reuse(struct bpf_object *obj, uint8_t map_id)
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

static int fw_map_pin(struct bpf_object *obj, uint8_t map_id)
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

void fw_maps_unpin(void)
{
	char *pinned_map_path;
	int i;

	for (i = 0; i < FW_MAP_MAX; i++) {
		pinned_map_path = fw_map_path(i);
		unlink(pinned_map_path);
	}
}

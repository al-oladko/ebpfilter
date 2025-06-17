// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2025 Aleksei Oladko <aleks.oladko@gmail.com>
#pragma once

enum {
	FW_MAP_RULES = 0,
	FW_MAP_GENID,
	FW_MAP_STATS,
	FW_MAP_NAT,
	FW_MAP_PROG_TABLE,
	FW_MAP_MAX,
};

int fw_map_get(uint8_t map_id);
int fw_maps_reuse(struct bpf_object *obj);
int fw_maps_pin(struct bpf_object *obj);
int fw_maps_reuse(struct bpf_object *obj);
void fw_maps_unpin(void);

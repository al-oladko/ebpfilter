// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2025 Aleksei Oladko <aleks.oladko@gmail.com>
#pragma once

#include "fw_progtable.h"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, FW_PROG_CALL_MAX * 2);
} fw_prog_table SEC(".maps");

static __always_inline int fw_bpf_goto(void *ctx, int label)
{
	bpf_tail_call(ctx, &fw_prog_table, label);
	return XDP_PASS;
}

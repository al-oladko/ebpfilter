// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2025 Aleksei Oladko <aleks.oladko@gmail.com>
#pragma once

#include "fw_config.h"

#define FW_PASS 0
#define FW_DROP 1

#define FW_RULE_PARAM_NONE		0
#define FW_RULE_PARAM_L7_PROTOCOL	1
#define FW_RULE_PARAM_CONNLIMIT		2

#define FW_RULE_MAX_PARAMS		2
struct fw_param {
	__u8	type;
	__u8	arg_u8;
	__u16	arg_u16;
	__u32	arg0_u32;
	__u32	arg1_u32;
	__u64	arg0_u64;
	__u64	arg1_u64;
};

struct connlimit {
	__u8	type;
	__u8	credit;
	__u16	ct_cost;
	__u32	tick_cost;
	__s32	max_budget;
	/* It is necessary to use __s64 instead of __s32 due to the defect "fatal
	 * error: error in backend: Cannot select: 0x3c1c2c80: i64,ch = AtomicLoadSub
	 * <(load store seq_cst (s32) on %ir.896)>"
	 */
	__s64	budget;
	__u64	jiffies;
};

struct fw_rule {
	__be32 saddr;
	__be32 daddr;
	__be32 smask;
	__be32 dmask;
	union {
		struct {
			__be16 sport;
			__be16 dport;
		};
		struct {
			__u8 icmp_type;
			__u8 icmp_code;
			__be16 icmp_id;
		};
	};
	__u8 protocol;
	__u8 action;
	int flags;
	struct fw_param params[FW_RULE_MAX_PARAMS];
};

struct fw_rule_set {
	int num;
	struct fw_rule rules[FW_MAX_RULES];
};

struct fw_rule_stats {
	__u64 packets;
	__u64 bytes;
};


// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2025 Aleksei Oladko <aleks.oladko@gmail.com>
#pragma once

#include "fw_rule.h"
#include "fw_dpi.h"

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
	/* connlimit */
	int ct_cost;
	int tick_cost;
	int connlimit_budget;
};

int fw_prog_rule(int argc, char **argv);

extern struct config_ops rule_config_txt;
extern struct config_ops rule_config_yaml;

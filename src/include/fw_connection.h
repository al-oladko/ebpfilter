// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2025 Aleksei Oladko <aleks.oladko@gmail.com>
#pragma once

#include "fw_dpi.h"

#define FW_CT_NEW		1
#define FW_CT_ESTABLISHED	2

#define FWCT_DIR_FORWARD	0
#define FWCT_DIR_REPLY		1

struct fw_conn {
	int ppc;
	int status;
	__u64 timeout;
	/* fw fields */
	int fw_table_genid;
	__u16 fw_action;
	__u16 fw_rule_num;
	__u8 need_recheck;
	/* l4 fields */
	__u8 tcp_state;
	__u8 revert_dir;
	struct dpi_ctx dpi;
};


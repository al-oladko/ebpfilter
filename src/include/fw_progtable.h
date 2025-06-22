// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2025 Aleksei Oladko <aleks.oladko@gmail.com>
#pragma once

enum {
	FW_PROG_TC_NAT = 0,
#define FW_PROG_CALL_START FW_PROG_TC_NAT
	FW_PROG_TC_NAT_FRAGMENT,
	FW_PROG_CALL_MAX,
#define FW_PROG_CALL_END FW_PROG_CALL_MAX
};

// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2025 Aleksei Oladko <aleks.oladko@gmail.com>
#pragma once

#define DPI_NONE	0
#define DPI_IN_PROGRESS 1
#define DPI_FINISHED	2
#define DPI_PROTO_NONE		0
#define DPI_PROTO_SSH		1
#define DPI_PROTO_HTTP		2
#define DPI_PROTO_DNS		3
#define DPI_PROTO_TLS		4
#define DPI_PROTO_UNKNOWN	5
#define DPI_PROTO_MAX		(DPI_PROTO_UNKNOWN+1)

struct dpi_ctx {
	int status;
	__u32 protocol;
	int excluded_protocols;
	int changed;
};

struct rule_l7 {
	__u8 type;
	__u8 pad0;
	__u16	pad1;
	__u32	protocol;
	__u32	pad2;
};

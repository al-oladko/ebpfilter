// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2025 Aleksei Oladko <aleks.oladko@gmail.com>
#pragma once

struct fw4_tuple {
	__be32 saddr;
	__be32 daddr;
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
		__u32	l4all;
	};
	//__u8 l4protocol;
	__be32 l4protocol; /* 32bit bound for map keys */
};


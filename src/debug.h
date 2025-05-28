// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2025 Aleksei Oladko <aleks.oladko@gmail.com>
#pragma once

#define DEBUG
#ifdef DEBUG

#define pr_dbg(format, ...) bpf_printk(format, ##__VA_ARGS__)

#else
static __always_inline void no_bpf_printk(__attribute__((unused)) char *format, ...)
{
	return;
}
#define pr_dbg(format, ...)	\
	if (0)	\
		no_bpf_printk(format, ##__VA_ARGS__)
#endif

// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2025 Aleksei Oladko <aleks.oladko@gmail.com>
#pragma once

static __always_inline __s64 atomic_read(__s64 *v)
{
	return (__s64)*(volatile __s64 *)v;
}

static __always_inline __s64 atomic64_sub_return(__s64 *v, int sub)
{
	return __sync_sub_and_fetch(v, sub);
	*v -= sub;
	return *v;
}

static __always_inline __s64 atomic64_add_return(__s64 *v, int add)
{
	return __sync_add_and_fetch(v, add);
}

static __always_inline __s64 atomic64_cmpxchg(__s64 *v, __s64 old, __s64 new)
{
	return __sync_val_compare_and_swap(v, old, new);
}


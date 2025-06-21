// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2025 Aleksei Oladko <aleks.oladko@gmail.com>
#pragma once

#include <stdio.h>
#include <netinet/in.h>

#define RED_TEXT(text)		"\033[1;31m" text "\033[0m"
#define GREEN_TEXT(text)	"\033[1;32m" text "\033[0m"
#define GET_STR2(s) #s
#define GET_STR(s) GET_STR2(s)

#define print_verbose(format, ...)			\
({							\
	if (opts.verbose)				\
		printf((format), ##__VA_ARGS__);	\
})

#define check_array_index(array, index) ((index) < (sizeof(array) / sizeof(array[0])))
#define print_array_index(array, index, width)				\
({									\
	int __ret = -1;							\
	if (check_array_index((array), (index))) {			\
		__ret = 0;						\
		printf("%" #width "s", (array)[(index)]);		\
	} else								\
		printf("\nInvalid rule. " #index " %d\n", (index));	\
	__ret;								\
})

#define MAX_RULE_WORDS 64

char *fw_ip_str(__be32 addr, __be32 mask);
void fw_print_ip(__be32 addr, __be32 mask, int width);
int fw_opts_check_and_get_dev(void);
int fw_try_set_dev(int argc, char **argv);
int fw_for_each_dev(int (*f)(struct if_nameindex *, int));
int parse_dev(char *iface);
int fwlib_file_line_parse(FILE *f, void *ctx, int (*cb)(void *, int, char **));
extern char *protos[IPPROTO_RAW];

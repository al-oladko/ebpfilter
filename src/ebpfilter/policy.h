// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2025 Aleksei Oladko <aleks.oladko@gmail.com>
#pragma once

struct config_ops {
	int (*apply)(void *parser);
	int (*show)(void *parser);
	int (*save)(void *parser);
};

int fw_prog_policy(int argc, char **argv);

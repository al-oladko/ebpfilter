// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2025 Aleksei Oladko <aleks.oladko@gmail.com>
#pragma once

#include "policy.h"

int fw_prog_nat(int argc, char **argv);
int fw_prog_snat(int argc, char **argv);


extern struct config_ops nat_config_txt;
extern struct config_ops nat_config_yaml;

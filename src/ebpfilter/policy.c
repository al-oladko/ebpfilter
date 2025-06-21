// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2025 Aleksei Oladko <aleks.oladko@gmail.com>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <linux/limits.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <linux/icmp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <yaml.h>

#include "ebpfilter.h"
#include "lib.h"
#include "map.h"
#include "rule.h"
#include "nat.h"
#include "policy.h"

#include "fw_nat.h"

static int fw_policy_get_path(char *path, size_t len)
{
	if (!opts.rules_file) {
		snprintf(path, len, "%s/policy_%s", cfg.conf_dir, opts.iface);
		return 0;
	}

	if (getcwd(path, len) == NULL) {
		fprintf(stderr, "Error: Internal error. Please try again.\n");
		return -1;
	}

	snprintf(path + strlen(path), len - strlen(path), "/%s", opts.rules_file);
	return 0;
}

enum {
	FW_CONFIG_FORMAT_TXT = 0,
	FW_CONFIG_FORMAT_YAML,
	FW_CONFIG_FORMAT_UNKNOWN,
#define	FW_CONFIG_FORMAT_MAX FW_CONFIG_FORMAT_UNKNOWN
};

enum {
	FW_POLICY_RULES = 0,
	FW_POLICY_NAT,
	FW_POLICY_MAX,
};

enum {
	FW_POLICY_CMD_APPLY,
	FW_POLICY_CMD_SHOW,
	FW_POLICY_CMD_SAVE,
	FW_POLICY_CMD_MAX,
};

typedef int (*format_cmd)(void *);
struct format_ops {
	void *(*open)(int);
	int (*close)(void *);
	format_cmd cmd[FW_POLICY_CMD_MAX];
};

static struct config_ops *txt_mods[FW_POLICY_MAX] = {
	[FW_POLICY_RULES] = &rule_config_txt,
	[FW_POLICY_NAT] = &nat_config_txt,
};

static int fw_txt_apply(char *rpath)
{
	int i;
	int ret;
	FILE *f;

	f = fopen(rpath, "r");
	if (!f) {
		fprintf(stderr, "Error: Internal error. Please try again.\n");
		return -1;
	}
	for (i = 0; i < FW_POLICY_MAX; i++) {
		struct config_ops *c = txt_mods[i];
		ret = c->apply(f);
		if (ret < 0)
			goto out;
	}
out:
	fclose(f);
	return ret;
}

static int fw_txt_show(char *rpath)
{
	int i;
	int ret;
	FILE *f;

	f = fopen(rpath, "r");
	if (!f) {
		fprintf(stderr, "Error: Internal error. Please try again.\n");
		return -1;
	}

	for (i = 0; i < FW_POLICY_MAX; i++) {
		struct config_ops *c = txt_mods[i];
		ret = c->show(f);
		if (ret < 0)
			goto out;
	}
out:
	fclose(f);
	return ret;
}

static int fw_txt_save(char *rpath)
{
	int i;
	int ret;
	FILE *f;

	f = fopen(rpath, "w");
	if (!f) {
		fprintf(stderr, "Error: Internal error. Please try again.\n");
		return -1;
	}

	for (i = 0; i < FW_POLICY_MAX; i++) {
		struct config_ops *c = txt_mods[i];
		ret = c->save(f);
		if (ret < 0)
			goto out;
	}
out:
	fclose(f);
	return ret;
}

static int fw_policy_command_txt(int command)
{
	char rpath[PATH_MAX] = "";
	int ret;

	ret = fw_policy_get_path(rpath, sizeof(rpath));
	if (ret < 0)
		return ret;
	switch (command) {
	case FW_POLICY_CMD_APPLY:
		return fw_txt_apply(rpath);
	case FW_POLICY_CMD_SHOW:
		return fw_txt_show(rpath);
	case FW_POLICY_CMD_SAVE:
		return fw_txt_save(rpath);
	}

	return -1;
}

static struct config_ops *yaml_mods[FW_POLICY_MAX] = {
	[FW_POLICY_RULES] = &rule_config_yaml,
	[FW_POLICY_NAT] = &nat_config_yaml,
};
static int fw_yaml_save(char *rpath)
{
	FILE *f = fopen(rpath, "w");
	yaml_emitter_t emitter;
	yaml_event_t event;
	int ret = 0;
	int i;
	struct config_ops *conf;

	if (!f) {
		fprintf(stderr, "Error: File not found: %s\n", rpath);
		return -1;
	}

	yaml_emitter_initialize(&emitter);
	yaml_emitter_set_output_file(&emitter, f);

	yaml_stream_start_event_initialize(&event, YAML_UTF8_ENCODING);
	if (!yaml_emitter_emit(&emitter, &event)) goto error;

	yaml_document_start_event_initialize(&event, NULL, NULL, NULL, 0);
	if (!yaml_emitter_emit(&emitter, &event)) goto error;

	yaml_mapping_start_event_initialize(&event, NULL, (yaml_char_t *)YAML_MAP_TAG,
			1, YAML_ANY_MAPPING_STYLE);
	if (!yaml_emitter_emit(&emitter, &event)) goto error;

	for (i = 0; i < FW_POLICY_MAX; i++) {
		conf = yaml_mods[i];
		ret = conf->save(&emitter);
		if (ret < 0)
			goto out;
	}

	yaml_mapping_end_event_initialize(&event);
	if (!yaml_emitter_emit(&emitter, &event)) goto error;

	yaml_document_end_event_initialize(&event, 0);
	if (!yaml_emitter_emit(&emitter, &event)) goto error;

	yaml_stream_end_event_initialize(&event);
	if (!yaml_emitter_emit(&emitter, &event)) goto error;

out:
	yaml_emitter_delete(&emitter);

	fclose(f);
	return ret;
error:
	fprintf(stderr, "Error: Failed to emit event %d: %s\n", event.type, emitter.problem);
	goto out;
}

static int fw_yaml_show_apply(char *rpath, int command)
{
	FILE *f = fopen(rpath, "r");
	yaml_parser_t parser;
	yaml_event_t event;
	int stop = 0;
	int ret = 0;
	struct config_ops *mod;
	char *current_value;

	if (!f) {
		fprintf(stderr, "Error: File not found: %s\n", rpath);
		return -1;
	}

	yaml_parser_initialize(&parser);
	yaml_parser_set_input_file(&parser, f);

	while (stop == 0) {
		if (!yaml_parser_parse(&parser, &event)) {
			fprintf(stderr, "Parse error: %s\n", parser.problem);
			return -1;
		}

		switch (event.type) {
		case YAML_STREAM_END_EVENT:
			stop = 1;
			break;
		case YAML_SCALAR_EVENT:
			current_value = (char *)event.data.scalar.value;
			if (strcmp(current_value, "firewall") == 0) {
				mod = yaml_mods[FW_POLICY_RULES];
			} else if (strcmp(current_value, "nat") == 0) {
				mod = yaml_mods[FW_POLICY_NAT];
			} else {
				fprintf(stderr, "Error: Malformed file\n");
				stop = 1;
				ret = -1;
				break;
			}
			yaml_event_delete(&event);
			if (command == FW_POLICY_CMD_SHOW)
				ret = mod->show(&parser);
			else if (command == FW_POLICY_CMD_APPLY)
				ret = mod->apply(&parser);
			if (ret < 0)
				stop = 1;
			continue;
		default:
			break;
		};
		yaml_event_delete(&event);
	} ;

	yaml_parser_delete(&parser);
	fclose(f);

	return ret;
}

static int fw_policy_command_yaml(int command)
{
	char rpath[PATH_MAX] = "";
	int ret;

	ret = fw_policy_get_path(rpath, sizeof(rpath));
	if (ret < 0)
		return ret;

	switch (command) {
	case FW_POLICY_CMD_APPLY:
		return fw_yaml_show_apply(rpath, command);
	case FW_POLICY_CMD_SHOW:
		return fw_yaml_show_apply(rpath, command);
	case FW_POLICY_CMD_SAVE:
		return fw_yaml_save(rpath);
	}
	return 0;
}

static int fw_policy_command(int argc, char **argv, int command)
{
	int format = FW_CONFIG_FORMAT_YAML;
	bool f_param = false;
	int ret;

	while (argc > 0) {
		if (strcmp("file", *argv) == 0) {
			argv++;
			argc--;
			if (argc <= 0) {
				fprintf(stderr, "Error: Option 'file' requires an argument\n");
				return -1;
			}
			opts.rules_file = *argv;
			goto next;
		}
		if (strcmp("format", *argv) == 0) {
			argv++;
			argc--;
			if (argc <= 0) {
				fprintf(stderr, "Error: Option 'format' requires an argument\n");
				return -1;
			}
			if (strcmp("txt", *argv) == 0) {
				format = FW_CONFIG_FORMAT_TXT;
			} else if (strcmp("yaml", *argv) == 0) {
				format = FW_CONFIG_FORMAT_YAML;
			} else {
				fprintf(stderr, "Error: only \"txt\' and \"yaml\" are supported\n");
				return -1;
			}
			f_param = true;
			goto next;
		}
		if (strcmp("dev", *argv) == 0) {
			argc--;
			if (argc <= 0) {
				fprintf(stderr, "Error: Option 'dev' requires an argument\n");
				return -1;
			}
			argv++;
			ret = parse_dev(*argv);
			if (ret < 0) {
				return -1;
			}
			goto next;
		}
		fprintf(stderr,"UError: nknown option '%s'\n", *argv);
		return -1;
next:
		argc--;
		argv++;
	}
	if (command != FW_POLICY_CMD_SHOW && fw_opts_check_and_get_dev() < 0) {
		return -1;
	}

	if (format == FW_CONFIG_FORMAT_YAML) {
		ret = fw_policy_command_yaml(command);
		if (ret < 0 && !f_param) {
			format = FW_CONFIG_FORMAT_TXT;
		}
	}
	if (format == FW_CONFIG_FORMAT_TXT)
		return fw_policy_command_txt(command);

	return ret;
}

static int fw_policy_save(int argc, char **argv)
{
	return fw_policy_command(argc, argv, FW_POLICY_CMD_SAVE);
}

static int fw_policy_apply(int argc, char **argv)
{
	return fw_policy_command(argc, argv, FW_POLICY_CMD_APPLY);
}

static int fw_policy_show(int argc, char **argv)
{
	return fw_policy_command(argc, argv, FW_POLICY_CMD_SHOW);
}

static int fw_policy_help(__unused int argc, __unused char **argv)
{
	printf("Usage: %s rule apply options [dev IFNAME]\n"
	       "       %s rule save options [dev IFNAME]\n"
	       "       %s rule show options\n"
	       " If the XDP program is attached to only one interface, the dev parameter may be omitted.\n\n"
	       "Commands        Description\n"
	       "  apply         Load a policy from a file into the firewall\n"
	       "  save          Save the currently loaded policy to a file\n"
	       "  show          Display the saved policy\n"
	       "options:\n"
	       "  file          specifies the path to the policy file\n"
	       "  format        allows specifying the file format for saving the policy.\n"
	       "                Accepts yaml or txt. Defaults to yaml\n",
	       opts.argv[0], opts.argv[0], opts.argv[0]);
	return 0;
}

static struct cmd policy_cmds[] = {
	{ "show", fw_policy_show },
	{ "save", fw_policy_save },
	{ "apply", fw_policy_apply },
	{ "help", fw_policy_help },
	{ NULL, fw_policy_help },
};

int fw_prog_policy(int argc, char **argv)
{
	return fw_run_cmd(policy_cmds, argc, argv);
}


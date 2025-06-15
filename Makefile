ROOT_DIR := $(shell dirname "$(realpath $(lastword $(MAKEFILE_LIST)))")
SRC_DIR := ${ROOT_DIR}/src
BASH_COMPLETION_PATH := /usr/share/bash-completion/completions/
export ROOT_DIR SRC_DIR

all: ebpf

ebpf:
	$(MAKE) -C $(SRC_DIR)

clean:
	$(MAKE) -C $(SRC_DIR) clean

install: all
	$(MAKE) -C $(SRC_DIR) install
	install -D -m 0644 ${ROOT_DIR}/bash-completion/ebpfilter     $(DESTDIR)$(BASH_COMPLETION_PATH)

.PHONY: all clean install ebpf

ROOT_DIR := $(shell dirname "$(realpath $(lastword $(MAKEFILE_LIST)))")
SRC_DIR := ${ROOT_DIR}/src
XDP_DIR := ${SRC_DIR}/xdp
EBPF_DIR := ${SRC_DIR}/ebpfilter
BASH_COMPLETION_PATH := /usr/share/bash-completion/completions/
export ROOT_DIR SRC_DIR XDP_DIR EBPF_DIR

all: ebpf xdp

ebpf:
	$(MAKE) -C $(EBPF_DIR)

xdp:
	$(MAKE) -C $(XDP_DIR)

clean:
	$(MAKE) -C $(XDP_DIR) clean
	$(MAKE) -C $(EBPF_DIR) clean

install: all
	$(MAKE) -C $(XDP_DIR) install
	$(MAKE) -C $(EBPF_DIR) install
	install -D -m 0644 ${ROOT_DIR}/bash-completion/ebpfilter     $(DESTDIR)$(BASH_COMPLETION_PATH)

.PHONY: all clean install ebpf

ROOT_DIR := $(shell dirname "$(realpath $(lastword $(MAKEFILE_LIST)))")
SRC_DIR := ${ROOT_DIR}/src
export ROOT_DIR SRC_DIR

all: ebpf

ebpf:
	$(MAKE) -C $(SRC_DIR)

clean:
	$(MAKE) -C $(SRC_DIR) clean

install: all
	$(MAKE) -C $(SRC_DIR) install

#	install -D -m 0755 $(USER_APP) $(DESTDIR)$(INSTALL_SBIN)/$(LOADER_BIN)
#	install -D -m 0644 $(XDP_PROG_OBJ)     $(DESTDIR)$(INSTALL_BPF)/$(XDP_PROG_OBJ)

.PHONY: all clean install ebpf

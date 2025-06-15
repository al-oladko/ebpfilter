CLANG = clang
CFLAGS = -O2 -g -Wall -Wextra
LDFLAGS = -lbpf

-include ../build.conf

ifeq (1,$(HAVE_LIBXDP))
LDFLAGS += -lxdp
CFLAGS += -DHAVE_LIBXDP
endif
ifeq (1,$(HAVE_BPF_XDP_ATTACH))
CFLAGS += -DHAVE_BPF_XDP_ATTACH
endif
SRC_DIR ?= $(CURDIR)
INCLUDE_OPTS := -I$(SRC_DIR) -I$(SRC_DIR)/include

COMPONENTS := $(shell find $(SRC_DIR) -name '*.h')
XDP_PROG = ebpfilter.xdp
XDP_PROG_OBJ = $(XDP_PROG).o
INSTALL_SBIN := /usr/sbin
INSTALL_BPF  := /lib/bpf

USER_APP = ebpfilter

all: $(XDP_PROG_OBJ) $(USER_APP)

$(XDP_PROG_OBJ): $(XDP_PROG).c $(COMPONENTS)
	$(CLANG) $(CFLAGS) \
		-target bpf \
		$(INCLUDE_OPTS) \
		-c $< -o $@

$(USER_APP): $(USER_APP).c
	$(CLANG) $(CFLAGS) $(INCLUDE_OPTS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(XDP_PROG_OBJ) $(USER_APP)

install: all
	install -D -m 0755 $(USER_APP) $(DESTDIR)$(INSTALL_SBIN)/
	install -D -m 0644 $(XDP_PROG_OBJ)     $(DESTDIR)$(INSTALL_BPF)/$(XDP_PROG_OBJ)

.PHONY: all clean install

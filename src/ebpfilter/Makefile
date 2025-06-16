CLANG = clang
CFLAGS = -O2 -Wall -Wextra -MMD -MP
LDFLAGS = -lbpf

-include $(ROOT_DIR)/build.conf

ifeq (1,$(HAVE_LIBXDP))
LDFLAGS += -lxdp
CFLAGS += -DHAVE_LIBXDP
endif
ifeq (1,$(HAVE_BPF_XDP_ATTACH))
CFLAGS += -DHAVE_BPF_XDP_ATTACH
endif
INCLUDE_OPTS := -I$(EBPF_DIR) -I$(SRC_DIR)/include
SRC_DIR ?= $(CURDIR)

INSTALL_SBIN := /usr/sbin

USER_APP = ebpfilter

-include ebpfilter.d

all: $(USER_APP)

$(USER_APP): $(USER_APP).c
	$(CLANG) $(CFLAGS) $(INCLUDE_OPTS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(USER_APP) ebpfilter.d

install: all
	install -D -m 0755 $(USER_APP) $(DESTDIR)$(INSTALL_SBIN)/

.PHONY: all clean install

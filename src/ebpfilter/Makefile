CLANG = clang
CFLAGS = -O2 -Wall -Wextra -MMD -MP
LDFLAGS = -lbpf -lyaml

ROOT_DIR ?= $(CURDIR)/../..
-include $(ROOT_DIR)/build.conf

ifeq (1,$(HAVE_LIBXDP))
LDFLAGS += -lxdp
CFLAGS += -DHAVE_LIBXDP
endif
ifeq (1,$(HAVE_BPF_XDP_ATTACH))
CFLAGS += -DHAVE_BPF_XDP_ATTACH
endif
SRC_DIR ?= $(CURDIR)/..
EBPF_DIR ?= $(CURDIR)
INCLUDE_OPTS := -I$(EBPF_DIR) -I$(SRC_DIR)/include
SOURCES := $(wildcard *.c)
OBJECTS := $(patsubst %.c,%.o,$(SOURCES))
INSTALL_SBIN := /usr/sbin

DEPDIR := $(EBPF_DIR)/.deps
DEPS := $(patsubst %.c,$(DEPDIR)/%.d,$(SOURCES))

USER_APP = ebpfilter

all: depdir $(USER_APP)

depdir:
	@mkdir -p $(DEPDIR)

$(USER_APP): $(OBJECTS)
	$(CLANG) $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CLANG) $(INCLUDE_OPTS) $(CFLAGS) -c $< -o $@
	@mv $(basename $@).d $(DEPDIR)/$(notdir $(basename $@)).d

-include $(DEPS)

clean:
	rm -f $(USER_APP) $(OBJECTS) $(DEPS)

install: all
	install -D -m 0755 $(USER_APP) $(DESTDIR)$(INSTALL_SBIN)/

.PHONY: all depdir clean install

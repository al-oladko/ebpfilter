CLANG = clang
CFLAGS = -O2 -g -Wall -Wextra -MMD -MP

-include $(ROOT_DIR)/build.conf

INCLUDE_OPTS := -I$(XDP_DIR) -I$(SRC_DIR)/include
SRC_DIR ?= $(CURDIR)

XDP_PROG = ebpfilter.xdp
XDP_PROG_OBJ = $(XDP_PROG).o
INSTALL_BPF  := /lib/bpf

-include ebpfilter.xdp.d

all: $(XDP_PROG_OBJ)

#$(XDP_PROG_OBJ): $(XDP_PROG).c $(COMPONENTS)
$(XDP_PROG_OBJ): $(XDP_PROG).c $(COMPONENTS)
	$(CLANG) $(CFLAGS) \
		-target bpf \
		$(INCLUDE_OPTS) \
		-c $< -o $@

clean:
	rm -f $(XDP_PROG_OBJ) ebpfilter.xdp.d

install: all
	install -D -m 0644 $(XDP_PROG_OBJ)     $(DESTDIR)$(INSTALL_BPF)/$(XDP_PROG_OBJ)

.PHONY: all clean install

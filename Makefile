CC      ?= gcc
# -ffile-prefix-map is not optional: -g writes the compiler's working directory
# into DWARF .debug_line_str and the build stops being byte-reproducible.
CFLAGS  ?= -std=c11 -g -O2 -Wall -Wextra -Wpedantic -D_FORTIFY_SOURCE=2 \
           -fstack-protector-strong -ffile-prefix-map=$(CURDIR)=.

all: sockv t/probe

sockv: sockv.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# The oracle's own tool: builds netlink replies, well formed and otherwise.
t/probe: t/probe.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test: all
	@t/run.sh

clean:
	rm -f sockv t/probe
	rm -rf t/tmp

.PHONY: all test clean

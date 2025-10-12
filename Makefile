CC      ?= gcc
# -ffile-prefix-map is not optional: -g writes the compiler's working directory
# into DWARF .debug_line_str and the build stops being byte-reproducible.
CFLAGS  ?= -std=c11 -g -O2 -Wall -Wextra -Wpedantic -D_FORTIFY_SOURCE=2 \
           -fstack-protector-strong -ffile-prefix-map=$(CURDIR)=.

all: sockv

sockv: sockv.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f sockv

.PHONY: all clean

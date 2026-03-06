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

# A netlink reply is untrusted input, so the whole suite has to pass with the
# sanitizers on as well. Separate binaries, so `make test` stays fast.
#
# exitcode=86 is load-bearing rather than decoration. A sanitizer abort exits
# 1 by default, and t/run.sh asserts exit 1 for "the kernel returned an error"
# and exit 2 for "refused these bytes" -- so with the default, a heap overread
# would have scored as a clean diagnostic and test-asan could not have failed.
# UBSan needs halt_on_error as well, because otherwise it prints and carries
# on with the wrong value.
#
# t/probe is sanitised too. It is a test tool that pokes raw bytes into a
# fixed buffer with no bounds checks of its own, and a defect in the harness
# is at least as likely as one in the program it judges.
SANFLAGS = -std=c11 -g -O1 -fsanitize=address,undefined \
           -fno-omit-frame-pointer -Wall -Wextra -Wpedantic \
           -ffile-prefix-map=$(CURDIR)=.
SANOPT   = ASAN_OPTIONS=exitcode=86 \
           UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:exitcode=86

# Can the suite fail? Plants a defect, builds it, runs the whole suite against
# the broken binary, and asserts the verdict -- including for the mutants that
# are documented as surviving. Slow (one build and one full suite per mutant),
# so it is not part of `make test`.
mutants: all
	@t/mutants.sh

test-asan: sockv.c t/probe.c
	$(CC) $(SANFLAGS) -o sockv-san sockv.c $(LDFLAGS)
	$(CC) $(SANFLAGS) -o t/probe-san t/probe.c $(LDFLAGS)
	@$(SANOPT) t/run.sh $(CURDIR)/sockv-san $(CURDIR)/t/probe-san

clean:
	rm -f sockv sockv-san t/probe t/probe-san
	rm -rf t/tmp

.PHONY: all test test-asan mutants clean

#!/bin/sh
# Mutation testing for the oracle: can t/run.sh actually fail?
#
# The question a test suite has to answer is never "do the tests pass" but
# "have I watched this harness fail". Across the eighteen repositories this one
# belongs to, ten of the recorded defects were in the test rig rather than in
# the code -- suites that passed because they were quietly doing nothing. This
# project has already contributed one: --parse read its fixtures into a
# one-megabyte buffer, so a deleted bounds check overread into uninitialised
# bytes that were still inside the allocation and AddressSanitizer could not
# see it. `make test-asan` had no ability to detect the defect class it exists
# for, and every run of it was green.
#
# So: plant a defect in sockv.c with sed, build it, run the whole suite against
# the broken binary, and assert the result. Every mutant is expected either to
# be CAUGHT or to SURVIVE, and the survivors carry the reason -- asserting that
# a defect is *not* caught is how the suite's ceiling stays written down
# instead of becoming folklore. A survivor that starts being caught fails this
# script too, because then this file and the README are the things that are
# wrong.
set -u
LC_ALL=C
export LC_ALL

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CC=${CC:-gcc}
# -O1 and -w: this build exists to be broken, so its warnings are noise and
# its optimisation level only needs to be enough to compile.
MCFLAGS="-std=c11 -O1 -w"

WORK=$ROOT/t/tmp
rm -rf "$WORK"
mkdir -p "$WORK" || exit 2
trap 'rm -rf "$WORK"' EXIT INT TERM

pass=0; fail=0

# failcount OUTPUT -- how many assertions went red, from the suite's own line
failcount() {
	printf '%s\n' "$1" |
		sed -n 's/^[0-9]* passed, \([0-9]*\) failed.*/\1/p' | tail -1
}

# mutant NAME caught|survived SED_EXPR WHY
mutant() {
	_n=$1; _w=$2; _e=$3; _y=$4

	sed "$_e" "$ROOT/sockv.c" > "$WORK/m.c" || exit 2
	if cmp -s "$WORK/m.c" "$ROOT/sockv.c"; then
		fail=$((fail + 1))
		printf 'FAIL   %-38s the mutation did not apply; sockv.c moved\n' \
		    "$_n"
		printf '         sed: %s\n' "$_e"
		return
	fi
	if ! $CC $MCFLAGS -o "$WORK/mut" "$WORK/m.c" 2>"$WORK/cc"; then
		fail=$((fail + 1))
		printf 'FAIL   %-38s the mutant does not compile\n' "$_n"
		sed 's/^/         /' "$WORK/cc"
		return
	fi

	_o=$("$ROOT/t/run.sh" "$WORK/mut" 2>&1)
	_c=$(failcount "$_o")
	[ -n "$_c" ] || _c=unknown

	if [ "$_w" = caught ]; then
		if [ "$_c" != unknown ] && [ "$_c" -gt 0 ]; then
			pass=$((pass + 1))
			printf 'ok     %-38s caught by %s assertion(s)\n' "$_n" "$_c"
			printf '%s\n' "$_o" | sed -n 's/^FAIL  /         /p' |
				head -3
		else
			fail=$((fail + 1))
			printf 'FAIL   %-38s SHOULD be caught; the suite was clean\n' \
			    "$_n"
			printf '         the harness has lost the ability to see this\n'
		fi
	else
		if [ "$_c" = 0 ]; then
			pass=$((pass + 1))
			printf 'ok     %-38s survived, as documented\n' "$_n"
			printf '         %s\n' "$_y"
		else
			fail=$((fail + 1))
			printf 'FAIL   %-38s now CAUGHT by %s assertion(s)\n' \
			    "$_n" "$_c"
			printf '         good news; this file and the README now\n'
			printf '         claim a ceiling that is no longer there\n'
		fi
	fi
}

# Sanity first. With nothing planted the suite must be clean, or every verdict
# below means nothing.
[ -x "$ROOT/sockv" ] && [ -x "$ROOT/t/probe" ] || {
	echo "run 'make' first" >&2
	exit 2
}
clean=$("$ROOT/t/run.sh" 2>&1)
cc=$(failcount "$clean")
if [ "$cc" = 0 ]; then
	pass=$((pass + 1))
	printf 'ok     %-38s %s\n' "(no defect planted)" \
	    "$(printf '%s\n' "$clean" | tail -1)"
else
	printf 'FAIL   the unmutated suite is not clean:\n'
	printf '%s\n' "$clean" | sed -n 's/^FAIL  /         /p'
	printf '       nothing below can be trusted; fix that first\n'
	exit 1
fi
echo

# --- rendering: the fields every row carries ------------------------------
mutant 'port printed without ntohs' caught \
	's/ntohs(be_port)/be_port/' ''
mutant 'AF_INET address read as 16 bytes' caught \
	's/if (family == AF_INET) {/if (0) {/' ''
mutant 'INET_DIAG_SKV6ONLY ignored' caught \
	's/if (attr_u8(&at, INET_DIAG_SKV6ONLY, &v6only) < 0) return -1;/v6only = 1;/' ''
mutant 'ifindex scope suffix dropped' caught \
	's/if (ifindex) {/if (0) {/' ''
mutant 'uid hardcoded to zero' caught \
	's/m.idiag_inode, m.idiag_uid);/m.idiag_inode, 0);/' ''
mutant 'local and peer endpoints swapped' caught \
	's/m.id.idiag_src,$/m.id.idiag_dst,/' ''
mutant 'abstract name loses its @' caught \
	"s/name\\[0\\] = '@';/name[0] = 0;/" ''
mutant 'u_dgr relabelled u_str' caught \
	's/netid = "u_dgr"/netid = "u_str"/' ''
mutant 'UNIX_DIAG_PEER ignored' caught \
	's/if (attr_u32(&at, UNIX_DIAG_PEER, &peer) < 0) return -1;/peer = 0;/' ''
mutant 'every unix socket reads as unnamed' caught \
	's/if (!name\[0\]) snprintf/snprintf/' ''

# --- state filters: which sockets come back at all ------------------------
mutant '-l uses TCP_LISTEN for UDP' caught \
	's/listening ? SF(TCP_CLOSE)/listening ? SF(TCP_LISTEN)/' ''
# This replaces '-l treats u_dgr like u_str', which targeted a per-socket-type
# conditional that no longer exists: -l now accepts TCP_LISTEN or TCP_CLOSE for
# every UNIX type, because that is ss's own state mask and the type-conditional
# form was dropping the one unbound stream socket ss reports. Dropping the
# TCP_CLOSE arm is the equivalent mutation against the new shape -- it loses
# every u_dgr row and the UNCONN stream ones.
#
# The old mutant did not silently pass when its pattern stopped matching; the
# harness said "the mutation did not apply; sockv.c moved", which is why this
# needed retargeting rather than deleting.
mutant '-l drops the TCP_CLOSE half of the unix state mask' caught \
	's/m.udiag_state != TCP_LISTEN \&\& m.udiag_state != TCP_CLOSE/m.udiag_state != TCP_LISTEN/' ''

# --- the record walker: framing and bounds --------------------------------
mutant 'only the first record is read' caught \
	's/case SOCK_DIAG_BY_FAMILY:/case SOCK_DIAG_BY_FAMILY: d->done = 1;/' ''
mutant 'advance by nlmsg_len, not aligned' caught \
	's/step = NLMSG_ALIGN(h.nlmsg_len);/step = h.nlmsg_len;/' ''
mutant 'nlmsg_len lower bound deleted' caught \
	's/if (h.nlmsg_len < sizeof h)/if (0)/' ''
mutant 'nlmsg_len upper bound deleted' caught \
	's/if (h.nlmsg_len > len)/if (0)/' ''
mutant 'short-buffer check deleted' caught \
	's/if (len < sizeof h)/if (0)/' ''
mutant 'nla_len lower bound deleted' caught \
	's/if (a.nla_len < sizeof(struct nlattr))/if (0)/' ''
mutant 'nla_len upper bound deleted' caught \
	's/if (a.nla_len > len)/if (0)/' ''
mutant 'payload size check deleted' caught \
	's/if (payload < off)/if (0)/' ''
mutant 'unix name length check deleted' caught \
	's/if (n >= sizeof name)/if (0)/' ''
mutant 'u8 attribute length check deleted' caught \
	's/if (at->len\[t\] < 1)/if (0)/' ''
mutant 'NLM_F_DUMP_INTR ignored' caught \
	's/if (h.nlmsg_flags & NLM_F_DUMP_INTR) {/if (0) {/' ''

# The attribute walker and the record walker end with the same line, and
# loosening it is a real defect in one of them and provably equivalent in the
# other. Testing them separately is the only way to say which -- an earlier
# version of this file changed both at once, called the result equivalent, and
# was wrong: the empty-attribute fixture is exactly four bytes long and sits
# last in its message, so the loosened attribute test walks straight past it.
mutant 'attribute end-of-buffer loosened by 4' caught \
	'/step = NLA_ALIGN/{n;s/if (step >= len) return 0;/if (step + 4 >= len) return 0;/;}' ''

# --- documented survivors -------------------------------------------------
mutant 'record end-of-buffer loosened by 4' survived \
	'/step = NLMSG_ALIGN/{n;s/if (step >= len) return 0;/if (step + 4 >= len) return 0;/;}' \
	'provably equivalent: the test fires after the record has been
         processed, so the mutant only declines to look for a further
         record in fewer than four remaining bytes, and an nlmsghdr is
         sixteen. The same change to the attribute walker above is a real
         defect, because an attribute can be four bytes long'
mutant 'MSG_TRUNC check deleted' survived \
	's/if (msg.msg_flags & MSG_TRUNC)/if (0)/' \
	'unreachable on this machine: the receive buffer is 256KB and the
         kernel caps a dump datagram well below that, so nothing here can
         produce a truncated datagram to notice. Only a netns with tens of
         thousands of sockets, or a smaller buffer, would exercise it'

# --- and the one assertion that needs the sanitisers ----------------------
# Deleting a single bounds check does not overread: the attribute walker's own
# bound catches the inconsistency first. It takes removing both to leave the
# buffer, and that is what proves `make test-asan` can still see it.
echo
printf 'AddressSanitizer, both netlink bounds deleted:\n'
sed -e 's/if (h.nlmsg_len > len)/if (0)/' -e 's/if (a.nla_len > len)/if (0)/' \
	"$ROOT/sockv.c" > "$WORK/san.c"
if $CC -std=c11 -g -O1 -w -fsanitize=address,undefined \
     -fno-omit-frame-pointer -o "$WORK/mutsan" "$WORK/san.c" 2>"$WORK/cc"; then
	"$ROOT/t/probe" emit len-over "$WORK/f.bin"
	_e=$(ASAN_OPTIONS=exitcode=86 "$WORK/mutsan" --parse tcp "$WORK/f.bin" \
	     2>&1 >/dev/null)
	_s=$?
	if [ "$_s" -eq 86 ] &&
	   printf '%s' "$_e" | grep -q 'heap-buffer-overflow'; then
		pass=$((pass + 1))
		printf 'ok     %-38s heap-buffer-overflow, exit 86\n' \
		    'overread is reported'
	else
		fail=$((fail + 1))
		printf 'FAIL   %-38s want exit 86 and heap-buffer-overflow,\n' \
		    'overread is reported'
		printf '         got exit %s\n' "$_s"
		printf '%s\n' "$_e" | head -5 | sed 's/^/         /'
	fi
else
	printf 'skip   %-38s this compiler has no sanitisers\n' \
	    'overread is reported'
fi

echo
printf '%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]

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

# mktemp, not a fixed t/tmp. Two concurrent runs of this script used to
# delete each other's working directory at startup, and a sweep that takes
# minutes is exactly the thing somebody starts twice.
WORK=$(mktemp -d) || exit 2
trap 'rm -rf "$WORK"' EXIT INT TERM

# --check applies every mutation and reports whether it still matches the
# source, without building or running anything. A pattern that has stopped
# matching is a mutant that silently tests nothing, and sed expressions here
# pass through the shell's quote processing first, so grepping sockv.c for the
# pattern text answers a different question than sed does.
#
# It is deliberately NOT called from t/run.sh. A check that asks whether every
# pattern still appears in the source cannot run inside a harness that is
# replacing those patterns one at a time: during a sweep it would fail for
# that reason alone, the suite would go red, and the sweep would read red as
# the mutant having been caught. Every mutant would score as killed. See
# METHOD.md, which records two repositories that ran whole sweeps that way.
CHECK=0
QUIET=0
case "${1-}" in
--check)       CHECK=1 ;;
--check-quiet) CHECK=1; QUIET=1 ;;
esac

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
	if [ "$CHECK" = 1 ]; then
		# How many lines the expression changed. One is the intent of
		# every entry here: two means the pattern has grown a second
		# call site, which is how a mutant documented as provably
		# equivalent turned out to be a real defect in one of the two
		# places it was hitting.
		_d=$(diff "$ROOT/sockv.c" "$WORK/m.c" | grep -c '^<')
		if [ "$_d" = 1 ]; then
			pass=$((pass + 1))
			[ "$QUIET" = 1 ] ||
			    printf 'ok     %-38s matches one line\n' "$_n"
		else
			fail=$((fail + 1))
			printf 'FAIL   %-38s changes %s lines, not 1\n' \
			    "$_n" "$_d"
			printf '         sed: %s\n' "$_e"
		fi
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
clean=$([ "$CHECK" = 1 ] && echo '0 passed, 0 failed' ||
        "$ROOT/t/run.sh" 2>&1)
cc=$(failcount "$clean")
if [ "$CHECK" = 1 ]; then
	[ "$QUIET" = 1 ] ||
	    printf 'pattern check only: nothing is built and nothing is run\n\n'
elif [ "$cc" = 0 ]; then
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
	's/m.idiag_inode, m.idiag_uid, ext);/m.idiag_inode, 0, ext);/' ''
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

# --- INET_DIAG_REQ_BYTECODE: the filter the kernel runs -------------------
# The output assertions alone cannot judge most of these, because a filter
# applied in userspace after a full dump produces identical output. The pair
# that can are the record counts: the kernel must send fewer records with a
# filter than without, and exactly as many as sockv prints.
mutant 'bytecode attribute never attached' caught \
	's/if (bclen) {/if (0) {/' ''
# Anchored on the bc_add call rather than on the bare op code name, which
# also appears in the comment above it. Changing a comment as well did no
# harm, and a pattern that is looser than it reads is how a mutant ends up
# hitting a second place nobody meant it to -- the two call sites below are
# the case where that mattered.
mutant 'filter tests the peer end, not the local' caught \
	's/bc_add(INET_DIAG_BC_S_COND/bc_add(INET_DIAG_BC_D_COND/' ''
mutant 'hostcond port left as -1 (any port)' caught \
	's/c.port = port;/c.port = -1;/' ''
mutant 'hostcond port sent big-endian' caught \
	's/c.port = port;/c.port = (int)htons((uint16_t)port);/' ''
mutant 'hostcond prefix length zeroed' caught \
	's/c.prefix_len = (uint8_t)prefix_len;/c.prefix_len = 0;/' ''
# The kernel reads a jump past the end of the program as "reject" and a jump
# to exactly the end as "accept", so losing the +4 turns every filter into a
# filter that matches everything -- while still being a legal program the
# kernel's own audit pass accepts.
mutant 'reject jump lands on the end, not past it' caught \
	's/bclen - bcoff\[i\] + 4/bclen - bcoff[i]/' ''
mutant 'DEV_COND ifindex operand never written' caught \
	's/memcpy(bc.b + off, &idx, sizeof idx);/(void)idx;/' ''
# The witness itself. --records is the only thing that distinguishes a
# kernel-side filter from a userspace one, so a counter that does not count
# has to turn the suite red or the distinction is decoration.
mutant 'the record counter does not count' caught \
	's/d->recs++;//' ''
mutant 'a filter flag given twice is quietly ANDed' caught \
	's/if (seen\[which\]) {/if (0) {/' ''

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
# Two handlers, two separate mutants. The pattern used to hit both at once,
# which is the shape that made 'record end-of-buffer loosened by 4' look
# equivalent when one of its two sites was a real defect: a single sed
# changing two call sites cannot say which one the suite can see.
mutant 'inet payload size check deleted' caught \
	'/static int show_inet/,/^}/{s/if (payload < off)/if (0)/;}' ''
mutant 'unix payload size check deleted' caught \
	'/static int show_unix/,/^}/{s/if (payload < off)/if (0)/;}' ''
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

# --- idiag_ext and the columns it brings back -----------------------------
# An output comparison cannot see most of this on its own, for the same
# reason it cannot see where a filter ran: a listing of "-" is what both a
# request that never carried the mask and a kernel declining to answer look
# like. The arrival counts --records prints are what judge those, exactly as
# the record counts judge the bytecode.
mutant 'idiag_ext never set on the request' caught \
	's/req.r.idiag_ext = ext_mask;//' ''
# idiag_ext is a mask of (extension - 1). Losing the -1 asks for
# INET_DIAG_SHUTDOWN instead of INET_DIAG_SKMEMINFO and INET_DIAG_TOS instead
# of INET_DIAG_CONG, which are legal requests the kernel answers, so the
# reply is well formed and the columns are empty.
mutant 'idiag_ext bit computed without the -1' caught \
	's/1U << (INET_DIAG_SKMEMINFO - 1)/1U << INET_DIAG_SKMEMINFO/' ''
# udiag_show is the UNIX spelling and a separate field, so it needs its own
# pair rather than being assumed to follow from idiag_ext.
mutant 'UDIAG_SHOW_RQLEN never requested' caught \
	's/if (want_o) req.r.udiag_show |= UDIAG_SHOW_RQLEN;//' ''
mutant 'UDIAG_SHOW_MEMINFO never requested' caught \
	's/if (want_m) req.r.udiag_show |= UDIAG_SHOW_MEMINFO;//' ''
mutant 'Recv-Q and Send-Q swapped' caught \
	's/m->idiag_rqueue, m->idiag_wqueue,/m->idiag_wqueue, m->idiag_rqueue,/' ''
mutant 'the timer name table is off by one' caught \
	's/tm < NTIMER ? TIMER\[tm\]/tm < NTIMER ? TIMER[tm ? tm - 1 : 0]/' ''
# The expiry is the one sub-field the differential against ss deliberately
# does not compare, because it is a countdown read at two different instants.
# So this one is caught only by the probe's own keepalive socket, where the
# value is bounded by the TCP_KEEPIDLE the suite set, and by the sandwich
# that brackets it between two ss readings.
mutant 'the timer expiry is always zero' caught \
	's/m->idiag_expires, m->idiag_retrans);/0, m->idiag_retrans);/' ''
mutant 'the skmem labels are in the wrong order' caught \
	's/"r", "rb", "t", "tb"/"r", "rb", "tb", "t"/' ''
mutant 'a declined attribute prints as zeroes' caught \
	's/app(out, cap, n, " skmem:-");/app(out, cap, n, " skmem:(r0,rb0,t0,tb0,f0,w0,o0,bl0,d0)");/' ''
# The witnesses themselves. A counter that does not count makes every
# assertion about whether the attribute arrived pass by default.
mutant 'the skmem arrival counter does not count' caught \
	's/seen_skmem++;//' ''
mutant 'the cong arrival counter does not count' caught \
	's/seen_cong++;//' ''
mutant 'the timer counter does not count' caught \
	's/if (tm) seen_timer++;//' ''
# The new length checks. Each is only reached when its flag asked for the
# attribute, which is why each fixture passes the flag.
mutant 'skmem array length check deleted' caught \
	's/if (at->len\[type\] < sizeof v)/if (0)/' ''
mutant 'cong empty-attribute check deleted' caught \
	's/if (!len)$/if (0)/' ''
mutant 'cong over-long name check deleted' caught \
	's/if (len > sizeof name - 1)/if (0)/' ''
mutant 'unix_diag_rqlen length check deleted' caught \
	's/if (at->len\[UNIX_DIAG_RQLEN\] < sizeof q)/if (0)/' ''
# UNIX_DIAG_MEMINFO is 5 and INET_DIAG_SKMEMINFO is 7, and 7 on a UNIX
# record is UNIX_DIAG_UID -- four bytes where the array needs thirty-six, so
# this one is refused rather than printed wrongly.
mutant 'unix memory counters read from the wrong attribute' caught \
	's/at, UNIX_DIAG_MEMINFO)/at, INET_DIAG_SKMEMINFO)/' ''

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
if [ "$CHECK" = 1 ]; then
	if [ "$QUIET" = 1 ]; then
		if [ "$fail" -eq 0 ]; then
			printf '%d mutation patterns still match one line each\n' \
			    "$pass"
		fi
	else
		echo
		printf '%d passed, %d failed\n' "$pass" "$fail"
	fi
	[ "$fail" -eq 0 ]
	exit
fi

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

# And the same question for the attribute the -m column reads, because the
# length check in front of it is new and a bound nothing has been seen to
# enforce is a bound nobody has tested. The fixture matters as much as the
# mutation: the short array has to be the LAST thing in the reply, or the
# four bytes read past it land inside the same allocation and the sanitizer
# says nothing. Both shapes were measured and the README carries the table.
sed 's/if (at->len\[type\] < sizeof v)/if (0)/' "$ROOT/sockv.c" \
	> "$WORK/san2.c"
if $CC -std=c11 -g -O1 -w -fsanitize=address,undefined \
     -fno-omit-frame-pointer -o "$WORK/mutsan2" "$WORK/san2.c" 2>"$WORK/cc"; then
	"$ROOT/t/probe" emit ext-skmem-short-last "$WORK/f2.bin"
	_e=$(ASAN_OPTIONS=exitcode=86 "$WORK/mutsan2" -m --parse tcp \
	     "$WORK/f2.bin" 2>&1 >/dev/null)
	_s=$?
	if [ "$_s" -eq 86 ] &&
	   printf '%s' "$_e" | grep -q 'heap-buffer-overflow'; then
		pass=$((pass + 1))
		printf 'ok     %-38s heap-buffer-overflow, exit 86\n' \
		    'skmem overread is reported'
	else
		fail=$((fail + 1))
		printf 'FAIL   %-38s want exit 86 and heap-buffer-overflow,\n' \
		    'skmem overread is reported'
		printf '         got exit %s\n' "$_s"
		printf '%s\n' "$_e" | head -5 | sed 's/^/         /'
	fi
else
	printf 'skip   %-38s this compiler has no sanitisers\n' \
	    'skmem overread is reported'
fi

echo
printf '%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]

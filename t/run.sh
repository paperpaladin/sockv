#!/bin/sh
# The oracle.
#
# `ss` from iproute2 is a program written by other people that reads the same
# netlink interface from the same kernel. Where it disagrees with sockv, sockv
# is wrong. Nothing in here inspects sockv's internals or trusts it about
# anything: every assertion is a set of sockets produced independently twice.
#
# Compared in BOTH directions, because a comparison that only checks that
# every socket sockv reports was also reported by ss passes trivially for a
# program that reports nothing. Every test that compares sets also asserts how
# many rows it compared, for the same reason.
#
# Live-system racing is handled by sandwiching: ss runs, then sockv, then ss
# again. A socket in both ss runs existed for the whole of sockv's window and
# must appear in sockv's output. A socket in sockv's output must appear in at
# least one ss run. Anything else was created or destroyed while the three
# programs took turns, which is churn rather than disagreement -- so the
# sandwich is retried a few times and a persistent mismatch is the only
# failure. A real defect mismatches on every attempt.
set -u
LC_ALL=C
export LC_ALL

ROOT=$(cd "$(dirname "$0")/.." && pwd)
# Optional arguments: which binaries to judge. t/mutants.sh uses the first to
# point the whole suite at a deliberately broken build, and `make test-asan`
# uses both to point it at sanitised ones.
S=${1:-$ROOT/sockv}
P=${2:-$ROOT/t/probe}

pass=0; fail=0; skip=0

ok()    { pass=$((pass + 1)); printf 'ok    %s\n' "$1"; }
skipt() { skip=$((skip + 1)); printf 'skip  %s  (%s)\n' "$1" "$2"; }
bad()   {
	fail=$((fail + 1)); printf 'FAIL  %s\n' "$1"; shift
	if [ $# -gt 0 ]; then printf '%s\n' "$@" | sed 's/^/      | /'; fi
}

# Belt and braces with the Makefile's ASAN_OPTIONS=exitcode=86. A sanitizer
# abort exits 1 by default, and several assertions below legitimately expect
# exit 1 -- so a heap overread could be scored as a clean error diagnostic.
# Catching the report text closes that hole even if the options are not set.
sanitizer_fired() {
	case $1 in *Sanitizer*) return 0;; esac
	return 1
}

# t NAME WANT_STATUS -- CMD...   assert the exit status of CMD
t() {
	_n=$1; _w=$2; shift 3
	_o=$("$@" 2>&1); _s=$?
	if sanitizer_fired "$_o"; then
		bad "$_n" "a sanitizer fired" "$_o"
	elif [ "$_s" -eq "$_w" ]; then ok "$_n"
	else bad "$_n" "want status $_w, got $_s" "$_o"; fi
}

[ -x "$S" ] || { echo "run 'make' first" >&2; exit 2; }

TD=$(mktemp -d) || exit 2
trap 'rm -rf "$TD"' EXIT INT TERM

# --- is sock_diag reachable at all? ----------------------------------------
# Two things were wrong with this gate.
#
# It asked the binary under test. `"$S" -tl` failing was taken to mean the
# kernel has no sock_diag -- so any defect in sockv's own netlink transport
# turned the whole suite into a skip. Changing NETLINK_SOCK_DIAG to 99 in
# sockv.c produced "0 passed, 0 failed, 7 skipped" and exit 0. ss uses the
# same interface, so it can adjudicate: if ss can dump and sockv cannot, the
# fault is sockv's and that is a failure, not an environment.
#
# And it exited 0 having asserted nothing. A suite that compared nothing is
# not a passing suite, whatever the reason -- the same rule applied to wasmi's
# empty fixture directory and psh's all-skipped corpus. A genuinely restricted
# environment now exits 1 and says how to acknowledge that deliberately.
if ! "$S" -tl >/dev/null 2>"$TD/why"; then
	if command -v ss >/dev/null 2>&1 && ss -tln >/dev/null 2>&1; then
		bad "sock_diag is reachable but sockv cannot use it" \
		    "ss -tln works on this kernel, so this is sockv's bug" \
		    "$(sed 's/^/  /' "$TD/why")"
		printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
		exit 1
	fi
	echo "sockv cannot reach NETLINK_SOCK_DIAG on this kernel"
	echo "($(uname -r)):"
	sed 's/^/  /' "$TD/why"
	echo "ss cannot either, so this is the environment and not sockv."
	echo "Likely CONFIG_INET_DIAG=n, or a seccomp or netlink restriction in"
	echo "whatever this is running inside. Every assertion below needs the"
	echo "kernel to be the oracle, so they are SKIPPED, not passed."
	for n in tcp-udp-all tcp-udp-listen unix-all unix-listen all-families \
	         family-partition no-duplicate-rows; do
		skipt "$n" "no sock_diag"
	done
	printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
	echo "Nothing was compared, so this is not a pass. Set"
	echo "SOCKV_ALLOW_NO_SOCK_DIAG=1 to make that exit 0 on purpose."
	[ "${SOCKV_ALLOW_NO_SOCK_DIAG:-0}" = 1 ] && exit 0
	exit 1
fi

HAVE_SS=yes
command -v ss >/dev/null 2>&1 || HAVE_SS=no

# ===========================================================================
# normalisers: reduce both programs to the same fields, one row per socket
# ===========================================================================
# sockv prints  FAMILY NETID STATE LOCAL PEER INODE UID. Dropping the family
# column leaves exactly what ss reports. Two projections, because ss's -e
# output gives uid for inet sockets and not for UNIX ones.
my6() { "$S" "$@" | awk '{print $2, $3, $4, $5, $6, $7}' | sort; }
my5() { "$S" "$@" | awk '{print $2, $3, $4, $5, $6}'     | sort; }

# ss prints  netid state recvq sendq local peer  and then, for inet sockets, a
# bag of key:value tokens. uid and inode come out of that bag by prefix rather
# than by position, because its contents vary with kernel and cgroup.
#
# ss omits the uid: token entirely when the uid is zero, so the default below
# is load-bearing rather than defensive: on this machine the four rows without
# one are TIME-WAIT sockets, which carry no owning socket to ask and which
# sockv therefore reports as uid 0 and inode 0 -- the same answer, by
# agreement rather than by coincidence.
#
# A UNIX row is shaped differently: $5 is the name, $6 the socket's own inode
# (ss calls it the Port), $7 is always "*" and $8 the peer's inode. sockv
# joins those into name:inode and *:peer-inode so both kinds of row compare
# the same way.
ss6() {
	ss "$@" 2>/dev/null | awk '
		{
			u = ""; n = ""
			for (i = 7; i <= NF; i++) {
				if ($i ~ /^uid:/) u = substr($i, 5)
				if ($i ~ /^ino:/) n = substr($i, 5)
			}
			if (u == "") u = 0
			print $1, $2, $5, $6, n, u
		}' | sort
}
ss5() {
	ss "$@" 2>/dev/null | awk -v unp="$TD/unparsed" '
		$1 ~ /^u_/ {
			# A socket name containing whitespace shifts every
			# field after it, in ss as much as in sockv. Such rows
			# are counted and reported, never quietly dropped.
			if (NF < 8 || $6 !~ /^[0-9]+$/ || $8 !~ /^[0-9]+$/) {
				bad++; next
			}
			print $1, $2, $5 ":" $6, $7 ":" $8, $6
			next
		}
		{
			n = ""
			for (i = 7; i <= NF; i++)
				if ($i ~ /^ino:/) n = substr($i, 5)
			print $1, $2, $5, $6, n
		}
		END { if (bad) print bad > unp }' | sort
}

# ===========================================================================
# the differential: both directions, with a count that proves it had teeth
# ===========================================================================
# difftest NAME MINROWS SOCKV_ARGS SS_ARGS NFIELDS
difftest() {
	_n=$1; _min=$2; _sa=$3; _ssa=$4; _nf=$5
	_try=0
	while [ "$_try" -lt 4 ]; do
		_try=$((_try + 1))
		"ss$_nf" $_ssa                    > "$TD/before"
		"my$_nf" $_sa                     > "$TD/mine"
		"ss$_nf" $_ssa                    > "$TD/after"
		# sockets ss saw on both sides of our window
		comm -12 "$TD/before" "$TD/after" > "$TD/stable"
		sort -u "$TD/before" "$TD/after"  > "$TD/either"
		comm -23 "$TD/stable" "$TD/mine"  > "$TD/missing"
		comm -23 "$TD/mine" "$TD/either"  > "$TD/extra"
		if [ ! -s "$TD/missing" ] && [ ! -s "$TD/extra" ]; then break; fi
	done
	_c=$(wc -l < "$TD/stable" | tr -d ' ')
	if [ -s "$TD/missing" ] || [ -s "$TD/extra" ]; then
		bad "$_n: ss agrees both ways" \
		    "after $_try attempts, $_c sockets stable across the window" \
		    "ss reported and sockv did not:" \
		    "$(head -20 "$TD/missing" | sed 's/^/  /')" \
		    "sockv reported and ss did not:" \
		    "$(head -20 "$TD/extra" | sed 's/^/  /')"
	else
		ok "$_n: ss agrees both ways ($_c sockets)"
	fi
	# Two empty sets compare equal. This is the assertion that stops that
	# from counting as agreement.
	if [ "$_c" -ge "$_min" ]; then
		ok "$_n: compared $_c sockets (>= $_min)"
	else
		bad "$_n: compared $_c sockets (>= $_min)" \
		    "the comparison above was vacuous or nearly so"
	fi
}

if [ "$HAVE_SS" = no ]; then
	echo "iproute2's ss is not installed; the differential tests have no"
	echo "independent reader to compare against and are SKIPPED."
	for n in 'tcp+udp, all states' 'tcp+udp, listening' \
	         'unix, all states' 'unix, listening' \
	         'tcp+udp+unix together'; do
		skipt "$n" "no ss(8)"
		skipt "$n: teeth" "no ss(8)"
	done
else
	echo "sockv vs $(ss --version 2>/dev/null) on $(uname -r)"
	echo
	# ss only prints its Netid column when asked for more than one family,
	# so every ss command here asks for at least two. `ss -tanHe` drops the
	# column and shifts every field, and a second differently-shaped parser
	# would be a second place to be wrong.
	difftest 'tcp+udp, all states'    4 '-tu'  '-tuanHe'  6
	difftest 'tcp+udp, listening'     1 '-tul' '-tulnHe'  6
	difftest 'unix, all states'       4 '-x'   '-xanHe'   5
	difftest 'unix, listening'        1 '-xl'  '-xlnHe'   5
	# All three families from one invocation of each program: proves the
	# three dumps compose on one netlink socket and that nothing is lost
	# when they run back to back.
	difftest 'tcp+udp+unix together'  8 '-tux' '-tuxanHe' 5

	if [ -s "$TD/unparsed" ]; then
		skipt 'socket names containing whitespace' \
		    "$(cat "$TD/unparsed") ss rows would not split into fields"
	fi
fi

# ===========================================================================
# -t, -u and -x select, and together they partition the default listing
# ===========================================================================
# Self-consistency, not an oracle: it catches an option-parsing mistake, which
# the differentials above cannot see because they always ask both programs for
# the same families.
_try=0
while [ "$_try" -lt 4 ]; do
	_try=$((_try + 1))
	my6 > "$TD/all"
	my6 -t > "$TD/jt"
	my6 -u > "$TD/ju"
	my6 -x > "$TD/jx"
	sort -u "$TD/jt" "$TD/ju" "$TD/jx" > "$TD/union"
	cmp -s "$TD/all" "$TD/union" && break
done
if cmp -s "$TD/all" "$TD/union"; then
	ok "-t -u -x partition the default listing ($(wc -l < "$TD/all" | tr -d ' ') rows)"
else
	bad '-t -u -x partition the default listing' \
	    "$(diff "$TD/all" "$TD/union" | head -20 | sed 's/^/  /')"
fi
if [ "$(awk '$1 != "tcp"' "$TD/jt" | wc -l)" -eq 0 ] &&
   [ "$(awk '$1 != "udp"' "$TD/ju" | wc -l)" -eq 0 ] &&
   [ "$(awk '$1 !~ /^u_/' "$TD/jx" | wc -l)" -eq 0 ]; then
	ok 'each family flag yields only its own netids'
else
	bad 'each family flag yields only its own netids'
fi

# ss -e reports no uid for a UNIX socket, so the differential above compares
# five fields there rather than six. Saying so out loud beats comparing five
# fields and calling it six.
skipt 'unix uid against ss' 'ss -e does not report uid for unix sockets'

# ===========================================================================
# a socket reported twice is a defect the set comparisons cannot see, because
# comparing sets throws duplicates away
# ===========================================================================
"$S" | sort | uniq -d > "$TD/dup"
if [ -s "$TD/dup" ]; then
	bad 'no duplicate rows' "$(sed 's/^/  /' "$TD/dup")"
else
	ok 'no duplicate rows'
fi

# ===========================================================================
# the record walker, driven with bytes no kernel would send
# ===========================================================================
# This is the other half of the oracle and it is not a differential: the
# fixtures are built by t/probe with values chosen there, so the expected row
# is known exactly rather than compared against whatever the machine runs.
# That matters twice over -- it pins the rendering rules the live system does
# not happen to exercise (a v4-mapped address, a dual-stack wildcard, an
# abstract name with no NUL terminator), and it is the only way to feed the
# walker a record that lies about its own length.
#
# --parse runs the same walk() over the same handlers as the live path, so a
# bounds check these fixtures prove is the bounds check the kernel meets.
TO=
command -v timeout >/dev/null 2>&1 && TO="timeout 10"

if [ ! -x "$P" ]; then
	skipt 'record walker fixtures' 'run make: t/probe is not built'
else
	# pok NAME PROTO CASE ROW...   exit 0 and exactly these rows
	pok() {
		_n=$1; _p=$2; _c=$3; shift 3
		if ! "$P" emit "$_c" "$TD/f.bin" 2>"$TD/e"; then
			bad "$_n" "probe emit $_c failed" "$(cat "$TD/e")"
			return
		fi
		# The status has to come from sockv, not from the pipeline.
		# `_s=$?` after a pipe reads awk's status, which is always 0 --
		# so the "exit 0" half of this assertion was dead for all 17
		# pok cases. A binary whose *successful* --parse returned 2
		# passed every one of them; only the separate
		# `t '--parse of an empty file' 0` noticed.
		$TO "$S" --parse "$_p" "$TD/f.bin" >"$TD/p.out" 2>"$TD/e"
		_s=$?
		_got=$(awk 'NF {print $1, $2, $3, $4, $5, $6, $7}' "$TD/p.out")
		_want=$(printf '%s\n' "$@")
		if [ "$_s" -eq 0 ] && [ "$_got" = "$_want" ]; then ok "$_n"
		else bad "$_n" "want exit 0 and" "$_want" \
		         "got exit $_s and" "$_got" "$(cat "$TD/e")"; fi
	}

	# pbad NAME PROTO CASE WANT_STATUS MSG   nonzero exit, and the
	# diagnostic must name the field that was wrong -- a test that only
	# checks the status cannot tell one bounds check from another, or from
	# a typo in the parser.
	pbad() {
		_n=$1; _p=$2; _c=$3; _w=$4; _m=$5
		if ! "$P" emit "$_c" "$TD/f.bin" 2>"$TD/e"; then
			bad "$_n" "probe emit $_c failed" "$(cat "$TD/e")"
			return
		fi
		_e=$($TO "$S" --parse "$_p" "$TD/f.bin" 2>&1 >/dev/null)
		_s=$?
		if sanitizer_fired "$_e"
		then bad "$_n" "a sanitizer fired" "$_e"
		elif [ "$_s" -eq "$_w" ] && printf '%s' "$_e" | grep -qF "$_m"
		then ok "$_n"
		else bad "$_n" "want exit $_w and stderr naming [$_m]" \
		         "got exit $_s: $_e"; fi
	}

	# --- well formed: the rendering rules, pinned to known values ---
	pok 'v4 endpoint' tcp v4 \
	    'inet tcp ESTAB 127.0.0.1:8080 10.0.0.1:443 4242 1001'
	pok 'v4 listener and %ifname scope' tcp v4-listen-scoped \
	    'inet tcp LISTEN 127.0.0.53%lo:53 0.0.0.0:* 4243 65534'
	pok 'v6 endpoint in brackets' tcp v6 \
	    'inet6 tcp ESTAB [2001:db8::1]:8080 [2001:db8::2]:443 4244 1001'
	pok 'v6 wildcard, v6only, prints [::]' tcp v6-wild-v6only \
	    'inet6 tcp LISTEN [::]:8080 [::]:* 4245 0'
	pok 'v6 wildcard, dual stack, prints *' tcp v6-wild-dual \
	    'inet6 tcp LISTEN *:8080 *:* 4246 0'
	pok 'v4-mapped address on a v6 socket' tcp v6-mapped \
	    'inet6 tcp LISTEN [::ffff:127.0.0.1]:8080 *:* 4247 0'
	# Brackets, then the scope, then the port. Nothing on a loopback-only
	# machine binds a scoped IPv6 address, so this fixture is the only
	# thing holding that order in place.
	pok 'scoped IPv6 address' tcp v6-scoped \
	    'inet6 tcp LISTEN [fe80::1]%lo:546 [::]:* 4253 0'
	# Both of these render a value the kernel cannot currently produce.
	# They must keep the socket in the listing rather than drop it: losing
	# a socket is worse than naming one of its fields badly, and the
	# differential reports the disagreement either way.
	pok 'unknown state keeps the row' tcp state-unknown \
	    'inet tcp state-200 127.0.0.1:8080 10.0.0.1:443 4254 1001'
	pok 'unknown unix socket type keeps the row' unix unix-type-unknown \
	    'unix u_? LISTEN /run/odd.sock:4255 *:0 4255 1001'
	pok 'udp netid comes from the request' udp v4 \
	    'inet udp ESTAB 127.0.0.1:8080 10.0.0.1:443 4242 1001'
	pok 'unix filesystem path' unix unix-path \
	    'unix u_str LISTEN /run/probe.sock:4248 *:0 4248 1001'
	pok 'unix abstract name as @name' unix unix-abstract \
	    'unix u_dgr UNCONN @probe-abstract:4249 *:0 4249 1001'
	pok 'unix unnamed, with a peer inode' unix unix-unnamed \
	    'unix u_seq ESTAB *:4250 *:4251 4250 1001'
	# The name here has no NUL terminator at all, so printing eleven
	# characters instead of ten is an overread by one.
	pok 'unix name bounded by nla_len, not by a NUL' unix unix-name-no-nul \
	    'unix u_str LISTEN abcdefghij:4252 *:0 4252 1001'
	pok 'two records in one datagram' tcp two-records \
	    'inet tcp ESTAB 127.0.0.1:1 127.0.0.2:2 5001 1001' \
	    'inet tcp ESTAB 127.0.0.3:3 127.0.0.4:4 5002 1001'
	# An attribute type newer than this build knows must be skipped, not
	# refused: the kernel grows that enum every few releases.
	pok 'unknown attribute type is ignored' tcp attr-type-unknown \
	    'inet tcp ESTAB 127.0.0.1:8080 10.0.0.1:443 4242 1001'
	# nlmsg_len that is not a multiple of four. Every length a kernel emits
	# is already aligned, so this is the only way to tell a walker that
	# advances by NLMSG_ALIGN(nlmsg_len) from one that advances by
	# nlmsg_len -- and the second one silently loses the next record.
	pok 'unaligned nlmsg_len keeps the next record' unix unaligned-len \
	    'unix u_str LISTEN /run/ab.sock:5003 *:0 5003 0' \
	    'unix u_str LISTEN /run/c.sock:5004 *:0 5004 1001'

	# --- malformed: refused, by name --------------------------------
	pbad 'buffer shorter than an nlmsghdr' tcp short-buffer 2 \
	    '9 trailing bytes, too few for an nlmsghdr'
	pbad 'nlmsg_len below the header size' tcp len-under 2 \
	    'nlmsg_len 8 is below the 16-byte nlmsghdr'
	# A zero nlmsg_len is the one that spins a careless walker forever
	# rather than overreading, which is why it is timed out above.
	pbad 'nlmsg_len of zero' tcp len-zero 2 \
	    'nlmsg_len 0 is below the 16-byte nlmsghdr'
	pbad 'nlmsg_len past the end of the buffer' tcp len-over 2 \
	    'overruns the 88 bytes left in the reply'
	pbad 'nlmsg_len of 0xffffffff does not wrap' tcp len-huge 2 \
	    'nlmsg_len 4294967295 overruns'
	pbad 'truncated final record' tcp trailing-bytes 2 \
	    '7 trailing bytes, too few for an nlmsghdr'
	pbad 'payload too small for inet_diag_msg' tcp payload-short 2 \
	    'carries 8 payload bytes, inet_diag_msg needs 72'
	pbad 'nla_len below the attribute header' tcp attr-len-under 2 \
	    'nla_len 2 is below the 4-byte attribute header'
	pbad 'nla_len past the end of its message' tcp attr-len-over 2 \
	    'nla_len 512 overruns the 8 bytes left in this message'
	pbad 'attribute area ends mid-header' tcp attr-truncated 2 \
	    '3 trailing bytes after the last attribute'
	pbad 'u8 attribute with no payload' tcp attr-empty-u8 2 \
	    'attribute 11 carries 0 bytes, needs 1'
	pbad 'unix name longer than sun_path' unix unix-name-too-long 2 \
	    'UNIX_DIAG_NAME is 200 bytes'
	pbad 'address family we never asked for' tcp bad-family 2 \
	    'idiag_family 99 is neither AF_INET'
	pbad 'nlmsg_type we never asked for' tcp unknown-msg-type 2 \
	    'unexpected nlmsg_type 1234'

	# --- not malformed, but not a listing either --------------------
	pbad 'NLMSG_ERROR is reported with its errno' tcp nlmsg-error 1 \
	    'kernel refused the request: Operation not permitted'
	pbad 'NLMSG_ERROR with no room for an errno' tcp nlmsg-error-empty 2 \
	    'NLMSG_ERROR with no error code'
	# On the live path this means "ask the kernel again"; replayed from a
	# file there is nothing to ask, so it is reported rather than quietly
	# truncating the listing at the flagged record.
	pbad 'NLM_F_DUMP_INTR is not a listing' tcp dump-intr 1 \
	    'carries NLM_F_DUMP_INTR'

	t '--parse with an unknown protocol'  3 -- "$S" --parse sctp /dev/null
	t '--parse with a missing file'       1 -- "$S" --parse tcp "$TD/nope"
	t '--parse with no arguments'         3 -- "$S" --parse
	# An empty reply is not malformed: it is a dump with nothing in it.
	: > "$TD/empty.bin"
	t '--parse of an empty file'          0 -- "$S" --parse tcp "$TD/empty.bin"
fi

# ===========================================================================
# /proc/net/*: the same kernel, through a different formatter
# ===========================================================================
# Ranked last among the three oracles, and for a reason worth stating. ss is a
# different program, written by other people, reading the same netlink
# interface -- so it catches a misunderstanding on our side of that interface.
# /proc/net/tcp is the same kernel rendering the same structures through a
# different printf, so a kernel-side misunderstanding, or a wrong idea about
# what a field means, would sail through both.
#
# It is also provably lossy, which is why sockv does not read it: a TCP socket
# that is bound and neither listening nor connected lives only in the bind
# hash, and /proc/net/tcp does not list it at all while sock_diag reports it.
# That asymmetry is asserted further down rather than assumed, with a socket
# the suite creates for the purpose.
#
# So this is a one-directional check, and it compares inode, uid and port --
# the three fields /proc encodes differently enough to be worth a second
# opinion. The port in particular: /proc writes it as big-endian hex text and
# the address as little-endian hex text, so agreeing with it about a port
# number is an encoding-independent check on the byte order.
#
# proc_inet NAME: every socket /proc lists must be one sockv lists.
proc_inet() {
	awk 'function hx(s,  i, c, v, d) {
		v = 0
		for (i = 1; i <= length(s); i++) {
			d = index("0123456789abcdef", tolower(substr(s, i, 1)))
			if (d == 0) return -1
			v = v * 16 + d - 1
		}
		return v
	}
	FNR > 1 { split($2, a, ":"); print $10, $8, hx(a[2]) }' \
		/proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 \
		2>/dev/null | sort
}
my_inet_ino() {
	"$S" -tu | awk '{
		n = split($4, a, ":")
		if (a[n] == "*") a[n] = 0
		print $6, $7, a[n]
	}' | sort
}
# /proc/net/unix prints inode 0 for a socket with no struct socket behind it,
# and sock_diag does not enumerate those at all -- so the (inode, name) pair
# `0 /var/run/abrt/abrt.socket` could never match anything sockv produces, and
# this comparison failed on any machine with a service holding connections in
# its accept backlog. On this one that is 12 of 1261 rows: 11 in St=02
# (connecting, abrt's backlog) and 1 in St=04 (disconnecting). Both are states
# where /proc has a struct sock to list and no inode to name it by.
#
# They are excluded, and the count is printed rather than quietly dropped, so
# a carve-out that grew would be visible. Everything with a real inode is
# still compared in both directions.
proc_unix() {
	awk 'FNR > 1 && $7 != 0 { print $7, (NF >= 8 ? $8 : "*") }' \
		/proc/net/unix 2>/dev/null | sort -u
}

proc_unix_noinode() {
	awk 'FNR > 1 && $7 == 0' /proc/net/unix 2>/dev/null | wc -l
}
my_unix_name() {
	"$S" -x | awk '{ l = $4; sub(/:[0-9]+$/, "", l); print $6, l }' |
		sort -u
}

# procsub NAME MINROWS PROCFN MYFN
procsub() {
	_n=$1; _min=$2; _pf=$3; _mf=$4
	_try=0
	while [ "$_try" -lt 4 ]; do
		_try=$((_try + 1))
		"$_pf"                            > "$TD/pbefore"
		"$_mf"                            > "$TD/pmine"
		"$_pf"                            > "$TD/pafter"
		comm -12 "$TD/pbefore" "$TD/pafter" > "$TD/pstable"
		comm -23 "$TD/pstable" "$TD/pmine"  > "$TD/pmissing"
		[ ! -s "$TD/pmissing" ] && break
	done
	_c=$(wc -l < "$TD/pstable" | tr -d ' ')
	if [ -s "$TD/pmissing" ]; then
		bad "$_n" "after $_try attempts, $_c rows stable in /proc" \
		    "/proc lists these and sockv does not:" \
		    "$(head -20 "$TD/pmissing" | sed 's/^/  /')"
	else
		ok "$_n ($_c rows)"
	fi
	if [ "$_c" -ge "$_min" ]; then
		ok "$_n: compared $_c rows (>= $_min)"
	else
		bad "$_n: compared $_c rows (>= $_min)" \
		    "the check above was vacuous or nearly so"
	fi
}

if [ -r /proc/net/tcp ] && [ -r /proc/net/unix ]; then
	procsub '/proc/net/{tcp,tcp6,udp,udp6} inode+uid+port' 4 \
	    proc_inet my_inet_ino
	procsub '/proc/net/unix inode+name' 4 proc_unix my_unix_name
	# Say how many rows the comparison above could not use, so the
	# exclusion is a reported number rather than an invisible filter.
	_ni=$(proc_unix_noinode)
	printf 'note: %s /proc/net/unix row(s) carry inode 0 and are excluded;\n' "$_ni"
	printf '      sock_diag does not enumerate a socket with no struct socket\n'
	t '/proc/net/unix: the inode-0 exclusion stays small' 0 -- \
		sh -c "[ $_ni -lt 100 ]"
else
	skipt '/proc/net inet cross-check' '/proc/net is not readable here'
	skipt '/proc/net/unix cross-check' '/proc/net is not readable here'
fi

# ===========================================================================
# sockets this suite made itself, so it knows the answer before it asks
# ===========================================================================
# The third oracle, and the only one that is not a comparison: t/probe binds
# and connects sockets whose address, state and type it chose, reads each
# one's inode straight out of fstat(2) on its own descriptor -- the same
# number the kernel reports as idiag_inode -- and prints the exact row sockv
# must produce. The addresses it prints come from the numbers it passed to
# bind(2), not from rendering a sockaddr back out, so it cannot share a
# formatting mistake with sockv.
#
# This is what makes a failure specific. The differential can only ever say
# "these sets differ"; these assertions say which socket and which field.
if [ ! -x "$P" ]; then
	skipt 'sockets created by the suite' 'run make: t/probe is not built'
else
	# Five consecutive ports, and a base unlikely to collide with whatever
	# else is on the machine or with a concurrent run of this suite.
	PORT=$((47000 + ($$ % 400) * 8))
	mkdir -p "$TD/un"
	"$P" hold "$PORT" "$TD/un" 30 > "$TD/inv" 2>"$TD/inverr" &
	HOLD=$!
	_i=0
	while [ "$_i" -lt 200 ] && ! grep -q '^READY$' "$TD/inv" 2>/dev/null; do
		_i=$((_i + 1))
		sleep 0.05
	done
	if ! grep -q '^READY$' "$TD/inv" 2>/dev/null; then
		bad 'the probe brought its sockets up' \
		    "$(cat "$TD/inv" "$TD/inverr" 2>/dev/null)"
	else
		ok "the probe brought its sockets up (ports $PORT..$((PORT + 5)))"
		"$S" -tux | awk '{print $1, $2, $3, $4, $5, $6, $7}' |
			sort > "$TD/live"
		while read -r _kw _tag _rest; do
			case $_kw in
			EXPECT)
				if grep -qxF "$_rest" "$TD/live"; then
					ok "created: $_tag"
				else
					bad "created: $_tag" \
					    "this row is not in sockv's output:" \
					    "  $_rest" \
					    "sockv says of that inode:" \
					    "$(awk -v i="${_rest##* }" \
					        '$6 == i || $7 == i' "$TD/live" |
					       sed 's/^/  /')"
				fi ;;
			SKIP)
				skipt "created: $_tag" "$_rest" ;;
			esac
		done < "$TD/inv"

		# A socket name with whitespace in it shifts every field after
		# it, in sockv's output and in ss's alike, so this one is
		# matched as a substring. The point is that the name reaches
		# the output verbatim and bounded, not that it can be parsed.
		_sp=$(sed -n 's/^SPACED //p' "$TD/inv")
		if [ -z "$_sp" ]; then
			skipt 'unix name containing spaces' \
			    'the probe could not bind it'
		elif "$S" -x | grep -qF "$_sp"; then
			ok 'unix name containing spaces appears verbatim'
		else
			bad 'unix name containing spaces appears verbatim' \
			    "looked for [$_sp]"
		fi

		# The claim that justifies not reading /proc in the first
		# place, asserted rather than assumed: the probe's bound-only
		# TCP socket is in sockv's output and is not in /proc/net/tcp,
		# because a socket in neither the listening nor the
		# established hash is in the bind hash only and /proc walks
		# the first two. Like the ABI-1 truncate test in jail, this is
		# a passing test whose expectation is that something is
		# missing.
		_bo=$(awk '$1 == "EXPECT" && $2 == "tcp4-bound-only" {print $8}' \
		    "$TD/inv")
		if [ -z "$_bo" ]; then
			skipt 'bound-only TCP socket is absent from /proc/net/tcp' \
			    'the probe could not bind it'
		elif ! grep -qxF "inet tcp UNCONN 127.0.0.1:$((PORT + 1)) 0.0.0.0:* $_bo $(id -u)" "$TD/live"; then
			bad 'bound-only TCP socket is absent from /proc/net/tcp' \
			    "sockv did not report inode $_bo either, so the" \
			    "asymmetry claim is untested rather than confirmed"
		elif awk 'FNR > 1 {print $10}' /proc/net/tcp 2>/dev/null |
		     grep -qxF "$_bo"; then
			bad 'bound-only TCP socket is absent from /proc/net/tcp' \
			    "inode $_bo turned up in /proc/net/tcp after all;" \
			    "the kernel changed and the README is now wrong"
		else
			ok 'bound-only TCP socket is absent from /proc/net/tcp'
		fi

		# The differential's socket counts only prove something if the
		# sockets with known identities are inside the population being
		# compared. This is that assertion.
		if [ "$HAVE_SS" = yes ]; then
			{ ss6 -tuanHe | awk '{print $5}'
			  ss5 -xanHe  | awk '{print $5}'; } |
				sort -u > "$TD/ssino"
			_tot=0; _miss=0
			for _i in $(awk '$1 == "EXPECT" {print $8}' "$TD/inv"); do
				_tot=$((_tot + 1))
				grep -qxF "$_i" "$TD/ssino" || _miss=$((_miss + 1))
			done
			if [ "$_tot" -gt 0 ] && [ "$_miss" -eq 0 ]; then
				ok "ss sees all $_tot sockets the probe created"
			else
				bad "ss sees all $_tot sockets the probe created" \
				    "$_miss of $_tot were missing from ss's output"
			fi
		else
			skipt 'ss sees the sockets the probe created' 'no ss(8)'
		fi

		# =======================================================
		# INET_DIAG_REQ_BYTECODE: the filter the KERNEL applies
		# =======================================================
		# What has to be proved here is not that the output is
		# right. A filter applied in userspace after a full dump
		# would produce byte-identical output and pass every
		# comparison below, so agreement alone cannot tell the two
		# apart. --records reports how many SOCK_DIAG_BY_FAMILY
		# records the kernel actually sent, and that number is the
		# only witness: a bytecode that matches everything, or one
		# that never reaches the request, shows up there and
		# nowhere else.
		#
		# Three independent checks per filter, and they fail in
		# different ways:
		#
		#  1. the same selection made here in userspace over
		#     sockv's own unfiltered listing must give the same
		#     set -- this says the bytecode selects the right
		#     sockets;
		#  2. ss, told the equivalent filter in its own syntax,
		#     must give the same set -- this says sockv and
		#     another implementation of the same interface agree
		#     about what the filter means;
		#  3. the kernel must have sent fewer records with the
		#     filter than without, and exactly as many as sockv
		#     printed -- this says the kernel did the work.
		#
		# And the sockets being selected are the probe's own, bound
		# a few lines above with known ports and addresses, so none
		# of this depends on what happens to be running here.

		# nrecs ARGS...  -- how many records the kernel sent
		nrecs() {
			"$S" "$@" --records 2>"$TD/nr" >/dev/null
			if sanitizer_fired "$(cat "$TD/nr")"; then
				echo "sanitizer"
				return
			fi
			sed -n 's/^records: //p' "$TD/nr"
		}
		# usel AWKCOND -- the same selection, made in userspace over
		# sockv's own unfiltered listing. The condition is an awk
		# expression over the full row, so it can test the family
		# column as well as the local endpoint.
		usel() {
			"$S" -tu |
			    awk "$1 {print \$2, \$3, \$4, \$5, \$6, \$7}" |
			    sort
		}

		# bcf NAME FILTER_ARGS SS_FILTER AWKCOND
		bcf() {
			_n=$1; _f=$2; _ssf=$3; _re=$4
			_try=0
			while [ "$_try" -lt 4 ]; do
				_try=$((_try + 1))
				my6 -tu $_f > "$TD/bmine"
				usel "$_re"  > "$TD/bus"
				cmp -s "$TD/bmine" "$TD/bus" && break
			done
			if cmp -s "$TD/bmine" "$TD/bus"; then
				ok "$_n: kernel bytecode selects what userspace selection does ($(wc -l < "$TD/bmine" | tr -d ' ') rows)"
			else
				bad "$_n: kernel bytecode selects what userspace selection does" \
				    "$(diff "$TD/bus" "$TD/bmine" | head -20 | sed 's/^/  /')"
			fi
			if [ "$HAVE_SS" = yes ]; then
				difftest "$_n vs ss" 1 "-tu $_f" "-tuanHe $_ssf" 6
			else
				skipt "$_n vs ss" 'no ss(8)'
				skipt "$_n vs ss: teeth" 'no ss(8)'
			fi
			# The kernel did the filtering, not this program.
			#
			# Both numbers come from ONE invocation, because they
			# are two facts about the same dump. Taking them from
			# two runs of sockv made this assertion fail about
			# once in thirteen on a machine churning sockets: it
			# reported 36 records against 35 rows and accused
			# sockv of discarding a record, when what had happened
			# was that a socket went away between the two runs.
			# A loop that kept the output found it on the
			# thirteenth; guessing would not have.
			"$S" -tu $_f --records >"$TD/brow" 2>"$TD/nr"
			if sanitizer_fired "$(cat "$TD/nr")"; then
				bad "$_n: the kernel sent as many records as sockv printed rows" \
				    "a sanitizer fired" "$(cat "$TD/nr")"
				return
			fi
			_rf=$(sed -n 's/^records: //p' "$TD/nr")
			_rows=$(wc -l < "$TD/brow" | tr -d ' ')
			if [ "$_rf" = "$_rows" ]; then
				ok "$_n: the kernel sent $_rf records and sockv printed $_rows rows"
			else
				bad "$_n: the kernel sent $_rf records and sockv printed $_rows rows" \
				    "sockv discarded records after receiving them;" \
				    "that is a userspace filter wearing a kernel one's name"
			fi
			# This one is inherently two invocations, so it is
			# re-measured and retried like every other cross-run
			# comparison here.
			_try=0
			_unf=$UNFILT
			while [ "$_try" -lt 4 ]; do
				_try=$((_try + 1))
				case $_unf in '' | sanitizer) break;; esac
				[ "$_rf" -lt "$_unf" ] && break
				_unf=$(nrecs -tu)
			done
			case $_unf in
			'' | sanitizer)
				bad "$_n: the kernel sent fewer records than an unfiltered dump" \
				    "could not count an unfiltered dump: [$_unf]" ;;
			*)
				if [ "$_rf" -lt "$_unf" ]; then
					ok "$_n: the kernel sent $_rf records, an unfiltered dump $_unf"
				else
					bad "$_n: the kernel sent $_rf records, an unfiltered dump $_unf" \
					    "the bytecode matched everything, or never" \
					    "reached the request at all"
				fi ;;
			esac
		}

		# expectrow TAG -- the row the probe says that socket must
		# produce, or empty if the probe skipped it
		expectrow() {
			awk -v t="$1" '$1 == "EXPECT" && $2 == t {
				print $3, $4, $5, $6, $7, $8, $9 }' "$TD/inv"
		}
		# inout NAME FILTER_ARGS IN_TAG OUT_TAG -- the socket the
		# probe created with IN_TAG must be in the filtered listing
		# and the one with OUT_TAG must not. A filter is only shown
		# to work when something appears AND something disappears;
		# a filter matching everything passes the first half alone.
		inout() {
			_n=$1; _f=$2; _in=$(expectrow "$3"); _out=$(expectrow "$4")
			if [ -z "$_in" ] || [ -z "$_out" ]; then
				skipt "$_n" "the probe could not bind $3 or $4"
				return
			fi
			"$S" -tu $_f |
			    awk '{print $1, $2, $3, $4, $5, $6, $7}' > "$TD/bsel"
			if ! grep -qxF "$_in" "$TD/bsel"; then
				bad "$_n" "this row should have been selected:" \
				    "  $_in" "got:" \
				    "$(head -10 "$TD/bsel" | sed 's/^/  /')"
			elif grep -qxF "$_out" "$TD/bsel"; then
				bad "$_n" "this row should NOT have been selected:" \
				    "  $_out"
			else
				ok "$_n"
			fi
		}

		# One invocation again: with no filter every record the kernel
		# sends is printed, so these two numbers are equal, and
		# comparing numbers from two runs would be comparing two
		# different moments on a machine that does not hold still.
		"$S" -tu --records >"$TD/brow" 2>"$TD/nr"
		UNFILT=$(sed -n 's/^records: //p' "$TD/nr")
		if sanitizer_fired "$(cat "$TD/nr")" || [ -z "$UNFILT" ]; then
			bad '--records reports the kernel record count' \
			    "got [$UNFILT]" "$(cat "$TD/nr")"
			UNFILT=sanitizer
		elif [ "$UNFILT" = "$(wc -l < "$TD/brow" | tr -d ' ')" ]; then
			ok "--records reports the kernel record count ($UNFILT)"
		else
			bad '--records reports the kernel record count' \
			    "$UNFILT records for $(wc -l < "$TD/brow") printed rows"
		fi

		bcf '--port'         "--port $PORT"       "sport = :$PORT" \
		    "\$4 ~ /:$PORT\$/"
		bcf '--addr v4'      '--addr 127.0.0.1'   'src 127.0.0.1' \
		    '$4 ~ /^127\.0\.0\.1[%:]/'
		bcf '--addr v4 /8'   '--addr 127.0.0.0/8' 'src 127.0.0.0/8' \
		    '$4 ~ /^127\./'
		# ss cannot parse a bare ::1 as a source address: it splits
		# host from port on a colon and gives up. [::1] and ::1/128
		# are the two forms it accepts, and sockv takes either.
		bcf '--addr v6'      '--addr ::1'         'src [::1]' \
		    '$4 ~ /^\[::1\][%:]/'
		bcf '--dev'          '--dev lo'           'dev == lo' \
		    '$4 ~ /%lo:/'
		bcf '--port --dev'   "--port $((PORT + 5)) --dev lo" \
		    "sport = :$((PORT + 5)) and dev == lo" \
		    "\$4 ~ /%lo:$((PORT + 5))\$/"
		# A prefix length of zero still selects by address FAMILY,
		# which is not what "match any address" sounds like and is
		# not what the kernel's documented order of tests suggests
		# either. ss agrees with the kernel here, so this pins a
		# surprise rather than describing one.
		bcf '--addr 0.0.0.0/0' '--addr 0.0.0.0/0' 'src 0.0.0.0/0' \
		    '$1 == "inet"'
		bcf '--addr ::/0'      '--addr ::/0'      'src ::/0' \
		    '$1 == "inet6"'

		inout '--port selects the probe listener and not its udp socket' \
		    "--port $PORT" tcp4-listen udp4-bound
		inout '--addr 127.0.0.1 selects the v4 listener and not the v6 one' \
		    '--addr 127.0.0.1' tcp4-listen tcp6-listen
		inout '--addr ::1 selects the v6 listener and not the v4 one' \
		    '--addr ::1' tcp6-listen tcp4-listen
		inout '--dev lo selects the scope-bound socket and not an unbound one' \
		    '--dev lo' udp6-dev-lo tcp4-listen

		# The other direction, and the sharpest of the lot: a port
		# nothing on this machine is using must make the kernel send
		# nothing at all. A filter implemented here after a full dump
		# prints the same empty listing and reports every record on
		# the machine.
		_free=$((PORT + 6))
		if [ -n "$("$S" -tu | awk -v p=":$_free\$" '$4 ~ p')" ]; then
			skipt 'a port nothing is bound to returns no records' \
			    "something is bound to port $_free after all"
		else
			"$S" -tu --port "$_free" --records \
			    >"$TD/brow" 2>"$TD/nr"
			_rz=$(sed -n 's/^records: //p' "$TD/nr")
			_oz=$(wc -l < "$TD/brow" | tr -d ' ')
			if [ "$_rz" = 0 ] && [ "$_oz" = 0 ]; then
				ok 'a port nothing is bound to returns no records'
			else
				bad 'a port nothing is bound to returns no records' \
				    "kernel sent $_rz records, sockv printed $_oz rows"
			fi
		fi

		# unix_diag has no bytecode, so the combination is refused
		# rather than answered with sockets nobody filtered.
		t '-x with a filter is refused'  3 -- "$S" -x --port 80
		t '--port with no value'         3 -- "$S" --port
		t '--port out of range'          3 -- "$S" --port 65536
		t '--port is not a number'       3 -- "$S" --port 8o80
		t '--addr is not an address'     3 -- "$S" --addr localhost
		t '--addr prefix out of range'   3 -- "$S" --addr 10.0.0.0/33
		t '--dev names no interface'     3 -- "$S" --dev no-such-dev0
		# Two local ports cannot both be true. ANDing them would
		# return an empty listing that reads as a correct answer.
		t '--port given twice is refused' 3 -- "$S" --port 1 --port 2
		# A filter with no family flag lists tcp and udp, not unix:
		# the default cannot include a family the filter cannot reach.
		if [ -z "$("$S" --port "$PORT" | awk '$1 == "unix"')" ] &&
		   [ -n "$("$S" | awk '$1 == "unix"')" ]; then
			ok 'a filter drops unix from the default family set'
		else
			bad 'a filter drops unix from the default family set'
		fi
	fi
	kill "$HOLD" 2>/dev/null
	wait "$HOLD" 2>/dev/null
fi

# ===========================================================================
# the command line fails closed
# ===========================================================================
t 'unknown option'            3  -- "$S" -Z
t 'stray argument'            3  -- "$S" tcp
t '--help exits 0'            0  -- "$S" --help
t 'listing exits 0'           0  -- "$S" -tux

printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]

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
# Optional argument: which binary to judge. t/mutants.sh uses it to point the
# whole suite at a deliberately broken build.
S=${1:-$ROOT/sockv}

pass=0; fail=0; skip=0

ok()    { pass=$((pass + 1)); printf 'ok    %s\n' "$1"; }
skipt() { skip=$((skip + 1)); printf 'skip  %s  (%s)\n' "$1" "$2"; }
bad()   {
	fail=$((fail + 1)); printf 'FAIL  %s\n' "$1"; shift
	if [ $# -gt 0 ]; then printf '%s\n' "$@" | sed 's/^/      | /'; fi
}

# t NAME WANT_STATUS -- CMD...   assert the exit status of CMD
t() {
	_n=$1; _w=$2; shift 3
	_o=$("$@" 2>&1); _s=$?
	if [ "$_s" -eq "$_w" ]; then ok "$_n"
	else bad "$_n" "want status $_w, got $_s" "$_o"; fi
}

[ -x "$S" ] || { echo "run 'make' first" >&2; exit 2; }

TD=$(mktemp -d) || exit 2
trap 'rm -rf "$TD"' EXIT INT TERM

# --- is sock_diag reachable at all? skip loudly, never silently pass --------
if ! "$S" -tl >/dev/null 2>"$TD/why"; then
	echo "sockv cannot reach NETLINK_SOCK_DIAG on this kernel"
	echo "($(uname -r)):"
	sed 's/^/  /' "$TD/why"
	echo "Likely CONFIG_INET_DIAG=n, or a seccomp or netlink restriction in"
	echo "whatever this is running inside. Every assertion below needs the"
	echo "kernel to be the oracle, so they are SKIPPED, not passed."
	for n in tcp-udp-all tcp-udp-listen unix-all unix-listen all-families \
	         family-partition no-duplicate-rows; do
		skipt "$n" "no sock_diag"
	done
	printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
	exit 0
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
# the command line fails closed
# ===========================================================================
t 'unknown option'            3  -- "$S" -Z
t 'stray argument'            3  -- "$S" tcp
t '--help exits 0'            0  -- "$S" --help
t 'listing exits 0'           0  -- "$S" -tux

printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]

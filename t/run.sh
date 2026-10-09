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
	for n in tcp-udp-all tcp-udp-all-teeth tcp-udp-listen \
	         tcp-udp-listen-teeth no-duplicate-rows; do
		skipt "$n" "no sock_diag"
	done
	printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
	exit 0
fi

HAVE_SS=yes
command -v ss >/dev/null 2>&1 || HAVE_SS=no

# ===========================================================================
# normalisers: reduce both programs to the same six fields, one row per socket
# ===========================================================================
# sockv prints  FAMILY NETID STATE LOCAL PEER INODE UID, so dropping the
# family column leaves exactly what ss -e reports.
sockv_rows() { "$S" "$@" | awk '{print $2, $3, $4, $5, $6, $7}' | sort; }

# ss -tuanHe prints  netid state recvq sendq local peer, then a bag of
# key:value tokens. uid and inode are picked out by prefix rather than by
# position, because the bag's contents vary with kernel and cgroup.
ss_rows_inet() {
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

# ===========================================================================
# the differential: both directions, with a count that proves it had teeth
# ===========================================================================
# difftest NAME MINROWS SOCKV_ARGS SS_ARGS
difftest() {
	_n=$1; _min=$2; _sa=$3; _ssa=$4
	_try=0
	while [ "$_try" -lt 4 ]; do
		_try=$((_try + 1))
		ss_rows_inet $_ssa                > "$TD/before"
		sockv_rows $_sa                   > "$TD/mine"
		ss_rows_inet $_ssa                > "$TD/after"
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
		    "after $_try attempts, with $_c sockets stable across the window" \
		    "ss reported and sockv did not:" \
		    "$(sed 's/^/  /' "$TD/missing")" \
		    "sockv reported and ss did not:" \
		    "$(sed 's/^/  /' "$TD/extra")"
	else
		ok "$_n: ss agrees both ways ($_c sockets)"
	fi
	# A set comparison of two empty sets passes. This is the assertion that
	# stops that from counting.
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
	for n in tcp-udp-all tcp-udp-all-teeth tcp-udp-listen \
	         tcp-udp-listen-teeth; do
		skipt "$n" "no ss(8)"
	done
else
	echo "sockv vs $(ss --version 2>/dev/null) on $(uname -r)"
	echo
	# Both ss commands keep the Netid column, which ss only prints when it
	# is asked for more than one family. `ss -tanHe` drops it and shifts
	# every field, so the single-family cases are checked below against the
	# combined run instead of against a second, differently-shaped parser.
	difftest 'tcp+udp, all states' 4 '-tu'  '-tuanHe'
	difftest 'tcp+udp, listening'  1 '-tul' '-tulnHe'
fi

# ===========================================================================
# -t and -u select, and together they partition -tu
# ===========================================================================
# Self-consistency, not an oracle: it catches an option-parsing mistake, which
# is the one thing the differential above cannot see because it always asks
# both programs for the same two families.
_try=0
while [ "$_try" -lt 4 ]; do
	_try=$((_try + 1))
	sockv_rows -tu > "$TD/both"
	sockv_rows -t  > "$TD/justt"
	sockv_rows -u  > "$TD/justu"
	sort -u "$TD/justt" "$TD/justu" > "$TD/union"
	cmp -s "$TD/both" "$TD/union" && break
done
if cmp -s "$TD/both" "$TD/union"; then
	ok "-t and -u partition -tu ($(wc -l < "$TD/both" | tr -d ' ') rows)"
else
	bad '-t and -u partition -tu' "$(diff "$TD/both" "$TD/union" | sed 's/^/  /')"
fi
if [ "$(awk '$1 != "tcp"' "$TD/justt" | wc -l)" -eq 0 ] &&
   [ "$(awk '$1 != "udp"' "$TD/justu" | wc -l)" -eq 0 ]; then
	ok '-t yields only tcp rows and -u only udp rows'
else
	bad '-t yields only tcp rows and -u only udp rows'
fi

# ===========================================================================
# a socket reported twice is a defect the set comparison above cannot see,
# because comparing sets throws duplicates away
# ===========================================================================
"$S" -tu | sort | uniq -d > "$TD/dup"
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
t 'listing exits 0'           0  -- "$S" -tu

printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]

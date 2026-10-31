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
# the same thing one column at a time, for the columns -o, -m and -i add
# ===========================================================================
# ss asks the kernel for the same extensions and prints them, which makes it
# a per-FIELD oracle here rather than a per-socket one. So each of the new
# columns gets its own projection: key plus that column and nothing else, so
# a disagreement names the column instead of saying that two rows differ.
#
# These values move, which is the whole difficulty. A queue length and a
# memory counter change with traffic, and a timer's remaining time changes
# every millisecond, so two readings seconds apart are two different states
# and not a disagreement. Three things handle that and they are deliberately
# different:
#
#  - For the live comparison, difftest's sandwich already does it. Only
#    sockets whose projected row is identical in BOTH ss runs are required to
#    be in sockv's output, so a socket whose counter moved during the window
#    drops out of the claim rather than failing it. The count assertion is
#    what stops that from becoming a silent narrowing: if the volatile
#    columns emptied the stable set, the number falls under its floor and the
#    assertion fails.
#  - For exact per-field values, the sockets the probe owns. Nothing is sent
#    on them, so their counters do not move at all, and the probe knows what
#    rb, tb and the listen backlog must be from a different interface.
#  - For the one value that is a countdown, a bound rather than an equality.
#    See the keepalive assertions further down.
#
# sockv is always run with -omi so the extension columns sit at fixed
# positions, and they are indexed from NF rather than from the left because a
# UNIX socket name containing whitespace shifts the middle of a row and never
# its end.
#
#   sockv -omi:  fam netid state local peer inode uid rq wq timer skmem cong
mext() {
	_c=$1; shift
	"$S" -omi "$@" | awk -v c="$_c" '
		{
			if ($1 == "unix") key = $2 " " $3 " " $(NF-6)
			else key = $2 " " $3 " " $4 " " $5 " " $(NF-6)
			if (c == "q") { print key, $(NF-4), $(NF-3); next }
			if (c == "sk") { print key, $(NF-1); next }
			if (c == "cg") { print key, $NF; next }
			tm = $(NF-2)
			if (tm == "timer:-") { print key, "-"; next }
			sub(/^timer:\(/, "", tm)
			sub(/\)$/, "", tm)
			split(tm, f, ",")
			# The expiry is dropped here on purpose: it is the one
			# sub-field that cannot be equated across two readings.
			#
			# A timer of "off" becomes "-" because that is the same
			# statement ss makes by printing no timer token at all,
			# and it is the kernel saying no timer is running rather
			# than an attribute that failed to arrive. It does mean
			# the retransmit count is not compared against ss for a
			# socket with no timer, because ss prints that count
			# only inside the timer token and so reports nothing
			# there either. The fixture and the probe cover it.
			print key, (f[1] == "off" ? "-" : f[1] "/" f[3])
		}' | sort
}

# ss, projected the same way.
#
# -m and -i put their output on a continuation line for an inet socket and
# inline for a UNIX one, so a continuation is folded back onto the row it
# belongs to before anything is read off it.
#
# ss prints no token at all for an attribute it did not get, where sockv
# prints "-", so an absence is mapped to "-" here. That is a mapping of
# presence and not of value: there is no ss string for "the kernel declined"
# for this to be wrong about.
#
# The congestion control name is the last token of the colon-free run that
# follows ss's "<->" marker. ss prints bare flag words there ahead of the
# name ("ts", "sack"), so taking the first colon-free token finds one of
# those instead, and taking the whole run would include them. A row where
# this picks the wrong token makes the comparison FAIL rather than pass,
# which is the safe direction for a parser on the oracle's side of a
# differential.
sext() {
	_c=$1; shift
	ss "$@" 2>/dev/null | awk -v c="$_c" '
		function emit(L,   i, j, ino, tm, sk, cg, key, f) {
			$0 = L
			tm = "-"; sk = "skmem:-"; cg = "cong:-"; ino = ""
			if ($1 ~ /^u_/) {
				if (NF < 8 || $6 !~ /^[0-9]+$/) { nf++; return }
				key = $1 " " $2 " " $6
				for (i = 9; i <= NF; i++)
					if ($i ~ /^skmem:\(/) sk = $i
			} else {
				for (i = 7; i <= NF; i++) {
					if ($i ~ /^ino:/) ino = substr($i, 5)
					else if ($i ~ /^skmem:\(/) sk = $i
					else if ($i ~ /^timer:\(/) {
						tm = $i
						sub(/^timer:\(/, "", tm)
						sub(/\)$/, "", tm)
						split(tm, f, ",")
						tm = f[1] "/" f[3]
					}
					# The shutdown marker, and it is not
					# always "<->": a socket whose peer has
					# sent FIN prints "-->", and the other
					# two forms are "<--" and "---". The
					# first version of this matched the
					# literal "<->" and so found no
					# congestion control name for the one
					# CLOSE-WAIT socket on the machine,
					# which failed the comparison rather
					# than passing it.
					else if ($i ~ /^[<-]-[->]$/) j = i + 1
				}
				if (ino == "") ino = 0
				key = $1 " " $2 " " $5 " " $6 " " ino
				while (j && j <= NF && $j !~ /:/) {
					cg = "cong:" $j
					j++
				}
			}
			if (c == "q") print key, $3, $4
			else if (c == "sk") print key, sk
			else if (c == "cg") print key, cg
			else print key, tm
		}
		/^[[:blank:]]/ { held = held " " $0; next }
		{
			# emit() assigns to $0 to re-split the joined line,
			# so $0 is no longer this line once it returns. The
			# first version of this read $0 afterwards and set
			# held to the row it had just emitted, which emitted
			# every row again on the next line and grew without
			# bound: ss appeared to report one socket fifty times.
			cur = $0
			if (held != "") emit(held)
			held = cur
		}
		END { if (held != "") emit(held) }' | sort
}

# difftest calls "my$5" and "ss$5", so these wrappers are what let the whole
# sandwich, both directions, the retries and the count floor be reused rather
# than written again for each column.
my_q()  { mext q  "$@"; }
ss_q()  { sext q  "$@"; }
my_tm() { mext tm "$@"; }
ss_tm() { sext tm "$@"; }
my_sk() { mext sk "$@"; }
ss_sk() { sext sk "$@"; }
my_cg() { mext cg "$@"; }
ss_cg() { sext cg "$@"; }

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
	         'tcp+udp+unix together' 'queue lengths, inet' \
	         'timer, inet vs ss -o' 'skmem, inet vs ss -m' \
	         'cong, inet vs ss -i' 'queue lengths, unix' \
	         'skmem, unix vs ss -m'; do
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

	# One differential per new column. Each ss command carries exactly the
	# one flag whose column is being read, because the flags interfere:
	# -i adds ino: and dev: tokens to a UNIX row, where ino: is the
	# socket FILE's inode and not the socket's, and reading the wrong one
	# would compare two different numbers and call them equal.
	difftest 'queue lengths, inet'    4 '-tu' '-tuaneH'  _q
	difftest 'timer, inet vs ss -o'   4 '-tu' '-tuanoeH' _tm
	difftest 'skmem, inet vs ss -m'   4 '-tu' '-tuanmeH' _sk
	# A column where both sides agree on "-" everywhere would pass this
	# while proving nothing, which is what the arrival counts further
	# down are for: this says the values agree, those say there were
	# values. The congestion control name is the sharpest case, since the
	# kernel reports none at all for a UDP socket.
	difftest 'cong, inet vs ss -i'    4 '-tu' '-tuanieH' _cg
	difftest 'queue lengths, unix'    4 '-x'  '-xaneH'   _q
	difftest 'skmem, unix vs ss -m'   4 '-x'  '-xanmeH'  _sk

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
# idiag_ext: a request is a wish, and the kernel decides what to answer
# ===========================================================================
# An output comparison cannot see any of this. A listing full of "-" is what
# a request that never carried the mask looks like, and it is also what a
# kernel declining to answer looks like, and it is also what a column of
# agreeing absences looks like in a diff. So --records reports how many
# records carried each optional attribute, and these are the assertions that
# say the new code path ran at all. Same shape as the record count the
# bytecode filters are judged by, for the same reason: the number is the only
# witness.
#
# Three outcomes, counted apart. Arrived and agrees is the differentials
# above. Arrived and disagrees is a failure there. Never arrived is neither,
# and is what is counted here.
ext_read() {
	"$S" --records "$@" >"$TD/x.out" 2>"$TD/x.err"
	_rec=$(sed -n 's/^records: //p' "$TD/x.err")
	_sk=$(sed -n 's/^ext: skmem \([0-9]*\).*/\1/p' "$TD/x.err")
	_cg=$(sed -n 's/^ext:.*cong \([0-9]*\).*/\1/p' "$TD/x.err")
	_rq=$(sed -n 's/^ext:.*rqlen \([0-9]*\).*/\1/p' "$TD/x.err")
	_tm=$(sed -n 's/^ext:.*timer \([0-9]*\)$/\1/p' "$TD/x.err")
	_rows=$(grep -c . "$TD/x.out")
}

# eq NAME GOT WANT ...   a plain equality with a name on it
#
# The three values are copied out before the shift. The first version read
# $2 and $3 after it, so the FAILURE branch died with "parameter not set"
# under set -u and the whole suite stopped with no summary line -- which
# t/mutants.sh scores as an unknown fail count rather than as the mutant
# being caught. Found by planting one: a harness whose red path is itself
# broken reports the wrong thing about every defect it meets.
eq() {
	_n=$1; _g=$2; _w=$3
	shift 3
	if [ "$_g" = "$_w" ]; then ok "$_n"
	else bad "$_n" "got [$_g], wanted [$_w]" "$@"; fi
}

# The control. Without -m or -i the mask is zero, and a kernel that sent an
# optional attribute unasked would show up here rather than being mistaken
# for one that was requested. INET_DIAG_SKV6ONLY does arrive unasked on every
# AF_INET6 socket, which is why "the kernel sends nothing unrequested" is NOT
# the claim: the claim is about these four.
ext_read -tux
eq 'no -o -m -i: nothing optional arrives' \
    "$_sk/$_cg/$_rq/$_tm" '0/0/0/0' \
    "records: $_rec, rows: $_rows"

# Each flag asks for its own attribute and not the other one, which is what
# makes idiag_ext the thing doing the selecting rather than the kernel
# volunteering everything.
ext_read -t -m
if [ "${_sk:-0}" -gt 0 ] && [ "$_cg" = 0 ]; then
	ok "-m asks for the memory counters only ($_sk of $_rec records)"
else
	bad '-m asks for the memory counters only' \
	    "skmem $_sk, cong $_cg, over $_rec records"
fi
ext_read -t -i
if [ "${_cg:-0}" -gt 0 ] && [ "$_sk" = 0 ]; then
	ok "-i asks for the congestion control name only ($_cg of $_rec records)"
else
	bad '-i asks for the congestion control name only' \
	    "skmem $_sk, cong $_cg, over $_rec records"
fi
# udiag_show is the UNIX spelling of the same idea, and a different word in
# the request struct, so it gets its own assertion rather than being assumed
# to follow.
ext_read -x -om
if [ "${_rq:-0}" -gt 0 ] && [ "${_sk:-0}" -gt 0 ]; then
	ok "udiag_show brings back rqlen and meminfo ($_rq and $_sk of $_rec)"
else
	bad 'udiag_show brings back rqlen and meminfo' \
	    "rqlen $_rq, skmem $_sk, over $_rec records"
fi

# A decline, measured rather than inferred. INET_DIAG_CONG is requested for
# every UDP socket here and the kernel answers for none of them, because a
# UDP socket has no congestion control to report. That is not a disagreement
# with ss, which prints nothing there either, and the differential above
# passes on those rows for the right reason only because this says the count
# is zero on purpose.
ext_read -u -i
if [ "${_rec:-0}" -gt 0 ] && [ "$_cg" = 0 ]; then
	ok "the kernel declines INET_DIAG_CONG for all $_rec udp sockets"
elif [ "${_rec:-0}" -eq 0 ]; then
	skipt 'the kernel declines INET_DIAG_CONG for udp' 'no udp sockets'
else
	bad 'the kernel declines INET_DIAG_CONG for udp' \
	    "$_cg of $_rec udp records carried one; this kernel is not the" \
	    "one the README describes"
fi

# The counters and the listing have to be two facts about one dump, which is
# why both come out of a single invocation. Taking them from two runs is the
# defect the filter's record-count assertion already had once: ordinary churn
# makes them differ and the message accuses sockv of the thing the assertion
# exists to catch.
ext_read -tux -omi
_nsk=$(awk '$(NF-1) != "skmem:-"' "$TD/x.out" | grep -c .)
_ncg=$(awk '$NF != "cong:-"' "$TD/x.out" | grep -c .)
_ntm=$(awk '$(NF-2) != "timer:-" && $(NF-2) !~ /^timer:\(off,/' "$TD/x.out" |
    grep -c .)
eq "skmem arrivals equal the rows showing one ($_sk)" "$_sk" "$_nsk"
eq "cong arrivals equal the rows showing one ($_cg)" "$_cg" "$_ncg"
eq "timer count equals the rows with a timer running ($_tm)" "$_tm" "$_ntm"

# Which sockets the kernel declined, and why it is a coherent answer rather
# than a gap. A TIME-WAIT entry and a half-open SYN-RECV request socket have
# no full struct sock behind them, so there is no memory accounting and no
# congestion control to report -- the same reason both already report inode 0
# and uid 0. Every declining inet row must be one of those two.
_dstates=$(awk '$1 != "unix" && $(NF-1) == "skmem:-" {print $3}' "$TD/x.out" |
    sort -u | tr '\n' ' ')
_nd=$(awk '$1 != "unix" && $(NF-1) == "skmem:-"' "$TD/x.out" | grep -c .)
if [ "$_nd" -eq 0 ]; then
	skipt 'the inet sockets that declined are the ones with no struct sock' \
	    'no socket on this machine declined, so there is nothing to classify'
elif [ -z "$(printf '%s' "$_dstates" | tr ' ' '\n' |
             grep -vx 'TIME-WAIT\|SYN-RECV\|')" ]; then
	ok "the $_nd inet socket(s) that declined are in state(s): $_dstates"
else
	bad 'the inet sockets that declined are the ones with no struct sock' \
	    "states that declined: $_dstates"
fi

# A UNIX socket has no timer and no congestion control in the interface at
# all, which is a different thing again from an attribute the kernel chose
# not to send, and the column says so on every row rather than on some of
# them.
if [ -z "$(awk '$1 == "unix" &&
                ($(NF-2) != "timer:-" || $NF != "cong:-")' "$TD/x.out")" ]; then
	ok 'unix_diag has no timer and no congestion control, on every row'
else
	bad 'unix_diag has no timer and no congestion control, on every row' \
	    "$(awk '$1 == "unix" && ($(NF-2) != "timer:-" || $NF != "cong:-")' \
	        "$TD/x.out" | head -5 | sed 's/^/  /')"
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
	# pokf FLAGS NCOLS NAME PROTO CASE ROW...   exit 0 and exactly these
	# rows, comparing NCOLS columns of each and passing FLAGS to sockv.
	# The columns -o, -m and -i add sit past the seventh and are only
	# printed when their flag is given, so those cases need both.
	pokf() {
		_f=$1; _k=$2; _n=$3; _p=$4; _c=$5; shift 5
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
		$TO "$S" $_f --parse "$_p" "$TD/f.bin" >"$TD/p.out" 2>"$TD/e"
		_s=$?
		_got=$(awk -v k="$_k" 'NF {
			s = $1
			for (i = 2; i <= k; i++) s = s " " $i
			print s
		}' "$TD/p.out")
		_want=$(printf '%s\n' "$@")
		if [ "$_s" -eq 0 ] && [ "$_got" = "$_want" ]; then ok "$_n"
		else bad "$_n" "want exit 0 and" "$_want" \
		         "got exit $_s and" "$_got" "$(cat "$TD/e")"; fi
	}

	# pok NAME PROTO CASE ROW...   the seven columns of the default row
	pok() { _n=$1; _p=$2; _c=$3; shift 3; pokf '' 7 "$_n" "$_p" "$_c" "$@"; }

	# pbad NAME PROTO CASE WANT_STATUS MSG   nonzero exit, and the
	# diagnostic must name the field that was wrong -- a test that only
	# checks the status cannot tell one bounds check from another, or from
	# a typo in the parser.
	# A sixth argument, when given, is extra flags for sockv: the
	# extension attributes are only read when -o, -m or -i asked for them,
	# so a reply that lies about one of their lengths is only refused then.
	pbad() {
		_n=$1; _p=$2; _c=$3; _w=$4; _m=$5; _f=${6-}
		if ! "$P" emit "$_c" "$TD/f.bin" 2>"$TD/e"; then
			bad "$_n" "probe emit $_c failed" "$(cat "$TD/e")"
			return
		fi
		_e=$($TO "$S" $_f --parse "$_p" "$TD/f.bin" 2>&1 >/dev/null)
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

	# --- the optional extension columns, pinned to known values -----
	# Three outcomes to keep apart, and the fixtures are the only place
	# all three can be put side by side on demand.
	#
	# The attribute arrived: ext-full carries a full SK_MEMINFO array, a
	# congestion control name of "bbr" and a zero-window-probe timer, none
	# of which any socket on this machine has.
	#
	# The kernel declined: the v4 fixture carries no extension attribute
	# at all, which is what a TIME-WAIT entry sends, and the columns read
	# "-" rather than zero. A zero is a value the kernel reported; "-" is
	# the kernel not reporting one.
	#
	# Refused on our side: an attribute too short to hold what it claims
	# to be. Those are the pbad cases below.
	pokf '-omi' 12 'extension columns, every one populated' tcp ext-full \
	    'inet tcp ESTAB 127.0.0.1:8080 10.0.0.1:443 4260 1001 111 222 timer:(persist,3456ms,7) skmem:(r1,rb2,t3,tb4,f5,w6,o7,bl8,d9) cong:bbr'
	pokf '-omi' 12 'an extension the kernel did not send reads as -' tcp v4 \
	    'inet tcp ESTAB 127.0.0.1:8080 10.0.0.1:443 4242 1001 0 0 timer:(off,0ms,0) skmem:- cong:-'
	# A timer number past the end of ss's table, the same argument as the
	# unknown state: name it and keep the socket.
	pokf '-o' 10 'a timer number this build does not know' tcp \
	    ext-timer-unknown \
	    'inet tcp ESTAB 127.0.0.1:8080 10.0.0.1:443 4261 1001 0 0 timer:(unknown,1ms,0)'
	# A longer array than this build knows is a newer kernel, read to the
	# width we have. A shorter one is a reply lying about its own length.
	pokf '-m' 8 'more memory counters than this build knows' tcp \
	    ext-skmem-wide \
	    'inet tcp ESTAB 127.0.0.1:8080 10.0.0.1:443 4262 1001 skmem:(r1,rb2,t3,tb4,f5,w6,o7,bl8,d9)'
	pokf '-o' 10 'unix queue lengths come from UNIX_DIAG_RQLEN' unix \
	    ext-unix-rqlen \
	    'unix u_str LISTEN /run/probe.sock:4266 *:0 4266 1001 77 88 timer:-'
	# Without the flag the attribute is never read, so the same bytes that
	# are refused below are listed without complaint here. The refusal is
	# scoped to what is actually parsed, which is why each of those cases
	# names the flag that reaches it.
	pok 'a short memory array nobody asked for is not read' tcp \
	    ext-skmem-short \
	    'inet tcp ESTAB 127.0.0.1:8080 10.0.0.1:443 4263 1001'

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
	# The same bytes read as a unix_diag reply. Both handlers bound the
	# payload against the struct they are about to copy out of it, and
	# until this was here only the inet one was covered: the mutation
	# sweep listed one 'payload size check deleted' hitting both call
	# sites at once, so it could not say which half the suite could see.
	pbad 'payload too small for unix_diag_msg' unix payload-short 2 \
	    'unix_diag_msg needs 16'
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
	# The extension attributes, each refused only when the flag that
	# reads it was given. Same rule as everywhere else here: an unknown
	# attribute TYPE is ignored because the kernel's enum grows, and an
	# unknown LENGTH is refused because it cannot be interpreted at all.
	pbad 'memory array shorter than SK_MEMINFO_VARS' tcp ext-skmem-short 2 \
	    'the 9 SK_MEMINFO_VARS counters need 36' '-m'
	# The same array with nothing after it in the reply, which is the
	# fixture shape AddressSanitizer needs: with a NLMSG_DONE record
	# following, the overread a deleted check produces lands inside the
	# same allocation and the sanitizer sees nothing. Measured both ways
	# and written down in the README.
	pbad 'memory array shorter than its claim, and last in the reply' \
	    tcp ext-skmem-short-last 2 \
	    'the 9 SK_MEMINFO_VARS counters need 36' '-m'
	pbad 'congestion control name with no terminator' tcp ext-cong-empty 2 \
	    'attribute 4 is empty' '-i'
	pbad 'congestion control name too long to hold' tcp ext-cong-long 2 \
	    'carries 40 bytes; a congestion control name holds at most 31' '-i'
	pbad 'unix_diag_rqlen with one of its two counters' unix \
	    ext-unix-rqlen-short 2 'unix_diag_rqlen needs 8' '-o'

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

		# ===============================================
		# the extension columns, against values the probe
		# knows before sockv is asked
		# ===============================================
		# The live differential can only compare two readings of a
		# moving number. These sockets are the suite's own, nothing is
		# sent on them, so their counters do not move -- and the
		# numbers they must show come from somewhere other than
		# netlink.
		"$S" -tux -omi > "$TD/liveext"

		# rb and tb are sk_rcvbuf and sk_sndbuf, which is the same
		# pair of fields getsockopt(SO_RCVBUF) and
		# getsockopt(SO_SNDBUF) read. So this compares a value that
		# arrived as an optional netlink attribute against the same
		# value fetched through a syscall that touches no netlink at
		# all, on a socket whose identity is known.
		while read -r _kw _tag _ino _rb _tb; do
			[ "$_kw" = EXT ] || continue
			_got=$(awk -v i="$_ino" '$(NF-6) == i { print $(NF-1) }' \
			    "$TD/liveext")
			_wnt="rb$_rb,"
			case $_got in
			*"$_wnt"*) ;;
			*) bad "skmem rb/tb from getsockopt: $_tag" \
			       "sockv says $_got, getsockopt says" \
			       "rb$_rb and tb$_tb"
			   continue ;;
			esac
			case $_got in
			*",tb$_tb,"*) ok "skmem rb/tb from getsockopt: $_tag" ;;
			*) bad "skmem rb/tb from getsockopt: $_tag" \
			       "sockv says $_got, getsockopt says" \
			       "rb$_rb and tb$_tb" ;;
			esac
		done < "$TD/inv"

		# Send-Q on a listening socket is sk_max_ack_backlog, which is
		# the number this program passed to listen(2) -- so unlike rb
		# and tb this is not a second reading of a kernel value, it is
		# a value the suite chose. Recv-Q is the number of connections
		# waiting to be accepted, and nothing is connecting to these.
		while read -r _kw _tag _ino _bl; do
			[ "$_kw" = BACKLOG ] || continue
			_got=$(awk -v i="$_ino" \
			    '$(NF-6) == i { print $(NF-4), $(NF-3) }' \
			    "$TD/liveext")
			eq "listen backlog is Send-Q: $_tag" "$_got" "0 $_bl"
		done < "$TD/inv"

		# The timer. A column of timers over a corpus of sockets with
		# none running is a column of zeroes that agrees with ss
		# perfectly, so the probe arms one rather than hoping the
		# machine has one: SO_KEEPALIVE with TCP_KEEPIDLE, the only
		# timer reachable here without a privilege or a peer that
		# stops answering.
		_nka=0
		while read -r _kw _tag _ino _ms; do
			[ "$_kw" = KEEP ] || continue
			_nka=$((_nka + 1))
			_got=$(awk -v i="$_ino" '$(NF-6) == i { print $(NF-2) }' \
			    "$TD/liveext")
			# Not `set --`: that would overwrite the script's own
			# positional parameters, and $1 here is which binary
			# the whole suite is judging.
			_tn=$(printf '%s' "$_got" | sed -n \
			    's/^timer:(\([a-z]*\),[0-9]*ms,[0-9]*)$/\1/p')
			_te=$(printf '%s' "$_got" | sed -n \
			    's/^timer:([a-z]*,\([0-9]*\)ms,[0-9]*)$/\1/p')
			_tr=$(printf '%s' "$_got" | sed -n \
			    's/^timer:([a-z]*,[0-9]*ms,\([0-9]*\))$/\1/p')
			if [ -z "$_tn" ] || [ -z "$_te" ] || [ -z "$_tr" ]; then
				bad "keepalive timer: $_tag" \
				    "sockv printed [$_got] for inode $_ino"
				continue
			fi
			# The name and the retransmit count do not move. The
			# expiry does, so it gets a bound and not an equality:
			# it counts down from the TCP_KEEPIDLE this program
			# set, and the probe holds its sockets for 30 seconds,
			# so anything outside that window is sockv reading the
			# wrong field or reading it the wrong way round.
			if [ "$_tn" = keepalive ] && [ "$_tr" = 0 ] &&
			   [ "$_te" -gt 0 ] && [ "$_te" -le "$_ms" ] &&
			   [ "$_te" -gt "$((_ms > 30000 ? _ms - 30000 : 0))" ]
			then
				ok "keepalive timer: $_tag (${_te}ms of $_ms)"
			else
				bad "keepalive timer: $_tag" \
				    "sockv says [$_got]; TCP_KEEPIDLE was" \
				    "${_ms}ms and the hold window is 30s"
			fi
		done < "$TD/inv"
		if [ "$_nka" -eq 0 ]; then
			skipt 'keepalive timer' \
			    'the probe could not arm one'
		fi

		# And the count, because every assertion above is about rows
		# that exist. If no socket anywhere carried a timer, the
		# timer column would agree with ss over nothing.
		ext_read -tux -omi
		if [ "${_tm:-0}" -gt 0 ]; then
			ok "$_tm of $_rec records carried a timer"
		else
			bad 'some record carried a timer' \
			    'the timer column agreed with ss over a corpus of' \
			    'sockets that have no timer running, which it would' \
			    'also do if the field were never read'
		fi

		# The expiry against ss, bracketed rather than equated. ss
		# renders a remaining time under ten seconds to the
		# millisecond and anything longer to the second or the
		# minute, so this uses the socket the probe armed with a
		# nine-second idle, and skips if ss rendered it coarsely
		# anyway. The reading is sandwiched: ss, sockv, ss, and a
		# countdown read in the middle must lie between the two.
		# A keepalive timer that fires and re-arms inside the window
		# makes the later reading the larger one, which is churn
		# rather than disagreement, so that attempt is retried.
		sstimer() {
			ss -tuanoeH 2>/dev/null | awk -v i="ino:$1" '
				{ t = ""; f = 0
				  for (j = 1; j <= NF; j++) {
					if ($j == i) f = 1
					if ($j ~ /^timer:\(/) t = $j
				  }
				  if (f && t != "") {
					sub(/^timer:\([^,]*,/, "", t)
					sub(/,[0-9]*\)$/, "", t)
					print t
				  } }'
		}
		# ss's own rendering, converted back. Only the two exact forms
		# are accepted: "235ms" and "4.886sec" are a value, while
		# "11sec" is any value in a one-second range and "9min58sec"
		# in a one-minute one, and a bound built out of a range that
		# wide would pass for anything.
		msof() {
			awk -v t="$1" 'BEGIN {
				if (t ~ /^[0-9]+ms$/) {
					sub(/ms$/, "", t); print t + 0; exit
				}
				if (t ~ /^[0-9]+\.[0-9][0-9][0-9]sec$/) {
					split(t, f, ".")
					sub(/sec$/, "", f[2])
					print f[1] * 1000 + f[2] + 0; exit
				}
				print -1 }'
		}
		_ka=$(awk '$1 == "KEEP" && $2 == "tcp4-server" {print $3}' \
		    "$TD/inv")
		if [ -z "$_ka" ] || [ "$HAVE_SS" = no ]; then
			skipt 'the timer expiry is between two ss readings' \
			    'no short-idle keepalive socket, or no ss(8)'
		else
			_try=0; _done=no; _why=
			while [ "$_try" -lt 4 ] && [ "$_done" = no ]; do
				_try=$((_try + 1))
				_a=$(msof "$(sstimer "$_ka")")
				# -omi and not -o alone: NF-6 is the inode
				# only when all three columns are present.
				_v=$("$S" -t -omi |
				    awk -v i="$_ka" '$(NF-6) == i {
					t = $(NF-2)
					sub(/^timer:\([^,]*,/, "", t)
					sub(/ms,[0-9]*\)$/, "", t)
					print t }')
				_b=$(msof "$(sstimer "$_ka")")
				if [ "$_a" = -1 ] || [ "$_b" = -1 ]; then
					_why='ss rendered the expiry coarsely'
				elif [ -z "$_v" ]; then
					_why='sockv did not report that socket'
				elif [ "$_b" -gt "$_a" ]; then
					_why='the timer re-armed inside the window'
				elif [ "$_v" -le "$_a" ] && [ "$_v" -ge "$_b" ]
				then
					_done=yes
				else
					_why="sockv said ${_v}ms, ss said ${_a}ms then ${_b}ms"
				fi
			done
			if [ "$_done" = yes ]; then
				ok "the timer expiry is between two ss readings ($_b <= $_v <= $_a ms)"
			else
				bad 'the timer expiry is between two ss readings' \
				    "after $_try attempts: $_why"
			fi
		fi

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

		# A bytecode attribute and a nonzero idiag_ext travel in the
		# same request struct, and the attribute offset is computed
		# from the end of that struct, so the two are not obviously
		# independent. Same filter with and without -m must select
		# the same sockets, and the extension must still come back.
		# EXPECT tag fam netid state local peer inode uid, so the
		# local endpoint is the sixth field and the port is what
		# follows its last colon.
		_pf=$(awk -v t=tcp4-listen \
		    '$1 == "EXPECT" && $2 == t { print $6 }' "$TD/inv" |
		    sed 's/.*://')
		if [ -z "$_pf" ]; then
			skipt 'a filter and an extension in one request' \
			    'the probe could not bind its listener'
		else
			ext_read -t --port "$_pf" -m
			_f1=$(awk '{ print $6 }' "$TD/x.out" | sort)
			_f2=$("$S" -t --port "$_pf" | awk '{ print $6 }' | sort)
			if [ "$_f1" = "$_f2" ] && [ "${_sk:-0}" -gt 0 ] &&
			   [ "${_rec:-0}" -gt 0 ] && [ "$_rec" = "$_rows" ]
			then
				ok "a filter and an extension in one request ($_rec records, skmem $_sk)"
			else
				bad 'a filter and an extension in one request' \
				    "with -m: $_rec records, $_rows rows, skmem $_sk" \
				    "inodes with -m: $(printf '%s' "$_f1" | tr '\n' ' ')" \
				    "inodes without:  $(printf '%s' "$_f2" | tr '\n' ' ')"
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
t '-omi listing exits 0'      0  -- "$S" -tux -omi
t '-m with -x is not refused' 0  -- "$S" -x -m

printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]

# sockv

List the kernel's sockets by asking the kernel, over `NETLINK_SOCK_DIAG`.

```
sockv -t          TCP
sockv -u          UDP
sockv -x          UNIX domain
sockv -l          listening only
sockv -a          every state (the default)
sockv             all three families

sockv -tu -o      and the queue lengths and the timer   (ss -o)
sockv -tu -m      and the nine memory counters          (ss -m)
sockv -t  -i      and the congestion control name       (ss -i)

sockv -t --port 443             local port 443,   filtered by the kernel
sockv -tu --addr 127.0.0.0/8    local address in 127/8
sockv -tu --dev lo              bound to interface lo
sockv -t --port 443 --records   ... and say how many records the kernel sent
```

One row per socket, no header:

```
inet  tcp   LISTEN     127.0.0.1:631                0.0.0.0:*                       14994  65534
inet  tcp   LISTEN     127.0.0.53%lo:53             0.0.0.0:*                        9667  65534
inet6 tcp   LISTEN     [::1]:6010                   [::]:*                          73812   1000
inet  tcp   ESTAB      192.168.122.10:41378         13.248.151.210:443             237069   1000
inet  udp   UNCONN     0.0.0.0:5353                 0.0.0.0:*                        9661  65534
unix  u_str LISTEN     /run/user/1000/bus:44077     *:0                             44077   1000
unix  u_str ESTAB      /run/user/1000/bus:44078     *:33753                         44078   1000
unix  u_dgr UNCONN     @sockv-probe-47310:195741    *:0                            195741   1000
```

`FAMILY NETID STATE LOCAL PEER INODE UID`, and `-o`, `-m` and `-i` append
further columns after the uid in that order. A UNIX socket's local end is
`name:inode` and its peer end is `*:peer-inode`, because `ss` reports a UNIX
socket's inode in the column it labels Port, so both kinds of row have the
same `address:port` shape and one comparison covers both.

## Filtering in the kernel

`--port`, `--addr` and `--dev` are compiled into an
`INET_DIAG_REQ_BYTECODE` attribute and attached to the dump request, so the
kernel never serialises a socket that does not match. They combine with AND,
they test the **local** end, and `ss` has an equivalent for each:

| sockv | ss |
|---|---|
| `--port N` | `sport = :N` |
| `--addr A[/LEN]` | `src A/LEN` |
| `--dev NAME` | `dev == NAME` |

The point of a kernel-side filter is not the output, which a userspace filter
would get right too. It is that the sockets never cross the netlink socket.
That is not something an output comparison can see, so `--records` prints to
stderr how many `SOCK_DIAG_BY_FAMILY` records the kernel actually sent:

```
$ sockv -tu --records >/dev/null
records: 43
$ sockv -tu --records --port 53 >/dev/null
records: 4
```

43 against 4 is the whole claim, and the suite asserts it: a filtered dump
must bring back fewer records than an unfiltered one, and exactly as many as
sockv prints. A bytecode that matches everything, or one that never reaches
the request, is invisible in the listing and obvious here. `--records` is
documented as part of the interface for that reason and not hidden behind a
debug flag.

Three details that are not obvious:

- A port in a bytecode operand is **host** byte order, not `__be16`. The
  kernel compares against `inet->inet_num`, which is already host order.
  Addresses in the same operand are network order. A mutant that sends the
  port big-endian is in `make mutants` and is caught.
- A condition's failure jump points one word **past** the end of the
  program. The kernel accepts a socket when control reaches exactly the end
  and rejects it when a jump lands beyond it, so losing that `+4` turns every
  filter into a filter that matches everything while still being a program
  the kernel's own audit pass accepts. Also a mutant, also caught.
- A prefix length of zero still selects by address **family**.
  `--addr 0.0.0.0/0` lists the IPv4 sockets and `--addr ::/0` lists the IPv6
  ones, rather than both listing everything. `ss src 0.0.0.0/0` does the same,
  so this is the kernel's rule and not a misreading of it, and both cases are
  in the suite.

## The optional extensions

`-o`, `-m` and `-i` are named after the `ss` flags that print the same thing,
because `ss` is the oracle for every column they add and a differential is
easier to read when both sides spell the request the same way.

```
$ sockv -t -omi
inet  tcp   LISTEN     127.0.0.1:631                0.0.0.0:*                       18528  65534 0 4096 timer:(off,0ms,0) skmem:(r0,rb131072,t0,tb16384,f0,w0,o0,bl0,d0) cong:cubic
inet  tcp   ESTAB      127.0.0.1:47386              127.0.0.1:47901              28170985   1000 0 0 timer:(keepalive,598464ms,0) skmem:(r0,rb131072,t0,tb2626560,f0,w0,o0,bl0,d0) cong:cubic
inet  tcp   TIME-WAIT  192.168.122.10:51982         172.64.155.209:443                  0      0 0 0 timer:(timewait,24001ms,0) skmem:- cong:-
```

The third row is the one worth looking at. A TIME-WAIT entry reports inode 0
and uid 0 because it has no owning socket left to ask, and for the same
reason the kernel sends no memory counters and no congestion control name
for it at all.

The three are not the same kind of thing, and the difference is the point of
the group. `idiag_rqueue`, `idiag_wqueue`, `idiag_timer`, `idiag_retrans` and
`idiag_expires` are fields of `inet_diag_msg` and arrive whether or not
anybody asks, so `-o` needs nothing from the kernel it was not already
getting. `INET_DIAG_SKMEMINFO` and `INET_DIAG_CONG` have to be requested
through `idiag_ext`, which is a bitmask of (extension - 1) in eight bits, and
the kernel then answers or does not. On the UNIX side the same two columns
come from `UNIX_DIAG_RQLEN` and `UNIX_DIAG_MEMINFO`, requested through
`udiag_show`, which is a flag word rather than a shifted mask: the same idea
spelled differently in a different request struct, so it gets its own
assertions rather than being assumed to follow.

An optional attribute therefore has three outcomes, and keeping them apart is
most of the work here:

- It arrived and the value agrees with `ss`. That is the differential.
- It arrived and the value disagrees. That is a failure.
- It never arrived, which is not a disagreement with anything. It prints as
  `-`, never as a zero, and is counted.

A zero is a value the kernel reported. A `-` is the kernel not reporting one.
The two look identical in a diff, which is why the counts below exist.

### What this kernel actually returned

`--records` prints the arrival count per attribute, measured in one run on
7.2.13-200.fc44.x86_64:

```
$ sockv -t -omi --records >/dev/null
records: 62
ext: skmem 26, cong 26, rqlen 0, timer 51

$ sockv -u -omi --records >/dev/null
records: 22
ext: skmem 22, cong 0, rqlen 0, timer 0

$ sockv -x -omi --records >/dev/null
records: 1577
ext: skmem 1577, cong 0, rqlen 1577, timer 0

$ sockv -tux --records >/dev/null
records: 1661
ext: skmem 0, cong 0, rqlen 0, timer 0
```

Four facts in those numbers, each of them a passing assertion:

`INET_DIAG_SKMEMINFO` and `INET_DIAG_CONG` came back for 26 of 62 TCP
records. The 36 that declined are every TIME-WAIT socket on the machine, and
that is coherent rather than a gap: a timewait entry has no full `struct
sock` behind it, so there is no memory accounting and no congestion control
module to report, which is the same reason it already reports inode 0 and
uid 0. The suite asserts that every inet record which declined is in a state
with no full socket behind it, and prints the states it found.

The kernel declines `INET_DIAG_CONG` for all 22 UDP sockets, every time. A
UDP socket has no congestion control. `ss -ui` prints nothing there either,
so this is agreement and not a hole, but only the count says the column was
empty for that reason rather than because the request never went out.

`UNIX_DIAG_RQLEN` and `UNIX_DIAG_MEMINFO` came back for all 1577 UNIX
records.

With no extension flag, `idiag_ext` is zero and nothing optional arrives at
all. That is the control that makes the other three mean something.
`INET_DIAG_SKV6ONLY` does arrive unrequested on every `AF_INET6` socket, so
"this kernel sends nothing it was not asked for" is not the claim being
made; the claim is about these four.

Two timer kinds occur live: `keepalive` on 15 sockets and `timewait` on 36.
`on` (a retransmit timer) and `persist` (a zero-window probe) do not occur
here, and neither does a nonzero retransmit count, because provoking either
needs a peer that stops answering. Both are reached by a `--parse` fixture
instead, along with a timer number past the end of the table.

### These values move

A queue length and a memory counter change with traffic, and a timer's
remaining time changes every millisecond, so two readings a second apart are
two different states and not a disagreement. Three separate mechanisms handle
that, and they are deliberately different:

The live comparison uses the sandwich the rest of the suite already uses.
`ss` runs, then sockv, then `ss` again, and only sockets whose projected row
is identical in **both** `ss` runs are required to appear in sockv's output.
A socket whose counter moved during the window drops out of the claim rather
than failing it. The count assertion beside each comparison is what stops
that from becoming a silent narrowing: if the volatile columns emptied the
stable set, the number falls below its floor and the assertion fails. In
practice the narrowing is small. In the run below all four inet projections
compared the same 60 sockets, the six-field one included. Where the numbers
do differ between one differential and the next it is mostly not the columns
at all but the TIME-WAIT population turning over between one sandwich and
the next, since each differential takes its own.

Exact per-field values come from the sockets the suite creates. Nothing is
sent on them, so their counters do not move at all, and the numbers they
must show come from somewhere other than netlink: `skmem`'s `rb` and `tb`
are `sk_rcvbuf` and `sk_sndbuf`, which is the same pair of fields
`getsockopt(SO_RCVBUF)` and `getsockopt(SO_SNDBUF)` read, so the probe
compares a value that arrived as an optional netlink attribute against one
fetched through a syscall that touches no netlink. `Send-Q` on a listening
socket is `sk_max_ack_backlog`, which is the number the probe passed to
`listen(2)`, so that one is not a second reading of a kernel value at all.

The expiry gets a bound rather than an equality, and the probe arms the timer
rather than hoping the machine has one: `SO_KEEPALIVE` with `TCP_KEEPIDLE`,
the only timer reachable here without a privilege or a peer that stops
answering. One socket is given a ten-minute idle, so its remaining time must
be inside the thirty-second window the probe holds its sockets for and below
the value `setsockopt` was given. A second socket is given nine seconds,
because `ss` renders a remaining time under ten seconds to the millisecond
and anything longer to the second or the minute: that one is read in a
sandwich, `ss` then sockv then `ss`, and the countdown read in the middle
must lie between the two. A measured run: `8830 <= 8845 <= 8853` ms. When the
timer fires and re-arms inside the window the later reading is the larger
one, which is churn rather than disagreement, so that attempt is retried.

The timer column is the one where a passing comparison proves least on its
own. Over a corpus of sockets with no timer running it is a column of zeroes
that agrees with `ss` perfectly, and it would agree just as well if the field
were never read, which is why the arrival count is required to be non-zero
and why the probe arms a timer it chose.

### What the comparison does not cover

The expiry is not compared to `ss` by the column differential, only bounded
by the two mechanisms above. `ss` renders it through a formatter that drops
the milliseconds above nine seconds and the seconds above nine minutes, so
`11sec` is any value in a one-second range; sockv prints the raw millisecond
count the kernel gave instead of reproducing that formatter.

A retransmit count is not compared against `ss` for a socket with no timer
running, because `ss` prints that count only inside its timer token and so
reports nothing there either. The fixture and the probe cover it.

`ss -i` prints dozens of further tokens out of `tcp_info`: `cwnd`, `rtt`,
`wscale`, byte counters. Only the congestion control name is implemented
here, `INET_DIAG_INFO` is not requested at all, and the rest of that line is
in the list of what does not work below.

## Build

```
make            # sockv, and t/probe
make test       # the oracle
make test-asan  # the same suite under ASan and UBSan
make mutants    # can the suite fail? plants 53 defects and asserts the verdict
```

`make test` also runs `t/mutants.sh --check-quiet` first, which asks whether
every pattern in the mutation table still matches exactly one line of
`sockv.c`. A pattern that has stopped matching is a mutant that tests
nothing, and it goes stale silently: adding an argument to `row()` broke one,
and the only thing that said so was that check. It is called from the
Makefile and deliberately not from `t/run.sh`, because the check reads
`sockv.c` and a mutation sweep rewrites it. Run from inside the suite it
would fail during every mutant for that reason alone and the sweep would read
the red suite as the mutant having been caught, scoring every mutation as
killed. `t/mutants.sh` invokes `t/run.sh` directly, so the sweep never
reaches that line.

Pure C11, Linux only, no dependencies. The netlink socket is driven with
`socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG)`, `sendmsg(2)` and
`recvmsg(2)` directly. There is no `libmnl`, no `libnl`, and no helper.

## Why not /proc/net/tcp

Because it is lossy, and demonstrably so.

A TCP socket that has been `bind`ed and has neither listened nor connected
sits in `TCP_CLOSE` and lives in the kernel's bind hash. `/proc/net/tcp` walks
the listening and established hashes, so **it does not list that socket at
all**, and `sock_diag` reports it. The test suite creates exactly such a
socket and asserts both halves: that sockv lists it, and that `/proc/net/tcp`
does not. If a future kernel starts listing bhash sockets there, that test
fails and says this paragraph is now wrong.

Beyond that: `/proc` cannot be filtered kernel-side, so "listening sockets
only" means reading every line and discarding most of them; it renders
addresses as hex text that the kernel has to format and the reader has to
unformat, and on a machine with 1500 UNIX sockets it is a 160KB text file
parsed to recover numbers the kernel already had.

`/proc` is still used here, as the weakest of three oracles. See below.

## The oracle

Three authorities, ranked by how little of each is ours:

1. `ss` from iproute2: a different program, written by other people,
reading the same netlink interface from the same kernel. Where it disagrees,
sockv is wrong. Five differentials compare netid, state, local endpoint, peer
endpoint, inode and uid, field for field:

| sockv | ss |
|---|---|
| `sockv -tu` | `ss -tuanHe` |
| `sockv -tul` | `ss -tulnHe` |
| `sockv -x` | `ss -xanHe` |
| `sockv -xl` | `ss -xlnHe` |
| `sockv -tux` | `ss -tuxanHe` |

Compared **in both directions**. A comparison that only checks that every
socket sockv reports was also reported by `ss` passes trivially for a program
that reports nothing, so every socket `ss` saw across the whole of sockv's run
must also appear in sockv's output. And because two empty sets compare equal,
each differential emits a **second, separately named assertion about how many
sockets it compared**: 1641 in the run below, and a count under the floor
is a failure, not a pass.

Six more differentials compare one extension column at a time, which makes
`ss` a per-field oracle here rather than a per-socket one: `ss -o` for the
timer, `ss -m` for the memory counters, `ss -i` for the congestion control
name, and the Recv-Q/Send-Q pair that `ss` prints by default. Each projects
both programs down to a socket key plus that one column, so a disagreement
names the column instead of saying that two rows differ. Each `ss` command
carries exactly the one flag whose column is being read, because the flags
interfere: `-i` adds `ino:` and `dev:` tokens to a UNIX row where `ino:` is
the socket file's inode and not the socket's, and reading the wrong one would
compare two different numbers and call them equal.

The live-system race is handled by sandwiching, not by hoping. `ss`
runs, then sockv, then `ss` again. A socket present in both `ss` runs existed
for the whole window and must be in sockv's output; a socket in sockv's output
must be in at least one `ss` run. Sockets that come and go while the three
programs take turns fall outside both claims, and that is what they are. The
sandwich retries up to four times, so only a mismatch that survives every
attempt fails: a real defect mismatches on all of them, while churn moves.

Each of the eight filters is judged three separate ways, because the three
fail differently: the same selection made in userspace over sockv's own
unfiltered listing must give the same set (the bytecode picks the right
sockets); `ss`, told the equivalent filter in its own syntax, must give the
same set (two implementations agree about what the filter means); and the
kernel must have sent fewer records with the filter than without (the kernel
did the work). Only the third can tell a kernel-side filter from a userspace
one.

2. Sockets the suite creates itself. `t/probe hold` binds and connects
twenty sockets whose family, type, state and address it chose, reads each
one's inode out of `fstat(2)` on its own descriptor. The same number the
kernel reports as `idiag_inode`, and prints the exact row sockv must
produce. Addresses in those expectations are printed from the numbers
passed to `bind(2)`, never by rendering a `sockaddr` back out, so the probe
cannot share a formatting mistake with sockv. This is what makes a failure
specific: the differential can only say "these sets differ", and these
assertions say which socket and which field.

A further assertion checks that `ss` reports all twenty of those inodes,
because a socket count of 1641 and a set of twenty known sockets are each
weak alone and strong together.

The extension columns lean on this oracle harder than on `ss`, because the
probe's sockets are quiet and `ss` can only ever give a second reading of a
moving number. It also arms the one timer reachable here. See the section on
the optional extensions above.

3. `/proc/net/{tcp,tcp6,udp,udp6,unix}`, weakest, and ranked last for a
reason worth stating. `ss` is a different program reading the same interface,
so it catches a misunderstanding on *our* side of that interface. `/proc` is
the same kernel rendering the same structures through a different `printf`, so
a kernel-side misunderstanding, or a wrong idea about what a field means,
would sail through both. What it can do that `ss` cannot is disagree about
*encoding*: `/proc` writes the port as big-endian hex text and the address as
little-endian hex text, so agreeing with it about a port number is a byte-order
check that shares no code and no convention with `sock_diag`'s `__be16`. It is
used one-directionally, every socket `/proc` lists must be one sockv lists,
for the reason in the section above.

And the other half: bytes no kernel would send. The kernel's reply is a
stream of self-describing records and every length in it comes off the wire; a
walker that trusts `nlmsg_len` reads past the end of its buffer. `--parse
PROTO FILE` exposes the same `walk()` the live path uses to a file, and
`t/probe emit` builds the files: seventeen cases where a record or an
attribute lies about its length (or where the reply is an error, not a
listing), and sixteen well-formed ones for the rendering rules no socket on
this machine happens to have.

## `make test`

```
sockv vs ss utility, iproute2-6.15.0 on 7.2.13-200.fc44.x86_64

ok    tcp+udp, all states: ss agrees both ways (60 sockets)
ok    tcp+udp, all states: compared 60 sockets (>= 4)
ok    tcp+udp, listening: ss agrees both ways (24 sockets)
ok    tcp+udp, listening: compared 24 sockets (>= 1)
ok    unix, all states: ss agrees both ways (1581 sockets)
ok    unix, all states: compared 1581 sockets (>= 4)
ok    unix, listening: ss agrees both ways (181 sockets)
ok    unix, listening: compared 181 sockets (>= 1)
ok    tcp+udp+unix together: ss agrees both ways (1641 sockets)
ok    tcp+udp+unix together: compared 1641 sockets (>= 8)
ok    queue lengths, inet: ss agrees both ways (60 sockets)
ok    queue lengths, inet: compared 60 sockets (>= 4)
ok    timer, inet vs ss -o: ss agrees both ways (60 sockets)
ok    timer, inet vs ss -o: compared 60 sockets (>= 4)
ok    skmem, inet vs ss -m: ss agrees both ways (60 sockets)
ok    skmem, inet vs ss -m: compared 60 sockets (>= 4)
ok    cong, inet vs ss -i: ss agrees both ways (60 sockets)
ok    cong, inet vs ss -i: compared 60 sockets (>= 4)
ok    queue lengths, unix: ss agrees both ways (1581 sockets)
ok    queue lengths, unix: compared 1581 sockets (>= 4)
ok    skmem, unix vs ss -m: ss agrees both ways (1581 sockets)
ok    skmem, unix vs ss -m: compared 1581 sockets (>= 4)
ok    -t -u -x partition the default listing (1641 rows)
ok    each family flag yields only its own netids
skip  unix uid against ss  (ss -e does not report uid for unix sockets)
ok    no duplicate rows
ok    no -o -m -i: nothing optional arrives
ok    -m asks for the memory counters only (25 of 37 records)
ok    -i asks for the congestion control name only (25 of 37 records)
ok    udiag_show brings back rqlen and meminfo (1581 and 1581 of 1581)
ok    the kernel declines INET_DIAG_CONG for all 23 udp sockets
ok    skmem arrivals equal the rows showing one (1629)
ok    cong arrivals equal the rows showing one (25)
ok    timer count equals the rows with a timer running (26)
ok    the 12 inet socket(s) that declined are in state(s): TIME-WAIT 
ok    unix_diag has no timer and no congestion control, on every row
ok    v4 endpoint
ok    v4 listener and %ifname scope
ok    v6 endpoint in brackets
ok    v6 wildcard, v6only, prints [::]
ok    v6 wildcard, dual stack, prints *
ok    v4-mapped address on a v6 socket
ok    scoped IPv6 address
ok    unknown state keeps the row
ok    unknown unix socket type keeps the row
ok    udp netid comes from the request
ok    unix filesystem path
ok    unix abstract name as @name
ok    unix unnamed, with a peer inode
ok    unix name bounded by nla_len, not by a NUL
ok    two records in one datagram
ok    unknown attribute type is ignored
ok    unaligned nlmsg_len keeps the next record
ok    extension columns, every one populated
ok    an extension the kernel did not send reads as -
ok    a timer number this build does not know
ok    more memory counters than this build knows
ok    unix queue lengths come from UNIX_DIAG_RQLEN
ok    a short memory array nobody asked for is not read
ok    buffer shorter than an nlmsghdr
ok    nlmsg_len below the header size
ok    nlmsg_len of zero
ok    nlmsg_len past the end of the buffer
ok    nlmsg_len of 0xffffffff does not wrap
ok    truncated final record
ok    payload too small for inet_diag_msg
ok    payload too small for unix_diag_msg
ok    nla_len below the attribute header
ok    nla_len past the end of its message
ok    attribute area ends mid-header
ok    u8 attribute with no payload
ok    unix name longer than sun_path
ok    address family we never asked for
ok    nlmsg_type we never asked for
ok    memory array shorter than SK_MEMINFO_VARS
ok    memory array shorter than its claim, and last in the reply
ok    congestion control name with no terminator
ok    congestion control name too long to hold
ok    unix_diag_rqlen with one of its two counters
ok    NLMSG_ERROR is reported with its errno
ok    NLMSG_ERROR with no room for an errno
ok    NLM_F_DUMP_INTR is not a listing
ok    --parse with an unknown protocol
ok    --parse with a missing file
ok    --parse with no arguments
ok    --parse of an empty file
ok    /proc/net/{tcp,tcp6,udp,udp6} inode+uid+port (60 rows)
ok    /proc/net/{tcp,tcp6,udp,udp6} inode+uid+port: compared 60 rows (>= 4)
ok    /proc/net/unix inode+name (1581 rows)
ok    /proc/net/unix inode+name: compared 1581 rows (>= 4)
note: 0 /proc/net/unix row(s) carry inode 0 and are excluded;
      sock_diag does not enumerate a socket with no struct socket
ok    /proc/net/unix: the inode-0 exclusion stays small
ok    the probe brought its sockets up (ports 49720..49725)
ok    created: tcp4-listen
ok    created: tcp4-client
ok    created: tcp4-server
ok    created: tcp4-bound-only
ok    created: tcp6-listen
ok    created: tcp6-client
ok    created: tcp6-server
ok    created: udp4-bound
ok    created: udp6-bound
ok    created: udp4-connected
ok    created: udp4-connected-peer
ok    created: udp6-dev-lo
ok    created: unix-path-listen
ok    created: unix-pair-server
ok    created: unix-pair-client
ok    created: unix-abstract-listen
ok    created: unix-dgram
ok    created: unix-seqpacket
ok    created: unix-socketpair-a
ok    created: unix-socketpair-b
ok    skmem rb/tb from getsockopt: tcp4-listen
ok    skmem rb/tb from getsockopt: tcp4-client
ok    skmem rb/tb from getsockopt: udp4-bound
ok    skmem rb/tb from getsockopt: unix-abstract-listen
ok    skmem rb/tb from getsockopt: unix-socketpair-a
ok    listen backlog is Send-Q: tcp4-listen
ok    listen backlog is Send-Q: unix-abstract-listen
ok    keepalive timer: tcp4-client (599891ms of 600000)
ok    keepalive timer: tcp4-server (8891ms of 9000)
ok    28 of 1662 records carried a timer
ok    the timer expiry is between two ss readings (8732 <= 8752 <= 8766 ms)
ok    unix name containing spaces appears verbatim
ok    bound-only TCP socket is absent from /proc/net/tcp
ok    ss sees all 20 sockets the probe created
ok    --records reports the kernel record count (72)
ok    --port: kernel bytecode selects what userspace selection does (4 rows)
ok    --port vs ss: ss agrees both ways (4 sockets)
ok    --port vs ss: compared 4 sockets (>= 1)
ok    --port vs ss: the kernel sent 4 records and sockv printed 4 rows
ok    --port vs ss: the kernel sent 4 records, an unfiltered dump 72
ok    --addr v4: kernel bytecode selects what userspace selection does (16 rows)
ok    --addr v4 vs ss: ss agrees both ways (16 sockets)
ok    --addr v4 vs ss: compared 16 sockets (>= 1)
ok    --addr v4 vs ss: the kernel sent 16 records and sockv printed 16 rows
ok    --addr v4 vs ss: the kernel sent 16 records, an unfiltered dump 72
ok    --addr v4 /8: kernel bytecode selects what userspace selection does (20 rows)
ok    --addr v4 /8 vs ss: ss agrees both ways (20 sockets)
ok    --addr v4 /8 vs ss: compared 20 sockets (>= 1)
ok    --addr v4 /8 vs ss: the kernel sent 20 records and sockv printed 20 rows
ok    --addr v4 /8 vs ss: the kernel sent 20 records, an unfiltered dump 72
ok    --addr v6: kernel bytecode selects what userspace selection does (11 rows)
ok    --addr v6 vs ss: ss agrees both ways (11 sockets)
ok    --addr v6 vs ss: compared 11 sockets (>= 1)
ok    --addr v6 vs ss: the kernel sent 11 records and sockv printed 11 rows
ok    --addr v6 vs ss: the kernel sent 11 records, an unfiltered dump 72
ok    --dev: kernel bytecode selects what userspace selection does (3 rows)
ok    --dev vs ss: ss agrees both ways (3 sockets)
ok    --dev vs ss: compared 3 sockets (>= 1)
ok    --dev vs ss: the kernel sent 3 records and sockv printed 3 rows
ok    --dev vs ss: the kernel sent 3 records, an unfiltered dump 72
ok    --port --dev: kernel bytecode selects what userspace selection does (1 rows)
ok    --port --dev vs ss: ss agrees both ways (1 sockets)
ok    --port --dev vs ss: compared 1 sockets (>= 1)
ok    --port --dev vs ss: the kernel sent 1 records and sockv printed 1 rows
ok    --port --dev vs ss: the kernel sent 1 records, an unfiltered dump 72
ok    --addr 0.0.0.0/0: kernel bytecode selects what userspace selection does (53 rows)
ok    --addr 0.0.0.0/0 vs ss: ss agrees both ways (53 sockets)
ok    --addr 0.0.0.0/0 vs ss: compared 53 sockets (>= 1)
ok    --addr 0.0.0.0/0 vs ss: the kernel sent 53 records and sockv printed 53 rows
ok    --addr 0.0.0.0/0 vs ss: the kernel sent 53 records, an unfiltered dump 72
ok    --addr ::/0: kernel bytecode selects what userspace selection does (19 rows)
ok    --addr ::/0 vs ss: ss agrees both ways (19 sockets)
ok    --addr ::/0 vs ss: compared 19 sockets (>= 1)
ok    --addr ::/0 vs ss: the kernel sent 19 records and sockv printed 19 rows
ok    --addr ::/0 vs ss: the kernel sent 19 records, an unfiltered dump 72
ok    --port selects the probe listener and not its udp socket
ok    --addr 127.0.0.1 selects the v4 listener and not the v6 one
ok    --addr ::1 selects the v6 listener and not the v4 one
ok    --dev lo selects the scope-bound socket and not an unbound one
ok    a port nothing is bound to returns no records
ok    a filter and an extension in one request (4 records, skmem 4)
ok    -x with a filter is refused
ok    --port with no value
ok    --port out of range
ok    --port is not a number
ok    --addr is not an address
ok    --addr prefix out of range
ok    --dev names no interface
ok    --port given twice is refused
ok    a filter drops unix from the default family set
ok    unknown option
ok    stray argument
ok    --help exits 0
ok    listing exits 0
ok    -omi listing exits 0
ok    -m with -x is not refused

187 passed, 0 failed, 1 skipped
```

Exit status is part of the interface, because the suite asserts on it: `0`
listed, `1` a syscall failed or the kernel returned an error reply, `2` a
netlink reply was malformed and sockv refused to walk it, `3` the command line
was wrong. `86` is reserved for the sanitizers, see below.

If `sock_diag` is unreachable, or `ss` is not installed, or `/proc/net` is not
readable, the affected assertions are reported as skipped, with the kernel
version and the reason. A skip is never dressed up as a pass.

## Have I watched this harness fail?

`make mutants` plants 53 defects in `sockv.c` with `sed`, builds each one, runs
the whole suite against the broken binary, and asserts the verdict. Two
mutants are expected to *survive*, and asserting that is the point. A
survivor that starts being caught fails the script too, because at that moment
this README is the thing that has become wrong.

`t/mutants.sh --check` applies every one of those patterns without building
or running anything, and requires each to change exactly one line. It exists
because a pattern goes stale silently: adding an argument to `row()` stopped
`uid hardcoded to zero` from matching at all, which the check reported at
once. It also found two patterns that had always been looser than they read,
one changing a comment as well as its line and one hitting both of two call
sites, which is the shape that once made a real defect look provably
equivalent. `--check-quiet` is the form `make test` runs.

```
ok     (no defect planted)                    187 passed, 0 failed, 1 skipped

ok     port printed without ntohs             caught by 51 assertion(s)
         tcp+udp, all states: ss agrees both ways
         tcp+udp, listening: ss agrees both ways
         tcp+udp+unix together: ss agrees both ways
ok     AF_INET address read as 16 bytes       caught by 35 assertion(s)
         tcp+udp, all states: ss agrees both ways
         tcp+udp, listening: ss agrees both ways
         tcp+udp+unix together: ss agrees both ways
ok     INET_DIAG_SKV6ONLY ignored             caught by 11 assertion(s)
         tcp+udp, all states: ss agrees both ways
         tcp+udp, listening: ss agrees both ways
         tcp+udp+unix together: ss agrees both ways
ok     ifindex scope suffix dropped           caught by 18 assertion(s)
         tcp+udp, all states: ss agrees both ways
         tcp+udp, listening: ss agrees both ways
         tcp+udp+unix together: ss agrees both ways
ok     uid hardcoded to zero                  caught by 40 assertion(s)
         tcp+udp, all states: ss agrees both ways
         tcp+udp, listening: ss agrees both ways
         v4 endpoint
ok     local and peer endpoints swapped       caught by 43 assertion(s)
         tcp+udp, all states: ss agrees both ways
         tcp+udp, listening: ss agrees both ways
         tcp+udp+unix together: ss agrees both ways
ok     abstract name loses its @              caught by 8 assertion(s)
         unix, all states: ss agrees both ways
         unix, listening: ss agrees both ways
         tcp+udp+unix together: ss agrees both ways
ok     u_dgr relabelled u_str                 caught by 7 assertion(s)
         unix, all states: ss agrees both ways
         unix, listening: ss agrees both ways
         tcp+udp+unix together: ss agrees both ways
ok     UNIX_DIAG_PEER ignored                 caught by 7 assertion(s)
         unix, all states: ss agrees both ways
         tcp+udp+unix together: ss agrees both ways
         unix unnamed, with a peer inode
ok     every unix socket reads as unnamed     caught by 16 assertion(s)
         unix, all states: ss agrees both ways
         unix, listening: ss agrees both ways
         tcp+udp+unix together: ss agrees both ways
ok     -l uses TCP_LISTEN for UDP             caught by 1 assertion(s)
         tcp+udp, listening: ss agrees both ways
ok     -l drops the TCP_CLOSE half of the unix state mask caught by 1 assertion(s)
         unix, listening: ss agrees both ways
ok     bytecode attribute never attached      caught by 29 assertion(s)
         --port: kernel bytecode selects what userspace selection does
         --port vs ss: ss agrees both ways
         --port vs ss: the kernel sent 102 records, an unfiltered dump 102
ok     filter tests the peer end, not the local caught by 13 assertion(s)
         --port: kernel bytecode selects what userspace selection does
         --port vs ss: ss agrees both ways
         --addr v4: kernel bytecode selects what userspace selection does
ok     hostcond port left as -1 (any port)    caught by 7 assertion(s)
         --port: kernel bytecode selects what userspace selection does
         --port vs ss: ss agrees both ways
         --port vs ss: the kernel sent 105 records, an unfiltered dump 105
ok     hostcond port sent big-endian          caught by 18 assertion(s)
         --port: kernel bytecode selects what userspace selection does
         --port vs ss: ss agrees both ways
         --addr v4: kernel bytecode selects what userspace selection does
ok     hostcond prefix length zeroed          caught by 6 assertion(s)
         --addr v4: kernel bytecode selects what userspace selection does
         --addr v4 vs ss: ss agrees both ways
         --addr v4 /8: kernel bytecode selects what userspace selection does
ok     reject jump lands on the end, not past it caught by 29 assertion(s)
         --port: kernel bytecode selects what userspace selection does
         --port vs ss: ss agrees both ways
         --port vs ss: the kernel sent 105 records, an unfiltered dump 105
ok     DEV_COND ifindex operand never written caught by 5 assertion(s)
         --dev: kernel bytecode selects what userspace selection does
         --dev vs ss: ss agrees both ways
         --port --dev: kernel bytecode selects what userspace selection does
ok     the record counter does not count      caught by 18 assertion(s)
         --records reports the kernel record count
         --port vs ss: the kernel sent 0 records and sockv printed 6 rows
         --port vs ss: the kernel sent 0 records, an unfiltered dump 0
ok     a filter flag given twice is quietly ANDed caught by 1 assertion(s)
         --port given twice is refused
ok     only the first record is read          caught by 52 assertion(s)
         tcp+udp, all states: ss agrees both ways
         tcp+udp, listening: ss agrees both ways
         unix, all states: ss agrees both ways
ok     advance by nlmsg_len, not aligned      caught by 1 assertion(s)
         unaligned nlmsg_len keeps the next record
ok     nlmsg_len lower bound deleted          caught by 2 assertion(s)
         nlmsg_len below the header size
         nlmsg_len of zero
ok     nlmsg_len upper bound deleted          caught by 2 assertion(s)
         nlmsg_len past the end of the buffer
         nlmsg_len of 0xffffffff does not wrap
ok     short-buffer check deleted             caught by 2 assertion(s)
         buffer shorter than an nlmsghdr
         truncated final record
ok     nla_len lower bound deleted            caught by 1 assertion(s)
         nla_len below the attribute header
ok     nla_len upper bound deleted            caught by 1 assertion(s)
         nla_len past the end of its message
ok     inet payload size check deleted        caught by 1 assertion(s)
         payload too small for inet_diag_msg
ok     unix payload size check deleted        caught by 1 assertion(s)
         payload too small for unix_diag_msg
ok     unix name length check deleted         caught by 1 assertion(s)
         unix name longer than sun_path
ok     u8 attribute length check deleted      caught by 1 assertion(s)
         u8 attribute with no payload
ok     NLM_F_DUMP_INTR ignored                caught by 1 assertion(s)
         NLM_F_DUMP_INTR is not a listing
ok     attribute end-of-buffer loosened by 4  caught by 1 assertion(s)
         u8 attribute with no payload
ok     idiag_ext never set on the request     caught by 9 assertion(s)
         skmem, inet vs ss -m: ss agrees both ways
         cong, inet vs ss -i: ss agrees both ways
         -m asks for the memory counters only
ok     idiag_ext bit computed without the -1  caught by 7 assertion(s)
         skmem, inet vs ss -m: ss agrees both ways
         -m asks for the memory counters only
         the inet sockets that declined are the ones with no struct sock
ok     UDIAG_SHOW_RQLEN never requested       caught by 3 assertion(s)
         queue lengths, unix: ss agrees both ways
         udiag_show brings back rqlen and meminfo
         listen backlog is Send-Q: unix-abstract-listen
ok     UDIAG_SHOW_MEMINFO never requested     caught by 4 assertion(s)
         skmem, unix vs ss -m: ss agrees both ways
         udiag_show brings back rqlen and meminfo
         skmem rb/tb from getsockopt: unix-abstract-listen
ok     Recv-Q and Send-Q swapped              caught by 3 assertion(s)
         queue lengths, inet: ss agrees both ways
         extension columns, every one populated
         listen backlog is Send-Q: tcp4-listen
ok     the timer name table is off by one     caught by 4 assertion(s)
         timer, inet vs ss -o: ss agrees both ways
         extension columns, every one populated
         keepalive timer: tcp4-client
ok     the timer expiry is always zero        caught by 5 assertion(s)
         extension columns, every one populated
         a timer number this build does not know
         keepalive timer: tcp4-client
ok     the skmem labels are in the wrong order caught by 9 assertion(s)
         skmem, inet vs ss -m: ss agrees both ways
         skmem, unix vs ss -m: ss agrees both ways
         extension columns, every one populated
ok     a declined attribute prints as zeroes  caught by 3 assertion(s)
         skmem, inet vs ss -m: ss agrees both ways
         skmem arrivals equal the rows showing one (1627)
         an extension the kernel did not send reads as -
ok     the skmem arrival counter does not count caught by 4 assertion(s)
         -m asks for the memory counters only
         udiag_show brings back rqlen and meminfo
         skmem arrivals equal the rows showing one (0)
ok     the cong arrival counter does not count caught by 2 assertion(s)
         -i asks for the congestion control name only
         cong arrivals equal the rows showing one (0)
ok     the timer counter does not count       caught by 2 assertion(s)
         timer count equals the rows with a timer running (0)
         some record carried a timer
ok     skmem array length check deleted       caught by 2 assertion(s)
         memory array shorter than SK_MEMINFO_VARS
         memory array shorter than its claim, and last in the reply
ok     cong empty-attribute check deleted     caught by 1 assertion(s)
         congestion control name with no terminator
ok     cong over-long name check deleted      caught by 1 assertion(s)
         congestion control name too long to hold
ok     unix_diag_rqlen length check deleted   caught by 1 assertion(s)
         unix_diag_rqlen with one of its two counters
ok     unix memory counters read from the wrong attribute caught by 8 assertion(s)
         queue lengths, unix: ss agrees both ways
         skmem, unix vs ss -m: ss agrees both ways
         udiag_show brings back rqlen and meminfo
ok     record end-of-buffer loosened by 4     survived, as documented
         provably equivalent: the test fires after the record has been
         processed, so the mutant only declines to look for a further
         record in fewer than four remaining bytes, and an nlmsghdr is
         sixteen. The same change to the attribute walker above is a real
         defect, because an attribute can be four bytes long
ok     MSG_TRUNC check deleted                survived, as documented
         unreachable on this machine: the receive buffer is 256KB and the
         kernel caps a dump datagram well below that, so nothing here can
         produce a truncated datagram to notice. Only a netns with tens of
         thousands of sockets, or a smaller buffer, would exercise it

AddressSanitizer, both netlink bounds deleted:
ok     overread is reported                   heap-buffer-overflow, exit 86
ok     skmem overread is reported             heap-buffer-overflow, exit 86

56 passed, 0 failed
```

The counts move a little from run to run, because most of them include the
live differentials and the machine's socket table is not the same twice. What
does not move is the shape, and the shape is the diagnosis, not an
alarm: the IPv4-only defect fails 35 assertions and **not one of them is an
IPv6 assertion**, a deleted bounds check fails one or two by name, and a
dropped record fails 51.

The extension mutants separate along the same lines. `the timer expiry is
always zero` is caught only by the `--parse` fixture and by the probe's own
keepalive socket, because the expiry is the one sub-field the differential
against `ss` deliberately does not compare. `the skmem arrival counter does
not count` is caught only by the count assertions, which is the whole reason
they exist: the listing is identical either way.

### The two that survive

- `record end-of-buffer loosened by 4` is provably equivalent, not a gap.
  The test fires after the record has already been processed, so the mutant
  only declines to look for a *further* record in fewer than four remaining
  bytes, and an `nlmsghdr` is sixteen. An identical change to the *attribute* walker is a real defect and is caught, because an attribute can be exactly
  four bytes long, so the two call sites are separate mutants.
  An earlier version of this file changed both at once and called the result
  equivalent. It was wrong, and `make mutants` is what said so.
- `MSG_TRUNC check deleted` cannot be reached on this machine. The receive
  buffer is 256KB and the kernel caps a dump datagram well below that, so
  nothing here can produce a truncated datagram to notice. Only a network
  namespace with tens of thousands of sockets, or a deliberately smaller
  buffer, would exercise it.

### Four defects found, and three of them were in the harness

- The handler was reading the attribute area out of its own stack frame.
  `walk()` copied each `nlmsghdr` into a local and passed `&local` to the
  handler, so `NLMSG_DATA()` of it pointed at whatever followed that copy in
  the frame. Every message was refused with "nla_len 1 is below the 4-byte
  attribute header": the bounds check doing its job on the program's own
  bug. Handlers now take the record where it lies in the receive buffer.
- `-l` dropped every datagram socket. `sockv -xl` listed 105 sockets where
  `ss -xl` listed 165, and the 60 missing ones were every `u_dgr` socket on
  the machine. "Listening" is `TCP_LISTEN` for a stream socket and `TCP_CLOSE`
  for a datagram one, because UDP and UNIX datagrams have no state machine of
  their own; `unix_diag` takes one state mask for a dump that contains both,
  so the request asks for both states and the display drops the combinations
  that are not listening. Found by the differential on its first run against
  UNIX sockets.
- The filter's record-count assertion raced itself. It took the number of
  records the kernel sent and the number of rows sockv printed from two
  separate runs of sockv, so a socket that went away in between made them
  differ, and the message it printed was "sockv discarded records after
  receiving them" -- accusing the program of the exact defect the assertion
  exists to catch. It failed on the thirteenth run of a loop that kept the
  output, reporting 36 records against 35 rows; the first twelve were green
  and the first six after that were green too, so a summary line would not
  have found it. Both numbers now come from one invocation, because they are
  two facts about the same dump. The one cross-run comparison that is left,
  filtered against unfiltered, is re-measured and retried like every other
  cross-run comparison in the file.
- `make test-asan` could not fail. With both netlink bounds deleted, the
  sanitised build read past the end of the reply and AddressSanitizer said
  nothing: `--parse` was reading its fixtures into a fixed one-megabyte
  buffer, so a short overread landed on uninitialised bytes that were *still
  inside the allocation*. The buffer is now exactly the size of the file, and
  the comment in `sockv.c` says that this is a property of the oracle rather
  than a micro-optimisation.

  Worse, the exit code collided: a sanitizer abort exits `1` by default and
  this suite asserts `1` for "the kernel returned an error", so an overread
  would have scored as a clean diagnostic. `ASAN_OPTIONS=exitcode=86` and
  `UBSAN_OPTIONS=halt_on_error=1:exitcode=86` fix that: the same problem
  `inflate` records in its own Makefile, and belt-and-braces, the suite's
  two assertion helpers now fail outright on seeing the word `Sanitizer` in a
  program's output.

## What does not work

Plainly, and this list is the part worth reading before trusting any of the
above.

### Protocols not implemented

- Only TCP, UDP and UNIX domain. `sock_diag` also serves SCTP, DCCP, raw
  sockets, `AF_PACKET`, netlink sockets themselves (`netlink_diag`), `AF_VSOCK`,
  `AF_XDP`, MPTCP and TCP metrics. None of those is implemented, and `ss`
  shows all of them. `ss -s` reports a summary across every family. Sockv has
  no equivalent and would under-count.
- No `AF_UNSPEC` dump. Each family and protocol is a separate request.
  That is four netlink round trips for `-tu` and five for `-tux`.

### Fields not implemented

- No process names or PIDs. `ss -p` works by scanning every `/proc/*/fd`
  for a socket inode, no netlink feature at all, and something an
  unprivileged process cannot do for sockets owned by other users. sockv does
  not attempt it. The uid column is what it offers instead. This is a
  deliberate non-goal, not a privilege skip, because the information is
  not in the interface this program reads.
- No `tcp_info`. `idiag_ext` can request `INET_DIAG_INFO`, which is the
  struct behind most of what `ss -i` prints: `cwnd`, `rtt`, `rto`, `wscale`,
  the byte and segment counters, `pacing_rate`, `delivery_rate`. sockv does
  not request it and prints none of it. `-i` here is the congestion control
  name from `INET_DIAG_CONG` and nothing else, which is one token of a line
  `ss` fills with forty.
- No `INET_DIAG_MEMINFO`, the four-counter `inet_diag_meminfo`. `-m` reports
  `INET_DIAG_SKMEMINFO`, the nine `SK_MEMINFO_VARS` counters, which is what
  `ss -m` prints. `ss` falls back to the four-counter form when the nine are
  absent, and sockv has no such fallback: there would be no oracle for it,
  because `ss` only prints that form on a kernel too old to send the other.
- No `INET_DIAG_TOS`, `INET_DIAG_TCLASS`, `INET_DIAG_SHUTDOWN` or
  `INET_DIAG_VEGASINFO`. `ss` prints the shutdown state as the `<->`, `-->`,
  `<--` and `---` marker at the end of each row; sockv does not.
- No `INET_DIAG_MARK`, which needs `CAP_NET_ADMIN`. Not implemented, so
  nothing is skipped for want of privileges here.
- The timer expiry is printed as a raw millisecond count, not the way `ss`
  renders it. `ss` drops the milliseconds above nine seconds and the seconds
  above nine minutes, so its `11sec` is any value in a one-second range.
  Reproducing that formatter would mean guessing at it or copying it, and
  the number is a countdown that the two programs read at two different
  instants, so there is no byte-for-byte comparison to be had either way.
  What the suite does instead is in the section on the extensions above.
- UNIX uid is not corroborated by `ss`. `ss -e` reports no uid for UNIX
  sockets, so the UNIX differentials compare five fields where the inet ones
  compare six, and the suite prints that as an explicit `skip` line rather
  than quietly comparing less. The UNIX uid column is checked against the
  twenty sockets the probe creates, where the expected value is known.
- No `UNIX_DIAG_VFS`, `ICONS` or `SHUTDOWN`. `ss -e` prints the socket
  file's `ino:`/`dev:` for a path-bound UNIX socket, and `ss -x` the list of
  pending connections for a listener. Not implemented. `UNIX_DIAG_RQLEN` and
  `UNIX_DIAG_MEMINFO` are, under `-o` and `-m`.

### Filtering

- The local end only. `--port`, `--addr` and `--dev` compile to
  `INET_DIAG_BC_S_COND` and `INET_DIAG_BC_DEV_COND`. There is no `--dport` or
  `--daddr`, although the kernel has `INET_DIAG_BC_D_COND` and `ss` exposes it
  as `dport` and `dst`. Adding them is one more op code and one more flag; it
  is not done, so "which sockets are talking to 10.0.0.1" is a question this
  program cannot ask the kernel.
- No `INET_DIAG_BC_MARK_COND` (needs `CAP_NET_ADMIN`), no
  `INET_DIAG_BC_CGROUP_COND`, no `INET_DIAG_BC_AUTO`, and no OR or NOT. The
  filters AND together and that is all the structure there is. `ss` has a
  whole expression language with parentheses; this is three flags.
- UNIX sockets cannot be filtered at all, because `unix_diag` has no
  bytecode. `-x` together with a filter is **refused** with exit 3 rather
  than answered. The two alternatives were to list every UNIX socket
  unfiltered, which is not what was asked for, or to filter them here in
  userspace, which would mean the same flag runs in the kernel for one family
  and in this process for another with nothing in the output saying which.
  As a consequence `sockv --port 53` with no family flag defaults to `-t -u`
  and not to `-t -u -x`.
- `--dev` matches `sk_bound_dev_if`, which is `SO_BINDTODEVICE` or a bind to
  a scoped address, not the interface a packet would leave by. An ordinary
  socket on a machine with one NIC has ifindex 0 and no `--dev` value selects
  it. This is `ss dev ==`'s meaning too.
- Creating a dev-bound socket to test `--dev` against needs no privilege
  only because of a trick: `SO_BINDTODEVICE` requires `CAP_NET_RAW`, so the
  probe binds an IPv6 UDP socket to `ff02::1` with `sin6_scope_id` set to
  `lo` instead, which makes the kernel fill in `sk_bound_dev_if` with no
  capability involved. If that bind ever fails the `--dev` assertions report
  a skip naming the socket, and are not silently narrowed to whatever
  dev-bound sockets the machine happens to have.
- Only state filtering otherwise, and only `-l` or all.
- No equivalent of `ss`'s default state filter. `ss -tn` with no `-a`
  applies a state mask that is not documented anywhere and that this project
  declined to reverse-engineer, because reproducing it would be mimicry of
  something undocumented with no oracle value, and getting it subtly wrong
  would poison every comparison made through it. sockv is all-states unless
  `-l`. So `sockv -t` is comparable to `ss -tan`, never to `ss -tn`.
- `-l` means a different state per protocol and that is intentional, not a
  wart: `TCP_LISTEN` for TCP, stream and seqpacket, `TCP_CLOSE` for UDP and
  UNIX datagram. It matches `ss` and the differential holds it there, but it
  will surprise anyone who expects one state mask.

### Output

- Not quoted, and not safely parseable in general. A socket name
  containing whitespace shifts every field after it. Any unprivileged process
  can bind an abstract UNIX socket whose name contains a space or a newline,
  and then a row of sockv's output can be forged. `ss` has exactly the same
  property and sockv matches it deliberately, because the whole oracle is a
  byte-for-byte comparison and an escaping scheme on one side would end it.
  Do not parse this output when a hostile local process can create sockets.
  The suite creates such a name, checks that it reaches the output verbatim
  and bounded, and reports rows it cannot split into fields as a loud
  skip, not dropping them.
- An abstract name containing a NUL is truncated at it. Abstract names are
  arbitrary byte strings and may legally contain NULs. `ss` renders the
  leading NUL as `@` and stops at the next one. Sockv does the same.
- No header line, by design, so the output pipes into `grep` and `awk`
  without a filter. The column widths are fixed and a long UNIX path pushes
  the inode and uid columns rightwards, which is cosmetic, every consumer
  here splits on whitespace.
- Two of `ss`'s rendering quirks are reproduced, not corrected. An
  all-zero IPv6 address prints as `*` and not `[::]`, but only when the socket
  is not `IPV6_V6ONLY`, and a nonzero `idiag_if` appends `%ifname` to the local
  end and never to the peer end. Both are what `ss` does, byte-identical
  output is what makes the differential a comparison instead of an
  interpretation, and the fixtures pin both.
- A TIME-WAIT socket reports inode 0 and uid 0. That is what the kernel
  puts in `inet_diag_msg` for a timewait entry, there is no owning socket
  left to ask, and `ss` reports the same, so the differential agrees. It is
  still a row whose last two columns mean "unknown", not "root".

### Inherently racy

- The listing is a snapshot of something moving. Sockets appear and vanish
  while the dump is being produced. `NLM_F_DUMP_INTR` is handled. The kernel
  sets it when its iterator was disturbed, the dump is restarted up to eight
  times, and after that sockv fails loudly instead of printing a listing the
  kernel has already said is inconsistent, but a socket created after the
  dump began is simply not in it, and that is not fixable. Its test suite deals with the same race by sandwiching and could not exist otherwise.
- A long dump can be interrupted forever on a machine churning sockets
  faster than the kernel can walk them. Eight attempts and then exit 1.

### Buffers and limits

- The receive buffer is a fixed 256KB static array and a datagram that
  does not fit is reported as a failure, not grown into. `MSG_TRUNC`
  makes `recvmsg` report the real size, so this fails loudly instead of
  silently dropping sockets, but see the mutation list. It is the one check
  the suite cannot exercise on this machine, because no dump here comes close.
  Marked `shortcut:` in the source. The upgrade is a realloc loop driven by
  the returned length.
- AddressSanitizer cannot see an overread on the live path. That static
  buffer is always larger than the data in it, so a read past the end of a
  reply stays inside the object. Only the `--parse` path has an allocation
  that ends where the data ends. Every hostile fixture goes through
  `--parse` for that reason.
- `SO_RCVBUF` is set best-effort and not checked. On a machine with enough
  sockets the kernel can still run out of space mid-dump; `recvmsg` returns
  `ENOBUFS` and sockv exits 1 naming it.
- The bytecode program lives in a fixed 64-byte static buffer, which is
  larger than any program this program builds (48 bytes is the maximum: three
  conditions, the widest an IPv6 host condition). That is the shape that makes
  AddressSanitizer blind, the same shape `--parse`'s fixture buffer had, and
  it is mitigated here by bound rather than by trimming: the one function that
  writes to it checks the remaining room and the condition count on every
  append and exits rather than truncating. A write that stayed inside the
  array but past the program would still be invisible. The exact-allocation
  fix is not worth a `malloc` for 48 bytes, and this sentence is the honest
  version of that trade.
- `nlmsg_seq` is not matched. Safe only because one request is outstanding
  at a time on a socket nobody else holds, and marked `shortcut:` where that
  assumption lives. The datagram's source port *is* checked, so a reply from
  anything other than the kernel is ignored.
- The extension columns add two more buffers of that shape, and both were
  measured rather than reasoned about. The row's extension string is a
  256-byte stack buffer that holds about 90 bytes, and `fmt_cong` copies the
  congestion control name into a 32-byte one that holds six. A read past the
  data in either stays inside the object, where AddressSanitizer is blind by
  construction, so the length checks in front of them are what matters and
  each has its own `--parse` fixture and its own mutant.

### What the sanitizers can and cannot see here

Four reads were planted and measured, because two paragraphs of reasoning
about this in METHOD were wrong in a row before anybody planted one. Built
with `-fsanitize=address,undefined`, `halt_on_error=1`, `exitcode=86`, and
separately under valgrind:

```
plant                                               ASan+UBSan      valgrind
past the data inside the 256-byte row buffer        nothing, 0      uninit, 86
past the name inside fmt_cong's char name[32]       nothing, 0      uninit, 86
skmem length check deleted, NLMSG_DONE after it     nothing, 0      nothing, 0
skmem length check deleted, attribute last          heap-bo, 86     read 4, 86
cong length check deleted, 40 bytes into name[32]   stack-bo, 86    nothing, 0
```

Five rows, and neither tool sees more than three of them. The two that stay
inside a live stack object are invisible to AddressSanitizer and caught by
valgrind, which reads them as uninitialised rather than as out of bounds:
the same asymmetry `sha2` hit on the day this was written, where a case only
valgrind could see had ASan, UBSan and MSan all silent. The one that reads
past a heap allocation is the reverse, caught by both. The stack smash is
caught by AddressSanitizer alone, because valgrind does not track the bounds
of arrays inside a frame.

The third row is the interesting one and it is not about the program at all.
The same deleted check, the same four bytes read past the same attribute,
and whether the sanitizer can see it depends on whether the fixture puts a
`NLMSG_DONE` record after that attribute or ends the reply there. With a
record following, the overread lands inside the same allocation and nothing
is reported. So `t/probe emit` builds both shapes, the suite refuses both by
exit code, and `make mutants` runs the sanitised plant against the one that
ends the reply. A fixture can turn a sanitizer off as effectively as a
rounded-up buffer can.

### Environment

- Requires `sock_diag`. `CONFIG_INET_DIAG`, `CONFIG_UNIX_DIAG` and the
  matching modules. There is no `/proc` fallback, deliberately. A fallback
  would mean sometimes returning the lossy answer without the caller knowing
  which. `socket(AF_NETLINK, ..., NETLINK_SOCK_DIAG)` failing is exit 1 with
  the errno, and the suite skips every assertion loudly.
- Behaviour on a kernel without IPv6 is untested. The `AF_INET6` request
  would presumably return no sockets, since the diag handler is registered per
  protocol, not per family, but if it returns an error reply instead
  then `sockv -t` fails instead of listing the IPv4 sockets. Nothing here can
  test that without rebuilding the kernel, so it is an unverified claim and is
  listed as one.
- One network namespace, the caller's. `ss -N` can enter another; sockv
  cannot.
- No `SOCK_DESTROY`. `sock_diag` can also kill a socket. Out of scope: this
  program reads.

## Design

One file, `sockv.c`, 1409 lines, about a quarter of them comments explaining why
the kernel or `ss` insists on something.

```
parse args  ->  compile --port/--addr/--dev to bytecode
            ->  socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG)
            ->  per family and protocol:
                  sendmsg  inet_diag_req_v2 | unix_diag_req, NLM_F_DUMP
                           + INET_DIAG_REQ_BYTECODE when a filter was given
                           + idiag_ext / udiag_show when -m or -i was given
                  recvmsg  -> walk() the records -> show_inet | show_unix
                  NLM_F_DUMP_INTR -> start that dump again
```

Five decisions worth naming.

The record walker is the whole security surface. Every bound is checked
against the number of bytes `recvmsg` actually delivered, never against
anything a record claims about itself, and there are two independent layers:
the record walker bounds `nlmsg_len` and the attribute walker bounds
`nla_len`. Deleting either one alone does not produce an overread, because the
other catches the inconsistency first. It takes removing both, which is
exactly what the sanitizer check in `make mutants` does.

`walk()` is shared between the live path and `--parse`. Not a test hook
bolted on: `--parse` selects the same handler by protocol and calls the same
function. A bounds check the fixtures prove is the bounds check the kernel
meets.

Output is `ss`'s, down to its quirks. State names are `ss`'s,
not the kernel's enum names: `TCP_CLOSE` prints as `UNCONN`, and addresses are
formatted the way `ss` formats them. The alternative is a translation table in
the test harness, a place for a disagreement to hide.

An absent optional attribute is a third outcome, not a zero. `idiag_ext` is
a request and the kernel decides, so a column can be empty because nobody
asked, because the kernel had nothing to report, or because the value really
is zero. Printing `-` separates the first two from the third in the output,
and the arrival counts `--records` prints separate the first from the second,
which no comparison of listings could.

An unknown attribute type is ignored. An unknown length is refused. The
kernel grows the attribute enum every few releases and sends some of it unasked:
`INET_DIAG_CGROUP_ID` and `INET_DIAG_SOCKOPT` arrive on this kernel without
being requested, so refusing an unrecognised type would break the program on
any kernel newer than the one it was built against. A length that does not fit
is a different thing entirely and is always refused.

## License

GPL-3.0. See `LICENSE`.

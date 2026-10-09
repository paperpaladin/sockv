# sockv

List the kernel's sockets by asking the kernel, over `NETLINK_SOCK_DIAG`.

```
sockv -t          TCP
sockv -u          UDP
sockv -x          UNIX domain
sockv -l          listening only
sockv -a          every state (the default)
sockv             all three families
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

`FAMILY NETID STATE LOCAL PEER INODE UID`. A UNIX socket's local end is
`name:inode` and its peer end is `*:peer-inode`, because `ss` reports a UNIX
socket's inode in the column it labels Port -- so both kinds of row have the
same `address:port` shape and one comparison covers both.

## Build

```
make            # sockv, and t/probe
make test       # the oracle
make test-asan  # the same suite under ASan and UBSan
make mutants    # can the suite fail? plants 26 defects and asserts the verdict
```

Pure C11, Linux only, no dependencies. The netlink socket is driven with
`socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG)`, `sendmsg(2)` and
`recvmsg(2)` directly; there is no `libmnl`, no `libnl`, and no helper.

## Why not /proc/net/tcp

Because it is lossy, and demonstrably so rather than as a matter of taste.

A TCP socket that has been `bind`ed and has neither listened nor connected
sits in `TCP_CLOSE` and lives in the kernel's bind hash. `/proc/net/tcp` walks
the listening and established hashes, so **it does not list that socket at
all** -- and `sock_diag` reports it. The test suite creates exactly such a
socket and asserts both halves: that sockv lists it, and that `/proc/net/tcp`
does not. If a future kernel starts listing bhash sockets there, that test
fails and says this paragraph is now wrong.

Beyond that: `/proc` cannot be filtered kernel-side, so "listening sockets
only" means reading every line and discarding most of them; it renders
addresses as hex text that the kernel has to format and the reader has to
unformat; and on a machine with 1500 UNIX sockets it is a 160KB text file
parsed to recover numbers the kernel already had.

`/proc` is still used here, as the weakest of three oracles. See below.

## The oracle

Three authorities, ranked by how little of each is ours:

**1. `ss` from iproute2** -- a different program, written by other people,
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
sockets it compared** -- 1597 in the run below -- and a count under the floor
is a failure, not a pass.

The live-system race is handled by sandwiching rather than by hoping. `ss`
runs, then sockv, then `ss` again. A socket present in both `ss` runs existed
for the whole window and must be in sockv's output; a socket in sockv's output
must be in at least one `ss` run. Sockets that come and go while the three
programs take turns fall outside both claims, which is what they are. The
sandwich retries up to four times, so only a mismatch that survives every
attempt fails -- a real defect mismatches on all of them, while churn moves.

**2. Sockets the suite creates itself.** `t/probe hold` binds and connects
nineteen sockets whose family, type, state and address it chose, reads each
one's inode out of `fstat(2)` on its own descriptor -- the same number the
kernel reports as `idiag_inode` -- and prints the exact row sockv must
produce. The addresses in those expectations are printed from the numbers
passed to `bind(2)`, never by rendering a `sockaddr` back out, so the probe
cannot share a formatting mistake with sockv. This is what makes a failure
specific: the differential can only say "these sets differ", and these
assertions say which socket and which field.

A further assertion checks that `ss` reports all nineteen of those inodes,
because a socket count of 1597 and a set of nineteen known sockets are each
weak alone and strong together.

**3. `/proc/net/{tcp,tcp6,udp,udp6,unix}`** -- weakest, and ranked last for a
reason worth stating. `ss` is a different program reading the same interface,
so it catches a misunderstanding on *our* side of that interface. `/proc` is
the same kernel rendering the same structures through a different `printf`, so
a kernel-side misunderstanding, or a wrong idea about what a field means,
would sail through both. What it can do that `ss` cannot is disagree about
*encoding*: `/proc` writes the port as big-endian hex text and the address as
little-endian hex text, so agreeing with it about a port number is a byte-order
check that shares no code and no convention with `sock_diag`'s `__be16`. It is
used one-directionally -- every socket `/proc` lists must be one sockv lists --
for the reason in the section above.

**And the other half: bytes no kernel would send.** The kernel's reply is a
stream of self-describing records and every length in it comes off the wire; a
walker that trusts `nlmsg_len` reads past the end of its buffer. `--parse
PROTO FILE` exposes the same `walk()` the live path uses to a file, and
`t/probe emit` builds the files: seventeen cases where a record or an
attribute lies about its length (or where the reply is an error rather than a
listing), and sixteen well-formed ones for the rendering rules no socket on
this machine happens to have.

## `make test`

```
sockv vs ss utility, iproute2-6.15.0 on 7.2.8-200.fc44.x86_64

ok    tcp+udp, all states: ss agrees both ways (69 sockets)
ok    tcp+udp, all states: compared 69 sockets (>= 4)
ok    tcp+udp, listening: ss agrees both ways (18 sockets)
ok    tcp+udp, listening: compared 18 sockets (>= 1)
ok    unix, all states: ss agrees both ways (1528 sockets)
ok    unix, all states: compared 1528 sockets (>= 4)
ok    unix, listening: ss agrees both ways (165 sockets)
ok    unix, listening: compared 165 sockets (>= 1)
ok    tcp+udp+unix together: ss agrees both ways (1597 sockets)
ok    tcp+udp+unix together: compared 1597 sockets (>= 8)
ok    -t -u -x partition the default listing (1597 rows)
ok    each family flag yields only its own netids
skip  unix uid against ss  (ss -e does not report uid for unix sockets)
ok    no duplicate rows
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
ok    buffer shorter than an nlmsghdr
ok    nlmsg_len below the header size
ok    nlmsg_len of zero
ok    nlmsg_len past the end of the buffer
ok    nlmsg_len of 0xffffffff does not wrap
ok    truncated final record
ok    payload too small for inet_diag_msg
ok    nla_len below the attribute header
ok    nla_len past the end of its message
ok    attribute area ends mid-header
ok    u8 attribute with no payload
ok    unix name longer than sun_path
ok    address family we never asked for
ok    nlmsg_type we never asked for
ok    NLMSG_ERROR is reported with its errno
ok    NLMSG_ERROR with no room for an errno
ok    NLM_F_DUMP_INTR is not a listing
ok    --parse with an unknown protocol
ok    --parse with a missing file
ok    --parse with no arguments
ok    --parse of an empty file
ok    /proc/net/{tcp,tcp6,udp,udp6} inode+uid+port (69 rows)
ok    /proc/net/{tcp,tcp6,udp,udp6} inode+uid+port: compared 69 rows (>= 4)
ok    /proc/net/unix inode+name (1528 rows)
ok    /proc/net/unix inode+name: compared 1528 rows (>= 4)
ok    the probe brought its sockets up (ports 49848..49852)
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
ok    created: unix-path-listen
ok    created: unix-pair-server
ok    created: unix-pair-client
ok    created: unix-abstract-listen
ok    created: unix-dgram
ok    created: unix-seqpacket
ok    created: unix-socketpair-a
ok    created: unix-socketpair-b
ok    unix name containing spaces appears verbatim
ok    bound-only TCP socket is absent from /proc/net/tcp
ok    ss sees all 19 sockets the probe created
ok    unknown option
ok    stray argument
ok    --help exits 0
ok    listing exits 0

82 passed, 0 failed, 1 skipped
```

Exit status is part of the interface, because the suite asserts on it: `0`
listed, `1` a syscall failed or the kernel returned an error reply, `2` a
netlink reply was malformed and sockv refused to walk it, `3` the command line
was wrong. `86` is reserved for the sanitizers -- see below.

If `sock_diag` is unreachable, or `ss` is not installed, or `/proc/net` is not
readable, the affected assertions are reported as **skipped**, with the kernel
version and the reason. A skip is never dressed up as a pass.

## Have I watched this harness fail?

`make mutants` plants 26 defects in `sockv.c` with `sed`, builds each one, runs
the whole suite against the broken binary, and asserts the verdict. Two
mutants are expected to *survive*, and asserting that is the point: a
survivor that starts being caught fails the script too, because at that moment
this README is the thing that has become wrong.

```
ok     (no defect planted)                    82 passed, 0 failed, 1 skipped

ok     port printed without ntohs             caught by 27 assertion(s)
ok     AF_INET address read as 16 bytes       caught by 17 assertion(s)
ok     INET_DIAG_SKV6ONLY ignored             caught by 6 assertion(s)
ok     ifindex scope suffix dropped           caught by 5 assertion(s)
ok     uid hardcoded to zero                  caught by 22 assertion(s)
ok     local and peer endpoints swapped       caught by 18 assertion(s)
ok     abstract name loses its @              caught by 8 assertion(s)
ok     u_dgr relabelled u_str                 caught by 5 assertion(s)
ok     UNIX_DIAG_PEER ignored                 caught by 7 assertion(s)
ok     every unix socket reads as unnamed     caught by 15 assertion(s)
ok     -l uses TCP_LISTEN for UDP             caught by 1 assertion(s)
ok     -l treats u_dgr like u_str             caught by 1 assertion(s)
ok     only the first record is read          caught by 25 assertion(s)
ok     advance by nlmsg_len, not aligned      caught by 1 assertion(s)
ok     nlmsg_len lower bound deleted          caught by 2 assertion(s)
ok     nlmsg_len upper bound deleted          caught by 2 assertion(s)
ok     short-buffer check deleted             caught by 2 assertion(s)
ok     nla_len lower bound deleted            caught by 1 assertion(s)
ok     nla_len upper bound deleted            caught by 1 assertion(s)
ok     payload size check deleted             caught by 1 assertion(s)
ok     unix name length check deleted         caught by 1 assertion(s)
ok     u8 attribute length check deleted      caught by 1 assertion(s)
ok     NLM_F_DUMP_INTR ignored                caught by 1 assertion(s)
ok     attribute end-of-buffer loosened by 4  caught by 1 assertion(s)
ok     record end-of-buffer loosened by 4     survived, as documented
ok     MSG_TRUNC check deleted                survived, as documented

AddressSanitizer, both netlink bounds deleted:
ok     overread is reported                   heap-buffer-overflow, exit 86
```

The counts move a little from run to run, because most of them include the
live differentials and the machine's socket table is not the same twice. What
does not move is the shape, and the shape is the diagnosis rather than an
alarm: the IPv4-only defect fails seventeen assertions of which **not one is
an IPv6 assertion**, a deleted bounds check fails one or two by name, and a
dropped record fails twenty-five.

### The two that survive

- **`record end-of-buffer loosened by 4`** is provably equivalent, not a gap.
  The test fires after the record has already been processed, so the mutant
  only declines to look for a *further* record in fewer than four remaining
  bytes, and an `nlmsghdr` is sixteen. The identical change to the *attribute*
  walker is a real defect and is caught, because an attribute can be exactly
  four bytes long -- which is why the two call sites are separate mutants.
  An earlier version of this file changed both at once and called the result
  equivalent. It was wrong, and `make mutants` is what said so.
- **`MSG_TRUNC check deleted`** cannot be reached on this machine. The receive
  buffer is 256KB and the kernel caps a dump datagram well below that, so
  nothing here can produce a truncated datagram to notice. Only a network
  namespace with tens of thousands of sockets, or a deliberately smaller
  buffer, would exercise it.

### Three defects found, and two of them were in the harness

- **The handler was reading the attribute area out of its own stack frame.**
  `walk()` copied each `nlmsghdr` into a local and passed `&local` to the
  handler, so `NLMSG_DATA()` of it pointed at whatever followed that copy in
  the frame. Every message was refused with "nla_len 1 is below the 4-byte
  attribute header" -- the bounds check doing its job on the program's own
  bug. Handlers now take the record where it lies in the receive buffer.
- **`-l` dropped every datagram socket.** `sockv -xl` listed 105 sockets where
  `ss -xl` listed 165, and the 60 missing ones were every `u_dgr` socket on
  the machine. "Listening" is `TCP_LISTEN` for a stream socket and `TCP_CLOSE`
  for a datagram one, because UDP and UNIX datagrams have no state machine of
  their own; `unix_diag` takes one state mask for a dump that contains both,
  so the request asks for both states and the display drops the combinations
  that are not listening. Found by the differential on its first run against
  UNIX sockets.
- **`make test-asan` could not fail.** With both netlink bounds deleted, the
  sanitised build read past the end of the reply and AddressSanitizer said
  nothing: `--parse` was reading its fixtures into a fixed one-megabyte
  buffer, so a short overread landed on uninitialised bytes that were *still
  inside the allocation*. The buffer is now exactly the size of the file, and
  the comment in `sockv.c` says that this is a property of the oracle rather
  than a micro-optimisation.

  Worse, the exit code collided: a sanitizer abort exits `1` by default and
  this suite asserts `1` for "the kernel returned an error", so an overread
  would have scored as a clean diagnostic. `ASAN_OPTIONS=exitcode=86` and
  `UBSAN_OPTIONS=halt_on_error=1:exitcode=86` fix that -- the same problem
  `inflate` records in its own Makefile -- and belt-and-braces, the suite's
  two assertion helpers now fail outright on seeing the word `Sanitizer` in a
  program's output.

## What does not work

Plainly, and this list is the part worth reading before trusting any of the
above.

### Protocols not implemented

- **Only TCP, UDP and UNIX domain.** `sock_diag` also serves SCTP, DCCP, raw
  sockets, `AF_PACKET`, netlink sockets themselves (`netlink_diag`), `AF_VSOCK`,
  `AF_XDP`, MPTCP and TCP metrics. None of those is implemented, and `ss`
  shows all of them. `ss -s` reports a summary across every family; sockv has
  no equivalent and would under-count.
- **No `AF_UNSPEC` dump.** Each family and protocol is a separate request.
  That is four netlink round trips for `-tu` and five for `-tux`.

### Fields not implemented

- **No process names or PIDs.** `ss -p` works by scanning every `/proc/*/fd`
  for a socket inode, which is not a netlink feature at all, and which an
  unprivileged process cannot do for sockets owned by other users. sockv does
  not attempt it; the uid column is what it offers instead. This is a
  deliberate non-goal rather than a privilege skip, because the information is
  not in the interface this program reads.
- **No queue lengths, timers, retransmits, congestion control, memory
  accounting or TCP info.** `inet_diag_msg` carries `idiag_rqueue`,
  `idiag_wqueue`, `idiag_timer`, `idiag_retrans` and `idiag_expires`, and
  `idiag_ext` can request `INET_DIAG_INFO`, `INET_DIAG_MEMINFO`,
  `INET_DIAG_CONG` and more. sockv requests `idiag_ext = 0` and prints none of
  it. The two Recv-Q/Send-Q columns `ss` prints are therefore not compared by
  the differential either.
- **No `INET_DIAG_MARK`**, which needs `CAP_NET_ADMIN`. Not implemented, so
  nothing is skipped for want of privileges here.
- **UNIX uid is not corroborated by `ss`.** `ss -e` reports no uid for UNIX
  sockets, so the UNIX differentials compare five fields where the inet ones
  compare six, and the suite prints that as an explicit `skip` line rather
  than quietly comparing less. The UNIX uid column is checked against the
  nineteen sockets the probe creates, where the expected value is known.
- **No `UNIX_DIAG_VFS`, `ICONS`, `RQLEN` or `SHUTDOWN`.** `ss -e` prints the
  socket file's `ino:`/`dev:` for a path-bound UNIX socket, and the pending
  connection queue for a listener. Not implemented.

### Filtering

- **Only state filtering, and only `-l` or all.** `inet_diag` accepts an
  `INET_DIAG_REQ_BYTECODE` attribute that filters on address, port, interface,
  cgroup and mark **inside the kernel** -- which is how `ss 'dport = :443'`
  avoids transferring sockets the caller will discard. sockv transfers
  everything and has no address or port filter at all. This is the single
  largest unimplemented capability of the interface.
- **No equivalent of `ss`'s default state filter.** `ss -tn` with no `-a`
  applies a state mask that is not documented anywhere and that this project
  declined to reverse-engineer, because reproducing it would be mimicry of
  something undocumented with no oracle value, and getting it subtly wrong
  would poison every comparison made through it. sockv is all-states unless
  `-l`. So `sockv -t` is comparable to `ss -tan`, never to `ss -tn`.
- **`-l` means a different state per protocol** and that is intentional, not a
  wart: `TCP_LISTEN` for TCP, stream and seqpacket, `TCP_CLOSE` for UDP and
  UNIX datagram. It matches `ss` and the differential holds it there, but it
  will surprise anyone who expects one state mask.

### Output

- **Not quoted, and not safely parseable in general.** A socket name
  containing whitespace shifts every field after it. Any unprivileged process
  can bind an abstract UNIX socket whose name contains a space or a newline,
  and then a row of sockv's output can be forged. `ss` has exactly the same
  property and sockv matches it deliberately, because the whole oracle is a
  byte-for-byte comparison and an escaping scheme on one side would end it.
  **Do not parse this output when a hostile local process can create sockets.**
  The suite creates such a name, checks that it reaches the output verbatim
  and bounded, and reports rows it cannot split into fields as a loud skip
  rather than dropping them.
- **An abstract name containing a NUL is truncated at it.** Abstract names are
  arbitrary byte strings and may legally contain NULs. `ss` renders the
  leading NUL as `@` and stops at the next one; sockv does the same.
- **No header line**, by design, so the output pipes into `grep` and `awk`
  without a filter. The column widths are fixed and a long UNIX path pushes
  the inode and uid columns rightwards, which is cosmetic -- every consumer
  here splits on whitespace.
- **Two of `ss`'s rendering quirks are reproduced rather than corrected.** An
  all-zero IPv6 address prints as `*` and not `[::]`, but only when the socket
  is not `IPV6_V6ONLY`; and a nonzero `idiag_if` appends `%ifname` to the local
  end and never to the peer end. Both are what `ss` does, byte-identical
  output is what makes the differential a comparison instead of an
  interpretation, and the fixtures pin both.
- **A TIME-WAIT socket reports inode 0 and uid 0.** That is what the kernel
  puts in `inet_diag_msg` for a timewait entry -- there is no owning socket
  left to ask -- and `ss` reports the same, so the differential agrees. It is
  still a row whose last two columns mean "unknown" rather than "root".

### Inherently racy

- **The listing is a snapshot of something moving.** Sockets appear and vanish
  while the dump is being produced. `NLM_F_DUMP_INTR` is handled -- the kernel
  sets it when its iterator was disturbed, the dump is restarted up to eight
  times, and after that sockv fails loudly rather than printing a listing the
  kernel has already said is inconsistent -- but a socket created after the
  dump began is simply not in it, and that is not fixable. The test suite
  deals with the same race by sandwiching and could not exist otherwise.
- **A long dump can be interrupted forever** on a machine churning sockets
  faster than the kernel can walk them. Eight attempts and then exit 1.

### Buffers and limits

- **The receive buffer is a fixed 256KB static array** and a datagram that
  does not fit is reported as a failure rather than grown into. `MSG_TRUNC`
  makes `recvmsg` report the real size, so this fails loudly instead of
  silently dropping sockets -- but see the mutation list: it is the one check
  the suite cannot exercise on this machine, because no dump here comes close.
  Marked `shortcut:` in the source; the upgrade is a realloc loop driven by
  the returned length.
- **AddressSanitizer cannot see an overread on the live path.** That static
  buffer is always larger than the data in it, so a read past the end of a
  reply stays inside the object. Only the `--parse` path has an allocation
  that ends where the data ends, which is why every hostile fixture goes
  through `--parse`.
- **`SO_RCVBUF` is set best-effort and not checked.** On a machine with enough
  sockets the kernel can still run out of space mid-dump; `recvmsg` returns
  `ENOBUFS` and sockv exits 1 naming it.
- **`nlmsg_seq` is not matched.** Safe only because one request is outstanding
  at a time on a socket nobody else holds, and marked `shortcut:` where that
  assumption lives. The datagram's source port *is* checked, so a reply from
  anything other than the kernel is ignored.

### Environment

- **Requires `sock_diag`.** `CONFIG_INET_DIAG`, `CONFIG_UNIX_DIAG` and the
  matching modules. There is no `/proc` fallback, deliberately: a fallback
  would mean sometimes returning the lossy answer without the caller knowing
  which. `socket(AF_NETLINK, ..., NETLINK_SOCK_DIAG)` failing is exit 1 with
  the errno, and the suite skips every assertion loudly.
- **Behaviour on a kernel without IPv6 is untested.** The `AF_INET6` request
  would presumably return no sockets, since the diag handler is registered per
  protocol rather than per family, but if it returns an error reply instead
  then `sockv -t` fails rather than listing the IPv4 sockets. Nothing here can
  test that without rebuilding the kernel, so it is an unverified claim and is
  listed as one.
- **One network namespace, the caller's.** `ss -N` can enter another; sockv
  cannot.
- **No `SOCK_DESTROY`.** `sock_diag` can also kill a socket. Out of scope: this
  program reads.

## Design

One file, `sockv.c`, 866 lines, about a quarter of them comments explaining why
the kernel or `ss` insists on something.

```
parse args  ->  socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG)
            ->  per family and protocol:
                  sendmsg  inet_diag_req_v2 | unix_diag_req, NLM_F_DUMP
                  recvmsg  -> walk() the records -> show_inet | show_unix
                  NLM_F_DUMP_INTR -> start that dump again
```

Four decisions worth naming.

**The record walker is the whole security surface.** Every bound is checked
against the number of bytes `recvmsg` actually delivered, never against
anything a record claims about itself, and there are two independent layers:
the record walker bounds `nlmsg_len` and the attribute walker bounds
`nla_len`. Deleting either one alone does not produce an overread, because the
other catches the inconsistency first; it takes removing both, which is
exactly what the sanitizer check in `make mutants` does.

**`walk()` is shared between the live path and `--parse`.** Not a test hook
bolted on: `--parse` selects the same handler by protocol and calls the same
function. A bounds check the fixtures prove is the bounds check the kernel
meets.

**Output is `ss`'s, down to its quirks.** State names are `ss`'s rather than
the kernel's enum names -- `TCP_CLOSE` prints as `UNCONN` -- and addresses are
formatted the way `ss` formats them. The alternative is a translation table in
the test harness, which is a place for a disagreement to hide.

**An unknown attribute type is ignored; an unknown length is refused.** The
kernel grows the attribute enum every few releases and sends some of it unasked
-- `INET_DIAG_CGROUP_ID` and `INET_DIAG_SOCKOPT` arrive on this kernel without
being requested -- so refusing an unrecognised type would break the program on
any kernel newer than the one it was built against. A length that does not fit
is a different thing entirely and is always refused.

## License

GPL-3.0. See `LICENSE`.

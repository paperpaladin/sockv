# PLAN

## Contract

`sockv [-tux] [-l | -a]`, and `sockv --parse PROTO FILE`.

List the kernel's TCP, UDP and UNIX domain sockets by asking the kernel over
`NETLINK_SOCK_DIAG`, with `inet_diag_req_v2` for TCP and UDP and
`unix_diag_req` for UNIX, driven with `sendmsg(2)` and `recvmsg(2)` on an
`AF_NETLINK` socket. Not by reading `/proc/net/*`, which is lossy: a TCP
socket that is bound and neither listening nor connected does not appear
there at all.

One row per socket on stdout, no header, whitespace separated:

```
FAMILY NETID STATE LOCAL PEER INODE UID
```

`FAMILY` is `inet`, `inet6` or `unix`. `NETID` is `tcp`, `udp`, `u_str`,
`u_dgr` or `u_seq`. `STATE`, `LOCAL` and `PEER` are rendered exactly as
`ss -n` renders them, including `ss`'s two quirks: an all-zero IPv6 address
prints as `*` rather than `[::]` when the socket is not `IPV6_V6ONLY`, and a
nonzero `idiag_if` appends `%ifname` to the local end only. For a UNIX socket
`LOCAL` is `name:inode` and `PEER` is `*:peer-inode`, matching the two columns
`ss -x` prints.

`-t`, `-u` and `-x` select families and combine; with none given, all three
are listed. `-l` is listening only, which means `TCP_LISTEN` for TCP, stream
and seqpacket sockets and `TCP_CLOSE` for UDP and UNIX datagram sockets,
because those have no state machine of their own. `-a` is every state and is
the default. There is deliberately no equivalent of `ss`'s undocumented
default state filter.

Exit status is part of the interface because the suite asserts on it: `0`
listed, `1` a syscall failed or the kernel returned an error reply, `2` a
netlink reply was malformed and was refused, `3` the command line was wrong.
`86` is reserved for the sanitizers, which otherwise exit `1` and would be
indistinguishable from a kernel error.

`--parse PROTO FILE` runs the same record walker over bytes from a file, so
the walker can be fed input no kernel would send. It is part of the contract
rather than a test hook: the live path and `--parse` share `walk()` and the
handlers, and a bounds check the fixtures prove is the bounds check the kernel
meets.

## Hard invariant

**Every socket the kernel reports is listed exactly once with every field as
the kernel gave it, and a reply that lies about its own lengths is refused
rather than read out of bounds.**

Three halves, and all three are checked by something outside this program:

1. **Completeness and fidelity.** `ss` reads the same netlink interface from
   the same kernel; every socket it reports across the whole of sockv's run
   must be in sockv's output, with the same netid, state, local endpoint, peer
   endpoint, inode and uid. Byte for byte, not normalised.
2. **Exactly once.** Comparing sets cannot see a duplicate, and a mishandled
   `NLM_F_DUMP_INTR` produces exactly that, so the raw output is checked for
   repeated rows separately. An interrupted dump is restarted rather than
   printed.
3. **Refusal, not overread.** Every length in a netlink reply is wire data.
   `nlmsg_len` below the header size, zero, past the end of the buffer, or
   `0xffffffff`; `nla_len` below its header or past the end of its message; a
   payload too small for the struct it claims to be. All refused with exit 2
   and a diagnostic naming the field, and the same suite passes under
   `-fsanitize=address,undefined`.

If any of those three fails, the program is worthless: a socket enumerator
that silently drops sockets is worse than no enumerator, and a netlink parser
that reads out of bounds is a vulnerability in anything that uses it.

## Oracle

Ranked by how little of each is ours.

1. **`ss` from iproute2, in both directions.** A program written by other
   people, reading the same netlink interface from the same kernel. Five
   differentials -- `-tu`, `-tul`, `-x`, `-xl`, `-tux` against `ss -tuanHe`,
   `-tulnHe`, `-xanHe`, `-xlnHe`, `-tuxanHe` -- comparing netid, state, both
   endpoints, inode and uid. Both directions, because a comparison that only
   checks that every socket sockv reports was also reported by `ss` passes for
   a program that reports nothing. Each differential also emits a separate
   named assertion about the number of sockets it compared, because two empty
   sets compare equal. Racing is handled by sandwiching: `ss`, then sockv,
   then `ss` again, with the stable intersection required to be present and
   the union required to contain everything sockv printed, retried four times
   so churn moves and a defect does not.

   `ss -e` reports no uid for UNIX sockets, so the UNIX differentials compare
   five fields and the suite prints a `skip` line saying so.

2. **Sockets the suite creates.** `t/probe hold` binds and connects nineteen
   sockets whose family, type, state and address it chose, takes each inode
   from `fstat(2)` on its own descriptor -- the same number the kernel reports
   as `idiag_inode` -- and prints the exact row sockv must produce. Addresses
   are printed from the numbers passed to `bind(2)` rather than by rendering a
   `sockaddr` back out, so the probe cannot share a formatting mistake with
   sockv. This is less independent than `ss`, since the expectations are ours,
   but it is the only oracle that can name the socket and the field when
   something is wrong, and the only one that covers shapes the machine does
   not happen to have. A further assertion requires `ss` to report all
   nineteen inodes, because the differential's socket counts only mean
   something if the sockets with known identities are inside the population
   being compared.

3. **Bytes no kernel would send.** `t/probe emit` builds seventeen replies
   that lie about their own lengths and sixteen that are well formed, and
   `--parse` walks them. Less independent again -- both the input and the
   expectation are ours -- but it is the only way to reach the bounds checks
   at all, since the kernel never produces a malformed reply, and the only way
   to reach the rendering rules no local socket exercises: a v4-mapped address
   on an `AF_INET6` socket, a scoped IPv6 address, an abstract name with no
   NUL terminator, an unaligned `nlmsg_len`, an attribute type newer than this
   build knows.

4. **`/proc/net/{tcp,tcp6,udp,udp6,unix}`.** Weakest, and here is why: `ss` is
   a different program reading the same interface, so it catches a
   misunderstanding on *our* side of that interface. `/proc` is the same
   kernel rendering the same structures through a different `printf`. A
   kernel-side misunderstanding -- or a wrong idea about what a field means,
   which is the same thing from outside -- would sail through both, so an
   agreement here is much weaker evidence than it looks. What it can do that
   `ss` cannot is disagree about *encoding*: `/proc` writes the port as
   big-endian hex text and the address as little-endian hex text, so agreeing
   with it about a port number is a byte-order check sharing no code and no
   convention with `sock_diag`'s `__be16`. Used one-directionally only,
   because it is provably lossy -- the bound-only TCP socket the probe creates
   is reported by sockv and absent from `/proc/net/tcp`, and that asymmetry is
   a passing assertion whose expectation is that something is missing.

5. **`make mutants`.** Not an oracle for the program but for the suite: 26
   planted defects, each built and run through the whole suite, with the
   verdict asserted -- including for the two documented survivors, so a
   ceiling that disappears fails the script instead of becoming folklore. It
   has already earned its place twice, by showing that a mutant called
   provably equivalent was not, and by exposing the `--parse` fixture buffer
   that made `make test-asan` unable to fail.

## Non-goals

- **A second rendering path.** No `/proc` fallback. A fallback would mean
  sometimes returning the lossy answer without the caller knowing which.
- **Process names and PIDs.** `ss -p` scans every `/proc/*/fd` for a socket
  inode. That is not a netlink feature, it cannot be done unprivileged for
  other users' sockets, and bolting it on would turn a netlink client into a
  `/proc` crawler. The uid column is what is offered instead.
- **Being `ss`.** No `-s` summary, no `-i` TCP info, no `-m` memory, no `-o`
  timers, no `-r` name resolution, no `-N` namespace entry, no interactive
  filter expression language.
- **Writing.** `sock_diag` can also destroy a socket. This program reads.
- **Root.** Everything here runs unprivileged, like `jail`. Anything needing
  privilege is skipped loudly and listed in the README.
- **Portability beyond Linux**, or beyond a kernel with `CONFIG_INET_DIAG` and
  `CONFIG_UNIX_DIAG`.
- **Escaping the output.** A socket name containing whitespace forges a row.
  `ss` has the same property, and matching it byte for byte is what makes the
  differential a comparison instead of an interpretation. Documented, not
  fixed.
- **A library.** One program, one job.

## Commit sequence

Eleven commits so far, every one of which builds, and every one from the
second onwards committed through `cq c` so the suite ran against the working
tree first.

- [x] `Makefile`, `LICENSE`, `.gitignore`, and `sockv.c` with the netlink
      transport, the bounds-checked record walker, and TCP and UDP over
      `inet_diag` for both address families.
      why: the walker is the whole hostile surface and the endpoint renderer
      is where address-family handling lives, and both decide the shape of
      everything after them. Retrofitting either around a working `/proc`
      parser would mean rewriting the program. Found the first bug before any
      test existed: the handler was reading the attribute area out of
      `walk()`'s own stack frame.
- [x] `t/run.sh`: the `ss` differential, both directions, with the
      compared-count assertion that stops an empty comparison from passing.
      why: the oracle is the project. Landing it second means every commit
      after it is gated by an external authority rather than by review, and
      the nine-mutation table in its message is the evidence that the
      comparison has teeth rather than a hope that it does.
- [x] `-x` and `unix_diag`.
      why: a different request struct and a different reply struct, not a
      family parameter to the same one. The differential caught `-l` dropping
      every `u_dgr` socket on its first run, which is the whole argument for
      writing the harness before the feature it judges.
- [x] `--parse` and `t/probe emit`: the record walker driven with bytes no
      kernel would send.
      why: the live machine is a weak source of hostile input, since every
      reply it produces is well formed by construction. This is the only way
      to reach a bounds check, and it killed the one mutant that had survived
      the previous commit.
- [x] `t/probe hold`: sockets the suite creates, with the exact row each must
      produce.
      why: the differential can only ever say "these sets differ". Naming the
      socket and the field turns a mutation report from an alarm into a
      diagnosis, and the inode from `fstat(2)` is an oracle that knows the
      answer before sockv is asked.
- [x] The `/proc/net/*` cross-check, and the bound-only-socket asymmetry.
      why: ranked last among the oracles and worth having anyway, because it
      disagrees about encoding where `ss` agrees about everything. The
      asymmetry assertion turns the README's reason for not reading `/proc`
      into a test that fails if the kernel ever changes.
- [x] `make test-asan`, with `exitcode=86`.
      why: a netlink reply is untrusted input. Found that `--parse`'s
      one-megabyte fixture buffer left an overread inside the allocation,
      where AddressSanitizer could not see it -- the target had no ability to
      detect the defect class it exists for.
- [x] `t/mutants.sh` and `make mutants`.
      why: a mutation table in a commit message is a table nobody runs again.
      It immediately showed that a survivor documented as provably equivalent
      was a real defect in one of the two call sites the `sed` was hitting.
- [x] Fixtures for the three branches nothing here can reach: a scoped IPv6
      address, an out-of-range state, an out-of-range UNIX socket type.
      why: the bracket-then-scope-then-port order had been worked out by hand
      once and then held in place by nothing, and the two placeholder
      branches were the only untested code left in the renderer.
- [x] `README.md`.
      why: the "what does not work" list is longer than everything else in it,
      and that list is the part someone needs before trusting the output.
- [x] `PLAN.md`.
      why: the contract, the ranked oracle and the forward order belong in a
      different document from the transcript, and someone reverting one rarely
      wants to revert the other.

### Milestone 1 -- close the gaps the interface already offers

- [ ] `INET_DIAG_REQ_BYTECODE`: a `--port`, `--addr` and `--dev` filter
      evaluated inside the kernel.
      why: the single largest unimplemented capability of `inet_diag`, and the
      one place sockv is structurally worse than `ss` rather than merely
      smaller. Today every socket crosses the netlink socket so that userspace
      can throw most of them away; on a machine with 1500 sockets that is most
      of the cost of the program. It also comes with the strongest possible
      oracle: the same filter applied in userspace must select the same set,
      and `ss 'sport = :443'` must agree with both.
- [ ] `idiag_ext` and the queue, timer and retransmit columns, so `ss -o` and
      the Recv-Q/Send-Q pair become comparable.
      why: two columns of `ss`'s default output are currently not compared by
      the differential at all, which is a hole in an oracle that otherwise
      compares every field. Queue lengths are already in `inet_diag_msg` and
      cost nothing to print.
- [ ] `netlink_diag`, so `sockv -N` lists netlink sockets.
      why: the one remaining family that needs no new concepts -- a third
      request struct alongside the two already here -- and the one `ss -f
      netlink` shows that nothing else can. It is also the family whose
      sockets this program is itself using, which makes a self-check possible:
      sockv's own netlink socket must appear in its own output.
- [ ] Grow the receive buffer on `MSG_TRUNC` instead of failing.
      why: the `shortcut:` note in `sockv.c` names this, and `make mutants`
      lists deleting the check as a surviving mutant because nothing on this
      machine can produce a datagram that large. A realloc loop driven by the
      length `recvmsg` already returns removes the limit and the untestable
      branch together.
- [ ] `SOCK_DIAG_BY_FAMILY` with `NLM_F_REQUEST` only, to look up one socket
      by inode rather than dumping.
      why: `inet_diag` supports a single-socket query, and it is the right
      primitive for "what is inode 44078", which is the question anyone
      holding a `/proc/*/fd` entry actually has. Also the cheapest way to
      write a test that watches one socket change state.

### Milestone 2 -- the oracles the current suite cannot reach

- [ ] Run the whole suite inside a fresh network namespace created with
      `unshare -rn`, with a known and empty socket table.
      why: every differential here is sandwiched because the machine's socket
      table moves. In a private namespace it does not, so the comparison
      becomes exact rather than retried, and the compared-count floor can be
      an exact number instead of a minimum. It is also the only way to test
      the empty case honestly -- today "sockv prints nothing and `ss` prints
      nothing" is indistinguishable from a broken program, which is why the
      count assertions exist.
- [ ] Ten thousand UNIX sockets in that namespace, to force a dump larger than
      the receive buffer.
      why: closes the `MSG_TRUNC` mutant, which is the only surviving mutant
      that represents a real untested branch rather than a provable
      equivalence.
- [ ] Drive `NLM_F_DUMP_INTR` deliberately by churning sockets in a loop while
      dumping, and assert that the restart happens and that no duplicate row
      is ever printed.
      why: the retry logic is asserted only through a `--parse` fixture with
      the flag set by hand. Nothing has made the kernel set it, so the one
      thing the invariant's second half depends on has never actually
      happened.
- [ ] Compare against `ss` on two or three other kernels, oldest first.
      why: `INET_DIAG_SKV6ONLY` arriving unrequested, `UNIX_DIAG_UID` existing
      at all, and `/proc/net/tcp` omitting bind-hash sockets are all facts
      about this kernel that the README states as facts about Linux. Only
      another kernel can tell which of them are.
- [ ] A fuzzer over `--parse`, seeded with the well-formed fixtures, under
      ASan and UBSan.
      why: seventeen hand-written malformed cases cover the lengths that were
      thought of. The walker is small enough that a few million random
      mutations of a valid reply would be a stronger statement than any list,
      and `--parse` plus the tight fixture allocation already make it runnable
      without a harness.

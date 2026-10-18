/*
 * sockv - list the kernel's sockets by asking the kernel.
 *
 *   sockv -t      TCP        sockv -l   listening sockets only
 *   sockv -u      UDP        sockv -a   every state (the default)
 *   sockv -x      UNIX domain
 *
 * Over NETLINK_SOCK_DIAG, with inet_diag_req_v2 for TCP and UDP and
 * unix_diag_req for UNIX domain sockets, talking to
 * the kernel with sendmsg(2) and recvmsg(2). Not by parsing /proc/net/tcp:
 * that path is a second rendering of the same data, it is lossy (a bound but
 * unconnected TCP socket does not appear in it at all), it is quadratic in the
 * number of sockets, and it cannot be filtered kernel-side.
 *
 * Copyright (C) 2026  PLACEHOLDER.  Licensed under the GPLv3 (see LICENSE).
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
/* For the TCP state enum, which the kernel's own uapi headers do not export
 * and glibc does. The numbers are kernel ABI either way. */
#include <netinet/tcp.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/unix_diag.h>

/*
 * Exit status is part of the interface, because the test harness asserts on
 * it and "rejected these bytes" must never be confusable with anything else:
 *
 *   0   listed what was asked for
 *   1   a system call failed, or the kernel returned an error reply
 *   2   a netlink reply was malformed and we refused to walk it
 *   3   the command line was wrong
 *   86  reserved for -fsanitize, which otherwise exits 1 (see the Makefile)
 */
#define EX_OK     0
#define EX_FAIL   1
#define EX_BAD    2
#define EX_USAGE  3

static const char *prog = "sockv";

/*
 * Refusing malformed bytes is a first-class outcome rather than an error
 * path, so it gets one funnel. The message names the field that was wrong
 * because the harness asserts on which check fired: a test that only sees
 * "exit 2" cannot tell a bounds check from a typo in the parser.
 */
static int refuse(const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "%s: malformed netlink: ", prog);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	return -1;
}

static int fail(const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "%s: ", prog);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	return -2;
}

/* ------------------------------------------------------------------ output */

/*
 * State names, and they are ss's names rather than the kernel's enum names,
 * on purpose: the whole oracle is a byte-for-byte comparison with ss, and a
 * translation table in the test harness is a place for a disagreement to hide.
 *
 * TCP_CLOSE prints as UNCONN, not CLOSE. That is not a typo -- it is what ss
 * prints, and it is the right word for the two cases it actually covers: a
 * UDP socket that is bound but not connected, and a TCP socket that is bound
 * but has neither listened nor connected.
 */
static const char *const STATE[] = {
	[TCP_ESTABLISHED] = "ESTAB",
	[TCP_SYN_SENT]    = "SYN-SENT",
	[TCP_SYN_RECV]    = "SYN-RECV",
	[TCP_FIN_WAIT1]   = "FIN-WAIT-1",
	[TCP_FIN_WAIT2]   = "FIN-WAIT-2",
	[TCP_TIME_WAIT]   = "TIME-WAIT",
	[TCP_CLOSE]       = "UNCONN",
	[TCP_CLOSE_WAIT]  = "CLOSE-WAIT",
	[TCP_LAST_ACK]    = "LAST-ACK",
	[TCP_LISTEN]      = "LISTEN",
	[TCP_CLOSING]     = "CLOSING",
};
#define NSTATE ((unsigned)(sizeof STATE / sizeof *STATE))

static const char *state_name(unsigned s)
{
	static char buf[16];

	/* A newer kernel may grow the enum. Printing a placeholder keeps the
	 * row (and lets the differential report the disagreement) where
	 * refusing would lose a socket we did see. */
	if (s < NSTATE && STATE[s]) return STATE[s];
	snprintf(buf, sizeof buf, "state-%u", s);
	return buf;
}

static void row(const char *fam, const char *netid, const char *state,
                const char *local, const char *peer,
                uint32_t inode, uint32_t uid)
{
	printf("%-5s %-5s %-10s %-28s %-28s %8u %6u\n",
	    fam, netid, state, local, peer, inode, uid);
}

/*
 * One endpoint, rendered exactly the way ss renders it, including both of
 * ss's quirks. Byte-identical output is what makes the differential test a
 * comparison rather than an interpretation, so the quirks are reproduced
 * rather than corrected:
 *
 *  - An all-zero IPv6 address prints as "*", not "[::]" -- but only when the
 *    socket is not IPV6_V6ONLY. The kernel sets sk_ipv6only on any bind to a
 *    specific address that is not v4-mapped, so in practice "[::]" is what a
 *    v6-only socket's empty peer looks like and "*" is what a dual-stack
 *    socket's looks like. ss reads this from INET_DIAG_SKV6ONLY; so do we.
 *  - A nonzero idiag_if appends "%ifname" between address and port. This
 *    machine has one for real: systemd-resolved's 127.0.0.53%lo:53.
 *
 * Port 0 prints as "*", which is how a listener's empty peer end reads.
 */
static void endpoint(char *out, size_t cap, unsigned family,
                     const uint32_t be_addr[4], uint16_t be_port,
                     uint32_t ifindex, int v6only)
{
	char host[INET6_ADDRSTRLEN + 2];
	char scope[IF_NAMESIZE + 16];
	char nm[IF_NAMESIZE];

	if (family == AF_INET) {
		struct in_addr a;

		/* Exactly four bytes. idiag_src is sixteen bytes wide for both
		 * families and reading all of it for an AF_INET socket is the
		 * classic bug in this kind of code. */
		memcpy(&a, &be_addr[0], 4);
		if (!inet_ntop(AF_INET, &a, host, sizeof host))
			snprintf(host, sizeof host, "?");
	} else {
		struct in6_addr a6;
		char t[INET6_ADDRSTRLEN];

		memcpy(&a6, be_addr, 16);
		if (!v6only && IN6_IS_ADDR_UNSPECIFIED(&a6)) {
			snprintf(host, sizeof host, "*");
		} else if (inet_ntop(AF_INET6, &a6, t, sizeof t)) {
			snprintf(host, sizeof host, "[%s]", t);
		} else {
			snprintf(host, sizeof host, "?");
		}
	}

	scope[0] = '\0';
	if (ifindex) {
		if (if_indextoname(ifindex, nm))
			snprintf(scope, sizeof scope, "%%%s", nm);
		else
			snprintf(scope, sizeof scope, "%%%u", ifindex);
	}

	if (be_port)
		snprintf(out, cap, "%s%s:%u", host, scope, ntohs(be_port));
	else
		snprintf(out, cap, "%s%s:*", host, scope);
}

/* -------------------------------------------------------- netlink attributes */

/*
 * Highest attribute type we keep. Anything above is ignored rather than
 * refused: the kernel grows this enum every few releases and sends some of it
 * unasked (INET_DIAG_CGROUP_ID and INET_DIAG_SOCKOPT arrive on this kernel
 * without being requested), so refusing an unknown type would break the
 * program on any kernel newer than the one it was built against.
 */
#define MAXATTR 32

struct attrs {
	const unsigned char *val[MAXATTR + 1];
	uint16_t len[MAXATTR + 1];
};

/*
 * Walk the attribute area of one message. nla_len is wire data: it is checked
 * against the bytes actually present, never trusted.
 */
static int parse_attrs(const unsigned char *p, size_t len, struct attrs *out)
{
	memset(out, 0, sizeof *out);

	while (len >= sizeof(struct nlattr)) {
		struct nlattr a;
		unsigned t;
		size_t step;

		memcpy(&a, p, sizeof a);
		if (a.nla_len < sizeof(struct nlattr))
			return refuse("nla_len %u is below the %zu-byte "
			    "attribute header", a.nla_len,
			    sizeof(struct nlattr));
		if (a.nla_len > len)
			return refuse("nla_len %u overruns the %zu bytes left "
			    "in this message", a.nla_len, len);

		t = a.nla_type & NLA_TYPE_MASK;
		if (t <= MAXATTR) {
			out->val[t] = p + sizeof(struct nlattr);
			out->len[t] = (uint16_t)(a.nla_len -
			    sizeof(struct nlattr));
		}

		/*
		 * The kernel does not pad the last attribute of a message, so
		 * the aligned step can run past the end. The attribute itself
		 * was in bounds; there is simply nothing after it.
		 */
		step = NLA_ALIGN(a.nla_len);
		if (step >= len) return 0;
		p += step;
		len -= step;
	}
	if (len)
		return refuse("%zu trailing byte%s after the last attribute, "
		    "too few for an attribute header", len,
		    len == 1 ? "" : "s");
	return 0;
}

/* Absent attribute leaves *v alone, so the caller's default stands. */
static int attr_u8(const struct attrs *at, unsigned t, uint8_t *v)
{
	if (!at->val[t]) return 0;
	if (at->len[t] < 1)
		return refuse("attribute %u carries %u bytes, needs 1", t,
		    at->len[t]);
	*v = at->val[t][0];
	return 0;
}

static int attr_u32(const struct attrs *at, unsigned t, uint32_t *v)
{
	if (!at->val[t]) return 0;
	if (at->len[t] < 4)
		return refuse("attribute %u carries %u bytes, needs 4", t,
		    at->len[t]);
	memcpy(v, at->val[t], 4);
	return 0;
}

/* ------------------------------------------------------------- the messages */

/*
 * Handlers take the record where it lies in the receive buffer, not a copy of
 * its header: NLMSG_DATA() of a stack copy of an nlmsghdr points at whatever
 * follows that copy on the stack, which is how the first version of this
 * program read the attribute area out of its own frame.
 */
static int show_inet(const unsigned char *rec, size_t reclen, const char *netid)
{
	const unsigned char *base = rec + NLMSG_HDRLEN;
	struct inet_diag_msg m;
	struct attrs at;
	size_t payload, off;
	uint8_t v6only = 0;
	char local[160], peer[160];
	const char *fam;

	payload = reclen - NLMSG_HDRLEN;
	off = NLMSG_ALIGN(sizeof m);
	if (payload < off)
		return refuse("SOCK_DIAG_BY_FAMILY message carries %zu payload "
		    "bytes, inet_diag_msg needs %zu", payload, off);
	memcpy(&m, base, sizeof m);

	if (parse_attrs(base + off, payload - off, &at) < 0) return -1;
	if (attr_u8(&at, INET_DIAG_SKV6ONLY, &v6only) < 0) return -1;

	if (m.idiag_family == AF_INET) fam = "inet";
	else if (m.idiag_family == AF_INET6) fam = "inet6";
	else return refuse("idiag_family %u is neither AF_INET (%d) nor "
	    "AF_INET6 (%d)", m.idiag_family, AF_INET, AF_INET6);

	endpoint(local, sizeof local, m.idiag_family, m.id.idiag_src,
	    m.id.idiag_sport, m.id.idiag_if, v6only);
	/* The peer end never carries the scope: ss prints 127.0.0.53%lo:53
	 * against a bare 0.0.0.0:*, and we match it. */
	endpoint(peer, sizeof peer, m.idiag_family, m.id.idiag_dst,
	    m.id.idiag_dport, 0, v6only);

	row(fam, netid, state_name(m.idiag_state), local, peer,
	    m.idiag_inode, m.idiag_uid);
	return 0;
}

/*
 * -l selects sockets in TCP_LISTEN or TCP_CLOSE, for every UNIX socket type.
 * That is what ss does: its -l filter is a state mask of LISTEN|CLOSE, and
 * unix_diag reports TCP_CLOSE for anything unconnected, which ss prints as
 * UNCONN.
 *
 * This was conditioned on the socket type -- TCP_LISTEN for stream and
 * seqpacket, TCP_CLOSE for datagram -- on the reasoning that -l means "can
 * still receive something new", which an unbound stream socket cannot. The
 * reasoning is defensible and ss does not share it, and ss is the oracle
 * here. A stream socket that is neither bound nor connected sits in
 * TCP_CLOSE, `ss -xl` lists it, and sockv dropped it: `ss` reported
 * `u_str UNCONN *:16080849` and sockv reported 172 rows against ss's 173.
 * Any process holding an unbound AF_UNIX stream socket reproduced it, which
 * is why the suite was failing on this machine rather than intermittently.
 *
 * The comment this replaces already recorded the same mistake in the other
 * direction: an earlier version used TCP_LISTEN alone and the differential
 * found the 60 u_dgr sockets it was dropping. The fix then was to special-case
 * datagram rather than to take ss's state mask, which left stream wrong.
 */
static int listen_only;

/*
 * A UNIX socket's identity is its inode, and ss reports it in the column it
 * calls "Port" -- so the local end reads `name:inode` and the peer end reads
 * `*:peer-inode`, which is the same address:port shape the inet rows use and
 * keeps one comparison for both. The address half of a peer is always "*"
 * because a UNIX socket's peer has no name of its own to report.
 */
static int show_unix(const unsigned char *rec, size_t reclen, const char *unused)
{
	const unsigned char *base = rec + NLMSG_HDRLEN;
	struct unix_diag_msg m;
	struct attrs at;
	size_t payload, off;
	uint32_t peer = 0, uid = 0;
	char name[160], local[192], peerbuf[32];
	const char *netid;

	(void)unused;
	payload = reclen - NLMSG_HDRLEN;
	off = NLMSG_ALIGN(sizeof m);
	if (payload < off)
		return refuse("SOCK_DIAG_BY_FAMILY message carries %zu payload "
		    "bytes, unix_diag_msg needs %zu", payload, off);
	memcpy(&m, base, sizeof m);

	if (m.udiag_family != AF_UNIX)
		return refuse("udiag_family %u is not AF_UNIX (%d)",
		    m.udiag_family, AF_UNIX);

	if (parse_attrs(base + off, payload - off, &at) < 0) return -1;
	if (attr_u32(&at, UNIX_DIAG_PEER, &peer) < 0) return -1;
	/* Absent UNIX_DIAG_UID leaves 0, which is indistinguishable from a
	 * root-owned socket. The kernel has sent it since 4.17 and we ask for
	 * it; a kernel that does not would read as uid 0 throughout. */
	if (attr_u32(&at, UNIX_DIAG_UID, &uid) < 0) return -1;

	if (listen_only &&
	    m.udiag_state != TCP_LISTEN && m.udiag_state != TCP_CLOSE)
		return 0;

	switch (m.udiag_type) {
	case SOCK_STREAM:    netid = "u_str"; break;
	case SOCK_DGRAM:     netid = "u_dgr"; break;
	case SOCK_SEQPACKET: netid = "u_seq"; break;
	/* AF_UNIX accepts no other type, so this is unreachable rather than
	 * tolerant -- but printing a placeholder keeps the socket in the
	 * listing and lets the differential report the surprise. */
	default:             netid = "u_?";   break;
	}

	name[0] = '\0';
	if (at.val[UNIX_DIAG_NAME]) {
		size_t n = at.len[UNIX_DIAG_NAME];

		if (n >= sizeof name)
			return refuse("UNIX_DIAG_NAME is %zu bytes; sun_path "
			    "holds at most %zu", n, sizeof name - 1);
		memcpy(name, at.val[UNIX_DIAG_NAME], n);
		name[n] = '\0';
		/*
		 * A filesystem name arrives with the kernel's trailing NUL
		 * included in the attribute. An abstract name begins with a
		 * NUL and has no terminator at all, so the length is the only
		 * bound there is. ss renders the leading NUL as "@" and stops
		 * at the next NUL, and we match it -- see the README on what
		 * that means for a name containing whitespace.
		 */
		if (n && name[0] == '\0') name[0] = '@';
	}
	if (!name[0]) snprintf(name, sizeof name, "*");

	snprintf(local, sizeof local, "%s:%u", name, m.udiag_ino);
	snprintf(peerbuf, sizeof peerbuf, "*:%u", peer);
	row("unix", netid, state_name(m.udiag_state), local, peerbuf,
	    m.udiag_ino, uid);
	return 0;
}

/* ------------------------------------------------------------- the walker */

/*
 * This is the whole hostile surface of the program. A netlink reply is a
 * stream of self-describing records, and every length in it comes off the
 * wire: a walker that trusts nlmsg_len reads past the end of its buffer, and
 * the case is not hypothetical, since --parse replays bytes from a file.
 *
 * Every bound is checked against `len`, the number of bytes recvmsg actually
 * delivered, and never against anything a record claims about itself.
 */
struct dump {
	int fd;
	uint32_t seq;
	int done;                     /* saw NLMSG_DONE */
	int intr;                     /* kernel flagged the dump inconsistent */
	unsigned long recs;           /* records this attempt received */
	const char *netid;            /* which handler the records belong to */
	int (*show)(const unsigned char *, size_t, const char *);
};

/*
 * How many socket records the kernel actually sent, across every dump of one
 * invocation. This is not a statistic: it is the only way to tell a filter
 * the kernel applied from a filter applied here after the fact. Both produce
 * the same listing, and only this number says which one happened, so
 * --records exists for the suite to assert on and is documented as part of
 * the interface for that reason. See METHOD.md: "assert that the new path
 * ran".
 */
static unsigned long records;
static int show_records;

static int walk(const unsigned char *buf, size_t len, struct dump *d)
{
	while (len) {
		struct nlmsghdr h;
		size_t step;

		if (len < sizeof h)
			return refuse("%zu trailing byte%s, too few for an "
			    "nlmsghdr (%zu bytes)", len, len == 1 ? "" : "s",
			    sizeof h);
		memcpy(&h, buf, sizeof h);

		/* A zero nlmsg_len is caught here too, which is why the loop
		 * cannot spin: every iteration advances by at least sizeof h. */
		if (h.nlmsg_len < sizeof h)
			return refuse("nlmsg_len %u is below the %zu-byte "
			    "nlmsghdr", h.nlmsg_len, sizeof h);
		if (h.nlmsg_len > len)
			return refuse("nlmsg_len %u overruns the %zu bytes "
			    "left in the reply", h.nlmsg_len, len);

		/*
		 * NLM_F_DUMP_INTR means the socket table changed under the
		 * kernel's iterator and this dump may be missing or repeating
		 * entries. Reporting it as a result would be reporting a
		 * listing we know to be wrong, so the caller restarts.
		 */
		if (h.nlmsg_flags & NLM_F_DUMP_INTR) {
			d->intr = 1;
			return 0;
		}

		switch (h.nlmsg_type) {
		case NLMSG_DONE:
			d->done = 1;
			return 0;
		case NLMSG_NOOP:
			break;
		case NLMSG_OVERRUN:
			return fail("netlink reported NLMSG_OVERRUN: the "
			    "kernel dropped part of this dump");
		case NLMSG_ERROR: {
			struct nlmsgerr e;

			if (h.nlmsg_len - sizeof h < sizeof e.error)
				return refuse("NLMSG_ERROR with no error code");
			memcpy(&e.error, buf + sizeof h, sizeof e.error);
			if (e.error == 0) {       /* a plain ACK ends it */
				d->done = 1;
				return 0;
			}
			return fail("kernel refused the request: %s",
			    strerror(-e.error));
		}
		case SOCK_DIAG_BY_FAMILY:
			d->recs++;
			if (d->show(buf, h.nlmsg_len, d->netid) < 0) return -1;
			break;
		default:
			return refuse("unexpected nlmsg_type %u",
			    h.nlmsg_type);
		}

		step = NLMSG_ALIGN(h.nlmsg_len);
		if (step >= len) return 0;
		buf += step;
		len -= step;
	}
	return 0;
}

/* --------------------------------------------------------------- transport */

/* Big enough for any dump datagram the kernel produces; a short read is
 * reported rather than silently dropping sockets, see recv_dump. */
#define RECVBUF (256u * 1024u)
static unsigned char rbuf[RECVBUF];

static int nl_open(void)
{
	int fd, rcv = 1 << 20;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
	if (fd < 0) {
		/* EPROTONOSUPPORT: CONFIG_SOCK_DIAG or the per-family diag
		 * module is missing. EAFNOSUPPORT: no netlink at all. Either
		 * way there is nothing to fall back to that we would trust. */
		fail("socket(AF_NETLINK, NETLINK_SOCK_DIAG): %s",
		    strerror(errno));
		return -1;
	}
	/* Best effort. A busy machine's unix socket table is hundreds of
	 * kilobytes and a small receive buffer means ENOBUFS mid-dump. */
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof rcv);
	return fd;
}

static int nl_send(int fd, const void *req, size_t len)
{
	struct sockaddr_nl to;
	struct iovec iov;
	struct msghdr msg;

	memset(&to, 0, sizeof to);
	to.nl_family = AF_NETLINK;          /* nl_pid 0: the kernel */
	iov.iov_base = (void *)req;
	iov.iov_len = len;
	memset(&msg, 0, sizeof msg);
	msg.msg_name = &to;
	msg.msg_namelen = sizeof to;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (sendmsg(fd, &msg, 0) < 0)
		return fail("sendmsg: %s", strerror(errno));
	return 0;
}

static int recv_dump(struct dump *d)
{
	while (!d->done && !d->intr) {
		struct sockaddr_nl from;
		struct iovec iov;
		struct msghdr msg;
		ssize_t n;
		int r;

		iov.iov_base = rbuf;
		iov.iov_len = sizeof rbuf;
		memset(&msg, 0, sizeof msg);
		msg.msg_name = &from;
		msg.msg_namelen = sizeof from;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		/*
		 * MSG_TRUNC makes recvmsg report the datagram's real size even
		 * when it did not fit. Keeping the prefix would drop sockets
		 * from the listing and the listing would still look plausible,
		 * which is the exact failure this program exists not to have.
		 * shortcut: refuse rather than grow the buffer and retry; the
		 * upgrade is a realloc loop driven by the returned length.
		 */
		n = recvmsg(d->fd, &msg, MSG_TRUNC);
		if (n < 0) {
			if (errno == EINTR) continue;
			return fail("recvmsg: %s", strerror(errno));
		}
		if (n == 0)
			return fail("netlink socket gave EOF mid-dump");
		if (msg.msg_flags & MSG_TRUNC)
			return fail("netlink datagram of %zd bytes does not fit "
			    "the %u-byte buffer", n, RECVBUF);
		/* Only the kernel's own replies. shortcut: we do not match
		 * nlmsg_seq, which is safe only because one request is
		 * outstanding at a time on a socket nobody else holds. */
		if (from.nl_pid != 0) continue;

		r = walk(rbuf, (size_t)n, d);
		if (r < 0) return r;
	}
	return 0;
}

/* ------------------------------------------------------------- bytecode */

/*
 * INET_DIAG_REQ_BYTECODE: the filter the KERNEL runs, which is the whole
 * point of it. Without one, every socket on the machine crosses the netlink
 * socket so that userspace can throw most of them away; with one, the kernel
 * never serialises the sockets that do not match. On a machine with 1500
 * sockets that is most of the cost of the program, and it is the one place
 * this program was structurally worse than ss rather than merely smaller.
 *
 * The format is a sequence of four-byte ops, each optionally followed by an
 * operand, and every op is a conditional forward jump: `yes` bytes on if the
 * test passed, `no` bytes on if it did not. The program accepts the socket if
 * control reaches exactly the end, and rejects it if a jump lands past the
 * end -- so a chain of conditions ANDed together is every op falling through
 * to the next (yes = its own length) with every `no` pointing one word beyond
 * the program. The kernel's own audit pass (inet_diag_bc_audit) insists that
 * `no` be at most len+4, which is where that +4 comes from: it is the
 * canonical "reject" target and not an off-by-one.
 *
 * Ports in a bytecode operand are host byte order, not __be16. The kernel
 * compares against inet->inet_num and ntohs(inet->inet_dport), both already
 * host order. Addresses are network order. Getting that backwards produces a
 * filter that quietly matches nothing, which is why the suite asserts that a
 * filter selects sockets it created rather than only that it selects fewer.
 */
#define BCMAX 64
static union {
	uint32_t align[BCMAX / 4];      /* an operand needs 4-byte alignment */
	unsigned char b[BCMAX];
} bc;
static size_t bclen;
static size_t bcoff[3];             /* --port, --addr, --dev at most */
static unsigned bcops;

/* Append one op plus `extra` operand bytes, and return the operand's offset.
 * The caller's conditions are bounded at three and the widest operand is a
 * 24-byte IPv6 hostcond, so BCMAX cannot be reached; it is asserted anyway
 * because a silent truncation here would be a filter that means something
 * else. */
static size_t bc_add(unsigned char code, size_t extra)
{
	struct inet_diag_bc_op op;

	if (bclen + sizeof op + extra > BCMAX || bcops >= 3) {
		fail("internal: the bytecode filter does not fit");
		exit(EX_FAIL);
	}
	op.code = code;
	op.yes = (unsigned char)(sizeof op + extra);   /* fall through */
	op.no = 0;                                     /* patched by bc_end */
	bcoff[bcops++] = bclen;
	memcpy(bc.b + bclen, &op, sizeof op);
	memset(bc.b + bclen + sizeof op, 0, extra);
	bclen += sizeof op + extra;
	return bclen - extra;
}

/* Point every condition's failure jump one word past the end of the program,
 * which is the kernel's encoding for "reject this socket". */
static void bc_end(void)
{
	unsigned i;

	for (i = 0; i < bcops; i++) {
		struct inet_diag_bc_op op;

		memcpy(&op, bc.b + bcoff[i], sizeof op);
		op.no = (unsigned short)(bclen - bcoff[i] + 4);
		memcpy(bc.b + bcoff[i], &op, sizeof op);
	}
}

/*
 * One INET_DIAG_BC_S_COND carries both halves of a "local end looks like
 * this" test: a port, or -1 for any port, and an address prefix, or a
 * prefix length of zero for any address. --port and --addr are kept as two
 * separate ops anyway, because combining them would make the two filters
 * indistinguishable to a mutation of either.
 *
 * A cond of family AF_INET against an AF_INET6 socket matches only a
 * v4-mapped address; that is the kernel's rule, it is what `ss src 10.0.0.1`
 * does, and sockv inherits it by sending the same cond to both dumps.
 */
static void bc_hostcond(int family, int prefix_len, int port,
                        const void *addr, size_t alen)
{
	struct inet_diag_hostcond c;
	size_t off;

	memset(&c, 0, sizeof c);
	c.family = (uint8_t)family;
	c.prefix_len = (uint8_t)prefix_len;
	c.port = port;
	off = bc_add(INET_DIAG_BC_S_COND, sizeof c + alen);
	memcpy(bc.b + off, &c, sizeof c);
	if (alen) memcpy(bc.b + off + sizeof c, addr, alen);
}

static void bc_port(long port)
{
	bc_hostcond(AF_UNSPEC, 0, (int)port, NULL, 0);
}

/* ADDR or ADDR/LEN. Returns 0, or -1 having said what was wrong. */
static int bc_addr(const char *spec)
{
	char host[64];
	struct in6_addr a6;
	struct in_addr a4;
	const char *slash;
	long bits;
	size_t n;

	slash = strchr(spec, '/');
	n = slash ? (size_t)(slash - spec) : strlen(spec);
	if (n == 0 || n >= sizeof host) {
		fprintf(stderr, "%s: --addr: '%s' is not an address\n", prog,
		    spec);
		return -1;
	}
	memcpy(host, spec, n);
	host[n] = '\0';

	if (inet_pton(AF_INET, host, &a4) == 1) {
		bits = 32;
		if (slash) bits = strtol(slash + 1, NULL, 10);
		if (bits < 0 || bits > 32) {
			fprintf(stderr, "%s: --addr: prefix length must be "
			    "0..32 for an IPv4 address\n", prog);
			return -1;
		}
		bc_hostcond(AF_INET, (int)bits, -1, &a4, sizeof a4);
		return 0;
	}
	if (inet_pton(AF_INET6, host, &a6) == 1) {
		bits = 128;
		if (slash) bits = strtol(slash + 1, NULL, 10);
		if (bits < 0 || bits > 128) {
			fprintf(stderr, "%s: --addr: prefix length must be "
			    "0..128 for an IPv6 address\n", prog);
			return -1;
		}
		bc_hostcond(AF_INET6, (int)bits, -1, &a6, sizeof a6);
		return 0;
	}
	fprintf(stderr, "%s: --addr: '%s' is not an IPv4 or IPv6 address\n",
	    prog, host);
	return -1;
}

/*
 * INET_DIAG_BC_DEV_COND tests sk_bound_dev_if, which is the same number that
 * arrives as idiag_if and that this program renders as the %ifname suffix.
 * It is SO_BINDTODEVICE, or a bind to a scoped address, and not the interface
 * the route happens to use -- an unbound socket on a machine with one NIC has
 * ifindex 0 and no --dev value matches it.
 */
static int bc_dev(const char *name)
{
	uint32_t idx = if_nametoindex(name);
	size_t off;

	if (idx == 0) {
		fprintf(stderr, "%s: --dev: no interface named '%s'\n", prog,
		    name);
		return -1;
	}
	off = bc_add(INET_DIAG_BC_DEV_COND, sizeof idx);
	memcpy(bc.b + off, &idx, sizeof idx);
	return 0;
}

/* ---------------------------------------------------------------- requests */

/*
 * A dump of a live machine races every program on it. NLM_F_DUMP_INTR is the
 * kernel telling us the iterator was disturbed, and the only correct response
 * is to ask again -- so the retry count is part of the contract, not a
 * workaround. Failing loudly after a few tries beats printing a listing the
 * kernel has already said is wrong.
 */
#define DUMP_TRIES 8

static int run_dump(struct dump *d, const void *req, size_t len)
{
	int i;

	for (i = 0; i < DUMP_TRIES; i++) {
		int r;

		/* Reset per attempt: a dump the kernel asked us to restart
		 * delivered records that are about to be delivered again, and
		 * counting both would hide a duplicate rather than expose
		 * one. */
		d->done = d->intr = 0;
		d->recs = 0;
		if (nl_send(d->fd, req, len) < 0) return -2;
		r = recv_dump(d);
		if (r < 0) return r;
		if (!d->intr) {
			records += d->recs;
			return 0;
		}
	}
	return fail("the socket table kept changing under %d dump attempts "
	    "(NLM_F_DUMP_INTR); refusing to print an inconsistent listing",
	    DUMP_TRIES);
}

static int dump_inet(struct dump *d, int family, int proto, uint32_t states,
                     const char *netid)
{
	struct {
		struct nlmsghdr nlh;
		struct inet_diag_req_v2 r;
		struct nlattr a;
		unsigned char prog[BCMAX];
	} req;
	size_t len = NLMSG_LENGTH(sizeof req.r);

	memset(&req, 0, sizeof req);
	req.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nlh.nlmsg_seq = ++d->seq;
	req.r.sdiag_family = (uint8_t)family;
	req.r.sdiag_protocol = (uint8_t)proto;
	req.r.idiag_states = states;
	/*
	 * idiag_ext stays zero: the base inet_diag_msg carries everything we
	 * print. INET_DIAG_SKV6ONLY is not requestable anyway -- idiag_ext is
	 * eight bits wide and that attribute is number 11 -- the kernel sends
	 * it unasked for every AF_INET6 socket.
	 */
	if (bclen) {
		/* The offset is computed rather than assumed: an attribute
		 * has to start on a four-byte boundary after the request
		 * struct, and both structs happen to be a multiple of four
		 * on this ABI, but the kernel reads nlmsg_len and not our
		 * arithmetic about it. */
		req.a.nla_type = INET_DIAG_REQ_BYTECODE;
		req.a.nla_len = (uint16_t)(NLA_HDRLEN + bclen);
		memcpy(req.prog, bc.b, bclen);
		len = (size_t)((unsigned char *)&req.a -
		    (unsigned char *)&req) + NLA_HDRLEN + bclen;
	}
	req.nlh.nlmsg_len = (uint32_t)len;
	d->netid = netid;
	d->show = show_inet;
	return run_dump(d, &req, len);
}

static int dump_unix(struct dump *d, uint32_t states)
{
	struct {
		struct nlmsghdr nlh;
		struct unix_diag_req r;
	} req;

	memset(&req, 0, sizeof req);
	req.nlh.nlmsg_len = sizeof req;
	req.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nlh.nlmsg_seq = ++d->seq;
	req.r.sdiag_family = AF_UNIX;
	req.r.udiag_states = states;
	/* Unlike inet_diag, unix_diag sends nothing it was not asked for: the
	 * name, the peer's inode and the owning uid are all opt-in. */
	req.r.udiag_show = UDIAG_SHOW_NAME | UDIAG_SHOW_PEER | UDIAG_SHOW_UID;
	d->netid = NULL;
	d->show = show_unix;
	return run_dump(d, &req, sizeof req);
}

/*
 * --parse exposes the walker to bytes no kernel would send. It is the same
 * walk() the live path uses, over the same handlers, so a bounds check that
 * the fixtures prove is the bounds check that runs against the kernel.
 */
static int parse_file(const char *proto, const char *path)
{
	struct dump d;
	unsigned char *buf;
	struct stat st;
	size_t len;
	FILE *f;
	int r;

	memset(&d, 0, sizeof d);
	if (!strcmp(proto, "tcp") || !strcmp(proto, "udp")) {
		d.show = show_inet;
		d.netid = proto;
	} else if (!strcmp(proto, "unix")) {
		d.show = show_unix;
	} else {
		fprintf(stderr, "%s: --parse: PROTO must be tcp, udp or unix, "
		    "not '%s'\n", prog, proto);
		return EX_USAGE;
	}

	f = fopen(path, "rb");
	if (!f) {
		fail("%s: %s", path, strerror(errno));
		return EX_FAIL;
	}
	/*
	 * The buffer is exactly the size of the file, and that is a property
	 * of the test rig rather than a micro-optimisation. Reading into a
	 * generously sized buffer leaves a deleted bounds check reading
	 * uninitialised bytes that are still inside the allocation, where
	 * AddressSanitizer cannot see it -- which is how `make test-asan`
	 * silently stopped being able to detect the one defect class it
	 * exists for. With the allocation ending where the data ends, the
	 * first byte past the reply is a heap-buffer-overflow.
	 */
	if (fstat(fileno(f), &st) < 0 || st.st_size < 0) {
		fclose(f);
		fail("%s: fstat: %s", path, strerror(errno));
		return EX_FAIL;
	}
	len = (size_t)st.st_size;
	buf = malloc(len ? len : 1);
	if (!buf) {
		fclose(f);
		fail("out of memory");
		return EX_FAIL;
	}
	if (len && fread(buf, 1, len, f) != len) {
		fclose(f);
		free(buf);
		fail("%s: short read", path);
		return EX_FAIL;
	}
	fclose(f);

	r = walk(buf, len, &d);
	free(buf);
	if (r == -1) return EX_BAD;
	if (r < 0) return EX_FAIL;
	/* On the live path NLM_F_DUMP_INTR means "ask again". There is nothing
	 * to ask here, so it is reported rather than silently truncating the
	 * listing at the flagged record. */
	if (d.intr) {
		fail("%s: a record carries NLM_F_DUMP_INTR; this capture is "
		    "an incomplete dump", path);
		return EX_FAIL;
	}
	return EX_OK;
}

/* --------------------------------------------------------------------- CLI */

/*
 * -l means a different state per protocol, because "listening" does:
 * a TCP listener is in TCP_LISTEN, while a UDP socket that is bound and
 * waiting is in TCP_CLOSE -- the kernel has no separate UDP state machine.
 * ss draws the same distinction and the differential test holds us to it.
 */
#define SF(s) (1U << (s))
#define STATES_ALL (~0U)

static void usage(FILE *f)
{
	fprintf(f,
	    "usage: %s [-tux] [-l | -a] [--port N] [--addr A[/LEN]] [--dev NAME]\n"
	    "              [--records]\n"
	    "       %s --parse PROTO FILE\n"
	    "\n"
	    "  -t       TCP sockets          -l   listening only\n"
	    "  -u       UDP sockets          -a   all states (the default)\n"
	    "  -x       UNIX domain sockets\n"
	    "\n"
	    "With no family flag, all of -t -u -x are listed.\n"
	    "\n"
	    "Filters, compiled to INET_DIAG_REQ_BYTECODE and run BY THE KERNEL,\n"
	    "so a socket that does not match is never sent. They combine with\n"
	    "AND, they match the local end, and they apply to -t and -u only:\n"
	    "unix_diag has no bytecode, so -x with a filter is refused rather\n"
	    "than silently filtered here. With a filter and no family flag,\n"
	    "-t -u is the default instead of -t -u -x.\n"
	    "\n"
	    "  --port N             local port is N          (ss: sport = :N)\n"
	    "  --addr A[/LEN]       local address is A/LEN   (ss: src A/LEN)\n"
	    "  --dev NAME           bound to interface NAME  (ss: dev == NAME)\n"
	    "  --records            print to stderr how many records the\n"
	    "                       kernel sent, which is what distinguishes a\n"
	    "                       kernel-side filter from a userspace one\n"
	    "\n"
	    "  --parse PROTO FILE   walk FILE as a captured netlink reply and\n"
	    "                       list what it holds. PROTO is tcp, udp or\n"
	    "                       unix. Same walker as the live path, exposed\n"
	    "                       so it can be fed bytes no kernel would send.\n"
	    "\n"
	    "One row per socket, no header:\n"
	    "  FAMILY NETID STATE LOCAL PEER INODE UID\n"
	    "Exit: 0 listed, 1 syscall or kernel error, 2 malformed reply,\n"
	    "3 usage.\n",
	    prog, prog);
}

int main(int argc, char **argv)
{
	int want_t = 0, want_u = 0, want_x = 0, listening = 0, explicit_x = 0;
	int seen[3] = { 0, 0, 0 };          /* --port, --addr, --dev */
	int i, r = 0;
	struct dump d;

	if (argv[0] && *argv[0]) prog = argv[0];

	for (i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
			usage(stdout);
			return EX_OK;
		}
		if (!strcmp(a, "--records")) {
			show_records = 1;
			continue;
		}
		/* The three filters. Each needs a value, and a missing one is
		 * a usage error rather than a filter that silently matches
		 * everything -- which is the failure mode that would make the
		 * rest of this program look like it worked. */
		if (!strcmp(a, "--port") || !strcmp(a, "--addr") ||
		    !strcmp(a, "--dev")) {
			const char *v;
			int which = a[2] == 'p' ? 0 : a[2] == 'a' ? 1 : 2;

			/* Twice is refused rather than ANDed. Two local ports
			 * cannot both be true, so the kernel would hand back
			 * an empty listing that looks exactly like a correct
			 * answer to a question nobody asked. */
			if (seen[which]) {
				fprintf(stderr, "%s: %s given twice\n",
				    prog, a);
				return EX_USAGE;
			}
			seen[which] = 1;
			if (i + 1 >= argc) {
				fprintf(stderr, "%s: %s needs a value\n",
				    prog, a);
				return EX_USAGE;
			}
			v = argv[++i];
			if (!strcmp(a, "--port")) {
				char *end;
				long n = strtol(v, &end, 10);

				if (*v == '\0' || *end != '\0' ||
				    n < 0 || n > 65535) {
					fprintf(stderr, "%s: --port: '%s' is "
					    "not a port number 0..65535\n",
					    prog, v);
					return EX_USAGE;
				}
				bc_port(n);
			} else if (!strcmp(a, "--addr")) {
				if (bc_addr(v) < 0) return EX_USAGE;
			} else {
				if (bc_dev(v) < 0) return EX_USAGE;
			}
			continue;
		}
		if (!strcmp(a, "--parse")) {
			if (i + 2 >= argc) {
				fprintf(stderr,
				    "%s: --parse needs PROTO and FILE\n", prog);
				return EX_USAGE;
			}
			return parse_file(argv[i + 1], argv[i + 2]);
		}
		if (a[0] == '-' && a[1] && a[1] != '-') {
			const char *c;

			for (c = a + 1; *c; c++) {
				switch (*c) {
				case 't': want_t = 1; break;
				case 'u': want_u = 1; break;
				case 'x': want_x = explicit_x = 1; break;
				case 'l': listening = 1; break;
				case 'a': listening = 0; break;
				default:
					fprintf(stderr,
					    "%s: unknown option -%c\n", prog,
					    *c);
					usage(stderr);
					return EX_USAGE;
				}
			}
			continue;
		}
		fprintf(stderr, "%s: unexpected argument '%s'\n", prog, a);
		usage(stderr);
		return EX_USAGE;
	}

	/*
	 * A filter is inet-only, because INET_DIAG_REQ_BYTECODE is. Asking
	 * for -x alongside one is refused rather than answered: the two
	 * honest alternatives are to list every UNIX socket unfiltered, which
	 * is not what was asked for, or to filter them here in userspace,
	 * which would mean the same flag sometimes runs in the kernel and
	 * sometimes does not with nothing in the output saying which.
	 */
	if (bclen && explicit_x) {
		fprintf(stderr, "%s: --port, --addr and --dev are "
		    "INET_DIAG_REQ_BYTECODE, which unix_diag has no "
		    "equivalent of; -x cannot be combined with them\n", prog);
		return EX_USAGE;
	}
	if (!want_t && !want_u && !want_x) {
		want_t = want_u = 1;
		want_x = !bclen;
	}
	bc_end();

	memset(&d, 0, sizeof d);
	d.fd = nl_open();
	if (d.fd < 0) return EX_FAIL;

	if (want_t) {
		uint32_t st = listening ? SF(TCP_LISTEN) : STATES_ALL;

		if (!r) r = dump_inet(&d, AF_INET, IPPROTO_TCP, st, "tcp");
		if (!r) r = dump_inet(&d, AF_INET6, IPPROTO_TCP, st, "tcp");
	}
	if (want_u) {
		uint32_t st = listening ? SF(TCP_CLOSE) : STATES_ALL;

		if (!r) r = dump_inet(&d, AF_INET, IPPROTO_UDP, st, "udp");
		if (!r) r = dump_inet(&d, AF_INET6, IPPROTO_UDP, st, "udp");
	}
	if (want_x && !r) {
		listen_only = listening;
		r = dump_unix(&d, listening ? SF(TCP_LISTEN) | SF(TCP_CLOSE)
		                            : STATES_ALL);
	}

	close(d.fd);
	if (show_records) fprintf(stderr, "records: %lu\n", records);
	if (r == -1) return EX_BAD;
	if (r < 0) return EX_FAIL;
	return EX_OK;
}

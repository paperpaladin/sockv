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
 * A UNIX socket's identity is its inode, and ss reports it in the column it
 * calls "Port" -- so the local end reads `name:inode` and the peer end reads
 * `*:peer-inode`, which is the same address:port shape the inet rows use and
 * keeps one comparison for both. The address half of a peer is always "*"
 * because a UNIX socket's peer has no name of its own to report.
 */
/*
 * -l selects sockets that can still receive something new, and for UNIX that
 * is a per-socket-type question rather than a per-dump one: a stream or
 * seqpacket listener sits in TCP_LISTEN, while a bound datagram socket sits in
 * TCP_CLOSE, exactly as a bound UDP socket does. unix_diag takes one state
 * mask for the whole dump, so the request asks for both and the display drops
 * the combinations that are not "listening". ss draws the same line -- a
 * previous version of this file used TCP_LISTEN alone and the differential
 * found the 60 u_dgr sockets it was dropping.
 */
static int listen_only;

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
	    m.udiag_state != (m.udiag_type == SOCK_DGRAM ? TCP_CLOSE
	                                                 : TCP_LISTEN))
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
	const char *netid;            /* which handler the records belong to */
	int (*show)(const unsigned char *, size_t, const char *);
};

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

		d->done = d->intr = 0;
		if (nl_send(d->fd, req, len) < 0) return -2;
		r = recv_dump(d);
		if (r < 0) return r;
		if (!d->intr) return 0;
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
	} req;

	memset(&req, 0, sizeof req);
	req.nlh.nlmsg_len = sizeof req;
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
	 *
	 * shortcut: no INET_DIAG_REQ_BYTECODE either, so every socket crosses
	 * the netlink socket even when the caller wanted one port. The ceiling
	 * is the whole socket table per invocation; the upgrade is to compile
	 * a bytecode program from an address/port/device filter and attach it
	 * to this request, which is how ss avoids the same cost.
	 */
	d->netid = netid;
	d->show = show_inet;
	return run_dump(d, &req, sizeof req);
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
	    "usage: %s [-tux] [-l | -a] | %s --parse PROTO FILE\n"
	    "\n"
	    "  -t       TCP sockets          -l   listening only\n"
	    "  -u       UDP sockets          -a   all states (the default)\n"
	    "  -x       UNIX domain sockets\n"
	    "\n"
	    "With no family flag, all of -t -u -x are listed.\n"
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
	int want_t = 0, want_u = 0, want_x = 0, listening = 0;
	int i, r = 0;
	struct dump d;

	if (argv[0] && *argv[0]) prog = argv[0];

	for (i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
			usage(stdout);
			return EX_OK;
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
				case 'x': want_x = 1; break;
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

	if (!want_t && !want_u && !want_x) want_t = want_u = want_x = 1;

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
	if (r == -1) return EX_BAD;
	if (r < 0) return EX_FAIL;
	return EX_OK;
}

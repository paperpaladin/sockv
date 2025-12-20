/*
 * probe - the oracle's two purpose-built tools.
 *
 *   probe emit CASE FILE   write a netlink reply to FILE: one well-formed
 *                          case per shape sockv must render, and one per way
 *                          the record stream can lie about its own lengths.
 *
 *   probe hold PORT DIR SECS   create sockets whose properties this program
 *                          chose, print the exact row each one must produce,
 *                          and stay alive for SECS so the row can be looked
 *                          for. The inode comes from fstat(2) on the socket's
 *                          own descriptor, which is the same number the
 *                          kernel reports as idiag_inode -- so this is an
 *                          oracle that knows the answer before sockv runs,
 *                          independent of ss and of /proc.
 *
 * Nothing here links against sockv or shares a line of code with it. The
 * well-formed cases are hand-built records with values chosen by this file,
 * so the harness can assert on an exact row rather than on whatever the
 * machine happens to be running -- the differential against ss covers the
 * live system, and these cover the shapes the live system does not have.
 *
 * The malformed cases exist because a netlink reply is a stream of
 * self-describing records and every length in it comes off the wire. A walker
 * that trusts nlmsg_len reads past the end of its buffer, and that is the
 * defect class this program's whole job is to provoke.
 *
 * Copyright (C) 2026  PLACEHOLDER.  Licensed under the GPLv3 (see LICENSE).
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/unix_diag.h>

static unsigned char B[8192];
static size_t L;
/* Where the last attribute ended before its padding. The kernel always pads,
 * so nlmsg_len is always aligned in a real reply; the unaligned-len fixture
 * needs the unpadded figure to build the case a real kernel cannot. */
static size_t unpadded;

static void raw(const void *p, size_t n)
{
	memcpy(B + L, p, n);
	L += n;
}

/* Records always start 4-aligned, so absolute alignment is the same as
 * alignment relative to the record. */
static void pad4(void)
{
	while (L & 3u) B[L++] = 0;
}

static size_t rec_start(uint16_t type, uint16_t flags)
{
	struct nlmsghdr h;
	size_t off = L;

	memset(&h, 0, sizeof h);
	h.nlmsg_type = type;
	h.nlmsg_flags = flags;
	h.nlmsg_seq = 1;
	raw(&h, sizeof h);
	return off;
}

/* Set nlmsg_len to the record's real length. It is the first field of the
 * header, hence the offset-0 poke. */
static void rec_len(size_t off, uint32_t n)
{
	memcpy(B + off, &n, sizeof n);
}

static void rec_end(size_t off)
{
	rec_len(off, (uint32_t)(L - off));
	pad4();
}

static void attr(uint16_t type, const void *v, size_t n)
{
	struct nlattr a;

	a.nla_len = (uint16_t)(sizeof a + n);
	a.nla_type = type;
	raw(&a, sizeof a);
	if (n) raw(v, n);
	unpadded = L;
	pad4();
}

/* An attribute whose declared length is a lie. */
static void attr_badlen(uint16_t type, uint16_t claim, const void *v, size_t n)
{
	struct nlattr a;

	a.nla_len = claim;
	a.nla_type = type;
	raw(&a, sizeof a);
	if (n) raw(v, n);
	pad4();
}

/*
 * One inet_diag_msg with values this file chose. 127.0.0.1:8080 connected to
 * 10.0.0.1:443, inode 4242, uid 1001 -- nothing the live machine would
 * produce, so a harness assertion on the exact row cannot pass by accident.
 */
static size_t inet_rec(int family, int state, uint16_t sport, uint16_t dport,
                       const char *src, const char *dst, uint32_t ifindex,
                       uint32_t inode, uint32_t uid, int v6only)
{
	struct inet_diag_msg m;
	size_t off = rec_start(SOCK_DIAG_BY_FAMILY, NLM_F_MULTI);

	memset(&m, 0, sizeof m);
	m.idiag_family = (uint8_t)family;
	m.idiag_state = (uint8_t)state;
	m.id.idiag_sport = htons(sport);
	m.id.idiag_dport = htons(dport);
	if (src) inet_pton(family, src, m.id.idiag_src);
	if (dst) inet_pton(family, dst, m.id.idiag_dst);
	m.id.idiag_if = ifindex;
	m.idiag_inode = inode;
	m.idiag_uid = uid;
	raw(&m, sizeof m);

	/* The kernel sends SKV6ONLY for every AF_INET6 socket and never for an
	 * AF_INET one, so the fixtures do the same. */
	if (family == AF_INET6) {
		uint8_t b = (uint8_t)v6only;
		attr(INET_DIAG_SKV6ONLY, &b, 1);
	}
	return off;
}

static size_t unix_rec(uint8_t type, uint8_t state, uint32_t inode,
                       uint32_t peer, uint32_t uid,
                       const void *name, size_t namelen)
{
	struct unix_diag_msg m;
	size_t off = rec_start(SOCK_DIAG_BY_FAMILY, NLM_F_MULTI);

	memset(&m, 0, sizeof m);
	m.udiag_family = AF_UNIX;
	m.udiag_type = type;
	m.udiag_state = state;
	m.udiag_ino = inode;
	raw(&m, sizeof m);
	if (name) attr(UNIX_DIAG_NAME, name, namelen);
	attr(UNIX_DIAG_PEER, &peer, sizeof peer);
	attr(UNIX_DIAG_UID, &uid, sizeof uid);
	return off;
}

static void done(void)
{
	size_t off = rec_start(NLMSG_DONE, NLM_F_MULTI);
	uint32_t zero = 0;

	raw(&zero, sizeof zero);
	rec_end(off);
}

/* ------------------------------------------------------------------- cases */

static int build(const char *c)
{
	size_t off;

	/* --- well formed: one row per rendering rule ------------------- */
	if (!strcmp(c, "v4")) {
		off = inet_rec(AF_INET, TCP_ESTABLISHED, 8080, 443,
		    "127.0.0.1", "10.0.0.1", 0, 4242, 1001, 0);
		rec_end(off);
		done();
		return 0;
	}
	if (!strcmp(c, "v4-listen-scoped")) {
		/* ifindex 1 is lo on every Linux, which is what makes the
		 * %ifname suffix assertable without a bound socket. */
		off = inet_rec(AF_INET, TCP_LISTEN, 53, 0,
		    "127.0.0.53", "0.0.0.0", 1, 4243, 65534, 0);
		rec_end(off);
		done();
		return 0;
	}
	if (!strcmp(c, "v6")) {
		off = inet_rec(AF_INET6, TCP_ESTABLISHED, 8080, 443,
		    "2001:db8::1", "2001:db8::2", 0, 4244, 1001, 1);
		rec_end(off);
		done();
		return 0;
	}
	if (!strcmp(c, "v6-wild-v6only")) {
		/* All-zero address on a v6-only socket renders as [::]. */
		off = inet_rec(AF_INET6, TCP_LISTEN, 8080, 0, "::", "::",
		    0, 4245, 0, 1);
		rec_end(off);
		done();
		return 0;
	}
	if (!strcmp(c, "v6-wild-dual")) {
		/* The same all-zero address on a dual-stack socket renders as
		 * "*", and that single bit of difference is the only thing
		 * separating this fixture from the one above. */
		off = inet_rec(AF_INET6, TCP_LISTEN, 8080, 0, "::", "::",
		    0, 4246, 0, 0);
		rec_end(off);
		done();
		return 0;
	}
	if (!strcmp(c, "v6-mapped")) {
		off = inet_rec(AF_INET6, TCP_LISTEN, 8080, 0,
		    "::ffff:127.0.0.1", "::", 0, 4247, 0, 0);
		rec_end(off);
		done();
		return 0;
	}
	if (!strcmp(c, "unix-path")) {
		off = unix_rec(SOCK_STREAM, TCP_LISTEN, 4248, 0, 1001,
		    "/run/probe.sock", sizeof "/run/probe.sock");
		rec_end(off);
		done();
		return 0;
	}
	if (!strcmp(c, "unix-abstract")) {
		off = unix_rec(SOCK_DGRAM, TCP_CLOSE, 4249, 0, 1001,
		    "\0probe-abstract", sizeof "\0probe-abstract" - 1);
		rec_end(off);
		done();
		return 0;
	}
	if (!strcmp(c, "unix-unnamed")) {
		off = unix_rec(SOCK_SEQPACKET, TCP_ESTABLISHED, 4250, 4251,
		    1001, NULL, 0);
		rec_end(off);
		done();
		return 0;
	}
	if (!strcmp(c, "unix-name-no-nul")) {
		/* An abstract name is not NUL-terminated, so the attribute
		 * length is the only bound there is. Ten bytes, no terminator,
		 * and the row must show exactly ten characters. */
		off = unix_rec(SOCK_STREAM, TCP_LISTEN, 4252, 0, 1001,
		    "abcdefghij", 10);
		rec_end(off);
		done();
		return 0;
	}
	if (!strcmp(c, "two-records")) {
		off = inet_rec(AF_INET, TCP_ESTABLISHED, 1, 2, "127.0.0.1",
		    "127.0.0.2", 0, 5001, 1001, 0);
		rec_end(off);
		off = inet_rec(AF_INET, TCP_ESTABLISHED, 3, 4, "127.0.0.3",
		    "127.0.0.4", 0, 5002, 1001, 0);
		rec_end(off);
		done();
		return 0;
	}
	if (!strcmp(c, "unaligned-len")) {
		/*
		 * nlmsg_len that is not a multiple of four, with a second
		 * record at the next aligned offset -- which is where the
		 * kernel would have put it. A 13-byte name gives the last
		 * attribute an nla_len of 17, so the record's real length is
		 * 49 and its padding to 52 belongs to the stream rather than
		 * to the record.
		 *
		 * A walker that advances by nlmsg_len instead of
		 * NLMSG_ALIGN(nlmsg_len) loses the second record here, and no
		 * live reply can expose that: nla_put reserves padded space
		 * for every attribute, so every length a kernel emits is
		 * already aligned and the two are indistinguishable.
		 */
		struct unix_diag_msg m;

		off = rec_start(SOCK_DIAG_BY_FAMILY, NLM_F_MULTI);
		memset(&m, 0, sizeof m);
		m.udiag_family = AF_UNIX;
		m.udiag_type = SOCK_STREAM;
		m.udiag_state = TCP_LISTEN;
		m.udiag_ino = 5003;
		raw(&m, sizeof m);
		attr(UNIX_DIAG_NAME, "/run/ab.sock", sizeof "/run/ab.sock");
		rec_len(off, (uint32_t)(unpadded - off));
		off = unix_rec(SOCK_STREAM, TCP_LISTEN, 5004, 0, 1001,
		    "/run/c.sock", sizeof "/run/c.sock");
		rec_end(off);
		done();
		return 0;
	}
	if (!strcmp(c, "attr-type-unknown")) {
		/* A type above anything this build knows must be ignored, not
		 * refused: the kernel adds attributes every few releases. */
		uint32_t junk = 0xdeadbeef;

		off = rec_start(SOCK_DIAG_BY_FAMILY, NLM_F_MULTI);
		{
			struct inet_diag_msg m;

			memset(&m, 0, sizeof m);
			m.idiag_family = AF_INET;
			m.idiag_state = TCP_ESTABLISHED;
			m.id.idiag_sport = htons(8080);
			m.id.idiag_dport = htons(443);
			inet_pton(AF_INET, "127.0.0.1", m.id.idiag_src);
			inet_pton(AF_INET, "10.0.0.1", m.id.idiag_dst);
			m.idiag_inode = 4242;
			m.idiag_uid = 1001;
			raw(&m, sizeof m);
		}
		attr(222, &junk, sizeof junk);
		rec_end(off);
		done();
		return 0;
	}

	/* --- malformed: every length in the stream, lying -------------- */
	if (!strcmp(c, "short-buffer")) {
		/* Nine bytes: fewer than an nlmsghdr. */
		memset(B, 0x41, 9);
		L = 9;
		return 0;
	}
	if (!strcmp(c, "len-under")) {
		off = rec_start(SOCK_DIAG_BY_FAMILY, NLM_F_MULTI);
		L = off + 72;
		rec_len(off, 8);
		return 0;
	}
	if (!strcmp(c, "len-zero")) {
		/* The one that makes a careless walker spin forever rather
		 * than overread. */
		off = rec_start(SOCK_DIAG_BY_FAMILY, NLM_F_MULTI);
		L = off + 72;
		rec_len(off, 0);
		return 0;
	}
	if (!strcmp(c, "len-over")) {
		off = inet_rec(AF_INET, TCP_ESTABLISHED, 1, 2, "127.0.0.1",
		    "127.0.0.2", 0, 1, 1, 0);
		rec_end(off);
		rec_len(off, (uint32_t)(L - off) + 64);
		return 0;
	}
	if (!strcmp(c, "len-huge")) {
		/* 0xffffffff, to catch a bounds check written as a subtraction
		 * that wraps instead of a comparison that does not. */
		off = inet_rec(AF_INET, TCP_ESTABLISHED, 1, 2, "127.0.0.1",
		    "127.0.0.2", 0, 1, 1, 0);
		rec_end(off);
		rec_len(off, 0xffffffffu);
		return 0;
	}
	if (!strcmp(c, "trailing-bytes")) {
		off = inet_rec(AF_INET, TCP_ESTABLISHED, 1, 2, "127.0.0.1",
		    "127.0.0.2", 0, 1, 1, 0);
		rec_end(off);
		memset(B + L, 0x5a, 7);          /* a truncated final header */
		L += 7;
		return 0;
	}
	if (!strcmp(c, "payload-short")) {
		/* Declares itself a socket record and carries eight bytes,
		 * where inet_diag_msg needs seventy-two. */
		off = rec_start(SOCK_DIAG_BY_FAMILY, NLM_F_MULTI);
		memset(B + L, 0, 8);
		L += 8;
		rec_end(off);
		return 0;
	}
	if (!strcmp(c, "attr-len-under")) {
		uint8_t b = 1;

		off = inet_rec(AF_INET6, TCP_ESTABLISHED, 1, 2, "::1", "::2",
		    0, 1, 1, 1);
		attr_badlen(INET_DIAG_SHUTDOWN, 2, &b, 1);
		rec_end(off);
		return 0;
	}
	if (!strcmp(c, "attr-len-over")) {
		uint8_t b = 1;

		off = inet_rec(AF_INET, TCP_ESTABLISHED, 1, 2, "127.0.0.1",
		    "127.0.0.2", 0, 1, 1, 0);
		attr_badlen(INET_DIAG_SHUTDOWN, 512, &b, 1);
		rec_end(off);
		return 0;
	}
	if (!strcmp(c, "attr-truncated")) {
		off = inet_rec(AF_INET, TCP_ESTABLISHED, 1, 2, "127.0.0.1",
		    "127.0.0.2", 0, 1, 1, 0);
		memset(B + L, 0x7f, 3);          /* 3 bytes: no attr header */
		L += 3;
		rec_end(off);
		return 0;
	}
	if (!strcmp(c, "attr-empty-u8")) {
		/* SKV6ONLY with a zero-byte payload: the attribute is in
		 * bounds, the value it promises is not there. */
		off = inet_rec(AF_INET6, TCP_ESTABLISHED, 1, 2, "::1", "::2",
		    0, 1, 1, 1);
		attr(INET_DIAG_SKV6ONLY, NULL, 0);
		rec_end(off);
		return 0;
	}
	if (!strcmp(c, "unix-name-too-long")) {
		char big[200];

		memset(big, 'x', sizeof big);
		off = unix_rec(SOCK_STREAM, TCP_LISTEN, 1, 0, 1,
		    big, sizeof big);
		rec_end(off);
		return 0;
	}
	if (!strcmp(c, "bad-family")) {
		off = rec_start(SOCK_DIAG_BY_FAMILY, NLM_F_MULTI);
		{
			struct inet_diag_msg m;

			memset(&m, 0, sizeof m);
			m.idiag_family = 99;
			m.idiag_state = TCP_ESTABLISHED;
			raw(&m, sizeof m);
		}
		rec_end(off);
		return 0;
	}
	if (!strcmp(c, "unknown-msg-type")) {
		off = rec_start(1234, NLM_F_MULTI);
		memset(B + L, 0, 16);
		L += 16;
		rec_end(off);
		return 0;
	}

	/* --- error and interruption: not malformed, but not a listing --- */
	if (!strcmp(c, "nlmsg-error")) {
		int32_t err = -EPERM;

		off = rec_start(NLMSG_ERROR, 0);
		raw(&err, sizeof err);
		rec_end(off);
		return 0;
	}
	if (!strcmp(c, "nlmsg-error-empty")) {
		off = rec_start(NLMSG_ERROR, 0);
		rec_end(off);
		return 0;
	}
	if (!strcmp(c, "dump-intr")) {
		off = inet_rec(AF_INET, TCP_ESTABLISHED, 1, 2, "127.0.0.1",
		    "127.0.0.2", 0, 1, 1, 0);
		rec_end(off);
		{
			uint16_t fl = NLM_F_MULTI | NLM_F_DUMP_INTR;

			memcpy(B + off + 6, &fl, sizeof fl);  /* nlmsg_flags */
		}
		done();
		return 0;
	}

	fprintf(stderr, "probe: unknown case '%s'\n", c);
	return 2;
}

/* ------------------------------------------------------------------- hold */

/*
 * The second oracle: sockets this program made, so it knows every field of
 * the row they must produce before sockv is asked. Addresses are printed from
 * the numbers passed to bind(2) rather than by rendering a sockaddr back out,
 * so nothing here can share a formatting misunderstanding with sockv.
 *
 * Everything binds to 127.0.0.1, ::1 or the filesystem. Nothing is sent, and
 * nothing is connected anywhere off this machine.
 */
static unsigned long myuid;

static void expect(const char *tag, const char *fam, const char *netid,
                   const char *state, const char *local, const char *peer,
                   unsigned long ino)
{
	printf("EXPECT %s %s %s %s %s %s %lu %lu\n", tag, fam, netid, state,
	    local, peer, ino, myuid);
}

static void skip(const char *tag, const char *why)
{
	printf("SKIP %s %s: %s\n", tag, why, strerror(errno));
}

static unsigned long ino_of(int fd)
{
	struct stat st;

	if (fstat(fd, &st) < 0) return 0;
	return (unsigned long)st.st_ino;
}

static int v4addr(struct sockaddr_in *a, int port)
{
	memset(a, 0, sizeof *a);
	a->sin_family = AF_INET;
	a->sin_port = htons((uint16_t)port);
	a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	return (int)sizeof *a;
}

static int v6addr(struct sockaddr_in6 *a, int port)
{
	memset(a, 0, sizeof *a);
	a->sin6_family = AF_INET6;
	a->sin6_port = htons((uint16_t)port);
	a->sin6_addr = in6addr_loopback;
	return (int)sizeof *a;
}

/* Returns the bound socket, or -1 having already printed a SKIP. */
static int bind_v4(const char *tag, int type, int port, int backlog)
{
	struct sockaddr_in a;
	int fd, one = 1, n = v4addr(&a, port);

	fd = socket(AF_INET, type, 0);
	if (fd < 0) { skip(tag, "socket"); return -1; }
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	if (bind(fd, (struct sockaddr *)&a, (socklen_t)n) < 0) {
		skip(tag, "bind");
		close(fd);
		return -1;
	}
	if (backlog && listen(fd, backlog) < 0) {
		skip(tag, "listen");
		close(fd);
		return -1;
	}
	return fd;
}

static int bind_v6(const char *tag, int type, int port, int backlog)
{
	struct sockaddr_in6 a;
	int fd, one = 1, n = v6addr(&a, port);

	fd = socket(AF_INET6, type, 0);
	if (fd < 0) { skip(tag, "socket"); return -1; }
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	if (bind(fd, (struct sockaddr *)&a, (socklen_t)n) < 0) {
		skip(tag, "bind");
		close(fd);
		return -1;
	}
	if (backlog && listen(fd, backlog) < 0) {
		skip(tag, "listen");
		close(fd);
		return -1;
	}
	return fd;
}

static int local_port(int fd)
{
	struct sockaddr_storage ss;
	socklen_t n = sizeof ss;

	if (getsockname(fd, (struct sockaddr *)&ss, &n) < 0) return -1;
	if (ss.ss_family == AF_INET)
		return ntohs(((struct sockaddr_in *)&ss)->sin_port);
	return ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
}

/* Bind a UNIX socket to a filesystem path or, when path starts with '@', to
 * that abstract name. Returns -1 having printed a SKIP. */
static int bind_unix(const char *tag, int type, const char *path, int backlog)
{
	struct sockaddr_un un;
	size_t n = strlen(path);
	socklen_t len;
	int fd;

	if (n + 1 > sizeof un.sun_path) { errno = ENAMETOOLONG;
		skip(tag, "name"); return -1; }
	memset(&un, 0, sizeof un);
	un.sun_family = AF_UNIX;
	if (path[0] == '@') {
		/* Abstract: a leading NUL, then the name, and the address
		 * length is the only thing that says where it ends. */
		memcpy(un.sun_path + 1, path + 1, n - 1);
		len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + n);
	} else {
		memcpy(un.sun_path, path, n);
		len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + n + 1);
		unlink(path);
	}
	fd = socket(AF_UNIX, type, 0);
	if (fd < 0) { skip(tag, "socket"); return -1; }
	if (bind(fd, (struct sockaddr *)&un, len) < 0) {
		skip(tag, "bind");
		close(fd);
		return -1;
	}
	if (backlog && listen(fd, backlog) < 0) {
		skip(tag, "listen");
		close(fd);
		return -1;
	}
	return fd;
}

static int connect_unix(const char *tag, int type, const char *path)
{
	struct sockaddr_un un;
	size_t n = strlen(path);
	socklen_t len;
	int fd;

	memset(&un, 0, sizeof un);
	un.sun_family = AF_UNIX;
	if (path[0] == '@') {
		memcpy(un.sun_path + 1, path + 1, n - 1);
		len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + n);
	} else {
		memcpy(un.sun_path, path, n);
		len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + n + 1);
	}
	fd = socket(AF_UNIX, type, 0);
	if (fd < 0) { skip(tag, "socket"); return -1; }
	if (connect(fd, (struct sockaddr *)&un, len) < 0) {
		skip(tag, "connect");
		close(fd);
		return -1;
	}
	return fd;
}

static int hold(int base, const char *dir, int secs)
{
	char loc[320], peer[320], path[192], path2[192];
	char abs1[64], abs2[64], spaced[64];
	struct sockaddr_in a4;
	struct sockaddr_in6 a6;
	int l4, l6, b4, u4, u6, p1, p2, c4, s4, c6, s6;
	int ul, ua, uc, us, ud, uq, sp[2];

	myuid = (unsigned long)getuid();

	/* --- TCP, IPv4: a listener, a connected pair, and a socket that is
	 *     bound and nothing else. That last one is the shape /proc/net/tcp
	 *     cannot see at all. */
	l4 = bind_v4("tcp4-listen", SOCK_STREAM, base, 8);
	if (l4 >= 0) {
		snprintf(loc, sizeof loc, "127.0.0.1:%d", base);
		expect("tcp4-listen", "inet", "tcp", "LISTEN", loc,
		    "0.0.0.0:*", ino_of(l4));

		v4addr(&a4, base);
		c4 = socket(AF_INET, SOCK_STREAM, 0);
		if (c4 >= 0 &&
		    connect(c4, (struct sockaddr *)&a4, sizeof a4) == 0 &&
		    (s4 = accept(l4, NULL, NULL)) >= 0) {
			int cp = local_port(c4);

			snprintf(loc, sizeof loc, "127.0.0.1:%d", cp);
			snprintf(peer, sizeof peer, "127.0.0.1:%d", base);
			expect("tcp4-client", "inet", "tcp", "ESTAB", loc,
			    peer, ino_of(c4));
			expect("tcp4-server", "inet", "tcp", "ESTAB", peer,
			    loc, ino_of(s4));
		} else {
			skip("tcp4-client", "connect/accept");
			skip("tcp4-server", "connect/accept");
		}
	} else {
		skip("tcp4-client", "no listener");
		skip("tcp4-server", "no listener");
	}

	b4 = bind_v4("tcp4-bound-only", SOCK_STREAM, base + 1, 0);
	if (b4 >= 0) {
		snprintf(loc, sizeof loc, "127.0.0.1:%d", base + 1);
		expect("tcp4-bound-only", "inet", "tcp", "UNCONN", loc,
		    "0.0.0.0:*", ino_of(b4));
	}

	/* --- TCP, IPv6. A bind to ::1 makes the kernel set sk_ipv6only, which
	 *     is why the listener's empty peer end reads [::] and not *. */
	l6 = bind_v6("tcp6-listen", SOCK_STREAM, base, 8);
	if (l6 >= 0) {
		snprintf(loc, sizeof loc, "[::1]:%d", base);
		expect("tcp6-listen", "inet6", "tcp", "LISTEN", loc,
		    "[::]:*", ino_of(l6));

		v6addr(&a6, base);
		c6 = socket(AF_INET6, SOCK_STREAM, 0);
		if (c6 >= 0 &&
		    connect(c6, (struct sockaddr *)&a6, sizeof a6) == 0 &&
		    (s6 = accept(l6, NULL, NULL)) >= 0) {
			int cp = local_port(c6);

			snprintf(loc, sizeof loc, "[::1]:%d", cp);
			snprintf(peer, sizeof peer, "[::1]:%d", base);
			expect("tcp6-client", "inet6", "tcp", "ESTAB", loc,
			    peer, ino_of(c6));
			expect("tcp6-server", "inet6", "tcp", "ESTAB", peer,
			    loc, ino_of(s6));
		} else {
			skip("tcp6-client", "connect/accept");
			skip("tcp6-server", "connect/accept");
		}
	} else {
		skip("tcp6-client", "no listener");
		skip("tcp6-server", "no listener");
	}

	/* --- UDP: bound is UNCONN, connected is ESTAB, same as the kernel's
	 *     TCP state numbers because UDP has no state machine of its own. */
	u4 = bind_v4("udp4-bound", SOCK_DGRAM, base + 2, 0);
	if (u4 >= 0) {
		snprintf(loc, sizeof loc, "127.0.0.1:%d", base + 2);
		expect("udp4-bound", "inet", "udp", "UNCONN", loc,
		    "0.0.0.0:*", ino_of(u4));
	}
	u6 = bind_v6("udp6-bound", SOCK_DGRAM, base + 2, 0);
	if (u6 >= 0) {
		snprintf(loc, sizeof loc, "[::1]:%d", base + 2);
		expect("udp6-bound", "inet6", "udp", "UNCONN", loc,
		    "[::]:*", ino_of(u6));
	}

	p1 = bind_v4("udp4-connected", SOCK_DGRAM, base + 3, 0);
	p2 = bind_v4("udp4-connected", SOCK_DGRAM, base + 4, 0);
	if (p1 >= 0 && p2 >= 0) {
		v4addr(&a4, base + 4);
		if (connect(p1, (struct sockaddr *)&a4, sizeof a4) == 0) {
			v4addr(&a4, base + 3);
			if (connect(p2, (struct sockaddr *)&a4,
			    sizeof a4) == 0) {
				snprintf(loc, sizeof loc, "127.0.0.1:%d",
				    base + 3);
				snprintf(peer, sizeof peer, "127.0.0.1:%d",
				    base + 4);
				expect("udp4-connected", "inet", "udp", "ESTAB",
				    loc, peer, ino_of(p1));
				expect("udp4-connected-peer", "inet", "udp",
				    "ESTAB", peer, loc, ino_of(p2));
			} else {
				skip("udp4-connected", "connect");
			}
		} else {
			skip("udp4-connected", "connect");
		}
	}

	/* --- UNIX. sockv's local column is name:inode, because ss reports a
	 *     UNIX socket's inode in the column it labels Port. */
	snprintf(path, sizeof path, "%s/stream.sock", dir);
	snprintf(path2, sizeof path2, "%s/dgram.sock", dir);
	snprintf(abs1, sizeof abs1, "@sockv-probe-%d", base);
	snprintf(abs2, sizeof abs2, "@sockv-probe-seq-%d", base);
	snprintf(spaced, sizeof spaced, "@sockv probe %d spaced", base);

	ul = bind_unix("unix-path-listen", SOCK_STREAM, path, 8);
	if (ul >= 0) {
		unsigned long li = ino_of(ul);

		snprintf(loc, sizeof loc, "%s:%lu", path, li);
		expect("unix-path-listen", "unix", "u_str", "LISTEN", loc,
		    "*:0", li);

		uc = connect_unix("unix-pair", SOCK_STREAM, path);
		if (uc >= 0 && (us = accept(ul, NULL, NULL)) >= 0) {
			unsigned long ci = ino_of(uc), si = ino_of(us);

			/* An accepted socket inherits the listener's name; the
			 * connecting side never had one. */
			snprintf(loc, sizeof loc, "%s:%lu", path, si);
			snprintf(peer, sizeof peer, "*:%lu", ci);
			expect("unix-pair-server", "unix", "u_str", "ESTAB",
			    loc, peer, si);
			snprintf(loc, sizeof loc, "*:%lu", ci);
			snprintf(peer, sizeof peer, "*:%lu", si);
			expect("unix-pair-client", "unix", "u_str", "ESTAB",
			    loc, peer, ci);
		} else {
			skip("unix-pair-server", "connect/accept");
			skip("unix-pair-client", "connect/accept");
		}
	}

	ua = bind_unix("unix-abstract-listen", SOCK_STREAM, abs1, 8);
	if (ua >= 0) {
		unsigned long i = ino_of(ua);

		snprintf(loc, sizeof loc, "%s:%lu", abs1, i);
		expect("unix-abstract-listen", "unix", "u_str", "LISTEN", loc,
		    "*:0", i);
	}

	ud = bind_unix("unix-dgram", SOCK_DGRAM, path2, 0);
	if (ud >= 0) {
		unsigned long i = ino_of(ud);

		snprintf(loc, sizeof loc, "%s:%lu", path2, i);
		expect("unix-dgram", "unix", "u_dgr", "UNCONN", loc, "*:0", i);
	}

	uq = bind_unix("unix-seqpacket", SOCK_SEQPACKET, abs2, 8);
	if (uq >= 0) {
		unsigned long i = ino_of(uq);

		snprintf(loc, sizeof loc, "%s:%lu", abs2, i);
		expect("unix-seqpacket", "unix", "u_seq", "LISTEN", loc,
		    "*:0", i);
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0) {
		unsigned long i0 = ino_of(sp[0]), i1 = ino_of(sp[1]);

		snprintf(loc, sizeof loc, "*:%lu", i0);
		snprintf(peer, sizeof peer, "*:%lu", i1);
		expect("unix-socketpair-a", "unix", "u_str", "ESTAB", loc,
		    peer, i0);
		expect("unix-socketpair-b", "unix", "u_str", "ESTAB", peer,
		    loc, i1);
	} else {
		skip("unix-socketpair-a", "socketpair");
		skip("unix-socketpair-b", "socketpair");
	}

	/*
	 * An abstract name with spaces in it. A row carrying one cannot be
	 * matched field by field -- in sockv's output or in ss's -- so the
	 * harness looks for the name as a substring instead, and the README
	 * says what that means for anyone parsing either program's output.
	 */
	{
		int fd = bind_unix("unix-spaced", SOCK_STREAM, spaced, 8);

		if (fd >= 0)
			printf("SPACED %s:%lu\n", spaced, ino_of(fd));
	}

	printf("READY\n");
	fflush(stdout);
	sleep((unsigned)secs);
	if (ul >= 0) unlink(path);
	if (ud >= 0) unlink(path2);
	return 0;
}

int main(int argc, char **argv)
{
	FILE *f;
	int r;

	if (argc == 5 && !strcmp(argv[1], "hold"))
		return hold(atoi(argv[2]), argv[3], atoi(argv[4]));
	if (argc != 4 || strcmp(argv[1], "emit")) {
		fprintf(stderr, "usage: %s emit CASE FILE\n"
		    "       %s hold PORT DIR SECONDS\n", argv[0], argv[0]);
		return 2;
	}
	r = build(argv[2]);
	if (r) return r;

	f = fopen(argv[3], "wb");
	if (!f) {
		fprintf(stderr, "probe: %s: %s\n", argv[3], strerror(errno));
		return 1;
	}
	if (fwrite(B, 1, L, f) != L || fclose(f)) {
		fprintf(stderr, "probe: %s: write failed\n", argv[3]);
		return 1;
	}
	return 0;
}

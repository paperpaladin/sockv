/*
 * probe - the oracle's two purpose-built tools.
 *
 *   probe emit CASE FILE   write a netlink reply to FILE: one well-formed
 *                          case per shape sockv must render, and one per way
 *                          the record stream can lie about its own lengths.
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
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

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

int main(int argc, char **argv)
{
	FILE *f;
	int r;

	if (argc != 4 || strcmp(argv[1], "emit")) {
		fprintf(stderr, "usage: %s emit CASE FILE\n", argv[0]);
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

#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <strings.h>

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>

#define MAX 65536
#define SA struct sockaddr
#define close closesocket

#include "tx_debug.h"

#define log_enter EnterCriticalSection(&logCriticalSection)
#define log_leave LeaveCriticalSection(&logCriticalSection)

#ifndef LOG_DEBUG
int log_tag_putlog(const char *tag, const char *fmt, ...);
#define LOG_DEBUG(fmt, args...)   do { log_enter; log_tag_putlog("D", fmt, ##args); log_leave; } while (0)
#endif

#ifndef LOG_VERBOSE
#define LOG_VERBOSE(fmt, args...) do { log_enter; log_tag_putlog("V", fmt, ##args); log_leave; } while (0)
#endif

struct tls_header {
    uint8_t type;
    uint8_t major;
    uint8_t minor;
    uint16_t length;
};

#define HANDSHAKE_TYPE 22

#define TAG_SNI        0
#define TAG_SESSION_TICKET 35

#define HANDSHAKE_TYPE_CLIENT_HELLO         1
#define HANDSHAKE_TYPE_SERVER_HELLO         2
#define HANDSHAKE_TYPE_CERTIFICATE         11
#define HANDSHAKE_TYPE_KEY_EXCHAGE         12
#define HANDSHAKE_TYPE_SERVER_HELLO_DONE   14

static int PORT = 4430;
static int ipv6only = 0;

static int YOUR_PORT = 4430;
static char YOUR_PORT_TEXT[64] = "4430";
static char YOUR_DOMAIN[256] = "app.yrli.bid";
static char YOUR_ADDRESS[256] = "100.42.78.149";

static int nentry = 0;
static int half_open_count = 0;
static int threading_count = 0;
static struct in_addr6 entry_points[256] = {};

struct connection_t {
	int fd;
	time_t time_created;
};

static CRITICAL_SECTION CriticalSection; 
static CRITICAL_SECTION logCriticalSection; 
static struct connection_t remote_connections[256] = {};

static char addrbuf[128];
#define ntop6(d) _ntop6(&d)
static char *_ntop6(const void *ptr)
{
	int i, n;
	int zero = 0;
	int maxoff = 0;
	int maxzero = 0;
	const uint16_t *p = (uint16_t *)ptr;

	char *strptr = addrbuf;

	for (i = 0; i < 8; i++) {
		if (p[i] == 0) {
			zero ++;
		}

		if (p[i] && zero > maxzero) {
			maxoff = i - zero;
			maxzero = zero;
		}
		
		if (p[i] != 0) {
			zero = 0;
		}
	}

	if (maxzero < 2) {
		for (i = 0; i < 8; i++) {
			n = sprintf(strptr, "%x:", ntohs(p[i]));
			strptr += n;
		}
		strptr[-1] = 0;
		return addrbuf;
	}

	if (maxoff == 0) {
		n = sprintf(strptr, ":");
		strptr += n;
	}

	for (i = 0; i < 8; i++) {
		if (i < maxoff) {
			n = sprintf(strptr, "%x:", ntohs(p[i]));
			strptr += n;
		} else if (i >= maxoff + maxzero) {
			n = sprintf(strptr, ":%x", ntohs(p[i]));
			strptr += n;
		}
	}

	if (maxoff + maxzero == 8) {
		n = sprintf(strptr, ":");
		strptr += n;
	}

	return addrbuf;
}

static int inet_pton(int family, const char *domain, void *ptr)
{
	assert(0);
	return 0;
}

int read_flush(int fd, void *buf, size_t count)
{
    int rc = 0;
    int process = 0;
    uint8_t *ptr = (uint8_t*)buf;

    while (process < count) {
        rc = recv(fd, ptr + process, count - process, 0);
        if (rc == -1) break;
        if (rc == 0) break;
        process += rc;
    }

    return process == 0? rc: process;
}

int write_flush(int fd, void *buf, size_t count)
{
    int rc = 0;
    int process = 0;
    uint8_t *ptr = (uint8_t*)buf;

    while (process < count) {
        rc = send(fd, ptr + process, count - process, 0);
        if (rc == -1) break;
        if (rc == 0) break;
        process += rc;
    }

    return process == 0? rc: process;
}

int pipling(int connfd, int remotefd)
{
    char buff[65536];
    size_t len = recv(connfd, buff, sizeof(buff), 0);
    // fprintf(stderr, "pipling %d -> %d %d\n", connfd, remotefd, len);
    if (len == -1) return -1;
    if (len == 0) return 0;
    return write_flush(remotefd, buff, len);
}

static const char *inet_4to6(void *v6ptr, const void *v4ptr)
{
    uint8_t *v4 = (uint8_t *)v4ptr;
    uint8_t *v6 = (uint8_t *)v6ptr;

    memset(v6, 0, 10);
    v6[10] = 0xff;
    v6[11] = 0xff;

    v6[12] = v4[0];
    v6[13] = v4[1];
    v6[14] = v4[2];
    v6[15] = v4[3];
    return "";
}

int setup_remote(struct sockaddr_in6 *cli, char *hostname)
{
    int i;
    int rc = -1;
    int remotefd = -1;
	u_long blocking = 0;
	u_long nonblocking = 1;
	struct connection_t *conn = NULL;

	EnterCriticalSection(&CriticalSection);

	threading_count++;
	for (i = 0; i < nentry; i++) {
		conn = &remote_connections[i];
		if (conn->time_created != 0 && 
				conn->time_created + 10 < time(NULL)) {
			conn->time_created = 0;
			close(conn->fd);
			conn->fd = -1;
			half_open_count--;
		}
	}

	for (i = 0; i < nentry; i++) {
		conn = &remote_connections[i];
		if (conn->time_created != 0) {
			continue;
		}

		remotefd = socket(AF_INET6, SOCK_STREAM, 0);
		ioctlsocket(remotefd, FIONBIO, &nonblocking);
		rc = setsockopt(remotefd, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&ipv6only, sizeof(ipv6only) );

		cli->sin6_addr = entry_points[i];
		// inet_4to6(&cli->sin6_addr, &entry_points[i]);
		rc = connect(remotefd, (struct sockaddr *)cli, sizeof(*cli));
		if (rc == 0 || (rc == -1 && WSAGetLastError() == WSAEINPROGRESS) || (rc == -1 && WSAGetLastError() == WSAEWOULDBLOCK)) {
			conn->time_created = time(NULL);
			conn->fd = remotefd;
			half_open_count++;
			continue;
		}

		LOG_DEBUG("connect code=%d\n", WSAGetLastError());
		close(remotefd);
		remotefd = -1;
	}

	int maxfd = -1, nready;
	FD_SET readfds, writefds, exceptionfds;

	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	FD_ZERO(&exceptionfds);

	remotefd = -1;
	for (i = 0; i < nentry; i++) {
		conn = &remote_connections[i];
		if (conn->time_created) {
			FD_SET(conn->fd, &readfds);
			FD_SET(conn->fd, &writefds);
			FD_SET(conn->fd, &exceptionfds);
			maxfd = maxfd < conn->fd? conn->fd: maxfd;
		}
	}

	int threadfd = -1;

	/* if (threading_count > half_open_count) */
	{
		threadfd = socket(AF_INET6, SOCK_STREAM, 0);
		rc = setsockopt(remotefd, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&ipv6only, sizeof(ipv6only) );

		// inet_4to6(&cli->sin6_addr, &entry_points[0]);
		cli->sin6_addr = entry_points[0];
		ioctlsocket(remotefd, FIONBIO, &nonblocking);
		rc = connect(threadfd, (struct sockaddr *)cli, sizeof(*cli));

		if (rc == 0 || (rc == -1 && WSAGetLastError() == WSAEINPROGRESS) || (rc == -1 && WSAGetLastError() == WSAEWOULDBLOCK)) {
			FD_SET(threadfd, &readfds);
			FD_SET(threadfd, &writefds);
			FD_SET(threadfd, &exceptionfds);
			maxfd = maxfd < threadfd? threadfd: maxfd;
		} else {
			close(threadfd);
			threadfd = -1;
		}
	}

	struct timeval timeo = {10, 10};
	LeaveCriticalSection(&CriticalSection);
	nready = select(maxfd + 1, &readfds, &writefds, &exceptionfds, &timeo);
	EnterCriticalSection(&CriticalSection);
	LOG_DEBUG("select return %d", nready);

	if (nready > 0) {
		for (i = 0; i < nentry; i++) {
			conn = &remote_connections[i];
			if (conn->time_created == 0) continue;
			if (FD_ISSET(conn->fd, &exceptionfds)) {
				int errNo = 0;
				int len = sizeof(errNo);
				getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, (char*)&errNo, &len);
				LOG_DEBUG("connect is failure: %d %s %d\n", conn->fd, ntop6(entry_points[i]), errNo);
			    half_open_count--;
				conn->time_created = 0;
				close(conn->fd);
				conn->fd = -1;
			} else if (FD_ISSET(conn->fd, &readfds)) {
				LOG_DEBUG("connect is closed: %d %s\n", conn->fd, ntop6(entry_points[i]));
			    half_open_count--;
				conn->time_created = 0;
				close(conn->fd);
				conn->fd = -1;
			} else if (FD_ISSET(conn->fd, &writefds)) {
				LOG_DEBUG("connect is ok: %d %s\n", conn->fd, ntop6(entry_points[i]));
			    half_open_count--;
				remotefd = conn->fd;
				conn->time_created = 0;
				conn->fd = -1;
				ioctlsocket(remotefd, FIONBIO, &blocking);
				break;
			}
		}
	}

	if (threadfd != -1) {
		if (remotefd == -1) {
			struct timeval timeo = {10, 10};
			FD_ZERO(&readfds); FD_SET(threadfd, &readfds);
			FD_ZERO(&writefds); FD_SET(threadfd, &writefds);
			FD_ZERO(&exceptionfds); FD_SET(threadfd, &exceptionfds);
			LeaveCriticalSection(&CriticalSection);
			nready = select(threadfd + 1, &readfds, &writefds, &exceptionfds, &timeo);
			EnterCriticalSection(&CriticalSection);

			if (FD_ISSET(threadfd, &exceptionfds)) {
				close(threadfd);
				threadfd = -1;
			} else if (FD_ISSET(threadfd, &readfds)) {
				close(threadfd);
				threadfd = -1;
			} else if (FD_ISSET(threadfd, &writefds)) {
				ioctlsocket(threadfd, FIONBIO, &blocking);
				remotefd = threadfd;
				threadfd = -1;
			}
		}

		if (threadfd != -1) {
			close(threadfd);
		}
	}

	threading_count--;
	LeaveCriticalSection(&CriticalSection);

	LOG_DEBUG("remote_connections %d", remotefd);
    return remotefd;
}

char * to_binary(uint8_t data[], size_t len, char *buf, size_t size)
{
    char *ptr = buf;
	char map[] = "0123456789abcdef";

	if (len == -1) return ptr;
    while (len > 0 && size > 3) {
		*ptr++ = map[(*data & 0xf0) >> 4];
		*ptr++ = map[(*data & 0xf)];
		*ptr++ = ' ';

		 data++, len--, size -= 3;
	}

	if (size) *ptr = 0;
	return buf;
}

char * get_sni_name(uint8_t *snibuff, size_t len, char *hostname)
{
    int i;
    int length;
    uint8_t *p = snibuff;

    if (*p != HANDSHAKE_TYPE_CLIENT_HELLO) {
        LOG_VERBOSE("bad\n");
        return NULL;
    }

    int type = *p++;
    LOG_VERBOSE("type: %x\n", type);
    length = p[2]|(p[1]<<8)|(p[0]<<16); p+=3;
    LOG_VERBOSE("length: %d\n", length);
    LOG_VERBOSE("version: %x.%x\n", p[0], p[1]);
    p += 2; // version;
            //
    p += 32; //random;
    LOG_VERBOSE("session id length: %d\n", *p);
    p += *p;
    p++;
    int cipher_suite_length = p[1]|(p[0]<<8); p+=2;
    LOG_VERBOSE("cipher_suite_length: %d\n", cipher_suite_length);
    p += cipher_suite_length;
    int compress_method_len = *p++;
    LOG_VERBOSE("compress_method_len: %d\n", compress_method_len);
    p += compress_method_len;
    int extention_length = p[1]|(p[0]<<8); p+=2;
    LOG_VERBOSE("extention_lengh: %d\n", extention_length);
    const uint8_t *limit = p + extention_length;

    *hostname = 0;
    while (p < limit) {
        uint16_t tag = p[1]|(p[0]<<8);
        uint16_t len = p[3]|(p[2]<<8);
        LOG_VERBOSE("ext tag: %d %d\n", tag, len);
        if (tag == TAG_SNI) {
            const uint8_t *sni = (p + 4);
            assert (sni[2] == 0);
            uint16_t list_name_len = sni[1]|(sni[0] << 8);
            uint16_t fqdn_name_len = sni[4]|(sni[3] << 8);
            assert (fqdn_name_len + 3 == list_name_len);
			LOG_VERBOSE("fqdn_name_len: %d\n", fqdn_name_len);
            memcpy(hostname, sni + 5, fqdn_name_len);
            hostname[fqdn_name_len] = 0;

#if 0
            uint8_t *lockm = (uint8_t*)(sni + 5);
            for (i = 0; i < fqdn_name_len; i++) lockm[i] ^= 0xf;
#endif
        }
        p += len;
        p += 4;
    }

    return hostname;
}
static int is_ssl_handshake(char *snibuff, size_t len)
{
    char hostname[128];
    struct tls_header header;

    if (len < 5) {
        return 0;
    }

    header.type = snibuff[0];
    header.major = snibuff[1];
    header.major = snibuff[2];
    memcpy(&header.length, &snibuff[3], 2);
    header.length = htons(header.length);

    if (header.type != HANDSHAKE_TYPE) {
        return 0;
    }

    if (header.length + 5 >= 4096) {
        LOG_DEBUG("len: %d\n", header.length);
        return 0;
    }

    if (header.length + 5 <  len) {
        LOG_DEBUG("data too short: expect %d but %d", header.length + 5, len);
        return 0;
    }

    get_sni_name(snibuff + 5, header.length, hostname);
    if (*hostname == 0) {
        return 0;
    }

    return 1;
}

int rewind_client_hello(uint8_t *snibuff, size_t length)
{
    int i;
    int mylength = 0;
    uint8_t hold[4096];
    uint8_t *p = snibuff + 5;
    uint8_t *dest = hold + 5;

    memcpy(hold, snibuff, 5);
    if (*p != HANDSHAKE_TYPE_CLIENT_HELLO) {
        LOG_VERBOSE("bad\n");
        return 0;
    }

    *dest++ = *p++;

    uint8_t *lengthp = dest;
    mylength = p[2]|(p[1]<<8)|(p[0]<<16);
    dest += 3;
    p += 3;

    dest[0] = p[0]; dest[1] = p[1];
    dest += 2;
    p += 2; // version;

    memcpy(dest, p, 32);
    dest += 32;
    p += 32; //random;

    dest[0] = p[0]; //session id length
    memcpy(&dest[1], &p[1], *p);
    dest += *p;
    dest++;

    p += *p;
    p++;

    int cipher_suite_length = p[1]|(p[0]<<8);
    dest[0] = p[0];
    dest[1] = p[1];
    dest+=2;
    p+=2;

    memcpy(dest, p, cipher_suite_length);
    dest += cipher_suite_length;
    p += cipher_suite_length;

    int compress_method_len = *p;
    *dest++ = *p++;

    memcpy(dest, p, compress_method_len);
    dest += compress_method_len;
    p += compress_method_len;

    int extention_length = p[1]|(p[0]<<8);
    uint8_t *extention_lengthp = dest;
    dest += 2;
    p += 2;

    const uint8_t *limit = p + extention_length;

    char hostname[256] = "";
    while (p < limit) {
        uint16_t tag = p[1]|(p[0]<<8);
        uint16_t len = p[3]|(p[2]<<8);
        LOG_VERBOSE("ext tag: %d %d\n", tag, len);
        uint16_t fqdn_name_len = 0;

        if (tag == TAG_SNI) {
            const uint8_t *sni = (p + 4);
            assert (sni[2] == 0);
            uint16_t list_name_len = sni[1]|(sni[0] << 8);
            fqdn_name_len = sni[4]|(sni[3] << 8);
            assert (fqdn_name_len + 3 == list_name_len);
            memcpy(hostname, sni + 5, fqdn_name_len);
            hostname[fqdn_name_len] = 0;
        }

        if (tag != TAG_SNI) {
            memcpy(dest, p, len + 4);
            dest += len;
            dest += 4;
        } else {
            dest[0] = 0; dest[1] = 0;
            dest[2] = 0; dest[3] = 0;
            size_t namelen = strlen(YOUR_DOMAIN);

            strcpy(dest + 4 + 5, YOUR_DOMAIN);
            dest[4 + 4] = namelen;
            dest[4 + 3] = (namelen >> 8);
            dest[4 + 2] = 0;
            dest[4 + 1] = (namelen + 3);
            dest[4 + 0] = (namelen + 3) >> 8;
            dest[3] = namelen + 5;
            dest[2] = (namelen + 5) >> 8;

            // assert(memcmp(dest, p, len + 4) == 0);
            dest += (namelen + 4 + 5);

#if 1
            dest[0] = TAG_SESSION_TICKET >> 8;
            dest[1] = TAG_SESSION_TICKET;
            dest[2] = fqdn_name_len >> 8;
            dest[3] = fqdn_name_len;
            memcpy(dest + 4, hostname, fqdn_name_len);
            for (i = 0; i < fqdn_name_len; i++) dest[i + 4] ^= 0xf;
            dest += (4 + fqdn_name_len);
            // (tag == TAG_SESSION_TICKET)
#endif
        }

        p += len;
        p += 4;
    }

    int extlen = (dest - extention_lengthp - 2);
    extention_lengthp[0] = extlen >> 8;
    extention_lengthp[1] = extlen;
    LOG_VERBOSE("extlen: %d %d\n", extlen, extention_length);

    int newlen = dest - lengthp - 3;
    lengthp[0] = newlen >> 16;
    lengthp[1] = newlen >> 8;
    lengthp[2] = newlen;
    LOG_VERBOSE("newlen: %d %d\n", newlen, mylength);

    memcpy(hold, snibuff, 5);
    int fulllength = (dest - hold - 5);
    hold[3] = fulllength >> 8;
    hold[4] = fulllength;

    int oldlen = (snibuff[3] << 8) | snibuff[4];
    LOG_VERBOSE("fulllen: %d %d %ld\n", fulllength, oldlen, length);

    memcpy(snibuff, hold, dest - hold);
    return dest - hold;
}

void func(int connfd)
{
    int rc;
    int n, l, i;
    fd_set test;
	char tmp[4096];
    uint8_t snibuff[4096];
    int remotefd = -1, newlen = 8;

#if 0
    struct timeval tv;
    tv.tv_sec = 30;  /* 30 Secs Timeout */
    int ret = setsockopt(connfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    assert(ret == 0);
#endif

    l = recv(connfd, snibuff, sizeof(snibuff), 0);
	LOG_DEBUG("fd %d byte[%d] %s", connfd, l, to_binary(snibuff, l, tmp, sizeof(tmp)));
    int port = snibuff[2] << 8|snibuff[3];
    LOG_DEBUG("port %d", port);
    // 04 01 00 50 00 00 00 01 00 77 77 77 2e 74 65 73 74 2d 69 70 76 36 2e 63 6f 6d 00 
    if (l < 9 || snibuff[0] != 0x04 || snibuff[1] != 0x01) {
		if (is_ssl_handshake(snibuff, l)) {
			newlen = l;
			goto found_sni;
		}
        close(connfd);
        return;
    }

    int pos = 8;
    // skip ident
    while (pos < l && snibuff[pos++] != 0);
    if (snibuff[4] == 0 && snibuff[5] == 0 && snibuff[6] == 0) {
        LOG_DEBUG(" domain %s", snibuff + pos);
        while (pos < l && snibuff[pos++] != 0);
    }

    assert(pos == l);

	int nbytes;
    char hostname[128];
    struct sockaddr_in6 cli;

	newlen = 8;
    snibuff[0] = 0;
    snibuff[1] = 90;
    rc = send(connfd, snibuff, newlen, 0);
    assert(rc == newlen);

    newlen = recv(connfd, snibuff, sizeof(snibuff), 0);
	if (!is_ssl_handshake(snibuff, newlen)) {
	    LOG_DEBUG("is not ssl\n");
		return;
	}

found_sni:
    get_sni_name(snibuff + 5, newlen -5, hostname);
	LOG_DEBUG("source hostname: %s %d", hostname, newlen);

    newlen = rewind_client_hello(snibuff, newlen);
    get_sni_name(snibuff + 5, newlen -5, hostname);

    cli.sin6_family = AF_INET6;
    cli.sin6_port   = htons(YOUR_PORT);
    // if (port == 443) cli.sin_port   = htons(4430);

	LOG_DEBUG("target hostname: %s %d", hostname, newlen);
    remotefd = setup_remote(&cli, YOUR_ADDRESS);

    if (remotefd == -1) {
		LOG_DEBUG("setup_remote failure: %s", YOUR_ADDRESS);
        close(connfd);
        return;
    }

	nbytes = send(remotefd, snibuff, newlen, 0);
	assert(nbytes == newlen);

    int stat = 0;
    int maxfd = connfd > remotefd? connfd: remotefd;

    do {
        FD_ZERO(&test);
        if (~stat & 1) FD_SET(connfd, &test);
        if (~stat & 2) FD_SET(remotefd, &test);
        assert(stat != 3);

        struct timeval timeo = {23, 5};
        n = select(maxfd + 1, &test, NULL, NULL, &timeo);
        if (n == 0) break;
        assert(n > 0);

        if (FD_ISSET(connfd, &test)) {
            // if (push(connfd, remotefd) <= 0) stat |= 1;
            if (pipling(connfd, remotefd) <= 0) stat |= 1;
        }

        if (FD_ISSET(remotefd, &test)) {
            // if (pull(remotefd, connfd) <= 0) stat |= 2;
            if (pipling(remotefd, connfd) <= 0) stat |= 2;
        }

		if (stat != 0 || n  <= 0)
			LOG_DEBUG("stat=%x n=%d", stat, n);
    } while (n > 0 && stat != 3);

    LOG_DEBUG("release connection");
    close(remotefd);
    close(connfd);
    return;
}

void call_func(void *arg)
{
     int *fdptr = (int *)arg;
     int fd = *fdptr;

	 *fdptr = -1;

	if (fd != -1) func(fd);
    LOG_DEBUG("thread exit");
	_endthread();
}

void append_entry_point(struct in_addr6 *newaddr)
{
	for (int i = 0; i < nentry; i++) {
		if (memcmp(newaddr, &entry_points[i], sizeof(*newaddr)) == 0) return;
	}

	if (nentry < 256) {
		entry_points[nentry] = *newaddr;
		nentry++;
	}
}

static void load_ipv6_domain(const char *mydomain)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int sfd, s;
	struct sockaddr_storage peer_addr;
	socklen_t peer_addr_len;
	ssize_t nread;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
	hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
	hints.ai_protocol = 0;          /* Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	s = getaddrinfo(NULL, mydomain, &hints, &result);
	if (s != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		return;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		struct sockaddr_in6 *inp6 = (struct sockaddr_in6*)rp->ai_addr;
		if (rp->ai_family == AF_INET6) {
			fprintf(stderr, "getaddrinfo: %s\n", ntop6(inp6->sin6_addr));
			append_entry_point(&inp6->sin6_addr);
		}
	}

	freeaddrinfo(result);           /* No longer needed */
}

void add_entry_points(const char *domain)
{
	int isipv6 = 0;
	int isdomain = 0;
	const char *ptr = domain;

	int ndot = 0;
	int ncolon = 0;
	int nalpha = 0;
	int left = 0, right = 0;
	int port_suffixes = 0;
	const char *pot = NULL;

	while (*ptr && port_suffixes == 0) {
		switch(*ptr) {
			case ':':
				pot = ptr + 1;
				port_suffixes = 1;
				while (*pot) {
					if (!isdigit(*pot)) {
						port_suffixes = 0;
						break;
					}
					pot++;
				}
				ncolon++;
				break;

			case '[':
				left ++;
				break;

			case ']':
				right ++;
				break;

			case '.':
				ndot++;
				break;

			default:
				if (isalpha(*ptr))
					nalpha++;
				break;
		}

		ptr++;
	}

	/*
	 * FORMAT:
	 * www.baidu.com:8080
	 * [2002:aabb::1]:8080
	 * 192.168.1.1:8080
	 * 192.168.1.1
	 * www.baidu.com
	 * [2002:aabb::1]
	 * 2002:aabb::1
	 * :8080
	 * 8080
	 */

	/* do not support IPv6
	 * [2002:aabb::1]:8080
	 * [2002:aabb::1]
	 */
	if (left || right) {
		assert (left == 1 && right == 1);
		const char *p = domain;
		char newdomain[256];
		char *dtp = newdomain;

		while (*p != '[') p++;
		p++; // skip '['

		while (*p != ']') *dtp++ = *p++;
		*dtp = 0;

		struct in_addr6 addr6 = {};
		if (inet_pton(AF_INET6, newdomain, &addr6))
			append_entry_point(&addr6);
		return;
	}

	/* do not support IPv6
	 * 2002:aabb::1
	 */
	if (ncolon > 1) {
		struct in_addr6 addr6 = {};
		if (inet_pton(AF_INET6, domain, &addr6))
			append_entry_point(&addr6);
		return;
	}

	/*
	 * www.baidu.com:8080
	 * www.baidu.com
	 * 192.168.1.1:8080
	 * 192.168.1.1
	 * :8080
	 * 8080
	 */

	char mydomain[256] = {};

	if (port_suffixes) {
		strncpy(mydomain, domain, ptr - domain - 1);
	} else {
		strcpy(mydomain, domain);
	}

	LOG_DEBUG("domain: %s\n", mydomain);
	if (nalpha > 0) {
		struct hostent * ent = gethostbyname(mydomain);
		load_ipv6_domain(mydomain);
		if (ent == NULL) {
			return;
		}

		struct in_addr6 addr6 = {};
		struct in_addr **addr_list = (struct in_addr **)ent->h_addr_list;

		for (int i = 0; addr_list[i] != NULL; i++) {
			LOG_DEBUG("entry: %s ", inet_ntoa(*addr_list[i]));
			inet_4to6(&addr6, addr_list[i]);
			append_entry_point(&addr6);
		}

		LOG_DEBUG("NAME: %s %d %d", ent->h_name, ent->h_length, ent->h_addrtype);
		for (int i = 0; ent->h_aliases[i]; i++) {
			LOG_DEBUG("CNAME: %s", ent->h_aliases[i]);
		}

	} else if (ndot > 0) {
		struct in_addr addr = {};
		struct in_addr6 addr6 = {};
		addr.s_addr = inet_addr(mydomain);

		LOG_DEBUG("entry: %s ", inet_ntoa(addr));

		if (addr.s_addr != INADDR_NONE) {
			inet_4to6(&addr6, &addr);
			append_entry_point(&addr6);
		}
	}

	return ;
}

/*
 * sniproxy -s -l 4430 -p 443 -d app.yrli.bid
 * sniproxy -c -l 4430 -p 4430 -d app.yrli.bid 100.42.78.149
 */
void parse_argopt(int argc, char *argv[])
{
    int i;

    LOG_DEBUG("parse_argopt>");
    for (i = 1; i < argc; i++) {
		const char *optname = argv[i];
		if (strcmp(optname, "-p") == 0) {
			assert(i + 1 < argc);
			YOUR_PORT = atoi(argv[++i]);
				sprintf(YOUR_PORT_TEXT, "%d", YOUR_PORT);
		} else
		if (strcmp(optname, "-l") == 0) {
			assert(i + 1 < argc);
			PORT = atoi(argv[++i]);
		} else
		if (strcmp(optname, "-d") == 0) {
			assert(i + 1 < argc);
			strcpy(YOUR_DOMAIN, argv[++i]);
		} else
		if (*optname != '-') {
			strcpy(YOUR_ADDRESS, argv[i]);
			add_entry_points(argv[i]);
		}
    }
    LOG_DEBUG("<parse_argopt");

}

// Driver function
int main(int argc, char *argv[])
{
	WSADATA data;
    int sockfd, connfds[256], len;
    struct sockaddr_in6 servaddr, cli;

	WSAStartup(0x101, &data);
	InitializeCriticalSection(&logCriticalSection);
    parse_argopt(argc, argv);

	int nextfd = 0;
	memset(connfds, -1, sizeof(connfds));

    // socket create and verification
    sockfd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sockfd == -1) {
        LOG_DEBUG("socket creation failed...\n");
        exit(0);
    }
    else
        LOG_DEBUG("Socket successfully created..");
    bzero(&servaddr, sizeof(servaddr));

	setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&ipv6only, sizeof(ipv6only));

    // assign IP, PORT
    servaddr.sin6_family = AF_INET6;
    servaddr.sin6_port = htons(PORT);
	memset(&servaddr.sin6_addr, 0, sizeof(servaddr.sin6_addr));

    int enable = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&enable, sizeof(enable));

    // Binding newly created socket to given IP and verification
    if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) {
        LOG_DEBUG("socket bind failed...\n");
        exit(0);
    }
    else
        LOG_DEBUG("Socket successfully binded..");

    // Now server is ready to listen and verification
    if ((listen(sockfd, 5)) != 0) {
        LOG_DEBUG("Listen failed...\n");
        exit(0);
    }
    else
        LOG_DEBUG("Server listening..");
    len = sizeof(cli);

	InitializeCriticalSection(&CriticalSection);

    do {
        len = sizeof(cli);
        // Accept the data packet from client and verification
		assert(connfds[nextfd] == -1);
        connfds[nextfd] = accept(sockfd, (SA*)&cli, &len);
        if (connfds[nextfd] < 0) {
            LOG_DEBUG("server accept failed...\n");
			assert(0);
            exit(0);
        }
        else
            LOG_DEBUG("server accept the client... fd=%d", connfds[nextfd]);

#if 0
        if (fork() == 0) {close(sockfd); func(connfd); exit(0); }
        close(connfd);
#endif
		uintptr_t thread = _beginthread(call_func, 0, &connfds[nextfd]);
		if (thread == -1) {
			if (connfds[nextfd] != -1) {
				LOG_DEBUG("close connfd = %d", connfds[nextfd]);
				close(connfds[nextfd]);
				connfds[nextfd] = -1;
			}
			assert(0);
		} else {
			LOG_DEBUG("connfd = %d", connfds[nextfd]);
			nextfd = ((nextfd + 1) & 0xff);
		}

        // Function for chatting between client and server
    } while (1);

    // After chatting close the socket
    close(sockfd);
    return 0;
}

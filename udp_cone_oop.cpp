#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#ifdef WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <netdb.h>
#define closesocket close
#endif

#include "txall.h"

#include <txall.h>
#define log_set_lastbuf(x, y)
#define DELAY_DUMP(expr) 					\
    do { 							\
	static int _match_##__LINE__ = 0; 			\
	static int _lock_guard_##__LINE__ = 0; 			\
	if (_lock_guard_##__LINE__ == _lock_guard_stamp) { 	\
	    _match_##__LINE__++; 				\
	    break; 						\
	} 							\
	int match = _match_##__LINE__;				\
	_match_##__LINE__ = 0;					\
	_lock_guard_##__LINE__ = _lock_guard_stamp; 		\
	expr; 							\
    } while ( 0 )

static uint32_t _last_rx = 0;
static uint32_t _last_tx = 0;
static uint32_t _total_tx = 0;
static uint32_t _total_rx = 0;
static time_t _last_foobar = 0;
static int _lock_guard_stamp = 0;

// tx_getticks
static uint32_t _last_rx_tick = 0;
static uint32_t _last_tx_tick = 0;
static uint32_t _first_rx_tick = 0;
static uint32_t _first_tx_tick = 0;

struct timer_task {
	tx_task_t task; 
	tx_timer_t timer; 
};

struct udp_exchange_context {
	int sockfd;
	int port;
	int dport;
	int group;
	tx_aiocb file;
	tx_task_t task;
};

#define HASH_MASK 0xFFFF

typedef struct _nat_conntrack_t {
	int sockfd;
	int mainfd;
	int group;
	int hash_idx;
	time_t last_alive;
	struct sockaddr_in6 source;
	struct sockaddr_in6 target;

	int port;
	in6_addr address;
	tx_aiocb file;
	tx_task_t task;
	LIST_ENTRY(_nat_conntrack_t) entry;
} nat_conntrack_t;

static nat_conntrack_t *_session_last[HASH_MASK + 1] = {};
static LIST_HEAD(nat_conntrack_q, _nat_conntrack_t) _session_header = LIST_HEAD_INITIALIZER(_session_header);

typedef struct _exchange_context_t {
	int port_origin;
	int port_mapping;
	int sockfd;
	int group;
	LIST_ENTRY(_exchange_context_t) entry;
};
static LIST_HEAD(_exchange_context_q, _exchange_context_t) _exchange_header = LIST_HEAD_INITIALIZER(_exchange_header);
#define ALLOC_NEW(type)  (type *)calloc(1, sizeof(type))

static int install_maping(int port, int dport, int sockfd, int group)
{
	_exchange_context_t *item, *next;

	LIST_FOREACH_SAFE(item, &_exchange_header, entry, next) {
		if (item->group == group &&
				item->port_mapping == htons(dport)) return -1;
	}

	_exchange_context_t * ctx = ALLOC_NEW(_exchange_context_t);

	if (ctx != NULL) {
		ctx->port_origin = htons(port);
		ctx->port_mapping = htons(dport);
		ctx->sockfd = sockfd;
		ctx->group = group;
		LIST_INSERT_HEAD(&_exchange_header, ctx, entry);
	}

	return 0;
}

static int pick_from_port(int port, int group)
{
	_exchange_context_t *item, *next;

	LIST_FOREACH_SAFE(item, &_exchange_header, entry, next) {
		if (group == item->group &&
				item->port_mapping == port) return item->sockfd;
	}

	return -1;
}

static inline unsigned int get_connection_match_hash(const void *src, const void *dst, uint16_t sport, uint16_t dport)
{
	uint32_t hash = 0, hashs[4];
	uint32_t *srcp = (uint32_t *)src;
	uint32_t *dstp = (uint32_t *)dst;

	hashs[0] = srcp[0] ^ dstp[0];
	hashs[1] = srcp[1] ^ dstp[1];
	hashs[2] = srcp[2] ^ dstp[2];
	hashs[3] = srcp[3] ^ dstp[3];

	hashs[0] = (hashs[0] ^ hashs[1]);
	hashs[2] = (hashs[2] ^ hashs[3]);

	hash = (hashs[0] ^ hashs[2]) ^ sport ^ dport;
	return ((hash >> 16)^ hash) & HASH_MASK;
}

static time_t _session_gc_time = 0;
static int conngc_session(time_t now, nat_conntrack_t *skip)
{
	int timeout = 30;
	if (now < _session_gc_time || now > _session_gc_time + 30) {
		nat_conntrack_t *item, *next;

		_session_gc_time = now;
		LIST_FOREACH_SAFE(item, &_session_header, entry, next) {
			if (item == skip) {
				continue;
			}

			if ((item->last_alive > now) ||
					(item->last_alive + timeout < now)) {
				DELAY_DUMP(LOG_DEBUG("free datagram connection: %p, %d\n", skip, match));
				int hash_idx = item->hash_idx;

				if (item == _session_last[hash_idx]) {
					_session_last[hash_idx] = NULL;
				}

				tx_aiocb_fini(&item->file);
				tx_task_drop(&item->task);
				close(item->sockfd);

				LIST_REMOVE(item, entry);
				free(item);
			}
		}
	}

	return 0;
}

static nat_conntrack_t * lookup_session(struct sockaddr_in6 *from, int group)
{
	nat_conntrack_t *item;
	char addr_buf[16] = {0};

	int hash_idx0 = get_connection_match_hash(&from->sin6_addr, addr_buf, 0, 0);

	item = _session_last[hash_idx0];
	if (item != NULL) {
		if ((item->source.sin6_port == from->sin6_port) && 
				item->group == group &&
				IN6_ARE_ADDR_EQUAL(&item->source.sin6_addr, &from->sin6_addr)) {
			item->last_alive = time(NULL);
			return item;
		}
	}

	LIST_FOREACH(item, &_session_header, entry) {
		if ((item->source.sin6_port == from->sin6_port) && 
				item->group == group &&
				IN6_ARE_ADDR_EQUAL(&item->source.sin6_addr, &from->sin6_addr)) {
			item->last_alive = time(NULL);
			assert(hash_idx0 == item->hash_idx);
			_session_last[hash_idx0] = item;
			return item;
		}
	}

	return NULL;
}

#define NONZERO(x) (x > 1? x: 1)
static uint64_t _tx_bytes = 0;
static uint64_t _rx_bytes = 0;
static char _last_log[4096] = {};

static void showbar(const char *title, size_t count)
{
	time_t foobar = 0;
	time_t delta  = _last_foobar ^ time(&foobar);

	if ((delta >> 1) == 0) {
		return;
	}

	int tx_rate = (_total_tx - _last_tx) * 1000 / NONZERO(_last_tx_tick - _first_tx_tick);
	int rx_rate = (_total_rx - _last_rx) * 1000 / NONZERO(_last_rx_tick - _first_rx_tick);

	_rx_bytes += (_total_rx - _last_rx);
	_tx_bytes += (_total_tx - _last_tx);

	LOG_INFO("%s len %d, rx/tx total: %ld/%ld rate: %d/%d ", title, count, _tx_bytes, _rx_bytes, tx_rate, rx_rate);
	LOG_INFO("%s", _last_log);
	_last_log[0] = 0;
	_first_tx_tick = _first_rx_tick = 0;
	// _first_rx_tick = _first_tx_tick = tx_getticks();

	_last_foobar = foobar;
	_last_tx = _total_tx;
	_last_rx = _total_rx;
}

static void update_timer(void *up)
{
	struct timer_task *ttp;
	ttp = (struct timer_task*)up;

	tx_timer_reset(&ttp->timer, 5000);
	log_set_lastbuf(NULL, 0);
	LOG_VERBOSE("update_timer %d\n", tx_ticks);
	showbar("showbar", 0);
	log_set_lastbuf(_last_log, sizeof(_last_log));

	conngc_session(time(NULL), NULL);
	_lock_guard_stamp++;
	return;
}


static int convert_from_ipv4(void *ipv6, const void *ipv4)
{
	unsigned *dest = (unsigned *)ipv6;
	const unsigned *from = (const unsigned *)ipv4;

	dest[0] = dest[1] = dest[2] = 0;
	dest[2] = htonl(0xffff);
	dest[3] = from[0];

	return 0;
}

static int udp6_recvmsg(int fd, void *buf, size_t len, int flags, struct sockaddr_in6 *from, struct sockaddr_in6 *dst)
{
	int count;
	struct iovec iovec[1];
	struct msghdr msg;
	char msg_control[1024];

	iovec[0].iov_base = buf;
	iovec[0].iov_len  = len;

	msg.msg_flags = 0;
	msg.msg_name = from;
	msg.msg_namelen = sizeof(*from);

	msg.msg_iov = iovec;
	msg.msg_iovlen = sizeof(iovec) / sizeof(*iovec);

	msg.msg_control = msg_control;
	msg.msg_controllen = sizeof(msg_control);

	count = recvmsg(fd, &msg, flags);

	if (count > 0) {
		struct cmsghdr *cmsg;
		for(cmsg = CMSG_FIRSTHDR(&msg);
				cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
				struct in_pktinfo *info = (struct in_pktinfo*)CMSG_DATA(cmsg);
				LOG_VERBOSE("message received on address %s\n", inet_ntoa(info->ipi_addr));
				convert_from_ipv4(&dst->sin6_addr, &info->ipi_addr);
			}

			if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
				char b[63];
				struct in6_pktinfo *info = (struct in6_pktinfo*)CMSG_DATA(cmsg);
				LOG_VERBOSE("message received on address %s\n", inet_ntop(AF_INET6, &info->ipi6_addr, b, sizeof(b)));
				dst->sin6_addr = info->ipi6_addr;
			}
		}
	}

	return count;
}

static int udp6_sendmsg(int fd, const void *buf, size_t len, int flags, const struct sockaddr_in6 *from, const struct sockaddr_in6 *dest)
{
	struct msghdr msg;
	struct iovec iovec[1];
	char msg_control[1024];

	iovec[0].iov_len  = len;
	iovec[0].iov_base = (void *)buf;

	msg.msg_flags = 0;
	msg.msg_name = (void *)dest;
	msg.msg_namelen = sizeof(*dest);

	msg.msg_iov = iovec;
	msg.msg_iovlen = sizeof(iovec) / sizeof(*iovec);

	msg.msg_control = msg_control;
	msg.msg_controllen = sizeof(msg_control);

	int cmsg_space = 0;
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	const int have_in6_pktinfo = 1, have_in_pktinfo = 0;

	if (have_in6_pktinfo && from) {
		struct in6_pktinfo in6_pktinfo = {};
		in6_pktinfo.ipi6_addr = from->sin6_addr;

		char b[63];
		LOG_VERBOSE("message send to address %s\n", inet_ntop(AF_INET6, &from->sin6_addr, b, sizeof(b)));

		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(in6_pktinfo));
		*(struct in6_pktinfo*)CMSG_DATA(cmsg) = in6_pktinfo;
		cmsg_space += CMSG_SPACE(sizeof(in6_pktinfo));
	}

	if (have_in_pktinfo && from) {
		struct in_pktinfo in_pktinfo = {};
		cmsg->cmsg_level = IPPROTO_IP;
		cmsg->cmsg_type = IP_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(in_pktinfo));
		*(struct in_pktinfo*)CMSG_DATA(cmsg) = in_pktinfo;
		cmsg_space += CMSG_SPACE(sizeof(in_pktinfo));
	}

	msg.msg_controllen = cmsg_space;

	return sendmsg(fd, &msg, flags);
}

enum {NONE, PING, PONG, LATEST};
static int ping_pong = 0;
static uint8_t prefix64[16] = {0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 127, 9, 9, 9};
static const uint8_t v4mapped[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 9, 9, 9};

static void do_udp_exchange_back(void *upp)
{
	int count;
	socklen_t in_len;
	char buf[2048];

	struct sockaddr_in6 in6addr;
	struct sockaddr * inaddr = (struct sockaddr *)&in6addr;
	nat_conntrack_t *up = (nat_conntrack_t *)upp;

	while (tx_readable(&up->file)) {
		in_len = sizeof(in6addr);
		count = recvfrom(up->sockfd, buf, sizeof(buf), MSG_DONTWAIT, inaddr, &in_len);
		tx_aincb_update(&up->file, count);

		if (count <= 0) {
			if (errno != EAGAIN)
				DELAY_DUMP(LOG_VERBOSE("recvfrom len %d, %d, strerr %s", count, errno, strerror(errno)));
			break;
		}

		int padding = 0;
		struct sockaddr_in6 dest = {.sin6_addr = up->address};
		struct sockaddr_in6 *test = &dest;

		if (memcmp(v4mapped, &in6addr.sin6_addr, 13) == 0) {
			memcpy(&dest.sin6_addr, prefix64, 16);
			char abuf[64];
			LOG_INFO("v4mapped match send to %s:%d\n", inet_ntop(AF_INET6, &dest.sin6_addr, abuf, sizeof(abuf)), htons(dest.sin6_port));

		} else if (ping_pong == PONG) {
			memcpy(buf + count, ((uint32_t *)&in6addr.sin6_addr) + 3, 4);
			memcpy(buf + count + 4, &in6addr.sin6_port, 2);
			memset(&dest.sin6_addr, 0, 16);
			padding = 6;
			test = NULL;

		} else if (ping_pong == PING) {
			uint32_t *troping = (uint32_t *)&dest.sin6_addr;
			memcpy(troping, prefix64, 16);
			memcpy(troping + 3, buf + count - 6, 4);
			memcpy(&dest.sin6_port, buf + count - 2, 2);
			padding = -6;

			if (IN6_IS_ADDR_V4MAPPED(&up->source.sin6_addr)) {
				convert_from_ipv4(&dest.sin6_addr, buf + count - 6);
			}

			up->mainfd = pick_from_port(dest.sin6_port, up->group);
		}

		count = udp6_sendmsg(up->mainfd, buf, count + padding, MSG_DONTWAIT, test, &up->source);
		if (count == -1 && errno != EAGAIN) {
			DELAY_DUMP(LOG_DEBUG("back sendto len %d, %d, strerr %s match %d", count, errno, strerror(errno), match));
		}

		if (count > 0) {
			if (!_first_tx_tick) _first_tx_tick = tx_getticks();
			_last_tx_tick = tx_getticks();
			_total_tx += count;
		}
	}

	tx_aincb_active(&up->file, &up->task);
	return;
}

static nat_conntrack_t * newconn_session(struct sockaddr_in6 *from, int group)
{
	int sockfd;
	int rcvbufsiz = 4096;

	time_t now;
	nat_conntrack_t *conn;

	now = time(NULL);

	conn = ALLOC_NEW(nat_conntrack_t);
	if (conn != NULL) {
		conn->last_alive = now;
		conn->source = *from;
		conn->target = *from;
		conn->group = group;
		memset(&conn->target.sin6_addr, 0xff, 12);
		memset(&conn->target.sin6_addr, 0, 10);

		sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
		TX_CHECK(sockfd != -1, "create udp socket failure");

		tx_setblockopt(sockfd, 0);
		// setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbufsiz, sizeof(rcvbufsiz));

		int sndbufsiz = 1638400;
		setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbufsiz, sizeof(sndbufsiz));
		conn->sockfd = sockfd;

		tx_loop_t *loop = tx_loop_default();
		tx_aiocb_init(&conn->file, loop, sockfd);
		tx_task_init(&conn->task, loop, do_udp_exchange_back, conn);

		tx_aincb_active(&conn->file, &conn->task);

		char addr_buf[16] = {0};
		conn->hash_idx = get_connection_match_hash(&from->sin6_addr, addr_buf, 0, 0);
		LIST_INSERT_HEAD(&_session_header, conn, entry);
		_session_last[conn->hash_idx] = conn;
	}

	conngc_session(now, conn);
	return conn;
}

static int _XOR_MASK_ = 0x5a;
static struct sockaddr_in6 router = {};

static int session_ping_data(nat_conntrack_t *session, char *buf, size_t len, struct sockaddr_in6 *dest)
{
	buf[0] ^= _XOR_MASK_;
	memcpy(buf + len, ((uint32_t *)&dest->sin6_addr) + 3, 4);
	memcpy(buf + len + 4, &dest->sin6_port, 2);

	dest->sin6_family = session->target.sin6_family;
	dest->sin6_port = session->target.sin6_port;
	dest->sin6_addr = session->target.sin6_addr;

	return len + 6;
}

static int session_pong_data(nat_conntrack_t *session, char *buf, size_t len, struct sockaddr_in6 *dest)
{
	dest->sin6_family = AF_INET6;

	uint32_t *troping = (uint32_t *)&dest->sin6_addr;
	troping[0] = troping[1] = 0; troping[2] = htonl(0xffff);
	memcpy(troping + 3, buf + len - 6, 4);
	memcpy(&dest->sin6_port, buf + len -2, 2);

	return len - 6;
}

static int session_wrap_data(nat_conntrack_t *session, char *buf, size_t len, struct sockaddr_in6 *dest)
{
	uint8_t * addr = (uint8_t *)&dest->sin6_addr;

	buf[0] ^= _XOR_MASK_;
	if (ping_pong == PING) {
		memcpy(buf + len, addr + 12, 4);
		memcpy(buf + len + 4, &dest->sin6_port, 2);
		return len + 6;
	} else if (ping_pong == PONG) {
		memcpy(&dest->sin6_port, buf + len - 2, 2);
		convert_from_ipv4(&dest->sin6_addr, buf + len - 6);
		return len - 6;
	}

	return 0;
}

static void do_udp_exchange_recv(void *upp)
{
	int count;
	socklen_t in_len;
	char buf[2048];
	nat_conntrack_t *session = NULL;

	struct sockaddr_in6 in6addr;
	struct sockaddr_in6 dest;
	struct sockaddr * inaddr = (struct sockaddr *)&in6addr;
	udp_exchange_context *up = (udp_exchange_context *)upp;

	while (tx_readable(&up->file)) {
		in_len = sizeof(in6addr);
		count = udp6_recvmsg(up->sockfd, buf, sizeof(buf), MSG_DONTWAIT, &in6addr, &dest);
		tx_aincb_update(&up->file, count);

		if (count <= 0) {
			if (errno != EAGAIN)
				LOG_VERBOSE("back recvfrom len %d, %d, strerr %s", count, errno, strerror(errno));
			break;
		}

		_total_rx += count;
		if (!_first_rx_tick) _first_rx_tick = tx_getticks();
		_last_rx_tick = tx_getticks();

		session = lookup_session(&in6addr, up->group);
		session = session? session: newconn_session(&in6addr, up->group);
		if (session == NULL) {
			LOG_DEBUG("session is NULL");
			continue;
		}

		session->mainfd = up->sockfd;
		dest.sin6_port = htons(up->dport);
		dest.sin6_family = AF_INET6;

		if (memcmp(prefix64, &dest.sin6_addr, 16) == 0) {
			char abuf[63];
			convert_from_ipv4(&dest.sin6_addr, prefix64 + 12);
			count = sendto(session->sockfd, buf, count, MSG_DONTWAIT, (struct sockaddr *)&dest, sizeof(dest));
			LOG_DEBUG("prefix64 match send to %s:%d ret=%d\n", inet_ntop(AF_INET6, &dest.sin6_addr, abuf, sizeof(abuf)), htons(dest.sin6_port), count);
			continue;
		}

		int datalen = session_wrap_data(session, buf, count, &dest);
		if (router.sin6_family == AF_INET6)
			memcpy(&dest, &router, sizeof(dest));

		count = sendto(session->sockfd, buf, datalen, MSG_DONTWAIT, (struct sockaddr *)&dest, sizeof(dest));
		if (count == -1) {
			DELAY_DUMP(LOG_DEBUG("sendto len %d, %d, strerr %s match %d", count, errno, strerror(errno), match));
		}
	}

	tx_aincb_active(&up->file, &up->task);
	return;
}

static void * udp_exchange_create(int port, int dport, int group)
{
	int sockfd;
	int error = -1;
	struct sockaddr_in6 in6addr;

	fprintf(stderr, "udp_exchange_create %d -> %d group %d\n", port, dport, group);
	sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
	TX_CHECK(sockfd != -1, "create udp socket failure");

	if (-1 == install_maping(port, dport, sockfd, group)) {
		fprintf(stderr, "install_maping %d -> %d failure\n", port, dport);
		closesocket(sockfd);
		return NULL;
	}

	tx_setblockopt(sockfd, 0);
	int rcvbufsiz = 4096;
	// setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbufsiz, sizeof(rcvbufsiz));
	int sndbufsiz = 1638400;
	setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbufsiz, sizeof(sndbufsiz));

	in6addr.sin6_family = AF_INET6;
	in6addr.sin6_port = htons(port);
	in6addr.sin6_addr = in6addr_loopback;
	in6addr.sin6_addr = in6addr_any;

#ifdef IP_TRANSPARENT
	int yes = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
	setsockopt(sockfd, IPPROTO_IP, IP_PKTINFO, &yes, sizeof(yes));
	setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &yes, sizeof(yes));
	setsockopt(sockfd, SOL_IP, IP_TRANSPARENT, &yes, sizeof(yes));
	if (ping_pong == PING)
	    setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes));
#endif

	error = bind(sockfd, (struct sockaddr *)&in6addr, sizeof(in6addr));
	TX_CHECK(error == 0, "bind udp socket failure");

	struct udp_exchange_context *up = NULL;

	up = new udp_exchange_context();
	tx_loop_t *loop = tx_loop_default();

	up->port  = port;
	up->group = group;
	up->dport  = dport;
	up->sockfd = sockfd;
	tx_aiocb_init(&up->file, loop, sockfd);
	tx_task_init(&up->task, loop, do_udp_exchange_recv, up);

	tx_aincb_active(&up->file, &up->task);

	return 0;
}

int main(int argc, char *argv[])
{
	int err;
	unsigned int last_tick = 0;
	struct timer_task tmtask;

#ifndef WIN32
	signal(SIGPIPE, SIG_IGN);
#endif

	tx_loop_t *loop = tx_loop_default();
	tx_poll_t *poll = tx_epoll_init(loop);
	tx_timer_ring *provider = tx_timer_ring_get(loop);
	tx_timer_init(&tmtask.timer, loop, &tmtask.task);

	tx_task_init(&tmtask.task, loop, update_timer, &tmtask);
	tx_timer_reset(&tmtask.timer, 500);

	if (getenv("PING"))
	    ping_pong = PING;
	else if (getenv("PONG"))
	    ping_pong = PONG;

	int group = 0;
	for (int i = 1; i < argc; i++) {
		int port, dport, match;
		if (strcmp(argv[i], "-x") == 0 && i + 1 < argc) {
			_XOR_MASK_ = atoi(argv[++i]);
			continue;
		} else
		if (strcmp(argv[i], "--ping") == 0) {
			ping_pong = PING;
			continue;
		} else
		if (strcmp(argv[i], "--pong") == 0) {
			ping_pong = PONG;
			continue;
		}

		if (strcmp(argv[i], "-g") == 0 && i + 1 < argc) {
			group++;
			continue;
		}

		if (strcmp(argv[i], "--pfx64") == 0 && i + 1 < argc) {
			if (inet_pton(AF_INET6, argv[++i], prefix64)) {
			}
			continue;
		}

		if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
			char tmp[64];
			if (sscanf(argv[++i], "[%[a-fA-F0-9.:]]:%d", tmp, &port) == 2) {
				fprintf(stderr, "ROUTE: %s %d\n", tmp, port);
				if (inet_pton(AF_INET6, tmp, &router.sin6_addr)) {
					router.sin6_family = AF_INET6;
					router.sin6_port = htons(port);
				}
			}
			continue;
		}

		match = sscanf(argv[i], "%d:%d", &port, &dport);
		switch (match) {
			case 1:
				assert (port >  0 && port < 65536);
				udp_exchange_create(port, port, group);
				break;

			case 2:
				assert (port >  0 && port < 65536);
				assert (dport >  0 && dport < 65536);
				udp_exchange_create(port, dport, group);
				break;

			default:
				fprintf(stderr, "argument is invalid: %s .%d\n", argv[i], match);
				break;
		}
	}

	log_set_lastbuf(_last_log, sizeof(_last_log));
	tx_loop_main(loop);

	tx_timer_stop(&tmtask.timer);
	tx_loop_delete(loop);

	TX_UNUSED(last_tick);

	return 0;
}

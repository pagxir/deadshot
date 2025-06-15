#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include <netinet/in.h>
#include <netinet/udp.h>
#include <linux/errqueue.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <poll.h>

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

#if 0
#undef MSG_ZEROCOPY
#define MSG_ZEROCOPY 0
#undef MSG_ERRQUEUE
#define MSG_ERRQUEUE 0
#endif

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
static int enabled = 1;
static int _XOR_MASK_ = 0x5a;

#define MAX_NIOV 128

struct timer_task {
	tx_task_t task; 
	tx_timer_t timer; 
};

struct udp_exchange_context {
	int sockfd;
	int port;
	int dport;
	int gso_size;
	int group;
	tx_aiocb file;
	tx_task_t task;
};

#define HASH_MASK 0xFFFF

typedef struct _nat_conntrack_t {
	int sockfd;
	int mainfd;
	int group;
	int gso_size;
	int hash_idx;
	time_t last_alive;
	struct sockaddr_in6 source;
	struct sockaddr_in6 target;
	struct udp_exchange_context *mainctx;

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
	void *context;
	LIST_ENTRY(_exchange_context_t) entry;
} _exchange_context_t;
static LIST_HEAD(_exchange_context_q, _exchange_context_t) _exchange_header = LIST_HEAD_INITIALIZER(_exchange_header);
#define ALLOC_NEW(type)  (type *)calloc(1, sizeof(type))

static int install_maping(int port, int dport, int sockfd, int group, void *context)
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
		ctx->context = context;
		LIST_INSERT_HEAD(&_exchange_header, ctx, entry);
	}

	return 0;
}

static int pick_from_port(int port, int group, struct udp_exchange_context **upp)
{
	_exchange_context_t *item, *next;

	LIST_FOREACH_SAFE(item, &_exchange_header, entry, next) {
		if (group == item->group &&
				item->port_mapping == port) {
			*upp = (struct udp_exchange_context *)item->context;
			return item->sockfd;
		}
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

	LOG_INFO("%s len %d, rx/tx total: %ld/%ld rate: %d/%d\n", title, count, _tx_bytes, _rx_bytes, tx_rate, rx_rate);
	LOG_INFO("%s\n", _last_log);
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

static int udp6_recvmsg(int fd, void *buf, size_t len, int flags, struct sockaddr_in6 *from, struct sockaddr_in6 *dst, int *gso_size)
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

			if (cmsg->cmsg_level == SOL_UDP && cmsg->cmsg_type == UDP_GRO) {
				uint16_t *gsosizeptr = (uint16_t *) CMSG_DATA(cmsg);
				*gso_size = *gsosizeptr;
				break;
			}

			if (cmsg->cmsg_level == SOL_IP &&
					cmsg->cmsg_type == IP_RECVERR) {
				LOG_INFO("mesg IP_RECVERR");

				struct sock_extended_err *serr;
				serr = (struct sock_extended_err *) CMSG_DATA(cmsg);
				if (serr->ee_errno != 0 ||
						serr->ee_origin != SO_EE_ORIGIN_ZEROCOPY);
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

static int mkiovec(struct iovec iov[MAX_NIOV], const void *buf, ssize_t len, void *hdr, ssize_t hdrlen, ssize_t gso_size)
{
	int count = 0;
	size_t len0 = len;
	uint8_t *ptr = (uint8_t *)buf;

	if (gso_size > 0 && len > gso_size && hdrlen != 0) {
		while (len >= gso_size) {
			iov[count].iov_base = ptr;
			iov[count].iov_len = gso_size;
			*ptr ^= _XOR_MASK_;

			if (hdrlen > 0) {
				count++;
				iov[count].iov_base = hdr;
				iov[count].iov_len = hdrlen;
			} else {
				assert(gso_size + hdrlen > 0);
				iov[count].iov_len += hdrlen;
			}
			count++;

			len -= gso_size;
			ptr += gso_size;
		}

		if (len > 0) {
			iov[count].iov_base = ptr;
			iov[count].iov_len = len;
			*ptr ^= _XOR_MASK_;

			if (hdrlen > 0) {
				count++;
				iov[count].iov_base = hdr;
				iov[count].iov_len = hdrlen;
			} else {
				assert(len + hdrlen > 0);
				iov[count].iov_len += hdrlen;
			}

			count++;
		}

	} else if (hdrlen > 0) {
		iov[count].iov_base = ptr;
		iov[count].iov_len = len;
		count++;
		if (len > 0) *ptr ^= _XOR_MASK_;

		iov[count].iov_base = hdr;
		iov[count].iov_len = hdrlen;
		count++;

	} else if (hdrlen <= 0) {
		iov[count].iov_base = ptr;
		iov[count].iov_len = len + hdrlen;
		assert(len + hdrlen > 0);
		count++;
		if (len + hdrlen > 0) *ptr ^= _XOR_MASK_;
	}

	if (count >= MAX_NIOV) fprintf(stderr, "iovec count=%d len0=%d\n", count, len0);
	assert(count < MAX_NIOV);
	return count;
}

static int udp6_sendmsg(int fd, struct iovec *iovec, size_t count, int flags, const struct sockaddr_in6 *from, const struct sockaddr_in6 *dest)
{
	struct msghdr msg;
	char msg_control[1024];

	msg.msg_flags = 0;
	msg.msg_name = (void *)dest;
	msg.msg_namelen = sizeof(*dest);

	msg.msg_iov = iovec;
	msg.msg_iovlen = count;

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

enum {NONE, PING, PONG, NAT64, LATEST};
static int ping_pong = NAT64;
static uint8_t prefix64[16] = {0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 127, 9, 9, 9};
static const uint8_t v4mapped[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 9, 9, 9};

static int pull_errqueue(int fd)
{
	struct pollfd pfd;
	struct msghdr msg = {};
	struct iovec iov;
	char buffer[1245];

	iov.iov_base = NULL;
	iov.iov_len = 0;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	msg.msg_flags = 0;
	msg.msg_control = buffer;
	msg.msg_controllen = sizeof(buffer);

	pfd.fd = fd;
	pfd.events = 0;
	if (poll(&pfd, 1, 0) != 1 || pfd.revents & POLLERR == 0)
		return 0;

	int ret = recvmsg(fd, &msg, MSG_ERRQUEUE| MSG_DONTWAIT);
	if (ret == -1)
		LOG_INFO("recvmsg");

	if (ret > 0) {
		struct cmsghdr *cmsg;
		for(cmsg = CMSG_FIRSTHDR(&msg);
				cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (cmsg->cmsg_level == SOL_IPV6 &&
					cmsg->cmsg_type == IPV6_RECVERR) {
				LOG_INFO("mesg IP_RECVERR");

				struct sock_extended_err *serr;
				serr = (struct sock_extended_err *) CMSG_DATA(cmsg);
				if (serr->ee_errno != 0 ||
						serr->ee_origin != SO_EE_ORIGIN_ZEROCOPY);
			}
		}
	}


	return 0;
}

static int buf_index = 0;
struct buf_block {
	int fd;
	char header[64];
	char buf[65536];
} data_block[256];

static int get_buf(char **header, char **buf, int *len, int fd)
{
	if (data_block[buf_index].fd > 0) {
	}

    *header = data_block[buf_index].header;
    *buf = data_block[buf_index].buf;
    *len = sizeof(data_block[buf_index].buf);
	data_block[buf_index].fd = fd;
    return 0;
}

static int next_buf()
{
    buf_index = (buf_index + 1) % 256;
	return 0;
}

static void do_udp_exchange_back(void *upp)
{
	int count;
	int gso_size;
	socklen_t in_len;
	char *buf, *header;
	int buflen = 0;
    int flags = MSG_ERRQUEUE;

	struct sockaddr_in6 in6addr;
	struct sockaddr_in6 dest; // ignore
	struct sockaddr * inaddr = (struct sockaddr *)&in6addr;
	nat_conntrack_t *up = (nat_conntrack_t *)upp;

	if (tx_readable(&up->file)) {
		pull_errqueue(up->sockfd);
		flags = 0;
	}

	while (tx_readable(&up->file)) {
		gso_size = 0;
		in_len = sizeof(in6addr);
		// count = recvfrom(up->sockfd, buf, sizeof(buf), MSG_DONTWAIT, inaddr, &in_len);
		get_buf(&header, &buf, &buflen, up->sockfd);
		count = udp6_recvmsg(up->sockfd, buf, buflen, flags, &in6addr, &dest, &gso_size);
		tx_aincb_update(&up->file, count);
		flags = MSG_DONTWAIT;

		if (count <= 0) {
			LOG_VERBOSE("udp6_recvmsg: %d\n", count);
			if (errno != EAGAIN)
				DELAY_DUMP(LOG_VERBOSE("recvfrom len %d, %d, strerr %s", count, errno, strerror(errno)));
			break;
		}

		int hdrlen = 0;
		next_buf();

		// if (gso_size > 0) LOG_INFO("back gso_size = %d %d\n", gso_size, count);

		struct sockaddr_in6 dest = {};
		struct sockaddr_in6 *test = &dest;
		struct udp_exchange_context *mainctx = up->mainctx;

		memcpy(&dest.sin6_addr, &up->address, sizeof(dest.sin6_addr));
		if (memcmp(v4mapped, &in6addr.sin6_addr, 13) == 0) {
			memcpy(&dest.sin6_addr, prefix64, 16);
			char abuf[64];
			LOG_INFO("v4mapped match send to %s:%d\n", inet_ntop(AF_INET6, &dest.sin6_addr, abuf, sizeof(abuf)), htons(dest.sin6_port));

		} else if (ping_pong == PONG) {
			memcpy(header, ((uint32_t *)&in6addr.sin6_addr) + 3, 4);
			memcpy(header + 4, &in6addr.sin6_port, 2);
			memset(&dest.sin6_addr, 0, 16);
			hdrlen = 6;
			test = NULL;

		} else if (ping_pong == PING) {
			uint32_t *troping = (uint32_t *)&dest.sin6_addr;
			memcpy(troping, prefix64, 16);
			memcpy(troping + 3, buf + count - 6, 4);
			memcpy(&dest.sin6_port, buf + count - 2, 2);
			hdrlen = -6;

			if (IN6_IS_ADDR_V4MAPPED(&up->source.sin6_addr)) {
				convert_from_ipv4(&dest.sin6_addr, buf + count - 6);
			}

			mainctx = NULL;
			up->mainfd = pick_from_port(dest.sin6_port, up->group, &mainctx);
		} else if (ping_pong == NAT64) {
			memcpy(&dest, inaddr, in_len);
			mainctx = NULL;
			up->mainfd = pick_from_port(dest.sin6_port, up->group, &mainctx);
			memcpy(&dest.sin6_addr, prefix64, 12);
		}

		if ((gso_size > 0 && gso_size + hdrlen != mainctx->gso_size) ||
				(gso_size == 0 && hdrlen + count > mainctx->gso_size && mainctx->gso_size > 0)) {
			int previous_gso_size = mainctx->gso_size;
			mainctx->gso_size = gso_size? gso_size + hdrlen: 0;
			assert(mainctx->gso_size >= 0);
			assert(mainctx->sockfd == up->mainfd);
			LOG_INFO("update gso_size mainfd: %d -> %d\n", previous_gso_size, mainctx->gso_size);
			setsockopt(up->mainfd, IPPROTO_UDP, UDP_SEGMENT, &mainctx->gso_size, sizeof(gso_size));
		}

		struct iovec iov[MAX_NIOV];
		int niov = mkiovec(iov, buf, count, header, hdrlen, gso_size);
#if 0
		if (gso_size > 0) {
			int i = 0;
			for (i = 0; i < niov; i++)
				LOG_INFO("hdrlen %d, gso_size %d iov[%d] = %d\n",  hdrlen, gso_size, i, iov[i].iov_len);
			LOG_INFO("session->gso_size: %d\n", up->gso_size);
		}
#endif

		count = udp6_sendmsg(up->mainfd, iov, niov, MSG_ZEROCOPY, test, &up->source);
		if (count == -1 && errno != EAGAIN) {
			DELAY_DUMP(LOG_DEBUG("back sendto len %d, %d, strerr %s match %d\n", count, errno, strerror(errno), match));
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
		conn->gso_size = 0;
		conn->mainctx = 0;
		memset(&conn->target.sin6_addr, 0xff, 12);
		memset(&conn->target.sin6_addr, 0, 10);

		sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
		TX_CHECK(sockfd != -1, "create udp socket failure");

		tx_setblockopt(sockfd, 0);

		setsockopt(sockfd, IPPROTO_UDP, UDP_GRO, &enabled, sizeof(enabled));
		setsockopt(sockfd, SOL_IPV6, IPV6_RECVERR, &enabled, sizeof(enabled));
		// setsockopt(sockfd, IPPROTO_UDP, UDP_SEGMENT, &enabled, sizeof(enabled));
		
		// setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbufsiz, sizeof(rcvbufsiz));

		int sndbufsiz = 1638400;
		setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbufsiz, sizeof(sndbufsiz));
	   if (setsockopt(sockfd, SOL_SOCKET, SO_ZEROCOPY, &enabled, sizeof(enabled))) LOG_DEBUG("setsockopt zerocopy");
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

static struct sockaddr_in6 router = {};

static int session_wrap_data(nat_conntrack_t *session, char *buf, size_t len, struct sockaddr_in6 *dest, char *header, size_t hdrsz)
{
	uint8_t * addr = (uint8_t *)&dest->sin6_addr;

	if (ping_pong == PING) {
		memcpy(header, addr + 12, 4);
		memcpy(header + 4, &dest->sin6_port, 2);
		return 6;
	} else if (ping_pong == PONG) {
		memcpy(&dest->sin6_port, buf + len - 2, 2);
		convert_from_ipv4(&dest->sin6_addr, buf + len - 6);
		return -6;
       } else if (ping_pong == NAT64) {
	       return 0;
	} 

	return 0;
}

static void do_udp_exchange_recv(void *upp)
{
	int count;
	int gso_size = 0;
	socklen_t in_len;
	int flags = MSG_ERRQUEUE;
	nat_conntrack_t *session = NULL;
	char *header;
    char *buf;
	int buflen;

	struct sockaddr_in6 in6addr;
	struct sockaddr_in6 dest;
	struct sockaddr * inaddr = (struct sockaddr *)&in6addr;
	struct udp_exchange_context *up = (udp_exchange_context *)upp;

	if (tx_readable(&up->file)) {
		pull_errqueue(up->sockfd);
		flags = 0;
	}

	while (tx_readable(&up->file)) {
		gso_size = 0;
		in_len = sizeof(in6addr);
		get_buf(&header, &buf, &buflen, up->sockfd);
		count = udp6_recvmsg(up->sockfd, buf, buflen, flags, &in6addr, &dest, &gso_size);
		tx_aincb_update(&up->file, count);
		flags = MSG_DONTWAIT;

		if (count <= 0) {
			LOG_VERBOSE("XXX udp6_recvmsg: %d, %s\n", count, strerror(errno));
			if (errno != EAGAIN)
				LOG_VERBOSE("back recvfrom len %d, %d, strerr %s", count, errno, strerror(errno));
			break;
		}
		next_buf();
		if (gso_size > 0) LOG_INFO("gso_size = %d conunt=%d\n", gso_size, count);

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
		session->mainctx = up;
		dest.sin6_port = htons(up->dport);
		dest.sin6_family = AF_INET6;

		if (memcmp(prefix64, &dest.sin6_addr, 16) == 0) {
			char abuf[63];
			convert_from_ipv4(&dest.sin6_addr, prefix64 + 12);
			count = sendto(session->sockfd, buf, count, MSG_DONTWAIT, (struct sockaddr *)&dest, sizeof(dest));
			LOG_DEBUG("prefix64 match send to %s:%d ret=%d\n", inet_ntop(AF_INET6, &dest.sin6_addr, abuf, sizeof(abuf)), htons(dest.sin6_port), count);
			continue;
		}

		struct iovec iovec[MAX_NIOV];

		int hdrlen = session_wrap_data(session, buf, count, &dest, header, sizeof(header));
		if (router.sin6_family == AF_INET6)
			memcpy(&dest, &router, sizeof(dest));

		int niov = mkiovec(iovec, buf, count, header, hdrlen, gso_size);
#if 0
		if (gso_size > 0) {
			int i = 0;
			for (i = 0; i < niov; i++)
				LOG_INFO("hdrlen %d, gso_size %d iov[%d] = %d\n",  hdrlen, gso_size, i, iovec[i].iov_len);
			LOG_INFO("session->gso_size: %d\n", session->gso_size);
		}
#endif

		if ((gso_size > 0 && gso_size + hdrlen != session->gso_size) ||
				(gso_size == 0 && hdrlen + count > session->gso_size && session->gso_size > 0)) {
			int previous_gso_size = session->gso_size;
			session->gso_size = gso_size? gso_size + hdrlen: 0;
			assert(session->gso_size >= 0);
			LOG_INFO("update gso_size: %d -> %d\n", previous_gso_size, session->gso_size);
			setsockopt(session->sockfd, IPPROTO_UDP, UDP_SEGMENT, &session->gso_size, sizeof(gso_size));
		}

		int count1 = udp6_sendmsg(session->sockfd, iovec, niov, MSG_ZEROCOPY, NULL, &dest);
		if (count1 == -1) {
			DELAY_DUMP(LOG_DEBUG("sendto len %d, %d, strerr %s match %d", count1, errno, strerror(errno), match));
		}
	}

	tx_aincb_active(&up->file, &up->task);
	return;
}

extern "C" int socket_netns(int family, int type, int protocol, const char *netns);
// #define socket_netns(family, type, protocol, netns) socket(family, type, protocol)

static void * udp_exchange_create(int port, int dport, int group)
{
	int sockfd;
	int error = -1;
	struct sockaddr_in6 in6addr;
	struct udp_exchange_context *up = NULL;

	up = new udp_exchange_context();

	fprintf(stderr, "udp_exchange_create %d -> %d group %d\n", port, dport, group);
	sockfd = socket_netns(AF_INET6, SOCK_DGRAM, 0, getenv("NETNS"));
	TX_CHECK(sockfd != -1, "create udp socket failure");

	if (-1 == install_maping(port, dport, sockfd, group, up)) {
		fprintf(stderr, "install_maping %d -> %d failure\n", port, dport);
		closesocket(sockfd);
		return NULL;
	}

	tx_setblockopt(sockfd, 0);
	int rcvbufsiz = 4096;
	// setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbufsiz, sizeof(rcvbufsiz));
	int sndbufsiz = 1638400;
	setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbufsiz, sizeof(sndbufsiz));
	setsockopt(sockfd, IPPROTO_UDP, UDP_GRO, &enabled, sizeof(enabled));
	setsockopt(sockfd, SOL_IPV6, IPV6_RECVERR, &enabled, sizeof(enabled));
	if (setsockopt(sockfd, SOL_SOCKET, SO_ZEROCOPY, &enabled, sizeof(enabled))) LOG_DEBUG("setsockopt zerocopy");

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

	tx_loop_t *loop = tx_loop_default();

	up->port  = port;
	up->group = group;
	up->dport  = dport;
	up->sockfd = sockfd;
	up->gso_size = 0;
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

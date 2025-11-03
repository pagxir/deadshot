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

#include <txall.h>

struct timer_task {
    tx_task_t task; 
    tx_timer_t timer; 
};

struct tcp_exchange_context {
    int sockfd;
    int port;
    int dport;
    tx_aiocb file;
    tx_task_t task;
};

#define HASH_MASK 0xFFFF
typedef struct cache_s {
	size_t off;
	size_t len;
	char buf[655360];
} cache_t;

int socket_netns(int family, int type, int protocol, const char *netns);

typedef struct _nat_conntrack_t {
	int refcnt;
	char dbgflags[4];

    int sockfd;
    int mainfd;
    int hash_idx;
    time_t last_alive;
    struct sockaddr_in6 source;
    struct sockaddr_in6 target;

    int port;
    tx_aiocb file;
    tx_task_t task;
	cache_t cache;

    tx_aiocb mainfile;
    tx_task_t maintask;
	cache_t maincache;
    LIST_ENTRY(_nat_conntrack_t) entry;
} nat_conntrack_t;

static nat_conntrack_t *_session_last[HASH_MASK + 1] = {};
static LIST_HEAD(nat_conntrack_q, _nat_conntrack_t) _session_header = LIST_HEAD_INITIALIZER(_session_header);

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
                LOG_INFO("free datagram connection: %p, %d\n", skip, 0);
                int hash_idx = item->hash_idx;

                if (item == _session_last[hash_idx]) {
                    _session_last[hash_idx] = NULL;
                }

                tx_aiocb_fini(&item->file);
                tx_task_drop(&item->task);
                close(item->sockfd);

                tx_aiocb_fini(&item->mainfile);
                tx_task_drop(&item->maintask);
                close(item->mainfd);

                LIST_REMOVE(item, entry);
                free(item);
            }
        }
    }

    return 0;
}

static void update_timer(void *up)
{
    struct timer_task *ttp;
    ttp = (struct timer_task*)up;

    tx_timer_reset(&ttp->timer, 50000);
    LOG_INFO("update_timer %d\n", tx_ticks);

    conngc_session(time(NULL), NULL);
    return;
}

#define ALLOC_NEW(type)  (type *)calloc(1, sizeof(type))

static int session_release(nat_conntrack_t *up, int dbg)
{
	assert(up);
	assert(up->refcnt > 0);
	assert(dbg < 4 && dbg >= 0);

	up->dbgflags[dbg] = 'R';
	up->refcnt--;

	LOG_INFO("session_release: %s refcnt: %d", up->dbgflags, up->refcnt);
	if (up->refcnt == 0) {
		tx_aiocb_fini(&up->file);
		close(up->sockfd);

		tx_task_drop(&up->task);

		tx_aiocb_fini(&up->mainfile);
		close(up->mainfd);

		tx_task_drop(&up->maintask);
		LIST_REMOVE(up, entry);
		free(up);
	}

	return 0;
}

static int flush_cache(tx_aiocb *file, cache_t *cache)
{
	int len = 1;
	cache_t *d = cache;

	while (len > 0 && d->off < d->len) { 
		len = tx_outcb_write(file, d->buf + d->off, d->len - d->off);
		if (len > 0) d->off += len;
	}

	return d->len == d->off;
}

static int pipling(tx_aiocb *filpin, tx_aiocb *filpout, tx_task_t *task, cache_t *cache)
{
	int count = 0;
	cache_t *d = cache;

	do {

		if (!tx_writable(filpout)) {
			tx_outcb_prepare(filpout, task, 0);
			return 0;
		}

		if (!flush_cache(filpout, cache)) {
			tx_outcb_prepare(filpout, task, 0);
			LOG_INFO("main stream is slow down");
			return 0;
		}

		if (!tx_readable(filpin)) {
			tx_aincb_active(filpin, task);
			return 0;
		}

		count = recv(filpin->tx_fd, d->buf, sizeof(d->buf), MSG_DONTWAIT);
		tx_aincb_update(filpin, count);

		if (count > 0) {
			d->len = count;
			d->off = 0;
		} else if (!tx_readable(filpin)) {
			tx_aincb_active(filpin, task);
			return 0;
		}

	} while (0);

	return count;
}

static void do_tcp_exchange_backward(void *upp)
{
	int count;
	nat_conntrack_t *up = (nat_conntrack_t *)upp;
	cache_t *d = &up->cache;

	if (pipling(&up->file, &up->mainfile, &up->task, d) > 0) {
		up->last_alive = time(NULL);
		return;
	}

	LOG_INFO("read peerfd stream: %d errno=%d msg=%s", count, errno, strerror(errno));
	LOG_INFO("reach end of peerfd stream");
	tx_outcb_cancel(&up->mainfile, &up->task);
	tx_aincb_stop(&up->file, &up->task);
	tx_task_drop(&up->task);
	session_release(up, 0);
    return;
}

static void do_tcp_exchange_forward(void *upp)
{
	int count;
	nat_conntrack_t *up = (nat_conntrack_t *)upp;
	cache_t *d = &up->maincache;

	if (pipling(&up->mainfile, &up->file, &up->maintask, d) > 0) {
		up->last_alive = time(NULL);
		return;
	}

	LOG_INFO("reach end of mainfd stream");
	tx_outcb_cancel(&up->file, &up->maintask);
	tx_aincb_stop(&up->mainfile, &up->maintask);
	tx_task_drop(&up->maintask);
	session_release(up, 1);
    return;
}

static int new_tcp_channel(int newfd, struct sockaddr_in6 *target)
{
	int error;

	assert(newfd >= 0);
	if (newfd < 1000) {
        tx_loop_t *loop = tx_loop_default();
        int sockfd = socket(AF_INET6, SOCK_STREAM, 0);
		if (sockfd == -1) return -1;

		nat_conntrack_t *conn = ALLOC_NEW(nat_conntrack_t);
		conn->refcnt = 2;
		memcpy(conn->dbgflags, "...", 4);

        conn->mainfd = newfd;
        tx_aiocb_init(&conn->mainfile, loop, newfd);
        tx_task_init(&conn->maintask, loop, do_tcp_exchange_forward, conn);
        tx_aincb_active(&conn->mainfile, &conn->maintask);

#if 0
        conn->sockfd = sockfd;
        tx_aiocb_init(&conn->file, loop, sockfd);
        tx_task_init(&conn->task, loop, do_tcp_exchange_backward, conn);

		error = tx_aiocb_connect(&conn->file, (struct sockaddr *)target, sizeof(*target), &conn->task);
		assert (error == 0 || error == -EINPROGRESS);
#endif

		LIST_INSERT_HEAD(&_session_header, conn, entry);
		return 0;
	}

	return -1;
}

static void do_tcp_accept(void *upp)
{
	int newfd;
    socklen_t in_len;
    nat_conntrack_t *session = NULL;

    struct sockaddr_in6 in6addr;
    struct sockaddr * inaddr = (struct sockaddr *)&in6addr;
    tcp_exchange_context *up = (tcp_exchange_context *)upp;

    struct sockaddr_in6 newaddr;
    size_t newlen = sizeof(newaddr);

    newfd = tx_listen_accept(&up->file, (struct sockaddr *)&newaddr, &newlen);
    tx_listen_active(&up->file, &up->task);

    if (newfd != -1) {
		char abuf[64], cbuf[64];
		struct sockaddr_in6 target;
		socklen_t tolen = sizeof(target);

        tx_setblockopt(newfd, 0);
		int err = getsockname(newfd, (struct sockaddr *)&target, &tolen);

		inet_ntop(AF_INET6, &target.sin6_addr, abuf, sizeof(abuf));
		inet_ntop(AF_INET6, &newaddr.sin6_addr, cbuf, sizeof(cbuf));

        LOG_DEBUG("new client: %s:%u\n", cbuf, ntohs(newaddr.sin6_port));
        LOG_DEBUG("destination: %s:%u\n", abuf, ntohs(target.sin6_port));

		uint32_t v4mapped_prefix[4];
		inet_pton(AF_INET6, "::ffff:0:0", v4mapped_prefix);
		target.sin6_port = htons(up->dport);
		memcpy(&target.sin6_addr, v4mapped_prefix, 12);

		inet_ntop(AF_INET6, &target.sin6_addr, abuf, sizeof(abuf));
        LOG_DEBUG("real destination: %s:%u\n", abuf, ntohs(target.sin6_port));

#if 1
		if (err == 0 && 0 == new_tcp_channel(newfd, &target)) {
			newfd = -1;
		}
#endif

		close(newfd);
    }

    return;
}

static void * tcp_exchange_create(int port, int dport)
{
    int sockfd;
    int error = -1;
    struct sockaddr_in6 in6addr;

    LOG_INFO("tcp_exchange_create %d\n", port);
    sockfd = socket_netns(AF_INET6, SOCK_STREAM, 0, getenv("NETNS"));
    TX_CHECK(sockfd != -1, "create tcp socket failure");

    tx_setblockopt(sockfd, 0);
    in6addr.sin6_family = AF_INET6;
    in6addr.sin6_port = htons(port);
    in6addr.sin6_addr = in6addr_loopback;
    in6addr.sin6_addr = in6addr_any;

    error = bind(sockfd, (struct sockaddr *)&in6addr, sizeof(in6addr));
    TX_CHECK(error == 0, "bind udp socket failure");

    struct tcp_exchange_context *up = NULL;

    up = new tcp_exchange_context();
    tx_loop_t *loop = tx_loop_default();

    up->port  = port;
    up->dport  = dport;
    up->sockfd = sockfd;

    error = listen(sockfd, 5);
    assert(error == 0);

    tx_listen_init(&up->file, loop, sockfd);
    tx_task_init(&up->task, loop, do_tcp_accept, up);
	tx_listen_active(&up->file, &up->task);

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

    for (int i = 1; i < argc; i++) {
	int port, dport, match;
        match = sscanf(argv[i], "%d:%d", &port, &dport);
        switch (match) {
            case 1:
                assert (port >  0 && port < 65536);
                tcp_exchange_create(port, port);
                break;

            case 2:
                assert (port >  0 && port < 65536);
                assert (dport >  0 && dport < 65536);
                tcp_exchange_create(port, dport);
                break;

            default:
                fprintf(stderr, "argument is invalid: %s .%d\n", argv[i], match);
                break;
        }
    }

    tx_loop_main(loop);

    tx_timer_stop(&tmtask.timer);
    tx_loop_delete(loop);

    TX_UNUSED(last_tick);

    return 0;
}

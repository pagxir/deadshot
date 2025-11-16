#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <sched.h>
#include <sys/syscall.h>

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

extern "C" int pidfd_open (__pid_t __pid, unsigned int __flags) __THROW;

struct ssl_parse_ctx {
    size_t size;
    uint8_t *base;

    size_t off_ext;
    size_t len_ext;
};

void parse_argopt(int argc, char *argv[]);
const char *ssl_parse_get_sni(struct ssl_parse_ctx *ctx);
int ssl_rewind_client_hello(struct ssl_parse_ctx *ctx, const char *buf, size_t size);
struct ssl_parse_ctx * ssl_parse_prepare(struct ssl_parse_ctx *ctx, void *buf, size_t size);

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
    struct sockaddr_in6 *gateway;
};

#define HASH_MASK 0xFFFF
typedef struct cache_s {
    size_t off;
    size_t len;
    char buf[655360];
} cache_t;

static int sendfd(int unixfd, int netfd)
{
    char dummy[] = "ABC";
    struct iovec io = {
        .iov_base = dummy,
        .iov_len = 3
    };
    struct msghdr msg = { 0 };
    char buf[CMSG_SPACE(sizeof(netfd))] = {};

    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(netfd));

    memmove(CMSG_DATA(cmsg), &netfd, sizeof(netfd));
    msg.msg_controllen = CMSG_SPACE(sizeof(netfd));

    return sendmsg(unixfd, &msg, 0);
}

static int receivefd(int unixfd)
{
    int netfd;
    char buffer[256];
    struct iovec io = {
        .iov_base = buffer,
        .iov_len = sizeof(buffer)
    };

    struct msghdr msg = {0};
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;

    char control[256];
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    if (recvmsg(unixfd, &msg, 0) < 0) {
        return -1;
    }

    struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);
    unsigned char * data = CMSG_DATA(cmsg);

    memcpy(&netfd, data, sizeof(netfd));
    return netfd;
}

int socket_netns(int family, int type, int protocol, const char *netns)
{
    int sv[2];
    int netfd;
    pid_t pid, child;
    int fd, err, newfd;

    netns = netns? netns: getenv("NETNS");

    if (netns == NULL)
        return socket(family, type, protocol);

    if (sscanf(netns, "%d", &pid) != 1)
        return socket(family, type, protocol);

    err = socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
    assert (err == 0);

    child = fork();
    assert(child != -1);

    if (child > 0) {
        close(sv[0]);
        netfd = receivefd(sv[1]);
        close(sv[1]);
        return netfd;
    }

    assert (child == 0);
    fd = pidfd_open(pid, 0);
    close(sv[1]);
    err = setns(fd, CLONE_NEWNET);
    // fprintf(stderr, "socket_netns pid=%d fd=%d err=%d\n", pid, fd, err);
    newfd = socket(family, type, protocol);
    sendfd(sv[0], newfd);
    close(sv[0]);
    exit(0);
}

typedef struct _nat_conntrack_t {
    int refcnt;
    int st_flag;
    char dbgflags[4];

    int sockfd;
    int mainfd;
    int hash_idx;
    time_t last_alive;
    struct sockaddr_in6 source;
    struct sockaddr_in6 target;
    tx_task_t neg;

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

                tx_task_drop(&item->neg);
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
        tx_task_drop(&up->neg);

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
            break;
        }

        if (!flush_cache(filpout, d)) {
            if (tx_writable(filpout)) return 0;
            tx_outcb_prepare(filpout, task, 0);
            break;
        }

        if (!tx_readable(filpin)) {
            tx_aincb_active(filpin, task);
            break;
        }

        count = recv(filpin->tx_fd, d->buf, sizeof(d->buf), MSG_DONTWAIT);
        tx_aincb_update(filpin, count);

        if (count > 0) {
            d->len = count;
            d->off = 0;
        } else if (!tx_readable(filpin)) {
            tx_aincb_active(filpin, task);
            break;
        } else {
            /* TODO:XXX */
            return 0;
        }

    } while (count > 0);

    return 1;
}

static void save_file(const char *path, void *buf, size_t len)
{
#if 0
    FILE *fp = fopen(path, "wb");
    if (fp) {
        fwrite(buf, len, 1, fp);
        fclose(fp);
    }
#endif
    return;
}

static void do_sni_ssl_neg(void *upp)
{
    nat_conntrack_t *up = (nat_conntrack_t *)upp;
    tx_aiocb *filp = &up->mainfile;
    cache_t *d = &up->maincache;
    uint16_t len = 0;
    int count, error;

    assert(up->st_flag == 0);
    count = recv(filp->tx_fd, d->buf, sizeof(d->buf), MSG_DONTWAIT);
    tx_aincb_update(filp, count);

    if (count > 0) {
        d->len += count;
    } else {
        tx_aincb_active(&up->mainfile, &up->neg);
        return;
    }

    if (d->len < 5) {
        tx_aincb_active(&up->mainfile, &up->neg);
        return;
    }

    if (d->buf[0] == 22 && d->buf[1] == 0x3 && d->buf[2] <= 3) {
        struct ssl_parse_ctx ctx;

        memcpy(&len, &d->buf[3], 2);
        len = htons(len);
        if (len + 5 >= sizeof(d->buf)) {
            session_release(up, 0);
            return;
        }

        if (d->len < len + 5) {
            tx_aincb_active(&up->mainfile, &up->neg);
            return;
        }

        if (NULL != ssl_parse_prepare(&ctx, d->buf + 5, len)) {
            ssl_parse_get_sni(&ctx);
            size_t size = ssl_rewind_client_hello(&ctx, d->buf + 5, len);
            d->len = size + 5;

            void *check  = ssl_parse_prepare(&ctx, d->buf + 5, size);
            fprintf(stderr, "TODO:XXX size %ld old len %d check %p\n", size, len, check);
            d->buf[3] = (size >> 8);
            d->buf[4] = (size & 0xff);

            save_file("ech_data.pcap", d->buf, d->len);
            ssl_parse_get_sni(&ctx);
        }
    }

    error = tx_aiocb_connect(&up->file, (struct sockaddr *)&up->target, sizeof(up->target), &up->maintask);
    if (error == 0 || errno == EINPROGRESS) {
    } else {
        fprintf(stderr, "tx_aiocb_connect errno=%d\n", errno);
        session_release(up, 0);
        return;
    }

    tx_aincb_stop(&up->mainfile, &up->neg);
    tx_task_drop(&up->neg);

    tx_task_active(&up->task, "pipling");

    up->st_flag = 1;
    up->refcnt++;

    char host[128];
    inet_ntop(AF_INET6, &up->target.sin6_addr, host, sizeof(host));
    fprintf(stderr, "ssl segment length: %d dlen %ld doff %ld %s:%d\n", len, d->len, d->off, host, htons(up->target.sin6_port));
    return;
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
    shutdown(up->mainfd, SHUT_WR);
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
    shutdown(up->sockfd, SHUT_WR);
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
        tx_setblockopt(sockfd, 0);

        nat_conntrack_t *conn = ALLOC_NEW(nat_conntrack_t);
        conn->refcnt = 1;
        memcpy(conn->dbgflags, "...", 4);

        conn->mainfd = newfd;
        tx_aiocb_init(&conn->mainfile, loop, newfd);
        tx_task_init(&conn->maintask, loop, do_tcp_exchange_forward, conn);

        conn->sockfd = sockfd;
        tx_aiocb_init(&conn->file, loop, sockfd);
        tx_task_init(&conn->task, loop, do_tcp_exchange_backward, conn);

        tx_task_init(&conn->neg, loop, do_sni_ssl_neg, conn);
        tx_aincb_active(&conn->mainfile, &conn->neg);

        memset(&conn->maincache, 0, sizeof(conn->maincache));
        memset(&conn->cache, 0, sizeof(conn->cache));

        conn->target  = *target;
        conn->st_flag = 0;
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

        inet_ntop(AF_INET6, &newaddr.sin6_addr, cbuf, sizeof(cbuf));
        if (up->gateway) {
            target.sin6_addr = up->gateway->sin6_addr;
        } else {
            inet_ntop(AF_INET6, &target.sin6_addr, abuf, sizeof(abuf));
        }

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

static void * tcp_exchange_create(int port, int dport, struct sockaddr_in6 *gateway)
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
    up->gateway = gateway;

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
    struct sockaddr_in6 gateway0;
    struct sockaddr_in6 * gateway = NULL;

#ifndef WIN32
    signal(SIGPIPE, SIG_IGN);
#endif

    tx_loop_t *loop = tx_loop_default();
    tx_poll_t *poll = tx_epoll_init(loop);
    tx_timer_ring *provider = tx_timer_ring_get(loop);
    tx_timer_init(&tmtask.timer, loop, &tmtask.task);

    tx_task_init(&tmtask.task, loop, update_timer, &tmtask);
    tx_timer_reset(&tmtask.timer, 500);

    gateway0.sin6_family = AF_INET6;
    gateway0.sin6_port   = 0;
    parse_argopt(argc, argv);
    for (int i = 1; i < argc; i++) {
        int port, dport, match;

        if (strchr(argv[i], '=') != NULL) {
            continue;
        } else if (strcmp(argv[i], "-p") == 0 && i < argc) {
            gateway0.sin6_port = atoi(argv[++i]);
            continue;
        } else if (strcmp(argv[i], "-r") == 0 && i < argc) {
            inet_pton(AF_INET6, argv[++i], &gateway0.sin6_addr);
            gateway = &gateway0;
            continue;
        } else if (*argv[i] == '-') {
            i++;
            continue;
        }

        match = sscanf(argv[i], "%d:%d", &port, &dport);
        switch (match) {
            case 1:
                assert (port >  0 && port < 65536);
                tcp_exchange_create(port, port, gateway);
                break;

            case 2:
                assert (port >  0 && port < 65536);
                assert (dport >  0 && dport < 65536);
                tcp_exchange_create(port, dport, gateway);
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

#if 0
/tools/ech_sni_proxy -r -l 443 -p 8443 -d smartad.10010.com ech=AET+DQBAyQAgACANIGbucQKF5Mwxg+73GX6mEndmLJtu5U3UiNzu7+1XNQAEAAEAAQARc21hcnRhZC4xMDAxMC5jb20AAA== priv=GNP+9QLS+AjZ9nvD9clyxnn1t7/j/loZ4N1+6eA/HXQ= ::ffff:137.175.6.201
#endif

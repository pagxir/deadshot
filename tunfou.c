#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

#include <linux/if.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>

int tun_alloc(char *dev)
{
    struct ifreq ifr;
    int fd, err;

    if( (fd = open("/dev/net/tun", O_RDWR)) < 0 )
        return -1;

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags  = IFF_TUN;
    ifr.ifr_flags |= IFF_NO_PI;
    if( *dev )
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
        close(fd);
        return err;
    }

    strcpy(dev, ifr.ifr_name);
    return fd;
}

int setblockopt(int devfd, int block)
{
    int flags;
    int test = block? 0: O_NONBLOCK;

    flags = fcntl(devfd, F_GETFL);
    if ((test ^ flags) & O_NONBLOCK) {
        flags = fcntl(devfd, F_SETFL, flags ^ O_NONBLOCK);
    }

    return flags;
}

int update_bufsize(int sockfd)
{
    int ret;
    int bufsize = 0;
    socklen_t optlen = sizeof(bufsize);
#define BUFSIZE (655360 * 3)

    ret = getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, &optlen);
    if (ret == 0 && bufsize < BUFSIZE) {
        printf("update send buffer to %d %d\n", bufsize, BUFSIZE);
        bufsize = BUFSIZE;
        setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    }

    optlen = sizeof(bufsize);
    ret = getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &bufsize, &optlen);
    if (ret == 0 && bufsize < BUFSIZE) {
        printf("update receive buffer to %d %d\n", bufsize, BUFSIZE);
        bufsize = BUFSIZE;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    }

    return ret;
}

uint32_t csum_fold(uint32_t check)
{
    uint16_t high = 0;

    for (high = check >> 16; high; high = check >> 16) {
        check = high + (uint16_t)check;
    }

    return check;
}

struct session_tracker {
    int sockfd;
    time_t last_active;

    uint32_t ident;
    struct sockaddr_in from;
};

struct ip6_hdr {
    uint32_t ip6_verison;
    uint16_t ip6_plen;
    uint8_t ip6_next;
    uint8_t ip6_limit;
    struct in6_addr ip6_src;
    struct in6_addr ip6_dst;
};

struct tcp_hdr {
    uint16_t th_sport;
    uint16_t th_dport;
    uint32_t th_seq;
    uint32_t th_ack;
    uint8_t  th_hlen;
    uint8_t  th_flags;
    uint16_t th_win;
    uint16_t th_sum;
    uint16_t th_urp;
} __packed;

struct session_tracker *_tracker_list[100];
#define ALLOC_NEW(T) (T *) calloc(1, sizeof(T))
#define ARRAY_SIZE(array) (sizeof(array)/sizeof(array[0]))

static int from_len = 0;
static struct sockaddr_in6 tunnel_from6;

int tunnel_read(int tunnelfd, void *buf, size_t len, int passive)
{
    int nbyte;
    uint8_t data[20480];
    static int ipv4_ident = 0;

    if (passive)
        nbyte = recvfrom(tunnelfd, data, sizeof(data), 0, (struct sockaddr *)&tunnel_from6, &from_len);
    else
        nbyte = read(tunnelfd, data, sizeof(data));

    if (nbyte == -1) {
        return -1;
    }

    if (nbyte < 12) {
        return -1;
    }

    nbyte -= 4;

    uint32_t src, dst, src6[4], dst6[4];
    uint64_t s4rc, d4st;
    uint16_t plen = 0;
    uint8_t tagid = data[nbyte + 0];
    uint8_t proto = data[nbyte + 1];
    memcpy(&plen, data + nbyte + 2, sizeof(plen));

    int ip_header_len = 0;
    int ipv4 = (tagid == 0xb7 || tagid == 0x48 || tagid == 0x40 || tagid == 0xbf);
    int ipv6 = (tagid == 0x97 || tagid == 0x68 || tagid == 0x60 || tagid == 0x9f);

    if (!ipv6 && !ipv4) {
        return -1;
    }

    size_t dlen = htons(plen);
    const uint8_t * sod = (data + nbyte - dlen);

    if (ipv4) {
        // nbyte -= 4;
        // ip_header_len = 20;

        sod -= 4;
        assert (sod >= data);
        if (passive) {
            memcpy(&src, sod - sizeof(src), sizeof(src));
            memcpy(&dst, sod + dlen, sizeof(dst));
        } else {
            memcpy(&dst, sod - sizeof(dst), sizeof(dst));
            memcpy(&src, sod + dlen, sizeof(src));
        }
    } else if (ipv6) {
        // nbyte -= 16;
        // ip_header_len = 40;

        sod -= 16;
        assert (sod >= data);
        if (passive) {
            inet_pton(AF_INET6, "3402:52e2:76b5::5efe:0:0", src6);
            memcpy(src6 + 2, sod - sizeof(s4rc), sizeof(s4rc));
            memcpy(&dst6, sod + dlen, sizeof(dst6));
        } else {
            inet_pton(AF_INET6, "3402:52e2:76b5::5efe:0:0", dst6);
            memcpy(dst6 + 2, sod - sizeof(d4st), sizeof(d4st));
            memcpy(&src6, sod + dlen, sizeof(src6));
        }
    }

    uint8_t *packet = (uint8_t *)buf;
    uint8_t XOR = (tagid == 0xb7 || tagid == 0x97 || tagid == 0xbf || tagid == 0x9f)? 0xf: 0;

    if (ipv4) {
        uint16_t packetId = htons(ipv4_ident++);
        uint16_t dontFrag = (uint16_t)htons(proto == 6? 0x4000: 0);

        *packet++ = 0x45;
        *packet++ = 0x00;

        plen = htons(dlen + 20);
        memcpy(packet, &plen, sizeof(plen));
        packet += sizeof(plen);

        memcpy(packet, &packetId, sizeof(packetId));
        packet += sizeof(packetId);

        memcpy(packet, &dontFrag, sizeof(dontFrag));
        packet += sizeof(dontFrag);

        *packet++ = 0xff;
        *packet++ = proto;

        int check = csum_fold(src) + csum_fold(dst) + htons(proto + 0xff00) + dontFrag + packetId + plen + htons(0x4500);

        uint16_t check16 = ~csum_fold(check);
        memcpy(packet, &check16, sizeof(check16));
        packet += sizeof(check16);

        memcpy(packet, &src, sizeof(src));
        packet += sizeof(src);

        memcpy(packet, &dst, sizeof(dst));
        packet += sizeof(dst);
    } else if (ipv6) {
        *(uint32_t*)packet = htonl(0x60000000);
        packet += sizeof(uint32_t);

        *(uint16_t*)packet = plen;
        packet += sizeof(plen);

        *packet++ = proto;
        *packet++ = 0xff;

        memcpy(packet, src6, sizeof(src6));
        packet += sizeof(src6);

        memcpy(packet, &dst6, sizeof(dst6));
        packet += sizeof(dst6);
    }

    for (int i = 0; i < dlen; i++) {
        *packet++ = sod[i] ^ XOR;
    }

    return packet - (uint8_t *)buf;
}

#define H2N htonl
static uint32_t net10 = 0x0a000000, net172 = 0xac100000, net192168 = 0xc0a80000;
static uint32_t msk10 = 0xff000000, msk172 = 0xfff00000, msk192168 = 0xffff0000;

int is_ipv4_local(uint32_t addr)
{
    return (net10 == (msk10 & H2N(addr))) ||
        (net172 == (msk172 & H2N(addr))) ||
        (net192168 == (msk192168 & H2N(addr)));
}

static uint32_t prefix6 = 0x340252e2;
int is_ipv6_local(uint32_t *addr)
{
    return addr[0] == H2N(prefix6);
}

int tunnel_write(int tunnelfd, void *buf, size_t len, int passive)
{
    uint8_t *data = (uint8_t *)buf;
    if (len < 28) {
        fprintf(stderr, "tunnelfd len=%ld\n", len);
        return -1;
    }

    uint8_t iver = *data & 0xf0;
    int ipv4 = (iver == 0x40);
    int ipv6 = (iver == 0x60);

    if (!ipv4 && !ipv6) {
        fprintf(stderr, "tunnelfd ver=%x\n", iver);
        return -1;
    }

    if (ipv4) {
        uint32_t src, dst;
        uint16_t plen = 0;
        uint8_t hop = data[8];
        uint8_t proto = data[9];
        uint16_t *port_start = NULL;

        memcpy(&plen, data + 2, sizeof(plen));
        memcpy(&src, data + 12, sizeof(src));
        memcpy(&dst, data + 16, sizeof(dst));

        port_start = (uint16_t *)(data + 20);
        uint16_t sport = port_start[0];
        uint16_t dport = port_start[1];

        int xorlen = 0;
        uint8_t tagid = 0x40;

        plen = ntohs(plen) - 20;
        if (proto == 17 && dport == htons(53)) {
            tagid = 0xbf;
            xorlen = (plen);
        } else if (proto == 6 && dport == htons(443)) {
            tagid = 0xbf;
            xorlen = (plen);
        } else if (proto == 6 && dport == htons(80)) {
            tagid = 0xbf;
            xorlen = (plen);
        } else if (proto == 58) {
            tagid = 0xbf;
            xorlen = (plen);
        }

        if (is_ipv4_local(dst)) {
            uint32_t temp = src;
            tagid ^= 0x8;
            src = dst;
            dst = temp;
        }

        memcpy(data + 16, &src, sizeof(src));
        memcpy(data + len, &dst, sizeof(dst));
        data[len + 4] = tagid;
        data[len + 5] = proto;

        plen = htons(plen);
        memcpy(&data[len + 6], &plen, sizeof(plen));

        for (int i = 0; i < xorlen; i++) {
            data[20 + i] ^= 0xf;
        }

        if (passive)
            return sendto(tunnelfd, data + 16, len - 20 + 4 + 8, 0, (struct sockaddr *)&tunnel_from6, from_len);

        return write(tunnelfd, data + 16, len - 20 + 4 + 8);
    } else if (ipv6) {
        uint16_t plen = 0;
        uint8_t hop = data[7];
        uint8_t proto = data[6];
        uint32_t src6[4], dst6[4];
        uint16_t *port_start = NULL;

        memcpy(&plen, data + 4, sizeof(plen));
        memcpy(src6, data + 8, sizeof(src6));
        memcpy(dst6, data + 24, sizeof(dst6));

        port_start = (uint16_t *)(data + 40);
        uint16_t sport = port_start[0];
        uint16_t dport = port_start[1];

        int xorlen = 0;
        uint8_t tagid = 0x60;

        if (proto == 17 && dport == htons(53)) {
            tagid = 0x9F;
            xorlen = htons(plen);
        } else if (proto == 6 && dport == htons(443)) {
            tagid = 0x9f;
            xorlen = htons(plen);
        } else if (proto == 6 && dport == htons(80)) {
            tagid = 0x9f;
            xorlen = htons(plen);
        } else if (proto == 58) {
            tagid = 0x9f;
            xorlen = htons(plen);
        }

        // IN6_ARE_ADDR_EQUAL dst6
        if (is_ipv6_local(dst6)) {
            uint32_t temp[4];
            tagid ^= 0x8;
            memcpy(temp, src6, sizeof(temp));
            memcpy(src6, dst6, sizeof(temp));
            memcpy(dst6, temp, sizeof(temp));
        }

        memcpy(data + 40 - 16, src6, sizeof(src6));
        memcpy(data + len, dst6, sizeof(dst6));
        data[len + 16] = tagid;
        data[len + 17] = proto;
        memcpy(&data[len + 18], &plen, sizeof(plen));

        for (int i = 0; i < xorlen; i++) {
            data[40 + i] ^= 0xf;
        }

        if (passive)
            return sendto(tunnelfd, data + 40 - 4 - 4, len - 40 + 4 + 20 + 4, 0, (struct sockaddr *)&tunnel_from6, from_len);

        return write(tunnelfd, data + 40 - 4 - 4, len - 40 + 4 + 20 + 4);
    }

    return -1;
}

static int reinitfd(struct session_tracker *tracker, struct sockaddr_in6 *dest)
{
    int sockfd = tracker->sockfd;

    if (tracker->last_active + 1000 <  time(NULL)) {
        sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
        if (dest) connect(sockfd, (struct sockaddr *)dest, sizeof(*dest));
        update_bufsize(sockfd);
        setblockopt(sockfd, 0);
        close(tracker->sockfd);
        tracker->sockfd = sockfd;
        assert(sockfd != -1);
    }

    return sockfd;
}

static int lockfd(struct session_tracker **list, int *pcount, size_t size, void *buf, size_t nbytes, struct sockaddr_in6 *dest, int defaultfd)
{
    int count = pcount[0];
    uint32_t ident = 0;
    uint32_t *dlist;

    int ndefrag = 0;
    time_t stamp = time(NULL);
    struct session_tracker *oldest = NULL;
    struct session_tracker *tracker = NULL;

    uint8_t *v4v6 = (uint8_t *)buf;
    uint16_t *ttlproto = (uint16_t *)buf;

    if ((v4v6[0] & 0xf0) == 0x60) {
        dlist = (uint32_t *)(v4v6 + 8);
        ident = dlist[8] + ttlproto[3];

        ident ^= (dlist[0] ^ dlist[1]);
        ident ^= (dlist[2] + dlist[3]);

        ident ^= (dlist[4] ^ dlist[5]);
        ident ^= (dlist[6] + dlist[7]);
    } else if (v4v6[0] == 0x45) {
        dlist = (uint32_t *)(v4v6 + 12);
        ident = dlist[2] + ttlproto[4];
        ident ^= (dlist[0] ^ dlist[1]);
    }

    for (int cc = 0; cc < count; cc++) {
        tracker = list[cc];

        if (tracker->ident == ident) {
            reinitfd(tracker, dest);
            tracker->last_active = time(NULL) - 1;
            return tracker->sockfd;
        }

        if (tracker->last_active + 150 < time(NULL)) {
            ndefrag++;
        }

        if (stamp > tracker->last_active) {
            oldest = tracker;
            stamp  = tracker->last_active;
        }
    }

    if (ndefrag == count) {
        for (int cc = 0; cc < count; cc++) {
            struct session_tracker *tracker = list[cc];
            close(tracker->sockfd);
            free(tracker);
            list[cc] = 0;
        }

        *pcount = 0;
        ndefrag = 0;
        count = 0;
    }

    if (count < size) {
        tracker = ALLOC_NEW(struct session_tracker);
        list[count++] = tracker;
        tracker->sockfd = socket(AF_INET6, SOCK_DGRAM, 0); 
        if (dest) connect(tracker->sockfd, (struct sockaddr *)dest, sizeof(*dest));
        setblockopt(tracker->sockfd, 0);
        update_bufsize(tracker->sockfd);
        tracker->ident = ident;
        tracker->last_active = time(NULL) - 1;
        assert(tracker->sockfd != -1);
        *pcount = count;
        return tracker->sockfd;
    }

    if (oldest != NULL && stamp + 27 < time(NULL)) {
        tracker = oldest;
        tracker->ident = ident;
        tracker->last_active = 0;
        reinitfd(tracker, dest);
        tracker->last_active = time(NULL) - 1;
        assert(tracker->sockfd != -1);
        return tracker->sockfd;
    }

    return defaultfd;
}

int main(int argc, char *argv[])
{
    struct sockaddr_in6 destination;
    char buffer[2048];
    char devname[IFNAMSIZ] = "tun1";
    char thepeer[64] = "::ffff:185.201.226.236";
    fd_set exceptfds;
    fd_set readfds;

    int error = 0;
    int maxfd = 2;
    int ready = 0;
    int nbytes = 0;

    int tuninfd = 0;
    int tunoutfd = 0;
    int passive_mode = 0;
    int port = 0;

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (strncmp("-dev", arg, 4) == 0) {
            if (i >= argc) continue;
            strncpy(devname, argv[++i], IFNAMSIZ - 1);
        } else if (strcmp(arg, "-passive") == 0) {
            passive_mode = 1;
        } else if (strcmp(arg, "-port") == 0) {
            if (i >= argc) continue;
            port = atoi(argv[++i]);
        } else if (strcmp(arg, "-help") == 0) {
			fprintf(stderr, "%s [options] target\n", argv[0]);
			fprintf(stderr, "\t -dev <tun>   tun device name\n");
			fprintf(stderr, "\t -port <port> destination port\n");
			fprintf(stderr, "\t -passive     use passive mode, accept client to connect\n");
			fprintf(stderr, "\t              act as a server\n");
			fprintf(stderr, "\t -help        print this usage\n");
			fprintf(stderr, "\t target       destination ipv6 address\n");
			fprintf(stderr, "\n");
			exit(0);
        } else if (*arg != '-') {
            strncpy(thepeer, arg, 63);
        }
    }

    if (strcmp(devname, "stdio") == 0) {
        tunoutfd = 1;
        tuninfd = 0;
    } else {
        tuninfd = tunoutfd = tun_alloc(devname);
        assert(tuninfd != -1);
    }

    int tunnelfd = socket(AF_INET6, SOCK_DGRAM, 0);
    assert(tunnelfd != -1);

    destination.sin6_family = AF_INET6;
    destination.sin6_port   = htons(port);

    if (passive_mode == 0) {
        inet_pton(AF_INET6, thepeer, &destination.sin6_addr);

        error = connect(tunnelfd, (struct sockaddr *)&destination, sizeof(destination));
        assert(error == 0);
    } else {
        inet_pton(AF_INET6, "::", &destination.sin6_addr);

        error = bind(tunnelfd, (struct sockaddr *)&destination, sizeof(destination));
        assert(error == 0);
    }

    maxfd = tunnelfd;

    FD_ZERO(&readfds);
    FD_SET(tuninfd, &readfds);
    FD_SET(tunnelfd, &readfds);

    FD_ZERO(&exceptfds);
#if 0
    FD_SET(tuninfd, &exceptfds);
    FD_SET(tunoutfd, &exceptfds);
    FD_SET(tunnelfd, &exceptfds);
#endif
    setblockopt(tuninfd, 0);
    setblockopt(tunnelfd, 0);

    int _tracker_count = 0;
    struct session_tracker *_tracker_list[100];
    for (int cc = 0; cc < _tracker_count; cc++) {
        int sockfd = _tracker_list[cc]->sockfd;
        FD_SET(sockfd, &readfds);
        maxfd = sockfd > maxfd? sockfd: maxfd;
    }

    for (ready = select(maxfd + 1, &readfds, NULL, &exceptfds, 0); ready != -1; ready = select(maxfd + 1, &readfds, NULL, &exceptfds, 0)) {
        int more_todo = 0;

again:
        more_todo = 0;
        if (FD_ISSET(tuninfd, &readfds)) {
            int sockfd;
            nbytes = read(tuninfd, buffer, sizeof(buffer));

            error = nbytes;
            if (nbytes > 0) {
                sockfd = lockfd(_tracker_list, &_tracker_count, ARRAY_SIZE(_tracker_list), buffer, nbytes, passive_mode? NULL: &destination, tunnelfd);
                error = tunnel_write(sockfd, buffer, nbytes, passive_mode);
            } else {
                /* clear */
                FD_CLR(tuninfd, &readfds);
            }

            if (error == -1 && errno != EAGAIN) {
                int code = errno;
                perror("write tuninfd");
                fprintf(stderr, "ready tuninfd=%d nbytes=%d errno=%d\n", sockfd, nbytes, code);
                if (passive_mode == 0) {
                    close(sockfd);
                    if (tunnelfd == sockfd) {
                        tunnelfd = socket(AF_INET6, SOCK_DGRAM, 0);
                        assert(tunnelfd != -1);
                        error = connect(tunnelfd, (struct sockaddr *)&destination, sizeof(destination));
                        assert(error == 0);
                    } else {
                        int ntracker = 0;
                        for (int cc = 0; cc < _tracker_count; cc++)
                            if (sockfd != _tracker_list[cc]->sockfd)
                                _tracker_list[ntracker++] = _tracker_list[cc];
                        _tracker_count = ntracker;
                    }
                }
            } else if (nbytes > 0) {
                more_todo++;
            }
        }

        if (FD_ISSET(tunnelfd, &readfds)) {
            nbytes = tunnel_read(tunnelfd, buffer, sizeof(buffer), passive_mode);

            if (nbytes > 0) {
                error = write(tunoutfd, buffer, nbytes);
                assert (error == nbytes);
                more_todo++;
            } else if (nbytes == -1 && errno == EAGAIN) {
                FD_CLR(tunnelfd, &readfds);
            } else {
                fprintf(stderr, "ready tunnelfd=%d nbytes=%d\n", tunnelfd, nbytes);
                perror("write tunnelfd");
                FD_CLR(tunnelfd, &readfds);
            }
        }

        for (int cc = 0; cc < _tracker_count; cc++) {
            int sockfd = _tracker_list[cc]->sockfd;
            if (FD_ISSET(sockfd, &readfds)) {
                nbytes = tunnel_read(sockfd, buffer, sizeof(buffer), passive_mode);

                if (nbytes > 0) {
                    _tracker_list[cc]->last_active = time(NULL);
                    error = write(tunoutfd, buffer, nbytes);
                    assert (error == nbytes);
                    more_todo++;
				} else if (nbytes == -1 && errno == EAGAIN) {
                    FD_CLR(sockfd, &readfds);
                } else {
                    fprintf(stderr, "ready tunnelfd=%d nbytes=%d\n", sockfd, nbytes);
                    perror("write tunnelfd");
                    FD_CLR(sockfd, &readfds);
                }
            }
        }

        if (more_todo) goto again;

        FD_ZERO(&readfds);
        FD_SET(tuninfd, &readfds);
        FD_SET(tunnelfd, &readfds);

        for (int cc = 0; cc < _tracker_count; cc++) {
            int sockfd = _tracker_list[cc]->sockfd;
            FD_SET(sockfd, &readfds);
            maxfd = sockfd > maxfd? sockfd: maxfd;
        }
    }

    return 0;
}


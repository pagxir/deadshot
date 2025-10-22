
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

    flags = fcntl(devfd, F_GETFL);
    if ((block? 0: O_NONBLOCK) ^ (flags & O_NONBLOCK)) {
        flags = fcntl(devfd, F_SETFL, flags^O_NONBLOCK);
    }

    return flags;
}

uint32_t csum_fold(uint32_t check)
{
    uint16_t high = 0;

    for (high = check >> 16; high; high = check >> 16) {
        check = high + (uint16_t)check;
    }

    return check;
}

static int from_len = 0;
static struct sockaddr_in6 tunnel_from6;

int tunnel_read(int tunnelfd, void *buf, size_t len, int passive)
{
    int nbyte;
    uint8_t data[2048];
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

    if (ipv4) {
        nbyte -= 4;
	ip_header_len = 20;
	if (passive) {
	    memcpy(&src, data, sizeof(src));
	    memcpy(&dst, data + nbyte, sizeof(dst));
	} else {
	    memcpy(&dst, data, sizeof(dst));
	    memcpy(&src, data + nbyte, sizeof(src));
	}
    } else if (ipv6) {
        nbyte -= 16;
	ip_header_len = 40;
	if (passive) {
	    inet_pton(AF_INET6, "3402:52e2:76b5::5efe:0:0", src6);
	    memcpy(src6 + 3, data, sizeof(src));
	    memcpy(&dst6, data + nbyte, sizeof(dst6));
	} else {
	    inet_pton(AF_INET6, "3402:52e2:76b5::5efe:0:0", dst6);
	    memcpy(dst6 + 3, data, sizeof(dst));
	    memcpy(&src6, data + nbyte, sizeof(src6));
	}
    }

    nbyte -= 4;
    uint8_t *packet = (uint8_t *)buf;
    uint8_t XOR = (tagid == 0xb7 || tagid == 0x97 || tagid == 0xbf || tagid == 0x9f)? 0xf: 0;

    if (ipv4) {
        uint16_t packetId = htons(ipv4_ident++);
        uint16_t dontFrag = (uint16_t)htons(proto == 6? 0x4000: 0);

        *packet++ = 0x45;
        *packet++ = 0x00;

        plen = htons(ntohs(plen) + 20);
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

    for (int i = 0; i < nbyte; i++)
        *packet++ = data[4 + i] ^ XOR;

    return nbyte + ip_header_len;
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
        fprintf(stderr, "tunnelfd len=%d\n", len);
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
	    return sendto(tunnelfd, data + 40 - 4, len - 40 + 4 + 20, 0, (struct sockaddr *)&tunnel_from6, from_len);

	return write(tunnelfd, data + 40 - 4, len - 40 + 4 + 20);
    }

    return -1;
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

    for (ready = select(maxfd + 1, &readfds, NULL, &exceptfds, 0); ready != -1; ready = select(maxfd + 1, &readfds, NULL, &exceptfds, 0)) {

        if (FD_ISSET(tuninfd, &readfds)) {
            nbytes = read(tuninfd, buffer, sizeof(buffer));

            error = nbytes;
            if (nbytes > 0)
                error = tunnel_write(tunnelfd, buffer, nbytes, passive_mode);

            if (error == -1) {
                perror("write tuninfd");
                fprintf(stderr, "ready tuninfd=%d nbytes=%d\n", tuninfd, nbytes);
            }
        }

        if (FD_ISSET(tunnelfd, &readfds)) {
            nbytes = tunnel_read(tunnelfd, buffer, sizeof(buffer), passive_mode);

            if (nbytes > 0) {
                error = write(tunoutfd, buffer, nbytes);
                assert (error == nbytes);
            } else {
                fprintf(stderr, "ready tunnelfd=%d nbytes=%d\n", tunnelfd, nbytes);
                perror("write tunnelfd");
            }
        }

        FD_ZERO(&readfds);
        FD_SET(tuninfd, &readfds);
        FD_SET(tunnelfd, &readfds);
    }

    return 0;
}


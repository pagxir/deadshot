#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <assert.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h> // read(), write(), close()
#define MAX 65536
#define SA struct sockaddr

#include "tx_debug.h"

#ifndef LOG_DEBUG
int log_tag_putlog(const char *tag, const char *fmt, ...);
#define LOG_DEBUG(fmt, args...)   log_tag_putlog("D", fmt, ##args)
#endif

#ifndef LOG_VERBOSE
#define LOG_VERBOSE(fmt, args...) log_tag_putlog("V", fmt, ##args)
#endif

static int PORT = 4430;

static int YOUR_PORT = 4430;
static char YOUR_PORT_TEXT[64] = "4430";
static char YOUR_DOMAIN[256] = "app.yrli.bid";
static char YOUR_ADDRESS[256] = "100.42.78.149";

int read_flush(int fd, void *buf, size_t count)
{
    int rc = 0;
    int process = 0;
    uint8_t *ptr = (uint8_t*)buf;

    while (process < count) {
        rc = read(fd, ptr + process, count - process);
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
        rc = write(fd, ptr + process, count - process);
        if (rc == -1) break;
        if (rc == 0) break;
        process += rc;
    }

    return process == 0? rc: process;
}

int pipling(int connfd, int remotefd)
{
    char buff[65536];
    size_t len = read(connfd, buff, sizeof(buff));
    // fprintf(stderr, "pipling %d -> %d %d\n", connfd, remotefd, len);
    if (len == -1) return -1;
    if (len == 0) return 0;
    return write_flush(remotefd, buff, len);
}

int setup_remote(struct sockaddr_in6 *cli, char *hostname)
{
    int i;
    int rc = -1;
    int remotefd = -1;

    remotefd = socket(AF_INET6, SOCK_STREAM, 0);

    inet_pton(AF_INET6, hostname, &cli->sin6_addr);
    rc = connect(remotefd, (struct sockaddr *)cli, sizeof(*cli));
    if (rc == -1) {
	    close(remotefd);
	    remotefd = -1;
    }

    return remotefd;
}

char * to_binary(uint8_t data[], size_t len, char *buf, size_t size)
{
    char *ptr = buf;
	char map[] = "0123456789abcdef";

    while (len > 0 && size > 3) {
		*ptr++ = map[(*data & 0xf0) >> 4];
		*ptr++ = map[(*data & 0xf)];
		*ptr++ = ' ';

		 data++, len--, size -= 3;
	}

	if (size) *ptr = 0;
	return buf;
}

void func(int connfd)
{
    int rc;
    int n, l, i;
    fd_set test;
	char tmp[4096];
    uint8_t snibuff[4096];
    int remotefd = -1;

#if 0
    struct timeval tv;
    tv.tv_sec = 30;  /* 30 Secs Timeout */
    int ret = setsockopt(connfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    assert(ret == 0);
#endif

    l = read(connfd, snibuff, sizeof(snibuff));
	LOG_DEBUG("BYTES: %s", to_binary(snibuff, l, tmp, sizeof(tmp)));
    int port = snibuff[2] << 8|snibuff[3];
    LOG_DEBUG("port %d", port);
    // 04 01 00 50 00 00 00 01 00 77 77 77 2e 74 65 73 74 2d 69 70 76 36 2e 63 6f 6d 00 
    if (l < 9 || snibuff[0] != 0x04 || snibuff[1] != 0x01) {
        close(connfd);
        return 0;
    }

    int pos = 8;
    // skip ident
    while (pos < l && snibuff[pos++] != 0);
    if (snibuff[4] == 0 && snibuff[5] == 0 && snibuff[6] == 0) {
        LOG_DEBUG(" domain %s", snibuff + pos);
        while (pos < l && snibuff[pos++] != 0);
    }

    assert(pos == l);

    int newlen = 8;

    snibuff[0] = 0;
    snibuff[1] = 90;
    rc = write(connfd, snibuff, newlen);
    assert(rc == newlen);

    struct sockaddr_in6 cli;
    cli.sin6_family = AF_INET6;
    cli.sin6_port   = htons(port);
   if (port == 443) cli.sin6_port   = htons(4430);
    remotefd = setup_remote(&cli, "::ffff:127.0.0.1");

    if (remotefd == -1) {
        close(connfd);
        return;
    }

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

void clean_pcb(int signo)
{
    int st;
    LOG_DEBUG("clean_pcb");
    while(waitpid(-1, &st, WNOHANG) > 0);
    // signal(SIGCHLD, clean_pcb);
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
	}
    }
    LOG_DEBUG("<parse_argopt");

}

// Driver function
int main(int argc, char *argv[])
{
    int sockfd, connfd, len;
    struct sockaddr_in6 servaddr, cli;
    signal(SIGCHLD, clean_pcb);

    parse_argopt(argc, argv);

    // socket create and verification
    sockfd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sockfd == -1) {
        LOG_DEBUG("socket creation failed...");
        exit(0);
    }
    else
        LOG_DEBUG("Socket successfully created..");
    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin6_family = AF_INET6;
    servaddr.sin6_port = htons(PORT);
    servaddr.sin6_addr = in6addr_any;

    int enable = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

    // Binding newly created socket to given IP and verification
    if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) {
        LOG_DEBUG("socket bind failed...");
        exit(0);
    }
    else
        LOG_DEBUG("Socket successfully binded..");

    // Now server is ready to listen and verification
    if ((listen(sockfd, 5)) != 0) {
        LOG_DEBUG("Listen failed...");
        exit(0);
    }
    else
        LOG_DEBUG("Server listening..");
    len = sizeof(cli);

    do {
        len = sizeof(cli);
        // Accept the data packet from client and verification
        connfd = accept(sockfd, (SA*)&cli, &len);
        if (connfd < 0) {
            LOG_DEBUG("server accept failed...");
            exit(0);
        }
        else
            LOG_DEBUG("server accept the client...");

        if (fork() == 0) {close(sockfd); func(connfd); exit(0); }
        close(connfd);
        // Function for chatting between client and server
    } while (1);

    // After chatting close the socket
    close(sockfd);
    return 0;
}

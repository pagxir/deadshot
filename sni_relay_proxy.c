
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <netinet/in.h>
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

#define LOG(fmt, arg...) 
#define LOGV(fmt, arg...) 
#define LOGI(fmt, arg...) fprintf(stderr, fmt, ##arg)

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

static int set_hook_name = 0;

char * get_sni_name(uint8_t *snibuff, size_t len, char *hostname)
{
    int i;
    int length;
    uint8_t *p = snibuff;

    if (*p != HANDSHAKE_TYPE_CLIENT_HELLO) {
        LOG("bad\n");
        return NULL;
    }

    int type = *p++;
    LOG("type: %x\n", type);
    length = p[2]|(p[1]<<8)|(p[0]<<16); p+=3;
    LOG("length: %d\n", length);
    LOG("version: %x.%x\n", p[0], p[1]);
    p += 2; // version;
            //
    p += 32; //random;
    LOG("session id length: %d\n", *p);
    p += *p;
    p++;
    int cipher_suite_length = p[1]|(p[0]<<8); p+=2;
    LOG("cipher_suite_length: %d\n", cipher_suite_length);
    p += cipher_suite_length;
    int compress_method_len = *p++;
    LOG("compress_method_len: %d\n", compress_method_len);
    p += compress_method_len;
    int extention_length = p[1]|(p[0]<<8); p+=2;
    LOG("extention_lengh: %d\n", extention_length);
    const uint8_t *limit = p + extention_length;

    *hostname = 0;
    while (p < limit) {
        uint16_t tag = p[1]|(p[0]<<8);
        uint16_t len = p[3]|(p[2]<<8);
        LOG("ext tag: %d %d\n", tag, len);
        if (tag == TAG_SNI) {
            const uint8_t *sni = (p + 4);
            assert (sni[2] == 0);
            uint16_t list_name_len = sni[1]|(sni[0] << 8);
            uint16_t fqdn_name_len = sni[4]|(sni[3] << 8);
            assert (fqdn_name_len + 3 == list_name_len);
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

    if (set_hook_name)
	strcpy(hostname, "www.cloudflare.com");

    return hostname;
}

enum {MODE_RELAY_SERVER, MODE_RELAY_CLIENT, MODE_RELAY_NONE};

static int PORT = 4430;
static int RELAY_MODE = MODE_RELAY_NONE;

static int YOUR_PORT = 4430;
static char YOUR_DOMAIN[256] = "app.yrli.bid";
static char YOUR_ADDRESS[256] = "100.42.78.149";
static int (*unwind_rewind_client_hello)(uint8_t *, size_t) = NULL;

int rewind_client_hello(uint8_t *snibuff, size_t length)
{
    int i;
    int mylength = 0;
    uint8_t hold[4096];
    uint8_t *p = snibuff + 5;
    uint8_t *dest = hold + 5;

    memcpy(hold, snibuff, 5);
    if (*p != HANDSHAKE_TYPE_CLIENT_HELLO) {
        LOG("bad\n");
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
        LOG("ext tag: %d %d\n", tag, len);
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
    LOG("extlen: %d %d\n", extlen, extention_length);

    int newlen = dest - lengthp - 3;
    lengthp[0] = newlen >> 16;
    lengthp[1] = newlen >> 8;
    lengthp[2] = newlen;
    LOG("newlen: %d %d\n", newlen, mylength);

    memcpy(hold, snibuff, 5);
    int fulllength = (dest - hold - 5);
    hold[3] = fulllength >> 8;
    hold[4] = fulllength;

    int oldlen = (snibuff[3] << 8) | snibuff[4];
    LOG("fulllen: %d %d %ld\n", fulllength, oldlen, length);

    memcpy(snibuff, hold, dest - hold);
    return dest - hold;
}

int unwind_client_hello(uint8_t *snibuff, size_t length)
{
    int i;
    int modify = 0;
    int mylength = 0;
    uint8_t hold[4096];
    uint8_t *p = snibuff + 5;
    uint8_t *dest = hold + 5;

    memcpy(hold, snibuff, 5);
    if (*p != HANDSHAKE_TYPE_CLIENT_HELLO) {
        LOG("bad\n");
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

    int last_tag = -1;
    char hostname[256] = "";
    while (p < limit) {
        uint16_t tag = p[1]|(p[0]<<8);
        uint16_t len = p[3]|(p[2]<<8);
        LOG("ext tag: %d %d\n", tag, len);
        uint16_t fqdn_name_len = 0;

        if (tag == TAG_SNI) {
            const uint8_t *sni = (p + 4);
            assert (sni[2] == 0);
            uint16_t list_name_len = sni[1]|(sni[0] << 8);
            fqdn_name_len = sni[4]|(sni[3] << 8);
            assert (fqdn_name_len + 3 == list_name_len);
            memcpy(hostname, sni + 5, fqdn_name_len);
            hostname[fqdn_name_len] = 0;
            LOG("source: %s\n", hostname);
        } else if (tag == TAG_SESSION_TICKET && last_tag == TAG_SNI) {
            if (strcmp(hostname, YOUR_DOMAIN) == 0) {
                memcpy(hostname, p + 4, len);
                hostname[len] = 0;
                fqdn_name_len = strlen(hostname);
                for (i = 0; i < fqdn_name_len; i++) hostname[i] ^= 0xf;
                LOG("target: %s\n", hostname);
            }
        }

        if (strcmp(hostname, YOUR_DOMAIN) == 0 && tag == TAG_SNI) {

        } else if (tag != TAG_SESSION_TICKET || last_tag != TAG_SNI) {
            memcpy(dest, p, len + 4);
            dest += len;
            dest += 4;
        } else if (tag == TAG_SESSION_TICKET) {
            dest[0] = 0; dest[1] = 0;
            dest[2] = 0; dest[3] = 0;
            size_t namelen = strlen(hostname);

            strcpy(dest + 4 + 5, hostname);
            dest[4 + 4] = namelen;
            dest[4 + 3] = (namelen >> 8);
            dest[4 + 2] = 0;
            dest[4 + 1] = (namelen + 3);
            dest[4 + 0] = (namelen + 3) >> 8;
            dest[3] = namelen + 5;
            dest[2] = (namelen + 5) >> 8;

            dest += (namelen + 4 + 5);
	    modify = 1;
        }

        last_tag = tag;
        p += len;
        p += 4;
    }

    int extlen = (dest - extention_lengthp - 2);
    extention_lengthp[0] = extlen >> 8;
    extention_lengthp[1] = extlen;
    LOG("extlen: %d %d\n", extlen, extention_length);

    int newlen = dest - lengthp - 3;
    lengthp[0] = newlen >> 16;
    lengthp[1] = newlen >> 8;
    lengthp[2] = newlen;
    LOG("newlen: %d %d\n", newlen, mylength);

    memcpy(hold, snibuff, 5);
    int fulllength = (dest - hold - 5);
    hold[3] = fulllength >> 8;
    hold[4] = fulllength;

    int oldlen = (snibuff[3] << 8) | snibuff[4];
    LOG("fulllen: %d %d %ld\n", fulllength, oldlen, length);

    set_hook_name = 0;
    if (modify == 0 && strcmp(YOUR_DOMAIN, hostname)) { set_hook_name = 1; }
    if (modify == 0) return length;
    memcpy(snibuff, hold, dest - hold);
    return dest - hold;
}

void dump(char *buff, size_t len, struct tls_header *header, const char *title)
{
    LOG("%s: %d %x.%x %d\n", title, header->type, header->major, header->minor, header->length);
    if (22 == header->type) {
        int length = 0;
        uint8_t *p = buff;
        if (*p == 11) {
            LOG("certificate\n");
            return ;
        }
	int type = *p++;
        LOG("type: %x\n", type);
        length = p[2]|(p[1]<<8)|(p[0]<<16); p+=3;
        LOG("length: %d\n", length);
        LOG("version: %x.%x\n", p[0], p[1]);
        p += 2; // version;
                //
        p += 32; //random;
        LOG("session id length: %d\n", *p);
        p += *p;
        p++;
        int cipher_suite_length = p[1]|(p[0]<<8); p+=2;
        if (buff[0] == 2) {
            LOG("cipher_suite: %x\n", cipher_suite_length);
        } else {
            LOG("cipher_suite_length: %d\n", cipher_suite_length);
            p += cipher_suite_length;
        }
        int compress_method_len = *p++;
        LOG("compress_method_len: %d\n", compress_method_len);
        p += compress_method_len;
        int extention_length = p[1]|(p[0]<<8); p+=2;
        LOG("extention_lengh: %d\n", extention_length);
        const uint8_t *limit = p + extention_length;

        while (p < limit) {
            uint16_t tag = p[1]|(p[0]<<8);
            uint16_t len = p[3]|(p[2]<<8);
            LOG("ext tag: %d %d\n", tag, len);
            p += len;
            p += 4;
        }

    }
}

int pull(int connfd, int remotefd)
{
    char buff[MAX];
    int n, l, i;
    struct tls_header header;
    // infinite loop for chat

    // read the message from client and copy it in buffer
    l = read_flush(connfd, buff, 5);
    LOGV("%d l %d\n", connfd, l);
    if (l <= 0) return l;
    // perror("read");
    LOGV("l %d\n", l);
    assert(l == 5);
    // print buffer which contains the client contents
    header.type = buff[0];
    header.major = buff[1];
    header.major = buff[2];
    memcpy(&header.length, &buff[3], 2);
    header.length = htons(header.length);

    l = read_flush(connfd, buff + 5, header.length);

    // dump(buff + 5, l, &header, "PULL");
    return write_flush(remotefd, buff, l + 5);
}


// Function designed for chat between client and server.
int push(int connfd, int remotefd)
{
    char buff[MAX];
    int n, l, i;
    struct tls_header header;
    // infinite loop for chat

    // read the message from client and copy it in buffer
    l = read_flush(connfd, buff, 5);
    LOGV("%d l %d\n", connfd, l);
    if (l <= 0) return l;
    assert(l == 5);
    header.type = buff[0];
    header.major = buff[1];
    header.major = buff[2];
    memcpy(&header.length, &buff[3], 2);
    header.length = htons(header.length);

    l = read_flush(connfd, buff + 5, header.length);

    // dump(buff + 5, l, &header, "PUSH");
    return write_flush(remotefd, buff, l + 5);
}

int pipling(int connfd, int remotefd)
{
    char buff[65536];
    size_t len = read(connfd, buff, sizeof(buff));
    if (len == -1) return -1;
    return write_flush(remotefd, buff, len);
}

int setup_remote(struct sockaddr_in *cli, char *hostname)
{
    int i;
    int rc = -1;
    int remotefd = -1;
    struct hostent *phostent = NULL;

    if (RELAY_MODE == MODE_RELAY_CLIENT) {
	remotefd = socket(AF_INET, SOCK_STREAM, 0);

	cli->sin_addr.s_addr = inet_addr(YOUR_ADDRESS);
	rc = connect(remotefd, (struct sockaddr *)cli, sizeof(*cli));
	if (rc == -1) {
	    close(remotefd);
	    remotefd = -1;
	}

	return remotefd;
    }

    if (RELAY_MODE != MODE_RELAY_SERVER) {
	LOG("relay mode unkown: %d\n", RELAY_MODE);
	return -1;
    }

    phostent = gethostbyname(hostname);
    if (phostent == NULL) {
        return -1;
    }

    struct in_addr ** addr_list = (struct in_addr **)phostent->h_addr_list;

    for (i = 0; addr_list[i] != NULL; i++) {
        remotefd = socket(AF_INET, SOCK_STREAM, 0);

        LOG("connect %s \n", inet_ntoa(*addr_list[i]));

        cli->sin_addr = *addr_list[i];
        rc = connect(remotefd, (struct sockaddr *)cli, sizeof(*cli));
        if (rc == 0) {
            break;
        }

	perror("connect");
        close(remotefd);
        remotefd = -1;
    }

    return remotefd;
}

void func(int connfd)
{
    int rc;
    int n, l, i;
    fd_set test;
    uint8_t snibuff[4096];
    struct tls_header header;
    int remotefd = -1;

#if 0
    struct timeval tv;
    tv.tv_sec = 30;  /* 30 Secs Timeout */
    int ret = setsockopt(connfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    assert(ret == 0);
#endif

    l = read(connfd, snibuff, 5);
    assert (l == 5);

    header.type = snibuff[0];
    header.major = snibuff[1];
    header.major = snibuff[2];
    memcpy(&header.length, &snibuff[3], 2);
    header.length = htons(header.length);

    if (header.type != HANDSHAKE_TYPE) {
        close(remotefd);
        close(connfd);
        return;
    }

    if (header.length + 5 > sizeof(snibuff))
	fprintf(stderr, "len: %d\n", header.length);
    assert(header.length + 5 < sizeof(snibuff));

    int nbyte = read_flush(connfd, snibuff + 5, header.length);
    assert (nbyte == header.length);

    char hostname[128];
    int newlen = unwind_rewind_client_hello(snibuff, header.length + 5);
    header.length = newlen - 5;

    get_sni_name(snibuff + 5, header.length, hostname);
    LOGI("hostname: %s\n", hostname);
    if (*hostname == 0) {
        close(connfd);
        return;
    }

    struct sockaddr_in cli;
    cli.sin_family = AF_INET;
    cli.sin_port   = htons(YOUR_PORT);
    remotefd = setup_remote(&cli, hostname);

    if (remotefd == -1) {
        close(connfd);
        return;
    }

    rc = write(remotefd, snibuff, newlen);
    assert(rc == newlen);
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
		LOG("stat=%x n=%d\n", stat, n);
    } while (n > 0 && stat != 3);

    LOG("release connection\n");
    write(2, "RELEASE\n", 8);
    close(remotefd);
    close(connfd);
    return;
}

void clean_pcb(int signo)
{
    int st;
    LOG("clean_pcb\n");
    write(2, "clean_pcb\n", 10);
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

    LOG("parse_argopt>");
    for (i = 1; i < argc; i++) {
	const char *optname = argv[i];
	if (strcmp(optname, "-p") == 0) {
	    assert(i + 1 < argc);
	    YOUR_PORT = atoi(argv[++i]);
	} else
	if (strcmp(optname, "-l") == 0) {
	    assert(i + 1 < argc);
	    PORT = atoi(argv[++i]);
	} else
	if (strcmp(optname, "-d") == 0) {
	    assert(i + 1 < argc);
	    strcpy(YOUR_DOMAIN, argv[++i]);
	} else
	if (strcmp(optname, "-s") == 0) {
	    RELAY_MODE = MODE_RELAY_SERVER;
	    unwind_rewind_client_hello = unwind_client_hello;
	} else
	if (strcmp(optname, "-c") == 0) {
	    RELAY_MODE = MODE_RELAY_CLIENT;
	    unwind_rewind_client_hello = rewind_client_hello;
	} else
	if (*optname != '-') {
	    strcpy(YOUR_ADDRESS, argv[i]);
	}
    }
    LOG("<parse_argopt\n");

    assert(RELAY_MODE != MODE_RELAY_NONE);
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
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin6_family = AF_INET6;
    servaddr.sin6_port = htons(PORT);
    servaddr.sin6_addr = in6addr_any;

    int enable = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

    // Binding newly created socket to given IP and verification
    if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) {
        printf("socket bind failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully binded..\n");

    // Now server is ready to listen and verification
    if ((listen(sockfd, 5)) != 0) {
        printf("Listen failed...\n");
        exit(0);
    }
    else
        printf("Server listening..\n");
    len = sizeof(cli);

    do {
        len = sizeof(cli);
        // Accept the data packet from client and verification
        connfd = accept(sockfd, (SA*)&cli, &len);
        if (connfd < 0) {
            LOGI("server accept failed...\n");
            exit(0);
        }
        else
            LOGI("server accept the client...\n");

        if (fork() == 0) {close(sockfd); func(connfd); exit(0); }
        close(connfd);
        // Function for chatting between client and server
    } while (1);

    // After chatting close the socket
    close(sockfd);
    return 0;
}

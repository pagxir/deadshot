#define _GNU_SOURCE

#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>  /* compatibility layer */
#include <wolfssl/error-ssl.h>

#define caCertFile "./certs/ca-cert.pem"

int tx_setblockopt(int fd, int blockopt)
{
    int iflags, oflags;

    iflags = fcntl(fd, F_GETFL);

    oflags = (iflags | O_NONBLOCK);
    if (blockopt)
        oflags = (iflags & ~O_NONBLOCK);

    if (iflags != oflags)
        iflags = fcntl(fd, F_SETFL, oflags);

    return iflags;
}

#ifdef ENABLE_HTTP_CONVERT
int pidfd_open (pid_t pid, unsigned int flags)
{
    char buf[256];
    int fd = syscall(SYS_pidfd_open, pid, flags);

    if (fd == -1) {
        sprintf(buf, "/proc/%d/ns/net", pid);
        return open(buf, O_RDONLY);
    }

    return fd;
}

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
    if (err == -1)
        fprintf(stderr, "socket_netns pid=%d fd=%d err=%d %d %s\n", pid, fd, err, errno, strerror(errno));
    newfd = socket(family, type, protocol);
    sendfd(sv[0], newfd);
    close(sv[0]);
    exit(0);
}

static int http_set_connection_close(char *header, size_t len, int *outlen)
{
    int sol = 0;
    int line = 0;
    int adjust = 0;
    char * url = header;
    char connetionopt[256] = "Connection: Close\r\n";
    int connection0 = 0, connection9 = 0, urlend = 0;

    for (int i = 0; i < len; i++) {
        if (header[i] == '\n') {
            if (sol == 0) {
                urlend = i;
            } else if (strncasecmp(header + sol, "Connection:", 11) == 0) {
                connection0 = sol;
                connection9 = i + 1;
                break;
            } else if (strncasecmp(header + sol, "host:", 5) == 0 && connection0 == 0) {
                connection0 = i + 1;
                connection9 = i + 1;
            }

            sol = i + 1;
            line++;
        }
    }

    if (connection0 > 0) {
        adjust = connection0 + strlen(connetionopt);
        memmove(header + adjust, header + connection9, len - connection9);
        memcpy(header + connection0, connetionopt, strlen(connetionopt));
        len = len + strlen(connetionopt) - (connection9 - connection0);
        header[len] = 0;
        *outlen = len;
    }

    return 0;
}

static int http_convert(const char *hostopt, char *header, size_t len, int *outlen)
{
    int line = 0;
    int sol = 0;
    char * url = header;
    char domain[256] = "dummy";
    int host0 = 0, host9 = 0, urlend = 0;
    int connection0 = 0, connection9 = 0;

    for (int i = 0; i < len; i++) {
        if (header[i] == '\n') {
            if (sol == 0) {
                // fprintf(stderr, "\n--------------\n");
                // write(2, header, i);
                // fprintf(stderr, "\n///////////////////\n");
                urlend = i;
            } else if (strncasecmp(header + sol, "host:", 5) == 0) {
                sscanf(header + sol + 5, "%255s", domain);
                fprintf(stderr, "host: %s\n", domain);
                host0 = sol;
                host9 = i + 1;
                break;
            } else if (strncasecmp(header + sol, "Connection:", 11) == 0) {
                connection0 = sol;
                connection9 = i + 1;
                break;
            } else {
                // fprintf(stderr, "\n===%c.%c.%c=====\n", header[sol], header[sol+1], header[sol+2]);
                // write(2, header + sol, i - sol);
                // fprintf(stderr, "\n************\n");
            }

            sol = i + 1;
            line++;
        }
    }

    fprintf(stderr, "host0 %d host9 %d urlend %d domain %s line %d\n", host0, host9, urlend, domain, line);
    if (host0) {
        size_t len0 = strlen("/surfing.http/");
        size_t len1 = strlen(domain);

        size_t lenopt = strlen(hostopt);
        size_t result = len + len0 + len1 + lenopt - (host9 - host0);

        header[len] = 0;
        fprintf(stderr, "ORIGIN \n%s\n", header);
        fprintf(stderr, "------------------\n");
        fprintf(stderr, "\n\n");

        size_t part = len - host9;
        memmove(header + result - part, header + host9, part);

        int slash = 0;
        for (slash = 0; slash < urlend && header[slash] != '/'; slash++) ;
        assert (slash > 0 && header[slash - 1] == ' ');
        assert (slash < urlend);

        memmove(header + slash + len0 + len1, header + slash, host0 - slash);
        memmove(header + result - part - lenopt, hostopt, lenopt);

        strncpy(header + slash, "/surfing.http/", 14);
        strncpy(header + slash + 14, domain, strlen(domain));

        header[result] = 0;
        *outlen = result;
        http_set_connection_close(header, result, outlen);

        fprintf(stderr, "UPDATE \n%s\n", header);
        fprintf(stderr, "------------------\n");
        fprintf(stderr, "\n\n");

#if 0
        {
            FILE *fp = fopen("dump_http.dat", "wb");
            if (fp) { fwrite(header, result, 1, fp); fclose(fp); }
        }
#endif

        return 1;
        exit(0);
    }

    return 0;
}
#endif

static int child_quit = 0;
static void child_check_flags(int signo)
{
    child_quit = 1;
}

int main(int argc, char *argv[])
{
    int ret, err;
    int sockfd = 0;
    const char *host = "www.baidu.com";
    const char *netns = NULL;
    const char *servername = "www.baidu.com";
    const char *listen_port = "80";
    const char *connect_host = "172.67.206.226";
    char hostopt[384] = "Host: dl.603030.xyz\r\n";

    WOLFSSL*     ssl = NULL;
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (strcmp(arg, "-ca") == 0 && i < argc) {
            const char *caCert = argv[++i];
            if (WOLFSSL_SUCCESS != wolfSSL_CTX_load_verify_locations(ctx, caCert, 0)) {
                perror("wolfSSL_CTX_load_verify_locations");
            }
        } else if (strcmp(arg, "-cert") == 0 && i < argc) {
            const char *caCert = argv[++i];
            if (WOLFSSL_SUCCESS != wolfSSL_CTX_load_verify_locations_ex(ctx, argv[i], NULL, WOLFSSL_LOAD_FLAG_NONE)) {
                perror("wolfSSL_CTX_load_verify_locations_ex");
            }
        } else if (strcmp(arg, "-host") == 0 && i < argc) {
            host = argv[++i];
			snprintf(hostopt, sizeof(hostopt), "Host: %s\r\n", host);
        } else if (strcmp(arg, "-connect") == 0 && i < argc) {
            connect_host = argv[++i];
        } else if (strcmp(arg, "-listen") == 0 && i < argc) {
            listen_port = argv[++i];
        } else if (strcmp(arg, "-servername") == 0 && i < argc) {
            servername = argv[++i];
        } else if (strcmp(arg, "-netns") == 0) {
            netns = argv[++i];
        } else if (strcmp(arg, "-nonca") == 0) {
            wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
        }
    }

#ifdef ENABLE_HTTP_CONVERT
    int servfd = socket_netns(AF_INET6, SOCK_STREAM, 0, netns); 

    struct sockaddr_in6 local6;
    local6.sin6_family = AF_INET6;
    local6.sin6_port   = htons(atoi(listen_port));
    local6.sin6_addr   = in6addr_any;

    int reuse = 1;
    if (setsockopt(servfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) perror("setsockopt(SO_REUSEADDR) failed");

    int error = bind(servfd, (struct sockaddr *)&local6, sizeof(local6));
    assert (error == 0);

    error = listen(servfd, 0);
    assert (error == 0);

    socklen_t addrln = sizeof(local6);
    int httpfd = accept(servfd, (struct sockaddr *)&local6, &addrln);

    int child_count = 0;
    signal(SIGCHLD, child_check_flags);
    while (httpfd  > 0) {
        char buf[128];
        fprintf(stderr, "%d from %s:%d\n", child_count,
                inet_ntop(AF_INET6, &local6.sin6_addr, buf, sizeof(buf)), htons(local6.sin6_port));

        pid_t pid = child_count < 500? fork(): -1;

        if (pid == 0) {
            dup2(httpfd, 0);
            dup2(httpfd, 1);

            close(httpfd);
            break;
        }

        if (pid > 0) {
            child_count++;
        }

        close(httpfd);
        addrln = sizeof(local6);
        httpfd = accept(servfd, (struct sockaddr *)&local6, &addrln);
        if (child_quit) {
            child_quit = 0;
            int status = 0;
            pid_t pid = waitpid(-1, &status, WNOHANG);
            while (pid > 0) {
                child_quit--;
                pid = waitpid(-1, &status, WNOHANG);
            }
        }
    }
    assert(httpfd > 0);
#endif

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        goto done;
    }

    wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, servername, strlen(servername));

#if 0
    wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_NONE, NULL);
#endif

    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_port   = htons(443);
    inet_pton(AF_INET, connect_host, &servaddr.sin_addr);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    err = connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    if (err) {
        perror("connect");
        goto done;
    }

    if (wolfSSL_set_fd(ssl, sockfd) != WOLFSSL_SUCCESS) {
        /*err_sys("SSL_set_fd failed");*/
        goto done;
    }

    ret = wolfSSL_connect(ssl);
    err = wolfSSL_get_error(ssl, 0);
    wolfSSL_set_using_nonblock(ssl, 1);

#if 0
    char msg[] = "GET / HTTP/1.0\r\n"
        "Host: www.baidu.com\r\n"
        "\r\n";
    size_t msgSz = sizeof(msg);

    if (wolfSSL_write(ssl, msg, msgSz) != msgSz) {
        /*err_sys("SSL_write failed");*/
        goto done;
    }

    size_t input;
    char reply[1200];

    input = wolfSSL_read(ssl, reply, sizeof(reply)-1);
    if (input > 0) {
        reply[input] = '\0';
        fprintf(stderr, "Server response: %s\n", reply);
    }
#endif

    fd_set readfds, writefds;
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);

    int selected, converted = 1;
    int indir = 0, outdir = 0, reserve = 0;
    char inbuf[16384], outbuf[16384];
    size_t inoff = 0, outoff = 0, inlen = 0, outlen = 0;

    tx_setblockopt(0, 0);
    tx_setblockopt(1, 0);
    tx_setblockopt(sockfd, 0);

#ifdef ENABLE_HTTP_CONVERT
    converted = 0;
#endif

    do {
        ssize_t transfer = 0;
        if (FD_ISSET(0, &readfds)) indir |= 1;
        if (FD_ISSET(sockfd, &writefds)) indir |= 2;

        if (FD_ISSET(1, &writefds)) outdir |= 2;
        if (FD_ISSET(sockfd, &readfds)) outdir |= 1;

        while (indir == 3) {
            if (inoff < inlen) {
                transfer = wolfSSL_write(ssl, inbuf + inoff, inlen - inoff);
                if (transfer > 0) {
                    inoff += transfer;
                    indir &= ~2;
                } else if (wolfSSL_want_write(ssl)) {
                    indir &= ~2;
                } else if (wolfSSL_want_read(ssl)) {
                    outdir &= ~1;
                } else {
                    err = wolfSSL_get_error(ssl, transfer);
                    fprintf(stderr, "wolfSSL_write %ld error %d\n", transfer, err);
                    assert(transfer == SSL_FATAL_ERROR);
                    if (inoff == inlen) indir |= 4;
                    return 0;
                }
            }

            if (inoff == inlen && reserve == 0) {
                inlen = 0;
                inoff = 0;
            }

            if (inlen + reserve < sizeof(inbuf)) {
                transfer = read(0, inbuf + inlen + reserve, sizeof(inbuf) - inlen - reserve - (converted? 0: 512));
                if (transfer > 0) {
                    if (converted) {
                        inlen += transfer;
                    } else {
                        reserve += transfer;
                    }
                } else if (transfer == -1 && errno == EAGAIN) {
                    indir &= ~1;
                } else {
                    perror("read");
                    indir |= 4;
                    // return 0;
                }
            }

#ifdef ENABLE_HTTP_CONVERT
            // fprintf(stderr, "LONE %d %d %d %d %d\n", __LINE__, inoff, inlen, reserve, converted);
            if (converted == 0 && http_convert(hostopt, inbuf, reserve, &reserve)) {
                fprintf(stderr, "LINE %d %ld %ld %d %d\n", __LINE__, inoff, inlen, reserve, converted);
                converted = 1;
                inlen = reserve;
                reserve = 0;
            }
#endif
        }

        while (outdir == 3) {
            if (outoff < outlen) {
                transfer = write(1, outbuf + outoff, outlen - outoff);
                if (transfer > 0) {
                    outoff += transfer;
                    outdir &= ~2;
                } else if (errno == EAGAIN) {
                    outdir &= ~2;
                } else {
                    outdir |= 4;
                    perror("write");
                    return 0;
                }
            }

            if (outoff == outlen) {
                outlen = 0;
                outoff = 0;
            }

            if (outlen < sizeof(outbuf)) {
                transfer = wolfSSL_read(ssl, outbuf + outlen, sizeof(outbuf) - outlen);
                if (transfer > 0) {
                    outlen += transfer;
                } else if (wolfSSL_want_read(ssl)) {
                    outdir &= ~1;
                } else if (wolfSSL_want_write(ssl)) {
                    indir &= ~2;
                } else {
                    err = wolfSSL_get_error(ssl, transfer);
                    fprintf(stderr, "wolfSSL_read %ld error %d\n", transfer, err);
                    assert(transfer == SSL_FATAL_ERROR || err == WOLFSSL_ERROR_ZERO_RETURN);
                    if (outoff == outlen) outdir |= 4;
                    // return 0;
                }
            }
        }

        FD_ZERO(&readfds);
        if (~indir & 1) FD_SET(0, &readfds);
        if (~outdir & 1) FD_SET(sockfd, &readfds);

        FD_ZERO(&writefds);
        if (~outdir & 2) FD_SET(1, &writefds);
        if (~indir & 2) FD_SET(sockfd, &writefds);

        struct timeval timeout = { .tv_sec = 100, .tv_usec = 100 };
        selected = select(sockfd + 1, &readfds, &writefds, NULL, &timeout);

    }  while (selected > 0 && (indir < 4 || outdir < 4));

done:
    return 0;
}

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32_
#include <winsock.h>
typedef int socklen_t;
typedef unsigned long in_addr_t;
typedef unsigned short in_port_t;
#else
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#define getmappedbybuf(buff, buflen, addrptr, portptr) \
    getaddrbybuf(buff, buflen, MAPPED_ADDRESS, addrptr, portptr)

#define getchangedbybuf(buff, buflen, addrptr, portptr) \
    getaddrbybuf(buff, buflen, CHANGED_ADDRESS, addrptr, portptr)

/*
 * stun.l.google.com:19302
 * stun.ekiga.net:3478
 */

enum {
    BindingRequest = 0x0001,
    BindingResponse = 0x0101,
    BindingErrorResponse = 0x0111,
    MAPPED_ADDRESS = 0x0001,
    CHANGE_REQUEST = 0x0003,
    CHANGED_ADDRESS = 0x0005
};

int getaddrbybuf(void *buff, size_t buflen, int type,
        in_addr_t *addrptr, in_port_t *portptr)
{
    int error = -1;
    size_t ix, nx, cut;
    unsigned short hdr[2];
    unsigned char *bp = (unsigned char *)buff;

    for (ix=20,nx=24; nx<=buflen; ix=nx, nx+=4){
        memcpy(hdr, bp+ix, sizeof(hdr));
        cut = ntohs(hdr[1]);
        ix  = nx;
        nx += cut;
        if (htons(hdr[0])!=type)
            continue;
        if (nx > buflen)
            continue;
        if (cut==8 && bp[ix+1]==1){
            memcpy(portptr, bp+ix+2, 2);
            memcpy(addrptr, bp+ix+4, 4);
            error = 0;
        }
        break;
    }
    return error;

}

struct mapping_args{
    unsigned short binding_request, zero_field;
    unsigned int  tid0, tid1, tid2, tid3;
};

struct changing_args{
    unsigned short binding_request, zero_field;
    unsigned int  tid0, tid1, tid2, tid3;
    unsigned short change_request, len_field;
    unsigned char data[4];
};

static int _stid3 = 0;
static struct sockaddr_in  _schgaddr, _sinaddr;

#ifdef _WIN32_
void __declspec(dllexport) _()
{
}
#endif

struct natcb_t {
    int sockfd;
    int pending;
    int buflen;
    char stunbuf[2048];

    socklen_t peerlen;
    struct sockaddr_in peeraddr;
    struct sockaddr_in stunbear;
};

struct natcb_t * natcb_setup(struct natcb_t *cb)
{
    int fd;

#ifdef _WIN32_
    WSADATA data;
    WSAStartup(0x101, &data);
#endif

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        return NULL;

    cb->sockfd = fd;
    cb->pending = 0;
    cb->peerlen = sizeof(cb->peeraddr);
    return cb;
}

int natcb_free(struct natcb_t *cb)
{
#ifdef _WIN32_
    closesocket(cb->sockfd);
    WSACleanup();
#else
    close(cb->sockfd);
#endif
    return 0;
}

static int MAGIC_MAPPING = 0;
static int MAGIC_CHANGING = 1;

typedef void stun_callback(char *buf, void *udata);

int do_stun_maping(struct natcb_t *cb, stun_callback *callback, void *udata)
{
    int sent;
    struct mapping_args req;

    req.binding_request = htons(BindingRequest);
    req.zero_field      = htons(0);
    req.tid0 = (uint32_t)(uint64_t)&MAGIC_MAPPING;
    req.tid1 = htonl(0x5a5a5a5a);
    req.tid2 = htonl(0xaaaaaaaa);
    req.tid3 = htonl(_stid3++);

    sent = sendto(cb->sockfd, (const char *)&req, sizeof(req), 0, 
            (const struct sockaddr *)&cb->stunbear, sizeof(cb->stunbear));

    if (sent > 0) {
        cb->pending++;
    }

    return sent;
}

int do_stun_changing(struct natcb_t *cb, stun_callback *callback, void *udata)
{
    int sent;
    struct changing_args req;

    req.binding_request = htons(BindingRequest);
    req.zero_field = htons(8);
    req.tid0 = (uint32_t)(uint64_t)&MAGIC_CHANGING;
    req.tid1 = htonl(0x5a5a5a5a);
    req.tid2 = htonl(0xaaaaaaaa);
    req.tid3 = htonl(_stid3++);

    req.change_request = htons(CHANGE_REQUEST);
    req.len_field = htons(4);
    req.data[0] = 0;
    req.data[1] = 0;
    req.data[2] = 0;
#ifdef _TEST_SAME_IP
    req.data[3] = 4;
#else
    req.data[3] = 6;
#endif

    sent = sendto(cb->sockfd, (const char *)&req, sizeof(req), 0, 
            (const struct sockaddr *)&cb->stunbear, sizeof(cb->stunbear));

    if (sent > 0) {
        cb->pending++;
    }

    return sent;
}

void update_timer_list(struct natcb_t *cb)
{

}

void do_receive_update(struct natcb_t *cb)
{
    struct sockaddr_in  _schgaddr, _sinaddr;
    struct mapping_args *r = (struct mapping_args *)cb->stunbuf;

    printf("\r  from: %s:%d\n",
	    inet_ntoa(cb->peeraddr.sin_addr), htons(cb->peeraddr.sin_port));

    if (r->tid0 == (uint32_t)(uint64_t)&MAGIC_MAPPING
	    || r->tid0 == (uint32_t)(uint64_t)&MAGIC_CHANGING) {

	if (-1 == getmappedbybuf(cb->stunbuf, cb->buflen,
		    (in_addr_t*)&_schgaddr.sin_addr, &_schgaddr.sin_port))
	    return;

	printf("  mapped address: %s:%d\n",
		inet_ntoa(_schgaddr.sin_addr), htons(_schgaddr.sin_port));

	if (-1 == getchangedbybuf(cb->stunbuf, cb->buflen,
		    (in_addr_t*)&_schgaddr.sin_addr, &_schgaddr.sin_port))
	    return;

        printf(" changed server address: %s:%d\n",
                inet_ntoa(_schgaddr.sin_addr), htons(_schgaddr.sin_port));
    } else if (cb->buflen > 0) {
	printf("%s\n", cb->stunbuf);
	// receive FROM dupit8@gmail.com TO pagxir@gmail.com SESSION xxxx EXCHANGE 103.119.224.18:51901
	// send    FROM pagxir@gmail.com TO dupit8@gmail.com SESSION xxxx EXCHANGE 0.0.0.0:0
	// send    FROM pagxir@gmail.com SESSION xxxx (SYN|SYN+ACK) # check SESSION is receive any packet

    }

    return;
}

void check_and_receive(struct natcb_t *cb)
{
    fd_set readfds;
    int maxfd = cb->sockfd;
    int readycount = 0;

    struct sockaddr  rcvaddr;
    socklen_t rcvaddrlen = sizeof(rcvaddr);

    cb->peerlen = sizeof(cb->peeraddr);

    do {
        FD_ZERO(&readfds);
        FD_SET(cb->sockfd, &readfds);
        FD_SET(STDIN_FILENO, &readfds);
	struct timeval timeout = {1, 1};

        readycount = select(maxfd + 1, &readfds, NULL, NULL, &timeout);

        if (readycount > 0 && FD_ISSET(cb->sockfd, &readfds)) {
            cb->buflen = recvfrom(cb->sockfd, cb->stunbuf, sizeof(cb->stunbuf) -1,
                    0, (struct sockaddr *)&cb->peeraddr, &cb->peerlen);
	    if (cb->buflen > 0) {
		cb->stunbuf[cb->buflen] = 0;
		do_receive_update(cb);
		cb->pending--;
	    }
        }

        if (readycount > 0 && FD_ISSET(STDIN_FILENO, &readfds)) {
            /* handle next command */
            return;
        }

	if (readycount == 0) {
            update_timer_list(cb);
	}

    } while (cb->pending > 0);

    return;
}

int do_helo_exchange(struct natcb_t *cb, const char *buf)
{
    int sent;
    char barnner[] = "HELLO, WELCOME TO STUN.";

    sent = sendto(cb->sockfd, buf, strlen(buf), 0, 
            (const struct sockaddr *)&cb->peeraddr, cb->peerlen);

    if (sent > 0) {
	fprintf(stderr, "hello exchange!\n");
        cb->pending++;
    }

    fprintf(stderr, "hello %d\n", sent);
    return sent;
}

int do_update_config(struct natcb_t *cb, const char *buf)
{
    int match;
    char action[128], key[128], value[128];

    match = sscanf(buf, "%128s %128s %128s", action, key, value);

    if (3 != match) {
	fprintf(stderr, "missing set %d\n", match);
	return 0;
    }

    if (strcmp(key, "server") == 0 || strcmp(key, "peer") == 0) {
	char *port;
	struct hostent *phost;

	port = strchr(value, ':');
	if (port) *port++ = 0;

        phost = gethostbyname(value);
	if (!phost) {
	    return 0;
	}

	if (strcmp(key, "server") == 0) {
	    cb->stunbear.sin_family = AF_INET;
	    cb->stunbear.sin_port = htons(port? atoi(port): 3478);
	    cb->stunbear.sin_addr.s_addr = *(in_addr_t*)phost->h_addr;
	} else {
            cb->peerlen = sizeof(cb->peeraddr);
	    cb->peeraddr.sin_family = AF_INET;
	    cb->peeraddr.sin_port = htons(port? atoi(port): 3478);
	    cb->peeraddr.sin_addr.s_addr = *(in_addr_t*)phost->h_addr;
	}
    } else if (strcmp(key, "config") == 0) {
    }

    return 0;
}

int do_bind_address(struct natcb_t *cb, const char *buf)
{
    int match;
    char action[128], bufaddr[128];

    match = sscanf(buf, "%128s %128s", action, bufaddr);

    if (2 != match) {
        fprintf(stderr, "missing set %d\n", match);
        return 0;
    }

    char *port;
    struct hostent *phost;

    port = strchr(bufaddr, ':');
    if (port) *port++ = 0;

    phost = gethostbyname(bufaddr);
    if (!phost) {
        return 0;
    }

    struct sockaddr_in selfaddr;
    selfaddr.sin_family = AF_INET;
    selfaddr.sin_port = htons(port? atoi(port): 3478);
    selfaddr.sin_addr.s_addr = *(in_addr_t*)phost->h_addr;

    match = bind(cb->sockfd, (const struct sockaddr *)&selfaddr, sizeof(selfaddr));

    return 0;
}

void do_dump_status(struct natcb_t *cb)
{
    int error;
    struct sockaddr_in *inp, selfaddr;

    fprintf(stderr, "  sockfd %d\n", cb->sockfd);
    fprintf(stderr, "  pending %d\n", cb->pending);
    fprintf(stderr, "  buflen  %d\n", cb->buflen);

    inp = &cb->peeraddr;
    printf("  peer: %s:%d\n",
            inet_ntoa(inp->sin_addr), htons(inp->sin_port));

    inp = &cb->stunbear;
    printf("  bear: %s:%d\n",
            inet_ntoa(inp->sin_addr), htons(inp->sin_port));

    socklen_t selflen = sizeof(selfaddr);
    error = getsockname(cb->sockfd, (struct sockaddr *)&selfaddr, &selflen);
    if (error == -1) return;

    inp = &selfaddr;
    printf("  self: %s:%d\n",
            inet_ntoa(inp->sin_addr), htons(inp->sin_port));
    cb->pending++;
    return;
}

void print_usage()
{
   fprintf(stderr, "  help              print usage\n");
   fprintf(stderr, "  bind <address>    bind socket to address\n");
   fprintf(stderr, "  set <key> <value> set server|peer value\n");
   fprintf(stderr, "  helo              send hello to peer\n");
   fprintf(stderr, "  stun.map          send stun request to server\n");
   fprintf(stderr, "  stun.change       send stun change request to server\n");
}

int main(int argc, char *argv[])
{
    char action[128];
    char stdbuf[1024];
    struct natcb_t cb = {};

    natcb_setup(&cb);
    do_update_config(&cb, "set server stun.ekiga.net:3478");

    fprintf(stderr, "> ");
    while (fgets(stdbuf, sizeof(stdbuf), stdin)) {
        if (sscanf(stdbuf, "%128s", action) != 1) {
            goto check_pending;
        }

        if (strcmp(action, "bind") == 0) {
	    do_bind_address(&cb, stdbuf);
        } else if (strcmp(action, "dump") == 0) {
	    do_dump_status(&cb);
        } else if (strcmp(action, "help") == 0) {
	    print_usage();
        } else if (strcmp(action, "set") == 0) {
	    do_update_config(&cb, stdbuf);
        } else if (strcmp(action, "helo") == 0) {
	    do_helo_exchange(&cb, stdbuf +5);
        } else if (strcmp(action, "stun.map") == 0) {
            do_stun_maping(&cb, NULL, 0);
        } else if (strcmp(action, "stun.change") == 0) {
            do_stun_changing(&cb, NULL, 0);
        }

check_pending:
	fprintf(stderr, "> ");
        if (cb.pending > 0) {
           check_and_receive(&cb);
        }
    }

    natcb_free(&cb);

    return 0;
}

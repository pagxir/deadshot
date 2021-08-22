#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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

int do_bear_exchange(struct natcb_t *cb, const char *buf);
int do_peer_exchange(struct natcb_t *cb, const char *buf);
int set_config_host(struct sockaddr_in *target, char *value);

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

    char ident[128];
    char lock_key[128];
    char session[128];
    char acked_session[128];

    time_t lock_interval;
    time_t lock_nextcheck;

    int pair_ttl;
    time_t pair_interval;
    time_t pair_nextcheck;

    socklen_t peerlen;
    struct sockaddr_in bear;
    struct sockaddr_in stun;
    struct sockaddr_in peer;
    struct sockaddr_in from;
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
    cb->peerlen = sizeof(cb->bear);
    cb->pair_interval = 2;
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
            (const struct sockaddr *)&cb->stun, sizeof(cb->stun));

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
            (const struct sockaddr *)&cb->stun, sizeof(cb->stun));

    if (sent > 0) {
        cb->pending++;
    }

    return sent;
}

void run_session_action(struct natcb_t *cb)
{
    int is_acked = strcmp(cb->acked_session, cb->session) == 0;
    char peer_cmd[2048];

    sprintf(peer_cmd, "FROM %s SESSION %s SYN%s", cb->ident, cb->session, is_acked? "+ACK":"");
    fprintf(stderr, ">> %s\n", peer_cmd);
    do_peer_exchange(cb, peer_cmd);
    return;
}

void update_timer_list(struct natcb_t *cb)
{
    char ident_lock[2048];
    time_t current = time(NULL);

    if (cb->lock_interval > 0 &&
	    (cb->lock_nextcheck < current || cb->lock_nextcheck > current + cb->lock_interval)) {
	snprintf(ident_lock, sizeof(ident_lock), "FROM %s LOCK %s", cb->ident, cb->lock_key);
	do_bear_exchange(cb, ident_lock);
	cb->lock_nextcheck = current + cb->lock_interval;
	// fprintf(stderr, "+@ \n");
    }

    if (cb->pair_ttl > 0 && cb->pair_interval > 0 &&
	    (cb->pair_nextcheck < current || cb->pair_nextcheck > current + cb->pair_interval)) {
	// fprintf(stderr, "+# %d\n", cb->pair_ttl);
        if (cb->pair_ttl > 0) {
            run_session_action(cb);
            cb->pair_nextcheck = current + cb->pair_interval;
            cb->pair_ttl --;
        } 
    }

    return;
}

void do_receive_update(struct natcb_t *cb)
{
    struct sockaddr_in  _schgaddr, _sinaddr;
    struct mapping_args *r = (struct mapping_args *)cb->stunbuf;

    printf("\r<  from: %s:%d\n",
	    inet_ntoa(cb->from.sin_addr), htons(cb->from.sin_port));

    if (r->tid0 == (uint32_t)(uint64_t)&MAGIC_MAPPING
	    || r->tid0 == (uint32_t)(uint64_t)&MAGIC_CHANGING) {

	if (-1 == getmappedbybuf(cb->stunbuf, cb->buflen,
		    (in_addr_t*)&_schgaddr.sin_addr, &_schgaddr.sin_port))
	    return;

	printf("<  mapped address: %s:%d\n",
		inet_ntoa(_schgaddr.sin_addr), htons(_schgaddr.sin_port));

	if (-1 == getchangedbybuf(cb->stunbuf, cb->buflen,
		    (in_addr_t*)&_schgaddr.sin_addr, &_schgaddr.sin_port))
	    return;

        printf("< changed server address: %s:%d\n",
                inet_ntoa(_schgaddr.sin_addr), htons(_schgaddr.sin_port));
    } else if (cb->buflen > 0) {
	printf("<  %s\n", cb->stunbuf);
	// receive FROM dupit8@gmail.com TO pagxir@gmail.com SESSION xxxx EXCHANGE 103.119.224.18:51901
	// send    FROM pagxir@gmail.com TO dupit8@gmail.com SESSION xxxx EXCHANGE 0.0.0.0:0
	// send    FROM pagxir@gmail.com SESSION xxxx (SYN|SYN+ACK) # check SESSION is receive any packet
        char peer_cmd[2048];
	char from[128], to[128], session[128], exchange[128], flags[128];

	int match = sscanf(cb->stunbuf, "FROM %s TO %s SESSION %s EXCHANGE %s%s", from, to, session, exchange, flags);
        if (match == 4 || match == 5) {
            fprintf(stderr, "start session %s handshake %s\n", session, exchange);
            set_config_host(&cb->peer, exchange);

            if (strcmp(flags, "ACK")) {
                snprintf(peer_cmd, sizeof(peer_cmd), "FROM %s TO %s SESSION %s EXCHANGE 0.0.0.0:0 ACK", cb->ident, from, session);
		fprintf(stderr, ">> %s\n", peer_cmd);
                do_bear_exchange(cb, peer_cmd);
            }

	    strcpy(cb->session, session);
	    cb->pair_ttl = 3;
            run_session_action(cb);
            return;
        }

	match = sscanf(cb->stunbuf, "FROM %s SESSION %s SY%s", from, session, flags);
        if (match == 3) {
            cb->peer = cb->from;
            strcpy(cb->acked_session, session);
	    if (strcmp(flags, "N+ACK") == 0) {
                snprintf(peer_cmd, sizeof(peer_cmd), "FROM %s SESSION %s ACK", cb->ident, session);
                do_peer_exchange(cb, peer_cmd);
		cb->pair_ttl = 0;
	    } else {
		run_session_action(cb);
	    }
            fprintf(stderr, "receive session %s handshake %s %d\n", session, flags, cb->pair_ttl);
            return;
        }

	match = sscanf(cb->stunbuf, "FROM %s SESSION %s AC%s", from, session, flags);
        if (match == 3) {
            fprintf(stderr, "receive session %s handshake %d\n", session, cb->pair_ttl);
            cb->peer = cb->from;
            strcpy(cb->acked_session, session);
	    cb->pair_ttl = 0;
            return;
        }
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

    cb->peerlen = sizeof(cb->from);

    do {
        FD_ZERO(&readfds);
        FD_SET(cb->sockfd, &readfds);
        FD_SET(STDIN_FILENO, &readfds);
	struct timeval timeout = {1, 1};

        readycount = select(maxfd + 1, &readfds, NULL, NULL, &timeout);

        if (readycount > 0 && FD_ISSET(cb->sockfd, &readfds)) {
            cb->buflen = recvfrom(cb->sockfd, cb->stunbuf, sizeof(cb->stunbuf) -1,
                    0, (struct sockaddr *)&cb->from, &cb->peerlen);
	    if (cb->buflen > 0) {
		cb->stunbuf[cb->buflen] = 0;
		do_receive_update(cb);
		// cb->pending--;
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

int do_peer_exchange(struct natcb_t *cb, const char *buf)
{
    int sent;

    sent = sendto(cb->sockfd, buf, strlen(buf), 0, 
            (const struct sockaddr *)&cb->peer, sizeof(cb->peer));

    if (sent > 0) {
	// fprintf(stderr, "hello exchange!\n");
        cb->pending++;
    } else {
      fprintf(stderr, "hello %d\n", sent);
    }

    return sent;
}

int do_bear_exchange(struct natcb_t *cb, const char *buf)
{
    int sent;
    char barnner[] = "HELLO, WELCOME TO STUN.";

    sent = sendto(cb->sockfd, buf, strlen(buf), 0, 
            (const struct sockaddr *)&cb->bear, cb->peerlen);

    if (sent > 0) {
	// fprintf(stderr, "hello exchange!\n");
        cb->pending++;
    } else {
      fprintf(stderr, "hello %d\n", sent);
    }

    return sent;
}

int set_config_host(struct sockaddr_in *target, char *value)
{
    char *port;
    struct hostent *phost;

    port = strchr(value, ':');
    if (port) *port++ = 0;

    phost = gethostbyname(value);
    if (!phost) {
	return 0;
    }

    target->sin_family = AF_INET;
    target->sin_port = htons(port? atoi(port): 3478);
    target->sin_addr.s_addr = *(in_addr_t*)phost->h_addr;
    return 0;
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

    if (strcmp(key, "bear") == 0) {
	set_config_host(&cb->bear, value);
    } else if (strcmp(key, "peer") == 0) {
	set_config_host(&cb->peer, value);
    } else if (strcmp(key, "stun") == 0) {
	set_config_host(&cb->stun, value);
    } else if (strcmp(key, "lock.key") == 0) {
	strncpy(cb->lock_key, value, sizeof(cb->lock_key) -1);
    } else if (strcmp(key, "lock.interval") == 0) {
	cb->lock_interval = atoi(value);
    } else if (strcmp(key, "ident") == 0) {
	strncpy(cb->ident, value, sizeof(cb->ident) -1);
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
    fprintf(stderr, "  ident  %s\n", cb->ident);
    fprintf(stderr, "  lock_key  %s\n", cb->lock_key);
    fprintf(stderr, "  lock_interval  %ld\n", cb->lock_interval);

    inp = &cb->peer;
    printf("  peer: %s:%d\n",
            inet_ntoa(inp->sin_addr), htons(inp->sin_port));

    inp = &cb->bear;
    printf("  bear: %s:%d\n",
            inet_ntoa(inp->sin_addr), htons(inp->sin_port));

    inp = &cb->stun;
    printf("  stun: %s:%d\n",
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
   fprintf(stderr, "  peer              send message to peer\n");
   fprintf(stderr, "  bear              send message to bear\n");
   fprintf(stderr, "  bear.stun         send stun message to bear\n");
   fprintf(stderr, "  stun.map          send stun request to server\n");
   fprintf(stderr, "  stun.change       send stun change request to server\n");
}

int main(int argc, char *argv[])
{
    char action[128];
    char stdbuf[1024];
    char helo_line[2048];
    char last_line[2048];
    struct natcb_t cb = {};

    natcb_setup(&cb);
    do_update_config(&cb, "set server stun.ekiga.net:3478");

    fprintf(stderr, "> ");
    while (fgets(stdbuf, sizeof(stdbuf), stdin)) {
        if (sscanf(stdbuf, "%128s", action) != 1) {
            goto check_pending;
        }

        if (strcmp(action, "r") == 0) {
	    fprintf(stderr, "+ %s\n", last_line);
            strncpy(stdbuf, last_line, sizeof(stdbuf) -1);
            sscanf(stdbuf, "%128s", action);
        }

        if (strcmp(action, "bind") == 0) {
	    do_bind_address(&cb, stdbuf);
        } else if (strcmp(action, "dump") == 0) {
	    do_dump_status(&cb);
        } else if (strcmp(action, "help") == 0) {
	    print_usage();
        } else if (strcmp(action, "set") == 0) {
	    do_update_config(&cb, stdbuf);
        } else if (strcmp(action, "peer") == 0) {
            strncpy(last_line, stdbuf, sizeof(last_line) -1);
	    do_peer_exchange(&cb, stdbuf +5);
        } else if (strcmp(action, "bear") == 0) {
            strncpy(last_line, stdbuf, sizeof(last_line) -1);
	    do_bear_exchange(&cb, stdbuf +5);
        } else if (strcmp(action, "print") == 0) {
	    printf("%s", stdbuf + 5);
        } else if (strcmp(action, "bear.stun") == 0) {
	    snprintf(helo_line, sizeof(helo_line), "FROM %s STUN.MAP", cb.ident);
	    do_bear_exchange(&cb, helo_line);
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

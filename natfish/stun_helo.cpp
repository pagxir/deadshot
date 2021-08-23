#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

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

int do_peer_bearing(struct natcb_t *cb, const char *buf);
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

struct session_t {
    int sockfd;
    int lastout;

    int ttl;
    int readable;
    char cache[2028];

    time_t interval;
    time_t lastcheck;
    struct sockaddr_in target;
};

void update_session(struct session_t *s)
{
    int nbyte;
    time_t current;

    if (s->interval == 0 || s->ttl == 0) {
	return;
    }

    time(&current);
    if (current > s->lastcheck && 
	    current < s->lastcheck + s->interval) {
	return;
    }

    nbyte = sendto(s->sockfd, s->cache, strlen(s->cache), 0,
	    (const struct sockaddr *)&s->target, sizeof(s->target));

    if (s->ttl > 0) {
	s->ttl --;
    }

    s->readable++;
    s->lastout = nbyte;
    s->lastcheck = current;
    return;
}

struct natcb_t {
    struct session_t bear;
    struct session_t peer;

    int buflen;
    char stunbuf[2048];

    int passfd;
    char ident[128];
    char lock_key[128];
    char session[128];
    char acked_session[128];

    socklen_t size;
    struct sockaddr_in stun;
    struct sockaddr_in from;
};

struct natcb_t * natcb_setup(struct natcb_t *cb)
{
    int fd;

#ifdef _WIN32_
    WSADATA data;
    WSAStartup(0x101, &data);
#endif

    cb->bear.sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    cb->peer.sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (cb->bear.sockfd == -1 ||
	    cb->peer.sockfd == -1) {
	close(cb->bear.sockfd);
	close(cb->peer.sockfd);
	return NULL;
    }

    cb->peer.interval = 2;
    return cb;
}

int natcb_free(struct natcb_t *cb)
{
#ifdef _WIN32_
    closesocket(cb->peer.sockfd);
    closesocket(cb->bear.sockfd);
    WSACleanup();
#else
    close(cb->peer.sockfd);
    close(cb->bear.sockfd);
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

    sent = sendto(cb->peer.sockfd, (const char *)&req, sizeof(req), 0, 
            (const struct sockaddr *)&cb->stun, sizeof(cb->stun));

    if (sent > 0) cb->peer.readable++;

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

    sent = sendto(cb->peer.sockfd, (const char *)&req, sizeof(req), 0, 
            (const struct sockaddr *)&cb->stun, sizeof(cb->stun));

    if (sent > 0) cb->peer.readable++;

    return sent;
}

void update_timer_list(struct natcb_t *cb)
{
    update_session(&cb->peer);
    update_session(&cb->bear);
    return;
}

void set_session_action(struct natcb_t *cb)
{
    int nbyte;
    int is_acked = strcmp(cb->acked_session, cb->session) == 0;
    struct session_t *s = &cb->peer;

    snprintf(s->cache, sizeof(s->cache),
	    "FROM %s SESSION %s SYN%s", cb->ident, cb->session, is_acked? "+ACK":"");

    nbyte = sendto(s->sockfd, s->cache, strlen(s->cache), 0,
	    (const struct sockaddr *)&s->target, sizeof(s->target));
    if (nbyte > 0) s->readable++;

    fprintf(stderr, ">> %s\n", s->cache);
    return;
}

void do_receive_update(struct natcb_t *cb)
{
    struct sockaddr_in  _schgaddr, _sinaddr;
    struct mapping_args *r = (struct mapping_args *)cb->stunbuf;

    printf("\r<<  from: %s:%d\n",
	    inet_ntoa(cb->from.sin_addr), htons(cb->from.sin_port));

    if (r->tid0 == (uint32_t)(uint64_t)&MAGIC_MAPPING
	    || r->tid0 == (uint32_t)(uint64_t)&MAGIC_CHANGING) {

	if (-1 == getmappedbybuf(cb->stunbuf, cb->buflen,
		    (in_addr_t*)&_schgaddr.sin_addr, &_schgaddr.sin_port))
	    return;

	printf("<<  mapped address: %s:%d\n",
		inet_ntoa(_schgaddr.sin_addr), htons(_schgaddr.sin_port));

	if (-1 == getchangedbybuf(cb->stunbuf, cb->buflen,
		    (in_addr_t*)&_schgaddr.sin_addr, &_schgaddr.sin_port))
	    return;

        printf("<< changed server address: %s:%d\n",
                inet_ntoa(_schgaddr.sin_addr), htons(_schgaddr.sin_port));
    } else if (cb->buflen > 0) {
	printf("<<  %s\n", cb->stunbuf);
	// receive FROM dupit8@gmail.com TO pagxir@gmail.com SESSION xxxx EXCHANGE 103.119.224.18:51901
	// send    FROM pagxir@gmail.com TO dupit8@gmail.com SESSION xxxx EXCHANGE 0.0.0.0:0
	// send    FROM pagxir@gmail.com SESSION xxxx (SYN|SYN+ACK) # check SESSION is receive any packet
        char peer_cmd[2048];
	char from[128], to[128], session[128], exchange[128], flags[128];

	int match = sscanf(cb->stunbuf, "FROM %s TO %s SESSION %s EXCHANGE %s%s", from, to, session, exchange, flags);
        if (match == 4 || match == 5) {
            fprintf(stderr, "start session %s handshake %s\n", session, exchange);
            set_config_host(&cb->peer.target, exchange);

            if (strcmp(flags, "ACK")) {
                snprintf(peer_cmd, sizeof(peer_cmd), "FROM %s TO %s SESSION %s EXCHANGE 0.0.0.0:0 ACK", cb->ident, from, session);
		fprintf(stderr, ">> %s\n", peer_cmd);
                do_peer_bearing(cb, peer_cmd);
            } else {
		strcpy(cb->acked_session, "");
	    }

	    strcpy(cb->session, session);
	    cb->peer.ttl = 8;
            set_session_action(cb);
            return;
        }

	match = sscanf(cb->stunbuf, "FROM %s SESSION %s SY%s", from, session, flags);
        if (match == 3) {
            cb->peer.target = cb->from;
            strcpy(cb->acked_session, session);
	    if (strcmp(flags, "N+ACK") == 0) {
                snprintf(peer_cmd, sizeof(peer_cmd), "FROM %s SESSION %s ACK", cb->ident, session);
                do_peer_exchange(cb, peer_cmd);
		cb->peer.ttl = 0;
	    } else {
                set_session_action(cb);
	    }

            fprintf(stderr, "receive session %s handshake %s %d\n", session, flags, cb->peer.ttl);
            return;
        }

	match = sscanf(cb->stunbuf, "FROM %s SESSION %s AC%s", from, session, flags);
        if (match == 3) {
            fprintf(stderr, "receive session %s handshake %d\n", session, cb->peer.ttl);
            cb->peer.target = cb->from;
            strcpy(cb->acked_session, session);
	    cb->peer.ttl = 0;
            return;
        }

	match = sscanf(cb->stunbuf, "FROM %s PIN%s", from, flags);
        if (match == 2) {
	    sprintf(cb->stunbuf, "FROM %s PONG", cb->ident);
	    int sent = sendto(cb->peer.sockfd, cb->stunbuf, strlen(cb->stunbuf), 0, 
			    (const struct sockaddr *)&cb->from, sizeof(cb->from));
            fprintf(stderr, "receive ping %s %d\n", from, sent);
            return;
        }
    }

    return;
}


void session_receive(struct natcb_t *cb, struct session_t *sb)
{
    cb->size = sizeof(cb->from);
    cb->buflen = recvfrom(sb->sockfd, cb->stunbuf, sizeof(cb->stunbuf) -1,
	    0, (struct sockaddr *)&cb->from, &cb->size);

    if (cb->buflen > 0) {
	cb->stunbuf[cb->buflen] = 0;
	do_receive_update(cb);
    }

    return;
}

void check_and_receive(struct natcb_t *cb, int usestdin)
{
    fd_set readfds;
    int maxfd = STDIN_FILENO;
    int readycount = 0;

    FD_ZERO(&readfds);
    if (usestdin) {
	FD_SET(STDIN_FILENO, &readfds);
    }

    if (cb->bear.sockfd > 0 && cb->bear.readable) {
        FD_SET(cb->bear.sockfd, &readfds);
	maxfd = cb->bear.sockfd > maxfd? cb->bear.sockfd: maxfd;
    }

    if (cb->peer.sockfd > 0 && cb->peer.readable) {
        FD_SET(cb->peer.sockfd, &readfds);
	maxfd = cb->peer.sockfd > maxfd? cb->peer.sockfd: maxfd;
    }

    do {
	fd_set myfds = readfds;
	struct timeval timeout = {1, 1};

        readycount = select(maxfd + 1, &myfds, NULL, NULL, &timeout);
	if (readycount == 0) {
	    update_timer_list(cb);
	}

	if (readycount > 0 && cb->peer.readable && FD_ISSET(cb->peer.sockfd, &myfds)) {
	    session_receive(cb, &cb->peer);
	    readycount--;
	}

	if (readycount > 0 && cb->bear.readable && FD_ISSET(cb->bear.sockfd, &myfds)) {
	    session_receive(cb, &cb->bear);
	    readycount--;
	}

	if (readycount > 0 && FD_ISSET(STDIN_FILENO, &readfds)) {
	    /* handle next command */
	    return;
	}

    } while ((cb->bear.readable || cb->peer.readable) && usestdin);

    return;
}

int do_peer_exchange(struct natcb_t *cb, const char *buf)
{
    int sent;

    sent = sendto(cb->peer.sockfd, buf, strlen(buf), 0, 
            (const struct sockaddr *)&cb->peer.target, sizeof(cb->peer.target));

    if (sent > 0) {
        cb->peer.readable++;
    }

    return sent;
}

int do_peer_bearing(struct natcb_t *cb, const char *buf)
{
    int sent;

    sent = sendto(cb->peer.sockfd, buf, strlen(buf), 0, 
            (const struct sockaddr *)&cb->bear.target, sizeof(cb->bear.target));

    if (sent > 0) {
        cb->peer.readable++;
    }

    return sent;
}

int do_bear_exchange(struct natcb_t *cb, const char *buf)
{
    int sent;

    sent = sendto(cb->bear.sockfd, buf, strlen(buf), 0, 
            (const struct sockaddr *)&cb->bear.target, sizeof(cb->bear.target));

    if (sent > 0) {
        cb->bear.readable++;
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

void config_ident_lock(struct natcb_t *cb)
{
    int nbyte;
    struct session_t *s = &cb->bear;

    if (*cb->ident && *cb->lock_key) {
      snprintf(cb->bear.cache, sizeof(cb->bear.cache),
	  "FROM %s LOCK %s", cb->ident, cb->lock_key);

      nbyte = sendto(s->sockfd, s->cache, strlen(s->cache), 0,
	  (const struct sockaddr *)&s->target, sizeof(s->target));

      fprintf(stderr, ">> %s\n", cb->peer.cache);
      if (nbyte > 0) s->readable++;
      s->ttl = -1;
    }

    return;
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
	set_config_host(&cb->bear.target, value);
    } else if (strcmp(key, "peer") == 0) {
	set_config_host(&cb->peer.target, value);
    } else if (strcmp(key, "stun") == 0) {
	set_config_host(&cb->stun, value);
    } else if (strcmp(key, "lock.key") == 0) {
	strncpy(cb->lock_key, value, sizeof(cb->lock_key) -1);
	config_ident_lock(cb);
    } else if (strcmp(key, "lock.interval") == 0) {
	cb->bear.interval = atoi(value);
    } else if (strcmp(key, "passfd") == 0) {
	cb->passfd = atoi(value);
    } else if (strcmp(key, "ident") == 0) {
	strncpy(cb->ident, value, sizeof(cb->ident) -1);
	config_ident_lock(cb);
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

    match = bind(cb->peer.sockfd, (const struct sockaddr *)&selfaddr, sizeof(selfaddr));

    return 0;
}

void do_dump_status(struct natcb_t *cb)
{
    int error;
    struct sockaddr_in *inp, selfaddr;

    fprintf(stderr, "  buflen  %d\n", cb->buflen);
    fprintf(stderr, "  ident  %s\n", cb->ident);
    fprintf(stderr, "  lock_key  %s\n", cb->lock_key);
    fprintf(stderr, "  lock_interval  %ld\n", cb->bear.interval);

    inp = &cb->peer.target;
    printf("  peer: %s:%d\n",
            inet_ntoa(inp->sin_addr), htons(inp->sin_port));

    inp = &cb->bear.target;
    printf("  bear: %s:%d\n",
            inet_ntoa(inp->sin_addr), htons(inp->sin_port));

    inp = &cb->stun;
    printf("  stun: %s:%d\n",
            inet_ntoa(inp->sin_addr), htons(inp->sin_port));

    socklen_t selflen = sizeof(selfaddr);
    error = getsockname(cb->bear.sockfd, (struct sockaddr *)&selfaddr, &selflen);
    if (error == -1) return;

    inp = &selfaddr;
    printf("  self-bear: %s:%d\n",
            inet_ntoa(inp->sin_addr), htons(inp->sin_port));

    error = getsockname(cb->peer.sockfd, (struct sockaddr *)&selfaddr, &selflen);
    inp = &selfaddr;
    printf("  self-peer: %s:%d\n",
            inet_ntoa(inp->sin_addr), htons(inp->sin_port));
    return;
}

void do_repl_exec(struct natcb_t *cb, const char *buf)
{
    char value[1024];
    struct sockaddr_in selfaddr;

    socklen_t selflen = sizeof(selfaddr);
    int error = getsockname(cb->peer.sockfd, (struct sockaddr *)&selfaddr, &selflen);
    if (error == -1) return;


    sprintf(value, "%s:%d\n",
		    inet_ntoa(selfaddr.sin_addr), htons(selfaddr.sin_port));
    setenv("LOCAL", value, 1);

    selfaddr = cb->peer.target;
    sprintf(value, "%s:%d\n",
		    inet_ntoa(selfaddr.sin_addr), htons(selfaddr.sin_port));
    setenv("REMOTE", value, 1);

    sprintf(value, "%d", cb->peer.sockfd);
    if (cb->passfd == 0) {
	close(cb->peer.sockfd);
    } else {
	setenv("SOCKFD", value, 1);
    }

    close(cb->bear.sockfd);

    execl("/bin/sh", "sh", "-c", buf, (char *) NULL);
    exit(0);
}

void do_fork_exec(struct natcb_t *cb, const char *buf)
{
    pid_t pid;
    char value[1024];
    struct sockaddr_in selfaddr;

    socklen_t selflen = sizeof(selfaddr);
    int error = getsockname(cb->peer.sockfd, (struct sockaddr *)&selfaddr, &selflen);
    if (error == -1) return;

    pid = fork();
    if (pid == 0) {
	sprintf(value, "%s:%d\n",
		inet_ntoa(selfaddr.sin_addr), htons(selfaddr.sin_port));
	setenv("LOCAL", value, 1);

	selfaddr = cb->peer.target;
        sprintf(value, "%s:%d\n",
		inet_ntoa(selfaddr.sin_addr), htons(selfaddr.sin_port));
	setenv("REMOTE", value, 1);

	sprintf(value, "%d", cb->peer.sockfd);
	if (cb->passfd == 0) {
	    close(cb->peer.sockfd);
	} else {
	    setenv("SOCKFD", value, 1);
	}

        execl("/bin/sh", "sh", "-c", buf, (char *) NULL);
	exit(0);
    }

    close(cb->peer.sockfd);
    cb->peer.sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    cb->peer.readable = 0;
    return;
}

void print_usage()
{
   fprintf(stderr, "  help              print usage\n");
   fprintf(stderr, "  dump              dump status\n");
   fprintf(stderr, "  ping              request peer remote endpoint echo\n");
   fprintf(stderr, "  delay             delay handle next command\n");
   fprintf(stderr, "  exec              exec command\n");
   fprintf(stderr, "  fork              fork command\n");
   fprintf(stderr, "  handover          handover peer socket to command\n");
   fprintf(stderr, "  bind <address>    bind socket to address\n");
   fprintf(stderr, "  set <key> <value> set server|peer value\n");
   fprintf(stderr, "  peer              send message to peer\n");
   fprintf(stderr, "  peer.bear         send message to bear (use peer channel)\n");
   fprintf(stderr, "  bear              send message to bear\n");
   fprintf(stderr, "  bear.stun         send stun message to bear\n");
   fprintf(stderr, "  stun.map          send stun request to server\n");
   fprintf(stderr, "  stun.change       send stun change request to server\n");
}

void signal_child_handler(int signo)
{
    int wstatus;

    while (waitpid(-1, &wstatus, WNOHANG) > 0);
}

int main(int argc, char *argv[])
{
    char action[128];
    char stdbuf[1024];
    char helo_line[2048];
    char last_line[2048];
    struct natcb_t cb = {};

    natcb_setup(&cb);
    do_update_config(&cb, "set stun stun.ekiga.net:3478");

    signal(SIGCHLD, signal_child_handler);
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
        } else if (strcmp(action, "peer.bear") == 0) {
            strncpy(last_line, stdbuf, sizeof(last_line) -1);
	    do_peer_bearing(&cb, stdbuf +10);
        } else if (strcmp(action, "bear") == 0) {
            strncpy(last_line, stdbuf, sizeof(last_line) -1);
	    do_bear_exchange(&cb, stdbuf +5);
        } else if (strcmp(action, "bear.stun") == 0) {
	    snprintf(helo_line, sizeof(helo_line), "FROM %s STUN.MAP", cb.ident);
	    do_bear_exchange(&cb, helo_line);
        } else if (strcmp(action, "print") == 0) {
	    printf("%s", stdbuf + 5);
        } else if (strcmp(action, "ping") == 0) {
	    snprintf(helo_line, sizeof(helo_line), "FROM %s PING", cb.ident);
	    do_peer_exchange(&cb, helo_line);
        } else if (strcmp(action, "exec") == 0) {
             do_repl_exec(&cb, stdbuf + 5);
        } else if (strcmp(action, "fork") == 0) {
             do_fork_exec(&cb, stdbuf + 5);
        } else if (strcmp(action, "delay") == 0) {
            int delay = 0;
	    if (sscanf(stdbuf, "delay %d", &delay) == 1 &&
		    delay > 0 && delay < 30) {
		time_t start = time(NULL);
		while (start + delay > time(NULL))
			check_and_receive(&cb, 0);
	    }
        } else if (strcmp(action, "stun.map") == 0) {
            do_stun_maping(&cb, NULL, 0);
        } else if (strcmp(action, "stun.change") == 0) {
            do_stun_changing(&cb, NULL, 0);
        }

check_pending:
	fprintf(stderr, "> ");
	check_and_receive(&cb, 1);
    }

    natcb_free(&cb);

    return 0;
}

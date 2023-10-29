#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
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

struct natcb_t {
	int sockfd;
	int pending;
	int buflen;
	char stunbuf[2048];

	socklen_t peerlen;
	struct sockaddr_in6 peeraddr;
	struct sockaddr_in6 stunbear;
};

struct natcb_t * natcb_setup(struct natcb_t *cb)
{
	int fd;

#ifdef _WIN32_
	WSADATA data;
	WSAStartup(0x101, &data);
#endif

	if ((fd = socket(AF_INET6, SOCK_DGRAM, 0)) == -1)
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

/*
 * handle following command:
 * 1. FROM aaa LOCK yyy
 * 2. FROM aaa TO bbb SESSION sss EXCHANGE cc.cc.cc.cc:cc
 * 3. FROM aaa STUN.MAP
 */

struct friend_t {
	char ident[128];
	char lockword[128];

	time_t lastactive;
	struct sockaddr_in6 endpoint;
};

#define MAX_FRIEND 128
static int _all_nfriend = 0;
static struct friend_t _all_friends[MAX_FRIEND];

static int update_friend(const char *buf, const struct sockaddr_in6 *endpoint)
{
	int match, n;
	char title[128], from[128], action[128], lockname[128];

	match = sscanf(buf, "%128s %128s %128s %128s", title, from, action, lockname);
	if (match != 4) {
		return 0;
	}

	struct friend_t *fptr;
	struct friend_t *found = NULL;

	for (n = 0; n < _all_nfriend; n++) {
		fptr = _all_friends + n;
		if (strcmp(fptr->ident, from) == 0) {
			found = fptr;
			break;
		}
	}

	if (found != NULL && strcmp(found->lockword, lockname)) {
		return 0;
	}

	if (found == NULL && _all_nfriend < MAX_FRIEND) {
		found = _all_friends + _all_nfriend;
		strncpy(found->lockword, lockname, sizeof(found->lockword) -1);
		strncpy(found->ident, from, sizeof(found->ident) -1);
		_all_nfriend++;
	}

	if (found != NULL) {
		found->lastactive = time(NULL);
		found->endpoint = *endpoint;
		return 1;
	}

	fprintf(stderr, "ident table is full!\n");
	fprintf(stderr, "please drop unused ident!\n");
	return 0;
}

static char addrbuf[128];
#define ntop6(addr) inet_ntop(AF_INET6, &addr, addrbuf, sizeof(addrbuf))

/* 2. FROM aaa TO bbb SESSION sss EXCHANGE cc.cc.cc.cc:cc */
static int exchange_forward(struct natcb_t *cb, const char *buf, const struct sockaddr_in6 *endpoint)
{
	int match, n;
	char from[128], to[128], action[128], fill[1280], session[128];

	match = sscanf(buf, "FROM %128s TO %128s SESSION %128s %[A-Z]%*[ ]%[ .:a-zA-Z0-9]", from, to, session, action, fill);

	if (match != 4 && match != 5) {
		fprintf(stderr, "invalid exchange format! missing argument");
		return 0;
	}

	struct friend_t *fptr;
	struct friend_t *found = NULL;
	char deliverybuf[2048];

	for (n = 0; n < _all_nfriend; n++) {
		fptr = _all_friends + n;
		if (strcmp(fptr->ident, to) == 0) {
			found = fptr;
			break;
		}
	}

	if (found == NULL) {
		fprintf(stderr, "exchange peer not found!");
		return 0;
	}

	if (strcmp(action, "EXCHANGE") == 0 && strncmp(fill, "0.0.0.0:0", 9) == 0) {
		match = snprintf(deliverybuf, sizeof(deliverybuf),
				"FROM %s TO %s SESSION %s EXCHANGE [%s]:%d %s",
				from, to, session, ntop6(endpoint->sin6_addr), htons(endpoint->sin6_port), fill + 9);
	} else {
		match = snprintf(deliverybuf, sizeof(deliverybuf), "%s", buf);
	}

	match = sendto(cb->sockfd, deliverybuf, match, 0,
			(struct sockaddr *)&found->endpoint, sizeof(found->endpoint));

	if (match == -1) {
		fprintf(stderr, "exchange failed! %s", to);
		return 0;
	}

	fprintf(stderr, "%s\n", deliverybuf);
	return 1;
}

void do_receive_update(struct natcb_t *cb)
{
	int len, match;
	char title[128], from[128], action[128], buf[2048];

	printf("\r  from: [%s]:%d\n",
			ntop6(cb->peeraddr.sin6_addr), htons(cb->peeraddr.sin6_port));

	if (cb->buflen <= 0) {
		return;
	}

	cb->stunbuf[cb->buflen] = 0;
	match = sscanf(cb->stunbuf, "%128s %128s %128s", title, from, action);
	if (match != 3) {
		return;
	}

	if (strcmp(action, "TO") == 0) {
		match = exchange_forward(cb, cb->stunbuf, &cb->peeraddr);
		len = snprintf(buf, sizeof(buf), "FROM RESPONSE EXCHANE FORWARD");
		sendto(cb->sockfd, buf, len, 0, (const struct sockaddr *)&cb->peeraddr, sizeof(cb->peeraddr));
	} else if (strcmp(action, "LOCK") == 0) {
		match = update_friend(cb->stunbuf, &cb->peeraddr);
		len = snprintf(buf, sizeof(buf), "FROM RESPONSE LOCK %s", match? "ACCEPT": "REJECT");
		sendto(cb->sockfd, buf, len, 0, (const struct sockaddr *)&cb->peeraddr, sizeof(cb->peeraddr));
	} else if (strcmp(action, "STUN.MAP") == 0) {
		len = snprintf(buf, sizeof(buf), "FROM RESPONSE STUN ADDRESS [%s]:%d", 
				ntop6(cb->peeraddr.sin6_addr), htons(cb->peeraddr.sin6_port));
		sendto(cb->sockfd, buf, len, 0, (const struct sockaddr *)&cb->peeraddr, sizeof(cb->peeraddr));
	}

	return;
}

void check_and_receive(struct natcb_t *cb)
{
	fd_set readfds;
	int maxfd = cb->sockfd;
	int readycount = 0;

	struct sockaddr_in6  rcvaddr;
	socklen_t rcvaddrlen = sizeof(rcvaddr);

	cb->peerlen = sizeof(cb->peeraddr);

	do {
		FD_ZERO(&readfds);
		FD_SET(cb->sockfd, &readfds);
		FD_SET(STDIN_FILENO, &readfds);

		readycount = select(maxfd + 1, &readfds, NULL, NULL, 0);

		if (readycount > 0 && FD_ISSET(cb->sockfd, &readfds)) {
			cb->buflen = recvfrom(cb->sockfd, cb->stunbuf, sizeof(cb->stunbuf) -1,
					0, (struct sockaddr *)&cb->peeraddr, &cb->peerlen);
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
	} while (cb->pending > 0);

	return;
}

#define NTOA(ptr) inet_ntoa6(ptr)

static const char *inet_ntoa6(const void *ptr)
{
	static char vbuf[256];
	snprintf(vbuf, sizeof(vbuf), "::ffff:%s", inet_ntoa(*(in_addr *)ptr));
	return vbuf;
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
		void *addr_ptr = NULL;
		struct hostent *phost;

		port = strchr(value, ':');
		if (port) *port++ = 0;

		phost = gethostbyname(value);

		if (strcmp(key, "server") == 0) {
			cb->stunbear.sin6_family = AF_INET6;
			cb->stunbear.sin6_port = htons(port? atoi(port): 3478);
			addr_ptr = cb->stunbear.sin6_addr;
		} else {
			cb->peerlen = sizeof(cb->peeraddr);
			cb->peeraddr.sin6_family = AF_INET6;
			cb->peeraddr.sin6_port = htons(port? atoi(port): 3478);
			addr_ptr = cb->peeraddr.sin6_addr;
		}

		if (phost) {
			inet_pton(AF_INET6, NTOA(phost->h_addr), addr_ptr);
		} else if (bufaddr[0] == '[') {
			char *right = strrchr(bufaddr, ']');
			if (right && *right == ']') *right = 0;
			inet_pton(AF_INET6, bufaddr + 1, addr_ptr);
		} else {
			inet_pton(AF_INET6, bufaddr, addr_ptr);
		}
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

	port = strrchr(bufaddr, ':');
	if (port) *port++ = 0;

	struct sockaddr_in6 selfaddr;
	selfaddr.sin6_family = AF_INET6;
	selfaddr.sin6_port = htons(port? atoi(port): 3478);

	phost = gethostbyname(bufaddr);
	if (phost) {
		inet_pton(AF_INET6, NTOA(phost->h_addr), &selfaddr.sin6_addr);
	} else if (bufaddr[0] == '[') {
		char *right = strrchr(bufaddr, ']');
		if (right && *right == ']') *right = 0;
		inet_pton(AF_INET6, bufaddr + 1, &selfaddr.sin6_addr);
	} else {
		inet_pton(AF_INET6, bufaddr, &selfaddr.sin6_addr);
	}

	fprintf(stderr, "host %s port %s %s\n", bufaddr, port, ntop6(selfaddr.sin6_addr));
	match = bind(cb->sockfd, (const struct sockaddr *)&selfaddr, sizeof(selfaddr));
	assert(match == 0);

	cb->pending++;
	return 0;
}

void do_dump_status(struct natcb_t *cb)
{
	int n;
	int error;
	struct sockaddr_in6 *inp, selfaddr;

	fprintf(stderr, "  sockfd %d\n", cb->sockfd);
	fprintf(stderr, "  pending %d\n", cb->pending);
	fprintf(stderr, "  buflen  %d\n", cb->buflen);

	inp = &cb->peeraddr;
	printf("  peer: [%s]:%d\n",
			ntop6(inp->sin6_addr), htons(inp->sin6_port));

	inp = &cb->stunbear;
	printf("  bear: [%s]:%d\n",
			ntop6(inp->sin6_addr), htons(inp->sin6_port));

	socklen_t selflen = sizeof(selfaddr);
	error = getsockname(cb->sockfd, (struct sockaddr *)&selfaddr, &selflen);
	if (error == -1) return;

	inp = &selfaddr;
	printf("  self: [%s]:%d\n",
			ntop6(inp->sin6_addr), htons(inp->sin6_port));

	for (n = 0; n < _all_nfriend; n++) {
		inp = &_all_friends[n].endpoint;
		printf("  %d: %s %s [%s]:%d\n", n, _all_friends[n].ident,
				_all_friends[n].lockword, ntop6(inp->sin6_addr), htons(inp->sin6_port));
	}

	return;
}

void print_usage()
{
	fprintf(stderr, "  help              print usage\n");
	fprintf(stderr, "  bind <address>    bind socket to address\n");
	fprintf(stderr, "  set <key> <value> set server|peer value\n");
}

int main(int argc, char *argv[])
{
	char action[128];
	char stdbuf[1024];
	struct natcb_t cb = {};

	natcb_setup(&cb);

	fprintf(stderr, "$ ");
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
		}

check_pending:
		fprintf(stderr, "$ ");
		if (cb.pending > 0) {
			check_and_receive(&cb);
		}
	}

	natcb_free(&cb);

	return 0;
}

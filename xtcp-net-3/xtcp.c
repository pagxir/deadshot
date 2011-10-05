#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>

#include <assert.h>
#include "pthread.h"

#include "tcp.h"
#include "xtcp.h"
#include "xreq.h"
#include "dtype.h"

#define MAX_LINK 100
#define close(s) closesocket(s)

struct xreq_stat {
	int xs_file;
	int xs_quit;
	int xs_piperd;
	int xs_pipewr;
	int xs_flags;
	pthread_t xs_thrid;
	pthread_cond_t xs_cond;
	pthread_mutex_t xs_mutex;

	u_long xs_slowto;
	u_long xs_fastto;
};

int ticks = 0;
int pipe(int fildes[]);
static struct xreq_stat stat = {0};
static struct tcpcb * fd_table[MAX_LINK] = {0};
u_short tcp_port = 0;
u_long  tcp_addr = 0;

static int update_ticks(void)
{
	ticks = GetTickCount();
	return 0;
}

static int xreq_select(struct fd_set * readfds, struct timeval * timeout,
		struct xreq_stat * stat)
{
	int count;
	int fd, pipefd;
	int max_fd = 0;

	FD_ZERO(readfds);

	max_fd = fd = stat->xs_file;
	assert(fd != -1);
	FD_SET(fd, readfds);

	pipefd = stat->xs_piperd;
	assert(pipefd != -1);
	FD_SET(pipefd, readfds);

	pthread_mutex_unlock(&stat->xs_mutex);
	max_fd = umax(max_fd, pipefd);
	count = select(max_fd + 1, readfds, NULL, NULL, timeout);
	pthread_mutex_lock(&stat->xs_mutex);
	update_ticks();

	assert(count >= 0);
	return count;
}

static int drop_data(int fd)
{
	char drpdat[1024];
	return recv(fd, drpdat, sizeof(drpdat), 0);
}

static void * xreq_thread(void * thr_args)
{
	struct fd_set readfds;
	struct timeval t_out;
	struct xreq_stat * stat;
	stat = (struct xreq_stat *) thr_args;

	pthread_mutex_lock(&stat->xs_mutex);
	update_ticks();
	stat->xs_fastto = ticks + 100;
	stat->xs_slowto = ticks + 100;
	while (stat->xs_quit == 0 || !tcp_empty()) {
		int count;
		char packet[2048];

		int flags;
		socklen_t dst_len;
		struct sockaddr_in dst_addr;

		t_out.tv_sec = 0;
		t_out.tv_usec = 100000;
		count = xreq_select(&readfds, &t_out, stat);

		flags = 0;

		if (FD_ISSET(stat->xs_piperd, &readfds)) {
			fprintf(stderr, "Hello World!\n");
			drop_data(stat->xs_piperd);
		}

		if (FD_ISSET(stat->xs_file, &readfds)) {
			dst_len = sizeof(dst_addr);
			count = recvfrom(stat->xs_file, packet, sizeof(packet), 0,
					(struct sockaddr *)&dst_addr, &dst_len);
			while (count > 0) {
				int drop_flags = 0;
				tcp_packet(stat->xs_file, packet, count, &flags, &dst_addr, dst_len);  
				count = recvfrom(stat->xs_file, packet, sizeof(packet), 0,
						(struct sockaddr *)&dst_addr, &dst_len);
			}
		}

		if (stat->xs_slowto <= (u_long) ticks) {
			stat->xs_slowto = (ticks + 100);
			tcp_slowtimeo(&flags);
		}

		if (stat->xs_fastto <= (u_long)ticks) {
			stat->xs_fastto = (ticks + 100);
			tcp_fasttimeo(&flags);
		}

		if (flags & stat->xs_flags) {
			stat->xs_flags = 0;
			pthread_cond_signal(&stat->xs_cond);
		}

		if (flags & XF_ACKNOW) {
			tcp_fasttimeo(&flags);
			flags &= ~XF_ACKNOW;
		}
	}
	pthread_mutex_unlock(&stat->xs_mutex);

	return 0;
}

int xreq_init(u_short port)
{
	int error;
	int fildes[2];
	u_long nonblock = 1;
	pthread_t * pthrid;

	socklen_t if_len;
	struct sockaddr_in if_addr;

	WSADATA data;
	WSAStartup(0x101, &data);

	update_ticks();
	error = pipe(fildes);
	assert(error == 0);
	stat.xs_piperd = fildes[0];
	stat.xs_pipewr = fildes[1];
	stat.xs_quit = 0;
	stat.xs_flags = 0;
	srand(ticks);
	tcp_iss = rand();
	tcp_port = 1234;
	tcp_addr = (rand() << 16) | rand();
	pthrid = &stat.xs_thrid;
	pthread_cond_init(&stat.xs_cond, NULL);
	pthread_mutex_init(&stat.xs_mutex, NULL);

	stat.xs_file = socket(AF_INET, SOCK_DGRAM, 0);
	do {
		int rcvbufsiz = 8192;
		setsockopt(stat.xs_file, SOL_SOCKET, SO_RCVBUF, &rcvbufsiz, sizeof(rcvbufsiz));
	} while ( 0 );

	if_addr.sin_family = AF_INET;
	if_addr.sin_port   = htons(port);
	if_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	error = bind(stat.xs_file, (struct sockaddr *)&if_addr, sizeof(if_addr));
	assert(error == 0);

	ioctlsocket(stat.xs_file, FIONBIO, &nonblock);
	error = pthread_create(pthrid, NULL, xreq_thread, &stat);
	assert(error == 0);

	if (port != 0) {
		/* port is known by caller */
		return 0;
	}

	if_len = sizeof(if_addr);
	error = getsockname(stat.xs_file, (struct sockaddr *)&if_addr, &if_len);
	assert(error == 0);
	fprintf(stderr, "if port: %d\n", ntohs(if_addr.sin_port));
	return 0;
}

int xreq_clean(void)
{
	int error;
	void * xvalue = NULL;

	pthread_mutex_lock(&stat.xs_mutex);
	stat.xs_quit = 1;
	pthread_mutex_unlock(&stat.xs_mutex);

	send(stat.xs_pipewr, "QUIT", 4, 0);
	fprintf(stderr, "join thread\n");
	error = pthread_join(stat.xs_thrid, &xvalue);
	fprintf(stderr, "join thread end\n");
	assert(error == 0);

	pthread_mutex_destroy(&stat.xs_mutex);
	pthread_cond_destroy(&stat.xs_cond);
	close(stat.xs_piperd);
	close(stat.xs_pipewr);
	close(stat.xs_file);

	WSACleanup();
	return 0;
}

int xopen(void)
{
	int i;
	int fd = -1;
	struct tcpcb * tp;

	pthread_mutex_lock(&stat.xs_mutex);
	for (i = 0; i < MAX_LINK; i++) {
		if (fd_table[i] == NULL) {
			break;
		}
	}

	if (i < MAX_LINK) {
		tp = tcp_create(stat.xs_file);
		tcp_attach(tp);
		assert(tp != NULL);
		fd_table[i] = tp;
		fd = i;
	}

	pthread_mutex_unlock(&stat.xs_mutex);

	send(stat.xs_pipewr, "OPEN", 4, 0);
	return fd;
}

int xclose(int fd)
{
	int error = -1;
	struct tcpcb * tp = NULL;

	if (fd < 0 || fd >= MAX_LINK) {
		return error;
	}

	pthread_mutex_lock(&stat.xs_mutex);
	tp = fd_table[fd];
	fd_table[fd] = NULL;

	if (tp != NULL) {
		tcp_shutdown(tp);
		tcp_detach(tp);
		error = 0;
	}
	pthread_mutex_unlock(&stat.xs_mutex);

	send(stat.xs_pipewr, "CLOS", 4, 0);
	return error;
}

int xconnect(int fd, const struct sockaddr_in * name, socklen_t namelen)
{
	int error = -1;
	struct tcpcb * tp = NULL;

	if (fd < 0 || fd >= MAX_LINK) {
		return error;
	}

	pthread_mutex_lock(&stat.xs_mutex);
	update_ticks();
	tp = fd_table[fd];
	if (tp != NULL) {
		error = tcp_connect(tp, name, namelen);
		while (error == 1) {
			stat.xs_flags |= XF_WRITE;
			pthread_cond_wait(&stat.xs_cond, &stat.xs_mutex);
			error = tcp_connected(tp);
		}
	}
	pthread_mutex_unlock(&stat.xs_mutex);

	return 0;
}

ssize_t xread(int fd, void * buf, size_t len)
{
	ssize_t count = 0;
	struct tcpcb * tp = NULL;

	if (fd < 0 || fd >= MAX_LINK) {
		return -1;
	}

	pthread_mutex_lock(&stat.xs_mutex);
	update_ticks();
	tp = fd_table[fd];
	if (tp != NULL) {
		while (!tcp_readable(tp)) {
			stat.xs_flags |= XF_READ;
			pthread_cond_wait(&stat.xs_cond, &stat.xs_mutex);
		}

		count = tcp_read(tp, buf, len);
	}
	pthread_mutex_unlock(&stat.xs_mutex);

	/* write(stat.xs_pipewr, "READ", 4); */
	return count;
}

ssize_t xwrite(int fd, const void * buf, size_t len)
{
	ssize_t count = 0;
	struct tcpcb * tp;

	if (fd < 0 || fd >= MAX_LINK) {
		return -1;
	}

	pthread_mutex_lock(&stat.xs_mutex);
	update_ticks();
	tp = fd_table[fd];
	if (tp != NULL) {
		while (!tcp_writable(tp)) {
			stat.xs_flags |= XF_WRITE;
			pthread_cond_wait(&stat.xs_cond, &stat.xs_mutex);
		}

		count = tcp_write(tp, buf, len);
	}
	pthread_mutex_unlock(&stat.xs_mutex);

	/* write(stat.xs_pipewr, "WRIT", 4); */
	return count;
}

int xbind(int fd, const struct sockaddr_in * name, socklen_t namelen)
{
	int error = -1;

	if (fd < 0 || fd >= MAX_LINK) {
		return error;
	}

	return 0;
}

int xaccept(int fd, struct sockaddr_in * addr, socklen_t * addrlen)
{
	int error = -1;
	struct tcpcb * tp;

	if (fd < 0 || fd >= MAX_LINK) {
		fprintf(stderr, "bad file: %d\n", fd);
		return error;
	}

	pthread_mutex_lock(&stat.xs_mutex);
	tp = fd_table[fd];
	assert(tp != NULL);
	if (tp != NULL) {
		error = tcp_listen(tp);
		while (error == 1) {
			stat.xs_flags |= XF_WRITE;
			pthread_cond_wait(&stat.xs_cond, &stat.xs_mutex);
			error = tcp_connected(tp);
		}
	}
	pthread_mutex_unlock(&stat.xs_mutex);

	return error;
}


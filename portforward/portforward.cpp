#ifndef __WIN32__
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#define S_CLOSE  close
#define S_READ   read
#define S_WRITE  write
#else
#include <winsock2.h>
#define socklen_t int
#define S_CLOSE(s)  closesocket(s)
#define S_READ(fd, buf, len) recv(fd, buf, len, 0)
#define S_WRITE(fd, buf, len) send(fd, buf, len, 0)
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <list>


#include "vio.h"
#include "xio.h"

#define SCF_VERSION4    0x04
#define SCF_ERROR		0x10
#define SCF_CONNECTED	0x20
#define SCF_NEEDAUTH	0x40
#define SCF_NEEDLINK	0x80

#define MAX(a, b) ((a) < (b)? (b): (a))
#define BUFSIZE   (64 * 1024)

struct s4_ctx {
	int sc_flags;
	int sc_src_fd;
	int sc_dst_fd;

	struct xiocb sc_s2d;
	struct xiocb sc_d2s;

	char sc_d2s_buf[64 * 1024];
	char sc_s2d_buf[64 * 1024];
};

int dumphex(char *buf, int len)
{
#if 0
	if (len <= 0)
		return 0;
	while (len-- > 0)
		printf("%02x", *buf++ & 0xff);
	printf("\n");
#endif
	return 0;
}

int setblockopt(int fd, int block)
{
#ifndef __WIN32__
	int flag = fcntl(fd, F_GETFL);
	flag &= ~O_NONBLOCK;
	if (block == 0)
		flag |= O_NONBLOCK;
	return fcntl(fd, F_GETFL, flag);
#else
	u_long blockopt = !block;
	return ioctlsocket(fd, FIONBIO, &blockopt);
#endif
}

void s4ctx_close(struct xiocb * xiocbp)
{
	struct s4_ctx * ctxp;
   	ctxp = (struct s4_ctx*)xiocbp->xio_udata;
	assert (ctxp != NULL);

	if (xio_error(&ctxp->sc_s2d) == 0 &&
			xio_error(&ctxp->sc_d2s) == 0 &&
			(xio_complete(&ctxp->sc_s2d) == 0 ||
			 xio_complete(&ctxp->sc_d2s) == 0))
	   	return;
   	xio_cancel(&ctxp->sc_s2d);
   	xio_cancel(&ctxp->sc_d2s);
   	S_CLOSE(ctxp->sc_src_fd);
   	S_CLOSE(ctxp->sc_dst_fd);
   	rate_cacl(0, 0, -1);
	delete ctxp;
}

void s4ctx_init(struct s4_ctx * ctx, int s_fd)
{
	int error;
	struct sockaddr_in addr_in1;

	memset(ctx, 0, sizeof(struct s4_ctx));
	ctx->sc_src_fd = s_fd;
	ctx->sc_flags  = SCF_NEEDAUTH;

	ctx->sc_s2d.xio_size = BUFSIZE;
	ctx->sc_s2d.xio_buf  = ctx->sc_s2d_buf;
	ctx->sc_s2d.xio_udata = ctx;
   	ctx->sc_s2d.xio_notify = s4ctx_close;

	ctx->sc_d2s.xio_size = BUFSIZE;
	ctx->sc_d2s.xio_buf  = ctx->sc_d2s_buf;
   	ctx->sc_d2s.xio_udata = ctx;
   	ctx->sc_d2s.xio_notify = s4ctx_close;

	ctx->sc_dst_fd = socket(PF_INET, SOCK_STREAM, 0);
   	setblockopt(ctx->sc_dst_fd, 0);
   	memset(&addr_in1, 0, sizeof(addr_in1));
   	addr_in1.sin_family = PF_INET;
   	addr_in1.sin_port   = htons(1080);
   	addr_in1.sin_addr.s_addr   = htonl(INADDR_LOOPBACK);
   	error = connect(ctx->sc_dst_fd, (struct sockaddr*)&addr_in1, sizeof(addr_in1));

	ctx->sc_s2d.xio_fdr = ctx->sc_src_fd;
	ctx->sc_s2d.xio_fdw = ctx->sc_dst_fd;

	ctx->sc_d2s.xio_fdr = ctx->sc_dst_fd;
	ctx->sc_d2s.xio_fdw = ctx->sc_src_fd;

	xio_add(&ctx->sc_s2d);
	xio_add(&ctx->sc_d2s);
}

int monitor_init(void)
{
	int error;
	struct sockaddr_in addr_in1;
	int reuse = 1;
	int monitor = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(monitor, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));
	memset(&addr_in1, 0, sizeof(addr_in1));
	addr_in1.sin_family = AF_INET;
	addr_in1.sin_port   = htons(8081);
	addr_in1.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	error = bind(monitor, (struct sockaddr *)&addr_in1, sizeof(addr_in1));
	assert (error == 0);

	error = listen(monitor, 5);
	assert (error == 0);
	return monitor;
}

int main(int argc, char *argv[])
{
	int error;
	int reuse = 1;
	char buf[30];
	int l_fd, s_fd;

	size_t count;
	socklen_t len;
	fd_set readfds, writefds, errorfds;

	struct sockaddr_in addr_in1;
	struct sockaddr_in addr_in2, addr_in3;

#ifndef __WIN32__
	signal(SIGPIPE, SIG_IGN);
#else
	WSADATA data;
	WSAStartup(0x201, &data);
#endif

	l_fd = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(l_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));

	memset(&addr_in1, 0, sizeof(addr_in1));
	addr_in1.sin_family = AF_INET;
	addr_in1.sin_port   = htons(8080);
	addr_in1.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	error = bind(l_fd, (struct sockaddr *)&addr_in1, sizeof(addr_in1));
	assert (error == 0);

	error = listen(l_fd, 5);
	assert (error == 0);

	int monitor = monitor_init();

	int max_fd = 0;
	for ( ; ; ) {
		FD_ZERO(&readfds);
		FD_ZERO(&writefds);
		FD_ZERO(&errorfds);

		max_fd = xio_fd_set(&readfds, &writefds, &errorfds);

		FD_SET(l_fd, &readfds);
		max_fd = MAX(l_fd, max_fd);

		FD_SET(monitor, &readfds);
		max_fd = MAX(monitor, max_fd);

		struct timeval timeout = {1, 1};
		count = select(max_fd + 1, &readfds, &writefds, &errorfds, &timeout);
		if (count == -1) {
			printf("select error: %d \n", count);
			continue;
		}

		if (count == 0) {
		   	rate_cacl(0, 0, 0);
			continue;
		}

		xio_event(&readfds, &writefds, &errorfds);

		if ( FD_ISSET(l_fd, &readfds) ) {
			struct s4_ctx * ctxp = new s4_ctx;
			len = sizeof(addr_in2);
			s_fd = accept(l_fd, (struct sockaddr *)&addr_in2, &len);
			s4ctx_init(ctxp, s_fd);
			rate_cacl(0, 0, +1);
		}

		if ( FD_ISSET(monitor, &readfds) ) {
			s_fd = accept(monitor, NULL, NULL);
			xio_monitor(s_fd);
			S_CLOSE(s_fd);
		}
	}

	S_CLOSE(l_fd);
	return 0;
}


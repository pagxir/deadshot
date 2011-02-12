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

}

void sock5_session(struct s4_ctx & s4ctx)
{
	int error;
	int count;
	size_t nmethod;
	size_t off = s4ctx.sc_s2d.xio_len;
	size_t len = s4ctx.sc_s2d.xio_size;
	char * buf = (char *)s4ctx.sc_s2d.xio_buf;
	count = S_READ(s4ctx.sc_src_fd, buf + off, len - off);
	if (count <= 0) {
		s4ctx.sc_flags |= SCF_ERROR;
		return;
	}
	dumphex(buf, off + count);
	s4ctx.sc_s2d.xio_len = off + count;
   	size_t total = off + count;
   	if (buf[0] == 0x4 || (s4ctx.sc_flags & SCF_VERSION4)) {
		s4ctx.sc_flags |= SCF_VERSION4;
		if (total > 2 && buf[1] != 0x01) {
		   	s4ctx.sc_flags |= SCF_ERROR;
			return;
		}
		char * pfin = total < 9? NULL: (char *)memchr(buf + 8, 0, total - 8);
		if (total < 9 || pfin == NULL) {
		   	if (total >= s4ctx.sc_s2d.xio_size)
			   	s4ctx.sc_flags |= SCF_ERROR;
			return;
		}

		in_addr in_addr1;
		unsigned short in_port1;

		memcpy(&in_addr1, &buf[4], sizeof(in_addr1));
		memcpy(&in_port1, &buf[2], sizeof(in_port1));

		total -= (++pfin - buf);
		memmove(buf, pfin, total);
		s4ctx.sc_s2d.xio_len = total;
#if 0
		printf("remote point: %s:%d\n",
				inet_ntoa(in_addr1), ntohs(in_port1));
		printf("total: %d\n", total);
#endif

		s4ctx.sc_flags &= ~SCF_NEEDLINK;

		struct sockaddr_in addr_in1;
		s4ctx.sc_dst_fd = socket(PF_INET, SOCK_STREAM, 0);
		setblockopt(s4ctx.sc_dst_fd, 0);
		memset(&addr_in1, 0, sizeof(addr_in1));
		addr_in1.sin_family = PF_INET;
		addr_in1.sin_port   = in_port1;
		addr_in1.sin_addr   = in_addr1;
		error = connect(s4ctx.sc_dst_fd,
				(struct sockaddr*)&addr_in1, sizeof(addr_in1));

		s4ctx.sc_flags |= SCF_CONNECTED;

		s4ctx.sc_s2d.xio_fdr = s4ctx.sc_src_fd;
		s4ctx.sc_s2d.xio_fdw = s4ctx.sc_dst_fd;

		s4ctx.sc_d2s.xio_fdr = s4ctx.sc_dst_fd;
		s4ctx.sc_d2s.xio_fdw = s4ctx.sc_src_fd;

		char resp[] = {
			0x00, 0x5A, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00
		};

		count = S_WRITE(s4ctx.sc_src_fd, resp, 8);
		if (count != 8) {
			s4ctx.sc_flags |= SCF_ERROR;
			return;
		}

		xio_add(&s4ctx.sc_s2d);
		xio_add(&s4ctx.sc_d2s);

		return;
	}
	
	if (buf[0] != 0x5) {
		s4ctx.sc_flags |= SCF_ERROR;
		return;
	}
	assert (s4ctx.sc_s2d.xio_size > 2);
	if (s4ctx.sc_flags & SCF_NEEDAUTH) {
		nmethod = (buf[1] & 0xff);
		if (total < 2 || (nmethod + 2) < total) {
			s4ctx.sc_s2d.xio_len = total;
			return;
		}

		if (memchr(buf + 2, 0x0, nmethod) == NULL) {
			s4ctx.sc_flags |= SCF_ERROR;
			return;
		}

		buf[1] = 0;
		count = S_WRITE(s4ctx.sc_src_fd, buf, 2);
		if (count != 2) {
			s4ctx.sc_flags |= SCF_ERROR;
			return;
		}
		total -= (2 + nmethod);
		s4ctx.sc_s2d.xio_len = total;
		memmove(buf, &buf[2 + nmethod], total);
		s4ctx.sc_flags |= SCF_NEEDLINK;
		s4ctx.sc_flags &= ~SCF_NEEDAUTH;
	}

	unsigned char pro_seq[] = {
		0x05, 0x01, 0x00, 0x01
	};
	if (s4ctx.sc_flags & SCF_NEEDLINK) {
		in_addr in_addr1;
		unsigned short in_port1;
		size_t cmplen = total < 4? total: 4;
		if ( memcmp(pro_seq, buf, cmplen) ) {
			s4ctx.sc_flags |= SCF_ERROR;
			return;
		}
		if (total < 10) {
			s4ctx.sc_s2d.xio_len = total;
			return;
		}
		total -= 10;
		s4ctx.sc_s2d.xio_len = total;
		memmove(buf, &buf[10], total);
		memcpy(&in_addr1, &buf[4], sizeof(in_addr1));
		memcpy(&in_port1, &buf[8], sizeof(in_port1));
#if 0
		printf("remote point: %s:%d\n",
				inet_ntoa(in_addr1), ntohs(in_port1));
#endif
		//printf("total: %d\n", total);

		s4ctx.sc_flags &= ~SCF_NEEDLINK;

		struct sockaddr_in addr_in1;
		s4ctx.sc_dst_fd = socket(PF_INET, SOCK_STREAM, 0);
		setblockopt(s4ctx.sc_dst_fd, 0);
		memset(&addr_in1, 0, sizeof(addr_in1));
		addr_in1.sin_family = PF_INET;
		addr_in1.sin_port   = in_port1;
		addr_in1.sin_addr   = in_addr1;
		error = connect(s4ctx.sc_dst_fd,
				(struct sockaddr*)&addr_in1, sizeof(addr_in1));

		s4ctx.sc_flags |= SCF_CONNECTED;

		s4ctx.sc_s2d.xio_fdr = s4ctx.sc_src_fd;
		s4ctx.sc_s2d.xio_fdw = s4ctx.sc_dst_fd;

		s4ctx.sc_d2s.xio_fdr = s4ctx.sc_dst_fd;
		s4ctx.sc_d2s.xio_fdw = s4ctx.sc_src_fd;

		char resp[] = {
			0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		};
		count = S_WRITE(s4ctx.sc_src_fd, resp, 10);
		if (count != 10) {
			s4ctx.sc_flags |= SCF_ERROR;
			return;
		}

		xio_add(&s4ctx.sc_s2d);
		xio_add(&s4ctx.sc_d2s);
	}
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
	std::list<struct s4_ctx *> s4_lists;
	std::list<struct s4_ctx *>::iterator iter;

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

		iter = s4_lists.begin();
		while (iter != s4_lists.end()) {
			struct s4_ctx * ctxp = *iter;
		   	FD_SET(ctxp->sc_src_fd, &readfds);
		   	max_fd = MAX(ctxp->sc_src_fd, max_fd);
			++iter;
		}

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

		iter = s4_lists.begin();
		while (iter != s4_lists.end()) {
			struct s4_ctx * ctxp = *iter;
			if ((ctxp->sc_flags & SCF_CONNECTED) == 0  &&
				   	FD_ISSET(ctxp->sc_src_fd, &readfds) )
				sock5_session(*ctxp);
			if (ctxp->sc_flags & SCF_ERROR) {
				iter = s4_lists.erase(iter);
				S_CLOSE(ctxp->sc_src_fd);
				if (ctxp->sc_flags & SCF_CONNECTED)
					S_CLOSE(ctxp->sc_dst_fd);
			   	rate_cacl(0, -1, 0);
				delete ctxp;
				continue;
			}
			if (ctxp->sc_flags & SCF_CONNECTED) {
				iter = s4_lists.erase(iter);
			   	rate_cacl(0, -1, +1);
				continue;
			}
			++iter;
		}

		if ( FD_ISSET(l_fd, &readfds) ) {
			struct s4_ctx * ctxp = new s4_ctx;
			len = sizeof(addr_in2);
			s_fd = accept(l_fd, (struct sockaddr *)&addr_in2, &len);
			s4ctx_init(ctxp, s_fd);
			s4_lists.push_back(ctxp);
			rate_cacl(0, +1, 0);
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


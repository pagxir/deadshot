#include <time.h>
#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#ifndef __WIN32__
#include <errno.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#else
#include <winsock2.h>
#define SHUT_WR SD_SEND
#endif

#include "vio.h"
#include "xio.h"
#define MAX(a, b) ((a) < (b)? (b): (a))

#define XIO_RDSTART	0x02
#define XIO_WRSTART	0x04
#define XIO_EOF		0x08
#define XIO_REOF	0x10
#define XIO_READ	0x20
#define XIO_WRITE	0x40
#define XIO_ERROR	0x80

#define XIO_NOTIFY  (XIO_EOF|XIO_ERROR)
#define XIO_RDCHECK (XIO_READ|XIO_RDSTART)
#define XIO_WRCHECK (XIO_WRITE|XIO_WRSTART)

extern struct xiocb __xio_list_header;

struct xiocb __xio_list_header = {
	0, 0, 0, 0, 0, 0, 0, 0, 0,
   	&__xio_list_header,
   	&__xio_list_header
};

int xio_add(struct xiocb * xiocbp)
{
	struct xiocb * cbp = &__xio_list_header;
	struct xiocb * prev = cbp->xio_prev;

	assert (xiocbp->xio_prev == NULL);
	assert (xiocbp->xio_next == NULL);

	prev->xio_next = xiocbp;
	xiocbp->xio_next = cbp;

	xiocbp->xio_prev = prev;
	cbp->xio_prev = xiocbp;
	return 0;
}

int xio_cancel(struct xiocb * xiocbp)
{
	struct xiocb * prev, * next;

	if (xiocbp->xio_prev == NULL &&
			xiocbp->xio_next == NULL)
		return 0;

	assert (xiocbp != &__xio_list_header);
	assert (xiocbp->xio_prev && xiocbp->xio_next);

   	prev = xiocbp->xio_prev;
   	next = xiocbp->xio_next;

	prev->xio_next = next;
	next->xio_prev = prev;

	xiocbp->xio_next = NULL;
	xiocbp->xio_prev = NULL;
	return 0;
}

int xio_error(struct xiocb * xiocbp)
{
	return (xiocbp->xio_flags & XIO_ERROR);
}

int xio_complete(struct xiocb * xiocbp)
{
	return (xiocbp->xio_flags & XIO_EOF);
}

int xio_fd_set(fd_set * readfds, fd_set * writefds, fd_set * errorfds)
{
	int fdmax = 0;
	struct xiocb * cbp = __xio_list_header.xio_next;

	while (cbp != &__xio_list_header) {
		if ((cbp->xio_len < cbp->xio_size) &&
				!(cbp->xio_flags & XIO_REOF)) {
			FD_SET(cbp->xio_fdr, readfds);
			cbp->xio_flags |= XIO_READ;
			fdmax = MAX(cbp->xio_fdr, fdmax);
		}

		if (cbp->xio_len > 0) {
			FD_SET(cbp->xio_fdw, writefds);
			cbp->xio_flags |= XIO_WRITE;
			fdmax = MAX(cbp->xio_fdw, fdmax);
		}

		if ((cbp->xio_flags & XIO_RDCHECK) == XIO_READ)
			FD_SET(cbp->xio_fdr, errorfds);

		if ((cbp->xio_flags & XIO_WRCHECK) == XIO_WRITE)
			FD_SET(cbp->xio_fdw, errorfds);

		cbp = cbp->xio_next;
	}

	return fdmax;
}

void die_if(struct xiocb * cur, struct xiocb *nxt)
{
	if (cur && nxt)
		return;
	printf("cur: %p nxt: %p\n", cur, nxt);
	if (cur != NULL)
		printf("cur: %p %p\n", cur->xio_prev,
			   	cur->xio_next);
	if (nxt != NULL)
		printf("nxt: %p %p\n", nxt->xio_prev,
				nxt->xio_next);
	struct xiocb * cbp = &__xio_list_header;
	printf("__xio_list_header.next: %p\n", cbp->xio_next);
	printf("__xio_list_header.prev: %p\n", cbp->xio_prev);
	printf("__xio_list_header.this: %p\n", cbp);
	exit(0);
}

int xio_event(fd_set * readfds, fd_set * writefds, fd_set * errorfds)
{
	int ibytes;
	struct iovec iovs[2];
	struct xiocb * xiocbp_free = NULL;
	struct xiocb * cbp, * next = __xio_list_header.xio_next;

	while (next != &__xio_list_header) {
		cbp = next;
		next = next->xio_next;
		die_if(cbp, next);
		if ((cbp->xio_flags & XIO_READ) &&
				FD_ISSET(cbp->xio_fdr, readfds)) {
			size_t len = (cbp->xio_size - cbp->xio_len);
			size_t off = (cbp->xio_off + cbp->xio_len) % cbp->xio_size;
			iovec_fill(iovs, cbp->xio_buf, cbp->xio_size, len, off);
			ibytes = readv(cbp->xio_fdr, iovs, 2);
			cbp->xio_flags &= ~XIO_READ;
			cbp->xio_flags |= XIO_RDSTART;
			switch (ibytes) {
				case 0:
					cbp->xio_flags |= XIO_REOF;
					break;
				case -1:
					cbp->xio_flags |= XIO_ERROR;
					break;
				default:
					cbp->xio_len += ibytes;
					rate_cacl(ibytes, 0, 0);
					break;
			}
		}
	   
		if ((cbp->xio_flags & XIO_RDCHECK) == XIO_READ &&
				FD_ISSET(cbp->xio_fdr, errorfds))
			cbp->xio_flags |= XIO_ERROR;

		if ((cbp->xio_flags & XIO_WRITE) &&
			FD_ISSET(cbp->xio_fdw, writefds)) {
			iovec_fill(iovs, cbp->xio_buf, cbp->xio_size,
				   	cbp->xio_len, cbp->xio_off);
		   	ibytes = writev(cbp->xio_fdw, iovs, 2);
			cbp->xio_flags &= ~XIO_WRITE;
			cbp->xio_flags |= XIO_WRSTART;
			switch ( ibytes ) {
			   	case -1:
				   	cbp->xio_flags |= XIO_ERROR;
					break;
			   	default:
				   	cbp->xio_len -= ibytes;
					cbp->xio_off += ibytes;
					cbp->xio_off %= cbp->xio_size;
				   	break;
		   	}
	   	}

		if ((cbp->xio_flags & XIO_WRCHECK) == XIO_WRITE &&
				FD_ISSET(cbp->xio_fdw, errorfds))
			cbp->xio_flags |= XIO_ERROR;

		if (cbp->xio_len == 0 &&
			   	(cbp->xio_flags & XIO_REOF)) {
		   	shutdown(cbp->xio_fdw, SHUT_WR);
			cbp->xio_flags |= XIO_EOF;
		}

		if (cbp->xio_flags & XIO_NOTIFY) {
			xio_cancel(cbp);
			if ( cbp->xio_notify )
				cbp->xio_notify(cbp);
			next = __xio_list_header.xio_next;
		}
	}

	return 0;
}

static size_t total = 0;
static time_t last_time = 0;
static uint64_t transfered = 0;
static int full_link = 0, half_link = 0;

const char * CountToText(char *title, uint64_t rate)
{
	if (rate < 8192) {
		sprintf(title, "%8lld", rate);
		return title;
	}
	if (rate < 8192 * 1024) {
	   	sprintf(title, "%7.1fK", rate / 1024.0);
		return title;
	}
	uint64_t limited = 8192;
	if (rate < limited * 1024 * 1024) {
	   	sprintf(title, "%7.1fM", rate / 1024.0 / 1024.0);
		return title;
	}
   	sprintf(title, "%7.1fG", rate / 1024.0 / 1024.0 / 1024.0);
   	return title;
}

void rate_cacl(size_t nbytes, int adj_half, int adj_full)
{
	time_t t_now;

	time(&t_now);
	full_link += adj_full;
	half_link += adj_half;
	transfered += nbytes;
	if (t_now != last_time) {
		char rate_buf[32], size_buf[32];
		total >>= 1;
		last_time = t_now;
		fprintf(stderr, "rate: %s %3d %3d %s\r",
			   	CountToText(rate_buf, total), half_link,
			   	full_link, CountToText(size_buf, transfered));
	}

	total += nbytes;
}

void dump_xiocb(int fd, struct xiocb *cbp)
{
	int len;
	char buf[8192];

	len = sprintf(buf, "#xiocb: %p\r\n", cbp);
	send(fd, buf, len, 0);

#define XXP(p) \
	len = sprintf(buf, "%s: %p@\r\n", #p, cbp->p); \
	send(fd, buf, len, 0);

#define XXU(u) \
	len = sprintf(buf, "%s: %d*\r\n", #u, cbp->u); \
	send(fd, buf, len, 0);

#define XXI(i) \
	len = sprintf(buf, "%s: %d-\r\n", #i, cbp->i); \
	send(fd, buf, len, 0);

	XXI(xio_fdr);
	XXI(xio_fdw);
	XXU(xio_off);
	XXU(xio_len);
	XXU(xio_size);
	XXU(xio_flags);
	XXP(xio_buf);
	XXU(xio_udata);
	XXP(xio_notify);

	XXP(xio_next);
	XXP(xio_prev);
#undef XXP
#undef XXU
#undef XXI
	len = sprintf(buf, "######################-%p-##########################\r\n", &__xio_list_header);
	send(fd, buf, len, 0);
}

int xio_monitor(int fd)
{
	struct xiocb *cbp = __xio_list_header.xio_next;
	while (cbp != &__xio_list_header) {
		dump_xiocb(fd, cbp);
		cbp = cbp->xio_next;
	}
	return 0;
}


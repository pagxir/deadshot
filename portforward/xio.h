#ifndef __XIO_H__
#define __XIO_H__
void rate_cacl(size_t nbytes, int adj_half, int adj_full);

struct xiocb {
	int xio_fdr;
	int xio_fdw;
	size_t xio_off;
	size_t xio_len;
	size_t xio_size;
	size_t xio_flags;
	void * xio_buf;
	void * xio_udata;
	void (* xio_notify)(struct xiocb *xiocbp);

#ifdef __FULL_SUPPORT__
	int xio_count;
	size_t xio_skip;
	size_t xio_drop;
#endif

#define __INTERNAL_FIELD__
	struct xiocb * xio_next;
	struct xiocb * xio_prev;
#undef  __INTERNAL_FIELD__
};

int xio_monitor(int fd);

int xio_add(struct xiocb * xiocbp);
int xio_error(struct xiocb * xiocbp);
int xio_cancel(struct xiocb * xiocbp);
int xio_complete(struct xiocb * xiocbp);

int xio_event(fd_set * readfds, fd_set * writefds, fd_set * errorfds);
int xio_fd_set(fd_set * readfds, fd_set * writefds, fd_set * errorfds);
#endif

#ifndef __VIO_H__
#define __VIO_H__

#ifdef __WIN32__

struct iovec {
	size_t iov_len;
	void * iov_base;
};

inline int readv(int fd, const struct iovec * iovecs, size_t count)
{
	DWORD nbytes;
	DWORD flags = 0;
	if ( WSARecv(fd, (LPWSABUF)iovecs, count, &nbytes, &flags, NULL, NULL) )
		return -1;
	return nbytes;
}

inline int writev(int fd, const struct iovec * iovecs, size_t count)
{
	DWORD nbytes = 0;

	if ( WSASend(fd, (LPWSABUF)iovecs, count, &nbytes, 0, NULL, NULL) )
		return -1;

	return nbytes;
}

#endif

inline void iovec_fill(struct iovec * iovs, void * buf,
	   	size_t size, size_t len, size_t off)
{
	char * bi_buf = (char *) buf;
	assert (off < size);
	size_t part1 = (off + len < size)? len: (size - off);
   	iovs[0].iov_base = bi_buf + off;
   	iovs[0].iov_len  = part1;
   	iovs[1].iov_base = buf;
   	iovs[1].iov_len  = len - part1;
}

#endif


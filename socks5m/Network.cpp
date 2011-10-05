#include <time.h>
#include <stdio.h>
#include <winsock2.h>
#include <mswsock.h>
#include <windows.h>

#include "Network.h"
#pragma warning(disable: 4996) 

static BOOL bIsRunning = TRUE;
static HANDLE gQuitPortHandle = INVALID_HANDLE_VALUE;
static LPFN_ACCEPTEX lpAcceptEx = NULL;
static LPFN_CONNECTEX lpConnectEx = NULL;

int NDSQuitCall(void)
{
	bIsRunning = FALSE;
	PostQueuedCompletionStatus(gQuitPortHandle, 0, 0, NULL); 
	return 0;
}

LPFN_ACCEPTEX GetAcceptExAddress(int fd1)
{
	DWORD dwBytes = 0;
	LPFN_ACCEPTEX AcceptExAddress = AcceptEx;
	GUID GuidAcceptEx = WSAID_ACCEPTEX;
	WSAIoctl(fd1, SIO_GET_EXTENSION_FUNCTION_POINTER, &GuidAcceptEx,
			sizeof(GuidAcceptEx), &AcceptExAddress, sizeof(AcceptExAddress), &dwBytes, NULL, NULL);
	NASSERT (AcceptExAddress != NULL);
	return AcceptExAddress;
}

#if 1

#ifndef WSAID_TRANSMITFILE
#define WSAID_TRANSMITFILE \
{0xb5367df0,0xcbac,0x11cf,{0x95,0xca,0x00,0x80,0x5f,0x48,0xa1,0x92}}
#endif

#ifndef WSAID_ACCEPTEX
#define WSAID_ACCEPTEX \
{0xb5367df1,0xcbac,0x11cf,{0x95,0xca,0x00,0x80,0x5f,0x48,0xa1,0x92}}
typedef BOOL (PASCAL *LPFN_ACCEPTEX)(SOCKET, SOCKET, PVOID, DWORD, 
		DWORD, DWORD, LPDWORD, LPOVERLAPPED);
#endif

#ifndef WSAID_CONNECTEX
#define WSAID_CONNECTEX \
{0x25a207b9,0xddf3,0x4660,{0x8e,0xe9,0x76,0xe5,0x8c,0x74,0x06,0x3e}}
typedef BOOL (PASCAL *LPFN_CONNECTEX)(SOCKET, const struct sockaddr *,
		int, PVOID, DWORD, LPDWORD, LPOVERLAPPED);
#endif

#ifndef SO_UPDATE_ACCEPT_CONTEXT
#define SO_UPDATE_ACCEPT_CONTEXT    0x700B
#endif

#ifndef SO_CONNECT_TIME
#define SO_CONNECT_TIME             0x700C
#endif

#ifndef SO_UPDATE_CONNECT_CONTEXT
#define SO_UPDATE_CONNECT_CONTEXT   0x7010
#endif


int setblockopt(int fd, int block)
{
	u_long blockopt = !block;
	return ioctlsocket(fd, FIONBIO, &blockopt);
}

static size_t total = 0;
static time_t last_time = 0;
static __int64 transfered = 0;
static int full_link = 0, half_link = 0;

const char * CountToText(char *title, __int64 rate)
{
	if (rate < 8192) {
		sprintf(title, "%8lld", rate);
		return title;
	}
	if (rate < 8192 * 1024) {
		sprintf(title, "%7.1fK", rate / 1024.0);
		return title;
	}
	__int64 limited = 8192;
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
		printf("rate: %s %3d %3d %s\r",
				CountToText(rate_buf, total), half_link,
				full_link, CountToText(size_buf, transfered));
	}

	total += nbytes;
}

#define XIOCBCTX_FLAG  0x19821130
#define XIOCBCTX_FLAG1 0x19821131

#define XYF_ACCEPTING  0x00000001
#define XYF_ACCEPTED   0x00000002
#define XYF_CONNECTING 0x00000004
#define XYF_CONNECTED  0x00000008
#define XYF_READMORE   0x00000010
#define XYF_AUTHED     0x00000020
#define XYF_RESULTED   0x00000040
#define XYF_READING    0x00000080
#define XYF_WRITING    0x00000100
#define XYF_XIOING     0x00000200
#define XYF_VERSION4   0x00000400
#define XYF_ERROR      0x80000000
#define XYF_EOF        0x40000000
#define XYF_CLOSE      0x20000000
#define XYF_UDP        0x04000000
#define XYF_DELAY      0x08000000
#define XYF_UDPREADING 0x00800000

#define XIO_FIN        0x10000000
#define XIO_REOF       XYF_EOF
#define XIO_DELAY      0x08000000
#define XIO_ERROR      XYF_ERROR
#define XIO_READING    XYF_READING
#define XIO_WRITING    XYF_WRITING

#define XY_OVER_INIT(xcb, cb, fn)  \
	do { \
		strcpy((xcb)->xc_magic, "ovr"); \
		(xcb)->xc_udata = (cb); \
		(xcb)->xc_callback = (fn); \
	} while ( 0 )

struct XIOCBCTX;
typedef void FN_XIOCALLBACK(struct XIOCBCTX * ctx, size_t iosize, BOOL success, HANDLE handle);

struct XIOCBCTX {
	WSAOVERLAPPED xc_over;
	char xc_magic[4];
	void * xc_udata;
	FN_XIOCALLBACK * xc_callback;
};

struct xiocb {
	char xio_magic[4];
	int xio_fdr;
	int xio_fdw;
	size_t xio_off;
	size_t xio_len;
	size_t xio_size;
	size_t xio_flags;
	void * xio_buf;
	void * xio_udata;
	int (* xio_notify)(struct xiocb *xiocbp);

	DWORD xio_rd_flags;
	struct XIOCBCTX xio_rdover;
	struct XIOCBCTX xio_wrover;

	const char * xio_header;
	FILE * xio_logfile;
};

struct proxycb {
	char xy_magic[4];
	int fd_src;
	int fd_dst;
	int xy_flags;
	u_short xy_port;
	in_addr xy_addr;
	DWORD xy_rcv_flags;

	XIOCBCTX xy_read;
	XIOCBCTX xy_write;
	XIOCBCTX xy_accept;
	XIOCBCTX xy_connect;

	int xy_addr_len;
	struct sockaddr_in xy_rcv_addr;	

	struct xiocb xy_s2d;
	struct xiocb xy_d2s;

	size_t xy_rcv_len;
	char   xy_rcv_buf[81920];
	size_t xy_snd_len;
	char   xy_snd_buf[81920];
	FILE * log_file;
};


inline void iovec_fill(WSABUF * iovs, void * buf,
		size_t size, size_t len, size_t off)
{
	char * bi_buf = (char *) buf;
	NASSERT (off < size);
	size_t part1 = (off + len < size)? len: (size - off);
	iovs[0].buf  = bi_buf + off;
	iovs[0].len  = part1;
	iovs[1].buf  = (char *)buf;
	iovs[1].len  = len - part1;
}

size_t check_data_len(struct xiocb * cb)
{
	NASSERT(memcmp(cb->xio_magic, ".xio", 4) == 0);
	char * buf = (char *)cb->xio_buf;
	size_t len = cb->xio_len;
	size_t size = cb->xio_size;
	size_t off = cb->xio_off % size;

	while (len > 0) {
		len--;
		int ch = buf[off++] & 0xFF;
		if (ch == '%')
			break;
		off %= size;
	}

	return (cb->xio_len - len);
}

int xio_call(struct xiocb * cb)
{
	int error = 0;
	size_t flags = 0;
	WSABUF wsabufs[2];

	flags = (XIO_READING | XIO_ERROR | XIO_REOF);
	if ((cb->xio_len < cb->xio_size) &&
			0 == (cb->xio_flags & flags)) {
		flags = XIO_ERROR;
		cb->xio_rd_flags = 0;
		size_t len = (cb->xio_size - cb->xio_len);
		size_t off = (cb->xio_off  + cb->xio_len) % cb->xio_size;
		iovec_fill(wsabufs, cb->xio_buf, cb->xio_size, len, off);
		memset(&cb->xio_rdover.xc_over, 0, sizeof(cb->xio_rdover.xc_over));
		error = WSARecv(cb->xio_fdr, wsabufs, 2, NULL, &cb->xio_rd_flags,
				&cb->xio_rdover.xc_over, NULL);
		if (error == 0 ||
				(ERROR_IO_PENDING == WSAGetLastError()))
			flags = XIO_READING;
		cb->xio_flags |= flags;
	}

	flags = (XIO_WRITING | XIO_ERROR | XIO_REOF);
	if ((flags & cb->xio_flags) == XIO_REOF &&
			cb->xio_len == 0) {
		error = shutdown(cb->xio_fdw, SD_SEND);
		cb->xio_flags |= XIO_FIN;
	}

	flags = (XIO_WRITING | XIO_ERROR );
	if ((cb->xio_len > 0) &&
			0 == (cb->xio_flags & flags)) {
		flags = XIO_ERROR;
		size_t adj_len = (cb->xio_flags & XIO_DELAY)? check_data_len(cb): cb->xio_len;
		NASSERT (adj_len <= cb->xio_len && adj_len > 0);
		iovec_fill(wsabufs, cb->xio_buf, cb->xio_size, adj_len, cb->xio_off);
		memset(&cb->xio_wrover.xc_over, 0, sizeof(cb->xio_wrover.xc_over));
		error = WSASend(cb->xio_fdw, wsabufs, 2, NULL, 0, 
				&cb->xio_wrover.xc_over, NULL);
		if (error == 0 ||
				(ERROR_IO_PENDING == WSAGetLastError()))
			flags = XIO_WRITING;
		cb->xio_flags |= flags;

		if (adj_len < cb->xio_len)
			Sleep(100);
	}

	int test_flags = XIO_READING | XIO_WRITING;
	if ((cb->xio_flags & test_flags) == 0 &&
			cb->xio_notify != NULL) {
		NASSERT (cb->xio_flags & (XIO_FIN|XIO_ERROR));
		return cb->xio_notify(cb);
	}
	return 0;
}

void cache_append(struct xiocb * cb, size_t iosize)
{
	WSABUF wsabufs[2];
	size_t len = iosize;
	size_t off = (cb->xio_off + cb->xio_len) % cb->xio_size;

	if (cb->xio_logfile != NULL) {
		iovec_fill(wsabufs, cb->xio_buf, cb->xio_size, len, off);

		for (int i = 0; i < 2; i++) {
			if (wsabufs[0].len == 0)
				continue;
			fwrite(wsabufs[i].buf, wsabufs[i].len, 1, cb->xio_logfile);
		}
	}
}

int xio_wakeup(struct xiocb * cb, struct XIOCBCTX * over, size_t iosize, int err_flags)
{
	if (over == &cb->xio_rdover) {
		NASSERT (cb->xio_flags & XIO_READING);
		cb->xio_flags &= ~XIO_READING;
		if (iosize == 0)
			cb->xio_flags |= XIO_REOF;
		cache_append(cb, iosize);
		cb->xio_len += iosize;
		rate_cacl(iosize, 0, 0);
	} else if (over == &cb->xio_wrover) {
		NASSERT (cb->xio_flags & XIO_WRITING);
		cb->xio_flags &= ~XIO_WRITING;
		cb->xio_off += iosize;
		cb->xio_len -= iosize;
		cb->xio_off %= cb->xio_size;
	}
	if (err_flags > 0)
		err_flags = XIO_ERROR;
	cb->xio_flags |= err_flags;
	return 0;
}

void xio_post(struct XIOCBCTX * ctx, size_t iosize, BOOL success, HANDLE handle)
{
	struct xiocb * cb = NULL;
	cb = reinterpret_cast<struct xiocb*>(ctx->xc_udata);
	NASSERT(0 == memcmp(cb->xio_magic, "xio", 4));
	xio_wakeup(cb, ctx, iosize, success? 0: XIO_ERROR);
	xio_call(cb);
}

void xio_add(struct xiocb * cbp)
{
	XY_OVER_INIT(&cbp->xio_rdover, cbp, xio_post);
	XY_OVER_INIT(&cbp->xio_wrover, cbp, xio_post);
}

int proxy_notify(struct xiocb * cbp)
{
	struct proxycb * pcb;
	pcb = reinterpret_cast<struct proxycb *>(cbp->xio_udata);
	NASSERT(0 == memcmp(pcb->xy_magic, ".xy", 4));

	if ((pcb->xy_s2d.xio_flags & XIO_ERROR) == 0 &&
			(pcb->xy_d2s.xio_flags & XIO_ERROR) == 0 &&
			((pcb->xy_d2s.xio_flags & XIO_FIN) == 0 ||
			 (pcb->xy_s2d.xio_flags & XIO_FIN) == 0)) {
#if 0
		if ((pcb->xy_d2s.xio_flags & XIO_FIN) == 0)

			if ((pcb->xy_s2d.xio_flags & XIO_FIN) == 0)
#endif
				return 0;
	}

	int test_flags  = XYF_WRITING | XYF_READING | XYF_XIOING;
	if ((pcb->xy_flags & XYF_ACCEPTED) == 0)
		test_flags |= XYF_ACCEPTING;
	if ((pcb->xy_flags & XYF_CONNECTED) == 0)
		test_flags |= XYF_CONNECTING;
	NASSERT ((test_flags & pcb->xy_flags) == XYF_XIOING);

	if ((pcb->xy_d2s.xio_flags & XIO_FIN) == 0 ||
			(pcb->xy_s2d.xio_flags & XIO_FIN) == 0) {
		pcb->xy_s2d.xio_flags |= XIO_ERROR;
		pcb->xy_d2s.xio_flags |= XIO_ERROR;
	}

	if ((pcb->xy_flags & XYF_CLOSE) == 0) {
		pcb->xy_flags |= XYF_CLOSE;	
		closesocket(pcb->fd_src);
		closesocket(pcb->fd_dst);
		pcb->fd_src = -1;
		pcb->fd_dst = -1;
	}

	test_flags = XIO_READING | XIO_WRITING;
	if ((pcb->xy_s2d.xio_flags & test_flags) == 0 &&
			(pcb->xy_d2s.xio_flags & test_flags) == 0) {
		rate_cacl(0, 0, -1);
		if (pcb->log_file)
			fclose(pcb->log_file);
		delete pcb;
		return  -1;
	}

	return 0;
}

int proxy_xioing(struct proxycb *cb)
{
	char buf[1024];

	if (cb->log_file == NULL) {
#if 0
		sprintf(buf, "http_trace-%08d-%08x.txt", GetTickCount(), cb);
		cb->log_file = fopen(buf, "ab");
#endif
	}

	if (cb->log_file != NULL) {
		int error;
		time_t now;
		struct sockaddr_in addr_in1 = {0};
		int addr_len = sizeof(addr_in1);

		time(&now);
		fprintf(cb->log_file, "time: %d\r\n", now);

		error = getpeername(cb->fd_dst, (struct sockaddr*)&addr_in1, &addr_len);
		fprintf(cb->log_file, "server: %s:%d\r\n",
				inet_ntoa(addr_in1.sin_addr), htons(addr_in1.sin_port));

		error = getpeername(cb->fd_src, (struct sockaddr*)&addr_in1, &addr_len);
		fprintf(cb->log_file, "client: %s\r\n\r\n",
				inet_ntoa(addr_in1.sin_addr), htons(addr_in1.sin_port));
	}

	cb->xy_d2s.xio_buf = cb->xy_snd_buf;
	cb->xy_d2s.xio_fdr = cb->fd_dst;
	cb->xy_d2s.xio_fdw = cb->fd_src;
	NASSERT(cb->xy_d2s.xio_len == 0);
	NASSERT(cb->xy_d2s.xio_off == 0);
	cb->xy_d2s.xio_size = sizeof(cb->xy_snd_buf);
	cb->xy_d2s.xio_notify = proxy_notify;
	cb->xy_d2s.xio_udata = cb;
	cb->xy_d2s.xio_header = "Server";
	cb->xy_d2s.xio_logfile = cb->log_file;
	xio_add(&cb->xy_d2s);

	cb->xy_s2d.xio_buf = cb->xy_rcv_buf;
	cb->xy_s2d.xio_len = cb->xy_rcv_len;
	cb->xy_s2d.xio_fdr = cb->fd_src;
	cb->xy_s2d.xio_fdw = cb->fd_dst;
	cb->xy_s2d.xio_size = sizeof(cb->xy_rcv_buf);
	cb->xy_s2d.xio_udata = cb;
	if (cb->xy_flags & XYF_DELAY)
		cb->xy_s2d.xio_flags |= XIO_DELAY;
	cb->xy_s2d.xio_notify = proxy_notify;
	cb->xy_s2d.xio_header = "Client";
	cb->xy_s2d.xio_logfile = cb->log_file;
	xio_add(&cb->xy_s2d);
	return 0;
}

LPFN_CONNECTEX GetConnectExAddress(int fd1)
{
	DWORD dwBytes = 0;
	LPFN_CONNECTEX ConnectExAddress = NULL;
#if 1
	GUID GuidConnectEx = WSAID_CONNECTEX;
	WSAIoctl(fd1, SIO_GET_EXTENSION_FUNCTION_POINTER, &GuidConnectEx,
			sizeof(GuidConnectEx), &ConnectExAddress, sizeof(ConnectExAddress), &dwBytes, NULL, NULL);
	NASSERT (ConnectExAddress != NULL);
#endif
	return ConnectExAddress;
}

int proxy_udpass(HANDLE hPort, in_addr & addr1, u_short & port1, struct proxycb * cb)
{
	int error = 0;
	struct sockaddr_in addr_in1;
	int fd1 = socket(AF_INET, SOCK_DGRAM, 0);
	NASSERT (fd1 != -1);

	int rcvbufsiz = 8192;
	setsockopt(fd1, SOL_SOCKET, SO_RCVBUF, &rcvbufsiz, sizeof(rcvbufsiz));

	memset(&addr_in1, 0, sizeof(addr_in1));
	addr_in1.sin_family = AF_INET;
	addr_in1.sin_port   = 0;
	addr_in1.sin_addr.s_addr = INADDR_ANY;
	error = bind(fd1, (struct sockaddr *)&addr_in1, sizeof(addr_in1));

	cb->xy_addr = addr1;
	cb->xy_port = port1;
	setblockopt(fd1, 0);
	HANDLE hPort1 = CreateIoCompletionPort((HANDLE)fd1, hPort, XIOCBCTX_FLAG, 0);
	NASSERT (hPort1 != NULL && lpConnectEx != NULL);

	if (addr1.s_addr == 0) {
		int addr_len = sizeof(addr_in1);
		int error = getpeername(cb->fd_src, (struct sockaddr*)&addr_in1, &addr_len);
		if (error == 0)
			cb->xy_addr = addr_in1.sin_addr;
	}

	return fd1;
}

int proxy_connect(HANDLE hPort, in_addr addr1, u_short port1, struct proxycb * cb)
{
	int error = 0;
	struct sockaddr_in addr_in1;
	int fd1 = socket(AF_INET, SOCK_STREAM, 0);
	NASSERT (fd1 != -1);
	memset(&addr_in1, 0, sizeof(addr_in1));
	addr_in1.sin_family = AF_INET;
	addr_in1.sin_port   = 0;
	addr_in1.sin_addr.s_addr = INADDR_ANY;
	error = bind(fd1, (struct sockaddr *)&addr_in1, sizeof(addr_in1));

	addr_in1.sin_family = PF_INET;
	addr_in1.sin_port   = port1;
	addr_in1.sin_addr   = addr1;
	HANDLE hPort1 = CreateIoCompletionPort((HANDLE)fd1, hPort, XIOCBCTX_FLAG, 0);
	NASSERT (hPort1 != NULL && lpConnectEx != NULL);

	error = lpConnectEx(fd1, (struct sockaddr *)&addr_in1, sizeof(addr_in1),
			NULL, 0, NULL, &cb->xy_connect.xc_over);

	if (error == 0 &&
			(WSAGetLastError() != ERROR_IO_PENDING)) {
		closesocket(fd1);
		fd1 = -1;
	}

#if 0
	u_long googlehk = ntohl(inet_addr("64.233.0.0"));
	u_long curraddr = ntohl(addr1.s_addr);
	if (googlehk == (0xFFFF0000 & curraddr))
		cb->xy_flags |= XYF_DELAY;
#endif

	return fd1;
}

void dump_error(struct proxycb * cb)
{
	int i = 0;
	int len = cb->xy_rcv_len;

	printf("dump error start\n");
	for (i = 0; i < len; i++)
		printf("%02x ", cb->xy_rcv_buf[i] & 0xFF);
	printf("\ndump error end\n");	
}

void udp_readed(struct XIOCBCTX * ctx, size_t iosize, BOOL success, HANDLE handle)
{
	size_t namelen;
	int test_flags;
	HANDLE handle1 = NULL;
	struct proxycb * cb = NULL;
	cb = reinterpret_cast<struct proxycb*>(ctx->xc_udata);
	NASSERT(0 == memcmp(cb->xy_magic, ".xy", 4));

	cb->xy_snd_len += iosize;

	printf("\nudp readed: %d\n", iosize);
	for (int i = 0; i < int(iosize); i++)
		printf("%02x ", cb->xy_snd_buf[i] & 0xFF);
	printf("\n");
	int data_sended = 0;
	struct sockaddr_in & from = cb->xy_rcv_addr;
	do {
		const u_char * rcvbuf = (const u_char *)cb->xy_snd_buf;
		printf("udp: %s:%d\n", inet_ntoa(from.sin_addr), ntohs(from.sin_port));
		printf("udp ddd: %s:%d\n", inet_ntoa(cb->xy_addr), ntohs(cb->xy_port));
		if (success && (from.sin_addr.s_addr == cb->xy_addr.s_addr) &&
				(from.sin_port == cb->xy_port)) {
			if (iosize < 4 || rcvbuf[0] != 0 || rcvbuf[1] != 0) {
				printf("bad packet %d %d %d %d\n", __LINE__, iosize, rcvbuf[0], rcvbuf[1]);
				goto skip_check;
			}
			/* frag is not support now */
			NASSERT(rcvbuf[2] == 0);
			/* IPv6 is not support now */
			NASSERT(rcvbuf[3] != 0x04);
			char hostname[256];
			struct sockaddr_in to;
			struct hostent * host;
			switch (rcvbuf[3]) {
				case 0x03:
					if (int(iosize) < rcvbuf[4] + 7) {
						printf("bad packet %d %d %d\n", __LINE__, iosize, rcvbuf[4]);
						goto skip_check;
					}
					namelen = rcvbuf[4] & 0xFF;
					rcvbuf += 5;
					memcpy(hostname, rcvbuf, namelen);
					rcvbuf += namelen;
					memcpy(&to.sin_port, rcvbuf, sizeof(to.sin_port));
					rcvbuf += sizeof(to.sin_port);
					hostname[namelen] = 0;
					printf("hostname: %s:%d\n", hostname, ntohs(to.sin_port));
					host = gethostbyname(hostname);
					if (host == NULL)
						goto skip_check;
					memcpy(&to.sin_addr, host->h_addr, sizeof(to.sin_addr));
					break;
				case 0x01:
					if (iosize < 10)
						goto skip_check;
					memcpy(&to.sin_addr, &rcvbuf[4], sizeof(to.sin_addr));
					memcpy(&to.sin_port, &rcvbuf[8], sizeof(to.sin_port));
					rcvbuf += 10;
					break;
				default:
					goto skip_check;
			}
			to.sin_family = AF_INET;
			size_t datalen = &cb->xy_snd_buf[iosize] - (char *)rcvbuf;
			printf("send out: %d\n", datalen);
			sendto(cb->fd_dst, (const char *)rcvbuf, datalen, 0,
					(struct sockaddr *)&to, sizeof(to));
			data_sended = 1;
		}
	} while ( 0 );

skip_check:
	if (data_sended == 0 && iosize + 10 <= sizeof(cb->xy_snd_buf)) {
		struct sockaddr_in to;
		memmove(&cb->xy_snd_buf[10], cb->xy_snd_buf, iosize);
		to.sin_family = AF_INET;
		to.sin_port   = cb->xy_port;
		to.sin_addr   = cb->xy_addr;
		memset(cb->xy_snd_buf, 0, 10);
		cb->xy_snd_buf[3] = 0x01;
		memcpy(&cb->xy_snd_buf[4], &from.sin_addr, sizeof(from.sin_addr));
		memcpy(&cb->xy_snd_buf[8], &from.sin_port, sizeof(from.sin_port));
		printf("send in: %d\n", iosize + 10);
		sendto(cb->fd_dst, cb->xy_snd_buf, iosize + 10, 0,
				(struct sockaddr *)&to, sizeof(to));
	}
	cb->xy_snd_len = 0;
	cb->xy_flags &= ~XYF_UDPREADING;

	NASSERT (ctx == &cb->xy_write);
	int xyf_flags = XYF_EOF | XYF_RESULTED | XYF_WRITING | XYF_UDP | XYF_ERROR | XYF_UDPREADING | XYF_CLOSE;
	if ((cb->xy_flags & xyf_flags) == (XYF_RESULTED | XYF_UDP)) {
		WSABUF wsabufs[1];
		wsabufs[0].len = sizeof(cb->xy_snd_buf);
		wsabufs[0].buf = cb->xy_snd_buf;
		cb->xy_rcv_flags = 0;
		cb->xy_addr_len  = sizeof(cb->xy_rcv_addr);

		int error = WSARecvFrom(cb->fd_dst, wsabufs, 1, NULL, &cb->xy_rcv_flags,
				(struct sockaddr* )&cb->xy_rcv_addr, &cb->xy_addr_len, &cb->xy_write.xc_over, NULL);

		test_flags = XYF_ERROR;
		if (error == 0 ||
				(ERROR_IO_PENDING == WSAGetLastError()))
			test_flags = XYF_UDPREADING;
		cb->xy_flags |= test_flags;
	}

	xyf_flags  = XYF_WRITING | XYF_READING | XYF_XIOING;
	if ((cb->xy_flags & xyf_flags) == 0) {
		if ((cb->xy_flags & XYF_CLOSE) == 0) {
			closesocket(cb->fd_src);
			if (cb->xy_flags & XYF_CONNECTING)
				closesocket(cb->fd_dst);
			cb->xy_flags |= XYF_CLOSE;
		}
		if ((cb->xy_flags & XYF_UDPREADING) == 0) {
			rate_cacl(0, -1, 0);
			if (cb->log_file)
				fclose(cb->log_file);
			delete cb;
		}
	}
}

int proxy_session(struct proxycb * cb, HANDLE handle)
{
	size_t len = cb->xy_rcv_len;
	char * buf = cb->xy_rcv_buf;

	NASSERT (cb->xy_flags & XYF_ACCEPTED);
	NASSERT (0 == memcmp(cb->xy_magic, ".xy", 4));

	if ((XYF_CONNECTING & cb->xy_flags) == 0) {
		if (len == 0) {
			cb->xy_flags |= XYF_READMORE;
			return 0;
		}

		if (buf[0] != 0x5 && buf[0] != 0x4) {
			dump_error(cb);
			cb->xy_flags |= XYF_ERROR;
			return 0;
		}
	}

	if ((XYF_AUTHED & cb->xy_flags) == 0 && buf[0] == 0x4) {
		if (len > 2 && buf[1] != 0x1) {
			dump_error(cb);
			cb->xy_flags |= XYF_ERROR;
			return 0;
		}
		char * pfin = len < 9? NULL: (char *)memchr(buf + 8, 0, len - 8);
		if (len < 9 || pfin == NULL) {
			cb->xy_flags |= (len < sizeof(cb->xy_rcv_buf)? XYF_READMORE: XYF_ERROR);
			return 0;			
		}

		in_addr in_addr1;
		u_short in_port1;
		memcpy(&in_addr1, &buf[4], sizeof(in_addr1));
		memcpy(&in_port1, &buf[2], sizeof(in_port1));
		len -= (++pfin - buf);
		cb->xy_rcv_len = len;

		cb->fd_dst = proxy_connect(handle, in_addr1, in_port1, cb);
		cb->xy_flags |= (XYF_CONNECTING | XYF_AUTHED | XYF_VERSION4);
		NASSERT (cb->fd_dst != -1);
	}

	int nmethod;
	if ((cb->xy_flags & XYF_AUTHED) == 0) {
		nmethod = (buf[1] & 0xFF);
		if (len < 2 || (nmethod + 2) < int(len)) {
			cb->xy_flags |= XYF_READMORE;
			return 0;
		}

		if (memchr(buf + 2, 0x0, nmethod) == NULL) {
			dump_error(cb);
			cb->xy_flags |= XYF_ERROR;
			return 0;
		}

		buf[1] = 0;
		NASSERT (cb->xy_snd_len + 2 < sizeof(cb->xy_snd_buf));
		memcpy(&cb->xy_snd_buf[cb->xy_snd_len], buf, 2);
		cb->xy_snd_len += 2;
		len -= (2 + nmethod);
		cb->xy_rcv_len = len;
		memmove(buf, &buf[2 + nmethod], len);
		cb->xy_flags |= XYF_AUTHED;
	}

	u_char pro_seq[] = { 0x05, 0x01, 0x00, 0x01 };
	u_char pro_seq_udp[] = { 0x05, 0x03, 0x00, 0x01 };

	int xyf_flags = XYF_AUTHED | XYF_CONNECTING;
	if ((cb->xy_flags & xyf_flags) == XYF_AUTHED) {
		in_addr in_addr1;
		u_short in_port1;
		size_t cmplen = len < 4? len: 4;
		if (memcmp(pro_seq, buf, cmplen) &&
				memcmp(pro_seq_udp, buf, cmplen)) {
			cb->xy_flags |= XYF_ERROR;
			return 0;
		}
		if (len  < 10) {
			cb->xy_flags |= XYF_READMORE;
			return 0;
		}
		if (memcmp(pro_seq, buf, cmplen)) {
			cb->xy_flags |= XYF_UDP;
			//dump_error(cb);
		}

		len -= 10;
		cb->xy_rcv_len = len;
		memmove(buf, &buf[10], len);
		memcpy(&in_addr1, &buf[4], sizeof(in_addr1));
		memcpy(&in_port1, &buf[8], sizeof(in_port1));

		if (cb->xy_flags & XYF_UDP) {
			cb->xy_flags |= (XYF_CONNECTED | XYF_CONNECTING);
			cb->fd_dst = proxy_udpass(handle, in_addr1, in_port1, cb);
		} else {
			cb->xy_flags |= XYF_CONNECTING;
			cb->fd_dst = proxy_connect(handle, in_addr1, in_port1, cb);
		}
		NASSERT (cb->fd_dst != -1);
	}

	u_char resp[] = {
		0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	u_char resp_v4[] = {
		0x00, 0x5A, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00
	};

	xyf_flags = XYF_CONNECTING | XYF_CONNECTED | XYF_RESULTED;
	if ((cb->xy_flags & xyf_flags) == (XYF_CONNECTING|XYF_CONNECTED)) {
		struct sockaddr_in addr_in1;
		int addr_len =  sizeof(addr_in1);
		int error = getsockname(cb->fd_dst, (struct sockaddr*)&addr_in1, &addr_len);
		if (error == 0) {
			u_short port1 = addr_in1.sin_port;
			memcpy(&resp[8], &port1, sizeof(port1));
		}
		error = getsockname(cb->fd_src, (struct sockaddr*)&addr_in1, &addr_len);
		if (error == 0) {
			in_addr addr1 = addr_in1.sin_addr;
			memcpy(&resp[4], &addr1, sizeof(addr1));
		}

		if (cb->xy_flags & XYF_VERSION4) {
			NASSERT (cb->xy_snd_len + 8 < sizeof(cb->xy_snd_buf));
			memcpy(&cb->xy_snd_buf[cb->xy_snd_len], resp_v4, 8);
			cb->xy_snd_len += 8;
		} else {
			NASSERT (cb->xy_snd_len + 10 < sizeof(cb->xy_snd_buf));
			memcpy(&cb->xy_snd_buf[cb->xy_snd_len], resp, 10);
			cb->xy_snd_len += 10;
		}
		cb->xy_flags |= XYF_RESULTED;		
	}

	xyf_flags = XYF_XIOING | XYF_RESULTED | XYF_READING | XYF_WRITING | XYF_UDP;
	if (cb->xy_snd_len == 0 &&
			(cb->xy_flags & xyf_flags) == XYF_RESULTED) {
		int error = 0;
		if (proxy_xioing(cb) == 0) {
			cb->xy_flags |= XYF_XIOING;
			rate_cacl(0, -1, +1);
			error = xio_call(&cb->xy_d2s);
			if (error != 0)
				return -1;
			error = xio_call(&cb->xy_s2d);
			if (error != 0)
				return -1;
		}
	}

	xyf_flags = XYF_EOF | XYF_RESULTED | XYF_READING | XYF_WRITING | XYF_UDP | XYF_ERROR;
	if (cb->xy_snd_len == 0 &&
			(cb->xy_flags & xyf_flags) == (XYF_RESULTED | XYF_UDP)) {
		WSABUF wsabufs[1];
		wsabufs[0].len = sizeof(cb->xy_rcv_buf);
		wsabufs[0].buf = cb->xy_rcv_buf;
		cb->xy_rcv_flags = 0;
		int error = WSARecv(cb->fd_src, wsabufs, 1, NULL, &cb->xy_rcv_flags, &cb->xy_read.xc_over, NULL);
		int test_flags = XYF_ERROR;
		if (error == 0 ||
				(ERROR_IO_PENDING == WSAGetLastError()))
			test_flags = XYF_READING;
		cb->xy_flags |= test_flags;
	}

	xyf_flags = XYF_EOF | XYF_RESULTED | XYF_WRITING | XYF_UDP | XYF_ERROR | XYF_UDPREADING;
	if (cb->xy_snd_len == 0 &&
			(cb->xy_flags & xyf_flags) == (XYF_RESULTED | XYF_UDP)) {
		WSABUF wsabufs[1];
		wsabufs[0].len = sizeof(cb->xy_snd_buf);
		wsabufs[0].buf = cb->xy_snd_buf;
		cb->xy_rcv_flags = 0;
		cb->xy_addr_len  = sizeof(cb->xy_rcv_addr);
		XY_OVER_INIT(&cb->xy_write, cb, udp_readed);
		int error = WSARecvFrom(cb->fd_dst, wsabufs, 1, NULL, &cb->xy_rcv_flags,
				(struct sockaddr* )&cb->xy_rcv_addr, &cb->xy_addr_len, &cb->xy_write.xc_over, NULL);

		int test_flags = XYF_ERROR;
		if (error == 0 ||
				(ERROR_IO_PENDING == WSAGetLastError()))
			test_flags = XYF_UDPREADING;
		cb->xy_flags |= test_flags;
	}
	return 0;
}

void proxy_post(struct XIOCBCTX * ctx, size_t iosize, BOOL success, HANDLE handle)
{
	int test_flags;
	HANDLE handle1 = NULL;
	struct proxycb * cb = NULL;
	NASSERT(0 == memcmp(ctx->xc_magic, "ovr", 4));
	cb = reinterpret_cast<struct proxycb*>(ctx->xc_udata);
	NASSERT(0 == memcmp(cb->xy_magic, ".xy", 4));
	if (ctx == &cb->xy_accept) {
		test_flags = cb->xy_flags & (XYF_ACCEPTED|XYF_ACCEPTING);
		NASSERT (test_flags == XYF_ACCEPTING);
		cb->xy_flags |= XYF_ACCEPTED;
		handle1 = CreateIoCompletionPort((HANDLE)cb->fd_src, handle, XIOCBCTX_FLAG, 0);

		int update_context = cb->fd_dst;
		int error = setsockopt(cb->fd_src, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&update_context, sizeof(update_context));
		int nodelay = 1;
		setsockopt(cb->fd_src, TCP_NODELAY, TCP_NODELAY, (char *)&nodelay, sizeof(nodelay));
		NASSERT (error == 0);
		rate_cacl(0, +1, 0);
		NASSERT (success != FALSE);
		NASSERT (handle1 != NULL);
		NASSERT (iosize == 0);
	}
	if (ctx == &cb->xy_connect) {
		test_flags = cb->xy_flags & (XYF_CONNECTED|XYF_CONNECTING);
		NASSERT (test_flags == XYF_CONNECTING);
		setsockopt(cb->fd_dst, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
		cb->xy_flags |= XYF_CONNECTED;
		NASSERT (iosize == 0);
	}
	if (ctx == &cb->xy_read) {
		test_flags = cb->xy_flags & XYF_READING;
		NASSERT (test_flags == XYF_READING);
		cb->xy_flags &= ~XYF_READING;
		cb->xy_rcv_len += iosize;
		if (iosize == 0)
			cb->xy_flags |= XYF_EOF;
		cb->xy_flags &= ~XYF_READMORE;
	}
	if (ctx == &cb->xy_write) {
		int test_flags = cb->xy_flags & XYF_WRITING;
		NASSERT (test_flags == XYF_WRITING);
		cb->xy_flags &= ~XYF_WRITING;
		NASSERT (cb->xy_snd_len >= iosize);
		cb->xy_snd_len -= iosize;		
		memmove(cb->xy_snd_buf, &cb->xy_snd_buf[iosize], cb->xy_snd_len);
	}

	if (success == FALSE)
		cb->xy_flags |= XYF_ERROR;

	if (proxy_session(cb, handle) != 0)
		return;

	int error = 0;
	WSABUF wsabufs[2];
	test_flags = XYF_READMORE | XYF_READING | XYF_ERROR | XYF_EOF;
	if ((cb->xy_flags & test_flags) == XYF_READMORE && 
			cb->xy_rcv_len < sizeof(cb->xy_rcv_buf)) {
		NASSERT((XYF_XIOING & cb->xy_flags) == 0);
		cb->xy_rcv_flags = 0;
		wsabufs[0].buf = &cb->xy_rcv_buf[cb->xy_rcv_len];
		wsabufs[0].len = sizeof(cb->xy_rcv_buf) - cb->xy_rcv_len;
		NASSERT (wsabufs[0].len > 0);
		memset(&cb->xy_read.xc_over, 0, sizeof(cb->xy_read.xc_over));
		error = WSARecv(cb->fd_src, wsabufs, 1, NULL,
				&cb->xy_rcv_flags, &cb->xy_read.xc_over, NULL);
		test_flags = XYF_ERROR;
		if (error == 0 ||
				(ERROR_IO_PENDING == WSAGetLastError()))
			test_flags = XYF_READING;
		cb->xy_flags |= test_flags;
	}

	test_flags = XYF_WRITING | XYF_ERROR;
	if ((cb->xy_flags & test_flags) == 0 && 
			0 < cb->xy_snd_len) {
		NASSERT((XYF_XIOING & cb->xy_flags) == 0);
		wsabufs[0].buf = cb->xy_snd_buf;
		wsabufs[0].len = cb->xy_snd_len;
		NASSERT (wsabufs[0].len > 0);
		memset(&cb->xy_write.xc_over, 0, sizeof(cb->xy_write.xc_over));
		error = WSASend(cb->fd_src, wsabufs, 1, NULL, 0, 
				&cb->xy_write.xc_over, NULL);
		test_flags = XYF_ERROR;
		if (error == 0 ||
				(ERROR_IO_PENDING == WSAGetLastError()))
			test_flags = XYF_WRITING;
		cb->xy_flags |= test_flags;
	}

	test_flags  = XYF_WRITING | XYF_READING | XYF_XIOING;
	if ((cb->xy_flags & XYF_ACCEPTED) == 0)
		test_flags |= XYF_ACCEPTING;

	if ((cb->xy_flags & XYF_CONNECTED) == 0)
		test_flags |= XYF_CONNECTING;

	if ((cb->xy_flags & test_flags) == 0) {
		if ((cb->xy_flags & XYF_CLOSE) == 0) {
			closesocket(cb->fd_src);
			if (cb->xy_flags & XYF_CONNECTING)
				closesocket(cb->fd_dst);
			cb->xy_flags |= XYF_CLOSE;
		}
		if ((cb->xy_flags & XYF_UDPREADING) == 0) {
			rate_cacl(0, -1, 0);
			if (cb->log_file)
				fclose(cb->log_file);
			delete cb;
		}
	}
	return ;
}

int proxy_accept(int listen1)
{
	int error;
	struct proxycb * cb = new proxycb;
	memset(cb, 0, sizeof(proxycb));
	NASSERT (cb != NULL);
	int fd1 = socket(AF_INET, SOCK_STREAM, 0);
	memset(cb, 0, sizeof(struct proxycb));
	strcpy(cb->xy_magic, ".xy");
	strcpy(cb->xy_s2d.xio_magic, "xio");
	strcpy(cb->xy_d2s.xio_magic, "xio");
	NASSERT (fd1 != -1);

	cb->fd_src = fd1;
	cb->fd_dst = listen1;
	cb->log_file = NULL;

	XY_OVER_INIT(&cb->xy_read, cb, proxy_post);
	XY_OVER_INIT(&cb->xy_write, cb, proxy_post);
	XY_OVER_INIT(&cb->xy_accept, cb, proxy_post);
	XY_OVER_INIT(&cb->xy_connect, cb, proxy_post);
	size_t soaddr_buf_len = sizeof(struct sockaddr_in) + 16;
	error = lpAcceptEx(listen1, fd1, cb->xy_rcv_buf, 0, soaddr_buf_len,
			soaddr_buf_len, NULL, &cb->xy_accept.xc_over);
	NASSERT (error == 0 || (WSAGetLastError() == ERROR_IO_PENDING));
	cb->xy_flags |= XYF_ACCEPTING;
	return 0;
}

DWORD proxy_event(HANDLE hPort, int listen1)
{
	int error;
	DWORD key = 0;
	DWORD ioSize = 0;
	BOOL  success = FALSE;
	XIOCBCTX * ctx = NULL;
	LPOVERLAPPED io_data = NULL;

	success = GetQueuedCompletionStatus(hPort, &ioSize, &key, &io_data, INFINITE);

	if (io_data == NULL) {
		/* NASSERT (success == FALSE); */
		return 0;
	}

	switch (key) {
		case XIOCBCTX_FLAG1:
			error = proxy_accept(listen1);
			NASSERT (error == 0);
		case XIOCBCTX_FLAG:
			ctx = reinterpret_cast<XIOCBCTX *>(io_data);
			NASSERT(0 == memcmp(ctx->xc_magic, "ovr", 4));
			ctx->xc_callback(ctx, ioSize, success, hPort);
			break;
		default:
			NASSERT ( 0 );
			break;
	}

	return 0;
}

#endif

int NDSMainCall(BOOL IsInterActive)
{
	WSADATA wsadata;
	HANDLE hPort = INVALID_HANDLE_VALUE;
	SOCKET listen1 = INVALID_SOCKET;

	int error = WSAStartup(0x101, &wsadata);
	NASSERT(error == 0);

	listen1 = socket(AF_INET, SOCK_STREAM, 0);
	NASSERT(listen1 != INVALID_SOCKET);

	struct sockaddr_in addr_in1;
	addr_in1.sin_family = AF_INET;
	addr_in1.sin_port   = htons(1080);
	addr_in1.sin_addr.s_addr = htonl(INADDR_ANY);

	error = bind(listen1, (struct sockaddr *)&addr_in1, sizeof(addr_in1));
	NASSERT(error == 0);

	error = listen(listen1, 5);
	NASSERT(error == 0);

	gQuitPortHandle = hPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	NASSERT(hPort != NULL);

	HANDLE handle = CreateIoCompletionPort((HANDLE)listen1, hPort, NDSMAGIC, 0);
	NASSERT(handle != NULL);

	lpAcceptEx = GetAcceptExAddress(listen1);
	lpConnectEx = GetConnectExAddress(listen1);

	error = proxy_accept(listen1);
	NASSERT(error == 0);

	int last_print = 0;
	while ( bIsRunning ) {
		proxy_event(hPort, listen1);
		rate_cacl(0, 0, 0);
	}

	closesocket(listen1);
	CloseHandle(hPort);
	WSACleanup();
	return 0;
}

//FILE _iob[3];

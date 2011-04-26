#include "Stdafx.h"
#include <assert.h>
#include <winsock2.h>
#include <mswsock.h>
#include <windows.h>

#include "Utils.h"
#include "Config.h"
#include "Network.h"
#include "SDServer.h"
#include "FlowControl.h"

#define XYF_CONNECTING 0x00000004
#define XYF_CONNECTED  0x00000008
#define XYF_AUTHED     0x00000020
#define XYF_RESULTED   0x00000040
#define XYF_VERSION4   0x00000400
#define XYF_UDP        0x04000000

#pragma comment(lib, "Psapi.lib")

typedef struct TransferCancel_Item {
	struct TransferCancel_Item * next;
	struct TransferCancel_Item ** prev;
	DWORD magic;
	DWORD state;
	LPVOID context;
	ASYNCCALL * callback;
} TransferCancelCallback;

#define LIST_NAME(x) TransferCancel_##x
#include "DLinkedList_c.h"
#undef LIST_NAME

typedef struct _PluginParam {
	BOOL quited;
	SOCKET tcp_fd;
	SOCKET incoming_fd;
	AIOCB tcp_acb;
	char tcp_buf[4096];
} PluginParam, * PPluginParam;

static AIOCB alivecb;
static Callout keepalive;
static PluginParam TcpTransfer;
static void TcpTransferCallback(LPVOID lpVoid);

class CTcpTransfer {
public:
	CTcpTransfer(int file);
	~CTcpTransfer(void);

public:
	int Run(void);
	static void TTCallback(LPVOID context);
	static void TTInterval(LPVOID context);
	static void TcpCancelCallback(LPVOID context);

public:
	void ResetTcpTimer(void);
	void StopTcpTimer(void);
	void DropTcpTimer(void);

private:
	int readMore(void);
	int PacketRead(void);
	int PacketWrite(void);
	int PacketProcess(PBOOL pchange);

private:
	int m_file;
	int m_killed;

private:
	int m_len, m_off;
	char m_buf[8192];
	int m_woff, m_wlen;
	char m_wbuf[16 * 1024];

private:
	DWORD m_flags;
	DWORD m_lastactive;
	CTcpTransfer * m_next;
	CTcpTransfer ** m_prev;

private:
	int m_pfd;
	AIOCB m_pacb;
	AIOCB m_pwcb;
	AIOCB m_pdiscb;

private:
	AIOCB m_acb;
	AIOCB m_wcb;
	AIOCB m_discb;
	FlowCtrlCallback m_fcb;
	TransferCancelCallback m_cancel;
	static int obj_cnt;
};

int CTcpTransfer::obj_cnt = 0;

static int TcpTransferStart(void)
{
	int tcp_fd;
	int incoming_fd;

	BOOL success;
	DWORD flags, ignore;
	LPVOID tcp_buf = TcpTransfer.tcp_buf;
	
	tcp_fd = TcpTransfer.tcp_fd;
	success = AssociateDeviceWithCompletionPort((HANDLE)tcp_fd, 0);
	DS_ASSERT(success != FALSE);

	flags = ignore = 0;
	incoming_fd = socket(AF_INET, SOCK_STREAM, 0);
	DS_ASSERT(incoming_fd != -1);

	TcpTransfer.quited = FALSE;
	success = AIO_AcceptEx(tcp_fd, incoming_fd, tcp_buf, 0,
		16 + sizeof(struct sockaddr), 16 + sizeof(struct sockaddr), &TcpTransfer.tcp_acb);

	DS_ASSERT(success != FALSE || WSAGetLastError() == ERROR_IO_PENDING);
	TcpTransfer.incoming_fd = incoming_fd;

	PushAsyncCall(&alivecb);
	return 0;
}

static AIOCB _async_callback = {0};

static void DoTcpStop(LPVOID ctx)
{
	TransferCancelCallback * fcb;

	if (TcpTransfer.quited == TRUE) {
		TcpTransfer.quited = FALSE;
		CancelIo(HANDLE(TcpTransfer.tcp_fd));

		while ( !TransferCancel_Empty() ) {
			fcb = TransferCancel_Header();
			TransferCancel_Delete(fcb);
			fcb->callback(fcb->context);
		}
	}
}

static int TcpTransferStop(void)
{
	BOOL success = PushAsyncCall(&_async_callback);
	/* DS_ASSERT(success == TRUE); */
	return 0;
}

static int TcpTransferInit(void)
{
	int error;
	int tcp_fd;
	struct sockaddr_in addr;

	tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
	DS_ASSERT(tcp_fd != -1);

	addr.sin_family = AF_INET;
	addr.sin_port   = htons(1080);
	addr.sin_addr.s_addr = INADDR_ANY;
	error = bind(tcp_fd, (const struct sockaddr *)&addr, sizeof(addr));
	DS_ASSERT(error == 0);

	error = listen(tcp_fd, 5);
	DS_ASSERT(error == 0);

	CalloutInit(&keepalive);
	TcpTransfer.tcp_fd = tcp_fd;
	AIOCB_Init(&_async_callback, DoTcpStop, NULL);
	AIOCB_Init(&alivecb, CTcpTransfer::TTInterval, NULL);
	AIOCB_Init(&TcpTransfer.tcp_acb, TcpTransferCallback, (PVOID)NULL);
	
	return 0;
}

static int TcpTransferClean(void)
{
	closesocket(TcpTransfer.tcp_fd);
	return 0;
}

static CTcpTransfer * tcp_header = 0;
static CTcpTransfer ** tcp_tailer = &tcp_header;

CTcpTransfer::CTcpTransfer(int file)
:m_file(file), m_killed(0), m_pfd(-1)
{
	m_flags = 0;
	m_next = NULL;
	m_prev = NULL;

	m_off = m_len = 0;
	m_woff = m_wlen = 0;
	
	FlowCtrlIdle_Init(&m_fcb);
	m_lastactive = GetTickCount();
	AIOCB_Init(&m_acb, TTCallback, this);
	AIOCB_Init(&m_wcb, TTCallback, this);
	AIOCB_Init(&m_discb, TTCallback, this);
	AIOCB_Init(&m_pacb, TTCallback, this);
	AIOCB_Init(&m_pwcb, TTCallback, this);
	AIOCB_Init(&m_pdiscb, TTCallback, this);

	TransferCancel_Init(&m_cancel);
	m_cancel.context = this;
	m_cancel.callback = TcpCancelCallback;
	TransferCancel_Insert(&m_cancel);

	obj_cnt++;
}

CTcpTransfer::~CTcpTransfer()
{
	TransferCancel_Drop(&m_cancel);
	FlowCtrlIdle_Drop(&m_fcb);
	closesocket(m_file);
	closesocket(m_pfd);
	DropTcpTimer();
	printf("close: %u\n", --obj_cnt);
}

int CTcpTransfer::PacketRead(void)
{
	if ( AIOCB_ISFINISH(&m_acb) ) {
		StopTcpTimer();
		if (m_acb.count == 0)
			m_killed = 1;
		m_len += m_acb.count;
		AIOCB_CLEAR(&m_acb);
	}

	if ( AIOCB_ISFINISH(&m_pwcb) ) {
		StopTcpTimer();
		m_flags |= XYF_CONNECTED;
		m_off += m_pwcb.count;
		AIOCB_CLEAR(&m_pwcb);
	}

	if ( AIOCB_ISFINISH(&m_pacb) ) {
		StopTcpTimer();
		if (m_pacb.count == 0)
			m_killed = 1;
		FlowCtrlAddflow(m_pacb.count);
		m_wlen += m_pacb.count;
		AIOCB_CLEAR(&m_pacb);
	}

	if ( AIOCB_ISFINISH(&m_wcb) ) {
		StopTcpTimer();
		if (m_wcb.count == 0)
			m_killed = 1;
		m_woff += m_wcb.count;
		AIOCB_CLEAR(&m_wcb);
	}

	return 1;
}

int CTcpTransfer::readMore(void)
{
	DWORD result;

	if (m_killed == 0 && !AIOCB_ISPENDING(&m_acb) && m_len < sizeof(m_buf)) {
		result = AIO_WSARecv(m_file, m_buf + m_len, sizeof(m_buf) - m_len, &m_acb);
		if (result == 0 || WSAGetLastError() == WSA_IO_PENDING) {
			ResetTcpTimer();
		} else {
			m_killed = 1;
		}
	}

	return 0;
}

int CTcpTransfer::PacketWrite(void)
{
	DWORD result;

	DS_ASSERT(m_woff <= m_wlen);
	if (m_woff < m_wlen && m_killed == 0 && !AIOCB_ISPENDING(&m_wcb)) {
		result = AIO_WSASend(m_file, m_wbuf + m_woff, m_wlen - m_woff, &m_wcb);
		if (result == 0 || WSAGetLastError() == WSA_IO_PENDING) {
			ResetTcpTimer();
		}else {
			m_killed = 1;
		}
	}

	return (m_killed == 0);
}

#if 0
void udp_readed(struct XIOCBCTX * ctx,
	   	size_t iosize, BOOL success, HANDLE handle)
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
#endif

#define S_RATE(s) ((s) < 30960? (s): 30960)
int CTcpTransfer::PacketProcess(PBOOL pchange)
{
	int fd1, error;
	in_addr in_addr1;
	u_short in_port1;
	struct sockaddr_in addr_in1;

	if ((XYF_AUTHED & m_flags) == 0) {
		if (m_len > 0 && m_buf[0] != 0x4 && m_buf[0] != 0x5)
			m_killed = 1;
		if (m_len == 0)
			return readMore();
	}

	if ((XYF_AUTHED & m_flags) == 0 &&
		m_len > 0 && m_buf[0] == 0x4) {
		if (m_len > 2 && m_buf[1] != 0x1) {
			m_killed = 1;
			return 0;
		}

		char * pfin = m_len < 9? NULL: (char *)memchr(m_buf + 8, 0, m_len - 8);
		if (m_len < 9 || pfin == NULL) {
			if (m_len >= sizeof(m_buf)) {
				m_killed = 1;
			} else {
				return readMore();
			}
			return 0;
		}

		memcpy(&in_addr1, &m_buf[4], sizeof(in_addr1));
		memcpy(&in_port1, &m_buf[2], sizeof(in_port1));
		m_len -= (++pfin - m_buf);

		fd1 = socket(AF_INET, SOCK_STREAM, 0);
		DS_ASSERT(fd1 != -1);

		memset(&addr_in1, 0, sizeof(addr_in1));
		addr_in1.sin_family = AF_INET;
		addr_in1.sin_port   = htons(0);
		addr_in1.sin_addr.s_addr = INADDR_ANY;
		error = bind(fd1, (struct sockaddr *)&addr_in1, sizeof(addr_in1));
		error = AssociateDeviceWithCompletionPort(HANDLE(fd1), 0);
		DS_ASSERT(error != 0);

		addr_in1.sin_family = AF_INET;
		addr_in1.sin_port   = in_port1;
		addr_in1.sin_addr   = in_addr1;
		error = AIO_ConnectEx(fd1, (struct sockaddr *)&addr_in1, sizeof(addr_in1), 0, 0, &m_pwcb);
		if (error == FALSE && WSAGetLastError() != ERROR_IO_PENDING) {
			closesocket(fd1);
			m_killed = 1;
			fd1 = -1;
		}

		m_flags |= XYF_AUTHED;
		m_flags |= XYF_VERSION4;
		m_flags |= XYF_CONNECTING;
		m_pfd = fd1;
	}

#if 0
	u_long googlehk = ntohl(inet_addr("64.233.0.0"));
	u_long curraddr = ntohl(addr1.s_addr);
	if (googlehk == (0xFFFF0000 & curraddr))
		cb->xy_flags |= XYF_DELAY;
#endif

	int nmethod;
	if ((m_flags & XYF_AUTHED) == 0 &&
		m_len > 0 && m_buf[0] == 0x5) {

		nmethod = (m_buf[1] & 0xFF);
		if (m_len < 2 || (nmethod + 2) < int(m_len)) {
			return readMore();
		}

		if (memchr(m_buf + 2, 0x0, nmethod) == NULL) {
			return readMore();
		}

		m_buf[1] = 0;
		DS_ASSERT(m_wlen + 2 < sizeof(m_wbuf));
		memcpy(m_wbuf + m_wlen, m_buf, 2);
		m_wlen += 2;

		m_len -= (2 + nmethod);
		memmove(m_buf, &m_buf[2 + nmethod], m_len);

		m_flags |= XYF_AUTHED;
		*pchange = TRUE;
	}
	
	u_char pro_seq[] = { 0x05, 0x01, 0x00, 0x01 };
	u_char pro_seq_udp[] = { 0x05, 0x03, 0x00, 0x01 };
	int xyf_flags = XYF_AUTHED | XYF_CONNECTING;
	if ((xyf_flags & m_flags) == XYF_AUTHED) {

		size_t cmplen = m_len < 4? m_len: 4;
		if (memcmp(pro_seq, m_buf, cmplen) &&
				memcmp(pro_seq_udp, m_buf, cmplen)) {
			return readMore();
		}

		if (m_len  < 10) {
			return readMore();
		}

		if (memcmp(pro_seq, m_buf, cmplen)) {
			m_flags |= XYF_UDP;
		}

		m_len -= 10;
		memmove(m_buf, &m_buf[10], m_len);
		memcpy(&in_addr1, &m_buf[4], sizeof(in_addr1));
		memcpy(&in_port1, &m_buf[8], sizeof(in_port1));

		if (m_flags & XYF_UDP) {
			m_flags |= (XYF_CONNECTED | XYF_CONNECTING);
		} else {
			fd1 = socket(AF_INET, SOCK_STREAM, 0);
			DS_ASSERT(fd1 != -1);

			memset(&addr_in1, 0, sizeof(addr_in1));
			addr_in1.sin_family = AF_INET;
			addr_in1.sin_port   = htons(0);
			addr_in1.sin_addr.s_addr = INADDR_ANY;
			error = bind(fd1, (struct sockaddr *)&addr_in1, sizeof(addr_in1));
			error = AssociateDeviceWithCompletionPort(HANDLE(fd1), 0);
			DS_ASSERT(error != 0);

			addr_in1.sin_family = AF_INET;
			addr_in1.sin_port   = in_port1;
			addr_in1.sin_addr   = in_addr1;
			error = AIO_ConnectEx(fd1, (struct sockaddr *)&addr_in1, sizeof(addr_in1), 0, 0, &m_pwcb);
			if (error == FALSE && WSAGetLastError() != ERROR_IO_PENDING) {
				closesocket(fd1);
				m_killed = 1;
				fd1 = -1;
			}

			printf("xio is connecting: %s\n", inet_ntoa(addr_in1.sin_addr));
			m_flags |= XYF_CONNECTING;
			m_pfd = fd1;
		}
	}

	u_char resp[] = {
		0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	u_char resp_v4[] = {
		0x00, 0x5A, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00
	};

	xyf_flags = XYF_CONNECTING | XYF_CONNECTED | XYF_RESULTED;
	if ((m_flags & xyf_flags) == (XYF_CONNECTING| XYF_CONNECTED)) {
		int addr_len =  sizeof(addr_in1);
		error = getsockname(m_pfd, (struct sockaddr*)&addr_in1, &addr_len);
		if (error == 0) {
			in_port1 = addr_in1.sin_port;
			memcpy(&resp[8], &in_port1, sizeof(in_port1));
		}

		error = getsockname(m_file, (struct sockaddr*)&addr_in1, &addr_len);
		if (error == 0) {
			in_addr1 = addr_in1.sin_addr;
			memcpy(&resp[4], &in_addr1, sizeof(in_addr1));
		}

		if (m_flags & XYF_VERSION4) {
			DS_ASSERT(m_wlen + 8 < sizeof(m_wbuf));
			memcpy(m_wbuf + m_wlen, resp_v4, 8);
			m_wlen += 8;
		} else {
			DS_ASSERT(m_wlen + 10 < sizeof(m_wbuf));
			memcpy(m_wbuf + m_wlen, resp, 10);
			m_wlen += 10;
		}

		m_flags |= XYF_RESULTED;
	}

	if ((m_flags & XYF_RESULTED) && m_killed == 0) {

		if (m_len == m_off && !AIOCB_ISPENDING(&m_acb)) {
			m_off = m_len = 0;
			error = AIO_WSARecv(m_file, m_buf, sizeof(m_buf), &m_acb);
			if (error == 0 || WSAGetLastError() == WSA_IO_PENDING) {
				ResetTcpTimer();
			} else {
				m_killed = 1;
				return 0;
			}
		}

		if (m_wlen == m_woff && !AIOCB_ISPENDING(&m_pacb)) {
			m_woff = m_wlen = 0;
			if (!FlowCtrlIsIdle()) {
				FlowCtrlIdle_Reset(&m_fcb, TTCallback, this);
			} else {
				error = AIO_WSARecv(m_pfd, m_wbuf, sizeof(m_wbuf), &m_pacb);
				if (error == 0 || WSAGetLastError() == WSA_IO_PENDING) {
					ResetTcpTimer();
				} else {
					m_killed = 1;
					return 0;
				}
			}
		}

		if (m_off < m_len && !AIOCB_ISPENDING(&m_pwcb)) {
			error = AIO_WSASend(m_pfd, m_buf + m_off, S_RATE(m_len - m_off), &m_pwcb);
			if (error == 0 || WSAGetLastError() == WSA_IO_PENDING) {
				FlowCtrlAddflow(S_RATE(m_len - m_off));
				ResetTcpTimer();
			} else {
				m_killed = 1;
				return 0;
			}
		}

		if (m_woff < m_wlen && !AIOCB_ISPENDING(&m_wcb)) {
			error = AIO_WSASend(m_file, m_wbuf + m_woff, S_RATE(m_wlen - m_woff), &m_wcb);
			if (error == 0 || WSAGetLastError() == WSA_IO_PENDING) {
				ResetTcpTimer();
			} else {
				m_killed = 1;
				return 0;
			}
		}
	}

	return 0;
}

int CTcpTransfer::Run(void)
{
	BOOL change, success;

	PacketRead();
	do {
		change = FALSE;
		PacketProcess(&change);
	} while (change);
	PacketWrite();

	if (m_killed == 1) {
		CancelIo(HANDLE(m_file));
		CancelIo(HANDLE(m_pfd));
	}

	if (AIOCB_ISPENDING(&m_acb) || AIOCB_ISPENDING(&m_wcb)) { 
		/* WSAGetOverlappedResult */
		return -1;
	}

	if (AIOCB_ISPENDING(&m_pacb) || AIOCB_ISPENDING(&m_pwcb)) { 
		/* WSAGetOverlappedResult */
		return -1;
	}

	if ( AIOCB_ISPENDING(&m_discb) ) {
		/* pending */
		return -1;
	}

	if ( !AIOCB_ISFINISH(&m_discb) ) {
		success = AIO_DisconnectEx(m_file, &m_discb);
		if (success == TRUE || WSAGetLastError() == WSA_IO_PENDING)
			return -1;
	}

	if ( AIOCB_ISPENDING(&m_pdiscb) ) {
		/* pending */
		return -1;
	}

#if 0
	if ( !AIOCB_ISFINISH(&m_discb) ) {
		success = AIO_DisconnectEx(m_file, &m_discb);
		if (success == TRUE || WSAGetLastError() == WSA_IO_PENDING)
			return -1;
	}
#endif

	return 0;
}

void CTcpTransfer::TTCallback(LPVOID context)
{
	CTcpTransfer * tt;
	tt = (CTcpTransfer *)context;

	if (tt->Run() == 0) {
		delete tt;
		return;
	}
}

void CTcpTransfer::TTInterval(LPVOID context)
{
	DWORD now;
	CTcpTransfer * tt;

	now = GetTickCount();
	while (tcp_header != NULL) {

		tt = tcp_header;
		if (int(tt->m_lastactive + 60000 - now) > 0) {
			break;
		}

		tt->StopTcpTimer();
		printf("Time Out!\n");
		tt->m_killed = 1;
		TTCallback(tt);
	}

	CalloutReset(&keepalive, CTcpTransfer::TTInterval, context, 6000);
}

void CTcpTransfer::TcpCancelCallback(LPVOID context)
{
	CTcpTransfer * tt;
	tt = (CTcpTransfer *)context;

	tt->m_killed = 1;
	if (tt->Run() == 0) {
		delete tt;
		return;
	}
}

void CTcpTransfer::ResetTcpTimer(void)
{
	m_lastactive = GetTickCount();
	
	if (tcp_tailer != &m_next) {
		if (m_prev != NULL)
			*m_prev = m_next;
		if (m_next != NULL)
			m_next->m_prev = m_prev;
		m_prev = tcp_tailer;
		*tcp_tailer = this;
		tcp_tailer = &m_next;
		m_next = NULL;
	}
}

void CTcpTransfer::DropTcpTimer(void)
{
	if (m_prev != NULL) {
		if (tcp_tailer == &m_next)
			tcp_tailer = m_prev;
		if (m_next != NULL)
			m_next->m_prev = m_prev;
		*m_prev = m_next;
	}
}

void CTcpTransfer::StopTcpTimer(void)
{
	if (m_prev != NULL) {
		if (tcp_tailer == &m_next)
			tcp_tailer = m_prev;
		if (m_next != NULL)
			m_next->m_prev = m_prev;
		*m_prev = m_next;
		m_next = NULL;
		m_prev = NULL;
	}
}

void NewTcpTansfer(int file)
{
	BOOL success;
	CTcpTransfer * tt;

	DS_ASSERT(file != -1); 
	success = AssociateDeviceWithCompletionPort((HANDLE)file, 0);
	DS_ASSERT(success == TRUE);

	tt = new CTcpTransfer(file);

	if (tt == NULL) {
		closesocket(file);
		return;
	}

	CTcpTransfer::TTCallback(tt);
}

static void TcpTransferCallback(LPVOID lpVoid)
{
	int tcp_fd;
	int incoming_fd;

	BOOL success;
	DWORD flags, ignore;
	LPVOID tcp_buf = TcpTransfer.tcp_buf;
	
	tcp_fd = TcpTransfer.tcp_fd;

	if (TcpTransfer.quited) {
		closesocket(TcpTransfer.incoming_fd);
		TcpTransfer.incoming_fd = -1;
		return;
	}

	if ( AIOCB_ISFINISH(&TcpTransfer.tcp_acb) ) {
		NewTcpTansfer(TcpTransfer.incoming_fd);
		AIOCB_CLEAR(&TcpTransfer.tcp_acb);
		TcpTransfer.incoming_fd = -1;
	}

	flags = ignore = 0;
	incoming_fd = socket(AF_INET, SOCK_STREAM, 0);
	DS_ASSERT(incoming_fd != -1);

	success = AIO_AcceptEx(tcp_fd, incoming_fd, tcp_buf, 0,
		16 + sizeof(struct sockaddr), 16 + sizeof(struct sockaddr), &TcpTransfer.tcp_acb);
	DS_ASSERT(success != FALSE || WSAGetLastError() == ERROR_IO_PENDING);

	DS_ASSERT(TcpTransfer.incoming_fd == -1);
	TcpTransfer.incoming_fd = incoming_fd;
}

DSPLUGIN_EXPORT int DSGetPlugin_TcpTransfer(PDSClientPlugin pplugin)
{
	pplugin->initialize = TcpTransferInit;
	pplugin->clean = TcpTransferClean;

	pplugin->start = TcpTransferStart;
	pplugin->stop = TcpTransferStop;
	return 0;
}

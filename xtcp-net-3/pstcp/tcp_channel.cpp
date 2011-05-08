#include <stdio.h>
#include <assert.h>
#include <winsock.h>

#include "event.h"
#include "tcpusr.h"
#include "modules.h"
#include "tcp_channel.h"

#define TF_CONNECT    1
#define TF_CONNECTING 2
#define TF_EOF0       4
#define TF_EOF1       8
#define TF_SHUT0     16
#define TF_SHUT1     32

class tcp_channel {
   	public:
		tcp_channel(int fd);
		~tcp_channel();

	public:
		int run(void);
		static void tc_callback(void * context);

	private:
		int m_file;
		int m_flags;

	private:
		event_t r_event;
		event_t w_event;

	private:
		int m_woff;
		int m_wlen;
		char m_wbuf[8192];

	private:
		int m_roff;
		int m_rlen;
		char m_rbuf[8192];

	private:
		event_t r_evt_peer;
		event_t w_evt_peer;
		struct tcpcb * m_peer;
};

static u_short _forward_port = 1080;
static u_long  _forward_addr = INADDR_LOOPBACK;

tcp_channel::tcp_channel(int file)
	:m_file(file), m_flags(0)
{
	m_peer = tcp_create();
	assert(m_peer != NULL);
	m_roff = m_rlen = 0;
	m_woff = m_wlen = 0;

	event_init(&r_event, tc_callback, this);
	event_init(&w_event, tc_callback, this);
	event_init(&r_evt_peer, tc_callback, this);
	event_init(&w_evt_peer, tc_callback, this);
}

tcp_channel::~tcp_channel()
{
	event_clean(&r_event);
	event_clean(&w_event);
	event_clean(&r_evt_peer);
	event_clean(&w_evt_peer);

	fprintf(stderr, "tcp_channel::~tcp_channel\n");
	closesocket(m_file);
	tcp_close(m_peer);
}

int tcp_channel::run(void)
{
	int len = 0;
	int error = 0;
	struct sockaddr_in name;

	if ((m_flags & TF_CONNECT) == 0) {
		name.sin_family = AF_INET;
		name.sin_port   = htons(_forward_port);
		name.sin_addr.s_addr = htonl(_forward_addr);
	   	error = tcp_connect(m_peer, &name, sizeof(name));
		m_flags |= TF_CONNECT;
		if (error == 1) {
			tcp_poll(m_peer, TCP_WRITE, &w_evt_peer);
			m_flags |= TF_CONNECTING;
			return 1;
		}

		if (error != 0) {
			fprintf(stderr, "udp connect error\n");
			return 0;
		}
	}

	if ( evt_completed(&w_evt_peer) ) {
		m_flags &= ~TF_CONNECTING;
	}

	if (m_flags & TF_CONNECTING) {
		return 1;
	}

	if ( evt_completed(&r_event) ) {
		len = recv(m_file, m_rbuf + m_rlen, sizeof(m_rbuf) - m_rlen, 0);
		if (len == -1 || len == 0) {
			m_flags |= TF_EOF1;
			len = 0;
		}
		evt_clear(&r_event);
		m_rlen += len;
	}

	if ( evt_completed(&r_evt_peer) ) {
		len = tcp_read(m_peer, m_wbuf + m_wlen, sizeof(m_wbuf) - m_wlen);
		if (len == -1 || len == 0) {
			m_flags |= TF_EOF0;
			len = 0;
		}
		evt_clear(&r_evt_peer);
		m_wlen += len;
	}

	if (evt_completed(&w_event) && m_woff < m_wlen) {
		len = send(m_file, m_wbuf + m_woff, m_wlen - m_woff, 0);
		if (len == -1)
			return 0;
		evt_clear(&w_event);
		m_woff += len;
	}

	if (evt_completed(&w_evt_peer) && m_roff < m_rlen) {
		len = tcp_write(m_peer, m_rbuf + m_roff, m_rlen - m_roff);
		if (len == -1)
			return 0;
		evt_clear(&w_evt_peer);
		m_roff += len;
	}

	error = 0;

	if (m_roff >= m_rlen) {
		int test_flags = (TF_EOF1 | TF_SHUT1);
		if ((m_flags & test_flags) == TF_EOF1) {
			tcp_shutdown(m_peer);
			m_flags |= TF_SHUT1;
		}
		m_roff = m_rlen = 0;
	}

	if (m_woff >= m_wlen) {
		int test_flags = (TF_EOF0 | TF_SHUT0);
		if ((m_flags & test_flags) == TF_EOF0) {
			shutdown(m_file, SD_BOTH);
			m_flags |= TF_SHUT0;
		}
		m_woff = m_wlen = 0;
	}

	if (m_roff < m_rlen) {
		tcp_poll(m_peer, TCP_WRITE, &w_evt_peer);
		error = 1;
	}

	if (m_woff < m_wlen) {
		reset_event(&w_event, m_file, EV_WRITE);
		error = 1;
	}

	if (m_rlen < sizeof(m_rbuf) &&
			(TF_EOF1 & m_flags) == 0) {
		reset_event(&r_event, m_file, EV_READ);
		error = 1;
	}

	if (m_wlen < sizeof(m_wbuf) && 
			(TF_EOF0 & m_flags) == 0) {
		tcp_poll(m_peer, TCP_READ, &r_evt_peer);
		error = 1;
	}

	return error;
}

void tcp_channel::tc_callback(void * context)
{
	tcp_channel * chan;
	chan = (tcp_channel *)context;

	if (chan->run() == 0) {
		delete chan;
		return;
	}
   
	return;
}

void new_tcp_channel(int fd)
{
	tcp_channel * chan;
   	chan = new tcp_channel(fd);

	if (chan == NULL) {
		closesocket(fd);
		return;
	}

	tcp_channel::tc_callback(chan);
	return;
}

void tcp_channel_forward(u_long addr, u_short port)
{
	_forward_addr = addr;
	_forward_port = port;
	return;
}

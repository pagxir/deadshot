#include <stdio.h>
#include <assert.h>
#include <winsock.h>

#include "event.h"
#include "tcpusr.h"
#include "modules.h"
#include "pstcp_channel.h"

#define TF_CONNECT    1
#define TF_CONNECTING 2
#define TF_EOF0       4
#define TF_EOF1       8
#define TF_SHUT0      16 
#define TF_SHUT1      32

class pstcp_channel {
   	public:
		pstcp_channel(struct tcpcb * tp);
		~pstcp_channel();

	public:
		int run(void);
		static void tc_callback(void * context);

	private:
		int m_flags;
		event_t r_event;
		event_t w_event;
		struct tcpcb * m_peer;

	private:
		int m_woff;
		int m_wlen;
		char m_wbuf[8192];

	private:
		int m_roff;
		int m_rlen;
		char m_rbuf[8192];
};

pstcp_channel::pstcp_channel(struct tcpcb * tp)
	:m_peer(tp), m_flags(0)
{
	m_roff = m_rlen = 0;
	m_woff = m_wlen = 0;
	event_init(&r_event, tc_callback, this);
	event_init(&w_event, tc_callback, this);
}

pstcp_channel::~pstcp_channel()
{
	event_clean(&r_event);
	event_clean(&w_event);

	fprintf(stderr, "pstcp_channel::~pstcp_channel\n");
	tcp_close(m_peer);
}

int pstcp_channel::run(void)
{
	int len = 0;
	int error = -1;

	if (evt_completed(&r_event) && m_wlen < sizeof(m_wbuf))) {
		len = tcp_read(m_peer, m_wbuf + m_wlen, sizeof(m_wbuf) - m_wlen);
		if (len == -1 || len == 0)
			return 0;
		evt_clear(&r_event);
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
		int test_flags = (TF_EOF0 | TF_SHUT0);
		if ((m_flags & test_flags) == TF_EOF0) {
			test_flags |= TF_SHUT0;
			tcp_shutdown(m_peer);
		}
		m_roff = m_rlen = 0;
	}

	if (m_woff >= m_wlen) {
		int test_flags = (TF_EOF1 | TF_SHUT1);
		if ((m_flags & test_flags) == TF_EOF1) {
			shutdown(m_file, SD_BOTH);
			test_flags |= TF_SHUT1;
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
			(m_flags & TF_EOF0) == 0) {
		reset_event(&r_event, m_file, EV_READ);
		error = 1;
	}

	if (m_wlen < sizeof(m_wbuf) &&
			(m_flags & TF_EOF1) == 0) {
		tcp_poll(m_peer, TCP_READ, &r_evt_peer);
		error = 1;
	}

	return error;
}

void pstcp_channel::tc_callback(void * context)
{
	pstcp_channel * chan;
	chan = (pstcp_channel *)context;

	if (chan->run() == 0) {
		delete chan;
		return;
	}
   
	return;
}

void new_pstcp_channel(struct tcpcb * tp)
{
	pstcp_channel * chan;
   	chan = new pstcp_channel(tp);

	if (chan == NULL) {
		tcp_close(tp);
		return;
	}

	pstcp_channel::tc_callback(chan);
	return;
}

void pstcp_channel_forward(u_long addr, u_short port)
{
	_forward_addr = addr;
	_forward_port = port;
	return;
}

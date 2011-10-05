#include <stdio.h>
#include <assert.h>
#include <winsock.h>

#include "tcp.h"
#include "event.h"
#include "tcpusr.h"
#include "modules.h"

static int _file = -1;
static event_t _stop;
static event_t _event;
static event_t _start;
static event_t _dev_idle;
static event_t * _dev_busy = 0;
static int _tcp_dev_busy = 0;
static struct sockaddr_in _addr_in;
static void listen_statecb(void * context);
static void listen_callback(void * context);

int tcp_busying(void)
{
	return _tcp_dev_busy;
}

static void dev_idle_callback(void * uup)
{
	event_t * evt;

	_tcp_dev_busy = 0;
	while (_dev_busy != NULL &&
			_tcp_dev_busy == 0) {
		evt = _dev_busy;
		evt->ev_callback(evt->ev_udata);
	}

	return ;
}

void tcp_devbusy(struct tcpcb * tp)
{
	if ((tp->t_flags & TF_DEVBUSY) == 0) {
		event_insert_header(&_dev_busy, &tp->t_event_devbusy);
		tp->t_flags |= TF_DEVBUSY;
		if (_tcp_dev_busy == 0) {
			reset_event(&_dev_idle, _file, EV_WRITE);
			_tcp_dev_busy = 1;
		}
		return;
	}
}

struct tcpcb * tcp_create(void)
{
	struct tcpcb * tp;
	tp = tcp_newtcpcb(_file);
	assert(tp != NULL);

	tp->t_flags &= ~TF_NOFDREF;
	tcp_attach(tp);

	return tp;
}

static u_short tcp_dev_port = 0;
void tcp_set_dev_port(u_short port)
{
	tcp_dev_port = port;
	return;
}

static void module_init(void)
{
	int error;
	u_long nonblock = 1;

	_addr_in.sin_family = AF_INET;
	_addr_in.sin_port   = htons(tcp_dev_port);
	_addr_in.sin_addr.s_addr = htonl(INADDR_ANY);

	event_init(&_event, listen_callback, NULL);
	event_init(&_stop, listen_statecb, (void *)EV_RUNSTOP);
	event_init(&_start, listen_statecb, (void *)EV_RUNSTART);
	event_init(&_dev_idle, dev_idle_callback, NULL);

	_file = socket(AF_INET, SOCK_DGRAM, 0);
	assert(_file != -1);

	do {
		int rcvbufsiz = 8192;
		setsockopt(stat.xs_file, SOL_SOCKET, SO_RCVBUF, &rcvbufsiz, sizeof(rcvbufsiz));
	} while ( 0 );

	error = bind(_file, (struct sockaddr *)&_addr_in, sizeof(_addr_in));
	assert(error == 0);

	ioctlsocket(_file, FIONBIO, &nonblock);
	reset_event(&_start, -1, EV_RUNSTART);
	reset_event(&_stop, -1, EV_RUNSTOP);
}

static void listen_statecb(void * context)
{
	int state;
	int addr_len;
	struct sockaddr_in addr_in;

	state = (int)context;
	switch (state) {
		case EV_RUNSTART:
			addr_len = sizeof(addr_in);
			getsockname(_file, (struct sockaddr *)&addr_in, &addr_len);
			fprintf(stderr, "bind!address# %s:%u\n",
					inet_ntoa(addr_in.sin_addr), htons(addr_in.sin_port));
			reset_event(&_event, _file, EV_READ);
			break;

		case EV_RUNSTOP:
			drop_event(&_event);
			break;

		default:
			break;
	}

	return;
}

static void listen_callback(void * context)
{
	int len;
	int addr_len;
	char buf[2048];
	struct sockaddr_in addr_in;

	if ( evt_completed(&_event) ) {
		for ( ; ; ) {
			addr_len = sizeof(addr_in);
			len = recvfrom(_file, buf, sizeof(buf),
					0, (struct sockaddr *)&addr_in, &addr_len);
			if (len < 28)
				break;
			tcp_packet(_file, buf, len, &addr_in, addr_len);
		}
		evt_clear(&_event);
	}

	reset_event(&_event, _file, EV_READ);
	return;
}

static void module_clean(void)
{
	fprintf(stderr, "udp_listen: exiting\n");
	event_clean(&_event);
	event_clean(&_start);
	event_clean(&_stop);
	closesocket(_file);
}

modules_t  tcp_device_mod = {
	module_init, module_clean
};


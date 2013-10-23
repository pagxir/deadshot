#include <stdio.h>
#include <assert.h>
#include "platform.h"

#include "event.h"
#include "tcpusr.h"
#include "modules.h"
#include "pstcp_channel.h"

static event_t _event;
static event_t _runstop;
static event_t _runstart;

static void accept_statecb(void * ignore);
static void accept_callback(void * context);

void module_init(void)
{
	event_init(&_event, accept_callback, NULL);
	event_init(&_runstop, accept_statecb, (void *)EV_RUNSTOP);
	event_init(&_runstart, accept_statecb, (void *)EV_RUNSTART);

	reset_event(&_runstop, -1, EV_RUNSTOP);
	reset_event(&_runstart, -1, EV_RUNSTART);
}

void module_clean(void)
{
	event_clean(&_event);
	event_clean(&_runstop);
	event_clean(&_runstart);

	fprintf(stderr, "tcp_listen: exiting\n");
}

static void accept_statecb(void * ignore)
{
	int state;
	int error = -1;

	state = (int)(long)ignore;
	if (state == EV_RUNSTOP) {
		fprintf(stderr, "listen_stop\n");
		drop_event(&_event);
		return;
	}

	if (state == EV_RUNSTART) {
		fprintf(stderr, "listen_start\n");
		tcp_poll(NULL, TCP_ACCEPT, &_event);
	}
}

static void accept_callback(void * context)
{
	struct tcpcb * newtp;
	struct sockaddr_in newaddr;
	size_t newlen = sizeof(newaddr);

	newtp = tcp_accept(&newaddr, &newlen);
	if (newtp != NULL) {
		fprintf(stderr, "new client: %s:%u\n",
				inet_ntoa(newaddr.sin_addr), ntohs(newaddr.sin_port));
		new_pstcp_channel(newtp);
	}

	tcp_poll(NULL, TCP_ACCEPT, &_event);
}

modules_t pstcp_listen_mod = {
	module_init, module_clean
};


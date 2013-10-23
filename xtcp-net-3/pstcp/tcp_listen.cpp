#include <stdio.h>
#include <assert.h>
#include "platform.h"

#include "event.h"
#include "modules.h"
#include "tcp_channel.h"

static int _lenfile = -1;
static struct sockaddr_in _lenaddr;
static event_t _event, _runstart, _runstop;

static void listen_statecb(void * ignore);
static void listen_callback(void * context);

void module_init(void)
{
	int error;

	_lenaddr.sin_family = AF_INET;
	_lenaddr.sin_port   = htons(1080);
	_lenaddr.sin_addr.s_addr = htonl(INADDR_ANY);

	event_init(&_event, listen_callback, NULL);
	event_init(&_runstop, listen_statecb, (void *)EV_RUNSTOP);
	event_init(&_runstart, listen_statecb, (void *)EV_RUNSTART);

	_lenfile = socket(AF_INET, SOCK_STREAM, 0);
	assert(_lenfile != -1);

	error = bind(_lenfile, (struct sockaddr *)&_lenaddr, sizeof(_lenaddr));
	assert(error == 0);

	error = listen(_lenfile, 5);
	assert(error == 0);

	reset_event(&_runstop, -1, EV_RUNSTOP);
	reset_event(&_runstart, -1, EV_RUNSTART);

	fprintf(stderr, "tcp_listen: Hello World\n");
}

void module_clean(void)
{
	closesocket(_lenfile);
	event_clean(&_event);
	event_clean(&_runstop);
	event_clean(&_runstart);

	fprintf(stderr, "tcp_listen: exiting\n");
}

void listen_statecb(void * ignore)
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
		error = reset_event(&_event, _lenfile, EV_READ);
		assert(error == 0);
	}
}

void listen_callback(void * context)
{
	int newfd;
	int error;
	struct sockaddr_in newaddr;
	socklen_t newlen = sizeof(newaddr);

	newfd = accept(_lenfile, (struct sockaddr *)&newaddr, &newlen);
	if (newfd != -1) {
		fprintf(stderr, "new client: %s:%u\n",
				inet_ntoa(newaddr.sin_addr), ntohs(newaddr.sin_port));
		new_tcp_channel(newfd);
	}

	error = reset_event(&_event, _lenfile, EV_READ);
	assert(error == 0);
}

modules_t tcp_listen_mod = {
	module_init, module_clean
};


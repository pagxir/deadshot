#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <math.h>
#include "platform.h"

#include "event.h"
#include "timer.h"
#include "modules.h"
#define EVT_MAGIC 0x19821130

#define EV_EVENT  1
#define EV_LISTED 2
#define EV_QUEUED 4
#define EV_INLINE 8
#define EV_COMPLETE 16

extern int ticks;

static event_t _quick_scan;
static struct timeval _timo = {0, 0};
static event_t * supp_events[4] = {0};

static int _scan_restart = 0;
static event_t * _ready_header = {0};
static event_t ** _ready_tailer = &_ready_header;

void event_init(event_t * evt, void (* callback)(void *), void * udata)
{
	assert(evt != NULL);
	evt->ev_flags = EV_EVENT;
	evt->ev_magic = EVT_MAGIC;
	evt->ev_next = NULL;
	evt->ev_prev = &evt->ev_next;
	evt->ev_udata = udata;
	evt->ev_callback = callback;
}

void event_insert_header(event_t ** header, event_t * evt)
{
	assert((evt->ev_flags & EV_LISTED) == 0);
	assert((evt->ev_flags & EV_QUEUED) == 0);

	evt->ev_flags |= EV_LISTED;
   	evt->ev_next = *header;
	if (evt->ev_next != NULL)
		evt->ev_next->ev_prev = &evt->ev_next;
   	evt->ev_prev = header;
	*header = evt;
}

void event_wakeup(event_t ** ppevt)
{
	event_t * evt;

	while (*ppevt != NULL) {
		evt = * ppevt;
		drop_event(evt);
		event_insert_tailer(evt);
	}

	return;
}

int reset_event(event_t * evt, int file, int type)
{
	int error = -1;

	drop_event(evt);

	switch (type) {
		case EV_READ:
		case EV_WRITE:
			evt->ev_file = file;
			assert(file >= 0);
			error = 0;
			break;

		case EV_RUNSTOP:
		case EV_RUNSTART:
			error = 0;
			break;

		default:
			error = -1;
			break;
	}

	if (error == 0) {
		event_insert_header(&supp_events[type], evt);
		return 0;
	}

	return error;
}

int evt_completed(event_t * evt)
{
	assert(evt != NULL);
	return (evt->ev_flags & EV_COMPLETE);
}

int evt_inactive(event_t * evt)
{
	int test_mask;
   	test_mask = (EV_LISTED | EV_QUEUED);
	return (evt->ev_flags & test_mask) == 0;
}

int evt_clear(event_t * evt)
{
	assert(evt != NULL);
	evt->ev_flags &= ~EV_COMPLETE;
	return 0;
}

int drop_event(event_t * evt)
{
	assert(evt != NULL);
	assert(evt->ev_magic == EVT_MAGIC);
	assert((evt->ev_flags & (EV_LISTED| EV_QUEUED)) != (EV_QUEUED| EV_LISTED));

	if (evt->ev_flags & EV_LISTED) {
		evt->ev_flags &= ~EV_LISTED;
		*evt->ev_prev = evt->ev_next;
		if (evt->ev_next != NULL)
			evt->ev_next->ev_prev = evt->ev_prev;
		evt->ev_prev = &evt->ev_next;
	}

	if (evt->ev_flags & EV_QUEUED) {
		evt->ev_flags &= ~EV_QUEUED;
		*evt->ev_prev = evt->ev_next;
		if (evt->ev_next != NULL)
			evt->ev_next->ev_prev = evt->ev_prev;
		else
			_ready_tailer = evt->ev_prev;
		evt->ev_prev = &evt->ev_next;
	} 

	return 0;
}

void event_clean(event_t * evt)
{
	assert(evt != NULL);
	assert(evt->ev_magic == EVT_MAGIC);

	drop_event(evt);
	evt->ev_magic = 0;
	evt->ev_flags = 0;
	evt->ev_udata  = 0;
	evt->ev_callback = 0;
}

void event_run_start(void)
{
	event_t * event;

	for ( ; ; ) {
		event = supp_events[EV_RUNSTART];
		if (event == NULL)
			break;
		drop_event(event);
		event->ev_callback(event->ev_udata);
	}
}

void event_run_stop(void)
{
	event_t * event;

	for ( ; ; ) {
		event = supp_events[EV_RUNSTOP];
		if (event == NULL)
			break;
		drop_event(event);
		event->ev_callback(event->ev_udata);
	}
}

void event_insert_tailer(event_t * evt)
{
	assert(evt != NULL);
	assert(evt->ev_magic == EVT_MAGIC);
	assert((evt->ev_flags & EV_LISTED) == 0);
	assert((evt->ev_flags & EV_QUEUED) == 0);

	if (evt->ev_flags & EV_EVENT)
	   	_scan_restart = 1;

	evt->ev_next = NULL;
	evt->ev_prev = _ready_tailer;
	evt->ev_flags |= EV_QUEUED;

	*_ready_tailer = evt;
	_ready_tailer = &evt->ev_next;
}

static void do_event_scan(void * context)
{
	int maxfd;
	int count;
	event_t * evt, *ev_next;
	struct timeval * timo;
	fd_set readfds, writefds;
	timo = (struct timeval *)context;

	FD_ZERO(&readfds);
	FD_ZERO(&writefds);

	maxfd = -1;
	for (evt = supp_events[EV_READ];
			evt != NULL; evt = evt->ev_next) {
		FD_SET(evt->ev_file, &readfds);
		maxfd = max(int(evt->ev_file), maxfd);
	}

	for (evt = supp_events[EV_WRITE];
			evt != NULL; evt = evt->ev_next) {
		FD_SET(evt->ev_file, &writefds);
		maxfd = max(int(evt->ev_file), maxfd);
	}

	if (maxfd > -1) {
		count = select(maxfd + 1, &readfds, &writefds, NULL, timo);
	} else {
		fprintf(stderr, "scan error\n");
		count = 0;
	}

	if (count == -1) {
		fprintf(stderr, "selerr: %u, %d\n", WSAGetLastError(), maxfd);
		return;
	}

	if (count == 0) {
	   	callout_invoke();
		return;
	}

	for (evt = supp_events[EV_READ];
			evt != NULL; evt = ev_next) {
		ev_next = evt->ev_next;
		if (FD_ISSET(evt->ev_file, &readfds)) {
			drop_event(evt);
			event_insert_tailer(evt);
		}
	}

	for (evt = supp_events[EV_WRITE];
			evt != NULL; evt = ev_next) {
		ev_next = evt->ev_next;
		if (FD_ISSET(evt->ev_file, &writefds)) {
			drop_event(evt);
			event_insert_tailer(evt);
		}
	}

	callout_invoke();
	return;
}

static void do_quick_scan(void * context)
{
	int maxfd;
	int count;
	int evt_count;
	struct timeval timo = {0, 0};
	event_t * evt, *ev_next;
	fd_set readfds, writefds;
	event_t * rd_scan0, * wr_scan0;
	event_t * rd_scan9, * wr_scan9;

	rd_scan9 = rd_scan0 = supp_events[EV_READ];
	wr_scan9 = wr_scan0 = supp_events[EV_WRITE];

	for ( ; ; ) {
	   	maxfd = -1;
	   	evt_count = 0;
	   	FD_ZERO(&readfds);
	   	for (evt = rd_scan9; evt != NULL; evt = evt->ev_next) {
			if (++evt_count > 60)
				break;
		   	FD_SET(evt->ev_file, &readfds);
		   	maxfd = max(int(evt->ev_file), maxfd);
		}
		rd_scan9 = evt;

		evt_count = 0;
	   	FD_ZERO(&writefds);
	   	for (evt = wr_scan9; evt != NULL; evt = evt->ev_next) {
			if (++evt_count > 60)
				break;
		   	FD_SET(evt->ev_file, &writefds);
		   	maxfd = max(int(evt->ev_file), maxfd);
	   	}
		wr_scan9 = evt;

		if (maxfd == -1) {
			//fprintf(stderr, "scan finish\n");
			break;
		}
	   
		count = select(maxfd + 1, &readfds, &writefds, NULL, &timo);

		if (count == -1) {
		   	fprintf(stderr, "selerr: %u, %d\n", WSAGetLastError(), maxfd);
		   	return;
	   	}

		if (count == 0) {
			wr_scan0 = wr_scan9;
			rd_scan0 = wr_scan9;
			continue;
		}

		for (evt = rd_scan0; evt != rd_scan9; evt = ev_next) {
		   	ev_next = evt->ev_next;
		   	if (FD_ISSET(evt->ev_file, &readfds)) {
			   	drop_event(evt);
			   	event_insert_tailer(evt);
		   	}
	   	}
		rd_scan0 = rd_scan9;

		for (evt = wr_scan0; evt != wr_scan9; evt = ev_next) {
		   	ev_next = evt->ev_next;
		   	if (FD_ISSET(evt->ev_file, &writefds)) {
			   	drop_event(evt);
			   	event_insert_tailer(evt);
		   	}
	   	}
		wr_scan0 = wr_scan9;
	}

	callout_invoke();
	return;
}

int get_event(event_t * evt)
{
	event_t * event;
	event_t marker = {0};
	event_init(&marker, 0, 0);
	marker.ev_flags &= ~EV_EVENT;
	event_insert_tailer(&marker);

	_scan_restart = 0;
	for ( ; ; ) {
		event = _ready_header;
		drop_event(_ready_header);
		if (event == &marker) {
			while (_scan_restart == 0) {
				struct timeval timo = {0, 20000};
				do_event_scan(&timo);
			}
			event_insert_tailer(&marker);
			_scan_restart = 0;
			continue;
		}

		if (event->ev_flags & EV_INLINE) {
			event->ev_callback(event->ev_udata);
			event_insert_tailer(event);
			continue;
		}

		event->ev_flags |= EV_COMPLETE;
		evt[0] = *event;
		break;
	}

	drop_event(&marker);
	return 1;
}

int ticks;
int fire_event(event_t * evt)
{
	ticks = GetTickCount();

	if (evt->ev_flags & EV_COMPLETE) {
		evt->ev_flags &= ~EV_COMPLETE;
		evt->ev_callback(evt->ev_udata);
		return 1;
	}

	return 0;
}

static void module_init(void)
{
	fprintf(stderr, "event_queue_mod init\n");
	event_init(&_quick_scan, do_quick_scan, &_timo);
	_quick_scan.ev_flags |= EV_INLINE;
	_quick_scan.ev_flags &= ~EV_EVENT;
	event_insert_tailer(&_quick_scan);
}

static void module_clean(void)
{
	fprintf(stderr, "event_queue_mod clean\n");
	drop_event(&_quick_scan);
}

modules_t event_queue_mod = {
	module_init, module_clean
};


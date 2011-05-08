#include <stdio.h>
#include <assert.h>
#include <windows.h>

#include "event.h"
#include "timer.h"
#include "modules.h"

static size_t _still_tick;
static event_t * _still_timers;

static size_t _micro_tick;
static size_t _micro_wheel;
static event_t * _micro_timers[50];

static size_t _macro_tick;
static size_t _macro_wheel;
static event_t * _macro_timers[60];

void callout_reset(event_t * evt, size_t millisec)
{
	size_t wheel;
	size_t micro_wheel, macro_wheel;

	drop_event(evt);
	evt->ev_file = (millisec + GetTickCount());
   	micro_wheel = (evt->ev_file - _micro_tick) / 20;
   	macro_wheel = (evt->ev_file - _macro_tick) / 1000;

	if (micro_wheel == 0) {
		fprintf(stderr, "warn: too small timer not supported!\n");
		micro_wheel = 1;
	}

	if (micro_wheel < 50) {
		wheel = (_micro_wheel + micro_wheel) % 50;
		event_insert_header(&_micro_timers[wheel], evt);
		return;
	}

	if (macro_wheel < 60) {
		wheel = (_macro_wheel + macro_wheel) % 60;
		event_insert_header(&_macro_timers[wheel], evt);
		return;
	}

	event_insert_header(&_still_timers, evt);
	return;
}

void callout_invoke(void)
{
	size_t tick;
	size_t wheel;
	event_t * event, * evt_next;

	tick = GetTickCount();

	for ( ; ; ) {
		if (int(tick - _micro_tick - 20) < 0)
			break;
		_micro_tick += 20;
		_micro_wheel++;
		wheel = (_micro_wheel % 50);
		while (_micro_timers[wheel] != NULL) {
			event = _micro_timers[wheel];
			drop_event(event);
		   	event_insert_tailer(event);
		}
	}

	for ( ; ; ) {
		if (int(tick - _macro_tick - 1000) < 0)
			break;
		_macro_tick += 1000;
		_macro_wheel++;
		wheel = (_macro_wheel % 60);
		while (_macro_timers[wheel] != NULL) {
			event = _macro_timers[wheel];
			if (int(event->ev_file - tick) < 20) {
			   	drop_event(event);
			   	event_insert_tailer(event);
			} else {
				drop_event(event);
				callout_reset(event, event->ev_file - tick);
			}
		}
	}

	event = _still_timers;
	while (event != NULL) {
		evt_next = event->ev_next;
		if (int(event->ev_file - tick) < 60000) {
			if (int(event->ev_file - tick) < 20) {
				drop_event(event);
				event_insert_tailer(event);
			} else {
				drop_event(event);
				callout_reset(event, event->ev_file - tick);
			}
		}
		event = evt_next;
	}
	
	return;
}

static void module_init(void)
{
	size_t tick;
	tick = GetTickCount();
	_still_tick = tick;

	_micro_tick = tick;
	_micro_wheel = 0;

	_macro_tick = tick;
	_macro_wheel = 0;
}

static void module_clean(void)
{

}

modules_t timer_event_mod = {
	module_init, module_clean
};


#ifndef _EVENT_H_
#define _EVENT_H_

#define EV_READ     0
#define EV_WRITE    1
#define EV_RUNSTOP  2
#define EV_RUNSTART 3

typedef struct _event_s {
	unsigned int ev_magic;
	unsigned int ev_flags;
	struct _event_s * ev_next;
	struct _event_s ** ev_prev;

	size_t ev_file;
	void * ev_udata;
	void (*ev_callback)(void * data);
} event_t;

void event_init(event_t * evt, void (* cb)(void *), void * data);
void event_clean(event_t * evt);

int  reset_event(event_t * evt, int fd, int type);
int  drop_event(event_t * evt);

void event_run_start(void);
void event_run_stop(void);

int get_event(event_t * evt);
int fire_event(event_t * evt);

int evt_completed(event_t * evt);
int evt_inactive(event_t * evt);
int evt_clear(event_t * evt);

void event_insert_header(event_t ** header, event_t * evt);
void event_insert_tailer(event_t * evt);
void event_wakeup(event_t ** ppevt);

#endif


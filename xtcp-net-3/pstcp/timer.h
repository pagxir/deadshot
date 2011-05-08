#ifndef _TIMER_H_
#define _TIMER_H_
void callout_invoke(void);
void callout_reset(event_t * evt, size_t millisec);
#endif


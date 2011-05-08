#ifndef _TCP_NAT_
#define _TCP_NAT_

struct sockaddr_in;
typedef struct _s_event_t event_t;
int tcp_setnat(const char * name, event_t * event);
int tcp_lookup(const char * name, struct sockaddr_in * soname);

#endif


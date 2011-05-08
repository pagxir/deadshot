#include "tcp_nat.h"

void update_peer(const char * name)
{
	if (!active(name)) 
		start();
	return;
}

void update_sock(void)
{
	if (active)
		return;
	start();
}

int tcp_setnat(const char * name, event_t * event)
{
	update_peer(name);
	update_sock();
	return 0;
}

int tcp_lookup(const char * name, struct sockaddr_in * soname)
{
	return 0;
}

int tcp_active(struct tcpcb * tp)
{
	struct sockaddr_in inaddr;

	if (rexmt && tp->idle_time > 30) {
		if (tcp_lookup(name, &inaddr) == -1 ||
				inaddr == tp->cur_addr) {
			tcp_setnat(name, &tp->routed);
			return 0;
		}
	}
	return 0;
}


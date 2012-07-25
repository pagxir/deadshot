#include <stdio.h>
#include <stdlib.h>
#include "platform.h"

#include "event.h"
#include "modules.h"
#include "tcp_channel.h"

extern modules_t tcp_timer_mod;
extern modules_t tcp_device_mod;
extern modules_t event_queue_mod;
extern modules_t timer_event_mod;
extern modules_t tcp_listen_mod;
modules_t * modules_list[] = {
	&event_queue_mod, &tcp_timer_mod, &tcp_device_mod,
   	&timer_event_mod, &tcp_listen_mod, NULL
};

int main(int argc, char * argv[])
{
	event_t event;
	u_long f4ward_addr;
	u_short f4ward_port;

#ifdef _WIN32_
	WSADATA data;
	WSAStartup(0x101, &data);
#endif
	initialize_modules(modules_list);
	if (argc == 3) {
	   	f4ward_addr = inet_addr(argv[1]);
		f4ward_port = atoi(argv[2]);
		tcp_channel_forward(ntohl(f4ward_addr), f4ward_port);
	}

	event_run_start();
	while ( get_event(&event) )
		fire_event(&event);
	event_run_stop();

	cleanup_modules(modules_list);
#ifdef _WIN32_
	WSACleanup();
#endif
	return 0;
}


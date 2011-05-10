#include <stdio.h>
#include <winsock.h>

#include "event.h"
#include "modules.h"
#include "tcp_device.h"
#include "pstcp_channel.h"

extern modules_t tcp_timer_mod;
extern modules_t tcp_device_mod;
extern modules_t event_queue_mod;
extern modules_t timer_event_mod;
extern modules_t pstcp_listen_mod;

modules_t * modules_list[] = {
	&event_queue_mod, &tcp_timer_mod, &tcp_device_mod,
   	&timer_event_mod, &pstcp_listen_mod,  NULL
};

int main(int argc, char * argv[])
{
	WSADATA data;
	event_t event;
	u_long f4ward_addr;
	u_short f4ward_port;

	WSAStartup(0x101, &data);

	if (argc == 3) {
	   	f4ward_addr = inet_addr(argv[1]);
		f4ward_port = atoi(argv[2]);
		pstcp_channel_forward(ntohl(f4ward_addr), f4ward_port);
	}
	tcp_set_dev_port(1080);
	initialize_modules(modules_list);

	event_run_start();
	while ( get_event(&event) )
		fire_event(&event);
	event_run_stop();

	cleanup_modules(modules_list);
	WSACleanup();
	return 0;
}

#include <stdio.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#ifdef WIN32
#include <winsock.h>
typedef int socklen_t;
typedef unsigned long in_addr_t;
typedef unsigned short in_port_t;
#define MSG_DONTWAIT 0
#else
#include <time.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include "dhcp-protocol.h"

static struct dhcp_packet dhcp_pkt;
#if 0
struct dhcp_packet {
  u8 op, htype, hlen, hops;
  u32 xid;
  u16 secs, flags;
  struct in_addr ciaddr, yiaddr, siaddr, giaddr;
  u8 chaddr[DHCP_CHADDR_MAX], sname[64], file[128];
  u8 options[312];
};
#endif

int main(int argc, char *argv[])
{
    int fildes, error;
    struct sockaddr_in mime, target;

    fildes = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fildes != -1);

    mime.sin_family = AF_INET;
    mime.sin_port   = htons(68);
    mime.sin_addr.s_addr = inet_addr("172.31.1.30");
    error = bind(fildes, (struct sockaddr *)&mime, sizeof(mime));

    fprintf(stderr, "error=%d\n", error);



    target.sin_family = AF_INET;
    target.sin_port   = htons(67);
    target.sin_addr.s_addr = inet_addr("255.255.255.255");

    dhcp_pkt.op = BOOTREQUEST;
    dhcp_pkt.htype = 1;
    dhcp_pkt.hlen = 6;
    dhcp_pkt.hops = 0;

    dhcp_pkt.secs = 0;
    dhcp_pkt.flags = 0;
#if 0
  struct in_addr ciaddr, yiaddr, siaddr, giaddr;
  u8 chaddr[DHCP_CHADDR_MAX], sname[64], file[128];
#endif
    char hwaddr[] = {0xe0, 0xbe, 0x03, 0x2d, 0x01, 0xbe};
    memmove(dhcp_pkt.chaddr, hwaddr, 6);

    char magic[] = {0x63, 0x82, 0x53, 0x63};
    memmove(dhcp_pkt.cookie, magic, 4);
    dhcp_pkt.options[0] = 0xff;
    size_t len = (size_t)((char *)(dhcp_pkt.options + 1) - (char*)&dhcp_pkt);

    int broadcastPermission = 1;
    if (setsockopt(fildes, SOL_SOCKET, SO_BROADCAST, (void *) &broadcastPermission,sizeof(broadcastPermission)) < 0){
	    fprintf(stderr, "setsockopt error");
	    exit(1);
    }

#define add_options(p, tag, val, len) do { \
	*p++ = tag;                        \
	*p++ = len;                        \
	memmove(p, val, len);              \
	p += len;                          \
} while (0)

#define add_options_u8(p, tag, val) do { \
	*p++ = tag;                      \
	*p++ = 1;                        \
	*p++ = val;                      \
} while (0)

#define add_options_u16(p, tag, val) do { \
	*p++ = tag;                       \
	*p++ = 2;                        \
	*p++ = (val >> 8);                \
	*p++ = (val & 0xff);              \
} while (0)

    char * optp = dhcp_pkt.options;
    add_options_u8(optp, OPTION_MESSAGE_TYPE, 1);
    add_options_u16(optp, OPTION_MAXMESSAGE, 1152);

    char client_ident[] = {0x01, 0xe0, 0xbe, 0x03, 0x2d, 0x01, 0xbe};
    add_options(optp, OPTION_CLIENT_ID, client_ident, sizeof(client_ident));

    char client_name[] = "funtoo";
    add_options(optp, OPTION_HOSTNAME, client_name, sizeof(client_name));

    char request_param[] = {1, 6, 15, 44, 3, 33, 150, 43};
    add_options(optp, OPTION_REQUESTED_OPTIONS, request_param, sizeof(request_param));

    *optp++ = 0xff;

    len = sizeof(dhcp_pkt);
    fprintf(stderr, "len = %d\n", len);
    error = sendto(fildes, &dhcp_pkt, len, 0, (struct sockaddr *)&target, sizeof(target));
    perror("sendto");
    fprintf(stderr, "send error = %d:%d\n", error, errno);

    socklen_t target_len = sizeof(target);
    error = recvfrom(fildes, &dhcp_pkt, sizeof(dhcp_pkt), 0, (struct sockaddr *)&target, &target_len);

    fprintf(stderr, "error=%d\n", error);

    return 0;
}



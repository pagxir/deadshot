#ifndef _DTYPE_H_
#define _DTYPE_H_

typedef unsigned int u_int;
typedef unsigned int tcp_seq;
typedef unsigned char u_char;
typedef unsigned long u_long;
typedef unsigned short u_short;

#if 0
u_long htonl(u_long l_host);
u_long ntohl(u_long l_host);
u_short htons(u_short s_host);
u_short ntohs(u_short s_host);
#endif

static u_int umin(u_int a, u_int b) { return a < b? a: b; }
static u_int umax(u_int a, u_int b) { return a < b? b: a; }
#endif


#ifndef _TCP_CHANNEL_H_
#define _TCP_CHANNEL_H_
struct tcpcb;
void new_pstcp_channel(struct tcpcb * tp);
void pstcp_channel_forward(u_long addr, u_short port);
#endif


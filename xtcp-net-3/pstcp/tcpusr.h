#ifndef _TCPUSR_H_
#define _TCPUSR_H_

#define TCP_READ   0
#define TCP_WRITE  1
#define TCP_ACCEPT 2

struct tcpcb;
struct tcpcb * tcp_create(void);
struct tcpcb * tcp_accept(struct sockaddr_in * name, size_t * namlen);

int tcp_shutdown(struct tcpcb * tp);
int tcp_error(struct tcpcb * tp);
int tcp_close(struct tcpcb * tp);

/* symmetry open */
int tcp_listen(struct tcpcb * tp, u_long addr, u_short port);
int tcp_soname(struct tcpcb * tp, u_long * addr, u_short * port);

/* traditional socket function */
int tcp_connect(struct tcpcb * tp, const struct sockaddr_in * name, size_t namlen);
int tcp_write(struct tcpcb * tp, const void * buf, size_t len);
int tcp_read(struct tcpcb * tp, void * buf, size_t len);
int tcp_poll(struct tcpcb * tp, int typ, event_t * evt);

#endif


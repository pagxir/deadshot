#ifndef _XREQ_H
#define _XREQ_H

typedef int socklen_t;

int xreq_init(u_short port);
int xreq_clean(void);

int xopen(void);
int xaccept(int fd, struct sockaddr_in * addr, socklen_t * addrlen);
int xbind(int fd, const struct sockaddr_in * name, socklen_t namelen);
int xconnect(int fd, const struct sockaddr_in * name, socklen_t namelen);
ssize_t xread(int fd, void * buf, size_t len);
ssize_t xwrite(int fd, const void * buf, size_t len);
int xclose(int fd);

#endif


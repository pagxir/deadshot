#include <stdio.h>
#include <string.h>
#include <unistd.h>
#if defined(__POSIX__)
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "dllwrap.h"

static int ioctlsocket(int fd)
{
    return 0;
}

typedef struct __sockaddr_in
{
    short          sin_family;
    u_short        sin_port;
    struct in_addr sin_addr;
    char           sin_zero[8];
}_xx_sockaddr_in;

typedef struct __hostent
{
    char* h_name;
    char** h_aliases;
    short h_addrtype;
    short h_length;
    char** h_addr_list;
#define h_addr h_addr_list[0]
}_xx_hostent;

static void *exp_gethostbyname(const char *name)
{
    hostent* retval = 0;
    static _xx_hostent __static_hostent[10];
    retval = gethostbyname(name);
    if (retval != NULL) {
        __static_hostent[0].h_addr_list
            = (char**)&__static_hostent[1];
        __static_hostent[0].h_addr_list[0]
            = (char*)&__static_hostent[2];
        memcpy(&__static_hostent[2], retval->h_addr, 4);
        return &__static_hostent[0];
    }
    return NULL;
}

static int exp_recvfrom(int fd, void *buf, size_t n,
        size_t fl, sockaddr *nm, socklen_t*ptr)
{
    int retval = 0;
    sockaddr_in unix_in;
    _xx_sockaddr_in *pwin32_in = (_xx_sockaddr_in*)nm;
    retval = recvfrom(fd, buf, n, fl, nm, ptr);
    pwin32_in->sin_port = unix_in.sin_port;
    pwin32_in->sin_addr = unix_in.sin_addr;
    pwin32_in->sin_family = unix_in.sin_family ;
    return retval;
}

static int exp_sendto(int fd, void *buf, size_t n,
        size_t fl, sockaddr *nm, socklen_t len)
{
    int retval = 0;
    sockaddr_in unix_in;
    _xx_sockaddr_in *pwin32_in = (_xx_sockaddr_in*)nm;
    unix_in.sin_port = pwin32_in->sin_port;
    unix_in.sin_addr = pwin32_in->sin_addr;
    unix_in.sin_family = pwin32_in->sin_family;
    retval = sendto(fd, buf, n, fl, (sockaddr*)&unix_in, len);
    return retval;
}

int WSAStartup(void *a, void *b)
{
    return 0;
}

int WSACleanup()
{
    return 0;
}

#define MATCH2(fNAME, proxy) \
    if (!strcmp(fNAME, name)){ *pfunc=(void*)proxy; return 0; }
#endif

int wsock32_GetProcAddress(const char *name, void **pfunc)
{
#if defined(__POSIX__)
    MATCH2("closesocket", close);

#define XF(Name) MATCH2(#Name, exp_##Name)
    XF(gethostbyname);
    XF(recvfrom);
    XF(sendto);
#undef XF

#define XF(Name) MATCH2(#Name, Name)
    XF(htonl);
    XF(ntohl);
    XF(htons);
    XF(ntohs);
    XF(inet_ntoa);
    XF(setsockopt);
    XF(socket);
    XF(send);
    XF(recv);
    XF(WSAStartup);
    XF(WSACleanup);
#undef XF

#if 0
    XF(accept);
    XF(bind);
    XF(connect);
    XF(inet_addr);
    XF(listen);
    XF(select);
    XF(ioctlsocket);
#endif
#endif

    return -1;
}

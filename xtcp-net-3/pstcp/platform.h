#ifndef _PLATFORM_H_
#define _PLATFORM_H_

#undef assert

#ifdef _WIN32_
#include <winsock.h>
//#define WSAEINPROGRESS WSAEWOULDBLOCK
#define assert(exp) do { if (exp); else {printf("%s:%d", __FILE__, __LINE__); Sleep(INFINITE); }; } while ( 0 );
#define max(a, b) (((a) < (b))? (b): (a))
#define min(a, b) (((a) < (b))? (a): (b))

#define socklen_t int
#else
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define assert(exp) do { if (exp); else {printf("%s:%d", __FILE__, __LINE__);  }; } while ( 0 );
#define closesocket(s) close(s)

#define WSAGetLastError() errno
#define WSAEWOULDBLOCK EAGAIN
#define SD_BOTH	SHUT_RDWR
#define max(a, b) ((a) < (b)? (b): (a))
#define min(a, b) ((a) < (b)? (a): (b))
#define WSAEINPROGRESS EINPROGRESS
#define WSAEINVAL EINVAL
#define stricmp strcmp
unsigned int GetTickCount(void);
#endif

void setnonblock(int fd);

#endif


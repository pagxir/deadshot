#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32_
#include <winsock.h>
typedef int socklen_t;
typedef unsigned long in_addr_t;
typedef unsigned short in_port_t;
#else
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#define getmappedbybuf(buff, buflen, addrptr, portptr) \
	getaddrbybuf(buff, buflen, MAPPED_ADDRESS, addrptr, portptr)

#define getchangedbybuf(buff, buflen, addrptr, portptr) \
	getaddrbybuf(buff, buflen, CHANGED_ADDRESS, addrptr, portptr)

/*
 * stun.l.google.com:19302
 * stun.ekiga.net:3478
 */

enum {
	BindingRequest = 0x0001,
	BindingResponse = 0x0101,
	BindingErrorResponse = 0x0111,
	MAPPED_ADDRESS = 0x0001,
	CHANGE_REQUEST = 0x0003,
	CHANGED_ADDRESS = 0x0005
};

int getaddrbybuf(void *buff, size_t buflen, int type,
		in_addr_t *addrptr, in_port_t *portptr)
{
	int error = -1;
	size_t ix, nx, cut;
	unsigned short hdr[2];
	unsigned char *bp = (unsigned char *)buff;

	for (ix=20,nx=24; nx<=buflen; ix=nx, nx+=4){
		memcpy(hdr, bp+ix, sizeof(hdr));
		cut = ntohs(hdr[1]);
		ix  = nx;
		nx += cut;
		if (htons(hdr[0])!=type)
			continue;
		if (nx > buflen)
			continue;
		if (cut==8 && bp[ix+1]==1){
			memcpy(portptr, bp+ix+2, 2);
			memcpy(addrptr, bp+ix+4, 4);
			error = 0;
		}
		break;
	}
	return error;

}

struct mapping_args{
	unsigned short binding_request, zero_field;
	unsigned int  tid0, tid1, tid2, tid3;
};

struct changing_args{
	unsigned short binding_request, zero_field;
	unsigned int  tid0, tid1, tid2, tid3;
	unsigned short change_request, len_field;
	unsigned char data[4];
};

static int _stid3 = 0;
static struct sockaddr_in  _schgaddr, _sinaddr;

int stun_changing(int fd, void *buff, size_t bufsize, 
		struct sockaddr *name, socklen_t namelen)
{
	int count;
	struct changing_args req;
	struct sockaddr  rcvaddr;
	socklen_t rcvaddrlen = sizeof(rcvaddr);

	req.binding_request = htons(BindingResponse);
	req.zero_field = htons(8);
	req.tid0 = htonl(0x55555555);
	req.tid1 = htonl(0x5a5a5a5a);
	req.tid2 = htonl(0xaaaaaaaa);
	req.tid3 = htonl(_stid3++);

	req.change_request = htons(CHANGE_REQUEST);
	req.len_field = htons(4);
	req.data[0] = 0;
	req.data[1] = 0;
	req.data[2] = 0;
#ifdef _TEST_SAME_IP
	req.data[3] = 4;
#else
	req.data[3] = 6;
#endif

	if (-1==sendto(fd, (const char*)&req, 
				sizeof(req), 0, name,namelen))
		return -1;

	count=recvfrom(fd, (char*)buff, bufsize,
			0, &rcvaddr, &rcvaddrlen);

#if 0
	if ((count==-1)||(rcvaddrlen!=namelen)
			||memcmp(&rcvaddr, name,namelen))
		return -1;

	struct changing_args *bpreq= (struct changing_args*)buff;
	printf("changing: %x\n", htons(bpreq->binding_request));
	printf("zero: %x\n", htons(bpreq->zero_field));
	printf("tid0: %x\n", htonl(bpreq->tid0));
	printf("tid1: %x\n", htonl(bpreq->tid1));
	printf("tid2: %x\n", htonl(bpreq->tid2));
	printf("tid3: %x\n", htonl(bpreq->tid3));
#endif
	return count;

}

int stun_maping(int fd, void *buff, size_t bufsize,
		struct sockaddr* name, socklen_t namelen)
{
	int retry=3;
	int count;
	struct mapping_args req;
	struct sockaddr  rcvaddr;
	socklen_t rcvaddrlen = sizeof(rcvaddr);

	req.binding_request = htons(0x0001);
	req.zero_field      = htons(0);
	req.tid0 = htonl(0x55555555);
	req.tid1 = htonl(0x5a5a5a5a);
	req.tid2 = htonl(0xaaaaaaaa);
	req.tid3 = htonl(_stid3++);

lretry:
	if (-1==sendto(fd, (const char*)&req, 
				sizeof(req), 0, name, namelen))
		return -1;

	count=recvfrom(fd, (char*)buff, bufsize,
			0, &rcvaddr, &rcvaddrlen);

	if ((count==-1)&&retry--)
		goto lretry;

#if 0
	if ((count==-1)||(rcvaddrlen!=namelen)
			||memcmp(&rcvaddr, name, namelen))
		return -1;
	struct mapping_args *bpreq= (struct mapping_args*)buff;
	printf("binding: %x\n", htons(bpreq->binding_request));
	printf("zero: %x\n", htons(bpreq->zero_field));
	printf("tid0: %x\n", htonl(bpreq->tid0));
	printf("tid1: %x\n", htonl(bpreq->tid1));
	printf("tid2: %x\n", htonl(bpreq->tid2));
	printf("tid3: %x\n", htonl(bpreq->tid3));
#endif
	return count;

}

int main(int argc, char *argv[])
{
	char buf[1024];
	int fd, count;
	char *port, *hostname;
	struct hostent *phost;
	struct timeval tval;

#ifdef _WIN32_
	WSADATA data;
	WSAStartup(0x101, &data);
#endif
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		return -2;

	struct sockaddr_in myaddr;
	myaddr.sin_family = AF_INET;
	myaddr.sin_port   = htons(9000);
	myaddr.sin_addr.s_addr = 0;
	if (-1 == bind(fd, (struct sockaddr *)&myaddr, sizeof(myaddr)))
		return -1;

	myaddr.sin_addr.s_addr = inet_addr(argv[1]);
	sendto(fd, "hello", 5, 0, (struct sockaddr *)&myaddr, sizeof(myaddr));

	tval.tv_sec = 12;
	tval.tv_usec = 0;
	if (-1==setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
				(const char*)&tval, sizeof(tval)))
		return -3;

	for (int i=1; i<argc; i++){

		strcpy(buf, argv[i]);
		hostname = buf;

		printf("gethostname: %s\n", hostname);
		if (port=strchr(buf, ':'))
			*port++ = 0;

		printf("-----load: %s\n", hostname);
		if ((phost=gethostbyname(hostname))==NULL)
			continue;

		_sinaddr.sin_family = AF_INET;
		_sinaddr.sin_port   = htons(port?atoi(port):3478);
		printf("load: %s\n", hostname);
		_sinaddr.sin_addr.s_addr = *(in_addr_t*)phost->h_addr;


		count = stun_maping(fd, buf, sizeof(buf),
				(struct sockaddr*)&_sinaddr, sizeof(_sinaddr));
		printf("stun_maping: %s:%d\n", hostname, count);
		if (count == -1)
			continue;

		if (-1==getmappedbybuf(buf, count,
					(in_addr_t*)&_schgaddr.sin_addr, &_schgaddr.sin_port))
			continue;

		printf("mapping mapped address: %s:%d\n",
				inet_ntoa(_schgaddr.sin_addr), htons(_schgaddr.sin_port));

		if (-1==getchangedbybuf(buf, count,
					(in_addr_t*)&_schgaddr.sin_addr, &_schgaddr.sin_port))
			continue;

		printf("mapping changed server address: %s:%d\n",
				inet_ntoa(_schgaddr.sin_addr), htons(_schgaddr.sin_port));

		_schgaddr.sin_family = AF_INET;
#if 1
		count = stun_changing(fd, buf, sizeof(buf), (struct sockaddr*)
				&_schgaddr, sizeof(_schgaddr));
		if (count > 0){
			printf("stun_changing: %d\n", count);
		}
#endif
		count = stun_maping(fd, buf, sizeof(buf), (struct sockaddr*)
				&_schgaddr, sizeof(_schgaddr));

		if (-1==getmappedbybuf(buf, count,
					(in_addr_t*)&_schgaddr.sin_addr, &_schgaddr.sin_port))
			continue;

		printf("mapping mapped address: %s:%d\n",
				inet_ntoa(_schgaddr.sin_addr), htons(_schgaddr.sin_port));

		if (-1==getchangedbybuf(buf, count,
					(in_addr_t*)&_schgaddr.sin_addr, &_schgaddr.sin_port))
			continue;

		printf("changing changed server address: %s:%d\n",
				inet_ntoa(_schgaddr.sin_addr), htons(_schgaddr.sin_port));

	}
#ifdef _WIN32_
	closesocket(fd);
	WSACleanup();
#else
	close(fd);
#endif
	return 0; 
}

#ifdef _WIN32_
void __declspec(dllexport) _()
{
}
#endif

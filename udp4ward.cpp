// udp4ward.cpp : Defines the entry point for the console application.
//

#ifndef WIN32
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#define S_CLOSE close
#define S_READ read
#define S_WRITE write
#else
#include <time.h>
#include <winsock2.h>
#define socklen_t int
#define S_CLOSE(s) closesocket(s)
#define S_READ(fd, buf, len) recv(fd, buf, len, 0)
#define S_WRITE(fd, buf, len) send(fd, buf, len, 0)
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <set>

#define UDPF_KEEP 0x00000001

struct udpiocb {
	int flags;
	int udpio_fd;
	int cc_file;
	int cc_count;
	char cc_packet[2048];
	time_t last_active;
	struct sockaddr_in udpio_addr;
};

bool operator < (const struct udpiocb & a, const struct udpiocb & b)
{
	struct sockaddr_in addr_a, addr_b;
	addr_a = a.udpio_addr;
	addr_b = b.udpio_addr;
	if (addr_a.sin_port == addr_b.sin_port)
		return (addr_a.sin_addr.s_addr < addr_b.sin_addr.s_addr);
	return (addr_a.sin_port < addr_b.sin_port);
}

static std::set<udpiocb> udpio_list;

int udpio_add(u_long addr, u_short d_port, u_short s_port)
{
	int error;
	struct udpiocb iocb;
	struct sockaddr_in addr_in1;
	int s_udp = socket(PF_INET, SOCK_DGRAM, 0);
	assert(s_udp != -1);
	addr_in1.sin_family = AF_INET;
	addr_in1.sin_port = htons(s_port);
	addr_in1.sin_addr.s_addr = htonl(INADDR_ANY);
	error = bind(s_udp, (struct sockaddr *)&addr_in1, sizeof(addr_in1));
	assert(error == 0);
	u_long mode = 1;
	ioctlsocket(s_udp, FIONBIO, &mode);
	iocb.flags = UDPF_KEEP;
	iocb.udpio_fd = s_udp;
	iocb.cc_file = -1;
	iocb.cc_count = 0;
	iocb.udpio_addr.sin_family = AF_INET;
	iocb.udpio_addr.sin_port = htons(d_port);
	iocb.udpio_addr.sin_addr.s_addr = addr;
	udpio_list.insert(iocb);
	printf("local port %d forward to %s:%d\n",
			s_port, inet_ntoa(iocb.udpio_addr.sin_addr),d_port);
	return 0;
}

int udpio_final(void)
{
	std::set<udpiocb>::const_iterator iter;
	iter = udpio_list.begin();
	while (iter != udpio_list.end()) {
		S_CLOSE(iter->udpio_fd);
		++iter;
	}
	return 0;
}

int udpio_realloc(const struct sockaddr_in & addr)
{
	u_long mode = 1;
	struct udpiocb iocb;
	iocb.flags = 0;
	iocb.udpio_addr = addr;
	std::set<udpiocb>::iterator iter;
	iter = udpio_list.find(iocb);
	if (iter != udpio_list.end()) {
		time((time_t*)&iter->last_active);
		return iter->udpio_fd;
	}
	iocb.udpio_fd = socket(AF_INET, SOCK_DGRAM, 0);
	ioctlsocket(iocb.udpio_fd, FIONBIO, &mode);
	time(&iocb.last_active);
	iocb.cc_file = -1;
	iocb.cc_count = 0;
	udpio_list.insert(iocb);
	return iocb.udpio_fd;
}

int udpio_event(fd_set * readfds, fd_set * writefds, fd_set * errorfds)
{
	int error;
	int fd, len;
	char buf[4096];
	int addr_len1;
	struct sockaddr_in addr_in1;
	std::set<udpiocb>::iterator iter;
	iter = udpio_list.begin();
	while (iter != udpio_list.end()) {
		int read_continue = 0;

		if (iter->cc_count > 0) {
			if (FD_ISSET(iter->cc_file, writefds)) {
			   	error = sendto(iter->cc_file, iter->cc_packet, iter->cc_count,
					   	0, (struct sockaddr *)&(iter->udpio_addr), sizeof(iter->udpio_addr));
				if (error == -1) {
					break;
				}

				*(int*)&iter->cc_count = 0;
				*(int*)&iter->cc_file = -1;
				read_continue = 1;
			}
		} 
		
		if (read_continue == 1 ||
				(iter->cc_count == 0 && FD_ISSET(iter->udpio_fd, readfds))) {
		   	for ( ; ; ) {
			   	addr_len1 = sizeof(addr_in1);
			   	len = recvfrom(iter->udpio_fd, buf, sizeof(buf), 0,
					   	(struct sockaddr *)&addr_in1, &addr_len1);
			   	if (len == -1) {
				   	break;
			   	}
			   
				fd = udpio_realloc(addr_in1);
			   	error = sendto(fd, buf, len, 0, 
						(struct sockaddr *)&(iter->udpio_addr), sizeof(iter->udpio_addr));
			   	if (error == -1) {
				   	memcpy((char *)iter->cc_packet, buf, len);
				   	*(int*)&iter->cc_count = len;
				   	*(int*)&iter->cc_file = fd;
				   	break;
			   	}
		   	}
		}

		++iter;
	}
	return 0;
}

int udpio_collect(time_t current)
{
	int count = udpio_list.size();
	std::set<udpiocb>::iterator iter;
	iter = udpio_list.begin();
	while (iter != udpio_list.end()) {
		if (iter->last_active + 60 < current &&
				(iter->flags & UDPF_KEEP) == 0) {
			closesocket(iter->udpio_fd);
			udpio_list.erase(iter++);
			continue;
		}
		++iter;
	}
	if (udpio_list.size() != count)
		printf("udpio collect: %d %d\n", udpio_list.size(), count);
	assert (udpio_list.size() <= count);
	return count - udpio_list.size();
}

int udpio_fd_set(fd_set * readfds, fd_set * writefds, fd_set * errorfds)
{
	int fd_max = 0;
	std::set<udpiocb>::const_iterator iter;

	iter = udpio_list.begin();
	while (iter != udpio_list.end()) {
		if (iter->cc_count == 0) {
			FD_SET(iter->udpio_fd, readfds);
			fd_max = (fd_max < iter->udpio_fd? iter->udpio_fd: fd_max);
		} else {
			FD_SET(iter->cc_file, writefds);
			fd_max = (fd_max < iter->cc_file? iter->cc_file: fd_max);
		}
		++iter;
	}

	return fd_max;
}

int udp_switch(void)
{
	int count;
	struct fd_set readfds, writefds, errorfds;

	time_t t_last, t_current;
	size_t c_active = udpio_list.size();

	time(&t_last);
	for ( ; ; ) {
		FD_ZERO(&readfds);
		FD_ZERO(&writefds);
		FD_ZERO(&errorfds);

		int max_fd = udpio_fd_set(&readfds, &writefds, &errorfds);

		struct timeval timeout = {1, 1};
		count = select(max_fd + 1, &readfds, &writefds, &errorfds, &timeout);
		if (count == -1) {
			printf("select error: %d %u\n", count, WSAGetLastError());
			continue;
		}

		if (count == 0) {
			continue;
		}

		if (c_active != udpio_list.size() &&
				time(&t_current) != t_last) {
			udpio_collect(t_current);
			t_last = t_current;
			c_active = udpio_list.size();
		}

		udpio_event(&readfds, &writefds, &errorfds);
	}
	return 0;
}

/* udp_switch addr1:port1 */
int main(int argc, char * argv[])
{
	int error;
	char buf[512];

	WSADATA data;
	WSAStartup(0x201, &data);

	int count = 0;
	for (int i = 1; i < argc; i++) {
		char * pdot = NULL;
		int s_port_0, d_port_0;
		const char * s_port, * d_port;

		strncpy(buf, argv[i], sizeof(buf));
		buf[sizeof(buf) - 1] = 0;
		pdot = strchr(buf, ':');
		if (pdot == NULL)
			continue;
		*pdot++ = 0;
		s_port = d_port = pdot;

		pdot = strchr(pdot, ':');
		if (pdot != NULL) {
			*pdot++ = 0;
			s_port = pdot;
		}

		s_port_0 = atoi(s_port);
		if (s_port_0 == 0 || s_port_0 == -1)
			continue;

		d_port_0 = atoi(d_port);
		if (d_port_0 == 0 || d_port_0 == -1)
			continue;

		udpio_add(inet_addr(buf), d_port_0, s_port_0);
		count++;
	}

	if (count > 0)
		udp_switch();
	udpio_final();
	return 0;
}


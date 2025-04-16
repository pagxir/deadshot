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
#define WSAStartup(x, y)
typedef int WSADATA;
#else
#include <winsock2.h>
#include <ws2tcpip.h>
typedef int socklen_t;
#define S_CLOSE(s) closesocket(s)
#define S_READ(fd, buf, len) recv(fd, buf, len, 0)
#define S_WRITE(fd, buf, len) send(fd, buf, len, 0)
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <set>

#define RCVSIZ 16384
#define UDPF_KEEP 0x00000001
#define IN6ADDRSZ  16
#define INT16SZ    2

struct udp6to4cb {
	int flags;
	int fildes;
	int source;
	time_t lastidle;
	struct sockaddr_in target;
};

bool operator < (const struct udp6to4cb & a, const struct udp6to4cb & b)
{
	u_short in_port1;
	u_short in_port2;
	struct in_addr in_addr1;
	struct in_addr in_addr2;

	in_port1 = a.target.sin_port;
	in_addr1 = a.target.sin_addr;

	in_port2 = b.target.sin_port;
	in_addr2 = b.target.sin_addr;

	if (in_port1 != in_port2)
		return (in_port1 < in_port2);

	return memcmp(&in_addr1, &in_addr2, sizeof(in_addr1)) < 0;
}

static std::set<udp6to4cb> udp6to4_list;

struct udp4to6cb {
	int flags;
	int fildes;
	int source;
	time_t lastidle;
	struct sockaddr_in6 target;
};

bool operator < (const struct udp4to6cb & a, const struct udp4to6cb & b)
{
	u_short in6_port1;
	u_short in6_port2;
	struct in6_addr in6_addr1;
	struct in6_addr in6_addr2;

	in6_port1 = a.target.sin6_port;
	in6_addr1 = a.target.sin6_addr;

	in6_port2 = b.target.sin6_port;
	in6_addr2 = b.target.sin6_addr;

	if (in6_port1 != in6_port2)
		return (in6_port1 < in6_port2);

	return memcmp(&in6_addr1, &in6_addr2, sizeof(in6_addr1)) < 0;
}

static std::set<udp4to6cb> udp4to6_list;

int udpio_add(u_long addr, u_short port)
{
	int error;
	int rcvsiz = RCVSIZ;
	struct udp6to4cb iocb;
	struct sockaddr_in addr_in1;
	struct sockaddr_in6 addr_in6;
	int s_udp = socket(PF_INET6, SOCK_DGRAM, 0);
	assert(s_udp != -1);

	setsockopt(s_udp, SOL_SOCKET, SO_RCVBUF, (char *)&rcvsiz, sizeof(rcvsiz));

	memset(&addr_in6, 0, sizeof(addr_in6));
	addr_in6.sin6_family = AF_INET6;
	addr_in6.sin6_port = htons(port + 2000);
	addr_in6.sin6_port = htons(port);
	error = bind(s_udp, (struct sockaddr *)&addr_in6, sizeof(addr_in6));
	assert(error == 0);

	addr_in1.sin_family = AF_INET;
	addr_in1.sin_port = htons(port);
	addr_in1.sin_addr.s_addr = htonl(INADDR_ANY);
	iocb.flags = UDPF_KEEP;
	iocb.fildes = s_udp;
	iocb.target = addr_in1;
	iocb.target.sin_addr.s_addr = addr;
	udp6to4_list.insert(iocb);
	return 0;
}

int udpio_final(void)
{
	std::set<udp6to4cb>::const_iterator iter64;
	std::set<udp4to6cb>::const_iterator iter46;

	iter64 = udp6to4_list.begin();
	while (iter64 != udp6to4_list.end()) {
		S_CLOSE(iter64->fildes);
		++iter64;
	}

	iter46 = udp4to6_list.begin();
	while (iter46 != udp4to6_list.end()) {
		S_CLOSE(iter46->fildes);
		++iter46;
	}

	return 0;
}

int udpio_realloc(const struct sockaddr_in & addr)
{
	int fd;
	int rcvsiz = RCVSIZ;
	struct udp6to4cb iocb;

	iocb.flags = 0;
	iocb.target = addr;
	std::set<udp6to4cb>::iterator iter;

	iter = udp6to4_list.find(iocb);
	if (iter != udp6to4_list.end()) {
		iocb = *iter;
		time(&iocb.lastidle);
		udp6to4_list.erase(iter);
		udp6to4_list.insert(iocb);
		return iocb.fildes;
	}

	fprintf(stderr, "failure\n");
	return -1;
}

int udpio_realloc(int source, const struct sockaddr_in6 & addr)
{
	int fd;
	int rcvsiz = RCVSIZ;
	struct udp4to6cb iocb;

	iocb.flags = 0;
	iocb.target = addr;
	iocb.source = source;
	std::set<udp4to6cb>::iterator iter;

	iter = udp4to6_list.find(iocb);
	if (iter != udp4to6_list.end()) {
		iocb = *iter;
		time(&iocb.lastidle);
		udp4to6_list.erase(iter);
		udp4to6_list.insert(iocb);
		return iocb.fildes;
	}

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *)&rcvsiz, sizeof(rcvsiz));

	iocb.fildes = fd;
	iocb.target = addr;
	iocb.source = source;
	time(&iocb.lastidle);
	udp4to6_list.insert(iocb);
	return iocb.fildes;
}

int udpio_event(fd_set * readfds, fd_set * writefds, fd_set * errorfds)
{
	int fd, len;
	socklen_t addr_len1;
	char buf[4096];
	struct sockaddr_in addr_in4;
	struct sockaddr_in6 addr_in6;
	std::set<udp6to4cb>::iterator iter64;
	std::set<udp4to6cb>::iterator iter46;

	iter64 = udp6to4_list.begin();
	while (iter64 != udp6to4_list.end()) {
		int source = -1;
		if (FD_ISSET(iter64->fildes, readfds)) {
			addr_len1 = sizeof(addr_in6);
			len = recvfrom(iter64->fildes, buf, sizeof(buf), 0,
					(struct sockaddr *)&addr_in6, &addr_len1);
			if (len == -1) continue;

			fprintf(stderr, "recvfrom6to4: len = %d\n", len);
			if (iter64->flags & UDPF_KEEP) {
				fd = udpio_realloc(iter64->fildes, addr_in6);
				fprintf(stderr, "alloc pair %d, src %d\n", fd, iter64->fildes);
			} else {
				fd = iter64->source;
				fprintf(stderr, "user source pair %d\n", fd);
			}

			int err = sendto(fd, buf, len, 0, (struct sockaddr *)
					&(iter64->target), sizeof(iter64->target));
		}
		++iter64;
	}

	iter46 = udp4to6_list.begin();
	while (iter46 != udp4to6_list.end()) {
		if (FD_ISSET(iter46->fildes, readfds)) {
			addr_len1 = sizeof(addr_in4);
			len = recvfrom(iter46->fildes, buf, sizeof(buf), 0,
					(struct sockaddr *)&addr_in4, &addr_len1);
			if (len == -1) continue;
			fprintf(stderr, "recvfrom4to6: len = %d\n", len);

			fd = iter46->source;
			if (iter46->flags & UDPF_KEEP) {
				fprintf(stderr, "failure send\n");
				continue;
			}

			int err = sendto(fd, buf, len, 0, (struct sockaddr *)
					&(iter46->target), sizeof(iter46->target));
		}
		++iter46;
	}

	return 0;
}

int udpio_collect(time_t current)
{
	int sum = 0;
	int count = udp6to4_list.size();
	std::set<udp6to4cb>::iterator iter64;
	std::set<udp4to6cb>::iterator iter46;

	iter64 = udp6to4_list.begin();
	while (iter64 != udp6to4_list.end()) {
		if (iter64->lastidle + 150 < current &&
				(iter64->flags & UDPF_KEEP) == 0) {
			S_CLOSE(iter64->fildes);
			udp6to4_list.erase(iter64++);
			continue;
		}
		++iter64;
	}

	if (udp6to4_list.size() != count) {
		fprintf(stderr, "udpio collect: %d %d\n", udp6to4_list.size(), count);
		assert (udp6to4_list.size() <= count);
		sum += (count - udp6to4_list.size());
	}

	count = udp4to6_list.size();
	iter46 = udp4to6_list.begin();
	while (iter46 != udp4to6_list.end()) {
		if (iter46->lastidle + 150 < current &&
				(iter46->flags & UDPF_KEEP) == 0) {
			S_CLOSE(iter46->fildes);
			udp4to6_list.erase(iter46++);
			continue;
		}
		++iter46;
	}

	if (udp4to6_list.size() != count) {
		fprintf(stderr, "udpio collect: %d %d\n", udp4to6_list.size(), count);
		assert (udp4to6_list.size() <= count);
		sum += (count - udp4to6_list.size());
	}

	return sum;
}

int udpio_fd_set(fd_set * readfds, fd_set * writefds, fd_set * errorfds)
{
	int fd_max = 0;
	std::set<udp6to4cb>::const_iterator iter64;
	std::set<udp4to6cb>::const_iterator iter46;

	iter64 = udp6to4_list.begin();
	while (iter64 != udp6to4_list.end()) {
		FD_SET(iter64->fildes, readfds);
		fd_max = (fd_max < iter64->fildes? iter64->fildes: fd_max);
		++iter64;
	}

	iter46 = udp4to6_list.begin();
	while (iter46 != udp4to6_list.end()) {
		FD_SET(iter46->fildes, readfds);
		fd_max = (fd_max < iter46->fildes? iter46->fildes: fd_max);
		++iter46;
	}

	return fd_max;
}

int udp_switch(void)
{
	int count;
	fd_set readfds, writefds, errorfds;

	time_t t_last, t_current;
	size_t c_active = udp6to4_list.size();

	time(&t_last);
	for ( ; ; ) {
		int max_fd;
		struct timeval timeout = {1, 1};

		FD_ZERO(&readfds);
		FD_ZERO(&writefds);
		FD_ZERO(&errorfds);

		max_fd = udpio_fd_set(&readfds, &writefds, &errorfds);

		count = select(max_fd + 1, &readfds, &writefds, &errorfds, &timeout);
		if (count == -1) {
			fprintf(stderr, "select error: %d \n", count);
			continue;
		}

		if (time(&t_current) > t_last + 150) {
			udpio_collect(t_current);
			c_active = udp6to4_list.size();
			t_last = t_current;
		}

		if (count > 0) {
			udpio_event(&readfds, &writefds, &errorfds);
			continue;
		}
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
		strncpy(buf, argv[i], sizeof(buf));
		buf[sizeof(buf) - 1] = 0;
		pdot = strchr(buf, ':');
		if (pdot == NULL)
			continue;
		*pdot++ = 0;
		int port = atoi(pdot);
		if (port == 0 || port == -1)
			continue;
		udpio_add(inet_addr(buf), port);
		count++;
	}

	if (count > 0)
		udp_switch();
	udpio_final();
	return 0;
}


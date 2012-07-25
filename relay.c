#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SAI2SAO(x) (struct sockaddr *)(x)

static int do_select(int relay_fd)
{
	int error;
	fd_set readfds;

	FD_ZERO(&readfds);
	FD_SET(0, &readfds);
	FD_SET(relay_fd, &readfds);

	error = select(relay_fd + 1, &readfds, NULL, NULL, NULL);
	return (error > 0 && !FD_ISSET(0, &readfds));
}

static int ip_addr_this(struct sockaddr_in *addr_in1)
{
	fprintf(stderr, "%s:%d",
			inet_ntoa(addr_in1->sin_addr),
			htons(addr_in1->sin_port));
	return 0;
}

int main(int argc, char *argv[])
{
	int error;
	int count;
	int relay_fd;
	char buf[8192];
	struct sockaddr_in addr_dst;
	struct sockaddr_in addr_src;
	struct sockaddr_in addr_in1;

	relay_fd = socket(AF_INET, SOCK_DGRAM, 0);
	addr_in1.sin_family = AF_INET;
	addr_in1.sin_port   = htons(8201);
	addr_in1.sin_addr.s_addr = htonl(INADDR_ANY);
	error = bind(relay_fd, SAI2SAO(&addr_in1), sizeof(addr_in1));
	assert(error == 0);

	while (do_select(relay_fd) > 0) {
		int have_addr = 0;
		socklen_t addr_len = sizeof(addr_src);
		count = recvfrom(relay_fd, buf, sizeof(buf),
					0, SAI2SAO(&addr_src), &addr_len);
		if (count < 8) {
			ip_addr_this(&addr_src);
			continue;
		}

		addr_dst.sin_family = AF_INET;
		memcpy(&addr_dst.sin_port, buf + 2, 2);
		if (0x01 == (buf[1] & 0x3F)) {
			memcpy(&addr_dst.sin_addr, buf + 4, 4);
			have_addr = 1;
		}

		if (0xAE == (buf[0] & 0xFF)) {
			int tag = (buf[1] & 0xC0);
			if (tag == 0x80) {
				buf[1] &= 0x3F;
				if (addr_dst.sin_port == 0) {
					addr_dst.sin_port = addr_src.sin_port;
					memcpy(buf + 2, &addr_src.sin_port, 2);
				}

				if (addr_dst.sin_addr.s_addr == htonl(INADDR_ANY)) {
					addr_dst.sin_addr.s_addr = addr_dst.sin_addr.s_addr;
					memcpy(buf + 4, &addr_src.sin_addr, 4);
				}

				sendto(relay_fd, buf, count, 0,
					SAI2SAO(&addr_dst), sizeof(addr_dst));
			}

			if (tag == 0x00) {
				printf("external address is: \n");
				ip_addr_this(&addr_dst);
			} else {
				printf("from address is: \n");
				ip_addr_this(&addr_src);
			}
		}
	}

	close(relay_fd);
	return 0;
}


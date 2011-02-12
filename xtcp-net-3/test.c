#include <stdio.h>
#include <assert.h>
#include <winsock2.h>
#include <windows.h>

int main(int argc, char * argv[])
{
	int fd;
	int error;
	int  yes = 1;
	char buf[1024];
	ssize_t count;
	struct sockaddr_in dstname;

	WSADATA data;
	WSAStartup(0x202, &data);

	fd = socket(AF_INET, SOCK_STREAM, 0);
	dstname.sin_family = AF_INET;
	dstname.sin_port   = htons(atoi(argv[1]));
	dstname.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes));
	error = bind(fd, (const struct sockaddr *)&dstname, sizeof(dstname));
	assert(error == 0);

	getchar();

	dstname.sin_port   = htons(atoi(argv[2]));
	error = connect(fd, (const struct sockaddr *)&dstname, sizeof(dstname));
	printf("error: %d\n", WSAGetLastError());
	assert(error == 0);
#if 0
	count = xread(fd, buf, sizeof(buf));
	if (count > 0) {
		buf[count] = 0;
		printf("buf[%d]: %s\n", count, buf);
	}

	size_t total = 0;
	count = read(0, buf, sizeof(buf));
	while (count > 0) {
		ssize_t off, len = 0;
		for (off = 0; off < count; off += len) {
			len = xwrite(fd, buf + off, count - off);
			if (len <= 0) {
				break;
			}
			total += len;
		}

		if (len <= 0) {
			break;
		}
		count = read(0, buf, sizeof(buf));
	}
	printf("total data length: %ld\n", total);
#endif

	closesocket(fd);

	printf("send all finish!\n");
	WSACleanup();
	return 0;
}


#include <stdio.h>
#include <assert.h>
#include <signal.h>
#include <winsock2.h>
#include <windows.h>

#include "xreq.h"

int sigint_occur = 0;

void sigint_handle(int no)
{
	sigint_occur = 1;
}

int main(int argc, char * argv[])
{
	int fd;
	size_t total;
	FILE * fp = 0;
	char buf[1024];
	ssize_t count;
	struct sockaddr_in dstname;
	signal(SIGINT, sigint_handle);

	xreq_init(1534);
	fp = fopen(argv[3], "rb");
	assert(fp != NULL);

	fd = xopen();
	dstname.sin_family = AF_INET;
	dstname.sin_port   = htons(atoi(argv[2]));
	dstname.sin_addr.s_addr = inet_addr(argv[1]);
	xconnect(fd, &dstname, sizeof(dstname));
#if 0
	count = xread(fd, buf, sizeof(buf));
	if (count > 0) {
		buf[count] = 0;
		printf("buf[%d]: %s\n", count, buf);
	}
#endif

	total = 0;
	count = fread(buf, 1, sizeof(buf), fp);
	while (count > 0 && sigint_occur == 0) {
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
		count = sizeof(buf); //fread(buf, 1, sizeof(buf), fp);
	}
	printf("total data length: %ld\n", total);

	xclose(fd);
	fclose(fp);

	printf("send all finish!\n");
	xreq_clean();
	return 0;
}


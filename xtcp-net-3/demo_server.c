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
	FILE * fp = 0;
	char buf[1024];
	ssize_t count;
	struct sockaddr_in dstname;
	signal(SIGINT, sigint_handle);

	xreq_init(1423);

	fd = xopen();

#if 0
	dstname.sin_family = AF_INET;
	dstname.sin_port   = htons(1423);
	dstname.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	xbind(fd, (const struct sockaddr *)&dstname, sizeof(dstname));
#endif

	xaccept(fd, NULL, NULL);

	/* count = xwrite(clientfd, "hello world", 11); */
	count = xread(fd, buf, sizeof(buf));
	if (count > 0) {
		fp = fopen("tcp_dump.dat", "wb");
		assert(fp != NULL);
	}

	while (count > 0 && sigint_occur == 0) {
		/* fwrite(buf, 1, count, fp); */
		count = xread(fd, buf, sizeof(buf));
	}

	if (fp != NULL) {
		fclose(fp);
	}
	xclose(fd);

	xreq_clean();
	return 0;
}


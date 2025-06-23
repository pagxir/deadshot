#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include <time.h>
#include <unistd.h>
#include <assert.h>

static int sendfd(int unixfd, int netfd)
{
    char dummy[] = "ABC";
	struct iovec io = {
		.iov_base = dummy,
		.iov_len = 3
	};
	struct msghdr msg = { 0 };
	char buf[CMSG_SPACE(sizeof(netfd))] = {};

	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(netfd));
	
	memmove(CMSG_DATA(cmsg), &netfd, sizeof(netfd));
	msg.msg_controllen = CMSG_SPACE(sizeof(netfd));

	return sendmsg(unixfd, &msg, 0);
}

static int receivefd(int unixfd)
{
	int netfd;
	char buffer[256];
	struct iovec io = {
		.iov_base = buffer,
		.iov_len = sizeof(buffer)
	};

	struct msghdr msg = {0};
	msg.msg_iov = &io;
	msg.msg_iovlen = 1;

	char control[256];
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	if (recvmsg(unixfd, &msg, 0) < 0) {
		return -1;
	}

	struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);
	unsigned char * data = CMSG_DATA(cmsg);

	memcpy(&netfd, data, sizeof(netfd));
	return netfd;
}

int socket_netns(int family, int type, int protocol, const char *netns)
{
	char protocolbuf[64];
	char familybuf[64];
	char typebuf[64];
	char afdbuf[64];

	int sv[2];
	int netfd;

	if (!netns || !getenv("NETNS_WRAP")) {
		return socket(family, type, protocol);
	}

	int err = socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
	assert (err == 0);

	pid_t pid = fork();
	assert(pid != -1);

	if (pid > 0) {
		close(sv[0]);
		netfd = receivefd(sv[1]);
		close(sv[1]);
		return netfd;
	}

	close(sv[1]);
	snprintf(afdbuf, sizeof(afdbuf), "%d", sv[0]);
	snprintf(typebuf, sizeof(typebuf), "%d", type);
	snprintf(familybuf, sizeof(familybuf), "%d", family);
	snprintf(protocolbuf, sizeof(protocolbuf), "%d", protocol);
	char * const list[] = {"ip", "netns", "exec", strdup(netns), getenv("NETNS_WRAP"), "sockmake", "-fd", afdbuf, "-family", familybuf, "-type", typebuf, "-protocol", protocolbuf, NULL};
	execvp("ip", list);
	return -1;
}

static int run_netns_helper(int argc, char *argv[])
{
	int i;
	int unixfd = -1;
	int protocol = 0;
	int family = AF_INET6;
	int type = SOCK_STREAM;
	int sockmake = 0;

	for (i = 0; i < argc; i++) {
		const char *data = argv[i];

		if (strcmp(data, "sockmake") == 0) {
			sockmake = 1;
		} else if (strcmp(data, "-family") == 0
				&& i + 1 < argc) {
			const char *fdpath = argv[++i];
			sscanf(fdpath, "%d", &family);
		} else if (strcmp(data, "-type") == 0
				&& i + 1 < argc) {
			const char *fdpath = argv[++i];
			sscanf(fdpath, "%d", &type);
		} else if (strcmp(data, "-protocol") == 0
				&& i + 1 < argc) {
			const char *fdpath = argv[++i];
			sscanf(fdpath, "%d", &protocol);
		} else if (strcmp(data, "-fd") == 0
				&& i + 1 < argc) {
			const char *fdpath = argv[++i];
			sscanf(fdpath, "%d", &unixfd);
		}
	}

	if (unixfd != -1 && sockmake) {
		int netfd = socket(family, type, protocol);
		fprintf(stderr, "unixfd %d family %d type %d protocol %d netfd %d\n", unixfd, family, type, protocol, netfd);
		sendfd(unixfd, netfd);
		close(netfd);
		close(unixfd);
	}

	exit(0);
	return 0;
}

#if NETNS_HELPER 
int main(int argc, char *argv[])
{
	struct sockaddr_in6 one;
	int netfd;
	int newfd;
	int err;

	if (argc > 2 && getenv("NETNS_LEVEL") == NULL) {
		setenv("NETNS_LEVEL", "bridge", 0);
		run_netns_helper(argc, argv);
		return 0;
	}

	netfd = socket_netns(AF_INET6, SOCK_STREAM, 0, argc > 1? argv[1]: "test");
	printf("newfd = %d\n", netfd);

	one.sin6_family = AF_INET6;
	one.sin6_port   = htons(9000);
	one.sin6_addr   = in6addr_any;
	err = bind(netfd, (const struct sockaddr *)&one, sizeof(one));
	perror("bind");
	assert (err == 0);

	err = listen(netfd, 0);
	assert (err == 0);

	do {
		char addrbuf[64];
		socklen_t addrlen = sizeof(one);
		newfd = accept(netfd, (struct sockaddr *)&one, &addrlen);
		if (newfd >= 0) {
			inet_ntop(AF_INET6, &one.sin6_addr, addrbuf, sizeof(addrbuf));
			fprintf(stderr, "netfd=%d, [%s]:%d\n", newfd, addrbuf, htons(one.sin6_port));
		}
	} while (newfd >= 0);

	return 0;
}
#endif

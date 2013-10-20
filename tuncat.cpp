#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <fstream>
#include <iostream>

#include <sys/types.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <netdb.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <net/if.h>
#include <linux/if_tun.h>

using namespace std;

typedef struct _netcat {
	int l_mode;
	const char *s_port;
	const char *s_addr;
	const char *d_port;
	const char *d_addr;
} netcat_t;

static void error_check(int exited, const char *str)
{
	if (exited) {
		fprintf(stderr, "%s\n", str);
		exit(-1);
	}

	return;
}

static char* memdup(const void *buf, size_t len)
{
	char *p = (char *)malloc(len);
	if (p != NULL)
		memcpy(p, buf, len);
	return p;
}

static int tun_create(char *dev, int flags)
{
	int fd, err, flag;
	struct ifreq ifr;

	fd = open("/dev/net/tun", O_RDWR);
	fd = (fd > -1? fd: open("/dev/tun", O_RDWR));
	if (fd < 0) {
		return fd;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags |= flags;
	if (dev != NULL) {
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
		fprintf(stderr, "dev: %s\n", dev);
	}

	if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
		close(fd);
		return err;
	}

	if (dev != NULL) {
		fprintf(stderr, "dev: %s\n", ifr.ifr_name);
		strcpy(dev, ifr.ifr_name);
	}

#if 0
	/* Set the MTU of the tap interface */
	ifr.ifr_mtu = 1500;
	ifr.ifr_flags = IFF_UP| IFF_RUNNING;
	if (ioctl(fd, SIOCSIFMTU, &ifr) < 0)  {
		close(fd);
		return -1;
	}
#endif

	flag = fcntl(fd, F_GETFL);
	if (flag != -1) {
		flag |= O_NONBLOCK;
		fcntl(fd, F_SETFL, flag);
	}
	return fd;
}

static int get_cat_socket(netcat_t *upp)
{
	int val = 1;
	int flag = 0;
	int serv = socket(AF_INET, SOCK_DGRAM, 0);

	sockaddr_in my_addr;
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(upp->s_port? atoi(upp->s_port): 0);
	if (upp->s_addr == NULL) {
		my_addr.sin_addr.s_addr = INADDR_ANY;
	} else if (inet_pton(AF_INET, upp->s_addr, &my_addr.sin_addr) <= 0) {
		cerr << "incorrect network address.\n";
		return -1;
	}

	val = IP_PMTUDISC_DONT;
	setsockopt(serv, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));

	if ((upp->s_addr != NULL || upp->s_port != NULL) &&
			(-1 == bind(serv, (sockaddr*)&my_addr, sizeof(my_addr)))) {
		cerr << "bind network address.\n";
		return -1;
	}

	if (upp->l_mode) {
		int ret;
		char buf[8192];
		struct sockaddr their_addr;
		socklen_t namlen = sizeof(their_addr);

		fprintf(stderr, "server is ready at port: %s\n", upp->s_port);
		ret = recvfrom(serv, buf, sizeof(buf), MSG_PEEK, &their_addr, &namlen);
		error_check(ret == -1, "recvfrom failure");

		ret = connect(serv, &their_addr, namlen);
		error_check(ret == -1, "bind failure");

		flag = fcntl(serv, F_GETFL);
		if (flag != -1) {
			flag |= O_NONBLOCK;
			fcntl(serv, F_SETFL, flag);
		}
		return serv;
	} else {
		sockaddr_in their_addr;
		their_addr.sin_family = AF_INET;
		their_addr.sin_port = htons(short(atoi(upp->d_port)));
		if (inet_pton(AF_INET, upp->d_addr, &their_addr.sin_addr) <= 0) {
			cerr << "incorrect network address.\n";
			close(serv);
			return -1;
		}

		if (-1 == connect(serv, (sockaddr*)&their_addr, sizeof(their_addr))) {
			cerr << "connect: " << endl;
			close(serv);
			return -1;
		}

		flag = fcntl(serv, F_GETFL);
		if (flag != -1) {
			flag |= O_NONBLOCK;
			fcntl(serv, F_SETFL, flag);
		}
		return serv;
	}

	return -1;
}

static netcat_t* get_cat_context(netcat_t *upp, int argc, char **argv)
{
	int i;
	int opt_pidx = 0;
	int opt_listen = 0;
	char *parts[2] = {0};
	const char *domain = 0, *port = 0;
	const char *s_domain = 0, *s_port = 0;

	for (i = 1; i < argc; i++) {
		if (!strcmp("-l", argv[i])) {
			opt_listen = 1;
		} else if (!strcmp("-s", argv[i])) {
			error_check(++i == argc, "-s need an argument");
			s_domain = argv[i];
		} else if (!strcmp("-p", argv[i])) {
			error_check(++i == argc, "-p need an argument");
			s_port = argv[i];
		} else if (opt_pidx < 2) {
			parts[opt_pidx++] = argv[i];
		} else {
			fprintf(stderr, "too many argument");
			return 0;
		}
	}

	if (opt_pidx == 1) {
		port = parts[0];
		for (i = 0; port[i]; i++) {
			if (!isdigit(port[i])) {
				domain = port;
				port = NULL;
				break;
			}
		}
	} else if (opt_pidx == 2) {
		port = parts[1];
		domain = parts[0];
		for (i = 0; domain[i]; i++) {
			if (!isdigit(domain[i])) {
				break;
			}
		}

		error_check(domain[i] == 0, "should give one port only");
	}

	if (opt_listen) {
		if (s_domain != NULL)
			error_check(domain != NULL, "domain repeat twice");
		else
			s_domain = domain;

		if (s_port != NULL)
			error_check(port != NULL, "port repeat twice");
		else
			s_port = port;
	} else {
		u_long f4ward_addr = 0;
		u_short f4ward_port = 0;
		error_check(domain == NULL, "hostname is request");
		f4ward_addr = inet_addr(domain);
		f4ward_port = atoi(port? port: "8080");
		error_check(f4ward_addr == INADDR_ANY, "bad hostname");
		error_check(f4ward_addr == INADDR_NONE, "bad hostname");
	}

	upp->l_mode = opt_listen;
	upp->s_addr = s_domain;
	upp->s_port = s_port;
	upp->d_addr = domain;
	upp->d_port = port;
	return upp;
}

#define STATUS_NETR 0x0001
#define STATUS_NETW 0x0010
#define STATUS_TUNR 0x0100
#define STATUS_TUNW 0x1000

#ifdef USE_CACHE
static int _t2n_w = 0;
static int _t2n_r = 0;
static int _t2n_len[USE_CACHE];
static char *_t2n_buf[USE_CACHE];

static int _n2t_w = 0;
static int _n2t_r = 0;
static int _n2t_len[USE_CACHE];
static char *_n2t_buf[USE_CACHE];
#endif

int main(int argc, char* argv[])
{
	int rdwr = 0x1111;
	int check = 0, result = 0;
	char packet[4096] = {0};
	netcat_t netcat_context = {0};


	int tun_fd = tun_create(NULL, IFF_TUN | IFF_NO_PI);
	if (tun_fd < 0) {
		perror("tun_create");
		return 1;
	}

	netcat_t* upp = get_cat_context(&netcat_context, argc, argv);
	if (upp == NULL) {
		perror("get_cat_context");
		return 1;
	}

	int net_fd = get_cat_socket(upp);
	if (net_fd < 0) {
		perror("net_create");
		return 1;
	}

	for ( ; ; ) {
		fd_set readfds, writefds;

		FD_ZERO(&readfds);
		if (rdwr & STATUS_NETR)
			FD_SET(net_fd, &readfds);
		if (rdwr & STATUS_TUNR)
			FD_SET(tun_fd, &readfds);

		FD_ZERO(&writefds);
		if (rdwr & STATUS_NETW)
			FD_SET(net_fd, &writefds);
		if (rdwr & STATUS_TUNW)
			FD_SET(tun_fd, &writefds);

		result = select(net_fd + 1, &readfds, &writefds, NULL, NULL);
		if (result == -1) {
			perror("select");
			break;
		}

		check = ((rdwr & STATUS_NETR) && FD_ISSET(net_fd, &readfds));
		check? (rdwr &= ~STATUS_NETR): (STATUS_NETR);

		check = ((rdwr & STATUS_NETW) && FD_ISSET(net_fd, &writefds));
		check? (rdwr &= ~STATUS_NETW): (STATUS_NETW);

		check = ((rdwr & STATUS_TUNR) && FD_ISSET(tun_fd, &readfds));
		check? (rdwr &= ~STATUS_TUNR): (STATUS_TUNR);

		check = ((rdwr & STATUS_TUNW) && FD_ISSET(tun_fd, &writefds));
		check? (rdwr &= ~STATUS_TUNW): (STATUS_TUNW);

#ifdef USE_CACHE
		while (0x0 == (STATUS_NETW & rdwr) && (_t2n_len[_t2n_w] > 0)) {
			result = write(net_fd, _t2n_buf[_t2n_w], _t2n_len[_t2n_w]);
			if (result == -1) {
				rdwr |= STATUS_NETW;
				break;
			}

			free(_t2n_buf[_t2n_w]);
			_t2n_len[_t2n_w++] = 0;
			_t2n_w %= CACHE_SIZE;
		}
#endif

		check = (STATUS_TUNR | STATUS_NETW);
		while (0x0 == (rdwr & check)) {
			result = read(tun_fd, packet, sizeof(packet));
			if (result == -1) {
				rdwr |= STATUS_TUNR;
				break;
			}
			
			if (result > 1472)
				fprintf(stderr, "too long mtu %d\n", result);

			check = write(net_fd, packet, result); 
			if (check == -1) {
				rdwr |= STATUS_NETW;
#ifdef USE_CACHE
				goto pack_tun_d;
#endif
			}
		}

#ifdef USE_CACHE
		while ((STATUS_TUNR & rdwr) == 0 && (_t2n_len[_t2n_r] == 0)) {
			result = read(tun_fd, packet, sizeof(packet));
			if (result == -1) {
				rdwr |= STATUS_TUNR;
				break;
			}

pack_tun_d:
			_t2n_buf[_t2n_r] = memdup(packet, result);
			if (_t2n_buf[_t2n_r]) {
				_t2n_len[_t2n_r++] = result;
				_t2n_r %= CACHE_SIZE;
			}
		}

		while ((STATUS_TUNW & rdwr) == 0 && (_n2t_len[_n2t_w] > 0)) {
			result = write(tun_fd, _n2t_buf[_n2t_w], _n2t_len[_n2t_w]);
			if (result == -1) {
				rdwr |= STATUS_TUNW;
				break;
			}

			free(_n2t_buf[_n2t_w]);
			_n2t_len[_n2t_w++] = 0;
			_n2t_w %= CACHE_SIZE;
		}
#endif

		check = (STATUS_TUNW | STATUS_NETR);
		while (0 == (rdwr & check)) {
			result = read(net_fd, packet, sizeof(packet));
			if (result == -1) {
				rdwr |= STATUS_NETR;
				break;
			}

			check = write(tun_fd, packet, result); 
			if (check == -1) {
				rdwr |= STATUS_TUNW;
#ifdef USE_CACHE
				goto pack_net_d;
#endif
			}
		}

#ifdef USE_CACHE
		while ((STATUS_NETR & rdwr) == 0x0 && (_n2t_len[_n2t_r] == 0)) {
			result = read(net_fd, packet, sizeof(packet));
			if (result == -1) {
				rdwr |= STATUS_NETR;
				break;
			}
pack_net_d:
			_n2t_buf[_n2t_r] = memdup(packet, result);
			if (_n2t_buf[_n2t_r] != NULL) {
				_n2t_len[_n2t_r++] = result;
				_n2t_r %= CACHE_SIZE;
			}
		}
#endif
	}

	close(net_fd);
	close(tun_fd);

	return 1;
}

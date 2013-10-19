#ifndef WIN32
   #include <cstdlib>
   #include <unistd.h>
   #include <ctype.h>
   #include <arpa/inet.h>
#else
   #include <winsock2.h>
   #include <ws2tcpip.h>
#endif
#include <fstream>
#include <iostream>
#include <cstring>
#include <udt.h>

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

static UDTSOCKET get_cat_socket(netcat_t *upp)
{

	UDTSOCKET serv = UDT::socket(AF_INET, SOCK_STREAM, 0);

	// Windows UDP issue
	// For better performance, modify HKLM\System\CurrentControlSet\Services\Afd\Parameters\FastSendDatagramThreshold
#ifdef WIN32
	int mss = 1052;
	UDT::setsockopt(serv, 0, UDT_MSS, &mss, sizeof(int));
#endif

	sockaddr_in my_addr;
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(upp->s_port? atoi(upp->s_port): 0);
	if (upp->s_addr == NULL) {
		my_addr.sin_addr.s_addr = INADDR_ANY;
	} else
#ifndef WIN32
		if (inet_pton(AF_INET, upp->s_addr, &my_addr.sin_addr) <= 0) {
#else
		if (INADDR_NONE == (my_addr.sin_addr.s_addr = inet_addr(upp->s_addr))) {
#endif
			cerr << "incorrect network address.\n";
			return 0;
		}

	if ((upp->s_addr != NULL || upp->s_port != NULL) &&
			(UDT::ERROR == UDT::bind(serv, (sockaddr*)&my_addr, sizeof(my_addr)))) {
		cerr << "bind: " << UDT::getlasterror().getErrorMessage() << endl;
		return 0;
	}

	sockaddr_in their_addr;
	if (upp->l_mode) {
		UDT::listen(serv, 1);
		fprintf(stderr, "server is ready at port: %s\n", upp->s_port);
		int namelen = sizeof(their_addr);
		UDTSOCKET fhandle = UDT::accept(serv, (sockaddr*)&their_addr, &namelen);
		if (UDT::INVALID_SOCK == fhandle)
			cerr << "accept: " << UDT::getlasterror().getErrorMessage() << endl;
		fprintf(stderr, "client is accepted: \n");
		UDT::close(serv);
		return fhandle;
	} else {
		their_addr.sin_family = AF_INET;
		their_addr.sin_port = htons(short(atoi(upp->d_port)));
#ifndef WIN32
		if (inet_pton(AF_INET, upp->d_addr, &their_addr.sin_addr) <= 0)
#else
		if (INADDR_NONE == (their_addr.sin_addr.s_addr = inet_addrupp->d_addr)))
#endif
		{
			cerr << "incorrect network address.\n";
			UDT::close(serv);
			return UDT::INVALID_SOCK;
		}

		if (UDT::ERROR == UDT::connect(serv, (sockaddr*)&their_addr, sizeof(their_addr)))
		{
			cerr << "connect: " << UDT::getlasterror().getErrorMessage() << endl;
			UDT::close(serv);
			return UDT::INVALID_SOCK;
		}

		return serv;
	}

	return UDT::INVALID_SOCK;
}

int main(int argc, char* argv[])
{
	int i;
	int opt_pidx = 0;
	int opt_listen = 0;
	char *parts[2] = {0};
	netcat_t netcat_context = {0};
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
		f4ward_port = atoi(port? port: "8080");
		f4ward_addr = inet_addr(domain);
		error_check(f4ward_addr == INADDR_ANY, "bad hostname");
		error_check(f4ward_addr == INADDR_NONE, "bad hostname");
	}

   // use this function to initialize the UDT library
   UDT::startup();
   netcat_context.d_port = port;
   netcat_context.d_addr = domain;
   netcat_context.s_port = s_port;
   netcat_context.s_addr = s_domain;
   netcat_context.l_mode = opt_listen;

	UDTSOCKET fhandle = get_cat_socket(&netcat_context);

   UDT::TRACEINFO trace;
   UDT::perfmon(fhandle, &trace);

#if 0
   // send the file
   if (UDT::ERROR == UDT::sendfile(fhandle, ifs, 0, size)) {
      cerr << "sendfile: " << UDT::getlasterror().getErrorMessage() << endl;
      return 0;
   }

   if (UDT::ERROR == (recvsize = UDT::recvfile(fhandle, ofs, 0, size))) {
      cerr << "recvfile: " << UDT::getlasterror().getErrorMessage() << endl;
      return 0;
   }
#endif
   timeval tv0, tv1;

   tv0.tv_sec = 0;
   tv0.tv_usec = 0;
   tv1.tv_sec = 0;
   tv1.tv_usec = 50000;
   
   int last_direct = 0;
   int fd_status = 0;
   int udt_status = 0;
   int fdudt_eof = 0;
   
	int uflen, ufoff;
   char udt2fd[8192];
   ufoff = uflen = 0;

	int fulen, fuoff;
   char fd2udt[8192];
   fulen = fuoff = 0;

#define DIRECT_UDT2FD 1
#define DIRECT_FD2UDT 2

   time_t last_time = 0;
   do {
	   int result;
	   fd_set readfds, writefds;
	   UDT::UDSET sendfds, receivefds;

	   if (fd_status != 3) {
		   int wait = 0;
		   FD_ZERO(&readfds);
		   if ((fd_status & 1) == 0) {
			   FD_SET(0, &readfds);
			   wait |= (last_direct != DIRECT_UDT2FD);
		   }

		   FD_ZERO(&writefds);
		   if ((fd_status & 2) == 0) {
			   FD_SET(1, &writefds);
			   wait |= (last_direct != DIRECT_FD2UDT);
		   }

		   if (((fd_status & 1) && (udt_status & 2)) ||
				   ((fd_status & 2) && (udt_status & 1))) {
			   result = select(2, &readfds, &writefds, NULL, &tv0);
		   } else if (udt_status == 3) {
			   result = select(2, &readfds, &writefds, NULL, NULL);
		   } else {
			   result = select(2, &readfds, &writefds, NULL, wait? &tv1: &tv0);
		   }

		   if (result > 0) {
			   if (FD_ISSET(0, &readfds)) {
				   fd_status |= 1;
			   }

			   if (FD_ISSET(1, &writefds)) {
				   fd_status |= 2;
			   }
		   }
	   }

	   if (udt_status != 3) {
		   int wait = 0;
		   UD_ZERO(&receivefds);
		   if ((udt_status & 1) == 0) {
			   UD_SET(fhandle, &receivefds);
			   wait |= (last_direct != DIRECT_FD2UDT);
		   }

		   UD_ZERO(&sendfds);
		   if ((udt_status & 2) == 0) {
			   UD_SET(fhandle, &sendfds);
			   wait |= (last_direct != DIRECT_UDT2FD);
		   }

		   if (((fd_status & 1) && (udt_status & 2)) ||
				   ((fd_status & 2) && (udt_status & 1))) {
			   result = UDT::select(0, &receivefds, &sendfds, NULL, &tv0);
		   } else if (fd_status == 3) {
			   result = UDT::select(0, &receivefds, &sendfds, NULL, NULL);
		   } else {
			   result = UDT::select(0, &receivefds, &sendfds, NULL, wait? &tv1: &tv0);
		   }

		   if (result > 0) {
			   if (UD_ISSET(fhandle, &receivefds)) {
				   udt_status |= 1;
			   }

			   if (UD_ISSET(fhandle, &sendfds)) {
				   udt_status |= 2;
			   }
		   }
	   }

	   if ((udt_status & 2) && (fuoff < fulen)) {
		   int r = UDT::send(fhandle, fd2udt + fuoff, fulen - fuoff, 0);
		   if (r < 0) {
			   fprintf(stderr, "send error\n");
			   break;
		   }
		   fuoff += r;
		   if (fuoff == fulen) {
			   last_direct &= ~((fd_status & 1)? 0: DIRECT_FD2UDT);
			   fuoff = fulen = 0;
		   }
		   udt_status &= ~2;
	   }

	   if ((fd_status & 1) && (size_t(fulen) < sizeof(fd2udt)) && fdudt_eof == 0) {
		   int r = read(0, fd2udt + fulen, sizeof(fd2udt) - fulen);
		   if (r <= 0) {
			   fprintf(stderr, "reach end of file\n");
			   fdudt_eof = 1;
		   } else {
			   fulen += r;
		   	   fd_status &= ~1;
			   last_direct = (last_direct? last_direct: DIRECT_FD2UDT);
		   }
	   }

	   if ((fd_status & 2) && (ufoff < uflen)) {
		   int r = write(1, udt2fd + ufoff, uflen - ufoff);
		   if (r < 0) {
			   fprintf(stderr, "write error\n");
			   break;
		   }

		   ufoff += r;
		   if (ufoff == uflen) {
			   last_direct &= ~((udt_status & 1)? 0: DIRECT_UDT2FD);
			   ufoff = uflen = 0;
		   }
		   fd_status &= ~2;
	   }

	   if ((udt_status & 1) && (size_t(uflen) < sizeof(udt2fd)) && fdudt_eof == 0) {
		   int r = UDT::recv(fhandle, udt2fd + uflen, sizeof(udt2fd) - uflen, 0);
		   if (r <= 0) {
			   fprintf(stderr, "reach end of file\n");
			   fdudt_eof = 1;
		   } else {
			   uflen += r;
		   	   udt_status &= ~1;
			   last_direct = (last_direct? last_direct: DIRECT_FD2UDT);
		   }
	   }

	   if (last_time == 0 && (udt_status & 1)) {
   			UDT::perfmon(fhandle, &trace);
   			last_time = time(NULL);
	   }

   } while (!fdudt_eof || (fulen > fuoff) || (uflen > ufoff));

   UDT::perfmon(fhandle, &trace);
   fprintf(stderr, "RX packet = %ld , TX packet = %ld\n", trace.pktRecv, trace.pktSent);
   fprintf(stderr, "RX = %f MB/sec, TX = %f MB/sec\n", trace.mbpsRecvRate / 8, trace.mbpsSendRate / 8);
   fprintf(stderr, "RX packet loss = %d , TX packet loss = %d, rexmt = %d\n", trace.pktRcvLoss, trace.pktSndLoss, trace.pktRetrans);

   UDT::close(fhandle);

   // use this function to release the UDT library
   UDT::cleanup();

   return 1;
}

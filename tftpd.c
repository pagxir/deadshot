#include <stdio.h>
#include <signal.h>
#include <assert.h>
#include <winsock.h>

#define MSS 1460
#define close closesocket

typedef int socklen_t;

struct tftp_session {
	int t_file; /* for data sent. */
	int t_flags;
	
};

struct tftp_socket {
	int t_file;
	int t_refcnt;
	struct tftp_socket * t_next;
};

int wait_ack(int fudp, u_short ackno, int *pcancel)
{

	int result;
	char buffer[32+MSS];
	fd_set readfds;
	FD_ZERO(&readfds);
	FD_SET(fudp, &readfds);
	struct timeval timeout;
	timeout.tv_sec = 2;
	timeout.tv_usec = 0;
	if (select(fudp+1, &readfds, 0, 0, &timeout)) {
		u_short  *ackhdr = (u_short*)buffer;
		result = recv(fudp, buffer, sizeof(buffer), 0);
		if (result < 4) {
			pcancel[0] = 1;
			return 0;
		}
		if (ackhdr[0]==htons(4)
				&& ackhdr[1]==htons(ackno))
			return 1;
		if (ackhdr[0]==htons(5))
			pcancel[0] = 1;
	}
	return 0;

}

int stable_send(int fudp, const void *sndbuf, socklen_t len,
		u_short ackno, int *pcancel)
{
	const char *psndbuf = (const char*)sndbuf;
	int result = send(fudp, psndbuf, len, 0);
	size_t maxtry = len>4?5:1;
	for (int i=0; i<maxtry && result==len && *pcancel==0; i++) {
		if (wait_ack(fudp, ackno, pcancel))
			return 1;
		result = send(fudp, psndbuf, len, 0);
	}
	if (result != len)
		pcancel[0] = 1;
	return 0;

}

struct tftp_session * create_session(int fd1, void * buf,
									 size_t len, struct sockaddr * sa_addr)
{
	return NULL;
}

int tftp_exec(int tfdp, const char *buffer, socklen_t len,
		const struct sockaddr *paddr, socklen_t sinlen)
{
	int result;
	int count = 0;
	u_short  tftpidx, *tftphdr, *reqhdr;

	char sndbuf[32 + MSS];
	int fudp = tfdp; //socket(AF_INET, SOCK_DGRAM, 0);
	assert (fudp != -1);
#if 0
	result = connect(fudp, paddr, sinlen);
	if (result == -1)
		return result;
#endif

	char msg_deny[] = "Access Deny";
	char msg_badop[] = "Invalid Operation";
	char msg_notfound[] = "TFTP File Not Found";

	do {
		reqhdr = (u_short*)buffer;
		tftphdr = (u_short*)sndbuf;
		if (len<9 || reqhdr[0]!=htons(1)) {
			tftphdr[0] = htons(5);
			if (len < 9)
				break;
			count = 4;
			if (reqhdr[1] == htons(2)) {
				tftphdr[1] = htons(2); count+=sizeof(msg_deny);
				memcpy(tftphdr+2, msg_deny, sizeof(msg_deny));
			} else {
				tftphdr[1] = htons(4); count+=sizeof(msg_badop);
				memcpy(tftphdr+2, msg_badop, sizeof(msg_badop));
			}
			send(fudp, sndbuf, count, 0);
		} else {
			FILE *fbin = fopen(buffer+2, "rb");
			if (fbin == NULL) {
				tftphdr[0] = htons(5);
				tftphdr[1] = htons(2); count=sizeof(msg_notfound)+4;
				memcpy(tftphdr+2, msg_notfound, sizeof(msg_notfound));
				send(fudp, sndbuf, count, 0);
				break;
			}
			printf("get file: %s\n", buffer+2);
			tftpidx = 1;
			tftphdr = (u_short*)sndbuf;
			int cancel = 0;
			do {
				tftphdr[0] = htons(3);
				tftphdr[1] = htons(tftpidx);
				count = fread(sndbuf+4, 1, MSS, fbin);
				if ( !stable_send(fudp, sndbuf, count+4,
							tftpidx, &cancel) ) {
					printf("error ocurr!\n");
					break;
				}
				tftpidx++;
			}while(count>0 && cancel==0);
			fclose(fbin);
		}
	} while (FALSE);
	//close(fudp);
	return 0;
}

int tftpd_run(int argc, char *argv[])
{
	int fd1, result;
	struct sockaddr_in addr1;
	struct sockaddr *sa_addr = NULL;

	int len, sa_len;
	char buf[32 + MSS];

	fd1 = socket(AF_INET, SOCK_DGRAM, 0);
	assert(fd1 != -1);
	
	addr1.sin_family = AF_INET;
	addr1.sin_port  = htons(69);
	addr1.sin_addr.s_addr = htonl(INADDR_ANY);
	sa_addr = (struct sockaddr*)&addr1;
	
	result = bind(fd1, sa_addr, sizeof(addr1));
	assert(result == 0);

	struct tftp_socket head = {fd1, 1, NULL};
	
	for ( ; ; ) {
		int count;
		fd_set readfds;
		int max_file = -1;
		struct tftp_session * psess = NULL;
		
		FD_ZERO(&readfds);
		struct timeval timeout = {1, 1};
		for (struct tftp_socket * iter = &head;
			 iter != NULL; iter = iter->t_next) {
			max_file = max_file < iter->t_file? iter->t_file: max_file;
			FD_SET(iter->t_file, &readfds);
		}
		count = select(max_file + 1, &readfds, NULL, NULL, &timeout);
		assert(count != -1);
		for (struct tftp_socket * iter = &head;
			 iter != NULL; iter = iter->t_next) {
			if ( FD_ISSET(iter->t_file, &readfds) ) {
				sa_len = sizeof(addr1);
				printf("Wait for next request!\n");
				len = recvfrom(iter->t_file, buf, sizeof(buf), 0,
							   sa_addr, &sa_len);
				if (len <= 0)
					continue;
				
				psess = tftp_find(sa_addr);
				if (psess != NULL) {
					if (iter->t_file == psess->t_file)
						process_session(psess, buf, len);
					if (iter->t_flags & TF_FIN)
						;
					continue;
				}
				if (psess->t_file == fd1) {
					psess = create_session(fd1, buf, len, sa_addr, sa_len);
					if (psess != NULL)
						;
					continue;
				}
				printf("receive unexpected packet!\n");
			}
		}
	}
	printf("WSAGetLastError %d\n", WSAGetLastError());
	close(fd1);
	return 0;

}

int main(int argc, char* argv[])
{
	WSADATA data;
	WSAStartup(0x101, &data);
	tftpd_run(argc, argv);
	WSACleanup();
	return 0;
}

#include <stdio.h>
#include <assert.h>
#include <winsock.h>

struct dns_query_packet {
	unsigned short q_ident;
	unsigned short q_flags;
	unsigned short q_qdcount;
	unsigned short q_ancount;
	unsigned short q_nscount;
	unsigned short q_arcount;
};

const char * dns_extract_name(char * name, size_t namlen,
		const char * dnsp, const char * finp)
{
	int partlen;
	char nouse = '.';
	char * lastdot = &nouse;

	if (dnsp == finp)
		return finp;

	partlen = (unsigned char)*dnsp++;
	while (partlen) {
		if (dnsp + partlen > finp)
			return finp;

		if (namlen > partlen + 1) {
			memcpy(name, dnsp, partlen);
			namlen -= partlen;
			name += partlen;
			dnsp += partlen;

			lastdot = name;
			*name++ = '.';
			namlen--;
		}

		if (dnsp == finp)
			return finp;
		partlen = (unsigned char)*dnsp++;
	}

	*lastdot = 0;
	return dnsp;
}

const char * dns_extract_value(void * valp, size_t size,
		const char * dnsp, const char * finp)
{
	if (dnsp + size > finp)
		return finp;

	memcpy(valp, dnsp, size);
	dnsp += size;
	return dnsp;
}

char * dns_copy_name(char *outp, const char * name)
{
	int count = 0;
	char * lastdot = outp++;

	while (*name) {
		if (*name == '.') {
			assert(count > 0 && count < 64);
			*lastdot = count;
			name++;

			lastdot = outp++;
			count = 0;
			continue;
		}

		*outp++ = *name++;
		count++;
	}

	*lastdot = count;
	*outp++ = 0;

	return outp;
}

char * dns_copy_value(char *outp, void * valp, size_t count)
{
	memcpy(outp, valp, count);
	return (outp + count);
}

int do_remote_dns_query(const char *domain, u_long *buf, size_t count)
{
	int fd;
	int error;
	struct sockaddr_in in_addr1;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		return -1;

	in_addr1.sin_family = AF_INET;
	in_addr1.sin_port   = htons(8567);
	in_addr1.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	error = connect(fd, (struct sockaddr *)&in_addr1, sizeof(in_addr1));
	if (error == -1) {
		closesocket(fd);
		return -1;
	}

	error = send(fd, domain, strlen(domain), 0);
	if (error != strlen(domain)) {
		closesocket(fd);
		return -1;
	}

	error = recv(fd, (char *)buf,  count * sizeof(u_long), 0);

	closesocket(fd);
	return error;
}

int dns_query(char * s_buf, size_t size, const char * buf, size_t len)
{
	int outlen;
	char *outp;
	char name[1024];
	const char *queryp;
	const char *finishp;
	unsigned short type, dnscls;
	struct dns_query_packet *dnsp, *dnsoutp;

#if 0
	int udpfd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in in_addr1;
	in_addr1.sin_family = AF_INET;
	in_addr1.sin_port   = htons(53);
	in_addr1.sin_addr.s_addr = inet_addr("8.8.8.8");
	sendto(udpfd, buf, len, 0,
			(struct sockaddr *)&in_addr1, sizeof(in_addr1));
	fprintf(stderr, "l%d\n", len);
	int count = recv(udpfd, s_buf, size, 0);
	closesocket(udpfd);
	{
		FILE * lf = fopen("C:\\LOG.dat", "wb");
		fwrite(s_buf, count, 1, lf);
		fclose(lf);
	}
	fprintf(stderr, "%d\n", count);
	return count;
#endif

	dnsp = (struct dns_query_packet *)buf;
	dnsp->q_flags = ntohs(dnsp->q_flags);
	dnsp->q_qdcount = ntohs(dnsp->q_qdcount);
	dnsp->q_ancount = ntohs(dnsp->q_ancount);
	dnsp->q_nscount = ntohs(dnsp->q_nscount);
	dnsp->q_arcount = ntohs(dnsp->q_arcount);

	if (dnsp->q_flags == 0x100 &&
			dnsp->q_qdcount == 1 &&
			dnsp->q_ancount == 0 &&
			dnsp->q_nscount == 0 &&
			dnsp->q_arcount == 0) {
		queryp = (char *)(dnsp + 1);
		finishp = buf + len;
		queryp = dns_extract_name(name, sizeof(name), queryp, finishp);
		queryp = dns_extract_value(&type, sizeof(type), queryp, finishp);
		queryp = dns_extract_value(&dnscls, sizeof(dnscls), queryp, finishp);

		printf("\nlen %d\n", len);
		printf("qustion %d\n", dnsp->q_qdcount);
		printf("answer  %d\n", dnsp->q_ancount);
		printf("name %d\n", dnsp->q_nscount);
		printf("addition %d\n", dnsp->q_nscount);
		printf("type %d, class %d\n", ntohs(type), ntohs(dnscls));

		if (type == htons(28))
			type = htons(1);

		if (ntohs(type) == 28 && ntohs(dnscls) == 1) {
			dnsoutp = (struct dns_query_packet *)s_buf;
			dnsoutp->q_flags = ntohs(0x8183);
			dnsoutp->q_ident = dnsp->q_ident;
			dnsoutp->q_qdcount = ntohs(1);
			dnsoutp->q_ancount = ntohs(0);
			dnsoutp->q_nscount = ntohs(0);
			dnsoutp->q_arcount = ntohs(0);

			outp = (char *)(dnsoutp + 1);
			outlen = queryp - (const char *)(dnsp + 1);
			memcpy(outp, dnsp + 1, outlen);
			outp += outlen;

#if 0
			outp = dns_copy_name(outp, name);
			outp = dns_copy_value(outp, &type, sizeof(type));
			outp = dns_copy_value(outp, &dnscls, sizeof(dnscls));

			int ttl = htonl(3600);
			unsigned short dnslen = htons(16);
			unsigned long dnsaddr[4] = {INADDR_LOOPBACK, 3, 4, 8};

			outp = dns_copy_value(outp, &ttl, sizeof(ttl));
			outp = dns_copy_value(outp, &dnslen, sizeof(dnslen));
			outp = dns_copy_value(outp, dnsaddr, sizeof(dnsaddr));
#endif
			return outp - s_buf;
		} else if (ntohs(type) == 1 && ntohs(dnscls) == 1) {
			int i;
			struct hostent * hp;
			dnsoutp = (struct dns_query_packet *)s_buf;
			dnsoutp->q_flags = ntohs(0x8180);
			dnsoutp->q_ident = dnsp->q_ident;
			dnsoutp->q_qdcount = ntohs(1);
			dnsoutp->q_nscount = ntohs(0);
			dnsoutp->q_arcount = ntohs(0);

			outp = (char *)(dnsoutp + 1);
			outlen = queryp - (const char *)(dnsp + 1);
			memcpy(outp, dnsp + 1, outlen);
			outp += outlen;


			u_long h_addr_list[20];
			int error = do_remote_dns_query(name, h_addr_list, 20);

			for (i = 0; error != -1 && i < error / 4; i++) {
				outp = dns_copy_name(outp, name);
				outp = dns_copy_value(outp, &type, sizeof(type));
				outp = dns_copy_value(outp, &dnscls, sizeof(dnscls));

				int ttl = htonl(3600);
				unsigned short dnslen = htons(4);
				unsigned long dnsaddr = htonl(INADDR_LOOPBACK);

				memcpy(&dnsaddr, &h_addr_list[i], sizeof(dnsaddr));
				outp = dns_copy_value(outp, &ttl, sizeof(ttl));
				outp = dns_copy_value(outp, &dnslen, sizeof(dnslen));
				outp = dns_copy_value(outp, &dnsaddr, sizeof(dnsaddr));
			}

			dnsoutp->q_ancount = ntohs(i);
			return (outp - s_buf);
		}
	}

	return 0;
}

int main(int argc, char * argv[])
{
	int error;
	int count;
	int sockfd;
	int in_len1;
	WSADATA data;
	char buf[2048], s_buf[2048];
	struct sockaddr_in in_addr1;

	WSAStartup(0x101, &data);
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	assert(sockfd != -1);

	do {
		int rcvbufsiz = 8192;
		setsockopt(stat.xs_file, SOL_SOCKET, SO_RCVBUF, &rcvbufsiz, sizeof(rcvbufsiz));
	} while ( 0 );

	in_addr1.sin_family = AF_INET;
	in_addr1.sin_port   = htons(53);
	in_addr1.sin_addr.s_addr = htonl(INADDR_ANY);
	error = bind(sockfd, (struct sockaddr *)&in_addr1, sizeof(in_addr1));
	assert(error == 0);

	do {
		in_len1 = sizeof(in_addr1);
		count = recvfrom(sockfd, buf, sizeof(buf), 0,
				(struct sockaddr *)&in_addr1, &in_len1);
		if (count < 12)
			continue;
		count = dns_query(s_buf, sizeof(s_buf), buf, count);
		if (count < 12)
			continue;
		count = sendto(sockfd, s_buf, count, 0,
				(struct sockaddr *)&in_addr1, in_len1);
		if (count == -1)
			fprintf(stderr, "sendto: %d\n", WSAGetLastError());
		fprintf(stderr, "sendto: len = %d\n", count);
	} while (1);

	closesocket(sockfd);

	WSACleanup();
	return 0;
}


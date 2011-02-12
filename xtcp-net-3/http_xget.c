#include <stdio.h>
#include <assert.h>
#include <winsock.h>

int send_full(int fd, const void * buf, size_t len, int flag)
{
	int count;
	size_t off = 0;
	const char * p = (const char * )buf;

	while (off < len) {
		count = send(fd, p, len - off, flag);
		if (count == -1)
			break;
		off += count;
		p += count;
	}

	return off;
}

struct in_addr inaddr_convert(const char * str)
{
	struct in_addr addr;
	struct hostent * hostent;

	const char * test = str;

	while (*test) {
		char ch = *test++;

		if (ch == '.' ||
				'0' <= ch && ch <= '9')
			continue;

		addr.s_addr = INADDR_NONE;
		hostent = gethostbyname(str);
		if (hostent)
			addr.s_addr = *(u_long *)hostent->h_addr_list[0];

		return addr;
	}

	addr.s_addr = inet_addr(str);
	return addr;
}

const char * get_schema(const char * url, char * schema, size_t len)
{
	if (strncmp(url, "http://", 7) == 0) {
		strncpy(schema, "http://", len);
		return (url + 7);
	}

	fprintf(stderr, "unkown schema\n");
	return url;
}

const char * get_hostname(const char * url, char * hostname, size_t len)
{
	while (*url) {
		switch (*url) {
			case '/':
			   	if (len > 0)
				   	*hostname = 0;
				return url;

			case ':':
			   	if (len > 0)
				   	*hostname = 0;
				return url;

			default:
				if (len > 1) {
					*hostname++ = *url;
					len--;
				}
				break;
		}

		url++;
	}

	if (len > 0)
		*hostname = 0;
	return url;
}

const char * get_porttext(const char * url, char * porttext, size_t len)
{
	if (*url != ':') {
		strncpy(porttext, "80", len);
		return url;
	}

	url++;
	while (*url) {
		switch (*url) {
			case '/':
			   	if (len > 0)
				   	*porttext = 0;
				return url;

			default:
				if (len > 1) {
					*porttext ++ = *url;
					len--;
				}
				break;
		}

		url++;
	}

	if (len > 0)
		*porttext = 0;

	return url;
}

const char * get_url_path(const char * url, char * url_path, size_t len)
{
	int c = len;

	if (*url != '/') {
		strncpy(url_path, "/", len);
		return url;
	}

	while ((c-- > 0) && (*url_path++ = *url++));
	return url;
}

int http_xget(const char * url, const char * out)
{
	int fd;
	int err;
	int len;
	char buf[8192];
	char schema[8];
	char porttext[8];
	char hostname[256];
	char url_path[512];
	const char * partial_url;
	struct sockaddr_in name;

	partial_url = get_schema(url, schema, sizeof(schema));
	partial_url = get_hostname(partial_url, hostname, sizeof(hostname));
	partial_url = get_porttext(partial_url, porttext, sizeof(porttext));
	partial_url = get_url_path(partial_url, url_path, sizeof(url_path));

	//fd = xopen();
	fd = socket(AF_INET, SOCK_STREAM, 0);
	assert(fd != -1);

	name.sin_family = AF_INET;
	name.sin_port = htons(atoi(porttext));
	name.sin_addr = inaddr_convert(hostname);

	printf("host: %s\n", hostname);
	err = connect(fd, (struct sockaddr *)&name, sizeof(name));
	assert(err == 0);

	sprintf(buf, "GET %s HTTP/1.0\r\n\r\n", url_path);
	len = send_full(fd, buf, strlen(buf), 0);
	assert(len == strlen(buf));

	len = recv(fd, buf, sizeof(buf) - 1, 0);
	while (len > 0) {
		buf[len] = 0;
		printf("%s", buf);
		len = recv(fd, buf, sizeof(buf), 0);
	}

	closesocket(fd);

#if 0
	xconnect(fd, &name, sizeof(name));
	xwrite(fd, buf, strlen(buf));
	xread(fd, buf, sizeof(buf));
	xclose(fd);
#endif

	return 0;
}

int main(int argc, char * argv[])
{
	int i;
	WSADATA data;
	char * filename = NULL;

	for (i = 1; i < argc; i++) {
		char * line = argv[i];

		if (strcmp(line, "-O") == 0) {
			filename = argv[++i];
			continue;
		}

		if (*line == '-' && *line != '\0') {
			printf("%s: illegal option -- %s\n",
					argv[0], line + 1);
			return -1;
		}
	}

	WSAStartup(0x101, &data);
	// xreq_init(1234);
	for (i = 1; i < argc; i++) {
		char * line = argv[i];

		if (strcmp(line, "-O") == 0) {
			++i;
			continue;
		}

		http_xget(line, filename);
	}
	// xreq_clean();
	WSACleanup();

	return 0;
}


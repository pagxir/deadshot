#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <signal.h>
#include <assert.h>

struct waitcb;

static char search[] = {
	"M-SEARCH * HTTP/1.1\r\n"
	"HOST: 239.255.255.250:1900\r\n"
	"MAN: \"ssdp:discover\"\r\n"
	"MX: 5\r\n"
	"ST: %s\r\n"
	"\r\n"
};

static char *devices[] = {
	"urn:schemas-upnp-org:service:WANPPPConnection:1",
	"urn:schemas-upnp-org:service:WANIPConnection:1",
#if 0
	"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
	"UPnP:rootdevice",
#endif
	NULL
};

static void out_of_time(int second)
{
	exit(-1);
	return;
}

void put_location(char* head)
{
	char sch;
	char *sp, *ep;

	ep = strstr(head, "Location:");
	if (ep == NULL)
		ep = strstr(head, "LOCATION:");
	if (ep == NULL)
		return;

	sp = ep + 9;
	while (*sp == ' ')
		sp++;

	ep = sp;
	while (*ep != '\r' && *ep != '\n' && *ep)
		ep++;

	sch = *ep;
	*ep = 0;

	fprintf(stderr, "%s\n", sp);
	*ep = sch;
	return;
}

int UPnPSearch(const char *domain)
{
	int n;
	int i, s, err;
	int broadcast;
	char buffer[4096];
	struct sockaddr_in addr;

	s = socket(AF_INET, SOCK_DGRAM, 0);

	broadcast = 1;
	addr.sin_family = AF_INET;
	addr.sin_port   = htons(1900);
	addr.sin_addr.s_addr = inet_addr(domain? domain: "239.255.255.250");
	err = setsockopt(s, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
	assert(err == 0);

	signal(SIGALRM,out_of_time);
	for (i = 0; devices[i]; i++) {
		int n = sprintf(buffer, search, devices[i]);
		sendto(s, buffer, n, 0, (struct sockaddr *)&addr, sizeof(addr));
	}

	alarm(2);
	for (i = 0; i < 5; i++) {
		n = recv(s, buffer, sizeof(buffer) - 1, 0);
		if (n > 0) {
			buffer[n] = 0;
			printf("%s", buffer);
			put_location(buffer);
			printf("\n");
		}
	}

	close(s);
	return 0;
}

static char msg[] =	{
	"POST %s HTTP/1.1\r\n"
		"HOST: %s%s\r\n"
		"Content-Length: %d\r\n"
		"Content-Type: text/xml; charset=\"utf-8\"\r\n"
		"Proxy-Authorization: Basic cHJveHk6QWRabkdXVE0wZExU\r\n"
		"Connection: close\r\n"
		"SOAPACTION: %s#%s\r\n"
};

static char body[] = {
	"<s:Envelope\r\n"
		"    xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\""
		"    s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n"
		"  <s:Body>\r\n"
		"    <u:%s xmlns:u=\"%s\">\r\n"
		"%s"
		"    </u:%s>\r\n"
		"  </s:Body>\r\n"
		"</s:Envelope>\r\n"
};

typedef struct {
	int count;
	int held_len;
	char *names[16];
	char *values[16];
	char  held_data[4096];
} UPnPData;

typedef struct {
	char *port;
	char *path;
	char *domain;
	char *schema;
	char held_data[1024];
	const char *orig_url;
} UPnPDev;

int UPnPSend(UPnPDev *dev, const char *action,
		const UPnPData *inp, UPnPData *outp, struct waitcb *cbp)
{
	int i, n, s, l;
	struct sockaddr_in addr;

	char *p;
	char title[1024];
	char param[8192];
	char content[16384];
	char datagram[16384];

	p = param;
	for (i = 0; i < inp->count; i++) {
		p += sprintf(p, "	<New%s>",  inp->names[i]);
		if (inp->values[i] != NULL)
			p += sprintf(p, "%s", inp->values[i]);
		p += sprintf(p, "</New%s>\r\n", inp->names[i]);
	}

	n = sprintf(content, body, action, dev->schema, param, action);
	sprintf(title, msg, dev->orig_url, dev->domain, dev->port, n + 2, dev->schema, action);
	n = sprintf(datagram, "%s\r\n%s\r\n", title, content);

	s = socket(AF_INET, SOCK_STREAM, 0);
	addr.sin_family = AF_INET;
	addr.sin_port   = htons(*dev->port == ':'? atoi(dev->port + 1): 80);
	addr.sin_port   = htons(1080);
	addr.sin_addr.s_addr = inet_addr(dev->domain);
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	if (-1 == connect(s, (struct sockaddr *)&addr, sizeof(addr))) {
		printf("Connect fail\n");
		exit(-1);
	}

	signal(SIGALRM, out_of_time);
	alarm(25);
	l = send(s, datagram, n, 0);
	assert(l == n);

	do {
		char buf[1024];
		n = recv(s, buf, sizeof(buf) - 1, 0);
		if (n > 0) {
			buf[n] = 0;
			printf("%s", buf);
		}
	} while (n > 0);

	close(s);
	return 0;
}

int UPnPString(UPnPData *data, const char *name, const char *value)
{
	int len;
	int index = data->count++;
	char *held_data = data->held_data + data->held_len;

	data->names[index] = held_data;
	strcpy(held_data, name);
	len = strlen(name) + 1;
	data->held_len += len;

	if (value == NULL) {
		data->values[index] = NULL;
		return 0;
	}

	data->values[index] = held_data + len;
	strcpy(held_data + len, value);
	len = strlen(value) + 1;
	data->held_len += len;
	return 0;
}

int GetGenericPortMappingEntry(UPnPDev *dev, const char *index)
{
	UPnPData pnpData = {0, 0};
	/* xmlns:dt=\"urn:schemas-microsoft-com:datatypes\" dt:dt=\"ui2\" */
	UPnPString(&pnpData, "PortMappingIndex", index);
	return UPnPSend(dev, "GetGenericPortMappingEntry", &pnpData, NULL, NULL);
}

int DeletePortMapping(UPnPDev *dev, const char *RemoteHost,
		const char *ExternalPort, const char *Protocol)
{
	UPnPData pnpData = {0, 0};
	UPnPString(&pnpData, "RemoteHost", RemoteHost);
	UPnPString(&pnpData, "ExternalPort", ExternalPort);
	UPnPString(&pnpData, "Protocol", Protocol);
	return UPnPSend(dev, "DeletePortMapping", &pnpData, NULL, NULL);
}

int AddPortMapping(UPnPDev *dev, const char *RemoteHost,
		const char *ExternalPort, const char *Protocol, 
		const char *InternalPort, const char *InternalClient,
		const char *Enabled, const char *PortMappingDescription, const char *LeaseDuration)
{
	UPnPData pnpData = {0, 0};
	UPnPString(&pnpData, "RemoteHost", RemoteHost);
	UPnPString(&pnpData, "ExternalPort", ExternalPort);
	UPnPString(&pnpData, "Protocol", Protocol);
	UPnPString(&pnpData, "InternalPort", InternalPort);
	UPnPString(&pnpData, "InternalClient", InternalClient);
	UPnPString(&pnpData, "Enabled", Enabled);
	UPnPString(&pnpData, "PortMappingDescription", PortMappingDescription);
	UPnPString(&pnpData, "LeaseDuration", LeaseDuration);
	return UPnPSend(dev, "DeletePortMapping", &pnpData, NULL, NULL);
}

const char *get_schema(const char *url, char *schema, size_t len)
{
	if (strncmp(url, "http://", 7) == 0) {
		strncpy(schema, "http://", len);
		return (url + 7);
	}

	fprintf(stderr, "unkown schema\n");
	return url;
}

const char *get_hostname(const char *url, char *hostname, size_t len)
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

const char *get_porttext(const char *url, char *porttext, size_t len)
{
	if (*url != ':') {
		strncpy(porttext, "", len);
		return url;
	}

	if (len > 1) {
		*porttext++ = *url++;
		len--;
	}

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

const char *get_url_path(const char *url, char *url_path, size_t len)
{
	int c = len;

	if (*url != '/') {
		strncpy(url_path, "/", len);
		return url;
	}

	while ((c-- > 0) && (*url_path++ = *url++));
	return url;
}

static void UPnPDev_Init(UPnPDev *dev, const char *url, const char *schema)
{
	char *p, *limit;
	const char *partial_url;

	p = dev->held_data;
	limit = dev->held_data + sizeof(dev->held_data);
	partial_url = get_schema(url, p, limit - p);
	dev->schema = p;

	p += (strlen(p) + 1);
	partial_url = get_hostname(partial_url, p, limit - p);
	dev->domain = p;

	p += (strlen(p) + 1);
	partial_url = get_porttext(partial_url, p, limit - p);
	dev->port = p;

	p += (strlen(p) + 1);
	partial_url = get_url_path(partial_url, p, limit - p);
	dev->path = p;

	p += (strlen(p) + 1);
	strncpy(p, schema, limit - p);
	dev->schema = p;

	dev->orig_url = url;
}

int main(int argc, char *argv[])
{
	int i;
	UPnPDev device;
	UPnPData pnpData = {0, 0};

	if (argc < 4) {
		printf("delete <url> <schema> <action> [<name>=<value>]...\n");
		printf("GetExternalIPAddress();\n");
		printf("DeletePortMapping(RemoteHost, ExternalPort, Protocol);\n");
		printf("GetGenericPortMappingEntry(PortMappingIndex);\n");
		printf("AddPortMapping(RemoteHost, ExternalPort, Protocol,"
				"InternalPort, InternalClient, Enabled, PortMappingDescription, LeaseDuration);\n");
		printf("schema should be: [urn:schemas-upnp-org:service:WANIPConnection:1]\n");
		printf("\t\t  [urn:schemas-upnp-org:service:WANPPPConnection:1]\n");
		UPnPSearch(NULL);
		return 0;
	}

	UPnPDev_Init(&device, argv[1], argv[2]);
	for (i = 4; i < argc; i++) {
		char *split;
		char pair[1024];

		strcpy(pair, argv[i]);
		split = strchr(pair, '=');
		if (split == NULL)
			continue;
		*split = 0;
		UPnPString(&pnpData, pair, split + 1);
	}

	UPnPSend(&device, argv[3], &pnpData, NULL, NULL);
	return 78;
}


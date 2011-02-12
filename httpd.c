#include <time.h>
#include <ctype.h>
#include <stdio.h>
#include <assert.h>
#include <winsock.h>

#define TF_RDABLE 1
#define TF_WRABLE 2
#define TF_DELETE 4
#define TF_RDEOF  8
#define TF_TIMEOUT 16 
#define close(s) closesocket(s)

struct http_context {
	int file;
	int flags;
	time_t last_rcv;
	void * context;
	struct http_context * next;

	void ( * callback)(void * context);
};

static int _timeout = 30;
static struct http_context * _http_list_header = NULL;

int setnonblock(int fildes)
{
	u_long blockopt = 1;

	ioctlsocket(fildes, FIONBIO, &blockopt);
	return 0;
}

#define CF_URLHDR  1
#define CF_URLFILE 2
#define CF_URLPREPARE 4

struct connect_context {
	struct http_context * context;

	int len;
	int flags;
	char buf[8192];
	int padding;

	int respoff;
	int resplen;
	FILE * respfile;
	char response[8192];
};

int get_request_path(const char * request, char * buf, size_t len)
{
	char * end_slash;
	const char * slash = request;

	assert(len > 0);
	end_slash = (buf + len - 1);
	while (isspace(*slash))
		slash++;

	while (isalpha(*slash))
		slash++;

	if (!isspace(*slash))
		return 0;

	while (isspace(*slash))
		slash++;

	while (*slash &&
		   	!isspace(*slash)) {
		if (len == 0)
			break;
		if (*slash == '\r')
			break;
		if (*slash == '\n')
			break;
		*buf++ = *slash++;
		len--;
	}

	if (len > 0) {
		*buf = 0;
		return 0;
	}

	*end_slash = 0;
	return 0;
}

char resp404_template[] = {
	"HTTP/1.1 404 Not Found\r\n"
	"Server: nginx/0.7.63\r\n"
	"Date: Mon, 03 Jan 2011 12:15:23 GMT\r\n"
	"Content-Type: text/html\r\n"
	"Content-Length: %u\r\n"
	"Connection: close\r\n"
	"\r\n"
};

char resp404_body[] = {
	"<html>\r\n"
	"<head><title>400 Bad Request</title></head>\r\n"
	"<body bgcolor='white'>\r\n"
	"<center><h1>400 Bad Request</h1></center>\r\n"
	"<hr><center>nginx/0.7.63</center>\r\n"
	"</body>\r\n"
    "</html>\r\n"
};

char resp200_template[] = {
	"HTTP/1.1 200 OK\r\n"
	"Date: Mon, 03 Jan 2011 10:54:18 GMT\r\n"
	"Server: BWS/1.0\r\n"
	"Content-Length: %u\r\n"
	"Content-Type: %s\r\n" /* text/html */
	"Expires: Mon, 03 Jan 2011 10:54:18 GMT\r\n"
	"Connection: Close\r\n"
	"\r\n"
};

const char * get_file_type(const char * path)
{
	const char * ext = strrchr(path, '.');

	if (ext == NULL)
	   	return "application/octet-stream";

	if (stricmp(ext, ".swf") == 0)
		return "application/x-shockwave-flash";

	if (stricmp(ext, ".jpg") == 0)
		return "image/jpg";

	if (stricmp(ext, ".png") == 0)
		return "image/png";

	if (stricmp(ext, ".html") == 0)
		return "text/html";

	if (stricmp(ext, ".htm") == 0)
		return "text/html";

	if (stricmp(ext, ".txt") == 0)
		return "text/plain";

	if (stricmp(ext, ".txt") == 0)
		return "text/plain";

	if (stricmp(ext, ".c") == 0)
		return "text/plain";

	if (stricmp(ext, ".cpp") == 0)
		return "text/plain";

	return "application/octet-stream";
}

int create_response_stream(struct connect_context * cc,
	   	struct http_context * hc, const char * path)
{
	FILE * file = NULL;
	long file_len = 0;

	if (*path == '/' && *(path + 1) != 0)
		file = fopen(path + 1, "rb");

	if (file == NULL) {
		printf("not found: %s\n", path);
		sprintf(cc->response, resp404_template, strlen(resp404_body));
		strncat(cc->response, resp404_body, sizeof(cc->response));
		cc->resplen = strlen(cc->response);
		return 0;
	}

	cc->respfile = file;
	fseek(file, 0, SEEK_END);
	file_len = ftell(file);
	rewind(file);

	sprintf(cc->response, resp200_template,
		   	file_len, get_file_type(path));
	cc->resplen = strlen(cc->response);
	cc->flags |= CF_URLFILE;
	cc->respoff = 0;

	//printf("request: %s\n", path);
	return 0;
}

int fill_buffer(struct connect_context * cc, struct http_context * hc)
{
	int off, readed;
	int total = 0;

	off = cc->len;
	if (off == sizeof(cc->buf)) {
		hc->flags |= TF_DELETE;
		cc->padding = 0;
		return 0;
	}

	readed = recv(hc->file, cc->buf + off, sizeof(cc->buf) - off, 0);

	while (readed > 0) {
		total += readed;
		cc->len += readed;
		off = cc->len;
		hc->last_rcv = time(NULL);
		readed = recv(hc->file, cc->buf + off, sizeof(cc->buf) - off, 0);
	}

	if (readed == -1 &&
		   	WSAGetLastError() == 10035) {
		hc->flags |= TF_RDABLE;
	}
	
	if (readed == 0) {
		hc->flags |= TF_RDEOF;
	}

	if (cc->len < sizeof(cc->buf)) {
		cc->buf[cc->len] = 0;
	}

	cc->padding = 0;
	return total;
}

void connect_callback(void * context)
{
	int off;
	char path[4096];
	struct http_context * hc;
	struct connect_context * cc;

	cc = (struct connect_context *) context;
	hc = (struct http_context *) cc->context;

	assert((hc->flags & TF_DELETE) == 0);

	if ((cc->flags & CF_URLHDR) == 0) {
		fill_buffer(cc, hc);
		if (strstr(cc->buf, "\r\n\r\n") ||
				(hc->flags & TF_RDEOF) == TF_RDEOF)
		   	cc->flags |= CF_URLHDR;
	}

	if ((cc->flags & (CF_URLPREPARE| CF_URLHDR)) == CF_URLHDR) {
		get_request_path(cc->buf, path, sizeof(path));
		create_response_stream(cc, hc, path);
		printf("path: %s\n", path);
		cc->flags |= CF_URLPREPARE;
	}

resend:
	if (cc->respoff < cc->resplen) {
		int writed;
		int respoff = cc->respoff;
		int resplen = cc->resplen;
		char * response = cc->response + respoff;

		writed = send(hc->file, response, resplen - respoff, 0); 
		while (writed > 0 && respoff < resplen) {
			response += writed;
			respoff += writed;
			hc->last_rcv = time(NULL);
			if (respoff == resplen)
				break;
			writed = send(hc->file, response, resplen - respoff, 0); 
		}

		if (writed == -1 &&
			   	WSAGetLastError() != 10035) {
			hc->flags |= TF_DELETE;
		}

		if (writed == -1 &&
				WSAGetLastError() == 10035) {
			hc->flags |= TF_WRABLE;
		}

		cc->respoff = respoff;
		cc->resplen = resplen;
	}

	if (cc->respoff == cc->resplen &&
			(cc->flags & CF_URLFILE) == CF_URLFILE) {
		cc->resplen = fread(cc->response, 1,
			   	sizeof(cc->response), cc->respfile);
		cc->respoff = 0;
		if (cc->resplen > 0)
		   	goto resend;
		hc->flags |= TF_DELETE;
	}

	if (hc->last_rcv + _timeout < time(NULL) ||
			cc->respoff == cc->resplen &&
		   	(cc->flags & (CF_URLHDR| CF_URLFILE)) == CF_URLHDR) {
		hc->flags |= TF_DELETE;
	}

	if (hc->flags & TF_DELETE) {
		if (cc->flags & CF_URLFILE) {
			cc->flags &= ~CF_URLFILE;
			fclose(cc->respfile);
			cc->respfile = NULL;
		}
		free(hc->context);
		hc->context = NULL;
	}

   	assert(hc->flags & (TF_WRABLE| TF_RDABLE| TF_DELETE));
	return;
}

void httpd_new_connection(int client)
{
	struct http_context * ctx;
	struct connect_context * connect_context;

	ctx = (struct http_context *)malloc(sizeof(struct http_context));
	ctx->file = client;
	ctx->flags = TF_RDABLE| TF_WRABLE| TF_TIMEOUT;

	connect_context = (struct connect_context *)malloc(sizeof(struct connect_context));
	ctx->context = connect_context;
	ctx->callback = connect_callback;
	ctx->last_rcv = time(NULL);

	memset(connect_context, 0, sizeof(struct connect_context));
	connect_context->context = ctx;

	ctx->next = _http_list_header;
	_http_list_header = ctx;

	return;
}

void httpd_callback(void * context)
{
	int i_len;
	int client;
	struct http_context * ctx;
	struct sockaddr_in i_addr;
   	ctx = (struct http_context *)context;

	i_len = sizeof(i_addr);
	client = accept(ctx->file, (struct sockaddr *)&i_addr, &i_len);
	while (client != -1) {
		setnonblock(client);
		httpd_new_connection(client);
		printf("accept: %d %s:%d\n", client, 
			   	inet_ntoa(i_addr.sin_addr), ntohs(i_addr.sin_port));
	   	client = accept(ctx->file, (struct sockaddr *)&i_addr, &i_len);
	}

	ctx->flags |= TF_RDABLE;
	return;
}

int main(int argc, char * argv[])
{
	int error;
	WSADATA data;
	int client, httpd, count;
	struct sockaddr_in addr;
	struct http_context * httpdctx;

	WSAStartup(0x101, &data);
	httpd = socket(AF_INET, SOCK_STREAM, 0);
	assert(httpd != -1);

	addr.sin_family = AF_INET;
	addr.sin_port   = htons(7788);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	error = bind(httpd, (const struct sockaddr *)&addr, sizeof(addr));
	assert(error == 0);

	error = listen(httpd, 5);
	assert(error == 0);

	httpdctx = (struct http_context *)malloc(sizeof(struct http_context));
	assert(httpdctx != NULL);
	httpdctx->file = httpd;
	httpdctx->next = NULL;
	httpdctx->flags = TF_RDABLE;
	httpdctx->context = httpdctx;
	httpdctx->callback = httpd_callback;
	setnonblock(httpd);
	_http_list_header = httpdctx;

	for ( ; ; ) {
		int max_fd = -1;
		struct http_context * ctx;
		struct http_context ** prev_ctx;
		fd_set readfds, writefds;

		FD_ZERO(&readfds);
		FD_ZERO(&writefds);

		prev_ctx = &_http_list_header;
		for (ctx = _http_list_header;
			 ctx != NULL; ctx = *prev_ctx) {

			if (ctx->flags & TF_DELETE) {
				*prev_ctx = ctx->next;
				printf("close %d\n", ctx->file);
				close(ctx->file);
				free(ctx);
				continue;
			}

			if (ctx->flags & TF_RDABLE) {
				max_fd = max(max_fd, ctx->file);
				FD_SET(ctx->file, &readfds);
			}

			if (ctx->flags & TF_WRABLE) {
				max_fd = max(max_fd, ctx->file);
				FD_SET(ctx->file, &writefds);
			}

			prev_ctx = &ctx->next;
		}
		*prev_ctx = NULL;

		struct timeval timeo = {1, 1};

		count = select(max_fd + 1, &readfds, &writefds, NULL, &timeo);

		if (count == -1) {
			break;
		}

		for (ctx = _http_list_header;
			 ctx != NULL; ctx = ctx->next) {
			int need_notify = 0;
			
			if ((ctx->flags & TF_RDABLE) &&
				FD_ISSET(ctx->file, &readfds)) {
				ctx->flags &= ~TF_RDABLE;
				need_notify = 1;
			}

			if ((ctx->flags & TF_WRABLE) &&
				FD_ISSET(ctx->file, &writefds)) {
				ctx->flags &= ~TF_WRABLE;
				need_notify = 1;
			}

			if ((ctx->flags & TF_TIMEOUT) &&
				   	(ctx->last_rcv + _timeout < time(NULL))) {
			   	printf("timeout: \r\n");
			   	need_notify = 1;
			}

			if (need_notify == 0 ||
			   (ctx->flags & TF_DELETE)) {
				continue;
			}

			ctx->callback(ctx->context);
		}
	}

	close(httpd);
	free(httpdctx);

	WSACleanup();
	return 0;
}


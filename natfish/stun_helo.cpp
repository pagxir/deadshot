#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifdef _WIN32_
#include <winsock.h>
typedef int socklen_t;
typedef unsigned long in_addr_t;
typedef unsigned short in_port_t;
#else
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#define LOG_DEBUG(fmt...) log_put(LEVEL_DEBUG, fmt)
#define LOG_INFO(fmt...) log_put(LEVEL_INFO, fmt)
#define LOG_ERROR(fmt...) log_put(LEVEL_ERROR, fmt)
#define LOG_VERBOSE(fmt...) log_put(LEVEL_VERBOSE, fmt)

enum {LEVEL_VERBOSE, LEVEL_DEBUG, LEVEL_INFO, LEVEL_WARNING, LEVEL_ERROR, LEVEL_FATAL};
static int _log_level = LEVEL_INFO;

int log_put(int level, const char *format, ...)
{
	va_list args;

	if (level >= _log_level) {
		va_start(args, format);
		vprintf(format, args);
		va_end(args);
	}

	return 0;
}


enum noop_subtype {NOOP_NOOP, NOOP_CONTINUE, NOOP_PONG, NOOP_ACCEPT, NOOP_UNKOWN};
enum session_method {REQUEST, ACCEPT, NOOP, PING, SELECT, REJECT, SELECTED, UNKOWN_METHOD};

struct frame_t {
	int type;
	int subtype;
	int seq, ack;
	char session[64];
	char src[64], dst[64];

	time_t birth;
	time_t refresh;
	struct sockaddr_in6 via;
};

struct nat_session_t {
	char name[64];
	int una_seq;
	int nxt_seq;
	int rcv_nxt;
	int init_seq;
	int ping_seq;
	int accept_seq;
	int short_ttl, got_ping, select;
	int output, send_ack;

	char peer[64];
	const char *self;
	struct sockaddr_in6 gateway;

	struct frame_t frames[2];
};

#define HELP_CHANNEL 0
#define PEER_CHANNEL 1
#define PEER_CHANNEL_MASK (1 << PEER_CHANNEL)
#define HELP_CHANNEL_MASK (1 << HELP_CHANNEL)

static noop_subtype noop_by_name(const char *name)
{
	if (strcmp(name, "CONTINUE") == 0) {
		return NOOP_CONTINUE;
	} else if (strcmp(name, "ACCEPT") == 0) {
		return NOOP_ACCEPT;
	} else if (strcmp(name, "PONG") == 0) {
		return NOOP_PONG;
	}

	return NOOP_UNKOWN;
}

static const char * method_to_name(int type)
{
	switch (type) {
		case REQUEST: return "REQUEST";
		case ACCEPT: return "ACCEPT";
		case NOOP: return "NOOP";
		case PING: return "PING";
		case SELECT: return "SELECT";
		case SELECTED: return "SELECTED";
		case REJECT: return "REJECT";
	}

	return "UNKOWN_METHOD";
}

static session_method method_by_name(const char *name)
{
	if (strncmp(name, "REQUEST", 7) == 0) {
		return REQUEST;
	} else if (strncmp(name, "NOOP", 4) == 0) {
		return NOOP;
	} else if (strncmp(name, "PING", 4) == 0) {
		return PING;
	} else if (strncmp(name, "REJECT", 6) == 0) {
		return REJECT;
	} else if (strncmp(name, "SELECTED", 8) == 0) {
		return SELECTED;
	} else if (strncmp(name, "SELECT", 6) == 0) {
		return SELECT;
	} else if (strncmp(name, "ACCEPT", 6) == 0) {
		return ACCEPT;
	}

	return UNKOWN_METHOD;
}

static int get_method_name(char *buf, int type, int subtype)
{
	const char *name = "";
	const char *subname = "";

	if (type == NOOP) {
		switch (subtype) {
			case NOOP_PONG:
				subname = "PONG";
				break;

			case NOOP_ACCEPT:
				subname = "ACCEPT";
				break;

			case NOOP_CONTINUE:
				subname = "CONTINUE";
				break;
		}

		return sprintf(buf, "NOOP %s", subname);
	}

	switch (type) {
		case REQUEST:
			name = "REQUEST";
			break;

		case ACCEPT:
			name = "ACCEPT";
			break;

		case SELECT:
			name = "SELECT";
			break;

		case PING:
			name = "PING";
			break;

		case REJECT:
			name = "REJECT";
			break;

		case SELECTED:
			name = "SELECTED";
			break;

		default:
			name = "NOOP UNKOWN";
			break;
	}

	return sprintf(buf, "%s", name);
}

enum field_member { fm_ack, fm_seq, fm_via, fm_dst, fm_src, fm_session, fm_unkown };

static int field_by_name(const char *name)
{
	if (strcmp(name, "ack") == 0) {
		return fm_ack;
	} else if (strcmp(name, "seq") == 0) {
		return fm_seq;
	} else if (strcmp(name, "dst") == 0) {
		return fm_dst;
	} else if (strcmp(name, "via") == 0) {
		return fm_via;
	} else if (strcmp(name, "src") == 0) {
		return fm_src;
	} else if (strcmp(name, "session") == 0) {
		return fm_session;
	}

	return fm_unkown;
}

#define TYPE_CHAR(v) (char *)v

static frame_t *nat_parse_frame(const char *buf)
{
	int port;
	int first = 1;
	char addr[64];
	char key[128], value[256];
	char* token = strtok(TYPE_CHAR(buf), "\n");
	static struct frame_t frame;
 
	frame.via.sin6_port = 0;
	frame.via.sin6_addr = {};
	for (; (token != NULL); token = strtok(NULL, "\n")) {
		if (first) {
			frame.type = method_by_name(token);
			if (frame.type == NOOP)
				frame.subtype = noop_by_name(token + 5);
			first = 0;
			continue;
		}

		if (2 != sscanf(token, "%[a-z]: %s", key, value)) {
			continue;
		}

		LOG_VERBOSE("key=%s value=%s\n", key, value);
		switch(field_by_name(key)) {
			case fm_session:
				strncpy(frame.session, value, sizeof(frame.session) -1);
				break;

			case fm_seq:
				frame.seq = atoi(value);
				break;

			case fm_ack:
				frame.ack = atoi(value);
				break;

			case fm_via:
				if (2 == sscanf(value, "[%[:a-zA-Z0-9.]]:%d", addr, &port)) {
					int test = inet_pton(AF_INET6, addr, &frame.via.sin6_addr);
					frame.via.sin6_family = AF_INET6;
					frame.via.sin6_port = htons(port);
				}
				break;

			case fm_src:
				strncpy(frame.src, value, sizeof(frame.src) -1);
				break;

			case fm_dst:
				strncpy(frame.dst, value, sizeof(frame.dst) -1);
				break;

			default:
				break;
		}
    }

	return &frame;
}

static nat_session_t session0;
static nat_session_t *get_session_by_frame(frame_t *frame)
{
	return &session0;
}

static frame_t *nat_session_frame(nat_session_t *session, int type, int ch)
{
	frame_t *frame = &session->frames[ch];

	frame->type = type;
	frame->subtype = 0;

	assert(session->nxt_seq <= session->una_seq + 1);
	frame->seq = session->nxt_seq;
	frame->ack = session->rcv_nxt;

	strcpy(frame->src, session->self);
	strcpy(frame->dst, session->peer);
	strcpy(frame->session, session->name);

	memset(&frame->via, 0, sizeof(frame->via));
	session->output |= (1 << ch);
	session->send_ack = 0;
	time(&frame->birth);
	frame->refresh = 0;

	return frame;
}

static void nat_session_request(nat_session_t *session)
{
	frame_t *frame = nat_session_frame(session, REQUEST, HELP_CHANNEL);
	session->nxt_seq++;
	return;
}

static void nat_session_accept(nat_session_t *session)
{
	frame_t *frame = nat_session_frame(session, ACCEPT, HELP_CHANNEL);
	session->accept_seq = frame->seq;
	session->nxt_seq++;
	return;
}

static void nat_session_select(nat_session_t *session)
{
	frame_t *frame = nat_session_frame(session, SELECT, PEER_CHANNEL);
	session->nxt_seq++;
	return;
}

static void nat_session_selected(nat_session_t *session)
{
	frame_t *frame = nat_session_frame(session, SELECTED, PEER_CHANNEL);
	session->nxt_seq++;
	return;
}

static void nat_session_pong(nat_session_t *session)
{
	if (session->output & PEER_CHANNEL_MASK) return;
	frame_t *frame = nat_session_frame(session, NOOP, PEER_CHANNEL);
	frame->subtype = NOOP_PONG;
	return;
}

static void nat_session_ping(nat_session_t *session)
{
	frame_t *frame = nat_session_frame(session, PING, PEER_CHANNEL);
	session->ping_seq = frame->seq;
	session->nxt_seq++;
	return;
}

static void nat_session_continue(nat_session_t *session)
{
	if (session->output & HELP_CHANNEL_MASK) return;
	frame_t *frame = nat_session_frame(session, NOOP, HELP_CHANNEL);
	frame->subtype = NOOP_CONTINUE;
	return;
}

static void nat_session_noop(nat_session_t *session, int ch)
{
	frame_t *frame;
	if (session->output & (1 << ch)) return;
	frame = nat_session_frame(session, NOOP, ch);
	frame->subtype = 0;
	return;
}

static void nat_process_session(frame_t *frame)
{
	char tmp[64];
	int updated = 0;
	nat_session_t *session = get_session_by_frame(frame);

	if ((frame->type == REQUEST ||
				frame->type == ACCEPT) &&
			session->init_seq != frame->seq) {
		if (frame->type == REQUEST) {
			const char *save = session->self;
			memset(session, 0, sizeof(*session));

			session->una_seq = rand() % 1747;
			session->nxt_seq = session->una_seq;
			strcpy(session->name, frame->session);
			strcpy(session->peer, frame->src);
			session->self = save;
		}
		session->init_seq = frame->seq;
		session->rcv_nxt = frame->seq;
		session->output = 0;
		LOG_DEBUG("set session->output=0 by init\n");
		updated = 1;
	} else if (frame->ack > session->una_seq) {
		session->una_seq = frame->ack;
		if (frame->ack >= session->nxt_seq)
			session->output = 0;
		LOG_DEBUG("set session->output=0 by ack %d %d %x\n", frame->ack, session->nxt_seq, session->output);
		updated = 1;
	}

	LOG_DEBUG("nat_process_session: seq=%d rcv_nxt=%d una_seq=%d output=%x\n", frame->seq, session->rcv_nxt, session->una_seq, session->output);
	LOG_DEBUG("nat_process_session: type=%s subtype=%d update=%d\n", method_to_name(frame->type), frame->subtype, updated);

	if (frame->type == NOOP) {
		if (updated == 0) return;
		get_method_name(tmp, frame->type, frame->subtype);
		LOG_INFO("NOOP: %s\n", tmp);
	} else if (frame->seq == session->rcv_nxt) {
		session->frames[0].subtype = 0;
		session->frames[1].subtype = 0;
		session->send_ack = 1;
		session->rcv_nxt++;
		updated = 1;
	} else if (frame->seq < session->rcv_nxt) {
		session->frames[0].subtype = 0;
		session->frames[1].subtype = 0;
		session->send_ack = 1;
	}

	if (updated) {
		switch (frame->type) {
			case REQUEST:
				session->gateway = frame->via;
				nat_session_accept(session);
				session->short_ttl = 1;
				nat_session_pong(session);
				break;

			case ACCEPT:
				session->gateway = frame->via;
				nat_session_continue(session);
				nat_session_ping(session);
				break;

			case SELECT:
				nat_session_selected(session);
				session->select = 1;
				break;

			case REJECT:
			case SELECTED:
				nat_session_noop(session, PEER_CHANNEL);
				session->select = 1;
				break;

			case PING:
				if (memcmp(&session->gateway, &frame->via, sizeof(frame->via)))
					session->gateway = frame->via;
				else 
					session->select = 1;
				nat_session_pong(session);
				session->got_ping = 1;
			case NOOP:
			default:
				if (session->accept_seq > 0 &&
						(session->ping_seq == 0) &&
						(session->accept_seq < session->una_seq))
					nat_session_ping(session);

				if (session->ping_seq > 0 &&
						session->got_ping && !session->select &&
						session->ping_seq < session->una_seq)
					nat_session_select(session);

				break;
		}
	}
}

#define getmappedbybuf(buff, buflen, addrptr, portptr) \
    getaddrbybuf(buff, buflen, MAPPED_ADDRESS, addrptr, portptr)

#define getchangedbybuf(buff, buflen, addrptr, portptr) \
    getaddrbybuf(buff, buflen, CHANGED_ADDRESS, addrptr, portptr)

/*
 * stun.l.google.com:19302
 * stun.ekiga.net:3478
 */

enum {
    BindingRequest = 0x0001,
    BindingResponse = 0x0101,
    BindingErrorResponse = 0x0111,
    MAPPED_ADDRESS = 0x0001,
    CHANGE_REQUEST = 0x0003,
    CHANGED_ADDRESS = 0x0005
};

int do_peer_bearing(struct natcb_t *cb, const char *buf);
int do_bear_exchange(struct natcb_t *cb, const char *buf);
int do_peer_exchange(struct natcb_t *cb, const char *buf);
void do_fork_exec(struct natcb_t *cb, const char *buf);
int set_config_host(struct sockaddr_in6 *target, char *value);

int getaddrbybuf(void *buff, size_t buflen, int type,
        in_addr_t *addrptr, in_port_t *portptr)
{
    int error = -1;
    size_t ix, nx, cut;
    unsigned short hdr[2];
    unsigned char *bp = (unsigned char *)buff;

    for (ix=20,nx=24; nx<=buflen; ix=nx, nx+=4){
        memcpy(hdr, bp+ix, sizeof(hdr));
        cut = ntohs(hdr[1]);
        ix  = nx;
        nx += cut;
        if (htons(hdr[0])!=type)
            continue;
        if (nx > buflen)
            continue;
        if (cut==8 && bp[ix+1]==1){
            memcpy(portptr, bp+ix+2, 2);
            memcpy(addrptr, bp+ix+4, 4);
            error = 0;
        }
        break;
    }
    return error;

}

struct mapping_args{
    unsigned short binding_request, zero_field;
    unsigned int  tid0, tid1, tid2, tid3;
};

struct changing_args{
    unsigned short binding_request, zero_field;
    unsigned int  tid0, tid1, tid2, tid3;
    unsigned short change_request, len_field;
    unsigned char data[4];
};

static int _stid3 = 0;
static struct sockaddr_in  _schgaddr, _sinaddr;
static int have_child_exited = 0;

#ifdef _WIN32_
void __declspec(dllexport) _()
{
}
#endif

struct session_t {
    int sockfd;
    int lastout;

    int ttl;
    int readable;
    char cache[2028];

    time_t interval;
    time_t lastcheck;
    struct sockaddr_in6 target;
};

static char addrbuf[128];
#define ntop6(addr) inet_ntop(AF_INET6, &addr, addrbuf, sizeof(addrbuf))

static const char *inet_4to6(void *v6ptr, const void *v4ptr)
{
	uint8_t *v4 = (uint8_t *)v4ptr;
	uint8_t *v6 = (uint8_t *)v6ptr;

	memset(v6, 0, 10);
	v6[10] = 0xff;
	v6[11] = 0xff;

	v6[12] = v4[0];
	v6[13] = v4[1];
	v6[14] = v4[2];
	v6[15] = v4[3];
	return "";
}

#define MAX_EVENT 10
static int _nevent = 0;
static struct pending_event {void *context; int event; }  _events[MAX_EVENT];

enum {EVENT_PONG, EVENT_PING, EVENT_SESSION_EXECUTE, EVENT_SESSION_PING, EVENT_SESSION_PONG};

static int event_list_push(void *context, int event)
{
	if (_nevent + 1 < MAX_EVENT) {
		_events[_nevent].context = context;
		_events[_nevent].event = event;
		_nevent++;
	}

	return 0;
}

static void dump_peer(const char *title, const void *target)
{
	const struct sockaddr_in6 *inp = (const struct sockaddr_in6 *)target;
	LOG_VERBOSE("%s TO [%s]:%d\n", title, ntop6(inp->sin6_addr), htons(inp->sin6_port));
}

void update_session(struct session_t *s)
{
    int nbyte;
    time_t current;

    if (s->interval == 0 || s->ttl == 0) {
        return;
    }

    time(&current);
    if (current > s->lastcheck && 
            current < s->lastcheck + s->interval) {
        return;
    }

    dump_peer("update_session", &s->target);
    nbyte = sendto(s->sockfd, s->cache, strlen(s->cache), 0,
		    (const struct sockaddr *)&s->target, sizeof(s->target));

    if (s->ttl > 0) {
        s->ttl --;
    }

    s->readable++;
    s->lastout = nbyte;
    s->lastcheck = current;

    return;
}

#define MODE_PAIR 2
#define MODE_ONCE 1

struct natcb_t {
    struct session_t bear;
    struct session_t peer;

    int buflen;
    char stunbuf[2048];

    int mode;
    int ready;
    int passfd;
    int sack_want;
    int exit_child;
    int out_ping;
    int got_pong;
    int got_session_pong;
    int got_session_execute;

    pid_t childpid;
    char ident[128];
    char lock_key[128];
    char session[128];
    char acked_session[128];
    char command[1280];

    socklen_t size;
    struct sockaddr_in6 stun;
    struct sockaddr_in6 from;

	int waiting;
	char *pong_cmd;
	char *session_ping_cmd;
	char *session_pong_cmd;
};

struct natcb_t * natcb_setup(struct natcb_t *cb)
{
    int fd;

#ifdef _WIN32_
    WSADATA data;
    WSAStartup(0x101, &data);
#endif

    cb->bear.sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
    cb->peer.sockfd = socket(AF_INET6, SOCK_DGRAM, 0);

    if (cb->bear.sockfd == -1 ||
            cb->peer.sockfd == -1) {
        close(cb->bear.sockfd);
        close(cb->peer.sockfd);
        return NULL;
    }

    cb->mode = MODE_PAIR;
    cb->peer.interval = 2;
    return cb;
}

int natcb_free(struct natcb_t *cb)
{
#ifdef _WIN32_
    closesocket(cb->peer.sockfd);
    if (cb->peer.sockfd != cb->bear.sockfd)
        closesocket(cb->bear.sockfd);
    WSACleanup();
#else
    close(cb->peer.sockfd);
    if (cb->peer.sockfd != cb->bear.sockfd)
        close(cb->bear.sockfd);
#endif
    return 0;
}

static int MAGIC_MAPPING = 0;
static int MAGIC_CHANGING = 1;

typedef void stun_callback(char *buf, void *udata);

int do_stun_maping(struct natcb_t *cb, stun_callback *callback, void *udata)
{
    int sent;
    struct mapping_args req;

    req.binding_request = htons(BindingRequest);
    req.zero_field      = htons(0);
    req.tid0 = (uint32_t)(uint64_t)&MAGIC_MAPPING;
    req.tid1 = htonl(0x5a5a5a5a);
    req.tid2 = htonl(0xaaaaaaaa);
    req.tid3 = htonl(_stid3++);

    sent = sendto(cb->peer.sockfd, (const char *)&req, sizeof(req), 0, 
            (const struct sockaddr *)&cb->stun, sizeof(cb->stun));

    if (sent > 0) cb->peer.readable++;

    return sent;
}

int do_stun_changing(struct natcb_t *cb, stun_callback *callback, void *udata)
{
    int sent;
    struct changing_args req;

    req.binding_request = htons(BindingRequest);
    req.zero_field = htons(8);
    req.tid0 = (uint32_t)(uint64_t)&MAGIC_CHANGING;
    req.tid1 = htonl(0x5a5a5a5a);
    req.tid2 = htonl(0xaaaaaaaa);
    req.tid3 = htonl(_stid3++);

    req.change_request = htons(CHANGE_REQUEST);
    req.len_field = htons(4);
    req.data[0] = 0;
    req.data[1] = 0;
    req.data[2] = 0;
#ifdef _TEST_SAME_IP
    req.data[3] = 4;
#else
    req.data[3] = 6;
#endif

    sent = sendto(cb->peer.sockfd, (const char *)&req, sizeof(req), 0, 
            (const struct sockaddr *)&cb->stun, sizeof(cb->stun));

    if (sent > 0) cb->peer.readable++;

    return sent;
}

void update_timer_list(struct natcb_t *cb)
{
    update_session(&cb->peer);
    update_session(&cb->bear);
    return;
}

void set_session_action(struct natcb_t *cb, int patch)
{
    int nbyte;
    struct session_t *s = &cb->peer;

    snprintf(s->cache, sizeof(s->cache), "FROM %s SESSION %s PING", cb->ident, cb->session);

    int ttl = 3;
    int ttl_origin = 0;

    if (patch) {
        socklen_t ttl_length = sizeof(ttl_origin);
        if (getsockopt(s->sockfd, IPPROTO_IP, IP_TTL, &ttl, &ttl_length)) {
            if (setsockopt(s->sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl))) patch = 0;
        } else {
            patch = 0;
        }
    }

    dump_peer("set_session_action", &s->target);
    if (patch) {
	nbyte = sendto(s->sockfd, s->cache, strlen(s->cache), 0, (const struct sockaddr *)&s->target, sizeof(s->target));
    }

    if (patch) {
        setsockopt(s->sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl_origin));
    }

    if (nbyte > 0) s->readable++;

    LOG_DEBUG(">> %s set_session_action patch = %d\n", s->cache, patch);
    return;
}

static const char *COMMANDS[] = {
	"REQUEST", "ACCEPT", "PING", "NOOP CONTINUE", "NOOP PONG",
	"REJECT", "NOOP SELECTED", "NOOP", "SELECT", NULL
};

static int is_new_version(const char *title)
{
	int i, n;

	for (i = 0; COMMANDS[i]; i++) {
		const char *command = COMMANDS[i];
		n = strlen(command);
		if (0 == strncmp(command, title, n)) 
			return 1;
	}

	return 0;
}

void do_receive_update(struct natcb_t *cb)
{
    struct sockaddr_in  _schgaddr, _sinaddr;
    struct mapping_args *r = (struct mapping_args *)cb->stunbuf;

    LOG_DEBUG("\r<<<<< from: %s:%d\n",
            ntop6(cb->from.sin6_addr), htons(cb->from.sin6_port));

    if (r->tid0 == (uint32_t)(uint64_t)&MAGIC_MAPPING
            || r->tid0 == (uint32_t)(uint64_t)&MAGIC_CHANGING) {

        if (-1 == getmappedbybuf(cb->stunbuf, cb->buflen,
                    (in_addr_t*)&_schgaddr.sin_addr, &_schgaddr.sin_port))
            return;

        LOG_DEBUG("<<  mapped address: %s:%d\n",
                inet_ntoa(_schgaddr.sin_addr), htons(_schgaddr.sin_port));

        if (-1 == getchangedbybuf(cb->stunbuf, cb->buflen,
                    (in_addr_t*)&_schgaddr.sin_addr, &_schgaddr.sin_port))
            return;

        LOG_DEBUG("<< changed server address: %s:%d\n",
                inet_ntoa(_schgaddr.sin_addr), htons(_schgaddr.sin_port));
    } else if (cb->buflen > 0) {
        LOG_VERBOSE("<<<<<<\n %s\nEND\n", cb->stunbuf);
        // receive FROM dupit8@gmail.com TO pagxir@gmail.com SESSION xxxx EXCHANGE 103.119.224.18:51901
        // send    FROM pagxir@gmail.com TO dupit8@gmail.com SESSION xxxx EXCHANGE 0.0.0.0:0 ACK
        // send    FROM pagxir@gmail.com SESSION xxxx (SYN|SYN+ACK) # check SESSION is receive any packet
        char peer_cmd[2048];
        char from[128], to[128], session[128], exchange[128], flags[128];

		if (is_new_version(cb->stunbuf)) {
			frame_t * frame = nat_parse_frame(cb->stunbuf);
			if (!frame->via.sin6_port) frame->via = cb->from;
			LOG_DEBUG("start nat_parse_frame\n");
			nat_process_session(frame);
			return;
		}

        int match = sscanf(cb->stunbuf, "FROM %s TO %s SESSION %s EXCHANGE %s%s", from, to, session, exchange, flags);
        if (match == 4 || match == 5) {
            set_config_host(&cb->peer.target, exchange);

            if (!strstr(flags, "ACK")) {
                snprintf(peer_cmd, sizeof(peer_cmd), "FROM %s TO %s SESSION %s EXCHANGE 0.0.0.0:0 ACK", cb->ident, from, session);
                do_peer_bearing(cb, peer_cmd);
                cb->sack_want = 1;
            }

            LOG_DEBUG("start session %s handshake %s flags %s\n", session, exchange, flags);
            strcpy(cb->session, session);

            LOG_INFO("reset got_session_pong and got_pong\n");
			if (strcmp(cb->session, cb->acked_session) || cb->sack_want == 0) {
				strcpy(cb->acked_session, "");
				cb->got_session_pong = 0;
				cb->got_pong = 0;
			}

            cb->peer.ttl = 4;
            cb->ready = 0;
	    // set_session_action(cb, !!strstr(flags, "PING"));
			set_session_action(cb, 1);
            return;
        }

        match = sscanf(cb->stunbuf, "FROM %s SESSION %s P%[OING]", from, session, flags);
        if (match == 3) {
            char good_resp[19];
            cb->peer.target = cb->from;

            if (strcmp(flags, "ING") == 0) {
                snprintf(peer_cmd, sizeof(peer_cmd), "FROM %s SESSION %s PONG [%s]:%d", cb->ident, session, ntop6(cb->from.sin6_addr), htons(cb->from.sin6_port));
                do_peer_exchange(cb, peer_cmd);

				event_list_push(cb, EVENT_SESSION_PING);
            } else if (2 == sscanf(cb->stunbuf, "FROM %*s SESSION %*s P%[OING] %s", flags, good_resp) && cb->sack_want){
                snprintf(peer_cmd, sizeof(peer_cmd), "FROM %s TO %s SESSION %s ESTABLISED %s ", cb->ident, from, session, good_resp);
                do_bear_exchange(cb, peer_cmd);
                cb->sack_want = 0;

				cb->got_session_pong = 1;
				event_list_push(cb, EVENT_SESSION_PONG);
            }

            LOG_DEBUG("receive session %s handshake %s %d\n", session, flags, cb->peer.ttl);
            strcpy(cb->acked_session, session);
            cb->peer.ttl = 0;
            return;
        }

        match = sscanf(cb->stunbuf, "FROM %s P%[IONG]", from, flags);
        if (match == 2) {
            int sent = 0;

            if (strcmp(flags, "ING") == 0) {
                sprintf(cb->stunbuf, "FROM %s PONG", cb->ident);
				dump_peer("do_receive_update", &cb->from);
                sent = sendto(cb->peer.sockfd, cb->stunbuf, strlen(cb->stunbuf), 0, 
                        (const struct sockaddr *)&cb->from, sizeof(cb->from));
				event_list_push(cb, EVENT_PING);
            } else if (strcmp(flags, "ONG") == 0) {
                LOG_DEBUG("receive %s %d %s\n", from, sent, flags);
                cb->got_pong = 1;
				event_list_push(cb, EVENT_PONG);
                cb->out_ping = 0;
            }

            return;
        }

        match = sscanf(cb->stunbuf, "FROM %s TO %s SESSION %s COMMAN%[D]", from, to, session, flags);
        if (match == 4 && strcmp(to, cb->ident) == 0) {
            if (strcmp(cb->acked_session, session)) {
                snprintf(peer_cmd, sizeof(peer_cmd), "FROM %s TO %s SESSION %s RST+COMMAND", cb->ident, from, session);
                do_bear_exchange(cb, peer_cmd);
                return;
            }

            LOG_DEBUG("receive session %s command %s\n", session, from);
            snprintf(peer_cmd, sizeof(peer_cmd), "FROM %s TO %s SESSION %s ACK+COMMAND", cb->ident, from, session);
			do_bear_exchange(cb, peer_cmd);

			cb->got_session_execute = 1;
			event_list_push(cb, EVENT_SESSION_EXECUTE);

            return;
        }
    }

    return;
}


void session_receive(struct natcb_t *cb, struct session_t *sb)
{
    cb->size = sizeof(cb->from);
    cb->buflen = recvfrom(sb->sockfd, cb->stunbuf, sizeof(cb->stunbuf) -1,
            0, (struct sockaddr *)&cb->from, &cb->size);

    if (cb->buflen > 0) {
        cb->stunbuf[cb->buflen] = 0;
        do_receive_update(cb);
    }

    return;
}

#define SIZE(len) (sizeof(buf) - len)

static int nat_session_output(struct natcb_t *cb, nat_session_t *session)
{
    char buf[2038];
    frame_t *frame = session->frames;
	int output = session->output;

	frame = &session->frames[PEER_CHANNEL];
    if ((output & PEER_CHANNEL_MASK) && (session->send_ack || frame->refresh < time(NULL))) {
            int len = get_method_name(buf, frame->type, frame->subtype);
            frame->ack = session->rcv_nxt;
            session->send_ack = 0;

            len += snprintf(buf + len, SIZE(len), "\n");
            len += snprintf(buf + len, SIZE(len), "session: %s\n", frame->session);
            len += snprintf(buf + len, SIZE(len), "src: %s\n", frame->src);
            len += snprintf(buf + len, SIZE(len), "dst: %s\n", frame->dst);

            len += snprintf(buf + len, SIZE(len), "seq: %d\n", frame->seq);
            len += snprintf(buf + len, SIZE(len), "ack: %d\n", frame->ack);

            LOG_DEBUG(">>>>>>>>>>>>>>>>> peer: %d via %x >>>>>>>>>>>>>>> \n", len, session->output);
            LOG_DEBUG("%s\n", buf);

            time(&frame->refresh);

            int ttl = 3;
            int ttl_origin = 0;
            int should_reset = 0;
            struct session_t *s = &cb->peer;

            socklen_t ttl_length = sizeof(ttl_origin);
            if (session->short_ttl && !getsockopt(s->sockfd, IPPROTO_IP, IP_TTL, &ttl_origin, &ttl_length))
                should_reset = !setsockopt(s->sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
			LOG_DEBUG("short_ttl: %d %d %d\n", session->short_ttl, ttl_origin, should_reset);

            int nbyte = sendto(s->sockfd, buf, len, 0, (const struct sockaddr *)&session->gateway, sizeof(session->gateway));
			assert(nbyte > 0);

            if (should_reset) {
                setsockopt(s->sockfd, IPPROTO_IP, IP_TTL, &ttl_origin, sizeof(ttl_origin));
                session->short_ttl = 0;
			}

			if (frame->seq < session->una_seq
					|| frame->type == NOOP
					|| frame->refresh > frame->birth + 15)
				session->output &= ~PEER_CHANNEL_MASK;
    }

    if (session->send_ack && !(output & HELP_CHANNEL_MASK)) {
        nat_session_noop(session, HELP_CHANNEL);
        output |= HELP_CHANNEL_MASK;
    }

    frame = &session->frames[HELP_CHANNEL];
    if ((output & HELP_CHANNEL_MASK) && (session->send_ack || frame->refresh < time(NULL))) {
        int len = get_method_name(buf, frame->type, frame->subtype);

        len += snprintf(buf + len, SIZE(len), "\n");
        len += snprintf(buf + len, SIZE(len), "session: %s\n", frame->session);
        len += snprintf(buf + len, SIZE(len), "src: %s\n", frame->src);
        len += snprintf(buf + len, SIZE(len), "dst: %s\n", frame->dst);

        if (!IN6_IS_ADDR_UNSPECIFIED(&frame->via.sin6_addr)) {
            len += snprintf(buf + len, SIZE(len), "via: [%s]:%d\n", ntop6(frame->via.sin6_addr), htons(frame->via.sin6_port));
        } else {
            len += snprintf(buf + len, SIZE(len), "via: GATEWAY\n");
        }

        len += snprintf(buf + len, SIZE(len), "seq: %d\n", frame->seq);
        len += snprintf(buf + len, SIZE(len), "ack: %d\n", frame->ack);

		LOG_DEBUG(">>>>>>>>>>>>>>>>> help: %d via %x >>>>>>>>>>>>>>> \n", len, session->output);
        LOG_DEBUG("%s\n", buf);

		time(&frame->refresh);
		if (frame->seq < session->una_seq
				|| frame->type == NOOP
				|| frame->refresh > frame->birth + 15)
            session->output &= ~HELP_CHANNEL_MASK;

        return do_peer_bearing(cb, buf);
    }

    assert(!session->send_ack);
    return 0;
}

void check_and_receive(struct natcb_t *cb, int usestdin)
{
    fd_set myfds;
    int maxfd = STDIN_FILENO;
    int readycount = 0;
	int save_nevent = _nevent;

    do {
        FD_ZERO(&myfds);
        if (usestdin) {
            FD_SET(STDIN_FILENO, &myfds);
        }

        if (cb->bear.sockfd > 0 && cb->bear.readable) {
            FD_SET(cb->bear.sockfd, &myfds);
            maxfd = cb->bear.sockfd > maxfd? cb->bear.sockfd: maxfd;
        }

        if (cb->peer.sockfd > 0 && cb->peer.readable && cb->mode == MODE_PAIR) {
            FD_SET(cb->peer.sockfd, &myfds);
            maxfd = cb->peer.sockfd > maxfd? cb->peer.sockfd: maxfd;
        }

        struct timeval timeout = {1, 1};
        if (have_child_exited) {
            pid_t child;
            do {
                int wstatus;
                have_child_exited = 0;
                child = waitpid(-1, &wstatus, WNOHANG);
                if (child == cb->childpid)
                    cb->childpid = -1;
            } while (child > 0);
        }

		nat_session_output(cb, &session0);
		if (session0.select == 1 &&
				session0.nxt_seq == session0.una_seq) {
			event_list_push(cb, EVENT_SESSION_PONG);
			cb->peer.target = session0.gateway;
			session0.select++;
		}

		if (cb->waiting == 1 && session0.select == 2) {
			event_list_push(cb, EVENT_SESSION_EXECUTE);
			cb->got_session_execute = 1;
			session0.select++;
		}

        readycount = select(maxfd + 1, &myfds, NULL, NULL, &timeout);
        if (readycount == 0) {
            update_timer_list(cb);
        }

        if (readycount > 0 && cb->peer.readable && FD_ISSET(cb->peer.sockfd, &myfds) && cb->mode == MODE_PAIR) {
            session_receive(cb, &cb->peer);
            readycount--;
        }

        if (readycount > 0 && cb->bear.readable && FD_ISSET(cb->bear.sockfd, &myfds)) {
            session_receive(cb, &cb->bear);
            readycount--;
        }

        if (readycount > 0 && FD_ISSET(STDIN_FILENO, &myfds)) {
            /* handle next command */
            break;
        }

		if (_nevent > save_nevent) {
			break;
		}

    } while ((cb->bear.readable || cb->peer.readable) && usestdin);

    /* process pending events */
    if (cb->waiting == 0) {
	    int nevent = _nevent;
	    _nevent = 0;
	    for (int i = 0; i < nevent; i++) {
		    struct pending_event pe = _events[i];
		    switch (pe.event) {
			    case EVENT_SESSION_PING:
				    setenv("EVENT", "session_ping", 1);
				    do_fork_exec(cb, cb->session_ping_cmd);
				    strcpy(cb->acked_session, "");
				    break;

			    case EVENT_SESSION_PONG:
				    setenv("EVENT", "session_pong", 1);
				    do_fork_exec(cb, cb->session_pong_cmd);
				    break;

			    case EVENT_SESSION_EXECUTE:
				    setenv("EVENT", "session_execute", 1);
					cb->got_session_execute = 0;
					break;

			    case EVENT_PONG:
				    setenv("EVENT", "pong", 1);
				    do_fork_exec(cb, cb->pong_cmd);
				    break;

			    default:
				    LOG_ERROR("unsupported event: %d\n", pe.event);
				    break;
		    }
	    }
    }

    return;
}

int do_peer_exchange(struct natcb_t *cb, const char *buf)
{
    int sent;

	dump_peer("do_peer_exchange", &cb->peer.target);
    sent = sendto(cb->peer.sockfd, buf, strlen(buf), 0, 
            (const struct sockaddr *)&cb->peer.target, sizeof(cb->peer.target));

    if (sent > 0) {
        cb->peer.readable++;
    }

    return sent;
}

int do_peer_bearing(struct natcb_t *cb, const char *buf)
{
    int sent;

	dump_peer("do_peer_bearing", &cb->bear.target);
    sent = sendto(cb->peer.sockfd, buf, strlen(buf), 0, 
            (const struct sockaddr *)&cb->bear.target, sizeof(cb->bear.target));

    if (sent > 0) {
        cb->peer.readable++;
    }

    return sent;
}

int do_bear_exchange(struct natcb_t *cb, const char *buf)
{
    int sent;

	dump_peer("do_peer_exchange", &cb->bear.target);
    sent = sendto(cb->bear.sockfd, buf, strlen(buf), 0, 
            (const struct sockaddr *)&cb->bear.target, sizeof(cb->bear.target));

    if (sent > 0) {
        cb->bear.readable++;
    }

    return sent;
}

int set_config_host(struct sockaddr_in6 *target, char *value0)
{
    char *port;
    char value[128] = {};
    struct hostent *phost;

    strncpy(value, value0, sizeof(value) -1);
    target->sin6_family = AF_INET6;

	if (*value != '[') {
		port = strrchr(value, ':');
		if (port) *port++ = 0;

		target->sin6_port = htons(port? atoi(port): 3478);

		phost = gethostbyname(value);
		if (phost) {
			inet_4to6(&target->sin6_addr, phost->h_addr);
		} else {
			inet_pton(AF_INET6, value, &target->sin6_addr);
		}
	} else {
		port = strrchr(value, ']');
		if (port) *port++ = 0;
		if (port && *port == ':') port++;

		target->sin6_port = htons(port? atoi(port): 3478);
		inet_pton(AF_INET6, value + 1, &target->sin6_addr);
	}

    return 0;
}

void config_ident_lock(struct natcb_t *cb)
{
    int nbyte;
    struct session_t *s = &cb->bear;

    if (*cb->ident && *cb->lock_key) {
        snprintf(cb->bear.cache, sizeof(cb->bear.cache),
                "FROM %s LOCK %s", cb->ident, cb->lock_key);

		dump_peer("config_ident_lock", &s->target);
        nbyte = sendto(s->sockfd, s->cache, strlen(s->cache), 0,
                (const struct sockaddr *)&s->target, sizeof(s->target));

        LOG_INFO(">> %s\n", cb->peer.cache);
        if (nbyte > 0) s->readable++;
        s->ttl = -1;
    }

    return;
}

int nametologlevel(const char *level)
{
	if (strcmp(level, "verbose") == 0) {
		return LEVEL_VERBOSE;
	} else
	if (strcmp(level, "debug") == 0) {
		return LEVEL_DEBUG;
	} else
	if (strcmp(level, "info") == 0) {
		return LEVEL_INFO;
	} else
	if (strcmp(level, "error") == 0) {
		return LEVEL_ERROR;
	} else
	if (strcmp(level, "warn") == 0) {
		return LEVEL_WARNING;
	} else
	if (strcmp(level, "fatal") == 0) {
		return LEVEL_FATAL;
	}

	return LEVEL_INFO;
}

int nametomode(const char *mode, int initval)
{
    if (strcmp(mode, "pair") == 0) {
        return MODE_PAIR;
    }

    if (strcmp(mode, "once") == 0) {
        return MODE_ONCE;
    }

    return initval;
}

void mode_reconfig(struct natcb_t *cb)
{
    switch(cb->mode) {
        case MODE_PAIR:
            if (cb->peer.sockfd == cb->bear.sockfd) {
                cb->peer.sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
                cb->peer.ttl = 0;
            }
            break;

        case MODE_ONCE:
            if (cb->peer.sockfd != cb->bear.sockfd) {
                close(cb->peer.sockfd);
                cb->peer.sockfd = cb->bear.sockfd;
                cb->peer.ttl = 0;
            }
            break;

        default:
            break;
    }

    return;
}

int do_recover_config(struct natcb_t *cb)
{
    switch(cb->mode) {
        case MODE_PAIR:
            close(cb->peer.sockfd);
            cb->peer.sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
            cb->peer.readable = 0;
            cb->peer.ttl = 0;
            break;

        case MODE_ONCE:
            assert(cb->peer.sockfd == cb->bear.sockfd);
            close(cb->peer.sockfd);
            cb->peer.sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
            cb->peer.readable = 0;
            cb->peer.ttl = 0;
            cb->bear.sockfd = cb->peer.sockfd;
            cb->bear.readable = 0;
            cb->peer.ttl = 0;
            config_ident_lock(cb);
            break;

        default:
            break;
    }

    return 0;
}

int do_update_ready(struct natcb_t *cb, const char *buf)
{
    int match;
    char action[128], key[128];

    match = sscanf(buf, "%128s %128s", action, key);

    cb->ready = 0;
    if (match != 2) {
        return 0;
    }

    int dowait = strcmp(action, "wait") == 0;

    if (strcmp(key, "any") == 0) {
        cb->ready = (_nevent > 0);
		dowait = cb->peer.ttl > 0 ||  cb->out_ping > 0 || session0.output;
    } else if (strcmp(key, "session") == 0) {
        cb->ready = cb->got_session_execute;
		dowait = 1;
    } else if (strcmp(key, "session.pong") == 0) {
        cb->ready = cb->got_session_pong;
        dowait = cb->peer.ttl <= 0? 0: dowait;
    } else if (strcmp(key, "pong") == 0) {
        cb->ready = cb->got_pong;
        dowait = cb->out_ping > 0? dowait: 0;
    } else {
        return 0;
    }

    return cb->ready == 0 && dowait;
}

char * do_wrap_command(struct natcb_t *cb, const char *value)
{
	if (strcmp(value, "COMMAND") == 0)
		return cb->command;
	return strdup(value);
}

int do_update_config(struct natcb_t *cb, const char *buf)
{
    int match;
    char action[128], key[128], value[1280];

    match = sscanf(buf, "%128s %128s %128[^\n]", action, key, value);

    if (3 != match) {
        fprintf(stderr, "missing set %d\n", match);
        return 0;
    }

    if (strcmp(key, "bear") == 0) {
        set_config_host(&cb->bear.target, value);
    } else if (strcmp(key, "mode") == 0) {
        cb->mode = nametomode(value, cb->mode);
        mode_reconfig(cb);
    } else if (strcmp(key, "loglevel") == 0) {
        _log_level = nametologlevel(value);
    } else if (strcmp(key, "exitchild") == 0) {
        cb->exit_child = atoi(value);
    } else if (strcmp(key, "peer") == 0) {
        set_config_host(&cb->peer.target, value);
    } else if (strcmp(key, "stun") == 0) {
        set_config_host(&cb->stun, value);
    } else if (strcmp(key, "lock.key") == 0) {
        strncpy(cb->lock_key, value, sizeof(cb->lock_key) -1);
        config_ident_lock(cb);
    } else if (strcmp(key, "lock.interval") == 0) {
        cb->bear.interval = atoi(value);
    } else if (strcmp(key, "passfd") == 0) {
        cb->passfd = atoi(value);
    } else if (strcmp(key, "pong_cmd") == 0) {
		if (cb->pong_cmd && cb->pong_cmd != cb->command)
			free(cb->pong_cmd);
		cb->pong_cmd = do_wrap_command(cb, value);
    } else if (strcmp(key, "session.ping_cmd") == 0) {
		if (cb->session_ping_cmd &&
				cb->session_ping_cmd != cb->command)
			free(cb->session_ping_cmd);
		cb->session_ping_cmd = do_wrap_command(cb, value);
    } else if (strcmp(key, "session.pong_cmd") == 0) {
		if (cb->session_pong_cmd &&
				cb->session_pong_cmd != cb->command)
			free(cb->session_pong_cmd);
		cb->session_pong_cmd = do_wrap_command(cb, value);
    } else if (strcmp(key, "command") == 0) {
        strncpy(cb->command, value, sizeof(cb->command) -1);
    } else if (strcmp(key, "ident") == 0) {
        strncpy(cb->ident, value, sizeof(cb->ident) -1);
		session0.self = cb->ident;
        config_ident_lock(cb);
    } else if (strcmp(key, "help") == 0) {
        fprintf(stderr, "  key list\n");
        fprintf(stderr, "  bear\n");
        fprintf(stderr, "  mode\n");
        fprintf(stderr, "  peer\n");
        fprintf(stderr, "  stun\n");
        fprintf(stderr, "  ident\n");
        fprintf(stderr, "  passfd\n");
        fprintf(stderr, "  command\n");
        fprintf(stderr, "  lock.key\n");
        fprintf(stderr, "  lock.interval\n");
        fprintf(stderr, "  exitchild\n");
        fprintf(stderr, "\n");
    }

    return 0;
}

int do_bind_address(struct natcb_t *cb, const char *buf)
{
    int match;
    char action[128], bufaddr[128];

    match = sscanf(buf, "%128s %128s", action, bufaddr);

    if (2 != match) {
        fprintf(stderr, "missing set %d\n", match);
        return 0;
    }

    char *port;
    struct hostent *phost;

    port = strchr(bufaddr, ':');
    if (port) *port++ = 0;

    phost = gethostbyname(bufaddr);
    if (!phost) {
        return 0;
    }

    struct sockaddr_in6 selfaddr;
    selfaddr.sin6_family = AF_INET6;
    selfaddr.sin6_port = htons(port? atoi(port): 3478);
    inet_4to6(&selfaddr.sin6_addr, phost->h_addr);

    match = bind(cb->peer.sockfd, (const struct sockaddr *)&selfaddr, sizeof(selfaddr));

    return 0;
}

void do_dump_status(struct natcb_t *cb)
{
    int error;
    struct sockaddr_in6 *inp, selfaddr;

    fprintf(stderr, "set ident  %s\n", cb->ident);
    fprintf(stderr, "set lock.key  %s\n", cb->lock_key);
    fprintf(stderr, "set lock.interval  %ld\n", cb->bear.interval);
    fprintf(stderr, "set command %s\n", cb->command);
    fprintf(stderr, "set pong_command %s\n", cb->pong_cmd);
    fprintf(stderr, "set session.ping_command %s\n", cb->session_ping_cmd);
    fprintf(stderr, "set session.pong_command %s\n", cb->session_pong_cmd);
    fprintf(stderr, "set exitchild %d\n", cb->exit_child);
    fprintf(stderr, "set passfd %d\n", cb->passfd);
    fprintf(stderr, "set mode %s\n", cb->mode==MODE_PAIR?"pair":"once");

    inp = &cb->peer.target;
    printf("set peer [%s]:%d\n",
            ntop6(inp->sin6_addr), htons(inp->sin6_port));

    inp = &cb->bear.target;
    printf("set bear [%s]:%d\n",
            ntop6(inp->sin6_addr), htons(inp->sin6_port));

    inp = &cb->stun;
    printf("set stun [%s]:%d\n",
            ntop6(inp->sin6_addr), htons(inp->sin6_port));

    socklen_t selflen = sizeof(selfaddr);
    error = getsockname(cb->bear.sockfd, (struct sockaddr *)&selfaddr, &selflen);
    if (error == -1) return;

    fprintf(stderr, "  ready %d\n", cb->ready);
    fprintf(stderr, "  buflen  %d\n", cb->buflen);
    fprintf(stderr, "  got_ping %d\n", cb->got_pong);
    fprintf(stderr, "  out_ping %d\n", cb->out_ping);
    fprintf(stderr, "  childpid %d\n", cb->childpid);
    fprintf(stderr, "  session %s\n", cb->session);
    fprintf(stderr, "  acked_session %s\n", cb->acked_session);
    fprintf(stderr, "  got_session_pong %d\n", cb->got_session_pong);
    fprintf(stderr, "  got_session_execute %d\n", cb->got_session_execute);

    inp = &selfaddr;
    printf("  self-bear: [%s]:%d\n",
            ntop6(inp->sin6_addr), htons(inp->sin6_port));

    error = getsockname(cb->peer.sockfd, (struct sockaddr *)&selfaddr, &selflen);
    inp = &selfaddr;
    printf("  self-peer: [%s]:%d\n",
            ntop6(inp->sin6_addr), htons(inp->sin6_port));
    return;
}

static int to_ipv4(char *buf, const struct sockaddr_in6 *from)
{
	uint8_t *v4p = (uint8_t*)&from->sin6_addr;
	uint16_t v6any[] = {0, 0, 0, 0, 0, 0, 0, 0};
	uint16_t v4prefix[] = {0, 0, 0, 0, 0, 0xffff, 0, 0};

	if (0 == memcmp(v4prefix, v4p, 12)) {
		sprintf(buf, "%d.%d.%d.%d:%d\n",
				v4p[12], v4p[13], v4p[14], v4p[15], htons(from->sin6_port));
		return 1;
	}

	if (0 == memcmp(v4p, v6any, 16)) {
		sprintf(buf, "0.0.0.0:%d\n", htons(from->sin6_port));
		return 1;
	}

	fprintf(stderr, "to_ipv4 %s\n", inet_ntop(AF_INET6, &from->sin6_addr, buf, sizeof(buf)));
	return 0;
}

void do_repl_exec(struct natcb_t *cb, const char *buf)
{
    char value[1024];
    struct sockaddr_in6 selfaddr;

    socklen_t selflen = sizeof(selfaddr);
    int error = getsockname(cb->peer.sockfd, (struct sockaddr *)&selfaddr, &selflen);
    if (error == -1) return;


    sprintf(value, "[%s]:%d\n",
            ntop6(selfaddr.sin6_addr), htons(selfaddr.sin6_port));
    setenv("LOCAL6", value, 1);
	if (to_ipv4(value, &selfaddr)) setenv("LOCAL", value, 1);

    selfaddr = cb->peer.target;
    sprintf(value, "[%s]:%d\n",
            ntop6(selfaddr.sin6_addr), htons(selfaddr.sin6_port));
    setenv("REMOTE6", value, 1);
	if (to_ipv4(value, &selfaddr)) setenv("REMOTE", value, 1);

    sprintf(value, "%d", cb->peer.sockfd);
    if (cb->passfd == 0) {
        close(cb->peer.sockfd);
    } else {
        setenv("SOCKFD", value, 1);
    }

    close(cb->bear.sockfd);

    execl("/bin/sh", "sh", "-c", buf, (char *) NULL);
    exit(0);
}

void do_fork_exec(struct natcb_t *cb, const char *buf)
{
    pid_t pid;
    char value[1024];
    struct sockaddr_in6 selfaddr;

	if (buf == NULL) return;

    socklen_t selflen = sizeof(selfaddr);
    int error = getsockname(cb->peer.sockfd, (struct sockaddr *)&selfaddr, &selflen);
    if (error == -1) return;

    pid = fork();
    if (pid == 0) {
        sprintf(value, "[%s]:%d\n",
                ntop6(selfaddr.sin6_addr), htons(selfaddr.sin6_port));
        setenv("LOCAL6", value, 1);
		if (to_ipv4(value, &selfaddr)) setenv("LOCAL", value, 1);

        selfaddr = cb->peer.target;
        sprintf(value, "[%s]:%d\n",
                ntop6(selfaddr.sin6_addr), htons(selfaddr.sin6_port));
        setenv("REMOTE6", value, 1);
		if (to_ipv4(value, &selfaddr)) setenv("REMOTE", value, 1);

        sprintf(value, "%d", cb->peer.sockfd);
        if (cb->passfd == 0) {
            close(cb->peer.sockfd);
        } else {
            setenv("SOCKFD", value, 1);
        }

        if (cb->peer.sockfd != cb->bear.sockfd) {
            close(cb->bear.sockfd);
        }

        execl("/bin/sh", "sh", "-c", buf, (char *) NULL);
        exit(0);
    }

    if (cb->childpid > 0 && cb->exit_child) {
        kill(cb->childpid, SIGINT);
        cb->childpid = -1;
    }

    cb->childpid = pid;
    close(cb->peer.sockfd);
    cb->peer.sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
    cb->peer.readable = 0;
    cb->peer.ttl = 0;

    if (cb->mode == MODE_ONCE) {
        cb->bear.sockfd = cb->peer.sockfd;
        cb->bear.readable = 0;
        config_ident_lock(cb);
    }

    return;
}

void print_usage()
{
    fprintf(stderr, "  help              print usage\n");
    fprintf(stderr, "  dump              dump status\n");
    fprintf(stderr, "  ping.start        request peer remote endpoint echo\n");
    fprintf(stderr, "  ping.stop         request peer remote endpoint echo\n");
    fprintf(stderr, "  delay             delay handle next command\n");
    fprintf(stderr, "  exec              exec command\n");
    fprintf(stderr, "  fork              fork command\n");
    fprintf(stderr, "  set mode pair|once work mode pair|once\n");
    fprintf(stderr, "  bind <address>    bind socket to address\n");
    fprintf(stderr, "  set <key> <value> set server|peer value\n");
    fprintf(stderr, "  peer              send message to peer\n");
    fprintf(stderr, "  peer.bear         send message to bear (use peer channel)\n");
    fprintf(stderr, "  bear              send message to bear\n");
    fprintf(stderr, "  bear.stun         send stun message to bear\n");
    fprintf(stderr, "  stun.map          send stun request to server\n");
    fprintf(stderr, "  stun.change       send stun change request to server\n");
}

void signal_child_handler(int signo)
{
    have_child_exited = 1;
}

static void nat_session_parse(nat_session_t *session, const char *line)
{
	char name[63], dest[63];
	sscanf(line, "%s %s", name, dest);
	strcpy(session->name, name);
	strcpy(session->peer, dest);
	nat_session_request(session);
	return;
}

int main(int argc, char *argv[])
{
    int change;
    char action[128];
    char stdbuf[1024];
    char helo_line[2048];
    char last_line[2048];
    struct natcb_t cb = {};

    natcb_setup(&cb);
	srand(time(NULL));
    do_update_config(&cb, "set stun stun.ekiga.net:3478");

    setvbuf(stdin, NULL, _IONBF, 0);
    signal(SIGCHLD, signal_child_handler);
    while (fgets(stdbuf, sizeof(stdbuf), stdin)) {
        if (sscanf(stdbuf, "%128s", action) != 1) {
            goto check_pending;
        }

        change = 0;
        if (strcmp(action, "if") == 0) {
            strncpy(helo_line, stdbuf, sizeof(helo_line) -1);
            sscanf(helo_line, "%*s %[^\n]", stdbuf);
            change = cb.ready;
        } else if (strcmp(stdbuf, "r") == 0) {
            fprintf(stderr, "+ %s\n", last_line);
            strncpy(stdbuf, last_line, sizeof(stdbuf) -1);
            change = 1;
        }

        if (change && sscanf(stdbuf, "%128s", action) != 1) {
            goto check_pending;
        }

        if (strcmp(action, "bind") == 0) {
            do_bind_address(&cb, stdbuf);
        } else if (strcmp(action, "dump") == 0) {
            do_dump_status(&cb);
        } else if (strcmp(action, "help") == 0) {
            print_usage();
        } else if (strcmp(action, "check") == 0) {
            do_update_ready(&cb, stdbuf);
        } else if (strcmp(action, "wait") == 0) {
			cb.waiting = 1;
            while (do_update_ready(&cb, stdbuf))
                check_and_receive(&cb, 0);
			cb.waiting = 0;
            goto check_pending;
        } else if (strcmp(action, "set") == 0) {
            do_update_config(&cb, stdbuf);
        } else if (strcmp(action, "recover") == 0) {
            do_recover_config(&cb);
        } else if (strcmp(action, "peer") == 0) {
            strncpy(last_line, stdbuf, sizeof(last_line) -1);
            do_peer_exchange(&cb, stdbuf +5);
        } else if (strcmp(action, "peer.bear") == 0) {
            strncpy(last_line, stdbuf, sizeof(last_line) -1);
            do_peer_bearing(&cb, stdbuf +10);
            cb.peer.ttl = 2;
        } else if (strcmp(action, "bear") == 0) {
            strncpy(last_line, stdbuf, sizeof(last_line) -1);
            do_bear_exchange(&cb, stdbuf +5);
        } else if (strcmp(action, "bear.stun") == 0) {
            snprintf(helo_line, sizeof(helo_line), "FROM %s STUN.MAP", cb.ident);
            do_peer_bearing(&cb, helo_line);
        } else if (strcmp(action, "print") == 0) {
            fprintf(stderr, "%s\n", stdbuf + 5);
        } else if (strcmp(action, "session") == 0) {
			memset(&session0, 0, sizeof(session0));
			session0.self = cb.ident;
			session0.una_seq = rand() % 1747;
			session0.nxt_seq = session0.una_seq;
			nat_session_parse(&session0, stdbuf + 8);
			nat_session_output(&cb, &session0);
        } else if (strcmp(action, "ping.start") == 0) {
            snprintf(cb.peer.cache, sizeof(cb.peer.cache), "FROM %s PING", cb.ident);
            cb.peer.interval = 5;
            cb.peer.ttl = -1;
            cb.out_ping = 1;
        } else if (strcmp(action, "ping.stop") == 0) {
            cb.peer.interval = 2;
            cb.peer.ttl = 0;
        } else if (strcmp(action, "ping") == 0) {
            snprintf(helo_line, sizeof(helo_line), "FROM %s PING", cb.ident);
            do_peer_exchange(&cb, helo_line);
            cb.out_ping = 1;
        } else if (strcmp(action, "exec") == 0) {
            do_repl_exec(&cb, stdbuf + 5);
        } else if (strcmp(action, "fork") == 0) {
            do_fork_exec(&cb, stdbuf + 5);
        } else if (strcmp(action, "daemon") == 0) {
            daemon(0, 0);
            for ( ; ; ) check_and_receive(&cb, 0);
        } else if (strcmp(action, "delay") == 0) {
            int delay = 0;
            if (sscanf(stdbuf, "delay %d", &delay) == 1 &&
                    delay > 0 && delay < 1030) {
                time_t start = time(NULL);
                while (start + delay > time(NULL))
                    check_and_receive(&cb, 0);
                goto check_pending;
            }
        } else if (strcmp(action, "stun.map") == 0) {
            do_stun_maping(&cb, NULL, 0);
        } else if (strcmp(action, "stun.change") == 0) {
            do_stun_changing(&cb, NULL, 0);
        }

check_pending:
        fprintf(stderr, "\r> ");
        check_and_receive(&cb, 1);
    }

	if (cb.childpid > 0)
		kill(cb.childpid, SIGINT);
    natcb_free(&cb);

    return 0;
}


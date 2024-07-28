#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h> // read(), write(), close()

#include "tx_debug.h"

#define MAX 655360
#define SA struct sockaddr

struct tls_header {
    uint8_t type;
    uint8_t major;
    uint8_t minor;
    uint16_t length;
};

#define HANDSHAKE_TYPE 22
#define APPLICATION_DATA_TYPE 0x17

#define TAG_SNI        0
#define TAG_SESSION_TICKET 35

// #ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 0
// #endif

#define HANDSHAKE_TYPE_CLIENT_HELLO         1
#define HANDSHAKE_TYPE_SERVER_HELLO         2
#define HANDSHAKE_TYPE_CERTIFICATE         11
#define HANDSHAKE_TYPE_KEY_EXCHAGE         12
#define HANDSHAKE_TYPE_SERVER_HELLO_DONE   14

#define LOG(fmt, arg...) 
#define LOGV(fmt, arg...) 
#define LOGI(fmt, args...)   log_tag_putlog("D", fmt, ##args)

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

int read_flush(int fd, void *buf, size_t count)
{
    int rc = 0;
    int process = 0;
    uint8_t *ptr = (uint8_t*)buf;

    while (process < count) {
        rc = read(fd, ptr + process, count - process);
        if (rc == -1) break;
        if (rc == 0) break;
        process += rc;
    }

    return process == 0? rc: process;
}

int write_flush(int fd, void *buf, size_t count, int *statp)
{
    int rc = 0;
    int process = 0;
    uint8_t *ptr = (uint8_t*)buf;

    while (process < count) {
        rc = write(fd, ptr + process, count - process);
        if (rc == -1) break;
        if (rc == 0) break;
		if (rc != count) *statp = 1;
        process += rc;
    }

    return process == 0? rc: process;
}

static int set_hook_name = 0;
static int wrap_certificate = 0;
static char YOUR_DOMAIN[256] = "app.yrli.bid";

char * get_sni_name(uint8_t *snibuff, size_t len, char *hostname)
{
    int i;
    int length;
    uint8_t *p = snibuff;

    if (*p != HANDSHAKE_TYPE_CLIENT_HELLO) {
        LOG("bad\n");
        return NULL;
    }

    int type = *p++;
    LOG("type: %x\n", type);
    length = p[2]|(p[1]<<8)|(p[0]<<16); p+=3;
    LOG("length: %d\n", length);
    LOG("version: %x.%x\n", p[0], p[1]);
    p += 2; // version;
            //
    p += 32; //random;
    LOG("session id length: %d\n", *p);
    p += *p;
    p++;
    int cipher_suite_length = p[1]|(p[0]<<8); p+=2;
    LOG("cipher_suite_length: %d\n", cipher_suite_length);
    p += cipher_suite_length;
    int compress_method_len = *p++;
    LOG("compress_method_len: %d\n", compress_method_len);
    p += compress_method_len;
    int extention_length = p[1]|(p[0]<<8); p+=2;
    LOG("extention_lengh: %d\n", extention_length);
    const uint8_t *limit = p + extention_length;

    *hostname = 0;
    while (p < limit) {
        uint16_t tag = p[1]|(p[0]<<8);
        uint16_t len = p[3]|(p[2]<<8);
        LOG("ext tag: %d %d\n", tag, len);
        if (tag == TAG_SNI) {
            const uint8_t *sni = (p + 4);
            assert (sni[2] == 0);
            uint16_t list_name_len = sni[1]|(sni[0] << 8);
            uint16_t fqdn_name_len = sni[4]|(sni[3] << 8);
            assert (fqdn_name_len + 3 == list_name_len);
            memcpy(hostname, sni + 5, fqdn_name_len);
            hostname[fqdn_name_len] = 0;

#if 0
            uint8_t *lockm = (uint8_t*)(sni + 5);
            for (i = 0; i < fqdn_name_len; i++) lockm[i] ^= 0xf;
#endif
        }
        p += len;
        p += 4;
    }

	if (set_hook_name)
		strcpy(hostname, YOUR_DOMAIN);

    return hostname;
}

enum { MODE_RELAY_SERVER, MODE_RELAY_CLIENT,  MODE_RELAY_NONE};

static int PORT = 4430;
static int RELAY_MODE = MODE_RELAY_NONE;

static int YOUR_PORT = 4430;
static char YOUR_PORT_TEXT[64] = "4430";
static int iYOUR_ADDRESS = 0;
static const char * YOUR_ADDRESS[256] = {};
static int (*unwind_rewind_client_hello)(uint8_t *, size_t) = NULL;

static unsigned char encrypt_byte_list[] = {
	0x9b, 0x71, 0xd2, 0x24, 0xbd, 0x62, 0xf3, 0x78, 0x5d, 0x96, 0xd4, 0x6a, 0xd3, 0xea, 0x3d, 0x73,
	0x31, 0x9b, 0xfb, 0xc2, 0x89, 0x0c, 0xaa, 0xda, 0xe2, 0xdf, 0xf7, 0x25, 0x19, 0x67, 0x3c, 0xa7,
	0x23, 0x23, 0xc3, 0xd9, 0x9b, 0xa5, 0xc1, 0x1d, 0x7c, 0x7a, 0xcc, 0x6e, 0x14, 0xb8, 0xc5, 0xda,
	0x0c, 0x46, 0x63, 0x47, 0x5c, 0x2e, 0x5c, 0x3a, 0xde, 0xf4, 0x6f, 0x73, 0xbc, 0xde, 0xc0, 0x43
};

uint32_t update_checksum(uint8_t *snibuff, size_t length)
{
	uint32_t checksum = 0;

	union {
		uint8_t d[4];
		uint32_t u;
	} pading;

	while (length >= 4) {
		uint32_t item = 0;
		memcpy(&item, snibuff, sizeof(item));
		snibuff += 4;
		length -= 4;

		checksum += item;
		if (checksum < item)
			checksum += 1;
	}

	if (length > 0) {
		memset(&pading, 0, sizeof(pading)); 
		memcpy(&pading, snibuff, length);
		checksum += pading.u;
		if (checksum < pading.u)
			checksum += 1;
	}

	return ~checksum;
}

#define verify_checksum(snibuff, length) update_checksum(snibuff, length)

int dnsDomainIs(const char *host, const char *domain)
{
	if (strcasecmp(host, domain) == 0) {
		return 1;
	}

	size_t lenofhost = strlen(host);
	while (*domain != '.') domain++;
	size_t lenofdomain = strlen(domain);
	
	if (lenofhost > lenofdomain &&
			strcasecmp(host - lenofdomain + lenofhost, domain) == 0) {
		return 1;
	}

	return 0;
}

int generate_pseudo_hostname(char *pseudo, size_t len, const char *hostname, const char *domain)
{
	int ndotofhostname = 0, ndotofdomain = 0;

	if (*domain != '.') {
		strncpy(pseudo, domain, len -1);
		return 0;
	}

	const char *pdot = hostname;
	while (*pdot) {
		if (*pdot == '.') ndotofhostname++;
		pdot++;
	}

	pdot = domain;
	while (*pdot) {
		if (*pdot == '.') ndotofdomain++;
		pdot++;
	}

	if (ndotofdomain > ndotofhostname) {
		snprintf(pseudo, len, "www%s", domain);
		return 0;
	}

	int ndot = 0;
	const char *limit = pseudo + len;
	while (*hostname && ndot + ndotofdomain <= ndotofhostname) {
		if (*hostname == '.') ndot ++;
		if (pseudo < limit)
			*pseudo++ = *hostname;
		hostname++;
	}

	if (*domain == '.' && pseudo[-1] == '.') domain++;

	while (*domain) {
		if (pseudo < limit)
			*pseudo++ = *domain;
		domain++;
	}

	if (pseudo < limit)
		*pseudo = 0;

	return 0;
}

static char _log_hostname[1233];

int rewind_client_hello(uint8_t *snibuff, size_t length)
{
    int i;
    int mylength = 0;
    uint8_t hold[MAX];
    uint8_t *p = snibuff + 5;
    uint8_t *dest = hold + 5;

    memcpy(hold, snibuff, 5);
    if (*p != HANDSHAKE_TYPE_CLIENT_HELLO) {
        LOG("bad\n");
        return 0;
    }

    *dest++ = *p++;

    uint8_t *lengthp = dest;
    mylength = p[2]|(p[1]<<8)|(p[0]<<16);
    dest += 3;
    p += 3;

    dest[0] = p[0]; dest[1] = p[1];
    dest += 2;
    p += 2; // version;

    memcpy(dest, p, 32);
    dest += 32;
    p += 32; //random;

    dest[0] = p[0]; //session id length
    memcpy(&dest[1], &p[1], *p);
    dest += *p;
    dest++;

    p += *p;
    p++;

    int cipher_suite_length = p[1]|(p[0]<<8);
    dest[0] = p[0];
    dest[1] = p[1];
    dest+=2;
    p+=2;

    memcpy(dest, p, cipher_suite_length);
    dest += cipher_suite_length;
    p += cipher_suite_length;

    int compress_method_len = *p;
    *dest++ = *p++;

    memcpy(dest, p, compress_method_len);
    dest += compress_method_len;
    p += compress_method_len;

    int extention_length = p[1]|(p[0]<<8);
    uint8_t *extention_lengthp = dest;
    dest += 2;
    p += 2;

	int ntags = 0, session_ticket_ntag = 0;
    const uint8_t *limit = p + extention_length;
	uint8_t * session_ticket_place = NULL;

    char hostname[256] = "";
    while (p < limit) {
        uint16_t tag = p[1]|(p[0]<<8);
        uint16_t len = p[3]|(p[2]<<8);
        LOG("ext tag: %d %d\n", tag, len);
        uint16_t fqdn_name_len = 0;

		ntags++;
        if (tag == TAG_SNI) {
            const uint8_t *sni = (p + 4);
            assert (sni[2] == 0);
            uint16_t list_name_len = sni[1]|(sni[0] << 8);
            fqdn_name_len = sni[4]|(sni[3] << 8);
            assert (fqdn_name_len + 3 == list_name_len);
            memcpy(hostname, sni + 5, fqdn_name_len);
            hostname[fqdn_name_len] = 0;
			if (dnsDomainIs(hostname, YOUR_DOMAIN)) {
				return length;
			}
        }

		if (tag == TAG_SESSION_TICKET) {
			LOGI("TAG_SESSION_TICKET: %d\n", ntags);
			if (len == 0) {
				session_ticket_ntag = ntags;
				if (session_ticket_place) {
					session_ticket_place[0] = (ntags >> 8);
					session_ticket_place[1] = (ntags);
				}
			} else {
				memcpy(dest, p, len + 4);
				dest += len;
				dest += 4;
			}
		} else if (tag != TAG_SNI || dnsDomainIs(hostname, YOUR_DOMAIN)) {
            memcpy(dest, p, len + 4);
            dest += len;
            dest += 4;
        } else {
            dest[0] = (TAG_SNI >> 8);
			dest[1] = (TAG_SNI);
            dest[2] = 0; dest[3] = 0;
			char pseudo_hostname[512] = "";
			strcpy(_log_hostname, hostname);
			generate_pseudo_hostname(pseudo_hostname, sizeof(pseudo_hostname), hostname, YOUR_DOMAIN);
            size_t namelen = strlen(pseudo_hostname);

            strcpy(dest + 4 + 5, pseudo_hostname);
            dest[4 + 4] = namelen;
            dest[4 + 3] = (namelen >> 8);
            dest[4 + 2] = 0;
            dest[4 + 1] = (namelen + 3);
            dest[4 + 0] = (namelen + 3) >> 8;
            dest[3] = namelen + 5;
            dest[2] = (namelen + 5) >> 8;

            // assert(memcmp(dest, p, len + 4) == 0);
            dest += (namelen + 4 + 5);

#if 1
			wrap_certificate = 1;
            dest[0] = TAG_SESSION_TICKET >> 8;
            dest[1] = TAG_SESSION_TICKET;

            dest[2] = (fqdn_name_len + 6) >> 8;
            dest[3] = (fqdn_name_len + 6);

			dest[4] = (session_ticket_ntag >> 8);
			dest[5] = session_ticket_ntag;
			session_ticket_place = dest + 4;

			uint32_t checksum = update_checksum(snibuff, length);
			memcpy(session_ticket_place + 2, &checksum, sizeof(checksum));

            memcpy(dest + 10, hostname, fqdn_name_len);
			for (i = 0; i < fqdn_name_len + 4; i++)
				dest[i + 6] ^= encrypt_byte_list[i % sizeof(encrypt_byte_list)];
            dest += (10 + fqdn_name_len);
            // (tag == TAG_SESSION_TICKET)
#endif
        }

        p += len;
        p += 4;
    }

    int extlen = (dest - extention_lengthp - 2);
    extention_lengthp[0] = extlen >> 8;
    extention_lengthp[1] = extlen;
    LOG("extlen: %d %d\n", extlen, extention_length);

    int newlen = dest - lengthp - 3;
    lengthp[0] = newlen >> 16;
    lengthp[1] = newlen >> 8;
    lengthp[2] = newlen;
    LOG("newlen: %d %d\n", newlen, mylength);

    memcpy(hold, snibuff, 5);
    int fulllength = (dest - hold - 5);
    hold[3] = fulllength >> 8;
    hold[4] = fulllength;

    int oldlen = (snibuff[3] << 8) | snibuff[4];
    LOG("fulllen: %d %d %ld\n", fulllength, oldlen, length);
    LOGI("fulllen: %d %d %ld %d\n", fulllength, oldlen, length, session_ticket_ntag);

    memcpy(snibuff, hold, dest - hold);
    return dest - hold;
}

int rewind_client_zero(uint8_t *snibuff, size_t length)
{
    return length;
}

int unwind_client_hello(uint8_t *snibuff, size_t length)
{
    int i;
    int modify = 0;
    int mylength = 0;
    uint8_t hold[MAX];
    uint8_t *p = snibuff + 5;
    uint8_t *dest = hold + 5;

    memcpy(hold, snibuff, 5);
    if (*p != HANDSHAKE_TYPE_CLIENT_HELLO) {
        LOG("bad\n");
        return 0;
    }

    *dest++ = *p++;

    uint8_t *lengthp = dest;
    mylength = p[2]|(p[1]<<8)|(p[0]<<16);
    dest += 3;
    p += 3;

    dest[0] = p[0]; dest[1] = p[1];
    dest += 2;
    p += 2; // version;

    memcpy(dest, p, 32);
    dest += 32;
    p += 32; //random;

    dest[0] = p[0]; //session id length
    memcpy(&dest[1], &p[1], *p);
    dest += *p;
    dest++;

    p += *p;
    p++;

    int cipher_suite_length = p[1]|(p[0]<<8);
    dest[0] = p[0];
    dest[1] = p[1];
    dest+=2;
    p+=2;

    memcpy(dest, p, cipher_suite_length);
    dest += cipher_suite_length;
    p += cipher_suite_length;

    int compress_method_len = *p;
    *dest++ = *p++;

    memcpy(dest, p, compress_method_len);
    dest += compress_method_len;
    p += compress_method_len;

    int extention_length = p[1]|(p[0]<<8);
    uint8_t *extention_lengthp = dest;
    dest += 2;
    p += 2;

	int need_fixup = 0;
	uint32_t  checksum = 0;
	uint8_t * fixup_base = dest;
	int ntags = 0, session_ticket_ntag = -1;
    const uint8_t *limit = p + extention_length;

    int last_tag = -1;
    char hostname[256] = "";
    while (p < limit) {
        uint16_t tag = p[1]|(p[0]<<8);
        uint16_t len = p[3]|(p[2]<<8);
        LOG("ext tag: %d %d\n", tag, len);
        uint16_t fqdn_name_len = 0;

		ntags++;
        if (tag == TAG_SNI) {
            const uint8_t *sni = (p + 4);
            assert (sni[2] == 0);
            uint16_t list_name_len = sni[1]|(sni[0] << 8);
            fqdn_name_len = sni[4]|(sni[3] << 8);
            assert (fqdn_name_len + 3 == list_name_len);
            memcpy(hostname, sni + 5, fqdn_name_len);
            hostname[fqdn_name_len] = 0;
            LOG("source: %s\n", hostname);
        } else if (tag == TAG_SESSION_TICKET && last_tag == TAG_SNI) {
            if (dnsDomainIs(hostname, YOUR_DOMAIN) && len > 6) {
                memcpy(hostname, p + 6, len - 2);
                hostname[len - 2] = 0;
				for (i = 0; i < len - 2; i++)
					hostname[i] ^= encrypt_byte_list[i % sizeof(encrypt_byte_list)];
				memcpy(&checksum, hostname, sizeof(checksum));
				memmove(hostname, hostname + 4, len - 6 + 1);
                fqdn_name_len = strlen(hostname);
				session_ticket_ntag = (p[4] << 8) | p[5];
                LOGI("target: %s session_ticket_ntag %d\n", hostname, session_ticket_ntag);
				wrap_certificate = 1;
				if (session_ticket_ntag < ntags && session_ticket_ntag > 0) {
					LOGI("missing ticket: %d %d\n", session_ticket_ntag, ntags);
					need_fixup = 1;
				}
            }
        }

		if (ntags == session_ticket_ntag + 1) {
			LOGI("adding ticket: %d %d\n", session_ticket_ntag, ntags);
			dest[0] = (TAG_SESSION_TICKET >> 8);
			dest[1] = (TAG_SESSION_TICKET);
            dest[2] = 0; dest[3] = 0;
			dest += 4;
		}

        if (dnsDomainIs(hostname, YOUR_DOMAIN) && tag == TAG_SNI) {
#if 0
            memcpy(dest, p, len + 4);
            dest += len;
            dest += 4;
#endif
        } else if (tag != TAG_SESSION_TICKET || last_tag != TAG_SNI) {
            memcpy(dest, p, len + 4);
            dest += len;
            dest += 4;
        } else if (tag == TAG_SESSION_TICKET) {
			dest[0] = (TAG_SNI >> 8);
			dest[1] = (TAG_SNI);
            dest[2] = 0; dest[3] = 0;
            size_t namelen = strlen(hostname);

            strcpy(dest + 4 + 5, hostname);
            dest[4 + 4] = namelen;
            dest[4 + 3] = (namelen >> 8);
            dest[4 + 2] = 0;
            dest[4 + 1] = (namelen + 3);
            dest[4 + 0] = (namelen + 3) >> 8;
            dest[3] = namelen + 5;
            dest[2] = (namelen + 5) >> 8;

            dest += (namelen + 4 + 5);
			modify = 1;
        }

        last_tag = tag;
        p += len;
        p += 4;
    }

	if (ntags == session_ticket_ntag) {
		LOGI("adding ticket: %d %d\n", session_ticket_ntag, ntags);
		dest[0] = (TAG_SESSION_TICKET >> 8);
		dest[1] = (TAG_SESSION_TICKET);
		dest[2] = 0; dest[3] = 0;
		dest += 4;
	}

	LOGI("TODO:XXX session_ticket_ntag %d\n", session_ticket_ntag);
	if (need_fixup) {
		int tag_offset = 0;
		while (fixup_base < dest) {
			uint8_t *p = fixup_base;
			uint16_t tag = p[1]|(p[0]<<8);
			uint16_t len = p[3]|(p[2]<<8);

			tag_offset++;
			if (tag_offset >= session_ticket_ntag) break;
			LOG("ext tag: %d %d\n", tag, len);

            fixup_base += len;
            fixup_base += 4;
		}

		memmove(fixup_base + 4, fixup_base, dest - fixup_base);
		dest += 4;

		fixup_base[0] = (TAG_SESSION_TICKET >> 8);
		fixup_base[1] = (TAG_SESSION_TICKET);
		fixup_base[2] = 0; fixup_base[3] = 0;
	}

    int extlen = (dest - extention_lengthp - 2);
    extention_lengthp[0] = extlen >> 8;
    extention_lengthp[1] = extlen;
    LOG("extlen: %d %d\n", extlen, extention_length);

    int newlen = dest - lengthp - 3;
    lengthp[0] = newlen >> 16;
    lengthp[1] = newlen >> 8;
    lengthp[2] = newlen;
    LOG("newlen: %d %d\n", newlen, mylength);

    memcpy(hold, snibuff, 5);
    int fulllength = (dest - hold - 5);
    hold[3] = fulllength >> 8;
    hold[4] = fulllength;

    int oldlen = (snibuff[3] << 8) | snibuff[4];
    LOG("fulllen: %d %d %ld\n", fulllength, oldlen, length);

	uint32_t checksum1 = update_checksum(hold, dest - hold);
	LOGI("checksum %x, exptected %x modify %d\n", checksum, checksum1, modify);
	if (modify && checksum != checksum1) {
		set_hook_name = 1;
		modify = 0;
	}

    set_hook_name = 0;
    if (modify == 0 && !dnsDomainIs(hostname, YOUR_DOMAIN)) { set_hook_name = 1; }
    if (modify == 0) return length;

    memcpy(snibuff, hold, dest - hold);
    return dest - hold;
}

void dump(char *buff, size_t len, struct tls_header *header, const char *title)
{
    LOG("%s: %d %x.%x %d\n", title, header->type, header->major, header->minor, header->length);
    if (22 == header->type) {
        int length = 0;
        uint8_t *p = buff;
        if (*p == 11) {
            LOG("certificate\n");
            return ;
        }
		int type = *p++;
        LOG("type: %x\n", type);
        length = p[2]|(p[1]<<8)|(p[0]<<16); p+=3;
        LOG("length: %d\n", length);
        LOG("version: %x.%x\n", p[0], p[1]);
        p += 2; // version;
                //
        p += 32; //random;
        LOG("session id length: %d\n", *p);
        p += *p;
        p++;
        int cipher_suite_length = p[1]|(p[0]<<8); p+=2;
        if (buff[0] == 2) {
            LOG("cipher_suite: %x\n", cipher_suite_length);
        } else {
            LOG("cipher_suite_length: %d\n", cipher_suite_length);
            p += cipher_suite_length;
        }
        int compress_method_len = *p++;
        LOG("compress_method_len: %d\n", compress_method_len);
        p += compress_method_len;
        int extention_length = p[1]|(p[0]<<8); p+=2;
        LOG("extention_lengh: %d\n", extention_length);
        const uint8_t *limit = p + extention_length;

        while (p < limit) {
            uint16_t tag = p[1]|(p[0]<<8);
            uint16_t len = p[3]|(p[2]<<8);
            LOG("ext tag: %d %d\n", tag, len);
            p += len;
            p += 4;
        }

    }
}

static int do_certificate_wrap(char *buf, size_t len)
{
	int i;
    uint8_t hold[MAX];
    uint8_t *p = buf + 5;
    uint8_t *dest = hold + 5;

	if (wrap_certificate == 0) {
		return len;
	}

	const uint8_t * limit = buf + len;
	assert (len < sizeof(hold));
    memcpy(hold, buf, 5);

	while (limit > p) {
		int type = *p++;
		int length = p[2]|(p[1]<<8)|(p[0]<<16);
		p += 3;

		if (type == HANDSHAKE_TYPE_CERTIFICATE) {
			LOGI("test certificate: %d\n", length);
			for (i = 0; i < length; i++) p[i] ^= 0x56;
		}

		p += length;
	}

	return len;
}

int pull(int connfd, int remotefd, int *direct)
{
    char buff[MAX];
    int n, l, i;
    struct tls_header header;
    // infinite loop for chat

    // read the message from client and copy it in buffer
    l = read_flush(connfd, buff, 5);
    LOGV("%d l %d\n", connfd, l);
    if (l <= 0) return l;
    // perror("read");
    LOGV("l %d\n", l);
    assert(l == 5);
    // print buffer which contains the client contents
    header.type = buff[0];
    header.major = buff[1];
    header.major = buff[2];
    memcpy(&header.length, &buff[3], 2);
    header.length = htons(header.length);

	assert(header.length  < MAX);
    l = read_flush(connfd, buff + 5, header.length);
    if (header.type == APPLICATION_DATA_TYPE) *direct = 1;
    if (header.type == HANDSHAKE_TYPE && l == header.length) {
		int newl = do_certificate_wrap(buff, header.length + 5);
		l = newl - 5;
	}

    // dump(buff + 5, l, &header, "PULL");
	int ignore;
    return write_flush(remotefd, buff, l + 5, &ignore);
}


// Function designed for chat between client and server.
int push(int connfd, int remotefd, int *direct)
{
    char buff[MAX];
    int n, l, i;
    struct tls_header header;
    // infinite loop for chat

    // read the message from client and copy it in buffer
    l = read_flush(connfd, buff, 5);
    LOGV("%d l %d\n", connfd, l);
    if (l <= 0) return l;
    assert(l == 5);
    header.type = buff[0];
    header.major = buff[1];
    header.major = buff[2];
    memcpy(&header.length, &buff[3], 2);
    header.length = htons(header.length);

	if (header.length + 5 > sizeof(buff))
		LOGI("len: %d\n", header.length);
	assert(header.length + 5 < sizeof(buff));

    l = read_flush(connfd, buff + 5, header.length);

	
    if (header.type == APPLICATION_DATA_TYPE) *direct = 1;
    if (header.type == HANDSHAKE_TYPE && l == header.length && HANDSHAKE_TYPE_CLIENT_HELLO == (buff[0] & 0xff)) {

		char hostname[128];
		get_sni_name(buff + 5, header.length, hostname);
		LOGI("rehandshake origin hostname: %s: %s\n", hostname, _log_hostname);

		int newlen = unwind_rewind_client_hello(buff, header.length + 5);
		l = header.length = newlen - 5;

		get_sni_name(buff + 5, header.length, hostname);
		LOGI("rehandshake convert hostname: %s %s\n", hostname, _log_hostname);
		if (*hostname == 0) {
			LOGI("rehandshake failure: %s %s tag=%x\n", hostname, _log_hostname, buff[5]);
		}
	}

    // dump(buff + 5, l, &header, "PUSH");
	int ignore;
    return write_flush(remotefd, buff, l + 5, &ignore);
}

static char _buff[655360];

int pipling(int connfd, int remotefd, int *statp)
{
    size_t len = recv(connfd, _buff, sizeof(_buff), MSG_DONTWAIT);
	if (len == -1 && errno == EAGAIN) return 1;
    if (len == -1) return -1;
    if (len == 0) return 0;
    return write_flush(remotefd, _buff, len, statp);
}

int mptcp_enable(int sockfd)
{
    int error;
    int enable = 1;
    char pathmanager[] = "ndiffports";

    // error = setsockopt(sockfd, SOL_TCP, TCP_FASTOPEN_CONNECT, &enable, sizeof(enable)); 

#ifdef MPTCP_PATH_MANAGER
    // error = setsockopt(sockfd, SOL_TCP, MPTCP_PATH_MANAGER, pathmanager, sizeof(pathmanager));
#endif

#ifdef MPTCP_ENABLED
    // error = setsockopt(sockfd, SOL_TCP, MPTCP_ENABLED, &enable, sizeof(int));
#endif

    return 0;
}

int xor_get(const char *name)
{
    int sum = 0;

    while (*name)
      sum += (uint8_t)*name++;

    sum ^= (sum >> 16);
    sum ^= (sum >> 8);
    return sum & 0xff;
}

int setup_remote(struct sockaddr_in6 *cli, char *hostname, const char *origin)
{
    int i;
    int rc = -1;
    int remotefd = -1;
    struct hostent *phostent = NULL;

    if (RELAY_MODE == MODE_RELAY_CLIENT) {
        remotefd = socket(AF_INET6, SOCK_STREAM, IPPROTO_MPTCP);

		int pick = xor_get(origin);
        LOGI("pick=%d name=%s\n", pick, origin);
        inet_pton(AF_INET6, YOUR_ADDRESS[pick % iYOUR_ADDRESS], &cli->sin6_addr);
		
        mptcp_enable(remotefd);
        rc = connect(remotefd, (struct sockaddr *)cli, sizeof(*cli));
        if (rc == -1) {
            close(remotefd);
            remotefd = -1;
        }

        return remotefd;
    }

    if (RELAY_MODE != MODE_RELAY_SERVER) {
        LOG("relay mode unkown: %d\n", RELAY_MODE);
        return -1;
    }

#if 1
    struct addrinfo hints;
    struct addrinfo *result, *rp;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
    hints.ai_flags = 0;
    hints.ai_protocol = 0;          /* Any protocol */

    int sfd, s;
    s = getaddrinfo(hostname, YOUR_PORT_TEXT, &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1)
            continue;

        if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
            break;                  /* Success */

        close(sfd);
        sfd = -1;
    }

    LOGI("fd=%d, %s\n", sfd, hostname);
    freeaddrinfo(result);           /* No longer needed */
    return sfd;
#endif

    phostent = gethostbyname(hostname);
    if (phostent == NULL) {
        return -1;
    }

    struct in_addr ** addr_list = (struct in_addr **)phostent->h_addr_list;

    for (i = 0; addr_list[i] != NULL; i++) {
        remotefd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);

        LOG("connect %s \n", inet_ntoa(*addr_list[i]));
        mptcp_enable(remotefd);

        inet_4to6(&cli->sin6_addr, addr_list[i]);
        rc = connect(remotefd, (struct sockaddr *)cli, sizeof(*cli));
        if (rc == 0) {
            break;
        }

        perror("connect");
        close(remotefd);
        remotefd = -1;
    }

    return remotefd;
}

void func(int connfd)
{
    int rc;
    int n, l, i;
    fd_set test, wtest;
    uint8_t snibuff[MAX];
    struct tls_header header;
    int remotefd = -1;

    struct timeval tv = {};
    tv.tv_sec = 30;  /* 30 Secs Timeout */
    int ret = setsockopt(connfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (ret) perror("setsockopt");
    assert(ret == 0);

    l = read(connfd, snibuff, 5);
    assert (l == 5);

    header.type = snibuff[0];
    header.major = snibuff[1];
    header.major = snibuff[2];
    memcpy(&header.length, &snibuff[3], 2);
    header.length = htons(header.length);

    if (header.type != HANDSHAKE_TYPE) {
        close(remotefd);
        close(connfd);
        return;
    }

    if (header.length + 5 > sizeof(snibuff))
	LOGI("len: %d\n", header.length);
    assert(header.length + 5 < sizeof(snibuff));

    int nbyte = read_flush(connfd, snibuff + 5, header.length);
    assert (nbyte == header.length);

    char hostname[128], originname[128];
    get_sni_name(snibuff + 5, header.length, originname);
    LOGI("origin hostname: %s\n", originname);

    int newlen = unwind_rewind_client_hello(snibuff, header.length + 5);
    header.length = newlen - 5;

    get_sni_name(snibuff + 5, header.length, hostname);
    LOGI("convert hostname: %s\n", hostname);
    if (*hostname == 0) {
        close(connfd);
        return;
    }

    struct sockaddr_in6 cli;
    cli.sin6_family = AF_INET6;
    cli.sin6_port   = htons(YOUR_PORT);
    remotefd = setup_remote(&cli, hostname, originname);

    if (remotefd == -1) {
        close(connfd);
        return;
    }

    rc = write(remotefd, snibuff, newlen);
    assert(rc == newlen);
    int stat = 0;
    int wstat = 3;
    int maxfd = connfd > remotefd? connfd: remotefd;

	int direct = 0;
	int pull_direct = 0;
    do {
        FD_ZERO(&test);
        if (~stat & 1) FD_SET(connfd, &test);
        if (~stat & 2) FD_SET(remotefd, &test);
        assert(stat != 3);

        FD_ZERO(&wtest);
        if (wstat & 1) FD_SET(connfd, &wtest);
        if (wstat & 2) FD_SET(remotefd, &wtest);

        struct timeval timeo = {360, 360};
        n = select(maxfd + 1, &test, &wtest, NULL, &timeo);
        if (n == 0) break;
        assert(n > 0);

        if (FD_ISSET(connfd, &wtest)) {
			wstat &= ~1;
		}

        if (FD_ISSET(remotefd, &wtest)) {
			wstat &= ~2;
		}

		int half = 0;
		if (!direct && FD_ISSET(connfd, &test) && !(wstat & 2)) {
			if (push(connfd, remotefd, &direct) <= 0) stat |= 1;
		} else if (FD_ISSET(connfd, &test) && !(wstat & 2)) {
			half = 0;
            if (pipling(connfd, remotefd, &half) <= 0) stat |= 1;
			if (half) wstat |= 2;
        }

		if (!pull_direct && FD_ISSET(remotefd, &test) && !(wstat & 1)) {
            if (pull(remotefd, connfd, &pull_direct) <= 0) stat |= 2;
		} else if (FD_ISSET(remotefd, &test) && !(wstat & 1)) {
			half = 0;
            if (pipling(remotefd, connfd, &half) <= 0) stat |= 2;
			if (half) wstat |= 1;
        }

	if (stat != 0 || n  <= 0)
		LOG("stat=%x n=%d\n", stat, n);
    } while (n > 0 && stat != 3);

    LOG("release connection\n");
    close(remotefd);
    close(connfd);
    return;
}

void clean_pcb(int signo)
{
    int st;
    LOG("clean_pcb\n");
    while(waitpid(-1, &st, WNOHANG) > 0);
    // signal(SIGCHLD, clean_pcb);
}

/*
 * sniproxy -s -l 4430 -p 443 -d app.yrli.bid
 * sniproxy -c -l 4430 -p 4430 -d app.yrli.bid 100.42.78.149
 */
void parse_argopt(int argc, char *argv[])
{
    int i;

    LOG("parse_argopt>");
    for (i = 1; i < argc; i++) {
	const char *optname = argv[i];
	if (strcmp(optname, "-p") == 0) {
	    assert(i + 1 < argc);
	    YOUR_PORT = atoi(argv[++i]);
            sprintf(YOUR_PORT_TEXT, "%d", YOUR_PORT);
	} else
	if (strcmp(optname, "-l") == 0) {
	    assert(i + 1 < argc);
	    PORT = atoi(argv[++i]);
	} else
	if (strcmp(optname, "-d") == 0) {
	    assert(i + 1 < argc);
	    strcpy(YOUR_DOMAIN, argv[++i]);
	} else
	if (strcmp(optname, "-s") == 0) {
	    RELAY_MODE = MODE_RELAY_SERVER;
	    unwind_rewind_client_hello = unwind_client_hello;
	} else
	if (strcmp(optname, "-c") == 0) {
	    RELAY_MODE = MODE_RELAY_CLIENT;
	    unwind_rewind_client_hello = rewind_client_hello;
	} else
	if (strcmp(optname, "-Z") == 0) {
	    RELAY_MODE = MODE_RELAY_CLIENT;
	    unwind_rewind_client_hello = rewind_client_zero;
	} else
	if (strcmp(optname, "-z") == 0) {
	    RELAY_MODE = MODE_RELAY_SERVER;
	    unwind_rewind_client_hello = rewind_client_zero;
	} else
	if (*optname != '-') {
	    YOUR_ADDRESS[iYOUR_ADDRESS++ & 0xff] = strdup(argv[i]);
	}
    }
    LOG("<parse_argopt\n");

    assert(RELAY_MODE != MODE_RELAY_NONE);
}

// Driver function
int main(int argc, char *argv[])
{
    int sockfd, connfd, len;
    struct sockaddr_in6 servaddr, cli;
    signal(SIGCHLD, clean_pcb);

    parse_argopt(argc, argv);

    // socket create and verification
    sockfd = socket(AF_INET6, SOCK_STREAM, IPPROTO_MPTCP);
    if (sockfd == -1) {
        LOGI("socket creation failed...\n");
        exit(0);
    }
    else
        LOGI("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin6_family = AF_INET6;
    servaddr.sin6_port = htons(PORT);
    servaddr.sin6_addr = in6addr_any;

    int enable = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

	int sendbuff = 6553600;
	int err = setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sendbuff, sizeof(sendbuff));
        LOGI("socket senbuf %d...\n", err);

	err = setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &sendbuff, sizeof(sendbuff));
        LOGI("socket rcvbuf %d...\n", err);

    mptcp_enable(sockfd);

    // Binding newly created socket to given IP and verification
    if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) {
        LOGI("socket bind failed...\n");
        exit(0);
    }
    else
        LOGI("Socket successfully binded..\n");

    // Now server is ready to listen and verification
    if ((listen(sockfd, 5)) != 0) {
        LOGI("Listen failed...\n");
        exit(0);
    }
    else
        LOGI("Server listening..\n");
    len = sizeof(cli);


    do {
        len = sizeof(cli);
        // Accept the data packet from client and verification
        connfd = accept(sockfd, (SA*)&cli, &len);
        if (connfd < 0) {
            LOGI("server accept failed...\n");
            exit(0);
        }
        else
            LOGI("server accept the client...\n");

        if (fork() == 0) {close(sockfd); func(connfd); exit(0); }
        close(connfd);
        // Function for chatting between client and server
    } while (1);

    // After chatting close the socket
    close(sockfd);
    return 0;
}


#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <assert.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h> // read(), write(), close()

/* wolfSSL */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/hpke.h>

#define MAXSIZE 65536
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
#define TAG_ENCRYPT_CLIENT_HELLO 0xfe0d
#define TAG_OUTER_EXTENSIONS 0xfd00

#undef IPPROTO_MPTCP
#undef MPTCP_ENABLED
#undef MPTCP_PATH_MANAGER

#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 0
#endif

#define HANDSHAKE_TYPE_CLIENT_HELLO         1
#define HANDSHAKE_TYPE_SERVER_HELLO         2
#define HANDSHAKE_TYPE_CERTIFICATE         11
#define HANDSHAKE_TYPE_KEY_EXCHAGE         12
#define HANDSHAKE_TYPE_SERVER_HELLO_DONE   14

#define LOG(fmt, args...) fprintf(stderr, fmt, ##args)
#define LOGD(fmt, args...) fprintf(stderr, fmt, ##args)
#define LOGV(fmt, args...) 
#define LOGI(fmt, args...) fprintf(stderr, fmt, ##args)

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
static int wrap_certificate = 1;
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
    LOGV("type: %x\n", type);
    length = p[2]|(p[1]<<8)|(p[0]<<16); p+=3;
    LOGV("length: %d\n", length);
    LOGV("version: %x.%x\n", p[0], p[1]);
    p += 2; // version;
            //
    p += 32; //random;
    LOGV("session id length: %d\n", *p);
    p += *p;
    p++;
    int cipher_suite_length = p[1]|(p[0]<<8); p+=2;
    LOG("cipher_suite_length: %d\n", cipher_suite_length);
    p += cipher_suite_length;
    int compress_method_len = *p++;
    LOG("compress_method_len: %d\n", compress_method_len);
    p += compress_method_len;
    int extention_length = p[1]|(p[0]<<8); p+=2;
    LOGV("extention_lengh: %d\n", extention_length);
    const uint8_t *limit = p + extention_length;

    *hostname = 0;
    while (p < limit) {
        uint16_t tag = p[1]|(p[0]<<8);
        uint16_t len = p[3]|(p[2]<<8);
        LOGV("ext tag: %d %d\n", tag, len);
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
static char YOUR_ADDRESS[256] = "::FFFF:100.42.78.149";
static int (*unwind_rewind_client_hello)(uint8_t *, size_t) = NULL;

int rewind_client_hello(uint8_t *snibuff, size_t length)
{
    int i;
    int mylength = 0;
    uint8_t hold[4096];
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

    const uint8_t *limit = p + extention_length;

    char hostname[256] = "";
    while (p < limit) {
        uint16_t tag = p[1]|(p[0]<<8);
        uint16_t len = p[3]|(p[2]<<8);
        LOGV("ext tag: %d %d\n", tag, len);
        uint16_t fqdn_name_len = 0;

        if (tag == TAG_SNI) {
            const uint8_t *sni = (p + 4);
            assert (sni[2] == 0);
            uint16_t list_name_len = sni[1]|(sni[0] << 8);
            fqdn_name_len = sni[4]|(sni[3] << 8);
            assert (fqdn_name_len + 3 == list_name_len);
            memcpy(hostname, sni + 5, fqdn_name_len);
            hostname[fqdn_name_len] = 0;
        }

        if (tag != TAG_SNI) {
            memcpy(dest, p, len + 4);
            dest += len;
            dest += 4;
        } else {
            dest[0] = 0; dest[1] = 0;
            dest[2] = 0; dest[3] = 0;
            size_t namelen = strlen(YOUR_DOMAIN);

            strcpy((char *)dest + 4 + 5, YOUR_DOMAIN);
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
            dest[0] = TAG_SESSION_TICKET >> 8;
            dest[1] = TAG_SESSION_TICKET;
            dest[2] = fqdn_name_len >> 8;
            dest[3] = fqdn_name_len;
            memcpy(dest + 4, hostname, fqdn_name_len);
            for (i = 0; i < fqdn_name_len; i++) dest[i + 4] ^= 0xf;
            dest += (4 + fqdn_name_len);
            // (tag == TAG_SESSION_TICKET)
#endif
        }

        p += len;
        p += 4;
    }

    int extlen = (dest - extention_lengthp - 2);
    extention_lengthp[0] = extlen >> 8;
    extention_lengthp[1] = extlen;
    LOGV("extlen: %d %d\n", extlen, extention_length);

    int newlen = dest - lengthp - 3;
    lengthp[0] = newlen >> 16;
    lengthp[1] = newlen >> 8;
    lengthp[2] = newlen;
    LOGV("newlen: %d %d\n", newlen, mylength);

    memcpy(hold, snibuff, 5);
    int fulllength = (dest - hold - 5);
    hold[3] = fulllength >> 8;
    hold[4] = fulllength;

    int oldlen = (snibuff[3] << 8) | snibuff[4];
    LOGV("fulllen: %d %d %ld\n", fulllength, oldlen, length);

    memcpy(snibuff, hold, dest - hold);
    return dest - hold;
}

int rewind_client_zero(uint8_t *snibuff, size_t length)
{
    return length;
}

static byte pub [] = {
    0x16, 0xd4, 0x68, 0xcd, 0x30, 0xf4, 0x01, 0xaf, 0x98, 0x3e, 0xaa, 0x23,
    0xcc, 0x8d, 0xa9, 0x2f, 0xbf, 0x51, 0x9d, 0x13, 0x32, 0xbd, 0x9f, 0xe9,
    0xb2, 0xbd, 0xc1, 0x5c, 0xb6, 0x8b, 0xee, 0x7f
};

static byte priv[] = {
    0x4a, 0x15, 0x0a, 0xb0, 0x16, 0x8f, 0x74, 0x88, 0xdc, 0xea, 0xfd, 0x81,
    0x83, 0xe6, 0xe6, 0x69, 0xd6, 0x9d, 0xdf, 0x7f, 0x15, 0x84, 0xeb, 0xbf,
    0x88, 0xd0, 0xb5, 0x53, 0x6e, 0x86, 0x1b, 0xd0
};

static byte info[1024];
word32 infoLen = 0;

struct outer_extensions_t {
   uint8_t *tags[18];
   int order[18];
   int tagoff;

   int hold[18];
   int holdlen;

   int len;
   uint8_t buf[4096];
};

#define countof(x) (sizeof(x) / sizeof(x[0]))

static int TAGS[18] = {0x43690, 45, TAG_ENCRYPT_CLIENT_HELLO, 51, 17513, 43, 0, 16, 23, 11, 10, 35, 65281, 13, 27, 5, 18, 60138};

static uint8_t TAGS_01[] = {0xaa, 0xaa, 0x00, 0x00};
static uint8_t TAGS_02[] = {0x00, 0x2d, 0x00, 0x02, 0x01, 0x01};
static uint8_t TAGS_03[] = {0xfe, 0x0d, 0x00, 0x00};
#if 0
static uint8_t TAGS_04[] = {0x00, 0x33, 0x00, 0x00};
#else
static uint8_t TAGS_04[] = {
    0x00,  0x33,  0x04,  0xef,  0x04,  0xed,  0x0a,  0x0a,  0x00,  0x01,  0x00,  0x63,  0x99,  0x04,  0xc0,  0xff, 
    0x0d,  0x55,  0x7e,  0xa7,  0xdb,  0x5f,  0x12,  0xe7,  0x8c,  0x9e,  0xbf,  0x96,  0xe0,  0x03,  0xcd,  0x89, 
    0x6e,  0x27,  0xe2,  0x0d,  0x88,  0x26,  0x86,  0x7f,  0x0d,  0xcc,  0xc0,  0x52,  0x20,  0x77,  0x18,  0x3f, 
    0x13,  0xbd,  0xfb,  0xd0,  0x3f,  0x01,  0x35,  0x4b,  0xa4,  0x50,  0x83,  0x57,  0x61,  0x3e,  0x1b,  0x80, 
    0x5d,  0x04,  0x36,  0xa9,  0xca,  0xa4,  0xbb,  0x97,  0x1c,  0x59,  0x2c,  0xc0,  0xa9,  0x78,  0x05,  0x27, 
    0x40,  0x00,  0x86,  0x27,  0x06,  0x03,  0x56,  0xf7,  0xa6,  0x91,  0x27,  0xb1,  0xba,  0x59,  0x2f,  0xc0, 
    0x71,  0x93,  0xe0,  0x71,  0xaf,  0xd2,  0x83,  0xc3,  0xa8,  0x06,  0xc8,  0xa7,  0x48,  0x80,  0xe3,  0x00, 
    0x8c,  0x48,  0xa2,  0x77,  0x17,  0x1a,  0x4e,  0xfd,  0x83,  0x6d,  0x1c,  0xd3,  0x46,  0x79,  0x26,  0x32, 
    0x82,  0x81,  0x96,  0x91,  0x0c,  0x26,  0x81,  0xb6,  0x79,  0xc3,  0x23,  0x5a,  0x54,  0xd7,  0xbb,  0xa7, 
    0x62,  0xbd,  0x34,  0xa9,  0x25,  0x2f,  0x6c,  0x9e,  0xf4,  0x7b,  0xb3,  0xad,  0x3b,  0x1b,  0x39,  0x3c, 
    0x28,  0xcf,  0xe6,  0x37,  0x8c,  0xcb,  0xab,  0xad,  0xf1,  0xbe,  0x35,  0x28,  0x6a,  0xbb,  0xe0,  0x70, 
    0x0e,  0xd1,  0xa6,  0xee,  0xf9,  0x11,  0x62,  0x78,  0xa8,  0x7e,  0xcc,  0xa2,  0x51,  0x66,  0x09,  0xc3, 
    0xc8,  0x3a,  0x5d,  0xba,  0xae,  0x20,  0x43,  0xb8,  0x08,  0x66,  0x84,  0xda,  0x36,  0x58,  0xdd,  0x93, 
    0x9e,  0x6a,  0xea,  0x3d,  0xea,  0x5a,  0x25,  0xe7,  0x88,  0xc8,  0x23,  0x91,  0x4c,  0xae,  0x53,  0x42, 
    0x42,  0x06,  0xba,  0x6b,  0x14,  0x7a,  0xc7,  0xf6,  0xb0,  0x01,  0xc5,  0xa3,  0x48,  0x58,  0x4c,  0x37, 
    0xd7,  0x08,  0xa5,  0xc7,  0x28,  0xc8,  0xd8,  0x84,  0xab,  0x37,  0xaa,  0xeb,  0xd1,  0xc1,  0x4c,  0xac, 
    0x90,  0x6a,  0xeb,  0xb7,  0xff,  0x73,  0x3b,  0x47,  0x70,  0x15,  0x2e,  0x74,  0x48,  0x1e,  0x21,  0x0a, 
    0x39,  0x71,  0xa4,  0x86,  0xc6,  0x19,  0x94,  0xb6,  0x27,  0x48,  0x69,  0x47,  0x04,  0x79,  0xcf,  0x74, 
    0x29,  0xa0,  0xb5,  0x88,  0xa0,  0xe5,  0x25,  0x2b,  0xab,  0x29,  0xc6,  0xf0,  0xc0,  0x74,  0x23,  0x64, 
    0x02,  0x5d,  0xfc,  0x2f,  0x4a,  0x59,  0x1c,  0x4e,  0x36,  0x33,  0x71,  0x62,  0x3b,  0xed,  0xa6,  0x9e, 
    0x24,  0x93,  0x48,  0xaa,  0x04,  0x00,  0x1e,  0x38,  0x45,  0x24,  0x78,  0xb4,  0x4b,  0x41,  0xc4,  0x7d, 
    0x5c,  0x2a,  0xb1,  0x35,  0xb9,  0x6e,  0x5b,  0xb4,  0xe6,  0xd0,  0x65,  0xa9,  0x51,  0x57,  0x29,  0x68, 
    0x03,  0x8c,  0xb8,  0xb8,  0xa8,  0x54,  0x9a,  0x42,  0x7a,  0x66,  0x51,  0x5c,  0x57,  0x60,  0x10,  0x22, 
    0xc3,  0xba,  0x34,  0x66,  0x43,  0x3d,  0x3d,  0x66,  0x9d,  0x65,  0x94,  0x3c,  0x91,  0x38,  0x4a,  0x24, 
    0x90,  0x2e,  0xb4,  0x39,  0x3c,  0x95,  0x22,  0x13,  0x96,  0x74,  0xcc,  0xc2,  0xcc,  0x4d,  0x13,  0xa4, 
    0x88,  0xe3,  0x34,  0x85,  0xa4,  0x7c,  0x21,  0x9b,  0x45,  0xa8,  0x0f,  0xf0,  0x17,  0xd7,  0x78,  0x34, 
    0x86,  0x74,  0x9c,  0x2c,  0xc8,  0x61,  0x79,  0x2b,  0x0d,  0xa9,  0x08,  0x96,  0x39,  0xcc,  0x84,  0x30, 
    0xa8,  0xa9,  0x9f,  0x50,  0x95,  0x30,  0x96,  0x57,  0xe4,  0xcc,  0x92,  0x9a,  0x61,  0x9d,  0x0c,  0xd4, 
    0xb3,  0xb0,  0x88,  0x8a,  0x48,  0x52,  0x92,  0xea,  0xe7,  0x7b,  0x1f,  0x2a,  0x43,  0x9c,  0x54,  0x7b, 
    0x32,  0x26,  0xb8,  0xeb,  0x54,  0x95,  0x94,  0x22,  0xc5,  0x0b,  0x85,  0x93,  0x1c,  0xbb,  0x5c,  0x2d, 
    0x51,  0x81,  0x03,  0x72,  0x86,  0x27,  0x81,  0xbf,  0x07,  0x22,  0x0b,  0xd0,  0x26,  0x69,  0x45,  0xca, 
    0xa5,  0x12,  0x53,  0x73,  0x07,  0x9b,  0xc2,  0xdd,  0xb3,  0xa3,  0x15,  0x04,  0xb7,  0x13,  0x24,  0x23, 
    0x4a,  0xaa,  0x6a,  0xa4,  0x43,  0x61,  0xf1,  0x50,  0xad,  0x7a,  0x05,  0x36,  0xb8,  0xb9,  0x3f,  0xb5, 
    0x1a,  0xb9,  0xbc,  0x99,  0x93,  0x54,  0x2a,  0x48,  0x3d,  0x8c,  0x60,  0x34,  0x72,  0x94,  0xfd,  0x79, 
    0x8b,  0x7d,  0x33,  0x03,  0x19,  0xe2,  0x59,  0x48,  0x50,  0x71,  0x69,  0x24,  0xc8,  0x5b,  0x22,  0xa1, 
    0xb3,  0x89,  0xa4,  0xb8,  0xe6,  0xab,  0x11,  0x48,  0x3d,  0xe8,  0xdb,  0x5d,  0x85,  0x08,  0xbe,  0xbd, 
    0x49,  0x38,  0x60,  0xf0,  0x07,  0x33,  0x29,  0xaa,  0xee,  0x2c,  0x18,  0x08,  0xb4,  0x31,  0xd1,  0xbb, 
    0xc2,  0xc2,  0xcb,  0x2e,  0x3f,  0x20,  0x2a,  0xc9,  0xe3,  0x5a,  0x59,  0x90,  0xb2,  0x7e,  0xa3,  0xc3, 
    0x0c,  0x41,  0x37,  0x67,  0xc5,  0x3a,  0xc3,  0x57,  0x60,  0xad,  0x08,  0x1c,  0x71,  0x70,  0xaf,  0x55, 
    0xc4,  0x31,  0x39,  0x7c,  0x91,  0x7c,  0xeb,  0x70,  0xe0,  0xb7,  0xc2,  0x46,  0x93,  0x8a,  0xa0,  0x5c, 
    0x6c,  0xc3,  0x82,  0x38,  0x1b,  0xc6,  0xcf,  0x76,  0x47,  0x72,  0xbe,  0x76,  0x42,  0x74,  0x21,  0x0d, 
    0x71,  0x31,  0x11,  0x76,  0xf3,  0xaf,  0x3d,  0xc8,  0x4a,  0xb5,  0xa0,  0xcf,  0x3d,  0xd3,  0x25,  0x3e, 
    0xf4,  0x14,  0x9e,  0x32,  0xa9,  0x8a,  0x17,  0x9a,  0x99,  0x38,  0x59,  0x6e,  0x91,  0xb4,  0x93,  0xb1, 
    0x47,  0x3a,  0x3a,  0xa7,  0xa6,  0xa7,  0x85,  0x24,  0x4a,  0x5c,  0xa5,  0xd4,  0xca,  0x6c,  0xf8,  0x52, 
    0xf5,  0x1c,  0x5e,  0x4a,  0x24,  0x95,  0x23,  0x05,  0xc8,  0xbc,  0x64,  0x59,  0x0a,  0x1b,  0x67,  0xff, 
    0x1c,  0xae,  0x57,  0x07,  0x5c,  0xfa,  0x05,  0x23,  0x66,  0x61,  0x82,  0x5c,  0x0a,  0xc1,  0x55,  0xb6, 
    0x50,  0x8f,  0xaa,  0x95,  0xd1,  0xf2,  0x21,  0xd6,  0x82,  0x7a,  0xd3,  0xc3,  0xbe,  0xc9,  0x35,  0x42, 
    0x4d,  0x3a,  0xa2,  0xbb,  0xc0,  0x2f,  0xbc,  0x27,  0x6d,  0x72,  0xe0,  0x9f,  0x24,  0x56,  0x34,  0xeb, 
    0xf1,  0xa2,  0x05,  0x24,  0x81,  0xcb,  0x46,  0x0c,  0xd5,  0x9b,  0x7c,  0x20,  0x10,  0x8d,  0x7d,  0x28, 
    0xb1,  0x0f,  0xa8,  0x3f,  0x36,  0x06,  0xae,  0xc4,  0x58,  0x05,  0xd0,  0x1a,  0x4b,  0xe2,  0xc3,  0xbc, 
    0x35,  0xa9,  0x4d,  0x95,  0x9a,  0xb1,  0x3b,  0x97,  0x3c,  0x7e,  0x04,  0xaf,  0x69,  0x01,  0x79,  0x0a, 
    0x67,  0x86,  0x94,  0xb4,  0x02,  0xf4,  0xd1,  0x50,  0x0a,  0x5b,  0x5a,  0xaf,  0x27,  0xbc,  0xbf,  0xf3, 
    0x5b,  0x3d,  0x94,  0x4b,  0x8f,  0xa1,  0xca,  0x65,  0x8c,  0x1e,  0xe0,  0xc4,  0x95,  0xfe,  0x59,  0xa7, 
    0x15,  0x3c,  0x0f,  0x7a,  0x8a,  0x34,  0xbd,  0xa6,  0x5f,  0xd0,  0xa4,  0xa2,  0x40,  0x87,  0x36,  0x0a, 
    0x93,  0xb3,  0x4d,  0xd2,  0x6a,  0xc9,  0x62,  0x4c,  0x05,  0x27,  0x61,  0x72,  0x41,  0x71,  0xe1,  0x97, 
    0x4c,  0x47,  0xc8,  0xb3,  0xa9,  0xf4,  0x82,  0xc0,  0x15,  0xcd,  0x4a,  0xf0,  0x27,  0x45,  0x92,  0xaa, 
    0x7a,  0x12,  0x0f,  0x6b,  0x5a,  0xbb,  0xef,  0x18,  0x6c,  0xaa,  0xd4,  0x89,  0x91,  0x06,  0x34,  0x5a, 
    0xf3,  0x17,  0xef,  0x01,  0x43,  0xc0,  0x64,  0xa2,  0xff,  0x42,  0x89,  0x91,  0xac,  0x14,  0x12,  0x04, 
    0x8f,  0xc1,  0x56,  0xbf,  0x54,  0xa9,  0x87,  0x37,  0xf6,  0xaf,  0xe1,  0x00,  0x5c,  0xc8,  0x50,  0xb7, 
    0xf0,  0xd1,  0x36,  0xe7,  0x00,  0xb3,  0x27,  0x08,  0x62,  0x96,  0x6c,  0x92,  0xce,  0x57,  0xbf,  0x53, 
    0xf2,  0x43,  0x62,  0x28,  0x55,  0x74,  0xb8,  0xb2,  0xdd,  0xd7,  0x94,  0x41,  0x9a,  0x5f,  0x46,  0x50, 
    0x95,  0x8d,  0x63,  0x84,  0xa1,  0x21,  0xae,  0x09,  0x45,  0x45,  0x4c,  0xd7,  0x89,  0x4d,  0xb4,  0xc2, 
    0x87,  0xf4,  0x44,  0x03,  0xec,  0xb1,  0x5b,  0x59,  0x39,  0x36,  0x2c,  0xb7,  0x45,  0x7b,  0x70,  0x6f, 
    0x8a,  0x54,  0x11,  0x62,  0xae,  0x01,  0x05,  0x75,  0xaa,  0x5b,  0x6a,  0xac,  0xa2,  0xc5,  0x5b,  0x61, 
    0x26,  0xa4,  0x39,  0x8a,  0x9a,  0x05,  0x00,  0xf7,  0xb9,  0x09,  0x6a,  0x49,  0xb2,  0xde,  0x55,  0x75, 
    0xda,  0xd3,  0x09,  0x42,  0xe7,  0x61,  0x0e,  0xe0,  0xbb,  0x46,  0x10,  0x92,  0x04,  0x66,  0xa6,  0x0b, 
    0x47,  0x41,  0xce,  0x0a,  0xaa,  0x8a,  0x55,  0x8e,  0xd6,  0x8a,  0x8b,  0xdb,  0xe5,  0x3a,  0x31,  0xf6, 
    0xac,  0xfd,  0x6c,  0x0a,  0xfa,  0x13,  0x59,  0xf2,  0xa8,  0xc8,  0xfa,  0xfc,  0x31,  0x62,  0xf8,  0xb3, 
    0x20,  0x53,  0x6c,  0x65,  0xf2,  0xc5,  0x34,  0x50,  0xad,  0xfb,  0xc4,  0x9c,  0xbd,  0x64,  0x65,  0x76, 
    0x27,  0x0b,  0x5e,  0xc1,  0x37,  0xfb,  0x99,  0xa3,  0xe1,  0x61,  0x2e,  0x9e,  0x2a,  0x7e,  0x24,  0x82, 
    0x24,  0x3c,  0x42,  0x8c,  0x49,  0x9a,  0x22,  0x91,  0xbc,  0x70,  0xe8,  0x4a,  0x3a,  0x9e,  0xa8,  0x7a, 
    0xef,  0xa7,  0x0e,  0x30,  0x38,  0x84,  0xa1,  0x5a,  0xba,  0xc1,  0x20,  0x7e,  0x48,  0x07,  0x19,  0x76, 
    0x7a,  0x71,  0x8e,  0x27,  0x7d,  0xcc,  0x16,  0x88,  0xad,  0x77,  0xba,  0x34,  0xf4,  0xa2,  0x77,  0x93, 
    0xc9,  0xd1,  0xaa,  0xbe,  0x80,  0x94,  0x4b,  0x21,  0x71,  0xc0,  0x0f,  0x98,  0xae,  0x97,  0x0c,  0x58, 
    0x07,  0x88,  0xae,  0xfc,  0x39,  0x70,  0xeb,  0xb7,  0x98,  0x62,  0xe6,  0xa7,  0x30,  0xda,  0xc2,  0x0e, 
    0x6e,  0x28,  0x1a,  0x20,  0x18,  0x7a,  0xeb,  0x26,  0xf4,  0xaa,  0xe9,  0xa5,  0x9d,  0xbf,  0x7a,  0x0e, 
    0xb2,  0x2a,  0x1c,  0x8f,  0x59,  0x2c,  0x94,  0x06,  0x40,  0x01,  0x09,  0x03,  0xa3,  0x4c,  0xd8,  0x00, 
    0x1d,  0x00,  0x20,  0x3e,  0x0e,  0x7d,  0x26,  0x38,  0x76,  0x37,  0xe0,  0xb9,  0xe2,  0x89,  0xab,  0x4d, 
    0xc2,  0x6e,  0xca,  0x53,  0x45,  0xf1,  0x38,  0xe0,  0x01,  0x6c,  0x61,  0x66,  0xb3,  0x3a,  0xbc,  0x7c, 
    0xfc,  0xc1,  0x0b
};
#endif
static uint8_t TAGS_05[] = {0x44, 0x69, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32};
static uint8_t TAGS_06[] = {0x00, 0x2b, 0x00, 0x07, 0x06, 0x9a, 0x9a, 0x03, 0x04, 0x03, 0x03};
static uint8_t TAGS_07[400] = {0x00, 0x00, 0x00, 0x16, 0x00, 0x14, 0x00, 0x00, 0x11, 0x64, 0x6e, 0x73, 0x70, 0x6f, 0x64, 0x2e, 0x71, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2e, 0x63, 0x6f, 0x6d};
static uint8_t TAGS_08[] = {0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31};
static uint8_t TAGS_09[] = {0x00, 0x17, 0x00, 0x00};
static uint8_t TAGS_10[] = {0x00, 0x0b, 0x00, 0x02, 0x01, 0x00};
static uint8_t TAGS_11[] = {0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a, 0xea, 0xea, 0x63, 0x99, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18};
static uint8_t TAGS_12[] = {0x00, 0x23, 0x00, 0x00};
static uint8_t TAGS_13[] = {0xff, 0x01, 0x00, 0x01, 0x00};
static uint8_t TAGS_14[] = {0x00, 0x0d, 0x00, 0x12, 0x00, 0x10, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01};
static uint8_t TAGS_15[] = {0x00, 0x1b, 0x00, 0x03, 0x02, 0x00, 0x02};
static uint8_t TAGS_16[] = {0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00};
static uint8_t TAGS_17[] = {0x00, 0x12, 0x00, 0x00};
static uint8_t TAGS_18[] = {0xea, 0xea, 0x00, 0x01, 0x00};

static uint8_t *TAGS_DATA[18] = {TAGS_01, TAGS_02, TAGS_03, TAGS_04, TAGS_05, TAGS_06, TAGS_07, TAGS_08, TAGS_09, TAGS_10, TAGS_11, TAGS_12, TAGS_13, TAGS_14, TAGS_15, TAGS_16, TAGS_17, TAGS_18};

static int outer_extensions_init(struct outer_extensions_t *ctx)
{
    int i;

    for (i = 0; i < countof(ctx->tags); i++) {
	ctx->order[i] = TAGS[i];
	ctx->tags[i]  = TAGS_DATA[i];
    }
    ctx->holdlen = 0;
    ctx->tagoff = 0;
    ctx->len = 0;

    return 0;
}

static uint8_t *tag_alloc(struct outer_extensions_t *ctx, const uint8_t *buf, size_t len)
{
    uint8_t *tagbuf = ctx->buf + ctx->len;

    assert(ctx->len + len < sizeof(ctx->buf));
    memcpy(tagbuf, buf, len);
    ctx->len += len;

    return tagbuf;
}

static int outer_extensions_add(struct outer_extensions_t *ctx, int tag, const uint8_t buf[], size_t len)
{
    int i, j;
    int okay = 0;

    for (i = 0; i < countof(TAGS); i++) {
	if (tag == ctx->order[i]) {
	    ctx->tags[i] = tag_alloc(ctx, buf, len);
	    if (ctx->tagoff > i) {
		int order = ctx->order[i];
		uint8_t *tmp = ctx->tags[i];
		for (j = i; j < ctx->tagoff; j++) {
		    ctx->order[j] = ctx->order[j + 1];
		    ctx->tags[j] = ctx->tags[j + 1];
		}
		ctx->order[j] = order;
		ctx->tags[j] = tmp;
	    } else {
		ctx->tagoff = i;
	    }
	    okay = 1;

	    LOGV("ctx->holdlen = %d, ctx->len = %d, ctx->tagoff = %d\n", ctx->holdlen, ctx->len, ctx->tagoff);
	    ctx->hold[ctx->holdlen++] = tag;
	    break;
	}
    }

    if (okay == 0) LOGV("ctx->holdlen = %d, ctx->len = %d, ctx->tagoff = %d, lost tag=%d\n", ctx->holdlen, ctx->len, ctx->tagoff, tag);

    return okay;
}

static int outer_extensions_flush(struct outer_extensions_t *ctx, uint8_t *buf, size_t len)
{
    int count = ctx->holdlen;

    if (count == 0) return 0;

    ctx->holdlen = 0;
    buf[0] = (TAG_OUTER_EXTENSIONS >> 8);
    buf[1] = (TAG_OUTER_EXTENSIONS & 0xff);

    int val = count * 2 + 1;
    buf[2] = (val >> 8);
    buf[3] = (val);
    buf[4] = (count << 1);

    for (int i = 0; i < count; i++) {
	int code = ctx->hold[i];
	buf[5 + i * 2] = (code >> 8);
	buf[5 + i * 2 + 1] = (code);
	LOGV("outer_extensions_flush: code=%d\n", code);
    }

    LOGV("outer_extensions_flush: %d\n", count);

    return 4 + val;
}

static int should_pullout(int tag)
{
   int allow_tags[] = {0xeaea, 0x0033, 0x0010, 0x000a, 0x001b, 0x002d, 0x0005, 0x4469, 0x0012, 0x000d, 0xcaca};

   for (int i = 0; i < countof(allow_tags); i++) {
       if (allow_tags[i] == tag) return 1;
   }

    return (tag != 0 && tag != TAG_ENCRYPT_CLIENT_HELLO);
}

static int setrandomize(void *buf, size_t len)
{
    int i;
    int *data = (int *)buf;

    for (i = 0; len >= 4; i++, len -= 4)
	data[i] = random();

    if (len > 0) {
	int mask = ~0 << ((4 - len) * 8);
	data[i] &= htonl(~mask);
	data[i] |= htonl(mask & random());
    }

    return 0;
}

static void xxdump(const char *title, const void *data, size_t len)
{
    char line[128];
    const uint8_t *ptr;
    const uint8_t *start = (const uint8_t *)data;
    const char map[] = "0123456789abcdef0";

    ptr = start;
    for (; len >= 16; len -= 16) {
	char *p = line;

	for (int i = 0; i < 16; i++) {
	    int code = *ptr++;
	    *p++ = map[code >> 4];
	    *p++ = map[code & 0xf];
	    *p++ = ' ';
	}

	if (p > line) {
	    p--;
	    *p = 0;
	}

	printf("%s: %s\n", title, line); 
    }

    char *p1 = line;

    for (int i = 0; i < len; i++) {
	int code = *ptr++;
	*p1++ = map[code >> 4];
	*p1++ = map[code & 0xf];
	*p1++ = ' ';
    }

    if (p1 > line) {
	p1--;
	*p1 = 0;
    }

    if (p1 > line) {
	printf("%s: %s\n", title, line); 
    }

    return ;
}

static int load_encrypt_client_hello(const void *ch, size_t chlen, const void *payload, size_t payload_len, const void *enc, size_t enclen, uint8_t *output, size_t *outlen)
{
    word16 kemId = 0, kdfId = 0, aeadId =0;

    kemId = DHKEM_X25519_HKDF_SHA256;
    kdfId = HKDF_SHA256;
    aeadId = HPKE_AES_128_GCM;

    Hpke hpke[1];
    void *heap = NULL;
    curve25519_key receiverPrivkey0[1];
    int ret = wc_HpkeInit(hpke, kemId, kdfId, aeadId, heap);

    wc_curve25519_init(receiverPrivkey0);
    wc_curve25519_import_private_raw(priv, sizeof(priv), pub, sizeof(pub), receiverPrivkey0);

    byte aad[4096] = {};
    assert(sizeof(aad) > chlen);
    memcpy(aad, ch, chlen);

    uint8_t *d1 = (uint8_t*)ch;
    uint8_t *d2 = (uint8_t*)payload;
    memset(aad + (d2 - d1), 0, payload_len);

    ret = wc_HpkeOpenBase(hpke, receiverPrivkey0, (const byte *)enc,
		    enclen, info, infoLen, aad, chlen, (byte *)payload, payload_len - 16, output);

    if (ret == 0) *outlen = payload_len - 16;
    LOGI("load_encrypt_client_hello: ret=%d\n", ret);
    LOGI("TODO:XXXX load_encrypt_client_hello: ret=%d infoLen=%d aadlen=%d payload_len=%d\n", ret, infoLen, chlen, payload_len);

    if (ret) {
    xxdump("enc", enc, enclen);
    xxdump("info", info, infoLen);
    xxdump("aad", aad, chlen);
    xxdump("payload", payload, payload_len);
    xxdump("pub", pub, 32);
    xxdump("priv", priv, 32);
    }

    return ret;
}

int decode_client_hello(uint8_t *decoded, size_t ddsz, const uint8_t *plain, size_t len, const uint8_t *outer, size_t outerlen, size_t *outlen)
{
    uint8_t *dest = decoded;
    const uint8_t *p = plain;
    const uint8_t *refer = outer;

    uint8_t *ech_start = (uint8_t *)p;

    dest[0] = p[0]; dest[1] = p[1];
    dest += 2;
    p += 2; // version;
    refer += 2;

    memcpy(dest, p, 32);
    dest += 32;
    p += 32; //random;
    refer += 32;

    dest[0] = refer[0]; //session id length
    memcpy(&dest[1], &refer[1], dest[0]);
    dest += dest[0];
    dest++;

    refer += refer[0];
    refer++;

    assert(*p ==0);
    p += *p;
    p++;

    int cipher_suite_length = p[1]|(p[0]<<8);
    int cipher_suite_length_out = refer[1]|(refer[0]<<8);
    dest[0] = p[0];
    dest[1] = p[1];
    dest+=2;
    p+=2;
    refer+=2;

    memcpy(dest, p, cipher_suite_length);
    dest += cipher_suite_length;
    p += cipher_suite_length;
    refer += cipher_suite_length_out;

    int compress_method_len = *p;
    int compress_method_len_out = *refer;
    *dest++ = *p++;
    refer++;

    memcpy(dest, p, compress_method_len);
    dest += compress_method_len;
    p += compress_method_len;
    refer += compress_method_len_out;

    int extention_length = p[1]|(p[0]<<8);
    int extention_length_out = refer[1]|(refer[0]<<8);
    uint8_t *extention_lengthp = dest;
    dest += 2;
    p += 2;
    refer += 2;

    const uint8_t *limit = p + extention_length;
    const uint8_t *limit_out = refer + extention_length_out;

    int last_tag = -1;
    char hostname[256] = "";

    int out_tag_indx = 0;
    while (p < limit) {
        uint16_t tag = p[1]|(p[0]<<8);
        uint16_t len = p[3]|(p[2]<<8);
        LOGV("ext tag: %d %d %d\n", tag, len, p[4]);
        uint16_t fqdn_name_len = 0;

	if (tag == TAG_OUTER_EXTENSIONS) {
	    const uint8_t *start = (p + 4);
	    int len = *start++;

	    for (int i = 0; i < len; i +=2) {
		uint16_t etag = start[i + 1]|(start[i] << 8);
		LOGV("outer etag: 0x%04x\n", etag);

		int found = 0;
		while (refer < limit_out) {
		    uint16_t tag_out = refer[1]|(refer[0]<<8);
		    uint16_t len_out = refer[3]|(refer[2]<<8);

		    if (etag == tag_out) {
			LOGV("match tag: 0x%04x\n", tag_out);
			memcpy(dest, refer, len_out + 4);
			dest += len_out;
			dest += 4;
			found = 1;
			break;
		    }

		    // LOGV("mismatch tag%d: 0x%04x 0x%04x\n", out_tag_indx++, tag_out, etag);
                    refer += len_out;
                    refer += 4;
		}

		if (found == 0) LOGV("mismatch tag%d: 0x%04x 0x%04x\n", out_tag_indx++, 0, etag);
	    }
	} else {
	    memcpy(dest, p, len + 4);
	    dest += len;
	    dest += 4;
	}

        last_tag = tag;
        p += len;
        p += 4;
    }

    int extlen = (dest - extention_lengthp - 2);
    extention_lengthp[0] = extlen >> 8;
    extention_lengthp[1] = extlen;

    *outlen = dest - decoded;
    return 0;
}

int encode_client_hello(uint8_t *encoded, size_t ddsz, const uint8_t *plain, size_t len, size_t *outlen)
{
    int i, ret;
    uint8_t *dest = encoded;
    const uint8_t *p = plain;
    uint8_t _hold[4096];
    uint8_t *inner = _hold;

    // prepare outer variant value
    uint8_t session_id[132];

    const uint8_t *ech_start = p;

    inner[0] = p[0]; inner[1] = p[1];
    inner += 2;
    p += 2; // version;

    memcpy(inner, p, 32);
    inner += 32;
    p += 32; //random;

    // empty session_id
    inner[0] = 0;
    inner++;

    memcpy(session_id + 1, p + 1, p[0]);
    session_id[0] = p[0];
    p += p[0];
    p++;

    int cipher_suite_length = p[1]|(p[0]<<8);
    inner[0] = p[0];
    inner[1] = p[1];
    inner+=2;
    p+=2;

    memcpy(inner, p, cipher_suite_length);
    inner += cipher_suite_length;
    p += cipher_suite_length;

    int compress_method_len = *p;
    *inner++ = *p++;

    memcpy(inner, p, compress_method_len);
    inner += compress_method_len;
    p += compress_method_len;

    int extention_length = p[1]|(p[0]<<8);
    uint8_t *extention_lengthp = inner;
    inner += 2;
    p += 2;

    const uint8_t *limit = p + extention_length;

    int last_tag = -1;
    char hostname[256] = "";

    int out_tag_indx = 0;
    struct outer_extensions_t outter_ext;

    outer_extensions_init(&outter_ext);
    while (p < limit) {
        uint16_t tag = p[1]|(p[0]<<8);
        uint16_t len = p[3]|(p[2]<<8);
        LOGV("ext tag: %d %d\n", tag, len);

	if (!should_pullout(tag) || outer_extensions_add(&outter_ext, tag, p, len + 4) == 0) {
	    inner += outer_extensions_flush(&outter_ext, inner, 1024);
	    memcpy(inner, p, len + 4);
	    inner += len;
	    inner += 4;
	}

        last_tag = tag;
        p += len;
        p += 4;
    }
    inner += outer_extensions_flush(&outter_ext, inner, 1024);

    int extlen = (inner - extention_lengthp - 2);
    extention_lengthp[0] = extlen >> 8;
    extention_lengthp[1] = extlen;

    word16 kemId = 0, kdfId = 0, aeadId =0;

    kemId = DHKEM_X25519_HKDF_SHA256;
    kdfId = HKDF_SHA256;
    aeadId = HPKE_AES_128_GCM;

    Hpke hpke[1];
    void *heap = NULL;
    curve25519_key ephemeralKey[1];
    curve25519_key receiverPrivkey0[1];
    ret = wc_HpkeInit(hpke, kemId, kdfId, aeadId, heap);

    wc_curve25519_init(receiverPrivkey0);
    wc_curve25519_import_public(pub, sizeof(pub), receiverPrivkey0);
    wc_curve25519_import_private_raw(priv, sizeof(priv), pub, sizeof(pub), receiverPrivkey0);

    dest[0] = 0x03;
    dest[1] = 0x03;
    dest += 2;

    setrandomize(dest, 32);
    dest += 32;

    dest[0] = session_id[0];
    memcpy(dest + 1, session_id + 1, session_id[0]);
    dest+= dest[0];
    dest++;


    uint8_t cipher_suites[] = {
	0x3a, 0x3a, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30,
	0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35
    };

    dest[0] = sizeof(cipher_suites) >> 8;
    dest[1] = sizeof(cipher_suites);
    dest += 2;
    memcpy(dest, cipher_suites, sizeof(cipher_suites));
    dest += sizeof(cipher_suites);

    dest[0] = 1;
    dest[1] = 0;
    dest += 2;

    uint8_t *extention_start = dest;
    uint8_t *pubKey = NULL;
    uint8_t *ciphertext_start = NULL;
    size_t payload_len = 0;
    word16 pubKeySz = 0;

    dest += 2;
    for (i = 0; i < countof(outter_ext.tags); i++) {
	uint8_t *p = outter_ext.tags[i];

        uint16_t tag = p[1]|(p[0] << 8);
        uint16_t len = p[3]|(p[2] << 8);

	if (tag == TAG_ENCRYPT_CLIENT_HELLO) {
	    uint8_t *start = p = dest;
	    start += 4;
	    pubKey = start + 8;

	    pubKeySz = 32;
	    ret = wc_HpkeSerializePublicKey(hpke, receiverPrivkey0, pubKey, &pubKeySz);
	    start[6] = (pubKeySz >> 8);
	    start[7] = (pubKeySz);

	    start = start + 8 + pubKeySz;

	    payload_len = inner - _hold + 16;
	    start[0] = (payload_len >> 8);
	    start[1] = (payload_len);

	    ciphertext_start = start + 2;
	    memset(start + 2, 0, payload_len);
	    start += (2 + payload_len);

	    dest[0] = (TAG_ENCRYPT_CLIENT_HELLO >> 8);
	    dest[1] = (TAG_ENCRYPT_CLIENT_HELLO & 0xff);
	    dest[2] = (start - dest - 4) >> 8;
	    dest[3] = (start - dest - 4);

	    dest[4] = 0;
	    dest[4] = 0; // avoid GFW
	    dest[5] = 0;
	    dest[6] = 1;
	    dest[7] = 0;
	    dest[8] = 1;
	    dest[9] = 0x95;
	    len = (start - dest - 4);
	}

	memmove(dest, p, len + 4);
	dest += (len + 4);
    }

    uint16_t extlen0 = (dest - extention_start - 2);
    extention_start[0] = (extlen0 >> 8);
    extention_start[1] = (extlen0);

    uint8_t ciphertext[4096];
#if 0
    WC_RNG rng[1];
    ret = wc_InitRng(rng);
    assert(ret == 0);

    void *ephemeralKey1 = 0, * receiverPrivkey1 = 0;
    ret = wc_HpkeGenerateKeyPair(hpke, &ephemeralKey1, rng);
    assert(ret == 0);
#endif

    LOGV("payload_len=%d infoLen %d %d\n", payload_len, infoLen, dest - encoded);
    ret = wc_HpkeSealBase(hpke, receiverPrivkey0, receiverPrivkey0,
		    (byte*)info, (word32)infoLen,
		    (byte*)encoded, (word32)(dest - encoded),
		    (byte*)_hold, payload_len - 16,
		    ciphertext);

    if (ret) {
	xxdump("info", info, infoLen);
	xxdump("aad", encoded, dest - encoded);
	xxdump("cipher", ciphertext, payload_len);
	xxdump("priv", priv, sizeof(priv));
	xxdump("pub", pub, sizeof(pub));
	xxdump("enc", pubKey, pubKeySz);
    }

    uint8_t plaintext0[4096];
    int retval = wc_HpkeOpenBase(hpke, receiverPrivkey0, pubKey, pubKeySz,
		    (byte*)info, (word32)infoLen,
		    (byte*)encoded, (word32)(dest - encoded),
		    ciphertext, payload_len - 16,
		    plaintext0);


    memcpy(ciphertext_start, ciphertext, payload_len);

    LOGV("outter length: %d ret=%d, retval=%d, payload_len=%d, infoLen=%d aadlen=%d\n", dest - encoded, ret, retval, payload_len, infoLen, dest - encoded);
    *outlen = dest - encoded;
    assert(ret == 0);
    return 0;
}

int rewind_encrypt_client_hello(uint8_t *snibuff, size_t length)
{
    int i;
    int modify = 0;
    int mylength = 0;
    uint8_t hold[4096];
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

    uint8_t *ech_start = p;
    size_t outlen = 0;
    uint8_t decoded[8192];

    encode_client_hello(decoded, sizeof(decoded), snibuff + 9, length - 9, &outlen);

    memcpy(snibuff + 9, decoded, outlen);
    int newlen = outlen;
    snibuff[6] = newlen >> 16;
    snibuff[7] = newlen >> 8;
    snibuff[8] = newlen;

    newlen = outlen + 4;
    snibuff[3] = newlen >> 8;
    snibuff[4] = newlen;
    return outlen + 9;
}

int unwind_encrypt_client_hello(uint8_t *snibuff, size_t length)
{
    int i;
    int modify = 0;
    int mylength = 0;
    uint8_t hold[4096];
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

    uint8_t *ech_start = p;

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

    const uint8_t *limit = p + extention_length;

    int last_tag = -1;
    char hostname[256] = "";
    while (p < limit) {
        uint16_t tag = p[1]|(p[0]<<8);
        uint16_t len = p[3]|(p[2]<<8);
        LOGV("ext tag: %d %d\n", tag, len);
        uint16_t fqdn_name_len = 0;

        if (tag == TAG_SNI) {
            const uint8_t *sni = (p + 4);
            assert (sni[2] == 0);
            uint16_t list_name_len = sni[1]|(sni[0] << 8);
            fqdn_name_len = sni[4]|(sni[3] << 8);
            assert (fqdn_name_len + 3 == list_name_len);
            memcpy(hostname, sni + 5, fqdn_name_len);
            hostname[fqdn_name_len] = 0;
            LOGI("source: %s\n", hostname);
	} else if (tag == TAG_ENCRYPT_CLIENT_HELLO) {
            const uint8_t *start = (p + 4);
            LOGI("TAG_ENCRYPT_CLIENT_HELLO:\n");
            LOGV("client hello type: %d\n", start[0]);
            LOGV("kdfid: %d\n", (start[1] << 8) | start[2]);
            LOGV("aeadid: %d\n", (start[3] << 8) | start[4]);
            LOGV("config id: %d\n", start[5]);
            int enclen = (start[6] << 8) | start[7];
            LOGV("enclen: %d\n", enclen);
	    // dumpData("enc", start + 8, enclen);
            int payload_len = (start[8 + enclen] << 8) | start[8 + enclen +1];
            LOGV("payload_len: %d\n", payload_len);
	    // dumpData("payload", start + 8 + enclen + 2, payload_len);
            // dumpAadData("aad", ech_start, snibuff + length - ech_start, start + 8 + enclen + 2, payload_len);

	    uint8_t plain[4096], decoded[4096];
            size_t outlen = 0;
            int ret = load_encrypt_client_hello(ech_start, snibuff + length - ech_start, start + 8 + enclen + 2, payload_len, start + 8, enclen, plain, &outlen);
	    if (ret == 0) {
                decode_client_hello(decoded, 1024, plain, outlen, snibuff + 9, length - 9, &outlen);
		memcpy(snibuff + 9, decoded, outlen);
		int newlen = outlen;
		snibuff[6] = newlen >> 16;
		snibuff[7] = newlen >> 8;
		snibuff[8] = newlen;

		newlen = outlen + 4;
		snibuff[3] = newlen >> 8;
		snibuff[4] = newlen;

                return outlen + 9;
	    }
	} else {
	    memcpy(dest, p, len + 4);
	    dest += len;
	    dest += 4;
	}

        last_tag = tag;
        p += len;
        p += 4;
    }

    int extlen = (dest - extention_lengthp - 2);
    extention_lengthp[0] = extlen >> 8;
    extention_lengthp[1] = extlen;
    LOGV("extlen: %d %d\n", extlen, extention_length);

    int newlen = dest - lengthp - 3;
    lengthp[0] = newlen >> 16;
    lengthp[1] = newlen >> 8;
    lengthp[2] = newlen;
    LOGV("newlen: %d %d\n", newlen, mylength);

    memcpy(hold, snibuff, 5);
    int fulllength = (dest - hold - 5);
    hold[3] = fulllength >> 8;
    hold[4] = fulllength;

    int oldlen = (snibuff[3] << 8) | snibuff[4];
    LOGV("fulllen: %d %d %ld\n", fulllength, oldlen, length);

    set_hook_name = 0;
    if (modify == 0 && strcmp(YOUR_DOMAIN, hostname)) { set_hook_name = 1; }
    if (modify == 0) return length;
    memcpy(snibuff, hold, dest - hold);
    return dest - hold;
}

int unwind_client_hello(uint8_t *snibuff, size_t length)
{
    int i;
    int modify = 0;
    int mylength = 0;
    uint8_t hold[4096];
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

    const uint8_t *limit = p + extention_length;

    int last_tag = -1;
    char hostname[256] = "";
    while (p < limit) {
        uint16_t tag = p[1]|(p[0]<<8);
        uint16_t len = p[3]|(p[2]<<8);
        LOGV("ext tag: %d %d\n", tag, len);
        uint16_t fqdn_name_len = 0;

        if (tag == TAG_SNI) {
            const uint8_t *sni = (p + 4);
            assert (sni[2] == 0);
            uint16_t list_name_len = sni[1]|(sni[0] << 8);
            fqdn_name_len = sni[4]|(sni[3] << 8);
            assert (fqdn_name_len + 3 == list_name_len);
            memcpy(hostname, sni + 5, fqdn_name_len);
            hostname[fqdn_name_len] = 0;
            LOGI("source: %s\n", hostname);
        } else if (tag == TAG_SESSION_TICKET && last_tag == TAG_SNI) {
            if (strcmp(hostname, YOUR_DOMAIN) == 0) {
                memcpy(hostname, p + 4, len);
                hostname[len] = 0;
                fqdn_name_len = strlen(hostname);
                for (i = 0; i < fqdn_name_len; i++) hostname[i] ^= 0xf;
                LOGI("target: %s\n", hostname);
            }
        }

        if (strcmp(hostname, YOUR_DOMAIN) == 0 && tag == TAG_SNI) {

        } else if (tag != TAG_SESSION_TICKET || last_tag != TAG_SNI) {
            memcpy(dest, p, len + 4);
            dest += len;
            dest += 4;
        } else if (tag == TAG_SESSION_TICKET) {
            dest[0] = 0; dest[1] = 0;
            dest[2] = 0; dest[3] = 0;
            size_t namelen = strlen(hostname);

            strcpy((char *)dest + 4 + 5, hostname);
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

    int extlen = (dest - extention_lengthp - 2);
    extention_lengthp[0] = extlen >> 8;
    extention_lengthp[1] = extlen;
    LOGV("extlen: %d %d\n", extlen, extention_length);

    int newlen = dest - lengthp - 3;
    lengthp[0] = newlen >> 16;
    lengthp[1] = newlen >> 8;
    lengthp[2] = newlen;
    LOGV("newlen: %d %d\n", newlen, mylength);

    memcpy(hold, snibuff, 5);
    int fulllength = (dest - hold - 5);
    hold[3] = fulllength >> 8;
    hold[4] = fulllength;

    int oldlen = (snibuff[3] << 8) | snibuff[4];
    LOGV("fulllen: %d %d %ld\n", fulllength, oldlen, length);

    set_hook_name = 0;
    if (modify == 0 && strcmp(YOUR_DOMAIN, hostname)) { set_hook_name = 1; }
    if (modify == 0) return length;
    memcpy(snibuff, hold, dest - hold);
    return dest - hold;
}

void dump(char *buff, size_t len, struct tls_header *header, const char *title)
{
    LOGV("%s: %d %x.%x %d\n", title, header->type, header->major, header->minor, header->length);
    if (22 == header->type) {
        int length = 0;
        uint8_t *p = (uint8_t*)buff;
        if (*p == 11) {
            LOGV("certificate\n");
            return ;
        }
		int type = *p++;
        LOGV("type: %x\n", type);
        length = p[2]|(p[1]<<8)|(p[0]<<16); p+=3;
        LOGV("length: %d\n", length);
        LOGV("version: %x.%x\n", p[0], p[1]);
        p += 2; // version;
                //
        p += 32; //random;
        LOGV("session id length: %d\n", *p);
        p += *p;
        p++;
        int cipher_suite_length = p[1]|(p[0]<<8); p+=2;
        if (buff[0] == 2) {
            LOGV("cipher_suite: %x\n", cipher_suite_length);
        } else {
            LOGV("cipher_suite_length: %d\n", cipher_suite_length);
            p += cipher_suite_length;
        }
        int compress_method_len = *p++;
        LOGV("compress_method_len: %d\n", compress_method_len);
        p += compress_method_len;
        int extention_length = p[1]|(p[0]<<8); p+=2;
        LOGV("extention_lengh: %d\n", extention_length);
        const uint8_t *limit = p + extention_length;

        while (p < limit) {
            uint16_t tag = p[1]|(p[0]<<8);
            uint16_t len = p[3]|(p[2]<<8);
            LOGV("ext tag: %d %d\n", tag, len);
            p += len;
            p += 4;
        }

    }
}

static int do_certificate_wrap(char *buf, size_t len)
{
    int i;
    uint8_t hold[MAXSIZE];
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
    char buff[MAXSIZE];
    int n, l, i;
    struct tls_header header;
    // infinite loop for chat

    // read the message from client and copy it in buffer
    l = read_flush(connfd, buff, 5);
    LOGV("%d l %d\n", connfd, l);
    if (l == 0) shutdown(remotefd, SHUT_WR);
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

    assert(header.length  < MAXSIZE);
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
    char buff[MAXSIZE];
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
        LOGI("rehandshake origin hostname: %s: %s\n", hostname, "");

        int newlen = unwind_rewind_client_hello(buff, header.length + 5);
        l = header.length = newlen - 5;

        get_sni_name(buff + 5, header.length, hostname);
        LOGI("rehandshake convert hostname: %s %s\n", hostname, "");
        if (*hostname == 0) {
            LOGI("rehandshake failure: %s %s tag=%x\n", hostname, "", buff[5]);
        }
    }

    // dump(buff + 5, l, &header, "PUSH");
    int ignore;
    return write_flush(remotefd, buff, l + 5, &ignore);
}

int pipling(int connfd, int remotefd, int *statp)
{
    char buff[65536];
    // size_t len = read(connfd, buff, sizeof(buff));
    size_t len = recv(connfd, buff, sizeof(buff), MSG_DONTWAIT);
    if (len == -1 && errno == EAGAIN) return 1;
    if (len == -1) return -1;
    if (len == 0) shutdown(remotefd, SHUT_WR);
    if (len == 0) return 0;
    return write_flush(remotefd, buff, len, statp);
}

int mptcp_enable(int sockfd)
{
    int error;
    int enable = 1;
    char pathmanager[] = "ndiffports";

    error = setsockopt(sockfd, SOL_TCP, TCP_FASTOPEN_CONNECT, &enable, sizeof(enable)); 

#ifdef MPTCP_PATH_MANAGER
    error = setsockopt(sockfd, SOL_TCP, MPTCP_PATH_MANAGER, pathmanager, sizeof(pathmanager));
#endif

#ifdef MPTCP_ENABLED
    error = setsockopt(sockfd, SOL_TCP, MPTCP_ENABLED, &enable, sizeof(int));
#endif

    return 0;
}

int setup_remote(struct sockaddr_in6 *cli, char *hostname)
{
    int i;
    int rc = -1;
    int remotefd = -1;
    struct hostent *phostent = NULL;

    if (RELAY_MODE == MODE_RELAY_CLIENT) {
        remotefd = socket(AF_INET6, SOCK_STREAM, IPPROTO_MPTCP);

        inet_pton(AF_INET6, YOUR_ADDRESS, &cli->sin6_addr);
		
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

        if (rp->ai_family == AF_INET) {
           char buf[256];
           struct sockaddr_in *info = (struct sockaddr_in *)rp->ai_addr;
           LOGI("sfd=%d -> %s\n", sfd, inet_ntop(AF_INET, &info->sin_addr, buf, sizeof(buf)));
        }

        if (rp->ai_family == AF_INET6) {
           char buf[256];
           struct sockaddr_in6 *info = (struct sockaddr_in6 *)rp->ai_addr;
           LOGI("sfd=%d -> %s\n", sfd, inet_ntop(AF_INET6, &info->sin6_addr, buf, sizeof(buf)));
        }

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

        LOGI("connect %s \n", inet_ntoa(*addr_list[i]));
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

static int setkeepalive(int sockfd)
{
    int keepalive = 1;
    int keepcnt = 3, keepidle = 180, keepintvl = 30;

    setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(int));
    setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(int));
    setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(int));
    setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(int));

    return 0;
}


void func(int connfd)
{
    int rc;
    int n, l, i;
    fd_set test, wtest;
    uint8_t snibuff[4096];
    struct tls_header header;
    int remotefd = -1;

#if 0
    struct timeval tv;
    tv.tv_sec = 30;  /* 30 Secs Timeout */
    int ret = setsockopt(connfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    assert(ret == 0);
#endif

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

    char hostname[128];
    get_sni_name(snibuff + 5, header.length, hostname);
    LOGI("origin hostname: %s\n", hostname);

    int newlen = unwind_rewind_client_hello(snibuff, header.length + 5);
    header.length = newlen - 5;

    get_sni_name(snibuff + 5, header.length, hostname);
    LOGI("target hostname: %s\n", hostname);
    if (*hostname == 0) {
        close(connfd);
        return;
    }

    struct sockaddr_in6 cli;
    cli.sin6_family = AF_INET6;
    cli.sin6_port   = htons(YOUR_PORT);
    remotefd = setup_remote(&cli, hostname);

    if (remotefd == -1) {
        close(connfd);
        return;
    }

    rc = write(remotefd, snibuff, newlen);
    assert(rc == newlen);
    int stat = 0;
    int wstat = 3;
    int keepaliveset = 0;
    int maxfd = connfd > remotefd? connfd: remotefd;

    int direct = 0;
    int pull_direct = 0;
    time_t uptime = time(NULL);
    do {
        FD_ZERO(&test);
        if (~stat & 1) FD_SET(connfd, &test);
        if (~stat & 2) FD_SET(remotefd, &test);
        assert(stat != 3);

        FD_ZERO(&wtest);
        if (wstat & 1) FD_SET(connfd, &wtest);
        if (wstat & 2) FD_SET(remotefd, &wtest);

        struct timeval timeo = {50, 26};
        n = select(maxfd + 1, &test, &wtest, NULL, &timeo);
	if (n == 0 && !(stat & 0x3) && uptime + 1888 > time(NULL)) {
	    switch (keepaliveset? MODE_RELAY_NONE: RELAY_MODE) {
		case MODE_RELAY_CLIENT:
		    setkeepalive(remotefd);
		    keepaliveset = 1;
		    break;

		case MODE_RELAY_SERVER:
		    setkeepalive(connfd);
		    keepaliveset = 1;
		    break;
	    }

	    n = 1;
	    continue;
	}


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

	uptime = time(NULL);
        if (stat != 0 || n  <= 0)
            LOG("stat=%x n=%d\n", stat, n);
    } while (n > 0 && stat != 3);

    LOGD("release connection\n");
    close(remotefd);
    close(connfd);
    return;
}

static int sigchild = 0;
void clean_pcb(int signo)
{
    LOGD("clean_pcb\n");
    sigchild = 1;
    // signal(SIGCHLD, clean_pcb);
}

/*
 * sniproxy -s -l 4430 -p 443 -d app.yrli.bid
 * sniproxy -c -l 4430 -p 4430 -d app.yrli.bid 100.42.78.149
 */
void parse_argopt(int argc, char *argv[])
{
    int i;

    byte info_default[] = "dGxzIGVjaAD+DQA8MwAgACB/7ou2XMG9sumfvTITnVG/L6mNzCOqPpivAfQwzWjUFgAEAAEAAQANd3d3LmJhaWR1LmNvbQAA";
    infoLen = sizeof(info);
    Base64_Decode(info_default, sizeof(info_default) -1, info, &infoLen);

    LOGI("parse_argopt>");
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
	if (strcmp(optname, "-e") == 0) {
	    RELAY_MODE = MODE_RELAY_SERVER;
	    unwind_rewind_client_hello = unwind_encrypt_client_hello;
	} else
	if (strcmp(optname, "-r") == 0) {
	    RELAY_MODE = MODE_RELAY_CLIENT;
	    unwind_rewind_client_hello = rewind_encrypt_client_hello;
	} else
	if (strcmp(optname, "-c") == 0) {
	    RELAY_MODE = MODE_RELAY_CLIENT;
	    unwind_rewind_client_hello = rewind_client_hello;
	} else
	if (strncmp(optname, "ech=", 4) == 0) {
            optname += 4;

	    infoLen = sizeof(info) - 6;
            byte info_head[] = "tls ech";
	    Base64_Decode((const byte*)optname, strlen(optname), info + 6, &infoLen);
            memcpy(info, info_head, sizeof(info_head));
	    infoLen += 6;
	} else
	if (strncmp(optname, "pub=", 4) == 0) {
            optname += 4;
            byte mypub[33];
            word32 publen = sizeof(mypub);
            Base64_Decode((byte*)optname, strlen(optname), mypub, &publen);
	    memcpy(pub, mypub, sizeof(pub));
	} else
	if (strncmp(optname, "priv=", 5) == 0) {
            optname += 5;
            byte mypriv[33];
            word32 privlen = sizeof(mypriv);
            Base64_Decode((byte*)optname, strlen(optname), mypriv, &privlen);
	    memcpy(priv, mypriv, sizeof(priv));
	} else
	if (strcmp(optname, "-z") == 0) {
	    RELAY_MODE = MODE_RELAY_SERVER;
	    unwind_rewind_client_hello = rewind_client_zero;
	} else
	if (*optname != '-') {
	    strcpy(YOUR_ADDRESS, argv[i]);
	}
    }
    LOGI("<parse_argopt\n");


    fprintf(stderr, "ech=");
    for (int i = 0; i < infoLen; i++)
	    fprintf(stderr, "%02x ", info[i] & 0xff);
    fprintf(stderr, "\n");

    fprintf(stderr, "pub=");
    for (int i = 0; i < 32; i++)
	    fprintf(stderr, "%02x ", priv[i] & 0xff);
    fprintf(stderr, "\n");

    fprintf(stderr, "priv=");
    for (int i = 0; i < 32; i++)
	    fprintf(stderr, "%02x ", priv[i] & 0xff);
    fprintf(stderr, "\n");
    if (unwind_rewind_client_hello == rewind_encrypt_client_hello) {
	size_t domainlen = strlen(YOUR_DOMAIN);
	TAGS_07[0] = TAGS_07[1] = 0; // TAG_SNI;
	TAGS_07[2] = (domainlen + 5) >> 8;
	TAGS_07[3] = (domainlen + 5);
	TAGS_07[4] = (domainlen + 3) >> 8;
	TAGS_07[5] = (domainlen + 3);
	TAGS_07[6] = 0;
	TAGS_07[7] = (domainlen) >> 8;
	TAGS_07[8] = (domainlen);
	memmove(TAGS_07 + 9, YOUR_DOMAIN, domainlen);
    }

    assert(RELAY_MODE != MODE_RELAY_NONE);
}

// Driver function
int main(int argc, char *argv[])
{
    int sockfd, connfd;
    socklen_t len;
    struct sockaddr_in6 servaddr, cli;
    signal(SIGINT, SIG_DFL);
    signal(SIGPIPE, SIG_DFL);

    struct sigaction act = {};
    act.sa_flags = SA_NOCLDSTOP;
    act.sa_handler = &clean_pcb;
    sigaction(SIGCHLD, &act, NULL);

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

    setenv("BINDTO", "::ffff:127.0.0.1", 0);
    inet_pton(AF_INET6, getenv("BINDTO"), &servaddr.sin6_addr);

    int enable = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
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

    int st;
    int nsession = 0;

    sigset_t save, set;
    sigemptyset(&set);
    sigaddset(&set, SIGCHLD);

    do {
        len = sizeof(cli);
        // Accept the data packet from client and verification
        connfd = accept(sockfd, (SA*)&cli, &len);
        if (sigchild) {
	    sigprocmask(SIG_BLOCK, &set, &save);
            sigchild = 0;
	    while (waitpid(-1, &st, WNOHANG) > 0)
		nsession--;
	    sigprocmask(SIG_UNBLOCK, &set, &save);
	    if (connfd < 0 ) continue;
        }

        if (connfd < 0) {
            LOGI("server accept failed...\n");
            exit(0);
        }
        else {
            char tobuf[64], cmdline[2048];
	    inet_ntop(AF_INET6, &cli.sin6_addr, tobuf, sizeof(tobuf));
            LOGI("server accept the client %s...\n", tobuf);
	    snprintf(cmdline, sizeof(cmdline), "ip -6 n s |grep %s", tobuf);
	    system(cmdline);
	}

        pid_t child = 0;
	struct sockaddr_in6 mime;
	socklen_t mimelen = sizeof(mime);

        if (nsession > 1024) {
            LOGI("two many fork");
        } else if (getsockname(sockfd, (SA*)&mime, &mimelen) != 0 && (IN6_ARE_ADDR_EQUAL(&cli.sin6_addr, &mime.sin6_addr))) {
            LOGI("disable connect self from local host to avoid loop");
	} else if ((child = fork()) == 0) {
	    close(sockfd);
	    func(connfd);
	    exit(0); 
	} else if (child > 0) {
	    sigprocmask(SIG_BLOCK, &set, &save);
            nsession++;
	    sigprocmask(SIG_UNBLOCK, &set, &save);
        }
        close(connfd);
        // Function for chatting between client and server
    } while (1);

    // After chatting close the socket
    close(sockfd);
    return 0;
}

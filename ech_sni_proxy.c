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

#define MAX 65536
#define SA struct sockaddr

struct tls_header {
    uint8_t type;
    uint8_t major;
    uint8_t minor;
    uint16_t length;
};

#define HANDSHAKE_TYPE 22

#define TAG_SNI        0
#define TAG_SESSION_TICKET 35
#define TAG_ENCRYPT_CLIENT_HELLO 0xfe0d
#define TAG_OUTER_EXTENSIONS 0xfd00

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

int write_flush(int fd, void *buf, size_t count)
{
    int rc = 0;
    int process = 0;
    uint8_t *ptr = (uint8_t*)buf;

    while (process < count) {
        rc = write(fd, ptr + process, count - process);
        if (rc == -1) break;
        if (rc == 0) break;
        process += rc;
    }

    return process == 0? rc: process;
}

static int set_hook_name = 0;
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
static char YOUR_ADDRESS[256] = "100.42.78.149";
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

            strcpy(dest + 4 + 5, YOUR_DOMAIN);
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

    byte aad[2048] = {};
    assert(sizeof(aad) > chlen);
    memcpy(aad, ch, chlen);

    uint8_t *d1 = (uint8_t*)ch;
    uint8_t *d2 = (uint8_t*)payload;
    memset(aad + (d2 - d1), 0, payload_len);

    ret = wc_HpkeOpenBase(hpke, receiverPrivkey0, enc,
		    enclen, info, infoLen, aad, chlen, payload, payload_len - 16, output);

    if (ret == 0) *outlen = payload_len - 16;
    LOGI("load_encrypt_client_hello: ret=%d\n", ret);
    return ret;
}

int decode_client_hello(uint8_t *decoded, size_t ddsz, const uint8_t *plain, size_t len, const uint8_t *outer, size_t outerlen, size_t *outlen)
{
    uint8_t *dest = decoded;
    const uint8_t *p = plain;
    const uint8_t *refer = outer;

    uint8_t *ech_start = p;

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
        LOGV("ext tag: %d %d\n", tag, len);
        uint16_t fqdn_name_len = 0;

	if (tag == TAG_OUTER_EXTENSIONS) {
	    const uint8_t *start = (p + 4);
	    int len = *start++;

	    for (int i = 0; i < len; i +=2) {
		uint16_t etag = start[i + 1]|(start[i] << 8);
		LOGV("etag: 0x%04x\n", etag);

		while (refer < limit_out) {
		    uint16_t tag_out = refer[1]|(refer[0]<<8);
		    uint16_t len_out = refer[3]|(refer[2]<<8);

		    if (etag == tag_out) {
			LOGV("match tag: 0x%04x\n", tag_out);
			memcpy(dest, refer, len_out + 4);
			dest += len_out;
			dest += 4;
			break;
		    }

		    LOGV("mismatch tag%d: 0x%04x 0x%04x\n", out_tag_indx++, tag_out, etag);
                    refer += len_out;
                    refer += 4;
		}
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

	    uint8_t plain[1024], decoded[1024];
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
    return 0;
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
        uint8_t *p = buff;
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

int pull(int connfd, int remotefd)
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

    l = read_flush(connfd, buff + 5, header.length);

    // dump(buff + 5, l, &header, "PULL");
    return write_flush(remotefd, buff, l + 5);
}


// Function designed for chat between client and server.
int push(int connfd, int remotefd)
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

    l = read_flush(connfd, buff + 5, header.length);

    // dump(buff + 5, l, &header, "PUSH");
    return write_flush(remotefd, buff, l + 5);
}

int pipling(int connfd, int remotefd)
{
    char buff[65536];
    size_t len = read(connfd, buff, sizeof(buff));
    if (len == -1) return -1;
    if (len == 0) return 0;
    return write_flush(remotefd, buff, len);
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
           struct sockaddr_in *info = rp->ai_addr;
           LOGI("sfd=%d -> %s\n", sfd, inet_ntop(AF_INET, &info->sin_addr, buf, sizeof(buf)));
        }

        if (rp->ai_family == AF_INET6) {
           char buf[256];
           struct sockaddr_in6 *info = rp->ai_addr;
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
    int keepcnt = 3, keepidle = 360, keepintvl = 60;

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
    fd_set test;
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
	LOGI(stderr, "len: %d\n", header.length);
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
    int keepaliveset = 0;
    int maxfd = connfd > remotefd? connfd: remotefd;

    do {
        FD_ZERO(&test);
        if (~stat & 1) FD_SET(connfd, &test);
        if (~stat & 2) FD_SET(remotefd, &test);
        assert(stat != 3);

        struct timeval timeo = {360, 360};
        n = select(maxfd + 1, &test, NULL, NULL, &timeo);
	if (n == 0 && !(stat & 0x3)) {
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

	    continue;
	}

        if (n == 0) break;
        assert(n > 0);

        if (FD_ISSET(connfd, &test)) {
            // if (push(connfd, remotefd) <= 0) stat |= 1;
            if (pipling(connfd, remotefd) <= 0) stat |= 1;
        }

        if (FD_ISSET(remotefd, &test)) {
            // if (pull(remotefd, connfd) <= 0) stat |= 2;
            if (pipling(remotefd, connfd) <= 0) stat |= 2;
        }

	if (stat != 0 || n  <= 0)
		LOGD("stat=%x n=%d\n", stat, n);
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
	if (strcmp(optname, "-c") == 0) {
	    RELAY_MODE = MODE_RELAY_CLIENT;
	    unwind_rewind_client_hello = rewind_client_hello;
	} else
	if (strncmp(optname, "ech=", 4) == 0) {
            optname += 4;

	    infoLen = sizeof(info) - 6;
            byte info_head[] = "tls ech";
	    Base64_Decode(optname, strlen(optname), info + 6, &infoLen);
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

    assert(RELAY_MODE != MODE_RELAY_NONE);
}

// Driver function
int main(int argc, char *argv[])
{
    int sockfd, connfd, len;
    struct sockaddr_in6 servaddr, cli;
    signal(SIGCHLD, clean_pcb);
    signal(SIGINT, SIG_DFL);

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
        if (connfd < 0) {
            LOGI("server accept failed...\n");
            exit(0);
        }
        else
            LOGI("server accept the client...\n");

        if (sigchild) {
	    sigprocmask(SIG_BLOCK, &set, &save);
            sigchild = 0;
	    while (waitpid(-1, &st, WNOHANG) > 0)
		nsession--;
	    sigprocmask(SIG_UNBLOCK, &set, &save);
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

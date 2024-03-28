#include <stdio.h>
#include <glib.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <assert.h>
#include <gcrypt.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/hpke.h>


#define LOG_DEBUG(fmt...) fprintf(stderr, fmt)
#define LOG_VERBOSE(fmt...) fprintf(stderr, fmt)

#define TLS13_AEAD_NONCE_LENGTH 12

#define QUIC_MAX_CID_LENGTH  20

#define HANDSHAKE_TYPE_CLIENT_HELLO 1
#define TAG_SNI 0


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
    memcpy(aad, ch, chlen);

    uint8_t *d1 = (uint8_t*)ch;
    uint8_t *d2 = (uint8_t*)payload;
    memset(aad + (d2 - d1), 0, payload_len);

    ret = wc_HpkeOpenBase(hpke, receiverPrivkey0, enc,
	    enclen, info, infoLen, aad, chlen, payload, payload_len - 16, output);

    if (ret == 0) *outlen = payload_len - 16;
    LOG_DEBUG("load_encrypt_client_hello: ret=%d length %d aad %d\n", ret, payload_len, d2 - d1);
    return ret;
}

#define TAG_ENCRYPT_CLIENT_HELLO 0xfe0d
#define TAG_OUTER_EXTENSIONS 0xfd00

int decode_client_hello(uint8_t *decoded, size_t ddsz, const uint8_t *plain, size_t len, const uint8_t *outer, size_t outerlen, size_t *outlen)
{
    uint8_t *dest = decoded;
    const uint8_t *p = plain;
    const uint8_t *refer = outer;

    const uint8_t *ech_start = p;

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
        LOG_VERBOSE("ext tag: %d %d\n", tag, len);
        uint16_t fqdn_name_len = 0;

        if (tag == TAG_OUTER_EXTENSIONS) {
            const uint8_t *start = (p + 4);
            int len = *start++;

            for (int i = 0; i < len; i +=2) {
                uint16_t etag = start[i + 1]|(start[i] << 8);
                LOG_VERBOSE("etag: 0x%04x\n", etag);

                while (refer < limit_out) {
                    uint16_t tag_out = refer[1]|(refer[0]<<8);
                    uint16_t len_out = refer[3]|(refer[2]<<8);

                    if (etag == tag_out) {
                        LOG_VERBOSE("match tag: 0x%04x\n", tag_out);
                        memcpy(dest, refer, len_out + 4);
                        dest += len_out;
                        dest += 4;
                        break;
                    }

                    LOG_VERBOSE("mismatch tag%d: 0x%04x 0x%04x\n", out_tag_indx++, tag_out, etag);
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
    uint8_t *p = snibuff;
    uint8_t *dest = hold;

#if 0
    p = snibuff + 5;
    dest = hold + 5;

    memcpy(hold, snibuff, 5);
    if (*p != HANDSHAKE_TYPE_CLIENT_HELLO) {
        LOG_DEBUG("bad: %p\n", *p);
        return 0;
    }
#endif

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
        LOG_VERBOSE("ext tag: %d %d\n", tag, len);
        uint16_t fqdn_name_len = 0;

        if (tag == TAG_SNI) {
            const uint8_t *sni = (p + 4);
            assert (sni[2] == 0);
            uint16_t list_name_len = sni[1]|(sni[0] << 8);
            fqdn_name_len = sni[4]|(sni[3] << 8);
            assert (fqdn_name_len + 3 == list_name_len);
            memcpy(hostname, sni + 5, fqdn_name_len);
            hostname[fqdn_name_len] = 0;
            LOG_DEBUG("source: %s\n", hostname);
        } else if (tag == TAG_ENCRYPT_CLIENT_HELLO) {
            const uint8_t *start = (p + 4);
            LOG_DEBUG("TAG_ENCRYPT_CLIENT_HELLO:\n");
            LOG_VERBOSE("client hello type: %d\n", start[0]);
            LOG_VERBOSE("kdfid: %d\n", (start[1] << 8) | start[2]);
            LOG_VERBOSE("aeadid: %d\n", (start[3] << 8) | start[4]);
            LOG_VERBOSE("config id: %d\n", start[5]);
            int enclen = (start[6] << 8) | start[7];
            LOG_VERBOSE("enclen: %d\n", enclen);
            // dumpData("enc", start + 8, enclen);
            int payload_len = (start[8 + enclen] << 8) | start[8 + enclen +1];
            LOG_VERBOSE("payload_len: %d\n", payload_len);
            // dumpData("payload", start + 8 + enclen + 2, payload_len);
            // dumpAadData("aad", ech_start, snibuff + length - ech_start, start + 8 + enclen + 2, payload_len);

            uint8_t plain[1024], decoded[1024];
            size_t outlen = 0;
            int ret = load_encrypt_client_hello(ech_start, snibuff + length - ech_start, start + 8 + enclen + 2, payload_len, start + 8, enclen, plain, &outlen);
            if (ret == 0) {
                decode_client_hello(decoded, 1024, plain, outlen, snibuff + 9, length - 9, &outlen);
#if 0
                memcpy(snibuff + 9 - 5, decoded, outlen);
                int newlen = outlen;
                snibuff[6] = newlen >> 16;
                snibuff[7] = newlen >> 8;
                snibuff[8] = newlen;

                newlen = outlen + 4;
                snibuff[3] = newlen >> 8;
                snibuff[4] = newlen;
                return outlen + 9;
#endif

                int newlen = outlen;
                snibuff[1] = newlen >> 16;
                snibuff[2] = newlen >> 8;
                snibuff[3] = newlen;
                memcpy(snibuff + 4, decoded, outlen);
                return outlen + 4;
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
    LOG_VERBOSE("extlen: %d %d\n", extlen, extention_length);

    int newlen = dest - lengthp - 3;
    lengthp[0] = newlen >> 16;
    lengthp[1] = newlen >> 8;
    lengthp[2] = newlen;
    LOG_VERBOSE("newlen: %d %d\n", newlen, mylength);

#if 0
    // memcpy(hold, snibuff, 5);
    int fulllength = (dest - hold - 5);
    hold[3] = fulllength >> 8;
    hold[4] = fulllength;

    int oldlen = (snibuff[3] << 8) | snibuff[4];
    LOG_VERBOSE("fulllen: %d %d %ld\n", fulllength, oldlen, length);

    // set_hook_name = 0;
    // if (modify == 0 && strcmp(YOUR_DOMAIN, hostname)) { set_hook_name = 1; }
    if (modify == 0) return length;
#endif
    memcpy(snibuff, hold, dest - hold);
    return dest - hold;
}

char * get_sni_name(uint8_t *snibuff, size_t len, char *hostname)
{
    int i;
    int length;
    uint8_t *p = snibuff;

    if (*p != HANDSHAKE_TYPE_CLIENT_HELLO) {
	LOG_DEBUG("bad\n");
	return NULL;
    }

    int type = *p++;
    LOG_DEBUG("type: %x\n", type);
    length = p[2]|(p[1]<<8)|(p[0]<<16); p+=3;
    LOG_DEBUG("length: %d\n", length);
    LOG_DEBUG("version: %x.%x\n", p[0], p[1]);
    p += 2; // version;
	    //
    p += 32; //random;
    LOG_DEBUG("session id length: %d\n", *p);
    p += *p;
    p++;
    int cipher_suite_length = p[1]|(p[0]<<8); p+=2;
    LOG_DEBUG("cipher_suite_length: %d\n", cipher_suite_length);
    p += cipher_suite_length;
    int compress_method_len = *p++;
    LOG_DEBUG("compress_method_len: %d\n", compress_method_len);
    p += compress_method_len;
    int extention_length = p[1]|(p[0]<<8); p+=2;
    LOG_DEBUG("extention_lengh: %d\n", extention_length);
    const uint8_t *limit = p + extention_length;

    *hostname = 0;
    while (p < limit) {
	uint16_t tag = p[1]|(p[0]<<8);
	uint16_t len = p[3]|(p[2]<<8);
	// LOG_DEBUG("ext tag: %d %d\n", tag, len);
	if (tag == TAG_SNI) {
	    const uint8_t *sni = (p + 4);
	    assert (sni[2] == 0);
	    uint16_t list_name_len = sni[1]|(sni[0] << 8);
	    uint16_t fqdn_name_len = sni[4]|(sni[3] << 8);
	    assert (fqdn_name_len + 3 == list_name_len);
	    memcpy(hostname, sni + 5, fqdn_name_len);
	    hostname[fqdn_name_len] = 0;
	}
	p += len;
	p += 4;
    }

    LOG_DEBUG("sni parse finish: %s\n", hostname);
    return hostname;
}

typedef struct quic_cid {
    guint8      len;
    guint8      cid[QUIC_MAX_CID_LENGTH];
    guint8      reset_token[16];
    gboolean    reset_token_set;
    uint64_t    seq_num;
} quic_cid_t;

/* XXX Should we use GByteArray instead? */
typedef struct _StringInfo {
    uint8_t  *data;      /* Backing storage which may be larger than data_len */
    uint32_t    data_len;  /* Length of the meaningful part of data */
} StringInfo;

static inline void phton64(uint8_t *p, uint64_t v) {
    uint32_t *out = (uint32_t *)p;
    out[0] = htonl(v >> 32);
    out[1] = htonl(v);
}

static inline uint64_t pntoh64(uint8_t *p) {
    uint64_t v, v0;

    memcpy(&v0, p, sizeof(v0));
    phton64((uint8_t *)&v, v0);
    return v;
}

gcry_error_t
hkdf_expand(int hashalgo, const uint8_t *prk, unsigned prk_len, const uint8_t *info, unsigned info_len,
            uint8_t *out, unsigned out_len)
{
	// Current maximum hash output size: 48 bytes for SHA-384.
	unsigned char	        lastoutput[48];
	gcry_md_hd_t    h;
	gcry_error_t    err;
	const unsigned  hash_len = gcry_md_get_algo_dlen(hashalgo);

	/* Some sanity checks */
	if (!(out_len > 0 && out_len <= 255 * hash_len) ||
	    !(hash_len > 0 && hash_len <= sizeof(lastoutput))) {
		return GPG_ERR_INV_ARG;
	}

	err = gcry_md_open(&h, hashalgo, GCRY_MD_FLAG_HMAC);
	if (err) {
		return err;
	}

	for (unsigned offset = 0; offset < out_len; offset += hash_len) {
		gcry_md_reset(h);
		gcry_md_setkey(h, prk, prk_len);                    /* Set PRK */
		if (offset > 0) {
			gcry_md_write(h, lastoutput, hash_len);     /* T(1..N) */
		}
		gcry_md_write(h, info, info_len);                   /* info */
		gcry_md_putc(h, (uint8_t) (offset / hash_len + 1));  /* constant 0x01..N */

		memcpy(lastoutput, gcry_md_read(h, hashalgo), hash_len);
		memcpy(out + offset, lastoutput, MIN(hash_len, out_len - offset));
	}

	gcry_md_close(h);
	return 0;
}

int
tls13_hkdf_expand_label_context(int md, const StringInfo *secret,
                        const char *label_prefix, const char *label,
                        const uint8_t *context_hash, uint8_t context_length,
                        uint16_t out_len, uint8_t **out)
{
    gcry_error_t err;
    const uint32_t label_prefix_length = (uint32_t) strlen(label_prefix);
    const uint32_t label_length = (uint32_t) strlen(label);

    /* info = HkdfLabel { length, label, context } */

    GByteArray *info = g_byte_array_new();
    const guint16 length = g_htons(out_len);
    g_byte_array_append(info, (const guint8 *)&length, sizeof(length));

    const guint8 label_vector_length = label_prefix_length + label_length;
    g_byte_array_append(info, &label_vector_length, 1);
    g_byte_array_append(info, (const guint8 *)label_prefix, label_prefix_length);
    g_byte_array_append(info, (const guint8*)label, label_length);

    g_byte_array_append(info, &context_length, 1);
    if (context_length) {
        g_byte_array_append(info, context_hash, context_length);
    }

    *out = (uint8_t *)malloc(out_len);
    err = hkdf_expand(md, secret->data, secret->data_len, info->data, info->len, *out, out_len);
    g_byte_array_free(info, TRUE);
    return TRUE;
}

int
tls13_hkdf_expand_label(int md, const StringInfo *secret,
                        const char *label_prefix, const char *label,
                        uint16_t out_len, uint8_t **out)
{       
    return tls13_hkdf_expand_label_context(md, secret, label_prefix, label, NULL, 0, out_len, out);
}

static int
quic_hkdf_expand_label(int hash_algo, uint8_t *secret, int secret_len, const char *label, uint8_t *out, int out_len)
{
    const StringInfo secret_si = { secret, secret_len };
    uint8_t *out_mem = NULL;
    if (tls13_hkdf_expand_label(hash_algo, &secret_si, "tls13 ", label, out_len, &out_mem)) {
        memcpy(out, out_mem, out_len);
        free(out_mem);
        return TRUE;
    }
    return FALSE;
}

gcry_error_t ws_hmac_buffer(int algo, void *digest, const void *buffer, size_t length, const void *key, size_t keylen)
{
        gcry_md_hd_t hmac_handle;
        gcry_error_t result = gcry_md_open(&hmac_handle, algo, GCRY_MD_FLAG_HMAC);
        if (result) {
                return result;
        }
        result = gcry_md_setkey(hmac_handle, key, keylen);
        if (result) {
                gcry_md_close(hmac_handle);
                return result;
        }
        gcry_md_write(hmac_handle, buffer, length);
        memcpy(digest, gcry_md_read(hmac_handle, 0), gcry_md_get_algo_dlen(algo));
        gcry_md_close(hmac_handle);
        return GPG_ERR_NO_ERROR;
}

static inline gcry_error_t
hkdf_extract(int hashalgo, const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t *prk)
{
    /* PRK = HMAC-Hash(salt, IKM) where salt is key, and IKM is input. */
    return ws_hmac_buffer(hashalgo, prk, ikm, ikm_len, salt, salt_len);
}

#define HASH_SHA2_256_LENGTH 32

static const guint8 handshake_salt_v1[20] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
};

#define CID {0x30, 0x60, 0xa6, 0x41, 0x3b, 0x50, 0x60, 0xc4}

int tohex(int ch)
{
	int uch = (ch & 0xFF);
	if (uch >= '0' && uch <= '9')
		return uch - '0';
	if (uch >= 'a' && uch <= 'f')
		return uch - 'a' + 10;
	if (uch >= 'A' && uch <= 'F')
		return uch - 'A' + 10;
	return 0;
}

size_t HexToMemory(const char * hex, void * buf, size_t len)
{
	int code;
	unsigned char * p = (unsigned char *)buf;
	while (len > 0) {
		if (*hex == 0) break;
		code = tohex(*hex++);
		if (*hex == 0) break;
		code = (code << 4) | tohex(*hex++);
		*p++ = (unsigned char)code;
		len--;
	}
	return p - (unsigned char *)buf;
}

int get_token_length(guchar *decodec, guint32 *outlen)
{
    guchar token_length[4] = {};
    guchar idl_label = (*decodec >> 6) & 0x3;

    guchar fix = 3 - idl_label;
    memcpy(token_length + fix, decodec, idl_label + 1);
    token_length[fix] &= 0x3f;
    memcpy(outlen, token_length, 4);
    *outlen = htonl(*outlen);

    return idl_label + 1;
}

guint32 get_packet_number(guchar *decodec, guint32 *outlen, size_t idl_label)
{
    guchar token_length[4] = {};

    guchar fix = 3 - idl_label;
    memcpy(token_length + fix, decodec, idl_label + 1);
    memcpy(outlen, token_length, 4);
    *outlen = htonl(*outlen);

    return idl_label + 1;
}

static void dump_hex(const char *title, const void *data, size_t len)
{
    int i;
    guchar *base = (guchar *)data;

    if (len <= 16) {
	LOG_DEBUG("%s: ", title);
        for (i = 0; i < len; i++) LOG_DEBUG("%02x ", *base++);
	LOG_DEBUG("\n");
	return;
    }

    LOG_DEBUG("%s:", title);
    for (i = 0; i < len; i++) {
	if ((i % 16) == 0) LOG_DEBUG("\n%04x: ", i);
	LOG_DEBUG("%02x ", *base++);
    }
    LOG_DEBUG("\n");
    return;
}

int get_sni_name_from_quic(const void *data, size_t data_len, char *hostname, size_t len)
{
    gcry_error_t err;
    quic_cid_t  dcid = {.len=8, .cid = CID}, scid = {.len=0};
    quic_cid_t  *cid = &dcid;
    guint8      secret[HASH_SHA2_256_LENGTH];
    uint8_t client_initial_secret[HASH_SHA2_256_LENGTH]; 

    guchar buffer[2048], idl;
    memcpy(buffer, data, data_len);
 
    if (data_len < 20) return 0;
    guchar first_byte = buffer[0];
    if ((first_byte & 0xf0) != 0xc0) return -1;

    guchar *decodec = buffer;
    first_byte = *decodec++;
    uint32_t version = 0;
    memcpy(&version, decodec, sizeof(version));
    decodec += sizeof(version);
    LOG_DEBUG("version: %x\n", htonl(version));

    guint32 dcidlen;
    decodec += get_token_length(decodec, &dcidlen);
    memcpy(dcid.cid, decodec, dcidlen);
    dcid.len = dcidlen;
    decodec += dcidlen;

    guint32 scidlen;
    decodec += get_token_length(decodec, &scidlen);
    memcpy(scid.cid, decodec, scidlen);
    scid.len = scidlen;
    decodec += scidlen;

    dump_hex("dcid", dcid.cid, dcid.len);
    dump_hex("scid", scid.cid, scid.len);

    guint32 token_length = 0;
    decodec += get_token_length(decodec, &token_length);
    dump_hex("token", decodec, token_length);
    decodec += token_length;

    guint32 payload_length;
    decodec += get_token_length(decodec, &payload_length);

    err = hkdf_extract(GCRY_MD_SHA256, handshake_salt_v1, sizeof(handshake_salt_v1), cid->cid, cid->len, secret);
    if (!quic_hkdf_expand_label(GCRY_MD_SHA256, secret, sizeof(secret), "client in", client_initial_secret, HASH_SHA2_256_LENGTH)) {
        LOG_DEBUG("Key expansion (client) failed");
        return -1;
    }

    guchar      hp_key[256/8];
    guint8      hash_algo = GCRY_MD_SHA256;
    guint       hash_len = gcry_md_get_algo_dlen(hash_algo);
    guint       key_length = gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES128);
    char        *label = "quic hp"; 

    if (!quic_hkdf_expand_label(hash_algo, client_initial_secret, hash_len, label, hp_key, key_length)) {
        return -1;
    }

    label = "quic iv";
    guchar quic_iv[256/8];
    if (!quic_hkdf_expand_label(hash_algo, client_initial_secret, hash_len, label, quic_iv, TLS13_AEAD_NONCE_LENGTH)) {
        return -1;
    }

    label = "quic key";
    guchar quic_key[256/8];
    if (!quic_hkdf_expand_label(hash_algo, client_initial_secret, hash_len, label, quic_key, key_length)) {
        return -1;
    }

    guchar *simple = decodec;

    gcry_cipher_hd_t cipher;

    gcry_cipher_open(&cipher, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, 0);
    gcry_cipher_setkey(cipher, hp_key, key_length);

    guchar ciphertext[32];
    memcpy(ciphertext, simple + 4, 16);

    err = gcry_cipher_encrypt(cipher, ciphertext, 16, NULL, 0);
    gcry_cipher_close(cipher);
    LOG_DEBUG("err=%d\n", err);

    guchar idl_label = (ciphertext[0] ^ first_byte) & 0x3;
    for (int i = 0; i <= idl_label; i++)
        decodec[i] ^= ciphertext[i + 1];
    dump_hex("head protect", ciphertext, 16);
    buffer[0] = first_byte ^ (0xF & ciphertext[0]);

    gcry_cipher_open(&cipher, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, 0);
    gcry_cipher_setkey(cipher, quic_key, key_length);

    guint8 nonce[TLS13_AEAD_NONCE_LENGTH];
    memcpy(nonce, quic_iv, TLS13_AEAD_NONCE_LENGTH);

    guchar atag1[16];
    guchar * quic_end = decodec + payload_length;
    memcpy(atag1, decodec + payload_length - 16, 16);
    dump_hex("atag", atag1, 16);

    guint32 packet_number = 1;
    guint32 pnlen =  get_packet_number(decodec, &packet_number, idl_label);
    LOG_DEBUG("pn %d %x %d\n", packet_number, buffer[0], payload_length);
    decodec += pnlen;

    phton64(nonce + sizeof(nonce) - 8, pntoh64(nonce + sizeof(nonce) - 8) ^ packet_number);
    gcry_cipher_setiv(cipher, nonce, TLS13_AEAD_NONCE_LENGTH);

    guint32 aad_len = decodec - buffer;
    gcry_cipher_authenticate(cipher, buffer, aad_len);

    // err = gcry_cipher_decrypt(cipher, decodec, data_len - aad_len - 16, NULL, 0);
    err = gcry_cipher_decrypt(cipher, decodec, payload_length - 16 - pnlen, NULL, 0);

    // dump_hex("dec data", decodec, payload_length - 16 - pnlen);

    err = gcry_cipher_checktag(cipher, atag1, 16);

    if (err) {
        LOG_DEBUG("Decryption (checktag) failed: %s\n", gcry_strerror(err));
	err = gcry_cipher_gettag(cipher, atag1, 16);
        dump_hex("shoud atag", atag1, 16);
        dump_hex("decode data", decodec, payload_length - 16);
        dump_hex("data", data, data_len);
	gcry_cipher_close(cipher);
        return -1;
    }
    gcry_cipher_close(cipher);

    guint32 offset, length;
    enum {PADDING=0, PING=1, CRYPTO=6};
    char tlsdata[2048];
    guint32 total = 0, next = 0;

    quic_end = decodec + payload_length - 16 - pnlen;
    LOG_DEBUG("from %p, to %p\n", decodec, quic_end);
    while (decodec <  quic_end) {
	switch (*decodec) {
	    case PADDING:
	    case PING:
		decodec++;
		break;

	    case CRYPTO:
		decodec++;
		decodec += get_token_length(decodec, &offset);
		decodec += get_token_length(decodec, &length);
		LOG_DEBUG("crypto: offset=%d, length=%d\n", offset, length);
                memcpy(tlsdata + offset, decodec, length);
		decodec += length;
		if (next < offset + length) next = offset + length;
		total += length;
		break;

	    default:
		LOG_DEBUG("unknown QUIC tag: %x\n", *decodec);
		return 0;
	}
    }

    if (total > 0 && total == next) {
	// dump_hex("tlsdata", tlsdata, total);
	char oldhostname[256] =  "";
	get_sni_name(tlsdata, total, oldhostname);

	total = unwind_encrypt_client_hello(tlsdata, total);
	if (get_sni_name(tlsdata, total, hostname) && *hostname) {
	    LOG_DEBUG("quic: hostname0: %s\n", hostname);
	    return 0;
	}

	if (*oldhostname) {
		strcpy(hostname, oldhostname);
		LOG_DEBUG("quic: hostname %s\n", hostname);
		return 0;
	}
    }

    LOG_DEBUG("quic: total %d, next %d\n", total, next);
    return -1;
}

void parse_argopt(int argc, char *argv[])
{
  int i;

  byte info_default[] = "dGxzIGVjaAD+DQA8MwAgACB/7ou2XMG9sumfvTITnVG/L6mNzCOqPpivAfQwzWjUFgAEAAEAAQANd3d3LmJhaWR1LmNvbQAA";
  infoLen = sizeof(info);
  Base64_Decode(info_default, sizeof(info_default) -1, info, &infoLen);

  LOG_DEBUG("parse_argopt>");
  for (i = 1; i < argc; i++) {
    const char *optname = argv[i];
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
	}
  }
  LOG_DEBUG("<parse_argopt\n");

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

}

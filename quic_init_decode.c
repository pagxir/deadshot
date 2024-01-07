#include <stdio.h>
#include <glib.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <assert.h>
#include <gcrypt.h>

#define LOG_DEBUG(fmt...) fprintf(stderr, fmt)

#define TLS13_AEAD_NONCE_LENGTH 12

#define QUIC_MAX_CID_LENGTH  20

#define HANDSHAKE_TYPE_CLIENT_HELLO 1
#define TAG_SNI 0

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
	LOG_DEBUG("ext tag: %d %d\n", tag, len);
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

    return hostname;
}

static char init_packet[] = "c000000001083060a6413b5060c400404700fe3656bacfc6565bb4f38d4dd9390f0aa9cec2188daf9aff4631e3a5829c26c5a7c0e21590a6fb5932f25290be64b1dbd4dae08a9d2a0de19bbdc662e9678055d8cad430204d4474b0df479ea5308a7a6bfc6f982039c38be060d4c5651fb4b379efaec86079611bc6ee3a7c8dd4a8c423db97f73bb615e0807c5b1cd0ed75889aabc7b263cb8e0bf8dffb405c97edaf6da981302e82232e5cddd39921f0e1e5a57777f7d28c55c40c9c3c84e0719eeba75cafa07762a933db8d08f63640d0bf32b7dbaf6e130be99f75323e45b3a39ceca0bf5c4a6563b1351e4d82ff390bcdc48ec3a5246388ac7b4c7c0e503a27c20b78a507ad8214170724a2f34b3f7a7348fa501a47173dbf1dcd2481a6f6e1abbafae9c839a43ba1a2bc47a7da8679368937b4a5dd4fcfffed126fc539e651cb19d28b0213f09f0406506a9b4794dd2a5dd9b91ab71a41d50c14d58fd5d0a83c2b0e9c6be44fafe5f69a28a084b85116246cce1adbfc888351c013c3e1a81fcbfebc6ef76ded5f51430821acd16e8fc294e36b5a8da0c1f77e4cf35a5d786106796a8999cc16c5fd133eafe31aa26bb923b3117460859e468e6ec0d0eb10000866a1831e523691a9de028d61cd0f79ecb73a0b826633746432ce69e915d9a47e7f21df04da8a0cb7967c2825d23552fb5a0f100a8f1a908f1538ff2318c7e83f0b58a914628f8e19bb0bc1c880b656d10e9ab0e0f7fda747d9600a51692fa2817a17b9c4a6063b9b2c2b5a856bbd04114da6455dc9b95b84baaa1e469cfd101642f4572681714d15bf94157e09d3198c873fc0946461dc4dc38a20e67d882955a0ceff4ede10a22020d4bd4eaba6601f6fd794020a1524a9a3c4a90ddc90111c454a94dfe568c1d129418f119df69e6c04a9baa15b208c1fc24cb6e60c76f8a64707811d6e6cd506f5c4c718f6bb4cc8e84b7aba18eaec9f128aed97b734ea4600b6df0f0c948e5d0004cfac54499586b133de4c8e90127e5a7e54314aa579747fb3853417b7e272a3047016eef7c4d99700097235eb80c737631a41f54e7feae2c212a3a1e733b2aee0b90a62ab8e3fd15758a53c8acc56a6529930ecee1dedeed15781114bfeff9aa8ee01bd5700d7846fbbfab7fe3a368d53e3a192ea5a1b722ff41eae7622c802da4fdffe08ce591306aa64c182a25f22bb1d1a46fa0901bde187aaafab82f8bbc1cd4a4888662c6de92282591d28e0dd7a218ba0905b95f8b0ffe0c33f35f759e6a888aff5f516a78b92ae07a8489e09caa89cbe68fa2648957f7686452fc931e3d0c4d9c8abe624091bf653883a51ae140671c5d7ebb45304bcea5a0b7f379477bccd41028b77874a102aea8b1f660de64e347783fc23f1da8af990fe2925de6115b35687a083a2c3cee99a88a58c5c5426b38362a502bd524018cf50049852b896e5a6a688fb5cacf7d491b761bd79800b88c78d36482b9783366bb54a808364a70e3521eed215fb047ccbccff131ef13dee64238f563ec67fafa6660550da0ba3c9a20aa771934b54f3fb50bf7b5df21fcd540e5c56773fc04da9d30d297625dfb9338e079300baba7c8758991e3d842b0ae732ed728c1d080854ef5e473ac70aea02c6a99f048fa3a24e60814aabb437ee028bd5eed5e09e86c9d69ec7dc981f33b967548380d3870b46342daaa9b3af1437570ba038b85fbda20b79bbc9b0a716";
 
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
    guchar idl_label = (*decodec & 0xc0) >> 6;

    guchar fix = 3 - idl_label;
    memcpy(token_length + fix, decodec, idl_label + 1);
    token_length[fix] &= 0x3f;
    memcpy(outlen, token_length, 4);
    *outlen = htonl(*outlen);

    return idl_label + 1;
}

static void dump_hex(const char *title, void *data, size_t len)
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
    if ((first_byte & 0xf0) != 0xc0) return 0;

    guchar *decodec = buffer;
    first_byte = *decodec++;
    uint32_t version = 0;
    memcpy(&version, decodec, sizeof(version));
    decodec += sizeof(version);

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
        return FALSE;
    }

    guchar      hp_key[256/8];
    guint8      hash_algo = GCRY_MD_SHA256;
    guint       hash_len = gcry_md_get_algo_dlen(hash_algo);
    guint       key_length = gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES128);
    char        *label = "quic hp"; 

    if (!quic_hkdf_expand_label(hash_algo, client_initial_secret, hash_len, label, hp_key, key_length)) {
        return FALSE;
    }

    label = "quic iv";
    guchar quic_iv[256/8];
    if (!quic_hkdf_expand_label(hash_algo, client_initial_secret, hash_len, label, quic_iv, TLS13_AEAD_NONCE_LENGTH)) {
        return FALSE;
    }

    label = "quic key";
    guchar quic_key[256/8];
    if (!quic_hkdf_expand_label(hash_algo, client_initial_secret, hash_len, label, quic_key, key_length)) {
        return FALSE;
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
    for (int i = 0; i < idl_label + 1; i++)
        decodec[i] ^= ciphertext[i + 1];
	buffer[0] = first_byte ^ (0xF & ciphertext[0]);
    dump_hex("head protect", ciphertext, 16);

    gcry_cipher_open(&cipher, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, 0);
    gcry_cipher_setkey(cipher, quic_key, key_length);

    guint8 nonce[TLS13_AEAD_NONCE_LENGTH];
    memcpy(nonce, quic_iv, TLS13_AEAD_NONCE_LENGTH);

    guint32 packet_number = 1;
    decodec += get_token_length(decodec, &packet_number);

    phton64(nonce + sizeof(nonce) - 8, pntoh64(nonce + sizeof(nonce) - 8) ^ packet_number);
    gcry_cipher_setiv(cipher, nonce, TLS13_AEAD_NONCE_LENGTH);

    guint32 aad_len = decodec - buffer;
    gcry_cipher_authenticate(cipher, buffer, aad_len);
    guchar atag1[16];
    memcpy(atag1, buffer + data_len - 16, 16);
    dump_hex("atag", atag1, 16);

    err = gcry_cipher_decrypt(cipher, decodec, data_len - aad_len - 16, NULL, 0);
    // dump_hex("quic data", decodec, data_len - aad_len - 16);

    err = gcry_cipher_checktag(cipher, atag1, 16);

    if (err) {
        LOG_DEBUG("Decryption (checktag) failed: %s\n", gcry_strerror(err));
	err = gcry_cipher_gettag(cipher, atag1, 16);
        dump_hex("shoud atag", atag1, 16);
        return 0;
    }

    guint32 offset, length;
    enum {PADDING=0, PING=1, CRYPTO=6};
    char tlsdata[2048];
    guint32 total = 0, next = 0;

    while (decodec <  buffer + data_len - 16) {
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
		LOG_DEBUG("unknown tag: %d\b", *decodec);
		return 0;
	}
    }

    LOG_DEBUG("total=%d, next=%d\n", total, next);
    if (total > 0 && total == next) {
	dump_hex("tlsdata", tlsdata, total);
	LOG_DEBUG("hostname: %s\n", get_sni_name(tlsdata, total, hostname));
    }

    return 0;
}

int main(int argc, char *argv[])
{
    char hostname[256];
    guchar buffer[2048];
    int data_len = HexToMemory(init_packet, buffer, sizeof(buffer));
 
    if (data_len < 20) return 0;

    get_sni_name_from_quic(buffer, data_len, hostname, sizeof(hostname));

    return 0;
}

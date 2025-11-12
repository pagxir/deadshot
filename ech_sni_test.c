#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/hpke.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/curve25519.h>

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

int main()
{
    int ret = 0;
    int rngRet = 0;
    Hpke hpke[1];
    WC_RNG rng[1];
    const char* start_text = "this is a test";
    const char* info_text = "info";
    const char* aad_text = "aad";
    byte ciphertext[MAX_HPKE_LABEL_SZ];
    byte plaintext[MAX_HPKE_LABEL_SZ];
    void* receiverKey = NULL;
    void* ephemeralKey = NULL;
    uint8_t pubKey[HPKE_Npk_MAX]; /* public key */
    word16 pubKeySz = (word16)sizeof(pubKey);

    ret = wc_HpkeInit(hpke, DHKEM_X25519_HKDF_SHA256, HKDF_SHA256,
    HPKE_AES_128_GCM, NULL); /* or HPKE_AES_256_GCM */

    if (ret != 0)
    return ret;

    rngRet = ret = wc_InitRng(rng);

    if (ret != 0)
    return ret;

    /* generate the keys */
    if (ret == 0)
    ret = wc_HpkeGenerateKeyPair(hpke, &ephemeralKey, rng);

    if (ret == 0)
    ret = wc_HpkeGenerateKeyPair(hpke, &receiverKey, rng);

    /* seal */
    if (ret == 0)
    ret = wc_HpkeSealBase(hpke, ephemeralKey, receiverKey,
	    (byte*)info_text, (word32)XSTRLEN(info_text),
	    (byte*)aad_text, (word32)XSTRLEN(aad_text),
	    (byte*)start_text, (word32)XSTRLEN(start_text),
	    ciphertext);

    curve25519_key receiverPrivkey0[1];
    wc_curve25519_init(receiverPrivkey0);
    wc_curve25519_import_public_ex(pub, sizeof(pub), receiverPrivkey0, EC25519_LITTLE_ENDIAN);
    wc_curve25519_import_private_raw_ex(priv, sizeof(priv), pub, sizeof(pub), receiverPrivkey0, EC25519_LITTLE_ENDIAN);


    /* export ephemeral key */
    if (ret == 0)
    ret = wc_HpkeSerializePublicKey(hpke, ephemeralKey, pubKey, &pubKeySz);
    ret = wc_HpkeSerializePublicKey(hpke, receiverPrivkey0, pubKey, &pubKeySz);

    int i;
    for (i = 0; i < pubKeySz; i++) printf("%02x ", pubKey[i]);
    printf("\n");

    /* open with exported ephemeral key */
    if (ret == 0)
    ret = wc_HpkeOpenBase(hpke, receiverKey, pubKey, pubKeySz,
	    (byte*)info_text, (word32)XSTRLEN(info_text),
	    (byte*)aad_text, (word32)XSTRLEN(aad_text),
	    ciphertext, (word32)XSTRLEN(start_text),
	    plaintext);

    if (ret == 0)
    ret = XMEMCMP(plaintext, start_text, XSTRLEN(start_text));

#if 0
    if (ephemeralKey != NULL)
    wc_HpkeFreeKey(hpke->kem, ephemeralKey);

    if (receiverKey != NULL)
    wc_HpkeFreeKey(hpke->kem, receiverKey);
#endif

    if (rngRet == 0)
    wc_FreeRng(rng);

    if (ret == 0)
    printf("SUCCESS");
}

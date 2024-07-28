#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/hpke.h>

typedef struct EchCipherSuite {
    word16 kdfId;
    word16 aeadId;
} EchCipherSuite;

typedef struct WOLFSSL_EchConfig {
    byte* raw;
    char* publicName;
    void* receiverPrivkey;
    EchCipherSuite* cipherSuites;
    word32 rawLen;
    word16 kemId;
    byte configId;
    byte numCipherSuites;
    byte receiverPubkey[HPKE_Npk_MAX];
} WOLFSSL_EchConfig;

#define TLSX_ECH 0xfe0d
#define ECH_KEY_LEN 32

static void FreeEchConfigs(WOLFSSL_EchConfig* configs, void* heap)
{
    WOLFSSL_EchConfig* working_config = configs;
    WOLFSSL_EchConfig* next_config;

    // while (working_config != NULL) {
    //    next_config = working_config->next;

        XFREE(working_config->cipherSuites, heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(working_config->publicName, heap, DYNAMIC_TYPE_TMP_BUFFER);

        if (working_config->raw != NULL)
            XFREE(working_config->raw, heap, DYNAMIC_TYPE_TMP_BUFFER);

        if (working_config->receiverPrivkey != NULL) {
            wc_HpkeFreeKey(NULL, working_config->kemId,
                working_config->receiverPrivkey, heap);
        }

        XFREE(working_config, heap, DYNAMIC_TYPE_TMP_BUFFER);

        working_config = next_config;
    // }

    (void)heap;
}

int GenerateEchConfig(void *heap, const char* publicName,
    word16 kemId, word16 kdfId, word16 aeadId, WOLFSSL_EchConfig **ptr)
{
    int ret = 0;
    word16 encLen = DHKEM_X25519_ENC_LEN;

    Hpke hpke[1];
    WC_RNG rng[1];

    if (publicName == NULL)
        return BAD_FUNC_ARG;

    ret = wc_InitRng(rng);
    if (ret != 0) {
        return ret;
    }

    WOLFSSL_EchConfig *echConfigs = (WOLFSSL_EchConfig*)XMALLOC(sizeof(WOLFSSL_EchConfig),
        heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (echConfigs == NULL)
        ret = MEMORY_E;
    else
        XMEMSET(echConfigs, 0, sizeof(WOLFSSL_EchConfig));

    /* set random config id */
    if (ret == 0)
        ret = wc_RNG_GenerateByte(rng, &echConfigs->configId);

    /* if 0 is selected for algorithms use default, may change with draft */
    if (kemId == 0)
        kemId = DHKEM_X25519_HKDF_SHA256;

    if (kdfId == 0)
        kdfId = HKDF_SHA256;

    if (aeadId == 0)
        aeadId = HPKE_AES_128_GCM;

    if (ret == 0) {
        /* set the kem id */
        echConfigs->kemId = kemId;

        /* set the cipher suite, only 1 for now */
        echConfigs->numCipherSuites = 1;
        echConfigs->cipherSuites = (EchCipherSuite*)XMALLOC(
            sizeof(EchCipherSuite), heap, DYNAMIC_TYPE_TMP_BUFFER);

        if (echConfigs->cipherSuites == NULL) {
            ret = MEMORY_E;
        }
        else {
            echConfigs->cipherSuites[0].kdfId = kdfId;
            echConfigs->cipherSuites[0].aeadId = aeadId;
        }
    }

    if (ret == 0)
        ret = wc_HpkeInit(hpke, kemId, kdfId, aeadId, heap);

    /* generate the receiver private key */
    if (ret == 0) {
       echConfigs->receiverPrivkey = XMALLOC(sizeof(curve25519_key), heap, DYNAMIC_TYPE_TMP_BUFFER);

       do {
	 byte priv[32], pub[32];
         word32 privsz = sizeof(priv), pubsz = sizeof(pub);

	 if (*ptr == NULL) {
	   wc_HpkeGenerateKeyPair(hpke, &echConfigs->receiverPrivkey, rng);
	   break;
	 }

	 void * receiverPrivkey = (*ptr)->receiverPrivkey;
	 wc_curve25519_export_key_raw(receiverPrivkey, priv, &privsz, pub, &pubsz);
	 FreeEchConfigs(*ptr, heap);

	 wc_curve25519_init(echConfigs->receiverPrivkey);
	 wc_curve25519_import_private_raw(priv, privsz, pub, pubsz, echConfigs->receiverPrivkey);
       } while (0);
    }

    /* done with RNG */
    wc_FreeRng(rng);

    /* serialize the receiver key */
    if (ret == 0) {
        ret = wc_HpkeSerializePublicKey(hpke, echConfigs->receiverPrivkey,
            echConfigs->receiverPubkey, &encLen);
    }

    if (ret == 0) {
        echConfigs->publicName = (char*)XMALLOC(XSTRLEN(publicName) + 1,
            heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (echConfigs->publicName == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMCPY(echConfigs->publicName, publicName,
                XSTRLEN(publicName) + 1);
        }
    }

    if (ret != 0) {
        if (echConfigs) {
            XFREE(echConfigs->cipherSuites, heap,
                DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(echConfigs->publicName, heap,
                DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(echConfigs, heap, DYNAMIC_TYPE_TMP_BUFFER);
            /* set to null to avoid double free in cleanup */
            echConfigs = NULL;
        }
    }

    if (ret == 0) {
        ret = WOLFSSL_SUCCESS;
	*ptr = echConfigs;
    }

    return ret;
}

/* convert 16 bit integer to opaque */
WC_INLINE void c16toa(word16 wc_u16, byte* c)
{
    c[0] = (byte)((wc_u16 >> 8) & 0xff);
    c[1] =  (byte)(wc_u16       & 0xff);
}

/* get the raw ech config from our struct */
int GetEchConfig(WOLFSSL_EchConfig* config, byte* output, word32* outputLen)
{
    int i;
    word16 totalLen = 0;

    if (config == NULL || (output == NULL && outputLen == NULL))
        return BAD_FUNC_ARG;

    /* 2 for version */
    totalLen += 2;
    /* 2 for length */
    totalLen += 2;
    /* 1 for configId */
    totalLen += 1;
    /* 2 for kemId */
    totalLen += 2;
    /* 2 for hpke_len */
    totalLen += 2;

    /* hpke_pub_key */
    switch (config->kemId) {
        case DHKEM_P256_HKDF_SHA256:
            totalLen += DHKEM_P256_ENC_LEN;
            break;
        case DHKEM_P384_HKDF_SHA384:
            totalLen += DHKEM_P384_ENC_LEN;
            break;
        case DHKEM_P521_HKDF_SHA512:
            totalLen += DHKEM_P521_ENC_LEN;
            break;
        case DHKEM_X25519_HKDF_SHA256:
            totalLen += DHKEM_X25519_ENC_LEN;
            break;
        case DHKEM_X448_HKDF_SHA512:
            totalLen += DHKEM_X448_ENC_LEN;
            break;
    }

    /* cipherSuitesLen */
    totalLen += 2;
    /* cipherSuites */
    totalLen += config->numCipherSuites * 4;
    /* public name len */
    totalLen += 2;

    /* public name */
    totalLen += XSTRLEN(config->publicName);
    /* trailing zeros */
    totalLen += 2;

    if (output == NULL) {
        *outputLen = totalLen;
        return LENGTH_ONLY_E;
    }

    if (totalLen > *outputLen) {
        *outputLen = totalLen;
        return INPUT_SIZE_E;
    }

    /* version */
    c16toa(TLSX_ECH, output);
    output += 2;

    /* length - 4 for version and length itself */
    c16toa(totalLen - 4, output);
    output += 2;

    /* configId */
    *output = config->configId;
    output++;
    /* kemId */
    c16toa(config->kemId, output);
    output += 2;

    /* length and key itself */
    switch (config->kemId) {
        case DHKEM_P256_HKDF_SHA256:
            c16toa(DHKEM_P256_ENC_LEN, output);
            output += 2;
            XMEMCPY(output, config->receiverPubkey, DHKEM_P256_ENC_LEN);
            output += DHKEM_P256_ENC_LEN;
            break;
        case DHKEM_P384_HKDF_SHA384:
            c16toa(DHKEM_P384_ENC_LEN, output);
            output += 2;
            XMEMCPY(output, config->receiverPubkey, DHKEM_P384_ENC_LEN);
            output += DHKEM_P384_ENC_LEN;
            break;
        case DHKEM_P521_HKDF_SHA512:
            c16toa(DHKEM_P521_ENC_LEN, output);
            output += 2;
            XMEMCPY(output, config->receiverPubkey, DHKEM_P521_ENC_LEN);
            output += DHKEM_P521_ENC_LEN;
            break;
        case DHKEM_X25519_HKDF_SHA256:
            c16toa(DHKEM_X25519_ENC_LEN, output);
            output += 2;
            XMEMCPY(output, config->receiverPubkey, DHKEM_X25519_ENC_LEN);
            output += DHKEM_X25519_ENC_LEN;
            break;
        case DHKEM_X448_HKDF_SHA512:
            c16toa(DHKEM_X448_ENC_LEN, output);
            output += 2;
            XMEMCPY(output, config->receiverPubkey, DHKEM_X448_ENC_LEN);
            output += DHKEM_X448_ENC_LEN;
            break;
    }

    /* cipherSuites len */
    c16toa(config->numCipherSuites * 4, output);
    output += 2;

    /* cipherSuites */
    for (i = 0; i < config->numCipherSuites; i++) {
        c16toa(config->cipherSuites[i].kdfId, output);
        output += 2;
        c16toa(config->cipherSuites[i].aeadId, output);
        output += 2;
    }

    /* publicName len */
    c16toa(XSTRLEN(config->publicName), output);
    output += 2;

    /* publicName */
    XMEMCPY(output, config->publicName,
        XSTRLEN(config->publicName));
    output += XSTRLEN(config->publicName);

    /* terminating zeros */
    c16toa(0, output);
    /* output += 2; */

    *outputLen = totalLen;

    return 0;
}


/* get the raw ech configs from our linked list of ech config structs */
int GetEchConfigsEx(WOLFSSL_EchConfig* configs, byte* output, word32* outputLen)
{
    int ret = 0;
    WOLFSSL_EchConfig* workingConfig = NULL;
    byte* outputStart = output;
    word32 totalLen = 2;
    word32 workingOutputLen;

    if (configs == NULL || outputLen == NULL)
        return BAD_FUNC_ARG;

    workingOutputLen = *outputLen - totalLen;

    /* skip over total length which we fill in later */
    if (output != NULL)
        output += 2;

    workingConfig = configs;

    while (workingConfig != NULL) {
        /* get this config */
        ret = GetEchConfig(workingConfig, output, &workingOutputLen);

        if (output != NULL)
            output += workingOutputLen;

        /* add this config's length to the total length */
        totalLen += workingOutputLen;

        if (totalLen > *outputLen)
            workingOutputLen = 0;
        else
            workingOutputLen = *outputLen - totalLen;

        /* only error we break on, other 2 we need to keep finding length */
        if (ret == BAD_FUNC_ARG)
            return BAD_FUNC_ARG;

        workingConfig = NULL;
    }

    if (output == NULL) {
        *outputLen = totalLen;
        return LENGTH_ONLY_E;
    }

    if (totalLen > *outputLen) {
        *outputLen = totalLen;
        return INPUT_SIZE_E;
    }

    /* total size -2 for size itself */
    c16toa(totalLen - 2, outputStart);

    *outputLen = totalLen;

    return WOLFSSL_SUCCESS;
}

byte enc64[]="PzoBjq45KqqJZS3Bfcux4exMbd5G5l6n/oLZdzuSFXI=";
// enclen=32
byte info64[]="dGxzIGVjaAD+DQA8MwAgACB/7ou2XMG9sumfvTITnVG/L6mNzCOqPpivAfQwzWjUFgAEAAEAAQANd3d3LmJhaWR1LmNvbQAA";
// infolen=72
byte aad64[]="AwOwnnGcWW5RP7YEleLve20b7Ov9Gykf0ClwKukPSE0I4wAANhMBEwITA8AswCvAMMAvAJ8AnsypzKjMqsAnwCPAKMAkwArACcAUwBMAawBnADkAM8wUzBPMFQEAAfwAAAASABAAAA13d3cuYmFpZHUuY29tADMARwBFABcAQQQIVsejuEMgTUYPATjzeORQcbxvmOgiHPWqe+/MXN2t3p+NkwDtAlrIvtCUYgFWPJr+yxcqpGNIv7WAgT4CEDjDACsAAwIDBAANABwAGgYDBQMEAwgGCAsIBQgKCAQICQYBBQEEAQMBAAoADgAMABkAGAAXAB0AFQEAABYAAP4NAVoAAAEAATMAID86AY6uOSqqiWUtwX3LseHsTG3eRuZep/6C2Xc7khVyATAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
// aadlen=603
byte outerClientPayload64[]="DxRTauCkssIl+1j5pHVufv+SlCdW9DUfNhWmiifJY6urV9VLqNEJ04i8hx+ggFr6zUqsS03mX89WZYD/wt+4M8h3lpawzfgObUKMKZJYwslGd4LicRHjbTWlBvz8VWxIuJiG96QbQ0/eHmbeUwv7nHw6xXoJysK6VvkpnmK1mCgIauJdNXQ7R7PAN+VfAklaugDxMb473QHCD8JnFI3m11mh2IaHpE7k5L2UYvoPgP4G6b0wF8F8GjkKRsiKgilhLthM5FJCTCTHp+x6t570scNWA7xbLN1MbUg+VolQ2kZrezOANE7LFkr4SqGir8T52U15g1EE47mSwYfXmTy9FPD7q7BPhz3DE6dJlx4mv1e5yPljX8fLqp35ZGem2MbOb3NO82WRUE8giQCoLh9NIA==";

int ech_verify(int argc, const char *list[])
{
    word16 kemId = 0, kdfId = 0, aeadId =0;
    kemId = DHKEM_X25519_HKDF_SHA256;
    kdfId = HKDF_SHA256;
    aeadId = HPKE_AES_128_GCM;

    Hpke hpke[1];
    void *heap = NULL;
    curve25519_key receiverPrivkey0[1];
    int ret = wc_HpkeInit(hpke, kemId, kdfId, aeadId, heap);

    byte enc[1024];
    word32 encLen = sizeof(enc);
    Base64_Decode(enc64, sizeof(enc64) -1, enc, &encLen);

    byte info[1024];
    word32 infoLen = sizeof(info);
    Base64_Decode(info64, sizeof(info64) -1, info, &infoLen);

    byte aad[1024];
    word32 aadLen = sizeof(aad);
    Base64_Decode(aad64, sizeof(aad64) -1, aad, &aadLen);

    byte outerClientPayload[1024];
    word32 outerLen = sizeof(outerClientPayload);
    Base64_Decode(outerClientPayload64, sizeof(outerClientPayload64) -1, outerClientPayload, &outerLen);

    byte pubData [33] = {
	0x16, 0xd4, 0x68, 0xcd, 0x30, 0xf4, 0x01, 0xaf, 0x98, 0x3e, 0xaa, 0x23,
	0xcc, 0x8d, 0xa9, 0x2f, 0xbf, 0x51, 0x9d, 0x13, 0x32, 0xbd, 0x9f, 0xe9,
	0xb2, 0xbd, 0xc1, 0x5c, 0xb6, 0x8b, 0xee, 0x7f
    };

    byte privData[33] = {
	0x4a, 0x15, 0x0a, 0xb0, 0x16, 0x8f, 0x74, 0x88, 0xdc, 0xea, 0xfd, 0x81,
	0x83, 0xe6, 0xe6, 0x69, 0xd6, 0x9d, 0xdf, 0x7f, 0x15, 0x84, 0xeb, 0xbf,
	0x88, 0xd0, 0xb5, 0x53, 0x6e, 0x86, 0x1b, 0xd0
    };

#if 0
pub=FtRozTD0Aa+YPqojzI2pL79RnRMyvZ/psr3BXLaL7n8=
priv=ShUKsBaPdIjc6v2Bg+bmadad338VhOu/iNC1U26GG9A=
#endif

    for (int i = 0; i < argc; i++) {
       const char *vtag = list[i];
	if (strncmp(vtag, "enc=", 4) == 0) {
            vtag += 4;
	    encLen = sizeof(enc);
	    Base64_Decode((byte*)vtag, strlen(vtag), enc, &encLen);
	} else if (strncmp(vtag, "info=", 5) == 0) {
            vtag += 5;
	    infoLen = sizeof(info);
	    Base64_Decode((byte*)vtag, strlen(vtag), info, &infoLen);
	} else if (strncmp(vtag, "aad=", 4) == 0) {
            vtag += 4;
	    aadLen = sizeof(aad);
	    Base64_Decode((byte*)vtag, strlen(vtag), aad, &aadLen);
	} else if (strncmp(vtag, "pub=", 4) == 0) {
            vtag += 4;
	    word32 publen = sizeof(pubData);
	    Base64_Decode((byte*)vtag, strlen(vtag), pubData, &publen);
	} else if (strncmp(vtag, "priv=", 5) == 0) {
            vtag += 5;
	    word32 privlen = sizeof(privData);
	    Base64_Decode((byte*)vtag, strlen(vtag), privData, &privlen);
	} else if (strncmp(vtag, "payload=", 8) == 0) {
            vtag += 8;
	    outerLen = sizeof(outerClientPayload);
	    Base64_Decode((byte*)vtag, strlen(vtag), outerClientPayload, &outerLen);
	}
    }

    wc_curve25519_init(receiverPrivkey0);
    wc_curve25519_import_private_raw(privData, ECH_KEY_LEN, pubData, ECH_KEY_LEN, receiverPrivkey0);

    outerLen -= 16;
    byte output[1024] = {};
    ret = wc_HpkeOpenBase(hpke, receiverPrivkey0, enc,
		    encLen, info, infoLen, aad, aadLen, outerClientPayload,
		    outerLen,
		    output);

    fprintf(stderr, "verifyECH: ret %d, outerLen=%d, aadLen=%d encLen=%d infoLen=%d\n", ret, outerLen, aadLen, encLen, infoLen);

    byte echConfigBase64[1024];
    word32 echConfigBase64Len = sizeof(echConfigBase64);
    Base64_Encode_NoNl(output, outerLen, (byte*)echConfigBase64, &echConfigBase64Len);
    fprintf(stderr, "verifyECH: %s\n", echConfigBase64);
    return ret;
}

static int keygen_ech(void *heap, const char *publicName, const char *list[])
{
    WOLFSSL_EchConfig *echConfigp = NULL;

    byte               echConfig[512] = {};
    word32             echConfigLen = 512;
    char               echConfigBase64[512] = {};
    word32             echConfigBase64Len = 512;

#define FLAG_KEY_PRIV (1 << 0)
#define FLAG_KEY_PUB  (1 << 1)
#define FLAG_KEY_PAIR (FLAG_KEY_PUB| FLAG_KEY_PRIV)

    int flags = 0;
    word32 outerLen = 0;
    byte privData[33], pubData[33];

    for (int i = 0; list[i]; i++) {
       const char *vtag = list[i];
	if (strncmp(vtag, "pub=", 4) == 0) {
            vtag += 4;
	    outerLen = sizeof(pubData);
	    Base64_Decode((byte*)vtag, strlen(vtag), pubData, &outerLen);
	    flags |= FLAG_KEY_PUB;
	} else if (strncmp(vtag, "priv=", 4) == 0) {
            vtag += 5;
	    outerLen = sizeof(privData);
	    Base64_Decode((byte*)vtag, strlen(vtag), privData, &outerLen);
	    flags |= FLAG_KEY_PRIV;
	}
    }

    GenerateEchConfig(heap, publicName, 0, 0, 0, &echConfigp);
    assert(echConfigp);

    if (flags == FLAG_KEY_PAIR) {
      wc_curve25519_init(echConfigp->receiverPrivkey);
      wc_curve25519_import_private_raw(privData, ECH_KEY_LEN, pubData, ECH_KEY_LEN, echConfigp->receiverPrivkey);
      GenerateEchConfig(heap, publicName, 0, 0, 0, &echConfigp);
    }

    GetEchConfigsEx(echConfigp, echConfig, &echConfigLen);

    Base64_Encode_NoNl(echConfig, echConfigLen, (byte*)echConfigBase64, &echConfigBase64Len);
    fprintf(stderr, "keygen_ech: %s\n", echConfigBase64);

    byte pub[256], priv[256];
    word32 pubsz = sizeof(pub), privsz = sizeof(priv);

    wc_curve25519_export_key_raw(echConfigp->receiverPrivkey, priv, &privsz, pub, &pubsz);

    echConfigBase64Len = 512;
    Base64_Encode_NoNl(pub, pubsz, (byte*)echConfigBase64, &echConfigBase64Len);
    fprintf(stderr, "keygen_ech: pub_ %s\n", echConfigBase64);

    echConfigBase64Len = 512;
    Base64_Encode_NoNl(priv, privsz, (byte*)echConfigBase64, &echConfigBase64Len);
    fprintf(stderr, "keygen_ech: priv %s\n", echConfigBase64);

    return 0;
}

static void usage(void)
{
    fprintf(stderr, "usage: ech_util action parmeter_list\n");
    fprintf(stderr, "	verify \n");
    fprintf(stderr, "	keygen <publicname>\n");
}

int main(int argc, char *argv[])
{
    int ret = 0;
    const char *action = argv[1];

    if (argc > 1) {
        if (strcmp(action, "verify") == 0) {
            return ech_verify(argc - 2, argv + 2);
        } else if (strcmp(action, "keygen") == 0) {
            assert(argc > 2);
            keygen_ech(NULL, argv[2], argv + 3);
        } else {
            fprintf(stderr, "unsupport option: %s\n", action);
            usage();
        }
    } else {
	fprintf(stderr, "missing action\n");
	usage();
    }

    return ret;
}

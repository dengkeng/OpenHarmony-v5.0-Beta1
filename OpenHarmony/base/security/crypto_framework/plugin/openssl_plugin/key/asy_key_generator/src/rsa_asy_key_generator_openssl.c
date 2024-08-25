/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "securec.h"
#include "string.h"

#include "openssl_adapter.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "openssl/pem.h"
#include "openssl/x509.h"

#include "algorithm_parameter.h"
#include "asy_key_generator_spi.h"
#include "detailed_rsa_key_params.h"
#include "log.h"
#include "memory.h"
#include "rsa_openssl_common.h"
#include "utils.h"

#include "rsa_asy_key_generator_openssl.h"

#define OPENSSL_BITS_PER_BYTE 8
#define OPENSSL_RSA_KEYPAIR_CNT 3
#define OPENSSL_RSA_KEYGEN_DEFAULT_PRIMES 2
#define MAX_KEY_SIZE 8192
#define MIN_KEY_SIZE 512

enum OpensslRsaKeySize {
    OPENSSL_RSA_KEY_SIZE_BY_SPEC = 0,
    OPENSSL_RSA_KEY_SIZE_512 = 512,
    OPENSSL_RSA_KEY_SIZE_768 = 768,
    OPENSSL_RSA_KEY_SIZE_1024 = 1024,
    OPENSSL_RSA_KEY_SIZE_2048 = 2048,
    OPENSSL_RSA_KEY_SIZE_3072 = 3072,
    OPENSSL_RSA_KEY_SIZE_4096 = 4096,
    OPENSSL_RSA_KEY_SIZE_8192 = 8192,
};

enum OpensslRsaPrimesSize {
    OPENSSL_RSA_PRIMES_SIZE_2 = 2,
    OPENSSL_RSA_PRIMES_SIZE_3 = 3,
    OPENSSL_RSA_PRIMES_SIZE_4 = 4,
    OPENSSL_RSA_PRIMES_SIZE_5 = 5,
};

typedef struct {
    int32_t bits;
    int32_t primes;
    BIGNUM *pubExp;
} HcfAsyKeyGenSpiRsaParams;

typedef struct {
    HcfAsyKeyGeneratorSpi base;

    HcfAsyKeyGenSpiRsaParams *params;
} HcfAsyKeyGeneratorSpiRsaOpensslImpl;

static HcfResult CheckRsaKeyGenParams(HcfAsyKeyGenSpiRsaParams *params)
{
    switch (params->bits) {
        case OPENSSL_RSA_KEY_SIZE_BY_SPEC:
            break;
        case OPENSSL_RSA_KEY_SIZE_512:
        case OPENSSL_RSA_KEY_SIZE_768:
            if (params->primes != OPENSSL_RSA_PRIMES_SIZE_2) {
                LOGE("Set invalid primes %d to Keygen bits %d.", params->primes, params->bits);
                return HCF_INVALID_PARAMS;
            }
            break;
        case OPENSSL_RSA_KEY_SIZE_1024:
        case OPENSSL_RSA_KEY_SIZE_2048:
        case OPENSSL_RSA_KEY_SIZE_3072:
            if (params->primes > OPENSSL_RSA_PRIMES_SIZE_3 || params->primes < OPENSSL_RSA_PRIMES_SIZE_2) {
                LOGE("Set invalid primes %d to Keygen bits %d.", params->primes, params->bits);
                return HCF_INVALID_PARAMS;
            }
            break;
        case OPENSSL_RSA_KEY_SIZE_4096:
            if (params->primes > OPENSSL_RSA_PRIMES_SIZE_4 || params->primes < OPENSSL_RSA_PRIMES_SIZE_2) {
                LOGE("Set invalid primes %d to Keygen bits %d.", params->primes, params->bits);
                return HCF_INVALID_PARAMS;
            }
            break;
        case OPENSSL_RSA_KEY_SIZE_8192: // This keySize can use primes from 2 to 5.
            break;
        default:
            LOGE("The current bits %d is invalid.", params->bits);
            return HCF_INVALID_PARAMS;
    }
    return HCF_SUCCESS;
}

static const char *GetOpensslPubkeyClass(void)
{
    return OPENSSL_RSA_PUBKEY_CLASS;
}

static const char *GetOpensslPrikeyClass(void)
{
    return OPENSSL_RSA_PRIKEY_CLASS;
}

static const char *GetOpensslKeyPairClass(void)
{
    return OPENSSL_RSA_KEYPAIR_CLASS;
}

static HcfResult GetRsaPubKeySpecString(const HcfPubKey *self, const AsyKeySpecItem item,
    char **returnString)
{
    (void)self;
    (void)returnString;
    LOGE("Rsa has no string attribute");
    return HCF_NOT_SUPPORT;
}

static HcfResult GetRsaPubKeySpecInt(const HcfPubKey *self, const AsyKeySpecItem item,
    int *returnInt)
{
    (void)self;
    (void)returnInt;
    LOGE("Rsa has no integer attribute");
    return HCF_NOT_SUPPORT;
}

static HcfResult GetRsaPriKeySpecString(const HcfPriKey *self, const AsyKeySpecItem item,
    char **returnString)
{
    (void)self;
    (void)returnString;
    LOGE("Rsa has no string attribute");
    return HCF_NOT_SUPPORT;
}

static HcfResult GetRsaPriKeySpecInt(const HcfPriKey *self, const AsyKeySpecItem item,
    int *returnInt)
{
    (void)self;
    (void)returnInt;
    LOGE("Rsa has no integer attribute");
    return HCF_NOT_SUPPORT;
}
static HcfResult GetRsaPriKeyEncodedDer(const HcfPriKey *self, const char *format, HcfBlob *returnBlob)
{
    (void)self;
    (void)format;
    (void)returnBlob;
    return HCF_INVALID_PARAMS;
}

static HcfResult GetRsaPriKeySpecBigInteger(const HcfPriKey *self, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    if (self == NULL || returnBigInteger == NULL) {
        LOGE("Input params is invalid.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PRIKEY_CLASS)) {
        LOGE("Class not match");
        return HCF_INVALID_PARAMS;
    }
    HcfOpensslRsaPriKey *impl = (HcfOpensslRsaPriKey *)self;
    if (impl->sk == NULL) {
        LOGE("Cannot use priKey after free");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = HCF_INVALID_PARAMS;
    if (item == RSA_N_BN) {
        const BIGNUM *n = OpensslRsaGet0N(impl->sk);
        if (n == NULL) {
            LOGD("[error] fail to get n");
            return HCF_ERR_CRYPTO_OPERATION;
        }
        ret = BigNumToBigInteger(n, returnBigInteger);
        if (ret != HCF_SUCCESS) {
            LOGD("[error] fail get RSA Big Integer n");
            return ret;
        }
    } else if (item == RSA_SK_BN) {
        const BIGNUM *d = OpensslRsaGet0D(impl->sk);
        if (d == NULL) {
            LOGD("[error] fail to get sk");
            return HCF_ERR_CRYPTO_OPERATION;
        }
        ret = BigNumToBigInteger(d, returnBigInteger);
        if (ret != HCF_SUCCESS) {
            LOGE("fail get RSA Big Integer d");
            return ret;
        }
    } else {
        LOGE("Invalid RSA pri key spec");
        return HCF_INVALID_PARAMS;
    }
    return ret;
}

static HcfResult GetRsaPubKeySpecBigInteger(const HcfPubKey *self, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    if (self == NULL || returnBigInteger == NULL) {
        LOGE("Input params is invalid.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PUBKEY_CLASS)) {
        LOGE("Class not match");
        return HCF_INVALID_PARAMS;
    }
    HcfOpensslRsaPubKey *impl = (HcfOpensslRsaPubKey *)self;
    HcfResult ret = HCF_INVALID_PARAMS;
    if (item == RSA_N_BN) {
        const BIGNUM *n = OpensslRsaGet0N(impl->pk);
        if (n == NULL) {
            LOGD("[error] fail to get n");
            return HCF_ERR_CRYPTO_OPERATION;
        }
        ret = BigNumToBigInteger(n, returnBigInteger);
        if (ret != HCF_SUCCESS) {
            LOGE("fail get RSA Big Integer n");
            return ret;
        }
    } else if (item == RSA_PK_BN) {
        const BIGNUM *e = OpensslRsaGet0E(impl->pk);
        if (e == NULL) {
            LOGD("[error] fail to get pk");
            return HCF_ERR_CRYPTO_OPERATION;
        }
        ret = BigNumToBigInteger(e, returnBigInteger);
        if (ret != HCF_SUCCESS) {
            LOGE("fail get RSA Big Integer e");
            return ret;
        }
    } else {
        LOGE("Invalid RSA pub key spec");
        return HCF_INVALID_PARAMS;
    }
    return ret;
}

static void DestroyPubKey(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("PubKey is NULL.");
        return;
    }
    if (!IsClassMatch(self, OPENSSL_RSA_PUBKEY_CLASS)) {
        LOGE("Class not match");
        return;
    }
    HcfOpensslRsaPubKey *impl = (HcfOpensslRsaPubKey *)self;
    OpensslRsaFree(impl->pk);
    impl->pk = NULL;
    HcfFree(self);
}

static void DestroyPriKey(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("PubKey is NULL.");
        return;
    }
    if (!IsClassMatch(self, OPENSSL_RSA_PRIKEY_CLASS)) {
        LOGE("Class not match");
        return;
    }
    HcfOpensslRsaPriKey *impl = (HcfOpensslRsaPriKey*)self;
    // RSA_free func will clear private information
    OpensslRsaFree(impl->sk);
    impl->sk = NULL;
    HcfFree(self);
}

static void DestroyKeyPair(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("PubKey is NULL.");
        return;
    }
    if (!IsClassMatch(self, OPENSSL_RSA_KEYPAIR_CLASS)) {
        LOGE("Class not match");
        return;
    }
    HcfOpensslRsaKeyPair *impl = (HcfOpensslRsaKeyPair*)self;
    if (impl->base.pubKey != NULL) {
        DestroyPubKey((HcfObjectBase *)impl->base.pubKey);
        impl->base.pubKey = NULL;
    }
    if (impl->base.priKey != NULL) {
        DestroyPriKey((HcfObjectBase *)impl->base.priKey);
        impl->base.priKey = NULL;
    }
    HcfFree(self);
}

static HcfResult CopyMemFromBIO(BIO *bio, HcfBlob *outBlob)
{
    if (bio == NULL || outBlob == NULL) {
        LOGE("Invalid input.");
        return HCF_INVALID_PARAMS;
    }
    int len = BIO_pending(bio);
    if (len < 0) {
        LOGE("Bio len less than 0.");
        return HCF_INVALID_PARAMS;
    }
    HcfBlob blob;
    blob.len = len;
    blob.data = (uint8_t *)HcfMalloc(sizeof(uint8_t) * len, 0);
    if (blob.data == NULL) {
        LOGE("Malloc mem for blob fail.");
        return HCF_ERR_MALLOC;
    }
    if (OpensslBioRead(bio, blob.data, blob.len) <= 0) {
        LOGD("[error] Bio read fail");
        HcfPrintOpensslError();
        HcfFree(blob.data);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    outBlob->len = blob.len;
    outBlob->data = blob.data;
    return HCF_SUCCESS;
}

static HcfResult CopyStrFromBIO(BIO *bio, char **returnString)
{
    if (bio == NULL || returnString == NULL) {
        LOGE("Invalid input.");
        return HCF_INVALID_PARAMS;
    }
    int len = BIO_pending(bio);
    if (len < 0) {
        LOGE("Bio len less than 0.");
        return HCF_INVALID_PARAMS;
    }
    *returnString = (char *)HcfMalloc(len + 1, 0);
    if (*returnString == NULL) {
        LOGE("Malloc mem for blob fail.");
        return HCF_ERR_MALLOC;
    }
    if (OpensslBioRead(bio, *returnString, len) <= 0) {
        LOGE("Bio read fail");
        HcfPrintOpensslError();
        HcfFree(*returnString);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult ConvertPubKeyFromX509(HcfBlob *x509Blob, RSA **rsa)
{
    uint8_t *temp = x509Blob->data;
    RSA *tempRsa = OpensslD2iRsaPubKey(NULL, (const unsigned char **)&temp, x509Blob->len);
    if (tempRsa == NULL) {
        LOGD("[error] d2i_RSA_PUBKEY fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *rsa = tempRsa;
    return HCF_SUCCESS;
}

static HcfResult ConvertPriKeyFromPKCS8(HcfBlob *pkcs8Blob, RSA **rsa)
{
    const unsigned char *temp = (const unsigned char *)pkcs8Blob->data;
    EVP_PKEY *pKey = OpensslD2iAutoPrivateKey(NULL, &temp, pkcs8Blob->len);
    if (pKey == NULL) {
        LOGD("[error] d2i_AutoPrivateKey fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    RSA *tmpRsa = OpensslEvpPkeyGet1Rsa(pKey);
    if (tmpRsa == NULL) {
        LOGD("[error] EVP_PKEY_get1_RSA fail");
        HcfPrintOpensslError();
        OpensslEvpPkeyFree(pKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *rsa = tmpRsa;
    OpensslEvpPkeyFree(pKey);
    return HCF_SUCCESS;
}

static HcfResult EncodePubKeyToX509(RSA *rsa, HcfBlob *returnBlob)
{
    unsigned char *tempData = NULL;
    int len = OpensslI2dRsaPubKey(rsa, &tempData);
    if (len <= 0) {
        LOGD("[error] i2d_RSA_PUBKEY fail");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->data = tempData;
    returnBlob->len = len;
    return HCF_SUCCESS;
}

static HcfResult EncodePriKeyToPKCS8(RSA *rsa, HcfBlob *returnBlob)
{
    EVP_PKEY *pKey = NewEvpPkeyByRsa(rsa, true);
    if (pKey == NULL) {
        LOGD("[error] NewEvpPkeyByRsa fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = HCF_SUCCESS;
    BIO *bio = OpensslBioNew(OpensslBioSMem());
    if (bio == NULL) {
        LOGD("[error] BIO new fail.");
        HcfPrintOpensslError();
        ret = HCF_ERR_CRYPTO_OPERATION;
        goto ERR2;
    }
    if (OpensslI2dPkcs8PrivateKeyBio(bio, pKey, NULL, NULL, 0, NULL, NULL) != HCF_OPENSSL_SUCCESS) {
        LOGD("[error] i2b_PrivateKey_bio fail.");
        HcfPrintOpensslError();
        ret = HCF_ERR_CRYPTO_OPERATION;
        goto ERR1;
    }
    if (CopyMemFromBIO(bio, returnBlob) != HCF_SUCCESS) {
        LOGD("[error] CopyMemFromBIO fail.");
        ret = HCF_ERR_CRYPTO_OPERATION;
        goto ERR1;
    }
ERR1:
    OpensslBioFreeAll(bio);
ERR2:
    OpensslEvpPkeyFree(pKey);
    return ret;
}

static HcfResult GetPubKeyEncoded(HcfKey *self, HcfBlob *returnBlob)
{
    if (self == NULL || returnBlob == NULL) {
        LOGE("Input params is invalid.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PUBKEY_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfOpensslRsaPubKey *impl = (HcfOpensslRsaPubKey *)self;
    return EncodePubKeyToX509(impl->pk, returnBlob);
}

static HcfResult GetPubKeyPkcs1Pem(RSA *pk, char **returnString)
{
    BIO *bio = OpensslBioNew(OpensslBioSMem());
    if (bio == NULL) {
        LOGE("BIO new fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int ret = OpensslPemWriteBioRsaPublicKey(bio, pk);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("OpensslPemWriteBioRsaPublicKey fail.");
        HcfPrintOpensslError();
        OpensslBioFreeAll(bio);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (CopyStrFromBIO(bio, returnString) != HCF_SUCCESS) {
        LOGE("CopyMemFromBIO fail.");
        OpensslBioFreeAll(bio);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    OpensslBioFreeAll(bio);
    return HCF_SUCCESS;
}

static HcfResult GetPubKeyX509Pem(RSA *pk, char **returnString)
{
    BIO *bio = OpensslBioNew(OpensslBioSMem());
    if (bio == NULL) {
        LOGE("BIO new fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int ret = OpensslPemWriteBioRsaPubKey(bio, pk);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("OpensslPemWriteBioRsaPubKey fail.");
        HcfPrintOpensslError();
        OpensslBioFreeAll(bio);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (CopyStrFromBIO(bio, returnString) != HCF_SUCCESS) {
        LOGE("CopyMemFromBIO fail.");
        OpensslBioFreeAll(bio);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    OpensslBioFreeAll(bio);
    return HCF_SUCCESS;
}

static HcfResult GetPubKeyPem(const char *format, RSA *pk, char **returnString)
{
    HcfResult result;
    if (strcmp(format, "PKCS1") == 0) {
        result = GetPubKeyPkcs1Pem(pk, returnString);
        if (result != HCF_SUCCESS) {
            return result;
        }
    }
    if (strcmp(format, "X509") == 0) {
        result = GetPubKeyX509Pem(pk, returnString);
        if (result != HCF_SUCCESS) {
            return result;
        }
    }
    return HCF_SUCCESS;
}


static HcfResult GetPubKeyEncodedPem(HcfKey *self, const char *format, char **returnString)
{
    if (self == NULL || format == NULL|| returnString == NULL) {
        LOGE("param is null.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PUBKEY_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    const char *outPutStruct = NULL;
    if (strcmp(format, "PKCS1") == 0) {
        outPutStruct = "pkcs1";
    } else if (strcmp(format, "X509") == 0) {
        outPutStruct = "subjectPublicKeyInfo";
    } else {
        LOGE("format is invalid.");
        return HCF_INVALID_PARAMS;
    }
    HcfOpensslRsaPubKey *impl = (HcfOpensslRsaPubKey *)self;
    EVP_PKEY *pkey = NewEvpPkeyByRsa(impl->pk, true);
    if (pkey == NULL) {
        LOGE("NewEvpPkeyByRsa failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult result = GetKeyEncodedPem(pkey, outPutStruct, EVP_PKEY_PUBLIC_KEY, returnString);
    OpensslEvpPkeyFree(pkey);
    if (result != HCF_SUCCESS) {
        if (GetPubKeyPem(format, impl->pk, returnString) != HCF_SUCCESS) {
            LOGE("GetPubKeyPem failed.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    return HCF_SUCCESS;
}

static HcfResult GetPriKeyEncoded(HcfKey *self, HcfBlob *returnBlob)
{
    if (self == NULL || returnBlob == NULL) {
        LOGE("Key is null.");
        return HCF_INVALID_PARAMS;
    }

    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PRIKEY_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfOpensslRsaPriKey *impl = (HcfOpensslRsaPriKey *)self;
    const BIGNUM *p = NULL;
    const BIGNUM *q = NULL;
    OpensslRsaGet0Factors(impl->sk, &p, &q);
    if (p == NULL || q == NULL) {
        LOGD("[error] RSA private key missing p, q, not support to get encoded PK");
        return HCF_NOT_SUPPORT;
    }
    return EncodePriKeyToPKCS8(impl->sk, returnBlob);
}

static HcfResult GetPrikeyPkcs8Pem(EVP_PKEY *pkey, char **returnString)
{
    BIO *bio = OpensslBioNew(OpensslBioSMem());
    if (bio == NULL) {
        LOGE("BIO new fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int ret = OpensslPemWriteBioPkcs8PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("OpensslPemWriteBioPkcs8PrivateKey fail.");
        HcfPrintOpensslError();
        OpensslBioFreeAll(bio);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (CopyStrFromBIO(bio, returnString) != HCF_SUCCESS) {
        LOGE("CopyMemFromBIO fail.");
        OpensslBioFreeAll(bio);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    OpensslBioFreeAll(bio);
    return HCF_SUCCESS;
}

static HcfResult GetPrikeyPkcs1Pem(RSA *sk, char **returnString)
{
    BIO *bio = OpensslBioNew(OpensslBioSMem());
    if (bio == NULL) {
        LOGE("BIO new fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int ret = OpensslPemWriteBioRsaPrivateKey(bio, sk, NULL, NULL, 0, NULL, NULL);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("OpensslPemWriteBioRsaPrivateKey fail.");
        HcfPrintOpensslError();
        OpensslBioFreeAll(bio);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (CopyStrFromBIO(bio, returnString) != HCF_SUCCESS) {
        LOGE("CopyStrFromBIO fail.");
        OpensslBioFreeAll(bio);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    OpensslBioFreeAll(bio);
    return HCF_SUCCESS;
}

static HcfResult GetPriKeyPem(const char *format, EVP_PKEY *pkey, RSA *sk, char **returnString)
{
    HcfResult result;
    if (strcmp(format, "PKCS8") == 0) {
        result = GetPrikeyPkcs8Pem(pkey, returnString);
        if (result != HCF_SUCCESS) {
            return result;
        }
    }
    if (strcmp(format, "PKCS1") == 0) {
        result = GetPrikeyPkcs1Pem(sk, returnString);
        if (result != HCF_SUCCESS) {
            return result;
        }
    }
    return HCF_SUCCESS;
}

static HcfResult GetPriKeyEncodedPem(HcfKey *self, const char *format, char **returnString)
{
    if (self == NULL || format == NULL|| returnString == NULL) {
        LOGE("param is null.");
        return HCF_INVALID_PARAMS;
    }

    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PRIKEY_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    char *outPutStruct = NULL;
    if (strcmp(format, "PKCS1") == 0) {
        outPutStruct = "type-specific";
    } else if (strcmp(format, "PKCS8") == 0) {
        outPutStruct = "PrivateKeyInfo";
    } else {
        LOGE("format is invalid.");
        return HCF_INVALID_PARAMS;
    }

    HcfOpensslRsaPriKey *impl = (HcfOpensslRsaPriKey *)self;
    EVP_PKEY *pkey = NewEvpPkeyByRsa(impl->sk, true);
    if (pkey == NULL) {
        LOGE("NewEvpPkeyByRsa failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    HcfResult result = GetKeyEncodedPem(pkey, outPutStruct, EVP_PKEY_KEYPAIR, returnString);
    if (result != HCF_SUCCESS) {
        if (GetPriKeyPem(format, pkey, impl->sk, returnString) != HCF_SUCCESS) {
            LOGE("GetPriKeyPem failed.");
            OpensslEvpPkeyFree(pkey);
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    OpensslEvpPkeyFree(pkey);
    return HCF_SUCCESS;
}

static const char *GetPubKeyFormat(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PUBKEY_CLASS)) {
        return NULL;
    }
    return OPENSSL_RSA_PUBKEY_FORMAT;
}

static const char *GetPriKeyFormat(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PRIKEY_CLASS)) {
        return NULL;
    }
    return OPENSSL_RSA_PRIKEY_FORMAT;
}

static const char *GetPriKeyAlgorithm(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PRIKEY_CLASS)) {
        return NULL;
    }
    return OPENSSL_RSA_ALGORITHM;
}

static const char *GetPubKeyAlgorithm(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PUBKEY_CLASS)) {
        return NULL;
    }
    return OPENSSL_RSA_ALGORITHM;
}

static void ClearPriKeyMem(HcfPriKey *self)
{
    if (self == NULL) {
        LOGE("PriKey is NULL.");
        return;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PRIKEY_CLASS)) {
        LOGE("Class not match");
        return;
    }
    HcfOpensslRsaPriKey *impl = (HcfOpensslRsaPriKey *)self;
    OpensslRsaFree(impl->sk);
    impl->sk = NULL;
}

static HcfResult GetRsaPubKeyEncodedDer(const HcfPubKey *self, const char *format, HcfBlob *returnBlob)
{
    (void)self;
    (void)format;
    (void)returnBlob;
    return HCF_INVALID_PARAMS;
}

static HcfResult PackPubKey(RSA *rsaPubKey, HcfOpensslRsaPubKey **retPubKey)
{
    if (retPubKey == NULL || rsaPubKey == NULL) {
        LOGE("Invalid params");
        return HCF_INVALID_PARAMS;
    }
    *retPubKey = (HcfOpensslRsaPubKey *)HcfMalloc(sizeof(HcfOpensslRsaPubKey), 0);
    if (*retPubKey == NULL) {
        LOGE("Malloc retPubKey fail");
        return HCF_ERR_MALLOC;
    }
    (*retPubKey)->pk = rsaPubKey;
    (*retPubKey)->bits = (uint32_t)OpensslRsaBits(rsaPubKey);
    (*retPubKey)->base.base.getAlgorithm = GetPubKeyAlgorithm;
    (*retPubKey)->base.base.getEncoded = GetPubKeyEncoded;
    (*retPubKey)->base.base.getEncodedPem = GetPubKeyEncodedPem;
    (*retPubKey)->base.base.getFormat = GetPubKeyFormat;
    (*retPubKey)->base.base.base.getClass = GetOpensslPubkeyClass;
    (*retPubKey)->base.base.base.destroy = DestroyPubKey;
    (*retPubKey)->base.getAsyKeySpecBigInteger = GetRsaPubKeySpecBigInteger;
    (*retPubKey)->base.getAsyKeySpecString = GetRsaPubKeySpecString;
    (*retPubKey)->base.getAsyKeySpecInt = GetRsaPubKeySpecInt;
    (*retPubKey)->base.getEncodedDer = GetRsaPubKeyEncodedDer;
    return HCF_SUCCESS;
}

// spec中，prikey只有n，e，d，没有p, q
static HcfResult PackPriKey(RSA *rsaPriKey, HcfOpensslRsaPriKey **retPriKey)
{
    if (retPriKey == NULL || rsaPriKey == NULL) {
        LOGE("Invalid params");
        return HCF_INVALID_PARAMS;
    }
    *retPriKey = (HcfOpensslRsaPriKey *)HcfMalloc(sizeof(HcfOpensslRsaPriKey), 0);
    if (*retPriKey == NULL) {
        LOGE("Malloc retPriKey fail");
        return HCF_ERR_MALLOC;
    }
    (*retPriKey)->sk = rsaPriKey;
    (*retPriKey)->bits = (uint32_t)OpensslRsaBits(rsaPriKey);
    (*retPriKey)->base.clearMem = ClearPriKeyMem;
    (*retPriKey)->base.base.getAlgorithm = GetPriKeyAlgorithm;
    (*retPriKey)->base.base.getEncoded = GetPriKeyEncoded;
    (*retPriKey)->base.base.getEncodedPem = GetPriKeyEncodedPem;
    (*retPriKey)->base.base.getFormat = GetPriKeyFormat;
    (*retPriKey)->base.base.base.getClass = GetOpensslPrikeyClass;
    (*retPriKey)->base.base.base.destroy = DestroyPriKey;
    (*retPriKey)->base.getAsyKeySpecBigInteger = GetRsaPriKeySpecBigInteger;
    (*retPriKey)->base.getAsyKeySpecString = GetRsaPriKeySpecString;
    (*retPriKey)->base.getAsyKeySpecInt = GetRsaPriKeySpecInt;
    (*retPriKey)->base.getEncodedDer = GetRsaPriKeyEncodedDer;
    return HCF_SUCCESS;
}

static HcfResult DuplicatePkAndSkFromRSA(RSA *rsa, RSA **pubKey, RSA **priKey)
{
    if (rsa == NULL) {
        LOGE("Rsa is NULL.");
        return HCF_INVALID_PARAMS;
    }
    if (DuplicateRsa(rsa, false, pubKey) != HCF_SUCCESS) {
        LOGD("[error] Duplicate pubkey rsa fail");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (DuplicateRsa(rsa, true, priKey) != HCF_SUCCESS) {
        LOGD("[error] Duplicate prikey rsa fail");
        OpensslRsaFree(*pubKey);
        *pubKey = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult PackKeyPair(RSA *rsa, uint32_t realBits, HcfOpensslRsaKeyPair **retKeyPair)
{
    if (retKeyPair == NULL || rsa == NULL) {
        LOGE("Invalid params");
        return HCF_INVALID_PARAMS;
    }
    RSA *pubKey = NULL;
    RSA *priKey = NULL;
    if (DuplicatePkAndSkFromRSA(rsa, &pubKey, &priKey) != HCF_SUCCESS) {
        LOGD("[error] DuplicatePkAndSkFromRSA fail");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = HCF_SUCCESS;
    *retKeyPair = (HcfOpensslRsaKeyPair *)HcfMalloc(sizeof(HcfOpensslRsaKeyPair), 0);
    if (*retKeyPair == NULL) {
        LOGE("Malloc keypair fail");
        OpensslRsaFree(pubKey);
        OpensslRsaFree(priKey);
        return HCF_ERR_MALLOC;
    }
    HcfOpensslRsaPriKey *priKeyImpl = NULL;
    HcfOpensslRsaPubKey *pubKeyImpl = NULL;
    ret = PackPubKey(pubKey, &pubKeyImpl);
    if (ret != HCF_SUCCESS) {
        LOGE("Pack pubKey fail.");
        goto ERR2;
    }
    ret = PackPriKey(priKey, &priKeyImpl);
    if (ret != HCF_SUCCESS) {
        LOGE("Pack priKey fail.");
        goto ERR1;
    }
    (*retKeyPair)->base.priKey = (HcfPriKey *)priKeyImpl;
    (*retKeyPair)->base.pubKey = (HcfPubKey *)pubKeyImpl;
    (*retKeyPair)->base.base.getClass = GetOpensslKeyPairClass;
    (*retKeyPair)->base.base.destroy = DestroyKeyPair;
    return HCF_SUCCESS;
ERR1:
    HcfFree(pubKeyImpl);
ERR2:
    OpensslRsaFree(pubKey);
    OpensslRsaFree(priKey);
    HcfFree(*retKeyPair);
    *retKeyPair = NULL;
    return ret;
}

static HcfResult GenerateKeyPair(HcfAsyKeyGenSpiRsaParams *params, HcfKeyPair **keyPair)
{
    // check input params is valid
    HcfResult res = CheckRsaKeyGenParams(params);
    if (res != HCF_SUCCESS) {
        LOGE("Rsa CheckRsaKeyGenParams fail.");
        return HCF_INVALID_PARAMS;
    }
    // Generate keyPair RSA
    RSA *rsa = OpensslRsaNew();
    if (rsa == NULL) {
        LOGE("new RSA fail.");
        return HCF_ERR_MALLOC;
    }
    LOGD("keygen bits is %d, primes is %d", params->bits, GetRealPrimes(params->primes));
    if (GetRealPrimes(params->primes) != OPENSSL_RSA_KEYGEN_DEFAULT_PRIMES) {
        if (RSA_generate_multi_prime_key(rsa, params->bits, GetRealPrimes(params->primes), params->pubExp, NULL)
            != HCF_OPENSSL_SUCCESS) {
            LOGD("[error] Generate multi-primes rsa key fail");
            HcfPrintOpensslError();
            OpensslRsaFree(rsa);
            return HCF_ERR_CRYPTO_OPERATION;
        }
    } else {
        if (RSA_generate_key_ex(rsa, params->bits, params->pubExp, NULL) != HCF_OPENSSL_SUCCESS) {
            LOGD("[error] Generate rsa key fail");
            HcfPrintOpensslError();
            OpensslRsaFree(rsa);
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }

    // devided to pk and sk;
    HcfOpensslRsaKeyPair *keyPairImpl = NULL;
    res = PackKeyPair(rsa, params->bits, &keyPairImpl);
    if (res != HCF_SUCCESS) {
        LOGE("Generate keyPair fail.");
        OpensslRsaFree(rsa);
        return res;
    }
    *keyPair = (HcfKeyPair *)keyPairImpl;
    OpensslRsaFree(rsa);
    LOGD("Generate keypair success.");
    return res;
}

static HcfResult EngineGenerateKeyPair(HcfAsyKeyGeneratorSpi *self, HcfKeyPair **keyPair)
{
    if (self == NULL || keyPair == NULL) {
        LOGE("Invalid params.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_GENERATOR_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGeneratorSpiRsaOpensslImpl *impl = (HcfAsyKeyGeneratorSpiRsaOpensslImpl *)self;
    return GenerateKeyPair(impl->params, keyPair);
}

static const char *GetKeyGeneratorClass(void)
{
    return OPENSSL_RSA_GENERATOR_CLASS;
}

static void DestroyKeyGeneratorSpiImpl(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("DestroyKeyGeneratorSpiImpl is null");
        return;
    }
    if (!IsClassMatch(self, OPENSSL_RSA_GENERATOR_CLASS)) {
        LOGE("Class not match.");
        return;
    }
    // destroy pubExp first.
    HcfAsyKeyGeneratorSpiRsaOpensslImpl *impl = (HcfAsyKeyGeneratorSpiRsaOpensslImpl *)self;
    if (impl->params != NULL && impl->params->pubExp != NULL) {
        OpensslBnFree(impl->params->pubExp);
    }
    HcfFree(impl->params);
    impl->params = NULL;
    HcfFree(self);
}

static HcfResult ConvertPubKey(HcfBlob *pubKeyBlob, HcfOpensslRsaPubKey **pubkeyRet)
{
    RSA *rsaPk = NULL;
    if (ConvertPubKeyFromX509(pubKeyBlob, &rsaPk) != HCF_SUCCESS) {
        LOGD("[error] Convert pubKey from X509 fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfOpensslRsaPubKey *pubKey = NULL;
    HcfResult ret = PackPubKey(rsaPk, &pubKey);
    if (ret != HCF_SUCCESS) {
        LOGD("[error] PackPubKey fail");
        goto ERR;
    }
    *pubkeyRet = pubKey;
    return ret;
ERR:
    OpensslRsaFree(rsaPk);
    return ret;
}

static HcfResult ConvertPemKeyToKey(const char *keyStr, int selection, RSA **rsa)
{
    EVP_PKEY *pkey = NULL;
    const char *inputType = "PEM";
    const char *keytype = "RSA";
    OSSL_DECODER_CTX *ctx = OpensslOsslDecoderCtxNewForPkey(&pkey, inputType,
        NULL, keytype, selection, NULL, NULL);
    if (ctx == NULL) {
        LOGE("OpensslOsslDecoderCtxNewForPkey fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    size_t pdataLen = strlen(keyStr);
    const unsigned char *pdata = (const unsigned char *)keyStr;
    int ret = OpensslOsslDecoderFromData(ctx, &pdata, &pdataLen);
    OpensslOsslDecoderCtxFree(ctx);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("OpensslOsslDecoderFromData failed.");
        HcfPrintOpensslError();
        OpensslEvpPkeyFree(pkey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *rsa = OpensslEvpPkeyGet1Rsa(pkey);
    OpensslEvpPkeyFree(pkey);
    if (*rsa == NULL) {
        LOGE("OpensslEvpPkeyGet1Rsa fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult ConvertPemPubKey(const char *pubKeyStr, int selection, HcfOpensslRsaPubKey **pubKeyRet)
{
    RSA *rsaPk = NULL;
    HcfResult ret;
    ret = ConvertPemKeyToKey(pubKeyStr, selection, &rsaPk);
    if (ret != HCF_SUCCESS) {
        LOGE("ConvertPemKeyToKey failed.");
        return ret;
    }

    HcfOpensslRsaPubKey *pubKey = NULL;
    HcfResult result = PackPubKey(rsaPk, &pubKey);
    if (result != HCF_SUCCESS) {
        LOGE("PackPubKey fail.");
        OpensslRsaFree(rsaPk);
        return result;
    }
    *pubKeyRet = pubKey;
    return HCF_SUCCESS;
}

static HcfResult ConvertPriKey(HcfBlob *priKeyBlob, HcfOpensslRsaPriKey **priKeyRet)
{
    RSA *rsaSk = NULL;
    if (ConvertPriKeyFromPKCS8(priKeyBlob, &rsaSk) != HCF_SUCCESS) {
        LOGE("ConvertPriKeyFromPKCS8 fail.");
        return HCF_ERR_MALLOC;
    }
    HcfOpensslRsaPriKey *priKey = NULL;
    HcfResult ret = PackPriKey(rsaSk, &priKey);
    if (ret != HCF_SUCCESS) {
        LOGD("[error] PackPriKey fail");
        goto ERR;
    }
    *priKeyRet = priKey;
    return ret;
ERR:
    OpensslRsaFree(rsaSk);
    return ret;
}

static HcfResult ConvertPemPriKey(const char *priKeyStr, int selection, HcfOpensslRsaPriKey **priKeyRet)
{
    RSA *rsaSk = NULL;
    HcfResult ret;
    ret = ConvertPemKeyToKey(priKeyStr, selection, &rsaSk);
    if (ret != HCF_SUCCESS) {
        LOGE("ConvertPemKeyToKey failed.");
        return ret;
    }
    HcfOpensslRsaPriKey *priKey = NULL;
    HcfResult result = PackPriKey(rsaSk, &priKey);
    if (result != HCF_SUCCESS) {
        LOGE("PackPriKey fail.");
        OpensslRsaFree(rsaSk);
        return result;
    }
    *priKeyRet = priKey;
    return HCF_SUCCESS;
}

static HcfResult EngineConvertKey(HcfAsyKeyGeneratorSpi *self, HcfParamsSpec *params, HcfBlob *pubKeyBlob,
    HcfBlob *priKeyBlob, HcfKeyPair **returnKeyPair)
{
    (void)params;
    if ((self == NULL) || (returnKeyPair == NULL) || ((pubKeyBlob == NULL) && (priKeyBlob == NULL))) {
        LOGE("ConvertKeyParams is invalid.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_GENERATOR_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }

    HcfOpensslRsaPubKey *pubKey = NULL;
    if ((pubKeyBlob != NULL) && (pubKeyBlob->len != 0) && (pubKeyBlob->data != NULL)) {
        if (ConvertPubKey(pubKeyBlob, &pubKey) != HCF_SUCCESS) {
            LOGE("convert pubkey fail.");
            return HCF_INVALID_PARAMS;
        }
    }

    HcfOpensslRsaPriKey *priKey = NULL;
    if ((priKeyBlob != NULL) && (priKeyBlob->len != 0) && (priKeyBlob->data != NULL)) {
        if (ConvertPriKey(priKeyBlob, &priKey) != HCF_SUCCESS) {
            LOGE("convert prikey fail.");
            HcfObjDestroy((HcfObjectBase *)pubKey);
            return HCF_INVALID_PARAMS;
        }
    }

    if (pubKey == NULL && priKey == NULL) {
        LOGE("Convert key failed with invalid blob");
        return HCF_INVALID_PARAMS;
    }

    HcfOpensslRsaKeyPair *keyPair = (HcfOpensslRsaKeyPair *)HcfMalloc(sizeof(HcfOpensslRsaKeyPair), 0);
    if (keyPair == NULL) {
        LOGE("Malloc keyPair fail.");
        HcfObjDestroy((HcfObjectBase *)pubKey);
        HcfObjDestroy((HcfObjectBase *)priKey);
        return HCF_ERR_MALLOC;
    }

    keyPair->base.priKey = (HcfPriKey *)priKey;
    keyPair->base.pubKey = (HcfPubKey *)pubKey;
    keyPair->base.base.getClass = GetOpensslKeyPairClass;
    keyPair->base.base.destroy = DestroyKeyPair;
    *returnKeyPair = (HcfKeyPair *)keyPair;
    return HCF_SUCCESS;
}

static HcfResult EngineConvertPemKey(HcfAsyKeyGeneratorSpi *self, HcfParamsSpec *params, const char *pubKeyStr,
    const char *priKeyStr, HcfKeyPair **returnKeyPair)
{
    (void)params;
    if ((self == NULL) || (returnKeyPair == NULL) || ((pubKeyStr == NULL) && (priKeyStr == NULL))) {
        LOGE("ConvertPemKeyParams is invalid.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_GENERATOR_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfOpensslRsaPubKey *pubKey = NULL;
    if (pubKeyStr != NULL && strlen(pubKeyStr) != 0) {
        if (ConvertPemPubKey(pubKeyStr, EVP_PKEY_PUBLIC_KEY, &pubKey) != HCF_SUCCESS) {
            LOGE("convert pubkey fail.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    HcfOpensslRsaPriKey *priKey = NULL;
    if (priKeyStr != NULL && strlen(priKeyStr) != 0) {
        if (ConvertPemPriKey(priKeyStr, EVP_PKEY_KEYPAIR, &priKey) != HCF_SUCCESS) {
            LOGE("convert prikey fail.");
            HcfObjDestroy((HcfObjectBase *)pubKey);
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }

    HcfOpensslRsaKeyPair *keyPair = (HcfOpensslRsaKeyPair *)HcfMalloc(sizeof(HcfOpensslRsaKeyPair), 0);
    if (keyPair == NULL) {
        LOGE("Malloc keyPair fail.");
        HcfObjDestroy((HcfObjectBase *)pubKey);
        HcfObjDestroy((HcfObjectBase *)priKey);
        return HCF_ERR_MALLOC;
    }
    keyPair->base.priKey = (HcfPriKey *)priKey;
    keyPair->base.pubKey = (HcfPubKey *)pubKey;
    keyPair->base.base.getClass = GetOpensslKeyPairClass;
    keyPair->base.base.destroy = DestroyKeyPair;
    *returnKeyPair = (HcfKeyPair *)keyPair;
    return HCF_SUCCESS;
}

static HcfResult ParseRsaBnFromBin(const HcfAsyKeyParamsSpec *paramsSpec, BIGNUM **n,
    BIGNUM **e, BIGNUM **d)
{
    // when meeting the fail situation, the BIGNUM will be NULL and other BIGNUM will be freeed in InitRsaStructByBin();
    if (BigIntegerToBigNum(&((HcfRsaCommParamsSpec *)paramsSpec)->n, n) != HCF_SUCCESS) {
        LOGD("[error] Rsa new BN n fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (paramsSpec->specType == HCF_KEY_PAIR_SPEC) {
        if (BigIntegerToBigNum(&((HcfRsaKeyPairParamsSpec *)paramsSpec)->pk, e) != HCF_SUCCESS) {
            LOGD("[error] Rsa new BN e fail.");
            OpensslBnFree(*n);
            *n = NULL;
            return HCF_ERR_CRYPTO_OPERATION;
        }
        if (BigIntegerToBigNum(&((HcfRsaKeyPairParamsSpec *)paramsSpec)->sk, d) != HCF_SUCCESS) {
            LOGD("[error] Rsa new BN d fail.");
            OpensslBnFree(*n);
            *n = NULL;
            OpensslBnFree(*e);
            *e = NULL;
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    if (paramsSpec->specType == HCF_PUBLIC_KEY_SPEC) {
        if (BigIntegerToBigNum(&((HcfRsaPubKeyParamsSpec *)paramsSpec)->pk, e) != HCF_SUCCESS) {
            LOGD("[error] Rsa new BN e fail.");
            OpensslBnFree(*n);
            *n = NULL;
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    return HCF_SUCCESS;
}

static RSA *InitRsaStructByBin(const HcfAsyKeyParamsSpec *paramsSpec)
{
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    BIGNUM *d = NULL;
    RSA *rsa = NULL;

    if (ParseRsaBnFromBin(paramsSpec, &n, &e, &d) != HCF_SUCCESS) {
        LOGD("[error] ParseRsaBnFromBin fail");
        return rsa;
    }
    rsa = OpensslRsaNew();
    if (rsa == NULL) {
        OpensslBnFree(n);
        OpensslBnFree(e);
        OpensslBnClearFree(d);
        LOGD("[error] new RSA fail");
        return rsa;
    }
    // if set0 success, RSA object will take the owner of n, e, d and will free them.
    // as a new RSA object, in RSA_set0_key(), n and e cannot be NULL.
    if (OpensslRsaSet0Key(rsa, n, e, d) != HCF_OPENSSL_SUCCESS) {
        LOGD("[error] set RSA fail");
        HcfPrintOpensslError();
        OpensslBnFree(n);
        OpensslBnFree(e);
        OpensslBnClearFree(d);
        OpensslRsaFree(rsa);
        rsa = NULL;
        return rsa;
    }
    return rsa;
}

static HcfResult GenerateKeyPairBySpec(const HcfAsyKeyParamsSpec *paramsSpec, HcfKeyPair **keyPair)
{
    // Generate keyPair RSA by spec
    RSA *rsa = InitRsaStructByBin(paramsSpec);
    if (rsa == NULL) {
        LOGD("[error] Generate RSA fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfOpensslRsaKeyPair *keyPairImpl = (HcfOpensslRsaKeyPair *)HcfMalloc(sizeof(HcfOpensslRsaKeyPair), 0);
    if (keyPairImpl == NULL) {
        LOGE("Malloc keyPair fail.");
        OpensslRsaFree(rsa);
        return HCF_ERR_MALLOC;
    }
    // devided to pk and sk;
    HcfOpensslRsaPubKey *pubKeyImpl = NULL;
    HcfOpensslRsaPriKey *priKeyImpl = NULL;

    RSA *pubKeyRsa = NULL;
    if (DuplicateRsa(rsa, false, &pubKeyRsa) != HCF_SUCCESS) {
        LOGD("[error] Duplicate pubKey rsa fail");
        OpensslRsaFree(rsa);
        HcfFree(keyPairImpl);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    HcfResult res = PackPubKey(pubKeyRsa, &pubKeyImpl);
    if (res != HCF_SUCCESS) {
        LOGE("pack pup key fail.");
        OpensslRsaFree(rsa);
        OpensslRsaFree(pubKeyRsa);
        HcfFree(keyPairImpl);
        return res;
    }

    res = PackPriKey(rsa, &priKeyImpl);
    if (res != HCF_SUCCESS) {
        LOGE("pack pri key fail.");
        OpensslRsaFree(rsa);
        OpensslRsaFree(pubKeyRsa);
        HcfFree(keyPairImpl);
        HcfFree(pubKeyImpl);
        return res;
    }
    keyPairImpl->base.priKey = (HcfPriKey *)priKeyImpl;
    keyPairImpl->base.pubKey = (HcfPubKey *)pubKeyImpl;
    keyPairImpl->base.base.getClass = GetOpensslKeyPairClass;
    keyPairImpl->base.base.destroy = DestroyKeyPair;
    *keyPair = (HcfKeyPair *)keyPairImpl;
    LOGD("Generate keypair success.");
    return res;
}

static HcfResult GeneratePubKeyBySpec(const HcfAsyKeyParamsSpec *paramsSpec, HcfPubKey **pubKey)
{
    RSA *rsa = InitRsaStructByBin(paramsSpec);
    if (rsa == NULL) {
        LOGD("[error] Generate RSA fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    RSA *pubKeyRsa = NULL;
    if (DuplicateRsa(rsa, false, &pubKeyRsa) != HCF_SUCCESS) {
        LOGD("[error] Duplicate pubKey rsa fail");
        OpensslRsaFree(rsa);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfOpensslRsaPubKey *pubKeyImpl = NULL;
    HcfResult res = PackPubKey(pubKeyRsa, &pubKeyImpl);
    if (res != HCF_SUCCESS) {
        LOGD("[error] pack pup key fail.");
        OpensslRsaFree(rsa);
        OpensslRsaFree(pubKeyRsa);
        return res;
    }
    *pubKey = (HcfPubKey *)pubKeyImpl;
    OpensslRsaFree(rsa);
    LOGD("Generate pub key success.");
    return res;
}

static HcfResult GeneratePriKeyBySpec(const HcfAsyKeyParamsSpec *paramsSpec, HcfPriKey **priKey)
{
    RSA *rsa = InitRsaStructByBin(paramsSpec);
    if (rsa == NULL) {
        LOGD("[error] Generate RSA fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfOpensslRsaPriKey *priKeyImpl = NULL;
    HcfResult res = PackPriKey(rsa, &priKeyImpl);
    if (res != HCF_SUCCESS) {
        LOGD("[error] pack pri key fail.");
        OpensslRsaFree(rsa);
        return res;
    }
    *priKey = (HcfPriKey *)priKeyImpl;
    LOGD("Generate pri key success.");
    return res;
}

static HcfResult EngineGenerateKeyPairBySpec(const HcfAsyKeyGeneratorSpi *self,
    const HcfAsyKeyParamsSpec *paramsSpec, HcfKeyPair **returnKeyPair)
{
    if ((self == NULL) || (returnKeyPair == NULL) || (paramsSpec == NULL)) {
        LOGE("GenerateKeyPairBySpec Params is invalid.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_GENERATOR_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    if (strcmp(paramsSpec->algName, RSA_ALG_NAME) != 0) {
        LOGE("Spec alg not match.");
        return HCF_INVALID_PARAMS;
    }
    if (paramsSpec->specType != HCF_KEY_PAIR_SPEC) {
        LOGE("Spec type not match.");
        return HCF_INVALID_PARAMS;
    }
    return GenerateKeyPairBySpec(paramsSpec, returnKeyPair);
}

static HcfResult EngineGeneratePubKeyBySpec(const HcfAsyKeyGeneratorSpi *self,
    const HcfAsyKeyParamsSpec *paramsSpec, HcfPubKey **returnPubKey)
{
    if ((self == NULL) || (returnPubKey == NULL) || (paramsSpec == NULL)) {
        LOGE("GeneratePubKeyBySpec Params is invalid.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_GENERATOR_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    if (strcmp(paramsSpec->algName, RSA_ALG_NAME) != 0) {
        LOGE("Spec alg not match.");
        return HCF_INVALID_PARAMS;
    }
    if (paramsSpec->specType != HCF_PUBLIC_KEY_SPEC && paramsSpec->specType != HCF_KEY_PAIR_SPEC) {
        LOGE("Spec not match.");
        return HCF_INVALID_PARAMS;
    }
    return GeneratePubKeyBySpec(paramsSpec, returnPubKey);
}

static HcfResult EngineGeneratePriKeyBySpec(const HcfAsyKeyGeneratorSpi *self,
    const HcfAsyKeyParamsSpec *paramsSpec, HcfPriKey **returnPriKey)
{
    if ((self == NULL) || (returnPriKey == NULL) || (paramsSpec == NULL)) {
        LOGE("GeneratePriKeyBySpec Params is invalid.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_GENERATOR_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    if (strcmp(paramsSpec->algName, RSA_ALG_NAME) != 0) {
        LOGE("Spec alg not match.");
        return HCF_INVALID_PARAMS;
    }
    if (paramsSpec->specType != HCF_KEY_PAIR_SPEC) {
        LOGE("Spec not match.");
        return HCF_INVALID_PARAMS;
    }
    return GeneratePriKeyBySpec(paramsSpec, returnPriKey);
}

static HcfResult SetDefaultValue(HcfAsyKeyGenSpiRsaParams *params)
{
    if (params->primes == 0) {
        LOGD("set default primes 2");
        params->primes = OPENSSL_RSA_PRIMES_SIZE_2;
    }
    if (params->pubExp != NULL) {
        LOGE("RSA has pubKey default unexpectedly.");
        return HCF_SUCCESS;
    }
    BIGNUM *e = OpensslBnNew();
    if (e == NULL) {
        LOGD("[error] RSA new BN fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslBnSetWord(e, RSA_F4) != HCF_OPENSSL_SUCCESS) {
        LOGD("[error] RSA keygen Bn_set_word fail.");
        OpensslBnFree(e);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    params->pubExp = e;
    return HCF_SUCCESS;
}

static HcfResult DecodeParams(HcfAsyKeyGenParams *from, HcfAsyKeyGenSpiRsaParams **to)
{
    *to = (HcfAsyKeyGenSpiRsaParams *)HcfMalloc(sizeof(HcfAsyKeyGenSpiRsaParams), 0);
    if (*to == NULL) {
        LOGE("Malloc HcfAsyKeyGenSpiRsaParams fail");
        return HCF_ERR_MALLOC;
    }

    (*to)->bits = from->bits;
    (*to)->primes = from->primes;

    // set 2 as default primes, RSA_F4 as default pubExp
    if (SetDefaultValue(*to) != HCF_SUCCESS) {
        LOGE("Set default value fail.");
        HcfFree(*to);
        *to = NULL;
        return HCF_INVALID_PARAMS;
    }
    if (CheckRsaKeyGenParams(*to) != HCF_SUCCESS) {
        LOGE("Invalid keyGen params");
        HcfFree(*to);
        *to = NULL;
        return HCF_INVALID_PARAMS;
    }
    return HCF_SUCCESS;
}

HcfResult HcfAsyKeyGeneratorSpiRsaCreate(HcfAsyKeyGenParams *params, HcfAsyKeyGeneratorSpi **generator)
{
    if (params == NULL || generator == NULL) {
        LOGE("Invalid input, params is invalid or generator is null.");
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGeneratorSpiRsaOpensslImpl *impl = (HcfAsyKeyGeneratorSpiRsaOpensslImpl *)
        HcfMalloc(sizeof(HcfAsyKeyGeneratorSpiRsaOpensslImpl), 0);
    if (impl == NULL) {
        LOGE("Failed to allocate returnImpl memroy!");
        return HCF_ERR_MALLOC;
    }
    if (DecodeParams(params, &impl->params) != HCF_SUCCESS) {
        LOGE("Keygen params is invalid.");
        HcfFree(impl);
        return HCF_INVALID_PARAMS;
    }
    impl->base.base.getClass = GetKeyGeneratorClass;
    impl->base.base.destroy = DestroyKeyGeneratorSpiImpl;
    impl->base.engineGenerateKeyPair = EngineGenerateKeyPair;
    impl->base.engineConvertKey = EngineConvertKey;
    impl->base.engineConvertPemKey = EngineConvertPemKey;
    impl->base.engineGenerateKeyPairBySpec = EngineGenerateKeyPairBySpec;
    impl->base.engineGeneratePubKeyBySpec = EngineGeneratePubKeyBySpec;
    impl->base.engineGeneratePriKeyBySpec = EngineGeneratePriKeyBySpec;
    *generator = (HcfAsyKeyGeneratorSpi *)impl;
    return HCF_SUCCESS;
}

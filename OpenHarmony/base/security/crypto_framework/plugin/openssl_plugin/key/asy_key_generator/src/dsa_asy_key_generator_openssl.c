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

#include "dsa_asy_key_generator_openssl.h"

#include <openssl/dsa.h>
#include <openssl/evp.h>
#include <string.h>

#include "detailed_dsa_key_params.h"
#include "log.h"
#include "memory.h"
#include "openssl_adapter.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "utils.h"

#define OPENSSL_DSA_GENERATOR_CLASS "OPENSSL.DSA.KEYGENERATOR"
#define OPENSSL_DSA_PUBKEY_FORMAT "X.509"
#define OPENSSL_DSA_PRIKEY_FORMAT "PKCS#8"
#define ALGORITHM_NAME_DSA "DSA"

typedef struct {
    HcfAsyKeyGeneratorSpi base;

    int32_t bits;
} HcfAsyKeyGeneratorSpiDsaOpensslImpl;

static void FreeCtx(EVP_PKEY_CTX *paramsCtx, EVP_PKEY *paramsPkey, EVP_PKEY_CTX *pkeyCtx)
{
    if (paramsCtx != NULL) {
        OpensslEvpPkeyCtxFree(paramsCtx);
    }
    if (paramsPkey != NULL) {
        OpensslEvpPkeyFree(paramsPkey);
    }
    if (pkeyCtx != NULL) {
        OpensslEvpPkeyCtxFree(pkeyCtx);
    }
}

static void FreeCommSpecBn(BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    if (p != NULL) {
        OpensslBnFree(p);
    }
    if (q != NULL) {
        OpensslBnFree(q);
    }
    if (g != NULL) {
        OpensslBnFree(g);
    }
}

static const char *GetDsaKeyGeneratorSpiClass(void)
{
    return OPENSSL_DSA_GENERATOR_CLASS;
}

static const char *GetDsaKeyPairClass(void)
{
    return OPENSSL_DSA_KEYPAIR_CLASS;
}

static const char *GetDsaPubKeyClass(void)
{
    return OPENSSL_DSA_PUBKEY_CLASS;
}

static const char *GetDsaPriKeyClass(void)
{
    return OPENSSL_DSA_PRIKEY_CLASS;
}

static void DestroyDsaKeyGeneratorSpiImpl(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsClassMatch(self, GetDsaKeyGeneratorSpiClass())) {
        return;
    }
    HcfFree(self);
}

static void DestroyDsaPubKey(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsClassMatch(self, GetDsaPubKeyClass())) {
        return;
    }
    HcfOpensslDsaPubKey *impl = (HcfOpensslDsaPubKey *)self;
    OpensslDsaFree(impl->pk);
    impl->pk = NULL;
    HcfFree(impl);
}

static void DestroyDsaPriKey(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsClassMatch(self, GetDsaPriKeyClass())) {
        return;
    }
    HcfOpensslDsaPriKey *impl = (HcfOpensslDsaPriKey *)self;
    OpensslDsaFree(impl->sk);
    impl->sk = NULL;
    HcfFree(impl);
}

static void DestroyDsaKeyPair(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsClassMatch(self, GetDsaKeyPairClass())) {
        return;
    }
    HcfOpensslDsaKeyPair *impl = (HcfOpensslDsaKeyPair *)self;
    DestroyDsaPubKey((HcfObjectBase *)impl->base.pubKey);
    impl->base.pubKey = NULL;
    DestroyDsaPriKey((HcfObjectBase *)impl->base.priKey);
    impl->base.priKey = NULL;
    HcfFree(self);
}

static const char *GetDsaPubKeyAlgorithm(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetDsaPubKeyClass())) {
        return NULL;
    }
    return ALGORITHM_NAME_DSA;
}

static const char *GetDsaPriKeyAlgorithm(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetDsaPriKeyClass())) {
        return NULL;
    }
    return ALGORITHM_NAME_DSA;
}

static HcfResult GetDsaPubKeyEncoded(HcfKey *self, HcfBlob *returnBlob)
{
    if ((self == NULL) || (returnBlob == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetDsaPubKeyClass())) {
        return HCF_INVALID_PARAMS;
    }
    HcfOpensslDsaPubKey *impl = (HcfOpensslDsaPubKey *)self;
    unsigned char *returnData = NULL;
    int len = OpensslI2dDsaPubkey(impl->pk, &returnData);
    if (len <= 0) {
        LOGD("[error] Call i2d_DSA_PUBKEY failed");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->data = returnData;
    returnBlob->len = len;
    return HCF_SUCCESS;
}

static HcfResult GetDsaPubKeyEncodedPem(HcfKey *self, const char *format, char **returnString)
{
    (void)self;
    (void)format;
    (void)returnString;
    return HCF_INVALID_PARAMS;
}

static HcfResult GetDsaPriKeyEncoded(HcfKey *self, HcfBlob *returnBlob)
{
    if ((self == NULL) || (returnBlob == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetDsaPriKeyClass())) {
        return HCF_INVALID_PARAMS;
    }
    HcfOpensslDsaPriKey *impl = (HcfOpensslDsaPriKey *)self;
    unsigned char *returnData = NULL;
    int len = OpensslI2dDsaPrivateKey(impl->sk, &returnData);
    if (len <= 0) {
        LOGD("[error] Call i2d_DSAPrivateKey failed.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->data = returnData;
    returnBlob->len = len;
    return HCF_SUCCESS;
}

static HcfResult GetDsaPriKeyEncodedPem(HcfKey *self, const char *format, char **returnString)
{
    (void)self;
    (void)format;
    (void)returnString;
    return HCF_INVALID_PARAMS;
}

static const char *GetDsaPubKeyFormat(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetDsaPubKeyClass())) {
        return NULL;
    }
    return OPENSSL_DSA_PUBKEY_FORMAT;
}

static const char *GetDsaPriKeyFormat(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetDsaPriKeyClass())) {
        return NULL;
    }
    return OPENSSL_DSA_PRIKEY_FORMAT;
}

static HcfResult GetBigIntegerSpecFromDsaPubKey(const HcfPubKey *self, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    if (self ==  NULL || returnBigInteger == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetDsaPubKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = HCF_SUCCESS;
    HcfOpensslDsaPubKey *impl = (HcfOpensslDsaPubKey *)self;
    DSA *dsaPk = impl->pk;
    if (dsaPk == NULL) {
        return HCF_INVALID_PARAMS;
    }
    switch (item) {
        case DSA_P_BN:
            ret = BigNumToBigInteger(OpensslDsaGet0P(dsaPk), returnBigInteger);
            break;
        case DSA_Q_BN:
            ret = BigNumToBigInteger(OpensslDsaGet0Q(dsaPk), returnBigInteger);
            break;
        case DSA_G_BN:
            ret = BigNumToBigInteger(OpensslDsaGet0G(dsaPk), returnBigInteger);
            break;
        case DSA_PK_BN:
            ret = BigNumToBigInteger(OpensslDsaGet0PubKey(dsaPk), returnBigInteger);
            break;
        default:
            LOGE("Input item is invalid");
            ret = HCF_INVALID_PARAMS;
            break;
    }
    return ret;
}

static HcfResult GetBigIntegerSpecFromDsaPriKey(const HcfPriKey *self, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    if (self ==  NULL || returnBigInteger == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetDsaPriKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = HCF_SUCCESS;
    HcfOpensslDsaPriKey *impl = (HcfOpensslDsaPriKey *)self;
    DSA *dsaSk = impl->sk;
    if (dsaSk == NULL) {
        return HCF_INVALID_PARAMS;
    }
    switch (item) {
        case DSA_P_BN:
            ret = BigNumToBigInteger(OpensslDsaGet0P(dsaSk), returnBigInteger);
            break;
        case DSA_Q_BN:
            ret = BigNumToBigInteger(OpensslDsaGet0Q(dsaSk), returnBigInteger);
            break;
        case DSA_G_BN:
            ret = BigNumToBigInteger(OpensslDsaGet0G(dsaSk), returnBigInteger);
            break;
        case DSA_SK_BN:
            ret = BigNumToBigInteger(OpensslDsaGet0PrivKey(dsaSk), returnBigInteger);
            break;
        default:
            LOGE("Input item is invalid");
            ret = HCF_INVALID_PARAMS;
            break;
    }
    return ret;
}

static HcfResult GetIntSpecFromDsaPubKey(const HcfPubKey *self, const AsyKeySpecItem item, int *returnInt)
{
    (void)self;
    (void)returnInt;
    return HCF_NOT_SUPPORT;
}

static HcfResult GetIntSpecFromDsaPriKey(const HcfPriKey *self, const AsyKeySpecItem item, int *returnInt)
{
    (void)self;
    (void)returnInt;
    return HCF_NOT_SUPPORT;
}

static HcfResult GetStrSpecFromDsaPubKey(const HcfPubKey *self, const AsyKeySpecItem item, char **returnString)
{
    (void)self;
    (void)returnString;
    return HCF_NOT_SUPPORT;
}

static HcfResult GetStrSpecFromDsaPriKey(const HcfPriKey *self, const AsyKeySpecItem item, char **returnString)
{
    (void)self;
    (void)returnString;
    return HCF_NOT_SUPPORT;
}

static void ClearDsaPriKeyMem(HcfPriKey *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetDsaPriKeyClass())) {
        return;
    }
    HcfOpensslDsaPriKey *impl = (HcfOpensslDsaPriKey *)self;
    OpensslDsaFree(impl->sk);
    impl->sk = NULL;
}

static HcfResult GetDsaPriKeyEncodedDer(const HcfPriKey *self, const char *format, HcfBlob *returnBlob)
{
    (void)self;
    (void)format;
    (void)returnBlob;
    return HCF_INVALID_PARAMS;
}

static HcfResult GenerateDsaEvpKey(int32_t keyLen, EVP_PKEY **ppkey)
{
    EVP_PKEY_CTX *paramsCtx = NULL;
    EVP_PKEY *paramsPkey = NULL;
    EVP_PKEY_CTX *pkeyCtx = NULL;
    HcfResult ret = HCF_SUCCESS;
    do {
        paramsCtx = OpensslEvpPkeyCtxNewId(EVP_PKEY_DSA, NULL);
        if (paramsCtx == NULL) {
            LOGE("Create params ctx failed.");
            ret = HCF_ERR_MALLOC;
            break;
        }
        if (OpensslEvpPkeyParamGenInit(paramsCtx) != HCF_OPENSSL_SUCCESS) {
            LOGD("[error] Params ctx generate init failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        if (OpensslEvpPkeyCtxSetDsaParamgenBits(paramsCtx, keyLen) <= 0) {
            LOGD("[error] Set length of bits to params ctx failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        if (OpensslEvpPkeyParamGen(paramsCtx, &paramsPkey) != HCF_OPENSSL_SUCCESS) {
            LOGD("[error] Generate params pkey failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        pkeyCtx = OpensslEvpPkeyCtxNew(paramsPkey, NULL);
        if (pkeyCtx == NULL) {
            LOGD("[error] Create pkey ctx failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        if (OpensslEvpPkeyKeyGenInit(pkeyCtx) != HCF_OPENSSL_SUCCESS) {
            LOGD("[error] Key ctx generate init failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        if (OpensslEvpPkeyKeyGen(pkeyCtx, ppkey) != HCF_OPENSSL_SUCCESS) {
            LOGD("[error] Generate pkey failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
    } while (0);
    FreeCtx(paramsCtx, paramsPkey, pkeyCtx);
    return ret;
}

static HcfResult GetDsaPubKeyEncodedDer(const HcfPubKey *self, const char *format, HcfBlob *returnBlob)
{
    (void)self;
    (void)format;
    (void)returnBlob;
    return HCF_INVALID_PARAMS;
}

static void FillOpensslDsaPubKeyFunc(HcfOpensslDsaPubKey *pk)
{
    pk->base.base.base.destroy = DestroyDsaPubKey;
    pk->base.base.base.getClass = GetDsaPubKeyClass;
    pk->base.base.getAlgorithm = GetDsaPubKeyAlgorithm;
    pk->base.base.getEncoded = GetDsaPubKeyEncoded;
    pk->base.base.getEncodedPem = GetDsaPubKeyEncodedPem;
    pk->base.base.getFormat = GetDsaPubKeyFormat;
    pk->base.getAsyKeySpecBigInteger = GetBigIntegerSpecFromDsaPubKey;
    pk->base.getAsyKeySpecInt = GetIntSpecFromDsaPubKey;
    pk->base.getAsyKeySpecString = GetStrSpecFromDsaPubKey;
    pk->base.getEncodedDer = GetDsaPubKeyEncodedDer;
}

static void FillOpensslDsaPriKeyFunc(HcfOpensslDsaPriKey *sk)
{
    sk->base.base.base.destroy = DestroyDsaPriKey;
    sk->base.base.base.getClass = GetDsaPriKeyClass;
    sk->base.base.getAlgorithm = GetDsaPriKeyAlgorithm;
    sk->base.base.getEncoded = GetDsaPriKeyEncoded;
    sk->base.base.getEncodedPem = GetDsaPriKeyEncodedPem;
    sk->base.base.getFormat = GetDsaPriKeyFormat;
    sk->base.getAsyKeySpecBigInteger = GetBigIntegerSpecFromDsaPriKey;
    sk->base.getAsyKeySpecInt = GetIntSpecFromDsaPriKey;
    sk->base.getAsyKeySpecString = GetStrSpecFromDsaPriKey;
    sk->base.clearMem = ClearDsaPriKeyMem;
    sk->base.getEncodedDer = GetDsaPriKeyEncodedDer;
}

static HcfResult CreateDsaPubKey(DSA *pk, HcfOpensslDsaPubKey **returnPubKey)
{
    HcfOpensslDsaPubKey *dsaPubKey = (HcfOpensslDsaPubKey *)HcfMalloc(sizeof(HcfOpensslDsaPubKey), 0);
    if (dsaPubKey == NULL) {
        LOGE("Failed to allocate DSA public key memory.");
        return HCF_ERR_MALLOC;
    }
    FillOpensslDsaPubKeyFunc(dsaPubKey);
    dsaPubKey->pk = pk;

    *returnPubKey = dsaPubKey;
    return HCF_SUCCESS;
}

static HcfResult CreateDsaPriKey(DSA *sk, HcfOpensslDsaPriKey **returnPriKey)
{
    HcfOpensslDsaPriKey *dsaPriKey = (HcfOpensslDsaPriKey *)HcfMalloc(sizeof(HcfOpensslDsaPriKey), 0);
    if (dsaPriKey == NULL) {
        LOGE("Failed to allocate DSA private key memory.");
        return HCF_ERR_MALLOC;
    }
    FillOpensslDsaPriKeyFunc(dsaPriKey);
    dsaPriKey->sk = sk;

    *returnPriKey = dsaPriKey;
    return HCF_SUCCESS;
}

static HcfResult CreateDsaKeyPair(const HcfOpensslDsaPubKey *pubKey, const HcfOpensslDsaPriKey *priKey,
    HcfKeyPair **returnKeyPair)
{
    HcfOpensslDsaKeyPair *keyPair = (HcfOpensslDsaKeyPair *)HcfMalloc(sizeof(HcfOpensslDsaKeyPair), 0);
    if (keyPair == NULL) {
        LOGE("Failed to allocate keyPair memory.");
        return HCF_ERR_MALLOC;
    }
    keyPair->base.base.getClass = GetDsaKeyPairClass;
    keyPair->base.base.destroy = DestroyDsaKeyPair;
    keyPair->base.pubKey = (HcfPubKey *)pubKey;
    keyPair->base.priKey = (HcfPriKey *)priKey;

    *returnKeyPair = (HcfKeyPair *)keyPair;
    return HCF_SUCCESS;
}

static HcfResult GeneratePubKeyByPkey(EVP_PKEY *pkey, HcfOpensslDsaPubKey **returnPubKey)
{
    DSA *pk = OpensslEvpPkeyGet1Dsa(pkey);
    if (pk == NULL) {
        LOGD("[error] Get das public key from pkey failed");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = CreateDsaPubKey(pk, returnPubKey);
    if (ret != HCF_SUCCESS) {
        LOGD("[error] Create DSA public key failed");
        OpensslDsaFree(pk);
    }
    return ret;
}

static HcfResult GeneratePriKeyByPkey(EVP_PKEY *pkey, HcfOpensslDsaPriKey **returnPriKey)
{
    DSA *sk = OpensslEvpPkeyGet1Dsa(pkey);
    if (sk == NULL) {
        LOGD("[error] Get DSA private key from pkey failed");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = CreateDsaPriKey(sk, returnPriKey);
    if (ret != HCF_SUCCESS) {
        LOGD("[error] Create DSA private key failed");
        OpensslDsaFree(sk);
    }
    return ret;
}

static HcfResult GenerateDsaPubAndPriKey(int32_t keyLen, HcfOpensslDsaPubKey **returnPubKey,
    HcfOpensslDsaPriKey **returnPriKey)
{
    EVP_PKEY *pkey = NULL;
    HcfResult ret = GenerateDsaEvpKey(keyLen, &pkey);
    if (ret != HCF_SUCCESS) {
        LOGD("[error] Generate DSA EVP_PKEY failed.");
        return ret;
    }

    ret = GeneratePubKeyByPkey(pkey, returnPubKey);
    if (ret != HCF_SUCCESS) {
        OpensslEvpPkeyFree(pkey);
        return ret;
    }

    ret = GeneratePriKeyByPkey(pkey, returnPriKey);
    if (ret != HCF_SUCCESS) {
        HcfObjDestroy(*returnPubKey);
        *returnPubKey = NULL;
        OpensslEvpPkeyFree(pkey);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    OpensslEvpPkeyFree(pkey);
    return ret;
}

static HcfResult ConvertCommSpec2Bn(const HcfDsaCommParamsSpec *paramsSpec, BIGNUM **p, BIGNUM **q, BIGNUM **g)
{
    if (BigIntegerToBigNum(&(paramsSpec->p), p) != HCF_SUCCESS) {
        LOGD("[error] Get openssl BN p failed");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (BigIntegerToBigNum(&(paramsSpec->q), q) != HCF_SUCCESS)  {
        LOGD("[error] Get openssl BN q failed");
        OpensslBnFree(*p);
        *p = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (BigIntegerToBigNum(&(paramsSpec->g), g) != HCF_SUCCESS) {
        LOGD("[error] Get openssl BN g failed");
        OpensslBnFree(*p);
        *p = NULL;
        OpensslBnFree(*q);
        *q = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult CreateOpensslDsaKey(const HcfDsaCommParamsSpec *paramsSpec, BIGNUM *pk, BIGNUM *sk, DSA **returnDsa)
{
    BIGNUM *p = NULL;
    BIGNUM *q = NULL;
    BIGNUM *g = NULL;
    if (ConvertCommSpec2Bn(paramsSpec, &p, &q, &g)!= HCF_SUCCESS) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    DSA *dsa = OpensslDsaNew();
    if (dsa == NULL) {
        FreeCommSpecBn(p, q, g);
        LOGD("[error] Openssl DSA new failed");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslDsaSet0Pqg(dsa, p, q, g) != HCF_OPENSSL_SUCCESS) {
        LOGD("[error] Openssl DSA set pqg failed");
        FreeCommSpecBn(p, q, g);
        HcfPrintOpensslError();
        OpensslDsaFree(dsa);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if ((pk == NULL) && (sk == NULL)) {
        *returnDsa = dsa;
        return HCF_SUCCESS;
    }
    if (OpensslDsaSet0Key(dsa, pk, sk) != HCF_OPENSSL_SUCCESS) {
        LOGD("[error] Openssl DSA set pqg failed");
        HcfPrintOpensslError();
        OpensslDsaFree(dsa);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *returnDsa = dsa;
    return HCF_SUCCESS;
}

static HcfResult GenerateOpensslDsaKeyByCommSpec(const HcfDsaCommParamsSpec *paramsSpec, DSA **returnDsa)
{
    if (CreateOpensslDsaKey(paramsSpec, NULL, NULL, returnDsa) != HCF_SUCCESS) {
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (OpensslDsaGenerateKey(*returnDsa) != HCF_OPENSSL_SUCCESS) {
        LOGD("[error] Openssl DSA generate key failed");
        HcfPrintOpensslError();
        OpensslDsaFree(*returnDsa);
        *returnDsa = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult GenerateOpensslDsaKeyByPubKeySpec(const HcfDsaPubKeyParamsSpec *paramsSpec, DSA **returnDsa)
{
    BIGNUM *pubKey = NULL;
    if (BigIntegerToBigNum(&(paramsSpec->pk), &pubKey) != HCF_SUCCESS) {
        LOGD("[error] Get openssl BN pk failed");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (CreateOpensslDsaKey(&(paramsSpec->base), pubKey, NULL, returnDsa) != HCF_SUCCESS) {
        OpensslBnFree(pubKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult GenerateOpensslDsaKeyByKeyPairSpec(const HcfDsaKeyPairParamsSpec *paramsSpec, DSA **returnDsa)
{
    BIGNUM *pubKey = NULL;
    BIGNUM *priKey = NULL;
    if (BigIntegerToBigNum(&(paramsSpec->pk), &pubKey) != HCF_SUCCESS) {
        LOGD("[error] Get openssl BN pk failed");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (BigIntegerToBigNum(&(paramsSpec->sk), &priKey) != HCF_SUCCESS) {
        LOGD("[error] Get openssl BN sk failed");
        OpensslBnFree(pubKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (CreateOpensslDsaKey(&(paramsSpec->base), pubKey, priKey, returnDsa) != HCF_SUCCESS) {
        OpensslBnFree(pubKey);
        OpensslBnFree(priKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult CreateDsaKeyPairByCommSpec(const HcfDsaCommParamsSpec *paramsSpec, HcfKeyPair **returnKeyPair)
{
    DSA *dsa = NULL;
    if (GenerateOpensslDsaKeyByCommSpec(paramsSpec, &dsa) != HCF_SUCCESS) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfOpensslDsaPubKey *pubKey = NULL;
    if (CreateDsaPubKey(dsa, &pubKey) != HCF_SUCCESS) {
        OpensslDsaFree(dsa);
        return HCF_ERR_MALLOC;
    }

    if (OpensslDsaUpRef(dsa) != HCF_OPENSSL_SUCCESS) {
        LOGE("Dup DSA failed.");
        HcfPrintOpensslError();
        HcfObjDestroy(pubKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    HcfOpensslDsaPriKey *priKey = NULL;
    if (CreateDsaPriKey(dsa, &priKey) != HCF_SUCCESS) {
        OpensslDsaFree(dsa);
        HcfObjDestroy(pubKey);
        return HCF_ERR_MALLOC;
    }

    if (CreateDsaKeyPair(pubKey, priKey, returnKeyPair) != HCF_SUCCESS) {
        HcfObjDestroy(pubKey);
        HcfObjDestroy(priKey);
        return HCF_ERR_MALLOC;
    }
    return HCF_SUCCESS;
}

static HcfResult CreateDsaPubKeyByKeyPairSpec(const HcfDsaKeyPairParamsSpec *paramsSpec,
    HcfOpensslDsaPubKey **returnPubKey)
{
    DSA *dsa = NULL;
    if (GenerateOpensslDsaKeyByKeyPairSpec(paramsSpec, &dsa) != HCF_SUCCESS) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (CreateDsaPubKey(dsa, returnPubKey) != HCF_SUCCESS) {
        OpensslDsaFree(dsa);
        return HCF_ERR_MALLOC;
    }
    return HCF_SUCCESS;
}

static HcfResult CreateDsaPriKeyByKeyPairSpec(const HcfDsaKeyPairParamsSpec *paramsSpec,
    HcfOpensslDsaPriKey **returnPriKey)
{
    DSA *dsa = NULL;
    if (GenerateOpensslDsaKeyByKeyPairSpec(paramsSpec, &dsa) != HCF_SUCCESS) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (CreateDsaPriKey(dsa, returnPriKey) != HCF_SUCCESS) {
        OpensslDsaFree(dsa);
        return HCF_ERR_MALLOC;
    }
    return HCF_SUCCESS;
}

static HcfResult CreateDsaKeyPairByKeyPairSpec(const HcfDsaKeyPairParamsSpec *paramsSpec, HcfKeyPair **returnKeyPair)
{
    HcfOpensslDsaPubKey *pubKey = NULL;
    HcfResult ret = CreateDsaPubKeyByKeyPairSpec(paramsSpec, &pubKey);
    if (ret != HCF_SUCCESS) {
        return ret;
    }

    HcfOpensslDsaPriKey *priKey = NULL;
    ret = CreateDsaPriKeyByKeyPairSpec(paramsSpec, &priKey);
    if (ret != HCF_SUCCESS) {
        HcfObjDestroy(pubKey);
        return ret;
    }
    ret = CreateDsaKeyPair(pubKey, priKey, returnKeyPair);
    if (ret != HCF_SUCCESS) {
        HcfObjDestroy(pubKey);
        HcfObjDestroy(priKey);
        return ret;
    }
    return HCF_SUCCESS;
}

static HcfResult CreateDsaKeyPairBySpec(const HcfAsyKeyParamsSpec *paramsSpec, HcfKeyPair **returnKeyPair)
{
    if (paramsSpec->specType == HCF_COMMON_PARAMS_SPEC) {
        return CreateDsaKeyPairByCommSpec((const HcfDsaCommParamsSpec *)paramsSpec, returnKeyPair);
    } else {
        return CreateDsaKeyPairByKeyPairSpec((const HcfDsaKeyPairParamsSpec *)paramsSpec, returnKeyPair);
    }
}

static HcfResult CreateDsaPubKeyByPubKeySpec(const HcfDsaPubKeyParamsSpec *paramsSpec, HcfPubKey **returnPubKey)
{
    DSA *dsa = NULL;
    if (GenerateOpensslDsaKeyByPubKeySpec(paramsSpec, &dsa) != HCF_SUCCESS) {
        return HCF_ERR_CRYPTO_OPERATION;
    }

    HcfOpensslDsaPubKey *pubKey = NULL;
    if (CreateDsaPubKey(dsa, &pubKey) != HCF_SUCCESS) {
        OpensslDsaFree(dsa);
        return HCF_ERR_MALLOC;
    }
    *returnPubKey = (HcfPubKey *)pubKey;
    return HCF_SUCCESS;
}

static HcfResult ConvertDsaPubKey(const HcfBlob *pubKeyBlob, HcfOpensslDsaPubKey **returnPubKey)
{
    const unsigned char *tmpData = (const unsigned char *)(pubKeyBlob->data);
    DSA *dsa = OpensslD2iDsaPubKey(NULL, &tmpData, pubKeyBlob->len);
    if (dsa == NULL) {
        LOGD("[error] D2i_DSA_PUBKEY fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = CreateDsaPubKey(dsa, returnPubKey);
    if (ret != HCF_SUCCESS) {
        LOGD("[error] Create DSA public key failed");
        OpensslDsaFree(dsa);
    }
    return ret;
}

static HcfResult ConvertDsaPriKey(const HcfBlob *priKeyBlob, HcfOpensslDsaPriKey **returnPriKey)
{
    const unsigned char *tmpData = (const unsigned char *)(priKeyBlob->data);
    DSA *dsa = OpensslD2iDsaPrivateKey(NULL, &tmpData, priKeyBlob->len);
    if (dsa == NULL) {
        LOGD("[error] D2i_DSADSAPrivateKey fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = CreateDsaPriKey(dsa, returnPriKey);
    if (ret != HCF_SUCCESS) {
        LOGD("[error] Create DSA private key failed");
        OpensslDsaFree(dsa);
    }
    return ret;
}

static HcfResult ConvertDsaPubAndPriKey(const HcfBlob *pubKeyBlob, const HcfBlob *priKeyBlob,
    HcfOpensslDsaPubKey **returnPubKey, HcfOpensslDsaPriKey **returnPriKey)
{
    if (pubKeyBlob != NULL) {
        if (ConvertDsaPubKey(pubKeyBlob, returnPubKey) != HCF_SUCCESS) {
            LOGD("[error] Convert DSA public key failed.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    if (priKeyBlob != NULL) {
        if (ConvertDsaPriKey(priKeyBlob, returnPriKey) != HCF_SUCCESS) {
            LOGD("[error] Convert DSA private key failed.");
            HcfObjDestroy(*returnPubKey);
            *returnPubKey = NULL;
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    return HCF_SUCCESS;
}

static HcfResult EngineGenerateDsaKeyPair(HcfAsyKeyGeneratorSpi *self, HcfKeyPair **returnKeyPair)
{
    if (self == NULL || returnKeyPair == NULL) {
        LOGE("Invalid params.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetDsaKeyGeneratorSpiClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGeneratorSpiDsaOpensslImpl *impl = (HcfAsyKeyGeneratorSpiDsaOpensslImpl *)self;

    HcfOpensslDsaPubKey *pubKey = NULL;
    HcfOpensslDsaPriKey *priKey = NULL;
    HcfResult ret = GenerateDsaPubAndPriKey(impl->bits, &pubKey, &priKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Generate DSA pk and sk by openssl failed.");
        return ret;
    }

    ret = CreateDsaKeyPair(pubKey, priKey, returnKeyPair);
    if (ret != HCF_SUCCESS) {
        HcfObjDestroy(pubKey);
        HcfObjDestroy(priKey);
        return ret;
    }
    return HCF_SUCCESS;
}

static HcfResult EngineConvertDsaKey(HcfAsyKeyGeneratorSpi *self, HcfParamsSpec *params, HcfBlob *pubKeyBlob,
    HcfBlob *priKeyBlob, HcfKeyPair **returnKeyPair)
{
    (void)params;
    if ((self == NULL) || (returnKeyPair == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetDsaKeyGeneratorSpiClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    bool pubKeyValid = IsBlobValid(pubKeyBlob);
    bool priKeyValid = IsBlobValid(priKeyBlob);
    if ((!pubKeyValid) && (!priKeyValid)) {
        LOGE("The private key and public key cannot both be NULL.");
        return HCF_INVALID_PARAMS;
    }

    HcfOpensslDsaPubKey *pubKey = NULL;
    HcfOpensslDsaPriKey *priKey = NULL;
    HcfBlob *inputPk = pubKeyValid ? pubKeyBlob : NULL;
    HcfBlob *inputSk = priKeyValid ? priKeyBlob : NULL;
    HcfResult ret = ConvertDsaPubAndPriKey(inputPk, inputSk, &pubKey, &priKey);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    ret = CreateDsaKeyPair(pubKey, priKey, returnKeyPair);
    if (ret != HCF_SUCCESS) {
        HcfObjDestroy(pubKey);
        HcfObjDestroy(priKey);
    }
    return ret;
}

static HcfResult EngineGenerateDsaKeyPairBySpec(const HcfAsyKeyGeneratorSpi *self,
    const HcfAsyKeyParamsSpec *paramsSpec, HcfKeyPair **returnKeyPair)
{
    if ((self == NULL) || (paramsSpec == NULL) || (returnKeyPair == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    if (!IsClassMatch((HcfObjectBase *)self, GetDsaKeyGeneratorSpiClass())) {
        return HCF_INVALID_PARAMS;
    }

    if ((strcmp(paramsSpec->algName, ALGORITHM_NAME_DSA) != 0) ||
        ((paramsSpec->specType != HCF_COMMON_PARAMS_SPEC) && (paramsSpec->specType != HCF_KEY_PAIR_SPEC))) {
        LOGE("Invalid params spec.");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = CreateDsaKeyPairBySpec(paramsSpec, returnKeyPair);
    if (ret != HCF_SUCCESS) {
        LOGE("Create DSA key pair by spec failed.");
    }
    return ret;
}

static HcfResult EngineGenerateDsaPubKeyBySpec(const HcfAsyKeyGeneratorSpi *self,
    const HcfAsyKeyParamsSpec *paramsSpec, HcfPubKey **returnPubKey)
{
    if ((self == NULL) || (paramsSpec == NULL) || (returnPubKey == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    if (!IsClassMatch((HcfObjectBase *)self, GetDsaKeyGeneratorSpiClass())) {
        return HCF_INVALID_PARAMS;
    }

    if ((strcmp(paramsSpec->algName, ALGORITHM_NAME_DSA) != 0) ||
        ((paramsSpec->specType != HCF_PUBLIC_KEY_SPEC) && (paramsSpec->specType != HCF_KEY_PAIR_SPEC))) {
        LOGE("Invalid params spec.");
        return HCF_INVALID_PARAMS;
    }

    HcfResult ret = CreateDsaPubKeyByPubKeySpec((const HcfDsaPubKeyParamsSpec *)paramsSpec, returnPubKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Create DSA public key by spec failed.");
    }
    return ret;
}

static HcfResult EngineGenerateDsaPriKeyBySpec(const HcfAsyKeyGeneratorSpi *self,
    const HcfAsyKeyParamsSpec *paramsSpec, HcfPriKey **returnPriKey)
{
    if ((self == NULL) || (paramsSpec == NULL) || (returnPriKey == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetDsaKeyGeneratorSpiClass())) {
        return HCF_INVALID_PARAMS;
    }
    if ((strcmp(paramsSpec->algName, ALGORITHM_NAME_DSA) != 0) || (paramsSpec->specType != HCF_KEY_PAIR_SPEC)) {
        LOGE("Invalid params spec.");
        return HCF_INVALID_PARAMS;
    }

    HcfOpensslDsaPriKey *dsaSk = NULL;
    HcfResult ret = CreateDsaPriKeyByKeyPairSpec((const HcfDsaKeyPairParamsSpec *)paramsSpec, &dsaSk);
    if (ret != HCF_SUCCESS) {
        LOGE("Create DSA private key by spec failed.");
    } else {
        *returnPriKey = (HcfPriKey *)dsaSk;
    }
    return ret;
}

HcfResult HcfAsyKeyGeneratorSpiDsaCreate(HcfAsyKeyGenParams *params, HcfAsyKeyGeneratorSpi **returnSpi)
{
    if (params == NULL || returnSpi == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGeneratorSpiDsaOpensslImpl *impl = (HcfAsyKeyGeneratorSpiDsaOpensslImpl *)HcfMalloc(
        sizeof(HcfAsyKeyGeneratorSpiDsaOpensslImpl), 0);
    if (impl == NULL) {
        LOGE("Failed to allocate generator impl memroy.");
        return HCF_ERR_MALLOC;
    }
    impl->bits = params->bits;
    impl->base.base.getClass = GetDsaKeyGeneratorSpiClass;
    impl->base.base.destroy = DestroyDsaKeyGeneratorSpiImpl;
    impl->base.engineGenerateKeyPair = EngineGenerateDsaKeyPair;
    impl->base.engineConvertKey = EngineConvertDsaKey;
    impl->base.engineGenerateKeyPairBySpec = EngineGenerateDsaKeyPairBySpec;
    impl->base.engineGeneratePubKeyBySpec = EngineGenerateDsaPubKeyBySpec;
    impl->base.engineGeneratePriKeyBySpec = EngineGenerateDsaPriKeyBySpec;

    *returnSpi = (HcfAsyKeyGeneratorSpi *)impl;
    return HCF_SUCCESS;
}
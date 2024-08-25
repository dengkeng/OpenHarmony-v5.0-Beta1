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

#include "dh_asy_key_generator_openssl.h"
#include <string.h>

#include "dh_openssl_common.h"
#include "detailed_dh_key_params.h"
#include "log.h"
#include "memory.h"
#include "openssl_adapter.h"
#include "openssl_class.h"
#include "openssl_common.h"

#define OPENSSL_DH_GENERATOR_CLASS "OPENSSL.DH.KEYGENERATOR"
#define OPENSSL_DH_PUBKEY_FORMAT "X.509"
#define OPENSSL_DH_PRIKEY_FORMAT "PKCS#8"
#define ALGORITHM_NAME_DH "DH"
#define PARAMS_NUM_TWO 2
#define BIT8 8

typedef struct {
    HcfAsyKeyGeneratorSpi base;

    int32_t pBits;
} HcfAsyKeyGeneratorSpiDhOpensslImpl;

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

static void FreeCommSpecBn(BIGNUM *p, BIGNUM *g)
{
    if (p != NULL) {
        OpensslBnFree(p);
    }
    if (g != NULL) {
        OpensslBnFree(g);
    }
}

static const char *GetDhKeyGeneratorSpiClass(void)
{
    return OPENSSL_DH_GENERATOR_CLASS;
}

static const char *GetDhKeyPairClass(void)
{
    return OPENSSL_DH_KEYPAIR_CLASS;
}

static const char *GetDhPubKeyClass(void)
{
    return OPENSSL_DH_PUBKEY_CLASS;
}

static const char *GetDhPriKeyClass(void)
{
    return OPENSSL_DH_PRIKEY_CLASS;
}

static void DestroyDhKeyGeneratorSpiImpl(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Class is null.");
        return;
    }
    if (!IsClassMatch(self, GetDhKeyGeneratorSpiClass())) {
        LOGE("Class not match.");
        return;
    }
    HcfFree(self);
}

static void DestroyDhPubKey(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Class is null.");
        return;
    }
    if (!IsClassMatch(self, GetDhPubKeyClass())) {
        LOGE("Class not match.");
        return;
    }
    HcfOpensslDhPubKey *impl = (HcfOpensslDhPubKey *)self;
    OpensslDhFree(impl->pk);
    impl->pk = NULL;
    HcfFree(impl);
}

static void DestroyDhPriKey(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Class is null.");
        return;
    }
    if (!IsClassMatch(self, GetDhPriKeyClass())) {
        LOGE("Class not match.");
        return;
    }
    HcfOpensslDhPriKey *impl = (HcfOpensslDhPriKey *)self;
    OpensslDhFree(impl->sk);
    impl->sk = NULL;
    HcfFree(impl);
}

static void DestroyDhKeyPair(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Class is null.");
        return;
    }
    if (!IsClassMatch(self, GetDhKeyPairClass())) {
        LOGE("Class not match.");
        return;
    }
    HcfOpensslDhKeyPair *impl = (HcfOpensslDhKeyPair *)self;
    DestroyDhPubKey((HcfObjectBase *)impl->base.pubKey);
    impl->base.pubKey = NULL;
    DestroyDhPriKey((HcfObjectBase *)impl->base.priKey);
    impl->base.priKey = NULL;
    HcfFree(self);
}

static const char *GetDhPubKeyAlgorithm(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetDhPubKeyClass())) {
        LOGE("Class not match.");
        return NULL;
    }
    return ALGORITHM_NAME_DH;
}

static const char *GetDhPriKeyAlgorithm(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetDhPriKeyClass())) {
        LOGE("Class not match.");
        return NULL;
    }
    return ALGORITHM_NAME_DH;
}

static HcfResult GetDhPubKeyEncoded(HcfKey *self, HcfBlob *returnBlob)
{
    if ((self == NULL) || (returnBlob == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetDhPubKeyClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfOpensslDhPubKey *impl = (HcfOpensslDhPubKey *)self;
    unsigned char *returnData = NULL;
    EVP_PKEY *pKey = NewEvpPkeyByDh(impl->pk, true);
    if (pKey == NULL) {
        LOGD("[error] New pKey by dh fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int len = OpensslI2dPubKey(pKey, &returnData);
    if (len <= 0) {
        LOGD("[error] Call i2d_PUBKEY failed");
        HcfPrintOpensslError();
        OpensslEvpPkeyFree(pKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->data = returnData;
    returnBlob->len = len;
    OpensslEvpPkeyFree(pKey);
    return HCF_SUCCESS;
}

static HcfResult GetDhPubKeyEncodedPem(HcfKey *self, const char *format, char **returnString)
{
    (void)self;
    (void)format;
    (void)returnString;
    return HCF_INVALID_PARAMS;
}

static HcfResult GetDhPriKeyEncoded(HcfKey *self, HcfBlob *returnBlob)
{
    if ((self == NULL) || (returnBlob == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetDhPriKeyClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfOpensslDhPriKey *impl = (HcfOpensslDhPriKey *)self;
    unsigned char *returnData = NULL;
    EVP_PKEY *pKey = NewEvpPkeyByDh(impl->sk, true);
    if (pKey == NULL) {
        LOGD("[error] New pKey by dh fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int len = OpensslI2dPrivateKey(pKey, &returnData);
    if (len <= 0) {
        LOGD("[error] Call i2d_PrivateKey failed.");
        HcfPrintOpensslError();
        OpensslEvpPkeyFree(pKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->data = returnData;
    returnBlob->len = len;
    OpensslEvpPkeyFree(pKey);
    return HCF_SUCCESS;
}

static HcfResult GetDhPriKeyEncodedPem(HcfKey *self, const char *format, char **returnString)
{
    (void)self;
    (void)format;
    (void)returnString;
    return HCF_INVALID_PARAMS;
}

static const char *GetDhPubKeyFormat(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetDhPubKeyClass())) {
        LOGE("Class not match.");
        return NULL;
    }
    return OPENSSL_DH_PUBKEY_FORMAT;
}

static const char *GetDhPriKeyFormat(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetDhPriKeyClass())) {
        LOGE("Class not match.");
        return NULL;
    }
    return OPENSSL_DH_PRIKEY_FORMAT;
}

static HcfResult GetBigIntegerSpec(const HcfPubKey *pubSelf, const HcfPriKey *priSelf, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    DH *dh = NULL;
    if (pubSelf != NULL) {
        if (item == DH_SK_BN) {
            LOGE("Invalid item.");
            return HCF_INVALID_PARAMS;
        }
        HcfOpensslDhPubKey *impl = (HcfOpensslDhPubKey *)pubSelf;
        dh = impl->pk;
    } else {
        if (item == DH_PK_BN) {
            LOGE("Invalid item.");
            return HCF_INVALID_PARAMS;
        }
        HcfOpensslDhPriKey *impl = (HcfOpensslDhPriKey *)priSelf;
        dh = impl->sk;
    }
    if (dh == NULL) {
        LOGE("Dh is null.");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = HCF_SUCCESS;
    switch (item) {
        case DH_P_BN:
            ret = BigNumToBigInteger(OpensslDhGet0P(dh), returnBigInteger);
            break;
        case DH_G_BN:
            ret = BigNumToBigInteger(OpensslDhGet0G(dh), returnBigInteger);
            break;
        case DH_PK_BN:
            ret = BigNumToBigInteger(OpensslDhGet0PubKey(dh), returnBigInteger);
            break;
        case DH_SK_BN:
            ret = BigNumToBigInteger(OpensslDhGet0PrivKey(dh), returnBigInteger);
            break;
        default:
            LOGE("Input item [%d] is invalid", item);
            ret = HCF_INVALID_PARAMS;
            break;
    }
    return ret;
}

static HcfResult GetBigIntegerSpecFromDhPubKey(const HcfPubKey *self, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    if (self ==  NULL || returnBigInteger == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetDhPubKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = GetBigIntegerSpec(self, NULL, item, returnBigInteger);
    if (ret != HCF_SUCCESS) {
        LOGE("Get big integer failed.");
    }
    return ret;
}

static HcfResult GetBigIntegerSpecFromDhPriKey(const HcfPriKey *self, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    if (self ==  NULL || returnBigInteger == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetDhPriKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = HCF_SUCCESS;
    ret = GetBigIntegerSpec(NULL, self, item, returnBigInteger);
    if (ret != HCF_SUCCESS) {
        LOGE("Get big integer failed.");
    }
    return ret;
}

static HcfResult GetIntSpecFromDhPubKey(const HcfPubKey *self, const AsyKeySpecItem item, int *returnInt)
{
    (void)self;
    (void)returnInt;
    return HCF_NOT_SUPPORT;
}

static HcfResult GetIntSpecFromDhPriKey(const HcfPriKey *self, const AsyKeySpecItem item, int *returnInt)
{
    if (self ==  NULL || returnInt == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetDhPriKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_INVALID_PARAMS;
    }
    if (item != DH_L_NUM) {
        LOGE("Invalid input item.");
        return HCF_INVALID_PARAMS;
    }
    HcfOpensslDhPriKey *impl = (HcfOpensslDhPriKey *)self;
    DH *dh = impl->sk;
    if (dh == NULL) {
        LOGE("Dh is null.");
        return HCF_INVALID_PARAMS;
    }

    *returnInt = (int)OpensslDhGetLength(dh);
    return HCF_SUCCESS;
}

static HcfResult GetStrSpecFromDhPubKey(const HcfPubKey *self, const AsyKeySpecItem item, char **returnString)
{
    (void)self;
    (void)returnString;
    return HCF_NOT_SUPPORT;
}

static HcfResult GetStrSpecFromDhPriKey(const HcfPriKey *self, const AsyKeySpecItem item, char **returnString)
{
    (void)self;
    (void)returnString;
    return HCF_NOT_SUPPORT;
}

static HcfResult GetDhPriKeyEncodedDer(const HcfPriKey *self, const char *format, HcfBlob *returnBlob)
{
    (void)self;
    (void)format;
    (void)returnBlob;
    return HCF_INVALID_PARAMS;
}

static void ClearDhPriKeyMem(HcfPriKey *self)
{
    if (self == NULL) {
        LOGE("Class is null.");
        return;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetDhPriKeyClass())) {
        LOGE("Class not match.");
        return;
    }
    HcfOpensslDhPriKey *impl = (HcfOpensslDhPriKey *)self;
    OpensslDhFree(impl->sk);
    impl->sk = NULL;
}

static EVP_PKEY *ConstructDhOsslParamsAndGenPkey(int32_t dhId, EVP_PKEY_CTX *paramsCtx)
{
    EVP_PKEY *paramsPkey = NULL;
    OSSL_PARAM params[PARAMS_NUM_TWO];
    char *nidName = GetNidNameByDhId(dhId);
    if (nidName == NULL) {
        LOGE("Get nid name failed.");
        return NULL;
    }
    params[0] = OpensslOsslParamConstructUtf8String("group", nidName, 0);
    params[1] = OpensslOsslParamConstructEnd();
    if (OpensslEvpPkeyKeyGenInit(paramsCtx) != HCF_OPENSSL_SUCCESS) {
        LOGD("[error] ParamsCtx generate init failed.");
        return NULL;
    }
    if (OpensslEvpPkeyCtxSetParams(paramsCtx, params) != HCF_OPENSSL_SUCCESS) {
        LOGD("[error] ParamsCtx set failed.");
        return NULL;
    }
    if (OpensslEvpPkeyGenerate(paramsCtx, &paramsPkey) != HCF_OPENSSL_SUCCESS) {
        LOGD("[error] Create generate failed.");
        return NULL;
    }
    return paramsPkey;
}

static HcfResult GenerateDhEvpKey(int32_t dhId, EVP_PKEY **ppkey)
{
    HcfResult ret = HCF_SUCCESS;
    EVP_PKEY *paramsPkey = NULL;
    EVP_PKEY_CTX *pkeyCtx = NULL;
    EVP_PKEY_CTX *paramsCtx = NULL;

    do {
        paramsCtx = OpensslEvpPkeyCtxNewFromName(NULL, "DH", NULL);
        if (paramsCtx == NULL) {
            LOGD("[error] New paramsCtx from name failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        paramsPkey = ConstructDhOsslParamsAndGenPkey(dhId, paramsCtx);
        if (paramsPkey == NULL) {
            LOGD("[error] Construct dh params and generate pkey failed.");
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
        if (OpensslEvpPkeyCheck(pkeyCtx) != HCF_OPENSSL_SUCCESS) {
            LOGD("[error] Check pkey fail.");
            OpensslEvpPkeyFree(*ppkey);
            *ppkey = NULL;
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
    } while (0);
    FreeCtx(paramsCtx, paramsPkey, pkeyCtx);
    return ret;
}

static HcfResult GetDhPubKeyEncodedDer(const HcfPubKey *self, const char *format, HcfBlob *returnBlob)
{
    (void)self;
    (void)format;
    (void)returnBlob;
    return HCF_INVALID_PARAMS;
}

static void FillOpensslDhPubKeyFunc(HcfOpensslDhPubKey *pk)
{
    pk->base.base.base.destroy = DestroyDhPubKey;
    pk->base.base.base.getClass = GetDhPubKeyClass;
    pk->base.base.getAlgorithm = GetDhPubKeyAlgorithm;
    pk->base.base.getEncoded = GetDhPubKeyEncoded;
    pk->base.base.getEncodedPem = GetDhPubKeyEncodedPem;
    pk->base.base.getFormat = GetDhPubKeyFormat;
    pk->base.getAsyKeySpecBigInteger = GetBigIntegerSpecFromDhPubKey;
    pk->base.getAsyKeySpecInt = GetIntSpecFromDhPubKey;
    pk->base.getAsyKeySpecString = GetStrSpecFromDhPubKey;
    pk->base.getEncodedDer = GetDhPubKeyEncodedDer;
}

static void FillOpensslDhPriKeyFunc(HcfOpensslDhPriKey *sk)
{
    sk->base.base.base.destroy = DestroyDhPriKey;
    sk->base.base.base.getClass = GetDhPriKeyClass;
    sk->base.base.getAlgorithm = GetDhPriKeyAlgorithm;
    sk->base.base.getEncoded = GetDhPriKeyEncoded;
    sk->base.base.getEncodedPem = GetDhPriKeyEncodedPem;
    sk->base.base.getFormat = GetDhPriKeyFormat;
    sk->base.getAsyKeySpecBigInteger = GetBigIntegerSpecFromDhPriKey;
    sk->base.getAsyKeySpecInt = GetIntSpecFromDhPriKey;
    sk->base.getAsyKeySpecString = GetStrSpecFromDhPriKey;
    sk->base.getEncodedDer = GetDhPriKeyEncodedDer;
    sk->base.clearMem = ClearDhPriKeyMem;
}

static HcfResult CreateDhPubKey(DH *pk, HcfOpensslDhPubKey **returnPubKey)
{
    HcfOpensslDhPubKey *dhPubKey = (HcfOpensslDhPubKey *)HcfMalloc(sizeof(HcfOpensslDhPubKey), 0);
    if (dhPubKey == NULL) {
        LOGE("Failed to allocate DH public key memory.");
        return HCF_ERR_MALLOC;
    }
    FillOpensslDhPubKeyFunc(dhPubKey);
    dhPubKey->pk = pk;

    *returnPubKey = dhPubKey;
    return HCF_SUCCESS;
}

static HcfResult CreateDhPriKey(DH *sk, HcfOpensslDhPriKey **returnPriKey)
{
    HcfOpensslDhPriKey *dhPriKey = (HcfOpensslDhPriKey *)HcfMalloc(sizeof(HcfOpensslDhPriKey), 0);
    if (dhPriKey == NULL) {
        LOGE("Failed to allocate Dh private key memory.");
        return HCF_ERR_MALLOC;
    }
    FillOpensslDhPriKeyFunc(dhPriKey);
    dhPriKey->sk = sk;

    *returnPriKey = dhPriKey;
    return HCF_SUCCESS;
}

static HcfResult CreateDhKeyPair(const HcfOpensslDhPubKey *pubKey, const HcfOpensslDhPriKey *priKey,
    HcfKeyPair **returnKeyPair)
{
    HcfOpensslDhKeyPair *keyPair = (HcfOpensslDhKeyPair *)HcfMalloc(sizeof(HcfOpensslDhKeyPair), 0);
    if (keyPair == NULL) {
        LOGE("Failed to allocate keyPair memory.");
        return HCF_ERR_MALLOC;
    }
    keyPair->base.base.getClass = GetDhKeyPairClass;
    keyPair->base.base.destroy = DestroyDhKeyPair;
    keyPair->base.pubKey = (HcfPubKey *)pubKey;
    keyPair->base.priKey = (HcfPriKey *)priKey;

    *returnKeyPair = (HcfKeyPair *)keyPair;
    return HCF_SUCCESS;
}

static HcfResult GeneratePubKeyByPkey(EVP_PKEY *pkey, HcfOpensslDhPubKey **returnPubKey)
{
    DH *pk = OpensslEvpPkeyGet1Dh(pkey);
    if (pk == NULL) {
        LOGD("[error] Get dh public key from pkey failed");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = CreateDhPubKey(pk, returnPubKey);
    if (ret != HCF_SUCCESS) {
        LOGD("[error] Create DH public key failed");
        OpensslDhFree(pk);
    }
    return ret;
}

static HcfResult GeneratePriKeyByPkey(EVP_PKEY *pkey, HcfOpensslDhPriKey **returnPriKey)
{
    DH *sk = OpensslEvpPkeyGet1Dh(pkey);
    if (sk == NULL) {
        LOGD("[error] Get DH private key from pkey failed");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = CreateDhPriKey(sk, returnPriKey);
    if (ret != HCF_SUCCESS) {
        LOGD("[error] Create DH private key failed");
        OpensslDhFree(sk);
    }
    return ret;
}

static HcfResult GenerateDhPubAndPriKey(int32_t dhId, HcfOpensslDhPubKey **returnPubKey,
    HcfOpensslDhPriKey **returnPriKey)
{
    EVP_PKEY *pkey = NULL;
    HcfResult ret = GenerateDhEvpKey(dhId, &pkey);
    if (ret != HCF_SUCCESS) {
        LOGE("Generate DH EVP_PKEY failed.");
        return ret;
    }

    ret = GeneratePubKeyByPkey(pkey, returnPubKey);
    if (ret != HCF_SUCCESS) {
        OpensslEvpPkeyFree(pkey);
        LOGE("Generate public key failed.");
        return ret;
    }

    ret = GeneratePriKeyByPkey(pkey, returnPriKey);
    if (ret != HCF_SUCCESS) {
        HcfObjDestroy(*returnPubKey);
        *returnPubKey = NULL;
        OpensslEvpPkeyFree(pkey);
        LOGE("Generate private key failed.");
        return ret;
    }

    OpensslEvpPkeyFree(pkey);
    return ret;
}

static HcfResult ConvertCommSpec2Bn(const HcfDhCommParamsSpec *paramsSpec, BIGNUM **p, BIGNUM **g)
{
    if (BigIntegerToBigNum(&(paramsSpec->p), p) != HCF_SUCCESS) {
        LOGD("[error] Get openssl BN p failed");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (BigIntegerToBigNum(&(paramsSpec->g), g) != HCF_SUCCESS) {
        LOGD("[error] Get openssl BN g failed");
        OpensslBnFree(*p);
        *p = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult CreateOpensslDhKey(const HcfDhCommParamsSpec *paramsSpec, BIGNUM *pk, BIGNUM *sk, DH **returnDh)
{
    BIGNUM *p = NULL;
    BIGNUM *g = NULL;
    if (ConvertCommSpec2Bn(paramsSpec, &p, &g)!= HCF_SUCCESS) {
        LOGD("[error] Get openssl BN p q failed");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    DH *dh = OpensslDhNew();
    if (dh == NULL) {
        FreeCommSpecBn(p, g);
        LOGD("[error] Openssl dh new failed");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslDhSet0Pqg(dh, p, NULL, g) != HCF_OPENSSL_SUCCESS) {
        LOGD("[error] Openssl dh set pqg failed");
        HcfPrintOpensslError();
        FreeCommSpecBn(p, g);
        OpensslDhFree(dh);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (paramsSpec->length > 0) {
        if (OpensslDhSetLength(dh, paramsSpec->length) != HCF_OPENSSL_SUCCESS) {
            LOGD("[error] Openssl dh set length failed");
            HcfPrintOpensslError();
            OpensslDhFree(dh);
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    if ((pk == NULL) && (sk == NULL)) {
        *returnDh = dh;
        return HCF_SUCCESS;
    }
    if (OpensslDhSet0Key(dh, pk, sk) != HCF_OPENSSL_SUCCESS) {
        LOGD("[error] Openssl DH set key failed");
        HcfPrintOpensslError();
        OpensslDhFree(dh);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *returnDh = dh;
    return HCF_SUCCESS;
}

static HcfResult GenerateOpensslDhKeyByCommSpec(const HcfDhCommParamsSpec *paramsSpec, DH **returnDh)
{
    if (CreateOpensslDhKey(paramsSpec, NULL, NULL, returnDh) != HCF_SUCCESS) {
        LOGD("[error] Create openssl dh key failed");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (OpensslDhGenerateKey(*returnDh) != HCF_OPENSSL_SUCCESS) {
        LOGD("[error] Openssl DH generate key failed");
        HcfPrintOpensslError();
        OpensslDhFree(*returnDh);
        *returnDh = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult GenerateOpensslDhKeyByPubKeySpec(const HcfDhPubKeyParamsSpec *paramsSpec, DH **returnDh)
{
    BIGNUM *pubKey = NULL;
    if (BigIntegerToBigNum(&(paramsSpec->pk), &pubKey) != HCF_SUCCESS) {
        LOGD("[error] Get openssl BN pk failed");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (CreateOpensslDhKey(&(paramsSpec->base), pubKey, NULL, returnDh) != HCF_SUCCESS) {
        LOGD("[error] Create dh key failed.");
        OpensslBnFree(pubKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult GenerateOpensslDhKeyByPriKeySpec(const HcfDhPriKeyParamsSpec *paramsSpec, DH **returnDh)
{
    BIGNUM *priKey = NULL;
    if (BigIntegerToBigNum(&(paramsSpec->sk), &priKey) != HCF_SUCCESS) {
        LOGD("[error] Get openssl BN pk failed");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (CreateOpensslDhKey(&(paramsSpec->base), NULL, priKey, returnDh) != HCF_SUCCESS) {
        LOGD("[error] Create dh key failed.");
        OpensslBnFree(priKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult GenerateOpensslDhKeyByKeyPairSpec(const HcfDhKeyPairParamsSpec *paramsSpec, DH **returnDh)
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
    if (CreateOpensslDhKey(&(paramsSpec->base), pubKey, priKey, returnDh) != HCF_SUCCESS) {
        LOGD("[error] Create dh key failed.");
        OpensslBnFree(pubKey);
        OpensslBnFree(priKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult CreateDhKeyPairByCommSpec(const HcfDhCommParamsSpec *paramsSpec, HcfKeyPair **returnKeyPair)
{
    DH *dh = NULL;
    if (GenerateOpensslDhKeyByCommSpec(paramsSpec, &dh) != HCF_SUCCESS) {
        LOGD("[error] Generate openssl dh key by commSpec failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfOpensslDhPubKey *pubKey = NULL;
    if (CreateDhPubKey(dh, &pubKey) != HCF_SUCCESS) {
        LOGE("Create dh pubKey failed.");
        OpensslDhFree(dh);
        return HCF_ERR_MALLOC;
    }

    if (OpensslDhUpRef(dh) != HCF_OPENSSL_SUCCESS) {
        LOGD("[error] DH_up_ref failed.");
        HcfPrintOpensslError();
        HcfObjDestroy(pubKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    HcfOpensslDhPriKey *priKey = NULL;
    if (CreateDhPriKey(dh, &priKey) != HCF_SUCCESS) {
        LOGE("Create dh priKey failed.");
        OpensslDhFree(dh);
        HcfObjDestroy(pubKey);
        return HCF_ERR_MALLOC;
    }

    if (CreateDhKeyPair(pubKey, priKey, returnKeyPair) != HCF_SUCCESS) {
        LOGE("Create dh keyPair failed.");
        HcfObjDestroy(pubKey);
        HcfObjDestroy(priKey);
        return HCF_ERR_MALLOC;
    }
    return HCF_SUCCESS;
}

static HcfResult CreateDhPubKeyByKeyPairSpec(const HcfDhKeyPairParamsSpec *paramsSpec,
    HcfOpensslDhPubKey **returnPubKey)
{
    DH *dh = NULL;
    if (GenerateOpensslDhKeyByKeyPairSpec(paramsSpec, &dh) != HCF_SUCCESS) {
        LOGD("[error] Generate openssl dh key by keyPairSpec failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (CreateDhPubKey(dh, returnPubKey) != HCF_SUCCESS) {
        LOGE("Create dh pubKey failed.");
        OpensslDhFree(dh);
        return HCF_ERR_MALLOC;
    }
    return HCF_SUCCESS;
}

static HcfResult CreateDhPriKeyByKeyPairSpec(const HcfDhKeyPairParamsSpec *paramsSpec,
    HcfOpensslDhPriKey **returnPriKey)
{
    DH *dh = NULL;
    if (GenerateOpensslDhKeyByKeyPairSpec(paramsSpec, &dh) != HCF_SUCCESS) {
        LOGD("[error] Generate openssl dh key by keyPairSpec failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (CreateDhPriKey(dh, returnPriKey) != HCF_SUCCESS) {
        LOGE("Create dh priKey failed.");
        OpensslDhFree(dh);
        return HCF_ERR_MALLOC;
    }
    return HCF_SUCCESS;
}

static HcfResult CreateDhKeyPairByKeyPairSpec(const HcfDhKeyPairParamsSpec *paramsSpec, HcfKeyPair **returnKeyPair)
{
    HcfOpensslDhPubKey *pubKey = NULL;
    HcfResult ret = CreateDhPubKeyByKeyPairSpec(paramsSpec, &pubKey);
    if (ret != HCF_SUCCESS) {
        LOGD("[error] Create dh pubKey by keyPairSpec failed.");
        return ret;
    }

    HcfOpensslDhPriKey *priKey = NULL;
    ret = CreateDhPriKeyByKeyPairSpec(paramsSpec, &priKey);
    if (ret != HCF_SUCCESS) {
        LOGD("[error] Create dh priKey by keyPairSpec failed.");
        HcfObjDestroy(pubKey);
        return ret;
    }
    ret = CreateDhKeyPair(pubKey, priKey, returnKeyPair);
    if (ret != HCF_SUCCESS) {
        LOGD("[error] Create dh keyPair failed.");
        HcfObjDestroy(pubKey);
        HcfObjDestroy(priKey);
        return ret;
    }
    return HCF_SUCCESS;
}

static HcfResult CreateDhKeyPairBySpec(const HcfAsyKeyParamsSpec *paramsSpec, HcfKeyPair **returnKeyPair)
{
    if (paramsSpec->specType == HCF_COMMON_PARAMS_SPEC) {
        return CreateDhKeyPairByCommSpec((const HcfDhCommParamsSpec *)paramsSpec, returnKeyPair);
    } else {
        return CreateDhKeyPairByKeyPairSpec((const HcfDhKeyPairParamsSpec*)paramsSpec, returnKeyPair);
    }
}

static HcfResult CreateDhPubKeyBySpec(const HcfDhPubKeyParamsSpec *paramsSpec, HcfPubKey **returnPubKey)
{
    DH *dh = NULL;
    if (GenerateOpensslDhKeyByPubKeySpec(paramsSpec, &dh) != HCF_SUCCESS) {
        LOGD("[error] Generate openssl dh key by pubKeySpec failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    HcfOpensslDhPubKey *pubKey = NULL;
    if (CreateDhPubKey(dh, &pubKey) != HCF_SUCCESS) {
        LOGE("Create dh pubKey failed.");
        OpensslDhFree(dh);
        return HCF_ERR_MALLOC;
    }
    *returnPubKey = (HcfPubKey *)pubKey;
    return HCF_SUCCESS;
}

static HcfResult CreateDhPriKeyBySpec(const HcfDhPriKeyParamsSpec *paramsSpec, HcfPriKey **returnPriKey)
{
    DH *dh = NULL;
    if (GenerateOpensslDhKeyByPriKeySpec(paramsSpec, &dh) != HCF_SUCCESS) {
        LOGD("[error] Generate openssl dh key by priKeySpec failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    HcfOpensslDhPriKey *priKey = NULL;
    if (CreateDhPriKey(dh, &priKey) != HCF_SUCCESS) {
        LOGE("Create dh priKey failed.");
        OpensslDhFree(dh);
        return HCF_ERR_MALLOC;
    }
    *returnPriKey = (HcfPriKey *)priKey;
    return HCF_SUCCESS;
}

static HcfResult ConvertDhPubKey(const HcfBlob *pubKeyBlob, HcfOpensslDhPubKey **returnPubKey)
{
    const unsigned char *temp = (const unsigned char *)pubKeyBlob->data;
    EVP_PKEY *pKey = OpensslD2iPubKey(NULL, &temp, pubKeyBlob->len);
    if (pKey == NULL) {
        LOGD("[error] Call d2i_PUBKEY failed.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    DH *dh = OpensslEvpPkeyGet1Dh(pKey);
    if (dh == NULL) {
        LOGD("[error] EVP_PKEY_get1_DH failed");
        HcfPrintOpensslError();
        OpensslEvpPkeyFree(pKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    OpensslEvpPkeyFree(pKey);
    HcfResult ret = CreateDhPubKey(dh, returnPubKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Create dh public key failed");
        OpensslDhFree(dh);
    }
    return ret;
}

static HcfResult ConvertDhPriKey(const HcfBlob *priKeyBlob, HcfOpensslDhPriKey **returnPriKey)
{
    const unsigned char *temp = (const unsigned char *)priKeyBlob->data;
    EVP_PKEY *pKey = OpensslD2iPrivateKey(EVP_PKEY_DH, NULL, &temp, priKeyBlob->len);
    if (pKey == NULL) {
        LOGD("[error] Call d2i_PrivateKey failed.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    DH *dh = OpensslEvpPkeyGet1Dh(pKey);
    if (dh == NULL) {
        LOGD("[error] EVP_PKEY_get1_DH failed");
        HcfPrintOpensslError();
        OpensslEvpPkeyFree(pKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    OpensslEvpPkeyFree(pKey);
    HcfResult ret = CreateDhPriKey(dh, returnPriKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Create DH private key failed");
        OpensslDhFree(dh);
    }
    return ret;
}

static HcfResult ConvertDhPubAndPriKey(const HcfBlob *pubKeyBlob, const HcfBlob *priKeyBlob,
    HcfOpensslDhPubKey **returnPubKey, HcfOpensslDhPriKey **returnPriKey)
{
    if (pubKeyBlob != NULL) {
        if (ConvertDhPubKey(pubKeyBlob, returnPubKey) != HCF_SUCCESS) {
            LOGD("[error] Convert DH public key failed.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    if (priKeyBlob != NULL) {
        if (ConvertDhPriKey(priKeyBlob, returnPriKey) != HCF_SUCCESS) {
            LOGD("[error] Convert DH private key failed.");
            HcfObjDestroy(*returnPubKey);
            *returnPubKey = NULL;
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    return HCF_SUCCESS;
}

static HcfResult EngineGenerateDhKeyPair(HcfAsyKeyGeneratorSpi *self, HcfKeyPair **returnKeyPair)
{
    if (self == NULL || returnKeyPair == NULL) {
        LOGE("Invalid params.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetDhKeyGeneratorSpiClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGeneratorSpiDhOpensslImpl *impl = (HcfAsyKeyGeneratorSpiDhOpensslImpl *)self;

    HcfOpensslDhPubKey *pubKey = NULL;
    HcfOpensslDhPriKey *priKey = NULL;
    HcfResult ret = GenerateDhPubAndPriKey(impl->pBits, &pubKey, &priKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Generate DH pk and sk by openssl failed.");
        return ret;
    }
    ret = CreateDhKeyPair(pubKey, priKey, returnKeyPair);
    if (ret != HCF_SUCCESS) {
        LOGE("Create dh keyPair failed.");
        HcfObjDestroy(pubKey);
        HcfObjDestroy(priKey);
        return ret;
    }
    return HCF_SUCCESS;
}

static HcfResult EngineConvertDhKey(HcfAsyKeyGeneratorSpi *self, HcfParamsSpec *params, HcfBlob *pubKeyBlob,
    HcfBlob *priKeyBlob, HcfKeyPair **returnKeyPair)
{
    (void)params;
    if ((self == NULL) || (returnKeyPair == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetDhKeyGeneratorSpiClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    bool pubKeyValid = IsBlobValid(pubKeyBlob);
    bool priKeyValid = IsBlobValid(priKeyBlob);
    if ((!pubKeyValid) && (!priKeyValid)) {
        LOGE("The private key and public key cannot both be NULL.");
        return HCF_INVALID_PARAMS;
    }

    HcfOpensslDhPubKey *pubKey = NULL;
    HcfOpensslDhPriKey *priKey = NULL;
    HcfBlob *inputPk = pubKeyValid ? pubKeyBlob : NULL;
    HcfBlob *inputSk = priKeyValid ? priKeyBlob : NULL;
    HcfResult ret = ConvertDhPubAndPriKey(inputPk, inputSk, &pubKey, &priKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Convert dh pubKey and priKey failed.");
        return ret;
    }
    ret = CreateDhKeyPair(pubKey, priKey, returnKeyPair);
    if (ret != HCF_SUCCESS) {
        LOGE("Create dh keyPair failed.");
        HcfObjDestroy(pubKey);
        HcfObjDestroy(priKey);
    }
    return ret;
}

static HcfResult EngineGenerateDhKeyPairBySpec(const HcfAsyKeyGeneratorSpi *self,
    const HcfAsyKeyParamsSpec *paramsSpec, HcfKeyPair **returnKeyPair)
{
    if ((self == NULL) || (paramsSpec == NULL) || (returnKeyPair == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    if (!IsClassMatch((HcfObjectBase *)self, GetDhKeyGeneratorSpiClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }

    if ((strcmp(paramsSpec->algName, ALGORITHM_NAME_DH) != 0) ||
        ((paramsSpec->specType != HCF_COMMON_PARAMS_SPEC) && (paramsSpec->specType != HCF_KEY_PAIR_SPEC))) {
        LOGE("Invalid params spec.");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = CreateDhKeyPairBySpec(paramsSpec, returnKeyPair);
    if (ret != HCF_SUCCESS) {
        LOGE("Create DH key pair by spec failed.");
    }
    return ret;
}

static HcfResult EngineGenerateDhPubKeyBySpec(const HcfAsyKeyGeneratorSpi *self,
    const HcfAsyKeyParamsSpec *paramsSpec, HcfPubKey **returnPubKey)
{
    if ((self == NULL) || (paramsSpec == NULL) || (returnPubKey == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    if (!IsClassMatch((HcfObjectBase *)self, GetDhKeyGeneratorSpiClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }

    if ((strcmp(paramsSpec->algName, ALGORITHM_NAME_DH) != 0) ||
        ((paramsSpec->specType != HCF_PUBLIC_KEY_SPEC) && (paramsSpec->specType != HCF_KEY_PAIR_SPEC))) {
        LOGE("Invalid params spec.");
        return HCF_INVALID_PARAMS;
    }

    HcfResult ret = CreateDhPubKeyBySpec((const HcfDhPubKeyParamsSpec *)paramsSpec, returnPubKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Create DH public key by spec failed.");
    }
    return ret;
}

static HcfResult EngineGenerateDhPriKeyBySpec(const HcfAsyKeyGeneratorSpi *self,
    const HcfAsyKeyParamsSpec *paramsSpec, HcfPriKey **returnPriKey)
{
    if ((self == NULL) || (paramsSpec == NULL) || (returnPriKey == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetDhKeyGeneratorSpiClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    if ((strcmp(paramsSpec->algName, ALGORITHM_NAME_DH) != 0) ||
        ((paramsSpec->specType != HCF_PRIVATE_KEY_SPEC) && (paramsSpec->specType != HCF_KEY_PAIR_SPEC))) {
        LOGE("Invalid params spec.");
        return HCF_INVALID_PARAMS;
    }

    HcfResult ret = CreateDhPriKeyBySpec((const HcfDhPriKeyParamsSpec *)paramsSpec, returnPriKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Create DH private key by spec failed.");
    }
    return ret;
}

HcfResult HcfAsyKeyGeneratorSpiDhCreate(HcfAsyKeyGenParams *params, HcfAsyKeyGeneratorSpi **returnSpi)
{
    if (params == NULL || returnSpi == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGeneratorSpiDhOpensslImpl *impl = (HcfAsyKeyGeneratorSpiDhOpensslImpl *)HcfMalloc(
        sizeof(HcfAsyKeyGeneratorSpiDhOpensslImpl), 0);
    if (impl == NULL) {
        LOGE("Failed to allocate generator impl memroy.");
        return HCF_ERR_MALLOC;
    }
    impl->pBits = params->bits;
    impl->base.base.getClass = GetDhKeyGeneratorSpiClass;
    impl->base.base.destroy = DestroyDhKeyGeneratorSpiImpl;
    impl->base.engineGenerateKeyPair = EngineGenerateDhKeyPair;
    impl->base.engineConvertKey = EngineConvertDhKey;
    impl->base.engineGenerateKeyPairBySpec = EngineGenerateDhKeyPairBySpec;
    impl->base.engineGeneratePubKeyBySpec = EngineGenerateDhPubKeyBySpec;
    impl->base.engineGeneratePriKeyBySpec = EngineGenerateDhPriKeyBySpec;

    *returnSpi = (HcfAsyKeyGeneratorSpi *)impl;
    return HCF_SUCCESS;
}
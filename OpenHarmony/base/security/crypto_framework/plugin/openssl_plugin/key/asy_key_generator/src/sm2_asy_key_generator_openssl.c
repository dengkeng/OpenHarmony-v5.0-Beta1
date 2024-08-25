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

#include "sm2_asy_key_generator_openssl.h"
#include "securec.h"
#include "ecc_openssl_common.h"
#include "ecc_openssl_common_param_spec.h"
#include "log.h"
#include "memory.h"
#include "openssl_adapter.h"
#include "utils.h"

#define OPENSSL_SM2_256_BITS 256
#define OPENSSL_SM2_KEY_GENERATOR_CLASS "OPENSSL.SM2.KEY_GENERATOR_CLASS"
#define OPENSSL_SM2_ALGORITHM "SM2"
#define OPENSSL_SM2_PUB_KEY_FORMAT "X.509"
#define OPENSSL_SM2_PRI_KEY_FORMAT "PKCS#8"
static const char *const g_sm2GenerateFieldType = "Fp";

typedef struct {
    HcfAsyKeyGeneratorSpi base;

    int32_t curveId;
} HcfAsyKeyGeneratorSpiOpensslSm2Impl;

static HcfResult CheckSm256CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    BIGNUM *pStd = NULL;
    BIGNUM *bStd = NULL;
    BIGNUM *xStd = NULL;
    BIGNUM *yStd = NULL;
    pStd = OpensslBin2Bn(g_sm256CorrectBigP, NID_X9_62_prime256v1_len, NULL);
    bStd = OpensslBin2Bn(g_sm256CorrectBigB, NID_X9_62_prime256v1_len, NULL);
    xStd = OpensslBin2Bn(g_sm256CorrectBigGX, NID_X9_62_prime256v1_len, NULL);
    yStd = OpensslBin2Bn(g_sm256CorrectBigGY, NID_X9_62_prime256v1_len, NULL);
    if ((pStd == NULL) || (bStd == NULL) || (xStd == NULL) || (yStd == NULL)) {
        LOGD("[error] EC 256 Curve convert to BN fail");
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslBnCmp(p, pStd) == 0 && OpensslBnCmp(b, bStd) == 0 &&
        OpensslBnCmp(x, xStd) == 0 && OpensslBnCmp(y, yStd) == 0) {
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_SUCCESS;
    }
    LOGD("[error] EC 256 compare fail");
    FreeCurveBigNum(pStd, bStd, xStd, yStd);
    return HCF_INVALID_PARAMS;
}

static HcfResult CheckParamsSpecToGetCurveId(const HcfEccCommParamsSpec *ecParams, int32_t *curveId)
{
    BIGNUM *p = NULL;
    BIGNUM *b = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    HcfECFieldFp *field = (HcfECFieldFp *)(ecParams->field);
    if (BigIntegerToBigNum(&(field->p), &p) != HCF_SUCCESS ||
        BigIntegerToBigNum(&(ecParams->b), &b) != HCF_SUCCESS ||
        BigIntegerToBigNum(&(ecParams->g.x), &x) != HCF_SUCCESS ||
        BigIntegerToBigNum(&(ecParams->g.y), &y) != HCF_SUCCESS) {
        LOGD("[error] BigIntegerToBigNum failed.");
        FreeCurveBigNum(p, b, x, y);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    int32_t bitLenP = (int32_t)OpensslBnNumBits(p);
    HcfResult ret = HCF_INVALID_PARAMS;
    if (bitLenP != OPENSSL_SM2_256_BITS) {
        LOGE("Find no bit len");
        FreeCurveBigNum(p, b, x, y);
        return ret;
    }
    ret = CheckSm256CurveId(p, b, x, y);
    if (ret == HCF_SUCCESS) {
        *curveId = NID_sm2;
    }
    FreeCurveBigNum(p, b, x, y);
    return ret;
}

static HcfResult GenerateSm2KeyWithParamsSpec(const HcfEccCommParamsSpec *ecParams, EC_KEY **returnKey)
{
    if (ecParams == NULL || returnKey == NULL) {
        LOGE("Invalid input parameters.");
        return HCF_INVALID_PARAMS;
    }
    EC_KEY *ecKey = NULL;
    int32_t curveId = 0;
    HcfResult ret = CheckParamsSpecToGetCurveId(ecParams, &curveId);
    if (ret == HCF_SUCCESS && curveId != 0) {
        ecKey = OpensslEcKeyNewByCurveName(curveId);
        LOGD("Generate EC_KEY by curve name");
        if (ecKey == NULL) {
            LOGD("[error] New ec key failed.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    } else {
        EC_GROUP *group = NULL;
        ret = GenerateEcGroupWithParamsSpec(ecParams, &group);
        if (ret != HCF_SUCCESS) {
            LOGE("GenerateEcGroupWithParamsSpec failed.");
            return ret;
        }
        ecKey = OpensslEcKeyNew();
        if (ecKey == NULL) {
            LOGD("[error] OpensslEcKeyNew failed.");
            OpensslEcGroupFree(group);
            return HCF_ERR_CRYPTO_OPERATION;
        }
        if (OpensslEcKeySetGroup(ecKey, group) != HCF_OPENSSL_SUCCESS) {
            LOGD("[error] OpensslEcKeySetGroup failed.");
            OpensslEcGroupFree(group);
            OpensslEcKeyFree(ecKey);
            return HCF_ERR_CRYPTO_OPERATION;
        }
        OpensslEcGroupFree(group);
        LOGD("Generate EC_KEY by group spec parmas");
    }
    // all exceptions have been returned above.
    *returnKey = ecKey;
    return HCF_SUCCESS;
}

static HcfResult NewSm2KeyPairWithCommSpec(const HcfEccCommParamsSpec *ecParams, EC_KEY **returnEckey)
{
    if (ecParams == NULL || returnEckey == NULL) {
        LOGE("Invalid input parameters.");
        return HCF_INVALID_PARAMS;
    }
    EC_KEY *ecKey = NULL;
    HcfResult ret = GenerateSm2KeyWithParamsSpec(ecParams, &ecKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Generate EC key failed");
        return ret;
    }
    if (OpensslEcKeyGenerateKey(ecKey) != HCF_OPENSSL_SUCCESS) {
        LOGD("[error] OpensslEcKeyGenerateKey failed.");
        OpensslEcKeyFree(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (OpensslEcKeyCheckKey(ecKey) <= 0) {
        LOGD("[error] Check ecKey fail.");
        OpensslEcKeyFree(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *returnEckey = ecKey;
    return ret;
}

static HcfResult NewSm2PubKeyWithPubSpec(const HcfEccPubKeyParamsSpec *ecParams, EC_KEY **returnEcKey)
{
    if (ecParams == NULL || returnEcKey == NULL) {
        LOGE("Invalid input parameters.");
        return HCF_INVALID_PARAMS;
    }
    EC_KEY *ecKey = NULL;
    HcfResult ret = GenerateSm2KeyWithParamsSpec((HcfEccCommParamsSpec *)ecParams, &ecKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Generate EC key failed");
        return ret;
    }
    ret = SetEcKey(&(ecParams->pk), NULL, ecKey);
    if (ret != HCF_SUCCESS) {
        LOGD("[error] Set public ecKey failed.");
        OpensslEcKeyFree(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (OpensslEcKeyCheckKey(ecKey) <= 0) {
        LOGD("[error] Check ecKey fail.");
        OpensslEcKeyFree(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *returnEcKey = ecKey;
    return ret;
}

static HcfResult NewSm2PriKeyWithPriSpec(const HcfEccPriKeyParamsSpec *ecParams, EC_KEY **returnEcKey)
{
    if (ecParams == NULL || returnEcKey == NULL) {
        LOGE("Invalid input parameters.");
        return HCF_INVALID_PARAMS;
    }
    EC_KEY *ecKey = NULL;
    HcfResult ret = GenerateSm2KeyWithParamsSpec((HcfEccCommParamsSpec *)ecParams, &ecKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Generate EC key failed");
        return ret;
    }
    ret = SetEcKey(NULL, &(ecParams->sk), ecKey);
    if (ret != HCF_SUCCESS) {
        LOGD("[error] Set private ecKey failed.");
        OpensslEcKeyFree(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (OpensslEcKeyCheckKey(ecKey) <= 0) {
        LOGD("[error] Check ecKey failed.");
        OpensslEcKeyFree(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *returnEcKey = ecKey;
    return ret;
}

static HcfResult NewSm2KeyWithKeyPairSpec(const HcfEccKeyPairParamsSpec *ecParams, EC_KEY **returnEcKey,
    bool needPrivate)
{
    if (ecParams == NULL || returnEcKey == NULL) {
        LOGE("Invalid input parameters.");
        return HCF_INVALID_PARAMS;
    }
    EC_KEY *ecKey = NULL;
    HcfResult ret = GenerateSm2KeyWithParamsSpec((HcfEccCommParamsSpec *)ecParams, &ecKey);
    if (ret != HCF_SUCCESS) {
        LOGD("[error] Generate EC key failed");
        return ret;
    }
    if (needPrivate) {
        ret = SetEcKey(&(ecParams->pk), &(ecParams->sk), ecKey);
    } else {
        ret = SetEcKey(&(ecParams->pk), NULL, ecKey);
    }
    if (ret != HCF_SUCCESS) {
        LOGD("[error] SetEcKey failed.");
        OpensslEcKeyFree(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (OpensslEcKeyCheckKey(ecKey) <= 0) {
        LOGE("Check ecKey failed.");
        OpensslEcKeyFree(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *returnEcKey = ecKey;
    return ret;
}

static HcfResult GenKeyPairSm2KeyBySpec(const HcfAsyKeyParamsSpec *params, EC_KEY **ecKey)
{
    HcfResult ret = HCF_INVALID_PARAMS;
    switch (params->specType) {
        case HCF_COMMON_PARAMS_SPEC:
            ret = NewSm2KeyPairWithCommSpec((HcfEccCommParamsSpec *)params, ecKey);
            break;
        case HCF_KEY_PAIR_SPEC:
            ret = NewSm2KeyWithKeyPairSpec((HcfEccKeyPairParamsSpec *)params, ecKey, true);
            break;
        default:
            LOGE("Invaild input spec to gen key pair.");
            break;
    }
    return ret;
}

static HcfResult GenPubKeySm2KeyBySpec(const HcfAsyKeyParamsSpec *params, EC_KEY **ecKey)
{
    HcfResult ret = HCF_INVALID_PARAMS;
    switch (params->specType) {
        case HCF_PUBLIC_KEY_SPEC:
            ret = NewSm2PubKeyWithPubSpec((HcfEccPubKeyParamsSpec *)params, ecKey);
            break;
        case HCF_KEY_PAIR_SPEC:
            ret = NewSm2KeyWithKeyPairSpec((HcfEccKeyPairParamsSpec *)params, ecKey, false);
            break;
        default:
            LOGE("Invaild input spec to gen pub key");
            break;
    }
    return ret;
}

static HcfResult GenPriKeySm2KeyBySpec(const HcfAsyKeyParamsSpec *params, EC_KEY **ecKey)
{
    HcfResult ret = HCF_INVALID_PARAMS;
    switch (params->specType) {
        case HCF_PRIVATE_KEY_SPEC:
            ret = NewSm2PriKeyWithPriSpec((HcfEccPriKeyParamsSpec *)params, ecKey);
            break;
        case HCF_KEY_PAIR_SPEC:
            ret = NewSm2KeyWithKeyPairSpec((HcfEccKeyPairParamsSpec *)params, ecKey, true);
            break;
        default:
            LOGE("Invaild input spec to gen pri key");
            break;
    }
    return ret;
}

static const char *GetSm2KeyPairGeneratorClass(void)
{
    return OPENSSL_SM2_KEY_GENERATOR_CLASS;
}

static const char *GetSm2KeyPairClass(void)
{
    return HCF_OPENSSL_SM2_KEY_PAIR_CLASS;
}

static const char *GetSm2PubKeyClass(void)
{
    return HCF_OPENSSL_SM2_PUB_KEY_CLASS;
}

static const char *GetSm2PriKeyClass(void)
{
    return HCF_OPENSSL_SM2_PRI_KEY_CLASS;
}

static void DestroySm2KeyPairGenerator(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Class is null.");
        return;
    }
    if (!IsClassMatch(self, GetSm2KeyPairGeneratorClass())) {
        LOGE("Class not match.");
        return;
    }
    HcfFree(self);
}

static void DestroySm2PubKey(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Class is null.");
        return;
    }
    if (!IsClassMatch(self, GetSm2PubKeyClass())) {
        LOGE("Class not match.");
        return;
    }
    HcfOpensslSm2PubKey *impl = (HcfOpensslSm2PubKey *)self;
    OpensslEcKeyFree(impl->ecKey);
    impl->ecKey = NULL;
    HcfFree(impl->fieldType);
    impl->fieldType = NULL;
    HcfFree(impl);
}

static void DestroySm2PriKey(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Class is null.");
        return;
    }
    if (!IsClassMatch(self, GetSm2PriKeyClass())) {
        LOGE("Class not match.");
        return;
    }
    HcfOpensslSm2PriKey *impl = (HcfOpensslSm2PriKey *)self;
    OpensslEcKeyFree(impl->ecKey);
    impl->ecKey = NULL;
    HcfFree(impl->fieldType);
    impl->fieldType = NULL;
    HcfFree(impl);
}

static void DestroySm2KeyPair(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Class is null.");
        return;
    }
    if (!IsClassMatch(self, GetSm2KeyPairClass())) {
        LOGE("Class not match.");
        return;
    }
    HcfOpensslSm2KeyPair *impl = (HcfOpensslSm2KeyPair *)self;
    if (impl->base.pubKey != NULL) {
        DestroySm2PubKey((HcfObjectBase *)impl->base.pubKey);
        impl->base.pubKey = NULL;
    }
    if (impl->base.priKey != NULL) {
        DestroySm2PriKey((HcfObjectBase *)impl->base.priKey);
        impl->base.priKey = NULL;
    }
    HcfFree(impl);
}

static const char *GetSm2PubKeyAlgorithm(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_SM2_PUB_KEY_CLASS)) {
        LOGE("Invalid SM2 public key class for algorithm");
        return NULL;
    }
    return OPENSSL_SM2_ALGORITHM;
}

static const char *GetSm2PriKeyAlgorithm(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_SM2_PRI_KEY_CLASS)) {
        LOGE("Invalid SM2 private key class for algorithm");
        return NULL;
    }
    return OPENSSL_SM2_ALGORITHM;
}

static const char *GetSm2PubKeyFormat(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_SM2_PUB_KEY_CLASS)) {
        LOGE("Invalid SM2 public key class for format");
        return NULL;
    }
    return OPENSSL_SM2_PUB_KEY_FORMAT;
}

static const char *GetSm2PriKeyFormat(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_SM2_PRI_KEY_CLASS)) {
        LOGE("Invalid SM2 private key class for format");
        return NULL;
    }
    return OPENSSL_SM2_PRI_KEY_FORMAT;
}

static HcfResult GetSm2PubKeyEncoded(HcfKey *self, HcfBlob *returnBlob)
{
    if ((self == NULL) || (returnBlob == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_SM2_PUB_KEY_CLASS)) {
        LOGE("Invalid SM2 public key class for encode");
        return HCF_INVALID_PARAMS;
    }

    HcfOpensslSm2PubKey *impl = (HcfOpensslSm2PubKey *)self;
    if (impl->curveId != 0) {
        LOGD("Have a curveId");
        OpensslEcKeySetAsn1Flag(impl->ecKey, OPENSSL_EC_NAMED_CURVE);
    } else {
        OpensslEcKeySetAsn1Flag(impl->ecKey, OPENSSL_EC_EXPLICIT_CURVE);
    }

    unsigned char *returnData = NULL;
    int returnDataLen = OpensslI2dEcPubKey(impl->ecKey, &returnData);
    if (returnDataLen <= 0) {
        LOGD("[error] Call i2d_EC_PUBKEY fail");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->data = returnData;
    returnBlob->len = returnDataLen;
    return HCF_SUCCESS;
}

static HcfResult GetSm2PubKeyEncodedPem(HcfKey *self, const char *format, char **returnString)
{
    (void)self;
    (void)format;
    (void)returnString;
    return HCF_INVALID_PARAMS;
}

static HcfResult GetSm2PriKeyEncoded(HcfKey *self, HcfBlob *returnBlob)
{
    if ((self == NULL) || (returnBlob == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_SM2_PRI_KEY_CLASS)) {
        LOGE("Invalid SM2 private key class for encode");
        return HCF_INVALID_PARAMS;
    }

    HcfOpensslSm2PriKey *impl = (HcfOpensslSm2PriKey *)self;
    if (impl->curveId != 0) {
        LOGD("Have a curveId");
        OpensslEcKeySetAsn1Flag(impl->ecKey, OPENSSL_EC_NAMED_CURVE);
    } else {
        OpensslEcKeySetAsn1Flag(impl->ecKey, OPENSSL_EC_EXPLICIT_CURVE);
    }
    // keep consistence of 3.2
    OpensslEcKeySetEncFlags(impl->ecKey, EC_PKEY_NO_PUBKEY);
    // if the convert key has no pubKey, it will generate pub key automatically,
    // and set the no pubKey flag to ensure the consistency of blob.
    unsigned char *returnData = NULL;
    int returnDataLen = OpensslI2dEcPrivateKey(impl->ecKey, &returnData);
    if (returnDataLen <= 0) {
        LOGD("[error] Call i2d_ECPrivateKey fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->data = returnData;
    returnBlob->len = returnDataLen;
    return HCF_SUCCESS;
}

static HcfResult GetSm2PriKeyEncodedPem(HcfKey *self, const char *format, char **returnString)
{
    (void)self;
    (void)format;
    (void)returnString;
    return HCF_INVALID_PARAMS;
}

static void Sm2PriKeyClearMem(HcfPriKey *self)
{
    if (self == NULL) {
        LOGE("Class is null.");
        return;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetSm2PriKeyClass())) {
        LOGE("Class not match.");
        return;
    }
    HcfOpensslSm2PriKey *impl = (HcfOpensslSm2PriKey *)self;
    OpensslEcKeyFree(impl->ecKey);
    impl->ecKey = NULL;
}

static HcfResult GetCurveName(const HcfKey *self, bool isPriavte, char **returnString)
{
    int32_t curveId = 0;
    if (isPriavte) {
        curveId = ((HcfOpensslSm2PriKey *)self)->curveId;
    } else {
        curveId = ((HcfOpensslSm2PubKey *)self)->curveId;
    }

    if (curveId != NID_sm2) {
        LOGD("[error] Invalid curve name.");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    char *curveIdStr = "NID_sm2";
    size_t len = HcfStrlen(curveIdStr);
    if (len == 0) {
        LOGE("CurveIdStr is empty!");
        return HCF_INVALID_PARAMS;
    }
    *returnString = (char *)HcfMalloc(len + 1, 0);
    if (*returnString == NULL) {
        LOGE("Allocate returnString memory failed.");
        return HCF_ERR_MALLOC;
    }
    if (memcpy_s(*returnString, len, curveIdStr, len) != EOK) {
        LOGE("Memcpy returnString failed.");
        HcfFree(*returnString);
        return HCF_ERR_MALLOC;
    }
    return HCF_SUCCESS;
}

static HcfResult CheckSm2KeySelf(const HcfKey *self, bool *isPrivate)
{
    if (IsClassMatch((HcfObjectBase *)self, GetSm2PubKeyClass())) {
        *isPrivate = false;
        return HCF_SUCCESS;
    } else if (IsClassMatch((HcfObjectBase *)self, GetSm2PriKeyClass())) {
        if (((HcfOpensslSm2PriKey *)self)->ecKey == NULL) {
            LOGE("Cannot use priKey after free");
            return HCF_INVALID_PARAMS;
        }
        *isPrivate = true;
        return HCF_SUCCESS;
    } else {
        return HCF_INVALID_PARAMS;
    }
}

static HcfResult GetSm2KeySpecBigInteger(const HcfKey *self, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    if (self == NULL || returnBigInteger == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    bool isPrivate;
    HcfResult ret = CheckSm2KeySelf(self, &isPrivate);
    if (ret != HCF_SUCCESS) {
        LOGE("Invalid input key");
        return HCF_INVALID_PARAMS;
    }
    const EC_GROUP *group = NULL;
    if (isPrivate) {
        group = OpensslEcKeyGet0Group(((HcfOpensslSm2PriKey *)self)->ecKey);
    } else {
        group = OpensslEcKeyGet0Group(((HcfOpensslSm2PubKey *)self)->ecKey);
    }
    if (group == NULL) {
        LOGE("Get group failed");
        return HCF_INVALID_PARAMS;
    }
    switch (item) {
        case ECC_FP_P_BN:
        case ECC_A_BN:
        case ECC_B_BN:
            ret = GetCurveGFp(group, item, returnBigInteger);
            break;
        case ECC_G_X_BN:
        case ECC_G_Y_BN:
            ret = GetGenerator(group, item, returnBigInteger);
            break;
        case ECC_N_BN:
            ret = GetOrder(group, returnBigInteger);
            break;
        case ECC_SK_BN:
        case ECC_PK_X_BN:
        case ECC_PK_Y_BN:
            ret = GetPkSkBigInteger(self, isPrivate, item, returnBigInteger);
            break;
        default:
            LOGE("Invalid ecc key big number spec!");
            ret = HCF_INVALID_PARAMS;
            break;
    }
    return ret;
}

static HcfResult GetSm2KeySpecString(const HcfKey *self, const AsyKeySpecItem item, char **returnString)
{
    if (self == NULL || returnString == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    bool isPrivate;
    HcfResult ret = CheckSm2KeySelf(self, &isPrivate);
    if (ret != HCF_SUCCESS) {
        LOGE("Invalid input key");
        return HCF_INVALID_PARAMS;
    }

    switch (item) {
        case ECC_FIELD_TYPE_STR:
            ret = GetFieldType(self, isPrivate, returnString);
            break;
        case ECC_CURVE_NAME_STR:
            ret = GetCurveName(self, isPrivate, returnString);
            break;
        default:
            ret = HCF_INVALID_PARAMS;
            LOGE("Invalid spec of ec string");
            break;
    }
    return ret;
}

static HcfResult GetSm2KeySpecInt(const HcfKey *self, const AsyKeySpecItem item, int *returnInt)
{
    if (self == NULL || returnInt == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    bool isPrivate;
    HcfResult ret = CheckSm2KeySelf(self, &isPrivate);
    if (ret != HCF_SUCCESS) {
        LOGE("Invalid input key");
        return HCF_INVALID_PARAMS;
    }
    const EC_GROUP *group = NULL;
    if (isPrivate) {
        group = OpensslEcKeyGet0Group(((HcfOpensslSm2PriKey *)self)->ecKey);
    } else {
        group = OpensslEcKeyGet0Group(((HcfOpensslSm2PubKey *)self)->ecKey);
    }
    if (group == NULL) {
        LOGE("Get group failed");
        return HCF_INVALID_PARAMS;
    }
    switch (item) {
        case ECC_H_INT:
            ret = GetCofactor(group, returnInt);
            break;
        case ECC_FIELD_SIZE_INT:
            ret = GetFieldSize(group, returnInt);
            break;
        default:
            ret = HCF_INVALID_PARAMS;
            LOGE("Invalid ec key int spec");
            break;
    }
    return ret;
}

static HcfResult GetSm2PubKeySpecBigInteger(const HcfPubKey *self, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    return GetSm2KeySpecBigInteger((HcfKey *)self, item, returnBigInteger);
}

static HcfResult GetSm2PriKeySpecBigInteger(const HcfPriKey *self, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    return GetSm2KeySpecBigInteger((HcfKey *)self, item, returnBigInteger);
}

static HcfResult GetSm2PubKeySpecString(const HcfPubKey *self, const AsyKeySpecItem item, char **returnString)
{
    return GetSm2KeySpecString((HcfKey *)self, item, returnString);
}

static HcfResult GetSm2PriKeySpecString(const HcfPriKey *self, const AsyKeySpecItem item, char **returnString)
{
    return GetSm2KeySpecString((HcfKey *)self, item, returnString);
}

static HcfResult GetSm2PubKeySpecInt(const HcfPubKey *self, const AsyKeySpecItem item, int *returnInt)
{
    return GetSm2KeySpecInt((HcfKey *)self, item, returnInt);
}

static HcfResult GetSm2PriKeySpecInt(const HcfPriKey *self, const AsyKeySpecItem item, int *returnInt)
{
    return GetSm2KeySpecInt((HcfKey *)self, item, returnInt);
}

static HcfResult GetSm2PubKeyEncodedDer(const HcfPubKey *self, const char *format, HcfBlob *returnBlob)
{
    (void)self;
    (void)format;
    (void)returnBlob;
    return HCF_INVALID_PARAMS;
}

static HcfResult PackSm2PubKey(int32_t curveId, EC_KEY *ecKey, const char *fieldType,
    HcfOpensslSm2PubKey **returnObj)
{
    HcfOpensslSm2PubKey *returnPubKey = (HcfOpensslSm2PubKey *)HcfMalloc(sizeof(HcfOpensslSm2PubKey), 0);
    if (returnPubKey == NULL) {
        LOGE("Failed to allocate returnPubKey memory!");
        return HCF_ERR_MALLOC;
    }

    char *tmpFieldType = NULL;
    if (fieldType != NULL) {
        size_t len = HcfStrlen(fieldType);
        if (len == 0) {
            LOGE("FieldType is empty!");
            HcfFree(returnPubKey);
            return HCF_INVALID_PARAMS;
        }
        tmpFieldType = (char *)HcfMalloc(len + 1, 0);
        if (tmpFieldType == NULL) {
            LOGE("Allocate tmpFieldType memory failed.");
            HcfFree(returnPubKey);
            return HCF_ERR_MALLOC;
        }
        (void)memcpy_s(tmpFieldType, len, fieldType, len);
    }
    returnPubKey->base.base.base.destroy = DestroySm2PubKey;
    returnPubKey->base.base.base.getClass = GetSm2PubKeyClass;
    returnPubKey->base.base.getAlgorithm = GetSm2PubKeyAlgorithm;
    returnPubKey->base.base.getEncoded = GetSm2PubKeyEncoded;
    returnPubKey->base.base.getEncodedPem = GetSm2PubKeyEncodedPem;
    returnPubKey->base.base.getFormat = GetSm2PubKeyFormat;
    returnPubKey->base.getAsyKeySpecBigInteger = GetSm2PubKeySpecBigInteger;
    returnPubKey->base.getAsyKeySpecString = GetSm2PubKeySpecString;
    returnPubKey->base.getAsyKeySpecInt = GetSm2PubKeySpecInt;
    returnPubKey->base.getEncodedDer = GetSm2PubKeyEncodedDer;
    returnPubKey->curveId = curveId;
    returnPubKey->ecKey = ecKey;
    returnPubKey->fieldType = tmpFieldType;

    *returnObj = returnPubKey;
    return HCF_SUCCESS;
}

static HcfResult GetSm2PriKeyEncodedDer(const HcfPriKey *self, const char *format, HcfBlob *returnBlob)
{
    (void)self;
    (void)format;
    (void)returnBlob;
    return HCF_INVALID_PARAMS;
}

static HcfResult PackSm2PriKey(int32_t curveId, EC_KEY *ecKey, const char *fieldType,
    HcfOpensslSm2PriKey **returnObj)
{
    HcfOpensslSm2PriKey *returnPriKey = (HcfOpensslSm2PriKey *)HcfMalloc(sizeof(HcfOpensslSm2PriKey), 0);
    if (returnPriKey == NULL) {
        LOGE("Failed to allocate returnPriKey memory!");
        return HCF_ERR_MALLOC;
    }

    char *tmpFieldType = NULL;
    if (fieldType != NULL) {
        size_t len = HcfStrlen(fieldType);
        if (len == 0) {
            LOGE("FieldType is empty!");
            HcfFree(returnPriKey);
            return HCF_INVALID_PARAMS;
        }
        tmpFieldType = (char *)HcfMalloc(len + 1, 0);
        if (tmpFieldType == NULL) {
            LOGE("Allocate tmpFieldType memory failed.");
            HcfFree(returnPriKey);
            return HCF_ERR_MALLOC;
        }
        (void)memcpy_s(tmpFieldType, len, fieldType, len);
    }
    returnPriKey->base.base.base.destroy = DestroySm2PriKey;
    returnPriKey->base.base.base.getClass = GetSm2PriKeyClass;
    returnPriKey->base.base.getAlgorithm = GetSm2PriKeyAlgorithm;
    returnPriKey->base.base.getEncoded = GetSm2PriKeyEncoded;
    returnPriKey->base.base.getEncodedPem = GetSm2PriKeyEncodedPem;
    returnPriKey->base.base.getFormat = GetSm2PriKeyFormat;
    returnPriKey->base.getAsyKeySpecBigInteger = GetSm2PriKeySpecBigInteger;
    returnPriKey->base.getAsyKeySpecString = GetSm2PriKeySpecString;
    returnPriKey->base.getAsyKeySpecInt = GetSm2PriKeySpecInt;
    returnPriKey->base.clearMem = Sm2PriKeyClearMem;
    returnPriKey->base.getEncodedDer = GetSm2PriKeyEncodedDer;
    returnPriKey->curveId = curveId;
    returnPriKey->ecKey = ecKey;
    returnPriKey->fieldType = tmpFieldType;

    *returnObj = returnPriKey;
    return HCF_SUCCESS;
}

static HcfResult PackSm2KeyPair(HcfOpensslSm2PubKey *pubKey, HcfOpensslSm2PriKey *priKey,
    HcfOpensslSm2KeyPair **returnObj)
{
    HcfOpensslSm2KeyPair *returnKeyPair = (HcfOpensslSm2KeyPair *)HcfMalloc(sizeof(HcfOpensslSm2KeyPair), 0);
    if (returnKeyPair == NULL) {
        LOGE("Failed to allocate returnKeyPair memory!");
        return HCF_ERR_MALLOC;
    }
    returnKeyPair->base.base.getClass = GetSm2KeyPairClass;
    returnKeyPair->base.base.destroy = DestroySm2KeyPair;
    returnKeyPair->base.pubKey = (HcfPubKey *)pubKey;
    returnKeyPair->base.priKey = (HcfPriKey *)priKey;

    *returnObj = returnKeyPair;
    return HCF_SUCCESS;
}

static HcfResult ConvertEcPubKey(int32_t curveId, HcfBlob *pubKeyBlob, HcfOpensslSm2PubKey **returnPubKey)
{
    const unsigned char *tmpData = (const unsigned char *)(pubKeyBlob->data);
    EC_KEY *ecKey = OpensslD2iEcPubKey(NULL, &tmpData, pubKeyBlob->len);
    if (ecKey == NULL) {
        LOGD("[error] Call d2i_EC_PUBKEY fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = PackSm2PubKey(curveId, ecKey, g_sm2GenerateFieldType, returnPubKey);
    if (ret != HCF_SUCCESS) {
        LOGE("CreateSm2PubKey failed.");
        OpensslEcKeyFree(ecKey);
        return ret;
    }
    return HCF_SUCCESS;
}

static HcfResult ConvertEcPriKey(int32_t curveId, HcfBlob *priKeyBlob, HcfOpensslSm2PriKey **returnPriKey)
{
    const unsigned char *tmpData = (const unsigned char *)(priKeyBlob->data);
    EC_KEY *ecKey = OpensslD2iEcPrivateKey(NULL, &tmpData, priKeyBlob->len);
    if (ecKey == NULL) {
        LOGD("[error] Call d2i_ECPrivateKey fail");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = PackSm2PriKey(curveId, ecKey, g_sm2GenerateFieldType, returnPriKey);
    if (ret != HCF_SUCCESS) {
        LOGE("CreateSm2PriKey failed.");
        OpensslEcKeyFree(ecKey);
        return ret;
    }
    return HCF_SUCCESS;
}

static HcfResult EngineConvertSm2Key(HcfAsyKeyGeneratorSpi *self, HcfParamsSpec *params, HcfBlob *pubKeyBlob,
    HcfBlob *priKeyBlob, HcfKeyPair **returnKeyPair)
{
    (void)params;
    if ((self == NULL) || (returnKeyPair == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, self->base.getClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    bool pubKeyValid = IsBlobValid(pubKeyBlob);
    bool priKeyValid = IsBlobValid(priKeyBlob);
    if ((!pubKeyValid) && (!priKeyValid)) {
        LOGE("The private key and public key cannot both be NULL.");
        return HCF_INVALID_PARAMS;
    }

    HcfAsyKeyGeneratorSpiOpensslSm2Impl *impl = (HcfAsyKeyGeneratorSpiOpensslSm2Impl *)self;
    HcfResult ret = HCF_SUCCESS;
    HcfOpensslSm2PubKey *pubKey = NULL;
    HcfOpensslSm2PriKey *priKey = NULL;
    HcfOpensslSm2KeyPair *keyPair = NULL;
    do {
        if (pubKeyValid) {
            ret = ConvertEcPubKey(impl->curveId, pubKeyBlob, &pubKey);
            if (ret != HCF_SUCCESS) {
                LOGD("[error] Convert ec pubKey failed.");
                break;
            }
        }
        if (priKeyValid) {
            ret = ConvertEcPriKey(impl->curveId, priKeyBlob, &priKey);
            if (ret != HCF_SUCCESS) {
                LOGD("[error] Convert ec priKey failed.");
                break;
            }
        }
        ret = PackSm2KeyPair(pubKey, priKey, &keyPair);
    } while (0);
    if (ret != HCF_SUCCESS) {
        LOGD("[error] Convert sm2 keyPair failed.");
        HcfObjDestroy(pubKey);
        HcfObjDestroy(priKey);
        return ret;
    }

    *returnKeyPair = (HcfKeyPair *)keyPair;
    return HCF_SUCCESS;
}

static HcfResult PackAndAssignPubKey(const HcfAsyKeyGeneratorSpiOpensslSm2Impl *impl, const char *fieldType,
    EC_KEY *ecKey, HcfPubKey **returnObj)
{
    HcfOpensslSm2PubKey *pubKey = NULL;
    HcfResult ret = PackSm2PubKey(impl->curveId, ecKey, fieldType, &pubKey);
    if (ret != HCF_SUCCESS) {
        LOGD("[error] Create sm2 pubKey failed.");
        return ret;
    }
    *returnObj = (HcfPubKey *)pubKey;
    return HCF_SUCCESS;
}

static HcfResult PackAndAssignPriKey(const HcfAsyKeyGeneratorSpiOpensslSm2Impl *impl, const char *fieldType,
    EC_KEY *ecKey, HcfPriKey **returnObj)
{
    HcfOpensslSm2PriKey *priKey = NULL;
    HcfResult ret = PackSm2PriKey(impl->curveId, ecKey, fieldType, &priKey);
    if (ret != HCF_SUCCESS) {
        LOGD("[error] Create sm2 priKey failed.");
        return ret;
    }
    *returnObj = (HcfPriKey *)priKey;
    return HCF_SUCCESS;
}

static HcfResult CreateAndAssignKeyPair(const HcfAsyKeyGeneratorSpiOpensslSm2Impl *impl, const char *fieldType,
    EC_KEY *ecKey, HcfKeyPair **returnObj)
{
    EC_KEY *ecPriKey = EC_KEY_dup(ecKey);
    if (ecPriKey == NULL) {
        LOGD("[error] Dup ecKey fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfOpensslSm2PriKey *priKey = NULL;
    HcfResult ret = PackSm2PriKey(impl->curveId, ecPriKey, fieldType, &priKey);
    if (ret != HCF_SUCCESS) {
        LOGD("[error] Create sm2 priKey failed.");
        OpensslEcKeyFree(ecPriKey);
        return ret;
    }
    HcfOpensslSm2PubKey *pubKey = NULL;
    EC_KEY *ecPubKey = EC_KEY_dup(ecKey);
    if (ecPubKey == NULL) {
        LOGD("[error] Dup ecKey fail.");
        HcfObjDestroy(priKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    ret = PackSm2PubKey(impl->curveId, ecPubKey, fieldType, &pubKey);
    if (ret != HCF_SUCCESS) {
        LOGD("[error] Create sm2 pubKey failed.");
        HcfObjDestroy(priKey);
        OpensslEcKeyFree(ecPubKey);
        return ret;
    }

    HcfOpensslSm2KeyPair *returnKeyPair = NULL;
    ret = PackSm2KeyPair(pubKey, priKey, &returnKeyPair);
    if (ret != HCF_SUCCESS) {
        LOGE("Create sm2 keyPair failed.");
        HcfObjDestroy(pubKey);
        HcfObjDestroy(priKey);
    }
    *returnObj = (HcfKeyPair *)returnKeyPair;
    return ret;
}

static HcfResult EngineGenerateKeyPair(HcfAsyKeyGeneratorSpi *self, HcfKeyPair **returnObj)
{
    if ((self == NULL) || (returnObj == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, self->base.getClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }

    HcfAsyKeyGeneratorSpiOpensslSm2Impl *impl = (HcfAsyKeyGeneratorSpiOpensslSm2Impl *)self;
    EC_KEY *ecKey = NULL;
    HcfResult ret = NewEcKeyPair(impl->curveId, &ecKey);
    if (ret == HCF_SUCCESS) {
        ret = CreateAndAssignKeyPair(impl, g_sm2GenerateFieldType, ecKey, returnObj);
        if (ret != HCF_SUCCESS) {
            LOGD("[error] CreateAndAssignKeyPair failed.");
        }
        OpensslEcKeyFree(ecKey);
    }
    return ret;
}

static HcfResult EngineGenerateKeyPairBySpec(const HcfAsyKeyGeneratorSpi *self, const HcfAsyKeyParamsSpec *params,
    HcfKeyPair **returnKeyPair)
{
    if ((self == NULL) || (returnKeyPair == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetSm2KeyPairGeneratorClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }

    HcfAsyKeyGeneratorSpiOpensslSm2Impl *impl = (HcfAsyKeyGeneratorSpiOpensslSm2Impl *)self;
    EC_KEY *ecKey = NULL;
    HcfResult ret = GenKeyPairSm2KeyBySpec(params, &ecKey);
    if (ret != HCF_SUCCESS) {
        LOGD("[error] Gen ec key pair with spec failed.");
        return ret;
    }

    // curveId == 0 means no curve to match.
    int32_t curveId = (int32_t)OpensslEcGroupGetCurveName(OpensslEcKeyGet0Group(ecKey));
    if (curveId != 0) {
        impl->curveId = curveId;
    }
    // deep copy of ecKey, free ecKey whether it succeed or failed.
    ret = CreateAndAssignKeyPair(impl, ((HcfEccCommParamsSpec *)params)->field->fieldType, ecKey, returnKeyPair);
    OpensslEcKeyFree(ecKey);
    if (ret != HCF_SUCCESS) {
        LOGD("[error] CreateAndAssignKeyPair failed.");
        return ret;
    }
    return HCF_SUCCESS;
}

static HcfResult EngineGeneratePubKeyBySpec(const HcfAsyKeyGeneratorSpi *self, const HcfAsyKeyParamsSpec *params,
    HcfPubKey **returnPubKey)
{
    if ((self == NULL) || (returnPubKey == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetSm2KeyPairGeneratorClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }

    HcfAsyKeyGeneratorSpiOpensslSm2Impl *impl = (HcfAsyKeyGeneratorSpiOpensslSm2Impl *)self;
    EC_KEY *ecKey = NULL;
    HcfResult ret = GenPubKeySm2KeyBySpec(params, &ecKey);
    if (ret != HCF_SUCCESS) {
        LOGD("[error] Gen ec pubKey with spec failed.");
        return ret;
    }
    int32_t curveId = (int32_t)OpensslEcGroupGetCurveName(OpensslEcKeyGet0Group(ecKey));
    if (curveId != 0) {
        impl->curveId = curveId;
    }
    ret = PackAndAssignPubKey(impl, ((HcfEccCommParamsSpec *)params)->field->fieldType, ecKey, returnPubKey);
    if (ret != HCF_SUCCESS) {
        LOGD("[error] PackAndAssignPubKey failed.");
        OpensslEcKeyFree(ecKey);
        return ret;
    }
    return HCF_SUCCESS;
}

static HcfResult EngineGeneratePriKeyBySpec(const HcfAsyKeyGeneratorSpi *self, const HcfAsyKeyParamsSpec *params,
    HcfPriKey **returnPriKey)
{
    if ((self == NULL) || (returnPriKey == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetSm2KeyPairGeneratorClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }

    HcfAsyKeyGeneratorSpiOpensslSm2Impl *impl = (HcfAsyKeyGeneratorSpiOpensslSm2Impl *)self;
    EC_KEY *ecKey = NULL;
    HcfResult ret = GenPriKeySm2KeyBySpec(params, &ecKey);
    if (ret != HCF_SUCCESS) {
        LOGD("[error] Gen ec priKey with spec failed.");
        return ret;
    }

    int32_t curveId = (int32_t)OpensslEcGroupGetCurveName(OpensslEcKeyGet0Group(ecKey));
    if (curveId != 0) {
        impl->curveId = curveId;
    }

    ret = PackAndAssignPriKey(impl, ((HcfEccCommParamsSpec *)params)->field->fieldType, ecKey, returnPriKey);
    if (ret != HCF_SUCCESS) {
        LOGD("[error] PackAndAssignPriKey failed.");
        OpensslEcKeyFree(ecKey);
        return ret;
    }
    return HCF_SUCCESS;
}

HcfResult HcfAsyKeyGeneratorSpiSm2Create(HcfAsyKeyGenParams *params, HcfAsyKeyGeneratorSpi **returnObj)
{
    if (params == NULL || returnObj == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    int32_t curveId = 0;
    if (params->bits != 0) {
        if (GetOpensslCurveId(params->bits, &curveId) != HCF_SUCCESS) {
            LOGE("Get curve id failed.");
            return HCF_INVALID_PARAMS;
        }
    }

    HcfAsyKeyGeneratorSpiOpensslSm2Impl *returnImpl = (HcfAsyKeyGeneratorSpiOpensslSm2Impl *)HcfMalloc(
        sizeof(HcfAsyKeyGeneratorSpiOpensslSm2Impl), 0);
    if (returnImpl == NULL) {
        LOGE("Failed to allocate returnImpl memroy!");
        return HCF_ERR_MALLOC;
    }
    returnImpl->base.base.getClass = GetSm2KeyPairGeneratorClass;
    returnImpl->base.base.destroy = DestroySm2KeyPairGenerator;
    returnImpl->base.engineConvertKey = EngineConvertSm2Key;
    returnImpl->base.engineGenerateKeyPair = EngineGenerateKeyPair;
    returnImpl->base.engineGenerateKeyPairBySpec = EngineGenerateKeyPairBySpec;
    returnImpl->base.engineGeneratePubKeyBySpec = EngineGeneratePubKeyBySpec;
    returnImpl->base.engineGeneratePriKeyBySpec = EngineGeneratePriKeyBySpec;
    returnImpl->curveId = curveId;

    *returnObj = (HcfAsyKeyGeneratorSpi *)returnImpl;
    return HCF_SUCCESS;
}

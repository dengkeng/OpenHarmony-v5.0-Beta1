/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

#include "napi_utils.h"
#include "params_parser.h"
#include "log.h"
#include "memory.h"
#include "securec.h"
#include "napi_crypto_framework_defines.h"
#include "detailed_iv_params.h"
#include "detailed_gcm_params.h"
#include "detailed_ccm_params.h"
#include "detailed_dsa_key_params.h"
#include "detailed_ecc_key_params.h"
#include "detailed_rsa_key_params.h"
#include "detailed_alg_25519_key_params.h"
#include "detailed_dh_key_params.h"
#include "utils.h"

namespace OHOS {
namespace CryptoFramework {
using namespace std;

struct AsyKeySpecItemRelationT {
    AsyKeySpecItem item;
    int32_t itemType;
};
using AsyKeySpecItemRelation = AsyKeySpecItemRelationT;

static const AsyKeySpecItemRelation ASY_KEY_SPEC_RELATION_SET[] = {
    { DSA_P_BN, SPEC_ITEM_TYPE_BIG_INT },
    { DSA_Q_BN, SPEC_ITEM_TYPE_BIG_INT },
    { DSA_G_BN, SPEC_ITEM_TYPE_BIG_INT },
    { DSA_SK_BN, SPEC_ITEM_TYPE_BIG_INT },
    { DSA_PK_BN, SPEC_ITEM_TYPE_BIG_INT },

    { ECC_FP_P_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ECC_A_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ECC_B_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ECC_G_X_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ECC_G_Y_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ECC_N_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ECC_H_INT, SPEC_ITEM_TYPE_NUM },  // warning: ECC_H_NUM in JS
    { ECC_SK_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ECC_PK_X_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ECC_PK_Y_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ECC_FIELD_TYPE_STR, SPEC_ITEM_TYPE_STR },
    { ECC_FIELD_SIZE_INT, SPEC_ITEM_TYPE_NUM },  // warning: ECC_FIELD_SIZE_NUM in JS
    { ECC_CURVE_NAME_STR, SPEC_ITEM_TYPE_STR },

    { RSA_N_BN, SPEC_ITEM_TYPE_BIG_INT },
    { RSA_SK_BN, SPEC_ITEM_TYPE_BIG_INT },
    { RSA_PK_BN, SPEC_ITEM_TYPE_BIG_INT },
    { DH_P_BN, SPEC_ITEM_TYPE_BIG_INT },
    { DH_G_BN, SPEC_ITEM_TYPE_BIG_INT },
    { DH_L_NUM, SPEC_ITEM_TYPE_NUM },
    { DH_PK_BN, SPEC_ITEM_TYPE_BIG_INT },
    { DH_SK_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ED25519_SK_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ED25519_PK_BN, SPEC_ITEM_TYPE_BIG_INT },
    { X25519_SK_BN, SPEC_ITEM_TYPE_BIG_INT },
    { X25519_PK_BN, SPEC_ITEM_TYPE_BIG_INT },
};

int32_t GetAsyKeySpecType(AsyKeySpecItem targetItemType)
{
    for (uint32_t i = 0; i < sizeof(ASY_KEY_SPEC_RELATION_SET) / sizeof(AsyKeySpecItemRelation); i++) {
        if (ASY_KEY_SPEC_RELATION_SET[i].item == targetItemType) {
            return ASY_KEY_SPEC_RELATION_SET[i].itemType;
        }
    }
    LOGE("AsyKeySpecItem not support! ItemType: %d", targetItemType);
    return -1;
}

int32_t GetSignSpecType(SignSpecItem targetItemType)
{
    if (targetItemType == PSS_MD_NAME_STR || targetItemType == PSS_MGF_NAME_STR ||
        targetItemType == PSS_MGF1_MD_STR) {
        return SPEC_ITEM_TYPE_STR;
    }
    if (targetItemType == SM2_USER_ID_UINT8ARR) {
        return SPEC_ITEM_TYPE_UINT8ARR;
    }
    if (targetItemType == PSS_SALT_LEN_INT || targetItemType == PSS_TRAILER_FIELD_INT) {
        return SPEC_ITEM_TYPE_NUM;
    }
    LOGE("SignSpecItem not support! ItemType: %d", targetItemType);
    return -1;
}

int32_t GetCipherSpecType(CipherSpecItem targetItemType)
{
    if (targetItemType == OAEP_MD_NAME_STR || targetItemType == OAEP_MGF_NAME_STR ||
        targetItemType == OAEP_MGF1_MD_STR || targetItemType == SM2_MD_NAME_STR) {
        return SPEC_ITEM_TYPE_STR;
    }
    if (targetItemType == OAEP_MGF1_PSRC_UINT8ARR) {
        return SPEC_ITEM_TYPE_UINT8ARR;
    }
    LOGE("CipherSpecItem not support! ItemType: %d", targetItemType);
    return -1;
}

napi_value NapiGetNull(napi_env env)
{
    napi_value result = nullptr;
    napi_get_null(env, &result);
    return result;
}

static napi_value GetUint8ArrFromNapiDataBlob(napi_env env, napi_value arg)
{
    if ((env == nullptr) || (arg == nullptr)) {
        LOGE("Invalid params!");
        return nullptr;
    }
    napi_value data = nullptr;
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_get_named_property(env, arg, CRYPTO_TAG_DATA.c_str(), &data);
    napi_typeof(env, data, &valueType);
    if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid data property!");
        return nullptr;
    }
    return data;
}

HcfBlob *GetBlobFromNapiUint8Arr(napi_env env, napi_value data)
{
    size_t length = 0;
    size_t offset = 0;
    void *rawData = nullptr;
    napi_value arrayBuffer = nullptr;
    napi_typedarray_type arrayType;
    // Warning: Do not release the rawData returned by this interface because the rawData is managed by VM.
    napi_status status = napi_get_typedarray_info(env, data, &arrayType, &length,
        reinterpret_cast<void **>(&rawData), &arrayBuffer, &offset);
    if ((status != napi_ok)) {
        LOGE("failed to get valid rawData.");
        return nullptr;
    }
    if (arrayType != napi_uint8_array) {
        LOGE("input data is not uint8 array.");
        return nullptr;
    }

    HcfBlob *newBlob = reinterpret_cast<HcfBlob *>(HcfMalloc(sizeof(HcfBlob), 0));
    if (newBlob == nullptr) {
        LOGE("Failed to allocate newBlob memory!");
        return nullptr;
    }

    // input empty uint8Arr, ex: new Uint8Arr(), the length is 0 and rawData is nullptr;
    if ((length == 0) || (rawData == nullptr)) {
        newBlob->len = 0;
        newBlob->data = nullptr;
        LOGD("napi Uint8Arr is null");
        return newBlob;
    }
    newBlob->len = length;
    newBlob->data = static_cast<uint8_t *>(HcfMalloc(length, 0));
    if (newBlob->data == nullptr) {
        LOGE("malloc blob data failed!");
        HcfFree(newBlob);
        return nullptr;
    }
    (void)memcpy_s(newBlob->data, length, rawData, length);
    return newBlob;
}

HcfBlob *GetBlobFromNapiDataBlob(napi_env env, napi_value arg)
{
    napi_value data = GetUint8ArrFromNapiDataBlob(env, arg);
    if (data == nullptr) {
        LOGE("failed to get data in DataBlob");
        return nullptr;
    }
    return GetBlobFromNapiUint8Arr(env, data);
}

HcfResult GetBlobFromNapiValue(napi_env env, napi_value arg, HcfBlob *blob)
{
    napi_value data = GetUint8ArrFromNapiDataBlob(env, arg);
    if (data == nullptr) {
        LOGE("failed to get data in DataBlob");
        return HCF_INVALID_PARAMS;
    }

    void *rawData = nullptr;
    napi_typedarray_type arrayType;
    napi_status status = napi_get_typedarray_info(env, data, &arrayType, &(blob->len),
        reinterpret_cast<void **>(&rawData), nullptr, nullptr);
    if (status != napi_ok) {
        LOGE("failed to get valid rawData.");
        return HCF_ERR_NAPI;
    }
    if (arrayType != napi_uint8_array) {
        LOGE("input data is not uint8 array.");
        return HCF_INVALID_PARAMS;
    }

    blob->data = nullptr;
    if (blob->len == 0 || rawData == nullptr) {
        LOGD("napi Uint8Arr is null");
        return HCF_SUCCESS;
    }

    blob->data = static_cast<uint8_t *>(HcfMalloc(blob->len, 0));
    if (blob->data == nullptr) {
        LOGE("malloc blob data failed!");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(blob->data, blob->len, rawData, blob->len);
    return HCF_SUCCESS;
}

static HcfBlob *GetAadFromParamsSpec(napi_env env, napi_value arg)
{
    napi_value data = nullptr;
    HcfBlob *blob = nullptr;
    napi_valuetype valueType = napi_undefined;

    napi_status status = napi_get_named_property(env, arg, AAD_PARAMS.c_str(), &data);
    napi_typeof(env, data, &valueType);
    if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid param property!");
        return nullptr;
    }
    if (valueType == napi_null) {
        blob = reinterpret_cast<HcfBlob *>(HcfMalloc(sizeof(HcfBlob), 0));
        if (blob == nullptr) {
            LOGE("Failed to allocate newBlob memory!");
            return nullptr;
        }
        blob->data = nullptr;
        blob->len = 0;
        LOGD("Input GCM Aad is Null");
        return blob;
    }
    blob = GetBlobFromNapiDataBlob(env, data);
    if (blob == nullptr) {
        LOGE("GetBlobFromNapiDataBlob failed!");
        return nullptr;
    }
    return blob;
}

bool GetBigIntFromNapiValue(napi_env env, napi_value arg, HcfBigInteger *bigInt)
{
    if ((env == nullptr) || (arg == nullptr) || (bigInt == nullptr)) {
        LOGE("Invalid params!");
        return false;
    }

    int signBit;
    size_t wordCount;

    napi_get_value_bigint_words(env, arg, nullptr, &wordCount, nullptr);
    if ((wordCount == 0) || (wordCount > (INT_MAX / sizeof(uint64_t)))) {
        LOGE("Get big int failed.");
        return false;
    }
    int length = wordCount * sizeof(uint64_t);
    uint8_t *retArr = reinterpret_cast<uint8_t *>(HcfMalloc(length, 0));
    if (retArr == nullptr) {
        LOGE("malloc blob data failed!");
        return false;
    }
    if (napi_get_value_bigint_words(env, arg, &signBit, &wordCount, reinterpret_cast<uint64_t *>(retArr)) != napi_ok) {
        HcfFree(retArr);
        LOGE("failed to get valid rawData.");
        return false;
    }
    if (signBit != 0) {
        HcfFree(retArr);
        LOGE("failed to get gegative rawData.");
        return false;
    }
    bigInt->data = retArr;
    bigInt->len = length;
    return true;
}

bool GetPointFromNapiValue(napi_env env, napi_value arg, HcfPoint *point)
{
    if ((env == nullptr) || (arg == nullptr) || (point == nullptr)) {
        LOGE("Invalid params!");
        return false;
    }
    napi_value dataX = nullptr;
    napi_value dataY = nullptr;
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_get_named_property(env, arg, "x", &dataX);
    napi_typeof(env, dataX, &valueType);
    if ((status != napi_ok) || (dataX == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid algo name!");
        return false;
    }
    status = napi_get_named_property(env, arg, "y", &dataY);
    napi_typeof(env, dataY, &valueType);
    if ((status != napi_ok) || (dataY == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid algo name!");
        return false;
    }

    bool ret = GetBigIntFromNapiValue(env, dataX, &point->x);
    if (!ret) {
        LOGE("get point x failed!");
        return false;
    }
    ret = GetBigIntFromNapiValue(env, dataY, &point->y);
    if (!ret) {
        LOGE("get point y failed!");
        HcfFree((point->x).data);
        (point->x).data = nullptr;
        return false;
    }
    return true;
}

static const char *GetIvParamsSpecType()
{
    return IV_PARAMS_SPEC.c_str();
}

static const char *GetGcmParamsSpecType()
{
    return GCM_PARAMS_SPEC.c_str();
}

static const char *GetCcmParamsSpecType()
{
    return CCM_PARAMS_SPEC.c_str();
}

static HcfBlob *GetBlobFromParamsSpec(napi_env env, napi_value arg, const string &type)
{
    napi_value data = nullptr;
    HcfBlob *blob = nullptr;
    napi_valuetype valueType = napi_undefined;

    napi_status status = napi_get_named_property(env, arg, type.c_str(), &data);
    napi_typeof(env, data, &valueType);
    if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid param property!");
        return nullptr;
    }
    blob = GetBlobFromNapiDataBlob(env, data);
    if (blob == nullptr) {
        LOGE("GetBlobFromNapiDataBlob failed!");
        return nullptr;
    }
    return blob;
}

static bool GetIvParamsSpec(napi_env env, napi_value arg, HcfParamsSpec **paramsSpec)
{
    HcfIvParamsSpec *ivParamsSpec = reinterpret_cast<HcfIvParamsSpec *>(HcfMalloc(sizeof(HcfIvParamsSpec), 0));
    if (ivParamsSpec == nullptr) {
        LOGE("ivParamsSpec malloc failed!");
        return false;
    }

    HcfBlob *iv = GetBlobFromParamsSpec(env, arg, IV_PARAMS);
    if (iv == nullptr) {
        LOGE("GetBlobFromNapiDataBlob failed!");
        HcfFree(ivParamsSpec);
        return false;
    }
    ivParamsSpec->base.getType = GetIvParamsSpecType;
    ivParamsSpec->iv = *iv;
    *paramsSpec = reinterpret_cast<HcfParamsSpec *>(ivParamsSpec);
    HcfFree(iv);
    return true;
}

static bool GetIvAndAadBlob(napi_env env, napi_value arg, HcfBlob **iv, HcfBlob **aad)
{
    *iv = GetBlobFromParamsSpec(env, arg, IV_PARAMS);
    if (*iv == nullptr) {
        LOGE("get iv failed!");
        return false;
    }

    *aad = GetAadFromParamsSpec(env, arg);
    // error case free is in get paramspec func.
    if (*aad == nullptr) {
        LOGE("get aad failed!");
        return false;
    }
    return true;
}

static bool GetGcmParamsSpec(napi_env env, napi_value arg, HcfCryptoMode opMode, HcfParamsSpec **paramsSpec)
{
    HcfBlob *iv = nullptr;
    HcfBlob *aad = nullptr;
    HcfBlob *tag = nullptr;
    HcfBlob authTag = {};
    bool ret = false;

    HcfGcmParamsSpec *gcmParamsSpec = reinterpret_cast<HcfGcmParamsSpec *>(HcfMalloc(sizeof(HcfGcmParamsSpec), 0));
    if (gcmParamsSpec == nullptr) {
        LOGE("gcmParamsSpec malloc failed!");
        return false;
    }

    ret = GetIvAndAadBlob(env, arg, &iv, &aad);
    if (!ret) {
        LOGE("GetIvAndAadBlob failed!");
        goto clearup;
    }

    if (opMode == DECRYPT_MODE) {
        tag = GetBlobFromParamsSpec(env, arg, AUTHTAG_PARAMS);
        if (tag == nullptr) {
            LOGE("get tag failed!");
            goto clearup;
        }
    } else if (opMode == ENCRYPT_MODE) {
        authTag.data = static_cast<uint8_t *>(HcfMalloc(GCM_AUTH_TAG_LEN, 0));
        if (authTag.data == nullptr) {
            LOGE("get tag failed!");
            goto clearup;
        }
        authTag.len = GCM_AUTH_TAG_LEN;
    } else {
        goto clearup;
    }

    gcmParamsSpec->base.getType = GetGcmParamsSpecType;
    gcmParamsSpec->iv = *iv;
    gcmParamsSpec->aad = *aad;
    gcmParamsSpec->tag = opMode == DECRYPT_MODE ? *tag : authTag;
    *paramsSpec = reinterpret_cast<HcfParamsSpec *>(gcmParamsSpec);
    ret = true;
clearup:
   if (!ret) {
        HcfBlobDataFree(iv);
        HcfBlobDataFree(aad);
        HcfBlobDataFree(tag);
        HcfFree(gcmParamsSpec);
    }
    HcfFree(iv);
    HcfFree(aad);
    HcfFree(tag);
    return ret;
}

static bool GetCcmParamsSpec(napi_env env, napi_value arg, HcfCryptoMode opMode, HcfParamsSpec **paramsSpec)
{
    HcfBlob *iv = nullptr;
    HcfBlob *aad = nullptr;
    HcfBlob *tag = nullptr;
    HcfBlob authTag = {};
    bool ret = false;

    HcfCcmParamsSpec *ccmParamsSpec = reinterpret_cast<HcfCcmParamsSpec *>(HcfMalloc(sizeof(HcfCcmParamsSpec), 0));
    if (ccmParamsSpec == nullptr) {
        LOGE("ccmParamsSpec malloc failed!");
        return ret;
    }
    ret = GetIvAndAadBlob(env, arg, &iv, &aad);
    if (!ret) {
        LOGE("GetIvAndAadBlob failed!");
        goto clearup;
    }

    if (opMode == DECRYPT_MODE) {
        tag = GetBlobFromParamsSpec(env, arg, AUTHTAG_PARAMS);
        if (tag == nullptr) {
            LOGE("get tag failed!");
            goto clearup;
        }
    } else if (opMode == ENCRYPT_MODE) {
        authTag.data = static_cast<uint8_t *>(HcfMalloc(CCM_AUTH_TAG_LEN, 0));
        if (authTag.data == nullptr) {
            LOGE("get tag failed!");
            goto clearup;
        }
        authTag.len = CCM_AUTH_TAG_LEN;
    } else {
        goto clearup;
    }
    ccmParamsSpec->base.getType = GetCcmParamsSpecType;
    ccmParamsSpec->iv = *iv;
    ccmParamsSpec->aad = *aad;
    ccmParamsSpec->tag = opMode == DECRYPT_MODE ? *tag : authTag;
    *paramsSpec = reinterpret_cast<HcfParamsSpec *>(ccmParamsSpec);
    ret = true;
clearup:
    if (!ret) {
        HcfBlobDataFree(iv);
        HcfBlobDataFree(aad);
        HcfBlobDataFree(tag);
        HcfFree(ccmParamsSpec);
    }
    HcfFree(iv);
    HcfFree(aad);
    HcfFree(tag);
    return ret;
}

bool GetParamsSpecFromNapiValue(napi_env env, napi_value arg, HcfCryptoMode opMode, HcfParamsSpec **paramsSpec)
{
    napi_value data = nullptr;
    napi_valuetype valueType = napi_undefined;
    if ((env == nullptr) || (arg == nullptr) || (paramsSpec == nullptr)) {
        LOGE("Invalid params!");
        return false;
    }

    napi_status status = napi_get_named_property(env, arg, ALGO_PARAMS.c_str(), &data);
    napi_typeof(env, data, &valueType);
    if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
        status = napi_get_named_property(env, arg, ALGO_PARAMS_OLD.c_str(), &data);
        napi_typeof(env, data, &valueType);
        if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
            LOGE("failed to get valid algo name!");
            return false;
        }
    }
    string algoName;
    if (!GetStringFromJSParams(env, data, algoName)) {
        LOGE("GetStringFromJSParams failed!");
        return false;
    }
    if (algoName.compare(IV_PARAMS_SPEC) == 0) {
        return GetIvParamsSpec(env, arg, paramsSpec);
    } else if (algoName.compare(GCM_PARAMS_SPEC) == 0) {
        return GetGcmParamsSpec(env, arg, opMode, paramsSpec);
    } else if (algoName.compare(CCM_PARAMS_SPEC) == 0) {
        return GetCcmParamsSpec(env, arg, opMode, paramsSpec);
    } else {
        return false;
    }
}

napi_value GetDetailAsyKeySpecValue(napi_env env, napi_value arg, string argName)
{
    napi_value data = nullptr;
    napi_valuetype valueType = napi_undefined;
    if ((env == nullptr) || (arg == nullptr)) {
        LOGE("Invalid params!");
        return nullptr;
    }
    napi_status status = napi_get_named_property(env, arg, argName.c_str(), &data);
    napi_typeof(env, data, &valueType);
    if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid algo name!");
        return nullptr;
    }
    return data;
}

static napi_value GetCommSpecNapiValue(napi_env env, napi_value arg)
{
    napi_value data = nullptr;
    napi_valuetype valueType = napi_undefined;

    napi_status status = napi_get_named_property(env, arg, CRYPTO_TAG_COMM_PARAMS.c_str(), &data);
    napi_typeof(env, data, &valueType);

    if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid algo name!");
        return nullptr;
    }
    return data;
}

static bool InitDsaCommonAsyKeySpec(napi_env env, napi_value arg, HcfDsaCommParamsSpec *spec)
{
    size_t algNameLen = DSA_ASY_KEY_SPEC.length();
    spec->base.algName = static_cast<char *>(HcfMalloc(algNameLen + 1, 0));
    if (spec->base.algName == nullptr) {
        LOGE("malloc DSA algName failed!");
        return false;
    }
    (void)memcpy_s(spec->base.algName, algNameLen+ 1, DSA_ASY_KEY_SPEC.c_str(), algNameLen);
    spec->base.specType = HCF_COMMON_PARAMS_SPEC;

    napi_value p = GetDetailAsyKeySpecValue(env, arg, "p");
    napi_value q = GetDetailAsyKeySpecValue(env, arg, "q");
    napi_value g = GetDetailAsyKeySpecValue(env, arg, "g");
    bool ret = GetBigIntFromNapiValue(env, p, &spec->p);
    if (!ret) {
        HcfFree(spec->base.algName);
        spec->base.algName = nullptr;
        return false;
    }
    ret = GetBigIntFromNapiValue(env, q, &spec->q);
    if (!ret) {
        FreeDsaCommParamsSpec(spec);
        return false;
    }
    ret = GetBigIntFromNapiValue(env, g, &spec->g);
    if (!ret) {
        FreeDsaCommParamsSpec(spec);
        return false;
    }
    return true;
}

static bool GetDsaCommonAsyKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec)
{
    HcfDsaCommParamsSpec *spec = reinterpret_cast<HcfDsaCommParamsSpec *>(HcfMalloc(sizeof(HcfDsaCommParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }
    if (!InitDsaCommonAsyKeySpec(env, arg, spec)) {
        LOGE("InitDsaCommonAsyKeySpec failed!");
        HcfFree(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetDsaPubKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec)
{
    HcfDsaPubKeyParamsSpec *spec = reinterpret_cast<HcfDsaPubKeyParamsSpec *>(
        HcfMalloc(sizeof(HcfDsaPubKeyParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }

    napi_value commSpecValue = GetCommSpecNapiValue(env, arg);
    if (commSpecValue == nullptr) {
        LOGE("Get comm spec napi value failed.");
        HcfFree(spec);
        return false;
    }
    if (!InitDsaCommonAsyKeySpec(env, commSpecValue, reinterpret_cast<HcfDsaCommParamsSpec *>(spec))) {
        LOGE("InitDsaCommonAsyKeySpec failed.");
        HcfFree(spec);
        return false;
    }
    spec->base.base.specType = HCF_PUBLIC_KEY_SPEC;

    napi_value pk = GetDetailAsyKeySpecValue(env, arg, "pk");
    bool ret = GetBigIntFromNapiValue(env, pk, &spec->pk);
    if (!ret) {
        DestroyDsaPubKeySpec(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetDsaKeyPairAsyKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec)
{
    HcfDsaKeyPairParamsSpec *spec = reinterpret_cast<HcfDsaKeyPairParamsSpec *>(
        HcfMalloc(sizeof(HcfDsaKeyPairParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }

    napi_value commSpecValue = GetCommSpecNapiValue(env, arg);
    if (commSpecValue == nullptr) {
        LOGE("Get comm spec napi value failed.");
        HcfFree(spec);
        return false;
    }
    if (!InitDsaCommonAsyKeySpec(env, commSpecValue, reinterpret_cast<HcfDsaCommParamsSpec *>(spec))) {
        LOGE("InitDsaCommonAsyKeySpec failed!");
        HcfFree(spec);
        return false;
    }
    spec->base.base.specType = HCF_KEY_PAIR_SPEC;

    napi_value pk = GetDetailAsyKeySpecValue(env, arg, "pk");
    bool ret = GetBigIntFromNapiValue(env, pk, &spec->pk);
    if (!ret) {
        FreeDsaCommParamsSpec(reinterpret_cast<HcfDsaCommParamsSpec *>(spec));
        HcfFree(spec);
        return false;
    }
    napi_value sk = GetDetailAsyKeySpecValue(env, arg, "sk");
    ret = GetBigIntFromNapiValue(env, sk, &spec->sk);
    if (!ret) {
        FreeDsaCommParamsSpec(reinterpret_cast<HcfDsaCommParamsSpec *>(spec));
        HcfFree(spec->pk.data);
        HcfFree(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetDsaAsyKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec)
{
    napi_value data = nullptr;
    napi_valuetype valueType = napi_undefined;

    napi_status status = napi_get_named_property(env, arg, TAG_SPEC_TYPE.c_str(), &data);
    napi_typeof(env, data, &valueType);
    if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid algo name!");
        return false;
    }
    HcfAsyKeySpecType asyKeySpecType;
    status = napi_get_value_uint32(env, data, reinterpret_cast<uint32_t *>(&asyKeySpecType));
    if (status != napi_ok) {
        LOGE("failed to get valid asyKeySpecType!");
        return false;
    }
    if (asyKeySpecType == HCF_COMMON_PARAMS_SPEC) {
        return GetDsaCommonAsyKeySpec(env, arg, asyKeySpec);
    } else if (asyKeySpecType == HCF_PUBLIC_KEY_SPEC) {
        return GetDsaPubKeySpec(env, arg, asyKeySpec);
    } else if (asyKeySpecType == HCF_KEY_PAIR_SPEC) {
        return GetDsaKeyPairAsyKeySpec(env, arg, asyKeySpec);
    } else {
        return false;
    }
}

static bool GetFpField(napi_env env, napi_value arg, HcfECField **ecField)
{
    HcfECFieldFp *fp = reinterpret_cast<HcfECFieldFp *>(HcfMalloc(sizeof(HcfECFieldFp), 0));
    if (fp == nullptr) {
        LOGE("malloc fp failed!");
        return false;
    }

    size_t fieldTpyeLen = ECC_FIELD_TYPE_FP.length();
    fp->base.fieldType = static_cast<char *>(HcfMalloc(fieldTpyeLen + 1, 0));
    if (fp->base.fieldType == nullptr) {
        LOGE("malloc fieldType failed!");
        HcfFree(fp);
        return false;
    }
    (void)memcpy_s(fp->base.fieldType, fieldTpyeLen+ 1, ECC_FIELD_TYPE_FP.c_str(), fieldTpyeLen);

    napi_value p = GetDetailAsyKeySpecValue(env, arg, "p");
    bool ret = GetBigIntFromNapiValue(env, p, &fp->p);
    if (!ret) {
        HcfFree(fp->base.fieldType);
        HcfFree(fp);
        return false;
    }
    *ecField = reinterpret_cast<HcfECField *>(fp);
    return true;
}

static bool GetField(napi_env env, napi_value arg, HcfECField **ecField)
{
    // get fieldData in { field : fieldData, a : xxx, b : xxx, ... } of ECCCommonParamsSpec first
    napi_value fieldData = nullptr;
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_get_named_property(env, arg, "field", &fieldData);
    napi_typeof(env, fieldData, &valueType);
    if ((status != napi_ok) || (fieldData == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid field data!");
        return false;
    }

    // get fieldType in { fieldType : fieldTypeData } of ECField
    napi_value fieldTypeData = nullptr;
    status = napi_get_named_property(env, fieldData, "fieldType", &fieldTypeData);
    napi_typeof(env, fieldTypeData, &valueType);
    if ((status != napi_ok) || (fieldTypeData == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid fieldType data!");
        return false;
    }
    string fieldType;
    if (!GetStringFromJSParams(env, fieldTypeData, fieldType)) {
        LOGE("GetStringFromJSParams failed when extracting fieldType!");
        return false;
    }

    // get p in { p : pData } of ECField, and generateECField
    if (fieldType.compare("Fp") == 0) {
        return GetFpField(env, fieldData, ecField);
    }
    return false;
}

static bool InitEccDetailAsyKeySpec(napi_env env, napi_value arg, HcfEccCommParamsSpec *spec)
{
    napi_value a = GetDetailAsyKeySpecValue(env, arg, "a");
    napi_value b = GetDetailAsyKeySpecValue(env, arg, "b");
    napi_value n = GetDetailAsyKeySpecValue(env, arg, "n");
    napi_value g = GetDetailAsyKeySpecValue(env, arg, "g");
    bool ret = GetBigIntFromNapiValue(env, a, &spec->a);
    if (!ret) {
        LOGE("get ecc asyKeySpec a failed!");
        return false;
    }
    ret = GetBigIntFromNapiValue(env, b, &spec->b);
    if (!ret) {
        LOGE("get ecc asyKeySpec b failed!");
        return false;
    }
    ret = GetBigIntFromNapiValue(env, n, &spec->n);
    if (!ret) {
        LOGE("get ecc asyKeySpec n failed!");
        return false;
    }
    ret = GetPointFromNapiValue(env, g, &spec->g);
    if (!ret) {
        LOGE("get ecc asyKeySpec g failed!");
        return false;
    }
    return true;
}

static bool InitEccCommonAsyKeySpec(napi_env env, napi_value arg, HcfEccCommParamsSpec *spec, const string &algName)
{
    size_t algNameLen = ECC_ASY_KEY_SPEC.length();
    spec->base.algName = static_cast<char *>(HcfMalloc(algNameLen + 1, 0));
    if (spec->base.algName == nullptr) {
        LOGE("malloc ECC algName failed!");
        return false;
    }
    (void)memcpy_s(spec->base.algName, algNameLen+ 1, algName.c_str(), algNameLen);
    spec->base.specType = HCF_COMMON_PARAMS_SPEC;

    // get h
    napi_value hData = nullptr;
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_get_named_property(env, arg, "h", &hData);
    napi_typeof(env, hData, &valueType);
    if ((status != napi_ok) || (hData == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid h!");
        HcfFree(spec->base.algName);
        spec->base.algName = nullptr;
        return false;
    }
    if (!GetInt32FromJSParams(env, hData, spec->h)) {
        LOGE("get ecc asyKeySpec h failed!");
        HcfFree(spec->base.algName);
        spec->base.algName = nullptr;
        return false;
    }
    // get field
    if (!GetField(env, arg, &spec->field)) {
        LOGE("GetField failed!");
        HcfFree(spec->base.algName);
        spec->base.algName = nullptr;
        return false;
    }
    bool ret = InitEccDetailAsyKeySpec(env, arg, spec);
    if (!ret) {
        LOGE("get ecc asyKeySpec g failed!");
        FreeEccCommParamsSpec(spec);
        return false;
    }
    return true;
}

static bool GetEccCommonAsyKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec,
    const string &algName)
{
    HcfEccCommParamsSpec *spec = reinterpret_cast<HcfEccCommParamsSpec *>(HcfMalloc(sizeof(HcfEccCommParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }
    if (!InitEccCommonAsyKeySpec(env, arg, spec, algName)) {
        LOGE("InitEccCommonAsyKeySpec failed!");
        HcfFree(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetEccPriKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec, const string &algName)
{
    HcfEccPriKeyParamsSpec *spec =
        reinterpret_cast<HcfEccPriKeyParamsSpec *>(HcfMalloc(sizeof(HcfEccPriKeyParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }

    napi_value commSpecValue = GetCommSpecNapiValue(env, arg);
    if (commSpecValue == nullptr) {
        LOGE("Get comm spec napi value failed.");
        HcfFree(spec);
        return false;
    }
    if (!InitEccCommonAsyKeySpec(env, commSpecValue, reinterpret_cast<HcfEccCommParamsSpec *>(spec), algName)) {
        LOGE("InitEccCommonAsyKeySpec failed!");
        HcfFree(spec);
        return false;
    }
    spec->base.base.specType = HCF_PRIVATE_KEY_SPEC;

    napi_value sk = GetDetailAsyKeySpecValue(env, arg, "sk");
    bool ret = GetBigIntFromNapiValue(env, sk, &spec->sk);
    if (!ret) {
        // get big int fail, sk is null
        FreeEccCommParamsSpec(reinterpret_cast<HcfEccCommParamsSpec *>(spec));
        HcfFree(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetEccPubKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec, const string &algName)
{
    HcfEccPubKeyParamsSpec *spec =
        reinterpret_cast<HcfEccPubKeyParamsSpec *>(HcfMalloc(sizeof(HcfEccPubKeyParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }

    napi_value commSpecValue = GetCommSpecNapiValue(env, arg);
    if (commSpecValue == nullptr) {
        LOGE("Get comm spec napi value failed.");
        HcfFree(spec);
        return false;
    }
    if (!InitEccCommonAsyKeySpec(env, commSpecValue, reinterpret_cast<HcfEccCommParamsSpec *>(spec), algName)) {
        LOGE("InitEccCommonAsyKeySpec failed!");
        HcfFree(spec);
        return false;
    }
    spec->base.base.specType = HCF_PUBLIC_KEY_SPEC;

    napi_value pk = GetDetailAsyKeySpecValue(env, arg, "pk");
    bool ret = GetPointFromNapiValue(env, pk, &spec->pk);
    if (!ret) {
        DestroyEccPubKeySpec(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetEccKeyPairAsyKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec,
    const string &algName)
{
    HcfEccKeyPairParamsSpec *spec =
        reinterpret_cast<HcfEccKeyPairParamsSpec *>(HcfMalloc(sizeof(HcfEccKeyPairParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }

    napi_value commSpecValue = GetCommSpecNapiValue(env, arg);
    if (commSpecValue == nullptr) {
        LOGE("Get comm spec napi value failed.");
        HcfFree(spec);
        return false;
    }
    if (!InitEccCommonAsyKeySpec(env, commSpecValue, reinterpret_cast<HcfEccCommParamsSpec *>(spec), algName)) {
        LOGE("InitEccCommonAsyKeySpec failed!");
        HcfFree(spec);
        return false;
    }
    spec->base.base.specType = HCF_KEY_PAIR_SPEC;

    // get big int fail, sk is null
    napi_value pk = GetDetailAsyKeySpecValue(env, arg, "pk");
    bool ret = GetPointFromNapiValue(env, pk, &spec->pk);
    if (!ret) {
        FreeEccCommParamsSpec(reinterpret_cast<HcfEccCommParamsSpec *>(spec));
        HcfFree(spec);
        return false;
    }
    napi_value sk = GetDetailAsyKeySpecValue(env, arg, "sk");
    ret = GetBigIntFromNapiValue(env, sk, &spec->sk);
    if (!ret) {
        FreeEccCommParamsSpec(reinterpret_cast<HcfEccCommParamsSpec *>(spec));
        HcfFree(spec->pk.x.data);
        HcfFree(spec->pk.y.data);
        HcfFree(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetEccAsyKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec, const string &algName)
{
    napi_value data = nullptr;
    napi_valuetype valueType = napi_undefined;

    napi_status status = napi_get_named_property(env, arg, TAG_SPEC_TYPE.c_str(), &data);
    napi_typeof(env, data, &valueType);
    if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid algo name!");
        return false;
    }
    HcfAsyKeySpecType asyKeySpecType;
    status = napi_get_value_uint32(env, data, reinterpret_cast<uint32_t *>(&asyKeySpecType));
    if (status != napi_ok) {
        LOGE("failed to get valid asyKeySpecType!");
        return false;
    }
    if (asyKeySpecType == HCF_COMMON_PARAMS_SPEC) {
        return GetEccCommonAsyKeySpec(env, arg, asyKeySpec, algName);
    } else if (asyKeySpecType == HCF_PRIVATE_KEY_SPEC) {
        return GetEccPriKeySpec(env, arg, asyKeySpec, algName);
    } else if (asyKeySpecType == HCF_PUBLIC_KEY_SPEC) {
        return GetEccPubKeySpec(env, arg, asyKeySpec, algName);
    } else if (asyKeySpecType == HCF_KEY_PAIR_SPEC) {
        return GetEccKeyPairAsyKeySpec(env, arg, asyKeySpec, algName);
    } else {
        LOGE("keySpec not support!");
        return false;
    }
}

static bool InitRsaCommonAsyKeySpec(napi_env env, napi_value arg, HcfRsaCommParamsSpec *spec)
{
    size_t algNameLen = RSA_ASY_KEY_SPEC.length();
    spec->base.algName = static_cast<char *>(HcfMalloc(algNameLen + 1, 0));
    if (spec->base.algName == nullptr) {
        LOGE("malloc RSA algName failed!");
        return false;
    }
    (void)memcpy_s(spec->base.algName, algNameLen+ 1, RSA_ASY_KEY_SPEC.c_str(), algNameLen);
    spec->base.specType = HCF_COMMON_PARAMS_SPEC;

    napi_value n = GetDetailAsyKeySpecValue(env, arg, "n");

    bool ret = GetBigIntFromNapiValue(env, n, &spec->n);
    if (!ret) {
        LOGE("Rsa asyKeySpec get n failed!");
        HcfFree(spec->base.algName);
        spec->base.algName = nullptr;
        return false;
    }
    return true;
}

static bool GetRsaPubKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec)
{
    HcfRsaPubKeyParamsSpec *spec =
        reinterpret_cast<HcfRsaPubKeyParamsSpec *>(HcfMalloc(sizeof(HcfRsaPubKeyParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }

    napi_value commSpecValue = GetCommSpecNapiValue(env, arg);
    if (commSpecValue == nullptr) {
        LOGE("Get comm spec napi value failed.");
        HcfFree(spec);
        return false;
    }
    if (!InitRsaCommonAsyKeySpec(env, commSpecValue, reinterpret_cast<HcfRsaCommParamsSpec *>(spec))) {
        LOGE("InitRsaCommonAsyKeySpec failed!");
        HcfFree(spec);
        return false;
    }
    spec->base.base.specType = HCF_PUBLIC_KEY_SPEC;

    napi_value pk = GetDetailAsyKeySpecValue(env, arg, "pk");
    bool ret = GetBigIntFromNapiValue(env, pk, &spec->pk);
    if (!ret) {
        DestroyRsaPubKeySpec(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetRsaKeyPairAsyKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec)
{
    HcfRsaKeyPairParamsSpec *spec =
        reinterpret_cast<HcfRsaKeyPairParamsSpec *>(HcfMalloc(sizeof(HcfRsaKeyPairParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }

    napi_value commSpecValue = GetCommSpecNapiValue(env, arg);
    if (commSpecValue == nullptr) {
        LOGE("Get comm spec napi value failed.");
        HcfFree(spec);
        return false;
    }
    if (!InitRsaCommonAsyKeySpec(env, commSpecValue, reinterpret_cast<HcfRsaCommParamsSpec *>(spec))) {
        LOGE("InitRsaCommonAsyKeySpec failed!");
        HcfFree(spec);
        return false;
    }
    spec->base.base.specType = HCF_KEY_PAIR_SPEC;

    napi_value pk = GetDetailAsyKeySpecValue(env, arg, "pk");
    bool ret = GetBigIntFromNapiValue(env, pk, &spec->pk);
    if (!ret) {
        FreeRsaCommParamsSpec(&(spec->base));
        HcfFree(spec);
        return false;
    }
    napi_value sk = GetDetailAsyKeySpecValue(env, arg, "sk");
    ret = GetBigIntFromNapiValue(env, sk, &spec->sk);
    if (!ret) {
        FreeRsaCommParamsSpec(&(spec->base));
        HcfFree(spec->pk.data);
        HcfFree(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetRsaAsyKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec)
{
    napi_value data = nullptr;
    napi_valuetype valueType = napi_undefined;

    napi_status status = napi_get_named_property(env, arg, TAG_SPEC_TYPE.c_str(), &data);
    napi_typeof(env, data, &valueType);
    if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid algo name!");
        return false;
    }
    HcfAsyKeySpecType asyKeySpecType;
    status = napi_get_value_uint32(env, data, reinterpret_cast<uint32_t *>(&asyKeySpecType));
    if (status != napi_ok) {
        LOGE("failed to get valid asyKeySpecType!");
        return false;
    }
    if (asyKeySpecType == HCF_COMMON_PARAMS_SPEC) {
        LOGE("RSA not support comm key spec");
        return false;
    } else if (asyKeySpecType == HCF_PUBLIC_KEY_SPEC) {
        return GetRsaPubKeySpec(env, arg, asyKeySpec);
    } else if (asyKeySpecType == HCF_KEY_PAIR_SPEC) {
        return GetRsaKeyPairAsyKeySpec(env, arg, asyKeySpec);
    } else {
        return false;
    }
}

static bool InitAlg25519CommonAsyKeySpec(HcfAsyKeyParamsSpec *spec, const string &algName)
{
    size_t algNameLen = algName.length();
    spec->algName = static_cast<char *>(HcfMalloc(algNameLen + 1, 0));
    if (spec->algName == nullptr) {
        LOGE("malloc alg25519 algName failed!");
        return false;
    }
    (void)memcpy_s(spec->algName, algNameLen + 1, algName.c_str(), algNameLen);
    return true;
}

static bool GetAlg25519PriKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec, const string &algName)
{
    HcfAlg25519PriKeyParamsSpec *spec =
        reinterpret_cast<HcfAlg25519PriKeyParamsSpec *>(HcfMalloc(sizeof(HcfAlg25519PriKeyParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }
    if (!InitAlg25519CommonAsyKeySpec(reinterpret_cast<HcfAsyKeyParamsSpec *>(spec), algName)) {
        LOGE("InitRsaCommonAsyKeySpec failed!");
        DestroyAlg25519PriKeySpec(spec);
        return false;
    }
    spec->base.specType = HCF_PRIVATE_KEY_SPEC;

    napi_value sk = GetDetailAsyKeySpecValue(env, arg, "sk");
    bool ret = GetBigIntFromNapiValue(env, sk, &spec->sk);
    if (!ret) {
        // get big int fail, sk is null
        DestroyAlg25519PriKeySpec(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetAlg25519PubKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec, const string &algName)
{
    HcfAlg25519PubKeyParamsSpec *spec =
        reinterpret_cast<HcfAlg25519PubKeyParamsSpec *>(HcfMalloc(sizeof(HcfAlg25519PubKeyParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }
    if (!InitAlg25519CommonAsyKeySpec(reinterpret_cast<HcfAsyKeyParamsSpec *>(spec), algName)) {
        LOGE("InitRsaCommonAsyKeySpec failed!");
        DestroyAlg25519PubKeySpec(spec);
        return false;
    }
    spec->base.specType = HCF_PUBLIC_KEY_SPEC;

    napi_value pk = GetDetailAsyKeySpecValue(env, arg, "pk");
    bool ret = GetBigIntFromNapiValue(env, pk, &spec->pk);
    if (!ret) {
        DestroyAlg25519PubKeySpec(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetAlg25519KeyPairAsyKeySpec(napi_env env, napi_value arg,
    HcfAsyKeyParamsSpec **asyKeySpec, const string &algName)
{
    HcfAlg25519KeyPairParamsSpec *spec =
        reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(HcfMalloc(sizeof(HcfAlg25519KeyPairParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }
    if (!InitAlg25519CommonAsyKeySpec(reinterpret_cast<HcfAsyKeyParamsSpec *>(spec), algName)) {
        LOGE("InitRsaCommonAsyKeySpec failed!");
        HcfFree(spec);
        return false;
    }
    spec->base.specType = HCF_KEY_PAIR_SPEC;

    // get big int fail, sk is null
    napi_value pk = GetDetailAsyKeySpecValue(env, arg, "pk");
    bool ret = GetBigIntFromNapiValue(env, pk, &spec->pk);
    if (!ret) {
        DestroyAlg25519KeyPairSpec(spec);
        return false;
    }
    napi_value sk = GetDetailAsyKeySpecValue(env, arg, "sk");
    ret = GetBigIntFromNapiValue(env, sk, &spec->sk);
    if (!ret) {
        DestroyAlg25519KeyPairSpec(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetAlg25519AsyKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec, const string &algName)
{
    napi_value data = nullptr;
    napi_valuetype valueType = napi_undefined;

    napi_status status = napi_get_named_property(env, arg, TAG_SPEC_TYPE.c_str(), &data);
    napi_typeof(env, data, &valueType);
    if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid algo name!");
        return false;
    }
    HcfAsyKeySpecType asyKeySpecType;
    status = napi_get_value_uint32(env, data, reinterpret_cast<uint32_t *>(&asyKeySpecType));
    if (status != napi_ok) {
        LOGE("failed to get valid asyKeySpecType!");
        return false;
    }
    if (asyKeySpecType == HCF_PRIVATE_KEY_SPEC) {
        return GetAlg25519PriKeySpec(env, arg, asyKeySpec, algName);
    } else if (asyKeySpecType == HCF_PUBLIC_KEY_SPEC) {
        return GetAlg25519PubKeySpec(env, arg, asyKeySpec, algName);
    } else if (asyKeySpecType == HCF_KEY_PAIR_SPEC) {
        return GetAlg25519KeyPairAsyKeySpec(env, arg, asyKeySpec, algName);
    } else {
        LOGE("keySpec not support!");
        return false;
    }
}

static bool InitDhCommonAsyKeySpec(napi_env env, napi_value arg, HcfDhCommParamsSpec *spec)
{
    size_t algNameLen = DH_ASY_KEY_SPEC.length();
    spec->base.algName = static_cast<char *>(HcfMalloc(algNameLen + 1, 0));
    if (spec->base.algName == nullptr) {
        LOGE("malloc DH algName failed!");
        return false;
    }
    (void)memcpy_s(spec->base.algName, algNameLen+ 1, DH_ASY_KEY_SPEC.c_str(), algNameLen);
    spec->base.specType = HCF_COMMON_PARAMS_SPEC;

    napi_value length = nullptr;
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_get_named_property(env, arg, "l", &length);
    napi_typeof(env, length, &valueType);
    if ((status != napi_ok) || (length == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid l!");
        HcfFree(spec->base.algName);
        spec->base.algName = nullptr;
        return false;
    }
    if (!GetInt32FromJSParams(env, length, spec->length)) {
        LOGE("get dh asyKeySpec length failed!");
        HcfFree(spec->base.algName);
        spec->base.algName = nullptr;
        return false;
    }
    napi_value p = GetDetailAsyKeySpecValue(env, arg, "p");
    napi_value g = GetDetailAsyKeySpecValue(env, arg, "g");
    bool ret = GetBigIntFromNapiValue(env, p, &spec->p);
    if (!ret) {
        HcfFree(spec->base.algName);
        spec->base.algName = nullptr;
        return false;
    }
    ret = GetBigIntFromNapiValue(env, g, &spec->g);
    if (!ret) {
        FreeDhCommParamsSpec(spec);
        return false;
    }
    return true;
}

static bool GetDhCommonAsyKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec)
{
    HcfDhCommParamsSpec *spec = reinterpret_cast<HcfDhCommParamsSpec *>(HcfMalloc(sizeof(HcfDhCommParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }
    if (!InitDhCommonAsyKeySpec(env, arg, spec)) {
        LOGE("InitDhCommonAsyKeySpec failed!");
        HcfFree(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetDhPubKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec)
{
    HcfDhPubKeyParamsSpec *spec = reinterpret_cast<HcfDhPubKeyParamsSpec *>(
        HcfMalloc(sizeof(HcfDhPubKeyParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }

    napi_value commSpecValue = GetCommSpecNapiValue(env, arg);
    if (commSpecValue == nullptr) {
        LOGE("Get comm spec napi value failed.");
        HcfFree(spec);
        return false;
    }
    if (!InitDhCommonAsyKeySpec(env, commSpecValue, reinterpret_cast<HcfDhCommParamsSpec *>(spec))) {
        LOGE("InitDhCommonAsyKeySpec failed.");
        HcfFree(spec);
        return false;
    }
    spec->base.base.specType = HCF_PUBLIC_KEY_SPEC;

    napi_value pk = GetDetailAsyKeySpecValue(env, arg, "pk");
    bool ret = GetBigIntFromNapiValue(env, pk, &spec->pk);
    if (!ret) {
        DestroyDhPubKeySpec(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetDhPriKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec)
{
    HcfDhPriKeyParamsSpec *spec = reinterpret_cast<HcfDhPriKeyParamsSpec *>(
        HcfMalloc(sizeof(HcfDhPriKeyParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }

    napi_value commSpecValue = GetCommSpecNapiValue(env, arg);
    if (commSpecValue == nullptr) {
        LOGE("Get comm spec napi value failed.");
        HcfFree(spec);
        return false;
    }
    if (!InitDhCommonAsyKeySpec(env, commSpecValue, reinterpret_cast<HcfDhCommParamsSpec *>(spec))) {
        LOGE("InitDhCommonAsyKeySpec failed.");
        HcfFree(spec);
        return false;
    }
    spec->base.base.specType = HCF_PRIVATE_KEY_SPEC;

    napi_value pk = GetDetailAsyKeySpecValue(env, arg, "sk");
    bool ret = GetBigIntFromNapiValue(env, pk, &spec->sk);
    if (!ret) {
        DestroyDhPriKeySpec(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetDhKeyPairAsyKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec)
{
    HcfDhKeyPairParamsSpec *spec = reinterpret_cast<HcfDhKeyPairParamsSpec *>(
        HcfMalloc(sizeof(HcfDhKeyPairParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }

    napi_value commSpecValue = GetCommSpecNapiValue(env, arg);
    if (commSpecValue == nullptr) {
        LOGE("Get comm spec napi value failed.");
        HcfFree(spec);
        return false;
    }
    if (!InitDhCommonAsyKeySpec(env, commSpecValue, reinterpret_cast<HcfDhCommParamsSpec *>(spec))) {
        LOGE("InitDhCommonAsyKeySpec failed!");
        HcfFree(spec);
        return false;
    }
    spec->base.base.specType = HCF_KEY_PAIR_SPEC;

    napi_value pk = GetDetailAsyKeySpecValue(env, arg, "pk");
    bool ret = GetBigIntFromNapiValue(env, pk, &spec->pk);
    if (!ret) {
        FreeDhCommParamsSpec(reinterpret_cast<HcfDhCommParamsSpec *>(spec));
        HcfFree(spec);
        return false;
    }
    napi_value sk = GetDetailAsyKeySpecValue(env, arg, "sk");
    ret = GetBigIntFromNapiValue(env, sk, &spec->sk);
    if (!ret) {
        FreeDhCommParamsSpec(reinterpret_cast<HcfDhCommParamsSpec *>(spec));
        HcfFree(spec->pk.data);
        HcfFree(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetDh25519AsyKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec)
{
    napi_value data = nullptr;
    napi_valuetype valueType = napi_undefined;

    napi_status status = napi_get_named_property(env, arg, TAG_SPEC_TYPE.c_str(), &data);
    napi_typeof(env, data, &valueType);
    if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid algo name!");
        return false;
    }
    HcfAsyKeySpecType asyKeySpecType;
    status = napi_get_value_uint32(env, data, reinterpret_cast<uint32_t *>(&asyKeySpecType));
    if (status != napi_ok) {
        LOGE("failed to get valid asyKeySpecType!");
        return false;
    }
    if (asyKeySpecType == HCF_PRIVATE_KEY_SPEC) {
        return GetDhPriKeySpec(env, arg, asyKeySpec);
    } else if (asyKeySpecType == HCF_PUBLIC_KEY_SPEC) {
        return GetDhPubKeySpec(env, arg, asyKeySpec);
    } else if (asyKeySpecType == HCF_KEY_PAIR_SPEC) {
        return GetDhKeyPairAsyKeySpec(env, arg, asyKeySpec);
    } else if (asyKeySpecType == HCF_COMMON_PARAMS_SPEC) {
        return GetDhCommonAsyKeySpec(env, arg, asyKeySpec);
    } else {
        LOGE("keySpec not support!");
        return false;
    }
}

bool GetAsyKeySpecFromNapiValue(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec)
{
    napi_value data = nullptr;

    if ((env == nullptr) || (arg == nullptr) || (asyKeySpec == nullptr)) {
        LOGE("Invalid params!");
        return false;
    }

    napi_valuetype valueType = napi_undefined;

    napi_status status = napi_get_named_property(env, arg, CRYPTO_TAG_ALG_NAME.c_str(), &data);
    napi_typeof(env, data, &valueType);
    if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid algName!");
        return false;
    }
    string algName;
    if (!GetStringFromJSParams(env, data, algName)) {
        LOGE("GetStringFromJSParams failed!");
        return false;
    }
    if (algName.compare(DSA_ASY_KEY_SPEC) == 0) {
        return GetDsaAsyKeySpec(env, arg, asyKeySpec);
    } else if (algName.compare(ECC_ASY_KEY_SPEC) == 0 || algName.compare(SM2_ASY_KEY_SPEC) == 0) {
        return GetEccAsyKeySpec(env, arg, asyKeySpec, algName);
    } else if (algName.compare(RSA_ASY_KEY_SPEC) == 0) {
        return GetRsaAsyKeySpec(env, arg, asyKeySpec);
    } else if (algName.compare(ED25519_ASY_KEY_SPEC) == 0 || algName.compare(X25519_ASY_KEY_SPEC) == 0) {
        return GetAlg25519AsyKeySpec(env, arg, asyKeySpec, algName);
    } else if (algName.compare(DH_ASY_KEY_SPEC) == 0) {
        return GetDh25519AsyKeySpec(env, arg, asyKeySpec);
    } else {
        LOGE("AlgName not support! [AlgName]: %s", algName.c_str());
        return false;
    }
}

napi_value ConvertBlobToNapiValue(napi_env env, HcfBlob *blob)
{
    if (blob == nullptr || blob->data == nullptr || blob->len == 0) {
        LOGD("Invalid blob!");
        return NapiGetNull(env);
    }
    uint8_t *buffer = reinterpret_cast<uint8_t *>(HcfMalloc(blob->len, 0));
    if (buffer == nullptr) {
        LOGE("malloc uint8 array buffer failed!");
        return NapiGetNull(env);
    }

    if (memcpy_s(buffer, blob->len, blob->data, blob->len) != EOK) {
        LOGE("memcpy_s data to buffer failed!");
        HcfFree(buffer);
        return NapiGetNull(env);
    }

    napi_value outBuffer = nullptr;
    napi_status status = napi_create_external_arraybuffer(
        env, buffer, blob->len, [](napi_env env, void *data, void *hint) { HcfFree(data); }, nullptr, &outBuffer);
    if (status != napi_ok) {
        LOGE("create uint8 array buffer failed!");
        HcfFree(buffer);
        return NapiGetNull(env);
    }
    buffer = nullptr;

    napi_value outData = nullptr;
    napi_create_typedarray(env, napi_uint8_array, blob->len, outBuffer, 0, &outData);
    napi_value dataBlob = nullptr;
    napi_create_object(env, &dataBlob);
    napi_set_named_property(env, dataBlob, CRYPTO_TAG_DATA.c_str(), outData);

    return dataBlob;
}

HcfResult ConvertDataBlobToNapiValue(napi_env env, HcfBlob *blob, napi_value *napiValue)
{
    if (blob->data == nullptr || blob->len == 0) { // inner api, allow empty data
        *napiValue = NapiGetNull(env);
        return HCF_SUCCESS;
    }

    uint8_t *buffer = reinterpret_cast<uint8_t *>(HcfMalloc(blob->len, 0));
    if (buffer == nullptr) {
        LOGE("malloc uint8 array buffer failed!");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(buffer, blob->len, blob->data, blob->len);

    napi_value outBuffer = nullptr;
    napi_status status = napi_create_external_arraybuffer(
        env, buffer, blob->len, [](napi_env env, void *data, void *hint) { HcfFree(data); }, nullptr, &outBuffer);
    if (status != napi_ok) {
        LOGE("create napi uint8 array buffer failed!");
        HcfFree(buffer);
        return HCF_ERR_NAPI;
    }

    napi_value outData = nullptr;
    napi_create_typedarray(env, napi_uint8_array, blob->len, outBuffer, 0, &outData);
    napi_value dataBlob = nullptr;
    napi_create_object(env, &dataBlob);
    napi_set_named_property(env, dataBlob, CRYPTO_TAG_DATA.c_str(), outData);
    *napiValue = dataBlob;
    return HCF_SUCCESS;
}

napi_value ConvertObjectBlobToNapiValue(napi_env env, HcfBlob *blob)
{
    if (blob == nullptr || blob->data == nullptr || blob->len == 0) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "Invalid blob!"));
        LOGE("Invalid blob!");
        return NapiGetNull(env);
    }
    uint8_t *buffer = reinterpret_cast<uint8_t *>(HcfMalloc(blob->len, 0));
    if (buffer == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "malloc uint8 array buffer failed!"));
        LOGE("malloc uint8 array buffer failed!");
        return NapiGetNull(env);
    }

    if (memcpy_s(buffer, blob->len, blob->data, blob->len) != EOK) {
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "memcpy_s data to buffer failed!"));
        LOGE("memcpy_s data to buffer failed!");
        HcfFree(buffer);
        return NapiGetNull(env);
    }

    napi_value outBuffer = nullptr;
    napi_status status = napi_create_external_arraybuffer(
        env, buffer, blob->len, [](napi_env env, void *data, void *hint) { HcfFree(data); }, nullptr, &outBuffer);
    if (status != napi_ok) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "create uint8 array buffer failed!"));
        LOGE("create uint8 array buffer failed!");
        HcfFree(buffer);
        return NapiGetNull(env);
    }
    buffer = nullptr;

    napi_value outData = nullptr;
    napi_create_typedarray(env, napi_uint8_array, blob->len, outBuffer, 0, &outData);
    return outData;
}

napi_value ConvertBigIntToNapiValue(napi_env env, HcfBigInteger *blob)
{
    if (blob == nullptr || blob->data == nullptr || blob->len == 0) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "Invalid blob!"));
        LOGE("Invalid blob!");
        return NapiGetNull(env);
    }
    size_t wordsCount = (blob->len / sizeof(uint64_t)) + ((blob->len % sizeof(uint64_t)) == 0 ? 0 : 1);
    uint64_t *words = reinterpret_cast<uint64_t *>(HcfMalloc(wordsCount * sizeof(uint64_t), 0));
    if (words == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "malloc uint8 array buffer failed!"));
        LOGE("malloc uint8 array buffer failed!");
        return NapiGetNull(env);
    }

    size_t index = 0;
    for (size_t i = 0; index < wordsCount; i += sizeof(uint64_t), index++) {
        uint64_t tmp = 0;
        for (size_t j = 0; j < sizeof(uint64_t); j++) {
            if (i + j < blob->len) {
                tmp += ((uint64_t)blob->data[i + j] << (sizeof(uint64_t) * j));
            }
        }
        words[index] = tmp;
    }
    napi_value bigInt = nullptr;
    napi_status status = napi_create_bigint_words(env, 0, wordsCount, words, &bigInt);
    if (status != napi_ok) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "create bigint failed!"));
        LOGE("create bigint failed!");
        HcfFree(words);
        return NapiGetNull(env);
    }
    if (bigInt == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "bigInt is null!"));
        LOGE("bigInt is null!");
    }
    HcfFree(words);
    words = nullptr;
    return bigInt;
}

bool GetStringFromJSParams(napi_env env, napi_value arg, string &returnStr)
{
    napi_valuetype valueType;
    napi_typeof(env, arg, &valueType);
    if (valueType != napi_string) {
        LOGE("wrong argument type. expect string type.");
        return false;
    }

    size_t length = 0;
    if (napi_get_value_string_utf8(env, arg, nullptr, 0, &length) != napi_ok) {
        LOGE("can not get string length");
        return false;
    }
    returnStr.reserve(length + 1);
    returnStr.resize(length);
    if (napi_get_value_string_utf8(env, arg, returnStr.data(), (length + 1), &length) != napi_ok) {
        LOGE("can not get string value");
        return false;
    }
    return true;
}

bool GetInt32FromJSParams(napi_env env, napi_value arg, int32_t &returnInt)
{
    napi_valuetype valueType;
    napi_typeof(env, arg, &valueType);
    if (valueType != napi_number) {
        LOGE("wrong argument type. expect int type. [Type]: %d", valueType);
        return false;
    }

    if (napi_get_value_int32(env, arg, &returnInt) != napi_ok) {
        LOGE("can not get int value");
        return false;
    }
    return true;
}

bool GetUint32FromJSParams(napi_env env, napi_value arg, uint32_t &returnInt)
{
    napi_valuetype valueType;
    napi_typeof(env, arg, &valueType);
    if (valueType != napi_number) {
        LOGE("wrong argument type. expect int type. [Type]: %d", valueType);
        return false;
    }

    if (napi_get_value_uint32(env, arg, &returnInt) != napi_ok) {
        LOGE("can not get int value");
        return false;
    }
    return true;
}

bool GetCallbackFromJSParams(napi_env env, napi_value arg, napi_ref *returnCb)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, arg, &valueType);
    if (valueType != napi_function) {
        LOGE("wrong argument type. expect callback type. [Type]: %d", valueType);
        return false;
    }

    napi_create_reference(env, arg, 1, returnCb);
    return true;
}

static uint32_t GetJsErrValueByErrCode(HcfResult errCode)
{
    switch (errCode) {
        case HCF_INVALID_PARAMS:
            return JS_ERR_INVALID_PARAMS;
        case HCF_NOT_SUPPORT:
            return JS_ERR_NOT_SUPPORT;
        case HCF_ERR_MALLOC:
            return JS_ERR_OUT_OF_MEMORY;
        case HCF_ERR_NAPI:
            return JS_ERR_RUNTIME_ERROR;
        case HCF_ERR_CRYPTO_OPERATION:
            return JS_ERR_CRYPTO_OPERATION;
        default:
            return JS_ERR_DEFAULT_ERR;
    }
}

napi_value GenerateBusinessError(napi_env env, HcfResult errCode, const char *errMsg)
{
    napi_value businessError = nullptr;

    napi_value code = nullptr;
    napi_create_uint32(env, GetJsErrValueByErrCode(errCode), &code);

    napi_value msg = nullptr;
    napi_create_string_utf8(env, errMsg, NAPI_AUTO_LENGTH, &msg);

    napi_create_error(env, nullptr, msg, &businessError);
    napi_set_named_property(env, businessError, CRYPTO_TAG_ERR_CODE.c_str(), code);

    return businessError;
}

bool CheckArgsCount(napi_env env, size_t argc, size_t expectedCount, bool isSync)
{
    if (isSync) {
        if (argc != expectedCount) {
            LOGE("invalid params count!");
            return false;
        }
    } else {
        if ((argc != expectedCount) && (argc != (expectedCount - ARGS_SIZE_ONE))) {
            LOGE("invalid params count!");
            return false;
        }
    }
    return true;
}

bool isCallback(napi_env env, napi_value argv, size_t argc, size_t expectedArgc)
{
    if (argc == expectedArgc - 1) {
        return false;
    }
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv, &valueType);
    if (valueType == napi_undefined || valueType == napi_null) {
        return false;
    }
    return true;
}

napi_value GetResourceName(napi_env env, const char *name)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &resourceName);
    return resourceName;
}

static bool CheckEccCommonParamSpecBase(napi_env env, HcfEccCommParamsSpec *blob)
{
    if (blob->a.data == nullptr || blob->a.len == 0) {
        LOGE("Invalid blob a!");
        return false;
    }
    if (blob->b.data == nullptr || blob->b.len == 0) {
        LOGE("Invalid blob b!");
        return false;
    }
    if (blob->n.data == nullptr || blob->n.len == 0) {
        LOGE("Invalid blob n!");
        return false;
    }
    return true;
}

static bool CheckEccCommonParamSpec(napi_env env, HcfEccCommParamsSpec *blob)
{
    if (blob == nullptr) {
        LOGE("Invalid blob!");
        return false;
    }
    if (!CheckEccCommonParamSpecBase(env, blob)) {
        LOGE("Invalid blob ecc commonParamSpec base!");
        return false;
    }
    if (blob->base.algName == nullptr) {
        LOGE("Invalid blob algName!");
        return false;
    }
    if (blob->field == nullptr) {
        LOGE("Invalid blob field!");
        return false;
    }
    if (blob->field->fieldType == nullptr) {
        LOGE("Invalid blob fieldType!");
        return false;
    }
    if (blob->g.x.data == nullptr || blob->g.x.len == 0) {
        LOGE("Invalid blob point x!");
        return false;
    }
    if (blob->g.y.data == nullptr || blob->g.y.len == 0) {
        LOGE("Invalid blob point y!");
        return false;
    }
    HcfECFieldFp *tmpField = reinterpret_cast<HcfECFieldFp *>(blob->field);
    if (tmpField->p.data == nullptr || tmpField->p.len == 0) {
        LOGE("Invalid blob p!");
        return false;
    }
    return true;
}

static napi_value ConvertEccCommonParamFieldFpToNapiValue(napi_env env, HcfEccCommParamsSpec *blob)
{
    napi_value fieldFp;
    napi_value fieldType;
    napi_status status = napi_create_object(env, &fieldFp);
    if (status != napi_ok) {
        LOGE("create fieldFp failed!");
        return NapiGetNull(env);
    }
    size_t fieldTypeLength = HcfStrlen(blob->field->fieldType);
    if (!fieldTypeLength) {
        LOGE("fieldType is empty!");
        return NapiGetNull(env);
    }
    status = napi_create_string_utf8(env, blob->field->fieldType, fieldTypeLength, &fieldType);
    if (status != napi_ok) {
        LOGE("create object failed!");
        return NapiGetNull(env);
    }
    status = napi_set_named_property(env, fieldFp, "fieldType", fieldType);
    if (status != napi_ok) {
        LOGE("create object failed!");
        return NapiGetNull(env);
    }
    HcfECFieldFp *tmpField = reinterpret_cast<HcfECFieldFp *>(blob->field);
    napi_value p = ConvertBigIntToNapiValue(env, &(tmpField->p));
    if (p == nullptr) {
        LOGE("p is null!");
        return NapiGetNull(env);
    }
    status = napi_set_named_property(env, fieldFp, "p", p);
    if (status != napi_ok) {
        LOGE("create object failed!");
        return NapiGetNull(env);
    }
    return fieldFp;
}

static bool IsNapiNull(napi_env env, napi_value value)
{
    napi_valuetype valueType;
    napi_typeof(env, value, &valueType);
    return (valueType == napi_null);
}

napi_value ConvertEccPointToNapiValue(napi_env env, HcfPoint *p)
{
    if (p == nullptr) {
        LOGE("Invalid point data!");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "Invalid point data!"));
        return nullptr;
    }

    napi_value point;
    napi_status status = napi_create_object(env, &point);
    if (status != napi_ok) {
        LOGE("create object failed!");
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "create object failed!"));
        return nullptr;
    }

    napi_value x = ConvertBigIntToNapiValue(env, &(p->x));
    if (x == nullptr || IsNapiNull(env, x)) {
        LOGE("Failed to convert x to NapiValue!");
        return nullptr;
    }

    napi_value y = ConvertBigIntToNapiValue(env, &(p->y));
    if (y == nullptr || IsNapiNull(env, y)) {
        LOGE("Failed to convert y to NapiValue!");
        return nullptr;
    }

    status = napi_set_named_property(env, point, "x", x);
    if (status != napi_ok) {
        LOGE("set x property failed!");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "set x property failed!"));
        return nullptr;
    }

    status = napi_set_named_property(env, point, "y", y);
    if (status != napi_ok) {
        LOGE("set y property failed!");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "set y property failed!"));
        return nullptr;
    }

    return point;
}

static napi_value ConvertEccCommonParamPointToNapiValue(napi_env env, HcfEccCommParamsSpec *blob)
{
    napi_value point;
    napi_status status = napi_create_object(env, &point);
    if (status != napi_ok) {
        LOGE("create object failed!");
        return NapiGetNull(env);
    }
    napi_value x = ConvertBigIntToNapiValue(env, &(blob->g.x));
    if (x == nullptr) {
        LOGE("x is null!");
        return NapiGetNull(env);
    }

    napi_value y = ConvertBigIntToNapiValue(env, &(blob->g.y));
    if (y == nullptr) {
        LOGE("y is null!");
        return NapiGetNull(env);
    }
    status = napi_set_named_property(env, point, "x", x);
    if (status != napi_ok) {
        LOGE("create object failed!");
        return NapiGetNull(env);
    }
    status = napi_set_named_property(env, point, "y", y);
    if (status != napi_ok) {
        LOGE("create object failed!");
        return NapiGetNull(env);
    }
    return point;
}

bool BuildSetNamedProperty(napi_env env, HcfBigInteger *number, const char *name, napi_value *instance)
{
    napi_value value = ConvertBigIntToNapiValue(env, number);
    napi_status status = napi_set_named_property(env, *instance, name, value);
    if (status != napi_ok) {
        LOGE("create value failed!");
        return false;
    }
    return true;
}

static bool BuildIntancePartertoNapiValueSon(napi_env env, napi_status status, HcfEccCommParamsSpec *blob,
    napi_value *instance)
{
    if (!BuildSetNamedProperty(env, &(blob->a), "a", instance)) {
        LOGE("build setNamedProperty a failed!");
        return false;
    }
    if (!BuildSetNamedProperty(env, &(blob->b), "b", instance)) {
        LOGE("build setNamedProperty b failed!");
        return false;
    }
    if (!BuildSetNamedProperty(env, &(blob->n), "n", instance)) {
        LOGE("build setNamedProperty n failed!");
        return false;
    }
    napi_value h;
    status = napi_create_int32(env, blob->h, &h);
    if (status != napi_ok) {
        LOGE("create h uint32 failed!");
        return false;
    }
    status = napi_set_named_property(env, *instance, "h", h);
    if (status != napi_ok) {
        LOGE("create h uint32 failed!");
        return false;
    }
    return true;
}

static bool BuildInstanceParterToNapiValue(napi_env env, HcfEccCommParamsSpec *blob, napi_value *instance)
{
    napi_value algName;
    size_t algNameLength = HcfStrlen(blob->base.algName);
    if (!algNameLength) {
        LOGE("algName is empty!");
        return false;
    }
    napi_status status = napi_create_string_utf8(env, blob->base.algName, algNameLength, &algName);
    if (status != napi_ok) {
        LOGE("create algName failed!");
        return false;
    }
    napi_value specType;
    status = napi_create_uint32(env, blob->base.specType, &specType);
    if (status != napi_ok) {
        LOGE("create uint32 failed!");
        return false;
    }
    status = napi_set_named_property(env, *instance, "algName", algName);
    if (status != napi_ok) {
        LOGE("create set algName failed!");
        return false;
    }
    status = napi_set_named_property(env, *instance, "specType", specType);
    if (status != napi_ok) {
        LOGE("create set specType failed!");
        return false;
    }
    if (!BuildIntancePartertoNapiValueSon(env, status, blob, instance)) {
        LOGE("create intance parter napi value failed!");
        return false;
    }
    return true;
}

napi_value ConvertEccCommParamsSpecToNapiValue(napi_env env, HcfEccCommParamsSpec *blob)
{
    if (!CheckEccCommonParamSpec(env, blob)) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "Invalid blob!"));
        LOGE("Invalid blob!");
        return NapiGetNull(env);
    }
    napi_value instance;
    napi_status status = napi_create_object(env, &instance);
    if (status != napi_ok) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "create object failed!"));
        LOGE("create object failed!");
        return NapiGetNull(env);
    }
    napi_value point = ConvertEccCommonParamPointToNapiValue(env, blob);
    if (point == NapiGetNull(env)) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "covert commonParam failed!"));
        LOGE("Covert commonParam failed!");
        return NapiGetNull(env);
    }
    napi_value field = ConvertEccCommonParamFieldFpToNapiValue(env, blob);
    if (field == NapiGetNull(env)) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "covert commonParam fieldFp failed!"));
        LOGE("Covert commonParam fieldFp failed!");
        return NapiGetNull(env);
    }
    if (!BuildInstanceParterToNapiValue(env, blob, &instance)) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "build object failed!"));
        LOGE("Build object failed!");
        return NapiGetNull(env);
    }
    status = napi_set_named_property(env, instance, "field", field);
    if (status != napi_ok) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "set fieldFp failed!"));
        LOGE("set fieldFp failed!");
        return NapiGetNull(env);
    }
    status = napi_set_named_property(env, instance, "g", point);
    if (status != napi_ok) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "set g failed!"));
        LOGE("set g failed!");
        return NapiGetNull(env);
    }
    return instance;
}

static bool BuildDhInstanceToNapiValueSub(napi_env env, HcfDhCommParamsSpec *blob, napi_value *instance)
{
    if (!BuildSetNamedProperty(env, &(blob->p), "p", instance)) {
        LOGE("build setNamedProperty a failed!");
        return false;
    }
    if (!BuildSetNamedProperty(env, &(blob->g), "g", instance)) {
        LOGE("build setNamedProperty b failed!");
        return false;
    }
    napi_value length;
    napi_status status = napi_create_int32(env, blob->length, &length);
    if (status != napi_ok) {
        LOGE("create length number failed!");
        return false;
    }
    status = napi_set_named_property(env, *instance, "l", length);
    if (status != napi_ok) {
        LOGE("create length number failed!");
        return false;
    }
    return true;
}

static bool BuildDhInstanceToNapiValue(napi_env env, HcfDhCommParamsSpec *blob, napi_value *instance)
{
    napi_value algName;
    size_t algNameLength = HcfStrlen(blob->base.algName);
    if (!algNameLength) {
        LOGE("algName is empty!");
        return false;
    }
    napi_status status = napi_create_string_utf8(env, blob->base.algName, algNameLength, &algName);
    if (status != napi_ok) {
        LOGE("create algName failed!");
        return false;
    }
    napi_value specType;
    status = napi_create_uint32(env, blob->base.specType, &specType);
    if (status != napi_ok) {
        LOGE("create uint32 failed!");
        return false;
    }
    status = napi_set_named_property(env, *instance, "algName", algName);
    if (status != napi_ok) {
        LOGE("create set algName failed!");
        return false;
    }
    status = napi_set_named_property(env, *instance, "specType", specType);
    if (status != napi_ok) {
        LOGE("create set specType failed!");
        return false;
    }
    if (!BuildDhInstanceToNapiValueSub(env, blob, instance)) {
        LOGE("create intance parter napi value failed!");
        return false;
    }
    return true;
}

static bool CheckDhCommonParamSpec(napi_env env, HcfDhCommParamsSpec *blob)
{
    if (blob == nullptr) {
        LOGE("Invalid blob!");
        return false;
    }
    if (blob->base.algName == nullptr) {
        LOGE("Invalid blob algName!");
        return false;
    }
    if (blob->p.data == nullptr || blob->p.len == 0) {
        LOGE("Invalid blob a!");
        return false;
    }
    if (blob->g.data == nullptr || blob->g.len == 0) {
        LOGE("Invalid blob point x!");
        return false;
    }
    return true;
}

napi_value ConvertDhCommParamsSpecToNapiValue(napi_env env, HcfDhCommParamsSpec *blob)
{
    if (!CheckDhCommonParamSpec(env, blob)) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "Invalid blob!"));
        LOGE("Invalid blob!");
        return NapiGetNull(env);
    }
    napi_value instance;
    napi_status status = napi_create_object(env, &instance);
    if (status != napi_ok) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "create object failed!"));
        LOGE("create object failed!");
        return NapiGetNull(env);
    }
    if (!BuildDhInstanceToNapiValue(env, blob, &instance)) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "build object failed!"));
        LOGE("Build object failed!");
        return NapiGetNull(env);
    }
    return instance;
}
}  // namespace CryptoFramework
}  // namespace OHOS

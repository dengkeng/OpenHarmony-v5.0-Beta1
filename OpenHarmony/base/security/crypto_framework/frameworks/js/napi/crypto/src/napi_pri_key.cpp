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

#include "napi_pri_key.h"

#include "log.h"
#include "memory.h"
#include "napi_crypto_framework_defines.h"
#include "napi_utils.h"
#include "securec.h"
#include "key.h"

namespace OHOS {
namespace CryptoFramework {
thread_local napi_ref NapiPriKey::classRef_ = nullptr;

NapiPriKey::NapiPriKey(HcfPriKey *priKey) : NapiKey(reinterpret_cast<HcfKey *>(priKey)) {}

NapiPriKey::~NapiPriKey() {}

HcfPriKey *NapiPriKey::GetPriKey()
{
    return reinterpret_cast<HcfPriKey *>(NapiKey::GetHcfKey());
}

napi_value NapiPriKey::PriKeyConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

napi_value NapiPriKey::ConvertToJsPriKey(napi_env env)
{
    napi_value instance;
    napi_value constructor = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, 0, nullptr, &instance);

    const char *algName = this->GetPriKey()->base.getAlgorithm(&(this->GetPriKey()->base));
    const char *format = this->GetPriKey()->base.getFormat(&(this->GetPriKey()->base));

    napi_value napiAlgName = nullptr;
    napi_create_string_utf8(env, algName, NAPI_AUTO_LENGTH, &napiAlgName);
    napi_set_named_property(env, instance, CRYPTO_TAG_ALG_NAME.c_str(), napiAlgName);

    napi_value napiFormat = nullptr;
    napi_create_string_utf8(env, format, NAPI_AUTO_LENGTH, &napiFormat);
    napi_set_named_property(env, instance, CRYPTO_TAG_FORMAT.c_str(), napiFormat);
    return instance;
}

napi_value NapiPriKey::JsGetEncoded(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiPriKey *napiPriKey = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiPriKey));
    if (status != napi_ok || napiPriKey == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to unwrap napiPriKey obj!"));
        LOGE("failed to unwrap napiPriKey obj!");
        return nullptr;
    }

    HcfPriKey *priKey = napiPriKey->GetPriKey();
    if (priKey == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to get priKey obj!"));
        LOGE("failed to get priKey obj!");
        return nullptr;
    }

    HcfBlob returnBlob;
    HcfResult res = priKey->base.getEncoded(&priKey->base, &returnBlob);
    if (res != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, res, "c getEncoded fail."));
        LOGD("[error] c getEncoded fail.");
        return nullptr;
    }

    napi_value instance = ConvertBlobToNapiValue(env, &returnBlob);
    HcfBlobDataFree(&returnBlob);
    return instance;
}

napi_value NapiPriKey::JsGetEncodedPem(napi_env env, napi_callback_info info)
{
    size_t expectedArgc = PARAMS_NUM_ONE;
    size_t argc = expectedArgc;
    napi_value argv[PARAMS_NUM_ONE] = { nullptr };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc) {
        LOGE("The input args num is invalid.");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "The input args num is invalid."));
        return NapiGetNull(env);
    }

    std::string format = "";
    if (!GetStringFromJSParams(env, argv[0], format)) {
        LOGE("failed to get formatStr.");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to get formatStr."));
        return NapiGetNull(env);
    }

    NapiPriKey *napiPriKey = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiPriKey));
    if (status != napi_ok || napiPriKey == nullptr) {
        LOGE("failed to unwrap napiPriKey obj!");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to unwrap napiPriKey obj!"));
        return nullptr;
    }

    HcfPriKey *priKey = napiPriKey->GetPriKey();
    if (priKey == nullptr) {
        LOGE("failed to get priKey obj!");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to get priKey obj!"));
        return nullptr;
    }

    char *returnString = nullptr;
    HcfResult res = priKey->base.getEncodedPem(&priKey->base, format.c_str(), &returnString);
    if (res != HCF_SUCCESS) {
        LOGE("getEncodedPem fail.");
        napi_throw(env, GenerateBusinessError(env, res, "getEncodedPem fail."));
        return nullptr;
    }
    napi_value instance = nullptr;
    napi_create_string_utf8(env, returnString, NAPI_AUTO_LENGTH, &instance);
    HcfFree(returnString);
    return instance;
}

napi_value NapiPriKey::JsClearMem(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiPriKey *napiPriKey = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiPriKey));
    if (status != napi_ok || napiPriKey == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to unwrap napiPriKey obj!"));
        LOGE("failed to unwrap napiPriKey obj!");
        return nullptr;
    }

    HcfPriKey *priKey = napiPriKey->GetPriKey();
    if (priKey == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to get priKey obj!"));
        LOGE("failed to get priKey obj!");
        return nullptr;
    }

    priKey->clearMem(priKey);
    return nullptr;
}

static napi_value GetAsyKeySpecBigInt(napi_env env, AsyKeySpecItem item, HcfPriKey *priKey)
{
    HcfBigInteger returnBigInteger = { 0 };
    HcfResult res = priKey->getAsyKeySpecBigInteger(priKey, item, &returnBigInteger);
    if (res != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, res, "C getAsyKeySpecBigInteger failed."));
        LOGE("C getAsyKeySpecBigInteger failed.");
        return nullptr;
    }

    napi_value instance = ConvertBigIntToNapiValue(env, &returnBigInteger);
    HcfFree(returnBigInteger.data);
    return instance;
}

static napi_value GetAsyKeySpecNumber(napi_env env, AsyKeySpecItem item, HcfPriKey *priKey)
{
    int returnInt = 0;
    HcfResult res = priKey->getAsyKeySpecInt(priKey, item, &returnInt);
    if (res != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, res, "C getAsyKeySpecInt failed."));
        LOGE("C getAsyKeySpecInt fail.");
        return nullptr;
    }

    napi_value instance = nullptr;
    napi_create_int32(env, returnInt, &instance);
    return instance;
}

static napi_value GetAsyKeySpecString(napi_env env, AsyKeySpecItem item, HcfPriKey *priKey)
{
    char *returnString = nullptr;
    HcfResult res = priKey->getAsyKeySpecString(priKey, item, &returnString);
    if (res != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, res, "C getAsyKeySpecString failed."));
        LOGE("c getAsyKeySpecString fail.");
        return nullptr;
    }

    napi_value instance = nullptr;
    napi_create_string_utf8(env, returnString, NAPI_AUTO_LENGTH, &instance);
    HcfFree(returnString);
    return instance;
}

napi_value NapiPriKey::JsGetAsyKeySpec(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiPriKey *napiPriKey = nullptr;
    size_t expectedArgc = ARGS_SIZE_ONE;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "JsGetAsyKeySpec fail, wrong argument num."));
        LOGE("wrong argument num. require 1 arguments. [Argc]: %zu!", argc);
        return nullptr;
    }

    AsyKeySpecItem item;
    if (napi_get_value_uint32(env, argv[0], reinterpret_cast<uint32_t *>(&item)) != napi_ok) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "JsGetAsyKeySpec failed!"));
        LOGE("JsGetAsyKeySpec failed!");
        return nullptr;
    }

    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiPriKey));
    if (status != napi_ok || napiPriKey == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to unwrap napiPriKey obj!"));
        LOGE("failed to unwrap napiPriKey obj!");
        return nullptr;
    }
    HcfPriKey *priKey = napiPriKey->GetPriKey();
    if (priKey == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to get priKey obj!"));
        LOGE("failed to get priKey obj!");
        return nullptr;
    }
    LOGD("prepare priKey ok.");

    int32_t type = GetAsyKeySpecType(item);
    if (type == SPEC_ITEM_TYPE_BIG_INT) {
        return GetAsyKeySpecBigInt(env, item, priKey);
    } else if (type == SPEC_ITEM_TYPE_NUM) {
        return GetAsyKeySpecNumber(env, item, priKey);
    } else if (type == SPEC_ITEM_TYPE_STR) {
        return GetAsyKeySpecString(env, item, priKey);
    } else {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "AsyKeySpecItem not support!"));
        return nullptr;
    }
}

napi_value NapiPriKey::JsGetEncodedDer(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiPriKey *napiPriKey = nullptr;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != ARGS_SIZE_ONE) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "wrong argument num."));
        LOGE("wrong argument num. require 1 arguments. [Argc]: %zu!", argc);
        return nullptr;
    }
    std::string format;
    if (!GetStringFromJSParams(env, argv[0], format)) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to get format."));
        LOGE("get format fail.");
        return nullptr;
    }
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiPriKey));
    if (status != napi_ok || napiPriKey == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to unwrap private key obj!"));
        LOGE("failed to unwrap private key obj!");
        return nullptr;
    }
    HcfPriKey *priKey = napiPriKey->GetPriKey();
    if (priKey == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to get private key obj!"));
        LOGE("failed to get private key obj!");
        return nullptr;
    }
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    HcfResult res = priKey->getEncodedDer(priKey, format.c_str(), &returnBlob);
    if (res != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, res, "get private key encodedDer fail."));
        LOGE("get private key encodeDer fail.");
        return nullptr;
    }
    napi_value instance = ConvertBlobToNapiValue(env, &returnBlob);
    HcfBlobDataFree(&returnBlob);
    return instance;
}

void NapiPriKey::DefinePriKeyJSClass(napi_env env)
{
    napi_property_descriptor classDesc[] = {
        DECLARE_NAPI_FUNCTION("getEncoded", NapiPriKey::JsGetEncoded),
        DECLARE_NAPI_FUNCTION("getEncodedDer", NapiPriKey::JsGetEncodedDer),
        DECLARE_NAPI_FUNCTION("getEncodedPem", NapiPriKey::JsGetEncodedPem),
        DECLARE_NAPI_FUNCTION("clearMem", NapiPriKey::JsClearMem),
        DECLARE_NAPI_FUNCTION("getAsyKeySpec", NapiPriKey::JsGetAsyKeySpec),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, "PriKey", NAPI_AUTO_LENGTH, NapiPriKey::PriKeyConstructor, nullptr,
        sizeof(classDesc) / sizeof(classDesc[0]), classDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
} // CryptoFramework
} // OHOS

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

#include "napi_pub_key.h"

#include "log.h"
#include "memory.h"
#include "napi_crypto_framework_defines.h"
#include "napi_utils.h"
#include "securec.h"
#include "key.h"

namespace OHOS {
namespace CryptoFramework {
thread_local napi_ref NapiPubKey::classRef_ = nullptr;

NapiPubKey::NapiPubKey(HcfPubKey *pubKey) : NapiKey(reinterpret_cast<HcfKey *>(pubKey)) {}

NapiPubKey::~NapiPubKey() {}

HcfPubKey *NapiPubKey::GetPubKey()
{
    return reinterpret_cast<HcfPubKey *>(NapiKey::GetHcfKey());
}

napi_value NapiPubKey::PubKeyConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

napi_value NapiPubKey::ConvertToJsPubKey(napi_env env)
{
    napi_value instance;
    napi_value constructor = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, 0, nullptr, &instance);

    const char *algName = this->GetPubKey()->base.getAlgorithm(&(this->GetPubKey()->base));
    const char *format = this->GetPubKey()->base.getFormat(&(this->GetPubKey()->base));

    napi_value napiAlgName = nullptr;
    napi_create_string_utf8(env, algName, NAPI_AUTO_LENGTH, &napiAlgName);
    napi_set_named_property(env, instance, CRYPTO_TAG_ALG_NAME.c_str(), napiAlgName);

    napi_value napiFormat = nullptr;
    napi_create_string_utf8(env, format, NAPI_AUTO_LENGTH, &napiFormat);
    napi_set_named_property(env, instance, CRYPTO_TAG_FORMAT.c_str(), napiFormat);
    return instance;
}

napi_value NapiPubKey::JsGetEncoded(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiPubKey *napiPubKey = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiPubKey));
    if (status != napi_ok || napiPubKey == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to unwrap napiPubKey obj!"));
        LOGE("failed to unwrap napiPubKey obj!");
        return nullptr;
    }

    HcfPubKey *pubKey = napiPubKey->GetPubKey();
    if (pubKey == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to get pubKey obj!"));
        LOGE("failed to get pubKey obj!");
        return nullptr;
    }

    HcfBlob returnBlob;
    HcfResult res = pubKey->base.getEncoded(&pubKey->base, &returnBlob);
    if (res != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "c getEncoded fail."));
        LOGE("c getEncoded fail.");
        return nullptr;
    }

    napi_value instance = ConvertBlobToNapiValue(env, &returnBlob);
    HcfBlobDataFree(&returnBlob);
    return instance;
}

napi_value NapiPubKey::JsGetEncodedDer(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiPubKey *napiPubKey = nullptr;
    size_t expectedArgc = ARGS_SIZE_ONE;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc) {
        LOGE("wrong argument num. require 1 arguments. [Argc]: %zu!", argc);
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "JsGetEncodedDer fail, wrong argument num."));
        return nullptr;
    }
    std::string format;
    if (!GetStringFromJSParams(env, argv[PARAM0], format)) {
        LOGE("get format fail.");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to get format."));
        return nullptr;
    }
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiPubKey));
    if (status != napi_ok || napiPubKey == nullptr) {
        LOGE("failed to unwrap napiPubKeyDer obj!");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to unwrap napiPubKeyDer obj!"));
        return nullptr;
    }

    HcfPubKey *pubKey = napiPubKey->GetPubKey();
    if (pubKey == nullptr) {
        LOGE("failed to get pubKeyDer obj!");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to get pubKeyDer obj!"));
        return nullptr;
    }

    HcfBlob returnBlob;
    HcfResult res = pubKey->getEncodedDer(pubKey, format.c_str(), &returnBlob);
    if (res != HCF_SUCCESS) {
        LOGE("c getEncodedDer fail.");
        napi_throw(env, GenerateBusinessError(env, res, "c getEncodedDer fail."));
        return nullptr;
    }

    napi_value instance = ConvertBlobToNapiValue(env, &returnBlob);
    HcfBlobDataFree(&returnBlob);
    return instance;
}

napi_value NapiPubKey::JsGetEncodedPem(napi_env env, napi_callback_info info)
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

    NapiPubKey *napiPubKey = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiPubKey));
    if (status != napi_ok || napiPubKey == nullptr) {
        LOGE("failed to unwrap napiPriKey obj!");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to unwrap napiPubKey obj!"));
        return nullptr;
    }

    HcfPubKey *pubKey = napiPubKey->GetPubKey();
    if (pubKey == nullptr) {
        LOGE("failed to get pubKey obj!");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to get pubKey obj!"));
        return nullptr;
    }

    char *returnString = nullptr;
    HcfResult res = pubKey->base.getEncodedPem(&pubKey->base, format.c_str(), &returnString);
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

static napi_value GetAsyKeySpecBigInt(napi_env env, AsyKeySpecItem item, HcfPubKey *pubKey)
{
    HcfBigInteger returnBigInteger = { 0 };
    HcfResult res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &returnBigInteger);
    if (res != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, res, "C getAsyKeySpecBigInteger failed."));
        LOGE("C getAsyKeySpecBigInteger failed.");
        return nullptr;
    }

    napi_value instance = ConvertBigIntToNapiValue(env, &returnBigInteger);
    HcfFree(returnBigInteger.data);
    return instance;
}

static napi_value GetAsyKeySpecNumber(napi_env env, AsyKeySpecItem item, HcfPubKey *pubKey)
{
    int returnInt = 0;
    HcfResult res = pubKey->getAsyKeySpecInt(pubKey, item, &returnInt);
    if (res != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, res, "C getAsyKeySpecInt failed."));
        LOGE("C getAsyKeySpecInt fail.");
        return nullptr;
    }

    napi_value instance = nullptr;
    napi_create_int32(env, returnInt, &instance);
    return instance;
}

static napi_value GetAsyKeySpecString(napi_env env, AsyKeySpecItem item, HcfPubKey *pubKey)
{
    char *returnString = nullptr;
    HcfResult res = pubKey->getAsyKeySpecString(pubKey, item, &returnString);
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

napi_value NapiPubKey::JsGetAsyKeySpec(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiPubKey *napiPubKey = nullptr;
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

    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiPubKey));
    if (status != napi_ok || napiPubKey == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to unwrap napiPubKey obj!"));
        LOGE("failed to unwrap napiPubKey obj!");
        return nullptr;
    }
    HcfPubKey *pubKey = napiPubKey->GetPubKey();
    if (pubKey == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to get pubKey obj!"));
        LOGE("failed to get pubKey obj!");
        return nullptr;
    }

    int32_t type = GetAsyKeySpecType(item);
    if (type == SPEC_ITEM_TYPE_BIG_INT) {
        return GetAsyKeySpecBigInt(env, item, pubKey);
    } else if (type == SPEC_ITEM_TYPE_NUM) {
        return GetAsyKeySpecNumber(env, item, pubKey);
    } else if (type == SPEC_ITEM_TYPE_STR) {
        return GetAsyKeySpecString(env, item, pubKey);
    } else {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "AsyKeySpecItem not support!"));
        return nullptr;
    }
}

void NapiPubKey::DefinePubKeyJSClass(napi_env env)
{
    napi_property_descriptor classDesc[] = {
        DECLARE_NAPI_FUNCTION("getEncoded", NapiPubKey::JsGetEncoded),
        DECLARE_NAPI_FUNCTION("getEncodedDer", NapiPubKey::JsGetEncodedDer),
        DECLARE_NAPI_FUNCTION("getEncodedPem", NapiPubKey::JsGetEncodedPem),
        DECLARE_NAPI_FUNCTION("getAsyKeySpec", NapiPubKey::JsGetAsyKeySpec),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, "PubKey", NAPI_AUTO_LENGTH, NapiPubKey::PubKeyConstructor, nullptr,
        sizeof(classDesc) / sizeof(classDesc[0]), classDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
} // CryptoFramework
} // OHOS

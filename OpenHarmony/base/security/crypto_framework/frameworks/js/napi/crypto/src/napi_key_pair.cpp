/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#include "napi_key_pair.h"

#include "securec.h"
#include "log.h"
#include "napi_crypto_framework_defines.h"
#include "napi_pri_key.h"
#include "napi_pub_key.h"
#include "napi_utils.h"

namespace OHOS {
namespace CryptoFramework {
thread_local napi_ref NapiKeyPair::classRef_ = nullptr;

NapiKeyPair::NapiKeyPair(HcfKeyPair *keyPair)
{
    this->keyPair_ = keyPair;
}

NapiKeyPair::~NapiKeyPair()
{
    HcfObjDestroy(this->keyPair_);
    this->keyPair_ = nullptr;
}

napi_value NapiKeyPair::KeyPairConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

napi_value NapiKeyPair::ConvertToJsKeyPair(napi_env env)
{
    napi_value instance;
    napi_value constructor = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, 0, nullptr, &instance);

    if (this->keyPair_->pubKey != nullptr) {
        NapiPubKey *napiPubKey = new (std::nothrow) NapiPubKey(this->keyPair_->pubKey);
        if (napiPubKey == nullptr) {
            LOGE("new napi pub key failed");
            return nullptr;
        }
        napi_value pubKey = napiPubKey->ConvertToJsPubKey(env);
        napi_status status =  napi_wrap(
            env, pubKey, napiPubKey,
            [](napi_env env, void *data, void *hint) {
                NapiPubKey *napiPubKey = static_cast<NapiPubKey *>(data);
                delete napiPubKey;
                return;
            }, nullptr, nullptr);
        if (status != napi_ok) {
            LOGE("failed to wrap napiPubKey obj!");
            delete napiPubKey;
            return nullptr;
        }
        napi_set_named_property(env, instance, CRYPTO_TAG_PUB_KEY.c_str(), pubKey);
    }

    if (this->keyPair_->priKey != nullptr) {
        NapiPriKey *napiPriKey = new (std::nothrow) NapiPriKey(this->keyPair_->priKey);
        if (napiPriKey == nullptr) {
            LOGE("new napi pri key failed");
            return nullptr;
        }
        napi_value priKey = napiPriKey->ConvertToJsPriKey(env);
        napi_status status =  napi_wrap(
            env, priKey, napiPriKey,
            [](napi_env env, void *data, void *hint) {
                NapiPriKey *napiPriKey = static_cast<NapiPriKey *>(data);
                delete napiPriKey;
                return;
            }, nullptr, nullptr);
        if (status != napi_ok) {
            napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to wrap napiPriKey obj!"));
            LOGE("failed to wrap napiPriKey obj!");
            delete napiPriKey;
            return nullptr;
        }
        napi_set_named_property(env, instance, CRYPTO_TAG_PRI_KEY.c_str(), priKey);
    }
    return instance;
}

void NapiKeyPair::DefineKeyPairJSClass(napi_env env)
{
    napi_property_descriptor classDesc[] = {};
    napi_value constructor = nullptr;
    napi_define_class(env, "KeyPair", NAPI_AUTO_LENGTH, KeyPairConstructor, nullptr,
        sizeof(classDesc) / sizeof(classDesc[0]), classDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
} // CryptoFramework
} // OHOS

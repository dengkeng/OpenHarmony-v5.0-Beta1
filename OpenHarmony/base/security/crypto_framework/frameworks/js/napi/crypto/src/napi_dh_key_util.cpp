/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "napi_dh_key_util.h"
#include "securec.h"
#include "detailed_ecc_key_params.h"
#include "log.h"

#include "napi_crypto_framework_defines.h"
#include "napi_utils.h"
#include "napi_key_pair.h"
#include "napi_pri_key.h"
#include "napi_pub_key.h"

namespace OHOS {
namespace CryptoFramework {
NapiDHKeyUtil::NapiDHKeyUtil() {}

NapiDHKeyUtil::~NapiDHKeyUtil() {}

napi_value NapiDHKeyUtil::JsGenDHCommonParamsSpec(napi_env env, napi_callback_info info)
{
    size_t expectedArgc = PARAMS_NUM_TWO;
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

    if ((argc != expectedArgc) && (argc != (expectedArgc - 1))) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "The input args num is invalid."));
        LOGE("The input args num is invalid.");
        return nullptr;
    }

    int32_t pLen = 0;
    if (!GetInt32FromJSParams(env, argv[0], pLen)) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to get pLen."));
        LOGE("failed to get pLen.");
        return NapiGetNull(env);
    }

    int32_t skLen = 0;
    if (argc == expectedArgc) {
        if (!GetInt32FromJSParams(env, argv[1], skLen)) {
            napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to get skLen."));
            LOGE("failed to get skLen.");
            return NapiGetNull(env);
        }
    }
    HcfDhCommParamsSpec *dhCommParamsSpec = nullptr;
    if (HcfDhKeyUtilCreate(pLen, skLen, &dhCommParamsSpec) != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "create c generator fail."));
        LOGE("create c generator fail.");
        return NapiGetNull(env);
    }

    napi_value instance = ConvertDhCommParamsSpecToNapiValue(env, dhCommParamsSpec);
    FreeDhCommParamsSpec(dhCommParamsSpec);
    return instance;
}

napi_value NapiDHKeyUtil::DHKeyUtilConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    return thisVar;
}

napi_value NapiDHKeyUtil::GenDHCommonParamSpec(napi_env env)
{
    napi_value cons = nullptr;
    napi_property_descriptor clzDes[] = {
        DECLARE_NAPI_STATIC_FUNCTION("genDHCommonParamsSpec", NapiDHKeyUtil::JsGenDHCommonParamsSpec),
    };
    NAPI_CALL(env, napi_define_class(env, "DHKeyUtil", NAPI_AUTO_LENGTH, NapiDHKeyUtil::DHKeyUtilConstructor,
        nullptr, sizeof(clzDes) / sizeof(clzDes[0]), clzDes, &cons));
    return cons;
}

void NapiDHKeyUtil::DefineNapiDHKeyUtilJSClass(napi_env env, napi_value exports)
{
    napi_set_named_property(env, exports, "DHKeyUtil", NapiDHKeyUtil::GenDHCommonParamSpec(env));
}
} // CryptoFramework
} // OHOS

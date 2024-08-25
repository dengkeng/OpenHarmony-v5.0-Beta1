/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FOUNDATION_ACE_COMPONENTEXT_EXT_COMMON_EXT_NAPI_UTILS_H
#define FOUNDATION_ACE_COMPONENTEXT_EXT_COMMON_EXT_NAPI_UTILS_H

#include <string>

#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "base/utils/macros.h"

namespace OHOS::Ace {
class ACE_FORCE_EXPORT NapiAsyncEvent {
public:
    NapiAsyncEvent(napi_env env, napi_value callback);
    ~NapiAsyncEvent();
    napi_value Call(int32_t argc, napi_value* argv);
    napi_env GetEnv();

private:
    napi_env env_;
    napi_ref ref_;
};

class ACE_FORCE_EXPORT ExtNapiUtils {
public:
    static napi_value CreateInt32(napi_env env, int32_t code);
    static int32_t GetCInt32(napi_env env, napi_value value);
    static napi_value CreateNull(napi_env env);
    static bool GetBool(napi_env env, napi_value value);
    static napi_valuetype GetValueType(napi_env env, napi_value value);
    static std::string GetStringFromValueUtf8(napi_env env, napi_value value);
    static bool CheckTypeForNapiValue(napi_env env, napi_value param, napi_valuetype expectType);
};
}
#endif // FOUNDATION_ACE_COMPONENTEXT_EXT_COMMON_EXT_NAPI_UTILS_H
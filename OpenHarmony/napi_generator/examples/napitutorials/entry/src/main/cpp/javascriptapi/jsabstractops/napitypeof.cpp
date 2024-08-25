/*
 * Copyright (c) 2024 Shenzhen Kaihong Digital Industry Development Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "common.h"

static const char *TAG = "[jsapi_typeof]";

napi_value testNapiTypeof(napi_env env, napi_callback_info info)
{
    // pages/javascript/jsabstractops/typeof
    size_t requireArgc = PARAM1;
    size_t argc = PARAM1;
    napi_status status;
    napi_valuetype result;
    napi_value resultStr;
    napi_value args[PARAM1] = {nullptr};
    const napi_extended_error_info *extended_error_info;

    // Get args
    status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (status != napi_ok) {
        getErrMsg(status, env, extended_error_info, "get cb info", TAG);
        return NULL;
    }
    if (argc < requireArgc) {
        std::string errMsg = "Expected " + std::to_string(requireArgc) + " arguments";
        napi_throw_error(env, NULL, errMsg.c_str());
        return NULL;
    }

    // Call napi_typeof(), any -> napi_valuetype
    status = napi_typeof(env, args[PARAM0], &result);
    if (status != napi_ok) {
        getErrMsg(status, env, extended_error_info, "call napi_typeof()", TAG);
        return NULL;
    }

    // napi_valuetype -> string
    status = napiValueType2Str(env, result, &resultStr);
    if (status != napi_ok) {
        std::string errMsg = "Failed to convert napi_valuetype " + std::to_string(status) + " to string";
        napi_throw_error(env, NULL, errMsg.c_str());
        return NULL;
    }
    return resultStr;
}
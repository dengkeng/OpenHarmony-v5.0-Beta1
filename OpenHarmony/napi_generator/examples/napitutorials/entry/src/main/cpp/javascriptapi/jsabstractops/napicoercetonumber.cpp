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

static const char *TAG = "[jsapi_coercetonumber]";

napi_value testNapiCoerceToNumber(napi_env env, napi_callback_info info)
{
    // pages/javascript/jsabstractops/napicoercetonumber
    size_t requireArgc = 1;
    size_t argc = 1;
    napi_status status;
    napi_value result;
    napi_value args[1] = {nullptr};
    const napi_extended_error_info *extended_error_info;

    // Get args
    status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to parse arguments");
        return NULL;
    }

    // Call napi_coerce_to_number(), any -> number
    status = napi_coerce_to_number(env, args[0], &result);
    if (status != napi_ok) {
        status = napi_get_last_error_info(env, &extended_error_info);
        if (status == napi_ok && extended_error_info != NULL) {
            const char *errorMessage =
                extended_error_info->error_message != NULL ? extended_error_info->error_message : "Unknown error";

            OH_LOG_Print(LOG_APP, LOG_ERROR, GLOBAL_RESMGR, TAG, "errmsg %{public}s!, engine_err_code %{public}d!.",
                         errorMessage, extended_error_info->engine_error_code);
            std::string res = "Failed to coerce to number. em = " + std::string(errorMessage) +
                              ", eec = " + std::to_string(extended_error_info->engine_error_code) +
                              ", ec = " + std::to_string(extended_error_info->error_code);
            napi_throw_error(env, NULL, res.c_str());
            return NULL;
        }
    }

    // Check if the result is a number
    napi_valuetype resultType;
    napi_typeof(env, result, &resultType);
    if (resultType != napi_number) {
        std::string res = "Expected a number, got " + std::to_string(resultType);
        napi_throw_error(env, NULL, res.c_str());
        return NULL;
    }

    return result;
}
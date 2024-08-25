/*
 * Copyright (c) 2023 Shenzhen Kaihong Digital Industry Development Co., Ltd.
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

static const char *TAG = "[nodeapi_exterrinfo]";

napi_value testNapiExterrinfo(napi_env env, napi_callback_info info)
{
    // pages/nodeapi/datatypes/napiextendederrorinfo
    char buffer[PARAM100];
    size_t argc = PARAM2;
    napi_value argv[PARAM2];
    napi_status status;
    const napi_extended_error_info *extended_error_info;

    // 解析传入的参数
    status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to parse arguments");
        return NULL;
    }

    // 检查参数数量
    if (argc < PARAM2) {
        napi_throw_error(env, NULL, "Expected 2 arguments");
        return NULL;
    }

    int32_t num1 = 0;
    int32_t num2 = 0;
    status = napi_get_value_int32(env, argv[0], &num1);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Invalid first argument");
        return NULL;
    }

    status = napi_get_value_int32(env, argv[1], &num2);
    if (status != napi_ok) {
        status = napi_get_last_error_info(env, &extended_error_info);
        if (status == napi_ok && extended_error_info != NULL) {
            const char *errorMessage =
                extended_error_info->error_message != NULL ? extended_error_info->error_message : "Unknown error";
            OH_LOG_Print(LOG_APP, LOG_ERROR, GLOBAL_RESMGR, TAG, "errmsg %{public}s!, engine_err_code %{public}d!.",
                errorMessage, extended_error_info->engine_error_code);
            std::string res = "Failed to create threadsafe function em = " + std::string(errorMessage) +
                ", eec = " + std::to_string(extended_error_info->engine_error_code) +
                ", ec = " + std::to_string(extended_error_info->error_code);
            napi_throw_error(env, NULL, res.c_str());
        }
        
        return NULL;
    }

    // 执行加法操作
    int32_t result = num1 + num2;
    if (result > PARAM10) {
        napi_throw_error(env, NULL, "Invalid result > 10.");
        return NULL;
    }

    // 返回结果
    napi_value resultValue;
    status = napi_create_int32(env, result, &resultValue);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to create result value");
        return NULL;
    }

    return resultValue;
}

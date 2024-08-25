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

#include "nodeapi.h"

static const char *TAG = "[nodeapi_status]";

napi_value testNapiStatus(napi_env env, napi_callback_info info)
{
    // pages/nodeapi/datatypes/napistatus
    size_t argc = PARAM2;
    napi_value argv[PARAM2];
    napi_status status;

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
        napi_throw_error(env, NULL, "Invalid second argument");
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

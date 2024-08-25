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
#include "javascriptapi.h"
#include <bits/alltypes.h>

static const char *TAG = "[javascriptapi_values";

napi_value testNapiCreateUInt32(napi_env env, napi_callback_info info)
{
    // pages/javascript/jsvalues/napicreateuint32
    // 获取参数数量
    size_t argc = 1;
    // 准备接收参数的变量
    napi_value argv[1];
    uint32_t uintValue;
    napi_value result;
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    
    // 获取回调函数的参数信息
    status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    if (status != napi_ok) {
        getErrMsg(status, env, extended_error_info, "Failed to get callback info", TAG);
        return NULL;
    }
    
    // 检查参数数量是否符合预期
    if (argc != 1) {
        napi_throw_error(env, NULL, "Expected exactly one argument");
        return NULL;
    }

    // 从JavaScript值中提取出无符号整数
    status = napi_get_value_uint32(env, argv[0], &uintValue);
    if (status != napi_ok) {
        getErrMsg(status, env, extended_error_info, "Failed to convert argument to uint32", TAG);
        return NULL;
    }

    // 检查无符号整数是否为3
    if (uintValue != 3) {
        napi_throw_error(env, NULL, "The number is not 3");
        return NULL;
    }

    // 使用提取的无符号整数值创建一个新的napi_value
    status = napi_create_uint32(env, uintValue, &result);
    if (status != napi_ok) {
        getErrMsg(status, env, extended_error_info, "Failed to create uint32 value", TAG);
        return NULL;
    }

    // 返回创建的napi_value
    return result;
}
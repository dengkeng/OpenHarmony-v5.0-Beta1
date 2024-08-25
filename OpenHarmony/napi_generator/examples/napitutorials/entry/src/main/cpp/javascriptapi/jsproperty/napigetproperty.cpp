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

#include "javascriptapi.h"

static const char *TAG = "[javascriptapi_property]";

napi_value callFunctionIfTypeIsFunction(napi_env &env, napi_value &obj, napi_value &propValue)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    napi_valuetype valuetype;

    status = napi_typeof(env, propValue, &valuetype);
    if (status != napi_ok) {
        getErrMsg(status, env, extended_error_info, "get type", TAG);
        return NULL;
    }

    // propValue 是一个函数，我们可以尝试调用它
    if (valuetype == napi_function) {
        napi_value result;
        status = napi_call_function(env, obj, propValue, 0, NULL, &result);
        if (status != napi_ok) {
            getErrMsg(status, env, extended_error_info, "call function", TAG);
            return NULL;
        }
        // 函数被调用，其结果存储在 result 中,返回函数调用结果
        return result;
    }

    return propValue;
}

napi_value testNapiGetProperty(napi_env env, napi_callback_info info)
{
    // pages/javascript/jsproperties/napigetproperty
    size_t argc = PARAM2;
    napi_value argv[PARAM2];
    napi_status status;
    napi_value obj;
    napi_value propName;
    const napi_extended_error_info *extended_error_info;

    // 解析传入的参数
    status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    if (status != napi_ok) {
        getErrMsg(status, env, extended_error_info, "get cb info", TAG);
        return NULL;
    }

    // 检查参数数量
    if (argc < PARAM2) {
        napi_throw_error(env, NULL, "Expected 2 arguments");
        return NULL;
    }
    obj = argv[PARAM0];
    propName = argv[PARAM1];

    napi_valuetype valuetype0;

    // 确认第一个参数是个对象
    status = napi_typeof(env, obj, &valuetype0);
    if (status != napi_ok) {
        getErrMsg(status, env, extended_error_info, "get obj type", TAG);
        return NULL;
    }
    if (valuetype0 != napi_object) {
        napi_throw_type_error(env, NULL, "Wrong argument type, expected an object");
        return NULL;
    }

    // 读取属性
    napi_value propValue;
    status = napi_get_property(env, obj, propName, &propValue);
    if (status != napi_ok) {
        getErrMsg(status, env, extended_error_info, "get property", TAG);
        return NULL;
    }

    // 检查 propValue是否是一个函数
    napi_value result = callFunctionIfTypeIsFunction(env, obj, propValue);
    if (result != NULL) {
        return result;
    }

    // 返回属性值
    return propValue;
}

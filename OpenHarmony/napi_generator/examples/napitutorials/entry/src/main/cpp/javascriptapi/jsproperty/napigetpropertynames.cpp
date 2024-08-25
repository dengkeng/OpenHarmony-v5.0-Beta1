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

napi_value testNapiGetPropertyNames(napi_env env, napi_callback_info info)
{
    // pages/javascript/jsproperties/napigetpropertynames
    size_t argc = PARAM1;
    napi_value argv[PARAM1];
    napi_status status;
    napi_value obj;
    const napi_extended_error_info *extended_error_info;

    // 解析传入的参数
    status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    if (status != napi_ok) {
        getErrMsg(status, env, extended_error_info, "get cb info", TAG);
        return NULL;
    }

    // 检查参数数量
    if (argc < PARAM1) {
        napi_throw_error(env, NULL, "Expected 1 arguments");
        return NULL;
    }

    obj = argv[PARAM0];
    napi_value propertyNames;
    status = napi_get_property_names(env, obj, &propertyNames);
    if (status != napi_ok) {
        getErrMsg(status, env, extended_error_info, "get property names", TAG);
        return NULL;
    }

    uint32_t length = 0;
    status = napi_get_array_length(env, propertyNames, &length);
    if (status != napi_ok) {
        getErrMsg(status, env, extended_error_info, "get array length", TAG);
        return NULL;
    }
    // 打印属性个数
    OH_LOG_INFO(LOG_APP, "napi_get_array_length success! propertyNames length: %i", length);
    
    return propertyNames;
}

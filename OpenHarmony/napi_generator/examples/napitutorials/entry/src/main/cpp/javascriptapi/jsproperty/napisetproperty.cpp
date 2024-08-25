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

napi_value testNapiSetProperty(napi_env env, napi_callback_info info)
{
    // pages/javascript/jsproperties/napisetproperty
    size_t argc = PARAM3;
    napi_value argv[PARAM3];
    napi_status status;
    napi_value obj;
    napi_value propName;
    napi_value propValue;
    const napi_extended_error_info *extended_error_info;

    // 解析传入的参数
    status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    if (status != napi_ok) {
        getErrMsg(status, env, extended_error_info, "get cb info", TAG);
        return NULL;
    }

    // 检查参数数量
    if (argc < PARAM3) {
        napi_throw_error(env, NULL, "Expected 3 arguments");
        return NULL;
    }
    obj = argv[PARAM0];
    propName = argv[PARAM1];
    propValue = argv[PARAM2];

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
    
    // 设置对象的属性
    status = napi_set_property(env, obj, propName, propValue);
    if (status != napi_ok) {
        getErrMsg(status, env, extended_error_info, "set property", TAG);
        return NULL;
    }

    // 可以返回新设置对象
    return obj;
}

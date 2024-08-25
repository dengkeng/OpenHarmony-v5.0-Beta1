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

char *getSecondParamStr(napi_env &env, napi_value &propName)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    size_t str_size = 0;
    status = napi_get_value_string_utf8(env, propName, NULL, 0, &str_size);
    if (status != napi_ok) {
        getErrMsg(status, env, extended_error_info, "get value string", TAG);
        return NULL;
    }

    char *propertyName = new char[str_size + 1];
    status = napi_get_value_string_utf8(env, propName, propertyName, str_size + 1, &str_size);
    if (status != napi_ok) {
        getErrMsg(status, env, extended_error_info, "get value string", TAG);
        delete[] propertyName;
        return NULL;
    }
    return propertyName;
}

napi_value testNapiHasNamedProperty(napi_env env, napi_callback_info info)
{
    // pages/javascript/jsproperties/napihasnamedproperty
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
    // 判断参数有效性
    bool resValid = validateObjectProperty(env, obj, propName, TAG);
    if (resValid == false) {
        return NULL;
    }
    // 将第二个参数从napi_value转换为C字符串
    char *propertyName = getSecondParamStr(env, propName);
    // 获取对象上指定名称的属性
    bool hasProperty = false;
    status = napi_has_named_property(env, obj, propertyName, &hasProperty);
    free(propertyName);
    if (status != napi_ok) {
        if (status != napi_ok) {
            getErrMsg(status, env, extended_error_info, "has named property", TAG);
            return NULL;
        }
        return NULL;
    }
    // 返回属性是否存在的布尔值
    napi_value result;
    status = napi_get_boolean(env, hasProperty, &result);
    if (status != napi_ok) {
        getErrMsg(status, env, extended_error_info, "get boolean", TAG);
        return NULL;
    }
    return result;
}
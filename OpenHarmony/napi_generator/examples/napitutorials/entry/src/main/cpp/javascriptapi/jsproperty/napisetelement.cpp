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

napi_value testNapiSetElement(napi_env env, napi_callback_info info)
{
    // pages/javascript/jsproperties/napisetelement
    size_t argc = PARAM3;
    napi_value argv[PARAM3];
    napi_status status;
    napi_value arrayObj;
    napi_value elementIndex;
    napi_value valueToSet;
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
    arrayObj = argv[PARAM0];
    elementIndex = argv[PARAM1];
    valueToSet = argv[PARAM2];

    // 判断参数有效性
    bool resValid = validateArrayObjProperty(env, arrayObj, elementIndex, TAG);
    if (resValid == false) {
        return NULL;
    }
    
    uint32_t index = 0;
    // 将第二个参数（索引）转换为本地 uint32_t
    status = napi_get_value_uint32(env, elementIndex, &index);
    if (status != napi_ok) {
        getErrMsg(status, env, extended_error_info, "get value uint32", TAG);
        return NULL;
    }

    // 设置数组元素
    status = napi_set_element(env, arrayObj, index, valueToSet);
    if (status != napi_ok) {
        getErrMsg(status, env, extended_error_info, "set element", TAG);
        return NULL;
    }

    // 可以返回新设置对象
    return arrayObj;
}

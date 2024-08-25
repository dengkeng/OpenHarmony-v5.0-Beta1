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

static const char *TAG = "[nodeapi_value]";

napi_value testNapiValue(napi_env env, napi_callback_info info)
{
    // pages/nodeapi/datatypes/napivalue
    size_t argc = PARAM2;
    napi_value argv[PARAM2];
    napi_status status;

    // 返回结果
    napi_value resultValue;
    status = napi_create_string_utf8(env, "test_napi_value", NAPI_AUTO_LENGTH, &resultValue);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to create result value");
        return NULL;
    }

    return resultValue;
}

/*
 * Copyright (c) 2024 Shenzhen Kaihong Digital Industry Development Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "common.h"
#include "javascriptapi.h"

void getErrMsg(napi_status &status, napi_env &env, const napi_extended_error_info *&extended_error_info,
    const char *info, const char *tag)
{
    status = napi_get_last_error_info(env, &extended_error_info);
    if (status == napi_ok && extended_error_info != NULL) {
        const char *errorMessage =
            extended_error_info->error_message != NULL ? extended_error_info->error_message : "Unknown error";
        OH_LOG_Print(LOG_APP, LOG_ERROR, GLOBAL_RESMGR, tag, "errmsg %{public}s!, engine_err_code %{public}d!.",
                     std::to_string(extended_error_info->engine_error_code).c_str(), extended_error_info->error_code);
        std::string myInfo = info;
        std::string res = "Failed to " + myInfo + " em = " + std::to_string(extended_error_info->engine_error_code) +
                          ", eec = " + std::to_string(extended_error_info->engine_error_code) +
                          ", ec = " + std::to_string(extended_error_info->error_code);
        napi_throw_error(env, NULL, res.c_str());
    }
}

bool validateObjectProperty(napi_env &env, napi_value &obj, napi_value &propName, const char *tag)
{
    napi_status status;
    napi_valuetype valuetype0;
    napi_valuetype valuetype1;
    const napi_extended_error_info *extended_error_info;

    // 确认第一个参数是个对象
    status = napi_typeof(env, obj, &valuetype0);
    if (status != napi_ok) {
        getErrMsg(status, env, extended_error_info, "get obj type", tag);
        return false;
    }
    if (valuetype0 != napi_object) {
        napi_throw_type_error(env, NULL, "Wrong argument type, expected an object");
        return false;
    }

    // 确认第二个参数是个字符串
    status = napi_typeof(env, propName, &valuetype1);
    if (status != napi_ok) {
        getErrMsg(status, env, extended_error_info, "get propName type", tag);
        return false;
    }
    if (valuetype1 != napi_string) {
        napi_throw_type_error(env, NULL, "Wrong argument type, expected a string");
        return false;
    }
    return true;
}

bool validateArrayObjProperty(napi_env &env, napi_value &obj, napi_value &propName, const char *tag)
{
    napi_status status;
    napi_valuetype valuetype0;
    napi_valuetype valuetype1;
    const napi_extended_error_info *extended_error_info;

    // 确认第一个参数是个对象
    status = napi_typeof(env, obj, &valuetype0);
    if (status != napi_ok) {
        getErrMsg(status, env, extended_error_info, "get obj type", tag);
        return false;
    }
    if (valuetype0 != napi_object) {
        napi_throw_type_error(env, NULL, "Wrong argument type, expected an object");
        return false;
    }

    // 确认第二个参数是个数字
    status = napi_typeof(env, propName, &valuetype1);
    if (status != napi_ok) {
        getErrMsg(status, env, extended_error_info, "get propName type", tag);
        return false;
    }
    if (valuetype1 != napi_number) {
        napi_throw_type_error(env, NULL, "Wrong argument type, expected a number");
        return false;
    }
    return true;
}

napi_status napiValueType2Str(const napi_env &env, const napi_valuetype type, napi_value *result)
{
    const char *typeStr = "";
    napi_status status;
    // napi_valuetype -> const char *
    switch (type) {
        case napi_undefined:
            typeStr = "undefined";
            break;
        case napi_null:
            typeStr = "null";
            break;
        case napi_boolean:
            typeStr = "boolean";
            break;
        case napi_number:
            typeStr = "number";
            break;
        case napi_string:
            typeStr = "string";
            break;
        case napi_symbol:
            typeStr = "symbol";
            break;
        case napi_object:
            typeStr = "object";
            break;
        case napi_function:
            typeStr = "function";
            break;
        case napi_external:
            typeStr = "external";
            break;
        case napi_bigint:
            typeStr = "bigint";
            break;
        default:
            typeStr = "unknown";
            break;
    }
    // const char * -> napi_value
    status = napi_create_string_utf8(env, typeStr, NAPI_AUTO_LENGTH, result);
    return status;
}

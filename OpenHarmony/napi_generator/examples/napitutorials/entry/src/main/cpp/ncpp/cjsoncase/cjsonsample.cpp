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

#include "cjsonsample.h"
#include "nodeapi.h"
#include "cJsonNapiH/cjsonnapi.h"

napi_value cJsonCaseInit(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        {"KH418_cJSON_Parse", nullptr, KH418_CJSON_Parse, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"KH373_cJSON_GetArraySize", nullptr, KH373_cJSON_GetArraySize, nullptr, nullptr, nullptr, napi_default,
         nullptr},
        {"KH735_cJSON_Print", nullptr, KH735_cJSON_Print, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"KH361_cJSON_CreateObject", nullptr, KH361_cJSON_CreateObject, nullptr, nullptr, nullptr, napi_default,
         nullptr},
        {"KH515_cJSON_CreateString", nullptr, KH515_cJSON_CreateString, nullptr, nullptr, nullptr, napi_default,
         nullptr},
        {"KH526_cJSON_AddStringToObject", nullptr, KH526_cJSON_AddStringToObject, nullptr, nullptr, nullptr,
         napi_default, nullptr},
        {"KH206_cJSON_AddNumberToObject", nullptr, KH206_cJSON_AddNumberToObject, nullptr, nullptr, nullptr,
         napi_default, nullptr},
        {"KH545_cJSON_AddFalseToObject", nullptr, KH545_cJSON_AddFalseToObject, nullptr, nullptr, nullptr, napi_default,
         nullptr},
        {"KH180_cJSON_AddItemToObject", nullptr, KH180_cJSON_AddItemToObject, nullptr, nullptr, nullptr, napi_default,
         nullptr},
        {"KH386_cJSON_CreateArray", nullptr, KH386_cJSON_CreateArray, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"KH203_cJSON_CreateIntArray", nullptr, KH203_cJSON_CreateIntArray, nullptr, nullptr, nullptr, napi_default,
         nullptr},
        {"KH802_cJSON_AddItemToArray", nullptr, KH802_cJSON_AddItemToArray, nullptr, nullptr, nullptr, napi_default,
         nullptr},
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(napi_property_descriptor), desc);
    return exports;
}

napi_value createTctCJsonInstance(napi_env env)
{
    napi_status status;
    napi_value instance;

    OH_LOG_Print(LOG_APP, LOG_INFO, GLOBAL_RESMGR, "basesample", "Add in");
    
    status = napi_create_object(env, &instance);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "Failed to create object");
        return nullptr;
    }

    napi_value pname;
    status = napi_create_string_utf8(env, "tct_cjson", strlen("tct_cjson"), &pname);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "Invalid argument: name must be a string");
        return nullptr;
    }
    
    status = napi_set_named_property(env, instance, "name", pname);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "Failed to set property");
        return nullptr;
    }

    cJsonCaseInit(env, instance);
    napi_property_descriptor properties[] = {
        {"cjson_version", nullptr, cJSONVersion, nullptr, nullptr, nullptr, napi_default, nullptr},
    };

    status = napi_define_properties(env, instance, sizeof(properties) / sizeof(napi_property_descriptor), properties);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "Failed to define properties");
        return nullptr;
    }
    return instance;
}

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

#include "nadatatypes.h"
#include "nodeapi.h"

napi_value createTctNADataTypeInstance(napi_env env)
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
    status = napi_create_string_utf8(env, "tct_datatypes", strlen("tct_datatypes"), &pname);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "Invalid argument: name must be a string");
        return nullptr;
    }

    status = napi_set_named_property(env, instance, "name", pname);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "Failed to set property");
        return nullptr;
    }

    napi_property_descriptor properties[] = {
        {"testNapiStatus", nullptr, testNapiStatus, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"testExterrinfo", nullptr, testNapiExterrinfo, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"testNapiEnv", nullptr, testNapiEnv, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"testNapiValue", nullptr, testNapiValue, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"testNapiThreadsafefunc", nullptr, setThreadsafefunc, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"testNapiThreadsafefuncrel", nullptr, setThreadsafefuncrel, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"testNapiThreadsafefuncall", nullptr, setThreadsafefuncall, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"cjson_version", nullptr, cJSONVersion, nullptr, nullptr, nullptr, napi_default, nullptr},
    };

    status = napi_define_properties(env, instance, sizeof(properties) / sizeof(napi_property_descriptor), properties);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "Failed to define properties");
        return nullptr;
    }
    return instance;
}
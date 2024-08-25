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

#include "basesample.h"

static napi_value Add(napi_env env, napi_callback_info info)
{
    size_t requireArgc = 2;
    size_t argc = 2;
    napi_value args[2] = {nullptr};

    OH_LOG_Print(LOG_APP, LOG_INFO, GLOBAL_RESMGR, "basesample", "Add in");
    
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    napi_valuetype valuetype0;
    napi_typeof(env, args[0], &valuetype0);

    napi_valuetype valuetype1;
    napi_typeof(env, args[1], &valuetype1);

    double value0;
    napi_get_value_double(env, args[0], &value0);

    double value1;
    napi_get_value_double(env, args[1], &value1);

    napi_value sum;
    napi_create_double(env, value0 + value1, &sum);

    return sum;
}

napi_value createTctBaseInstance(napi_env env)
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
    status = napi_create_string_utf8(env, "tct_base", PARAM10, &pname);
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
        {"add", nullptr, Add, nullptr, nullptr, nullptr, napi_default, nullptr},
    };

    status = napi_define_properties(env, instance, sizeof(properties) / sizeof(napi_property_descriptor), properties);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "Failed to define properties");
        return nullptr;
    }
    return instance;
}

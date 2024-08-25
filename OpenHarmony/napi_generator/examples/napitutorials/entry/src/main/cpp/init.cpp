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

#include "napi/native_api.h"
#include <bits/alltypes.h>
#include "nodeapi.h"
#include "basesample.h"
#include "nadatatypes.h"
#include "cjsonsample.h"
#include "javascriptapi.h"
#include "ncpp/ffmpegcase/manager/plugin_manager.h"
#include <iostream>
#include <fstream>
#include "cJsonNapiH/cjsonnapi.h"

static napi_value Add(napi_env env, napi_callback_info info)
{
    size_t requireArgc = 2;
    size_t argc = 2;
    napi_value args[2] = {nullptr};

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

static napi_value getTestCase(napi_env env, napi_callback_info info)
{
    size_t requireArgc = 1;
    size_t argc = 1;
    napi_value args[1] = {nullptr};
    napi_status status;
    int32_t result = 0;

    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    napi_valuetype valuetype0;
    napi_typeof(env, args[0], &valuetype0);

    uint32_t value0;
    napi_get_value_uint32(env, args[0], &value0);

    OH_LOG_Print(LOG_APP, LOG_INFO, GLOBAL_RESMGR, "getTestCase", "input param %{public}d", value0);
    
    // 返回结果
    napi_value resultValue;
    switch (value0) {
        case TCT_BASE:
            {
                resultValue = createTctBaseInstance(env);
            }
            break;
        case TCT_NADATATYPE:
            {
                resultValue = createTctNADataTypeInstance(env);
            }
            break;
        case TCT_NAENVLCAPI:
        case TCT_JSABSTARCTOPS:
        case TCT_JSPREOPERTY:
        case TCT_JSVALUES:
            break;
        case TCT_CJSON:
            {
                resultValue = createTctCJsonInstance(env);
            }
            break;
        case TCT_FFMPEG:
        case TCT_OPENCV:
            break;
        default:
            break;
    }

    return resultValue;
}

EXTERN_C_START
static napi_value Init(napi_env env, napi_value exports)
{
    // 对应nodeapi/envlifecycleapis/napisetinstancedata
    setInstancedata(env, exports);
	
	// 对应 javascriptapi/jsvalues/jsValuesInit.cpp
    jsValuesInit(env, exports);

    // 对应 javascriptapi/jsproperty/jsPropertyInit.cpp
    jsPropertyInit(env, exports);

    napi_property_descriptor descArr[] = {
        {"add", nullptr, Add, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"getTestCase", nullptr, getTestCase, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"testNapiStatus", nullptr, testNapiStatus, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"testExterrinfo", nullptr, testNapiExterrinfo, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"testNapiEnv", nullptr, testNapiEnv, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"testNapiValue", nullptr, testNapiValue, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"testNapiThreadsafefunc", nullptr, setThreadsafefunc, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"testNapiThreadsafefuncrel", nullptr, setThreadsafefuncrel, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"testNapiThreadsafefuncall", nullptr, setThreadsafefuncall, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"cjson_version", nullptr, cJSONVersion, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"getContext", nullptr, NativeXComponentSample::PluginManager::GetContext,
            nullptr, nullptr, nullptr, napi_default, nullptr},
    };
    napi_define_properties(env, exports, sizeof(descArr) / sizeof(descArr[0]), descArr);

    NativeXComponentSample::PluginManager::GetInstance()->Export(env, exports);
    size_t len = sizeof(descArr) / sizeof(napi_property_descriptor);

    // Allocate memory & copy
    napi_property_descriptor *desc = (napi_property_descriptor *)malloc(sizeof(descArr));
    if (desc == nullptr) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, GLOBAL_RESMGR, "jsAbstractOpsInit", "Failed to allocated memory");
        napi_throw_error(env, NULL, "Failed to allocate memory");
    }
    for (size_t i = 0; i < len; ++i) {
        desc[i] = descArr[i];
    }

    // Initialization of functions in `javascriptapi/jsabstractops`
    jsAbstractOpsInit(&desc, &len);

    napi_define_properties(env, exports, len, desc);
    return exports;
}
EXTERN_C_END

static napi_module demoModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "entry",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void RegisterEntryModule(void) { napi_module_register(&demoModule); }

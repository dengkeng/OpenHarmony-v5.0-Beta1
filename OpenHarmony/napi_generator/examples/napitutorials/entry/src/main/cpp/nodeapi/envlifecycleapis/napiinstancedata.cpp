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

#include "common.h"

static const char *TAG = "[nodeapi_instancedata]";

// 设置要关联的自定义数据
// warning: 'napi_set_instance_data' is deprecated [-Wdeprecated-declarations]
// ld.lld: error: undefined symbol: napi_set_instance_data
#define TEST_INT32 315
napi_value setInstancedata(napi_env env, napi_value exports)
{
    // pages/nodeapi/envlifecycleapis/napisetinstancedata
    napi_value instance;
    napi_create_object(env, &instance);
    napi_value testint32 = nullptr;
    napi_create_int32(env, TEST_INT32, &testint32);
    napi_set_named_property(env, instance, "testint32", testint32);

    // 导出 N-API 实例对象
    napi_set_named_property(env, exports, "instance", instance);
    return instance;
}

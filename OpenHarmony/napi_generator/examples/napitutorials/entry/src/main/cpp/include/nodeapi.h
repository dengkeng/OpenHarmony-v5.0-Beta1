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

#ifndef NAPITUTORIALS_NODEAPI_H
#define NAPITUTORIALS_NODEAPI_H

#include "common.h"

extern napi_threadsafe_function g_threadsafeFunction;
extern napi_threadsafe_function g_threadsafeFunction_call;
extern napi_threadsafe_function g_threadsafeFunction_rel;

napi_value setInstancedata(napi_env env, napi_value exports);
napi_value testNapiStatus(napi_env env, napi_callback_info info);
napi_value testNapiExterrinfo(napi_env env, napi_callback_info info);
napi_value testNapiEnv(napi_env env, napi_callback_info info);
napi_value testNapiValue(napi_env env, napi_callback_info info);
napi_value setThreadsafefunc(napi_env env, napi_callback_info info);
napi_value setThreadsafefuncrel(napi_env env, napi_callback_info info);
napi_value setThreadsafefuncall(napi_env env, napi_callback_info info);

napi_value cJSONVersion(napi_env env, napi_callback_info info);

#endif //NAPITUTORIALS_NODEAPI_H

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
#include <thread>

static const char *TAG = "[nodeapi_threadsafefunc]";

// 线程安全的 JavaScript 函数对象
napi_threadsafe_function g_threadsafeFunction_rel;

// JavaScript 回调函数
static void CallbackFunction(napi_env env, napi_value jsCallback, void *context, void *data)
{
    // 在 JavaScript 环境中执行回调函数
    size_t argc = 1;
    napi_value argv[1];
    napi_create_string_utf8(env, "test_threadsafe_func", NAPI_AUTO_LENGTH, &argv[0]);
    napi_call_function(env, nullptr, jsCallback, argc, argv, nullptr);
}

// 线程函数，在这里异步调用 JavaScript 函数
static void ThreadFunction(void *data)
{
    // 在另一个线程中异步调用 JavaScript 函数
    napi_call_threadsafe_function(g_threadsafeFunction_rel, nullptr, napi_tsfn_nonblocking);
}

napi_value setThreadsafefuncrel(napi_env env, napi_callback_info info)
{
    // pages/nodeapi/envlifecycleapis/napithreadsafefunc
    // 创建线程安全的 JavaScript 函数对象

    size_t argc = PARAM2;
    napi_value argv[PARAM2];
    napi_status status;
    char buffer[PARAM100];
    const napi_extended_error_info *extended_error_info;

    // 解析传入的参数
    status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to parse arguments");
        return NULL;
    }

    // 检查参数数量
    if (argc < 1) {
        napi_throw_error(env, NULL, "Expected 1 arguments");
        return NULL;
    }
    napi_value name;
    napi_create_string_utf8(env, "testThreadsafefunc", NAPI_AUTO_LENGTH, &name);
    status = napi_create_threadsafe_function(env, argv[0], nullptr, name, 0, 1,
        nullptr, nullptr, nullptr, CallbackFunction, &g_threadsafeFunction_rel);
    if (status != napi_ok) {
        status = napi_get_last_error_info(env, &extended_error_info);
        if (status == napi_ok && extended_error_info != NULL) {
            const char *errorMessage =
                extended_error_info->error_message != NULL ? extended_error_info->error_message : "Unknown error";

            OH_LOG_Print(LOG_APP, LOG_ERROR, GLOBAL_RESMGR, TAG, "errmsg %{public}s!, engine_err_code %{public}d!.",
                         errorMessage, extended_error_info->engine_error_code);
            std::string res = "Failed to create threadsafe function em = " + std::string(errorMessage) +
                              ", eec = " + std::to_string(extended_error_info->engine_error_code) +
                              ", ec = " + std::to_string(extended_error_info->error_code);
            napi_throw_error(env, NULL, res.c_str());
            return NULL;
        }
    }

    // 设置释放模式为 NAPI_TSFN_RELEASE
    napi_threadsafe_function_release_mode release_mode = napi_tsfn_release;
    napi_release_threadsafe_function(g_threadsafeFunction_rel, release_mode);

    // 启动一个新线程
    std::thread newThread(ThreadFunction, nullptr);
    newThread.join();

    // 执行加法操作
    int32_t result = 0;
    if (result > PARAM10) {
        napi_throw_error(env, NULL, "Invalid result > 10.");
        return NULL;
    }

    // 返回结果
    napi_value resultValue;
    status = napi_create_int32(env, result, &resultValue);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to create result value");
        return NULL;
    }

    return resultValue;
}

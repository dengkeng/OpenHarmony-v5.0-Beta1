/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "native_engine/native_engine.h"

extern const char _binary_callee_js_start[];
extern const char _binary_callee_js_end[];
extern const char _binary_callee_abc_start[];
extern const char _binary_callee_abc_end[];

static napi_module _module = {
    .nm_version = 0,
    .nm_filename = "application/libcallee_napi.so/callee.js",
    .nm_modname = "application.Callee",
};
extern "C" __attribute__((constructor))
void NAPI_application_Callee_AutoRegister()
{
    napi_module_register(&_module);
}

extern "C" __attribute__((visibility("default")))
void NAPI_application_Callee_GetJSCode(const char **buf, int *bufLen)
{
    if (buf != nullptr) {
        *buf = _binary_callee_js_start;
    }

    if (bufLen != nullptr) {
        *bufLen = _binary_callee_js_end - _binary_callee_js_start;
    }
}

// callee JS register
extern "C" __attribute__((visibility("default")))
void NAPI_application_Callee_GetABCCode(const char **buf, int *buflen)
{
    if (buf != nullptr) {
        *buf = _binary_callee_abc_start;
    }
    if (buflen != nullptr) {
        *buflen = _binary_callee_abc_end - _binary_callee_abc_start;
    }
}

/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <native_engine/native_engine.h>

#include "js_screen_session_manager.h"

static napi_module g_screenSessionModule = {
    .nm_filename = "libscreensessionmanager_napi.so/screenSessionManager.js",
    .nm_register_func = OHOS::Rosen::JsScreenSessionManager::Init,
    .nm_modname = "screenSessionManager",
};

extern "C" __attribute__((constructor)) void NAPI_screenSessionManager_AutoRegister()
{
    napi_module_register(&g_screenSessionModule);
}

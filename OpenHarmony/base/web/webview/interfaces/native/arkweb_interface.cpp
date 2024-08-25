/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "arkweb_interface.h"

#include <dlfcn.h>

#include "arkweb_type.h"
#include "nweb_helper.h"
#include "nweb_log.h"

namespace {
#define ARKWEB_NATIVE_FOR_EACH_COMPONENT_API_FN(DO)          \
    DO(onControllerAttached, OH_ArkWeb_OnControllerAttached) \
    DO(onPageBegin, OH_ArkWeb_OnPageBegin)                   \
    DO(onPageEnd, OH_ArkWeb_OnPageEnd)                       \
    DO(onDestroy, OH_ArkWeb_OnDestroy)

#define ARKWEB_NATIVE_FOR_EACH_CONTROLLER_API_FN(DO)               \
    DO(runJavaScript, OH_ArkWeb_RunJavaScript)                     \
    DO(registerJavaScriptProxy, OH_ArkWeb_RegisterJavaScriptProxy) \
    DO(deleteJavaScriptRegister, OH_ArkWeb_DeleteJavaScriptProxy)  \
    DO(refresh, OH_ArkWeb_Refresh)                                 \
    DO(registerAsyncJavaScriptProxy, OH_ArkWeb_RegisterAsyncJavaScriptProxy)

ArkWeb_ComponentAPI* g_ComponentImpl = nullptr;
ArkWeb_ControllerAPI* g_ControllerImpl = nullptr;

} // namespace

template<typename Fn>
static void LoadFunction(void* handle, const char* functionName, Fn* fnOut)
{
    void* fn = dlsym(handle, functionName);
    if (!fn) {
        WVLOG_E("%{public}s not found.", functionName);
        return;
    }
    *fnOut = reinterpret_cast<Fn>(fn);
}

static bool LoadComponentAPI()
{
    if (g_ComponentImpl) {
        WVLOG_I("NativeArkWeb component api already loaded");
        return true;
    }
    g_ComponentImpl = new ArkWeb_ComponentAPI();
    if (!g_ComponentImpl) {
        WVLOG_E("NativeArkWeb component api is nullptr");
        return false;
    }
    g_ComponentImpl->size = sizeof(ArkWeb_ComponentAPI);

    void* webEngineHandle = OHOS::NWeb::NWebHelper::Instance().GetWebEngineHandler();
    if (!webEngineHandle) {
        WVLOG_E("NativeArkWeb webEngineHandle is nullptr");
        return false;
    }
#define ARKWEB_NATIVE_LOAD_FN_PTR(fn, ndkFn) LoadFunction(webEngineHandle, #ndkFn, &(g_ComponentImpl->fn));
    ARKWEB_NATIVE_FOR_EACH_COMPONENT_API_FN(ARKWEB_NATIVE_LOAD_FN_PTR)
#undef ARKWEB_NATIVE_LOAD_FN_PTR

    return true;
}

static bool LoadControllerAPI()
{
    if (g_ControllerImpl) {
        WVLOG_I("NativeArkWeb controller api already loaded");
        return true;
    }
    g_ControllerImpl = new ArkWeb_ControllerAPI();
    if (!g_ControllerImpl) {
        WVLOG_E("NativeArkWeb controller api is nullptr");
        return false;
    }
    g_ControllerImpl->size = sizeof(ArkWeb_ControllerAPI);

    void* webEngineHandle = OHOS::NWeb::NWebHelper::Instance().GetWebEngineHandler();
    if (!webEngineHandle) {
        WVLOG_E("NativeArkWeb webEngineHandle is nullptr");
        return false;
    }
#define ARKWEB_NATIVE_LOAD_FN_PTR(fn, ndkFn) LoadFunction(webEngineHandle, #ndkFn, &(g_ControllerImpl->fn));
    ARKWEB_NATIVE_FOR_EACH_CONTROLLER_API_FN(ARKWEB_NATIVE_LOAD_FN_PTR)
#undef ARKWEB_NATIVE_LOAD_FN_PTR

    return true;
}

ArkWeb_AnyNativeAPI* OH_ArkWeb_GetNativeAPI(ArkWeb_NativeAPIVariantKind type)
{
    switch (type) {
        case ARKWEB_NATIVE_COMPONENT: {
            if (!LoadComponentAPI()) {
                return nullptr;
            }
            return reinterpret_cast<ArkWeb_AnyNativeAPI*>(g_ComponentImpl);
        }
        case ARKWEB_NATIVE_CONTROLLER: {
            if (!LoadControllerAPI()) {
                return nullptr;
            }
            return reinterpret_cast<ArkWeb_AnyNativeAPI*>(g_ControllerImpl);
        }
        default: {
            WVLOG_E("fail to get %{public}d arkweb api family", type);
            return nullptr;
        }
    }
}

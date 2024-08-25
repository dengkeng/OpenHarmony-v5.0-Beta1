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

#include "ohos_adapter/cpptoc/ark_window_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

void* ARK_WEB_CALLBACK ark_window_adapter_create_native_window_from_surface(
    struct _ark_window_adapter_t* self, void* pSurface)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    ARK_WEB_CPPTOC_CHECK_PARAM(pSurface, NULL);

    // Execute
    return ArkWindowAdapterCppToC::Get(self)->CreateNativeWindowFromSurface(pSurface);
}

void ARK_WEB_CALLBACK ark_window_adapter_destroy_native_window(struct _ark_window_adapter_t* self, void* window)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(window, );

    // Execute
    ArkWindowAdapterCppToC::Get(self)->DestroyNativeWindow(window);
}

int32_t ARK_WEB_CALLBACK ark_window_adapter_native_window_set_buffer_geometry(
    struct _ark_window_adapter_t* self, void* window, int32_t width, int32_t height)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(window, 0);

    // Execute
    return ArkWindowAdapterCppToC::Get(self)->NativeWindowSetBufferGeometry(window, width, height);
}

void ARK_WEB_CALLBACK ark_window_adapter_native_window_surface_clean_cache(
    struct _ark_window_adapter_t* self, void* window)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(window, );

    // Execute
    ArkWindowAdapterCppToC::Get(self)->NativeWindowSurfaceCleanCache(window);
}

} // namespace

ArkWindowAdapterCppToC::ArkWindowAdapterCppToC()
{
    GetStruct()->create_native_window_from_surface = ark_window_adapter_create_native_window_from_surface;
    GetStruct()->destroy_native_window = ark_window_adapter_destroy_native_window;
    GetStruct()->native_window_set_buffer_geometry = ark_window_adapter_native_window_set_buffer_geometry;
    GetStruct()->native_window_surface_clean_cache = ark_window_adapter_native_window_surface_clean_cache;
}

ArkWindowAdapterCppToC::~ArkWindowAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkWindowAdapterCppToC, ArkWindowAdapter, ark_window_adapter_t>::kBridgeType =
    ARK_WINDOW_ADAPTER;

} // namespace OHOS::ArkWeb

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

#include "ohos_adapter/cpptoc/ark_surface_buffer_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

int32_t ARK_WEB_CALLBACK ark_surface_buffer_adapter_get_file_descriptor(struct _ark_surface_buffer_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkSurfaceBufferAdapterCppToC::Get(self)->GetFileDescriptor();
}

int32_t ARK_WEB_CALLBACK ark_surface_buffer_adapter_get_width(struct _ark_surface_buffer_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkSurfaceBufferAdapterCppToC::Get(self)->GetWidth();
}

int32_t ARK_WEB_CALLBACK ark_surface_buffer_adapter_get_height(struct _ark_surface_buffer_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkSurfaceBufferAdapterCppToC::Get(self)->GetHeight();
}

int32_t ARK_WEB_CALLBACK ark_surface_buffer_adapter_get_stride(struct _ark_surface_buffer_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkSurfaceBufferAdapterCppToC::Get(self)->GetStride();
}

int32_t ARK_WEB_CALLBACK ark_surface_buffer_adapter_get_format(struct _ark_surface_buffer_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkSurfaceBufferAdapterCppToC::Get(self)->GetFormat();
}

uint32_t ARK_WEB_CALLBACK ark_surface_buffer_adapter_get_size(struct _ark_surface_buffer_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkSurfaceBufferAdapterCppToC::Get(self)->GetSize();
}

void* ARK_WEB_CALLBACK ark_surface_buffer_adapter_get_vir_addr(struct _ark_surface_buffer_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    return ArkSurfaceBufferAdapterCppToC::Get(self)->GetVirAddr();
}

} // namespace

ArkSurfaceBufferAdapterCppToC::ArkSurfaceBufferAdapterCppToC()
{
    GetStruct()->get_file_descriptor = ark_surface_buffer_adapter_get_file_descriptor;
    GetStruct()->get_width = ark_surface_buffer_adapter_get_width;
    GetStruct()->get_height = ark_surface_buffer_adapter_get_height;
    GetStruct()->get_stride = ark_surface_buffer_adapter_get_stride;
    GetStruct()->get_format = ark_surface_buffer_adapter_get_format;
    GetStruct()->get_size = ark_surface_buffer_adapter_get_size;
    GetStruct()->get_vir_addr = ark_surface_buffer_adapter_get_vir_addr;
}

ArkSurfaceBufferAdapterCppToC::~ArkSurfaceBufferAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkSurfaceBufferAdapterCppToC, ArkSurfaceBufferAdapter,
    ark_surface_buffer_adapter_t>::kBridgeType = ARK_SURFACE_BUFFER_ADAPTER;

} // namespace OHOS::ArkWeb

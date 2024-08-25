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

#include "ohos_adapter/cpptoc/ark_display_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

uint64_t ARK_WEB_CALLBACK ark_display_adapter_get_id(struct _ark_display_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkDisplayAdapterCppToC::Get(self)->GetId();
}

int32_t ARK_WEB_CALLBACK ark_display_adapter_get_width(struct _ark_display_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkDisplayAdapterCppToC::Get(self)->GetWidth();
}

int32_t ARK_WEB_CALLBACK ark_display_adapter_get_height(struct _ark_display_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkDisplayAdapterCppToC::Get(self)->GetHeight();
}

float ARK_WEB_CALLBACK ark_display_adapter_get_virtual_pixel_ratio(struct _ark_display_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkDisplayAdapterCppToC::Get(self)->GetVirtualPixelRatio();
}

uint32_t ARK_WEB_CALLBACK ark_display_adapter_get_rotation(struct _ark_display_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkDisplayAdapterCppToC::Get(self)->GetRotation();
}

uint32_t ARK_WEB_CALLBACK ark_display_adapter_get_orientation(struct _ark_display_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkDisplayAdapterCppToC::Get(self)->GetOrientation();
}

int32_t ARK_WEB_CALLBACK ark_display_adapter_get_dpi(struct _ark_display_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkDisplayAdapterCppToC::Get(self)->GetDpi();
}
uint32_t ARK_WEB_CALLBACK ark_display_adapter_get_display_orientation(struct _ark_display_adapter_t* self) {
  ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

  ARK_WEB_CPPTOC_CHECK_PARAM(self,  0);

  // Execute
  return ArkDisplayAdapterCppToC::Get(self)->GetDisplayOrientation();
}
} // namespace

ArkDisplayAdapterCppToC::ArkDisplayAdapterCppToC()
{
    GetStruct()->get_id = ark_display_adapter_get_id;
    GetStruct()->get_width = ark_display_adapter_get_width;
    GetStruct()->get_height = ark_display_adapter_get_height;
    GetStruct()->get_virtual_pixel_ratio = ark_display_adapter_get_virtual_pixel_ratio;
    GetStruct()->get_rotation = ark_display_adapter_get_rotation;
    GetStruct()->get_orientation = ark_display_adapter_get_orientation;
    GetStruct()->get_dpi = ark_display_adapter_get_dpi;
    GetStruct()->get_display_orientation = ark_display_adapter_get_display_orientation;
}

ArkDisplayAdapterCppToC::~ArkDisplayAdapterCppToC() {}

template<>
ArkWebBridgeType
    ArkWebCppToCRefCounted<ArkDisplayAdapterCppToC, ArkDisplayAdapter, ark_display_adapter_t>::kBridgeType =
        ARK_DISPLAY_ADAPTER;

} // namespace OHOS::ArkWeb

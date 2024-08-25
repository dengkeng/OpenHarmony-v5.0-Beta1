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

#include "ohos_adapter/cpptoc/ark_video_control_support_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

bool ARK_WEB_CALLBACK ark_video_control_support_adapter_get_pan(struct _ark_video_control_support_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkVideoControlSupportAdapterCppToC::Get(self)->GetPan();
}

bool ARK_WEB_CALLBACK ark_video_control_support_adapter_get_tilt(struct _ark_video_control_support_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkVideoControlSupportAdapterCppToC::Get(self)->GetTilt();
}

bool ARK_WEB_CALLBACK ark_video_control_support_adapter_get_zoom(struct _ark_video_control_support_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkVideoControlSupportAdapterCppToC::Get(self)->GetZoom();
}

} // namespace

ArkVideoControlSupportAdapterCppToC::ArkVideoControlSupportAdapterCppToC()
{
    GetStruct()->get_pan = ark_video_control_support_adapter_get_pan;
    GetStruct()->get_tilt = ark_video_control_support_adapter_get_tilt;
    GetStruct()->get_zoom = ark_video_control_support_adapter_get_zoom;
}

ArkVideoControlSupportAdapterCppToC::~ArkVideoControlSupportAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkVideoControlSupportAdapterCppToC, ArkVideoControlSupportAdapter,
    ark_video_control_support_adapter_t>::kBridgeType = ARK_VIDEO_CONTROL_SUPPORT_ADAPTER;

} // namespace OHOS::ArkWeb

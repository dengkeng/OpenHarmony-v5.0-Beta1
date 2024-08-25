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

#include "ohos_adapter/cpptoc/ark_video_device_descriptor_adapter_cpptoc.h"

#include "ohos_adapter/cpptoc/ark_video_control_support_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

ArkWebString ARK_WEB_CALLBACK ark_video_device_descriptor_adapter_get_display_name(
    struct _ark_video_device_descriptor_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_default);

    // Execute
    return ArkVideoDeviceDescriptorAdapterCppToC::Get(self)->GetDisplayName();
}

ArkWebString ARK_WEB_CALLBACK ark_video_device_descriptor_adapter_get_device_id(
    struct _ark_video_device_descriptor_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_default);

    // Execute
    return ArkVideoDeviceDescriptorAdapterCppToC::Get(self)->GetDeviceId();
}

ArkWebString ARK_WEB_CALLBACK ark_video_device_descriptor_adapter_get_model_id(
    struct _ark_video_device_descriptor_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_default);

    // Execute
    return ArkVideoDeviceDescriptorAdapterCppToC::Get(self)->GetModelId();
}

ark_video_control_support_adapter_t* ARK_WEB_CALLBACK ark_video_device_descriptor_adapter_get_control_support(
    struct _ark_video_device_descriptor_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkVideoControlSupportAdapter> _retval =
        ArkVideoDeviceDescriptorAdapterCppToC::Get(self)->GetControlSupport();

    // Return type: refptr_same
    return ArkVideoControlSupportAdapterCppToC::Invert(_retval);
}

int32_t ARK_WEB_CALLBACK ark_video_device_descriptor_adapter_get_transport_type(
    struct _ark_video_device_descriptor_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkVideoDeviceDescriptorAdapterCppToC::Get(self)->GetTransportType();
}

int32_t ARK_WEB_CALLBACK ark_video_device_descriptor_adapter_get_facing_mode(
    struct _ark_video_device_descriptor_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkVideoDeviceDescriptorAdapterCppToC::Get(self)->GetFacingMode();
}

ArkFormatAdapterVector ARK_WEB_CALLBACK ark_video_device_descriptor_adapter_get_support_capture_formats(
    struct _ark_video_device_descriptor_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, { 0 });

    // Execute
    return ArkVideoDeviceDescriptorAdapterCppToC::Get(self)->GetSupportCaptureFormats();
}

} // namespace

ArkVideoDeviceDescriptorAdapterCppToC::ArkVideoDeviceDescriptorAdapterCppToC()
{
    GetStruct()->get_display_name = ark_video_device_descriptor_adapter_get_display_name;
    GetStruct()->get_device_id = ark_video_device_descriptor_adapter_get_device_id;
    GetStruct()->get_model_id = ark_video_device_descriptor_adapter_get_model_id;
    GetStruct()->get_control_support = ark_video_device_descriptor_adapter_get_control_support;
    GetStruct()->get_transport_type = ark_video_device_descriptor_adapter_get_transport_type;
    GetStruct()->get_facing_mode = ark_video_device_descriptor_adapter_get_facing_mode;
    GetStruct()->get_support_capture_formats = ark_video_device_descriptor_adapter_get_support_capture_formats;
}

ArkVideoDeviceDescriptorAdapterCppToC::~ArkVideoDeviceDescriptorAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkVideoDeviceDescriptorAdapterCppToC, ArkVideoDeviceDescriptorAdapter,
    ark_video_device_descriptor_adapter_t>::kBridgeType = ARK_VIDEO_DEVICE_DESCRIPTOR_ADAPTER;

} // namespace OHOS::ArkWeb

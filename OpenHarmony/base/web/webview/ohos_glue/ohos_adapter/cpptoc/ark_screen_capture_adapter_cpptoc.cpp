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

#include "ohos_adapter/cpptoc/ark_screen_capture_adapter_cpptoc.h"

#include "ohos_adapter/cpptoc/ark_surface_buffer_adapter_cpptoc.h"
#include "ohos_adapter/ctocpp/ark_screen_capture_callback_adapter_ctocpp.h"
#include "ohos_adapter/ctocpp/ark_screen_capture_config_adapter_ctocpp.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

int32_t ARK_WEB_CALLBACK ark_screen_capture_adapter_init(
    struct _ark_screen_capture_adapter_t* self, ark_screen_capture_config_adapter_t* config)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkScreenCaptureAdapterCppToC::Get(self)->Init(ArkScreenCaptureConfigAdapterCToCpp::Invert(config));
}

int32_t ARK_WEB_CALLBACK ark_screen_capture_adapter_set_microphone_enable(
    struct _ark_screen_capture_adapter_t* self, bool enable)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkScreenCaptureAdapterCppToC::Get(self)->SetMicrophoneEnable(enable);
}

int32_t ARK_WEB_CALLBACK ark_screen_capture_adapter_start_capture(struct _ark_screen_capture_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkScreenCaptureAdapterCppToC::Get(self)->StartCapture();
}

int32_t ARK_WEB_CALLBACK ark_screen_capture_adapter_stop_capture(struct _ark_screen_capture_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkScreenCaptureAdapterCppToC::Get(self)->StopCapture();
}

int32_t ARK_WEB_CALLBACK ark_screen_capture_adapter_set_capture_callback(
    struct _ark_screen_capture_adapter_t* self, ark_screen_capture_callback_adapter_t* callback)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkScreenCaptureAdapterCppToC::Get(self)->SetCaptureCallback(
        ArkScreenCaptureCallbackAdapterCToCpp::Invert(callback));
}

ark_surface_buffer_adapter_t* ARK_WEB_CALLBACK ark_screen_capture_adapter_acquire_video_buffer(
    struct _ark_screen_capture_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkSurfaceBufferAdapter> _retval = ArkScreenCaptureAdapterCppToC::Get(self)->AcquireVideoBuffer();

    // Return type: refptr_same
    return ArkSurfaceBufferAdapterCppToC::Invert(_retval);
}

int32_t ARK_WEB_CALLBACK ark_screen_capture_adapter_release_video_buffer(struct _ark_screen_capture_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkScreenCaptureAdapterCppToC::Get(self)->ReleaseVideoBuffer();
}

} // namespace

ArkScreenCaptureAdapterCppToC::ArkScreenCaptureAdapterCppToC()
{
    GetStruct()->init = ark_screen_capture_adapter_init;
    GetStruct()->set_microphone_enable = ark_screen_capture_adapter_set_microphone_enable;
    GetStruct()->start_capture = ark_screen_capture_adapter_start_capture;
    GetStruct()->stop_capture = ark_screen_capture_adapter_stop_capture;
    GetStruct()->set_capture_callback = ark_screen_capture_adapter_set_capture_callback;
    GetStruct()->acquire_video_buffer = ark_screen_capture_adapter_acquire_video_buffer;
    GetStruct()->release_video_buffer = ark_screen_capture_adapter_release_video_buffer;
}

ArkScreenCaptureAdapterCppToC::~ArkScreenCaptureAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkScreenCaptureAdapterCppToC, ArkScreenCaptureAdapter,
    ark_screen_capture_adapter_t>::kBridgeType = ARK_SCREEN_CAPTURE_ADAPTER;

} // namespace OHOS::ArkWeb

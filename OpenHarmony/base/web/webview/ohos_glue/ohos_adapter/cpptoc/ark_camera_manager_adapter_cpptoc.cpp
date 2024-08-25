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

#include "ohos_adapter/cpptoc/ark_camera_manager_adapter_cpptoc.h"

#include "ohos_adapter/cpptoc/ark_video_capture_range_adapter_cpptoc.h"
#include "ohos_adapter/ctocpp/ark_camera_buffer_listener_adapter_ctocpp.h"
#include "ohos_adapter/ctocpp/ark_camera_status_callback_adapter_ctocpp.h"
#include "ohos_adapter/ctocpp/ark_video_capture_params_adapter_ctocpp.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

int32_t ARK_WEB_CALLBACK ark_camera_manager_adapter_create(
    struct _ark_camera_manager_adapter_t* self, ark_camera_status_callback_adapter_t* cameraStatusCallback)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkCameraManagerAdapterCppToC::Get(self)->Create(
        ArkCameraStatusCallbackAdapterCToCpp::Invert(cameraStatusCallback));
}

ArkVideoDeviceDescriptorAdapterVector ARK_WEB_CALLBACK ark_camera_manager_adapter_get_devices_info(
    struct _ark_camera_manager_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, { 0 });

    // Execute
    return ArkCameraManagerAdapterCppToC::Get(self)->GetDevicesInfo();
}

int32_t ARK_WEB_CALLBACK ark_camera_manager_adapter_release_camera_manger(struct _ark_camera_manager_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkCameraManagerAdapterCppToC::Get(self)->ReleaseCameraManger();
}

int32_t ARK_WEB_CALLBACK ark_camera_manager_adapter_get_exposure_modes(
    struct _ark_camera_manager_adapter_t* self, ArkWebInt32Vector* exposureModesAdapter)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(exposureModesAdapter, 0);

    // Execute
    return ArkCameraManagerAdapterCppToC::Get(self)->GetExposureModes(*exposureModesAdapter);
}

int32_t ARK_WEB_CALLBACK ark_camera_manager_adapter_get_current_exposure_mode(
    struct _ark_camera_manager_adapter_t* self, int32_t* exposureModeAdapter)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(exposureModeAdapter, 0);

    // Execute
    return ArkCameraManagerAdapterCppToC::Get(self)->GetCurrentExposureMode(*exposureModeAdapter);
}

ark_video_capture_range_adapter_t* ARK_WEB_CALLBACK ark_camera_manager_adapter_get_caption_range_by_id(
    struct _ark_camera_manager_adapter_t* self, int32_t rangeId)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkVideoCaptureRangeAdapter> _retval =
        ArkCameraManagerAdapterCppToC::Get(self)->GetCaptionRangeById(rangeId);

    // Return type: refptr_same
    return ArkVideoCaptureRangeAdapterCppToC::Invert(_retval);
}

bool ARK_WEB_CALLBACK ark_camera_manager_adapter_is_focus_mode_supported(
    struct _ark_camera_manager_adapter_t* self, int32_t focusMode)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkCameraManagerAdapterCppToC::Get(self)->IsFocusModeSupported(focusMode);
}

int32_t ARK_WEB_CALLBACK ark_camera_manager_adapter_get_current_focus_mode(struct _ark_camera_manager_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkCameraManagerAdapterCppToC::Get(self)->GetCurrentFocusMode();
}

bool ARK_WEB_CALLBACK ark_camera_manager_adapter_is_flash_mode_supported(
    struct _ark_camera_manager_adapter_t* self, int32_t flashMode)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkCameraManagerAdapterCppToC::Get(self)->IsFlashModeSupported(flashMode);
}

int32_t ARK_WEB_CALLBACK ark_camera_manager_adapter_restart_session(struct _ark_camera_manager_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkCameraManagerAdapterCppToC::Get(self)->RestartSession();
}

int32_t ARK_WEB_CALLBACK ark_camera_manager_adapter_stop_session(
    struct _ark_camera_manager_adapter_t* self, int32_t stopType)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkCameraManagerAdapterCppToC::Get(self)->StopSession(stopType);
}

int32_t ARK_WEB_CALLBACK ark_camera_manager_adapter_get_camera_status(struct _ark_camera_manager_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkCameraManagerAdapterCppToC::Get(self)->GetCameraStatus();
}

bool ARK_WEB_CALLBACK ark_camera_manager_adapter_is_exist_capture_task(struct _ark_camera_manager_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkCameraManagerAdapterCppToC::Get(self)->IsExistCaptureTask();
}

int32_t ARK_WEB_CALLBACK ark_camera_manager_adapter_start_stream(struct _ark_camera_manager_adapter_t* self,
    const ArkWebString* deviceId, ark_video_capture_params_adapter_t* captureParams,
    ark_camera_buffer_listener_adapter_t* listener)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(deviceId, 0);

    // Execute
    return ArkCameraManagerAdapterCppToC::Get(self)->StartStream(*deviceId,
        ArkVideoCaptureParamsAdapterCToCpp::Invert(captureParams),
        ArkCameraBufferListenerAdapterCToCpp::Invert(listener));
}

void ARK_WEB_CALLBACK ark_camera_manager_adapter_set_foreground_flag(
    struct _ark_camera_manager_adapter_t* self, bool isForeground)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkCameraManagerAdapterCppToC::Get(self)->SetForegroundFlag(isForeground);
}

void ARK_WEB_CALLBACK ark_camera_manager_adapter_set_camera_status(
    struct _ark_camera_manager_adapter_t* self, int32_t status)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkCameraManagerAdapterCppToC::Get(self)->SetCameraStatus(status);
}

ArkWebString ARK_WEB_CALLBACK ark_camera_manager_adapter_get_current_device_id(
    struct _ark_camera_manager_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_default);

    // Execute
    return ArkCameraManagerAdapterCppToC::Get(self)->GetCurrentDeviceId();
}

} // namespace

ArkCameraManagerAdapterCppToC::ArkCameraManagerAdapterCppToC()
{
    GetStruct()->create = ark_camera_manager_adapter_create;
    GetStruct()->get_devices_info = ark_camera_manager_adapter_get_devices_info;
    GetStruct()->release_camera_manger = ark_camera_manager_adapter_release_camera_manger;
    GetStruct()->get_exposure_modes = ark_camera_manager_adapter_get_exposure_modes;
    GetStruct()->get_current_exposure_mode = ark_camera_manager_adapter_get_current_exposure_mode;
    GetStruct()->get_caption_range_by_id = ark_camera_manager_adapter_get_caption_range_by_id;
    GetStruct()->is_focus_mode_supported = ark_camera_manager_adapter_is_focus_mode_supported;
    GetStruct()->get_current_focus_mode = ark_camera_manager_adapter_get_current_focus_mode;
    GetStruct()->is_flash_mode_supported = ark_camera_manager_adapter_is_flash_mode_supported;
    GetStruct()->restart_session = ark_camera_manager_adapter_restart_session;
    GetStruct()->stop_session = ark_camera_manager_adapter_stop_session;
    GetStruct()->get_camera_status = ark_camera_manager_adapter_get_camera_status;
    GetStruct()->is_exist_capture_task = ark_camera_manager_adapter_is_exist_capture_task;
    GetStruct()->start_stream = ark_camera_manager_adapter_start_stream;
    GetStruct()->set_foreground_flag = ark_camera_manager_adapter_set_foreground_flag;
    GetStruct()->set_camera_status = ark_camera_manager_adapter_set_camera_status;
    GetStruct()->get_current_device_id = ark_camera_manager_adapter_get_current_device_id;
}

ArkCameraManagerAdapterCppToC::~ArkCameraManagerAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkCameraManagerAdapterCppToC, ArkCameraManagerAdapter,
    ark_camera_manager_adapter_t>::kBridgeType = ARK_CAMERA_MANAGER_ADAPTER;

} // namespace OHOS::ArkWeb

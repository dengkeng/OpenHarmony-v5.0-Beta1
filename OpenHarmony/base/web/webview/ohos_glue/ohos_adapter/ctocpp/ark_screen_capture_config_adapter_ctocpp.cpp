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

#include "ohos_adapter/ctocpp/ark_screen_capture_config_adapter_ctocpp.h"

#include "ohos_adapter/ctocpp/ark_audio_info_adapter_ctocpp.h"
#include "ohos_adapter/ctocpp/ark_recorder_info_adapter_ctocpp.h"
#include "ohos_adapter/ctocpp/ark_video_info_adapter_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
int32_t ArkScreenCaptureConfigAdapterCToCpp::GetCaptureMode()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_screen_capture_config_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_capture_mode, 0);

    // Execute
    return _struct->get_capture_mode(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkScreenCaptureConfigAdapterCToCpp::GetDataType()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_screen_capture_config_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_data_type, 0);

    // Execute
    return _struct->get_data_type(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebRefPtr<ArkAudioInfoAdapter> ArkScreenCaptureConfigAdapterCToCpp::GetAudioInfo()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_screen_capture_config_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, nullptr);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_audio_info, nullptr);

    // Execute
    ark_audio_info_adapter_t* _retval = _struct->get_audio_info(_struct);

    // Return type: refptr_same
    return ArkAudioInfoAdapterCToCpp::Invert(_retval);
}

ARK_WEB_NO_SANITIZE
ArkWebRefPtr<ArkVideoInfoAdapter> ArkScreenCaptureConfigAdapterCToCpp::GetVideoInfo()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_screen_capture_config_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, nullptr);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_video_info, nullptr);

    // Execute
    ark_video_info_adapter_t* _retval = _struct->get_video_info(_struct);

    // Return type: refptr_same
    return ArkVideoInfoAdapterCToCpp::Invert(_retval);
}

ARK_WEB_NO_SANITIZE
ArkWebRefPtr<ArkRecorderInfoAdapter> ArkScreenCaptureConfigAdapterCToCpp::GetRecorderInfo()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_screen_capture_config_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, nullptr);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_recorder_info, nullptr);

    // Execute
    ark_recorder_info_adapter_t* _retval = _struct->get_recorder_info(_struct);

    // Return type: refptr_same
    return ArkRecorderInfoAdapterCToCpp::Invert(_retval);
}

ArkScreenCaptureConfigAdapterCToCpp::ArkScreenCaptureConfigAdapterCToCpp() {}

ArkScreenCaptureConfigAdapterCToCpp::~ArkScreenCaptureConfigAdapterCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkScreenCaptureConfigAdapterCToCpp, ArkScreenCaptureConfigAdapter,
    ark_screen_capture_config_adapter_t>::kBridgeType = ARK_SCREEN_CAPTURE_CONFIG_ADAPTER;

} // namespace OHOS::ArkWeb

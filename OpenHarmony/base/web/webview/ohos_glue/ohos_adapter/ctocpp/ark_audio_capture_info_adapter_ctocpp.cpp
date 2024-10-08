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

#include "ohos_adapter/ctocpp/ark_audio_capture_info_adapter_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
int32_t ArkAudioCaptureInfoAdapterCToCpp::GetAudioSampleRate()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_audio_capture_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_audio_sample_rate, 0);

    // Execute
    return _struct->get_audio_sample_rate(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkAudioCaptureInfoAdapterCToCpp::GetAudioChannels()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_audio_capture_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_audio_channels, 0);

    // Execute
    return _struct->get_audio_channels(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkAudioCaptureInfoAdapterCToCpp::GetAudioSource()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_audio_capture_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_audio_source, 0);

    // Execute
    return _struct->get_audio_source(_struct);
}

ArkAudioCaptureInfoAdapterCToCpp::ArkAudioCaptureInfoAdapterCToCpp() {}

ArkAudioCaptureInfoAdapterCToCpp::~ArkAudioCaptureInfoAdapterCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkAudioCaptureInfoAdapterCToCpp, ArkAudioCaptureInfoAdapter,
    ark_audio_capture_info_adapter_t>::kBridgeType = ARK_AUDIO_CAPTURE_INFO_ADAPTER;

} // namespace OHOS::ArkWeb

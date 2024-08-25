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

#include "ohos_adapter/ctocpp/ark_audio_renderer_options_adapter_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
int32_t ArkAudioRendererOptionsAdapterCToCpp::GetSamplingRate()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_audio_renderer_options_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_sampling_rate, 0);

    // Execute
    return _struct->get_sampling_rate(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkAudioRendererOptionsAdapterCToCpp::GetEncodingType()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_audio_renderer_options_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_encoding_type, 0);

    // Execute
    return _struct->get_encoding_type(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkAudioRendererOptionsAdapterCToCpp::GetSampleFormat()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_audio_renderer_options_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_sample_format, 0);

    // Execute
    return _struct->get_sample_format(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkAudioRendererOptionsAdapterCToCpp::GetChannel()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_audio_renderer_options_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_channel, 0);

    // Execute
    return _struct->get_channel(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkAudioRendererOptionsAdapterCToCpp::GetContentType()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_audio_renderer_options_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_content_type, 0);

    // Execute
    return _struct->get_content_type(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkAudioRendererOptionsAdapterCToCpp::GetStreamUsage()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_audio_renderer_options_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_stream_usage, 0);

    // Execute
    return _struct->get_stream_usage(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkAudioRendererOptionsAdapterCToCpp::GetRenderFlags()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_audio_renderer_options_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_render_flags, 0);

    // Execute
    return _struct->get_render_flags(_struct);
}

ArkAudioRendererOptionsAdapterCToCpp::ArkAudioRendererOptionsAdapterCToCpp() {}

ArkAudioRendererOptionsAdapterCToCpp::~ArkAudioRendererOptionsAdapterCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkAudioRendererOptionsAdapterCToCpp, ArkAudioRendererOptionsAdapter,
    ark_audio_renderer_options_adapter_t>::kBridgeType = ARK_AUDIO_RENDERER_OPTIONS_ADAPTER;

} // namespace OHOS::ArkWeb

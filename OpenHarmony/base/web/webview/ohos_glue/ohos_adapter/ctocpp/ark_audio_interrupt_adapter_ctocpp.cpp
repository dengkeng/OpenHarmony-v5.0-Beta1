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

#include "ohos_adapter/ctocpp/ark_audio_interrupt_adapter_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
int32_t ArkAudioInterruptAdapterCToCpp::GetStreamUsage()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_audio_interrupt_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_stream_usage, 0);

    // Execute
    return _struct->get_stream_usage(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkAudioInterruptAdapterCToCpp::GetContentType()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_audio_interrupt_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_content_type, 0);

    // Execute
    return _struct->get_content_type(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkAudioInterruptAdapterCToCpp::GetStreamType()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_audio_interrupt_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_stream_type, 0);

    // Execute
    return _struct->get_stream_type(_struct);
}

ARK_WEB_NO_SANITIZE
uint32_t ArkAudioInterruptAdapterCToCpp::GetSessionID()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_audio_interrupt_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_session_id, 0);

    // Execute
    return _struct->get_session_id(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkAudioInterruptAdapterCToCpp::GetPauseWhenDucked()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_audio_interrupt_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_pause_when_ducked, false);

    // Execute
    return _struct->get_pause_when_ducked(_struct);
}

ArkAudioInterruptAdapterCToCpp::ArkAudioInterruptAdapterCToCpp() {}

ArkAudioInterruptAdapterCToCpp::~ArkAudioInterruptAdapterCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkAudioInterruptAdapterCToCpp, ArkAudioInterruptAdapter,
    ark_audio_interrupt_adapter_t>::kBridgeType = ARK_AUDIO_INTERRUPT_ADAPTER;

} // namespace OHOS::ArkWeb

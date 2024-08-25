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

#include "ohos_adapter/cpptoc/ark_audio_capturer_adapter_cpptoc.h"

#include "ohos_adapter/ctocpp/ark_audio_capturer_options_adapter_ctocpp.h"
#include "ohos_adapter/ctocpp/ark_audio_capturer_read_callback_adapter_ctocpp.h"
#include "ohos_adapter/ctocpp/ark_buffer_desc_adapter_ctocpp.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

int32_t ARK_WEB_CALLBACK ark_audio_capturer_adapter_create(struct _ark_audio_capturer_adapter_t* self,
    ark_audio_capturer_options_adapter_t* capturerOptions, ArkWebString* cachePath)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(cachePath, 0);

    // Execute
    return ArkAudioCapturerAdapterCppToC::Get(self)->Create(
        ArkAudioCapturerOptionsAdapterCToCpp::Invert(capturerOptions), *cachePath);
}

bool ARK_WEB_CALLBACK ark_audio_capturer_adapter_start(struct _ark_audio_capturer_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkAudioCapturerAdapterCppToC::Get(self)->Start();
}

bool ARK_WEB_CALLBACK ark_audio_capturer_adapter_stop(struct _ark_audio_capturer_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkAudioCapturerAdapterCppToC::Get(self)->Stop();
}

bool ARK_WEB_CALLBACK ark_audio_capturer_adapter_release2(struct _ark_audio_capturer_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkAudioCapturerAdapterCppToC::Get(self)->Release2();
}

int32_t ARK_WEB_CALLBACK ark_audio_capturer_adapter_set_capturer_read_callback(
    struct _ark_audio_capturer_adapter_t* self, ark_audio_capturer_read_callback_adapter_t* callbck)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkAudioCapturerAdapterCppToC::Get(self)->SetCapturerReadCallback(
        ArkAudioCapturerReadCallbackAdapterCToCpp::Invert(callbck));
}

int32_t ARK_WEB_CALLBACK ark_audio_capturer_adapter_get_buffer_desc(
    struct _ark_audio_capturer_adapter_t* self, ark_buffer_desc_adapter_t* buffferDesc)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkAudioCapturerAdapterCppToC::Get(self)->GetBufferDesc(ArkBufferDescAdapterCToCpp::Invert(buffferDesc));
}

int32_t ARK_WEB_CALLBACK ark_audio_capturer_adapter_enqueue(
    struct _ark_audio_capturer_adapter_t* self, ark_buffer_desc_adapter_t* bufferDesc)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkAudioCapturerAdapterCppToC::Get(self)->Enqueue(ArkBufferDescAdapterCToCpp::Invert(bufferDesc));
}

int32_t ARK_WEB_CALLBACK ark_audio_capturer_adapter_get_frame_count(
    struct _ark_audio_capturer_adapter_t* self, uint32_t* frameCount)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(frameCount, 0);

    // Execute
    return ArkAudioCapturerAdapterCppToC::Get(self)->GetFrameCount(*frameCount);
}

int64_t ARK_WEB_CALLBACK ark_audio_capturer_adapter_get_audio_time(struct _ark_audio_capturer_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkAudioCapturerAdapterCppToC::Get(self)->GetAudioTime();
}

} // namespace

ArkAudioCapturerAdapterCppToC::ArkAudioCapturerAdapterCppToC()
{
    GetStruct()->create = ark_audio_capturer_adapter_create;
    GetStruct()->start = ark_audio_capturer_adapter_start;
    GetStruct()->stop = ark_audio_capturer_adapter_stop;
    GetStruct()->release2 = ark_audio_capturer_adapter_release2;
    GetStruct()->set_capturer_read_callback = ark_audio_capturer_adapter_set_capturer_read_callback;
    GetStruct()->get_buffer_desc = ark_audio_capturer_adapter_get_buffer_desc;
    GetStruct()->enqueue = ark_audio_capturer_adapter_enqueue;
    GetStruct()->get_frame_count = ark_audio_capturer_adapter_get_frame_count;
    GetStruct()->get_audio_time = ark_audio_capturer_adapter_get_audio_time;
}

ArkAudioCapturerAdapterCppToC::~ArkAudioCapturerAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkAudioCapturerAdapterCppToC, ArkAudioCapturerAdapter,
    ark_audio_capturer_adapter_t>::kBridgeType = ARK_AUDIO_CAPTURER_ADAPTER;

} // namespace OHOS::ArkWeb

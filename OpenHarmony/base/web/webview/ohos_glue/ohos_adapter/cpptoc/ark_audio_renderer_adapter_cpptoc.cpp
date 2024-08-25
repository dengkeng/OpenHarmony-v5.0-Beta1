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

#include "ohos_adapter/cpptoc/ark_audio_renderer_adapter_cpptoc.h"

#include "ohos_adapter/ctocpp/ark_audio_renderer_callback_adapter_ctocpp.h"
#include "ohos_adapter/ctocpp/ark_audio_renderer_options_adapter_ctocpp.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

int32_t ARK_WEB_CALLBACK ark_audio_renderer_adapter_create(
    struct _ark_audio_renderer_adapter_t* self, ark_audio_renderer_options_adapter_t* options, ArkWebString* str)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(str, 0);

    // Execute
    return ArkAudioRendererAdapterCppToC::Get(self)->Create(
        ArkAudioRendererOptionsAdapterCToCpp::Invert(options), *str);
}

bool ARK_WEB_CALLBACK ark_audio_renderer_adapter_start(struct _ark_audio_renderer_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkAudioRendererAdapterCppToC::Get(self)->Start();
}

bool ARK_WEB_CALLBACK ark_audio_renderer_adapter_pause(struct _ark_audio_renderer_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkAudioRendererAdapterCppToC::Get(self)->Pause();
}

bool ARK_WEB_CALLBACK ark_audio_renderer_adapter_stop(struct _ark_audio_renderer_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkAudioRendererAdapterCppToC::Get(self)->Stop();
}

bool ARK_WEB_CALLBACK ark_audio_renderer_adapter_release2(struct _ark_audio_renderer_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkAudioRendererAdapterCppToC::Get(self)->Release2();
}

int32_t ARK_WEB_CALLBACK ark_audio_renderer_adapter_write(
    struct _ark_audio_renderer_adapter_t* self, uint8_t* buffer, size_t bufferSize)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(buffer, 0);

    // Execute
    return ArkAudioRendererAdapterCppToC::Get(self)->Write(buffer, bufferSize);
}

int32_t ARK_WEB_CALLBACK ark_audio_renderer_adapter_get_latency(
    struct _ark_audio_renderer_adapter_t* self, uint64_t* latency)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(latency, 0);

    // Execute
    return ArkAudioRendererAdapterCppToC::Get(self)->GetLatency(*latency);
}

int32_t ARK_WEB_CALLBACK ark_audio_renderer_adapter_set_volume(struct _ark_audio_renderer_adapter_t* self, float volume)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkAudioRendererAdapterCppToC::Get(self)->SetVolume(volume);
}

float ARK_WEB_CALLBACK ark_audio_renderer_adapter_get_volume(struct _ark_audio_renderer_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkAudioRendererAdapterCppToC::Get(self)->GetVolume();
}

int32_t ARK_WEB_CALLBACK ark_audio_renderer_adapter_set_audio_renderer_callback(
    struct _ark_audio_renderer_adapter_t* self, ark_audio_renderer_callback_adapter_t* callback)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkAudioRendererAdapterCppToC::Get(self)->SetAudioRendererCallback(
        ArkAudioRendererCallbackAdapterCToCpp::Invert(callback));
}

void ARK_WEB_CALLBACK ark_audio_renderer_adapter_set_interrupt_mode(
    struct _ark_audio_renderer_adapter_t* self, bool audioExclusive)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkAudioRendererAdapterCppToC::Get(self)->SetInterruptMode(audioExclusive);
}

bool ARK_WEB_CALLBACK ark_audio_renderer_adapter_is_renderer_state_running(struct _ark_audio_renderer_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkAudioRendererAdapterCppToC::Get(self)->IsRendererStateRunning();
}

} // namespace

ArkAudioRendererAdapterCppToC::ArkAudioRendererAdapterCppToC()
{
    GetStruct()->create = ark_audio_renderer_adapter_create;
    GetStruct()->start = ark_audio_renderer_adapter_start;
    GetStruct()->pause = ark_audio_renderer_adapter_pause;
    GetStruct()->stop = ark_audio_renderer_adapter_stop;
    GetStruct()->release2 = ark_audio_renderer_adapter_release2;
    GetStruct()->write = ark_audio_renderer_adapter_write;
    GetStruct()->get_latency = ark_audio_renderer_adapter_get_latency;
    GetStruct()->set_volume = ark_audio_renderer_adapter_set_volume;
    GetStruct()->get_volume = ark_audio_renderer_adapter_get_volume;
    GetStruct()->set_audio_renderer_callback = ark_audio_renderer_adapter_set_audio_renderer_callback;
    GetStruct()->set_interrupt_mode = ark_audio_renderer_adapter_set_interrupt_mode;
    GetStruct()->is_renderer_state_running = ark_audio_renderer_adapter_is_renderer_state_running;
}

ArkAudioRendererAdapterCppToC::~ArkAudioRendererAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkAudioRendererAdapterCppToC, ArkAudioRendererAdapter,
    ark_audio_renderer_adapter_t>::kBridgeType = ARK_AUDIO_RENDERER_ADAPTER;

} // namespace OHOS::ArkWeb

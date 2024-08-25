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

#include "ohos_adapter/cpptoc/ark_player_adapter_cpptoc.h"

#include "ohos_adapter/cpptoc/ark_iconsumer_surface_adapter_cpptoc.h"
#include "ohos_adapter/ctocpp/ark_player_callback_adapter_ctocpp.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

int32_t ARK_WEB_CALLBACK ark_player_adapter_set_player_callback(
    struct _ark_player_adapter_t* self, ark_player_callback_adapter_t* callbackAdapter)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkPlayerAdapterCppToC::Get(self)->SetPlayerCallback(
        ArkPlayerCallbackAdapterCToCpp::Invert(callbackAdapter));
}

int32_t ARK_WEB_CALLBACK ark_player_adapter_set_source1(struct _ark_player_adapter_t* self, const ArkWebString* url)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(url, 0);

    // Execute
    return ArkPlayerAdapterCppToC::Get(self)->SetSource(*url);
}

int32_t ARK_WEB_CALLBACK ark_player_adapter_set_source2(
    struct _ark_player_adapter_t* self, int32_t fd, int64_t offset, int64_t size)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkPlayerAdapterCppToC::Get(self)->SetSource(fd, offset, size);
}

int32_t ARK_WEB_CALLBACK ark_player_adapter_set_video_surface(
    struct _ark_player_adapter_t* self, ark_iconsumer_surface_adapter_t* cSurfaceAdapter)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkPlayerAdapterCppToC::Get(self)->SetVideoSurface(
        ArkIConsumerSurfaceAdapterCppToC::Revert(cSurfaceAdapter));
}

int32_t ARK_WEB_CALLBACK ark_player_adapter_set_volume(
    struct _ark_player_adapter_t* self, float leftVolume, float rightVolume)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkPlayerAdapterCppToC::Get(self)->SetVolume(leftVolume, rightVolume);
}

int32_t ARK_WEB_CALLBACK ark_player_adapter_seek(struct _ark_player_adapter_t* self, int32_t mSeconds, int32_t mode)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkPlayerAdapterCppToC::Get(self)->Seek(mSeconds, mode);
}

int32_t ARK_WEB_CALLBACK ark_player_adapter_play(struct _ark_player_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkPlayerAdapterCppToC::Get(self)->Play();
}

int32_t ARK_WEB_CALLBACK ark_player_adapter_pause(struct _ark_player_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkPlayerAdapterCppToC::Get(self)->Pause();
}

int32_t ARK_WEB_CALLBACK ark_player_adapter_prepare_async(struct _ark_player_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkPlayerAdapterCppToC::Get(self)->PrepareAsync();
}

int32_t ARK_WEB_CALLBACK ark_player_adapter_get_current_time(struct _ark_player_adapter_t* self, int32_t* currentTime)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(currentTime, 0);

    // Execute
    return ArkPlayerAdapterCppToC::Get(self)->GetCurrentTime(*currentTime);
}

int32_t ARK_WEB_CALLBACK ark_player_adapter_get_duration(struct _ark_player_adapter_t* self, int32_t* duration)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(duration, 0);

    // Execute
    return ArkPlayerAdapterCppToC::Get(self)->GetDuration(*duration);
}

int32_t ARK_WEB_CALLBACK ark_player_adapter_set_playback_speed(struct _ark_player_adapter_t* self, int32_t mode)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkPlayerAdapterCppToC::Get(self)->SetPlaybackSpeed(mode);
}

} // namespace

ArkPlayerAdapterCppToC::ArkPlayerAdapterCppToC()
{
    GetStruct()->set_player_callback = ark_player_adapter_set_player_callback;
    GetStruct()->set_source1 = ark_player_adapter_set_source1;
    GetStruct()->set_source2 = ark_player_adapter_set_source2;
    GetStruct()->set_video_surface = ark_player_adapter_set_video_surface;
    GetStruct()->set_volume = ark_player_adapter_set_volume;
    GetStruct()->seek = ark_player_adapter_seek;
    GetStruct()->play = ark_player_adapter_play;
    GetStruct()->pause = ark_player_adapter_pause;
    GetStruct()->prepare_async = ark_player_adapter_prepare_async;
    GetStruct()->get_current_time = ark_player_adapter_get_current_time;
    GetStruct()->get_duration = ark_player_adapter_get_duration;
    GetStruct()->set_playback_speed = ark_player_adapter_set_playback_speed;
}

ArkPlayerAdapterCppToC::~ArkPlayerAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkPlayerAdapterCppToC, ArkPlayerAdapter, ark_player_adapter_t>::kBridgeType =
    ARK_PLAYER_ADAPTER;

} // namespace OHOS::ArkWeb

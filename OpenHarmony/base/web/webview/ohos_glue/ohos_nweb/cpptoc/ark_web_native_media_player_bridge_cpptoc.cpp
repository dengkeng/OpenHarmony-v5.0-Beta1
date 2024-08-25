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

#include "ohos_nweb/cpptoc/ark_web_native_media_player_bridge_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

void ARK_WEB_CALLBACK ark_web_native_media_player_bridge_update_rect(
    struct _ark_web_native_media_player_bridge_t* self, double x, double y, double width, double height)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkWebNativeMediaPlayerBridgeCppToC::Get(self)->UpdateRect(x, y, width, height);
}

void ARK_WEB_CALLBACK ark_web_native_media_player_bridge_play(struct _ark_web_native_media_player_bridge_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkWebNativeMediaPlayerBridgeCppToC::Get(self)->Play();
}

void ARK_WEB_CALLBACK ark_web_native_media_player_bridge_pause(struct _ark_web_native_media_player_bridge_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkWebNativeMediaPlayerBridgeCppToC::Get(self)->Pause();
}

void ARK_WEB_CALLBACK ark_web_native_media_player_bridge_seek(
    struct _ark_web_native_media_player_bridge_t* self, double time)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkWebNativeMediaPlayerBridgeCppToC::Get(self)->Seek(time);
}

void ARK_WEB_CALLBACK ark_web_native_media_player_bridge_set_volume(
    struct _ark_web_native_media_player_bridge_t* self, double volume)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkWebNativeMediaPlayerBridgeCppToC::Get(self)->SetVolume(volume);
}

void ARK_WEB_CALLBACK ark_web_native_media_player_bridge_set_muted(
    struct _ark_web_native_media_player_bridge_t* self, bool isMuted)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkWebNativeMediaPlayerBridgeCppToC::Get(self)->SetMuted(isMuted);
}

void ARK_WEB_CALLBACK ark_web_native_media_player_bridge_set_playback_rate(
    struct _ark_web_native_media_player_bridge_t* self, double playbackRate)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkWebNativeMediaPlayerBridgeCppToC::Get(self)->SetPlaybackRate(playbackRate);
}

void ARK_WEB_CALLBACK ark_web_native_media_player_bridge_release(struct _ark_web_native_media_player_bridge_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkWebNativeMediaPlayerBridgeCppToC::Get(self)->Release();
}

void ARK_WEB_CALLBACK ark_web_native_media_player_bridge_enter_full_screen(
    struct _ark_web_native_media_player_bridge_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkWebNativeMediaPlayerBridgeCppToC::Get(self)->EnterFullScreen();
}

void ARK_WEB_CALLBACK ark_web_native_media_player_bridge_exit_full_screen(
    struct _ark_web_native_media_player_bridge_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkWebNativeMediaPlayerBridgeCppToC::Get(self)->ExitFullScreen();
}

} // namespace

ArkWebNativeMediaPlayerBridgeCppToC::ArkWebNativeMediaPlayerBridgeCppToC()
{
    GetStruct()->update_rect = ark_web_native_media_player_bridge_update_rect;
    GetStruct()->play = ark_web_native_media_player_bridge_play;
    GetStruct()->pause = ark_web_native_media_player_bridge_pause;
    GetStruct()->seek = ark_web_native_media_player_bridge_seek;
    GetStruct()->set_volume = ark_web_native_media_player_bridge_set_volume;
    GetStruct()->set_muted = ark_web_native_media_player_bridge_set_muted;
    GetStruct()->set_playback_rate = ark_web_native_media_player_bridge_set_playback_rate;
    GetStruct()->release = ark_web_native_media_player_bridge_release;
    GetStruct()->enter_full_screen = ark_web_native_media_player_bridge_enter_full_screen;
    GetStruct()->exit_full_screen = ark_web_native_media_player_bridge_exit_full_screen;
}

ArkWebNativeMediaPlayerBridgeCppToC::~ArkWebNativeMediaPlayerBridgeCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkWebNativeMediaPlayerBridgeCppToC, ArkWebNativeMediaPlayerBridge,
    ark_web_native_media_player_bridge_t>::kBridgeType = ARK_WEB_NATIVE_MEDIA_PLAYER_BRIDGE;

} // namespace OHOS::ArkWeb

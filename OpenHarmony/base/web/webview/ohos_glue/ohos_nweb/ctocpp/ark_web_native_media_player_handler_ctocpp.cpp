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

#include "ohos_nweb/ctocpp/ark_web_native_media_player_handler_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
void ArkWebNativeMediaPlayerHandlerCToCpp::HandleStatusChanged(int status)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_native_media_player_handler_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, handle_status_changed, );

    // Execute
    _struct->handle_status_changed(_struct, status);
}

ARK_WEB_NO_SANITIZE
void ArkWebNativeMediaPlayerHandlerCToCpp::HandleVolumeChanged(double volume)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_native_media_player_handler_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, handle_volume_changed, );

    // Execute
    _struct->handle_volume_changed(_struct, volume);
}

ARK_WEB_NO_SANITIZE
void ArkWebNativeMediaPlayerHandlerCToCpp::HandleMutedChanged(bool isMuted)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_native_media_player_handler_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, handle_muted_changed, );

    // Execute
    _struct->handle_muted_changed(_struct, isMuted);
}

ARK_WEB_NO_SANITIZE
void ArkWebNativeMediaPlayerHandlerCToCpp::HandlePlaybackRateChanged(double playbackRate)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_native_media_player_handler_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, handle_playback_rate_changed, );

    // Execute
    _struct->handle_playback_rate_changed(_struct, playbackRate);
}

ARK_WEB_NO_SANITIZE
void ArkWebNativeMediaPlayerHandlerCToCpp::HandleDurationChanged(double duration)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_native_media_player_handler_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, handle_duration_changed, );

    // Execute
    _struct->handle_duration_changed(_struct, duration);
}

ARK_WEB_NO_SANITIZE
void ArkWebNativeMediaPlayerHandlerCToCpp::HandleTimeUpdate(double playTime)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_native_media_player_handler_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, handle_time_update, );

    // Execute
    _struct->handle_time_update(_struct, playTime);
}

ARK_WEB_NO_SANITIZE
void ArkWebNativeMediaPlayerHandlerCToCpp::HandleBufferedEndTimeChanged(double bufferedEndTime)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_native_media_player_handler_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, handle_buffered_end_time_changed, );

    // Execute
    _struct->handle_buffered_end_time_changed(_struct, bufferedEndTime);
}

ARK_WEB_NO_SANITIZE
void ArkWebNativeMediaPlayerHandlerCToCpp::HandleEnded()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_native_media_player_handler_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, handle_ended, );

    // Execute
    _struct->handle_ended(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebNativeMediaPlayerHandlerCToCpp::HandleNetworkStateChanged(int state)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_native_media_player_handler_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, handle_network_state_changed, );

    // Execute
    _struct->handle_network_state_changed(_struct, state);
}

ARK_WEB_NO_SANITIZE
void ArkWebNativeMediaPlayerHandlerCToCpp::HandleReadyStateChanged(int state)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_native_media_player_handler_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, handle_ready_state_changed, );

    // Execute
    _struct->handle_ready_state_changed(_struct, state);
}

ARK_WEB_NO_SANITIZE
void ArkWebNativeMediaPlayerHandlerCToCpp::HandleFullScreenChanged(bool isFullScreen)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_native_media_player_handler_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, handle_full_screen_changed, );

    // Execute
    _struct->handle_full_screen_changed(_struct, isFullScreen);
}

ARK_WEB_NO_SANITIZE
void ArkWebNativeMediaPlayerHandlerCToCpp::HandleSeeking()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_native_media_player_handler_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, handle_seeking, );

    // Execute
    _struct->handle_seeking(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebNativeMediaPlayerHandlerCToCpp::HandleSeekFinished()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_native_media_player_handler_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, handle_seek_finished, );

    // Execute
    _struct->handle_seek_finished(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebNativeMediaPlayerHandlerCToCpp::HandleError(int error, const ArkWebString& message)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_native_media_player_handler_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, handle_error, );

    // Execute
    _struct->handle_error(_struct, error, &message);
}

ARK_WEB_NO_SANITIZE
void ArkWebNativeMediaPlayerHandlerCToCpp::HandleVideoSizeChanged(double width, double height)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_native_media_player_handler_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, handle_video_size_changed, );

    // Execute
    _struct->handle_video_size_changed(_struct, width, height);
}

ArkWebNativeMediaPlayerHandlerCToCpp::ArkWebNativeMediaPlayerHandlerCToCpp() {}

ArkWebNativeMediaPlayerHandlerCToCpp::~ArkWebNativeMediaPlayerHandlerCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebNativeMediaPlayerHandlerCToCpp, ArkWebNativeMediaPlayerHandler,
    ark_web_native_media_player_handler_t>::kBridgeType = ARK_WEB_NATIVE_MEDIA_PLAYER_HANDLER;

} // namespace OHOS::ArkWeb

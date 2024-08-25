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

#ifndef ARK_WEB_NATIVE_MEDIA_PLAYER_HANDLER_CTOCPP_H_
#define ARK_WEB_NATIVE_MEDIA_PLAYER_HANDLER_CTOCPP_H_
#pragma once

#include "ohos_nweb/capi/ark_web_native_media_player_handler_capi.h"
#include "ohos_nweb/include/ark_web_native_media_player_handler.h"

#include "base/ctocpp/ark_web_ctocpp_ref_counted.h"

namespace OHOS::ArkWeb {

// Wrap a C structure with a C++ class.
// This class may be instantiated and accessed wrapper-side only.
class ArkWebNativeMediaPlayerHandlerCToCpp
    : public ArkWebCToCppRefCounted<ArkWebNativeMediaPlayerHandlerCToCpp, ArkWebNativeMediaPlayerHandler,
          ark_web_native_media_player_handler_t> {
public:
    ArkWebNativeMediaPlayerHandlerCToCpp();
    virtual ~ArkWebNativeMediaPlayerHandlerCToCpp();

    // ArkWebNativeMediaPlayerHandler methods.
    void HandleStatusChanged(int status) override;

    void HandleVolumeChanged(double volume) override;

    void HandleMutedChanged(bool isMuted) override;

    void HandlePlaybackRateChanged(double playbackRate) override;

    void HandleDurationChanged(double duration) override;

    void HandleTimeUpdate(double playTime) override;

    void HandleBufferedEndTimeChanged(double bufferedEndTime) override;

    void HandleEnded() override;

    void HandleNetworkStateChanged(int state) override;

    void HandleReadyStateChanged(int state) override;

    void HandleFullScreenChanged(bool isFullScreen) override;

    void HandleSeeking() override;

    void HandleSeekFinished() override;

    void HandleError(int error, const ArkWebString& message) override;

    void HandleVideoSizeChanged(double width, double height) override;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_NATIVE_MEDIA_PLAYER_HANDLER_CTOCPP_H_

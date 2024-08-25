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

#include "ohos_nweb/cpptoc/ark_web_create_native_media_player_callback_cpptoc.h"

#include "ohos_nweb/cpptoc/ark_web_native_media_player_bridge_cpptoc.h"
#include "ohos_nweb/ctocpp/ark_web_media_info_ctocpp.h"
#include "ohos_nweb/ctocpp/ark_web_native_media_player_handler_ctocpp.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

ark_web_native_media_player_bridge_t* ARK_WEB_CALLBACK ark_web_create_native_media_player_callback_on_create(
    struct _ark_web_create_native_media_player_callback_t* self, ark_web_native_media_player_handler_t* handler,
    ark_web_media_info_t* mediaInfo)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkWebNativeMediaPlayerBridge> _retval =
        ArkWebCreateNativeMediaPlayerCallbackCppToC::Get(self)->OnCreate(
            ArkWebNativeMediaPlayerHandlerCToCpp::Invert(handler), ArkWebMediaInfoCToCpp::Invert(mediaInfo));

    // Return type: refptr_same
    return ArkWebNativeMediaPlayerBridgeCppToC::Invert(_retval);
}

} // namespace

ArkWebCreateNativeMediaPlayerCallbackCppToC::ArkWebCreateNativeMediaPlayerCallbackCppToC()
{
    GetStruct()->on_create = ark_web_create_native_media_player_callback_on_create;
}

ArkWebCreateNativeMediaPlayerCallbackCppToC::~ArkWebCreateNativeMediaPlayerCallbackCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkWebCreateNativeMediaPlayerCallbackCppToC,
    ArkWebCreateNativeMediaPlayerCallback, ark_web_create_native_media_player_callback_t>::kBridgeType =
    ARK_WEB_CREATE_NATIVE_MEDIA_PLAYER_CALLBACK;

} // namespace OHOS::ArkWeb

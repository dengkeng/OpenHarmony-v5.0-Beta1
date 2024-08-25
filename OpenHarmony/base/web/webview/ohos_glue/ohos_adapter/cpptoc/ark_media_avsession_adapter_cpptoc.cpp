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

#include "ohos_adapter/cpptoc/ark_media_avsession_adapter_cpptoc.h"

#include "ohos_adapter/ctocpp/ark_media_avsession_callback_adapter_ctocpp.h"
#include "ohos_adapter/ctocpp/ark_media_avsession_metadata_adapter_ctocpp.h"
#include "ohos_adapter/ctocpp/ark_media_avsession_position_adapter_ctocpp.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

bool ARK_WEB_CALLBACK ark_media_avsession_adapter_create_avsession(
    struct _ark_media_avsession_adapter_t* self, int32_t type)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkMediaAVSessionAdapterCppToC::Get(self)->CreateAVSession(type);
}

void ARK_WEB_CALLBACK ark_media_avsession_adapter_destroy_avsession(struct _ark_media_avsession_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkMediaAVSessionAdapterCppToC::Get(self)->DestroyAVSession();
}

bool ARK_WEB_CALLBACK ark_media_avsession_adapter_regist_callback(
    struct _ark_media_avsession_adapter_t* self, ark_media_avsession_callback_adapter_t* callbackAdapter)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkMediaAVSessionAdapterCppToC::Get(self)->RegistCallback(
        ArkMediaAVSessionCallbackAdapterCToCpp::Invert(callbackAdapter));
}

bool ARK_WEB_CALLBACK ark_media_avsession_adapter_is_activated(struct _ark_media_avsession_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkMediaAVSessionAdapterCppToC::Get(self)->IsActivated();
}

bool ARK_WEB_CALLBACK ark_media_avsession_adapter_activate(struct _ark_media_avsession_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkMediaAVSessionAdapterCppToC::Get(self)->Activate();
}

void ARK_WEB_CALLBACK ark_media_avsession_adapter_de_activate(struct _ark_media_avsession_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkMediaAVSessionAdapterCppToC::Get(self)->DeActivate();
}

void ARK_WEB_CALLBACK ark_media_avsession_adapter_set_metadata(
    struct _ark_media_avsession_adapter_t* self, ark_media_avsession_metadata_adapter_t* metadata)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkMediaAVSessionAdapterCppToC::Get(self)->SetMetadata(ArkMediaAVSessionMetadataAdapterCToCpp::Invert(metadata));
}

void ARK_WEB_CALLBACK ark_media_avsession_adapter_set_playback_state(
    struct _ark_media_avsession_adapter_t* self, int32_t state)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkMediaAVSessionAdapterCppToC::Get(self)->SetPlaybackState(state);
}

void ARK_WEB_CALLBACK ark_media_avsession_adapter_set_playback_position(
    struct _ark_media_avsession_adapter_t* self, ark_media_avsession_position_adapter_t* position)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkMediaAVSessionAdapterCppToC::Get(self)->SetPlaybackPosition(
        ArkMediaAVSessionPositionAdapterCToCpp::Invert(position));
}

} // namespace

ArkMediaAVSessionAdapterCppToC::ArkMediaAVSessionAdapterCppToC()
{
    GetStruct()->create_avsession = ark_media_avsession_adapter_create_avsession;
    GetStruct()->destroy_avsession = ark_media_avsession_adapter_destroy_avsession;
    GetStruct()->regist_callback = ark_media_avsession_adapter_regist_callback;
    GetStruct()->is_activated = ark_media_avsession_adapter_is_activated;
    GetStruct()->activate = ark_media_avsession_adapter_activate;
    GetStruct()->de_activate = ark_media_avsession_adapter_de_activate;
    GetStruct()->set_metadata = ark_media_avsession_adapter_set_metadata;
    GetStruct()->set_playback_state = ark_media_avsession_adapter_set_playback_state;
    GetStruct()->set_playback_position = ark_media_avsession_adapter_set_playback_position;
}

ArkMediaAVSessionAdapterCppToC::~ArkMediaAVSessionAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkMediaAVSessionAdapterCppToC, ArkMediaAVSessionAdapter,
    ark_media_avsession_adapter_t>::kBridgeType = ARK_MEDIA_AVSESSION_ADAPTER;

} // namespace OHOS::ArkWeb

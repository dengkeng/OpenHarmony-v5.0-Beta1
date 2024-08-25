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

#include "ohos_adapter/ctocpp/ark_media_avsession_metadata_adapter_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
void ArkMediaAVSessionMetadataAdapterCToCpp::SetTitle(const ArkWebString& title)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_media_avsession_metadata_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_title, );

    // Execute
    _struct->set_title(_struct, &title);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkMediaAVSessionMetadataAdapterCToCpp::GetTitle()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_media_avsession_metadata_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_title, ark_web_string_default);

    // Execute
    return _struct->get_title(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkMediaAVSessionMetadataAdapterCToCpp::SetArtist(const ArkWebString& artist)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_media_avsession_metadata_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_artist, );

    // Execute
    _struct->set_artist(_struct, &artist);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkMediaAVSessionMetadataAdapterCToCpp::GetArtist()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_media_avsession_metadata_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_artist, ark_web_string_default);

    // Execute
    return _struct->get_artist(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkMediaAVSessionMetadataAdapterCToCpp::SetAlbum(const ArkWebString& album)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_media_avsession_metadata_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_album, );

    // Execute
    _struct->set_album(_struct, &album);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkMediaAVSessionMetadataAdapterCToCpp::GetAlbum()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_media_avsession_metadata_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_album, ark_web_string_default);

    // Execute
    return _struct->get_album(_struct);
}

ArkMediaAVSessionMetadataAdapterCToCpp::ArkMediaAVSessionMetadataAdapterCToCpp() {}

ArkMediaAVSessionMetadataAdapterCToCpp::~ArkMediaAVSessionMetadataAdapterCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkMediaAVSessionMetadataAdapterCToCpp, ArkMediaAVSessionMetadataAdapter,
    ark_media_avsession_metadata_adapter_t>::kBridgeType = ARK_MEDIA_AVSESSION_METADATA_ADAPTER;

} // namespace OHOS::ArkWeb

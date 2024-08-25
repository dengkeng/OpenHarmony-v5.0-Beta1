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

#include "ohos_nweb/ctocpp/ark_web_media_info_ctocpp.h"

#include "ohos_nweb/ctocpp/ark_web_native_media_player_surface_info_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
int ArkWebMediaInfoCToCpp::GetPreload()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_media_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_preload, 0);

    // Execute
    return _struct->get_preload(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebMediaInfoCToCpp::GetIsMuted()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_media_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_is_muted, false);

    // Execute
    return _struct->get_is_muted(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebMediaInfoCToCpp::GetEmbedId()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_media_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_embed_id, ark_web_string_default);

    // Execute
    return _struct->get_embed_id(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebMediaInfoCToCpp::GetPosterUrl()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_media_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_poster_url, ark_web_string_default);

    // Execute
    return _struct->get_poster_url(_struct);
}

ARK_WEB_NO_SANITIZE
int ArkWebMediaInfoCToCpp::GetMediaType()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_media_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_media_type, 0);

    // Execute
    return _struct->get_media_type(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebMediaInfoCToCpp::GetIsControlsShown()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_media_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_is_controls_shown, false);

    // Execute
    return _struct->get_is_controls_shown(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebStringVector ArkWebMediaInfoCToCpp::GetControls()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_media_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_vector_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_controls, ark_web_string_vector_default);

    // Execute
    return _struct->get_controls(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebStringMap ArkWebMediaInfoCToCpp::GetHeaders()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_media_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_map_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_headers, ark_web_string_map_default);

    // Execute
    return _struct->get_headers(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebStringMap ArkWebMediaInfoCToCpp::GetAttributes()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_media_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_map_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_attributes, ark_web_string_map_default);

    // Execute
    return _struct->get_attributes(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebMediaSourceInfoVector ArkWebMediaInfoCToCpp::GetSourceInfos()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_media_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_media_source_info_vector_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_source_infos, ark_web_media_source_info_vector_default);

    // Execute
    return _struct->get_source_infos(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebRefPtr<ArkWebNativeMediaPlayerSurfaceInfo> ArkWebMediaInfoCToCpp::GetSurfaceInfo()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_media_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, nullptr);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_surface_info, nullptr);

    // Execute
    ark_web_native_media_player_surface_info_t* _retval = _struct->get_surface_info(_struct);

    // Return type: refptr_same
    return ArkWebNativeMediaPlayerSurfaceInfoCToCpp::Invert(_retval);
}

ArkWebMediaInfoCToCpp::ArkWebMediaInfoCToCpp() {}

ArkWebMediaInfoCToCpp::~ArkWebMediaInfoCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebMediaInfoCToCpp, ArkWebMediaInfo, ark_web_media_info_t>::kBridgeType =
    ARK_WEB_MEDIA_INFO;

} // namespace OHOS::ArkWeb

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

#include "ohos_nweb/ctocpp/ark_web_drag_data_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
bool ArkWebDragDataCToCpp::SetFileUri(const ArkWebString& uri)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_drag_data_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_file_uri, false);

    // Execute
    return _struct->set_file_uri(_struct, &uri);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebDragDataCToCpp::GetLinkURL()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_drag_data_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_link_url, ark_web_string_default);

    // Execute
    return _struct->get_link_url(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebDragDataCToCpp::SetLinkURL(const ArkWebString& url)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_drag_data_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_link_url, false);

    // Execute
    return _struct->set_link_url(_struct, &url);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebDragDataCToCpp::GetLinkTitle()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_drag_data_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_link_title, ark_web_string_default);

    // Execute
    return _struct->get_link_title(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebDragDataCToCpp::SetLinkTitle(const ArkWebString& title)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_drag_data_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_link_title, false);

    // Execute
    return _struct->set_link_title(_struct, &title);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebDragDataCToCpp::GetFragmentText()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_drag_data_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_fragment_text, ark_web_string_default);

    // Execute
    return _struct->get_fragment_text(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebDragDataCToCpp::SetFragmentText(const ArkWebString& text)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_drag_data_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_fragment_text, false);

    // Execute
    return _struct->set_fragment_text(_struct, &text);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebDragDataCToCpp::GetFragmentHtml()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_drag_data_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_fragment_html, ark_web_string_default);

    // Execute
    return _struct->get_fragment_html(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebDragDataCToCpp::SetFragmentHtml(const ArkWebString& html)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_drag_data_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_fragment_html, false);

    // Execute
    return _struct->set_fragment_html(_struct, &html);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebDragDataCToCpp::GetImageFileName()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_drag_data_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_image_file_name, ark_web_string_default);

    // Execute
    return _struct->get_image_file_name(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebDragDataCToCpp::GetPixelMapSetting(const void** data, size_t& len, int& width, int& height)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_drag_data_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_pixel_map_setting, false);

    // Execute
    return _struct->get_pixel_map_setting(_struct, data, &len, &width, &height);
}

ARK_WEB_NO_SANITIZE
bool ArkWebDragDataCToCpp::SetPixelMapSetting(const void* data, size_t len, int width, int height)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_drag_data_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_pixel_map_setting, false);

    // Execute
    return _struct->set_pixel_map_setting(_struct, data, len, width, height);
}

ARK_WEB_NO_SANITIZE
void ArkWebDragDataCToCpp::ClearImageFileNames()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_drag_data_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, clear_image_file_names, );

    // Execute
    _struct->clear_image_file_names(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebDragDataCToCpp::IsSingleImageContent()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_drag_data_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, is_single_image_content, false);

    // Execute
    return _struct->is_single_image_content(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebDragDataCToCpp::GetDragStartPosition(int& x, int& y)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_drag_data_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_drag_start_position, );

    // Execute
    _struct->get_drag_start_position(_struct, &x, &y);
}

ArkWebDragDataCToCpp::ArkWebDragDataCToCpp() {}

ArkWebDragDataCToCpp::~ArkWebDragDataCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebDragDataCToCpp, ArkWebDragData, ark_web_drag_data_t>::kBridgeType =
    ARK_WEB_DRAG_DATA;

} // namespace OHOS::ArkWeb

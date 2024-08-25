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

#include "ohos_nweb/ctocpp/ark_web_context_menu_params_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
int32_t ArkWebContextMenuParamsCToCpp::GetXCoord()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_context_menu_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_xcoord, 0);

    // Execute
    return _struct->get_xcoord(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebContextMenuParamsCToCpp::GetYCoord()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_context_menu_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_ycoord, 0);

    // Execute
    return _struct->get_ycoord(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebContextMenuParamsCToCpp::IsEditable()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_context_menu_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, is_editable, false);

    // Execute
    return _struct->is_editable(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebContextMenuParamsCToCpp::GetLinkUrl()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_context_menu_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_link_url, ark_web_string_default);

    // Execute
    return _struct->get_link_url(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebContextMenuParamsCToCpp::GetPageUrl()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_context_menu_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_page_url, ark_web_string_default);

    // Execute
    return _struct->get_page_url(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebContextMenuParamsCToCpp::GetSourceUrl()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_context_menu_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_source_url, ark_web_string_default);

    // Execute
    return _struct->get_source_url(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebContextMenuParamsCToCpp::GetTitleText()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_context_menu_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_title_text, ark_web_string_default);

    // Execute
    return _struct->get_title_text(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebContextMenuParamsCToCpp::GetSelectionText()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_context_menu_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_selection_text, ark_web_string_default);

    // Execute
    return _struct->get_selection_text(_struct);
}

ARK_WEB_NO_SANITIZE
int ArkWebContextMenuParamsCToCpp::GetMediaType()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_context_menu_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_media_type, 0);

    // Execute
    return _struct->get_media_type(_struct);
}

ARK_WEB_NO_SANITIZE
int ArkWebContextMenuParamsCToCpp::GetSourceType()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_context_menu_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_source_type, 0);

    // Execute
    return _struct->get_source_type(_struct);
}

ARK_WEB_NO_SANITIZE
int ArkWebContextMenuParamsCToCpp::GetInputFieldType()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_context_menu_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_input_field_type, 0);

    // Execute
    return _struct->get_input_field_type(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebContextMenuParamsCToCpp::HasImageContents()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_context_menu_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, has_image_contents, false);

    // Execute
    return _struct->has_image_contents(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebContextMenuParamsCToCpp::GetEditStateFlags()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_context_menu_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_edit_state_flags, 0);

    // Execute
    return _struct->get_edit_state_flags(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebContextMenuParamsCToCpp::GetUnfilteredLinkUrl()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_context_menu_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_unfiltered_link_url, ark_web_string_default);

    // Execute
    return _struct->get_unfiltered_link_url(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebContextMenuParamsCToCpp::GetContextMenuTypeFlags()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_context_menu_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_context_menu_type_flags, 0);

    // Execute
    return _struct->get_context_menu_type_flags(_struct);
}

ArkWebContextMenuParamsCToCpp::ArkWebContextMenuParamsCToCpp() {}

ArkWebContextMenuParamsCToCpp::~ArkWebContextMenuParamsCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebContextMenuParamsCToCpp, ArkWebContextMenuParams,
    ark_web_context_menu_params_t>::kBridgeType = ARK_WEB_CONTEXT_MENU_PARAMS;

} // namespace OHOS::ArkWeb

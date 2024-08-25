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

#include "ohos_nweb/ctocpp/ark_web_select_popup_menu_param_ctocpp.h"

#include "ohos_nweb/ctocpp/ark_web_select_menu_bound_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
ArkWebSelectPopupMenuItemVector ArkWebSelectPopupMenuParamCToCpp::GetMenuItems()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_select_popup_menu_param_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_select_popup_menu_item_vector_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_menu_items, ark_web_select_popup_menu_item_vector_default);

    // Execute
    return _struct->get_menu_items(_struct);
}

ARK_WEB_NO_SANITIZE
int ArkWebSelectPopupMenuParamCToCpp::GetItemHeight()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_select_popup_menu_param_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_item_height, 0);

    // Execute
    return _struct->get_item_height(_struct);
}

ARK_WEB_NO_SANITIZE
int ArkWebSelectPopupMenuParamCToCpp::GetSelectedItem()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_select_popup_menu_param_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_selected_item, 0);

    // Execute
    return _struct->get_selected_item(_struct);
}

ARK_WEB_NO_SANITIZE
double ArkWebSelectPopupMenuParamCToCpp::GetItemFontSize()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_select_popup_menu_param_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_item_font_size, 0);

    // Execute
    return _struct->get_item_font_size(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebSelectPopupMenuParamCToCpp::GetIsRightAligned()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_select_popup_menu_param_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_is_right_aligned, false);

    // Execute
    return _struct->get_is_right_aligned(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebRefPtr<ArkWebSelectMenuBound> ArkWebSelectPopupMenuParamCToCpp::GetSelectMenuBound()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_select_popup_menu_param_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, nullptr);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_select_menu_bound, nullptr);

    // Execute
    ark_web_select_menu_bound_t* _retval = _struct->get_select_menu_bound(_struct);

    // Return type: refptr_same
    return ArkWebSelectMenuBoundCToCpp::Invert(_retval);
}

ARK_WEB_NO_SANITIZE
bool ArkWebSelectPopupMenuParamCToCpp::GetIsAllowMultipleSelection()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_select_popup_menu_param_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_is_allow_multiple_selection, false);

    // Execute
    return _struct->get_is_allow_multiple_selection(_struct);
}

ArkWebSelectPopupMenuParamCToCpp::ArkWebSelectPopupMenuParamCToCpp() {}

ArkWebSelectPopupMenuParamCToCpp::~ArkWebSelectPopupMenuParamCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebSelectPopupMenuParamCToCpp, ArkWebSelectPopupMenuParam,
    ark_web_select_popup_menu_param_t>::kBridgeType = ARK_WEB_SELECT_POPUP_MENU_PARAM;

} // namespace OHOS::ArkWeb

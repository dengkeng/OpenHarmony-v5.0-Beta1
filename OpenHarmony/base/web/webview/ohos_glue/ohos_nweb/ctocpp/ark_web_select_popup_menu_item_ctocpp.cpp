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

#include "ohos_nweb/ctocpp/ark_web_select_popup_menu_item_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
int ArkWebSelectPopupMenuItemCToCpp::GetType()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_select_popup_menu_item_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_type, 0);

    // Execute
    return _struct->get_type(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebSelectPopupMenuItemCToCpp::GetLabel()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_select_popup_menu_item_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_label, ark_web_string_default);

    // Execute
    return _struct->get_label(_struct);
}

ARK_WEB_NO_SANITIZE
uint32_t ArkWebSelectPopupMenuItemCToCpp::GetAction()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_select_popup_menu_item_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_action, 0);

    // Execute
    return _struct->get_action(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebSelectPopupMenuItemCToCpp::GetToolTip()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_select_popup_menu_item_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_tool_tip, ark_web_string_default);

    // Execute
    return _struct->get_tool_tip(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebSelectPopupMenuItemCToCpp::GetIsChecked()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_select_popup_menu_item_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_is_checked, false);

    // Execute
    return _struct->get_is_checked(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebSelectPopupMenuItemCToCpp::GetIsEnabled()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_select_popup_menu_item_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_is_enabled, false);

    // Execute
    return _struct->get_is_enabled(_struct);
}

ARK_WEB_NO_SANITIZE
int ArkWebSelectPopupMenuItemCToCpp::GetTextDirection()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_select_popup_menu_item_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_text_direction, 0);

    // Execute
    return _struct->get_text_direction(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebSelectPopupMenuItemCToCpp::GetHasTextDirectionOverride()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_select_popup_menu_item_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_has_text_direction_override, false);

    // Execute
    return _struct->get_has_text_direction_override(_struct);
}

ArkWebSelectPopupMenuItemCToCpp::ArkWebSelectPopupMenuItemCToCpp() {}

ArkWebSelectPopupMenuItemCToCpp::~ArkWebSelectPopupMenuItemCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebSelectPopupMenuItemCToCpp, ArkWebSelectPopupMenuItem,
    ark_web_select_popup_menu_item_t>::kBridgeType = ARK_WEB_SELECT_POPUP_MENU_ITEM;

} // namespace OHOS::ArkWeb

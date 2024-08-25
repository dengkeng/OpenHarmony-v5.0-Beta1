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

#include "ohos_nweb/ctocpp/ark_web_accessibility_node_info_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebAccessibilityNodeInfoCToCpp::GetHint()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_hint, ark_web_string_default);

    // Execute
    return _struct->get_hint(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebAccessibilityNodeInfoCToCpp::GetError()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_error, ark_web_string_default);

    // Execute
    return _struct->get_error(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebAccessibilityNodeInfoCToCpp::GetRectX()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_rect_x, 0);

    // Execute
    return _struct->get_rect_x(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebAccessibilityNodeInfoCToCpp::GetRectY()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_rect_y, 0);

    // Execute
    return _struct->get_rect_y(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebAccessibilityNodeInfoCToCpp::SetPageId(int32_t page_id)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_page_id, );

    // Execute
    _struct->set_page_id(_struct, page_id);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebAccessibilityNodeInfoCToCpp::GetPageId()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_page_id, 0);

    // Execute
    return _struct->get_page_id(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebUint32Vector ArkWebAccessibilityNodeInfoCToCpp::GetActions()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_uint32_vector_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_actions, ark_web_uint32_vector_default);

    // Execute
    return _struct->get_actions(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebAccessibilityNodeInfoCToCpp::GetContent()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_content, ark_web_string_default);

    // Execute
    return _struct->get_content(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebInt64Vector ArkWebAccessibilityNodeInfoCToCpp::GetChildIds()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_int64_vector_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_child_ids, ark_web_int64_vector_default);

    // Execute
    return _struct->get_child_ids(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebAccessibilityNodeInfoCToCpp::SetParentId(int64_t parentId_id)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_parent_id, );

    // Execute
    _struct->set_parent_id(_struct, parentId_id);
}

ARK_WEB_NO_SANITIZE
int64_t ArkWebAccessibilityNodeInfoCToCpp::GetParentId()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_parent_id, 0);

    // Execute
    return _struct->get_parent_id(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebAccessibilityNodeInfoCToCpp::GetIsHeading()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_is_heading, false);

    // Execute
    return _struct->get_is_heading(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebAccessibilityNodeInfoCToCpp::GetIsChecked()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_is_checked, false);

    // Execute
    return _struct->get_is_checked(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebAccessibilityNodeInfoCToCpp::GetIsEnabled()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_is_enabled, false);

    // Execute
    return _struct->get_is_enabled(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebAccessibilityNodeInfoCToCpp::GetIsFocused()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_is_focused, false);

    // Execute
    return _struct->get_is_focused(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebAccessibilityNodeInfoCToCpp::GetRectWidth()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_rect_width, 0);

    // Execute
    return _struct->get_rect_width(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebAccessibilityNodeInfoCToCpp::GetRectHeight()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_rect_height, 0);

    // Execute
    return _struct->get_rect_height(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebAccessibilityNodeInfoCToCpp::GetIsVisible()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_is_visible, false);

    // Execute
    return _struct->get_is_visible(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebAccessibilityNodeInfoCToCpp::GetIsHinting()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_is_hinting, false);

    // Execute
    return _struct->get_is_hinting(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebAccessibilityNodeInfoCToCpp::GetIsEditable()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_is_editable, false);

    // Execute
    return _struct->get_is_editable(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebAccessibilityNodeInfoCToCpp::GetIsSelected()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_is_selected, false);

    // Execute
    return _struct->get_is_selected(_struct);
}

ARK_WEB_NO_SANITIZE
size_t ArkWebAccessibilityNodeInfoCToCpp::GetItemCounts()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_item_counts, 0);

    // Execute
    return _struct->get_item_counts(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebAccessibilityNodeInfoCToCpp::GetLiveRegion()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_live_region, 0);

    // Execute
    return _struct->get_live_region(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebAccessibilityNodeInfoCToCpp::GetIsPassword()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_is_password, false);

    // Execute
    return _struct->get_is_password(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebAccessibilityNodeInfoCToCpp::GetIsCheckable()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_is_checkable, false);

    // Execute
    return _struct->get_is_checkable(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebAccessibilityNodeInfoCToCpp::GetIsClickable()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_is_clickable, false);

    // Execute
    return _struct->get_is_clickable(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebAccessibilityNodeInfoCToCpp::GetIsFocusable()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_is_focusable, false);

    // Execute
    return _struct->get_is_focusable(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebAccessibilityNodeInfoCToCpp::GetIsScrollable()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_is_scrollable, false);

    // Execute
    return _struct->get_is_scrollable(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebAccessibilityNodeInfoCToCpp::GetIsDeletable()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_is_deletable, false);

    // Execute
    return _struct->get_is_deletable(_struct);
}

ARK_WEB_NO_SANITIZE
int64_t ArkWebAccessibilityNodeInfoCToCpp::GetAccessibilityId()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_accessibility_id, 0);

    // Execute
    return _struct->get_accessibility_id(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebAccessibilityNodeInfoCToCpp::GetIsPopupSupported()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_is_popup_supported, false);

    // Execute
    return _struct->get_is_popup_supported(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebAccessibilityNodeInfoCToCpp::GetIsContentInvalid()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_is_content_invalid, false);

    // Execute
    return _struct->get_is_content_invalid(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebAccessibilityNodeInfoCToCpp::GetSelectionEnd()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_selection_end, 0);

    // Execute
    return _struct->get_selection_end(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebAccessibilityNodeInfoCToCpp::GetSelectionStart()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_selection_start, 0);

    // Execute
    return _struct->get_selection_start(_struct);
}

ARK_WEB_NO_SANITIZE
float ArkWebAccessibilityNodeInfoCToCpp::GetRangeInfoMin()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_range_info_min, 0);

    // Execute
    return _struct->get_range_info_min(_struct);
}

ARK_WEB_NO_SANITIZE
float ArkWebAccessibilityNodeInfoCToCpp::GetRangeInfoMax()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_range_info_max, 0);

    // Execute
    return _struct->get_range_info_max(_struct);
}

ARK_WEB_NO_SANITIZE
float ArkWebAccessibilityNodeInfoCToCpp::GetRangeInfoCurrent()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_range_info_current, 0);

    // Execute
    return _struct->get_range_info_current(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebAccessibilityNodeInfoCToCpp::GetInputType()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_input_type, 0);

    // Execute
    return _struct->get_input_type(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebAccessibilityNodeInfoCToCpp::GetComponentType()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_component_type, ark_web_string_default);

    // Execute
    return _struct->get_component_type(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebAccessibilityNodeInfoCToCpp::GetDescriptionInfo()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_description_info, ark_web_string_default);

    // Execute
    return _struct->get_description_info(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebAccessibilityNodeInfoCToCpp::GetGridRows()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_grid_rows, 0);

    // Execute
    return _struct->get_grid_rows(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebAccessibilityNodeInfoCToCpp::GetGridItemRow()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_grid_item_row, 0);

    // Execute
    return _struct->get_grid_item_row(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebAccessibilityNodeInfoCToCpp::GetGridColumns()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_grid_columns, 0);

    // Execute
    return _struct->get_grid_columns(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebAccessibilityNodeInfoCToCpp::GetGridItemColumn()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_grid_item_column, 0);

    // Execute
    return _struct->get_grid_item_column(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebAccessibilityNodeInfoCToCpp::GetGridItemRowSpan()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_grid_item_row_span, 0);

    // Execute
    return _struct->get_grid_item_row_span(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebAccessibilityNodeInfoCToCpp::GetGridSelectedMode()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_grid_selected_mode, 0);

    // Execute
    return _struct->get_grid_selected_mode(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebAccessibilityNodeInfoCToCpp::GetGridItemColumnSpan()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_grid_item_column_span, 0);

    // Execute
    return _struct->get_grid_item_column_span(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebAccessibilityNodeInfoCToCpp::GetIsAccessibilityFocus()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_is_accessibility_focus, false);

    // Execute
    return _struct->get_is_accessibility_focus(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebAccessibilityNodeInfoCToCpp::GetIsPluralLineSupported()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_accessibility_node_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_is_plural_line_supported, false);

    // Execute
    return _struct->get_is_plural_line_supported(_struct);
}

ArkWebAccessibilityNodeInfoCToCpp::ArkWebAccessibilityNodeInfoCToCpp() {}

ArkWebAccessibilityNodeInfoCToCpp::~ArkWebAccessibilityNodeInfoCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebAccessibilityNodeInfoCToCpp, ArkWebAccessibilityNodeInfo,
    ark_web_accessibility_node_info_t>::kBridgeType = ARK_WEB_ACCESSIBILITY_NODE_INFO;

} // namespace OHOS::ArkWeb

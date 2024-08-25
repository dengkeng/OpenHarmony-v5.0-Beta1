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

#include "ohos_nweb/ctocpp/ark_web_quick_menu_params_ctocpp.h"

#include "ohos_nweb/ctocpp/ark_web_touch_handle_state_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
int32_t ArkWebQuickMenuParamsCToCpp::GetXCoord()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_quick_menu_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_xcoord, 0);

    // Execute
    return _struct->get_xcoord(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebQuickMenuParamsCToCpp::GetYCoord()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_quick_menu_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_ycoord, 0);

    // Execute
    return _struct->get_ycoord(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebQuickMenuParamsCToCpp::GetWidth()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_quick_menu_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_width, 0);

    // Execute
    return _struct->get_width(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebQuickMenuParamsCToCpp::GetHeight()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_quick_menu_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_height, 0);

    // Execute
    return _struct->get_height(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebQuickMenuParamsCToCpp::GetEditStateFlags()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_quick_menu_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_edit_state_flags, 0);

    // Execute
    return _struct->get_edit_state_flags(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebQuickMenuParamsCToCpp::GetSelectX()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_quick_menu_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_select_x, 0);

    // Execute
    return _struct->get_select_x(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebQuickMenuParamsCToCpp::GetSelectY()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_quick_menu_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_select_y, 0);

    // Execute
    return _struct->get_select_y(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebQuickMenuParamsCToCpp::GetSelectWidth()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_quick_menu_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_select_width, 0);

    // Execute
    return _struct->get_select_width(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebQuickMenuParamsCToCpp::GetSelectXHeight()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_quick_menu_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_select_xheight, 0);

    // Execute
    return _struct->get_select_xheight(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebRefPtr<ArkWebTouchHandleState> ArkWebQuickMenuParamsCToCpp::GetTouchHandleState(int type)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_quick_menu_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, nullptr);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_touch_handle_state, nullptr);

    // Execute
    ark_web_touch_handle_state_t* _retval = _struct->get_touch_handle_state(_struct, type);

    // Return type: refptr_same
    return ArkWebTouchHandleStateCToCpp::Invert(_retval);
}

ArkWebQuickMenuParamsCToCpp::ArkWebQuickMenuParamsCToCpp() {}

ArkWebQuickMenuParamsCToCpp::~ArkWebQuickMenuParamsCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebQuickMenuParamsCToCpp, ArkWebQuickMenuParams,
    ark_web_quick_menu_params_t>::kBridgeType = ARK_WEB_QUICK_MENU_PARAMS;

} // namespace OHOS::ArkWeb

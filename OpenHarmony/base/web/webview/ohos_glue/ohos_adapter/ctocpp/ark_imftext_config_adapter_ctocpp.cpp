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

#include "ohos_adapter/ctocpp/ark_imftext_config_adapter_ctocpp.h"

#include "ohos_adapter/ctocpp/ark_imfcursor_info_adapter_ctocpp.h"
#include "ohos_adapter/ctocpp/ark_imfinput_attribute_adapter_ctocpp.h"
#include "ohos_adapter/ctocpp/ark_imfselection_range_adapter_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
ArkWebRefPtr<ArkIMFInputAttributeAdapter> ArkIMFTextConfigAdapterCToCpp::GetInputAttribute()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_imftext_config_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, nullptr);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_input_attribute, nullptr);

    // Execute
    ark_imfinput_attribute_adapter_t* _retval = _struct->get_input_attribute(_struct);

    // Return type: refptr_same
    return ArkIMFInputAttributeAdapterCToCpp::Invert(_retval);
}

ARK_WEB_NO_SANITIZE
ArkWebRefPtr<ArkIMFCursorInfoAdapter> ArkIMFTextConfigAdapterCToCpp::GetCursorInfo()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_imftext_config_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, nullptr);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_cursor_info, nullptr);

    // Execute
    ark_imfcursor_info_adapter_t* _retval = _struct->get_cursor_info(_struct);

    // Return type: refptr_same
    return ArkIMFCursorInfoAdapterCToCpp::Invert(_retval);
}

ARK_WEB_NO_SANITIZE
ArkWebRefPtr<ArkIMFSelectionRangeAdapter> ArkIMFTextConfigAdapterCToCpp::GetSelectionRange()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_imftext_config_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, nullptr);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_selection_range, nullptr);

    // Execute
    ark_imfselection_range_adapter_t* _retval = _struct->get_selection_range(_struct);

    // Return type: refptr_same
    return ArkIMFSelectionRangeAdapterCToCpp::Invert(_retval);
}

ARK_WEB_NO_SANITIZE
uint32_t ArkIMFTextConfigAdapterCToCpp::GetWindowId()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_imftext_config_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_window_id, 0);

    // Execute
    return _struct->get_window_id(_struct);
}

ArkIMFTextConfigAdapterCToCpp::ArkIMFTextConfigAdapterCToCpp() {}

ArkIMFTextConfigAdapterCToCpp::~ArkIMFTextConfigAdapterCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkIMFTextConfigAdapterCToCpp, ArkIMFTextConfigAdapter,
    ark_imftext_config_adapter_t>::kBridgeType = ARK_IMFTEXT_CONFIG_ADAPTER;

} // namespace OHOS::ArkWeb

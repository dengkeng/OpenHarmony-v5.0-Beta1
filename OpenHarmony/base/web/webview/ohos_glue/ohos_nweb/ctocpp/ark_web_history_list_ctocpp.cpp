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

#include "ohos_nweb/ctocpp/ark_web_history_list_ctocpp.h"

#include "ohos_nweb/ctocpp/ark_web_history_item_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
ArkWebRefPtr<ArkWebHistoryItem> ArkWebHistoryListCToCpp::GetItem(int32_t index)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_history_list_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, nullptr);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_item, nullptr);

    // Execute
    ark_web_history_item_t* _retval = _struct->get_item(_struct, index);

    // Return type: refptr_same
    return ArkWebHistoryItemCToCpp::Invert(_retval);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebHistoryListCToCpp::GetListSize()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_history_list_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_list_size, 0);

    // Execute
    return _struct->get_list_size(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebHistoryListCToCpp::GetCurrentIndex()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_history_list_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_current_index, 0);

    // Execute
    return _struct->get_current_index(_struct);
}

ArkWebHistoryListCToCpp::ArkWebHistoryListCToCpp() {}

ArkWebHistoryListCToCpp::~ArkWebHistoryListCToCpp() {}

template<>
ArkWebBridgeType
    ArkWebCToCppRefCounted<ArkWebHistoryListCToCpp, ArkWebHistoryList, ark_web_history_list_t>::kBridgeType =
        ARK_WEB_HISTORY_LIST;

} // namespace OHOS::ArkWeb

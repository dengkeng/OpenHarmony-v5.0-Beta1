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

#include "ohos_nweb/ctocpp/ark_web_history_item_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
bool ArkWebHistoryItemCToCpp::GetFavicon(void** data, int& width, int& height, int& color_type, int& alpha_type)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_history_item_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_favicon, false);

    // Execute
    return _struct->get_favicon(_struct, data, &width, &height, &color_type, &alpha_type);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebHistoryItemCToCpp::GetHistoryUrl()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_history_item_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_history_url, ark_web_string_default);

    // Execute
    return _struct->get_history_url(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebHistoryItemCToCpp::GetHistoryTitle()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_history_item_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_history_title, ark_web_string_default);

    // Execute
    return _struct->get_history_title(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebHistoryItemCToCpp::GetHistoryRawUrl()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_history_item_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_history_raw_url, ark_web_string_default);

    // Execute
    return _struct->get_history_raw_url(_struct);
}

ArkWebHistoryItemCToCpp::ArkWebHistoryItemCToCpp() {}

ArkWebHistoryItemCToCpp::~ArkWebHistoryItemCToCpp() {}

template<>
ArkWebBridgeType
    ArkWebCToCppRefCounted<ArkWebHistoryItemCToCpp, ArkWebHistoryItem, ark_web_history_item_t>::kBridgeType =
        ARK_WEB_HISTORY_ITEM;

} // namespace OHOS::ArkWeb

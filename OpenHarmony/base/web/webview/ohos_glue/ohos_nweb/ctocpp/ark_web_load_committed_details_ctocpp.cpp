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

#include "ohos_nweb/ctocpp/ark_web_load_committed_details_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
bool ArkWebLoadCommittedDetailsCToCpp::IsMainFrame()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_load_committed_details_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, is_main_frame, false);

    // Execute
    return _struct->is_main_frame(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebLoadCommittedDetailsCToCpp::IsSameDocument()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_load_committed_details_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, is_same_document, false);

    // Execute
    return _struct->is_same_document(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebLoadCommittedDetailsCToCpp::DidReplaceEntry()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_load_committed_details_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, did_replace_entry, false);

    // Execute
    return _struct->did_replace_entry(_struct);
}

ARK_WEB_NO_SANITIZE
int ArkWebLoadCommittedDetailsCToCpp::GetNavigationType()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_load_committed_details_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_navigation_type, 0);

    // Execute
    return _struct->get_navigation_type(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebLoadCommittedDetailsCToCpp::GetURL()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_load_committed_details_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_url, ark_web_string_default);

    // Execute
    return _struct->get_url(_struct);
}

ArkWebLoadCommittedDetailsCToCpp::ArkWebLoadCommittedDetailsCToCpp() {}

ArkWebLoadCommittedDetailsCToCpp::~ArkWebLoadCommittedDetailsCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebLoadCommittedDetailsCToCpp, ArkWebLoadCommittedDetails,
    ark_web_load_committed_details_t>::kBridgeType = ARK_WEB_LOAD_COMMITTED_DETAILS;

} // namespace OHOS::ArkWeb

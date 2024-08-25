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

#include "ohos_nweb/cpptoc/ark_web_find_callback_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

void ARK_WEB_CALLBACK ark_web_find_callback_on_find_result_received(struct _ark_web_find_callback_t* self,
    const int active_match_ordinal, const int number_of_matches, const bool is_done_counting)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkWebFindCallbackCppToC::Get(self)->OnFindResultReceived(
        active_match_ordinal, number_of_matches, is_done_counting);
}

} // namespace

ArkWebFindCallbackCppToC::ArkWebFindCallbackCppToC()
{
    GetStruct()->on_find_result_received = ark_web_find_callback_on_find_result_received;
}

ArkWebFindCallbackCppToC::~ArkWebFindCallbackCppToC() {}

template<>
ArkWebBridgeType
    ArkWebCppToCRefCounted<ArkWebFindCallbackCppToC, ArkWebFindCallback, ark_web_find_callback_t>::kBridgeType =
        ARK_WEB_FIND_CALLBACK;

} // namespace OHOS::ArkWeb

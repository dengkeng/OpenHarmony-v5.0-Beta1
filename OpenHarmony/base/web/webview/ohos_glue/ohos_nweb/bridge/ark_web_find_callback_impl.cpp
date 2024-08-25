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

#include "ohos_nweb/bridge/ark_web_find_callback_impl.h"

#include "base/bridge/ark_web_bridge_macros.h"

namespace OHOS::ArkWeb {

ArkWebFindCallbackImpl::ArkWebFindCallbackImpl(std::shared_ptr<OHOS::NWeb::NWebFindCallback> nweb_find_callback)
    : nweb_find_callback_(nweb_find_callback)
{}

void ArkWebFindCallbackImpl::OnFindResultReceived(
    const int active_match_ordinal, const int number_of_matches, const bool is_done_counting)
{
    nweb_find_callback_->OnFindResultReceived(active_match_ordinal, number_of_matches, is_done_counting);
}

} // namespace OHOS::ArkWeb

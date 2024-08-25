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

#include "extension_record.h"
#include "preload_uiext_state_observer.h"
#include "hilog_tag_wrapper.h"
#include "hilog_wrapper.h"


namespace OHOS {
namespace AAFwk {
PreLoadUIExtStateObserver::PreLoadUIExtStateObserver(
    std::weak_ptr<OHOS::AbilityRuntime::ExtensionRecord> extensionRecord) : extensionRecord_(extensionRecord) {}

void PreLoadUIExtStateObserver::OnProcessDied(const AppExecFwk::ProcessData &processData)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "called.");
    auto extensionRecord = extensionRecord_.lock();
    if (extensionRecord != nullptr) {
        extensionRecord->UnloadUIExtensionAbility();
    } else {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "extensionRecord null");
    }
}
} // namespace AAFwk
} // namespace OHOS
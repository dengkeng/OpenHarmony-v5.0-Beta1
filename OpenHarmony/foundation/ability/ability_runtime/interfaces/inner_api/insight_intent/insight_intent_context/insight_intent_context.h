/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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


#ifndef OHOS_ABILITY_RUNTIME_INSIGHT_INTENT_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_INSIGHT_INTENT_CONTEXT_H

#include "iremote_object.h"
#include "want.h"

namespace OHOS {
namespace AbilityRuntime {
/**
 * @class InsightIntentContext
 * InsightIntentContext provides a context for insightintent to execute certain tasks.
 */
class InsightIntentContext final {
public:
    InsightIntentContext(const sptr<IRemoteObject>& token, const std::string& bundleName, int32_t winMode,
        uint64_t intentId) : token_(token), bundleName_(bundleName), winMode_(winMode), intentId_(intentId) {}
    ~InsightIntentContext() = default;

    /**
     * Starts a new ability. Only such ability in the same application with the caller
     * can be started.
     *
     * @param want Indicates the Want containing information about the target ability to start.
     * @return result of StartAbility.
     */
    ErrCode StartAbilityByInsightIntent(const AAFwk::Want &want);

    std::string GetBundleName() const
    {
        return bundleName_;
    }

    int32_t GetCurrentWindowMode() const
    {
        return winMode_;
    }

private:
    sptr<IRemoteObject> token_ = nullptr;
    std::string bundleName_ = "";
    int32_t winMode_ = 0;
    uint64_t intentId_ = 0;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_JS_INSIGHT_INTENT_CONTEXT_H

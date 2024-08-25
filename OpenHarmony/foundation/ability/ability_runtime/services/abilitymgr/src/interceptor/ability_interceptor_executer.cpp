/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "interceptor/ability_interceptor_executer.h"
#include "hilog_wrapper.h"
#include "hitrace_meter.h"

namespace OHOS {
namespace AAFwk {
void AbilityInterceptorExecuter::AddInterceptor(const std::shared_ptr<IAbilityInterceptor> &interceptor)
{
    if (interceptor != nullptr) {
        interceptorList_.push_back(interceptor);
    }
}

ErrCode AbilityInterceptorExecuter::DoProcess(AbilityInterceptorParam param)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    int32_t result = ERR_OK;
    auto item = interceptorList_.begin();
    while (item != interceptorList_.end()) {
        result = (*item)->DoProcess(param);
        if (result != ERR_OK) {
            break;
        } else {
            item++;
        }
    }
    return result;
}

void AbilityInterceptorExecuter::SetTaskHandler(std::shared_ptr<AAFwk::TaskHandlerWrap> taskHandler)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    for (auto &interceptor : interceptorList_) {
        if (interceptor == nullptr) {
            continue;
        }
        interceptor->SetTaskHandler(taskHandler);
    }
}
} // namespace AAFwk
} // namespace OHOS
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

#include "frameworks/base/log/trace_id.h"

#include "hitrace/trace.h"

namespace OHOS::Ace {

class TraceIdImpl : public TraceId {
public:
    TraceIdImpl() : traceId_(std::make_unique<OHOS::HiviewDFX::HiTraceId>(OHOS::HiviewDFX::HiTraceChain::GetId())) {}

    ~TraceIdImpl() = default;

    void SetTraceId() override
    {
        if (traceId_ && traceId_->IsValid()) {
            OHOS::HiviewDFX::HiTraceChain::SetId(*(traceId_.get()));
        }
    }

    void ClearTraceId() override
    {
        OHOS::HiviewDFX::HiTraceChain::ClearId();
    }

private:
    std::unique_ptr<OHOS::HiviewDFX::HiTraceId> traceId_;
};

TraceId* TraceId::CreateTraceId()
{
    return new TraceIdImpl();
}

} // namespace OHOS::Ace
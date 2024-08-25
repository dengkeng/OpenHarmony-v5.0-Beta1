/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef IMS_BASE_H
#define IMS_BASE_H
#include <map>
#include <memory>
#include <string>

#include "event_runner.h"
#include "telephony_log_wrapper.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
class ImsBase {
public:
    ImsBase() = default;

    virtual ~ImsBase() = default;

    virtual bool Init() = 0;

    virtual bool CreateEventLoop(std::string loopName)
    {
        eventLoop_ = AppExecFwk::EventRunner::Create(loopName);
        if (eventLoop_ == nullptr) {
            TELEPHONY_LOGE("Failed to create EventRunner");
            return false;
        }
        return true;
    }

protected:
    std::shared_ptr<AppExecFwk::EventRunner> eventLoop_ = nullptr;
};
} // namespace Telephony
} // namespace OHOS
#endif // IMS_BASE_H

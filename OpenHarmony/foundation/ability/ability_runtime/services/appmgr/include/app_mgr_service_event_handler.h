/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_APP_MGR_SERVICE_EVENT_HANDLER_H
#define OHOS_ABILITY_RUNTIME_APP_MGR_SERVICE_EVENT_HANDLER_H

#include "event_handler_wrap.h"

namespace OHOS {
namespace AppExecFwk {
class AppMgrServiceInner;

class AMSEventHandler : public AAFwk::EventHandlerWrap {
public:
    AMSEventHandler(const std::shared_ptr<AAFwk::TaskHandlerWrap> &taskHandler,
        const std::weak_ptr<AppMgrServiceInner> &appMgr);
    virtual ~AMSEventHandler() override;

    virtual void ProcessEvent(const AAFwk::EventWrap &event) override;

    static constexpr uint32_t TERMINATE_ABILITY_TIMEOUT_MSG = 0;
    static constexpr uint32_t TERMINATE_APPLICATION_TIMEOUT_MSG = 1;
    static constexpr uint32_t ADD_ABILITY_STAGE_INFO_TIMEOUT_MSG = 2;
    static constexpr uint32_t START_SPECIFIED_ABILITY_TIMEOUT_MSG = 3;
    static constexpr uint32_t START_PROCESS_SPECIFIED_ABILITY_TIMEOUT_MSG = 4;
    static constexpr uint32_t START_SPECIFIED_PROCESS_TIMEOUT_MSG = 5;

#ifdef SUPPORT_ASAN
    static constexpr uint32_t TERMINATE_ABILITY_TIMEOUT = 45000; // ms
    static constexpr uint32_t TERMINATE_APPLICATION_TIMEOUT = 150000; // ms
    static constexpr uint32_t ADD_ABILITY_STAGE_INFO_TIMEOUT = 45000; // ms
    static constexpr uint32_t START_SPECIFIED_ABILITY_TIMEOUT = 45000; // ms
    static constexpr uint32_t START_PROCESS_SPECIFIED_ABILITY_TIMEOUT = 75000; // ms
    static constexpr uint32_t START_SPECIFIED_PROCESS_TIMEOUT = 45000; // ms
    static constexpr uint32_t KILL_PROCESS_TIMEOUT = 45000; // ms
#else
    static constexpr uint32_t TERMINATE_ABILITY_TIMEOUT = 3000; // ms
    static constexpr uint32_t TERMINATE_APPLICATION_TIMEOUT = 10000; // ms
    static constexpr uint32_t ADD_ABILITY_STAGE_INFO_TIMEOUT = 3000; // ms
    static constexpr uint32_t START_SPECIFIED_ABILITY_TIMEOUT = 3000; // ms
    static constexpr uint32_t START_PROCESS_SPECIFIED_ABILITY_TIMEOUT = 5000; // ms
    static constexpr uint32_t START_SPECIFIED_PROCESS_TIMEOUT = 2000; // ms
    static constexpr uint32_t KILL_PROCESS_TIMEOUT = 3000; // ms
#endif
    static constexpr uint32_t DELAY_KILL_PROCESS_TIMEOUT = 1000; // ms
private:
    std::weak_ptr<AppMgrServiceInner> appMgr_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_APP_MGR_SERVICE_EVENT_HANDLER_H

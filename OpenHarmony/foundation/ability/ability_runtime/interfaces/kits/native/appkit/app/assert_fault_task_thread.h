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

#ifndef OHOS_ABILITY_RUNTIME_ASSERT_FAULT_TASK_THREAD_H
#define OHOS_ABILITY_RUNTIME_ASSERT_FAULT_TASK_THREAD_H

#include <chrono>
#include <memory>
#include <mutex>

#include "ability_state.h"
#include "event_handler.h"
#include "event_runner.h"
#include "iremote_object.h"
#include "singleton.h"

namespace OHOS {
namespace AppExecFwk {
class MainThread;
} // namespace AppExecFwk
namespace AbilityRuntime {
class AssertFaultTaskThread : public DelayedSingleton<AssertFaultTaskThread>,
    public std::enable_shared_from_this<AssertFaultTaskThread> {
    DISALLOW_COPY_AND_MOVE(AssertFaultTaskThread);
public:
    AssertFaultTaskThread() = default;
    virtual ~AssertFaultTaskThread() = default;

    static std::shared_ptr<AssertFaultTaskThread> GetInstance();

    void InitAssertFaultTask(const wptr<AppExecFwk::MainThread> &weak, bool isDebugModule);
    void NotifyReleaseLongWaiting();
    void Stop();
    AAFwk::UserStatus RequestAssertResult(const std::string &exprStr);

private:
    AAFwk::UserStatus HandleAssertCallback(const std::string &exprStr);

private:
    wptr<AppExecFwk::MainThread> mainThread_;
    std::mutex assertResultMutex_;
    std::condition_variable assertResultCV_;
    bool isDebugModule_ = false;
    std::shared_ptr<AppExecFwk::EventRunner> assertRunner_ = nullptr;
    std::shared_ptr<AppExecFwk::EventHandler> assertHandler_ = nullptr;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_ASSERT_FAULT_TASK_THREAD_H
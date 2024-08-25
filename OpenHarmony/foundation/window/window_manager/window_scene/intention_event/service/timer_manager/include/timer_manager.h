/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef TIMER_MANAGER_H
#define TIMER_MANAGER_H

#include <cinttypes>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <thread>

#include "singleton.h"
#include "util.h"

namespace OHOS {
namespace Rosen {

enum class TimerMgrState {
    STATE_NOT_START,
    STATE_RUNNING,
    STATE_EXIT
};
class TimerManager final {
    DECLARE_DELAYED_SINGLETON(TimerManager);

public:
    DISALLOW_COPY_AND_MOVE(TimerManager);
    void Init();
    int32_t AddTimer(int32_t intervalMs, std::function<void()> callback);
    int32_t RemoveTimer(int32_t timerId);
private:
    struct TimerItem {
        int32_t id { 0 };
        int32_t intervalMs  { 0 };
        int64_t nextCallTime  { 0 };
        std::function<void()> callback;
    };
private:
    void OnThread();
    void OnStop();
    int32_t CalcNextDelay();
    void ProcessTimers();
    int32_t TakeNextTimerId();
    int32_t AddTimerInternal(int32_t intervalMs, std::function<void()> callback);
    int32_t RemoveTimerInternal(int32_t timerId);
    void InsertTimerInternal(std::unique_ptr<TimerItem>& timer);
    int32_t CalcNextDelayInternal();
    void ProcessTimersInternal();

private:
    std::recursive_mutex mutex_;
    std::atomic<TimerMgrState> state_ { TimerMgrState::STATE_NOT_START };
    std::thread timerWorker_;
    std::list<std::unique_ptr<TimerItem>> timers_;
};
} // namespace Rosen
} // namespace OHOS
#endif // TIMER_MANAGER_H
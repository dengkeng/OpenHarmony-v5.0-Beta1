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

#include "timer_manager.h"

#include <algorithm>
#include <cinttypes>

#include "entrance_log.h"
#include "window_manager_hilog.h"

namespace OHOS {
namespace Rosen {
namespace {
constexpr int32_t MIN_DELAY = 5000;
constexpr int32_t MIN_INTERVAL = 50;
constexpr int32_t MAX_INTERVAL_MS = 10000;
constexpr int32_t MAX_TIMER_COUNT = 64;
constexpr int32_t NONEXISTENT_ID = -1;
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, HILOG_DOMAIN_WINDOW, "TimerManager" };
const std::string TIMER_MANAGER_THREAD_NAME { "ANR_TIMER_MANAGER_THREAD" };
} // namespace

TimerManager::TimerManager() {}
TimerManager::~TimerManager()
{
    OnStop();
}

void TimerManager::Init()
{
    CALL_DEBUG_ENTER;
    if (state_ != TimerMgrState::STATE_RUNNING) {
        {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            timerWorker_ = std::thread(std::bind(&TimerManager::OnThread, this), TIMER_MANAGER_THREAD_NAME);
        }
        state_ = TimerMgrState::STATE_RUNNING;
    } else {
        WLOGFD("TimerManager init already");
    }
}

int32_t TimerManager::AddTimer(int32_t intervalMs, std::function<void()> callback)
{
    if (state_ != TimerMgrState::STATE_RUNNING) {
        return -1;
    }
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return AddTimerInternal(intervalMs, callback);
}

int32_t TimerManager::RemoveTimer(int32_t timerId)
{
    if (state_ != TimerMgrState::STATE_RUNNING) {
        return -1;
    }
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return RemoveTimerInternal(timerId);
}

int32_t TimerManager::CalcNextDelay()
{
    if (state_ != TimerMgrState::STATE_RUNNING) {
        return -1;
    }
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return CalcNextDelayInternal();
}

void TimerManager::ProcessTimers()
{
    if (state_ != TimerMgrState::STATE_RUNNING) {
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    ProcessTimersInternal();
}

void TimerManager::OnThread()
{
    CALL_DEBUG_ENTER;
    while (state_ == TimerMgrState::STATE_RUNNING) {
        int32_t timeout = CalcNextDelay();
        std::this_thread::sleep_for(std::chrono::milliseconds(timeout));
        ProcessTimers();
    }
}

void TimerManager::OnStop()
{
    CALL_DEBUG_ENTER;
    state_ = TimerMgrState::STATE_EXIT;
    if (timerWorker_.joinable()) {
        timerWorker_.join();
    }
}

int32_t TimerManager::TakeNextTimerId()
{
    WLOGFI("TimerManager::TakeNextTimerId enter");
    uint64_t timerSlot = 0;
    uint64_t one = 1;

    for (const auto &timer : timers_) {
        timerSlot |= (one << timer->id);
    }

    for (int32_t i = 0; i < MAX_TIMER_COUNT; i++) {
        if ((timerSlot & (one << i)) == 0) {
            return i;
        }
    }
    WLOGFI("TimerManager::TakeNextTimerId finish");
    return NONEXISTENT_ID;
}

int32_t TimerManager::AddTimerInternal(int32_t intervalMs, std::function<void()> callback)
{
    WLOGFI("TimerManager::AddTimerInternal enter");
    if (intervalMs < MIN_INTERVAL) {
        intervalMs = MIN_INTERVAL;
    } else if (intervalMs > MAX_INTERVAL_MS) {
        intervalMs = MAX_INTERVAL_MS;
    }
    if (!callback) {
        return NONEXISTENT_ID;
    }
    int32_t timerId = TakeNextTimerId();
    if (timerId < 0) {
        return NONEXISTENT_ID;
    }
    auto timer = std::make_unique<TimerItem>();
    timer->id = timerId;
    timer->intervalMs = intervalMs;
    auto nowTime = GetMillisTime();
    if (!AddInt64(nowTime, timer->intervalMs, timer->nextCallTime)) {
        WLOGFE("The addition of nextCallTime in TimerItem overflows, nowTime:%{public}" PRId64
                ", timerId:%{public}d, intervalMs:%{public}d, nextCallTime:%{public}" PRId64,
                nowTime, timer->id, timer->intervalMs, timer->nextCallTime);
        return NONEXISTENT_ID;
    }
    timer->callback = callback;
    InsertTimerInternal(timer);
    WLOGFI("TimerManager::AddTimerInternal finish");
    return timerId;
}

int32_t TimerManager::RemoveTimerInternal(int32_t timerId)
{
    for (auto it = timers_.begin(); it != timers_.end(); ++it) {
        if ((*it)->id == timerId) {
            timers_.erase(it);
            return 0;
        }
    }
    return -1;
}

void TimerManager::InsertTimerInternal(std::unique_ptr<TimerItem>& timer)
{
    WLOGFI("TimerManager::InsertTimerInternal enter");
    for (auto it = timers_.begin(); it != timers_.end(); ++it) {
        if ((*it)->nextCallTime > timer->nextCallTime) {
            timers_.insert(it, std::move(timer));
            return;
        }
    }
    timers_.push_back(std::move(timer));
    WLOGFI("TimerManager::InsertTimerInternal finish");
}

int32_t TimerManager::CalcNextDelayInternal()
{
    auto delay = MIN_DELAY;
    if (!timers_.empty()) {
        auto nowTime = GetMillisTime();
        const auto& item = *timers_.begin();
        if (nowTime >= item->nextCallTime) {
            delay = 0;
        } else {
            delay = item->nextCallTime - nowTime;
        }
    }
    return delay;
}

void TimerManager::ProcessTimersInternal()
{
    if (timers_.empty()) {
        return;
    }
    auto nowTime = GetMillisTime();
    for (;;) {
        auto it = timers_.begin();
        if (it == timers_.end()) {
            break;
        }
        if ((*it)->nextCallTime > nowTime) {
            break;
        }
        auto curTimer = std::move(*it);
        timers_.erase(it);
        if (curTimer->callback != nullptr) {
            curTimer->callback();
        }
    }
}
} // namespace Rosen
} // namespace OHOS

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

#include "platform/ohos/rs_jank_stats.h"

#include <algorithm>
#include <chrono>
#include <sstream>
#include <sys/time.h>
#include <unistd.h>

#include "hisysevent.h"
#include "rs_trace.h"

#include "common/rs_common_def.h"
#include "platform/common/rs_log.h"

namespace OHOS {
namespace Rosen {
namespace {
constexpr float VSYNC_PERIOD = 16.6f;                // 16.6ms
constexpr float S_TO_MS = 1000.f;                    // s to ms
constexpr int64_t ANIMATION_TIMEOUT = 5000;          // 5s
constexpr int64_t S_TO_NS = 1000000000;              // s to ns
constexpr int64_t VSYNC_JANK_LOG_THRESHOLED = 6;     // 6 times vsync
}

RSJankStats& RSJankStats::GetInstance()
{
    static RSJankStats instance;
    return instance;
}

void RSJankStats::SetOnVsyncStartTime(int64_t onVsyncStartTime, int64_t onVsyncStartTimeSteady,
                                      float onVsyncStartTimeSteadyFloat)
{
    std::lock_guard<std::mutex> lock(mutex_);
    rsStartTime_ = onVsyncStartTime;
    rsStartTimeSteady_ = onVsyncStartTimeSteady;
    if (IS_CALCULATE_PRECISE_HITCH_TIME) {
        rsStartTimeSteadyFloat_ = onVsyncStartTimeSteadyFloat;
    }
}

void RSJankStats::SetAccumulatedBufferCount(int accumulatedBufferCount)
{
    accumulatedBufferCount_ = accumulatedBufferCount;
}

void RSJankStats::SetStartTime(bool doDirectComposition)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!doDirectComposition) {
        rtStartTime_ = GetCurrentSystimeMs();
        rtStartTimeSteady_ = GetCurrentSteadyTimeMs();
    }
    if (isFirstSetStart_) {
        lastReportTime_ = rtStartTime_;
        lastReportTimeSteady_ = rtStartTimeSteady_;
    }
    for (auto &[animationId, jankFrames] : animateJankFrames_) {
        jankFrames.isReportEventResponse_ = jankFrames.isSetReportEventResponseTemp_;
        jankFrames.isSetReportEventResponseTemp_ = jankFrames.isSetReportEventResponse_;
        jankFrames.isSetReportEventResponse_ = false;
        jankFrames.isReportEventComplete_ = jankFrames.isSetReportEventComplete_;
        jankFrames.isSetReportEventComplete_ = false;
        jankFrames.isReportEventJankFrame_ = jankFrames.isSetReportEventJankFrame_;
        jankFrames.isSetReportEventJankFrame_ = false;
    }
    isFirstSetStart_ = false;
}

void RSJankStats::SetEndTime(bool skipJankAnimatorFrame, bool discardJankFrames, uint32_t dynamicRefreshRate,
                             bool doDirectComposition, bool isReportTaskDelayed)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (rtStartTime_ == TIMESTAMP_INITIAL || rtStartTimeSteady_ == TIMESTAMP_INITIAL ||
        rsStartTime_ == TIMESTAMP_INITIAL || rsStartTimeSteady_ == TIMESTAMP_INITIAL) {
        ROSEN_LOGE("RSJankStats::SetEndTime startTime is not initialized");
        return;
    }
    isCurrentFrameSwitchToNotDoDirectComposition_ = isLastFrameDoDirectComposition_ && !doDirectComposition;
    if (!doDirectComposition) { UpdateEndTime(); }
    if (discardJankFrames) { ClearAllAnimation(); }
    SetRSJankStats(dynamicRefreshRate);
    RecordJankFrame(dynamicRefreshRate);
    for (auto &[animationId, jankFrames] : animateJankFrames_) {
        if (jankFrames.isReportEventResponse_) {
            ReportEventResponse(jankFrames);
            jankFrames.isUpdateJankFrame_ = true;
        }
        if (jankFrames.isUpdateJankFrame_ && !jankFrames.isFirstFrame_ && !(!jankFrames.isDisplayAnimator_ &&
            (jankFrames.isReportEventComplete_ || jankFrames.isReportEventJankFrame_)) &&
            !(jankFrames.isDisplayAnimator_ && skipJankAnimatorFrame) &&
            !(!jankFrames.isDisplayAnimator_ && jankFrames.isImplicitAnimationEnd_)) {
            UpdateJankFrame(jankFrames, dynamicRefreshRate);
        }
        if (jankFrames.isReportEventComplete_) {
            ReportEventComplete(jankFrames);
        }
        if (jankFrames.isReportEventJankFrame_) {
            ReportEventJankFrame(jankFrames, isReportTaskDelayed);
            ReportEventHitchTimeRatio(jankFrames, isReportTaskDelayed);
        }
        if (jankFrames.isReportEventResponse_ && !jankFrames.isAnimationEnded_) {
            SetAnimationTraceBegin(animationId, jankFrames);
        }
        if (jankFrames.isReportEventJankFrame_) {
            RecordAnimationDynamicFrameRate(jankFrames, isReportTaskDelayed);
        }
        if (jankFrames.isReportEventComplete_ || jankFrames.isReportEventJankFrame_) {
            SetAnimationTraceEnd(jankFrames);
            jankFrames.isUpdateJankFrame_ = false;
            jankFrames.isAnimationEnded_ = true;
        }
        jankFrames.isFirstFrame_ = jankFrames.isFirstFrameTemp_;
        jankFrames.isFirstFrameTemp_ = false;
    }
    ReportEventFirstFrame();
    CheckAnimationTraceTimeout();
    isLastFrameDoDirectComposition_ = doDirectComposition;
    isFirstSetEnd_ = false;
}

void RSJankStats::UpdateEndTime()
{
    if (isFirstSetEnd_) {
        rtLastEndTime_ = GetCurrentSystimeMs();
        rtEndTime_ = rtLastEndTime_;
        rtLastEndTimeSteady_ = GetCurrentSteadyTimeMs();
        rtEndTimeSteady_ = rtLastEndTimeSteady_;
        if (IS_CALCULATE_PRECISE_HITCH_TIME) {
            rtLastEndTimeSteadyFloat_ = GetCurrentSteadyTimeMsFloat();
            rtEndTimeSteadyFloat_ = rtLastEndTimeSteadyFloat_;
        }
        return;
    }
    rtLastEndTime_ = rtEndTime_;
    rtEndTime_ = GetCurrentSystimeMs();
    rtLastEndTimeSteady_ = rtEndTimeSteady_;
    rtEndTimeSteady_ = GetCurrentSteadyTimeMs();
    if (IS_CALCULATE_PRECISE_HITCH_TIME) {
        rtLastEndTimeSteadyFloat_ = rtEndTimeSteadyFloat_;
        rtEndTimeSteadyFloat_ = GetCurrentSteadyTimeMsFloat();
    }
}

void RSJankStats::HandleDirectComposition(const JankDurationParams& rsParams, bool isReportTaskDelayed)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        rsStartTime_ = rsParams.timeStart_;
        rsStartTimeSteady_ = rsParams.timeStartSteady_;
        rtStartTime_ = rsParams.timeEnd_;
        rtStartTimeSteady_ = rsParams.timeEndSteady_;
        rtLastEndTime_ = rtEndTime_;
        rtEndTime_ = rsParams.timeEnd_;
        rtLastEndTimeSteady_ = rtEndTimeSteady_;
        rtEndTimeSteady_ = rsParams.timeEndSteady_;
        if (IS_CALCULATE_PRECISE_HITCH_TIME) {
            rsStartTimeSteadyFloat_ = rsParams.timeStartSteadyFloat_;
            rtLastEndTimeSteadyFloat_ = rtEndTimeSteadyFloat_;
            rtEndTimeSteadyFloat_ = rsParams.timeEndSteadyFloat_;
        }
    }
    SetStartTime(true);
    SetEndTime(rsParams.skipJankAnimatorFrame_, rsParams.discardJankFrames_,
               rsParams.refreshRate_, true, isReportTaskDelayed);
}

// dynamicRefreshRate is retained for future algorithm adjustment, keep it unused currently
void RSJankStats::SetRSJankStats(uint32_t /* dynamicRefreshRate */)
{
    auto frameTime = GetEffectiveFrameTime(true);
    const int64_t missedVsync = static_cast<int64_t>(frameTime / VSYNC_PERIOD);
    if (missedVsync <= 0) {
        return;
    }
    if (missedVsync >= VSYNC_JANK_LOG_THRESHOLED) {
        ROSEN_LOGW("RSJankStats::SetJankStats jank frames %{public} " PRId64 "", missedVsync);
    }
    size_t type = JANK_FRAME_INVALID;
    if (missedVsync < 6) {                                       // JANK_FRAME_6_FREQ   : (0,6)
        type = JANK_FRAME_6_FREQ;
    } else if (missedVsync < 15) {                               // JANK_FRAME_15_FREQ  : [6,15)
        type = JANK_FRAME_15_FREQ;
    } else if (missedVsync < 20) {                               // JANK_FRAME_20_FREQ  : [15,20)
        type = JANK_FRAME_20_FREQ;
    } else if (missedVsync < 36) {                               // JANK_FRAME_36_FREQ  : [20,36)
        type = JANK_FRAME_36_FREQ;
    } else if (missedVsync < 48) {                               // JANK_FRAME_48_FREQ  : [36,48)
        type = JANK_FRAME_48_FREQ;
    } else if (missedVsync < 60) {                               // JANK_FRAME_60_FREQ  : [48,60)
        type = JANK_FRAME_60_FREQ;
    } else if (missedVsync < 120) {                              // JANK_FRAME_120_FREQ : [60,120)
        type = JANK_FRAME_120_FREQ;
    } else if (missedVsync < 180) {                              // JANK_FRAME_180_FREQ : [120,180)
        type = JANK_FRAME_180_FREQ;
    } else {
        ROSEN_LOGW("RSJankStats::SetJankStats jank frames over 180");
        return;
    }
    if (rsJankStats_[type] == USHRT_MAX) {
        ROSEN_LOGW("RSJankStats::SetJankStats rsJankStats_ value oversteps USHRT_MAX");
        return;
    }

    RS_TRACE_NAME_FMT("RSJankStats::SetRSJankStats missedVsync %d frameTime %f", missedVsync, frameTime);

    if (type != JANK_FRAME_6_FREQ) {
        RS_TRACE_INT(JANK_FRAME_6F_COUNT_TRACE_NAME, missedVsync);
        lastJankFrame6FreqTimeSteady_ = rtEndTimeSteady_;
    }
    rsJankStats_[type]++;
    isNeedReportJankStats_ = true;
    if (type != JANK_FRAME_6_FREQ) {
        RS_TRACE_INT(JANK_FRAME_6F_COUNT_TRACE_NAME, 0);
    }
}

void RSJankStats::UpdateJankFrame(JankFrames& jankFrames, uint32_t dynamicRefreshRate)
{
    if (jankFrames.startTime_ == TIMESTAMP_INITIAL) {
        jankFrames.startTime_ = rsStartTime_;
    }
    if (jankFrames.startTimeSteady_ == TIMESTAMP_INITIAL) {
        jankFrames.startTimeSteady_ = rsStartTimeSteady_;
    }
    jankFrames.lastEndTimeSteady_ = jankFrames.endTimeSteady_;
    jankFrames.endTimeSteady_ = rtEndTimeSteady_;
    jankFrames.lastTotalFrames_ = jankFrames.totalFrames_;
    jankFrames.lastTotalFrameTimeSteady_ = jankFrames.totalFrameTimeSteady_;
    jankFrames.lastTotalMissedFrames_ = jankFrames.totalMissedFrames_;
    jankFrames.lastMaxFrameTimeSteady_ = jankFrames.maxFrameTimeSteady_;
    jankFrames.lastMaxSeqMissedFrames_ = jankFrames.maxSeqMissedFrames_;
    if (dynamicRefreshRate == 0) {
        dynamicRefreshRate = STANDARD_REFRESH_RATE;
    }
    const float standardFrameTime = S_TO_MS / dynamicRefreshRate;
    const bool isConsiderRsStartTime =
        jankFrames.isDisplayAnimator_ || jankFrames.isFirstFrame_ || isFirstSetEnd_;
    const float accumulatedTime = accumulatedBufferCount_ * standardFrameTime;
    const int64_t frameDuration = std::max<int64_t>(0, GetEffectiveFrameTime(isConsiderRsStartTime) - accumulatedTime);
    const int32_t missedFramesToReport = static_cast<int32_t>(frameDuration / VSYNC_PERIOD);
    jankFrames.totalFrames_++;
    jankFrames.totalFrameTimeSteady_ += frameDuration;
    jankFrames.maxFrameTimeSteady_ = std::max<int64_t>(jankFrames.maxFrameTimeSteady_, frameDuration);
    if (missedFramesToReport > 0) {
        jankFrames.totalMissedFrames_ += missedFramesToReport;
        jankFrames.seqMissedFrames_ += missedFramesToReport;
        jankFrames.maxSeqMissedFrames_ =
            std::max<int32_t>(jankFrames.maxSeqMissedFrames_, jankFrames.seqMissedFrames_);
    } else {
        jankFrames.seqMissedFrames_ = 0;
    }

    // hitch time ratio
    jankFrames.lastMaxHitchTime_ = jankFrames.maxHitchTime_;
    jankFrames.lastTotalHitchTimeSteady_ = jankFrames.totalHitchTimeSteady_;
    jankFrames.lastTotalFrameTimeSteadyForHTR_ = jankFrames.totalFrameTimeSteadyForHTR_;
    const float frameTimeForHTR = (IS_CALCULATE_PRECISE_HITCH_TIME ? GetEffectiveFrameTimeFloat(true) :
                                  static_cast<float>(GetEffectiveFrameTime(true)));
    const float frameHitchTime = std::max<float>(0.f, frameTimeForHTR - standardFrameTime);
    const bool isConsiderRsStartTimeForHTR = jankFrames.isFirstFrame_ || isFirstSetEnd_;
    const int64_t frameDurationForHTR = (isConsiderRsStartTimeForHTR ?
        (rtEndTimeSteady_ - rsStartTimeSteady_) : (rtEndTimeSteady_ - rtLastEndTimeSteady_));
    jankFrames.maxHitchTime_ = std::max<float>(jankFrames.maxHitchTime_, frameHitchTime);
    jankFrames.totalHitchTimeSteady_ += frameHitchTime;
    jankFrames.totalFrameTimeSteadyForHTR_ += frameDurationForHTR;
}

void RSJankStats::ReportJankStats()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (lastReportTime_ == TIMESTAMP_INITIAL || lastReportTimeSteady_ == TIMESTAMP_INITIAL) {
        ROSEN_LOGE("RSJankStats::ReportJankStats lastReportTime is not initialized");
        return;
    }
    int64_t reportTime = GetCurrentSystimeMs();
    int64_t reportTimeSteady = GetCurrentSteadyTimeMs();
    if (!isNeedReportJankStats_) {
        ROSEN_LOGD("RSJankStats::ReportJankStats Nothing need to report");
        lastReportTime_ = reportTime;
        lastReportTimeSteady_ = reportTimeSteady;
        lastJankFrame6FreqTimeSteady_ = TIMESTAMP_INITIAL;
        std::fill(rsJankStats_.begin(), rsJankStats_.end(), 0);
        return;
    }
    int64_t lastJankFrame6FreqTime = ((lastJankFrame6FreqTimeSteady_ == TIMESTAMP_INITIAL) ? 0 :
        (reportTime - (reportTimeSteady - lastJankFrame6FreqTimeSteady_)));
    RS_TRACE_NAME("RSJankStats::ReportJankStats receive notification: reportTime " + std::to_string(reportTime) +
                  ", lastJankFrame6FreqTime " + std::to_string(lastJankFrame6FreqTime));
    int64_t reportDuration = reportTimeSteady - lastReportTimeSteady_;
    auto reportName = "JANK_STATS_RS";
    HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::GRAPHIC, reportName,
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC, "STARTTIME", static_cast<uint64_t>(lastReportTime_),
        "DURATION", static_cast<uint64_t>(reportDuration), "JANK_STATS", rsJankStats_,
        "JANK_STATS_VER", JANK_RANGE_VERSION);
    lastReportTime_ = reportTime;
    lastReportTimeSteady_ = reportTimeSteady;
    lastJankFrame6FreqTimeSteady_ = TIMESTAMP_INITIAL;
    std::fill(rsJankStats_.begin(), rsJankStats_.end(), 0);
    isNeedReportJankStats_ = false;
}

void RSJankStats::SetReportEventResponse(const DataBaseRs& info)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RS_TRACE_NAME("RSJankStats::SetReportEventResponse receive notification: " + GetSceneDescription(info));
    int64_t setTimeSteady = GetCurrentSteadyTimeMs();
    EraseIf(animateJankFrames_, [setTimeSteady](const auto& pair) -> bool {
        return setTimeSteady - pair.second.setTimeSteady_ > ANIMATION_TIMEOUT;
    });
    EraseIf(traceIdRemainder_, [setTimeSteady](const auto& pair) -> bool {
        return setTimeSteady - pair.second.setTimeSteady_ > ANIMATION_TIMEOUT;
    });
    const auto animationId = GetAnimationId(info);
    if (animateJankFrames_.find(animationId) == animateJankFrames_.end()) {
        JankFrames jankFrames;
        jankFrames.info_ = info;
        jankFrames.isSetReportEventResponse_ = true;
        jankFrames.setTimeSteady_ = setTimeSteady;
        jankFrames.isFirstFrame_ = true;
        jankFrames.isFirstFrameTemp_ = true;
        jankFrames.traceId_ = GetTraceIdInit(info, setTimeSteady);
        jankFrames.isDisplayAnimator_ = info.isDisplayAnimator;
        animateJankFrames_.emplace(animationId, jankFrames);
    } else {
        animateJankFrames_[animationId].info_ = info;
        animateJankFrames_[animationId].isSetReportEventResponse_ = true;
        if (animateJankFrames_.at(animationId).isDisplayAnimator_ != info.isDisplayAnimator) {
            ROSEN_LOGW("RSJankStats::SetReportEventResponse isDisplayAnimator not consistent");
        }
    }
}

void RSJankStats::SetReportEventComplete(const DataBaseRs& info)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RS_TRACE_NAME("RSJankStats::SetReportEventComplete receive notification: " + GetSceneDescription(info));
    const auto animationId = GetAnimationId(info);
    if (animateJankFrames_.find(animationId) == animateJankFrames_.end()) {
        ROSEN_LOGD("RSJankStats::SetReportEventComplete Not find exited animationId");
    } else {
        animateJankFrames_[animationId].info_ = info;
        animateJankFrames_[animationId].isSetReportEventComplete_ = true;
        if (animateJankFrames_.at(animationId).isDisplayAnimator_ != info.isDisplayAnimator) {
            ROSEN_LOGW("RSJankStats::SetReportEventComplete isDisplayAnimator not consistent");
        }
        HandleImplicitAnimationEndInAdvance(animateJankFrames_[animationId], false);
    }
}

void RSJankStats::SetReportEventJankFrame(const DataBaseRs& info, bool isReportTaskDelayed)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RS_TRACE_NAME("RSJankStats::SetReportEventJankFrame receive notification: " + GetSceneDescription(info));
    const auto animationId = GetAnimationId(info);
    if (animateJankFrames_.find(animationId) == animateJankFrames_.end()) {
        ROSEN_LOGD("RSJankStats::SetReportEventJankFrame Not find exited animationId");
    } else {
        animateJankFrames_[animationId].info_ = info;
        animateJankFrames_[animationId].isSetReportEventJankFrame_ = true;
        if (animateJankFrames_.at(animationId).isDisplayAnimator_ != info.isDisplayAnimator) {
            ROSEN_LOGW("RSJankStats::SetReportEventJankFrame isDisplayAnimator not consistent");
        }
        HandleImplicitAnimationEndInAdvance(animateJankFrames_[animationId], isReportTaskDelayed);
    }
}

void RSJankStats::HandleImplicitAnimationEndInAdvance(JankFrames& jankFrames, bool isReportTaskDelayed)
{
    if (jankFrames.isDisplayAnimator_) {
        return;
    }
    if (jankFrames.isSetReportEventComplete_) {
        ReportEventComplete(jankFrames);
    }
    if (jankFrames.isSetReportEventJankFrame_) {
        ReportEventJankFrame(jankFrames, isReportTaskDelayed);
        ReportEventHitchTimeRatio(jankFrames, isReportTaskDelayed);
    }
    if (jankFrames.isSetReportEventJankFrame_) {
        RecordAnimationDynamicFrameRate(jankFrames, isReportTaskDelayed);
    }
    if (jankFrames.isSetReportEventComplete_ || jankFrames.isSetReportEventJankFrame_) {
        SetAnimationTraceEnd(jankFrames);
        jankFrames.isUpdateJankFrame_ = false;
        jankFrames.isAnimationEnded_ = true;
    }
    jankFrames.isSetReportEventComplete_ = false;
    jankFrames.isSetReportEventJankFrame_ = false;
}

void RSJankStats::SetAppFirstFrame(pid_t appPid)
{
    std::lock_guard<std::mutex> lock(mutex_);
    firstFrameAppPids_.push(appPid);
}

void RSJankStats::SetImplicitAnimationEnd(bool isImplicitAnimationEnd)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!isImplicitAnimationEnd) {
        return;
    }
    for (auto &[animationId, jankFrames] : animateJankFrames_) {
        if (jankFrames.isDisplayAnimator_) {
            continue;
        }
        jankFrames.isImplicitAnimationEnd_ = true;
    }
}

void RSJankStats::ReportEventResponse(const JankFrames& jankFrames) const
{
    auto reportName = "INTERACTION_RESPONSE_LATENCY";
    const auto &info = jankFrames.info_;
    int64_t inputTime = ConvertTimeToSystime(info.inputTime);
    int64_t beginVsyncTime = ConvertTimeToSystime(info.beginVsyncTime);
    int64_t responseLatency = rtEndTime_ - inputTime;
    RS_TRACE_NAME_FMT("RSJankStats::ReportEventResponse %s", GetSceneDescription(info).c_str());
    HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::GRAPHIC, reportName,
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "SCENE_ID", info.sceneId, "APP_PID", info.appPid,
        "VERSION_CODE", info.versionCode, "VERSION_NAME", info.versionName, "BUNDLE_NAME", info.bundleName,
        "ABILITY_NAME", info.abilityName, "PROCESS_NAME", info.processName, "PAGE_URL", info.pageUrl,
        "SOURCE_TYPE", info.sourceType, "NOTE", info.note, "INPUT_TIME", static_cast<uint64_t>(inputTime),
        "ANIMATION_START_TIME", static_cast<uint64_t>(beginVsyncTime), "RENDER_TIME", static_cast<uint64_t>(rtEndTime_),
        "RESPONSE_LATENCY", static_cast<uint64_t>(responseLatency));
}

void RSJankStats::ReportEventComplete(const JankFrames& jankFrames) const
{
    auto reportName = "INTERACTION_COMPLETED_LATENCY";
    const auto &info = jankFrames.info_;
    int64_t inputTime = ConvertTimeToSystime(info.inputTime);
    int64_t beginVsyncTime = ConvertTimeToSystime(info.beginVsyncTime);
    int64_t endVsyncTime = ConvertTimeToSystime(info.endVsyncTime);
    int64_t animationStartLatency = beginVsyncTime - inputTime;
    int64_t animationEndLatency = endVsyncTime - beginVsyncTime;
    int64_t completedLatency = GetCurrentSystimeMs() - inputTime;
    RS_TRACE_NAME_FMT("RSJankStats::ReportEventComplete %s", GetSceneDescription(info).c_str());
    HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::GRAPHIC, reportName,
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "APP_PID", info.appPid, "VERSION_CODE", info.versionCode,
        "VERSION_NAME", info.versionName, "BUNDLE_NAME", info.bundleName, "ABILITY_NAME", info.abilityName,
        "PROCESS_NAME", info.processName, "PAGE_URL", info.pageUrl, "SCENE_ID", info.sceneId,
        "SOURCE_TYPE", info.sourceType, "NOTE", info.note, "INPUT_TIME", static_cast<uint64_t>(inputTime),
        "ANIMATION_START_LATENCY", static_cast<uint64_t>(animationStartLatency), "ANIMATION_END_LATENCY",
        static_cast<uint64_t>(animationEndLatency), "E2E_LATENCY", static_cast<uint64_t>(completedLatency));
}

void RSJankStats::ReportEventJankFrame(const JankFrames& jankFrames, bool isReportTaskDelayed) const
{
    auto reportName = "INTERACTION_RENDER_JANK";
    const auto &info = jankFrames.info_;
    if (!isReportTaskDelayed) {
        if (jankFrames.totalFrames_ <= 0) {
            ROSEN_LOGD("RSJankStats::ReportEventJankFrame totalFrames is zero, nothing need to report");
            return;
        }
        float aveFrameTimeSteady = jankFrames.totalFrameTimeSteady_ / static_cast<float>(jankFrames.totalFrames_);
        RS_TRACE_NAME_FMT(
            "RSJankStats::ReportEventJankFrame maxFrameTime is %" PRId64 "ms, maxHitchTime is %" PRId64 "ms: %s",
            jankFrames.maxFrameTimeSteady_, static_cast<int64_t>(jankFrames.maxHitchTime_),
            GetSceneDescription(info).c_str());
        HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::GRAPHIC, reportName,
            OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC, "UNIQUE_ID", info.uniqueId, "SCENE_ID", info.sceneId,
            "PROCESS_NAME", info.processName, "MODULE_NAME", info.bundleName, "ABILITY_NAME", info.abilityName,
            "PAGE_URL", info.pageUrl, "TOTAL_FRAMES", jankFrames.totalFrames_, "TOTAL_MISSED_FRAMES",
            jankFrames.totalMissedFrames_, "MAX_FRAMETIME", static_cast<uint64_t>(jankFrames.maxFrameTimeSteady_),
            "AVERAGE_FRAMETIME", aveFrameTimeSteady, "MAX_SEQ_MISSED_FRAMES", jankFrames.maxSeqMissedFrames_,
            "IS_FOLD_DISP", IS_FOLD_DISP, "BUNDLE_NAME_EX", info.note, "MAX_HITCH_TIME",
            static_cast<uint64_t>(jankFrames.maxHitchTime_));
    } else {
        if (jankFrames.lastTotalFrames_ <= 0) {
            ROSEN_LOGD("RSJankStats::ReportEventJankFrame totalFrames is zero, nothing need to report");
            return;
        }
        float aveFrameTimeSteady =
            jankFrames.lastTotalFrameTimeSteady_ / static_cast<float>(jankFrames.lastTotalFrames_);
        RS_TRACE_NAME_FMT(
            "RSJankStats::ReportEventJankFrame maxFrameTime is %" PRId64 "ms, maxHitchTime is %" PRId64 "ms: %s",
            jankFrames.lastMaxFrameTimeSteady_, static_cast<int64_t>(jankFrames.lastMaxHitchTime_),
            GetSceneDescription(info).c_str());
        HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::GRAPHIC, reportName,
            OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC, "UNIQUE_ID", info.uniqueId, "SCENE_ID", info.sceneId,
            "PROCESS_NAME", info.processName, "MODULE_NAME", info.bundleName, "ABILITY_NAME", info.abilityName,
            "PAGE_URL", info.pageUrl, "TOTAL_FRAMES", jankFrames.lastTotalFrames_, "TOTAL_MISSED_FRAMES",
            jankFrames.lastTotalMissedFrames_, "MAX_FRAMETIME", static_cast<uint64_t>(
            jankFrames.lastMaxFrameTimeSteady_), "AVERAGE_FRAMETIME", aveFrameTimeSteady,
            "MAX_SEQ_MISSED_FRAMES", jankFrames.lastMaxSeqMissedFrames_, "IS_FOLD_DISP", IS_FOLD_DISP,
            "BUNDLE_NAME_EX", info.note, "MAX_HITCH_TIME", static_cast<uint64_t>(jankFrames.lastMaxHitchTime_));
    }
}

void RSJankStats::ReportEventHitchTimeRatio(const JankFrames& jankFrames, bool isReportTaskDelayed) const
{
    auto reportName = "INTERACTION_HITCH_TIME_RATIO";
    const auto &info = jankFrames.info_;
    int64_t beginVsyncTime = ConvertTimeToSystime(info.beginVsyncTime);
    if (!isReportTaskDelayed) {
        if (jankFrames.totalFrameTimeSteadyForHTR_ <= 0) {
            ROSEN_LOGD("RSJankStats::ReportEventHitchTimeRatio duration is zero, nothing need to report");
            return;
        }
        float hitchTimeRatio = jankFrames.totalHitchTimeSteady_ / (jankFrames.totalFrameTimeSteadyForHTR_ / S_TO_MS);
        RS_TRACE_NAME_FMT("RSJankStats::ReportEventHitchTimeRatio hitch time ratio is %g ms/s: %s",
                          hitchTimeRatio, GetSceneDescription(info).c_str());
        HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::GRAPHIC, reportName,
            OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC, "UNIQUE_ID", info.uniqueId, "SCENE_ID", info.sceneId,
            "PROCESS_NAME", info.processName, "MODULE_NAME", info.bundleName, "ABILITY_NAME", info.abilityName,
            "PAGE_URL", info.pageUrl, "UI_START_TIME", static_cast<uint64_t>(beginVsyncTime),
            "RS_START_TIME", static_cast<uint64_t>(jankFrames.startTime_), "DURATION",
            static_cast<uint64_t>(jankFrames.totalFrameTimeSteadyForHTR_), "HITCH_TIME",
            static_cast<uint64_t>(jankFrames.totalHitchTimeSteady_), "HITCH_TIME_RATIO", hitchTimeRatio,
            "IS_FOLD_DISP", IS_FOLD_DISP, "BUNDLE_NAME_EX", info.note);
    } else {
        if (jankFrames.lastTotalFrameTimeSteadyForHTR_ <= 0) {
            ROSEN_LOGD("RSJankStats::ReportEventHitchTimeRatio duration is zero, nothing need to report");
            return;
        }
        float hitchTimeRatio =
            jankFrames.lastTotalHitchTimeSteady_ / (jankFrames.lastTotalFrameTimeSteadyForHTR_ / S_TO_MS);
        RS_TRACE_NAME_FMT("RSJankStats::ReportEventHitchTimeRatio hitch time ratio is %g ms/s: %s",
                          hitchTimeRatio, GetSceneDescription(info).c_str());
        HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::GRAPHIC, reportName,
            OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC, "UNIQUE_ID", info.uniqueId, "SCENE_ID", info.sceneId,
            "PROCESS_NAME", info.processName, "MODULE_NAME", info.bundleName, "ABILITY_NAME", info.abilityName,
            "PAGE_URL", info.pageUrl, "UI_START_TIME", static_cast<uint64_t>(beginVsyncTime),
            "RS_START_TIME", static_cast<uint64_t>(jankFrames.startTime_), "DURATION",
            static_cast<uint64_t>(jankFrames.lastTotalFrameTimeSteadyForHTR_), "HITCH_TIME",
            static_cast<uint64_t>(jankFrames.lastTotalHitchTimeSteady_), "HITCH_TIME_RATIO", hitchTimeRatio,
            "IS_FOLD_DISP", IS_FOLD_DISP, "BUNDLE_NAME_EX", info.note);
    }
}

void RSJankStats::ReportEventFirstFrame()
{
    while (!firstFrameAppPids_.empty()) {
        pid_t appPid = firstFrameAppPids_.front();
        ReportEventFirstFrameByPid(appPid);
        firstFrameAppPids_.pop();
    }
}

void RSJankStats::ReportEventFirstFrameByPid(pid_t appPid) const
{
    RS_TRACE_NAME_FMT("RSJankStats::ReportEventFirstFrame app pid %d", appPid);
    auto reportName = "FIRST_FRAME_DRAWN";
    HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::GRAPHIC, reportName,
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "APP_PID", static_cast<int32_t>(appPid));
}

void RSJankStats::RecordJankFrame(uint32_t dynamicRefreshRate)
{
    if (dynamicRefreshRate == 0) {
        dynamicRefreshRate = STANDARD_REFRESH_RATE;
    }
    const float accumulatedTime = accumulatedBufferCount_ * S_TO_MS / dynamicRefreshRate;
    for (auto& recordStats : jankExplicitAnimatorFrameRecorder_) {
        recordStats.isRecorded_ = false;
    }
    const int64_t missedFramesByDuration = static_cast<int64_t>(
        std::max<float>(0.f, GetEffectiveFrameTime(true) - accumulatedTime) / VSYNC_PERIOD);
    if (missedFramesByDuration > 0 && explicitAnimationTotal_ > 0) {
        for (auto& recordStats : jankExplicitAnimatorFrameRecorder_) {
            RecordJankFrameSingle(missedFramesByDuration, recordStats);
        }
    }
    for (auto& recordStats : jankImplicitAnimatorFrameRecorder_) {
        recordStats.isRecorded_ = false;
    }
    const int64_t missedFramesByInterval = static_cast<int64_t>(
        std::max<float>(0.f, GetEffectiveFrameTime(isFirstSetEnd_) - accumulatedTime) / VSYNC_PERIOD);
    if (missedFramesByInterval > 0 && implicitAnimationTotal_ > 0) {
        for (auto& recordStats : jankImplicitAnimatorFrameRecorder_) {
            RecordJankFrameSingle(missedFramesByInterval, recordStats);
        }
    }
}

void RSJankStats::RecordJankFrameSingle(int64_t missedFrames, JankFrameRecordStats& recordStats)
{
    if (recordStats.isRecorded_) {
        return;
    }
    if (missedFrames >= recordStats.recordThreshold_) {
        RS_TRACE_INT(recordStats.countTraceName_, missedFrames);
        recordStats.isRecorded_ = true;
        RS_TRACE_INT(recordStats.countTraceName_, 0);
    }
}

void RSJankStats::RecordAnimationDynamicFrameRate(JankFrames& jankFrames, bool isReportTaskDelayed)
{
    if (jankFrames.isFrameRateRecorded_) {
        return;
    }
    const int32_t traceId = jankFrames.traceId_;
    if (traceId == TRACE_ID_INITIAL) {
        ROSEN_LOGE("RSJankStats::RecordAnimationDynamicFrameRate traceId not initialized");
        return;
    }
    if (!isReportTaskDelayed) {
        if (animationAsyncTraces_.find(traceId) == animationAsyncTraces_.end() || jankFrames.totalFrames_ <= 0 ||
            jankFrames.startTimeSteady_ == TIMESTAMP_INITIAL || jankFrames.endTimeSteady_ == TIMESTAMP_INITIAL ||
            jankFrames.endTimeSteady_ <= jankFrames.startTimeSteady_) {
            return;
        }
        float animationDuration = static_cast<float>(jankFrames.endTimeSteady_ - jankFrames.startTimeSteady_) / S_TO_MS;
        float animationTotalFrames = static_cast<float>(jankFrames.totalFrames_);
        float animationDynamicFrameRate = animationTotalFrames / animationDuration;
        RS_TRACE_NAME_FMT("RSJankStats::RecordAnimationDynamicFrameRate frame rate is %.2f: %s",
                          animationDynamicFrameRate, animationAsyncTraces_.at(traceId).traceName_.c_str());
    } else {
        if (animationAsyncTraces_.find(traceId) == animationAsyncTraces_.end() || jankFrames.lastTotalFrames_ <= 0 ||
            jankFrames.startTimeSteady_ == TIMESTAMP_INITIAL || jankFrames.lastEndTimeSteady_ == TIMESTAMP_INITIAL ||
            jankFrames.lastEndTimeSteady_ <= jankFrames.startTimeSteady_) {
            return;
        }
        float animationDuration =
            static_cast<float>(jankFrames.lastEndTimeSteady_ - jankFrames.startTimeSteady_) / S_TO_MS;
        float animationTotalFrames = static_cast<float>(jankFrames.lastTotalFrames_);
        float animationDynamicFrameRate = animationTotalFrames / animationDuration;
        RS_TRACE_NAME_FMT("RSJankStats::RecordAnimationDynamicFrameRate frame rate is %.2f: %s",
                          animationDynamicFrameRate, animationAsyncTraces_.at(traceId).traceName_.c_str());
    }
    jankFrames.isFrameRateRecorded_ = true;
}

void RSJankStats::SetAnimationTraceBegin(std::pair<int64_t, std::string> animationId, const JankFrames& jankFrames)
{
    const int32_t traceId = jankFrames.traceId_;
    if (traceId == TRACE_ID_INITIAL) {
        ROSEN_LOGE("RSJankStats::SetAnimationTraceBegin traceId not initialized");
        return;
    }
    if (animationAsyncTraces_.find(traceId) != animationAsyncTraces_.end()) {
        return;
    }
    const auto &info = jankFrames.info_;
    const std::string traceName = GetSceneDescription(info);
    AnimationTraceStats traceStat = {.animationId_ = animationId,
                                     .traceName_ = traceName,
                                     .traceCreateTimeSteady_ = rtEndTimeSteady_,
                                     .isDisplayAnimator_ = info.isDisplayAnimator};
    animationAsyncTraces_.emplace(traceId, traceStat);
    if (info.isDisplayAnimator) {
        explicitAnimationTotal_++;
    } else {
        implicitAnimationTotal_++;
    }
    RS_ASYNC_TRACE_BEGIN(traceName, traceId);
}

void RSJankStats::SetAnimationTraceEnd(const JankFrames& jankFrames)
{
    const int32_t traceId = jankFrames.traceId_;
    if (traceId == TRACE_ID_INITIAL) {
        ROSEN_LOGE("RSJankStats::SetAnimationTraceEnd traceId not initialized");
        return;
    }
    if (animationAsyncTraces_.find(traceId) == animationAsyncTraces_.end()) {
        return;
    }
    const bool isDisplayAnimator = animationAsyncTraces_.at(traceId).isDisplayAnimator_;
    RS_ASYNC_TRACE_END(animationAsyncTraces_.at(traceId).traceName_, traceId);
    animationAsyncTraces_.erase(traceId);
    if (isDisplayAnimator) {
        explicitAnimationTotal_--;
    } else {
        implicitAnimationTotal_--;
    }
}

void RSJankStats::CheckAnimationTraceTimeout()
{
    if (++animationTraceCheckCnt_ < ANIMATION_TRACE_CHECK_FREQ) {
        return;
    }
    EraseIf(animationAsyncTraces_, [this](const auto& pair) -> bool {
        bool needErase = rtEndTimeSteady_ - pair.second.traceCreateTimeSteady_ > ANIMATION_TIMEOUT;
        if (needErase) {
            RS_ASYNC_TRACE_END(pair.second.traceName_, pair.first);
            if (pair.second.isDisplayAnimator_) {
                explicitAnimationTotal_--;
            } else {
                implicitAnimationTotal_--;
            }
            animateJankFrames_.erase(pair.second.animationId_);
        }
        return needErase;
    });
    animationTraceCheckCnt_ = 0;
}

void RSJankStats::ClearAllAnimation()
{
    RS_TRACE_NAME("RSJankStats::ClearAllAnimation");
    EraseIf(animationAsyncTraces_, [](const auto& pair) -> bool {
        RS_ASYNC_TRACE_END(pair.second.traceName_, pair.first);
        return true;
    });
    explicitAnimationTotal_ = 0;
    implicitAnimationTotal_ = 0;
    animateJankFrames_.clear();
}

std::string RSJankStats::GetSceneDescription(const DataBaseRs& info) const
{
    std::stringstream sceneDescription;
    int64_t inputTime = ConvertTimeToSystime(info.inputTime);
    std::string animatorType = (info.isDisplayAnimator ? "EXPLICIT_ANIMATOR" : "IMPLICIT_ANIMATOR");
    sceneDescription << info.sceneId << ", " << info.bundleName << ", " << info.pageUrl
                     << ", " << inputTime << ", " << animatorType << ", uid" << info.uniqueId;
    return sceneDescription.str();
}

std::pair<int64_t, std::string> RSJankStats::GetAnimationId(const DataBaseRs& info) const
{
    std::pair<int64_t, std::string> animationId(info.uniqueId, info.sceneId);
    return animationId;
}

int32_t RSJankStats::GetTraceIdInit(const DataBaseRs& info, int64_t setTimeSteady)
{
    if (traceIdRemainder_.find(info.uniqueId) == traceIdRemainder_.end()) {
        TraceIdRemainderStats traceIdStat;
        traceIdRemainder_.emplace(info.uniqueId, traceIdStat);
    }
    if (traceIdRemainder_.at(info.uniqueId).remainder_ >= TRACE_ID_SCALE_PARAM) {
        traceIdRemainder_[info.uniqueId].remainder_ = 0;
    }
    traceIdRemainder_[info.uniqueId].setTimeSteady_ = setTimeSteady;
    int64_t mappedUniqueId = info.uniqueId * TRACE_ID_SCALE_PARAM + (traceIdRemainder_[info.uniqueId].remainder_++);
    int32_t traceId = static_cast<int32_t>(mappedUniqueId);
    return traceId;
}

int64_t RSJankStats::GetEffectiveFrameTime(bool isConsiderRsStartTime) const
{
    if (isConsiderRsStartTime) {
        return std::min<int64_t>(rtEndTimeSteady_ - rtLastEndTimeSteady_, rtEndTimeSteady_ - rsStartTimeSteady_);
    }
    if (isCurrentFrameSwitchToNotDoDirectComposition_) {
        return rtEndTimeSteady_ - rsStartTimeSteady_;
    }
    return rtEndTimeSteady_ - rtLastEndTimeSteady_;
}

float RSJankStats::GetEffectiveFrameTimeFloat(bool isConsiderRsStartTime) const
{
    if (isConsiderRsStartTime) {
        return std::min<float>(rtEndTimeSteadyFloat_ - rtLastEndTimeSteadyFloat_,
                               rtEndTimeSteadyFloat_ - rsStartTimeSteadyFloat_);
    }
    if (isCurrentFrameSwitchToNotDoDirectComposition_) {
        return rtEndTimeSteadyFloat_ - rsStartTimeSteadyFloat_;
    }
    return rtEndTimeSteadyFloat_ - rtLastEndTimeSteadyFloat_;
}

int64_t RSJankStats::ConvertTimeToSystime(int64_t time) const
{
    if (time <= 0) {
        ROSEN_LOGW("RSJankStats::ConvertTimeToSystime, time is error");
        return 0;
    }
    struct timespec ts = { 0, 0 };
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    int64_t nowTime = static_cast<int64_t>(ts.tv_sec) * S_TO_NS + static_cast<int64_t>(ts.tv_nsec);
    int64_t curSysTime = GetCurrentSystimeMs();
    int64_t sysTime = curSysTime - (nowTime - time) / MS_TO_NS;
    return sysTime;
}

int64_t RSJankStats::GetCurrentSystimeMs() const
{
    auto curTime = std::chrono::system_clock::now().time_since_epoch();
    int64_t curSysTime = std::chrono::duration_cast<std::chrono::milliseconds>(curTime).count();
    return curSysTime;
}

int64_t RSJankStats::GetCurrentSteadyTimeMs() const
{
    auto curTime = std::chrono::steady_clock::now().time_since_epoch();
    int64_t curSteadyTime = std::chrono::duration_cast<std::chrono::milliseconds>(curTime).count();
    return curSteadyTime;
}

float RSJankStats::GetCurrentSteadyTimeMsFloat() const
{
    auto curTime = std::chrono::steady_clock::now().time_since_epoch();
    int64_t curSteadyTimeUs = std::chrono::duration_cast<std::chrono::microseconds>(curTime).count();
    float curSteadyTime = curSteadyTimeUs / MS_TO_US;
    return curSteadyTime;
}
} // namespace Rosen
} // namespace OHOS

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
#undef LOG_TAG
#define LOG_TAG "CapturerInServer"

#include "capturer_in_server.h"
#include <cinttypes>
#include "securec.h"
#include "audio_errors.h"
#include "audio_utils.h"
#include "audio_log.h"
#include "audio_process_config.h"
#include "i_stream_manager.h"
#include "playback_capturer_manager.h"

namespace OHOS {
namespace AudioStandard {
namespace {
    static constexpr int32_t VOLUME_SHIFT_NUMBER = 16; // 1 >> 16 = 65536, max volume
    static const size_t CAPTURER_BUFFER_DEFAULT_NUM = 4;
    static const size_t CAPTURER_BUFFER_WAKE_UP_NUM = 100;
    static const uint32_t OVERFLOW_LOG_LOOP_COUNT = 100;
}

CapturerInServer::CapturerInServer(AudioProcessConfig processConfig, std::weak_ptr<IStreamListener> streamListener)
{
    processConfig_ = processConfig;
    streamListener_ = streamListener;
}

CapturerInServer::~CapturerInServer()
{
    if (status_ != I_STATUS_RELEASED && status_ != I_STATUS_IDLE) {
        Release();
    }
}

int32_t CapturerInServer::ConfigServerBuffer()
{
    if (audioServerBuffer_ != nullptr) {
        AUDIO_INFO_LOG("ConfigProcessBuffer: process buffer already configed!");
        return SUCCESS;
    }

    stream_->GetSpanSizePerFrame(spanSizeInFrame_);
    const size_t bufferNum = ((processConfig_.capturerInfo.sourceType == SOURCE_TYPE_WAKEUP)
        ? CAPTURER_BUFFER_WAKE_UP_NUM : CAPTURER_BUFFER_DEFAULT_NUM);
    totalSizeInFrame_ = spanSizeInFrame_ * bufferNum;
    stream_->GetByteSizePerFrame(byteSizePerFrame_);
    spanSizeInBytes_ = byteSizePerFrame_ * spanSizeInFrame_;
    AUDIO_INFO_LOG("ConfigProcessBuffer: totalSizeInFrame_: %{public}zu, spanSizeInFrame_: %{public}zu,"
        "byteSizePerFrame_: %{public}zu, spanSizeInBytes_ %{public}zu", totalSizeInFrame_, spanSizeInFrame_,
        byteSizePerFrame_, spanSizeInBytes_);
    if (totalSizeInFrame_ == 0 || spanSizeInFrame_ == 0 || totalSizeInFrame_ % spanSizeInFrame_ != 0) {
        AUDIO_ERR_LOG("ConfigProcessBuffer: ERR_INVALID_PARAM");
        return ERR_INVALID_PARAM;
    }

    int32_t ret = InitCacheBuffer(2 * spanSizeInBytes_);
    CHECK_AND_RETURN_RET_LOG(ret == SUCCESS, ret, "InitCacheBuffer failed %{public}d", ret);

    // create OHAudioBuffer in server
    audioServerBuffer_ = OHAudioBuffer::CreateFromLocal(totalSizeInFrame_, spanSizeInFrame_, byteSizePerFrame_);
    CHECK_AND_RETURN_RET_LOG(audioServerBuffer_ != nullptr, ERR_OPERATION_FAILED, "Create oh audio buffer failed");

    // we need to clear data buffer to avoid dirty data.
    memset_s(audioServerBuffer_->GetDataBase(), audioServerBuffer_->GetDataSize(), 0,
        audioServerBuffer_->GetDataSize());
    ret = InitBufferStatus();
    AUDIO_DEBUG_LOG("Clear data buffer, ret:%{public}d", ret);
    isBufferConfiged_ = true;
    isInited_ = true;
    return SUCCESS;
}

int32_t CapturerInServer::InitBufferStatus()
{
    if (audioServerBuffer_ == nullptr) {
        AUDIO_ERR_LOG("InitBufferStatus failed, null buffer.");
        return ERR_ILLEGAL_STATE;
    }

    uint32_t spanCount = audioServerBuffer_->GetSpanCount();
    AUDIO_INFO_LOG("InitBufferStatus: spanCount %{public}u", spanCount);
    for (uint32_t i = 0; i < spanCount; i++) {
        SpanInfo *spanInfo = audioServerBuffer_->GetSpanInfoByIndex(i);
        if (spanInfo == nullptr) {
            AUDIO_ERR_LOG("InitBufferStatus failed, null spaninfo");
            return ERR_ILLEGAL_STATE;
        }
        spanInfo->spanStatus = SPAN_READ_DONE;
        spanInfo->offsetInFrame = 0;

        spanInfo->readStartTime = 0;
        spanInfo->readDoneTime = 0;

        spanInfo->readStartTime = 0;
        spanInfo->readDoneTime = 0;

        spanInfo->volumeStart = 1 << VOLUME_SHIFT_NUMBER; // 65536 for initialize
        spanInfo->volumeEnd = 1 << VOLUME_SHIFT_NUMBER; // 65536 for initialize
        spanInfo->isMute = false;
    }
    return SUCCESS;
}

int32_t CapturerInServer::Init()
{
    int32_t ret = IStreamManager::GetRecorderManager().CreateCapturer(processConfig_, stream_);
    CHECK_AND_RETURN_RET_LOG(ret == SUCCESS && stream_ != nullptr, ERR_OPERATION_FAILED,
        "Construct CapturerInServer failed: %{public}d", ret);
    streamIndex_ = stream_->GetStreamIndex();
    ret = ConfigServerBuffer();
    CHECK_AND_RETURN_RET_LOG(ret == SUCCESS, ERR_OPERATION_FAILED, "ConfigServerBuffer failed: %{public}d", ret);
    stream_->RegisterStatusCallback(shared_from_this());
    stream_->RegisterReadCallback(shared_from_this());
    return SUCCESS;
}

void CapturerInServer::OnStatusUpdate(IOperation operation)
{
    AUDIO_INFO_LOG("CapturerInServer::OnStatusUpdate operation: %{public}d", operation);
    operation_ = operation;
    if (status_ == I_STATUS_RELEASED) {
        AUDIO_WARNING_LOG("Stream already released");
        return;
    }
    std::shared_ptr<IStreamListener> stateListener = streamListener_.lock();
    CHECK_AND_RETURN_LOG(stateListener != nullptr, "IStreamListener is nullptr");
    switch (operation) {
        case OPERATION_UNDERFLOW:
            underflowCount += 1;
            AUDIO_INFO_LOG("Underflow!! underflow count %{public}d", underflowCount);
            stateListener->OnOperationHandled(BUFFER_OVERFLOW, underflowCount);
            break;
        case OPERATION_STARTED:
            status_ = I_STATUS_STARTED;
            stateListener->OnOperationHandled(START_STREAM, 0);
            break;
        case OPERATION_PAUSED:
            status_ = I_STATUS_PAUSED;
            stateListener->OnOperationHandled(PAUSE_STREAM, 0);
            break;
        case OPERATION_STOPPED:
            status_ = I_STATUS_STOPPED;
            stateListener->OnOperationHandled(STOP_STREAM, 0);
            break;
        case OPERATION_FLUSHED:
            if (status_ == I_STATUS_FLUSHING_WHEN_STARTED) {
                status_ = I_STATUS_STARTED;
            } else if (status_ == I_STATUS_FLUSHING_WHEN_PAUSED) {
                status_ = I_STATUS_PAUSED;
            } else if (status_ == I_STATUS_FLUSHING_WHEN_STOPPED) {
                status_ = I_STATUS_STOPPED;
            } else {
                AUDIO_WARNING_LOG("Invalid status before flusing");
            }
            stateListener->OnOperationHandled(FLUSH_STREAM, 0);
            break;
        default:
            AUDIO_INFO_LOG("Invalid operation %{public}u", operation);
            status_ = I_STATUS_INVALID;
    }
}

BufferDesc CapturerInServer::DequeueBuffer(size_t length)
{
    return stream_->DequeueBuffer(length);
}

void CapturerInServer::ReadData(size_t length)
{
    CHECK_AND_RETURN_LOG(length >= spanSizeInBytes_,
        "Length %{public}zu is less than spanSizeInBytes %{public}zu", length, spanSizeInBytes_);
    std::shared_ptr<IStreamListener> stateListener = streamListener_.lock();
    CHECK_AND_RETURN_LOG(stateListener != nullptr, "IStreamListener is nullptr");

    uint64_t currentWriteFrame = audioServerBuffer_->GetCurWriteFrame();

    if (audioServerBuffer_->GetAvailableDataFrames() <= static_cast<int32_t>(spanSizeInFrame_)) {
        if (overFlowLogFlag_ == 0) {
            AUDIO_INFO_LOG("OverFlow!!!");
        } else if (overFlowLogFlag_ == OVERFLOW_LOG_LOOP_COUNT) {
            overFlowLogFlag_ = 0;
        }
        overFlowLogFlag_++;
        BufferDesc dstBuffer = stream_->DequeueBuffer(length);
        stream_->EnqueueBuffer(dstBuffer);
        stateListener->OnOperationHandled(UPDATE_STREAM, currentWriteFrame);
        return;
    }

    OptResult result = ringCache_->GetWritableSize();
    CHECK_AND_RETURN_LOG(result.ret == OPERATION_SUCCESS, "RingCache write invalid size %{public}zu", result.size);
    BufferDesc srcBuffer = stream_->DequeueBuffer(result.size);
    ringCache_->Enqueue({srcBuffer.buffer, srcBuffer.bufLength});
    result = ringCache_->GetReadableSize();
    if (result.ret != OPERATION_SUCCESS || result.size < spanSizeInBytes_) {
        AUDIO_INFO_LOG("RingCache size not full, return");
        stream_->EnqueueBuffer(srcBuffer);
        return;
    }

    BufferDesc dstBuffer = {nullptr, 0, 0};
    uint64_t curWritePos = audioServerBuffer_->GetCurWriteFrame();
    if (audioServerBuffer_->GetWriteBuffer(curWritePos, dstBuffer) < 0) {
        return;
    }
    if (processConfig_.capturerInfo.sourceType == SOURCE_TYPE_PLAYBACK_CAPTURE && processConfig_.innerCapMode ==
        LEGACY_MUTE_CAP) {
        dstBuffer.buffer = dischargeBuffer_.get(); // discharge valid data.
    }
    ringCache_->Dequeue({dstBuffer.buffer, dstBuffer.bufLength});

    uint64_t nextWriteFrame = currentWriteFrame + spanSizeInFrame_;
    AUDIO_DEBUG_LOG("Read data, current write frame: %{public}" PRIu64 ", next write frame: %{public}" PRIu64 "",
        currentWriteFrame, nextWriteFrame);
        audioServerBuffer_->SetCurWriteFrame(nextWriteFrame);
    audioServerBuffer_->SetHandleInfo(currentWriteFrame, ClockTime::GetCurNano());

    stream_->EnqueueBuffer(srcBuffer);
    stateListener->OnOperationHandled(UPDATE_STREAM, currentWriteFrame);
}

int32_t CapturerInServer::OnReadData(size_t length)
{
    Trace trace("CapturerInServer::OnReadData:" + std::to_string(length));
    ReadData(length);
    return SUCCESS;
}

int32_t CapturerInServer::UpdateReadIndex()
{
    AUDIO_DEBUG_LOG("audioServerBuffer_->GetAvailableDataFrames(): %{public}d, needStart: %{public}d",
        audioServerBuffer_->GetAvailableDataFrames(), needStart);
    return SUCCESS;
}

int32_t CapturerInServer::ResolveBuffer(std::shared_ptr<OHAudioBuffer> &buffer)
{
    buffer = audioServerBuffer_;
    return SUCCESS;
}

int32_t CapturerInServer::GetSessionId(uint32_t &sessionId)
{
    CHECK_AND_RETURN_RET_LOG(stream_ != nullptr, ERR_OPERATION_FAILED, "GetSessionId failed, stream_ is null");
    sessionId = streamIndex_;
    CHECK_AND_RETURN_RET_LOG(sessionId < INT32_MAX, ERR_OPERATION_FAILED, "GetSessionId failed, sessionId:%{public}d",
        sessionId);

    return SUCCESS;
}

int32_t CapturerInServer::Start()
{
    needStart = 0;
    std::unique_lock<std::mutex> lock(statusLock_);

    if (status_ != I_STATUS_IDLE && status_ != I_STATUS_PAUSED && status_ != I_STATUS_STOPPED) {
        AUDIO_ERR_LOG("CapturerInServer::Start failed, Illegal state: %{public}u", status_);
        return ERR_ILLEGAL_STATE;
    }
    status_ = I_STATUS_STARTING;
    int ret = stream_->Start();
    CHECK_AND_RETURN_RET_LOG(ret == SUCCESS, ret, "Start stream failed, reason: %{public}d", ret);
    resetTime_ = true;
    return SUCCESS;
}

int32_t CapturerInServer::Pause()
{
    std::unique_lock<std::mutex> lock(statusLock_);
    if (status_ != I_STATUS_STARTED) {
        AUDIO_ERR_LOG("CapturerInServer::Pause failed, Illegal state: %{public}u", status_);
        return ERR_ILLEGAL_STATE;
    }
    status_ = I_STATUS_PAUSING;
    int ret = stream_->Pause();
    CHECK_AND_RETURN_RET_LOG(ret == SUCCESS, ret, "Pause stream failed, reason: %{public}d", ret);
    return SUCCESS;
}

int32_t CapturerInServer::Flush()
{
    std::unique_lock<std::mutex> lock(statusLock_);
    if (status_ == I_STATUS_STARTED) {
        status_ = I_STATUS_FLUSHING_WHEN_STARTED;
    } else if (status_ == I_STATUS_PAUSED) {
        status_ = I_STATUS_FLUSHING_WHEN_PAUSED;
    } else if (status_ == I_STATUS_STOPPED) {
        status_ = I_STATUS_FLUSHING_WHEN_STOPPED;
    } else {
        AUDIO_ERR_LOG("CapturerInServer::Flush failed, Illegal state: %{public}u", status_);
        return ERR_ILLEGAL_STATE;
    }

    // Flush buffer of audio server
    uint64_t writeFrame = audioServerBuffer_->GetCurWriteFrame();
    uint64_t readFrame = audioServerBuffer_->GetCurReadFrame();

    while (readFrame < writeFrame) {
        BufferDesc bufferDesc = {nullptr, 0, 0};
        int32_t readResult = audioServerBuffer_->GetReadbuffer(readFrame, bufferDesc);
        if (readResult != 0) {
            return ERR_OPERATION_FAILED;
        }
        memset_s(bufferDesc.buffer, bufferDesc.bufLength, 0, bufferDesc.bufLength);
        readFrame += spanSizeInFrame_;
        AUDIO_INFO_LOG("On flush, write frame: %{public}" PRIu64 ", nextReadFrame: %{public}zu,"
            "readFrame: %{public}" PRIu64 "", writeFrame, spanSizeInFrame_, readFrame);
        audioServerBuffer_->SetCurReadFrame(readFrame);
    }

    int ret = stream_->Flush();
    CHECK_AND_RETURN_RET_LOG(ret == SUCCESS, ret, "Flush stream failed, reason: %{public}d", ret);
    return SUCCESS;
}

int32_t CapturerInServer::DrainAudioBuffer()
{
    return SUCCESS;
}

int32_t CapturerInServer::Stop()
{
    std::unique_lock<std::mutex> lock(statusLock_);
    if (status_ != I_STATUS_STARTED && status_ != I_STATUS_PAUSED) {
        AUDIO_ERR_LOG("CapturerInServer::Stop failed, Illegal state: %{public}u", status_);
        return ERR_ILLEGAL_STATE;
    }
    status_ = I_STATUS_STOPPING;
    int ret = stream_->Stop();
    CHECK_AND_RETURN_RET_LOG(ret == SUCCESS, ret, "Stop stream failed, reason: %{public}d", ret);
    return SUCCESS;
}

int32_t CapturerInServer::Release()
{
    {
        std::unique_lock<std::mutex> lock(statusLock_);
        if (status_ == I_STATUS_RELEASED) {
            AUDIO_INFO_LOG("Already released");
            return SUCCESS;
        }
    }
    AUDIO_INFO_LOG("Start release capturer");
    int32_t ret = IStreamManager::GetRecorderManager().ReleaseCapturer(streamIndex_);
    if (ret < 0) {
        AUDIO_ERR_LOG("Release stream failed, reason: %{public}d", ret);
        status_ = I_STATUS_INVALID;
        return ret;
    }
    status_ = I_STATUS_RELEASED;
    if (processConfig_.capturerInfo.sourceType == SOURCE_TYPE_PLAYBACK_CAPTURE) {
        AUDIO_INFO_LOG("Disable inner capturer for %{public}u", streamIndex_);
        if (processConfig_.innerCapMode == MODERN_INNER_CAP) {
            PlaybackCapturerManager::GetInstance()->RemovePlaybackCapturerFilterInfo(streamIndex_);
        } else {
            PlaybackCapturerManager::GetInstance()->SetInnerCapturerState(false);
        }
    }
    return SUCCESS;
}

int32_t CapturerInServer::UpdatePlaybackCaptureConfigInLegacy(const AudioPlaybackCaptureConfig &config)
{
    Trace trace("UpdatePlaybackCaptureConfigInLegacy");
    // Legacy mode, only usage filter works.
    AUDIO_INFO_LOG("Update config in legacy mode with %{public}zu usage", config.filterOptions.usages.size());

    std::vector<int32_t> usage;
    for (size_t i = 0; i < config.filterOptions.usages.size(); i++) {
        usage.push_back(config.filterOptions.usages[i]);
    }

    PlaybackCapturerManager::GetInstance()->SetSupportStreamUsage(usage);
    PlaybackCapturerManager::GetInstance()->SetInnerCapturerState(true);
    return SUCCESS;
}

int32_t CapturerInServer::UpdatePlaybackCaptureConfig(const AudioPlaybackCaptureConfig &config)
{
    Trace trace("UpdatePlaybackCaptureConfig:" + ProcessConfig::DumpInnerCapConfig(config));
    CHECK_AND_RETURN_RET_LOG(processConfig_.capturerInfo.sourceType == SOURCE_TYPE_PLAYBACK_CAPTURE,
        ERR_INVALID_OPERATION, "This not a inner-cap source!");

    AUDIO_INFO_LOG("Client using config: %{public}s", ProcessConfig::DumpInnerCapConfig(config).c_str());

    for (auto &usg : config.filterOptions.usages) {
        if (usg != STREAM_USAGE_VOICE_COMMUNICATION) {
            continue;
        }

        if (!PermissionUtil::VerifyPermission(CAPTURER_VOICE_DOWNLINK_PERMISSION, processConfig_.appInfo.appTokenId)) {
            AUDIO_ERR_LOG("downlink capturer permission check failed");
            return ERR_PERMISSION_DENIED;
        }
    }

    filterConfig_ = config;

    if (filterConfig_.filterOptions.usages.size() == 0) {
        std::vector<StreamUsage> defalutUsages = PlaybackCapturerManager::GetInstance()->GetDefaultUsages();
        for (size_t i = 0; i < defalutUsages.size(); i++) {
            filterConfig_.filterOptions.usages.push_back(defalutUsages[i]);
        }
        AUDIO_INFO_LOG("Reset config to %{public}s", ProcessConfig::DumpInnerCapConfig(filterConfig_).c_str());
    }

    if (processConfig_.innerCapMode != MODERN_INNER_CAP) {
        return UpdatePlaybackCaptureConfigInLegacy(filterConfig_);
    }

    // in plan: add more check and print config
    PlaybackCapturerManager::GetInstance()->SetPlaybackCapturerFilterInfo(streamIndex_, filterConfig_);
    return SUCCESS;
}

int32_t CapturerInServer::GetAudioTime(uint64_t &framePos, uint64_t &timestamp)
{
    if (status_ == I_STATUS_STOPPED) {
        AUDIO_WARNING_LOG("Current status is stopped");
        return ERR_ILLEGAL_STATE;
    }
    stream_->GetStreamFramesRead(framePos);
    stream_->GetCurrentTimeStamp(timestamp);
    if (resetTime_) {
        resetTime_ = false;
        resetTimestamp_ = timestamp;
    }
    return SUCCESS;
}

int32_t CapturerInServer::GetLatency(uint64_t &latency)
{
    return stream_->GetLatency(latency);
}

int32_t CapturerInServer::InitCacheBuffer(size_t targetSize)
{
    CHECK_AND_RETURN_RET_LOG(spanSizeInBytes_ != 0, ERR_OPERATION_FAILED, "spanSizeInByte_ invalid");

    AUDIO_INFO_LOG("old size:%{public}zu, new size:%{public}zu", cacheSizeInBytes_, targetSize);
    cacheSizeInBytes_ = targetSize;

    if (ringCache_ == nullptr) {
        ringCache_ = AudioRingCache::Create(cacheSizeInBytes_);
    } else {
        OptResult result = ringCache_->ReConfig(cacheSizeInBytes_, false); // false --> clear buffer
        if (result.ret != OPERATION_SUCCESS) {
            AUDIO_ERR_LOG("ReConfig AudioRingCache to size %{public}u failed:ret%{public}zu", result.ret, targetSize);
            return ERR_OPERATION_FAILED;
        }
    }

    if (processConfig_.capturerInfo.sourceType == SOURCE_TYPE_PLAYBACK_CAPTURE && processConfig_.innerCapMode ==
        LEGACY_MUTE_CAP) {
        dischargeBuffer_ = std::make_unique<uint8_t []>(cacheSizeInBytes_);
    }

    return SUCCESS;
}
} // namespace AudioStandard
} // namespace OHOS

/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_AV_TRANS_ENGINE_PLUGINS_OUTPUT_AUDIO_H
#define OHOS_AV_TRANS_ENGINE_PLUGINS_OUTPUT_AUDIO_H

#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <queue>

#include "av_sync_utils.h"
#include "av_trans_errno.h"
#include "av_trans_buffer.h"
#include "av_trans_constants.h"
#include "av_trans_log.h"
#include "av_trans_meta.h"
#include "av_trans_types.h"
#include "avtrans_output_plugin.h"
#include "foundation/osal/thread/mutex.h"
#include "foundation/osal/thread/scoped_lock.h"
#include "foundation/osal/thread/task.h"
#include "plugin_manager.h"
#include "plugin_types.h"
#include "plugin/convert/ffmpeg_convert.h"

namespace OHOS {
namespace DistributedHardware {

using namespace OHOS::Media;
using namespace OHOS::Media::Plugin;

using AVDataCallback = std::function<void(std::shared_ptr<Plugin::Buffer>)>;

class DaudioOutputPlugin : public AvTransOutputPlugin {
public:
    explicit DaudioOutputPlugin(std::string name);
    ~DaudioOutputPlugin();

    Status Init() override;
    Status Deinit() override;
    Status Prepare() override;
    Status Reset() override;
    Status Start() override;
    Status Stop() override;
    Status SetParameter(Tag tag, const ValueType &value) override;
    Status GetParameter(Tag tag, ValueType &value) override;
    Status PushData(const std::string &inPort, std::shared_ptr<Plugin::Buffer> buffer, int32_t offset) override;
    Status SetCallback(Callback *cb) override;
    Status SetDataCallback(AVDataCallback callback) override;

private:
    Status StartOutputQueue();
    Status ControlFrameRate(const int64_t timestamp);
    void HandleData();
    void DataQueueClear(std::queue<std::shared_ptr<Buffer>> &q);
    void RampleInit(uint32_t channels, uint32_t sampleRate, uint32_t channelLayout);
    void WriteMasterClockToMemory(const std::shared_ptr<Plugin::Buffer> &buffer);
    State GetCurrentState()
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        return state_;
    }

    void SetCurrentState(State state)
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        state_ = state;
    }
private:
    std::condition_variable dataCond_;
    std::mutex paramsMapMutex_;
    std::map<Tag, ValueType> paramsMap_;
    std::mutex dataQueueMtx_;
    std::queue<std::shared_ptr<Plugin::Buffer>> outputBuffer_;
    std::shared_ptr<OSAL::Task> sendPlayTask_;

    std::mutex stateMutex_;
    std::atomic<State> state_ = State::CREATED;
    Callback *eventcallback_ = nullptr;
    AVDataCallback datacallback_ = nullptr;
    std::shared_ptr<Ffmpeg::Resample> resample_ {nullptr};
    uint32_t smIndex_ = 0;
    std::mutex sharedMemMtx_;
    std::atomic<bool> isrunning_ = false;
    AVTransSharedMemory sharedMemory_ = AVTransSharedMemory{ 0, 0, "" };
};
} // namespace DistributedHardware
} // namespace OHOS

#endif // OHOS_AV_TRANS_ENGINE_PLUGINS_OUTPUT_AUDIO_H
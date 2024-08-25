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

#ifndef OHOS_AV_TRANS_ENGINE_PLUGINS_OUTPUT_DSOFTBUS_H
#define OHOS_AV_TRANS_ENGINE_PLUGINS_OUTPUT_DSOFTBUS_H

#include <algorithm>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <vector>

#include "av_trans_buffer.h"
#include "av_trans_errno.h"
#include "av_trans_constants.h"
#include "av_trans_log.h"
#include "av_trans_meta.h"
#include "av_trans_types.h"
#include "av_trans_utils.h"
#include "avtrans_output_plugin.h"
#include "cJSON.h"
#include "foundation/osal/thread/task.h"
#include "plugin_types.h"
#include "plugin_manager.h"
#include "softbus_channel_adapter.h"

namespace OHOS {
namespace DistributedHardware {

using namespace Media::Plugin;

using AVDataCallback = std::function<void(std::shared_ptr<Buffer>)>;

class DsoftbusOutputAudioPlugin : public AvTransOutputPlugin,
                             public ISoftbusChannelListener,
                             public std::enable_shared_from_this<DsoftbusOutputAudioPlugin> {
public:
    explicit DsoftbusOutputAudioPlugin(std::string name);
    ~DsoftbusOutputAudioPlugin();

    Status Init() override;
    Status Deinit() override;
    Status Prepare() override;
    Status Reset() override;
    Status Start() override;
    Status Stop() override;
    Status GetParameter(Tag tag, ValueType &value) override;
    Status SetParameter(Tag tag, const ValueType &value) override;
    Status PushData(const std::string &inPort, std::shared_ptr<Buffer> buffer, int32_t offset) override;
    Status SetCallback(Callback *cb) override;
    Status SetDataCallback(AVDataCallback callback) override;

    // interface from ISoftbusChannelListener
    void OnChannelEvent(const AVTransEvent &event) override;
    void OnStreamReceived(const StreamData *data, const StreamData *ext) override;

private:
    Status OpenSoftbusChannel();
    void SendDataToSoftbus(std::shared_ptr<Buffer> &buffer);
    void DataQueueClear(std::queue<std::shared_ptr<Buffer>> &queue);
    void CloseSoftbusChannel();
    void FeedChannelData();
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
    std::string ownerName_;
    std::string sessionName_;
    std::string peerDevId_;
    std::condition_variable dataCond_;
    std::mutex stateMutex_;
    std::mutex dataQueueMtx_;
    std::mutex paramMapMutex_;
    std::shared_ptr<Media::OSAL::Task> bufferPopTask_;
    std::queue<std::shared_ptr<Buffer>> dataQueue_;
    std::map<Tag, ValueType> paramsMap_;
    std::atomic<State> state_ = State::CREATED;
    Callback* eventsCb_ = nullptr;
    uint32_t sampleRate_ {0};
    uint32_t channels_ {0};
};
} // namespace DistributedHardware
} // namespace OHOS

#endif // OHOS_AV_TRANS_ENGINE_PLUGINS_OUTPUT_DSOFTBUS_H
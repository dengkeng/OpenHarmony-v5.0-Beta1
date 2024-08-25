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

#include "av_sender_engine_provider.h"

#include "av_sender_engine.h"

namespace OHOS {
namespace DistributedHardware {
#undef DH_LOG_TAG
#define DH_LOG_TAG "AVSenderEngineProvider"

AVSenderEngineProvider::AVSenderEngineProvider(const std::string ownerName) : ownerName_(ownerName)
{
    AVTRANS_LOGI("AVSenderEngineProvider ctor.");
    sessionName_ = ownerName + "_" + SENDER_CONTROL_SESSION_NAME_SUFFIX;
    if (ownerName == OWNER_NAME_D_MIC || ownerName == OWNER_NAME_D_VIRMODEM_MIC) {
        SoftbusChannelAdapter::GetInstance().CreateChannelServer(TransName2PkgName(ownerName), sessionName_);
        SoftbusChannelAdapter::GetInstance().RegisterChannelListener(sessionName_, AV_TRANS_SPECIAL_DEVICE_ID, this);
    }
}

AVSenderEngineProvider::~AVSenderEngineProvider()
{
    AVTRANS_LOGI("AVSenderEngineProvider dctor.");
    std::lock_guard<std::mutex> lock(listMutex_);
    for (auto &sender : senderEngineList_) {
        sender->Release();
    }
    if (ownerName_ == OWNER_NAME_D_MIC || ownerName_ == OWNER_NAME_D_VIRMODEM_MIC) {
        SoftbusChannelAdapter::GetInstance().RemoveChannelServer(TransName2PkgName(ownerName_), sessionName_);
        SoftbusChannelAdapter::GetInstance().UnRegisterChannelListener(sessionName_, AV_TRANS_SPECIAL_DEVICE_ID);
    }
    ownerName_ = "";
    sessionName_ = "";
    senderEngineList_.clear();
    providerCallback_ = nullptr;
}

std::shared_ptr<IAVSenderEngine> AVSenderEngineProvider::CreateAVSenderEngine(const std::string &peerDevId)
{
    AVTRANS_LOGI("CreateAVSenderEngine enter.");
    auto sender = std::make_shared<AVSenderEngine>(ownerName_, peerDevId);
    if (sender && sender->Initialize() == DH_AVT_SUCCESS) {
        {
            std::lock_guard<std::mutex> lock(listMutex_);
            senderEngineList_.push_back(sender);
        }
        return sender;
    }
    AVTRANS_LOGE("create sender failed or sender init failed.");
    return nullptr;
}

std::vector<std::shared_ptr<IAVSenderEngine>> AVSenderEngineProvider::GetAVSenderEngineList()
{
    std::lock_guard<std::mutex> lock(listMutex_);
    return senderEngineList_;
}

int32_t AVSenderEngineProvider::RegisterProviderCallback(const std::shared_ptr<IAVEngineProviderCallback> &callback)
{
    providerCallback_ = callback;
    return DH_AVT_SUCCESS;
}

void AVSenderEngineProvider::OnChannelEvent(const AVTransEvent &event)
{
    if (providerCallback_ == nullptr) {
        return;
    }
    if ((event.type == EventType::EVENT_CHANNEL_OPENED) || (event.type == EventType::EVENT_CHANNEL_CLOSED)) {
        AVTRANS_LOGI("on receiver channel event. event type:%{public}" PRId32, event.type);
        providerCallback_->OnProviderEvent(event);
    }
}

void AVSenderEngineProvider::OnStreamReceived(const StreamData *data, const StreamData *ext)
{
    (void)data;
    (void)ext;
}
} // namespace DistributedHardware
} // namespace OHOS

extern "C" __attribute__((visibility("default")))
    OHOS::DistributedHardware::IAVEngineProvider* GetAVSenderEngineProvider(const std::string ownerName)
{
    return new (std::nothrow) OHOS::DistributedHardware::AVSenderEngineProvider(ownerName);
}
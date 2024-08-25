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
#include "dsoftbus_output_audio_plugin.h"

#include "foundation/utils/constants.h"
#include "plugin/common/plugin_caps_builder.h"
#include "plugin/factory/plugin_factory.h"
#include "plugin/interface/generic_plugin.h"

namespace OHOS {
namespace DistributedHardware {

GenericPluginDef CreateDsoftbusOutputAudioPluginDef()
{
    GenericPluginDef definition;
    definition.name = "AVTransDsoftbusOutputAudioPlugin";
    definition.pkgName = "AVTransDsoftbusOutputAudioPlugin";
    definition.description = "Audio transport to dsoftbus";
    definition.rank = PLUGIN_RANK;
    definition.creator = [] (const std::string& name) -> std::shared_ptr<AvTransOutputPlugin> {
        return std::make_shared<DsoftbusOutputAudioPlugin>(name);
    };

    definition.pkgVersion = AVTRANS_OUTPUT_API_VERSION;
    definition.license = LicenseType::APACHE_V2;

    CapabilityBuilder capBuilder;
    capBuilder.SetMime(OHOS::Media::MEDIA_MIME_AUDIO_AAC);
    DiscreteCapability<uint32_t> valuesSampleRate = {8000, 11025, 12000, 16000,
        22050, 24000, 32000, 44100, 48000, 64000, 96000};
    capBuilder.SetAudioSampleRateList(valuesSampleRate);
    DiscreteCapability<AudioSampleFormat> valuesSampleFormat = {AudioSampleFormat::S16};
    capBuilder.SetAudioSampleFormatList(valuesSampleFormat);
    definition.inCaps.push_back(capBuilder.Build());
    return definition;
}

static AutoRegisterPlugin<DsoftbusOutputAudioPlugin> g_registerPluginHelper(CreateDsoftbusOutputAudioPluginDef());

DsoftbusOutputAudioPlugin::DsoftbusOutputAudioPlugin(std::string name)
    : AvTransOutputPlugin(std::move(name))
{
    AVTRANS_LOGI("ctor.");
}

DsoftbusOutputAudioPlugin::~DsoftbusOutputAudioPlugin()
{
    AVTRANS_LOGI("dtor.");
}

Status DsoftbusOutputAudioPlugin::Init()
{
    AVTRANS_LOGI("Init.");
    SetCurrentState(State::INITIALIZED);
    return Status::OK;
}

Status DsoftbusOutputAudioPlugin::Deinit()
{
    AVTRANS_LOGI("Deinit.");
    return Reset();
}

Status DsoftbusOutputAudioPlugin::Prepare()
{
    AVTRANS_LOGI("Prepare");
    if (GetCurrentState() != State::INITIALIZED) {
        AVTRANS_LOGE("The state is wrong.");
        return Status::ERROR_WRONG_STATE;
    }

    sessionName_ = ownerName_ + "_" + SENDER_DATA_SESSION_NAME_SUFFIX;
    if (!bufferPopTask_) {
        bufferPopTask_ = std::make_shared<Media::OSAL::Task>("audioBufferQueuePopThread");
        bufferPopTask_->RegisterHandler([this] { FeedChannelData(); });
    }

    ValueType channelsValue;
    TRUE_RETURN_V_MSG_E(GetParameter(Tag::AUDIO_CHANNELS, channelsValue) != Status::OK,
        Status::ERROR_UNKNOWN, "Not found AUDIO_CHANNELS");
    channels_ = static_cast<uint32_t>(Plugin::AnyCast<int>(channelsValue));

    ValueType sampleRateValue;
    TRUE_RETURN_V_MSG_E(GetParameter(Tag::AUDIO_SAMPLE_RATE, sampleRateValue) != Status::OK,
        Status::ERROR_UNKNOWN, "Not found AUDIO_SAMPLE_RATE");
    sampleRate_ = static_cast<uint32_t>(Plugin::AnyCast<int>(sampleRateValue));
    AVTRANS_LOGI("channels_ = %{public}u, sampleRate_ = %{public}u.", channels_, sampleRate_);

    SetCurrentState(State::PREPARED);
    return Status::OK;
}

Status DsoftbusOutputAudioPlugin::Reset()
{
    AVTRANS_LOGI("Reset");
    {
        std::lock_guard<std::mutex> lock(paramMapMutex_);
        paramsMap_.clear();
    }
    if (bufferPopTask_) {
        bufferPopTask_->Stop();
        bufferPopTask_.reset();
    }
    DataQueueClear(dataQueue_);
    eventsCb_ = nullptr;
    SoftbusChannelAdapter::GetInstance().RemoveChannelServer(TransName2PkgName(ownerName_), sessionName_);
    SoftbusChannelAdapter::GetInstance().UnRegisterChannelListener(sessionName_, peerDevId_);
    SetCurrentState(State::INITIALIZED);
    return Status::OK;
}

Status DsoftbusOutputAudioPlugin::Start()
{
    AVTRANS_LOGI("Dsoftbus Output Plugin start.");
    if (GetCurrentState() != State::PREPARED) {
        AVTRANS_LOGE("The state is wrong.");
        return Status::ERROR_WRONG_STATE;
    }
    Status ret = OpenSoftbusChannel();
    if (ret != Status::OK) {
        AVTRANS_LOGE("OpenSoftbusSession failed.");
        return Status::ERROR_INVALID_OPERATION;
    }
    DataQueueClear(dataQueue_);
    bufferPopTask_->Start();
    SetCurrentState(State::RUNNING);
    return Status::OK;
}

Status DsoftbusOutputAudioPlugin::Stop()
{
    AVTRANS_LOGI("Dsoftbus Output Plugin stop.");
    if (GetCurrentState() != State::RUNNING) {
        AVTRANS_LOGE("The state is wrong.");
        return Status::ERROR_WRONG_STATE;
    }
    SetCurrentState(State::PREPARED);
    bufferPopTask_->Stop();
    DataQueueClear(dataQueue_);
    CloseSoftbusChannel();
    return Status::OK;
}

Status DsoftbusOutputAudioPlugin::GetParameter(Tag tag, ValueType &value)
{
    std::lock_guard<std::mutex> lock(paramMapMutex_);
    auto res = paramsMap_.find(tag);
    if (res != paramsMap_.end()) {
        value = res->second;
        return Status::OK;
    }
    return Status::ERROR_NOT_EXISTED;
}

Status DsoftbusOutputAudioPlugin::SetParameter(Tag tag, const ValueType &value)
{
    std::lock_guard<std::mutex> lock(paramMapMutex_);
    if (tag == Tag::MEDIA_DESCRIPTION) {
        ParseChannelDescription(Plugin::AnyCast<std::string>(value), ownerName_, peerDevId_);
    }
    paramsMap_.insert(std::pair<Tag, ValueType>(tag, value));
    return Status::OK;
}

Status DsoftbusOutputAudioPlugin::SetCallback(Callback *cb)
{
    if (cb == nullptr) {
        AVTRANS_LOGE("SetCallback failed, cb is nullptr.");
        return Status::ERROR_INVALID_OPERATION;
    }
    eventsCb_ = cb;
    AVTRANS_LOGI("SetCallback success");
    return Status::OK;
}

Status DsoftbusOutputAudioPlugin::OpenSoftbusChannel()
{
    int32_t ret = SoftbusChannelAdapter::GetInstance().RegisterChannelListener(sessionName_, peerDevId_, this);
    if (ret != DH_AVT_SUCCESS) {
        AVTRANS_LOGE("Register channel listener failed ret: %{public}d.", ret);
        return Status::ERROR_INVALID_OPERATION;
    }
    std::string peerSessName = ownerName_ + "_" + RECEIVER_DATA_SESSION_NAME_SUFFIX;
    ret = SoftbusChannelAdapter::GetInstance().OpenSoftbusChannel(sessionName_, peerSessName, peerDevId_);
    if ((ret != DH_AVT_SUCCESS) && (ret != ERR_DH_AVT_SESSION_HAS_OPENED)) {
        AVTRANS_LOGE("Open softbus channel failed ret: %{public}d.", ret);
        return Status::ERROR_INVALID_OPERATION;
    }
    return Status::OK;
}

void DsoftbusOutputAudioPlugin::CloseSoftbusChannel()
{
    int32_t ret = SoftbusChannelAdapter::GetInstance().CloseSoftbusChannel(sessionName_, peerDevId_);
    if (ret != DH_AVT_SUCCESS) {
        AVTRANS_LOGE("Close softbus channle failed ret: %{public}d.", ret);
    }
}

void DsoftbusOutputAudioPlugin::OnChannelEvent(const AVTransEvent &event)
{
    AVTRANS_LOGI("OnChannelEvent enter, event type: %{public}d", event.type);
    if (eventsCb_ == nullptr) {
        AVTRANS_LOGE("OnChannelEvent failed, event callback is nullptr.");
        return;
    }
    switch (event.type) {
        case EventType::EVENT_CHANNEL_OPENED: {
            eventsCb_->OnEvent({PluginEventType::EVENT_CHANNEL_OPENED});
            break;
        }
        case EventType::EVENT_CHANNEL_OPEN_FAIL: {
            eventsCb_->OnEvent({PluginEventType::EVENT_CHANNEL_OPEN_FAIL});
            break;
        }
        case EventType::EVENT_CHANNEL_CLOSED: {
            eventsCb_->OnEvent({PluginEventType::EVENT_CHANNEL_CLOSED});
            break;
        }
        default:
            AVTRANS_LOGE("Unsupported event type.");
    }
}

void DsoftbusOutputAudioPlugin::OnStreamReceived(const StreamData *data, const StreamData *ext)
{
    (void)data;
    (void)ext;
}

Status DsoftbusOutputAudioPlugin::PushData(const std::string &inPort, std::shared_ptr<Buffer> buffer, int32_t offset)
{
    std::lock_guard<std::mutex> lock(dataQueueMtx_);
    if (buffer == nullptr || buffer->IsEmpty()) {
        AVTRANS_LOGE("Buffer is nullptr.");
        return Status::ERROR_NULL_POINTER;
    }
    while (dataQueue_.size() >= DATA_QUEUE_MAX_SIZE) {
        AVTRANS_LOGE("Data queue overflow.");
        dataQueue_.pop();
    }

    size_t bufSize = buffer->GetMemory()->GetSize();
    auto tempBuffer = std::make_shared<Plugin::Buffer>(BufferMetaType::AUDIO);
    tempBuffer->pts = buffer->pts;
    tempBuffer->AllocMemory(nullptr, bufSize);
    tempBuffer->GetMemory()->Write(buffer->GetMemory()->GetReadOnlyData(), bufSize);
    tempBuffer->UpdateBufferMeta(*(buffer->GetBufferMeta()->Clone()));
    dataQueue_.push(tempBuffer);
    dataCond_.notify_all();
    return Status::OK;
}

void DsoftbusOutputAudioPlugin::FeedChannelData()
{
    while (GetCurrentState() == State::RUNNING) {
        std::shared_ptr<Buffer> buffer;
        {
            std::unique_lock<std::mutex> lock(dataQueueMtx_);
            dataCond_.wait_for(lock, std::chrono::milliseconds(PLUGIN_TASK_WAIT_TIME),
                [this]() { return !dataQueue_.empty(); });
            if (GetCurrentState() != State::RUNNING) {
                return;
            }
            if (dataQueue_.empty()) {
                continue;
            }
            buffer = dataQueue_.front();
            dataQueue_.pop();
        }
        if (buffer == nullptr) {
            AVTRANS_LOGE("Data is null");
            continue;
        }
        SendDataToSoftbus(buffer);
    }
}

void DsoftbusOutputAudioPlugin::SendDataToSoftbus(std::shared_ptr<Buffer> &buffer)
{
    cJSON *jsonObj = cJSON_CreateObject();
    if (jsonObj == nullptr) {
        return;
    }
    auto bufferMeta = buffer->GetBufferMeta();
    BufferMetaType metaType = bufferMeta->GetType();
    cJSON_AddNumberToObject(jsonObj, AVT_DATA_META_TYPE.c_str(), static_cast<uint32_t>(metaType));
    if (metaType != BufferMetaType::AUDIO) {
        AVTRANS_LOGE("metaType is wrong");
        cJSON_Delete(jsonObj);
        return;
    }
    auto hisAMeta = std::make_shared<AVTransAudioBufferMeta>();
    if (!buffer->GetBufferMeta()->IsExist(Tag::USER_FRAME_NUMBER)) {
        hisAMeta->frameNum_ = DEFAULT_FRAME_NUMBER;
    } else {
        hisAMeta->frameNum_ = Plugin::AnyCast<uint32_t>(buffer->GetBufferMeta()->GetMeta(Tag::USER_FRAME_NUMBER));
    }
    if (!buffer->GetBufferMeta()->IsExist(Tag::USER_FRAME_PTS)) {
        hisAMeta->pts_ = DEFAULT_PTS;
    } else {
        hisAMeta->pts_ = Plugin::AnyCast<int64_t>(buffer->GetBufferMeta()->GetMeta(Tag::USER_FRAME_PTS));
    }
    cJSON_AddStringToObject(jsonObj, AVT_DATA_PARAM.c_str(), hisAMeta->MarshalAudioMeta().c_str());

    auto bufferData = buffer->GetMemory();
    char *str = cJSON_PrintUnformatted(jsonObj);
    if (str == nullptr) {
        cJSON_Delete(jsonObj);
        return;
    }
    std::string jsonStr = std::string(str);
    AVTRANS_LOGI("buffer data len = %{public}zu, ext data len = %{public}zu, ext data = %{public}s",
        bufferData->GetSize(), jsonStr.length(), jsonStr.c_str());

    StreamData data = {reinterpret_cast<char *>(const_cast<uint8_t*>(bufferData->GetReadOnlyData())),
        bufferData->GetSize()};
    StreamData ext = {const_cast<char *>(jsonStr.c_str()), jsonStr.length()};

    int32_t ret = SoftbusChannelAdapter::GetInstance().SendStreamData(sessionName_, peerDevId_, &data, &ext);
    if (ret != DH_AVT_SUCCESS) {
        AVTRANS_LOGE("Send data to softbus failed.");
    }
    cJSON_free(str);
    cJSON_Delete(jsonObj);
}

void DsoftbusOutputAudioPlugin::DataQueueClear(std::queue<std::shared_ptr<Buffer>> &queue)
{
    std::lock_guard<std::mutex> lock(dataQueueMtx_);
    std::queue<std::shared_ptr<Buffer>> empty;
    swap(empty, queue);
}

Status DsoftbusOutputAudioPlugin::SetDataCallback(AVDataCallback callback)
{
    AVTRANS_LOGI("SetDataCallback");
    return Status::OK;
}
}
}
/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#define LOG_TAG "AudioPolicyService"

#include "audio_policy_service.h"

#include <ability_manager_client.h>
#include "ipc_skeleton.h"
#include "hisysevent.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "parameter.h"

#include "audio_errors.h"
#include "audio_log.h"
#include "audio_utils.h"
#include "audio_manager_listener_stub.h"
#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "datashare_result_set.h"
#include "data_share_observer_callback.h"
#include "device_init_callback.h"
#ifdef FEATURE_DEVICE_MANAGER
#include "device_manager.h"
#include "device_manager_impl.h"
#endif
#include "uri.h"
#include "audio_spatialization_service.h"
#include "audio_converter_parser.h"
#include "audio_dialog_ability_connection.h"

#include "media_monitor_manager.h"
#include "event_bean.h"

namespace OHOS {
namespace AudioStandard {
using namespace std;

static const std::string INNER_CAPTURER_SINK_LEGACY = "InnerCapturer";
static const std::string RECEIVER_SINK_NAME = "Receiver";
static const std::string SINK_NAME_FOR_CAPTURE_SUFFIX = "_CAP";
static const std::string PIPE_PRIMARY_OUTPUT = "primary_output";
static const std::string PIPE_FAST_OUTPUT = "fast_output";
static const std::string PIPE_OFFLOAD_OUTPUT = "offload_output";
static const std::string PIPE_VOIP_OUTPUT = "voip_output";
static const std::string PIPE_PRIMARY_INPUT = "primary_input";
static const std::string PIPE_FAST_INPUT = "fast_input";
static const std::string PIPE_OFFLOAD_INPUT = "offload_input";
static const std::string PIPE_VOIP_INPUT = "voip_input";
static const std::string PIPE_A2DP_OUTPUT = "a2dp_output";
static const std::string PIPE_FAST_A2DP_OUTPUT = "fast_a2dp_output";
static const std::string PIPE_USB_ARM_OUTPUT = "usb_arm_output";
static const std::string PIPE_USB_ARM_INPUT = "usb_arm_input";
static const std::string PIPE_DISTRIBUTED_OUTPUT = "distributed_output";
static const std::string PIPE_FAST_DISTRIBUTED_OUTPUT = "fast_distributed_output";
static const std::string PIPE_DISTRIBUTED_INPUT = "distributed_input";
static const std::string PIPE_FAST_DISTRIBUTED_INPUT = "fast_distributed_input";

static const std::vector<AudioVolumeType> VOLUME_TYPE_LIST = {
    STREAM_VOICE_CALL,
    STREAM_RING,
    STREAM_MUSIC,
    STREAM_VOICE_ASSISTANT,
    STREAM_ALARM,
    STREAM_ACCESSIBILITY,
    STREAM_ULTRASONIC,
    STREAM_ALL
};

std::map<std::string, uint32_t> AudioPolicyService::formatStrToEnum = {
    {"SAMPLE_U8", SAMPLE_U8},
    {"SAMPLE_S16E", SAMPLE_S16LE},
    {"SAMPLE_S24LE", SAMPLE_S24LE},
    {"SAMPLE_S32LE", SAMPLE_S32LE},
    {"SAMPLE_F32LE", SAMPLE_F32LE},
    {"INVALID_WIDTH", INVALID_WIDTH},
};

std::map<std::string, ClassType> AudioPolicyService::classStrToEnum = {
    {PRIMARY_CLASS, TYPE_PRIMARY},
    {A2DP_CLASS, TYPE_A2DP},
    {USB_CLASS, TYPE_USB},
    {FILE_CLASS, TYPE_FILE_IO},
    {REMOTE_CLASS, TYPE_REMOTE_AUDIO},
    {INVALID_CLASS, TYPE_INVALID},
};

static const std::string SETTINGS_DATA_BASE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true";
static const std::string SETTINGS_DATA_EXT_URI = "datashare:///com.ohos.settingsdata.DataAbility";
static const std::string SETTINGS_DATA_FIELD_KEYWORD = "KEYWORD";
static const std::string SETTINGS_DATA_FIELD_VALUE = "VALUE";
static const std::string PREDICATES_STRING = "settings.general.device_name";
static const std::string EARPIECE_TYPE_NAME = "DEVICE_TYPE_EARPIECE";
static const std::string FLAG_MMAP_STRING = "AUDIO_FLAG_MMAP";
static const std::string USAGE_VOIP_STRING = "AUDIO_USAGE_VOIP";
const uint32_t PCM_8_BIT = 8;
const uint32_t PCM_16_BIT = 16;
const uint32_t PCM_24_BIT = 24;
const uint32_t PCM_32_BIT = 32;
const int32_t DEFAULT_MAX_OUTPUT_NORMAL_INSTANCES = 128;
const uint32_t BT_BUFFER_ADJUSTMENT_FACTOR = 50;
const uint32_t ABS_VOLUME_SUPPORT_RETRY_INTERVAL_IN_MICROSECONDS = 10000;
const float RENDER_FRAME_INTERVAL_IN_SECONDS = 0.02;
#ifdef BLUETOOTH_ENABLE
const uint32_t USER_NOT_SELECT_BT = 1;
const uint32_t USER_SELECT_BT = 2;
#endif
const std::string AUDIO_SERVICE_PKG = "audio_manager_service";
const int32_t UID_AUDIO = 1041;
const int ADDRESS_STR_LEN = 17;
const int START_POS = 6;
const int END_POS = 13;
const int32_t ONE_MINUTE = 60;
std::shared_ptr<DataShare::DataShareHelper> g_dataShareHelper = nullptr;
static sptr<IStandardAudioService> g_adProxy = nullptr;
#ifdef BLUETOOTH_ENABLE
static sptr<IStandardAudioService> g_btProxy = nullptr;
#endif
static int32_t startDeviceId = 1;
static int32_t startMicrophoneId = 1;
mutex g_adProxyMutex;
mutex g_dataShareHelperMutex;
#ifdef BLUETOOTH_ENABLE
const unsigned int BLUETOOTH_TIME_OUT_SECONDS = 8;
mutex g_btProxyMutex;
#endif
bool AudioPolicyService::isBtListenerRegistered = false;

static std::string GetEncryptAddr(const std::string &addr)
{
    if (addr.empty() || addr.length() != ADDRESS_STR_LEN) {
        return std::string("");
    }
    std::string tmp = "**:**:**:**:**:**";
    std::string out = addr;
    for (int i = START_POS; i <= END_POS; i++) {
        out[i] = tmp[i];
    }
    return out;
}

static string ConvertToHDIAudioFormat(AudioSampleFormat sampleFormat)
{
    switch (sampleFormat) {
        case SAMPLE_U8:
            return "u8";
        case SAMPLE_S16LE:
            return "s16le";
        case SAMPLE_S24LE:
            return "s24le";
        case SAMPLE_S32LE:
            return "s32le";
        default:
            return "";
    }
}

static uint32_t GetSampleFormatValue(AudioSampleFormat sampleFormat)
{
    switch (sampleFormat) {
        case SAMPLE_U8:
            return PCM_8_BIT;
        case SAMPLE_S16LE:
            return PCM_16_BIT;
        case SAMPLE_S24LE:
            return PCM_24_BIT;
        case SAMPLE_S32LE:
            return PCM_32_BIT;
        default:
            return PCM_16_BIT;
    }
}

static string ParseAudioFormat(string format)
{
    if (format == "AUDIO_FORMAT_PCM_16_BIT") {
        return "s16";
    } else if (format == "AUDIO_FORMAT_PCM_24_BIT") {
        return "s24";
    } else if (format == "AUDIO_FORMAT_PCM_32_BIT") {
        return "s32";
    } else {
        return "";
    }
}

static void GetUsbModuleInfo(string deviceInfo, AudioModuleInfo &moduleInfo)
{
    if (moduleInfo.role == "sink") {
        auto sinkRate_begin = deviceInfo.find("sink_rate:");
        auto sinkRate_end = deviceInfo.find_first_of(";", sinkRate_begin);
        moduleInfo.rate = deviceInfo.substr(sinkRate_begin + std::strlen("sink_rate:"),
            sinkRate_end - sinkRate_begin - std::strlen("sink_rate:"));
        auto sinkFormat_begin = deviceInfo.find("sink_format:");
        auto sinkFormat_end = deviceInfo.find_first_of(";", sinkFormat_begin);
        string format = deviceInfo.substr(sinkFormat_begin + std::strlen("sink_format:"),
            sinkFormat_end - sinkFormat_begin - std::strlen("sink_format:"));
        moduleInfo.format = ParseAudioFormat(format);
    } else {
        auto sourceRate_begin = deviceInfo.find("source_rate:");
        auto sourceRate_end = deviceInfo.find_first_of(";", sourceRate_begin);
        moduleInfo.rate = deviceInfo.substr(sourceRate_begin + std::strlen("source_rate:"),
            sourceRate_end - sourceRate_begin - std::strlen("source_rate:"));
        auto sourceFormat_begin = deviceInfo.find("source_format:");
        auto sourceFormat_end = deviceInfo.find_first_of(";", sourceFormat_begin);
        string format = deviceInfo.substr(sourceFormat_begin + std::strlen("source_format:"),
            sourceFormat_end - sourceFormat_begin - std::strlen("source_format:"));
        moduleInfo.format = ParseAudioFormat(format);
    }
}

static AudioStreamType GetStreamForVolumeMap(AudioStreamType streamType)
{
    switch (streamType) {
        case STREAM_VOICE_CALL:
        case STREAM_VOICE_MESSAGE:
        case STREAM_VOICE_COMMUNICATION:
            return STREAM_VOICE_CALL;
        case STREAM_RING:
        case STREAM_SYSTEM:
        case STREAM_NOTIFICATION:
        case STREAM_SYSTEM_ENFORCED:
        case STREAM_DTMF:
        case STREAM_VOICE_RING:
            return STREAM_RING;
        case STREAM_MUSIC:
        case STREAM_MEDIA:
        case STREAM_MOVIE:
        case STREAM_GAME:
        case STREAM_SPEECH:
        case STREAM_NAVIGATION:
            return STREAM_MUSIC;
        case STREAM_VOICE_ASSISTANT:
            return STREAM_VOICE_ASSISTANT;
        case STREAM_ALARM:
            return STREAM_ALARM;
        case STREAM_ACCESSIBILITY:
            return STREAM_ACCESSIBILITY;
        case STREAM_ULTRASONIC:
            return STREAM_ULTRASONIC;
        default:
            return STREAM_MUSIC;
    }
}

static void GetDPModuleInfo(AudioModuleInfo &moduleInfo, string deviceInfo)
{
    if (moduleInfo.role == "sink") {
        auto sinkRate_begin = deviceInfo.find("rate=");
        auto sinkRate_end = deviceInfo.find_first_of(" ", sinkRate_begin);
        moduleInfo.rate = deviceInfo.substr(sinkRate_begin + std::strlen("rate="),
            sinkRate_end - sinkRate_begin - std::strlen("rate="));

        auto sinkFormat_begin = deviceInfo.find("format=");
        auto sinkFormat_end = deviceInfo.find_first_of(" ", sinkFormat_begin);
        string format = deviceInfo.substr(sinkFormat_begin + std::strlen("format="),
            sinkFormat_end - sinkFormat_begin - std::strlen("format="));
        if (!format.empty()) moduleInfo.format = format;

        auto sinkChannel_begin = deviceInfo.find("channels=");
        auto sinkChannel_end = deviceInfo.find_first_of(" ", sinkChannel_begin);
        string channel = deviceInfo.substr(sinkChannel_begin + std::strlen("channels="),
            sinkChannel_end - sinkChannel_begin - std::strlen("channels="));
        moduleInfo.channels = channel;

        auto sinkBSize_begin = deviceInfo.find("buffer_size=");
        auto sinkBSize_end = deviceInfo.find_first_of(" ", sinkBSize_begin);
        string bufferSize = deviceInfo.substr(sinkBSize_begin + std::strlen("buffer_size="),
            sinkBSize_end - sinkBSize_begin - std::strlen("buffer_size="));
        moduleInfo.bufferSize = bufferSize;
    }
}

AudioPolicyService::~AudioPolicyService()
{
    AUDIO_DEBUG_LOG("~AudioPolicyService()");
}

bool AudioPolicyService::Init(void)
{
    AUDIO_INFO_LOG("init enter");
    serviceFlag_.reset();
    audioPolicyManager_.Init();
    audioEffectManager_.EffectManagerInit();
    audioDeviceManager_.ParseDeviceXml();
    audioPnpServer_.init();

    CHECK_AND_RETURN_RET_LOG(audioPolicyConfigParser_.LoadConfiguration(), false,
        "Audio Policy Config Load Configuration failed");
    CHECK_AND_RETURN_RET_LOG(audioPolicyConfigParser_.Parse(), false, "Audio Config Parse failed");

#ifdef FEATURE_DTMF_TONE
    std::unique_ptr<AudioToneParser> audioToneParser = make_unique<AudioToneParser>();
    CHECK_AND_RETURN_RET_LOG(audioToneParser != nullptr, false, "Failed to create AudioToneParser");
    std::string AUDIO_TONE_CONFIG_FILE = "system/etc/audio/audio_tone_dtmf_config.xml";

    if (audioToneParser->LoadConfig(toneDescriptorMap)) {
        AUDIO_ERR_LOG("Audio Tone Load Configuration failed");
        return false;
    }
#endif

    int32_t status = deviceStatusListener_->RegisterDeviceStatusListener();
    CHECK_AND_RETURN_RET_LOG(status == SUCCESS, false, "[Policy Service] Register for device status events failed");

    RegisterRemoteDevStatusCallback();

    if (policyVolumeMap_ == nullptr) {
        size_t mapSize = IPolicyProvider::GetVolumeVectorSize() * sizeof(Volume);
        AUDIO_INFO_LOG("InitSharedVolume create shared volume map with size %{public}zu", mapSize);
        policyVolumeMap_ = AudioSharedMemory::CreateFormLocal(mapSize, "PolicyVolumeMap");
        CHECK_AND_RETURN_RET_LOG(policyVolumeMap_ != nullptr && policyVolumeMap_->GetBase() != nullptr,
            false, "Get shared memory failed!");
        volumeVector_ = reinterpret_cast<Volume *>(policyVolumeMap_->GetBase());
    }
    return true;
}

const sptr<IStandardAudioService> AudioPolicyService::GetAudioServerProxy()
{
    AUDIO_DEBUG_LOG("[Policy Service] Start get audio policy service proxy.");
    lock_guard<mutex> lock(g_adProxyMutex);

    if (g_adProxy == nullptr) {
        auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        CHECK_AND_RETURN_RET_LOG(samgr != nullptr, nullptr, "[Policy Service] Get samgr failed.");

        sptr<IRemoteObject> object = samgr->GetSystemAbility(AUDIO_DISTRIBUTED_SERVICE_ID);
        CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr,
            "[Policy Service] audio service remote object is NULL.");

        g_adProxy = iface_cast<IStandardAudioService>(object);
        CHECK_AND_RETURN_RET_LOG(g_adProxy != nullptr, nullptr,
            "[Policy Service] init g_adProxy is NULL.");
    }
    const sptr<IStandardAudioService> gsp = g_adProxy;
    return gsp;
}

void AudioPolicyService::InitKVStore()
{
    audioPolicyManager_.InitKVStore();
    UpdateVolumeForLowLatency();
    AudioSpatializationService::GetAudioSpatializationService().InitSpatializationState();
}

void AudioPolicyService::UpdateVolumeForLowLatency()
{
    // update volumes for low latency streams when loading volumes from the database.
    Volume vol = {false, 1.0f, 0};
    for (auto iter = VOLUME_TYPE_LIST.begin(); iter != VOLUME_TYPE_LIST.end(); iter++) {
        int32_t volumeLevel = GetSystemVolumeLevel(*iter);
        vol.volumeFloat = GetSystemVolumeInDb(*iter, volumeLevel, currentActiveDevice_.deviceType_);
        SetSharedVolume(*iter, currentActiveDevice_.deviceType_, vol);
    }
}

bool AudioPolicyService::ConnectServiceAdapter()
{
    bool ret = audioPolicyManager_.ConnectServiceAdapter();
    CHECK_AND_RETURN_RET_LOG(ret, false, "Error in connecting to audio service adapter");

    OnServiceConnected(AudioServiceIndex::AUDIO_SERVICE_INDEX);

    return true;
}

void AudioPolicyService::Deinit(void)
{
    AUDIO_WARNING_LOG("Policy service died. closing active ports");

    std::unique_lock<std::mutex> ioHandleLock(ioHandlesMutex_);
    std::for_each(IOHandles_.begin(), IOHandles_.end(), [&](std::pair<std::string, AudioIOHandle> handle) {
        audioPolicyManager_.CloseAudioPort(handle.second);
    });

    IOHandles_.clear();
    ioHandleLock.unlock();
#ifdef ACCESSIBILITY_ENABLE
    accessibilityConfigListener_->UnsubscribeObserver();
#endif
    deviceStatusListener_->UnRegisterDeviceStatusListener();
    audioPnpServer_.StopPnpServer();

    if (isBtListenerRegistered) {
        UnregisterBluetoothListener();
    }
    volumeVector_ = nullptr;
    policyVolumeMap_ = nullptr;
    safeVolumeExit_ = true;
    if (calculateLoopSafeTime_ != nullptr && calculateLoopSafeTime_->joinable()) {
        calculateLoopSafeTime_->join();
        calculateLoopSafeTime_.reset();
        calculateLoopSafeTime_ = nullptr;
    }

    return;
}

int32_t AudioPolicyService::SetAudioSessionCallback(AudioSessionCallback *callback)
{
    return audioPolicyManager_.SetAudioSessionCallback(callback);
}

int32_t AudioPolicyService::GetMaxVolumeLevel(AudioVolumeType volumeType) const
{
    if (volumeType == STREAM_ALL) {
        volumeType = STREAM_MUSIC;
    }
    return audioPolicyManager_.GetMaxVolumeLevel(volumeType);
}

int32_t AudioPolicyService::GetMinVolumeLevel(AudioVolumeType volumeType) const
{
    if (volumeType == STREAM_ALL) {
        volumeType = STREAM_MUSIC;
    }
    return audioPolicyManager_.GetMinVolumeLevel(volumeType);
}

int32_t AudioPolicyService::SetSystemVolumeLevel(AudioStreamType streamType, int32_t volumeLevel)
{
    int32_t result;
    if (GetStreamForVolumeMap(streamType) == STREAM_MUSIC &&
        currentActiveDevice_.deviceType_ == DEVICE_TYPE_BLUETOOTH_A2DP) {
        result = SetA2dpDeviceVolume(activeBTDevice_, volumeLevel, true);
#ifdef BLUETOOTH_ENABLE
        if (result == SUCCESS) {
            // set to avrcp device
            return Bluetooth::AudioA2dpManager::SetDeviceAbsVolume(activeBTDevice_, volumeLevel);
        } else if (result == ERR_UNKNOWN) {
            return Bluetooth::AudioA2dpManager::SetDeviceAbsVolume(activeBTDevice_,
                audioPolicyManager_.GetSafeVolumeLevel());
        } else {
            AUDIO_ERR_LOG("AudioPolicyService::SetSystemVolumeLevel set abs volume failed");
        }
#endif
    }
    int32_t sVolumeLevel = volumeLevel;
    if (sVolumeLevel > audioPolicyManager_.GetSafeVolumeLevel() &&
        GetStreamForVolumeMap(streamType) == STREAM_MUSIC) {
        switch (currentActiveDevice_.deviceType_) {
            case DEVICE_TYPE_BLUETOOTH_A2DP:
            case DEVICE_TYPE_BLUETOOTH_SCO:
                sVolumeLevel = DealWithSafeVolume(volumeLevel, true);
                break;
            case DEVICE_TYPE_WIRED_HEADSET:
            case DEVICE_TYPE_WIRED_HEADPHONES:
            case DEVICE_TYPE_USB_HEADSET:
            case DEVICE_TYPE_USB_ARM_HEADSET:
                sVolumeLevel = DealWithSafeVolume(volumeLevel, false);
                break;
            default:
                AUDIO_INFO_LOG("unsupport safe volume");
                break;
        }
    }
    CHECK_AND_RETURN_RET_LOG(sVolumeLevel == volumeLevel, ERROR, "safevolume did not deal");
    result = audioPolicyManager_.SetSystemVolumeLevel(streamType, volumeLevel);
    if (result == SUCCESS && (streamType == STREAM_VOICE_CALL || streamType == STREAM_VOICE_COMMUNICATION)) {
        SetVoiceCallVolume(volumeLevel);
    }
    // todo
    Volume vol = {false, 1.0f, 0};
    vol.volumeFloat = GetSystemVolumeInDb(streamType, volumeLevel, currentActiveDevice_.deviceType_);
    SetSharedVolume(streamType, currentActiveDevice_.deviceType_, vol);

    if (result == SUCCESS) {
        SetOffloadVolume(streamType, volumeLevel);
    }
    return result;
}

void AudioPolicyService::SetVoiceCallVolume(int32_t volumeLevel)
{
    Trace trace("AudioPolicyService::SetVoiceCallVolume" + std::to_string(volumeLevel));
    // set voice volume by the interface from hdi.
    CHECK_AND_RETURN_LOG(volumeLevel != 0, "SetVoiceVolume: volume of voice_call cannot be set to 0");
    const sptr<IStandardAudioService> gsp = GetAudioServerProxy();
    CHECK_AND_RETURN_LOG(gsp != nullptr, "SetVoiceVolume: gsp null");
    float volumeDb = static_cast<float>(volumeLevel) /
        static_cast<float>(audioPolicyManager_.GetMaxVolumeLevel(STREAM_VOICE_CALL));
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    gsp->SetVoiceVolume(volumeDb);
    IPCSkeleton::SetCallingIdentity(identity);
    AUDIO_INFO_LOG("SetVoiceVolume: %{public}f", volumeDb);
}

void AudioPolicyService::SetOffloadVolume(AudioStreamType streamType, int32_t volume)
{
    if (!(streamType == STREAM_MUSIC || streamType == STREAM_SPEECH)) {
        return;
    }
    DeviceType dev = GetActiveOutputDevice();
    if (!(dev == DEVICE_TYPE_SPEAKER || dev == DEVICE_TYPE_BLUETOOTH_A2DP || dev == DEVICE_TYPE_USB_HEADSET)) {
        return;
    }
    const sptr <IStandardAudioService> gsp = GetAudioServerProxy();
    CHECK_AND_RETURN_LOG(gsp != nullptr, "gsp null");
    float volumeDb;
    if (dev == DEVICE_TYPE_BLUETOOTH_A2DP && IsAbsVolumeScene()) {
        volumeDb = 1;
    } else {
        volumeDb = GetSystemVolumeInDb(streamType, volume, currentActiveDevice_.deviceType_);
    }
    gsp->OffloadSetVolume(volumeDb);
}

AudioStreamType AudioPolicyService::OffloadStreamType()
{
    return offloadSessionID_.has_value() ? GetStreamType(*offloadSessionID_) : STREAM_MUSIC;
}

void AudioPolicyService::SetVolumeForSwitchDevice(DeviceType deviceType)
{
    Trace trace("AudioPolicyService::SetVolumeForSwitchDevice:" + std::to_string(deviceType));
    // Load volume from KvStore and set volume for each stream type
    audioPolicyManager_.SetVolumeForSwitchDevice(deviceType);

    // The volume of voice_call needs to be adjusted separately
    if (audioScene_ == AUDIO_SCENE_PHONE_CALL) {
        SetVoiceCallVolume(GetSystemVolumeLevel(STREAM_VOICE_CALL));
    }

    UpdateVolumeForLowLatency();

    if (deviceType == DEVICE_TYPE_SPEAKER || deviceType == DEVICE_TYPE_USB_HEADSET) {
        SetOffloadVolume(OffloadStreamType(), GetSystemVolumeLevel(OffloadStreamType()));
    } else if (deviceType == DEVICE_TYPE_BLUETOOTH_A2DP) {
        int32_t vol = audioPolicyManager_.IsAbsVolumeScene() ?
            audioPolicyManager_.GetMaxVolumeLevel(OffloadStreamType()) : GetSystemVolumeLevel(OffloadStreamType());
        SetOffloadVolume(OffloadStreamType(), vol);
    }
}

std::string AudioPolicyService::GetVolumeGroupType(DeviceType deviceType)
{
    std::string volumeGroupType = "";
    switch (deviceType) {
        case DEVICE_TYPE_EARPIECE:
        case DEVICE_TYPE_SPEAKER:
            volumeGroupType = "build-in";
            break;
        case DEVICE_TYPE_BLUETOOTH_A2DP:
        case DEVICE_TYPE_BLUETOOTH_SCO:
            volumeGroupType = "wireless";
            break;
        case DEVICE_TYPE_WIRED_HEADSET:
        case DEVICE_TYPE_USB_HEADSET:
        case DEVICE_TYPE_DP:
        case DEVICE_TYPE_USB_ARM_HEADSET:
            volumeGroupType = "wired";
            break;
        default:
            AUDIO_ERR_LOG("device %{public}d is not supported", deviceType);
            break;
    }
    return volumeGroupType;
}

int32_t AudioPolicyService::GetSystemVolumeLevel(AudioStreamType streamType) const
{
    {
        std::lock_guard<std::mutex> lock(a2dpDeviceMapMutex_);
        if (GetStreamForVolumeMap(streamType) == STREAM_MUSIC &&
            currentActiveDevice_.deviceType_ == DEVICE_TYPE_BLUETOOTH_A2DP) {
            auto configInfoPos = connectedA2dpDeviceMap_.find(activeBTDevice_);
            if (configInfoPos != connectedA2dpDeviceMap_.end()
                && configInfoPos->second.absVolumeSupport) {
                return configInfoPos->second.mute ? 0 : configInfoPos->second.volumeLevel;
            } else {
                AUDIO_WARNING_LOG("Get absolute volume failed for activeBTDevice :[%{public}s]",
                    GetEncryptAddr(activeBTDevice_).c_str());
            }
        }
    }
    return audioPolicyManager_.GetSystemVolumeLevel(streamType);
}

float AudioPolicyService::GetSystemVolumeDb(AudioStreamType streamType) const
{
    return audioPolicyManager_.GetSystemVolumeDb(streamType);
}

int32_t AudioPolicyService::SetLowPowerVolume(int32_t streamId, float volume) const
{
    return streamCollector_.SetLowPowerVolume(streamId, volume);
}

float AudioPolicyService::GetLowPowerVolume(int32_t streamId) const
{
    return streamCollector_.GetLowPowerVolume(streamId);
}


void AudioPolicyService::SetOffloadMode()
{
    if (!GetOffloadAvailableFromXml()) {
        AUDIO_INFO_LOG("Offload not available, skipped");
        return;
    }

    AUDIO_INFO_LOG("sessionId: %{public}d, PowerState: %{public}d, isAppBack: %{public}d",
        *offloadSessionID_, static_cast<int32_t>(currentPowerState_), currentOffloadSessionIsBackground_);

    streamCollector_.SetOffloadMode(*offloadSessionID_, static_cast<int32_t>(currentPowerState_),
        currentOffloadSessionIsBackground_);
}

void AudioPolicyService::ResetOffloadMode()
{
    AUDIO_DEBUG_LOG("Doing reset offload mode!");

    if (!CheckActiveOutputDeviceSupportOffload()) {
        AUDIO_DEBUG_LOG("Resetting offload not available on this output device! Release.");
        OffloadStreamReleaseCheck(*offloadSessionID_);
        return;
    }

    int32_t runningStreamId = streamCollector_.GetRunningStream(STREAM_MUSIC, AudioChannel::STEREO);
    if (runningStreamId == -1) {
        runningStreamId = streamCollector_.GetRunningStream(STREAM_MUSIC, AudioChannel::MONO);
    }
    if (runningStreamId == -1) {
        AUDIO_DEBUG_LOG("No running STREAM_MUSIC, wont restart offload");
        runningStreamId = streamCollector_.GetRunningStream(STREAM_SPEECH, AudioChannel::STEREO);
        if (runningStreamId == -1) {
            runningStreamId = streamCollector_.GetRunningStream(STREAM_SPEECH, AudioChannel::MONO);
        }
        if (runningStreamId == -1) {
            AUDIO_DEBUG_LOG("No running STREAM_SPEECH, wont restart offload");
            return;
        }
    }
    OffloadStreamSetCheck(runningStreamId);
}

void AudioPolicyService::OffloadStreamSetCheck(uint32_t sessionId)
{
    if (!GetOffloadAvailableFromXml()) {
        AUDIO_INFO_LOG("Offload not available, skipped for set");
        return;
    }

    if (!CheckActiveOutputDeviceSupportOffload()) {
        AUDIO_INFO_LOG("Offload not available on current output device, skipped");
        return;
    }

    AudioStreamType streamType = GetStreamType(sessionId);
    if ((streamType != STREAM_MUSIC) && (streamType != STREAM_SPEECH)) {
        AUDIO_DEBUG_LOG("StreamType not allowed get offload mode, Skipped");
        return;
    }

    int32_t channelCount = GetChannelCount(sessionId);
    if ((channelCount != AudioChannel::MONO) && (channelCount != AudioChannel::STEREO)) {
        AUDIO_DEBUG_LOG("ChannelNum not allowed get offload mode, Skipped");
        return;
    }

    int32_t offloadUID = GetUid(sessionId);
    if (offloadUID == -1) {
        AUDIO_DEBUG_LOG("offloadUID not valid, Skipped");
        return;
    }
    if (offloadUID == UID_AUDIO) {
        AUDIO_DEBUG_LOG("Skip anco_audio out of offload mode");
        return;
    }

    auto CallingUid = IPCSkeleton::GetCallingUid();
    AUDIO_INFO_LOG("sessionId[%{public}d] UID[%{public}d] CallingUid[%{public}d] StreamType[%{public}d] "
                   "Getting offload stream", sessionId, offloadUID, CallingUid, streamType);
    lock_guard<mutex> lock(offloadMutex_);

    if (!offloadSessionID_.has_value()) {
        offloadSessionID_ = sessionId;

        AUDIO_DEBUG_LOG("sessionId[%{public}d] try get offload stream", sessionId);
        SetOffloadMode();
    } else {
        if (sessionId == *(offloadSessionID_)) {
            AUDIO_DEBUG_LOG("sessionId[%{public}d] is already get offload stream", sessionId);
        } else {
            AUDIO_DEBUG_LOG("sessionId[%{public}d] no get offload, current offload sessionId[%{public}d]",
                sessionId, *(offloadSessionID_));
        }
    }

    return;
}

void AudioPolicyService::OffloadStreamReleaseCheck(uint32_t sessionId)
{
    if (!GetOffloadAvailableFromXml()) {
        AUDIO_INFO_LOG("Offload not available, skipped for release");
        return;
    }

    lock_guard<mutex> lock(offloadMutex_);

    if (((*offloadSessionID_) == sessionId) && offloadSessionID_.has_value()) {
        AUDIO_DEBUG_LOG("Doing unset offload mode!");
        streamCollector_.UnsetOffloadMode(*offloadSessionID_);
        offloadSessionID_.reset();
        AUDIO_DEBUG_LOG("sessionId[%{public}d] release offload stream", sessionId);
    } else {
        if (offloadSessionID_.has_value()) {
            AUDIO_DEBUG_LOG("sessionId[%{public}d] stopping stream not get offload, current offload [%{public}d]",
                sessionId, *offloadSessionID_);
        } else {
            AUDIO_DEBUG_LOG("sessionId[%{public}d] stopping stream not get offload, current offload stream is None",
                sessionId);
        }
    }
    return;
}

bool AudioPolicyService::CheckActiveOutputDeviceSupportOffload()
{
    DeviceType dev = GetActiveOutputDevice();
    return dev == DEVICE_TYPE_SPEAKER || (dev == DEVICE_TYPE_BLUETOOTH_A2DP && a2dpOffloadFlag_ == A2DP_OFFLOAD) ||
        dev == DEVICE_TYPE_USB_HEADSET;
}

void AudioPolicyService::SetOffloadAvailableFromXML(AudioModuleInfo &moduleInfo)
{
    if (moduleInfo.name == "Speaker") {
        for (const auto &portInfo : moduleInfo.ports) {
            if ((portInfo.adapterName == "primary") && (portInfo.offloadEnable == "1")) {
                isOffloadAvailable_ = true;
            }
        }
    }
}

bool AudioPolicyService::GetOffloadAvailableFromXml() const
{
    return isOffloadAvailable_;
}

void AudioPolicyService::HandlePowerStateChanged(PowerMgr::PowerState state)
{
    if (currentPowerState_ == state) {
        return;
    }
    currentPowerState_ = state;
    if (!CheckActiveOutputDeviceSupportOffload()) {
        return;
    }
    if (offloadSessionID_.has_value()) {
        AUDIO_DEBUG_LOG("SetOffloadMode! Offload power is state = %{public}d", state);
        SetOffloadMode();
    }
}

float AudioPolicyService::GetSingleStreamVolume(int32_t streamId) const
{
    return streamCollector_.GetSingleStreamVolume(streamId);
}

int32_t AudioPolicyService::SetStreamMute(AudioStreamType streamType, bool mute)
{
    int32_t result = SUCCESS;
    if (GetStreamForVolumeMap(streamType) == STREAM_MUSIC &&
        currentActiveDevice_.deviceType_ == DEVICE_TYPE_BLUETOOTH_A2DP) {
        std::lock_guard<std::mutex> lock(a2dpDeviceMapMutex_);
        auto configInfoPos = connectedA2dpDeviceMap_.find(activeBTDevice_);
        if (configInfoPos == connectedA2dpDeviceMap_.end() || !configInfoPos->second.absVolumeSupport) {
            AUDIO_WARNING_LOG("Set failed for macAddress:[%{public}s]", GetEncryptAddr(activeBTDevice_).c_str());
        } else {
            configInfoPos->second.mute = mute;
#ifdef BLUETOOTH_ENABLE
            // set to avrcp device
            if (mute) {
                return Bluetooth::AudioA2dpManager::SetDeviceAbsVolume(activeBTDevice_, 0);
            } else {
                return Bluetooth::AudioA2dpManager::SetDeviceAbsVolume(activeBTDevice_,
                    configInfoPos->second.volumeLevel);
            }
#endif
        }
    }
    result = audioPolicyManager_.SetStreamMute(streamType, mute);

    Volume vol = {false, 1.0f, 0};
    vol.isMute = mute;
    vol.volumeInt = GetSystemVolumeLevel(streamType);
    vol.volumeFloat = GetSystemVolumeInDb(streamType, vol.volumeInt, currentActiveDevice_.deviceType_);
    SetSharedVolume(streamType, currentActiveDevice_.deviceType_, vol);
    return result;
}

int32_t AudioPolicyService::SetSourceOutputStreamMute(int32_t uid, bool setMute) const
{
    int32_t status = audioPolicyManager_.SetSourceOutputStreamMute(uid, setMute);
    if (status > 0) {
        streamCollector_.UpdateCapturerInfoMuteStatus(uid, setMute);
    }
    return status;
}


bool AudioPolicyService::GetStreamMute(AudioStreamType streamType) const
{
    if (GetStreamForVolumeMap(streamType) == STREAM_MUSIC &&
        currentActiveDevice_.deviceType_ == DEVICE_TYPE_BLUETOOTH_A2DP) {
        std::lock_guard<std::mutex> lock(a2dpDeviceMapMutex_);
        auto configInfoPos = connectedA2dpDeviceMap_.find(activeBTDevice_);
        if (configInfoPos == connectedA2dpDeviceMap_.end() || !configInfoPos->second.absVolumeSupport) {
            AUDIO_WARNING_LOG("Get failed for macAddress:[%{public}s]", GetEncryptAddr(activeBTDevice_).c_str());
        } else {
            return configInfoPos->second.mute;
        }
    }
    return audioPolicyManager_.GetStreamMute(streamType);
}

inline std::string PrintSinkInput(SinkInput sinkInput)
{
    std::stringstream value;
    value << "streamId:[" << sinkInput.streamId << "] ";
    value << "streamType:[" << sinkInput.streamType << "] ";
    value << "uid:[" << sinkInput.uid << "] ";
    value << "pid:[" << sinkInput.pid << "] ";
    value << "statusMark:[" << sinkInput.statusMark << "] ";
    value << "sinkName:[" << sinkInput.sinkName << "] ";
    value << "startTime:[" << sinkInput.startTime << "]";
    return value.str();
}

inline std::string PrintSourceOutput(SourceOutput sourceOutput)
{
    std::stringstream value;
    value << "streamId:[" << sourceOutput.streamId << "] ";
    value << "streamType:[" << sourceOutput.streamType << "] ";
    value << "uid:[" << sourceOutput.uid << "] ";
    value << "pid:[" << sourceOutput.pid << "] ";
    value << "statusMark:[" << sourceOutput.statusMark << "] ";
    value << "deviceSourceId:[" << sourceOutput.deviceSourceId << "] ";
    value << "startTime:[" << sourceOutput.startTime << "]";
    return value.str();
}

inline std::string GetRemoteModuleName(std::string networkId, DeviceRole role)
{
    return networkId + (role == DeviceRole::OUTPUT_DEVICE ? "_out" : "_in");
}

std::string AudioPolicyService::GetSelectedDeviceInfo(int32_t uid, int32_t pid, AudioStreamType streamType)
{
    (void)streamType;

    std::lock_guard<std::mutex> lock(routerMapMutex_);
    if (!routerMap_.count(uid)) {
        AUDIO_INFO_LOG("no such uid[%{public}d]", uid);
        return "";
    }
    std::string selectedDevice = "";
    if (routerMap_[uid].second == pid) {
        selectedDevice = routerMap_[uid].first;
    } else if (routerMap_[uid].second == G_UNKNOWN_PID) {
        routerMap_[uid].second = pid;
        selectedDevice = routerMap_[uid].first;
    } else {
        AUDIO_INFO_LOG("uid[%{public}d] changed pid, get local as defalut", uid);
        routerMap_.erase(uid);
        selectedDevice = LOCAL_NETWORK_ID;
    }

    if (LOCAL_NETWORK_ID == selectedDevice) {
        AUDIO_INFO_LOG("uid[%{public}d]-->local.", uid);
        return "";
    }
    // check if connected.
    bool isConnected = false;
    for (auto device : connectedDevices_) {
        if (GetRemoteModuleName(device->networkId_, device->deviceRole_) == selectedDevice) {
            isConnected = true;
            break;
        }
    }

    if (isConnected) {
        AUDIO_INFO_LOG("result[%{public}s]", selectedDevice.c_str());
        return selectedDevice;
    } else {
        routerMap_.erase(uid);
        AUDIO_INFO_LOG("device already disconnected.");
        return "";
    }
}

void AudioPolicyService::NotifyRemoteRenderState(std::string networkId, std::string condition, std::string value)
{
    AUDIO_INFO_LOG("device<%{public}s> condition:%{public}s value:%{public}s",
        networkId.c_str(), condition.c_str(), value.c_str());

    vector<SinkInput> sinkInputs = audioPolicyManager_.GetAllSinkInputs();
    vector<SinkInput> targetSinkInputs = {};
    for (auto sinkInput : sinkInputs) {
        if (sinkInput.sinkName == networkId) {
            targetSinkInputs.push_back(sinkInput);
        }
    }
    AUDIO_DEBUG_LOG("move [%{public}zu] of all [%{public}zu]sink-inputs to local.",
        targetSinkInputs.size(), sinkInputs.size());
    sptr<AudioDeviceDescriptor> localDevice = new(std::nothrow) AudioDeviceDescriptor();
    CHECK_AND_RETURN_LOG(localDevice != nullptr, "Device error: null device.");
    localDevice->networkId_ = LOCAL_NETWORK_ID;
    localDevice->deviceRole_ = DeviceRole::OUTPUT_DEVICE;
    localDevice->deviceType_ = DeviceType::DEVICE_TYPE_SPEAKER;

    int32_t ret;
    if (localDevice->deviceType_ != currentActiveDevice_.deviceType_) {
        AUDIO_WARNING_LOG("device[%{public}d] not active, use device[%{public}d] instead.",
            static_cast<int32_t>(localDevice->deviceType_), static_cast<int32_t>(currentActiveDevice_.deviceType_));
        ret = MoveToLocalOutputDevice(targetSinkInputs, new AudioDeviceDescriptor(currentActiveDevice_));
    } else {
        ret = MoveToLocalOutputDevice(targetSinkInputs, localDevice);
    }
    CHECK_AND_RETURN_LOG((ret == SUCCESS), "MoveToLocalOutputDevice failed!");

    // Suspend device, notify audio stream manager that device has been changed.
    ret = audioPolicyManager_.SuspendAudioDevice(networkId, true);
    CHECK_AND_RETURN_LOG((ret == SUCCESS), "SuspendAudioDevice failed!");

    std::vector<sptr<AudioDeviceDescriptor>> desc = {};
    desc.push_back(localDevice);
    UpdateTrackerDeviceChange(desc);
    OnPreferredOutputDeviceUpdated(currentActiveDevice_);
    AUDIO_DEBUG_LOG("Success");
}

bool AudioPolicyService::IsDeviceConnected(sptr<AudioDeviceDescriptor> &audioDeviceDescriptors) const
{
    size_t connectedDevicesNum = connectedDevices_.size();
    for (size_t i = 0; i < connectedDevicesNum; i++) {
        if (connectedDevices_[i] != nullptr) {
            if (connectedDevices_[i]->deviceRole_ == audioDeviceDescriptors->deviceRole_
                && connectedDevices_[i]->deviceType_ == audioDeviceDescriptors->deviceType_
                && connectedDevices_[i]->interruptGroupId_ == audioDeviceDescriptors->interruptGroupId_
                && connectedDevices_[i]->volumeGroupId_ == audioDeviceDescriptors->volumeGroupId_
                && connectedDevices_[i]->networkId_ == audioDeviceDescriptors->networkId_
                && connectedDevices_[i]->macAddress_ == audioDeviceDescriptors->macAddress_) {
                return true;
            }
        }
    }
    return false;
}

int32_t AudioPolicyService::DeviceParamsCheck(DeviceRole targetRole,
    std::vector<sptr<AudioDeviceDescriptor>> &audioDeviceDescriptors) const
{
    size_t targetSize = audioDeviceDescriptors.size();
    CHECK_AND_RETURN_RET_LOG(targetSize == 1, ERR_INVALID_OPERATION,
        "Device error: size[%{public}zu]", targetSize);

    bool isDeviceTypeCorrect = false;
    if (targetRole == DeviceRole::OUTPUT_DEVICE) {
        isDeviceTypeCorrect = IsOutputDevice(audioDeviceDescriptors[0]->deviceType_) &&
            IsDeviceConnected(audioDeviceDescriptors[0]);
    } else if (targetRole == DeviceRole::INPUT_DEVICE) {
        isDeviceTypeCorrect = IsInputDevice(audioDeviceDescriptors[0]->deviceType_) &&
            IsDeviceConnected(audioDeviceDescriptors[0]);
    }

    CHECK_AND_RETURN_RET_LOG(audioDeviceDescriptors[0]->deviceRole_ == targetRole && isDeviceTypeCorrect,
        ERR_INVALID_OPERATION, "Device error: size[%{public}zu] deviceRole[%{public}d] isDeviceCorrect[%{public}d]",
        targetSize, static_cast<int32_t>(audioDeviceDescriptors[0]->deviceRole_), isDeviceTypeCorrect);
    return SUCCESS;
}

void AudioPolicyService::NotifyUserSelectionEventToBt(sptr<AudioDeviceDescriptor> audioDeviceDescriptor)
{
    Trace trace("AudioPolicyService::NotifyUserSelectionEventToBt");
    if (audioDeviceDescriptor == nullptr) {
        return;
    }
#ifdef BLUETOOTH_ENABLE
    if (currentActiveDevice_.deviceType_ == DEVICE_TYPE_BLUETOOTH_SCO &&
        audioDeviceDescriptor->deviceType_ != DEVICE_TYPE_BLUETOOTH_SCO) {
        Bluetooth::SendUserSelectionEvent(DEVICE_TYPE_BLUETOOTH_SCO,
            currentActiveDevice_.macAddress_, USER_NOT_SELECT_BT);
        Bluetooth::AudioHfpManager::DisconnectSco();
    }
    if (currentActiveDevice_.deviceType_ != DEVICE_TYPE_BLUETOOTH_SCO &&
        audioDeviceDescriptor->deviceType_ == DEVICE_TYPE_BLUETOOTH_SCO) {
        Bluetooth::SendUserSelectionEvent(DEVICE_TYPE_BLUETOOTH_SCO,
            audioDeviceDescriptor->macAddress_, USER_SELECT_BT);
    }
    if (currentActiveDevice_.deviceType_ == DEVICE_TYPE_BLUETOOTH_A2DP &&
        audioDeviceDescriptor->deviceType_ != DEVICE_TYPE_BLUETOOTH_A2DP) {
        Bluetooth::SendUserSelectionEvent(DEVICE_TYPE_BLUETOOTH_A2DP,
            currentActiveDevice_.macAddress_, USER_NOT_SELECT_BT);
    }
    if (currentActiveDevice_.deviceType_ != DEVICE_TYPE_BLUETOOTH_A2DP &&
        audioDeviceDescriptor->deviceType_ == DEVICE_TYPE_BLUETOOTH_A2DP) {
        Bluetooth::SendUserSelectionEvent(DEVICE_TYPE_BLUETOOTH_A2DP,
            audioDeviceDescriptor->macAddress_, USER_SELECT_BT);
    }
#endif
}

int32_t AudioPolicyService::SelectOutputDevice(sptr<AudioRendererFilter> audioRendererFilter,
    std::vector<sptr<AudioDeviceDescriptor>> selectedDesc)
{
    Trace trace("AudioPolicyService::SelectOutputDevice");
    AUDIO_INFO_LOG("Start for uid[%{public}d] type[%{public}d] mac[%{public}s] streamUsage[%{public}d]",
        audioRendererFilter->uid, selectedDesc[0]->deviceType_, GetEncryptAddr(selectedDesc[0]->macAddress_).c_str(),
        audioRendererFilter->rendererInfo.streamUsage);
    // check size == 1 && output device
    int32_t res = DeviceParamsCheck(DeviceRole::OUTPUT_DEVICE, selectedDesc);
    CHECK_AND_RETURN_RET_LOG(res == SUCCESS, res, "DeviceParamsCheck no success");
    if (audioRendererFilter->rendererInfo.rendererFlags == STREAM_FLAG_FAST) {
        return SelectFastOutputDevice(audioRendererFilter, selectedDesc[0]);
    }
    if (selectedDesc[0]->deviceType_ == DEVICE_TYPE_BLUETOOTH_A2DP ||
        selectedDesc[0]->deviceType_ == DEVICE_TYPE_BLUETOOTH_SCO) {
        selectedDesc[0]->isEnable_ = true;
        audioDeviceManager_.UpdateDevicesListInfo(selectedDesc[0], ENABLE_UPDATE);
    }
    if (selectedDesc[0]->deviceType_ == DEVICE_TYPE_BLUETOOTH_SCO) {
        ClearScoDeviceSuspendState(selectedDesc[0]->macAddress_);
    }
    StreamUsage strUsage = audioRendererFilter->rendererInfo.streamUsage;
    if (strUsage == STREAM_USAGE_VOICE_COMMUNICATION || strUsage == STREAM_USAGE_VOICE_MODEM_COMMUNICATION ||
        strUsage == STREAM_USAGE_VIDEO_COMMUNICATION) {
        audioStateManager_.SetPerferredCallRenderDevice(selectedDesc[0]);
    } else {
        audioStateManager_.SetPerferredMediaRenderDevice(selectedDesc[0]);
    }
    NotifyUserSelectionEventToBt(selectedDesc[0]);
    std::string networkId = selectedDesc[0]->networkId_;
    DeviceType deviceType = selectedDesc[0]->deviceType_;
    FetchDevice(true, AudioStreamDeviceChangeReason::OVERRODE);
    FetchDevice(false);
    if ((deviceType != DEVICE_TYPE_BLUETOOTH_A2DP) || (networkId != LOCAL_NETWORK_ID)) {
        UpdateOffloadWhenActiveDeviceSwitchFromA2dp();
    } else {
        UpdateA2dpOffloadFlagForAllStream(deviceType);
    }
    OnPreferredOutputDeviceUpdated(currentActiveDevice_);
    return SUCCESS;
}

int32_t AudioPolicyService::SelectFastOutputDevice(sptr<AudioRendererFilter> audioRendererFilter,
    sptr<AudioDeviceDescriptor> deviceDescriptor)
{
    AUDIO_INFO_LOG("Start for uid[%{public}d] device[%{public}s]", audioRendererFilter->uid,
        deviceDescriptor->networkId_.c_str());
    // note: check if stream is already running
    // if is running, call moveProcessToEndpoint.

    // otherwises, keep router info in the map
    std::lock_guard<std::mutex> lock(routerMapMutex_);
    fastRouterMap_[audioRendererFilter->uid] = std::make_pair(deviceDescriptor->networkId_, OUTPUT_DEVICE);
    return SUCCESS;
}

std::vector<SinkInput> AudioPolicyService::FilterSinkInputs(int32_t sessionId)
{
    // find sink-input id with audioRendererFilter
    std::vector<SinkInput> targetSinkInputs = {};
    std::vector<SinkInput> sinkInputs = audioPolicyManager_.GetAllSinkInputs();

    for (size_t i = 0; i < sinkInputs.size(); i++) {
        CHECK_AND_CONTINUE_LOG(sinkInputs[i].uid != dAudioClientUid,
            "Find sink-input with daudio[%{public}d]", sinkInputs[i].pid);
        CHECK_AND_CONTINUE_LOG(sinkInputs[i].streamType != STREAM_DEFAULT,
            "Sink-input[%{public}zu] of effect sink, don't move", i);
        AUDIO_DEBUG_LOG("sinkinput[%{public}zu]:%{public}s", i, PrintSinkInput(sinkInputs[i]).c_str());
        if (sessionId == sinkInputs[i].streamId) {
            targetSinkInputs.push_back(sinkInputs[i]);
        }
    }
    return targetSinkInputs;
}

std::vector<SourceOutput> AudioPolicyService::FilterSourceOutputs(int32_t sessionId)
{
    std::vector<SourceOutput> targetSourceOutputs = {};
    std::vector<SourceOutput> sourceOutputs = audioPolicyManager_.GetAllSourceOutputs();

    for (size_t i = 0; i < sourceOutputs.size(); i++) {
        AUDIO_DEBUG_LOG("sourceOutput[%{public}zu]:%{public}s", i, PrintSourceOutput(sourceOutputs[i]).c_str());
        if (sessionId == sourceOutputs[i].streamId) {
            targetSourceOutputs.push_back(sourceOutputs[i]);
        }
    }
    return targetSourceOutputs;
}

std::vector<SinkInput> AudioPolicyService::FilterSinkInputs(sptr<AudioRendererFilter> audioRendererFilter,
    bool moveAll)
{
    int32_t targetUid = audioRendererFilter->uid;
    AudioStreamType targetStreamType = audioRendererFilter->streamType;
    // find sink-input id with audioRendererFilter
    std::vector<SinkInput> targetSinkInputs = {};
    std::vector<SinkInput> sinkInputs = audioPolicyManager_.GetAllSinkInputs();

    for (size_t i = 0; i < sinkInputs.size(); i++) {
        CHECK_AND_CONTINUE_LOG(sinkInputs[i].uid != dAudioClientUid,
            "Find sink-input with daudio[%{public}d]", sinkInputs[i].pid);
        CHECK_AND_CONTINUE_LOG(sinkInputs[i].streamType != STREAM_DEFAULT,
            "Sink-input[%{public}zu] of effect sink, don't move", i);
        AUDIO_DEBUG_LOG("sinkinput[%{public}zu]:%{public}s", i, PrintSinkInput(sinkInputs[i]).c_str());
        if (moveAll || (targetUid == sinkInputs[i].uid && targetStreamType == sinkInputs[i].streamType)) {
            targetSinkInputs.push_back(sinkInputs[i]);
        }
    }
    return targetSinkInputs;
}

int32_t AudioPolicyService::RememberRoutingInfo(sptr<AudioRendererFilter> audioRendererFilter,
    sptr<AudioDeviceDescriptor> deviceDescriptor)
{
    AUDIO_INFO_LOG("Start for uid[%{public}d] device[%{public}s]", audioRendererFilter->uid,
        deviceDescriptor->networkId_.c_str());
    if (deviceDescriptor->networkId_ == LOCAL_NETWORK_ID) {
        std::lock_guard<std::mutex> lock(routerMapMutex_);
        routerMap_[audioRendererFilter->uid] = std::pair(LOCAL_NETWORK_ID, G_UNKNOWN_PID);
        return SUCCESS;
    }
    // remote device.
    std::string networkId = deviceDescriptor->networkId_;
    DeviceRole deviceRole = deviceDescriptor->deviceRole_;

    std::string moduleName = GetRemoteModuleName(networkId, deviceRole);
    CHECK_AND_RETURN_RET_LOG(IOHandles_.count(moduleName), ERR_INVALID_PARAM,
        "Device error: no such device:%{public}s", networkId.c_str());
    const sptr<IStandardAudioService> gsp = GetAudioServerProxy();
    CHECK_AND_RETURN_RET_LOG(gsp != nullptr, ERR_OPERATION_FAILED, "Service proxy unavailable");
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    int32_t ret = gsp->CheckRemoteDeviceState(networkId, deviceRole, true);
    IPCSkeleton::SetCallingIdentity(identity);
    CHECK_AND_RETURN_RET_LOG(ret == SUCCESS, ERR_OPERATION_FAILED, "remote device state is invalid!");

    std::lock_guard<std::mutex> lock(routerMapMutex_);
    routerMap_[audioRendererFilter->uid] = std::pair(moduleName, G_UNKNOWN_PID);
    return SUCCESS;
}

int32_t AudioPolicyService::MoveToLocalOutputDevice(std::vector<SinkInput> sinkInputIds,
    sptr<AudioDeviceDescriptor> localDeviceDescriptor)
{
    AUDIO_INFO_LOG("Start for [%{public}zu] sink-inputs", sinkInputIds.size());
    // check
    CHECK_AND_RETURN_RET_LOG(LOCAL_NETWORK_ID == localDeviceDescriptor->networkId_,
        ERR_INVALID_OPERATION, "failed: not a local device.");

    // start move.
    uint32_t sinkId = -1; // invalid sink id, use sink name instead.
    std::string sinkName = GetSinkPortName(localDeviceDescriptor->deviceType_);
    for (size_t i = 0; i < sinkInputIds.size(); i++) {
        int32_t ret = audioPolicyManager_.MoveSinkInputByIndexOrName(sinkInputIds[i].paStreamId, sinkId, sinkName);
        CHECK_AND_RETURN_RET_LOG(ret == SUCCESS, ERROR,
            "move [%{public}d] to local failed", sinkInputIds[i].streamId);
        std::lock_guard<std::mutex> lock(routerMapMutex_);
        routerMap_[sinkInputIds[i].uid] = std::pair(LOCAL_NETWORK_ID, sinkInputIds[i].pid);
    }

    isCurrentRemoteRenderer = false;
    return SUCCESS;
}

int32_t AudioPolicyService::OpenRemoteAudioDevice(std::string networkId, DeviceRole deviceRole, DeviceType deviceType,
    sptr<AudioDeviceDescriptor> remoteDeviceDescriptor)
{
    // open the test device. We should open it when device is online.
    std::string moduleName = GetRemoteModuleName(networkId, deviceRole);
    AudioModuleInfo remoteDeviceInfo = ConstructRemoteAudioModuleInfo(networkId, deviceRole, deviceType);
    OpenPortAndInsertIOHandle(moduleName, remoteDeviceInfo);

    // If device already in list, remove it else do not modify the list.
    auto isPresent = [&deviceType, &networkId] (const sptr<AudioDeviceDescriptor> &descriptor) {
        return descriptor->deviceType_ == deviceType && descriptor->networkId_ == networkId;
    };

    std::lock_guard<std::mutex> lock(deviceStatusUpdateSharedMutex_);
    connectedDevices_.erase(std::remove_if(connectedDevices_.begin(), connectedDevices_.end(), isPresent),
        connectedDevices_.end());
    UpdateDisplayName(remoteDeviceDescriptor);
    connectedDevices_.insert(connectedDevices_.begin(), remoteDeviceDescriptor);
    AddMicrophoneDescriptor(remoteDeviceDescriptor);
    return SUCCESS;
}

int32_t AudioPolicyService::MoveToRemoteOutputDevice(std::vector<SinkInput> sinkInputIds,
    sptr<AudioDeviceDescriptor> remoteDeviceDescriptor)
{
    AUDIO_INFO_LOG("Start for [%{public}zu] sink-inputs", sinkInputIds.size());

    std::string networkId = remoteDeviceDescriptor->networkId_;
    DeviceRole deviceRole = remoteDeviceDescriptor->deviceRole_;
    DeviceType deviceType = remoteDeviceDescriptor->deviceType_;

    // check: networkid
    CHECK_AND_RETURN_RET_LOG(networkId != LOCAL_NETWORK_ID, ERR_INVALID_OPERATION,
        "failed: not a remote device.");

    uint32_t sinkId = -1; // invalid sink id, use sink name instead.
    std::string moduleName = GetRemoteModuleName(networkId, deviceRole);
    if (IOHandles_.count(moduleName)) {
        IOHandles_[moduleName]; // mIOHandle is module id, not equal to sink id.
    } else {
        AUDIO_ERR_LOG("no such device.");
        if (!isOpenRemoteDevice) {
            return ERR_INVALID_PARAM;
        } else {
            return OpenRemoteAudioDevice(networkId, deviceRole, deviceType, remoteDeviceDescriptor);
        }
    }

    const sptr<IStandardAudioService> gsp = GetAudioServerProxy();
    CHECK_AND_RETURN_RET_LOG(gsp != nullptr, ERR_OPERATION_FAILED, "Service proxy unavailable");
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    int32_t res = gsp->CheckRemoteDeviceState(networkId, deviceRole, true);
    IPCSkeleton::SetCallingIdentity(identity);
    CHECK_AND_RETURN_RET_LOG(res == SUCCESS, ERR_OPERATION_FAILED, "remote device state is invalid!");

    // start move.
    for (size_t i = 0; i < sinkInputIds.size(); i++) {
        int32_t ret = audioPolicyManager_.MoveSinkInputByIndexOrName(sinkInputIds[i].paStreamId, sinkId, moduleName);
        CHECK_AND_RETURN_RET_LOG(ret == SUCCESS, ERROR, "move [%{public}d] failed", sinkInputIds[i].streamId);
        std::lock_guard<std::mutex> lock(routerMapMutex_);
        routerMap_[sinkInputIds[i].uid] = std::pair(moduleName, sinkInputIds[i].pid);
    }

    if (deviceType != DeviceType::DEVICE_TYPE_DEFAULT) {
        AUDIO_WARNING_LOG("Not defult type[%{public}d] on device:[%{public}s]", deviceType, networkId.c_str());
    }
    isCurrentRemoteRenderer = true;
    return SUCCESS;
}

int32_t AudioPolicyService::SelectFastInputDevice(sptr<AudioCapturerFilter> audioCapturerFilter,
    sptr<AudioDeviceDescriptor> deviceDescriptor)
{
    // note: check if stream is already running
    // if is running, call moveProcessToEndpoint.

    // otherwises, keep router info in the map
    std::lock_guard<std::mutex> lock(routerMapMutex_);
    fastRouterMap_[audioCapturerFilter->uid] = std::make_pair(deviceDescriptor->networkId_, INPUT_DEVICE);
    AUDIO_INFO_LOG("Success for uid[%{public}d] device[%{public}s]", audioCapturerFilter->uid,
        deviceDescriptor->networkId_.c_str());
    return SUCCESS;
}

int32_t AudioPolicyService::SelectInputDevice(sptr<AudioCapturerFilter> audioCapturerFilter,
    std::vector<sptr<AudioDeviceDescriptor>> selectedDesc)
{
    AUDIO_INFO_LOG("Select input device start for uid[%{public}d] type[%{public}d] mac[%{public}s]",
        audioCapturerFilter->uid, selectedDesc[0]->deviceType_, GetEncryptAddr(selectedDesc[0]->macAddress_).c_str());
    // check size == 1 && input device
    int32_t res = DeviceParamsCheck(DeviceRole::INPUT_DEVICE, selectedDesc);
    CHECK_AND_RETURN_RET(res == SUCCESS, res);

    if (audioCapturerFilter->capturerInfo.capturerFlags == STREAM_FLAG_FAST && selectedDesc.size() == 1) {
        return SelectFastInputDevice(audioCapturerFilter, selectedDesc[0]);
    }

    AudioScene scene = GetAudioScene(true);
    SourceType srcType = audioCapturerFilter->capturerInfo.sourceType;
    if (scene == AUDIO_SCENE_PHONE_CALL || scene == AUDIO_SCENE_PHONE_CHAT ||
        srcType == SOURCE_TYPE_VOICE_COMMUNICATION) {
        audioStateManager_.SetPerferredCallCaptureDevice(selectedDesc[0]);
    } else {
        audioStateManager_.SetPerferredRecordCaptureDevice(selectedDesc[0]);
    }
    FetchDevice(false);
    return SUCCESS;
}

int32_t AudioPolicyService::MoveToLocalInputDevice(std::vector<SourceOutput> sourceOutputs,
    sptr<AudioDeviceDescriptor> localDeviceDescriptor)
{
    AUDIO_DEBUG_LOG("Start");
    // check
    CHECK_AND_RETURN_RET_LOG(LOCAL_NETWORK_ID == localDeviceDescriptor->networkId_, ERR_INVALID_OPERATION,
        "failed: not a local device.");
    // start move.
    uint32_t sourceId = -1; // invalid source id, use source name instead.
    std::string sourceName = GetSourcePortName(localDeviceDescriptor->deviceType_);
    for (size_t i = 0; i < sourceOutputs.size(); i++) {
        int32_t ret = audioPolicyManager_.MoveSourceOutputByIndexOrName(sourceOutputs[i].paStreamId,
            sourceId, sourceName);
        CHECK_AND_RETURN_RET_LOG(ret == SUCCESS, ERROR,
            "move [%{public}d] to local failed", sourceOutputs[i].paStreamId);
    }

    return SUCCESS;
}

int32_t AudioPolicyService::MoveToRemoteInputDevice(std::vector<SourceOutput> sourceOutputs,
    sptr<AudioDeviceDescriptor> remoteDeviceDescriptor)
{
    AUDIO_INFO_LOG("Start");

    std::string networkId = remoteDeviceDescriptor->networkId_;
    DeviceRole deviceRole = remoteDeviceDescriptor->deviceRole_;
    DeviceType deviceType = remoteDeviceDescriptor->deviceType_;

    // check: networkid
    CHECK_AND_RETURN_RET_LOG(networkId != LOCAL_NETWORK_ID, ERR_INVALID_OPERATION,
        "failed: not a remote device.");

    uint32_t sourceId = -1; // invalid sink id, use sink name instead.
    std::string moduleName = GetRemoteModuleName(networkId, deviceRole);

    std::unique_lock<std::mutex> ioHandleLock(ioHandlesMutex_);
    if (IOHandles_.count(moduleName)) {
        IOHandles_[moduleName]; // mIOHandle is module id, not equal to sink id.
        ioHandleLock.unlock();
    } else {
        ioHandleLock.unlock();
        AUDIO_ERR_LOG("no such device.");
        if (!isOpenRemoteDevice) {
            return ERR_INVALID_PARAM;
        } else {
            return OpenRemoteAudioDevice(networkId, deviceRole, deviceType, remoteDeviceDescriptor);
        }
    }

    const sptr<IStandardAudioService> gsp = GetAudioServerProxy();
    CHECK_AND_RETURN_RET_LOG(gsp != nullptr, ERR_OPERATION_FAILED, "Service proxy unavailable");
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    int32_t res = gsp->CheckRemoteDeviceState(networkId, deviceRole, true);
    IPCSkeleton::SetCallingIdentity(identity);
    CHECK_AND_RETURN_RET_LOG(res == SUCCESS, ERR_OPERATION_FAILED, "remote device state is invalid!");

    // start move.
    for (size_t i = 0; i < sourceOutputs.size(); i++) {
        int32_t ret = audioPolicyManager_.MoveSourceOutputByIndexOrName(sourceOutputs[i].paStreamId,
            sourceId, moduleName);
        CHECK_AND_RETURN_RET_LOG(ret == SUCCESS, ERROR,
            "move [%{public}d] failed", sourceOutputs[i].paStreamId);
    }

    if (deviceType != DeviceType::DEVICE_TYPE_DEFAULT) {
        AUDIO_DEBUG_LOG("Not defult type[%{public}d] on device:[%{public}s]", deviceType, networkId.c_str());
    }
    return SUCCESS;
}

bool AudioPolicyService::IsStreamActive(AudioStreamType streamType) const
{
    CHECK_AND_RETURN_RET(streamType != STREAM_VOICE_CALL || audioScene_ != AUDIO_SCENE_PHONE_CALL, true);

    return streamCollector_.IsStreamActive(streamType);
}

void AudioPolicyService::ConfigDistributedRoutingRole(const sptr<AudioDeviceDescriptor> descriptor, CastType type)
{
    sptr<AudioDeviceDescriptor> intermediateDescriptor = new AudioDeviceDescriptor(descriptor);
    StoreDistributedRoutingRoleInfo(intermediateDescriptor, type);
    FetchDevice(true, AudioStreamDeviceChangeReason::OVERRODE);
    FetchDevice(false);
}

void AudioPolicyService::StoreDistributedRoutingRoleInfo(const sptr<AudioDeviceDescriptor> descriptor, CastType type)
{
    distributedRoutingInfo_.descriptor = descriptor;
    distributedRoutingInfo_.type = type;
}

DistributedRoutingInfo AudioPolicyService::GetDistributedRoutingRoleInfo()
{
    return distributedRoutingInfo_;
}

std::string AudioPolicyService::GetSinkPortName(InternalDeviceType deviceType)
{
    std::string portName = PORT_NONE;
    if (deviceType == DEVICE_TYPE_USB_HEADSET && isArmUsbDevice_) {
        deviceType = DEVICE_TYPE_USB_ARM_HEADSET;
    }
    switch (deviceType) {
        case InternalDeviceType::DEVICE_TYPE_BLUETOOTH_A2DP:
            if (a2dpOffloadFlag_ == A2DP_OFFLOAD) {
                portName = PRIMARY_SPEAKER;
            } else {
                portName = BLUETOOTH_SPEAKER;
            }
            break;
        case InternalDeviceType::DEVICE_TYPE_EARPIECE:
        case InternalDeviceType::DEVICE_TYPE_SPEAKER:
        case InternalDeviceType::DEVICE_TYPE_WIRED_HEADSET:
        case InternalDeviceType::DEVICE_TYPE_WIRED_HEADPHONES:
        case InternalDeviceType::DEVICE_TYPE_USB_HEADSET:
        case InternalDeviceType::DEVICE_TYPE_BLUETOOTH_SCO:
            portName = PRIMARY_SPEAKER;
            break;
        case InternalDeviceType::DEVICE_TYPE_USB_ARM_HEADSET:
            portName = USB_SPEAKER;
            break;
        case InternalDeviceType::DEVICE_TYPE_DP:
            portName = DP_SINK;
            break;
        case InternalDeviceType::DEVICE_TYPE_FILE_SINK:
            portName = FILE_SINK;
            break;
        case InternalDeviceType::DEVICE_TYPE_REMOTE_CAST:
            portName = REMOTE_CAST_INNER_CAPTURER_SINK_NAME;
            break;
        default:
            portName = PORT_NONE;
            break;
    }

    return portName;
}

std::string AudioPolicyService::GetSourcePortName(InternalDeviceType deviceType)
{
    std::string portName = PORT_NONE;
    if (deviceType == DEVICE_TYPE_USB_HEADSET && isArmUsbDevice_) {
        deviceType = DEVICE_TYPE_USB_ARM_HEADSET;
    }
    switch (deviceType) {
        case InternalDeviceType::DEVICE_TYPE_MIC:
            portName = PRIMARY_MIC;
            break;
        case InternalDeviceType::DEVICE_TYPE_USB_ARM_HEADSET:
            portName = USB_MIC;
            break;
        case InternalDeviceType::DEVICE_TYPE_WAKEUP:
            portName = PRIMARY_WAKEUP;
            break;
        case InternalDeviceType::DEVICE_TYPE_FILE_SOURCE:
            portName = FILE_SOURCE;
            break;
        default:
            portName = PORT_NONE;
            break;
    }

    return portName;
}

// private method
AudioModuleInfo AudioPolicyService::ConstructRemoteAudioModuleInfo(std::string networkId, DeviceRole deviceRole,
    DeviceType deviceType)
{
    AudioModuleInfo audioModuleInfo = {};
    if (deviceRole == DeviceRole::OUTPUT_DEVICE) {
        audioModuleInfo.lib = "libmodule-hdi-sink.z.so";
        audioModuleInfo.format = "s16le"; // 16bit little endian
        audioModuleInfo.fixedLatency = "1"; // here we need to set latency fixed for a fixed buffer size.
    } else if (deviceRole == DeviceRole::INPUT_DEVICE) {
        audioModuleInfo.lib = "libmodule-hdi-source.z.so";
        audioModuleInfo.format = "s16le"; // we assume it is bigger endian
    } else {
        AUDIO_WARNING_LOG("Invalid flag provided %{public}d", static_cast<int32_t>(deviceType));
    }

    // used as "sink_name" in hdi_sink.c, hope we could use name to find target sink.
    audioModuleInfo.name = GetRemoteModuleName(networkId, deviceRole);
    audioModuleInfo.networkId = networkId;

    std::stringstream typeValue;
    typeValue << static_cast<int32_t>(deviceType);
    audioModuleInfo.deviceType = typeValue.str();

    audioModuleInfo.adapterName = "remote";
    audioModuleInfo.className = "remote"; // used in renderer_sink_adapter.c
    audioModuleInfo.fileName = "remote_dump_file";

    audioModuleInfo.channels = "2";
    audioModuleInfo.rate = "48000";
    audioModuleInfo.bufferSize = "3840";

    return audioModuleInfo;
}

// private method
AudioModuleInfo AudioPolicyService::ConstructWakeUpAudioModuleInfo(int32_t wakeupNo, const AudioStreamInfo &streamInfo)
{
    uint32_t bufferSize = (streamInfo.samplingRate * GetSampleFormatValue(streamInfo.format)
        * streamInfo.channels) / (PCM_8_BIT * BT_BUFFER_ADJUSTMENT_FACTOR);

    AudioModuleInfo audioModuleInfo = {};
    audioModuleInfo.lib = "libmodule-hdi-source.z.so";
    audioModuleInfo.format = ConvertToHDIAudioFormat(streamInfo.format);

    audioModuleInfo.name = WAKEUP_NAMES[wakeupNo];
    audioModuleInfo.networkId = "LocalDevice";

    audioModuleInfo.adapterName = "primary";
    audioModuleInfo.className = "primary";
    audioModuleInfo.fileName = "";

    audioModuleInfo.channels = std::to_string(streamInfo.channels);
    audioModuleInfo.rate = std::to_string(streamInfo.samplingRate);
    audioModuleInfo.bufferSize = std::to_string(bufferSize);
    audioModuleInfo.OpenMicSpeaker = "1";

    audioModuleInfo.sourceType = std::to_string(SourceType::SOURCE_TYPE_WAKEUP);
    return audioModuleInfo;
}

void AudioPolicyService::OnPreferredOutputDeviceUpdated(const AudioDeviceDescriptor& deviceDescriptor)
{
    Trace trace("AudioPolicyService::OnPreferredOutputDeviceUpdated:" + std::to_string(deviceDescriptor.deviceType_));
    AUDIO_INFO_LOG("Start");

    if (audioPolicyServerHandler_ != nullptr) {
        audioPolicyServerHandler_->SendPreferredOutputDeviceUpdated();
    }
    spatialDeviceMap_.insert(make_pair(deviceDescriptor.macAddress_, deviceDescriptor.deviceType_));
    UpdateEffectDefaultSink(deviceDescriptor.deviceType_);
    AudioSpatializationService::GetAudioSpatializationService().UpdateCurrentDevice(deviceDescriptor.macAddress_);
    ResetOffloadMode();
}

void AudioPolicyService::OnPreferredInputDeviceUpdated(DeviceType deviceType, std::string networkId)
{
    AUDIO_INFO_LOG("Start");

    if (audioPolicyServerHandler_ != nullptr) {
        audioPolicyServerHandler_->SendPreferredInputDeviceUpdated();
    }
}

void AudioPolicyService::OnPreferredDeviceUpdated(const AudioDeviceDescriptor& activeOutputDevice,
    DeviceType activeInputDevice)
{
    OnPreferredOutputDeviceUpdated(activeOutputDevice);
    OnPreferredInputDeviceUpdated(activeInputDevice, LOCAL_NETWORK_ID);
}

int32_t AudioPolicyService::SetWakeUpAudioCapturer(InternalAudioCapturerOptions options)
{
    AUDIO_INFO_LOG("Start");

    int32_t wakeupNo = 0;
    {
        std::lock_guard<std::mutex> lock(wakeupCountMutex_);
        if (wakeupCount_ < 0) {
            AUDIO_ERR_LOG("wakeupCount_ = %{public}d", wakeupCount_);
            wakeupCount_ = 0;
        }
        if (wakeupCount_ >= WAKEUP_LIMIT) {
            return ERROR;
        }
        wakeupNo = wakeupCount_;
        wakeupCount_++;
    }

    AudioModuleInfo moduleInfo = ConstructWakeUpAudioModuleInfo(wakeupNo, options.streamInfo);
    OpenPortAndInsertIOHandle(moduleInfo.name, moduleInfo);

    AUDIO_DEBUG_LOG("Active Success!");
    return wakeupNo;
}

int32_t AudioPolicyService::SetWakeUpAudioCapturerFromAudioServer(const AudioProcessConfig &config)
{
    InternalAudioCapturerOptions capturerOptions;
    capturerOptions.streamInfo = config.streamInfo;
    return SetWakeUpAudioCapturer(capturerOptions);
}

int32_t AudioPolicyService::NotifyCapturerAdded(AudioCapturerInfo capturerInfo, AudioStreamInfo streamInfo,
    uint32_t sessionId)
{
    int32_t error = SUCCESS;
    audioPolicyServerHandler_->SendCapturerCreateEvent(capturerInfo, streamInfo, sessionId, true, error);
    return error;
}

int32_t AudioPolicyService::NotifyWakeUpCapturerRemoved()
{
    audioPolicyServerHandler_->SendWakeupCloseEvent(false);
    return SUCCESS;
}

bool AudioPolicyService::IsAbsVolumeSupported()
{
    return IsAbsVolumeScene();
}

int32_t AudioPolicyService::CloseWakeUpAudioCapturer()
{
    AUDIO_INFO_LOG("Start");

    {
        std::lock_guard<std::mutex> lock(wakeupCountMutex_);
        wakeupCount_--;
        if (wakeupCount_ > 0) {
            return SUCCESS;
        }
        for (auto key : WAKEUP_NAMES) {
            AudioIOHandle ioHandle;
            {
                std::lock_guard<std::mutex> lck(ioHandlesMutex_);
                auto ioHandleIter = IOHandles_.find(std::string(key));
                if (ioHandleIter == IOHandles_.end()) {
                    AUDIO_ERR_LOG("failed");
                    continue;
                } else {
                    ioHandle = ioHandleIter->second;
                    IOHandles_.erase(ioHandleIter);
                }
            }
            audioPolicyManager_.CloseAudioPort(ioHandle);
        }
    }
    return SUCCESS;
}

std::vector<sptr<AudioDeviceDescriptor>> AudioPolicyService::GetDevices(DeviceFlag deviceFlag)
{
    AUDIO_DEBUG_LOG("Start");

    std::lock_guard<std::mutex> lock(deviceStatusUpdateSharedMutex_);

    std::vector<sptr<AudioDeviceDescriptor>> deviceList = {};

    CHECK_AND_RETURN_RET_LOG(deviceFlag >= DeviceFlag::OUTPUT_DEVICES_FLAG &&
        deviceFlag <= DeviceFlag::ALL_L_D_DEVICES_FLAG,
        deviceList, "Invalid flag provided %{public}d", deviceFlag);

    CHECK_AND_RETURN_RET(deviceFlag != DeviceFlag::ALL_L_D_DEVICES_FLAG, connectedDevices_);

    for (auto device : connectedDevices_) {
        if (device == nullptr) {
            continue;
        }
        bool filterAllLocal = deviceFlag == DeviceFlag::ALL_DEVICES_FLAG && device->networkId_ == LOCAL_NETWORK_ID;
        bool filterLocalOutput = deviceFlag == DeviceFlag::OUTPUT_DEVICES_FLAG
            && device->networkId_ == LOCAL_NETWORK_ID
            && device->deviceRole_ == DeviceRole::OUTPUT_DEVICE;
        bool filterLocalInput = deviceFlag == DeviceFlag::INPUT_DEVICES_FLAG
            && device->networkId_ == LOCAL_NETWORK_ID
            && device->deviceRole_ == DeviceRole::INPUT_DEVICE;

        bool filterAllRemote = deviceFlag == DeviceFlag::ALL_DISTRIBUTED_DEVICES_FLAG
            && device->networkId_ != LOCAL_NETWORK_ID;
        bool filterRemoteOutput = deviceFlag == DeviceFlag::DISTRIBUTED_OUTPUT_DEVICES_FLAG
            && (device->networkId_ != LOCAL_NETWORK_ID || device->deviceType_ == DEVICE_TYPE_REMOTE_CAST)
            && device->deviceRole_ == DeviceRole::OUTPUT_DEVICE;
        bool filterRemoteInput = deviceFlag == DeviceFlag::DISTRIBUTED_INPUT_DEVICES_FLAG
            && device->networkId_ != LOCAL_NETWORK_ID
            && device->deviceRole_ == DeviceRole::INPUT_DEVICE;

        if (filterAllLocal || filterLocalOutput || filterLocalInput || filterAllRemote || filterRemoteOutput
            || filterRemoteInput) {
            sptr<AudioDeviceDescriptor> devDesc = new(std::nothrow) AudioDeviceDescriptor(*device);
            deviceList.push_back(devDesc);
        }
    }

    AUDIO_DEBUG_LOG("list size = [%{public}zu]", deviceList.size());
    return deviceList;
}

std::vector<sptr<AudioDeviceDescriptor>> AudioPolicyService::GetPreferredOutputDeviceDescriptors(
    AudioRendererInfo &rendererInfo, std::string networkId)
{
    std::vector<sptr<AudioDeviceDescriptor>> deviceList = {};
    if (rendererInfo.streamUsage <= STREAM_USAGE_UNKNOWN ||
        rendererInfo.streamUsage > STREAM_USAGE_VOICE_MODEM_COMMUNICATION) {
        sptr<AudioDeviceDescriptor> devDesc = new(std::nothrow) AudioDeviceDescriptor(currentActiveDevice_);
        deviceList.push_back(devDesc);
        return deviceList;
    }
    if (networkId == LOCAL_NETWORK_ID) {
        unique_ptr<AudioDeviceDescriptor> desc = audioRouterCenter_.FetchOutputDevice(rendererInfo.streamUsage, -1);
        sptr<AudioDeviceDescriptor> devDesc = new(std::nothrow) AudioDeviceDescriptor(*desc);
        deviceList.push_back(devDesc);
    } else {
        vector<unique_ptr<AudioDeviceDescriptor>> descs = audioDeviceManager_.GetRemoteRenderDevices();
        for (auto &desc : descs) {
            sptr<AudioDeviceDescriptor> devDesc = new(std::nothrow) AudioDeviceDescriptor(*desc);
            deviceList.push_back(devDesc);
        }
    }

    return deviceList;
}

std::vector<sptr<AudioDeviceDescriptor>> AudioPolicyService::GetPreferredInputDeviceDescriptors(
    AudioCapturerInfo &captureInfo, std::string networkId)
{
    std::vector<sptr<AudioDeviceDescriptor>> deviceList = {};
    if (captureInfo.sourceType <= SOURCE_TYPE_INVALID ||
        captureInfo.sourceType > SOURCE_TYPE_MAX) {
        sptr<AudioDeviceDescriptor> devDesc = new(std::nothrow) AudioDeviceDescriptor(currentActiveInputDevice_);
        deviceList.push_back(devDesc);
        return deviceList;
    }
    if (networkId == LOCAL_NETWORK_ID) {
        unique_ptr<AudioDeviceDescriptor> desc = audioRouterCenter_.FetchInputDevice(captureInfo.sourceType, -1);
        if (desc->deviceType_ == DEVICE_TYPE_NONE && (captureInfo.sourceType == SOURCE_TYPE_PLAYBACK_CAPTURE ||
            captureInfo.sourceType == SOURCE_TYPE_REMOTE_CAST)) {
            desc->deviceType_ = DEVICE_TYPE_INVALID;
            desc->deviceRole_ = INPUT_DEVICE;
        }
        sptr<AudioDeviceDescriptor> devDesc = new(std::nothrow) AudioDeviceDescriptor(*desc);
        deviceList.push_back(devDesc);
    } else {
        vector<unique_ptr<AudioDeviceDescriptor>> descs = audioDeviceManager_.GetRemoteCaptureDevices();
        for (auto &desc : descs) {
            sptr<AudioDeviceDescriptor> devDesc = new(std::nothrow) AudioDeviceDescriptor(*desc);
            deviceList.push_back(devDesc);
        }
    }

    return deviceList;
}

void AudioPolicyService::UpdateActiveDeviceRoute(InternalDeviceType deviceType, DeviceFlag deviceFlag)
{
    Trace trace("AudioPolicyService::UpdateActiveDeviceRoute DeviceType:" + std::to_string(deviceType));
    AUDIO_INFO_LOG("Active route with type[%{public}d]", deviceType);

    CHECK_AND_RETURN_LOG(g_adProxy != nullptr, "Audio Server Proxy is null");
    auto ret = SUCCESS;

    if (deviceType == DEVICE_TYPE_USB_HEADSET && isArmUsbDevice_) {
        deviceType = DEVICE_TYPE_USB_ARM_HEADSET;
    }
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    ret = g_adProxy->UpdateActiveDeviceRoute(deviceType, deviceFlag);
    IPCSkeleton::SetCallingIdentity(identity);
    CHECK_AND_RETURN_LOG(ret == SUCCESS, "Failed to update the route for %{public}d", deviceType);
}

void AudioPolicyService::SelectNewOutputDevice(unique_ptr<AudioRendererChangeInfo> &rendererChangeInfo,
    unique_ptr<AudioDeviceDescriptor> &outputDevice, const AudioStreamDeviceChangeReason reason)
{
    std::vector<SinkInput> targetSinkInputs = FilterSinkInputs(rendererChangeInfo->sessionId);

    bool needTriggerCallback = true;
    if (outputDevice->isSameDevice(rendererChangeInfo->outputDeviceInfo)) {
        needTriggerCallback = false;
    }
    AUDIO_INFO_LOG("move session %{public}d [%{public}d][%{public}s]-->[%{public}d][%{public}s], reason %{public}d",
        rendererChangeInfo->sessionId, rendererChangeInfo->outputDeviceInfo.deviceType,
        GetEncryptAddr(rendererChangeInfo->outputDeviceInfo.macAddress).c_str(),
        outputDevice->deviceType_, GetEncryptAddr(outputDevice->macAddress_).c_str(), reason);

    UpdateDeviceInfo(rendererChangeInfo->outputDeviceInfo, new AudioDeviceDescriptor(*outputDevice), true, true);

    if (needTriggerCallback) {
        audioPolicyServerHandler_->SendRendererDeviceChangeEvent(rendererChangeInfo->callerPid,
            rendererChangeInfo->sessionId, rendererChangeInfo->outputDeviceInfo, reason);
    }

    // MoveSinkInputByIndexOrName
    auto ret = (outputDevice->networkId_ == LOCAL_NETWORK_ID)
                ? MoveToLocalOutputDevice(targetSinkInputs, new AudioDeviceDescriptor(*outputDevice))
                : MoveToRemoteOutputDevice(targetSinkInputs, new AudioDeviceDescriptor(*outputDevice));
    CHECK_AND_RETURN_LOG((ret == SUCCESS), "Move sink input %{public}d to device %{public}d failed!",
        rendererChangeInfo->sessionId, outputDevice->deviceType_);
    SetVolumeForSwitchDevice(outputDevice->deviceType_);
    if (isUpdateRouteSupported_) {
        UpdateActiveDeviceRoute(outputDevice->deviceType_, DeviceFlag::OUTPUT_DEVICES_FLAG);
    }

    streamCollector_.UpdateRendererDeviceInfo(rendererChangeInfo->clientUID, rendererChangeInfo->sessionId,
        rendererChangeInfo->outputDeviceInfo);

    ResetOffloadMode();
}

void AudioPolicyService::SelectNewInputDevice(unique_ptr<AudioCapturerChangeInfo> &capturerChangeInfo,
    unique_ptr<AudioDeviceDescriptor> &inputDevice)
{
    std::vector<SourceOutput> targetSourceOutputs = FilterSourceOutputs(capturerChangeInfo->sessionId);

    // MoveSourceOuputByIndexName
    auto ret = (inputDevice->networkId_ == LOCAL_NETWORK_ID)
                ? MoveToLocalInputDevice(targetSourceOutputs, new AudioDeviceDescriptor(*inputDevice))
                : MoveToRemoteInputDevice(targetSourceOutputs, new AudioDeviceDescriptor(*inputDevice));
    CHECK_AND_RETURN_LOG((ret == SUCCESS), "Move source output %{public}d to device %{public}d failed!",
        capturerChangeInfo->sessionId, inputDevice->deviceType_);
    if (isUpdateRouteSupported_) {
        UpdateActiveDeviceRoute(inputDevice->deviceType_, DeviceFlag::INPUT_DEVICES_FLAG);
    }
    UpdateDeviceInfo(capturerChangeInfo->inputDeviceInfo, new AudioDeviceDescriptor(*inputDevice), true, true);
    streamCollector_.UpdateCapturerDeviceInfo(capturerChangeInfo->clientUID, capturerChangeInfo->sessionId,
        capturerChangeInfo->inputDeviceInfo);
}

void AudioPolicyService::FetchOutputDeviceWhenNoRunningStream()
{
    AUDIO_INFO_LOG("In");
    unique_ptr<AudioDeviceDescriptor> desc = audioRouterCenter_.FetchOutputDevice(STREAM_USAGE_MEDIA, -1);
    CHECK_AND_RETURN_LOG(desc != nullptr, "desc is nullptr");
    if (desc->deviceType_ == DEVICE_TYPE_NONE || IsSameDevice(desc, currentActiveDevice_)) {
        AUDIO_DEBUG_LOG("output device is not change");
        return;
    }
    SetVolumeForSwitchDevice(desc->deviceType_);
    if (desc->deviceType_ == DEVICE_TYPE_BLUETOOTH_A2DP) {
        SwitchActiveA2dpDevice(new AudioDeviceDescriptor(*desc));
    }
    currentActiveDevice_ = AudioDeviceDescriptor(*desc);
    AUDIO_DEBUG_LOG("currentActiveDevice update %{public}d", currentActiveDevice_.deviceType_);
    OnPreferredOutputDeviceUpdated(currentActiveDevice_);
}

void AudioPolicyService::FetchInputDeviceWhenNoRunningStream()
{
    AUDIO_INFO_LOG("In");
    unique_ptr<AudioDeviceDescriptor> desc = audioRouterCenter_.FetchInputDevice(SOURCE_TYPE_MIC, -1);
    if (desc->deviceType_ == DEVICE_TYPE_NONE || IsSameDevice(desc, currentActiveInputDevice_)) {
        AUDIO_DEBUG_LOG("input device is not change");
        return;
    }
    currentActiveInputDevice_ = AudioDeviceDescriptor(*desc);
    if (desc->deviceType_ == DEVICE_TYPE_BLUETOOTH_A2DP || desc->deviceType_ == DEVICE_TYPE_BLUETOOTH_SCO) {
        activeBTDevice_ = desc->macAddress_;
    }
    AUDIO_DEBUG_LOG("currentActiveInputDevice update %{public}d", currentActiveInputDevice_.deviceType_);
    OnPreferredInputDeviceUpdated(currentActiveInputDevice_.deviceType_, currentActiveInputDevice_.networkId_);
}

int32_t AudioPolicyService::ActivateA2dpDevice(unique_ptr<AudioDeviceDescriptor> &desc,
    vector<unique_ptr<AudioRendererChangeInfo>> &rendererChangeInfos, const AudioStreamDeviceChangeReason reason)
{
    sptr<AudioDeviceDescriptor> deviceDesc = new AudioDeviceDescriptor(*desc);
    int32_t ret = SwitchActiveA2dpDevice(deviceDesc);
    if (ret != SUCCESS) {
        AUDIO_ERR_LOG("Active A2DP device failed, retrigger fetch output device");
        deviceDesc->exceptionFlag_ = true;
        audioDeviceManager_.UpdateDevicesListInfo(deviceDesc, EXCEPTION_FLAG_UPDATE);
        FetchOutputDevice(rendererChangeInfos, reason);
        return ERROR;
    }
    return SUCCESS;
}

int32_t AudioPolicyService::HandleScoOutputDeviceFetched(unique_ptr<AudioDeviceDescriptor> &desc,
    vector<unique_ptr<AudioRendererChangeInfo>> &rendererChangeInfos)
{
#ifdef BLUETOOTH_ENABLE
        int32_t ret = Bluetooth::AudioHfpManager::SetActiveHfpDevice(desc->macAddress_);
        if (ret != SUCCESS) {
            AUDIO_ERR_LOG("Active hfp device failed, retrigger fetch output device.");
            desc->exceptionFlag_ = true;
            audioDeviceManager_.UpdateDevicesListInfo(new AudioDeviceDescriptor(*desc), EXCEPTION_FLAG_UPDATE);
            FetchOutputDevice(rendererChangeInfos);
            return ERROR;
        }
        if (desc->connectState_ == DEACTIVE_CONNECTED) {
            Bluetooth::AudioHfpManager::ConnectScoWithAudioScene(audioScene_);
            return SUCCESS;
        }
#endif
    return SUCCESS;
}

bool AudioPolicyService::IsRendererStreamRunning(unique_ptr<AudioRendererChangeInfo> &rendererChangeInfo)
{
    StreamUsage usage = rendererChangeInfo->rendererInfo.streamUsage;
    RendererState rendererState = rendererChangeInfo->rendererState;
    if ((usage == STREAM_USAGE_VOICE_MODEM_COMMUNICATION && audioScene_ != AUDIO_SCENE_PHONE_CALL) ||
        (usage != STREAM_USAGE_VOICE_MODEM_COMMUNICATION && rendererState != RENDERER_RUNNING)) {
        return false;
    }
    return true;
}

bool AudioPolicyService::NeedRehandleA2DPDevice(unique_ptr<AudioDeviceDescriptor> &desc)
{
    std::lock_guard<std::mutex> ioHandleLock(ioHandlesMutex_);
    if (desc->deviceType_ == DEVICE_TYPE_BLUETOOTH_A2DP && IOHandles_.find(BLUETOOTH_SPEAKER) == IOHandles_.end()) {
        AUDIO_INFO_LOG("A2DP module is not loaded, need rehandle");
        return true;
    }
    return false;
}

void AudioPolicyService::MuteSinkPort(unique_ptr<AudioDeviceDescriptor> &desc)
{
    int32_t duration = 1000000; // us
    string portName = GetSinkPortName(desc->deviceType_);
    thread switchThread(&AudioPolicyService::KeepPortMute, this, duration, portName, desc->deviceType_);
    switchThread.detach(); // add another sleep before switch local can avoid pop in some case
}

int32_t AudioPolicyService::HandleDeviceChangeForFetchOutputDevice(unique_ptr<AudioDeviceDescriptor> &desc,
    unique_ptr<AudioRendererChangeInfo> &rendererChangeInfo)
{
    if (desc->deviceType_ == DEVICE_TYPE_NONE || (IsSameDevice(desc, rendererChangeInfo->outputDeviceInfo) &&
        !NeedRehandleA2DPDevice(desc) && desc->connectState_ != DEACTIVE_CONNECTED && !sameDeviceSwitchFlag_)) {
        AUDIO_INFO_LOG("stream %{public}d device not change, no need move device", rendererChangeInfo->sessionId);
        if (!IsSameDevice(desc, currentActiveDevice_)) {
            currentActiveDevice_ = AudioDeviceDescriptor(*desc);
            SetVolumeForSwitchDevice(currentActiveDevice_.deviceType_);
        }
        return ERR_NEED_NOT_SWITCH_DEVICE;
    }
    return SUCCESS;
}

void AudioPolicyService::FetchOutputDevice(vector<unique_ptr<AudioRendererChangeInfo>> &rendererChangeInfos,
    const AudioStreamDeviceChangeReason reason)
{
    AUDIO_INFO_LOG("Start for %{public}zu stream", rendererChangeInfos.size());
    bool needUpdateActiveDevice = true;
    bool isUpdateActiveDevice = false;
    int32_t runningStreamCount = 0;
    for (auto &rendererChangeInfo : rendererChangeInfos) {
        if (!IsRendererStreamRunning(rendererChangeInfo) || (audioScene_ == AUDIO_SCENE_DEFAULT &&
            audioRouterCenter_.isCallRenderRouter(rendererChangeInfo->rendererInfo.streamUsage))) {
            AUDIO_INFO_LOG("stream %{public}d not running, no need fetch device", rendererChangeInfo->sessionId);
            continue;
        }
        runningStreamCount++;
        unique_ptr<AudioDeviceDescriptor> desc = audioRouterCenter_.FetchOutputDevice(
            rendererChangeInfo->rendererInfo.streamUsage, rendererChangeInfo->clientUID);
        if (HandleDeviceChangeForFetchOutputDevice(desc, rendererChangeInfo) == ERR_NEED_NOT_SWITCH_DEVICE) {
            continue;
        }
        std::string encryptMacAddr = GetEncryptAddr(desc->macAddress_);
        if (desc->deviceType_ == DEVICE_TYPE_BLUETOOTH_A2DP) {
            int32_t ret = ActivateA2dpDevice(desc, rendererChangeInfos, reason);
            CHECK_AND_RETURN_LOG(ret == SUCCESS, "activate a2dp [%{public}s] failed", encryptMacAddr.c_str());
            OffloadStartPlayingIfOffloadMode(rendererChangeInfo->sessionId);
        } else if (desc->deviceType_ == DEVICE_TYPE_BLUETOOTH_SCO) {
            int32_t ret = HandleScoOutputDeviceFetched(desc, rendererChangeInfos);
            CHECK_AND_RETURN_LOG(ret == SUCCESS, "sco [%{public}s] is not connected yet", encryptMacAddr.c_str());
        }
        if (needUpdateActiveDevice) {
            if (!IsSameDevice(desc, currentActiveDevice_)) {
                currentActiveDevice_ = AudioDeviceDescriptor(*desc);
                AUDIO_DEBUG_LOG("currentActiveDevice update %{public}d", currentActiveDevice_.deviceType_);
                isUpdateActiveDevice = true;
            }
            needUpdateActiveDevice = false;
            if (reason == AudioStreamDeviceChangeReason::OLD_DEVICE_UNAVALIABLE &&
                audioScene_ == AUDIO_SCENE_DEFAULT && !IsSameDevice(desc, rendererChangeInfo->outputDeviceInfo)) {
                MuteSinkPort(desc);
            }
        }
        SelectNewOutputDevice(rendererChangeInfo, desc, reason);
    }
    sameDeviceSwitchFlag_ = false;
    if (isUpdateActiveDevice) {
        OnPreferredOutputDeviceUpdated(currentActiveDevice_);
    }
    if (runningStreamCount == 0) {
        FetchOutputDeviceWhenNoRunningStream();
    }
}

void AudioPolicyService::FetchStreamForA2dpOffload(vector<unique_ptr<AudioRendererChangeInfo>> &rendererChangeInfos)
{
    AUDIO_INFO_LOG("start for %{public}zu stream", rendererChangeInfos.size());
    for (auto &rendererChangeInfo : rendererChangeInfos) {
        unique_ptr<AudioDeviceDescriptor> desc = audioRouterCenter_.FetchOutputDevice(
            rendererChangeInfo->rendererInfo.streamUsage, rendererChangeInfo->clientUID);
        if (desc->deviceType_ == DEVICE_TYPE_BLUETOOTH_A2DP) {
            int32_t ret = ActivateA2dpDevice(desc, rendererChangeInfos);
            CHECK_AND_RETURN_LOG(ret == SUCCESS, "activate a2dp [%{public}s] failed",
                GetEncryptAddr(desc->macAddress_).c_str());
            if (rendererChangeInfo->rendererInfo.rendererFlags == AUDIO_FLAG_MMAP &&
                a2dpOffloadFlag_ == A2DP_OFFLOAD) {
                const sptr<IStandardAudioService> gsp = GetAudioServerProxy();
                CHECK_AND_RETURN_LOG(gsp != nullptr, "Service proxy unavailable");
                gsp->ResetAudioEndpoint();
            }
            SelectNewOutputDevice(rendererChangeInfo, desc);
        }
    }
}

void AudioPolicyService::OffloadStartPlayingIfOffloadMode(uint64_t sessionId)
{
#ifdef BLUETOOTH_ENABLE
    if (a2dpOffloadFlag_ == A2DP_OFFLOAD) {
        Bluetooth::AudioA2dpManager::OffloadStartPlaying(std::vector<int32_t>(1, sessionId));
    }
#endif
}

bool AudioPolicyService::IsSameDevice(unique_ptr<AudioDeviceDescriptor> &desc, DeviceInfo &deviceInfo)
{
    if (desc->networkId_ == deviceInfo.networkId && desc->deviceType_ == deviceInfo.deviceType &&
        desc->macAddress_ == deviceInfo.macAddress && desc->connectState_ == deviceInfo.connectState) {
        return true;
    } else {
        return false;
    }
}

bool AudioPolicyService::IsSameDevice(unique_ptr<AudioDeviceDescriptor> &desc, AudioDeviceDescriptor &deviceDesc)
{
    if (desc->networkId_ == deviceDesc.networkId_ && desc->deviceType_ == deviceDesc.deviceType_ &&
        desc->macAddress_ == deviceDesc.macAddress_ && desc->connectState_ == deviceDesc.connectState_) {
        return true;
    } else {
        return false;
    }
}

int32_t AudioPolicyService::HandleScoInputDeviceFetched(unique_ptr<AudioDeviceDescriptor> &desc,
    vector<unique_ptr<AudioCapturerChangeInfo>> &capturerChangeInfos)
{
#ifdef BLUETOOTH_ENABLE
    int32_t ret = Bluetooth::AudioHfpManager::SetActiveHfpDevice(desc->macAddress_);
    if (ret != SUCCESS) {
        AUDIO_ERR_LOG("Active hfp device failed, retrigger fetch input device");
        desc->exceptionFlag_ = true;
        audioDeviceManager_.UpdateDevicesListInfo(new AudioDeviceDescriptor(*desc), EXCEPTION_FLAG_UPDATE);
        FetchInputDevice(capturerChangeInfos);
        return ERROR;
    }
    if (desc->connectState_ == DEACTIVE_CONNECTED) {
        Bluetooth::AudioHfpManager::ConnectScoWithAudioScene(audioScene_);
        return SUCCESS;
    }
#endif
    return SUCCESS;
}

void AudioPolicyService::FetchInputDevice(vector<unique_ptr<AudioCapturerChangeInfo>> &capturerChangeInfos)
{
    AUDIO_INFO_LOG("size %{public}zu", capturerChangeInfos.size());
    bool needUpdateActiveDevice = true;
    bool isUpdateActiveDevice = false;
    int32_t runningStreamCount = 0;
    for (auto &capturerChangeInfo : capturerChangeInfos) {
        SourceType sourceType = capturerChangeInfo->capturerInfo.sourceType;
        if ((sourceType == SOURCE_TYPE_VIRTUAL_CAPTURE && audioScene_ != AUDIO_SCENE_PHONE_CALL) ||
            (sourceType != SOURCE_TYPE_VIRTUAL_CAPTURE && capturerChangeInfo->capturerState != CAPTURER_RUNNING)) {
            AUDIO_INFO_LOG("stream %{public}d not running, no need fetch device", capturerChangeInfo->sessionId);
            continue;
        }
        runningStreamCount++;
        unique_ptr<AudioDeviceDescriptor> desc = audioRouterCenter_.FetchInputDevice(sourceType,
            capturerChangeInfo->clientUID);
        DeviceInfo inputDeviceInfo = capturerChangeInfo->inputDeviceInfo;
        if (desc->deviceType_ == DEVICE_TYPE_NONE ||
            (IsSameDevice(desc, inputDeviceInfo) && desc->connectState_ != DEACTIVE_CONNECTED)) {
            AUDIO_INFO_LOG("stream %{public}d device not change, no need move device", capturerChangeInfo->sessionId);
            continue;
        }
        if (desc->deviceType_ == DEVICE_TYPE_BLUETOOTH_SCO) {
            int32_t ret = HandleScoInputDeviceFetched(desc, capturerChangeInfos);
            CHECK_AND_RETURN_LOG(ret == SUCCESS, "sco [%{public}s] is not connected yet",
                GetEncryptAddr(desc->macAddress_).c_str());
        }
        if (needUpdateActiveDevice) {
            if (!IsSameDevice(desc, currentActiveInputDevice_)) {
                currentActiveInputDevice_ = AudioDeviceDescriptor(*desc);
                AUDIO_DEBUG_LOG("currentActiveInputDevice update %{public}d", currentActiveInputDevice_.deviceType_);
                isUpdateActiveDevice = true;
            }
            needUpdateActiveDevice = false;
        }
        // move sourceoutput to target device
        SelectNewInputDevice(capturerChangeInfo, desc);
        AddAudioCapturerMicrophoneDescriptor(capturerChangeInfo->sessionId, desc->deviceType_);
    }
    if (isUpdateActiveDevice) {
        OnPreferredInputDeviceUpdated(currentActiveInputDevice_.deviceType_, currentActiveInputDevice_.networkId_);
    }
    if (runningStreamCount == 0) {
        FetchInputDeviceWhenNoRunningStream();
    }
}

void AudioPolicyService::FetchDevice(bool isOutputDevice, const AudioStreamDeviceChangeReason reason)
{
    Trace trace("AudioPolicyService::FetchDevice reason:" + std::to_string(static_cast<int>(reason)));
    AUDIO_DEBUG_LOG("FetchDevice start");

    std::lock_guard<std::mutex> lock(fetchDeviceSharedMutex_);
    if (isOutputDevice) {
        vector<unique_ptr<AudioRendererChangeInfo>> rendererChangeInfos;
        streamCollector_.GetCurrentRendererChangeInfos(rendererChangeInfos);
        FetchOutputDevice(rendererChangeInfos, reason);
    } else {
        vector<unique_ptr<AudioCapturerChangeInfo>> capturerChangeInfos;
        streamCollector_.GetCurrentCapturerChangeInfos(capturerChangeInfos);
        FetchInputDevice(capturerChangeInfos);
    }
}

int32_t AudioPolicyService::SetMicrophoneMute(bool isMute)
{
    AUDIO_DEBUG_LOG("state[%{public}d]", isMute);
    const sptr<IStandardAudioService> gsp = GetAudioServerProxy();
    CHECK_AND_RETURN_RET_LOG(gsp != nullptr, ERR_OPERATION_FAILED, "Service proxy unavailable");
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    int32_t ret = gsp->SetMicrophoneMute(isMute);
    IPCSkeleton::SetCallingIdentity(identity);
    if (ret == SUCCESS) {
        isMicrophoneMute_ = isMute;
        streamCollector_.UpdateCapturerInfoMuteStatus(0, isMute);
    }
    return ret;
}

bool AudioPolicyService::IsMicrophoneMute()
{
    AUDIO_DEBUG_LOG("IsMicrophoneMute start");
    return isMicrophoneMute_;
}

int32_t AudioPolicyService::SetSystemSoundUri(const std::string &key, const std::string &uri)
{
    return audioPolicyManager_.SetSystemSoundUri(key, uri);
}

std::string AudioPolicyService::GetSystemSoundUri(const std::string &key)
{
    return audioPolicyManager_.GetSystemSoundUri(key);
}

bool AudioPolicyService::IsSessionIdValid(int32_t callerUid, int32_t sessionId)
{
    AUDIO_INFO_LOG("callerUid: %{public}d, sessionId: %{public}d", callerUid, sessionId);

    constexpr int32_t mediaUid = 1013; // "uid" : "media"
    if (callerUid == mediaUid) {
        AUDIO_INFO_LOG("sessionId:%{public}d is an valid id from media", sessionId);
        return true;
    }

    return true;
}

int32_t AudioPolicyService::SwitchActiveA2dpDevice(const sptr<AudioDeviceDescriptor> &deviceDescriptor)
{
    auto iter = connectedA2dpDeviceMap_.find(deviceDescriptor->macAddress_);
    CHECK_AND_RETURN_RET_LOG(iter != connectedA2dpDeviceMap_.end(), ERR_INVALID_PARAM,
        "the target A2DP device doesn't exist.");
    int32_t result = ERROR;
#ifdef BLUETOOTH_ENABLE
    {
        std::lock_guard<std::mutex> ioHandleLock(ioHandlesMutex_);
        if (Bluetooth::AudioA2dpManager::GetActiveA2dpDevice() == deviceDescriptor->macAddress_ &&
            IOHandles_.find(BLUETOOTH_SPEAKER) != IOHandles_.end()) {
            AUDIO_INFO_LOG("a2dp device [%{public}s] is already active",
                GetEncryptAddr(deviceDescriptor->macAddress_).c_str());
            return SUCCESS;
        }
    }
    AUDIO_INFO_LOG("a2dp device name [%{public}s]", (deviceDescriptor->deviceName_).c_str());
    std::string lastActiveA2dpDevice = activeBTDevice_;
    activeBTDevice_ = deviceDescriptor->macAddress_;
    DeviceType lastDevice = audioPolicyManager_.GetActiveDevice();
    audioPolicyManager_.SetActiveDevice(DEVICE_TYPE_BLUETOOTH_A2DP);
    result = Bluetooth::AudioA2dpManager::SetActiveA2dpDevice(deviceDescriptor->macAddress_);
    if (result != SUCCESS) {
        activeBTDevice_ = lastActiveA2dpDevice;
        audioPolicyManager_.SetActiveDevice(lastDevice);
        AUDIO_ERR_LOG("Active [%{public}s] failed, using original [%{public}s] device",
            GetEncryptAddr(activeBTDevice_).c_str(), GetEncryptAddr(lastActiveA2dpDevice).c_str());
        return result;
    }
    {
        std::unique_lock<std::mutex> lock(a2dpDeviceMapMutex_);
        A2dpDeviceConfigInfo configInfo = connectedA2dpDeviceMap_[activeBTDevice_];
        audioPolicyManager_.SetAbsVolumeScene(configInfo.absVolumeSupport);
    }
    result = LoadA2dpModule(DEVICE_TYPE_BLUETOOTH_A2DP);
    CHECK_AND_RETURN_RET_LOG(result == SUCCESS, ERR_OPERATION_FAILED, "LoadA2dpModule failed %{public}d", result);
#endif
    return result;
}

void AudioPolicyService::UnloadA2dpModule()
{
    ClosePortAndEraseIOHandle(BLUETOOTH_SPEAKER);
}

int32_t AudioPolicyService::LoadA2dpModule(DeviceType deviceType)
{
    std::list<AudioModuleInfo> moduleInfoList;
    {
        std::lock_guard<std::mutex> deviceInfoLock(deviceClassInfoMutex_);
        auto primaryModulesPos = deviceClassInfo_.find(ClassType::TYPE_A2DP);
        CHECK_AND_RETURN_RET_LOG(primaryModulesPos != deviceClassInfo_.end(), ERR_OPERATION_FAILED,
            "A2dp module is not exist in the configuration file");
        moduleInfoList = primaryModulesPos->second;
    }
    for (auto &moduleInfo : moduleInfoList) {
        std::lock_guard<std::mutex> ioHandleLock(ioHandlesMutex_);
        if (IOHandles_.find(moduleInfo.name) == IOHandles_.end()) {
            // a2dp device connects for the first time
            AUDIO_DEBUG_LOG("Load a2dp module [%{public}s]", moduleInfo.name.c_str());
            AudioStreamInfo audioStreamInfo = {};
            GetActiveDeviceStreamInfo(deviceType, audioStreamInfo);
            uint32_t bufferSize = (audioStreamInfo.samplingRate * GetSampleFormatValue(audioStreamInfo.format) *
                audioStreamInfo.channels) / (PCM_8_BIT * BT_BUFFER_ADJUSTMENT_FACTOR);
            AUDIO_DEBUG_LOG("a2dp rate: %{public}d, format: %{public}d, channel: %{public}d",
                audioStreamInfo.samplingRate, audioStreamInfo.format, audioStreamInfo.channels);
            moduleInfo.channels = to_string(audioStreamInfo.channels);
            moduleInfo.rate = to_string(audioStreamInfo.samplingRate);
            moduleInfo.format = ConvertToHDIAudioFormat(audioStreamInfo.format);
            moduleInfo.bufferSize = to_string(bufferSize);
            moduleInfo.renderInIdleState = "1";

            AudioIOHandle ioHandle = audioPolicyManager_.OpenAudioPort(moduleInfo);
            CHECK_AND_RETURN_RET_LOG(ioHandle != OPEN_PORT_FAILURE, ERR_OPERATION_FAILED,
                "OpenAudioPort failed %{public}d", ioHandle);
            IOHandles_[moduleInfo.name] = ioHandle;
        } else {
            // At least one a2dp device is already connected. A new a2dp device is connecting.
            // Need to reload a2dp module when switching to a2dp device.
            int32_t result = ReloadA2dpAudioPort(moduleInfo);
            CHECK_AND_RETURN_RET_LOG(result == SUCCESS, result, "ReloadA2dpAudioPort failed %{public}d", result);
        }
    }

    return SUCCESS;
}

int32_t AudioPolicyService::ReloadA2dpAudioPort(AudioModuleInfo &moduleInfo)
{
    AUDIO_INFO_LOG("switch device from a2dp to another a2dp, reload a2dp module");

    // Firstly, unload the existing a2dp sink.
    AudioIOHandle activateDeviceIOHandle = IOHandles_[BLUETOOTH_SPEAKER];
    int32_t result = audioPolicyManager_.CloseAudioPort(activateDeviceIOHandle);
    CHECK_AND_RETURN_RET_LOG(result == SUCCESS, result,
        "CloseAudioPort failed %{public}d", result);

    // Load a2dp sink module again with the configuration of active a2dp device.
    AudioStreamInfo audioStreamInfo = {};
    GetActiveDeviceStreamInfo(DEVICE_TYPE_BLUETOOTH_A2DP, audioStreamInfo);
    uint32_t bufferSize = (audioStreamInfo.samplingRate * GetSampleFormatValue(audioStreamInfo.format) *
        audioStreamInfo.channels) / (PCM_8_BIT * BT_BUFFER_ADJUSTMENT_FACTOR);
    AUDIO_DEBUG_LOG("a2dp rate: %{public}d, format: %{public}d, channel: %{public}d",
        audioStreamInfo.samplingRate, audioStreamInfo.format, audioStreamInfo.channels);
    moduleInfo.channels = to_string(audioStreamInfo.channels);
    moduleInfo.rate = to_string(audioStreamInfo.samplingRate);
    moduleInfo.format = ConvertToHDIAudioFormat(audioStreamInfo.format);
    moduleInfo.bufferSize = to_string(bufferSize);
    moduleInfo.renderInIdleState = "1";
    AudioIOHandle ioHandle = audioPolicyManager_.OpenAudioPort(moduleInfo);
    CHECK_AND_RETURN_RET_LOG(ioHandle != OPEN_PORT_FAILURE, ERR_OPERATION_FAILED,
        "OpenAudioPort failed %{public}d", ioHandle);
    IOHandles_[moduleInfo.name] = ioHandle;
    return SUCCESS;
}

int32_t AudioPolicyService::LoadUsbModule(string deviceInfo)
{
    std::list<AudioModuleInfo> moduleInfoList;
    {
        std::lock_guard<std::mutex> deviceInfoLock(deviceClassInfoMutex_);
        auto usbModulesPos = deviceClassInfo_.find(ClassType::TYPE_USB);
        if (usbModulesPos == deviceClassInfo_.end()) {
            return ERR_OPERATION_FAILED;
        }
        moduleInfoList = usbModulesPos->second;
    }
    for (auto &moduleInfo : moduleInfoList) {
        AUDIO_INFO_LOG("[module_load]::load module[%{public}s]", moduleInfo.name.c_str());
        GetUsbModuleInfo(deviceInfo, moduleInfo);
        OpenPortAndInsertIOHandle(moduleInfo.name, moduleInfo);
    }

    return SUCCESS;
}

int32_t AudioPolicyService::LoadDpModule(string deviceInfo)
{
    AUDIO_INFO_LOG("LoadDpModule");
    std::list<AudioModuleInfo> moduleInfoList;
    {
        std::lock_guard<std::mutex> deviceInfoLock(deviceClassInfoMutex_);
        auto usbModulesPos = deviceClassInfo_.find(ClassType::TYPE_DP);
        if (usbModulesPos == deviceClassInfo_.end()) {
            return ERR_OPERATION_FAILED;
        }
        moduleInfoList = usbModulesPos->second;
    }
    for (auto &moduleInfo : moduleInfoList) {
        AUDIO_INFO_LOG("[module_load]::load module[%{public}s]", moduleInfo.name.c_str());
        if (IOHandles_.find(moduleInfo.name) == IOHandles_.end()) {
            GetDPModuleInfo(moduleInfo, deviceInfo);
            return OpenPortAndInsertIOHandle(moduleInfo.name, moduleInfo);
        }
    }

    return SUCCESS;
}

int32_t AudioPolicyService::LoadDefaultUsbModule()
{
    AUDIO_INFO_LOG("LoadDefaultUsbModule");

    std::list<AudioModuleInfo> moduleInfoList;
    {
        std::lock_guard<std::mutex> deviceInfoLock(deviceClassInfoMutex_);
        auto usbModulesPos = deviceClassInfo_.find(ClassType::TYPE_USB);
        if (usbModulesPos == deviceClassInfo_.end()) {
            return ERR_OPERATION_FAILED;
        }
        moduleInfoList = usbModulesPos->second;
    }
    for (auto &moduleInfo : moduleInfoList) {
        AUDIO_INFO_LOG("[module_load]::load default module[%{public}s]", moduleInfo.name.c_str());
        OpenPortAndInsertIOHandle(moduleInfo.name, moduleInfo);
    }

    return SUCCESS;
}

int32_t AudioPolicyService::HandleActiveDevice(DeviceType deviceType)
{
    if (GetVolumeGroupType(currentActiveDevice_.deviceType_) != GetVolumeGroupType(deviceType)) {
        SetVolumeForSwitchDevice(deviceType);
    }
    if (deviceType == DEVICE_TYPE_USB_HEADSET && isArmUsbDevice_) {
        deviceType = DEVICE_TYPE_USB_ARM_HEADSET;
    }
    if (isUpdateRouteSupported_) {
        UpdateActiveDeviceRoute(deviceType, DeviceFlag::OUTPUT_DEVICES_FLAG);
    }
    std::string sinkPortName = GetSinkPortName(deviceType);
    std::string sourcePortName = GetSourcePortName(deviceType);
    if (sinkPortName == PORT_NONE && sourcePortName == PORT_NONE) {
        AUDIO_ERR_LOG("failed for sinkPortName and sourcePortName are none");
        return ERR_OPERATION_FAILED;
    }
    if (sinkPortName != PORT_NONE) {
        AudioIOHandle ioHandle = GetSinkIOHandle(deviceType);
        audioPolicyManager_.SetDeviceActive(ioHandle, deviceType, sinkPortName, true);
        audioPolicyManager_.SuspendAudioDevice(sinkPortName, false);
    }
    if (sourcePortName != PORT_NONE) {
        AudioIOHandle ioHandle = GetSourceIOHandle(deviceType);
        audioPolicyManager_.SetDeviceActive(ioHandle, deviceType, sourcePortName, true);
        audioPolicyManager_.SuspendAudioDevice(sourcePortName, false);
    }
    UpdateInputDeviceInfo(deviceType);

    return SUCCESS;
}

int32_t AudioPolicyService::HandleA2dpDevice(DeviceType deviceType)
{
    Trace trace("AudioPolicyService::HandleA2dpDevice");
    int32_t ret = LoadA2dpModule(deviceType);
    a2dpOffloadFlag_ = A2DP_NOT_OFFLOAD;
    CHECK_AND_RETURN_RET_LOG(ret == SUCCESS, ERR_OPERATION_FAILED,
        "load A2dp module failed");
    return SUCCESS;
}

int32_t AudioPolicyService::HandleArmUsbDevice(DeviceType deviceType)
{
    Trace trace("AudioPolicyService::HandleArmUsbDevice");

    if (deviceType == DEVICE_TYPE_USB_HEADSET) {
        string deviceInfo = "";
        if (g_adProxy != nullptr) {
            deviceInfo = g_adProxy->GetAudioParameter(LOCAL_NETWORK_ID, USB_DEVICE, "");
            AUDIO_INFO_LOG("device info from usb hal is %{public}s", deviceInfo.c_str());
        }
        int32_t ret;
        if (!deviceInfo.empty()) {
            ret = LoadUsbModule(deviceInfo);
        } else {
            ret = LoadDefaultUsbModule();
        }
        if (ret != SUCCESS) {
            AUDIO_ERR_LOG ("load usb module failed");
            return ERR_OPERATION_FAILED;
        }
        std::string activePort = GetSinkPortName(DEVICE_TYPE_USB_ARM_HEADSET);
        AUDIO_DEBUG_LOG("port %{public}s, active arm usb device", activePort.c_str());
    } else if (currentActiveDevice_.deviceType_ == DEVICE_TYPE_USB_HEADSET) {
        std::string activePort = GetSinkPortName(DEVICE_TYPE_USB_ARM_HEADSET);
        audioPolicyManager_.SuspendAudioDevice(activePort, true);
    }

    return SUCCESS;
}

int32_t AudioPolicyService::GetModuleInfo(ClassType classType, std::string &moduleInfoStr)
{
    std::list<AudioModuleInfo> moduleInfoList;
    {
        std::lock_guard<std::mutex> deviceInfoLock(deviceClassInfoMutex_);
        auto modulesPos = deviceClassInfo_.find(classType);
        if (modulesPos == deviceClassInfo_.end()) {
            AUDIO_ERR_LOG("find %{public}d type failed", classType);
            return ERR_OPERATION_FAILED;
        }
        moduleInfoList = modulesPos->second;
    }
    moduleInfoStr = audioPolicyManager_.GetModuleArgs(*moduleInfoList.begin());
    return SUCCESS;
}

int32_t AudioPolicyService::HandleDpDevice(DeviceType deviceType)
{
    Trace trace("AudioPolicyService::HandleDpDevice");
    if (deviceType == DEVICE_TYPE_DP) {
        std::string defaulyDPInfo = "";
        std::string getDPInfo = "";
        GetModuleInfo(ClassType::TYPE_DP, defaulyDPInfo);
        CHECK_AND_RETURN_RET_LOG(deviceType != DEVICE_TYPE_NONE, ERR_DEVICE_NOT_SUPPORTED, "Invalid device");

        if (g_adProxy != nullptr) {
            getDPInfo = g_adProxy->GetAudioParameter(LOCAL_NETWORK_ID, GET_DP_DEVICE_INFO, defaulyDPInfo);
            AUDIO_DEBUG_LOG("device info from dp hal is \n defaulyDPInfo:%{public}s \n getDPInfo:%{public}s",
                defaulyDPInfo.c_str(), getDPInfo.c_str());
        }
        getDPInfo = getDPInfo.empty() ? defaulyDPInfo : getDPInfo;
        int32_t ret = LoadDpModule(getDPInfo);
        if (ret != SUCCESS) {
            AUDIO_ERR_LOG ("load dp module failed");
            return ERR_OPERATION_FAILED;
        }
        std::string activePort = GetSinkPortName(DEVICE_TYPE_DP);
        AUDIO_INFO_LOG("port %{public}s, active dp device", activePort.c_str());
    } else if (currentActiveDevice_.deviceType_ == DEVICE_TYPE_DP) {
        std::string activePort = GetSinkPortName(DEVICE_TYPE_DP);
        audioPolicyManager_.SuspendAudioDevice(activePort, true);
    }

    return SUCCESS;
}

int32_t AudioPolicyService::HandleFileDevice(DeviceType deviceType)
{
    AUDIO_INFO_LOG("Start");

    std::string sinkPortName = GetSinkPortName(deviceType);
    std::string sourcePortName = GetSourcePortName(deviceType);
    CHECK_AND_RETURN_RET_LOG(sinkPortName != PORT_NONE || sourcePortName != PORT_NONE,
        ERR_OPERATION_FAILED, "failed for sinkPortName and sourcePortName are none");
    if (sinkPortName != PORT_NONE) {
        AudioIOHandle ioHandle = GetSinkIOHandle(deviceType);
        audioPolicyManager_.SetDeviceActive(ioHandle, deviceType, sinkPortName, true);
        audioPolicyManager_.SuspendAudioDevice(sinkPortName, false);
    }
    if (sourcePortName != PORT_NONE) {
        AudioIOHandle ioHandle = GetSourceIOHandle(deviceType);
        audioPolicyManager_.SetDeviceActive(ioHandle, deviceType, sourcePortName, true);
        audioPolicyManager_.SuspendAudioDevice(sourcePortName, false);
    }
    if (isUpdateRouteSupported_) {
        UpdateActiveDeviceRoute(deviceType, DeviceFlag::OUTPUT_DEVICES_FLAG);
    }

    UpdateInputDeviceInfo(deviceType);
    return SUCCESS;
}

int32_t AudioPolicyService::ActivateNormalNewDevice(DeviceType deviceType, bool isSceneActivation = false)
{
    bool isVolumeSwitched = false;
    if (isUpdateRouteSupported_ && !isSceneActivation) {
        if (GetDeviceRole(deviceType) == OUTPUT_DEVICE) {
            int32_t muteDuration = 1200000; // us
            std::string sinkPortName = GetSinkPortName(deviceType);
            CHECK_AND_RETURN_RET_LOG(sinkPortName != PORT_NONE,
                ERR_OPERATION_FAILED,
                "Invalid port %{public}s",
                sinkPortName.c_str());
            std::thread switchThread(&AudioPolicyService::KeepPortMute, this, muteDuration, sinkPortName, deviceType);
            switchThread.detach();
            int32_t beforSwitchDelay = 300000; // 300 ms
            usleep(beforSwitchDelay);
            UpdateActiveDeviceRoute(deviceType, DeviceFlag::OUTPUT_DEVICES_FLAG);
            if (GetVolumeGroupType(currentActiveDevice_.deviceType_) != GetVolumeGroupType(deviceType)) {
                SetVolumeForSwitchDevice(deviceType);
            }
            isVolumeSwitched = true;
        } else {
            UpdateActiveDeviceRoute(deviceType, DeviceFlag::INPUT_DEVICES_FLAG);
        }
    }
    if (GetDeviceRole(deviceType) == OUTPUT_DEVICE && !isVolumeSwitched &&
        GetVolumeGroupType(currentActiveDevice_.deviceType_) != GetVolumeGroupType(deviceType)) {
        SetVolumeForSwitchDevice(deviceType);
    }
    UpdateInputDeviceInfo(deviceType);
    return SUCCESS;
}

void AudioPolicyService::KeepPortMute(int32_t muteDuration, std::string portName, DeviceType deviceType)
{
    Trace trace("AudioPolicyService::KeepPortMute:" + portName + " for " + std::to_string(muteDuration) + "us");
    AUDIO_INFO_LOG("%{public}d us for device type[%{public}d]", muteDuration, deviceType);
    audioPolicyManager_.SetSinkMute(portName, true);
    usleep(muteDuration);
    audioPolicyManager_.SetSinkMute(portName, false);
}

int32_t AudioPolicyService::ActivateNewDevice(std::string networkId, DeviceType deviceType, bool isRemote)
{
    if (isRemote) {
        AudioModuleInfo moduleInfo = ConstructRemoteAudioModuleInfo(networkId, GetDeviceRole(deviceType), deviceType);
        std::string moduleName = GetRemoteModuleName(networkId, GetDeviceRole(deviceType));
        OpenPortAndInsertIOHandle(moduleName, moduleInfo);
    }
    return SUCCESS;
}

int32_t AudioPolicyService::SetDeviceActive(InternalDeviceType deviceType, bool active)
{
    AUDIO_INFO_LOG("Device type[%{public}d] flag[%{public}d]", deviceType, active);
    CHECK_AND_RETURN_RET_LOG(deviceType != DEVICE_TYPE_NONE, ERR_DEVICE_NOT_SUPPORTED, "Invalid device");

    // Activate new device if its already connected
    auto isPresent = [&deviceType] (const sptr<AudioDeviceDescriptor> &desc) {
        CHECK_AND_RETURN_RET_LOG(desc != nullptr, false, "Invalid device descriptor");
        return ((deviceType == desc->deviceType_) || (deviceType == DEVICE_TYPE_FILE_SINK));
    };

    vector<unique_ptr<AudioDeviceDescriptor>> callDevices = GetAvailableDevices(CALL_OUTPUT_DEVICES);
    std::vector<sptr<AudioDeviceDescriptor>> deviceList = {};
    for (auto &desc : callDevices) {
        sptr<AudioDeviceDescriptor> devDesc = new(std::nothrow) AudioDeviceDescriptor(*desc);
        deviceList.push_back(devDesc);
    }

    auto itr = std::find_if(deviceList.begin(), deviceList.end(), isPresent);
    CHECK_AND_RETURN_RET_LOG(itr != deviceList.end(), ERR_OPERATION_FAILED,
        "Requested device not available %{public}d ", deviceType);
    if (!active) {
        audioStateManager_.SetPerferredCallRenderDevice(new(std::nothrow) AudioDeviceDescriptor());
#ifdef BLUETOOTH_ENABLE
        if (currentActiveDevice_.deviceType_ == DEVICE_TYPE_BLUETOOTH_SCO &&
            deviceType == DEVICE_TYPE_BLUETOOTH_SCO) {
            Bluetooth::SendUserSelectionEvent(DEVICE_TYPE_BLUETOOTH_SCO,
                currentActiveDevice_.macAddress_, USER_NOT_SELECT_BT);
            Bluetooth::AudioHfpManager::DisconnectSco();
        }
#endif
    } else {
        audioStateManager_.SetPerferredCallRenderDevice(*itr);
#ifdef BLUETOOTH_ENABLE
        if (currentActiveDevice_.deviceType_ == DEVICE_TYPE_BLUETOOTH_SCO &&
            deviceType != DEVICE_TYPE_BLUETOOTH_SCO) {
            Bluetooth::SendUserSelectionEvent(DEVICE_TYPE_BLUETOOTH_SCO,
                currentActiveDevice_.macAddress_, USER_NOT_SELECT_BT);
            Bluetooth::AudioHfpManager::DisconnectSco();
        }
        if (currentActiveDevice_.deviceType_ != DEVICE_TYPE_BLUETOOTH_SCO &&
            deviceType == DEVICE_TYPE_BLUETOOTH_SCO) {
            Bluetooth::SendUserSelectionEvent(DEVICE_TYPE_BLUETOOTH_SCO,
                (*itr)->macAddress_, USER_SELECT_BT);
        }
#endif
    }
    FetchDevice(true);
    return SUCCESS;
}

bool AudioPolicyService::IsDeviceActive(InternalDeviceType deviceType) const
{
    AUDIO_INFO_LOG("type [%{public}d]", deviceType);
    return currentActiveDevice_.deviceType_ == deviceType;
}

DeviceType AudioPolicyService::GetActiveOutputDevice() const
{
    return currentActiveDevice_.deviceType_;
}

unique_ptr<AudioDeviceDescriptor> AudioPolicyService::GetActiveOutputDeviceDescriptor() const
{
    return make_unique<AudioDeviceDescriptor>(currentActiveDevice_);
}

DeviceType AudioPolicyService::GetActiveInputDevice() const
{
    return currentActiveInputDevice_.deviceType_;
}

int32_t AudioPolicyService::SetRingerMode(AudioRingerMode ringMode)
{
    int32_t result = audioPolicyManager_.SetRingerMode(ringMode);
    if (result == SUCCESS) {
        Volume vol = {false, 1.0f, 0};
        vol.isMute = (ringMode == RINGER_MODE_NORMAL) ? false : true;
        vol.volumeInt = GetSystemVolumeLevel(STREAM_RING);
        vol.volumeFloat = GetSystemVolumeInDb(STREAM_RING, vol.volumeInt, currentActiveDevice_.deviceType_);
        SetSharedVolume(STREAM_RING, currentActiveDevice_.deviceType_, vol);
    }
    return result;
}

AudioRingerMode AudioPolicyService::GetRingerMode() const
{
    return audioPolicyManager_.GetRingerMode();
}

int32_t AudioPolicyService::SetAudioScene(AudioScene audioScene)
{
    AUDIO_INFO_LOG("start %{public}d", audioScene);
    const sptr<IStandardAudioService> gsp = GetAudioServerProxy();
    CHECK_AND_RETURN_RET_LOG(gsp != nullptr, ERR_OPERATION_FAILED, "Service proxy unavailable");

    audioScene_ = audioScene;

    if (audioScene_ == AUDIO_SCENE_DEFAULT) {
        audioStateManager_.SetPerferredCallRenderDevice(new(std::nothrow) AudioDeviceDescriptor());
        audioStateManager_.SetPerferredCallCaptureDevice(new(std::nothrow) AudioDeviceDescriptor());
#ifdef BLUETOOTH_ENABLE
        Bluetooth::AudioHfpManager::DisconnectSco();
#endif
        ClearScoDeviceSuspendState();
    }

    // fetch input&output device
    FetchDevice(true);
    FetchDevice(false);

    int32_t result = SUCCESS;
    if (currentActiveDevice_.deviceType_ == DEVICE_TYPE_USB_HEADSET && isArmUsbDevice_) {
        std::string identity = IPCSkeleton::ResetCallingIdentity();
        result = gsp->SetAudioScene(audioScene, DEVICE_TYPE_USB_ARM_HEADSET, DEVICE_TYPE_USB_ARM_HEADSET);
        IPCSkeleton::SetCallingIdentity(identity);
    } else {
        std::string identity = IPCSkeleton::ResetCallingIdentity();
        result = gsp->SetAudioScene(audioScene, currentActiveDevice_.deviceType_,
            currentActiveInputDevice_.deviceType_);
        IPCSkeleton::SetCallingIdentity(identity);
    }
    CHECK_AND_RETURN_RET_LOG(result == SUCCESS, ERR_OPERATION_FAILED, "failed [%{public}d]", result);

    if (audioScene_ == AUDIO_SCENE_PHONE_CALL) {
        // Make sure the STREAM_VOICE_CALL volume is set before the calling starts.
        SetVoiceCallVolume(GetSystemVolumeLevel(STREAM_VOICE_CALL));
    }

    return SUCCESS;
}

void AudioPolicyService::AddEarpiece()
{
    if (!hasEarpiece_) {
        return;
    }
    sptr<AudioDeviceDescriptor> audioDescriptor =
        new (std::nothrow) AudioDeviceDescriptor(DEVICE_TYPE_EARPIECE, OUTPUT_DEVICE);
    // Use speaker streaminfo for earpiece cap
    auto itr = std::find_if(connectedDevices_.begin(), connectedDevices_.end(),
        [](const sptr<AudioDeviceDescriptor> &devDesc) {
        CHECK_AND_RETURN_RET_LOG(devDesc != nullptr, false, "Invalid device descriptor");
        return (devDesc->deviceType_ == DEVICE_TYPE_SPEAKER);
    });
    if (itr != connectedDevices_.end()) {
        audioDescriptor->SetDeviceCapability((*itr)->audioStreamInfo_, 0);
    }
    audioDescriptor->deviceId_ = startDeviceId++;
    UpdateDisplayName(audioDescriptor);
    audioDeviceManager_.AddNewDevice(audioDescriptor);
    std::lock_guard<std::mutex> lock(deviceStatusUpdateSharedMutex_);
    connectedDevices_.insert(connectedDevices_.begin(), audioDescriptor);
    AUDIO_INFO_LOG("Add earpiece to device list");
}

AudioScene AudioPolicyService::GetAudioScene(bool hasSystemPermission) const
{
    AUDIO_DEBUG_LOG("return value: %{public}d", audioScene_);
    if (!hasSystemPermission) {
        switch (audioScene_) {
            case AUDIO_SCENE_RINGING:
            case AUDIO_SCENE_PHONE_CALL:
                return AUDIO_SCENE_DEFAULT;
            default:
                break;
        }
    }
    return audioScene_;
}

void AudioPolicyService::OnUpdateRouteSupport(bool isSupported)
{
    isUpdateRouteSupported_ = isSupported;
}

bool AudioPolicyService::GetActiveDeviceStreamInfo(DeviceType deviceType, AudioStreamInfo &streamInfo)
{
    std::lock_guard<std::mutex> lock(a2dpDeviceMapMutex_);
    if (deviceType == DEVICE_TYPE_BLUETOOTH_A2DP) {
        auto configInfoPos = connectedA2dpDeviceMap_.find(activeBTDevice_);
        if (configInfoPos != connectedA2dpDeviceMap_.end()) {
            streamInfo.samplingRate = *configInfoPos->second.streamInfo.samplingRate.rbegin();
            streamInfo.format = configInfoPos->second.streamInfo.format;
            streamInfo.channels = *configInfoPos->second.streamInfo.channels.rbegin();
            return true;
        }
    }

    return false;
}

bool AudioPolicyService::IsConfigurationUpdated(DeviceType deviceType, const AudioStreamInfo &streamInfo)
{
    if (deviceType == DEVICE_TYPE_BLUETOOTH_A2DP) {
        AudioStreamInfo audioStreamInfo = {};
        if (GetActiveDeviceStreamInfo(deviceType, audioStreamInfo)) {
            AUDIO_DEBUG_LOG("Device configurations current rate: %{public}d, format: %{public}d, channel: %{public}d",
                audioStreamInfo.samplingRate, audioStreamInfo.format, audioStreamInfo.channels);
            AUDIO_DEBUG_LOG("Device configurations updated rate: %{public}d, format: %{public}d, channel: %{public}d",
                streamInfo.samplingRate, streamInfo.format, streamInfo.channels);
            if ((audioStreamInfo.samplingRate != streamInfo.samplingRate)
                || (audioStreamInfo.channels != streamInfo.channels)
                || (audioStreamInfo.format != streamInfo.format)) {
                return true;
            }
        }
    }

    return false;
}

void AudioPolicyService::UpdateConnectedDevicesWhenConnectingForOutputDevice(
    const AudioDeviceDescriptor &updatedDesc, std::vector<sptr<AudioDeviceDescriptor>> &descForCb)
{
    AUDIO_INFO_LOG("Filling output device for %{public}d", updatedDesc.deviceType_);

    sptr<AudioDeviceDescriptor> audioDescriptor = new(std::nothrow) AudioDeviceDescriptor(updatedDesc);
    audioDescriptor->deviceRole_ = OUTPUT_DEVICE;
    // Use speaker streaminfo for all output devices cap
    auto itr = std::find_if(connectedDevices_.begin(), connectedDevices_.end(),
        [](const sptr<AudioDeviceDescriptor> &devDesc) {
        CHECK_AND_RETURN_RET_LOG(devDesc != nullptr, false, "Invalid device descriptor");
        return (devDesc->deviceType_ == DEVICE_TYPE_SPEAKER);
    });
    if (itr != connectedDevices_.end()) {
        audioDescriptor->SetDeviceCapability((*itr)->audioStreamInfo_, 0);
    }

    audioDescriptor->deviceId_ = startDeviceId++;
    descForCb.push_back(audioDescriptor);
    UpdateDisplayName(audioDescriptor);
    connectedDevices_.insert(connectedDevices_.begin(), audioDescriptor);
    audioDeviceManager_.AddNewDevice(audioDescriptor);

    DeviceUsage usage = GetDeviceUsage(updatedDesc);
    if (audioDescriptor->deviceCategory_ != BT_UNWEAR_HEADPHONE && (usage == MEDIA || usage == ALL_USAGE)) {
        audioStateManager_.SetPerferredMediaRenderDevice(new(std::nothrow) AudioDeviceDescriptor());
    }
    if (audioDescriptor->deviceCategory_ != BT_UNWEAR_HEADPHONE && (usage == VOICE || usage == ALL_USAGE)) {
        audioStateManager_.SetPerferredCallRenderDevice(new(std::nothrow) AudioDeviceDescriptor());
    }
}

void AudioPolicyService::UpdateConnectedDevicesWhenConnectingForInputDevice(
    const AudioDeviceDescriptor &updatedDesc, std::vector<sptr<AudioDeviceDescriptor>> &descForCb)
{
    AUDIO_INFO_LOG("Filling input device for %{public}d", updatedDesc.deviceType_);

    sptr<AudioDeviceDescriptor> audioDescriptor = new(std::nothrow) AudioDeviceDescriptor(updatedDesc);
    audioDescriptor->deviceRole_ = INPUT_DEVICE;
    // Use mic streaminfo for all input devices cap
    auto itr = std::find_if(connectedDevices_.begin(), connectedDevices_.end(),
        [](const sptr<AudioDeviceDescriptor> &devDesc) {
        CHECK_AND_RETURN_RET_LOG(devDesc != nullptr, false, "Invalid device descriptor");
        return (devDesc->deviceType_ == DEVICE_TYPE_MIC);
    });
    if (itr != connectedDevices_.end()) {
        audioDescriptor->SetDeviceCapability((*itr)->audioStreamInfo_, 0);
    }

    audioDescriptor->deviceId_ = startDeviceId++;
    descForCb.push_back(audioDescriptor);
    UpdateDisplayName(audioDescriptor);
    connectedDevices_.insert(connectedDevices_.begin(), audioDescriptor);
    AddMicrophoneDescriptor(audioDescriptor);
    audioDeviceManager_.AddNewDevice(audioDescriptor);
    if (audioDescriptor->deviceCategory_ != BT_UNWEAR_HEADPHONE) {
        audioStateManager_.SetPerferredCallCaptureDevice(new(std::nothrow) AudioDeviceDescriptor());
        audioStateManager_.SetPerferredRecordCaptureDevice(new(std::nothrow) AudioDeviceDescriptor());
    }
}

void AudioPolicyService::UpdateConnectedDevicesWhenConnecting(const AudioDeviceDescriptor &updatedDesc,
    std::vector<sptr<AudioDeviceDescriptor>> &descForCb)
{
    AUDIO_INFO_LOG("UpdateConnectedDevicesWhenConnecting In, deviceType: %{public}d", updatedDesc.deviceType_);
    if (IsOutputDevice(updatedDesc.deviceType_)) {
        UpdateConnectedDevicesWhenConnectingForOutputDevice(updatedDesc, descForCb);
    }
    if (IsInputDevice(updatedDesc.deviceType_)) {
        UpdateConnectedDevicesWhenConnectingForInputDevice(updatedDesc, descForCb);
    }
}

void AudioPolicyService::UpdateConnectedDevicesWhenDisconnecting(const AudioDeviceDescriptor& updatedDesc,
    std::vector<sptr<AudioDeviceDescriptor>> &descForCb)
{
    AUDIO_INFO_LOG("[%{public}s], devType:[%{public}d]", __func__, updatedDesc.deviceType_);
    auto isPresent = [&updatedDesc](const sptr<AudioDeviceDescriptor>& descriptor) {
        return descriptor->deviceType_ == updatedDesc.deviceType_ &&
            descriptor->macAddress_ == updatedDesc.macAddress_ &&
            descriptor->networkId_ == updatedDesc.networkId_;
    };

    // Remember the disconnected device descriptor and remove it
    for (auto it = connectedDevices_.begin(); it != connectedDevices_.end();) {
        it = find_if(it, connectedDevices_.end(), isPresent);
        if (it != connectedDevices_.end()) {
            if ((*it)->deviceId_ == audioStateManager_.GetPerferredMediaRenderDevice()->deviceId_) {
                audioStateManager_.SetPerferredMediaRenderDevice(new(std::nothrow) AudioDeviceDescriptor());
            }
            if ((*it)->deviceId_ == audioStateManager_.GetPerferredCallRenderDevice()->deviceId_) {
                audioStateManager_.SetPerferredCallRenderDevice(new(std::nothrow) AudioDeviceDescriptor());
            }
            if ((*it)->deviceId_ == audioStateManager_.GetPerferredCallCaptureDevice()->deviceId_) {
                audioStateManager_.SetPerferredCallCaptureDevice(new(std::nothrow) AudioDeviceDescriptor());
            }
            if ((*it)->deviceId_ == audioStateManager_.GetPerferredRecordCaptureDevice()->deviceId_) {
                audioStateManager_.SetPerferredRecordCaptureDevice(new(std::nothrow) AudioDeviceDescriptor());
            }
            descForCb.push_back(*it);
            it = connectedDevices_.erase(it);
        }
    }

    sptr<AudioDeviceDescriptor> devDesc = new (std::nothrow) AudioDeviceDescriptor(updatedDesc);
    audioDeviceManager_.RemoveNewDevice(devDesc);
    RemoveMicrophoneDescriptor(devDesc);
    if (updatedDesc.deviceType_ == DEVICE_TYPE_BLUETOOTH_A2DP) {
        a2dpOffloadFlag_ = NO_A2DP_DEVICE;
    }
}

void AudioPolicyService::OnPnpDeviceStatusUpdated(DeviceType devType, bool isConnected)
{
    CHECK_AND_RETURN_LOG(devType != DEVICE_TYPE_NONE, "devType is none type");
    if (!hasModulesLoaded) {
        AUDIO_WARNING_LOG("modules has not loaded");
        pnpDeviceList_.push_back({devType, isConnected});
        return;
    }
    if (g_adProxy == nullptr) {
        GetAudioServerProxy();
    }
    AudioStreamInfo streamInfo = {};
    OnDeviceStatusUpdated(devType, isConnected, "", "", streamInfo);
}

void AudioPolicyService::UpdateLocalGroupInfo(bool isConnected, const std::string& macAddress,
    const std::string& deviceName, const DeviceStreamInfo& streamInfo, AudioDeviceDescriptor& deviceDesc)
{
    deviceDesc.SetDeviceInfo(deviceName, macAddress);
    deviceDesc.SetDeviceCapability(streamInfo, 0);
    UpdateGroupInfo(VOLUME_TYPE, GROUP_NAME_DEFAULT, deviceDesc.volumeGroupId_, LOCAL_NETWORK_ID, isConnected,
        NO_REMOTE_ID);
    UpdateGroupInfo(INTERRUPT_TYPE, GROUP_NAME_DEFAULT, deviceDesc.interruptGroupId_, LOCAL_NETWORK_ID, isConnected,
        NO_REMOTE_ID);
    deviceDesc.networkId_ = LOCAL_NETWORK_ID;
}

int32_t AudioPolicyService::HandleLocalDeviceConnected(const AudioDeviceDescriptor &updatedDesc)
{
    AUDIO_INFO_LOG("macAddress:[%{public}s]", GetEncryptAddr(updatedDesc.macAddress_).c_str());
    {
        std::lock_guard<std::mutex> lock(a2dpDeviceMapMutex_);
        if (updatedDesc.deviceType_ == DEVICE_TYPE_BLUETOOTH_A2DP) {
            A2dpDeviceConfigInfo configInfo = {updatedDesc.audioStreamInfo_, false};
            connectedA2dpDeviceMap_.insert(make_pair(updatedDesc.macAddress_, configInfo));
            sameDeviceSwitchFlag_ = true;
        }
    }

    if (isArmUsbDevice_ && updatedDesc.deviceType_ == DEVICE_TYPE_USB_HEADSET) {
        int32_t result = HandleArmUsbDevice(updatedDesc.deviceType_);
        return result;
    }

    if (updatedDesc.deviceType_ == DEVICE_TYPE_DP) {
        int32_t result = HandleDpDevice(updatedDesc.deviceType_);
        return result;
    }

    return SUCCESS;
}

int32_t AudioPolicyService::HandleLocalDeviceDisconnected(const AudioDeviceDescriptor &updatedDesc)
{
    if (updatedDesc.deviceType_ == DEVICE_TYPE_BLUETOOTH_A2DP) {
        UpdateActiveA2dpDeviceWhenDisconnecting(updatedDesc.macAddress_);
    }

    if (updatedDesc.deviceType_ == DEVICE_TYPE_USB_HEADSET && isArmUsbDevice_) {
        ClosePortAndEraseIOHandle(USB_SPEAKER);
        ClosePortAndEraseIOHandle(USB_MIC);
    }
    if (updatedDesc.deviceType_ == DEVICE_TYPE_DP) {
        ClosePortAndEraseIOHandle(DP_SINK);
    }

    CHECK_AND_RETURN_RET_LOG(g_adProxy != nullptr, ERROR, "Audio Server Proxy is null");
    g_adProxy->ResetRouteForDisconnect(updatedDesc.deviceType_);

    return SUCCESS;
}

void AudioPolicyService::UpdateActiveA2dpDeviceWhenDisconnecting(const std::string& macAddress)
{
    std::unique_lock<std::mutex> lock(a2dpDeviceMapMutex_);
    connectedA2dpDeviceMap_.erase(macAddress);

    if (connectedA2dpDeviceMap_.size() == 0) {
        activeBTDevice_ = "";
        ClosePortAndEraseIOHandle(BLUETOOTH_SPEAKER);
        audioPolicyManager_.SetAbsVolumeScene(false);
#ifdef BLUETOOTH_ENABLE
        Bluetooth::AudioA2dpManager::SetActiveA2dpDevice("");
#endif
        return;
    }
}

DeviceType AudioPolicyService::FindConnectedHeadset()
{
    DeviceType retType = DEVICE_TYPE_NONE;
    for (const auto& devDesc: connectedDevices_) {
        if ((devDesc->deviceType_ == DEVICE_TYPE_WIRED_HEADSET) ||
            (devDesc->deviceType_ == DEVICE_TYPE_WIRED_HEADPHONES) ||
            (devDesc->deviceType_ == DEVICE_TYPE_USB_HEADSET) ||
            (devDesc->deviceType_ == DEVICE_TYPE_DP) ||
            (devDesc->deviceType_ == DEVICE_TYPE_USB_ARM_HEADSET)) {
            retType = devDesc->deviceType_;
            break;
        }
    }
    return retType;
}

int32_t AudioPolicyService::HandleSpecialDeviceType(DeviceType &devType, bool &isConnected)
{
    // usb device needs to be distinguished form arm or hifi
    if (devType == DEVICE_TYPE_USB_HEADSET && isConnected) {
        if (g_adProxy == nullptr) {
            return ERROR;
        }
        const std::string value = g_adProxy->GetAudioParameter("need_change_usb_device");
        AUDIO_INFO_LOG("get value %{public}s  from hal when usb device connect", value.c_str());
        if (value == "false") {
            isArmUsbDevice_ = true;
        }
    }

    // Special logic for extern cable, need refactor
    if (devType == DEVICE_TYPE_EXTERN_CABLE) {
        CHECK_AND_RETURN_RET_LOG(isConnected, ERROR, "Extern cable disconnected, do nothing");
        DeviceType connectedHeadsetType = FindConnectedHeadset();
        if (connectedHeadsetType == DEVICE_TYPE_NONE) {
            AUDIO_INFO_LOG("Extern cable connect without headset connected before, do nothing");
            return ERROR;
        }
        devType = connectedHeadsetType;
        isConnected = false;
    }

    return SUCCESS;
}

void AudioPolicyService::ResetToSpeaker(DeviceType devType)
{
    if (devType != currentActiveDevice_.deviceType_) {
        return;
    }
    if (devType == DEVICE_TYPE_BLUETOOTH_SCO || (devType == DEVICE_TYPE_USB_HEADSET && !isArmUsbDevice_) ||
        devType == DEVICE_TYPE_WIRED_HEADSET || devType == DEVICE_TYPE_WIRED_HEADPHONES) {
        UpdateActiveDeviceRoute(DEVICE_TYPE_SPEAKER, DeviceFlag::OUTPUT_DEVICES_FLAG);
    }
}

void AudioPolicyService::OnDeviceStatusUpdated(DeviceType devType, bool isConnected, const std::string& macAddress,
    const std::string& deviceName, const AudioStreamInfo& streamInfo)
{
    // Pnp device status update
    AUDIO_INFO_LOG("Device connection state updated | TYPE[%{public}d] STATUS[%{public}d]", devType, isConnected);

    AudioStreamDeviceChangeReason reason;
    // fill device change action for callback
    std::vector<sptr<AudioDeviceDescriptor>> descForCb = {};

    {
        std::lock_guard<std::mutex> lock(deviceStatusUpdateSharedMutex_);

        int32_t result = ERROR;
        result = HandleSpecialDeviceType(devType, isConnected);
        CHECK_AND_RETURN_LOG(result == SUCCESS, "handle special deviceType failed.");
        AudioDeviceDescriptor updatedDesc(devType, GetDeviceRole(devType));
        UpdateLocalGroupInfo(isConnected, macAddress, deviceName, streamInfo, updatedDesc);

        auto isPresent = [&updatedDesc] (const sptr<AudioDeviceDescriptor> &descriptor) {
            return descriptor->deviceType_ == updatedDesc.deviceType_ &&
                descriptor->macAddress_ == updatedDesc.macAddress_ &&
                descriptor->networkId_ == updatedDesc.networkId_;
        };
        if (isConnected) {
            // If device already in list, remove it else do not modify the list
            connectedDevices_.erase(std::remove_if(connectedDevices_.begin(), connectedDevices_.end(), isPresent),
                connectedDevices_.end());
            UpdateConnectedDevicesWhenConnecting(updatedDesc, descForCb);
            result = HandleLocalDeviceConnected(updatedDesc);
            CHECK_AND_RETURN_LOG(result == SUCCESS, "Connect local device failed.");
            reason = AudioStreamDeviceChangeReason::NEW_DEVICE_AVAILABLE;
        } else {
            UpdateConnectedDevicesWhenDisconnecting(updatedDesc, descForCb);
            result = HandleLocalDeviceDisconnected(updatedDesc);
            if (devType == DEVICE_TYPE_USB_HEADSET && isArmUsbDevice_) {
                isArmUsbDevice_ = false;
            }
            CHECK_AND_RETURN_LOG(result == SUCCESS, "Disconnect local device failed.");
            reason = AudioStreamDeviceChangeReason::OLD_DEVICE_UNAVALIABLE;
        }
    }

    TriggerDeviceChangedCallback(descForCb, isConnected);
    TriggerAvailableDeviceChangedCallback(descForCb, isConnected);

    // fetch input&output device
    FetchDevice(true, reason);
    FetchDevice(false);

    // update a2dp offload
    UpdateA2dpOffloadFlagForAllStream();
}

void AudioPolicyService::OnDeviceStatusUpdated(AudioDeviceDescriptor &updatedDesc, bool isConnected)
{
    // Bluetooth device status updated
    DeviceType devType = updatedDesc.deviceType_;
    string macAddress = updatedDesc.macAddress_;
    string deviceName = updatedDesc.deviceName_;

    AudioStreamInfo streamInfo = {};
#ifdef BLUETOOTH_ENABLE
    if (devType == DEVICE_TYPE_BLUETOOTH_A2DP && isConnected) {
        int32_t ret = Bluetooth::AudioA2dpManager::GetA2dpDeviceStreamInfo(macAddress, streamInfo);
        CHECK_AND_RETURN_LOG(ret == SUCCESS, "Get a2dp device stream info failed!");
    }
#endif

    AUDIO_INFO_LOG("Device connection state updated | TYPE[%{public}d] STATUS[%{public}d]", devType, isConnected);
    AudioStreamDeviceChangeReason reason;
    // fill device change action for callback
    std::vector<sptr<AudioDeviceDescriptor>> descForCb = {};

    {
        std::lock_guard<std::mutex> lock(deviceStatusUpdateSharedMutex_);

        UpdateLocalGroupInfo(isConnected, macAddress, deviceName, streamInfo, updatedDesc);

        auto isPresent = [&updatedDesc] (const sptr<AudioDeviceDescriptor> &descriptor) {
            return descriptor->deviceType_ == updatedDesc.deviceType_ &&
                descriptor->macAddress_ == updatedDesc.macAddress_ &&
                descriptor->networkId_ == updatedDesc.networkId_;
        };
        if (isConnected) {
            // If device already in list, remove it else do not modify the list
            connectedDevices_.erase(std::remove_if(connectedDevices_.begin(), connectedDevices_.end(), isPresent),
                connectedDevices_.end());
            UpdateConnectedDevicesWhenConnecting(updatedDesc, descForCb);
            int32_t result = HandleLocalDeviceConnected(updatedDesc);
            CHECK_AND_RETURN_LOG(result == SUCCESS, "Connect local device failed.");
            reason = AudioStreamDeviceChangeReason::NEW_DEVICE_AVAILABLE;
        } else {
            UpdateConnectedDevicesWhenDisconnecting(updatedDesc, descForCb);
            int32_t result = HandleLocalDeviceDisconnected(updatedDesc);
            CHECK_AND_RETURN_LOG(result == SUCCESS, "Disconnect local device failed.");
            reason = AudioStreamDeviceChangeReason::OLD_DEVICE_UNAVALIABLE;
        }
    }

    TriggerDeviceChangedCallback(descForCb, isConnected);
    TriggerAvailableDeviceChangedCallback(descForCb, isConnected);

    // fetch input&output device
    FetchDevice(true, reason);
    FetchDevice(false);

    // update a2dp offload
    UpdateA2dpOffloadFlagForAllStream();
}

#ifdef FEATURE_DTMF_TONE
std::vector<int32_t> AudioPolicyService::GetSupportedTones()
{
    std::vector<int> supportedToneList = {};
    for (auto i = toneDescriptorMap.begin(); i != toneDescriptorMap.end(); i++) {
        supportedToneList.push_back(i->first);
    }
    return supportedToneList;
}

std::shared_ptr<ToneInfo> AudioPolicyService::GetToneConfig(int32_t ltonetype)
{
    if (toneDescriptorMap.find(ltonetype) == toneDescriptorMap.end()) {
        return nullptr;
    }
    AUDIO_DEBUG_LOG("tonetype %{public}d", ltonetype);
    return toneDescriptorMap[ltonetype];
}
#endif

void AudioPolicyService::UpdateA2dpOffloadFlagBySpatialService(
    const std::string& macAddress, std::unordered_map<uint32_t, bool> &sessionIDToSpatializationEnableMap)
{
    auto it = spatialDeviceMap_.find(macAddress);
    DeviceType spatialDevice;
    if (it != spatialDeviceMap_.end()) {
        spatialDevice = it->second;
    } else {
        AUDIO_DEBUG_LOG("we can't find the spatialDevice of hvs");
        spatialDevice = DEVICE_TYPE_NONE;
    }
    AUDIO_INFO_LOG("Update a2dpOffloadFlag spatialDevice: %{public}d", spatialDevice);
    UpdateA2dpOffloadFlagForAllStream(sessionIDToSpatializationEnableMap, spatialDevice);
}

void AudioPolicyService::UpdateA2dpOffloadFlagForAllStream(
    std::unordered_map<uint32_t, bool> &sessionIDToSpatializationEnableMap, DeviceType deviceType)
{
#ifdef BLUETOOTH_ENABLE
    vector<Bluetooth::A2dpStreamInfo> allSessionInfos;
    Bluetooth::A2dpStreamInfo a2dpStreamInfo;
    vector<unique_ptr<AudioRendererChangeInfo>> audioRendererChangeInfos;
    streamCollector_.GetCurrentRendererChangeInfos(audioRendererChangeInfos);
    std::vector<int32_t> stopPlayingStream(0);
    for (auto &changeInfo : audioRendererChangeInfos) {
        if (changeInfo->rendererState != RENDERER_RUNNING) {
            stopPlayingStream.emplace_back(changeInfo->sessionId);
            continue;
        }
        a2dpStreamInfo.sessionId = changeInfo->sessionId;
        a2dpStreamInfo.streamType = GetStreamType(changeInfo->sessionId);
        if (sessionIDToSpatializationEnableMap.count(static_cast<uint32_t>(a2dpStreamInfo.sessionId))) {
            a2dpStreamInfo.isSpatialAudio =
                sessionIDToSpatializationEnableMap[static_cast<uint32_t>(a2dpStreamInfo.sessionId)];
        } else {
            a2dpStreamInfo.isSpatialAudio = 0;
        }
        allSessionInfos.push_back(a2dpStreamInfo);
    }
    if (stopPlayingStream.size() > 0) {
        OffloadStopPlaying(stopPlayingStream);
    }
    UpdateAllActiveSessions(allSessionInfos);
    UpdateA2dpOffloadFlag(allSessionInfos, deviceType);
#endif
    AUDIO_DEBUG_LOG("deviceType %{public}d", deviceType);
}

void AudioPolicyService::UpdateA2dpOffloadFlagForAllStream(DeviceType deviceType)
{
#ifdef BLUETOOTH_ENABLE
    vector<Bluetooth::A2dpStreamInfo> allSessionInfos;
    Bluetooth::A2dpStreamInfo a2dpStreamInfo;
    vector<unique_ptr<AudioRendererChangeInfo>> audioRendererChangeInfos;
    streamCollector_.GetCurrentRendererChangeInfos(audioRendererChangeInfos);
    {
        AudioXCollie audioXCollie("AudioPolicyService::UpdateA2dpOffloadFlagForAllStream", BLUETOOTH_TIME_OUT_SECONDS);
        std::vector<int32_t> stopPlayingStream(0);
        for (auto &changeInfo : audioRendererChangeInfos) {
            if (changeInfo->rendererState != RENDERER_RUNNING) {
                stopPlayingStream.emplace_back(changeInfo->sessionId);
                continue;
            }
            a2dpStreamInfo.sessionId = changeInfo->sessionId;
            a2dpStreamInfo.streamType = GetStreamType(changeInfo->sessionId);
            StreamUsage tempStreamUsage = changeInfo->rendererInfo.streamUsage;
            AudioSpatializationState spatialState =
                AudioSpatializationService::GetAudioSpatializationService().GetSpatializationState(tempStreamUsage);
            a2dpStreamInfo.isSpatialAudio = spatialState.spatializationEnabled;
            allSessionInfos.push_back(a2dpStreamInfo);
        }
        if (stopPlayingStream.size() > 0) {
            OffloadStopPlaying(stopPlayingStream);
        }
    }
    UpdateAllActiveSessions(allSessionInfos);
    UpdateA2dpOffloadFlag(allSessionInfos, deviceType);
#endif
    AUDIO_DEBUG_LOG("deviceType %{public}d", deviceType);
}

void AudioPolicyService::OnDeviceConfigurationChanged(DeviceType deviceType, const std::string &macAddress,
    const std::string &deviceName, const AudioStreamInfo &streamInfo)
{
    AUDIO_INFO_LOG("OnDeviceConfigurationChanged start, deviceType: %{public}d, currentActiveDevice_: %{public}d, "
        "macAddress:[%{public}s], activeBTDevice_:[%{public}s]", deviceType, currentActiveDevice_.deviceType_,
        GetEncryptAddr(macAddress).c_str(), GetEncryptAddr(activeBTDevice_).c_str());
    // only for the active a2dp device.
    if ((deviceType == DEVICE_TYPE_BLUETOOTH_A2DP) && !macAddress.compare(activeBTDevice_)
        && IsDeviceActive(deviceType)) {
        UpdateA2dpOffloadFlagForAllStream();
        if (!IsConfigurationUpdated(deviceType, streamInfo)) {
            AUDIO_DEBUG_LOG("Audio configuration same");
            lastBTDevice_ = macAddress;
            return;
        }

        uint32_t bufferSize = (streamInfo.samplingRate * GetSampleFormatValue(streamInfo.format)
            * streamInfo.channels) / (PCM_8_BIT * BT_BUFFER_ADJUSTMENT_FACTOR);
        AUDIO_DEBUG_LOG("Updated buffer size: %{public}d", bufferSize);
        connectedA2dpDeviceMap_[macAddress].streamInfo = streamInfo;
        if (a2dpOffloadFlag_ != A2DP_OFFLOAD) {
            ReloadA2dpOffloadOnDeviceChanged(deviceType, macAddress, deviceName, streamInfo);
        }
    } else if (connectedA2dpDeviceMap_.find(macAddress) != connectedA2dpDeviceMap_.end()) {
        AUDIO_DEBUG_LOG("Audio configuration update, macAddress:[%{public}s]", GetEncryptAddr(macAddress).c_str());
        connectedA2dpDeviceMap_[macAddress].streamInfo = streamInfo;
    }
    lastBTDevice_ = macAddress;
}

void AudioPolicyService::ReloadA2dpOffloadOnDeviceChanged(DeviceType deviceType, const std::string &macAddress,
    const std::string &deviceName, const AudioStreamInfo &streamInfo)
{
    uint32_t bufferSize = (streamInfo.samplingRate * GetSampleFormatValue(streamInfo.format)
        * streamInfo.channels) / (PCM_8_BIT * BT_BUFFER_ADJUSTMENT_FACTOR);

    auto a2dpModulesPos = deviceClassInfo_.find(ClassType::TYPE_A2DP);
    if (a2dpModulesPos != deviceClassInfo_.end()) {
        auto moduleInfoList = a2dpModulesPos->second;
        for (auto &moduleInfo : moduleInfoList) {
            std::lock_guard<std::mutex> ioHandleLock(ioHandlesMutex_);
            if (IOHandles_.find(moduleInfo.name) != IOHandles_.end()) {
                moduleInfo.channels = to_string(streamInfo.channels);
                moduleInfo.rate = to_string(streamInfo.samplingRate);
                moduleInfo.format = ConvertToHDIAudioFormat(streamInfo.format);
                moduleInfo.bufferSize = to_string(bufferSize);

                // First unload the existing bt sink
                AUDIO_DEBUG_LOG("UnLoad existing a2dp module");
                std::string currentActivePort = GetSinkPortName(currentActiveDevice_.deviceType_);
                AudioIOHandle activateDeviceIOHandle = IOHandles_[BLUETOOTH_SPEAKER];
                audioPolicyManager_.SuspendAudioDevice(currentActivePort, true);
                audioPolicyManager_.CloseAudioPort(activateDeviceIOHandle);

                // Load bt sink module again with new configuration
                AUDIO_DEBUG_LOG("Reload a2dp module [%{public}s]", moduleInfo.name.c_str());
                AudioIOHandle ioHandle = audioPolicyManager_.OpenAudioPort(moduleInfo);
                CHECK_AND_RETURN_LOG(ioHandle != OPEN_PORT_FAILURE, "OpenAudioPort failed %{public}d", ioHandle);
                IOHandles_[moduleInfo.name] = ioHandle;
                std::string portName = GetSinkPortName(deviceType);
                audioPolicyManager_.SetDeviceActive(ioHandle, deviceType, portName, true);
                audioPolicyManager_.SuspendAudioDevice(portName, false);

                auto isPresent = [&macAddress] (const sptr<AudioDeviceDescriptor> &descriptor) {
                    return descriptor->macAddress_ == macAddress;
                };

                sptr<AudioDeviceDescriptor> audioDescriptor
                    = new(std::nothrow) AudioDeviceDescriptor(deviceType, OUTPUT_DEVICE);
                audioDescriptor->SetDeviceInfo(deviceName, macAddress);
                audioDescriptor->SetDeviceCapability(streamInfo, 0);
                std::replace_if(connectedDevices_.begin(), connectedDevices_.end(), isPresent, audioDescriptor);
                break;
            }
        }
    }
}

void AudioPolicyService::RemoveDeviceInRouterMap(std::string networkId)
{
    std::lock_guard<std::mutex> lock(routerMapMutex_);
    std::unordered_map<int32_t, std::pair<std::string, int32_t>>::iterator it;
    for (it = routerMap_.begin();it != routerMap_.end();) {
        if (it->second.first == networkId) {
            routerMap_.erase(it++);
        } else {
            it++;
        }
    }
}

void AudioPolicyService::RemoveDeviceInFastRouterMap(std::string networkId)
{
    std::lock_guard<std::mutex> lock(routerMapMutex_);
    std::unordered_map<int32_t, std::pair<std::string, DeviceRole>>::iterator it;
    for (it = fastRouterMap_.begin();it != fastRouterMap_.end();) {
        if (it->second.first == networkId) {
            fastRouterMap_.erase(it++);
        } else {
            it++;
        }
    }
}

void AudioPolicyService::SetDisplayName(const std::string &deviceName, bool isLocalDevice)
{
    for (const auto& deviceInfo : connectedDevices_) {
        if ((isLocalDevice && deviceInfo->networkId_ == LOCAL_NETWORK_ID) ||
            (!isLocalDevice && deviceInfo->networkId_ != LOCAL_NETWORK_ID)) {
            deviceInfo->displayName_ = deviceName;
        }
    }
}

void AudioPolicyService::RegisterRemoteDevStatusCallback()
{
#ifdef FEATURE_DEVICE_MANAGER
    AUDIO_INFO_LOG("Start");
    std::shared_ptr<DistributedHardware::DmInitCallback> initCallback = std::make_shared<DeviceInitCallBack>();
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().InitDeviceManager(AUDIO_SERVICE_PKG, initCallback);
    CHECK_AND_RETURN_LOG(ret == SUCCESS, "Init device manage failed");
    std::shared_ptr<DistributedHardware::DeviceStatusCallback> callback = std::make_shared<DeviceStatusCallbackImpl>();
    DistributedHardware::DeviceManager::GetInstance().RegisterDevStatusCallback(AUDIO_SERVICE_PKG, "", callback);
#endif
}

std::shared_ptr<DataShare::DataShareHelper> AudioPolicyService::CreateDataShareHelperInstance()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_AND_RETURN_RET_LOG(samgr != nullptr, nullptr, "[Policy Service] Get samgr failed.");

    sptr<IRemoteObject> remoteObject = samgr->GetSystemAbility(AUDIO_POLICY_SERVICE_ID);
    CHECK_AND_RETURN_RET_LOG(remoteObject != nullptr, nullptr, "[Policy Service] audio service remote object is NULL.");

    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = DataShare::DataShareHelper::Creator(remoteObject,
        SETTINGS_DATA_BASE_URI, SETTINGS_DATA_EXT_URI);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, nullptr, "create fail.");
    return dataShareHelper;
}

int32_t AudioPolicyService::GetDeviceNameFromDataShareHelper(std::string &deviceName)
{
    lock_guard<mutex> lock(g_dataShareHelperMutex);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelperInstance();
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, ERROR, "dataShareHelper is NULL");

    std::shared_ptr<Uri> uri = std::make_shared<Uri>(SETTINGS_DATA_BASE_URI);
    std::vector<std::string> columns;
    columns.emplace_back(SETTINGS_DATA_FIELD_VALUE);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTINGS_DATA_FIELD_KEYWORD, PREDICATES_STRING);

    auto resultSet = dataShareHelper->Query(*uri, predicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, ERROR, "query fail.");

    int32_t numRows = 0;
    resultSet->GetRowCount(numRows);

    CHECK_AND_RETURN_RET_LOG(numRows > 0, ERROR, "row zero.");
    int columnIndex;
    resultSet->GoToFirstRow();
    resultSet->GetColumnIndex(SETTINGS_DATA_FIELD_VALUE, columnIndex);
    resultSet->GetString(columnIndex, deviceName);
    AUDIO_INFO_LOG("deviceName[%{public}s]", deviceName.c_str());

    resultSet->Close();
    dataShareHelper->Release();
    return SUCCESS;
}

void AudioPolicyService::RegisterNameMonitorHelper()
{
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelperInstance();
    CHECK_AND_RETURN_LOG(dataShareHelper != nullptr, "dataShareHelper is NULL");

    auto uri = std::make_shared<Uri>(SETTINGS_DATA_BASE_URI + "&key=" + PREDICATES_STRING);
    sptr<AAFwk::DataAbilityObserverStub> settingDataObserver = std::make_unique<DataShareObserverCallBack>().release();
    dataShareHelper->RegisterObserver(*uri, settingDataObserver);

    dataShareHelper->Release();
}

void AudioPolicyService::UpdateDisplayName(sptr<AudioDeviceDescriptor> deviceDescriptor)
{
    if (deviceDescriptor->networkId_ == LOCAL_NETWORK_ID) {
        std::string devicesName = "";
        int32_t ret = GetDeviceNameFromDataShareHelper(devicesName);
        CHECK_AND_RETURN_LOG(ret == SUCCESS, "Local init device failed");
        deviceDescriptor->displayName_ = devicesName;
    } else {
#ifdef FEATURE_DEVICE_MANAGER
        std::shared_ptr<DistributedHardware::DmInitCallback> callback = std::make_shared<DeviceInitCallBack>();
        int32_t ret = DistributedHardware::DeviceManager::GetInstance().InitDeviceManager(AUDIO_SERVICE_PKG, callback);
        CHECK_AND_RETURN_LOG(ret == SUCCESS, "init device failed");
        std::vector<DistributedHardware::DmDeviceInfo> deviceList;
        if (DistributedHardware::DeviceManager::GetInstance()
            .GetTrustedDeviceList(AUDIO_SERVICE_PKG, "", deviceList) == SUCCESS) {
            for (auto deviceInfo : deviceList) {
                std::string strNetworkId(deviceInfo.networkId);
                if (strNetworkId == deviceDescriptor->networkId_) {
                    AUDIO_INFO_LOG("remote name [%{public}s]", deviceInfo.deviceName);
                    deviceDescriptor->displayName_ = deviceInfo.deviceName;
                    break;
                }
            }
        };
#endif
    }
}

void AudioPolicyService::HandleOfflineDistributedDevice()
{
    std::vector<sptr<AudioDeviceDescriptor>> deviceChangeDescriptor = {};
    {
        std::lock_guard<std::mutex> lock(deviceStatusUpdateSharedMutex_);
        std::vector<sptr<AudioDeviceDescriptor>> connectedDevices = connectedDevices_;
        for (auto deviceDesc : connectedDevices) {
            if (deviceDesc != nullptr && deviceDesc->networkId_ != LOCAL_NETWORK_ID) {
                const std::string networkId = deviceDesc->networkId_;
                UpdateConnectedDevicesWhenDisconnecting(deviceDesc, deviceChangeDescriptor);
                std::string moduleName = GetRemoteModuleName(networkId, GetDeviceRole(deviceDesc->deviceType_));
                ClosePortAndEraseIOHandle(moduleName);
                RemoveDeviceInRouterMap(moduleName);
                RemoveDeviceInFastRouterMap(networkId);
                if (GetDeviceRole(deviceDesc->deviceType_) == DeviceRole::INPUT_DEVICE) {
                    remoteCapturerSwitch_ = true;
                }
            }
        }
    }

    TriggerDeviceChangedCallback(deviceChangeDescriptor, false);
    TriggerAvailableDeviceChangedCallback(deviceChangeDescriptor, false);

    FetchDevice(true, AudioStreamDeviceChangeReason::OLD_DEVICE_UNAVALIABLE);
    FetchDevice(false);
}

int32_t AudioPolicyService::HandleDistributedDeviceUpdate(DStatusInfo &statusInfo,
    std::vector<sptr<AudioDeviceDescriptor>> &descForCb)
{
    std::lock_guard<std::mutex> lock(deviceStatusUpdateSharedMutex_);
    DeviceType devType = GetDeviceTypeFromPin(statusInfo.hdiPin);
    const std::string networkId = statusInfo.networkId;
    AudioDeviceDescriptor deviceDesc(devType, GetDeviceRole(devType));
    deviceDesc.SetDeviceInfo(statusInfo.deviceName, statusInfo.macAddress);
    deviceDesc.SetDeviceCapability(statusInfo.streamInfo, 0);
    deviceDesc.networkId_ = networkId;
    UpdateGroupInfo(VOLUME_TYPE, GROUP_NAME_DEFAULT, deviceDesc.volumeGroupId_, networkId, statusInfo.isConnected,
        statusInfo.mappingVolumeId);
    UpdateGroupInfo(INTERRUPT_TYPE, GROUP_NAME_DEFAULT, deviceDesc.interruptGroupId_, networkId,
        statusInfo.isConnected, statusInfo.mappingInterruptId);
    if (statusInfo.isConnected) {
        for (auto devDes : connectedDevices_) {
            if (devDes->deviceType_ == devType && devDes->networkId_ == networkId) {
                return ERROR;
            }
        }
        int32_t ret = ActivateNewDevice(statusInfo.networkId, devType,
            statusInfo.connectType == ConnectType::CONNECT_TYPE_DISTRIBUTED);
        CHECK_AND_RETURN_RET_LOG(ret == SUCCESS, ERROR, "DEVICE online but open audio device failed.");
        UpdateConnectedDevicesWhenConnecting(deviceDesc, descForCb);

        const sptr<IStandardAudioService> gsp = GetAudioServerProxy();
        if (gsp != nullptr && statusInfo.connectType == ConnectType::CONNECT_TYPE_DISTRIBUTED) {
            std::string identity = IPCSkeleton::ResetCallingIdentity();
            gsp->NotifyDeviceInfo(networkId, true);
            IPCSkeleton::SetCallingIdentity(identity);
        }
    } else {
        UpdateConnectedDevicesWhenDisconnecting(deviceDesc, descForCb);
        std::string moduleName = GetRemoteModuleName(networkId, GetDeviceRole(devType));
        ClosePortAndEraseIOHandle(moduleName);
        RemoveDeviceInRouterMap(moduleName);
        RemoveDeviceInFastRouterMap(networkId);
    }
    return SUCCESS;
}

void AudioPolicyService::OnDeviceStatusUpdated(DStatusInfo statusInfo, bool isStop)
{
    // Distributed devices status update
    AUDIO_INFO_LOG("Device connection updated | HDI_PIN[%{public}d] CONNECT_STATUS[%{public}d] NETWORKID[%{public}s]",
        statusInfo.hdiPin, statusInfo.isConnected, statusInfo.networkId);
    if (isStop) {
        HandleOfflineDistributedDevice();
        return;
    }
    std::vector<sptr<AudioDeviceDescriptor>> descForCb = {};
    int32_t ret = HandleDistributedDeviceUpdate(statusInfo, descForCb);
    CHECK_AND_RETURN_LOG(ret == SUCCESS, "HandleDistributedDeviceUpdate return directly.");

    TriggerDeviceChangedCallback(descForCb, statusInfo.isConnected);
    TriggerAvailableDeviceChangedCallback(descForCb, statusInfo.isConnected);

    FetchDevice(true);
    FetchDevice(false);

    DeviceType devType = GetDeviceTypeFromPin(statusInfo.hdiPin);
    if (GetDeviceRole(devType) == DeviceRole::INPUT_DEVICE) {
        remoteCapturerSwitch_ = true;
    }

    // update a2dp offload
    UpdateA2dpOffloadFlagForAllStream();
}

bool AudioPolicyService::OpenPortAndAddDeviceOnServiceConnected(AudioModuleInfo &moduleInfo)
{
    auto devType = GetDeviceType(moduleInfo.name);
    if (devType != DEVICE_TYPE_MIC) {
        AudioIOHandle ioHandle = OpenPortAndInsertIOHandle(moduleInfo.name, moduleInfo);

        if (devType == DEVICE_TYPE_SPEAKER) {
            auto result = audioPolicyManager_.SetDeviceActive(ioHandle, devType, moduleInfo.name, true);
            CHECK_AND_RETURN_RET_LOG(result == SUCCESS, false, "[module_load]::Device failed %{public}d", devType);
        }
    }

    if (devType == DEVICE_TYPE_MIC) {
        primaryMicModuleInfo_ = moduleInfo;
    }

    if (devType == DEVICE_TYPE_SPEAKER || devType == DEVICE_TYPE_MIC) {
        AddAudioDevice(moduleInfo, devType);
    }
    return true;
}

void AudioPolicyService::OnServiceConnected(AudioServiceIndex serviceIndex)
{
    AUDIO_INFO_LOG("[module_load]::OnServiceConnected for [%{public}d]", serviceIndex);
    CHECK_AND_RETURN_LOG(serviceIndex >= HDI_SERVICE_INDEX && serviceIndex <= AUDIO_SERVICE_INDEX, "invalid index");

    // If audio service or hdi service is not ready, donot load default modules
    lock_guard<mutex> lock(serviceFlagMutex_);
    serviceFlag_.set(serviceIndex, true);
    if (serviceFlag_.count() != MIN_SERVICE_COUNT) {
        AUDIO_INFO_LOG("[module_load]::hdi service or audio service not up. Cannot load default module now");
        return;
    }

    int32_t result = ERROR;
    AUDIO_DEBUG_LOG("[module_load]::HDI and AUDIO SERVICE is READY. Loading default modules");
    for (const auto &device : deviceClassInfo_) {
        if (device.first == ClassType::TYPE_PRIMARY || device.first == ClassType::TYPE_FILE_IO) {
            auto moduleInfoList = device.second;
            for (auto &moduleInfo : moduleInfoList) {
                AUDIO_INFO_LOG("[module_load]::Load module[%{public}s]", moduleInfo.name.c_str());
                moduleInfo.sinkLatency = sinkLatencyInMsec_ != 0 ? to_string(sinkLatencyInMsec_) : "";
                if (OpenPortAndAddDeviceOnServiceConnected(moduleInfo)) {
                    result = SUCCESS;
                }
                SetOffloadAvailableFromXML(moduleInfo);
            }
        }
    }

    if (result == SUCCESS) {
        AUDIO_INFO_LOG("[module_load]::Setting speaker as active device on bootup");
        hasModulesLoaded = true;
        unique_ptr<AudioDeviceDescriptor> outDevice = audioDeviceManager_.GetRenderDefaultDevice();
        currentActiveDevice_ = AudioDeviceDescriptor(*outDevice);
        ResetOffloadMode();
        unique_ptr<AudioDeviceDescriptor> inDevice = audioDeviceManager_.GetCaptureDefaultDevice();
        currentActiveInputDevice_ = AudioDeviceDescriptor(*inDevice);
        SetVolumeForSwitchDevice(currentActiveDevice_.deviceType_);
        OnPreferredDeviceUpdated(currentActiveDevice_, currentActiveInputDevice_.deviceType_);
        AddEarpiece();
        for (auto it = pnpDeviceList_.begin(); it != pnpDeviceList_.end(); ++it) {
            OnPnpDeviceStatusUpdated((*it).first, (*it).second);
        }
        audioEffectManager_.SetMasterSinkAvailable();
    }
    // load inner-cap-sink
    LoadModernInnerCapSink();
    RegisterBluetoothListener();
}

void AudioPolicyService::OnServiceDisconnected(AudioServiceIndex serviceIndex)
{
    AUDIO_WARNING_LOG("Start for [%{public}d]", serviceIndex);
    CHECK_AND_RETURN_LOG(serviceIndex >= HDI_SERVICE_INDEX && serviceIndex <= AUDIO_SERVICE_INDEX, "invalid index");
    if (serviceIndex == HDI_SERVICE_INDEX) {
        AUDIO_ERR_LOG("Auto exit audio policy service for hdi service stopped!");
        _Exit(0);
    }
}

void AudioPolicyService::OnForcedDeviceSelected(DeviceType devType, const std::string &macAddress)
{
    if (macAddress.empty()) {
        AUDIO_ERR_LOG("failed as the macAddress is empty!");
        return;
    }
    std::vector<unique_ptr<AudioDeviceDescriptor>> bluetoothDevices =
        audioDeviceManager_.GetAvailableBluetoothDevice(devType, macAddress);
    std::vector<sptr<AudioDeviceDescriptor>> audioDeviceDescriptors;
    for (auto &dec : bluetoothDevices) {
        if (dec->deviceRole_ == DeviceRole::OUTPUT_DEVICE) {
            sptr<AudioDeviceDescriptor> tempDec = new(std::nothrow) AudioDeviceDescriptor(*dec);
            audioDeviceDescriptors.push_back(move(tempDec));
        }
    }
    int32_t res = DeviceParamsCheck(DeviceRole::OUTPUT_DEVICE, audioDeviceDescriptors);
    CHECK_AND_RETURN_LOG(res == SUCCESS, "DeviceParamsCheck no success");
    audioDeviceDescriptors[0]->isEnable_ = true;
    audioDeviceManager_.UpdateDevicesListInfo(audioDeviceDescriptors[0], ENABLE_UPDATE);
    if (devType == DEVICE_TYPE_BLUETOOTH_SCO) {
        audioStateManager_.SetPerferredCallRenderDevice(audioDeviceDescriptors[0]);
        ClearScoDeviceSuspendState(audioDeviceDescriptors[0]->macAddress_);
    } else {
        audioStateManager_.SetPerferredMediaRenderDevice(audioDeviceDescriptors[0]);
    }
    FetchDevice(true, AudioStreamDeviceChangeReason::OVERRODE);
}

void AudioPolicyService::OnMonoAudioConfigChanged(bool audioMono)
{
    AUDIO_DEBUG_LOG("audioMono = %{public}s", audioMono? "true": "false");
    const sptr<IStandardAudioService> gsp = GetAudioServerProxy();
    CHECK_AND_RETURN_LOG(gsp != nullptr, "Service proxy unavailable: g_adProxy null");
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    gsp->SetAudioMonoState(audioMono);
    IPCSkeleton::SetCallingIdentity(identity);
}

void AudioPolicyService::OnAudioBalanceChanged(float audioBalance)
{
    AUDIO_DEBUG_LOG("audioBalance = %{public}f", audioBalance);
    const sptr<IStandardAudioService> gsp = GetAudioServerProxy();
    CHECK_AND_RETURN_LOG(gsp != nullptr, "Service proxy unavailable: g_adProxy null");
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    gsp->SetAudioBalanceValue(audioBalance);
    IPCSkeleton::SetCallingIdentity(identity);
}

void AudioPolicyService::UpdateEffectDefaultSink(DeviceType deviceType)
{
    Trace trace("AudioPolicyService::UpdateEffectDefaultSink:" + std::to_string(deviceType));
    effectActiveDevice_ = deviceType;
    switch (deviceType) {
        case DeviceType::DEVICE_TYPE_EARPIECE:
        case DeviceType::DEVICE_TYPE_SPEAKER:
        case DeviceType::DEVICE_TYPE_FILE_SINK:
        case DeviceType::DEVICE_TYPE_WIRED_HEADSET:
        case DeviceType::DEVICE_TYPE_USB_HEADSET:
        case DeviceType::DEVICE_TYPE_DP:
        case DeviceType::DEVICE_TYPE_USB_ARM_HEADSET:
        case DeviceType::DEVICE_TYPE_BLUETOOTH_A2DP:
        case DeviceType::DEVICE_TYPE_BLUETOOTH_SCO: {
            const sptr<IStandardAudioService> gsp = GetAudioServerProxy();
            CHECK_AND_RETURN_LOG(gsp != nullptr, "Service proxy unavailable");
            std::string sinkName = GetSinkPortName(deviceType);
            std::string identity = IPCSkeleton::ResetCallingIdentity();
            bool ret = gsp->SetOutputDeviceSink(deviceType, sinkName);
            IPCSkeleton::SetCallingIdentity(identity);
            CHECK_AND_RETURN_LOG(ret, "Failed to set output device sink");
            int res = audioPolicyManager_.UpdateSwapDeviceStatus();
            CHECK_AND_RETURN_LOG(res == SUCCESS, "Failed to update client swap device status");
            break;
        }
        default:
            break;
    }
}

void AudioPolicyService::LoadSinksForCapturer()
{
    AUDIO_INFO_LOG("Start");
    AudioStreamInfo streamInfo;
    LoadInnerCapturerSink(INNER_CAPTURER_SINK_LEGACY, streamInfo);
    LoadReceiverSink();
    const sptr<IStandardAudioService> gsp = GetAudioServerProxy();
    CHECK_AND_RETURN_LOG(gsp != nullptr, "error for g_adProxy null");
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    bool ret = gsp->CreatePlaybackCapturerManager();
    IPCSkeleton::SetCallingIdentity(identity);
    CHECK_AND_RETURN_LOG(ret, "PlaybackCapturerManager create failed");
}

void AudioPolicyService::LoadInnerCapturerSink(string moduleName, AudioStreamInfo streamInfo)
{
    AUDIO_INFO_LOG("Start");
    uint32_t bufferSize = (streamInfo.samplingRate * GetSampleFormatValue(streamInfo.format)
        * streamInfo.channels) / PCM_8_BIT * RENDER_FRAME_INTERVAL_IN_SECONDS;

    AudioModuleInfo moduleInfo = {};
    moduleInfo.lib = "libmodule-inner-capturer-sink.z.so";
    moduleInfo.format = ConvertToHDIAudioFormat(streamInfo.format);
    moduleInfo.name = moduleName;
    moduleInfo.networkId = "LocalDevice";
    moduleInfo.channels = std::to_string(streamInfo.channels);
    moduleInfo.rate = std::to_string(streamInfo.samplingRate);
    moduleInfo.bufferSize = std::to_string(bufferSize);

    OpenPortAndInsertIOHandle(moduleInfo.name, moduleInfo);
}

void AudioPolicyService::UnloadInnerCapturerSink(string moduleName)
{
    ClosePortAndEraseIOHandle(moduleName);
}

void AudioPolicyService::LoadReceiverSink()
{
    AUDIO_INFO_LOG("Start");
    AudioModuleInfo moduleInfo = {};
    moduleInfo.name = RECEIVER_SINK_NAME;
    moduleInfo.lib = "libmodule-receiver-sink.z.so";
    OpenPortAndInsertIOHandle(moduleInfo.name, moduleInfo);
}

void AudioPolicyService::LoadLoopback()
{
    AudioIOHandle ioHandle;
    std::string moduleName;
    AUDIO_INFO_LOG("Start");
    std::lock_guard<std::mutex> ioHandleLock(ioHandlesMutex_);
    CHECK_AND_RETURN_LOG(IOHandles_.count(INNER_CAPTURER_SINK_LEGACY) == 1u,
        "failed for InnerCapturer not loaded");

    LoopbackModuleInfo moduleInfo = {};
    moduleInfo.lib = "libmodule-loopback.z.so";
    moduleInfo.sink = INNER_CAPTURER_SINK_LEGACY;

    for (auto sceneType = AUDIO_SUPPORTED_SCENE_TYPES.begin(); sceneType != AUDIO_SUPPORTED_SCENE_TYPES.end();
        ++sceneType) {
        moduleInfo.source = sceneType->second + SINK_NAME_FOR_CAPTURE_SUFFIX + MONITOR_SOURCE_SUFFIX;
        ioHandle = audioPolicyManager_.LoadLoopback(moduleInfo);
        CHECK_AND_RETURN_LOG(ioHandle != OPEN_PORT_FAILURE, "failed %{public}d", ioHandle);
        moduleName = moduleInfo.source + moduleInfo.sink;
        IOHandles_[moduleName] = ioHandle;
    }

    if (IOHandles_.count(RECEIVER_SINK_NAME) != 1u) {
        AUDIO_WARNING_LOG("receiver sink not exist");
    } else {
        moduleInfo.source = RECEIVER_SINK_NAME + MONITOR_SOURCE_SUFFIX;
        ioHandle = audioPolicyManager_.LoadLoopback(moduleInfo);
        CHECK_AND_RETURN_LOG(ioHandle != OPEN_PORT_FAILURE, "failed %{public}d", ioHandle);
        moduleName = moduleInfo.source + moduleInfo.sink;
        IOHandles_[moduleName] = ioHandle;
    }
}

void AudioPolicyService::UnloadLoopback()
{
    std::string module;
    AUDIO_INFO_LOG("UnloadLoopback start");

    for (auto sceneType = AUDIO_SUPPORTED_SCENE_TYPES.begin(); sceneType != AUDIO_SUPPORTED_SCENE_TYPES.end();
        ++sceneType) {
        module = sceneType->second + SINK_NAME_FOR_CAPTURE_SUFFIX + MONITOR_SOURCE_SUFFIX + INNER_CAPTURER_SINK_LEGACY;
        ClosePortAndEraseIOHandle(module);
    }

    module = RECEIVER_SINK_NAME + MONITOR_SOURCE_SUFFIX + INNER_CAPTURER_SINK_LEGACY;
    ClosePortAndEraseIOHandle(module);
}

void AudioPolicyService::LoadModernInnerCapSink()
{
    AUDIO_INFO_LOG("Start");
    AudioModuleInfo moduleInfo = {};
    moduleInfo.lib = "libmodule-inner-capturer-sink.z.so";
    moduleInfo.name = INNER_CAPTURER_SINK;

    moduleInfo.format = "s16le";
    moduleInfo.channels = "2"; // 2 channel
    moduleInfo.rate = "48000";
    moduleInfo.bufferSize = "3840"; // 20ms

    OpenPortAndInsertIOHandle(moduleInfo.name, moduleInfo);
}

void AudioPolicyService::LoadEffectLibrary()
{
    // IPC -> audioservice load library
    const sptr<IStandardAudioService> gsp = GetAudioServerProxy();
    CHECK_AND_RETURN_LOG(gsp != nullptr, "Service proxy unavailable: g_adProxy null");
    OriginalEffectConfig oriEffectConfig = {};
    audioEffectManager_.GetOriginalEffectConfig(oriEffectConfig);
    vector<Effect> successLoadedEffects;
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    bool loadSuccess = gsp->LoadAudioEffectLibraries(oriEffectConfig.libraries,
                                                     oriEffectConfig.effects,
                                                     successLoadedEffects);
    IPCSkeleton::SetCallingIdentity(identity);
    if (!loadSuccess) {
        AUDIO_ERR_LOG("Load audio effect failed, please check log");
    }

    audioEffectManager_.UpdateAvailableEffects(successLoadedEffects);
    audioEffectManager_.BuildAvailableAEConfig();

    // Initialize EffectChainManager in audio service through IPC
    SupportedEffectConfig supportedEffectConfig;
    audioEffectManager_.GetSupportedEffectConfig(supportedEffectConfig);
    std::unordered_map<std::string, std::string> sceneTypeToEffectChainNameMap;
    audioEffectManager_.ConstructSceneTypeToEffectChainNameMap(sceneTypeToEffectChainNameMap);
    std::unordered_map<std::string, std::string> sceneTypeToEnhanceChainNameMap;
    audioEffectManager_.ConstructSceneTypeToEnhanceChainNameMap(sceneTypeToEnhanceChainNameMap);
    identity = IPCSkeleton::ResetCallingIdentity();
    bool ret = gsp->CreateEffectChainManager(supportedEffectConfig.effectChains,
        sceneTypeToEffectChainNameMap, sceneTypeToEnhanceChainNameMap);
    IPCSkeleton::SetCallingIdentity(identity);
    CHECK_AND_RETURN_LOG(ret, "EffectChainManager create failed");

    audioEffectManager_.SetEffectChainManagerAvailable();
    AudioSpatializationService::GetAudioSpatializationService().Init(supportedEffectConfig.effectChains);
}

void AudioPolicyService::GetEffectManagerInfo(OriginalEffectConfig& oriEffectConfig,
                                              std::vector<Effect>& availableEffects)
{
    audioEffectManager_.GetOriginalEffectConfig(oriEffectConfig);
    audioEffectManager_.GetAvailableEffects(availableEffects);
}

void AudioPolicyService::AddAudioDevice(AudioModuleInfo& moduleInfo, InternalDeviceType devType)
{
    // add new device into active device list
    std::string volumeGroupName = GetGroupName(moduleInfo.name, VOLUME_TYPE);
    std::string interruptGroupName = GetGroupName(moduleInfo.name, INTERRUPT_TYPE);
    int32_t volumeGroupId = GROUP_ID_NONE;
    int32_t interruptGroupId = GROUP_ID_NONE;
    UpdateGroupInfo(GroupType::VOLUME_TYPE, volumeGroupName, volumeGroupId, LOCAL_NETWORK_ID, true,
        NO_REMOTE_ID);
    UpdateGroupInfo(GroupType::INTERRUPT_TYPE, interruptGroupName, interruptGroupId, LOCAL_NETWORK_ID,
        true, NO_REMOTE_ID);

    sptr<AudioDeviceDescriptor> audioDescriptor = new(std::nothrow) AudioDeviceDescriptor(devType,
        GetDeviceRole(moduleInfo.role), volumeGroupId, interruptGroupId, LOCAL_NETWORK_ID);
    if (!moduleInfo.supportedRate_.empty() && !moduleInfo.supportedChannels_.empty()) {
        DeviceStreamInfo streamInfo = {};
        for (auto supportedRate : moduleInfo.supportedRate_) {
            streamInfo.samplingRate.insert(static_cast<AudioSamplingRate>(supportedRate));
        }
        for (auto supportedChannels : moduleInfo.supportedChannels_) {
            streamInfo.channels.insert(static_cast<AudioChannel>(supportedChannels));
        }
        audioDescriptor->SetDeviceCapability(streamInfo, 0);
    }

    audioDescriptor->deviceId_ = startDeviceId++;
    UpdateDisplayName(audioDescriptor);
    audioDeviceManager_.AddNewDevice(audioDescriptor);
    std::lock_guard<std::mutex> lock(deviceStatusUpdateSharedMutex_);
    connectedDevices_.insert(connectedDevices_.begin(), audioDescriptor);
    AddMicrophoneDescriptor(audioDescriptor);
}

void AudioPolicyService::OnAudioPolicyXmlParsingCompleted(
    const std::unordered_map<AdaptersType, AudioAdapterInfo> adapterInfoMap)
{
    AUDIO_INFO_LOG("adapterInfo num [%{public}zu]", adapterInfoMap.size());
    CHECK_AND_RETURN_LOG(!adapterInfoMap.empty(), "failed to parse audiopolicy xml file. Received data is empty");
    adapterInfoMap_ = adapterInfoMap;

    for (const auto &adapterInfo : adapterInfoMap_) {
        for (const auto &deviceInfos : (adapterInfo.second).deviceInfos_) {
            if (deviceInfos.type_ == EARPIECE_TYPE_NAME) {
                hasEarpiece_ = true;
                break;
            }
        }
        if (hasEarpiece_) {
            break;
        }
    }

    audioDeviceManager_.UpdateEarpieceStatus(hasEarpiece_);
}

// Parser callbacks
void AudioPolicyService::OnXmlParsingCompleted(const std::unordered_map<ClassType, std::list<AudioModuleInfo>> &xmlData)
{
    AUDIO_INFO_LOG("device class num [%{public}zu]", xmlData.size());
    CHECK_AND_RETURN_LOG(!xmlData.empty(), "failed to parse xml file. Received data is empty");

    deviceClassInfo_ = xmlData;
}

void AudioPolicyService::OnVolumeGroupParsed(std::unordered_map<std::string, std::string>& volumeGroupData)
{
    AUDIO_INFO_LOG("group data num [%{public}zu]", volumeGroupData.size());
    CHECK_AND_RETURN_LOG(!volumeGroupData.empty(), "failed to parse xml file. Received data is empty");

    volumeGroupData_ = volumeGroupData;
}

void AudioPolicyService::OnInterruptGroupParsed(std::unordered_map<std::string, std::string>& interruptGroupData)
{
    AUDIO_INFO_LOG("group data num [%{public}zu]", interruptGroupData.size());
    CHECK_AND_RETURN_LOG(!interruptGroupData.empty(), "failed to parse xml file. Received data is empty");

    interruptGroupData_ = interruptGroupData;
}

void AudioPolicyService::OnGlobalConfigsParsed(GlobalConfigs &globalConfigs)
{
    globalConfigs_ = globalConfigs;
}

void AudioPolicyService::GetAudioAdapterInfos(std::unordered_map<AdaptersType, AudioAdapterInfo> &adapterInfoMap)
{
    adapterInfoMap = adapterInfoMap_;
}

void AudioPolicyService::GetVolumeGroupData(std::unordered_map<std::string, std::string>& volumeGroupData)
{
    volumeGroupData = volumeGroupData_;
}

void AudioPolicyService::GetInterruptGroupData(std::unordered_map<std::string, std::string>& interruptGroupData)
{
    interruptGroupData = interruptGroupData_;
}

void AudioPolicyService::GetDeviceClassInfo(std::unordered_map<ClassType, std::list<AudioModuleInfo>> &deviceClassInfo)
{
    deviceClassInfo = deviceClassInfo_;
}

void AudioPolicyService::GetGlobalConfigs(GlobalConfigs &globalConfigs)
{
    globalConfigs = globalConfigs_;
}

void AudioPolicyService::AddAudioPolicyClientProxyMap(int32_t clientPid, const sptr<IAudioPolicyClient>& cb)
{
    if (audioPolicyServerHandler_ != nullptr) {
        audioPolicyServerHandler_->AddAudioPolicyClientProxyMap(clientPid, cb);
    }
}

void AudioPolicyService::ReduceAudioPolicyClientProxyMap(pid_t clientPid)
{
    if (audioPolicyServerHandler_ != nullptr) {
        audioPolicyServerHandler_->RemoveAudioPolicyClientProxyMap(clientPid);
    }
}

int32_t AudioPolicyService::SetAvailableDeviceChangeCallback(const int32_t clientId, const AudioDeviceUsage usage,
    const sptr<IRemoteObject> &object, bool hasBTPermission)
{
    sptr<IStandardAudioPolicyManagerListener> callback = iface_cast<IStandardAudioPolicyManagerListener>(object);

    if (callback != nullptr) {
        callback->hasBTPermission_ = hasBTPermission;

        if (audioPolicyServerHandler_ != nullptr) {
            audioPolicyServerHandler_->AddAvailableDeviceChangeMap(clientId, usage, callback);
        }
    }

    return SUCCESS;
}

int32_t AudioPolicyService::UnsetAvailableDeviceChangeCallback(const int32_t clientId, AudioDeviceUsage usage)
{
    AUDIO_INFO_LOG("Start");

    if (audioPolicyServerHandler_ != nullptr) {
        audioPolicyServerHandler_->RemoveAvailableDeviceChangeMap(clientId, usage);
    }
    return SUCCESS;
}

static void UpdateRendererInfoWhenNoPermission(const unique_ptr<AudioRendererChangeInfo> &audioRendererChangeInfos,
    bool hasSystemPermission)
{
    if (!hasSystemPermission) {
        audioRendererChangeInfos->clientUID = 0;
        audioRendererChangeInfos->rendererState = RENDERER_INVALID;
    }
}

static void UpdateCapturerInfoWhenNoPermission(const unique_ptr<AudioCapturerChangeInfo> &audioCapturerChangeInfos,
    bool hasSystemPermission)
{
    if (!hasSystemPermission) {
        audioCapturerChangeInfos->clientUID = 0;
        audioCapturerChangeInfos->capturerState = CAPTURER_INVALID;
    }
}

static bool HasLowLatencyCapability(DeviceType deviceType, bool isRemote)
{
    // Distributed devices are low latency devices
    if (isRemote) {
        return true;
    }

    switch (deviceType) {
        case DeviceType::DEVICE_TYPE_EARPIECE:
        case DeviceType::DEVICE_TYPE_SPEAKER:
        case DeviceType::DEVICE_TYPE_WIRED_HEADSET:
        case DeviceType::DEVICE_TYPE_WIRED_HEADPHONES:
        case DeviceType::DEVICE_TYPE_USB_HEADSET:
        case DeviceType::DEVICE_TYPE_DP:
            return true;

        case DeviceType::DEVICE_TYPE_BLUETOOTH_SCO:
        case DeviceType::DEVICE_TYPE_BLUETOOTH_A2DP:
            return false;
        default:
            return false;
    }
}

void AudioPolicyService::UpdateDeviceInfo(DeviceInfo &deviceInfo, const sptr<AudioDeviceDescriptor> &desc,
    bool hasBTPermission, bool hasSystemPermission)
{
    deviceInfo.deviceType = desc->deviceType_;
    deviceInfo.deviceRole = desc->deviceRole_;
    deviceInfo.deviceId = desc->deviceId_;
    deviceInfo.channelMasks = desc->channelMasks_;
    deviceInfo.channelIndexMasks = desc->channelIndexMasks_;
    deviceInfo.displayName = desc->displayName_;
    deviceInfo.connectState = desc->connectState_;

    if (deviceInfo.deviceType == DEVICE_TYPE_BLUETOOTH_A2DP) {
        deviceInfo.a2dpOffloadFlag = a2dpOffloadFlag_;
    }

    if (hasBTPermission) {
        deviceInfo.deviceName = desc->deviceName_;
        deviceInfo.macAddress = desc->macAddress_;
    } else {
        deviceInfo.deviceName = "";
        deviceInfo.macAddress = "";
    }

    deviceInfo.isLowLatencyDevice = HasLowLatencyCapability(deviceInfo.deviceType,
        desc->networkId_ != LOCAL_NETWORK_ID);

    if (hasSystemPermission) {
        deviceInfo.networkId = desc->networkId_;
        deviceInfo.volumeGroupId = desc->volumeGroupId_;
        deviceInfo.interruptGroupId = desc->interruptGroupId_;
    } else {
        deviceInfo.networkId = "";
        deviceInfo.volumeGroupId = GROUP_ID_NONE;
        deviceInfo.interruptGroupId = GROUP_ID_NONE;
    }
    deviceInfo.audioStreamInfo.samplingRate = desc->audioStreamInfo_.samplingRate;
    deviceInfo.audioStreamInfo.encoding = desc->audioStreamInfo_.encoding;
    deviceInfo.audioStreamInfo.format = desc->audioStreamInfo_.format;
    deviceInfo.audioStreamInfo.channels = desc->audioStreamInfo_.channels;
}

void AudioPolicyService::UpdateStreamChangeDeviceInfoForPlayback(AudioStreamChangeInfo &streamChangeInfo)
{
    std::vector<sptr<AudioDeviceDescriptor>> outputDevices = GetDevices(OUTPUT_DEVICES_FLAG);
    DeviceType activeDeviceType = currentActiveDevice_.deviceType_;
    DeviceRole activeDeviceRole = OUTPUT_DEVICE;
    for (sptr<AudioDeviceDescriptor> desc : outputDevices) {
        if ((desc->deviceType_ == activeDeviceType) && (desc->deviceRole_ == activeDeviceRole)) {
            if (activeDeviceType == DEVICE_TYPE_BLUETOOTH_A2DP &&
                desc->macAddress_ != currentActiveDevice_.macAddress_) {
                // This A2DP device is not the active A2DP device. Skip it.
                continue;
            }
            UpdateDeviceInfo(streamChangeInfo.audioRendererChangeInfo.outputDeviceInfo, desc, true, true);
            break;
        }
    }
}

void AudioPolicyService::UpdateStreamChangeDeviceInfoForRecord(AudioStreamChangeInfo &streamChangeInfo)
{
    std::vector<sptr<AudioDeviceDescriptor>> inputDevices = GetDevices(INPUT_DEVICES_FLAG);
    DeviceType activeDeviceType = currentActiveInputDevice_.deviceType_;
    DeviceRole activeDeviceRole = INPUT_DEVICE;
    for (sptr<AudioDeviceDescriptor> desc : inputDevices) {
        if ((desc->deviceType_ == activeDeviceType) && (desc->deviceRole_ == activeDeviceRole)) {
            int32_t sessionId = streamChangeInfo.audioCapturerChangeInfo.sessionId;
            AddAudioCapturerMicrophoneDescriptor(sessionId, activeDeviceType);
            break;
        }
    }
}

int32_t AudioPolicyService::RegisterTracker(AudioMode &mode, AudioStreamChangeInfo &streamChangeInfo,
    const sptr<IRemoteObject> &object)
{
    if (mode == AUDIO_MODE_RECORD) {
        AddAudioCapturerMicrophoneDescriptor(streamChangeInfo.audioCapturerChangeInfo.sessionId, DEVICE_TYPE_NONE);
        UpdateDeviceInfo(streamChangeInfo.audioCapturerChangeInfo.inputDeviceInfo,
            new AudioDeviceDescriptor(currentActiveInputDevice_), false, false);
    } else {
        UpdateDeviceInfo(streamChangeInfo.audioRendererChangeInfo.outputDeviceInfo,
            new AudioDeviceDescriptor(currentActiveDevice_), false, false);
    }
    return streamCollector_.RegisterTracker(mode, streamChangeInfo, object);
}

int32_t AudioPolicyService::UpdateTracker(AudioMode &mode, AudioStreamChangeInfo &streamChangeInfo)
{
    AUDIO_INFO_LOG("Entered AudioPolicyService UpdateTracker");
    if (mode == AUDIO_MODE_RECORD) {
        std::lock_guard<std::mutex> lock(microphonesMutex_);
        if (streamChangeInfo.audioCapturerChangeInfo.capturerState == CAPTURER_RELEASED) {
            audioCaptureMicrophoneDescriptor_.erase(streamChangeInfo.audioCapturerChangeInfo.sessionId);
        }
    }

    int32_t ret = streamCollector_.UpdateTracker(mode, streamChangeInfo);

    const auto &rendererState = streamChangeInfo.audioRendererChangeInfo.rendererState;
    if (mode == AUDIO_MODE_PLAYBACK && (rendererState == RENDERER_STOPPED || rendererState == RENDERER_PAUSED)) {
        FetchDevice(true);
    }

    UpdateA2dpOffloadFlagForAllStream(currentActiveDevice_.deviceType_);
    return ret;
}

void AudioPolicyService::FetchOutputDeviceForTrack(AudioStreamChangeInfo &streamChangeInfo)
{
    vector<unique_ptr<AudioRendererChangeInfo>> rendererChangeInfo;
    rendererChangeInfo.push_back(
        make_unique<AudioRendererChangeInfo>(streamChangeInfo.audioRendererChangeInfo));
    streamCollector_.GetRendererStreamInfo(streamChangeInfo, *rendererChangeInfo[0]);

    std::lock_guard<std::mutex> lock(fetchDeviceSharedMutex_);
    FetchOutputDevice(rendererChangeInfo);
}

void AudioPolicyService::FetchInputDeviceForTrack(AudioStreamChangeInfo &streamChangeInfo)
{
    vector<unique_ptr<AudioCapturerChangeInfo>> capturerChangeInfo;
    capturerChangeInfo.push_back(
        make_unique<AudioCapturerChangeInfo>(streamChangeInfo.audioCapturerChangeInfo));
    streamCollector_.GetCapturerStreamInfo(streamChangeInfo, *capturerChangeInfo[0]);

    std::lock_guard<std::mutex> lock(fetchDeviceSharedMutex_);
    FetchInputDevice(capturerChangeInfo);
}

int32_t AudioPolicyService::GetCurrentRendererChangeInfos(vector<unique_ptr<AudioRendererChangeInfo>>
    &audioRendererChangeInfos, bool hasBTPermission, bool hasSystemPermission)
{
    int32_t status = streamCollector_.GetCurrentRendererChangeInfos(audioRendererChangeInfos);
    CHECK_AND_RETURN_RET_LOG(status == SUCCESS, status,
        "AudioPolicyServer:: Get renderer change info failed");

    std::vector<sptr<AudioDeviceDescriptor>> outputDevices = GetDevices(OUTPUT_DEVICES_FLAG);
    DeviceType activeDeviceType = currentActiveDevice_.deviceType_;
    DeviceRole activeDeviceRole = OUTPUT_DEVICE;
    for (sptr<AudioDeviceDescriptor> desc : outputDevices) {
        if ((desc->deviceType_ == activeDeviceType) && (desc->deviceRole_ == activeDeviceRole)) {
            if (activeDeviceType == DEVICE_TYPE_BLUETOOTH_A2DP &&
                desc->macAddress_ != currentActiveDevice_.macAddress_) {
                // This A2DP device is not the active A2DP device. Skip it.
                continue;
            }
            size_t rendererInfosSize = audioRendererChangeInfos.size();
            for (size_t i = 0; i < rendererInfosSize; i++) {
                UpdateRendererInfoWhenNoPermission(audioRendererChangeInfos[i], hasSystemPermission);
                UpdateDeviceInfo(audioRendererChangeInfos[i]->outputDeviceInfo, desc, hasBTPermission,
                    hasSystemPermission);
            }
            break;
        }
    }

    return status;
}

int32_t AudioPolicyService::GetCurrentCapturerChangeInfos(vector<unique_ptr<AudioCapturerChangeInfo>>
    &audioCapturerChangeInfos, bool hasBTPermission, bool hasSystemPermission)
{
    int status = streamCollector_.GetCurrentCapturerChangeInfos(audioCapturerChangeInfos);
    CHECK_AND_RETURN_RET_LOG(status == SUCCESS, status,
        "AudioPolicyServer:: Get capturer change info failed");

    std::vector<sptr<AudioDeviceDescriptor>> inputDevices = GetDevices(INPUT_DEVICES_FLAG);
    DeviceType activeDeviceType = currentActiveInputDevice_.deviceType_;
    DeviceRole activeDeviceRole = INPUT_DEVICE;
    for (sptr<AudioDeviceDescriptor> desc : inputDevices) {
        if ((desc->deviceType_ == activeDeviceType) && (desc->deviceRole_ == activeDeviceRole)) {
            size_t capturerInfosSize = audioCapturerChangeInfos.size();
            for (size_t i = 0; i < capturerInfosSize; i++) {
                UpdateCapturerInfoWhenNoPermission(audioCapturerChangeInfos[i], hasSystemPermission);
                UpdateDeviceInfo(audioCapturerChangeInfos[i]->inputDeviceInfo, desc, hasBTPermission,
                    hasSystemPermission);
            }
            break;
        }
    }

    return status;
}

void AudioPolicyService::RegisteredTrackerClientDied(pid_t uid)
{
    RemoveAudioCapturerMicrophoneDescriptor(static_cast<int32_t>(uid));
    streamCollector_.RegisteredTrackerClientDied(static_cast<int32_t>(uid));
}

int32_t AudioPolicyService::ReconfigureAudioChannel(const uint32_t &channelCount, DeviceType deviceType)
{
    if (currentActiveDevice_.deviceType_ != DEVICE_TYPE_FILE_SINK) {
        AUDIO_INFO_LOG("FILE_SINK_DEVICE is not active. Cannot reconfigure now");
        return ERROR;
    }

    std::string module = FILE_SINK;

    if (deviceType == DeviceType::DEVICE_TYPE_FILE_SINK) {
        CHECK_AND_RETURN_RET_LOG(channelCount <= CHANNEL_8 && channelCount >= MONO, ERROR, "Invalid sink channel");
        module = FILE_SINK;
    } else if (deviceType == DeviceType::DEVICE_TYPE_FILE_SOURCE) {
        CHECK_AND_RETURN_RET_LOG(channelCount <= CHANNEL_6 && channelCount >= MONO, ERROR, "Invalid src channel");
        module = FILE_SOURCE;
    } else {
        AUDIO_ERR_LOG("Invalid DeviceType");
        return ERROR;
    }

    ClosePortAndEraseIOHandle(module);

    auto fileClass = deviceClassInfo_.find(ClassType::TYPE_FILE_IO);
    if (fileClass != deviceClassInfo_.end()) {
        auto moduleInfoList = fileClass->second;
        for (auto &moduleInfo : moduleInfoList) {
            if (module == moduleInfo.name) {
                moduleInfo.channels = to_string(channelCount);
                AudioIOHandle ioHandle = OpenPortAndInsertIOHandle(moduleInfo.name, moduleInfo);
                audioPolicyManager_.SetDeviceActive(ioHandle, deviceType, module, true);
            }
        }
    }

    return SUCCESS;
}

// private methods
AudioIOHandle AudioPolicyService::GetSinkIOHandle(InternalDeviceType deviceType)
{
    std::lock_guard<std::mutex> ioHandleLock(ioHandlesMutex_);
    AudioIOHandle ioHandle;
    switch (deviceType) {
        case InternalDeviceType::DEVICE_TYPE_WIRED_HEADSET:
        case InternalDeviceType::DEVICE_TYPE_WIRED_HEADPHONES:
        case InternalDeviceType::DEVICE_TYPE_USB_HEADSET:
        case InternalDeviceType::DEVICE_TYPE_EARPIECE:
        case InternalDeviceType::DEVICE_TYPE_SPEAKER:
        case InternalDeviceType::DEVICE_TYPE_BLUETOOTH_SCO:
            ioHandle = IOHandles_[PRIMARY_SPEAKER];
            break;
        case InternalDeviceType::DEVICE_TYPE_USB_ARM_HEADSET:
            ioHandle = IOHandles_[USB_SPEAKER];
            break;
        case InternalDeviceType::DEVICE_TYPE_BLUETOOTH_A2DP:
            ioHandle = IOHandles_[BLUETOOTH_SPEAKER];
            break;
        case InternalDeviceType::DEVICE_TYPE_FILE_SINK:
            ioHandle = IOHandles_[FILE_SINK];
            break;
        case InternalDeviceType::DEVICE_TYPE_DP:
            ioHandle = IOHandles_[DP_SINK];
            break;
        default:
            ioHandle = IOHandles_[PRIMARY_SPEAKER];
            break;
    }
    return ioHandle;
}

AudioIOHandle AudioPolicyService::GetSourceIOHandle(InternalDeviceType deviceType)
{
    std::lock_guard<std::mutex> ioHandleLock(ioHandlesMutex_);
    AudioIOHandle ioHandle;
    switch (deviceType) {
        case InternalDeviceType::DEVICE_TYPE_USB_ARM_HEADSET:
            ioHandle = IOHandles_[USB_MIC];
            break;
        case InternalDeviceType::DEVICE_TYPE_MIC:
            ioHandle = IOHandles_[PRIMARY_MIC];
            break;
        case InternalDeviceType::DEVICE_TYPE_FILE_SOURCE:
            ioHandle = IOHandles_[FILE_SOURCE];
            break;
        default:
            ioHandle = IOHandles_[PRIMARY_MIC];
            break;
    }
    return ioHandle;
}

InternalDeviceType AudioPolicyService::GetDeviceType(const std::string &deviceName)
{
    InternalDeviceType devType = InternalDeviceType::DEVICE_TYPE_NONE;
    if (deviceName == "Speaker") {
        devType = InternalDeviceType::DEVICE_TYPE_SPEAKER;
    } else if (deviceName == "Built_in_mic") {
        devType = InternalDeviceType::DEVICE_TYPE_MIC;
    } else if (deviceName == "Built_in_wakeup") {
        devType = InternalDeviceType::DEVICE_TYPE_WAKEUP;
    } else if (deviceName == "fifo_output" || deviceName == "fifo_input") {
        devType = DEVICE_TYPE_BLUETOOTH_SCO;
    } else if (deviceName == "file_sink") {
        devType = DEVICE_TYPE_FILE_SINK;
    } else if (deviceName == "file_source") {
        devType = DEVICE_TYPE_FILE_SOURCE;
    }

    return devType;
}

std::string AudioPolicyService::GetGroupName(const std::string& deviceName, const GroupType type)
{
    std::string groupName = GROUP_NAME_NONE;
    if (type == VOLUME_TYPE) {
        auto iter = volumeGroupData_.find(deviceName);
        if (iter != volumeGroupData_.end()) {
            groupName = iter->second;
        }
    } else {
        auto iter = interruptGroupData_.find(deviceName);
        if (iter != interruptGroupData_.end()) {
            groupName = iter->second;
        }
    }
    return groupName;
}

void AudioPolicyService::WriteDeviceChangedSysEvents(const vector<sptr<AudioDeviceDescriptor>> &desc, bool isConnected)
{
    for (auto deviceDescriptor : desc) {
        if (deviceDescriptor != nullptr) {
            if ((deviceDescriptor->deviceType_ == DEVICE_TYPE_WIRED_HEADSET)
                || (deviceDescriptor->deviceType_ == DEVICE_TYPE_USB_HEADSET)
                || (deviceDescriptor->deviceType_ == DEVICE_TYPE_WIRED_HEADPHONES)) {
                std::shared_ptr<Media::MediaMonitor::EventBean> bean = std::make_shared<Media::MediaMonitor::EventBean>(
                    Media::MediaMonitor::AUDIO, Media::MediaMonitor::HEADSET_CHANGE,
                    Media::MediaMonitor::BEHAVIOR_EVENT);
                bean->Add("HASMIC", 1);
                bean->Add("ISCONNECT", isConnected ? 1 : 0);
                bean->Add("DEVICETYPE", deviceDescriptor->deviceType_);
                Media::MediaMonitor::MediaMonitorManager::GetInstance().WriteLogMsg(bean);
            }

            if (!isConnected) {
                continue;
            }

            if (deviceDescriptor->deviceRole_ == OUTPUT_DEVICE) {
                vector<SinkInput> sinkInputs = audioPolicyManager_.GetAllSinkInputs();
                for (SinkInput sinkInput : sinkInputs) {
                    WriteOutDeviceChangedSysEvents(deviceDescriptor, sinkInput);
                }
            } else if (deviceDescriptor->deviceRole_ == INPUT_DEVICE) {
                vector<SourceOutput> sourceOutputs = audioPolicyManager_.GetAllSourceOutputs();
                for (SourceOutput sourceOutput : sourceOutputs) {
                    WriteInDeviceChangedSysEvents(deviceDescriptor, sourceOutput);
                }
            }
        }
    }
}

void AudioPolicyService::WriteOutDeviceChangedSysEvents(const sptr<AudioDeviceDescriptor> &deviceDescriptor,
    const SinkInput &sinkInput)
{
    std::shared_ptr<Media::MediaMonitor::EventBean> bean = std::make_shared<Media::MediaMonitor::EventBean>(
        Media::MediaMonitor::AUDIO, Media::MediaMonitor::DEVICE_CHANGE,
        Media::MediaMonitor::BEHAVIOR_EVENT);
    bean->Add("ISOUTPUT", 1);
    bean->Add("STREAMID", sinkInput.streamId);
    bean->Add("STREAMTYPE", sinkInput.streamType);
    bean->Add("DEVICETYPE", deviceDescriptor->deviceType_);
    bean->Add("NETWORKID", deviceDescriptor->networkId_);
    bean->Add("ADDRESS", GetEncryptAddr(deviceDescriptor->macAddress_));
    bean->Add("DEVICE_NAME", deviceDescriptor->deviceName_);
    bean->Add("CATEGORY", deviceDescriptor->deviceCategory_);
    Media::MediaMonitor::MediaMonitorManager::GetInstance().WriteLogMsg(bean);
}

void AudioPolicyService::WriteInDeviceChangedSysEvents(const sptr<AudioDeviceDescriptor> &deviceDescriptor,
    const SourceOutput &sourceOutput)
{
    std::shared_ptr<Media::MediaMonitor::EventBean> bean = std::make_shared<Media::MediaMonitor::EventBean>(
        Media::MediaMonitor::AUDIO, Media::MediaMonitor::DEVICE_CHANGE,
        Media::MediaMonitor::BEHAVIOR_EVENT);
    bean->Add("ISOUTPUT", 0);
    bean->Add("STREAMID", sourceOutput.streamId);
    bean->Add("STREAMTYPE", sourceOutput.streamType);
    bean->Add("DEVICETYPE", deviceDescriptor->deviceType_);
    bean->Add("NETWORKID", deviceDescriptor->networkId_);
    bean->Add("ADDRESS", GetEncryptAddr(deviceDescriptor->macAddress_));
    bean->Add("DEVICE_NAME", deviceDescriptor->deviceName_);
    bean->Add("CATEGORY", deviceDescriptor->deviceCategory_);
    Media::MediaMonitor::MediaMonitorManager::GetInstance().WriteLogMsg(bean);
}

void AudioPolicyService::UpdateTrackerDeviceChange(const vector<sptr<AudioDeviceDescriptor>> &desc)
{
    AUDIO_INFO_LOG("Start");

    DeviceType activeDevice = DEVICE_TYPE_NONE;
    auto isOutputDevicePresent = [&activeDevice, this] (const sptr<AudioDeviceDescriptor> &desc) {
        CHECK_AND_RETURN_RET_LOG(desc != nullptr, false, "Invalid device descriptor");
        if ((activeDevice == desc->deviceType_) && (OUTPUT_DEVICE == desc->deviceRole_)) {
            if (activeDevice == DEVICE_TYPE_BLUETOOTH_A2DP) {
                // If the device type is A2DP, need to compare mac address in addition.
                return desc->macAddress_ == currentActiveDevice_.macAddress_;
            }
            return true;
        }
        return false;
    };
    auto isInputDevicePresent = [&activeDevice] (const sptr<AudioDeviceDescriptor> &desc) {
        CHECK_AND_RETURN_RET_LOG(desc != nullptr, false, "Invalid device descriptor");
        return ((activeDevice == desc->deviceType_) && (INPUT_DEVICE == desc->deviceRole_));
    };

    for (sptr<AudioDeviceDescriptor> deviceDesc : desc) {
        if (deviceDesc->deviceRole_ == OUTPUT_DEVICE) {
            activeDevice = currentActiveDevice_.deviceType_;
            auto itr = std::find_if(connectedDevices_.begin(), connectedDevices_.end(), isOutputDevicePresent);
            if (itr != connectedDevices_.end()) {
                DeviceInfo outputDevice = {};
                UpdateDeviceInfo(outputDevice, *itr, true, true);
                streamCollector_.UpdateTracker(AUDIO_MODE_PLAYBACK, outputDevice);
            }
        }

        if (deviceDesc->deviceRole_ == INPUT_DEVICE) {
            activeDevice = currentActiveInputDevice_.deviceType_;
            auto itr = std::find_if(connectedDevices_.begin(), connectedDevices_.end(), isInputDevicePresent);
            if (itr != connectedDevices_.end()) {
                DeviceInfo inputDevice = {};
                UpdateDeviceInfo(inputDevice, *itr, true, true);
                UpdateAudioCapturerMicrophoneDescriptor((*itr)->deviceType_);
                streamCollector_.UpdateTracker(AUDIO_MODE_RECORD, inputDevice);
            }
        }
    }
}

void AudioPolicyService::UpdateGroupInfo(GroupType type, std::string groupName, int32_t& groupId, std::string networkId,
    bool connected, int32_t mappingId)
{
    ConnectType connectType = CONNECT_TYPE_LOCAL;
    if (networkId != LOCAL_NETWORK_ID) {
        connectType = CONNECT_TYPE_DISTRIBUTED;
    }
    if (type == GroupType::VOLUME_TYPE) {
        auto isPresent = [&groupName, &networkId] (const sptr<VolumeGroupInfo> &volumeInfo) {
            return ((groupName == volumeInfo->groupName_) || (networkId == volumeInfo->networkId_));
        };

        auto iter = std::find_if(volumeGroups_.begin(), volumeGroups_.end(), isPresent);
        if (iter != volumeGroups_.end()) {
            groupId = (*iter)->volumeGroupId_;
            // if status is disconnected, remove the group that has none audio device
            std::vector<sptr<AudioDeviceDescriptor>> devsInGroup = GetDevicesForGroup(type, groupId);
            if (!connected && devsInGroup.size() == 0) {
                volumeGroups_.erase(iter);
            }
            return;
        }
        if (groupName != GROUP_NAME_NONE && connected) {
            groupId = AudioGroupHandle::GetInstance().GetNextId(type);
            sptr<VolumeGroupInfo> volumeGroupInfo = new(std::nothrow) VolumeGroupInfo(groupId,
                mappingId, groupName, networkId, connectType);
            volumeGroups_.push_back(volumeGroupInfo);
        }
    } else {
        auto isPresent = [&groupName, &networkId] (const sptr<InterruptGroupInfo> &info) {
            return ((groupName == info->groupName_) || (networkId == info->networkId_));
        };

        auto iter = std::find_if(interruptGroups_.begin(), interruptGroups_.end(), isPresent);
        if (iter != interruptGroups_.end()) {
            groupId = (*iter)->interruptGroupId_;
            // if status is disconnected, remove the group that has none audio device
            std::vector<sptr<AudioDeviceDescriptor>> devsInGroup = GetDevicesForGroup(type, groupId);
            if (!connected && devsInGroup.size() == 0) {
                interruptGroups_.erase(iter);
            }
            return;
        }
        if (groupName != GROUP_NAME_NONE && connected) {
            groupId = AudioGroupHandle::GetInstance().GetNextId(type);
            sptr<InterruptGroupInfo> interruptGroupInfo = new(std::nothrow) InterruptGroupInfo(groupId, mappingId,
                groupName, networkId, connectType);
            interruptGroups_.push_back(interruptGroupInfo);
        }
    }
}

std::vector<sptr<OHOS::AudioStandard::AudioDeviceDescriptor>> AudioPolicyService::GetDevicesForGroup(GroupType type,
    int32_t groupId)
{
    std::vector<sptr<OHOS::AudioStandard::AudioDeviceDescriptor>> devices = {};
    for (auto devDes : connectedDevices_) {
        if (devDes == nullptr) {
            continue;
        }
        bool inVolumeGroup = type == VOLUME_TYPE && devDes->volumeGroupId_ == groupId;
        bool inInterruptGroup = type == INTERRUPT_TYPE && devDes->interruptGroupId_ == groupId;

        if (inVolumeGroup || inInterruptGroup) {
            sptr<AudioDeviceDescriptor> device = new AudioDeviceDescriptor(*devDes);
            devices.push_back(device);
        }
    }
    return devices;
}

void AudioPolicyService::UpdateDescWhenNoBTPermission(vector<sptr<AudioDeviceDescriptor>> &deviceDescs)
{
    AUDIO_WARNING_LOG("No bt permission");

    for (sptr<AudioDeviceDescriptor> &desc : deviceDescs) {
        if ((desc->deviceType_ == DEVICE_TYPE_BLUETOOTH_A2DP) || (desc->deviceType_ == DEVICE_TYPE_BLUETOOTH_SCO)) {
            sptr<AudioDeviceDescriptor> copyDesc = new AudioDeviceDescriptor(desc);
            copyDesc->deviceName_ = "";
            copyDesc->macAddress_ = "";
            desc = copyDesc;
        }
    }
}

int32_t AudioPolicyService::SetDeviceAbsVolumeSupported(const std::string &macAddress, const bool support)
{
    std::lock_guard<std::mutex> lock(a2dpDeviceMapMutex_);
    // Maximum number of attempts, preventing situations where a2dp device has not yet finished coming online.
    int maxRetries = 3;
    int retryCount = 0;
    while (retryCount < maxRetries) {
        retryCount++;
        auto configInfoPos = connectedA2dpDeviceMap_.find(macAddress);
        if (configInfoPos != connectedA2dpDeviceMap_.end()) {
            configInfoPos->second.absVolumeSupport = support;
            audioPolicyManager_.SetAbsVolumeScene(support);
            break;
        }
        CHECK_AND_RETURN_RET_LOG(retryCount != maxRetries, ERROR,
            "failed, can't find device for macAddress:[%{public}s]", GetEncryptAddr(macAddress).c_str());;
        usleep(ABS_VOLUME_SUPPORT_RETRY_INTERVAL_IN_MICROSECONDS);
    }

    AUDIO_INFO_LOG("success for macAddress:[%{public}s], support: %{public}d, active bt:[%{public}s]",
        GetEncryptAddr(macAddress).c_str(), support, GetEncryptAddr(activeBTDevice_).c_str());

    if (activeBTDevice_ == macAddress) {
        int32_t volumeLevel = audioPolicyManager_.GetSystemVolumeLevel(STREAM_MUSIC);
        audioPolicyManager_.SetSystemVolumeLevel(STREAM_MUSIC, volumeLevel);
    }
    return SUCCESS;
}

bool AudioPolicyService::IsAbsVolumeScene() const
{
    return audioPolicyManager_.IsAbsVolumeScene();
}

bool AudioPolicyService::IsWiredHeadSet(const DeviceType &deviceType)
{
    switch (deviceType) {
        case DEVICE_TYPE_WIRED_HEADSET:
        case DEVICE_TYPE_WIRED_HEADPHONES:
        case DEVICE_TYPE_USB_HEADSET:
        case DEVICE_TYPE_USB_ARM_HEADSET:
            return true;
        default:
            return false;
    }
}

bool AudioPolicyService::IsBlueTooth(const DeviceType &deviceType)
{
    if (deviceType == DEVICE_TYPE_BLUETOOTH_A2DP || deviceType == DEVICE_TYPE_BLUETOOTH_SCO) {
        if (currentActiveDevice_.deviceCategory_ == BT_HEADPHONE) {
            return true;
        }
    }
    return false;
}

void AudioPolicyService::CheckBlueToothActiveMusicTime(int32_t safeVolume)
{
    if (startSafeTimeBt_ == 0) {
        startSafeTimeBt_ = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    }
    int32_t currentTime = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    if (activeSafeTimeBt_ >= ONE_MINUTE * audioPolicyManager_.GetSafeVolumeTimeout()) {
        AUDIO_INFO_LOG("safe volume timeout");
        audioPolicyManager_.SetDeviceSafeStatus(DEVICE_TYPE_BLUETOOTH_A2DP, SAFE_ACTIVE);
        audioPolicyManager_.SetDeviceSafeTime(DEVICE_TYPE_BLUETOOTH_A2DP, 0);
        startSafeTimeBt_ = 0;
        safeStatusBt_ = SAFE_ACTIVE;
        userSelect_ = false;
        isDialogSelectDestroy_.store(false);
        SetSystemVolumeLevel(STREAM_MUSIC, safeVolume);
        activeSafeTimeBt_ = 0;
    } else if (currentTime - startSafeTimeBt_ >= ONE_MINUTE) {
        AUDIO_INFO_LOG("safe volume 1 min timeout");
        activeSafeTimeBt_ = audioPolicyManager_.GetCurentDeviceSafeTime(DEVICE_TYPE_BLUETOOTH_A2DP);
        activeSafeTimeBt_ += currentTime - startSafeTimeBt_;
        audioPolicyManager_.SetDeviceSafeTime(DEVICE_TYPE_BLUETOOTH_A2DP, activeSafeTimeBt_);
        startSafeTimeBt_ = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    }
    startSafeTime_ = 0;
}

void AudioPolicyService::CheckWiredActiveMusicTime(int32_t safeVolume)
{
    if (startSafeTime_ == 0) {
        startSafeTime_ = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    }
    int32_t currentTime = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    if (activeSafeTime_ >= ONE_MINUTE * audioPolicyManager_.GetSafeVolumeTimeout()) {
        AUDIO_INFO_LOG("safe volume timeout");
        audioPolicyManager_.SetDeviceSafeStatus(DEVICE_TYPE_WIRED_HEADSET, SAFE_ACTIVE);
        audioPolicyManager_.SetDeviceSafeTime(DEVICE_TYPE_WIRED_HEADSET, 0);
        startSafeTime_ = 0;
        safeStatus_ = SAFE_ACTIVE;
        userSelect_ = false;
        isDialogSelectDestroy_.store(false);
        SetSystemVolumeLevel(STREAM_MUSIC, safeVolume);
        activeSafeTime_ = 0;
    } else if (currentTime - startSafeTime_ >= ONE_MINUTE) {
        AUDIO_INFO_LOG("safe volume 1 min timeout");
        activeSafeTime_ = audioPolicyManager_.GetCurentDeviceSafeTime(DEVICE_TYPE_WIRED_HEADSET);
        activeSafeTime_ += currentTime - startSafeTime_;
        audioPolicyManager_.SetDeviceSafeTime(DEVICE_TYPE_WIRED_HEADSET, activeSafeTime_);
        startSafeTime_ = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    }
    startSafeTimeBt_ = 0;
}

int32_t AudioPolicyService::CheckActiveMusicTime()
{
    AUDIO_INFO_LOG("enter");
    int32_t safeVolume = audioPolicyManager_.GetSafeVolumeLevel();
    bool activeMusic = false;
    bool isUpSafeVolume = false;
    while (!safeVolumeExit_) {
        activeMusic = IsStreamActive(STREAM_MUSIC);
        isUpSafeVolume = GetSystemVolumeLevel(STREAM_MUSIC) > safeVolume ? true : false;
        AUDIO_INFO_LOG("activeMusic:%{public}d, deviceType_:%{public}d, isUpSafeVolume:%{public}d",
            activeMusic, currentActiveDevice_.deviceType_, isUpSafeVolume);
        if (activeMusic && (safeStatusBt_ == SAFE_INACTIVE) && isUpSafeVolume &&
            IsBlueTooth(currentActiveDevice_.deviceType_)) {
            CheckBlueToothActiveMusicTime(safeVolume);
        } else if (activeMusic && (safeStatus_ == SAFE_INACTIVE) && isUpSafeVolume &&
            IsWiredHeadSet(currentActiveDevice_.deviceType_)) {
            CheckWiredActiveMusicTime(safeVolume);
        } else {
            startSafeTime_ = 0;
            startSafeTimeBt_ = 0;
        }
        sleep(ONE_MINUTE);
    }
    return 0;
}

void AudioPolicyService::CreateCheckMusicActiveThread()
{
    if (calculateLoopSafeTime_ == nullptr) {
        calculateLoopSafeTime_ = std::make_unique<std::thread>(&AudioPolicyService::CheckActiveMusicTime, this);
        pthread_setname_np(calculateLoopSafeTime_->native_handle(), "OS_AudioPolicySafe");
    }
}

int32_t AudioPolicyService::DealWithSafeVolume(const int32_t volumeLevel, bool isA2dpDevice)
{
    if (isA2dpDevice) {
        AUDIO_INFO_LOG("bluetooth Category:%{public}d", currentActiveDevice_.deviceCategory_);
        if (currentActiveDevice_.deviceCategory_ != BT_HEADPHONE) {
            return volumeLevel;
        }
    }

    int32_t sVolumeLevel = volumeLevel;
    safeStatusBt_ = audioPolicyManager_.GetCurrentDeviceSafeStatus(DEVICE_TYPE_BLUETOOTH_A2DP);
    safeStatus_ = audioPolicyManager_.GetCurrentDeviceSafeStatus(DEVICE_TYPE_WIRED_HEADSET);
    if ((safeStatusBt_ == SAFE_INACTIVE && isA2dpDevice) ||
        (safeStatus_ == SAFE_INACTIVE && !isA2dpDevice)) {
        CreateCheckMusicActiveThread();
        return sVolumeLevel;
    }

    if (isA2dpDevice && (safeStatusBt_ == SAFE_ACTIVE)) {
        if (ShowDialog() != SUCCESS) {
            return volumeLevel;
        }
        sVolumeLevel = audioPolicyManager_.GetSafeVolumeLevel();
        if (userSelect_) {
            safeStatusBt_ = SAFE_INACTIVE;
            audioPolicyManager_.SetDeviceSafeStatus(DEVICE_TYPE_BLUETOOTH_A2DP, safeStatusBt_);
            CreateCheckMusicActiveThread();
        }
        return sVolumeLevel;
    } else if (!isA2dpDevice && safeStatus_ == SAFE_ACTIVE) {
        if (ShowDialog() != SUCCESS) {
            return volumeLevel;
        }
        sVolumeLevel = audioPolicyManager_.GetSafeVolumeLevel();
        if (userSelect_) {
            safeStatus_ = SAFE_INACTIVE;
            audioPolicyManager_.SetDeviceSafeStatus(DEVICE_TYPE_WIRED_HEADSET, safeStatus_);
            CreateCheckMusicActiveThread();
        }
        return sVolumeLevel;
    }
    return sVolumeLevel;
}


int32_t AudioPolicyService::ShowDialog()
{
    auto abilityMgrClient = AAFwk::AbilityManagerClient::GetInstance();
    CHECK_AND_RETURN_RET_LOG(abilityMgrClient != nullptr, ERROR, "abilityMgrClient malloc failed");
    sptr<OHOS::AAFwk::IAbilityConnection> dialogConnectionCallback = new (std::nothrow)AudioDialogAbilityConnection();
    CHECK_AND_RETURN_RET_LOG(dialogConnectionCallback != nullptr, ERROR, "abilityMgrClient malloc failed");

    AAFwk::Want want;
    std::string bundleName = "com.ohos.sceneboard";
    std::string abilityName = "com.ohos.sceneboard.systemdialog";
    want.SetElementName(bundleName, abilityName);
    ErrCode result = abilityMgrClient->ConnectAbility(want, dialogConnectionCallback,
        AppExecFwk::Constants::INVALID_USERID);
    CHECK_AND_RETURN_RET_LOG(result == SUCCESS, result, "ConnectAbility failed");

    std::unique_lock<std::mutex> lock(dialogMutex_);
    if (!isDialogSelectDestroy_.load()) {
        auto status = dialogSelectCondition_.wait_for(lock, std::chrono::seconds(WAIT_DIALOG_CLOSE_TIME_S),
            [this] () { return isDialogSelectDestroy_.load(); });
        if (!status) {
            AUDIO_ERR_LOG("user cancel or not select");
        }
        isDialogSelectDestroy_.store(false);
    }
    return result;
}

int32_t AudioPolicyService::HandleAbsBluetoothVolume(const std::string &macAddress, const int32_t volumeLevel)
{
    int32_t sVolumeLevel = volumeLevel;
    if (isAbsBtFirstBoot_) {
        sVolumeLevel = audioPolicyManager_.GetSafeVolumeLevel();
        isAbsBtFirstBoot_ = false;
        Bluetooth::AudioA2dpManager::SetDeviceAbsVolume(macAddress, sVolumeLevel);
    } else {
        sVolumeLevel = DealWithSafeVolume(volumeLevel, true);
        if (sVolumeLevel != volumeLevel) {
            Bluetooth::AudioA2dpManager::SetDeviceAbsVolume(macAddress, sVolumeLevel);
        }
    }
    return sVolumeLevel;
}

int32_t AudioPolicyService::SetA2dpDeviceVolume(const std::string &macAddress, const int32_t volumeLevel,
    bool internalCall)
{
    std::lock_guard<std::mutex> lock(a2dpDeviceMapMutex_);
    auto configInfoPos = connectedA2dpDeviceMap_.find(macAddress);
    CHECK_AND_RETURN_RET_LOG(configInfoPos != connectedA2dpDeviceMap_.end() && configInfoPos->second.absVolumeSupport,
        ERROR, "failed for macAddress:[%{public}s]", GetEncryptAddr(macAddress).c_str());
    configInfoPos->second.volumeLevel = volumeLevel;
    int32_t sVolumeLevel = volumeLevel;
    if (volumeLevel > audioPolicyManager_.GetSafeVolumeLevel()) {
        if (internalCall) {
            sVolumeLevel = DealWithSafeVolume(volumeLevel, true);
        } else {
            sVolumeLevel = HandleAbsBluetoothVolume(macAddress, volumeLevel);
        }
    }
    configInfoPos->second.volumeLevel = sVolumeLevel;
    if (sVolumeLevel > 0) {
        configInfoPos->second.mute = false;
    }
    AUDIO_DEBUG_LOG("success for macaddress:[%{public}s], volume value:[%{public}d]",
        GetEncryptAddr(macAddress).c_str(), sVolumeLevel);
    CHECK_AND_RETURN_RET_LOG(sVolumeLevel == volumeLevel, ERR_UNKNOWN, "safevolume did not deal");
    return SUCCESS;
}

void AudioPolicyService::TriggerDeviceChangedCallback(const vector<sptr<AudioDeviceDescriptor>> &desc, bool isConnected)
{
    Trace trace("AudioPolicyService::TriggerDeviceChangedCallback");
    WriteDeviceChangedSysEvents(desc, isConnected);
    if (audioPolicyServerHandler_ != nullptr) {
        audioPolicyServerHandler_->SendDeviceChangedCallback(desc, isConnected);
    }
}

DeviceRole AudioPolicyService::GetDeviceRole(DeviceType deviceType) const
{
    switch (deviceType) {
        case DeviceType::DEVICE_TYPE_EARPIECE:
        case DeviceType::DEVICE_TYPE_SPEAKER:
        case DeviceType::DEVICE_TYPE_BLUETOOTH_SCO:
        case DeviceType::DEVICE_TYPE_BLUETOOTH_A2DP:
        case DeviceType::DEVICE_TYPE_WIRED_HEADSET:
        case DeviceType::DEVICE_TYPE_WIRED_HEADPHONES:
        case DeviceType::DEVICE_TYPE_USB_HEADSET:
        case DeviceType::DEVICE_TYPE_DP:
        case DeviceType::DEVICE_TYPE_USB_ARM_HEADSET:
        case DeviceType::DEVICE_TYPE_REMOTE_CAST:
            return DeviceRole::OUTPUT_DEVICE;
        case DeviceType::DEVICE_TYPE_MIC:
        case DeviceType::DEVICE_TYPE_WAKEUP:
            return DeviceRole::INPUT_DEVICE;
        default:
            return DeviceRole::DEVICE_ROLE_NONE;
    }
}

DeviceRole AudioPolicyService::GetDeviceRole(const std::string &role)
{
    if (role == ROLE_SINK) {
        return DeviceRole::OUTPUT_DEVICE;
    } else if (role == ROLE_SOURCE) {
        return DeviceRole::INPUT_DEVICE;
    } else {
        return DeviceRole::DEVICE_ROLE_NONE;
    }
}

DeviceRole AudioPolicyService::GetDeviceRole(AudioPin pin) const
{
    switch (pin) {
        case OHOS::AudioStandard::AUDIO_PIN_NONE:
            return DeviceRole::DEVICE_ROLE_NONE;
        case OHOS::AudioStandard::AUDIO_PIN_OUT_SPEAKER:
        case OHOS::AudioStandard::AUDIO_PIN_OUT_HEADSET:
        case OHOS::AudioStandard::AUDIO_PIN_OUT_LINEOUT:
        case OHOS::AudioStandard::AUDIO_PIN_OUT_HDMI:
        case OHOS::AudioStandard::AUDIO_PIN_OUT_USB:
        case OHOS::AudioStandard::AUDIO_PIN_OUT_USB_EXT:
        case OHOS::AudioStandard::AUDIO_PIN_OUT_DAUDIO_DEFAULT:
            return DeviceRole::OUTPUT_DEVICE;
        case OHOS::AudioStandard::AUDIO_PIN_IN_MIC:
        case OHOS::AudioStandard::AUDIO_PIN_IN_HS_MIC:
        case OHOS::AudioStandard::AUDIO_PIN_IN_LINEIN:
        case OHOS::AudioStandard::AUDIO_PIN_IN_USB_EXT:
        case OHOS::AudioStandard::AUDIO_PIN_IN_DAUDIO_DEFAULT:
            return DeviceRole::INPUT_DEVICE;
        default:
            return DeviceRole::DEVICE_ROLE_NONE;
    }
}

void AudioPolicyService::OnAudioLatencyParsed(uint64_t latency)
{
    audioLatencyInMsec_ = latency;
}

int32_t AudioPolicyService::GetAudioLatencyFromXml() const
{
    return audioLatencyInMsec_;
}

void AudioPolicyService::OnSinkLatencyParsed(uint32_t latency)
{
    sinkLatencyInMsec_ = latency;
}

uint32_t AudioPolicyService::GetSinkLatencyFromXml() const
{
    return sinkLatencyInMsec_;
}

int32_t AudioPolicyService::GetPreferredOutputStreamType(AudioRendererInfo &rendererInfo)
{
    // Use GetPreferredOutputDeviceDescriptors instead of currentActiveDevice, if prefer != current, recreate stream
    std::vector<sptr<AudioDeviceDescriptor>> preferredDeviceList = GetPreferredOutputDeviceDescriptors(rendererInfo);
    if (preferredDeviceList.size() == 0) {
        return AUDIO_FLAG_INVALID;
    }
    std::string sinkPortName = GetSinkPortName(preferredDeviceList[0]->deviceType_);
    if (adapterInfoMap_.find(static_cast<AdaptersType>(classStrToEnum[sinkPortName])) == adapterInfoMap_.end()) {
        return AUDIO_FLAG_INVALID;
    }
    AudioAdapterInfo adapterInfo;
    auto it = adapterInfoMap_.find(static_cast<AdaptersType>(classStrToEnum[sinkPortName]));
    if (it != adapterInfoMap_.end()) {
        adapterInfo = it->second;
    } else {
        AUDIO_ERR_LOG("Invalid adapter");
        return AUDIO_FLAG_INVALID;
    }

    AudioPipeDeviceInfo* deviceInfo = adapterInfo.GetDeviceInfoByDeviceType(preferredDeviceList[0]->deviceType_);
    CHECK_AND_RETURN_RET_LOG(deviceInfo != nullptr, AUDIO_FLAG_INVALID, "Device type is not supported");
    for (auto &supportPipe : deviceInfo->supportPipes_) {
        PipeInfo* pipeInfo = adapterInfo.GetPipeByName(supportPipe);
        if (pipeInfo == nullptr) {
            continue;
        }
        if (rendererInfo.rendererFlags == AUDIO_FLAG_MMAP && pipeInfo->audioFlag_ == AUDIO_FLAG_MMAP) {
            return AUDIO_FLAG_MMAP;
        }
        if (rendererInfo.rendererFlags == AUDIO_FLAG_VOIP_FAST && pipeInfo->audioUsage_ == AUDIO_USAGE_VOIP &&
            pipeInfo->audioFlag_ == AUDIO_FLAG_MMAP) {
            return AUDIO_FLAG_VOIP_FAST;
        }
    }
    return AUDIO_FLAG_NORMAL;
}

int32_t AudioPolicyService::GetPreferredInputStreamType(AudioCapturerInfo &capturerInfo)
{
    // Use GetPreferredInputDeviceDescriptors instead of currentActiveDevice, if prefer != current, recreate stream
    std::vector<sptr<AudioDeviceDescriptor>> preferredDeviceList = GetPreferredInputDeviceDescriptors(capturerInfo);
    if (preferredDeviceList.size() == 0) {
        return AUDIO_FLAG_INVALID;
    }
    std::string sourcePortName = GetSourcePortName(preferredDeviceList[0]->deviceType_);
    if (adapterInfoMap_.find(static_cast<AdaptersType>(classStrToEnum[sourcePortName])) == adapterInfoMap_.end()) {
        return AUDIO_FLAG_INVALID;
    }
    AudioAdapterInfo adapterInfo;
    auto it = adapterInfoMap_.find(static_cast<AdaptersType>(classStrToEnum[sourcePortName]));
    if (it != adapterInfoMap_.end()) {
        adapterInfo = it->second;
    } else {
        AUDIO_ERR_LOG("Invalid adapter");
        return AUDIO_FLAG_INVALID;
    }
    AudioPipeDeviceInfo* deviceInfo = adapterInfo.GetDeviceInfoByDeviceType(preferredDeviceList[0]->deviceType_);
    CHECK_AND_RETURN_RET_LOG(deviceInfo != nullptr, AUDIO_FLAG_INVALID, "Device type is not supported");
    for (auto &supportPipe : deviceInfo->supportPipes_) {
        PipeInfo* pipeInfo = adapterInfo.GetPipeByName(supportPipe);
        if (pipeInfo == nullptr) {
            continue;
        }
        if (capturerInfo.capturerFlags == AUDIO_FLAG_MMAP && pipeInfo->audioFlag_ == AUDIO_FLAG_MMAP) {
            return AUDIO_FLAG_MMAP;
        }
        if (capturerInfo.capturerFlags == AUDIO_FLAG_VOIP_FAST && pipeInfo->audioUsage_ == AUDIO_USAGE_VOIP &&
            pipeInfo->audioFlag_ == AUDIO_FLAG_MMAP) {
            return AUDIO_FLAG_VOIP_FAST;
        }
    }
    return AUDIO_FLAG_NORMAL;
}

void AudioPolicyService::UpdateInputDeviceInfo(DeviceType deviceType)
{
    AUDIO_DEBUG_LOG("Current input device is %{public}d", currentActiveInputDevice_.deviceType_);

    switch (deviceType) {
        case DEVICE_TYPE_EARPIECE:
        case DEVICE_TYPE_SPEAKER:
        case DEVICE_TYPE_BLUETOOTH_A2DP:
            currentActiveInputDevice_.deviceType_ = DEVICE_TYPE_MIC;
            break;
        case DEVICE_TYPE_FILE_SINK:
            currentActiveInputDevice_.deviceType_ = DEVICE_TYPE_FILE_SOURCE;
            break;
        case DEVICE_TYPE_USB_ARM_HEADSET:
            currentActiveInputDevice_.deviceType_ = DEVICE_TYPE_USB_HEADSET;
            break;
        case DEVICE_TYPE_WIRED_HEADSET:
        case DEVICE_TYPE_USB_HEADSET:
        case DEVICE_TYPE_BLUETOOTH_SCO:
            currentActiveInputDevice_.deviceType_ = deviceType;
            break;
        default:
            break;
    }

    AUDIO_DEBUG_LOG("Input device updated to %{public}d", currentActiveInputDevice_.deviceType_);
}

int32_t AudioPolicyService::UpdateStreamState(int32_t clientUid,
    StreamSetStateEventInternal &streamSetStateEventInternal)
{
    return streamCollector_.UpdateStreamState(clientUid, streamSetStateEventInternal);
}

AudioStreamType AudioPolicyService::GetStreamType(int32_t sessionId)
{
    return streamCollector_.GetStreamType(sessionId);
}

int32_t AudioPolicyService::GetChannelCount(uint32_t sessionId)
{
    return streamCollector_.GetChannelCount(sessionId);
}

int32_t AudioPolicyService::GetUid(int32_t sessionId)
{
    return streamCollector_.GetUid(sessionId);
}

DeviceType AudioPolicyService::GetDeviceTypeFromPin(AudioPin hdiPin)
{
    switch (hdiPin) {
        case OHOS::AudioStandard::AUDIO_PIN_NONE:
            break;
        case OHOS::AudioStandard::AUDIO_PIN_OUT_SPEAKER:
        case OHOS::AudioStandard::AUDIO_PIN_OUT_DAUDIO_DEFAULT:
            return DeviceType::DEVICE_TYPE_SPEAKER;
        case OHOS::AudioStandard::AUDIO_PIN_OUT_HEADSET:
            break;
        case OHOS::AudioStandard::AUDIO_PIN_OUT_LINEOUT:
            break;
        case OHOS::AudioStandard::AUDIO_PIN_OUT_HDMI:
            break;
        case OHOS::AudioStandard::AUDIO_PIN_OUT_USB:
            break;
        case OHOS::AudioStandard::AUDIO_PIN_OUT_USB_EXT:
            break;
        case OHOS::AudioStandard::AUDIO_PIN_OUT_USB_HEADSET:
        case OHOS::AudioStandard::AUDIO_PIN_IN_USB_HEADSET:
            return DeviceType::DEVICE_TYPE_USB_ARM_HEADSET;
        case OHOS::AudioStandard::AUDIO_PIN_IN_MIC:
        case OHOS::AudioStandard::AUDIO_PIN_IN_DAUDIO_DEFAULT:
            return DeviceType::DEVICE_TYPE_MIC;
        case OHOS::AudioStandard::AUDIO_PIN_IN_HS_MIC:
            break;
        case OHOS::AudioStandard::AUDIO_PIN_IN_LINEIN:
            break;
        case OHOS::AudioStandard::AUDIO_PIN_IN_USB_EXT:
            break;
        default:
            break;
    }
    return DeviceType::DEVICE_TYPE_DEFAULT;
}

std::vector<sptr<VolumeGroupInfo>> AudioPolicyService::GetVolumeGroupInfos()
{
    std::vector<sptr<VolumeGroupInfo>> volumeGroupInfos = {};

    for (auto& v : volumeGroups_) {
        sptr<VolumeGroupInfo> info = new(std::nothrow) VolumeGroupInfo(v->volumeGroupId_, v->mappingId_, v->groupName_,
            v->networkId_, v->connectType_);
        volumeGroupInfos.push_back(info);
    }
    return volumeGroupInfos;
}

void AudioPolicyService::RegiestPolicy()
{
    AUDIO_INFO_LOG("Start");
    const sptr<IStandardAudioService> gsp = GetAudioServerProxy();
    CHECK_AND_RETURN_LOG(gsp != nullptr, "RegiestPolicy g_adProxy null");

    sptr<PolicyProviderWrapper> wrapper = new(std::nothrow) PolicyProviderWrapper(this);
    CHECK_AND_RETURN_LOG(wrapper != nullptr, "Get null PolicyProviderWrapper");
    sptr<IRemoteObject> object = wrapper->AsObject();
    CHECK_AND_RETURN_LOG(object != nullptr, "RegiestPolicy AsObject is nullptr");
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    int32_t ret = gsp->RegiestPolicyProvider(object);
    IPCSkeleton::SetCallingIdentity(identity);
    AUDIO_DEBUG_LOG("result:%{public}d", ret);
}

int32_t AudioPolicyService::GetProcessDeviceInfo(const AudioProcessConfig &config, DeviceInfo &deviceInfo)
{
    AUDIO_INFO_LOG("%{public}s", ProcessConfig::DumpProcessConfig(config).c_str());
    // todo
    // check process in routerMap, return target device for it
    // put the currentActiveDevice_ in deviceinfo, so it can create with current using device.
    // genarate the unique deviceid?

    if (config.audioMode == AUDIO_MODE_RECORD) {
        deviceInfo.deviceId = 1;
        deviceInfo.networkId = LOCAL_NETWORK_ID;
        deviceInfo.deviceRole = INPUT_DEVICE;
        deviceInfo.deviceType = currentActiveInputDevice_.deviceType_;
    } else {
        deviceInfo.deviceId = 6; // 6 for test
        deviceInfo.networkId = LOCAL_NETWORK_ID;
        deviceInfo.deviceType = currentActiveDevice_.deviceType_;
        deviceInfo.deviceRole = OUTPUT_DEVICE;
    }
    AudioStreamInfo targetStreamInfo = {SAMPLE_RATE_48000, ENCODING_PCM, SAMPLE_S16LE, STEREO}; // note: read from xml
    deviceInfo.audioStreamInfo = targetStreamInfo;
    deviceInfo.deviceName = "mmap_device";
    std::lock_guard<std::mutex> lock(routerMapMutex_);
    if (fastRouterMap_.count(config.appInfo.appUid) &&
        fastRouterMap_[config.appInfo.appUid].second == deviceInfo.deviceRole) {
        deviceInfo.networkId = fastRouterMap_[config.appInfo.appUid].first;
        AUDIO_INFO_LOG("use networkid in fastRouterMap_ :%{public}s ", deviceInfo.networkId.c_str());
    }
    deviceInfo.a2dpOffloadFlag = a2dpOffloadFlag_;
    return SUCCESS;
}

int32_t AudioPolicyService::InitSharedVolume(std::shared_ptr<AudioSharedMemory> &buffer)
{
    AUDIO_INFO_LOG("InitSharedVolume start");
    CHECK_AND_RETURN_RET_LOG(policyVolumeMap_ != nullptr && policyVolumeMap_->GetBase() != nullptr,
        ERR_OPERATION_FAILED, "Get shared memory failed!");

    // init volume map
    // todo device
    for (size_t i = 0; i < IPolicyProvider::GetVolumeVectorSize(); i++) {
        int32_t currentVolumeLevel = audioPolicyManager_.GetSystemVolumeLevel(g_volumeIndexVector[i].first);
        float volFloat =
            GetSystemVolumeInDb(g_volumeIndexVector[i].first, currentVolumeLevel, currentActiveDevice_.deviceType_);
        volumeVector_[i].isMute = false;
        volumeVector_[i].volumeFloat = volFloat;
        volumeVector_[i].volumeInt = 0;
    }
    buffer = policyVolumeMap_;

    return SUCCESS;
}

bool AudioPolicyService::GetSharedVolume(AudioVolumeType streamType, DeviceType deviceType, Volume &vol)
{
    CHECK_AND_RETURN_RET_LOG(volumeVector_ != nullptr, false, "Get shared memory failed!");
    size_t index = 0;
    if (!IPolicyProvider::GetVolumeIndex(streamType, GetVolumeGroupForDevice(deviceType), index) ||
        index >= IPolicyProvider::GetVolumeVectorSize()) {
        return false;
    }
    vol.isMute = volumeVector_[index].isMute;
    vol.volumeFloat = volumeVector_[index].volumeFloat;
    vol.volumeInt = volumeVector_[index].volumeInt;
    return true;
}

bool AudioPolicyService::SetSharedVolume(AudioVolumeType streamType, DeviceType deviceType, Volume vol)
{
    CHECK_AND_RETURN_RET_LOG(volumeVector_ != nullptr, false, "Set shared memory failed!");
    size_t index = 0;
    if (!IPolicyProvider::GetVolumeIndex(streamType, GetVolumeGroupForDevice(deviceType), index) ||
        index >= IPolicyProvider::GetVolumeVectorSize()) {
        return false;
    }
    volumeVector_[index].isMute = vol.isMute;
    volumeVector_[index].volumeFloat = vol.volumeFloat;
    volumeVector_[index].volumeInt = vol.volumeInt;
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    CHECK_AND_RETURN_RET_LOG(g_adProxy != nullptr, false, "Audio server Proxy is null");
    g_adProxy->NotifyStreamVolumeChanged(streamType, vol.volumeFloat);
    IPCSkeleton::SetCallingIdentity(identity);
    return true;
}

void AudioPolicyService::SetParameterCallback(const std::shared_ptr<AudioParameterCallback>& callback)
{
    AUDIO_INFO_LOG("Start");
    sptr<AudioManagerListenerStub> parameterChangeCbStub = new(std::nothrow) AudioManagerListenerStub();
    CHECK_AND_RETURN_LOG(parameterChangeCbStub != nullptr,
        "parameterChangeCbStub null");
    const sptr<IStandardAudioService> gsp = GetAudioServerProxy();
    CHECK_AND_RETURN_LOG(gsp != nullptr, "g_adProxy null");
    parameterChangeCbStub->SetParameterCallback(callback);

    sptr<IRemoteObject> object = parameterChangeCbStub->AsObject();
    if (object == nullptr) {
        AUDIO_ERR_LOG("listenerStub object is nullptr");
        delete parameterChangeCbStub;
        return;
    }
    AUDIO_DEBUG_LOG("done");
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    gsp->SetParameterCallback(object);
    IPCSkeleton::SetCallingIdentity(identity);
}

int32_t AudioPolicyService::GetMaxRendererInstances()
{
    for (auto &configInfo : globalConfigs_.outputConfigInfos_) {
        if (configInfo.name_ == "normal" && configInfo.value_ != "") {
            AUDIO_INFO_LOG("Max output normal instance is %{public}s", configInfo.value_.c_str());
            return (int32_t)std::stoi(configInfo.value_);
        }
    }
    return DEFAULT_MAX_OUTPUT_NORMAL_INSTANCES;
}

#ifdef BLUETOOTH_ENABLE
const sptr<IStandardAudioService> RegisterBluetoothDeathCallback()
{
    lock_guard<mutex> lock(g_btProxyMutex);
    if (g_btProxy == nullptr) {
        auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        CHECK_AND_RETURN_RET_LOG(samgr != nullptr, nullptr,
            "get sa manager failed");
        sptr<IRemoteObject> object = samgr->GetSystemAbility(BLUETOOTH_HOST_SYS_ABILITY_ID);
        CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr,
            "get audio service remote object failed");
        g_btProxy = iface_cast<IStandardAudioService>(object);
        CHECK_AND_RETURN_RET_LOG(g_btProxy != nullptr, nullptr,
            "get audio service proxy failed");

        // register death recipent
        sptr<AudioServerDeathRecipient> asDeathRecipient = new(std::nothrow) AudioServerDeathRecipient(getpid());
        if (asDeathRecipient != nullptr) {
            asDeathRecipient->SetNotifyCb(std::bind(&AudioPolicyService::BluetoothServiceCrashedCallback,
                std::placeholders::_1));
            bool result = object->AddDeathRecipient(asDeathRecipient);
            if (!result) {
                AUDIO_ERR_LOG("failed to add deathRecipient");
            }
        }
    }
    sptr<IStandardAudioService> gasp = g_btProxy;
    return gasp;
}

void AudioPolicyService::BluetoothServiceCrashedCallback(pid_t pid)
{
    AUDIO_INFO_LOG("Bluetooth sa crashed, will restore proxy in next call");
    lock_guard<mutex> lock(g_btProxyMutex);
    g_btProxy = nullptr;
    isBtListenerRegistered = false;
    Bluetooth::AudioA2dpManager::DisconnectBluetoothA2dpSink();
    Bluetooth::AudioHfpManager::DisconnectBluetoothHfpSink();
}
#endif

void AudioPolicyService::RegisterBluetoothListener()
{
#ifdef BLUETOOTH_ENABLE
    AUDIO_INFO_LOG("Enter");
    Bluetooth::RegisterDeviceObserver(deviceStatusListener_->deviceObserver_);
    if (isBtListenerRegistered) {
        AUDIO_INFO_LOG("audio policy service already register bt listerer, return");
        return;
    }
    Bluetooth::AudioA2dpManager::RegisterBluetoothA2dpListener();
    Bluetooth::AudioHfpManager::RegisterBluetoothScoListener();
    isBtListenerRegistered = true;
    const sptr<IStandardAudioService> gsp = RegisterBluetoothDeathCallback();
    Bluetooth::AudioA2dpManager::CheckA2dpDeviceReconnect();
    Bluetooth::AudioHfpManager::CheckHfpDeviceReconnect();
#endif
}

void AudioPolicyService::UnregisterBluetoothListener()
{
#ifdef BLUETOOTH_ENABLE
    AUDIO_INFO_LOG("Enter");
    Bluetooth::UnregisterDeviceObserver();
    Bluetooth::AudioA2dpManager::UnregisterBluetoothA2dpListener();
    Bluetooth::AudioHfpManager::UnregisterBluetoothScoListener();
    isBtListenerRegistered = false;
#endif
}

void AudioPolicyService::SubscribeAccessibilityConfigObserver()
{
#ifdef ACCESSIBILITY_ENABLE
    accessibilityConfigListener_->SubscribeObserver();
    AUDIO_INFO_LOG("Subscribe accessibility config observer successfully");
#endif
}

float AudioPolicyService::GetMinStreamVolume()
{
    return audioPolicyManager_.GetMinStreamVolume();
}

float AudioPolicyService::GetMaxStreamVolume()
{
    return audioPolicyManager_.GetMaxStreamVolume();
}

bool AudioPolicyService::IsVolumeUnadjustable()
{
    return audioPolicyManager_.IsVolumeUnadjustable();
}

void AudioPolicyService::GetStreamVolumeInfoMap(StreamVolumeInfoMap &streamVolumeInfoMap)
{
    return audioPolicyManager_.GetStreamVolumeInfoMap(streamVolumeInfoMap);
}

float AudioPolicyService::GetSystemVolumeInDb(AudioVolumeType volumeType, int32_t volumeLevel,
    DeviceType deviceType) const
{
    return audioPolicyManager_.GetSystemVolumeInDb(volumeType, volumeLevel, deviceType);
}

int32_t AudioPolicyService::QueryEffectManagerSceneMode(SupportedEffectConfig& supportedEffectConfig)
{
    int32_t ret = audioEffectManager_.QueryEffectManagerSceneMode(supportedEffectConfig);
    return ret;
}

void AudioPolicyService::RegisterDataObserver()
{
    std::string devicesName = "";
    int32_t ret = GetDeviceNameFromDataShareHelper(devicesName);
    AUDIO_INFO_LOG("UpdateDisplayName local name [%{public}s]", devicesName.c_str());
    CHECK_AND_RETURN_LOG(ret == SUCCESS, "Local UpdateDisplayName init device failed");
    SetDisplayName(devicesName, true);
    RegisterNameMonitorHelper();
}

int32_t AudioPolicyService::SetPlaybackCapturerFilterInfos(const AudioPlaybackCaptureConfig &config)
{
    if (!config.silentCapture) {
        LoadLoopback();
    }
    const sptr<IStandardAudioService> gsp = GetAudioServerProxy();
    CHECK_AND_RETURN_RET_LOG(gsp != nullptr, ERR_OPERATION_FAILED,
        "error for g_adProxy null");

    std::string identity = IPCSkeleton::ResetCallingIdentity();
    int32_t ret = gsp->SetCaptureSilentState(config.silentCapture);
    IPCSkeleton::SetCallingIdentity(identity);
    CHECK_AND_RETURN_RET_LOG(!ret, ERR_OPERATION_FAILED, "SetCaptureSilentState failed");

    std::vector<int32_t> targetUsages;
    AUDIO_INFO_LOG("start");
    for (size_t i = 0; i < config.filterOptions.usages.size(); i++) {
        if (count(targetUsages.begin(), targetUsages.end(), config.filterOptions.usages[i]) == 0) {
            targetUsages.emplace_back(config.filterOptions.usages[i]); // deduplicate
        }
    }

    identity = IPCSkeleton::ResetCallingIdentity();
    int32_t res = gsp->SetSupportStreamUsage(targetUsages);
    IPCSkeleton::SetCallingIdentity(identity);
    return res;
}

int32_t AudioPolicyService::SetCaptureSilentState(bool state)
{
    const sptr<IStandardAudioService> gsp = GetAudioServerProxy();
    if (gsp == nullptr) {
        AUDIO_ERR_LOG("SetCaptureSilentState error for g_adProxy null");
        return ERR_OPERATION_FAILED;
    }

    return gsp->SetCaptureSilentState(state);
}

bool AudioPolicyService::IsConnectedOutputDevice(const sptr<AudioDeviceDescriptor> &desc)
{
    DeviceType deviceType = desc->deviceType_;

    CHECK_AND_RETURN_RET_LOG(desc->deviceRole_ == DeviceRole::OUTPUT_DEVICE, false,
        "Not output device!");

    auto isPresent = [&deviceType] (const sptr<AudioDeviceDescriptor> &desc) {
        CHECK_AND_RETURN_RET_LOG(desc != nullptr, false, "Invalid device descriptor");
        if (deviceType == DEVICE_TYPE_FILE_SINK) {
            return false;
        }
        return ((deviceType == desc->deviceType_) && (desc->deviceRole_ == DeviceRole::OUTPUT_DEVICE));
    };

    auto itr = std::find_if(connectedDevices_.begin(), connectedDevices_.end(), isPresent);
    CHECK_AND_RETURN_RET_LOG(itr != connectedDevices_.end(), false, "Device not available");

    return true;
}

int32_t AudioPolicyService::GetHardwareOutputSamplingRate(const sptr<AudioDeviceDescriptor> &desc)
{
    int32_t rate = 48000;

    CHECK_AND_RETURN_RET_LOG(desc != nullptr, -1, "desc is null!");

    bool ret = IsConnectedOutputDevice(desc);
    CHECK_AND_RETURN_RET(ret, -1);

    DeviceType clientDevType = desc->deviceType_;
    for (const auto &device : deviceClassInfo_) {
        auto moduleInfoList = device.second;
        for (auto &moduleInfo : moduleInfoList) {
            auto serverDevType = GetDeviceType(moduleInfo.name);
            if (clientDevType == serverDevType) {
                rate = atoi(moduleInfo.rate.c_str());
                return rate;
            }
        }
    }

    return rate;
}

void AudioPolicyService::AddMicrophoneDescriptor(sptr<AudioDeviceDescriptor> &deviceDescriptor)
{
    std::lock_guard<std::mutex> lock(microphonesMutex_);
    if (deviceDescriptor->deviceRole_ == INPUT_DEVICE &&
        deviceDescriptor->deviceType_ != DEVICE_TYPE_FILE_SOURCE) {
        auto isPresent = [&deviceDescriptor](const sptr<MicrophoneDescriptor> &desc) {
            CHECK_AND_RETURN_RET_LOG(desc != nullptr, false, "Invalid device descriptor");
            return desc->deviceType_ == deviceDescriptor->deviceType_;
        };

        auto iter = std::find_if(connectedMicrophones_.begin(), connectedMicrophones_.end(), isPresent);
        if (iter == connectedMicrophones_.end()) {
            sptr<MicrophoneDescriptor> micDesc = new (std::nothrow) MicrophoneDescriptor(startMicrophoneId++,
                deviceDescriptor->deviceType_);
            connectedMicrophones_.push_back(micDesc);
        }
    }
}

void AudioPolicyService::RemoveMicrophoneDescriptor(sptr<AudioDeviceDescriptor> &deviceDescriptor)
{
    std::lock_guard<std::mutex> lock(microphonesMutex_);
    auto isPresent = [&deviceDescriptor](const sptr<MicrophoneDescriptor> &desc) {
        CHECK_AND_RETURN_RET_LOG(desc != nullptr, false, "Invalid device descriptor");
        return desc->deviceType_ == deviceDescriptor->deviceType_;
    };

    auto iter = std::find_if(connectedMicrophones_.begin(), connectedMicrophones_.end(), isPresent);
    if (iter != connectedMicrophones_.end()) {
        connectedMicrophones_.erase(iter);
    }
}

void AudioPolicyService::AddAudioCapturerMicrophoneDescriptor(int32_t sessionId, DeviceType devType)
{
    std::lock_guard<std::mutex> lock(microphonesMutex_);
    if (devType == DEVICE_TYPE_NONE) {
        audioCaptureMicrophoneDescriptor_[sessionId] = new MicrophoneDescriptor(0, DEVICE_TYPE_INVALID);
        return;
    }
    auto isPresent = [&devType] (const sptr<MicrophoneDescriptor> &desc) {
        CHECK_AND_RETURN_RET_LOG(desc != nullptr, false, "Invalid microphone descriptor");
        return (devType == desc->deviceType_);
    };

    auto itr = std::find_if(connectedMicrophones_.begin(), connectedMicrophones_.end(), isPresent);
    if (itr != connectedMicrophones_.end()) {
        audioCaptureMicrophoneDescriptor_[sessionId] = *itr;
    }
}

vector<sptr<MicrophoneDescriptor>> AudioPolicyService::GetAudioCapturerMicrophoneDescriptors(int32_t sessionId)
{
    std::lock_guard<std::mutex> lock(microphonesMutex_);
    vector<sptr<MicrophoneDescriptor>> descList = {};
    const auto desc = audioCaptureMicrophoneDescriptor_.find(sessionId);
    if (desc != audioCaptureMicrophoneDescriptor_.end()) {
        sptr<MicrophoneDescriptor> micDesc = new (std::nothrow) MicrophoneDescriptor(desc->second);
        descList.push_back(micDesc);
    }
    return descList;
}

vector<sptr<MicrophoneDescriptor>> AudioPolicyService::GetAvailableMicrophones()
{
    return connectedMicrophones_;
}

void AudioPolicyService::UpdateAudioCapturerMicrophoneDescriptor(DeviceType devType)
{
    std::lock_guard<std::mutex> lock(microphonesMutex_);
    auto isPresent = [&devType] (const sptr<MicrophoneDescriptor> &desc) {
        CHECK_AND_RETURN_RET_LOG(desc != nullptr, false, "Invalid microphone descriptor");
        return (devType == desc->deviceType_);
    };

    auto itr = std::find_if(connectedMicrophones_.begin(), connectedMicrophones_.end(), isPresent);
    if (itr != connectedMicrophones_.end()) {
        for (auto& desc : audioCaptureMicrophoneDescriptor_) {
            if (desc.second->deviceType_ != devType) {
                desc.second = *itr;
            }
        }
    }
}

void AudioPolicyService::RemoveAudioCapturerMicrophoneDescriptor(int32_t uid)
{
    std::lock_guard<std::mutex> lock(microphonesMutex_);
    vector<unique_ptr<AudioCapturerChangeInfo>> audioCapturerChangeInfos;
    streamCollector_.GetCurrentCapturerChangeInfos(audioCapturerChangeInfos);

    for (auto &info : audioCapturerChangeInfos) {
        if (info->clientUID != uid && info->createrUID != uid) {
            continue;
        }
        audioCaptureMicrophoneDescriptor_.erase(info->sessionId);
    }
}

int32_t AudioPolicyService::FetchTargetInfoForSessionAdd(const SessionInfo sessionInfo, SourceInfo &targetInfo)
{
    if (primaryMicModuleInfo_.supportedRate_.empty() || primaryMicModuleInfo_.supportedChannels_.empty()) {
        AUDIO_ERR_LOG("supportedRate or supportedChannels is empty");
        return ERROR;
    }
    uint32_t highestSupportedRate = *(primaryMicModuleInfo_.supportedRate_.rbegin());
    uint32_t highestSupportedChannels = *(primaryMicModuleInfo_.supportedChannels_.rbegin());
    SourceType targetSourceType;
    uint32_t targetRate;
    uint32_t targetChannels;
    if (sessionInfo.sourceType == SOURCE_TYPE_VOICE_COMMUNICATION) {
        targetSourceType = SOURCE_TYPE_VOICE_COMMUNICATION;
        targetRate = sessionInfo.rate;
        targetChannels = sessionInfo.channels;
        if (primaryMicModuleInfo_.supportedRate_.count(targetRate) == 0) {
            AUDIO_DEBUG_LOG("targetRate: %{public}u is not supported rate, using highestSupportedRate: %{public}u",
                targetRate, highestSupportedRate);
            targetRate = highestSupportedRate;
        }
        if (primaryMicModuleInfo_.supportedChannels_.count(targetChannels) == 0) {
            AUDIO_DEBUG_LOG(
                "targetChannels: %{public}u is not supported rate, using highestSupportedChannels: %{public}u",
                targetChannels, highestSupportedChannels);
            targetChannels = highestSupportedChannels;
        }
    } else if (sessionInfo.sourceType == SOURCE_TYPE_VOICE_CALL) {
        targetSourceType = SOURCE_TYPE_VOICE_CALL;
        targetRate = highestSupportedRate;
        targetChannels = highestSupportedChannels;
    } else if (sessionInfo.sourceType == SOURCE_TYPE_VOICE_RECOGNITION) {
        targetSourceType = SOURCE_TYPE_VOICE_RECOGNITION;
        targetRate = highestSupportedRate;
        targetChannels = highestSupportedChannels;
    } else {
        // For normal sourcetype, continue to use the default value
        targetSourceType = SOURCE_TYPE_MIC;
        targetRate = highestSupportedRate;
        targetChannels = highestSupportedChannels;
    }
    targetInfo = {targetSourceType, targetRate, targetChannels};
    return SUCCESS;
}

void AudioPolicyService::OnCapturerSessionRemoved(uint64_t sessionID)
{
    if (sessionWithSpecialSourceType_.count(sessionID) > 0) {
        if (sessionWithSpecialSourceType_[sessionID].sourceType == SOURCE_TYPE_REMOTE_CAST) {
            HandleRemoteCastDevice(false);
        }
        sessionWithSpecialSourceType_.erase(sessionID);
        return;
    }

    if (sessionWithNormalSourceType_.count(sessionID) > 0) {
        sessionWithNormalSourceType_.erase(sessionID);
        if (!sessionWithNormalSourceType_.empty()) {
            return;
        }
        ClosePortAndEraseIOHandle(PRIMARY_MIC);
        return;
    }

    AUDIO_INFO_LOG("Sessionid:%{public}" PRIu64 " not added, directly placed into sessionIdisRemovedSet_", sessionID);
    sessionIdisRemovedSet_.insert(sessionID);
}

int32_t AudioPolicyService::OnCapturerSessionAdded(uint64_t sessionID, SessionInfo sessionInfo,
    AudioStreamInfo streamInfo)
{
    if (sessionIdisRemovedSet_.count(sessionID) > 0) {
        sessionIdisRemovedSet_.erase(sessionID);
        AUDIO_INFO_LOG("sessionID: %{public}" PRIu64 " had already been removed earlier", sessionID);
        return SUCCESS;
    }
    if (specialSourceTypeSet_.count(sessionInfo.sourceType) == 0) {
        SourceInfo targetInfo;
        int32_t res = FetchTargetInfoForSessionAdd(sessionInfo, targetInfo);
        CHECK_AND_RETURN_RET_LOG(res == SUCCESS, res,
            "FetchTargetInfoForSessionAdd error, maybe device not support recorder");
        bool isSourceLoaded = !sessionWithNormalSourceType_.empty();
        if (!isSourceLoaded) {
            auto moduleInfo = primaryMicModuleInfo_;
            ClassType curClassType = classStrToEnum[moduleInfo.className];
            for (auto&[classType, moduleInfoList] : deviceClassInfo_) {
                CHECK_AND_CONTINUE_LOG(curClassType == classType, "module class name unmatch.");
                RectifyModuleInfo(moduleInfo, moduleInfoList, targetInfo);
                break;
            }
            AUDIO_INFO_LOG("rate:%{public}s, channels:%{public}s, bufferSize:%{public}s",
                moduleInfo.rate.c_str(), moduleInfo.channels.c_str(), moduleInfo.bufferSize.c_str());
            auto ioHandle = OpenPortAndInsertIOHandle(moduleInfo.name, moduleInfo);
            audioPolicyManager_.SetDeviceActive(ioHandle, currentActiveInputDevice_.deviceType_,
                moduleInfo.name, true, INPUT_DEVICES_FLAG);
        }
        sessionWithNormalSourceType_[sessionID] = sessionInfo;
    } else if (sessionInfo.sourceType == SOURCE_TYPE_REMOTE_CAST) {
        HandleRemoteCastDevice(true, streamInfo);
        sessionWithSpecialSourceType_[sessionID] = sessionInfo;
    } else {
        sessionWithSpecialSourceType_[sessionID] = sessionInfo;
    }
    AUDIO_INFO_LOG("sessionID: %{public}" PRIu64 " OnCapturerSessionAdded end", sessionID);
    return SUCCESS;
}

void AudioPolicyService::RectifyModuleInfo(AudioModuleInfo &moduleInfo, std::list<AudioModuleInfo> &moduleInfoList,
    SourceInfo &targetInfo)
{
    auto [targetSourceType, targetRate, targetChannels] = targetInfo;
    for (auto &adapterModuleInfo : moduleInfoList) {
        if (moduleInfo.role == adapterModuleInfo.role &&
            adapterModuleInfo.name.find(MODULE_SINK_OFFLOAD) == std::string::npos) {
            CHECK_AND_CONTINUE_LOG(adapterModuleInfo.rate == std::to_string(targetRate), "rate unmatch.");
            CHECK_AND_CONTINUE_LOG(adapterModuleInfo.channels == std::to_string(targetChannels), "channels unmatch.");
            moduleInfo.rate = std::to_string(targetRate);
            moduleInfo.channels = std::to_string(targetChannels);
            moduleInfo.bufferSize = adapterModuleInfo.bufferSize;
            AUDIO_INFO_LOG("match success. rate:%{public}s, channels:%{public}s, bufferSize:%{public}s",
                moduleInfo.rate.c_str(), moduleInfo.channels.c_str(), moduleInfo.bufferSize.c_str());
        }
    }
    moduleInfo.sourceType = std::to_string(targetSourceType);
    currentRate = targetRate;
    currentSourceType = targetSourceType;
}

std::vector<sptr<AudioDeviceDescriptor>> AudioPolicyService::DeviceFilterByUsage(AudioDeviceUsage usage,
    const std::vector<sptr<AudioDeviceDescriptor>>& descs)
{
    std::vector<unique_ptr<AudioDeviceDescriptor>> audioDeviceDescriptors;

    unordered_map<AudioDevicePrivacyType, list<DevicePrivacyInfo>> devicePrivacyMaps =
        audioDeviceManager_.GetDevicePrivacyMaps();
    for (const auto &dev : descs) {
        for (const auto &devicePrivacy : devicePrivacyMaps) {
            list<DevicePrivacyInfo> deviceInfos = devicePrivacy.second;
            audioDeviceManager_.GetAvailableDevicesWithUsage(usage, deviceInfos, dev, audioDeviceDescriptors);
        }
    }
    std::vector<sptr<AudioDeviceDescriptor>> deviceDescriptors;
    for (const auto &dec : audioDeviceDescriptors) {
        sptr<AudioDeviceDescriptor> tempDec = new(std::nothrow) AudioDeviceDescriptor(*dec);
        deviceDescriptors.push_back(move(tempDec));
    }
    return deviceDescriptors;
}

void AudioPolicyService::TriggerAvailableDeviceChangedCallback(
    const vector<sptr<AudioDeviceDescriptor>> &desc, bool isConnected)
{
    Trace trace("AudioPolicyService::TriggerAvailableDeviceChangedCallback");

    WriteDeviceChangedSysEvents(desc, isConnected);

    if (audioPolicyServerHandler_ != nullptr) {
        audioPolicyServerHandler_->SendAvailableDeviceChange(desc, isConnected);
    }
}

std::vector<unique_ptr<AudioDeviceDescriptor>> AudioPolicyService::GetAvailableDevices(AudioDeviceUsage usage)
{
    std::vector<unique_ptr<AudioDeviceDescriptor>> audioDeviceDescriptors;

    audioDeviceDescriptors = audioDeviceManager_.GetAvailableDevicesByUsage(usage);
    return audioDeviceDescriptors;
}

int32_t AudioPolicyService::OffloadStartPlaying(const std::vector<int32_t> &sessionIds)
{
#ifdef BLUETOOTH_ENABLE
    AUDIO_INFO_LOG("OffloadStartPlaying, a2dpOffloadFlag_: %{public}d, sessionIds: %{public}zu",
        a2dpOffloadFlag_, sessionIds.size());
    if (a2dpOffloadFlag_ != A2DP_OFFLOAD || sessionIds.size() == 0) {
        return SUCCESS;
    }
    return Bluetooth::AudioA2dpManager::OffloadStartPlaying(sessionIds);
#else
    return SUCCESS;
#endif
}

int32_t AudioPolicyService::OffloadStopPlaying(const std::vector<int32_t> &sessionIds)
{
#ifdef BLUETOOTH_ENABLE
    AUDIO_INFO_LOG("OffloadStopPlaying, a2dpOffloadFlag_: %{public}d, sessionIds: %{public}zu",
        a2dpOffloadFlag_, sessionIds.size());
    if (a2dpOffloadFlag_ != A2DP_OFFLOAD || sessionIds.size() == 0) {
        return SUCCESS;
    }
    return Bluetooth::AudioA2dpManager::OffloadStopPlaying(sessionIds);
#else
    return SUCCESS;
#endif
}

void AudioPolicyService::GetA2dpOffloadCodecAndSendToDsp()
{
#ifdef BLUETOOTH_ENABLE
    if (currentActiveDevice_.deviceType_ != DEVICE_TYPE_BLUETOOTH_A2DP) {
        return;
    }
    Bluetooth::BluetoothRemoteDevice bluetoothRemoteDevice_ = Bluetooth::AudioA2dpManager::GetCurrentActiveA2dpDevice();
    Bluetooth::A2dpOffloadCodecStatus offloadCodeStatus = Bluetooth::A2dpSource::GetProfile()->
        GetOffloadCodecStatus(bluetoothRemoteDevice_);
    std::string key = "AUDIO_EXT_PARAM_KEY_A2DP_OFFLOAD_CONFIG";
    std::string value = std::to_string(offloadCodeStatus.offloadInfo.mediaPacketHeader) + ","
        + std::to_string(offloadCodeStatus.offloadInfo.mPt) + ","
        + std::to_string(offloadCodeStatus.offloadInfo.ssrc) + ","
        + std::to_string(offloadCodeStatus.offloadInfo.boundaryFlag) + ","
        + std::to_string(offloadCodeStatus.offloadInfo.broadcastFlag) + ","
        + std::to_string(offloadCodeStatus.offloadInfo.codecType) + ","
        + std::to_string(offloadCodeStatus.offloadInfo.maxLatency) + ","
        + std::to_string(offloadCodeStatus.offloadInfo.scmsTEnable) + ","
        + std::to_string(offloadCodeStatus.offloadInfo.sampleRate) + ","
        + std::to_string(offloadCodeStatus.offloadInfo.encodedAudioBitrate) + ","
        + std::to_string(offloadCodeStatus.offloadInfo.bitsPerSample) + ","
        + std::to_string(offloadCodeStatus.offloadInfo.chMode) + ","
        + std::to_string(offloadCodeStatus.offloadInfo.aclHdl) + ","
        + std::to_string(offloadCodeStatus.offloadInfo.l2cRcid) + ","
        + std::to_string(offloadCodeStatus.offloadInfo.mtu) + ","
        + std::to_string(offloadCodeStatus.offloadInfo.codecSpecific0) + ","
        + std::to_string(offloadCodeStatus.offloadInfo.codecSpecific1) + ","
        + std::to_string(offloadCodeStatus.offloadInfo.codecSpecific2) + ","
        + std::to_string(offloadCodeStatus.offloadInfo.codecSpecific3) + ","
        + std::to_string(offloadCodeStatus.offloadInfo.codecSpecific4) + ","
        + std::to_string(offloadCodeStatus.offloadInfo.codecSpecific5) + ","
        + std::to_string(offloadCodeStatus.offloadInfo.codecSpecific6) + ","
        + std::to_string(offloadCodeStatus.offloadInfo.codecSpecific7) + ";";
    const sptr<IStandardAudioService> gsp = GetAudioServerProxy();
    gsp->SetAudioParameter(key, value);
    AUDIO_INFO_LOG("update offloadcodec[%{public}s]", value.c_str());
#endif
}

#ifdef BLUETOOTH_ENABLE
void AudioPolicyService::UpdateA2dpOffloadFlag(const std::vector<Bluetooth::A2dpStreamInfo> &allActiveSessions,
    DeviceType deviceType)
{
    std::lock_guard<std::mutex> lock(switchA2dpOffloadMutex_);
    auto receiveOffloadFlag = a2dpOffloadFlag_;
    if (deviceType == DEVICE_TYPE_BLUETOOTH_A2DP) {
        receiveOffloadFlag = static_cast<BluetoothOffloadState>(Bluetooth::AudioA2dpManager::A2dpOffloadSessionRequest(
            allActiveSessions));
    } else if (currentActiveDevice_.deviceType_ == DEVICE_TYPE_BLUETOOTH_A2DP &&
        currentActiveDevice_.networkId_ == LOCAL_NETWORK_ID && deviceType == DEVICE_TYPE_NONE) {
        receiveOffloadFlag = static_cast<BluetoothOffloadState>(Bluetooth::AudioA2dpManager::A2dpOffloadSessionRequest(
            allActiveSessions));
    } else {
        receiveOffloadFlag = NO_A2DP_DEVICE;
    }

    AUDIO_INFO_LOG("deviceType: %{public}d, currentActiveDevice_: %{public}d, allActiveSessions: %{public}zu, "
        "a2dpOffloadFlag_: %{public}d, receiveOffloadFlag: %{public}d",
        deviceType, currentActiveDevice_.deviceType_, allActiveSessions.size(), a2dpOffloadFlag_,
        receiveOffloadFlag);

    if (receiveOffloadFlag == NO_A2DP_DEVICE) {
        AUDIO_INFO_LOG("a2dpOffloadFlag_ change from %{public}d to %{public}d", a2dpOffloadFlag_, receiveOffloadFlag);
        a2dpOffloadFlag_ = receiveOffloadFlag;
        return;
    }

    if (receiveOffloadFlag != a2dpOffloadFlag_) {
        if (a2dpOffloadFlag_ == A2DP_OFFLOAD) {
            HandleA2dpDeviceOutOffload(receiveOffloadFlag);
        } else if (receiveOffloadFlag == A2DP_OFFLOAD) {
            HandleA2dpDeviceInOffload(receiveOffloadFlag);
        } else {
            AUDIO_INFO_LOG("a2dpOffloadFlag_ change from %{public}d to %{public}d", a2dpOffloadFlag_,
                receiveOffloadFlag);
            a2dpOffloadFlag_ = receiveOffloadFlag;
        }
    }

    if (a2dpOffloadFlag_ == A2DP_OFFLOAD) {
        GetA2dpOffloadCodecAndSendToDsp();
        std::vector<int32_t> allSessions;
        GetAllRunningStreamSession(allSessions);
        OffloadStartPlaying(allSessions);
        return;
    }
}

void AudioPolicyService::UpdateAllActiveSessions(std::vector<Bluetooth::A2dpStreamInfo> &allActiveSessions)
{
    std::lock_guard<std::mutex> lock(checkSpatializedMutex_);
    vector<unique_ptr<AudioRendererChangeInfo>> audioRendererChangeInfos;
    streamCollector_.GetCurrentRendererChangeInfos(audioRendererChangeInfos);
    std::unordered_map<uint32_t, bool> newSessionHasBeenSpatialized;
    for (auto &changeInfo : audioRendererChangeInfos) {
        if (changeInfo->rendererState != RENDERER_RUNNING) {
            newSessionHasBeenSpatialized[changeInfo->sessionId] = false;
            continue;
        }
        auto it = sessionHasBeenSpatialized_.find(changeInfo->sessionId);
        if (it == sessionHasBeenSpatialized_.end()) {
            newSessionHasBeenSpatialized[changeInfo->sessionId] = false;
        } else {
            newSessionHasBeenSpatialized[changeInfo->sessionId] = sessionHasBeenSpatialized_[changeInfo->sessionId];
        }
        for (auto &activeSession : allActiveSessions) {
            if (activeSession.sessionId == changeInfo->sessionId) {
                activeSession.isSpatialAudio =
                    activeSession.isSpatialAudio | newSessionHasBeenSpatialized[changeInfo->sessionId];
                newSessionHasBeenSpatialized[changeInfo->sessionId] = activeSession.isSpatialAudio;
                break;
            }
        }
    }
    sessionHasBeenSpatialized_ = newSessionHasBeenSpatialized;
}
#endif

int32_t AudioPolicyService::HandleA2dpDeviceOutOffload(BluetoothOffloadState a2dpOffloadFlag)
{
#ifdef BLUETOOTH_ENABLE
    GetA2dpOffloadCodecAndSendToDsp();
    std::vector<int32_t> allSessions;
    GetAllRunningStreamSession(allSessions);
    OffloadStopPlaying(allSessions);

    AUDIO_INFO_LOG("a2dpOffloadFlag_ change from %{public}d to %{public}d", a2dpOffloadFlag_, a2dpOffloadFlag);
    a2dpOffloadFlag_ = a2dpOffloadFlag;

    DeviceType dev = GetActiveOutputDevice();
    UpdateEffectDefaultSink(dev);
    AUDIO_INFO_LOG("Handle A2dpDevice Out Offload");
    ResetOffloadMode();

    vector<unique_ptr<AudioRendererChangeInfo>> rendererChangeInfos;
    streamCollector_.GetCurrentRendererChangeInfos(rendererChangeInfos);
    FetchStreamForA2dpOffload(rendererChangeInfos);

    if (currentActiveDevice_.deviceType_ == DEVICE_TYPE_BLUETOOTH_A2DP) {
        return HandleActiveDevice(DEVICE_TYPE_BLUETOOTH_A2DP);
    } else {
        return SUCCESS;
    }
#else
    return ERROR;
#endif
}

int32_t AudioPolicyService::HandleA2dpDeviceInOffload(BluetoothOffloadState a2dpOffloadFlag)
{
#ifdef BLUETOOTH_ENABLE
    AUDIO_INFO_LOG("a2dpOffloadFlag_ change from %{public}d to %{public}d", a2dpOffloadFlag_, a2dpOffloadFlag);
    a2dpOffloadFlag_ = a2dpOffloadFlag;

    DeviceType dev = GetActiveOutputDevice();
    UpdateEffectDefaultSink(dev);
    AUDIO_INFO_LOG("Handle A2dpDevice In Offload");
    ResetOffloadMode();

    vector<unique_ptr<AudioRendererChangeInfo>> rendererChangeInfos;
    streamCollector_.GetCurrentRendererChangeInfos(rendererChangeInfos);
    FetchStreamForA2dpOffload(rendererChangeInfos);

    std::string activePort = BLUETOOTH_SPEAKER;
    audioPolicyManager_.SuspendAudioDevice(activePort, true);

    GetA2dpOffloadCodecAndSendToDsp();
    std::vector<int32_t> allSessions;
    GetAllRunningStreamSession(allSessions);
    return OffloadStartPlaying(allSessions);
#else
    return ERROR;
#endif
}

void AudioPolicyService::GetAllRunningStreamSession(std::vector<int32_t> &allSessions, bool doStop)
{
#ifdef BLUETOOTH_ENABLE
    vector<unique_ptr<AudioRendererChangeInfo>> rendererChangeInfos;
    streamCollector_.GetCurrentRendererChangeInfos(rendererChangeInfos);
    std::vector<int32_t> stopPlayingStream(0);
    for (auto &changeInfo : rendererChangeInfos) {
        if (changeInfo->rendererState != RENDERER_RUNNING) {
            if (doStop) {
                stopPlayingStream.push_back(changeInfo->sessionId);
            }
            continue;
        }
        allSessions.push_back(changeInfo->sessionId);
    }
    if (doStop && stopPlayingStream.size() > 0) {
        OffloadStopPlaying(stopPlayingStream);
    }
#endif
}

void AudioPolicyService::OnScoStateChanged(const std::string &macAddress, bool isConnnected)
{
    AUDIO_INFO_LOG("macAddress: %{public}s, isConnnected: %{public}d", GetEncryptAddr(macAddress).c_str(),
        isConnnected);
    audioDeviceManager_.UpdateScoState(macAddress, isConnnected);
    FetchDevice(true);
    FetchDevice(false);
}

void AudioPolicyService::OnPreferredStateUpdated(AudioDeviceDescriptor &desc,
    const DeviceInfoUpdateCommand updateCommand)
{
    AudioStateManager& stateManager = AudioStateManager::GetAudioStateManager();
    unique_ptr<AudioDeviceDescriptor> userSelectMediaRenderDevice = stateManager.GetPerferredMediaRenderDevice();
    unique_ptr<AudioDeviceDescriptor> userSelectCallRenderDevice = stateManager.GetPerferredCallRenderDevice();
    unique_ptr<AudioDeviceDescriptor> userSelectCallCaptureDevice = stateManager.GetPerferredCallCaptureDevice();
    unique_ptr<AudioDeviceDescriptor> userSelectRecordCaptureDevice = stateManager.GetPerferredRecordCaptureDevice();
    AudioStreamDeviceChangeReason reason = AudioStreamDeviceChangeReason::UNKNOWN;
    if (updateCommand == CATEGORY_UPDATE) {
        if (desc.deviceCategory_ == BT_UNWEAR_HEADPHONE) {
            reason = AudioStreamDeviceChangeReason::OLD_DEVICE_UNAVALIABLE;
            if (userSelectMediaRenderDevice->deviceType_ == desc.deviceType_ &&
                userSelectMediaRenderDevice->macAddress_ == desc.macAddress_) {
                audioStateManager_.SetPerferredMediaRenderDevice(new(std::nothrow) AudioDeviceDescriptor());
            }
            if (userSelectCallRenderDevice->deviceType_ == desc.deviceType_ &&
                userSelectCallRenderDevice->macAddress_ == desc.macAddress_) {
                audioStateManager_.SetPerferredCallRenderDevice(new(std::nothrow) AudioDeviceDescriptor());
            }
            if (userSelectCallCaptureDevice->deviceType_ == desc.deviceType_ &&
                userSelectCallCaptureDevice->macAddress_ == desc.macAddress_) {
                audioStateManager_.SetPerferredCallCaptureDevice(new(std::nothrow) AudioDeviceDescriptor());
            }
            if (userSelectRecordCaptureDevice->deviceType_ == desc.deviceType_ &&
                userSelectRecordCaptureDevice->macAddress_ == desc.macAddress_) {
                audioStateManager_.SetPerferredRecordCaptureDevice(new(std::nothrow) AudioDeviceDescriptor());
            }
#ifdef BLUETOOTH_ENABLE
            if (desc.deviceType_ == DEVICE_TYPE_BLUETOOTH_A2DP &&
                desc.macAddress_ == currentActiveDevice_.macAddress_) {
                Bluetooth::AudioA2dpManager::SetActiveA2dpDevice("");
            }
#endif
        } else {
            reason = AudioStreamDeviceChangeReason::NEW_DEVICE_AVAILABLE;
            if (desc.deviceType_ == DEVICE_TYPE_BLUETOOTH_A2DP) {
                audioStateManager_.SetPerferredMediaRenderDevice(new(std::nothrow) AudioDeviceDescriptor());
                audioStateManager_.SetPerferredRecordCaptureDevice(new(std::nothrow) AudioDeviceDescriptor());
            } else {
                audioStateManager_.SetPerferredCallRenderDevice(new(std::nothrow) AudioDeviceDescriptor());
                audioStateManager_.SetPerferredCallCaptureDevice(new(std::nothrow) AudioDeviceDescriptor());
                ClearScoDeviceSuspendState(desc.macAddress_);
            }
        }
    } else if (updateCommand == ENABLE_UPDATE) {
        reason = desc.isEnable_ ? AudioStreamDeviceChangeReason::NEW_DEVICE_AVAILABLE :
            AudioStreamDeviceChangeReason::OLD_DEVICE_UNAVALIABLE;
    }
    FetchDevice(true, reason);
}

void AudioPolicyService::OnDeviceInfoUpdated(AudioDeviceDescriptor &desc, const DeviceInfoUpdateCommand command)
{
    AUDIO_INFO_LOG("[%{public}s] type[%{public}d] command: %{public}d category[%{public}d] connectState[%{public}d] " \
        "isEnable[%{public}d]", GetEncryptAddr(desc.macAddress_).c_str(), desc.deviceType_,
        command, desc.deviceCategory_, desc.connectState_, desc.isEnable_);
    if (command == ENABLE_UPDATE && desc.isEnable_ == true) {
        if (desc.deviceType_ == DEVICE_TYPE_BLUETOOTH_SCO) {
            ClearScoDeviceSuspendState(desc.macAddress_);
        }
        unique_ptr<AudioDeviceDescriptor> userSelectMediaDevice =
            AudioStateManager::GetAudioStateManager().GetPerferredMediaRenderDevice();
        unique_ptr<AudioDeviceDescriptor> userSelectCallDevice =
            AudioStateManager::GetAudioStateManager().GetPerferredCallRenderDevice();
        if ((userSelectMediaDevice->deviceType_ == desc.deviceType_ &&
            userSelectMediaDevice->macAddress_ == desc.macAddress_) ||
            (userSelectCallDevice->deviceType_ == desc.deviceType_ &&
            userSelectCallDevice->macAddress_ == desc.macAddress_)) {
            AUDIO_INFO_LOG("Current enable state has been set true during user selection, no need to be set again.");
            return;
        }
    } else if (command == ENABLE_UPDATE && desc.isEnable_ == false) {
        UnloadA2dpModule();
    }
    sptr<AudioDeviceDescriptor> audioDescriptor = new(std::nothrow) AudioDeviceDescriptor(desc);
    audioDeviceManager_.UpdateDevicesListInfo(audioDescriptor, command);

    OnPreferredStateUpdated(desc, command);
    FetchDevice(false);
    UpdateA2dpOffloadFlagForAllStream();
}

void AudioPolicyService::UpdateOffloadWhenActiveDeviceSwitchFromA2dp()
{
    std::vector<int32_t> allSessions;
    GetAllRunningStreamSession(allSessions);
    OffloadStopPlaying(allSessions);
    a2dpOffloadFlag_ = NO_A2DP_DEVICE;
}

int32_t AudioPolicyService::SetCallDeviceActive(InternalDeviceType deviceType, bool active, std::string address)
{
    AUDIO_INFO_LOG("Device type[%{public}d] flag[%{public}d] address[%{public}s]",
        deviceType, active, GetEncryptAddr(address).c_str());
    CHECK_AND_RETURN_RET_LOG(deviceType != DEVICE_TYPE_NONE, ERR_DEVICE_NOT_SUPPORTED, "Invalid device");

    // Activate new device if its already connected
    auto isPresent = [&deviceType, &address] (const unique_ptr<AudioDeviceDescriptor> &desc) {
        CHECK_AND_RETURN_RET_LOG(desc != nullptr, false, "Invalid device descriptor");
        return ((deviceType == desc->deviceType_) && (address == desc->macAddress_));
    };

    vector<unique_ptr<AudioDeviceDescriptor>> callDevices = GetAvailableDevices(CALL_OUTPUT_DEVICES);

    auto itr = std::find_if(callDevices.begin(), callDevices.end(), isPresent);
    CHECK_AND_RETURN_RET_LOG(itr != callDevices.end(), ERR_OPERATION_FAILED,
        "Requested device not available %{public}d ", deviceType);
    if (active) {
        if (deviceType == DEVICE_TYPE_BLUETOOTH_SCO) {
            (*itr)->isEnable_ = true;
            audioDeviceManager_.UpdateDevicesListInfo(new(std::nothrow) AudioDeviceDescriptor(**itr), ENABLE_UPDATE);
            ClearScoDeviceSuspendState(address);
        }
        audioStateManager_.SetPerferredCallRenderDevice(new(std::nothrow) AudioDeviceDescriptor(**itr));
#ifdef BLUETOOTH_ENABLE
        if (currentActiveDevice_.deviceType_ == DEVICE_TYPE_BLUETOOTH_SCO &&
            deviceType != DEVICE_TYPE_BLUETOOTH_SCO) {
            Bluetooth::SendUserSelectionEvent(DEVICE_TYPE_BLUETOOTH_SCO,
                currentActiveDevice_.macAddress_, USER_NOT_SELECT_BT);
            Bluetooth::AudioHfpManager::DisconnectSco();
        }
        if (currentActiveDevice_.deviceType_ != DEVICE_TYPE_BLUETOOTH_SCO &&
            deviceType == DEVICE_TYPE_BLUETOOTH_SCO) {
            Bluetooth::SendUserSelectionEvent(DEVICE_TYPE_BLUETOOTH_SCO,
                (new(std::nothrow) AudioDeviceDescriptor(**itr))->macAddress_, USER_SELECT_BT);
        }
#endif
    } else {
        audioStateManager_.SetPerferredCallRenderDevice(new(std::nothrow) AudioDeviceDescriptor());
#ifdef BLUETOOTH_ENABLE
        if (currentActiveDevice_.deviceType_ == DEVICE_TYPE_BLUETOOTH_SCO &&
            deviceType == DEVICE_TYPE_BLUETOOTH_SCO) {
            Bluetooth::SendUserSelectionEvent(DEVICE_TYPE_BLUETOOTH_SCO,
                currentActiveDevice_.macAddress_, USER_NOT_SELECT_BT);
            Bluetooth::AudioHfpManager::DisconnectSco();
        }
#endif
    }
    FetchDevice(true);
    return SUCCESS;
}

std::unique_ptr<AudioDeviceDescriptor> AudioPolicyService::GetActiveBluetoothDevice()
{
    std::vector<unique_ptr<AudioDeviceDescriptor>> audioPrivacyDeviceDescriptors =
        audioDeviceManager_.GetCommRenderPrivacyDevices();
    std::vector<unique_ptr<AudioDeviceDescriptor>> activeDeviceDescriptors;

    for (auto &desc : audioPrivacyDeviceDescriptors) {
        if (desc->deviceType_ == DEVICE_TYPE_BLUETOOTH_SCO && desc->isEnable_) {
            activeDeviceDescriptors.push_back(make_unique<AudioDeviceDescriptor>(*desc));
        }
    }

    uint32_t btDeviceSize = activeDeviceDescriptors.size();
    if (btDeviceSize == 0) {
        return make_unique<AudioDeviceDescriptor>();
    } else if (btDeviceSize == 1) {
        unique_ptr<AudioDeviceDescriptor> res = std::move(activeDeviceDescriptors[0]);
        return res;
    }

    uint32_t index = 0;
    for (uint32_t i = 1; i < btDeviceSize; ++i) {
        if (activeDeviceDescriptors[i]->connectTimeStamp_ >
            activeDeviceDescriptors[index]->connectTimeStamp_) {
            index = i;
        }
    }
    unique_ptr<AudioDeviceDescriptor> res = std::move(activeDeviceDescriptors[index]);
    return res;
}

ConverterConfig AudioPolicyService::GetConverterConfig()
{
    AudioConverterParser &converterParser = AudioConverterParser::GetInstance();
    return converterParser.LoadConfig();
}

void AudioPolicyService::ClearScoDeviceSuspendState(string macAddress)
{
    AUDIO_DEBUG_LOG("Clear sco suspend state %{public}s", GetEncryptAddr(macAddress).c_str());
    vector<shared_ptr<AudioDeviceDescriptor>> descs = audioDeviceManager_.GetDevicesByFilter(
        DEVICE_TYPE_BLUETOOTH_SCO, DEVICE_ROLE_NONE, macAddress, "", SUSPEND_CONNECTED);
    for (auto &desc : descs) {
        desc->connectState_ = DEACTIVE_CONNECTED;
    }
}

float AudioPolicyService::GetMaxAmplitude(const int32_t deviceId)
{
    const sptr<IStandardAudioService> gsp = GetAudioServerProxy();
    CHECK_AND_RETURN_RET_LOG(gsp != nullptr, 0, "Service proxy unavailable");

    if (deviceId == currentActiveDevice_.deviceId_) {
        float outputMaxAmplitude = gsp->GetMaxAmplitude(true, currentActiveDevice_.deviceType_);
        return outputMaxAmplitude;
    }

    if (deviceId == currentActiveInputDevice_.deviceId_) {
        float inputMaxAmplitude = gsp->GetMaxAmplitude(false, currentActiveInputDevice_.deviceType_);
        return inputMaxAmplitude;
    }

    return 0;
}

AudioIOHandle AudioPolicyService::OpenPortAndInsertIOHandle(const std::string &moduleName,
    const AudioModuleInfo &moduleInfo)
{
    AudioIOHandle ioHandle = audioPolicyManager_.OpenAudioPort(moduleInfo);
    CHECK_AND_RETURN_RET_LOG(ioHandle != OPEN_PORT_FAILURE, ERR_INVALID_HANDLE, "OpenAudioPort failed %{public}d",
        ioHandle);

    std::lock_guard<std::mutex> ioHandleLock(ioHandlesMutex_);
    IOHandles_[moduleName] = ioHandle;

    return SUCCESS;
}

int32_t AudioPolicyService::ClosePortAndEraseIOHandle(const std::string &moduleName)
{
    AudioIOHandle ioHandle;
    {
        std::lock_guard<std::mutex> ioHandleLock(ioHandlesMutex_);
        auto ioHandleIter = IOHandles_.find(moduleName);
        CHECK_AND_RETURN_RET_LOG(ioHandleIter != IOHandles_.end(), ERROR,
            "can not find %{public}s in io map", moduleName.c_str());
        ioHandle = ioHandleIter->second;
        IOHandles_.erase(moduleName);
    }
    int32_t result = audioPolicyManager_.CloseAudioPort(ioHandle);
    CHECK_AND_RETURN_RET_LOG(result == SUCCESS, result, "CloseAudioPort failed %{public}d", result);
    return SUCCESS;
}

void AudioPolicyService::HandleRemoteCastDevice(bool isConnected, AudioStreamInfo streamInfo)
{
    AudioDeviceDescriptor updatedDesc = AudioDeviceDescriptor(DEVICE_TYPE_REMOTE_CAST,
        GetDeviceRole(DEVICE_TYPE_REMOTE_CAST));
    std::vector<sptr<AudioDeviceDescriptor>> descForCb = {};
    auto isPresent = [&updatedDesc] (const sptr<AudioDeviceDescriptor> &descriptor) {
        return descriptor->deviceType_ == updatedDesc.deviceType_ &&
            descriptor->macAddress_ == updatedDesc.macAddress_ &&
            descriptor->networkId_ == updatedDesc.networkId_;
    };
    if (isConnected) {
        // If device already in list, remove it else do not modify the list
        connectedDevices_.erase(std::remove_if(connectedDevices_.begin(), connectedDevices_.end(), isPresent),
            connectedDevices_.end());
        UpdateConnectedDevicesWhenConnecting(updatedDesc, descForCb);
        LoadInnerCapturerSink(REMOTE_CAST_INNER_CAPTURER_SINK_NAME, streamInfo);
        audioPolicyManager_.ResetRemoteCastDeviceVolume();
    } else {
        UpdateConnectedDevicesWhenDisconnecting(updatedDesc, descForCb);
        UnloadInnerCapturerSink(REMOTE_CAST_INNER_CAPTURER_SINK_NAME);
    }
    TriggerFetchDevice();
}

int32_t AudioPolicyService::TriggerFetchDevice()
{
    FetchDevice(true);
    FetchDevice(false);
    return SUCCESS;
}

int32_t AudioPolicyService::DisableSafeMediaVolume()
{
    AUDIO_INFO_LOG("Enter");
    std::lock_guard<std::mutex> lock(dialogMutex_);
    userSelect_ = true;
    isDialogSelectDestroy_.store(true);
    dialogSelectCondition_.notify_all();
    return SUCCESS;
}

DeviceUsage AudioPolicyService::GetDeviceUsage(const AudioDeviceDescriptor &desc)
{
    return audioDeviceManager_.GetDeviceUsage(desc);
}

void AudioPolicyService::NotifyAccountsChanged(const int &id)
{
    audioPolicyManager_.NotifyAccountsChanged(id);
}

void AudioPolicyService::GetSafeVolumeDump(std::string &dumpString)
{
   audioPolicyManager_.SafeVolumeDump(dumpString);
}

void AudioPolicyService::DevicesInfoDump(std::string &dumpString)
{
    std::vector<sptr<AudioDeviceDescriptor>> audioDeviceDescriptors;

    dumpString += "\nInput local Devices:\n";
    audioDeviceDescriptors = GetDumpDeviceInfo(dumpString, INPUT_DEVICES_FLAG);
    AppendFormat(dumpString, "- %d Input Devices (s) available\n", audioDeviceDescriptors.size());

    dumpString += "\nOutput local Devices:\n";
    audioDeviceDescriptors = GetDumpDeviceInfo(dumpString, OUTPUT_DEVICES_FLAG);
    AppendFormat(dumpString, "- %d output Devices (s) available\n", audioDeviceDescriptors.size());

    dumpString += "\nInput distributed Devices:\n";
    audioDeviceDescriptors = GetDumpDeviceInfo(dumpString, DISTRIBUTED_INPUT_DEVICES_FLAG);
    AppendFormat(dumpString, "- %d output Devices (s) available\n", audioDeviceDescriptors.size());

    dumpString += "\nOutput distributed Devices:\n";
    audioDeviceDescriptors = GetDumpDeviceInfo(dumpString, DISTRIBUTED_OUTPUT_DEVICES_FLAG);
    AppendFormat(dumpString, "- %d output Devices (s) available\n", audioDeviceDescriptors.size());

    priorityOutputDevice_ = GetActiveOutputDevice();
    priorityInputDevice_ = GetActiveInputDevice();
    AppendFormat(dumpString, "\nHighest priority output device: %s",
        AudioInfoDumpUtils::GetDeviceTypeName(priorityOutputDevice_).c_str());
    AppendFormat(dumpString, "\nHighest priority input device: %s \n",
        AudioInfoDumpUtils::GetDeviceTypeName(priorityInputDevice_).c_str());

    GetMicrophoneDescriptorsDump(dumpString);
    GetOffloadStatusDump(dumpString);
}

std::vector<sptr<AudioDeviceDescriptor>> AudioPolicyService::GetDumpDeviceInfo(std::string &dumpString,
    DeviceFlag deviceFlag)
{
    std::vector<sptr<AudioDeviceDescriptor>> deviceDescs = GetDumpDevices(deviceFlag);

    for (auto &desc : deviceDescs) {
        sptr<AudioDeviceDescriptor> devDesc = new(std::nothrow) AudioDeviceDescriptor(*desc);
        dumpString += "\n";
        AppendFormat(dumpString, "  - device name:%s\n",
            AudioInfoDumpUtils::GetDeviceTypeName(devDesc->deviceType_).c_str());
        AppendFormat(dumpString, "  - device type:%d\n", devDesc->deviceType_);
        AppendFormat(dumpString, "  - device id:%d\n", devDesc->deviceId_);
        if (deviceFlag == DeviceFlag::INPUT_DEVICES_FLAG || deviceFlag == DeviceFlag::OUTPUT_DEVICES_FLAG) {
            conneceType_  = CONNECT_TYPE_LOCAL;
        } else if (deviceFlag == DeviceFlag::DISTRIBUTED_INPUT_DEVICES_FLAG ||
                deviceFlag == DeviceFlag::DISTRIBUTED_OUTPUT_DEVICES_FLAG) {
            conneceType_  = CONNECT_TYPE_DISTRIBUTED;
        }
        AppendFormat(dumpString, "  - connect type:%s\n", AudioInfoDumpUtils::GetConnectTypeName(conneceType_).c_str());
        for (auto &samplingRate : devDesc->audioStreamInfo_.samplingRate) {
            AppendFormat(dumpString, "  - device sampleRates:%d\n", samplingRate);
        }
        for (auto &channel : devDesc->audioStreamInfo_.channels) {
            AppendFormat(dumpString, "  - device channels:%d\n", channel);
        }
        AppendFormat(dumpString, "  - device format:%d\n", devDesc->audioStreamInfo_.format);
    }
    return deviceDescs;
}

std::vector<sptr<AudioDeviceDescriptor>> AudioPolicyService::GetDumpDevices(DeviceFlag deviceFlag)
{
    bool hasSystemPermission = PermissionUtil::VerifySystemPermission();
    switch (deviceFlag) {
        case NONE_DEVICES_FLAG:
        case DISTRIBUTED_OUTPUT_DEVICES_FLAG:
        case DISTRIBUTED_INPUT_DEVICES_FLAG:
        case ALL_DISTRIBUTED_DEVICES_FLAG:
        case ALL_L_D_DEVICES_FLAG:
            if (!hasSystemPermission) {
                AUDIO_ERR_LOG("GetDevices: No system permission");
                std::vector<sptr<AudioDeviceDescriptor>> info = {};
                return info;
            }
            break;
        default:
            break;
    }

    std::vector<sptr<AudioDeviceDescriptor>> deviceDescs = GetDevices(deviceFlag);

    if (!hasSystemPermission) {
        for (sptr<AudioDeviceDescriptor> desc : deviceDescs) {
            desc->networkId_ = "";
            desc->interruptGroupId_ = GROUP_ID_NONE;
            desc->volumeGroupId_ = GROUP_ID_NONE;
        }
    }
    return deviceDescs;
}

void AudioPolicyService::AudioModeDump(std::string &dumpString)
{
    GetCallStatusDump(dumpString);
    GetRingerModeDump(dumpString);
}

void AudioPolicyService::GetCallStatusDump(std::string &dumpString)
{
    dumpString += "\nAudio Scene:";
    bool hasSystemPermission = PermissionUtil::VerifySystemPermission();
    AudioScene callStatus = GetAudioScene(hasSystemPermission);
    switch (callStatus) {
        case AUDIO_SCENE_DEFAULT:
            dumpString += "DEFAULT";
            break;
        case AUDIO_SCENE_RINGING:
            dumpString += "RINGING";
            break;
        case AUDIO_SCENE_PHONE_CALL:
            dumpString += "PHONE_CALL";
            break;
        case AUDIO_SCENE_PHONE_CHAT:
            dumpString += "PHONE_CHAT";
            break;
        default:
            dumpString += "UNKNOWN";
    }
    dumpString += "\n";
}

void AudioPolicyService::GetRingerModeDump(std::string &dumpString)
{
    dumpString += "Ringer Mode:";
    AudioRingerMode ringerMode = GetRingerMode();
    switch (ringerMode) {
        case RINGER_MODE_NORMAL:
            dumpString += "NORMAL";
            break;
        case RINGER_MODE_SILENT:
            dumpString += "SILENT";
            break;
        case RINGER_MODE_VIBRATE:
            dumpString += "VIBRATE";
            break;
        default:
            dumpString += "UNKNOWN";
    }
    dumpString += "\n\n";
}

void AudioPolicyService::GetMicrophoneDescriptorsDump(std::string &dumpString)
{
    dumpString += "\nAvailable MicrophoneDescriptors:\n";

    std::vector<sptr<MicrophoneDescriptor>> micDescs = GetAvailableMicrophones();
    for (auto it = micDescs.begin();
        it != micDescs.end(); ++it) {
        AppendFormat(dumpString, " - id:%d \n", (*it)->micId_);
        AppendFormat(dumpString, " - device type:%d  \n", (*it)->deviceType_);
        AppendFormat(dumpString, " - group id:%d  \n", (*it)->groupId_);
        AppendFormat(dumpString, " - sensitivity:%d  \n", (*it)->sensitivity_);
        AppendFormat(dumpString, " - position:%f %f %f (x, y, z)\n",
            (*it)->position_.x, (*it)->position_.y, (*it)->position_.z);
        AppendFormat(dumpString, " - orientation:%f %f %f (x, y, z)\n",
            (*it)->orientation_.x, (*it)->orientation_.y, (*it)->orientation_.z);
    }
}

void AudioPolicyService::AudioPolicyParserDump(std::string &dumpString)
{
    dumpString += "\nAudioPolicyParser:\n";
    GetAudioAdapterInfos(adapterInfoMap_);
    GetVolumeGroupData(volumeGroupData_);
    GetInterruptGroupData(interruptGroupData_);
    GetGlobalConfigs(globalConfigs_);
    for (auto &[adapterType, adapterInfo] : adapterInfoMap_) {
        AppendFormat(dumpString, " - adapter : %s -- adapterType:%u\n", adapterInfo.adapterName_.c_str(), adapterType);
        for (auto &deviceInfo : adapterInfo.deviceInfos_) {
            AppendFormat(dumpString, "     - device --  name:%s, pin:%s, type:%s, role:%s\n", deviceInfo.name_.c_str(),
                deviceInfo.pin_.c_str(), deviceInfo.type_.c_str(), deviceInfo.role_.c_str());
        }
        for (auto &pipeInfo : adapterInfo.pipeInfos_) {
            AppendFormat(dumpString, "     - module : -- name:%s, pipeRole:%s, pipeFlags:%s, lib:%s, paPropRole:%s, "
                "fixedLatency:%s, renderInIdleState:%s\n", pipeInfo.name_.c_str(),
                pipeInfo.pipeRole_.c_str(), pipeInfo.pipeFlags_.c_str(), pipeInfo.lib_.c_str(),
                pipeInfo.paPropRole_.c_str(), pipeInfo.fixedLatency_.c_str(), pipeInfo.renderInIdleState_.c_str());

            for (auto &configInfo : pipeInfo.configInfos_) {
                AppendFormat(dumpString, "         - config : -- name:%s, value:%s\n", configInfo.name_.c_str(),
                    configInfo.value_.c_str());
            }
        }
    }
    for (auto& volume : volumeGroupData_) {
        AppendFormat(dumpString, " - volumeGroupMap_ first:%s, second:%s\n\n", volume.first.c_str(),
            volume.second.c_str());
    }
    for (auto& interrupt : interruptGroupData_) {
        AppendFormat(dumpString, " - interruptGroupMap_ first:%s, second:%s\n", interrupt.first.c_str(),
            interrupt.second.c_str());
    }
    AppendFormat(dumpString, " - globalConfig  adapter:%s, pipe:%s, device:%s, updateRouteSupport:%d, "
        "audioLatency:%s, sinkLatency:%s\n", globalConfigs_.adapter_.c_str(),
        globalConfigs_.pipe_.c_str(), globalConfigs_.device_.c_str(),
        globalConfigs_.updateRouteSupport_,
        globalConfigs_.globalPaConfigs_.audioLatency_.c_str(),
        globalConfigs_.globalPaConfigs_.sinkLatency_.c_str());
    for (auto &outputConfig : globalConfigs_.outputConfigInfos_) {
        AppendFormat(dumpString, " - output config name:%s, type:%s, value:%s\n", outputConfig.name_.c_str(),
            outputConfig.type_.c_str(), outputConfig.value_.c_str());
    }
    for (auto &inputConfig : globalConfigs_.inputConfigInfos_) {
        AppendFormat(dumpString, " - input config name:%s, type_%s, value:%s\n\n", inputConfig.name_.c_str(),
            inputConfig.type_.c_str(), inputConfig.value_.c_str());
    }
    AppendFormat(dumpString, " - module curActiveCount:%d\n\n", GetCurActivateCount());
}

void AudioPolicyService::XmlParsedDataMapDump(std::string &dumpString)
{
    dumpString += "\nXmlParsedDataParser:\n";

    GetDeviceClassInfo(deviceClassInfo_);

    for (auto &[adapterType, deviceClassInfos] : deviceClassInfo_) {
        AppendFormat(dumpString, " - DeviceClassInfo type %d\n", adapterType);
        for (auto &deviceClassInfo : deviceClassInfos) {
            AppendFormat(dumpString, " - Data : className:%s, name:%s, adapter:%s, id:%s, lib:%s, role:%s, rate:%s\n",
                deviceClassInfo.className.c_str(), deviceClassInfo.name.c_str(),
                deviceClassInfo.adapterName.c_str(), deviceClassInfo.id.c_str(),
                deviceClassInfo.lib.c_str(), deviceClassInfo.role.c_str(), deviceClassInfo.rate.c_str());

            for (auto rate : deviceClassInfo.supportedRate_) {
                AppendFormat(dumpString, "     - rate:%u\n", rate);
            }

            for (auto supportedChannel : deviceClassInfo.supportedChannels_) {
                AppendFormat(dumpString, "     - supportedChannel:%u\n", supportedChannel);
            }

            AppendFormat(dumpString, " -DeviceClassInfo : format:%s, channels:%s, bufferSize:%s, fixedLatency:%s, "
                " sinkLatency:%s, renderInIdleState:%s, OpenMicSpeaker:%s, fileName:%s, networkId:%s, "
                "deviceType:%s, sceneName:%s, sourceType:%s, offloadEnable:%s\n",
                deviceClassInfo.format.c_str(), deviceClassInfo.channels.c_str(), deviceClassInfo.bufferSize.c_str(),
                deviceClassInfo.fixedLatency.c_str(), deviceClassInfo.sinkLatency.c_str(),
                deviceClassInfo.renderInIdleState.c_str(), deviceClassInfo.OpenMicSpeaker.c_str(),
                deviceClassInfo.fileName.c_str(), deviceClassInfo.networkId.c_str(), deviceClassInfo.deviceType.c_str(),
                deviceClassInfo.sceneName.c_str(), deviceClassInfo.sourceType.c_str(),
                deviceClassInfo.offloadEnable.c_str());
        }
        AppendFormat(dumpString, "-----EndOfXmlParsedDataMap-----\n");
    }
}

void AudioPolicyService::GetGroupInfoDump(std::string &dumpString)
{
    dumpString += "\nVolume GroupInfo:\n";
    // Get group info
    std::vector<sptr<VolumeGroupInfo>> groupInfos = GetVolumeGroupInfos();
    AppendFormat(dumpString, "- %d Group Infos (s) available :\n", groupInfos.size());

    for (auto it = groupInfos.begin(); it != groupInfos.end(); it++) {
        AppendFormat(dumpString, "  Group Infos %d\n", it - groupInfos.begin() + 1);
        AppendFormat(dumpString, "  - ConnectType(0 for Local, 1 for Remote): %d\n", (*it)->connectType_);
        AppendFormat(dumpString, "  - Name: %s\n", (*it)->groupName_.c_str());
        AppendFormat(dumpString, "  - Id: %d\n", (*it)->volumeGroupId_);
    }
    dumpString += "\n";
}

void AudioPolicyService::StreamVolumesDump(std::string &dumpString)
{
    dumpString += "\nStream Volumes:\n";
    // Get stream volumes
    std::map<AudioStreamType, int32_t> streamVolumes_;
    for (int stream = AudioStreamType::STREAM_VOICE_CALL; stream <= AudioStreamType::STREAM_TYPE_MAX; stream++) {
        AudioStreamType streamType = (AudioStreamType)stream;

        if (IsStreamSupported(streamType)) {
            if (streamType == STREAM_ALL) {
                streamType = STREAM_MUSIC;
                AUDIO_DEBUG_LOG("GetVolume of STREAM_ALL for streamType = %{public}d ", streamType);
            }
            int32_t volume = GetSystemVolumeLevel(streamType);
            streamVolumes_.insert({ streamType, volume });
        }
    }
    AppendFormat(dumpString, "   [StreamName]: [Volume]\n");
    for (auto it = streamVolumes_.cbegin(); it != streamVolumes_.cend();
        ++it) {
        AppendFormat(dumpString, " - %s: %d\n", AudioInfoDumpUtils::GetStreamName(it->first).c_str(), it->second);
    }
    GetVolumeConfigDump(dumpString);
    GetGroupInfoDump(dumpString);
    GetSafeVolumeDump(dumpString);
}

bool AudioPolicyService::IsStreamSupported(AudioStreamType streamType)
{
    switch (streamType) {
        case STREAM_MUSIC:
        case STREAM_RING:
        case STREAM_VOICE_CALL:
        case STREAM_VOICE_COMMUNICATION:
        case STREAM_VOICE_ASSISTANT:
        case STREAM_WAKEUP:
            return true;
        default:
            return false;
    }
}

void AudioPolicyService::GetVolumeConfigDump(std::string &dumpString)
{
    dumpString += "\nVolume config of streams:\n";

    StreamVolumeInfoMap streamVolumeInfos;
    GetStreamVolumeInfoMap(streamVolumeInfos);
    for (auto it = streamVolumeInfos.cbegin();
        it != streamVolumeInfos.cend(); ++it) {
        auto streamType = it->first;
        AppendFormat(dumpString, " %s: ", AudioInfoDumpUtils::GetStreamName(streamType).c_str());
        if (streamType == STREAM_ALL) {
            streamType = STREAM_MUSIC;
            AUDIO_INFO_LOG("GetStreamMute of STREAM_ALL for streamType = %{public}d ", streamType);
        }
        AppendFormat(dumpString, "mute = %d  ", GetStreamMute(streamType));
        auto streamVolumeInfo = it->second;
        AppendFormat(dumpString, "minLevel = %d  ", streamVolumeInfo->minLevel);
        AppendFormat(dumpString, "maxLevel = %d  ", streamVolumeInfo->maxLevel);
        AppendFormat(dumpString, "defaultLevel = %d\n", streamVolumeInfo->defaultLevel);
        DeviceVolumeInfosDump(dumpString, streamVolumeInfo->deviceVolumeInfos);
    }
}

void AudioPolicyService::DeviceVolumeInfosDump(std::string &dumpString, DeviceVolumeInfoMap &deviceVolumeInfos)
{
    for (auto iter = deviceVolumeInfos.cbegin(); iter != deviceVolumeInfos.cend(); ++iter) {
        AppendFormat(dumpString, "    %s : {", AudioInfoDumpUtils::GetDeviceVolumeTypeName(iter->first).c_str());
        auto volumePoints = iter->second->volumePoints;
        for (auto volPoint = volumePoints.cbegin(); volPoint != volumePoints.cend(); ++volPoint) {
            AppendFormat(dumpString, "[%d, %d]", volPoint->index, volPoint->dbValue);
            if (volPoint + 1 != volumePoints.cend()) {
                dumpString += ", ";
            }
        }
        dumpString += "}\n";
    }
}

void AudioPolicyService::AudioStreamDump(std::string &dumpString)
{
    dumpString += "\nAudioRenderer stream:\n";
    vector<unique_ptr<AudioRendererChangeInfo>> audioRendererChangeInfos;
    streamCollector_.GetCurrentRendererChangeInfos(audioRendererChangeInfos);

    AppendFormat(dumpString, " - audiorenderer stream size : %d\n", audioRendererChangeInfos.size());
    for (auto it = audioRendererChangeInfos.begin(); it != audioRendererChangeInfos.end(); it++) {
        if ((*it)->rendererInfo.rendererFlags == STREAM_FLAG_NORMAL) {
            AppendFormat(dumpString, " - normal AudioCapturer stream:\n");
        } else if ((*it)->rendererInfo.rendererFlags == STREAM_FLAG_FAST) {
            AppendFormat(dumpString, " - fast AudioCapturer stream:\n");
        }
        AppendFormat(dumpString, " - clientUID : %d\n", (*it)->clientUID);
        AppendFormat(dumpString, " - streamId : %d\n", (*it)->sessionId);
        AppendFormat(dumpString, " - deviceType : %d\n", (*it)->outputDeviceInfo.deviceType);
        AppendFormat(dumpString, " - contentType : %d\n", (*it)->rendererInfo.contentType);
        AppendFormat(dumpString, " - streamUsage : %d\n", (*it)->rendererInfo.streamUsage);
        AppendFormat(dumpString, " - samplingRate : %d\n", (*it)->rendererInfo.samplingRate);
        AudioStreamType streamType = GetStreamType((*it)->sessionId);
        AppendFormat(dumpString, " - volume : %f\n", GetSystemVolumeDb(streamType));
        AppendFormat(dumpString, " - pipeType : %d\n", (*it)->rendererInfo.pipeType);
    }
    GetCapturerStreamDump(dumpString);
}

void AudioPolicyService::GetCapturerStreamDump(std::string &dumpString)
{
    dumpString += "\nAudioCapturer stream:\n";
    vector<unique_ptr<AudioCapturerChangeInfo>> audioCapturerChangeInfos;
    streamCollector_.GetCurrentCapturerChangeInfos(audioCapturerChangeInfos);
    AppendFormat(dumpString, " - audiocapturer stream size : %d\n", audioCapturerChangeInfos.size());
    for (auto it = audioCapturerChangeInfos.begin(); it != audioCapturerChangeInfos.end(); it++) {
        if ((*it)->capturerInfo.capturerFlags == STREAM_FLAG_NORMAL) {
            AppendFormat(dumpString, " - normal AudioCapturer stream:\n");
        } else if ((*it)->capturerInfo.capturerFlags == STREAM_FLAG_FAST) {
            AppendFormat(dumpString, " - fast AudioCapturer stream:\n");
        }
        AppendFormat(dumpString, " - clientUID : %d\n", (*it)->clientUID);
        AppendFormat(dumpString, " - streamId : %d\n", (*it)->sessionId);
        AppendFormat(dumpString, " - is muted : %s\n", (*it)->muted ? "true" : "false");
        AppendFormat(dumpString, " - deviceType : %d\n", (*it)->inputDeviceInfo.deviceType);
        AppendFormat(dumpString, " - samplingRate : %d\n", (*it)->capturerInfo.samplingRate);
        AppendFormat(dumpString, " - pipeType : %d\n", (*it)->capturerInfo.pipeType);
    }
}

void AudioPolicyService::GetOffloadStatusDump(std::string &dumpString)
{
    dumpString += "\nOffload status:";
    DeviceType dev = GetActiveOutputDevice();
    if (dev != DEVICE_TYPE_SPEAKER && dev != DEVICE_TYPE_USB_HEADSET && dev != DEVICE_TYPE_BLUETOOTH_A2DP) {
        AppendFormat(dumpString, " - current device do not supportted offload: %d\n", dev);
    }
    dumpString += "\nPrimary Offload\n";
    if (dev == DEVICE_TYPE_SPEAKER || dev == DEVICE_TYPE_USB_HEADSET) {
        AppendFormat(dumpString, " - primary deviceType : %d\n", dev);
        AppendFormat(dumpString, " - primary offloadEnable : %d\n", GetOffloadAvailableFromXml());
    } else {
        AppendFormat(dumpString, " - current device is not primary\n");
    }
    dumpString += "\nA2DP offload\n";
    if (dev == DEVICE_TYPE_BLUETOOTH_A2DP) {
        AppendFormat(dumpString, " - A2DP deviceType: %d\n", dev);
        AppendFormat(dumpString, " - A2DP offloadstatus : %d\n", a2dpOffloadFlag_);
    } else {
        AppendFormat(dumpString, " - current device is not A2DP\n");
    }
    AppendFormat(dumpString, "\n");
}

int32_t AudioPolicyService::GetCurActivateCount()
{
    return audioPolicyManager_.GetCurActivateCount();
}
} // namespace AudioStandard
} // namespace OHOS

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

#ifndef ST_AUDIO_INTERRUPT_SERVICE_H
#define ST_AUDIO_INTERRUPT_SERVICE_H

#include <mutex>

#include "iremote_object.h"

#include "i_audio_interrupt_event_dispatcher.h"
#include "audio_interrupt_info.h"
#include "audio_policy_server_handler.h"
#include "audio_policy_server.h"
#include "audio_service_dump.h"

namespace OHOS {
namespace AudioStandard {

typedef struct {
    int32_t zoneId; // Zone ID value should 0 on local device.
    std::set<int32_t> pids; // When Zone ID is 0, there does not need to be a value.
    std::set<uint32_t> interruptCbSessionIdsMap;
    std::set<int32_t> audioPolicyClientProxyCBClientPidMap;
    std::unordered_map<uint32_t /* sessionID */, std::shared_ptr<AudioInterruptCallback>> interruptCbsMap;
    std::unordered_map<int32_t /* clientPid */, sptr<IAudioPolicyClient>> audioPolicyClientProxyCBMap;
    std::list<std::pair<AudioInterrupt, AudioFocuState>> audioFocusInfoList;
} AudioInterruptZone;

class AudioPolicyServerHandler;

class AudioInterruptService : public std::enable_shared_from_this<AudioInterruptService>,
                              public IAudioInterruptEventDispatcher {
public:
    AudioInterruptService();
    virtual ~AudioInterruptService();

    // callback run in handler thread
    void DispatchInterruptEventWithSessionId(
        uint32_t sessionId, const InterruptEventInternal &interruptEvent) override;

    void Init(sptr<AudioPolicyServer> server);
    void AddDumpInfo(std::unordered_map<int32_t, std::shared_ptr<AudioInterruptZone>> &audioInterruptZonesMapDump);
    void SetCallbackHandler(std::shared_ptr<AudioPolicyServerHandler> handler);

    // deprecated interrupt interfaces
    int32_t SetAudioManagerInterruptCallback(const sptr<IRemoteObject> &object);
    int32_t UnsetAudioManagerInterruptCallback();
    int32_t RequestAudioFocus(const int32_t clientId, const AudioInterrupt &audioInterrupt);
    int32_t AbandonAudioFocus(const int32_t clientId, const AudioInterrupt &audioInterrupt);

    // modern interrupt interfaces
    int32_t SetAudioInterruptCallback(const int32_t zoneId, const uint32_t sessionId,
        const sptr<IRemoteObject> &object);
    int32_t UnsetAudioInterruptCallback(const int32_t zoneId, const uint32_t sessionId);
    int32_t ActivateAudioInterrupt(const int32_t zoneId, const AudioInterrupt &audioInterrupt);
    int32_t DeactivateAudioInterrupt(const int32_t zoneId, const AudioInterrupt &audioInterrupt);

    // zone debug interfaces
    int32_t CreateAudioInterruptZone(const int32_t zoneId, const std::set<int32_t> &pids);
    int32_t ReleaseAudioInterruptZone(const int32_t zoneId);
    int32_t AddAudioInterruptZonePids(const int32_t zoneId, const std::set<int32_t> &pids);
    int32_t RemoveAudioInterruptZonePids(const int32_t zoneId, const std::set<int32_t> &pids);

    int32_t GetAudioFocusInfoList(const int32_t zoneId,
        std::list<std::pair<AudioInterrupt, AudioFocuState>> &focusInfoList);
    int32_t SetAudioFocusInfoCallback(const int32_t zoneId, const sptr<IRemoteObject> &object);
    AudioStreamType GetStreamInFocus(const int32_t zoneId);
    int32_t GetSessionInfoInFocus(AudioInterrupt &audioInterrupt, const int32_t zoneId);
    void ClearAudioFocusInfoListOnAccountsChanged(const int &id);
    void AudioInterruptZoneDump(std::string &dumpString);

private:
    static constexpr int32_t ZONEID_DEFAULT = 0;
    static constexpr float DUCK_FACTOR = 0.2f;
    static constexpr int32_t DEFAULT_APP_PID = -1;
    static constexpr int64_t OFFLOAD_NO_SESSION_ID = -1;
    static constexpr uid_t UID_ROOT = 0;
    static constexpr uid_t UID_AUDIO = 1041;

    // Inner class AudioInterruptClient for callback and death handler
    class AudioInterruptClient : public IRemoteObject::DeathRecipient {
    public:
        explicit AudioInterruptClient(
            const std::shared_ptr<AudioInterruptService> &service,
            const std::shared_ptr<AudioInterruptCallback> &callback,
            uid_t uid, pid_t pid, uint32_t sessionId);
        virtual ~AudioInterruptClient();

        DISALLOW_COPY_AND_MOVE(AudioInterruptClient);

        // DeathRecipient
        void OnRemoteDied(const wptr<IRemoteObject> &remote);

        void OnInterrupt(const InterruptEventInternal &interruptEvent);

    private:
        const std::weak_ptr<AudioInterruptService> service_;
        const std::shared_ptr<AudioInterruptCallback> callback_;
        const uid_t uid_;
        const pid_t pid_;
        const uint32_t sessionId_;
    };

    // deprecated interrupt interfaces
    void NotifyFocusGranted(const int32_t clientId, const AudioInterrupt &audioInterrupt);
    int32_t NotifyFocusAbandoned(const int32_t clientId, const AudioInterrupt &audioInterrupt);
    int32_t AbandonAudioFocusInternal(const int32_t clientId, const AudioInterrupt &audioInterrupt);

    // modern interrupt interfaces
    void ProcessAudioScene(const AudioInterrupt &audioInterrupt, const uint32_t &incomingSessionId,
        const int32_t &zoneId, bool &shouldReturnSuccess);
    int32_t ProcessFocusEntry(const int32_t zoneId, const AudioInterrupt &incomingInterrupt);
    void HandleIncomingState(const int32_t zoneId, AudioFocuState incomingState, InterruptEventInternal &interruptEvent,
        const AudioInterrupt &incomingInterrupt);
    void ProcessActiveInterrupt(const int32_t zoneId, const AudioInterrupt &incomingInterrupt);
    void ResumeAudioFocusList(const int32_t zoneId);
    std::list<std::pair<AudioInterrupt, AudioFocuState>> SimulateFocusEntry(const int32_t zoneId);
    void SendActiveInterruptEvent(const uint32_t activeSessionId, const InterruptEventInternal &interruptEvent,
        const AudioInterrupt &incomingInterrupt);
    void DeactivateAudioInterruptInternal(const int32_t zoneId, const AudioInterrupt &audioInterrupt);
    void SendInterruptEvent(AudioFocuState oldState, AudioFocuState newState,
        std::list<std::pair<AudioInterrupt, AudioFocuState>>::iterator &iterActive);
    bool IsSameAppInShareMode(const AudioInterrupt incomingInterrupt, const AudioInterrupt activateInterrupt);
    AudioScene GetHighestPriorityAudioScene(const int32_t zoneId) const;
    void UpdateAudioSceneFromInterrupt(const AudioScene audioScene, AudioInterruptChangeType changeType);
    void SendFocusChangeEvent(const int32_t zoneId, int32_t callbackCategory, const AudioInterrupt &audioInterrupt);
    void RemoveClient(uint32_t sessionId);

    // zone debug interfaces
    bool CheckAudioInterruptZonePermission();
    int32_t CreateAudioInterruptZoneInternal(const int32_t zoneId, const std::set<int32_t> &pids);
    int32_t HitZoneId(const std::set<int32_t> &pids, const std::shared_ptr<AudioInterruptZone> &audioInterruptZone,
        const int32_t &zoneId, int32_t &hitZoneId, bool &haveSamePids);
    int32_t HitZoneIdHaveTheSamePidsZone(const std::set<int32_t> &pids, int32_t &hitZoneId);
    int32_t DealAudioInterruptZoneData(const int32_t pid,
        const std::shared_ptr<AudioInterruptZone> &audioInterruptZoneTmp,
        std::shared_ptr<AudioInterruptZone> &audioInterruptZone);
    int32_t NewAudioInterruptZoneByPids(std::shared_ptr<AudioInterruptZone> &audioInterruptZone,
        const std::set<int32_t> &pids, const int32_t &zoneId);
    int32_t ArchiveToNewAudioInterruptZone(const int32_t &fromZoneId, const int32_t &toZoneId);

    // interrupt members
    sptr<AudioPolicyServer> policyServer_;
    std::shared_ptr<AudioPolicyServerHandler> handler_;

    std::map<std::pair<AudioFocusType, AudioFocusType>, AudioFocusEntry> focusCfgMap_ = {};
    std::unordered_map<int32_t, std::shared_ptr<AudioInterruptZone>> zonesMap_;

    std::map<int32_t, sptr<AudioInterruptClient>> interruptClients_;

    // deprecated interrupt members
    std::unique_ptr<AudioInterrupt> focussedAudioInterruptInfo_;
    int32_t clientOnFocus_;

    std::mutex mutex_;
};
} // namespace AudioStandard
} // namespace OHOS

#endif // ST_AUDIO_INTERRUPT_SERVICE_H

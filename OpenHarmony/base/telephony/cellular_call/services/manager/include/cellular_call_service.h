/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef CELLULAR_CALL_SERVICE_H
#define CELLULAR_CALL_SERVICE_H

#include <memory>
#include <mutex>

#include "cellular_call_config.h"
#include "cellular_call_handler.h"
#include "cellular_call_stub.h"
#include "cellular_call_supplement.h"
#include "event_runner.h"
#include "iremote_broker.h"
#include "singleton.h"
#include "system_ability.h"
#include "system_ability_status_change_stub.h"

namespace OHOS {
namespace Telephony {
enum class ServiceRunningState { STATE_STOPPED, STATE_RUNNING };

class CellularCallService : public SystemAbility,
                            public CellularCallStub,
                            public std::enable_shared_from_this<CellularCallService> {
    DECLARE_DELAYED_SINGLETON(CellularCallService)
    DECLEAR_SYSTEM_ABILITY(CellularCallService)

public:
    /**
     * service OnStart
     */
    void OnStart() override;

    /**
     * service OnStop
     */
    void OnStop() override;

    /**
     * service dump
     *
     * @param fd
     * @param args
     * @return
     */
    int32_t Dump(std::int32_t fd, const std::vector<std::u16string> &args) override;

    /**
     * Get serviceRunningState_
     * @return serviceRunningState_
     */
    int32_t GetServiceRunningState();

    /**
     * RegisterHandler
     */
    void RegisterHandler();

    /**
     * Get bindTime_
     *
     * @return int64_t
     */
    std::string GetBindTime();

    /**
     * Get EndTime
     *
     * @return int64_t
     */
    std::string GetEndTime();

    /**
     * Get SpendTime
     *
     * @return int64_t
     */
    std::string GetSpendTime();

    /**
     * Dial
     *
     * @param CellularCallInfo, dial param.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t Dial(const CellularCallInfo &callInfo) override;

    /**
     * HangUp
     *
     * @param CellularCallInfo, HangUp param.
     * @param CallSupplementType
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t HangUp(const CellularCallInfo &callInfo, CallSupplementType type) override;

    /**
     * Reject
     *
     * @param CellularCallInfo, Reject param.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t Reject(const CellularCallInfo &callInfo) override;

    /**
     * Answer
     *
     * @param CellularCallInfo, Answer param.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t Answer(const CellularCallInfo &callInfo) override;

    /**
     * HoldCall
     *
     * @param CellularCallInfo, Hold param.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t HoldCall(const CellularCallInfo &callInfo) override;

    /**
     * UnHoldCall
     *
     * @param CellularCallInfo, UnHold param.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t UnHoldCall(const CellularCallInfo &callInfo) override;

    /**
     * SwitchCall
     *
     * @param CellularCallInfo, SwitchCall param.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SwitchCall(const CellularCallInfo &callInfo) override;

    /**
     * IsEmergencyPhoneNumber
     *
     * @param slotId
     * @param phone number
     * @param enabled Is Urgent Call
     * @return TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t IsEmergencyPhoneNumber(int32_t slotId, const std::string &phoneNum, bool &enabled) override;

    /**
     * SetEmergencyCallList
     *
     * @param slotId
     * @param eccVec
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetEmergencyCallList(int32_t slotId, std::vector<EmergencyCall> &eccVec) override;

    /**
     * Merge into multiple calls
     *
     * @param CellularCallInfo
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t CombineConference(const CellularCallInfo &callInfo) override;

    /**
     * SeparateConference
     *
     * @param CellularCallInfo
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SeparateConference(const CellularCallInfo &callInfo) override;

    /**
     * InviteToConference
     *
     * @param slotId
     * @param numberList
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t InviteToConference(int32_t slotId, const std::vector<std::string> &numberList) override;

    /**
     * KickOutFromConference
     *
     * @param CellularCallInfo
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t KickOutFromConference(const CellularCallInfo &callInfo) override;

    /**
     * Hang Up All Connection
     *
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t HangUpAllConnection() override;

    /**
     * Hang Up All Connection
     *
     * @param slotId
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t HangUpAllConnection(int32_t slotId) override;

    int32_t SetReadyToCall(int32_t slotId, int32_t callType, bool isReadyToCall) override;

    /**
     * IMS Send Update Call Media Mode Request
     *
     * @param CellularCallInfo
     * @param ImsCallMode
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SendUpdateCallMediaModeRequest(const CellularCallInfo &callInfo, ImsCallMode mode) override;

    /**
     * IMS Send Update Call Media Mode Response
     *
     * @param CellularCallInfo
     * @param ImsCallMode
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SendUpdateCallMediaModeResponse(const CellularCallInfo &callInfo, ImsCallMode mode) override;

    /**
     * Cancel Call Upgrade
     *
     * @param slotId the slot id
     * @param callIndex the call index number.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t CancelCallUpgrade(int32_t slotId, int32_t callIndex) override;

    /**
     * Request Camera Capabilities
     *
     * @param slotId the slot id
     * @param callIndex the call index number.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t RequestCameraCapabilities(int32_t slotId, int32_t callIndex) override;

    /**
     * Register CallManager CallBack
     *
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t RegisterCallManagerCallBack(const sptr<ICallStatusCallback> &callback) override;

    /**
     * UnRegister CallManager CallBack
     *
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t UnRegisterCallManagerCallBack() override;

    /**
     * StartDtmf
     *
     * @param Dtmf Code
     * @param CellularCallInfo
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t StartDtmf(char cDtmfCode, const CellularCallInfo &callInfo) override;

    /**
     * StopDtmf
     *
     * @param CellularCallInfo
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t StopDtmf(const CellularCallInfo &callInfo) override;

    int32_t PostDialProceed(const CellularCallInfo &callInfo, const bool proceed) override;

    /**
     * SendDtmf
     *
     * @param Dtmf Code
     * @param CellularCallInfo
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SendDtmf(char cDtmfCode, const CellularCallInfo &callInfo) override;

    /**
     * Start Rtt
     *
     * @param slotId
     * @param msg
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t StartRtt(int32_t slotId, const std::string &msg) override;

    /**
     * Stop Rtt
     *
     * @param slotId
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t StopRtt(int32_t slotId) override;

    /**
     * Set Call Transfer
     *
     * @param slotId
     * @param CallTransferInfo
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetCallTransferInfo(int32_t slotId, const CallTransferInfo &cfInfo) override;

    /**
     * confirm whether IMS can set call transfer time.
     *
     * @param slotId[in], The slot id
     * @param result[out], The result of can set or not
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t CanSetCallTransferTime(int32_t slotId, bool &result) override;

    /**
     * Get Call Transfer
     *
     * @param slotId
     * @param CallTransferType
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetCallTransferInfo(int32_t slotId, CallTransferType type) override;

    /**
     * Set Call Waiting
     *
     * @param slotId
     * @param activate
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetCallWaiting(int32_t slotId, bool activate) override;

    /**
     * Inquire Call Waiting
     *
     * @param slotId
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetCallWaiting(int32_t slotId) override;

    /**
     * Set Call Restriction
     *
     * @param slotId
     * @param CallRestrictionInfo
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetCallRestriction(int32_t slotId, const CallRestrictionInfo &crInfo) override;

    /**
     * Inquire Call Restriction
     *
     * @param slotId
     * @param CallRestrictionType
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetCallRestriction(int32_t slotId, CallRestrictionType facType) override;

    /**
     * @brief Set the call restriction password of the specified account
     *
     * @param slotId[in] the slot id
     * @param facType[in] indicate the call restriction type, just like all incoming, all outgoing .etc
     * @param oldPassword[in] indicate the call restriction old password
     * @param newPassword[in] indicate the call restriction new password
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetCallRestrictionPassword(
        int32_t slotId, CallRestrictionType facType, const char *oldPassword, const char *newPassword) override;

    /**
     * Set Domain Preference Mode
     *
     * @param slotId
     * @param mode
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetDomainPreferenceMode(int32_t slotId, int32_t mode) override;

    /**
     * Get Domain Preference Mode
     *
     * @param slotId
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetDomainPreferenceMode(int32_t slotId) override;

    /**
     * Set Ims Switch Status
     *
     * @param slotId
     * @param active
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetImsSwitchStatus(int32_t slotId, bool active) override;

    /**
     * Get Ims Switch Status
     *
     * @param slotId
     * @param enabled
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetImsSwitchStatus(int32_t slotId, bool &enabled) override;

    /**
     * Set Ims Config
     *
     * @param slotId
     * @param ImsConfigItem
     * @param value
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetImsConfig(int32_t slotId, ImsConfigItem item, const std::string &value) override;

    /**
     * Set VoNR Switch State
     *
     * @param slotId
     * @param state
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t SetVoNRState(int32_t slotId, int32_t state) override;

    /**
     * Get VoNR Switch State
     *
     * @param slotId
     * @param state
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t GetVoNRState(int32_t slotId, int32_t &state) override;

    /**
     * Set Ims Config
     *
     * @param slotId
     * @param ImsConfigItem
     * @param value
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetImsConfig(int32_t slotId, ImsConfigItem item, int32_t value) override;

    /**
     * Get Ims Config
     *
     * @param slotId
     * @param ImsConfigItem
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetImsConfig(int32_t slotId, ImsConfigItem item) override;

    /**
     * Set Ims Feature Value
     *
     * @param slotId
     * @param FeatureType
     * @param value
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetImsFeatureValue(int32_t slotId, FeatureType type, int32_t value) override;

    /**
     * Get Ims Feature Value
     *
     * @param slotId
     * @param FeatureType
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetImsFeatureValue(int32_t slotId, FeatureType type) override;

    /**
     * ControlCamera
     *
     * @param slotId[in], The slot id
     * @param index Indicates the call index number.
     * @param cameraId
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t ControlCamera(int32_t slotId, int32_t index, const std::string &cameraId) override;

    /**
     * SetPreviewWindow
     *
     * @param slotId[in], The slot id
     * @param index Indicates the call index number.
     * @param surfaceID Surface id of window object
     * @param surface The surface object of window
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetPreviewWindow(
        int32_t slotId, int32_t index, const std::string &surfaceId, sptr<Surface> surface) override;

    /**
     * SetDisplayWindow
     *
     * @param slotId[in], The slot id
     * @param index Indicates the call index number.
     * @param surfaceID Surface id of window object
     * @param surface The surface object of window
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetDisplayWindow(
        int32_t slotId, int32_t index, const std::string &surfaceId, sptr<Surface> surface) override;

    /**
     * SetCameraZoom
     *
     * @param zoomRatio
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetCameraZoom(float zoomRatio) override;

    /**
     * SetPausePicture
     *
     * @param slotId[in], The slot id
     * @param index Indicates the call index number.
     * @param path
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetPausePicture(int32_t slotId, int32_t index, const std::string &path) override;

    /**
     * SetDeviceDirection
     *
     * @param slotId[in], The slot id
     * @param index Indicates the call index number.
     * @param rotation
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetDeviceDirection(int32_t slotId, int32_t index, int32_t rotation) override;

    /**
     * SetMute
     *
     * @param mute
     * @param slotId
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetMute(int32_t slotId, int32_t mute) override;

    /**
     * GetMute
     *
     * @param slotId
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetMute(int32_t slotId) override;

    /**
     * Close Unfinished ussd
     *
     * @param slotId
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t CloseUnFinishedUssd(int32_t slotId) override;

    int32_t ClearAllCalls(const std::vector<CellularCallInfo> &infos) override;

    /**
     * Is need choose IMS for execute
     *
     * @param slotId
     * @return bool
     */
    bool IsNeedIms(int32_t slotId) const;

    /**
     * Get CSControl
     *
     * @param slotId
     * @return shared_ptr CSControl
     */
    std::shared_ptr<CSControl> GetCsControl(int32_t slotId);

    /**
     * Get IMControl
     *
     * @param slotId
     * @return shared_ptr CSControl
     */
    std::shared_ptr<IMSControl> GetImsControl(int32_t slotId);

    /**
     * Get SatelliteControl
     *
     * @param slotId
     * @return shared_ptr SatelliteControl
     */
    std::shared_ptr<SatelliteControl> GetSatelliteControl(int32_t slotId);

    /**
     * Set SetCsControl
     *
     * @param slotId
     * @param  shared_ptr CSControl
     */
    void SetCsControl(int32_t slotId, const std::shared_ptr<CSControl> &csControl);

    /**
     * Set IMSControl
     *
     * @param slotId
     * @param  shared_ptr IMSControl
     */
    void SetImsControl(int32_t slotId, const std::shared_ptr<IMSControl> &imsControl);

    /**
     * Set SatelliteControl
     *
     * @param slotId
     * @param  shared_ptr SatelliteControl
     */
    void SetSatelliteControl(int32_t slotId, const std::shared_ptr<SatelliteControl> &satelliteControl);

    /**
     * Get Handler
     *
     * @param slotId
     * @return CellularCallHandler
     */
    std::shared_ptr<CellularCallHandler> GetHandler(int32_t slotId);

    void SetSrvccState(int32_t srvccState);

    int32_t GetSrvccState();

#ifdef CALL_MANAGER_AUTO_START_OPTIMIZE
    /**
     * Get call manager service
     */
    void StartCallManagerService();
#endif

private:
    /**
     * Init service
     *
     * @return whether init success
     */
    bool Init();

    /**
     * Register Handler
     */
    void RegisterCoreServiceHandler();

    /**
     * Create Handler
     */
    void CreateHandler();

    /**
     * Handler Reset UnRegister
     */
    void HandlerResetUnRegister();

    /**
     * SendEventRegisterHandler
     */
    void SendEventRegisterHandler();

    /**
     * Is Valid Slot Id
     *
     * @param slotId
     * @return bool
     */
    bool IsValidSlotId(int32_t slotId) const;

    /**
     * Check whether IMS should be used firstly for emergency call
     */
    bool UseImsForEmergency(const CellularCallInfo &callInfo, bool isEcc);

    /**
     * Handle CallManager exception
     */
    void HandleCallManagerException();

    void HangUpWithCellularCallRestart(const std::vector<CellularCallInfo> &infos);

    int32_t SetControl(const CellularCallInfo &info);

    int32_t DialNormalCall(const CellularCallInfo &callInfo, bool isEcc);

    void HandleCellularControlException(const CellularCallInfo &callInfo);

    CallReportInfo EncapsulationCallReportInfo(const CellularCallInfo &callInfo);

private:
    enum class SatelliteState {
        SATELLITE_OFF,
        SATELLITE_ON,
    };

    int64_t bindTime_ = 0L;
    int64_t endTime_ = 0L;
    int64_t spendTime_ = 0L;
    ServiceRunningState state_;
    std::map<int32_t, std::shared_ptr<CellularCallHandler>> handlerMap_;
    int32_t srvccState_ = SrvccState::SRVCC_NONE;
    std::map<int32_t, std::shared_ptr<CSControl>> csControlMap_;
    std::map<int32_t, std::shared_ptr<IMSControl>> imsControlMap_;
    std::map<int32_t, std::shared_ptr<SatelliteControl>> satelliteControlMap_;
    sptr<NetworkSearchCallBackBase> networkSearchCallBack_;
    sptr<ISystemAbilityStatusChange> statusChangeListener_ = nullptr;
    sptr<ISystemAbilityStatusChange> callManagerListener_ = nullptr;
    std::mutex mutex_;

private:
    class SystemAbilityStatusChangeListener : public OHOS::SystemAbilityStatusChangeStub {
    public:
        SystemAbilityStatusChangeListener() = default;
        explicit SystemAbilityStatusChangeListener(std::shared_ptr<CellularCallHandler> &cellularCallHandler);
        ~SystemAbilityStatusChangeListener() = default;
        virtual void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
        virtual void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;

    private:
        std::shared_ptr<CellularCallHandler> cellularCallHandler_ = nullptr;
        int32_t count_ = 0;
    };
};
} // namespace Telephony
} // namespace OHOS

#endif // CELLULAR_CALL_SERVICE_H

/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef TELEPHONY_IMS_CALL_CLIENT_H
#define TELEPHONY_IMS_CALL_CLIENT_H

#include "event_runner.h"
#include "ims_call_interface.h"
#include "ims_core_service_interface.h"
#include "iremote_stub.h"
#include "rwlock.h"
#include "singleton.h"
#include "system_ability_status_change_stub.h"

namespace OHOS {
namespace Telephony {
class ImsCallClient {
    DECLARE_DELAYED_SINGLETON(ImsCallClient);

public:
    /**
     * @brief Get ImsCall Remote Object ptr
     *
     * @return sptr<ImsCallInterface>
     */
    sptr<ImsCallInterface> GetImsCallProxy();

    /**
     * @brief Get the remote object ptr, initiate a listener and subscribe the system ability
     */
    void Init();

    /**
     * @brief Clear the listener and the remote ptr when destroy the ImsCallClient Object
     */
    void UnInit();

    /**
     * @brief Register ImsCallCallback Handler, put the handler and slot id into {handlerMap_}
     *
     * @param slotId Indicates the card slot index number,
     * @param handler Indicates the event handler ptr
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t RegisterImsCallCallbackHandler(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    /**
     * @brief Get the event handler ptr from {handlerMap_}
     *
     * @param slotId Indicates the card slot index number,
     * @return AppExecFwk::EventHandler
     */
    std::shared_ptr<AppExecFwk::EventHandler> GetHandler(int32_t slotId);

    /****************** call basic ******************/
    /**
     * @brief IMS dial the call interface
     *
     * @param ImsCallInfo Indicates the call detail information, contains phone number, slot id,
     * video state, call index
     * @param CLIRMode Indicates the CLIR mode, like default, transfer, inhibition
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t Dial(const ImsCallInfo &callInfo, CLIRMode mode);

    /**
     * @brief IMS HangUp the call interface
     *
     * @param ImsCallInfo Indicates the call detail information, contains phone number, slot id,
     * video state, call index
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t HangUp(const ImsCallInfo &callInfo);

    /**
     * @brief IMS Reject the call interface
     *
     * @param ImsCallInfo Indicates the call detail information, contains phone number, slot id,
     * video state, call index
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t Reject(const ImsCallInfo &callInfo);

    /**
     * @brief IMS Reject the call with reason interface
     *
     * @param ImsCallInfo Indicates the call detail information, contains phone number, slot id,
     * video state, call index
     * @param ImsRejectReason Indicated the reject reason, like user is busy or user decline
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t RejectWithReason(const ImsCallInfo &callInfo, const ImsRejectReason &reason);

    /**
     * @brief IMS Answer the call interface
     *
     * @param ImsCallInfo Indicates the call detail information, contains phone number, slot id,
     * video state, call index
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t Answer(const ImsCallInfo &callInfo);

    /**
     * @brief Hold the Call
     *
     * @param slotId Indicates the card slot index number,
     * @param callType Indicates the call type,
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t HoldCall(int32_t slotId, int32_t callType);

    /**
     * @brief UnHold the Call
     *
     * @param slotId Indicates the card slot index number,
     * @param callType Indicates the type of video state, 0: voice, 1: video
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t UnHoldCall(int32_t slotId, int32_t callType);

    /**
     * @brief Switch the phone call between hold and unhold
     *
     * @param slotId Indicates the card slot index number,
     * @param callType Indicates the type of video state, 0: voice, 1: video
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SwitchCall(int32_t slotId, int32_t callType);

    /**
     * @brief Merge calls to form a conference
     *
     * @param slotId Indicates the card slot index number,
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t CombineConference(int32_t slotId);

    /**
     * @brief Invite someone to conference
     *
     * @param slotId Indicates the card slot index number,
     * @param numberList phone number list which will be invited to the conference call
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t InviteToConference(int32_t slotId, const std::vector<std::string> &numberList);

    /**
     * @brief Kick out someone from conference
     *
     * @param slotId Indicates the card slot index number,
     * @param index which will be kicked out from the conference call
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t KickOutFromConference(int32_t slotId, int32_t index);

    /**
     * @brief IMS SendUpdateCallMediaModeRequest interface
     *
     * @param ImsCallInfo Indicates the call detail information, contains phone number, slot id,
     * video state, call index
     * @param ImsCallType Indicates the call media mode, like audio only, send only .etc.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SendUpdateCallMediaModeRequest(const ImsCallInfo &callInfo, ImsCallType callType);

    /**
     * @brief IMS SendUpdateCallMediaModeResponse interface
     *
     * @param ImsCallInfo Indicates the call detail information, contains phone number, slot id,
     * video state, call index
     * @param ImsCallType Indicates the call media mode, like audio only, send only .etc.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SendUpdateCallMediaModeResponse(const ImsCallInfo &callInfo, ImsCallType callType);

    /**
     * @brief Cancel Call Upgrade
     *
     * @param slotId Indicates the slot id
     * @param Indicates Indicates the call index number.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t CancelCallUpgrade(int32_t slotId, int32_t callIndex);

    /**
     * @brief Request Camera Capabilities
     *
     * @param slotId Indicates the slot id
     * @param callIndex Indicates the call index number.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t RequestCameraCapabilities(int32_t slotId, int32_t callIndex);

    /**
     * @brief Get Ims Calls Data Request
     *
     * @param slotId Indicates the card slot index number,
     * @param lastCallsDataFlag The ims call data id, is a number in milliseconds
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetImsCallsDataRequest(int32_t slotId, int64_t lastCallsDataFlag);

    /**
     * @brief Get Last Call Fail Reason
     *
     * @param slotId Indicates the card slot index number,
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetLastCallFailReason(int32_t slotId);

    /****************** dtmf rtt ******************/
    /**
     * @brief start to paly a dtmf tone
     *
     * @param slotId Indicates the card slot index number,
     * @param cDTMFCode A character indicate the DTMF digit for which to play the tone. This
     * value must be one of {0~9}, {*} or {#}.
     * @param index Indicates the index of command.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t StartDtmf(int32_t slotId, char cDtmfCode, int32_t index);

    /**
     * @brief play a dtmf tone
     *
     * @param slotId Indicates the card slot index number,
     * @param cDtmfCode A character indicate the DTMF digit for which to play the tone. This
     * value must be one of {0~9}, {*} or {#}.
     * @param index Indicates the index of command.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SendDtmf(int32_t slotId, char cDtmfCode, int32_t index);

    /**
     * @brief stop the playing dtmf tone
     *
     * @param slotId Indicates the card slot index number,
     * @param index Indicates the index of command.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t StopDtmf(int32_t slotId, int32_t index);

    /**
     * @brief Start a RTT session
     *
     * @param slotId Indicates the card slot index number,
     * @param msg the specific RTT msg
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t StartRtt(int32_t slotId, const std::string &msg);

    /**
     * @brief Terminate the current RTT session
     *
     * @param slotId Indicates the card slot index number,
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t StopRtt(int32_t slotId);

    /****************** ims config ******************/
    /**
     * @brief Set Domain Preference Mode
     *
     * @param slotId Indicates the card slot index number,
     * @param mode indicate the domain preference, 1: CS only, 2: CS prefer, 3: PS prefer, 4: PS only
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetDomainPreferenceMode(int32_t slotId, int32_t mode);

    /**
     * @brief Get Domain Preference Mode
     *
     * @param slotId Indicates the card slot index number,
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetDomainPreferenceMode(int32_t slotId);

    /**
     * @brief Set the ims switch status
     *
     * @param slotId Indicates the card slot index number,
     * @param active 1: enable ims, 0: disable ims
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetImsSwitchStatus(int32_t slotId, int32_t active);

    /**
     * @brief IMS GetImsSwitchStatus interface
     *
     * @param slotId Indicates the card slot index number,
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetImsSwitchStatus(int32_t slotId);

    /**
     * @brief IMS SetImsConfig interface
     *
     * @param ImsConfigItem Identify specific item, like ITEM_VIDEO_QUALITY, ITEM_IMS_SWITCH_STATUS
     * @param value The specific value corresponding to the item
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetImsConfig(ImsConfigItem item, const std::string &value);

    /**
     * @brief IMS SetImsConfig interface
     *
     * @param ImsConfigItem Identify specific item, like ITEM_VIDEO_QUALITY, ITEM_IMS_SWITCH_STATUS
     * @param value The specific value corresponding to the item
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetImsConfig(ImsConfigItem item, int32_t value);

    /**
     * @brief IMS GetImsConfig interface
     *
     * @param ImsConfigItem Identify specific item, like ITEM_VIDEO_QUALITY, ITEM_IMS_SWITCH_STATUS
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetImsConfig(ImsConfigItem item);

    /**
     * @brief IMS SetImsFeatureValue interface
     *
     * @param FeatureType the ims feature item, like VoLTE, ViLTE, SS over UT
     * @param value The specific value corresponding to the item
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetImsFeatureValue(FeatureType type, int32_t value);

    /**
     * @brief IMS GetImsFeatureValue interface
     *
     * @param FeatureType Indicate which feature type to query.
     * @param value Indicate the return value of the query feature type.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetImsFeatureValue(FeatureType type, int32_t &value);

    /**
     * @brief Set the mute state of the call
     *
     * @param mute 0: not mute, 1:mute
     * @param slotId Indicates the card slot index number,
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetMute(int32_t slotId, int32_t mute);

    /**
     * @brief IMS GetMute interface
     *
     * @param slotId Indicates the card slot index number,
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetMute(int32_t slotId);

    /****************** video settings ******************/
    /**
     * @brief IMS ControlCamera interface
     *
     * @param slotId[in], The slot id
     * @param callIndex Indicates the call index number.
     * @param cameraId The id of the camera
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t ControlCamera(int32_t slotId, int32_t callIndex, const std::string &cameraId);

    /**
     * @brief Set a window which used to display a preview of camera capturing
     *
     * @param slotId[in], The slot id
     * @param callIndex Indicates the call index number.
     * @param surfaceID Surface id of window object
     * @param surface The surface object of window
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetPreviewWindow(int32_t slotId, int32_t callIndex, const std::string &surfaceID, sptr<Surface> surface);

    /**
     * @brief Set a window which used to display the viedo which is received from remote
     *
     * @param slotId[in], The slot id
     * @param callIndex Indicates the call index number.
     * @param surfaceID Surface id of window object
     * @param surface The surface object of window
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetDisplayWindow(int32_t slotId, int32_t callIndex, const std::string &surfaceID, sptr<Surface> surface);

    /**
     * @brief Set camera zoom ratio
     *
     * @param zoomRatio the camera zoom ratio
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetCameraZoom(float zoomRatio);

    /**
     * @brief Set a picture which will be displayed when the video signal is paused
     *
     * @param slotId[in], The slot id
     * @param callIndex Indicates the call index number.
     * @param path the dispalyed image path
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetPausePicture(int32_t slotId, int32_t callIndex, const std::string &path);

    /**
     * @brief Set the device orientation
     *
     * @param slotId[in], The slot id
     * @param callIndex Indicates the call index number.
     * @param rotation The device orientation, in degrees
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetDeviceDirection(int32_t slotId, int32_t callIndex, int32_t rotation);

    /****************** supplement ******************/
    /**
     * @brief SetClip IMS SetClip interface
     *
     * @param slotId Indicates the card slot index number,
     * ranging from 0 to the maximum card slot index number supported by the device.
     * @param action Indicates the action for SetClip,
     * 1, means turn on clip; 0, means turn off clip.
     * @param index Indicates the index of command.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetClip(int32_t slotId, int32_t action, int32_t index);

    /**
     * @brief GetClip IMS GetClip interface
     *
     * @param slotId Indicates the card slot index number,
     * ranging from 0 to the maximum card slot index number supported by the device.
     * @param index Indicates the index of command.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetClip(int32_t slotId, int32_t index);

    /**
     * @brief SetClir IMS SetClir interface
     *
     * @param slotId Indicates the card slot index number,
     * ranging from 0 to the maximum card slot index number supported by the device.
     * @param action Indicates the action for SetClir,
     * 1, means turn on clir; 0, means turn off clir.
     * @param index Indicates the index of command.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetClir(int32_t slotId, int32_t action, int32_t index);

    /**
     * @brief GetClir IMS GetClir interface
     *
     * @param slotId Indicates the card slot index number,
     * ranging from 0 to the maximum card slot index number supported by the device.
     * @param index Indicates the index of command.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetClir(int32_t slotId, int32_t index);

    /**
     * @brief SetCallTransfer Set Call Transfer Request
     *
     * @param slotId Indicates the card slot index number,
     * ranging from 0 to the maximum card slot index number supported by the device.
     * @param cfInfo Indicates the reason/mode/transferNum/timer of the set call transfer.
     * @param classType Indicates a sum of service class for setting call transfer.
     * @param index Indicates the index of command.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetCallTransfer(int32_t slotId, const CallTransferInfo &cfInfo, int32_t classType, int32_t index);

    /**
     * @brief confirm whether IMS can set call transfer time.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from 0 to the maximum card slot index number supported by the device.
     * @param result, The result of can set or not
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t CanSetCallTransferTime(int32_t slotId, bool &result);

    /**
     * @brief GetCallTransfer IMS GetCallTransfer interface
     *
     * @param slotId Indicates the card slot index number,
     * ranging from 0 to the maximum card slot index number supported by the device.
     * @param reason Indicates the reason of the get call transfer.
     * @param index Indicates the index of command.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetCallTransfer(int32_t slotId, int32_t reason, int32_t index);

    /**
     * @brief SetCallRestriction IMS SetCallRestriction interface
     *
     * @param slotId Indicates the card slot index number,
     * ranging from 0 to the maximum card slot index number supported by the device.
     * @param fac Indicates the facility of the set call restriction.
     * @param mode Indicates the mode of the set call restriction.
     * @param pw Indicates password or "" if not required.
     * @param index Indicates the index of command.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetCallRestriction(
        int32_t slotId, const std::string &fac, int32_t mode, const std::string &pw, int32_t index);

    /**
     * @brief GetCallRestriction IMS GetCallRestriction interface
     *
     * @param slotId Indicates the card slot index number,
     * ranging from 0 to the maximum card slot index number supported by the device.
     * @param fac Indicates the facility of the get call restriction.
     * @param index Indicates the index of command.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetCallRestriction(int32_t slotId, const std::string &fac, int32_t index);

    /**
     * @brief SetCallWaiting IMS SetCallWaiting interface
     *
     * @param slotId Indicates the card slot index number,
     * ranging from 0 to the maximum card slot index number supported by the device.
     * @param activate Indicates the action for SetCallWaiting,
     * true, means turn on CallWaiting; false, means turn off CallWaiting.
     * @param classType Call waiting and conditions +CCWA,
     * the value was {@code ServiceClassType}, See 3GPP TS 22.083.
     * @param index Indicates the index of command.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetCallWaiting(int32_t slotId, bool activate, int32_t classType, int32_t index);

    /**
     * @brief GetCallWaiting IMS GetCallWaiting interface
     *
     * @param slotId Indicates the card slot index number,
     * ranging from 0 to the maximum card slot index number supported by the device.
     * @param index Indicates the index of command.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetCallWaiting(int32_t slotId, int32_t index);

    /**
     * @brief SetColr IMS SetColr interface
     *
     * @param slotId Indicates the card slot index number,
     * ranging from 0 to the maximum card slot index number supported by the device.
     * @param presentation Indicates the action for SetColr,
     * 1, means turn on colr; 0, means turn off colr.
     * @param index Indicates the index of command.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetColr(int32_t slotId, int32_t presentation, int32_t index);

    /**
     * @brief GetColr IMS GetColr interface
     *
     * @param slotId Indicates the card slot index number,
     * ranging from 0 to the maximum card slot index number supported by the device.
     * @param index Indicates the index of command.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetColr(int32_t slotId, int32_t index);

    /**
     * @brief SetColp IMS SetColp interface
     *
     * @param slotId Indicates the card slot index number,
     * ranging from 0 to the maximum card slot index number supported by the device.
     * @param action Indicates the action for SetColp,
     * 1, means turn on colp; 0, means turn off colp.
     * @param index Indicates the index of command.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetColp(int32_t slotId, int32_t action, int32_t index);

    /**
     * @brief GetColp IMS GetColp interface
     *
     * @param slotId Indicates the card slot index number,
     * ranging from 0 to the maximum card slot index number supported by the device.
     * @param index Indicates the index of command.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetColp(int32_t slotId, int32_t index);

    /**
     * @brief Update Ims Capabilities
     *
     * @param slotId Indicates the card slot index number,
     * ranging from 0 to the maximum card slot index number supported by the device.
     * @param imsCapabilityList Indicates the related ims capability
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t UpdateImsCapabilities(int32_t slotId, const ImsCapabilityList &imsCapabilityList);

    /**
     * @brief Get impu which come form network
     *
     * @param slotId Indicates the card slot index number,
     * ranging from 0 to the maximum card slot index number supported by the device.
     * @param impu the result of impu
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetUtImpuFromNetwork(int32_t slotId, std::string &impu);

private:
    class SystemAbilityListener : public SystemAbilityStatusChangeStub {
    public:
        SystemAbilityListener() {}
        ~SystemAbilityListener() {}

    public:
        void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
        void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
    };

    /**
     * Is Connect ImsCall Remote Object
     *
     * @return bool
     */
    bool IsConnect() const;
    int32_t RegisterImsCallCallback();
    int32_t ReConnectService();
    void Clean();

private:
    sptr<ImsCoreServiceInterface> imsCoreServiceProxy_ = nullptr;
    sptr<ImsCallInterface> imsCallProxy_ = nullptr;
    sptr<ImsCallCallbackInterface> imsCallCallback_ = nullptr;
    std::map<int32_t, std::shared_ptr<AppExecFwk::EventHandler>> handlerMap_;
    Utils::RWLock rwClientLock_;
    sptr<ISystemAbilityStatusChange> statusChangeListener_ = nullptr;
};
} // namespace Telephony
} // namespace OHOS

#endif // TELEPHONY_IMS_CORE_SERVICE_CLIENT_H

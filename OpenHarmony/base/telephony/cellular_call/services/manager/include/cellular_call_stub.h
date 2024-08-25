/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef CELLULAR_CALL_STUB_H
#define CELLULAR_CALL_STUB_H

#include <map>

#include "cellular_call_data_struct.h"
#include "cellular_call_interface.h"
#include "cellular_call_ipc_interface_code.h"
#include "iremote_stub.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class CellularCallStub : public IRemoteStub<CellularCallInterface> {
public:
    /**
     * CellularCallStub Constructors
     */
    CellularCallStub();

    /**
     * ~CellularCallStub Destructor
     */
    virtual ~CellularCallStub();

    /**
     * OnRemoteRequest
     *
     * @param code
     * @param data
     * @param reply
     * @param option
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    /**
     * On Dial Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnDialInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On HangUp Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnHangUpInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On Reject Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnRejectInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On Answer Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnAnswerInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On Is Emergency Call Inner
     *
     * @param data  send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnIsEmergencyPhoneNumberInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On HoldCall Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnHoldCallInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On UnHoldCall Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnUnHoldCallInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On SwitchCall Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnSwitchCallInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On CombineConference Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnCombineConferenceInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On SeparateConference Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnSeparateConferenceInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On InviteToConference Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnInviteToConferenceInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On KickOutFromConference Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnKickOutFromConferenceInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On HangUpAllConnection Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnHangUpAllConnectionInner(MessageParcel &data, MessageParcel &reply);

    int32_t OnSetReadyToCallInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On SendUpdateCallMediaModeRequest Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnSendUpdateCallMediaModeRequestInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On SendUpdateCallMediaModeResponse Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnSendUpdateCallMediaModeResponseInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On Cancel Call Upgrade Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnCancelCallUpgradeInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On Request Camera Capabilities Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnRequestCameraCapabilitiesInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On Register Call Back Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnRegisterCallBackInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On UnRegister Call Back Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnUnRegisterCallBackInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On start Dtmf Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnStartDtmfInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On stop Dtmf Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnStopDtmfInner(MessageParcel &data, MessageParcel &reply);

    int32_t OnPostDialProceedInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On send Dtmf Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnSendDtmfInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On start Rtt Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnStartRttInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On stop Rtt Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnStopRttInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On Set Call Transfer Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnSetCallTransferInner(MessageParcel &data, MessageParcel &reply);

    /**
     * confirm whether IMS can set call transfer time.
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnCanSetCallTransferTimeInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On Inquire Call Transfer Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnGetCallTransferInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On Set Call Waiting
     *
     * @param data  send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnSetCallWaitingInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On Inquire Call Waiting
     *
     * @param data  send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnGetCallWaitingInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On Set Call Restriction
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnSetCallRestrictionInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On Get Call Restriction
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnGetCallRestrictionInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On Set Call Restriction Password
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnSetCallRestrictionPasswordInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On Set Domain Preference Mode
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnSetDomainPreferenceModeInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On Get Domain Preference Mode
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnGetDomainPreferenceModeInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On Set Ims Switch Status
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnSetImsSwitchStatusInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On Get Ims Switch Status
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnGetImsSwitchStatusInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On Set VoNR Switch Status
     *
     * @param data send data
     * @param reply received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnSetVoNRStateInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On Get VoNR Switch Status
     *
     * @param data send data
     * @param reply received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnGetVoNRStateInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On SetImsConfigStringInner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnSetImsConfigStringInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On SetImsConfigIntInner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnSetImsConfigIntInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On GetImsConfigInner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnGetImsConfigInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On SetImsFeatureValueInner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnSetImsFeatureValueInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On GetImsFeatureValueInner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnGetImsFeatureValueInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On Control Camera Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnControlCameraInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On Set Preview Window Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnSetPreviewWindowInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On Set Display Window Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnSetDisplayWindowInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On Set Camera Zoom Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnSetCameraZoomInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On Set Pause Picture Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnSetPausePictureInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On Set Device Direction Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnSetDeviceDirectionInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On Set Mute Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnSetMuteInner(MessageParcel &data, MessageParcel &reply);

    /**
     * On Get Mute Inner
     *
     * @param data send data
     * @param reply Received data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnGetMuteInner(MessageParcel &data, MessageParcel &reply);

    /**
     * Close Unfinished ussd
     *
     * @brief Close Unfinished ussd function for the current account
     * @param slotId[in], The slot id
     * @return Returns 0 on success, others on failure.
     */
    int32_t OnCloseUnFinishedUssdInner(MessageParcel &data, MessageParcel &reply);

    /**
     * @brief clear all call if cellular call service restart
     *
     * @param infos[in] the call detail info vector which contains phone number, call type, slot id .etc
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnClearAllCallsInner(MessageParcel &data, MessageParcel &reply);

    int32_t OnSetEmergencyCallList(MessageParcel &data, MessageParcel &reply);

private:
    using RequestFuncType = int32_t (CellularCallStub::*)(MessageParcel &data, MessageParcel &reply);
    std::map<CellularCallInterfaceCode, RequestFuncType> requestFuncMap_;
    void InitFuncMap();
    void InitDialFuncMap();
    void InitDtmfFuncMap();
    void InitConfigFuncMap();
    void InitVideoFuncMap();
    void InitSupplementFuncMap();
};
} // namespace Telephony
} // namespace OHOS

#endif // CELLULAR_CALL_STUB_H

/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef TELEPHONY_IMS_CALL_CALLBACK_INTERFACE_H
#define TELEPHONY_IMS_CALL_CALLBACK_INTERFACE_H

#include "call_manager_inner_type.h"
#include "tel_ril_call_parcel.h"
#include "ims_call_types.h"
#include "iremote_broker.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
class ImsCallCallbackInterface : public IRemoteBroker {
public:
    virtual ~ImsCallCallbackInterface() = default;

    /**
     * @brief DialResponse the result of dial by ims.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param info Indicates dial action was success or failure.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t DialResponse(int32_t slotId, const RadioResponseInfo &info) = 0;

    /**
     * @brief HangUpResponse the result of hang up by ims.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param info Indicates hang up action was success or failure.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t HangUpResponse(int32_t slotId, const RadioResponseInfo &info) = 0;

    /**
     * @brief RejectWithReasonResponse the result of reject with reason by ims.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param info Indicates reject action was success or failure.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t RejectWithReasonResponse(int32_t slotId, const RadioResponseInfo &info) = 0;

    /**
     * @brief AnswerResponse the result of answer by ims.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param info Indicates answer action was success or failure.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t AnswerResponse(int32_t slotId, const RadioResponseInfo &info) = 0;

    /**
     * @brief HoldCallResponse the result of hold call by ims.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param info Indicates hold action was success or failure.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t HoldCallResponse(int32_t slotId, const RadioResponseInfo &info) = 0;

    /**
     * @brief UnHoldCallResponse the result of unhold call by ims.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param info Indicates unhold action was success or failure.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t UnHoldCallResponse(int32_t slotId, const RadioResponseInfo &info) = 0;

    /**
     * @brief SwitchCallResponse the result of switch call by ims.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param info Indicates switch action was success or failure.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t SwitchCallResponse(int32_t slotId, const RadioResponseInfo &info) = 0;

    /**
     * @brief StartDtmfResponse the result of start dtmf by ims.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param info Indicates start action was success or failure.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t StartDtmfResponse(int32_t slotId, const RadioResponseInfo &info) = 0;
    /**
     * @brief SendDtmfResponse the result of send dtmf by ims.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param info Indicates send action was success or failure.
     * @param callIndex Indicates the call index number.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t SendDtmfResponse(int32_t slotId, const RadioResponseInfo &info, int32_t callIndex) = 0;

    /**
     * @brief StopDtmfResponse the result of stop dtmf by ims.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param info Indicates stop action was success or failure.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t StopDtmfResponse(int32_t slotId, const RadioResponseInfo &info) = 0;

    /**
     * @brief CallStateChangeReport receive call state changed notification with slotId by ims.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t CallStateChangeReport(int32_t slotId) = 0;

    /**
     * @brief GetImsCallsDataResponse the result of get ims calls data by ims.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param info Indicates get action was success or failure.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t GetImsCallsDataResponse(int32_t slotId, const RadioResponseInfo &info) = 0;

    /**
     * @brief GetImsCallsDataResponse the result of get ims calls data by ims.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param callList Indicates the result of get ims current call list.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t GetImsCallsDataResponse(int32_t slotId, const ImsCurrentCallList &callList) = 0;

    /**
     * @brief SetImsSwitchResponse the result of set ims switch by ims.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param info Indicates set action was success or failure.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t SetImsSwitchResponse(int32_t slotId, const RadioResponseInfo &info) = 0;

    /**
     * @brief GetImsSwitchResponse the result of get ims switch by ims.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param info Indicates get action was success or failure.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t GetImsSwitchResponse(int32_t slotId, const RadioResponseInfo &info) = 0;

    /**
     * @brief GetImsSwitchResponse the result of get ims switch by ims.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param active 1: ims is enabled, 0: ims is disabled.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t GetImsSwitchResponse(int32_t slotId, int32_t active) = 0;

    /**
     * @brief CallRingBackReport receive call ring back notification by ims.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param info Indicates the ring back voice status the status was,
     * ranging from {@code NETWORK_ALERTING} to {@code LOCAL_ALERTING} which define at {@code RBTPlayInfo}.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t CallRingBackReport(int32_t slotId, const RingbackVoice &info) = 0;

    /**
     * @brief SetMuteResponse the result of set mute by ims.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param response Indicates the result of set action.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t SetMuteResponse(int32_t slotId, const MuteControlResponse &response) = 0;

    /**
     * @brief LastCallFailReasonResponse the result of last call fail reason by ims.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param details Indicates the call fail reason and the remaind message,
     * reason ranging from {@code UNASSIGNED_NUMBER} to {@code UNKNOWN} which define at {@code DisconnectedReason}
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t LastCallFailReasonResponse(int32_t slotId, const DisconnectedDetails &details) = 0;

    /**
     * @brief SetClipResponse the result of set the clip by IMS.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param resultInfo Indicates the result info of ss command.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t SetClipResponse(int32_t slotId, const SsBaseResult &resultInfo) = 0;

    /**
     * @brief GetClipResponse the result of get the clip by IMS.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param result Indicates the result of get action.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t GetClipResponse(int32_t slotId, const GetClipResult &result) = 0;

    /**
     * @brief GetClirResponse the result of get the clir by IMS.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param result Indicates the result of get action.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t GetClirResponse(int32_t slotId, const GetClirResult &result) = 0;

    /**
     * @brief SetClirResponse the result of set the clir by IMS.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param resultInfo Indicates the result info of ss command.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t SetClirResponse(int32_t slotId, const SsBaseResult &resultInfo) = 0;

    /**
     * @brief GetCallTransferResponse the result of get the call transfer by IMS.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param cFQueryList Indicates the call forwarding list of get action.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t GetCallTransferResponse(int32_t slotId, const CallForwardQueryInfoList &cFQueryList) = 0;

    /**
     * @brief
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param resultInfo Indicates the result info of ss command.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t SetCallTransferResponse(int32_t slotId, const SsBaseResult &resultInfo) = 0;

    /**
     * @brief GetCallRestrictionResponse the result of get the call restriction by IMS.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param result Indicates the result of get action.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t GetCallRestrictionResponse(int32_t slotId, const CallRestrictionResult &result) = 0;

    /**
     * @brief SetCallRestrictionResponse the result of set the call restriction by IMS.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param resultInfo Indicates the result info of ss command.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t SetCallRestrictionResponse(int32_t slotId, const SsBaseResult &resultInfo) = 0;

    /**
     * @brief GetCallWaitingResponse the result of get the call waiting by IMS.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param result Indicates the result of get action.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t GetCallWaitingResponse(int32_t slotId, const CallWaitResult &result) = 0;

    /**
     * @brief SetCallWaitingResponse the result of set the call waiting by IMS.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param resultInfo Indicates the result info of ss command.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t SetCallWaitingResponse(int32_t slotId, const SsBaseResult &resultInfo) = 0;

    /**
     * @brief SetColrResponse the result of set the colr by IMS.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param resultInfo Indicates the result info of ss command.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t SetColrResponse(int32_t slotId, const SsBaseResult &resultInfo) = 0;

    /**
     * @brief GetColrResponse the result of get the colr by IMS.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param result Indicates the result of get action.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t GetColrResponse(int32_t slotId, const GetColrResult &result) = 0;

    /**
     * @brief SetColpResponse the result of set the colp by IMS.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param resultInfo Indicates the result info of ss command.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t SetColpResponse(int32_t slotId, const SsBaseResult &resultInfo) = 0;

    /**
     * @brief GetColpResponse the result of get the colp by IMS.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param result Indicates the result of get action.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t GetColpResponse(int32_t slotId, const GetColpResult &result) = 0;

    /**
     * @brief CombineConferenceResponse the result of get combine conference by ims.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param info Indicates get action was success or failure.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t CombineConferenceResponse(int32_t slotId, const RadioResponseInfo &info) = 0;

    /**
     * @brief InviteToConferenceResponse the result of get invite to conference by ims.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param info Indicates get action was success or failure.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t InviteToConferenceResponse(int32_t slotId, const RadioResponseInfo &info) = 0;

    /**
     * @brief ReceiveUpdateCallMediaModeRequest the result of receive update call media mode by ims.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param callModeResponse Indicates info of received.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t ReceiveUpdateCallMediaModeRequest(
        int32_t slotId, const ImsCallModeReceiveInfo &callModeRequest) = 0;

    /**
     * @brief ReceiveUpdateCallMediaModeResponse the result of send update call media mode by ims.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param callModeResponse Indicates info of received.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t ReceiveUpdateCallMediaModeResponse(
        int32_t slotId, const ImsCallModeReceiveInfo &callModeResponse) = 0;

    /**
     * CallSessionEventChanged report call session event change to up layer
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param callSessionEventInfo Indicates info of call session info.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t CallSessionEventChanged(int32_t slotId, const ImsCallSessionEventInfo &callSessionEventInfo) = 0;

    /**
     * PeerDimensionsChanged report ims video call peer dimensions changed to up layer
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param callPeerDimensionsInfo include video window width and height info.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t PeerDimensionsChanged(int32_t slotId, const ImsCallPeerDimensionsInfo &callPeerDimensionsInfo) = 0;

    /**
     * CallDataUsageChanged report ims call data usage changed to up layer
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param callDataUsageInfo Indicates ims call data usage info.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t CallDataUsageChanged(int32_t slotId, const ImsCallDataUsageInfo &callDataUsageInfo) = 0;

    /**
     * CameraCapabilitiesChanged report camera capabilities changed to up layer
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param cameraCapabilitiesInfo Indicates ims video call camera capabilities info
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t CameraCapabilitiesChanged(int32_t slotId, const CameraCapabilitiesInfo &cameraCapabilitiesInfo) = 0;

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Telephony.ImsCallCallback");
};
}  // namespace Telephony
}  // namespace OHOS

#endif  // TELEPHONY_IMS_CALL_CALLBACK_INTERFACE_H

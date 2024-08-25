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

#include "ims_call_callback_proxy.h"

#include "message_option.h"
#include "message_parcel.h"

namespace OHOS {
namespace Telephony {
ImsCallCallbackProxy::ImsCallCallbackProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ImsCallCallbackInterface>(impl) {}

int32_t ImsCallCallbackProxy::DialResponse(int32_t slotId, const RadioResponseInfo &info)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in, info);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_DIAL), in);
}

int32_t ImsCallCallbackProxy::HangUpResponse(int32_t slotId, const RadioResponseInfo &info)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in, info);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_HANG_UP), in);
}

int32_t ImsCallCallbackProxy::RejectWithReasonResponse(int32_t slotId, const RadioResponseInfo &info)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in, info);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_REJECT), in);
}

int32_t ImsCallCallbackProxy::AnswerResponse(int32_t slotId, const RadioResponseInfo &info)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in, info);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_ANSWER), in);
}

int32_t ImsCallCallbackProxy::HoldCallResponse(int32_t slotId, const RadioResponseInfo &info)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in, info);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_HOLD), in);
}

int32_t ImsCallCallbackProxy::UnHoldCallResponse(int32_t slotId, const RadioResponseInfo &info)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in, info);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_UN_HOLD), in);
}

int32_t ImsCallCallbackProxy::SwitchCallResponse(int32_t slotId, const RadioResponseInfo &info)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in, info);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_SWITCH), in);
}

int32_t ImsCallCallbackProxy::StartDtmfResponse(int32_t slotId, const RadioResponseInfo &info)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in, info);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_START_DTMF), in);
}

int32_t ImsCallCallbackProxy::SendDtmfResponse(int32_t slotId, const RadioResponseInfo &info, int32_t callIndex)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in, info);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(callIndex)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_SEND_DTMF), in);
}

int32_t ImsCallCallbackProxy::StopDtmfResponse(int32_t slotId, const RadioResponseInfo &info)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in, info);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_STOP_DTMF), in);
}

int32_t ImsCallCallbackProxy::CallStateChangeReport(int32_t slotId)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_CALL_STATE_CHANGE), in);
}

int32_t ImsCallCallbackProxy::GetImsCallsDataResponse(int32_t slotId, const RadioResponseInfo &info)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in, info);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_GET_CALLS_DATA), in);
}

int32_t ImsCallCallbackProxy::GetImsCallsDataResponse(int32_t slotId, const ImsCurrentCallList &callList)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(callList.callSize) || !in.WriteInt32(callList.flag)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(static_cast<int32_t>(callList.calls.size()))) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    for (auto call : callList.calls) {
        if (!in.WriteInt32(call.index) || !in.WriteInt32(call.dir) || !in.WriteInt32(call.state) ||
            !in.WriteInt32(call.mode) || !in.WriteInt32(call.mpty) || !in.WriteInt32(call.voiceDomain) ||
            !in.WriteInt32(call.callType) || !in.WriteString(call.number) || !in.WriteInt32(call.type) ||
            !in.WriteString(call.alpha) || !in.WriteInt32(call.toa) || !in.WriteInt32(call.toneType) ||
            !in.WriteInt32(call.callInitialType)) {
            return TELEPHONY_ERR_WRITE_DATA_FAIL;
        }
    }
    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_GET_CALLS_DATA), in);
}

int32_t ImsCallCallbackProxy::SetImsSwitchResponse(int32_t slotId, const RadioResponseInfo &info)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in, info);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }

    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_SET_SWITCH_STATUS), in);
}

int32_t ImsCallCallbackProxy::GetImsSwitchResponse(int32_t slotId, const RadioResponseInfo &info)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in, info);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }

    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_GET_SWITCH_STATUS), in);
}

int32_t ImsCallCallbackProxy::GetImsSwitchResponse(int32_t slotId, int32_t active)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(active)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }

    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_GET_SWITCH_STATUS), in);
}

int32_t ImsCallCallbackProxy::CallRingBackReport(int32_t slotId, const RingbackVoice &info)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteRawData((const void *)&info, sizeof(RingbackVoice))) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }

    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_CALL_CRING), in);
}

int32_t ImsCallCallbackProxy::SetMuteResponse(int32_t slotId, const MuteControlResponse &response)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteRawData((const void *)&response, sizeof(MuteControlResponse))) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }

    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_SET_MUTE), in);
}

int32_t ImsCallCallbackProxy::LastCallFailReasonResponse(int32_t slotId, const DisconnectedDetails &details)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(static_cast<int32_t>(details.reason))) {
        TELEPHONY_LOGE("[slot%{public}d] Write reason fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteString(details.message)) {
        TELEPHONY_LOGE("[slot%{public}d] Write message fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_LAST_CALL_FAIL_REASON), in);
}

int32_t ImsCallCallbackProxy::SetClipResponse(int32_t slotId, const SsBaseResult &resultInfo)
{
    MessageParcel in;
    int32_t ret = WriteSsBaseResultCommonInfo(slotId, __FUNCTION__, in, resultInfo);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }

    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_SET_CALL_CLIP), in);
}

int32_t ImsCallCallbackProxy::GetClipResponse(int32_t slotId, const GetClipResult &result)
{
    MessageParcel in;
    int32_t ret = WriteSsBaseResultCommonInfo(slotId, __FUNCTION__, in, result.result);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(result.action)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(result.clipStat)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }

    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_GET_CALL_CLIP), in);
}

int32_t ImsCallCallbackProxy::GetClirResponse(int32_t slotId, const GetClirResult &result)
{
    MessageParcel in;
    int32_t ret = WriteSsBaseResultCommonInfo(slotId, __FUNCTION__, in, result.result);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(result.action)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(result.clirStat)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }

    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_GET_CALL_CLIR), in);
}

int32_t ImsCallCallbackProxy::SetClirResponse(int32_t slotId, const SsBaseResult &resultInfo)
{
    MessageParcel in;
    int32_t ret = WriteSsBaseResultCommonInfo(slotId, __FUNCTION__, in, resultInfo);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }

    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_SET_CALL_CLIR), in);
}

int32_t ImsCallCallbackProxy::GetCallTransferResponse(int32_t slotId, const CallForwardQueryInfoList &cFQueryList)
{
    MessageParcel in;
    int32_t ret = WriteSsBaseResultCommonInfo(slotId, __FUNCTION__, in, cFQueryList.result);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(cFQueryList.callSize) || !in.WriteInt32(cFQueryList.flag)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(static_cast<int32_t>(cFQueryList.calls.size()))) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    for (auto call : cFQueryList.calls) {
        if (!in.WriteInt32(call.serial) || !in.WriteInt32(call.result) || !in.WriteInt32(call.status) ||
            !in.WriteInt32(call.classx) || !in.WriteString(call.number) || !in.WriteInt32(call.type) ||
            !in.WriteInt32(call.reason) || !in.WriteInt32(call.time) || !in.WriteInt32(call.startHour) ||
            !in.WriteInt32(call.startMinute) || !in.WriteInt32(call.endHour) || !in.WriteInt32(call.endMinute)) {
            return TELEPHONY_ERR_WRITE_DATA_FAIL;
        }
    }

    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_GET_CALL_FORWARD), in);
}

int32_t ImsCallCallbackProxy::SetCallTransferResponse(int32_t slotId, const SsBaseResult &resultInfo)
{
    MessageParcel in;
    int32_t ret = WriteSsBaseResultCommonInfo(slotId, __FUNCTION__, in, resultInfo);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }

    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_SET_CALL_FORWARD), in);
}

int32_t ImsCallCallbackProxy::GetCallRestrictionResponse(int32_t slotId, const CallRestrictionResult &result)
{
    MessageParcel in;
    int32_t ret = WriteSsBaseResultCommonInfo(slotId, __FUNCTION__, in, result.result);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(result.status)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(result.classCw)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }

    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_GET_CALL_RESTRICTION), in);
}

int32_t ImsCallCallbackProxy::SetCallRestrictionResponse(int32_t slotId, const SsBaseResult &resultInfo)
{
    MessageParcel in;
    int32_t ret = WriteSsBaseResultCommonInfo(slotId, __FUNCTION__, in, resultInfo);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }

    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_SET_CALL_RESTRICTION), in);
}

int32_t ImsCallCallbackProxy::GetCallWaitingResponse(int32_t slotId, const CallWaitResult &result)
{
    MessageParcel in;
    int32_t ret = WriteSsBaseResultCommonInfo(slotId, __FUNCTION__, in, result.result);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(result.status)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(result.classCw)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }

    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_GET_CALL_WAIT), in);
}

int32_t ImsCallCallbackProxy::SetCallWaitingResponse(int32_t slotId, const SsBaseResult &resultInfo)
{
    MessageParcel in;
    int32_t ret = WriteSsBaseResultCommonInfo(slotId, __FUNCTION__, in, resultInfo);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }

    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_SET_CALL_WAIT), in);
}

int32_t ImsCallCallbackProxy::SetColrResponse(int32_t slotId, const SsBaseResult &resultInfo)
{
    MessageParcel in;
    int32_t ret = WriteSsBaseResultCommonInfo(slotId, __FUNCTION__, in, resultInfo);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }

    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_SET_CALL_COLR), in);
}

int32_t ImsCallCallbackProxy::GetColrResponse(int32_t slotId, const GetColrResult &result)
{
    MessageParcel in;
    int32_t ret = WriteSsBaseResultCommonInfo(slotId, __FUNCTION__, in, result.result);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(result.action)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(result.colrStat)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }

    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_GET_CALL_COLR), in);
}

int32_t ImsCallCallbackProxy::SetColpResponse(int32_t slotId, const SsBaseResult &resultInfo)
{
    MessageParcel in;
    int32_t ret = WriteSsBaseResultCommonInfo(slotId, __FUNCTION__, in, resultInfo);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }

    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_SET_CALL_COLP), in);
}

int32_t ImsCallCallbackProxy::GetColpResponse(int32_t slotId, const GetColpResult &result)
{
    MessageParcel in;
    int32_t ret = WriteSsBaseResultCommonInfo(slotId, __FUNCTION__, in, result.result);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(result.action)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(result.colpStat)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }

    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_GET_CALL_COLP), in);
}

int32_t ImsCallCallbackProxy::CombineConferenceResponse(int32_t slotId, const RadioResponseInfo &info)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in, info);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_COMBINE_CONFERENCE), in);
}

int32_t ImsCallCallbackProxy::InviteToConferenceResponse(int32_t slotId, const RadioResponseInfo &info)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in, info);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendResponseInfo(static_cast<int32_t>(ImsCallCallbackInterfaceCode::IMS_INVITE_TO_CONFERENCE), in);
}

int32_t ImsCallCallbackProxy::ReceiveUpdateCallMediaModeRequest(
    int32_t slotId, const ImsCallModeReceiveInfo &callModeRequest)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteRawData((const void *)&callModeRequest, sizeof(ImsCallModeReceiveInfo))) {
        TELEPHONY_LOGE("[slot%{public}d]Write callModeRequest fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendResponseInfo(static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_RECV_CALL_MEDIA_MODE_REQUEST), in);
}

int32_t ImsCallCallbackProxy::ReceiveUpdateCallMediaModeResponse(
    int32_t slotId, const ImsCallModeReceiveInfo &callModeResponse)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteRawData((const void *)&callModeResponse, sizeof(ImsCallModeReceiveInfo))) {
        TELEPHONY_LOGE("[slot%{public}d]Write callModeResponse fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendResponseInfo(
        static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_RECV_CALL_MEDIA_MODE_RESPONSE), in);
}

int32_t ImsCallCallbackProxy::CallSessionEventChanged(
    int32_t slotId, const ImsCallSessionEventInfo &callSessionEventInfo)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteRawData((const void *)&callSessionEventInfo, sizeof(ImsCallSessionEventInfo))) {
        TELEPHONY_LOGE("[slot%{public}d]Write callSessionEventInfo fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendResponseInfo(static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_CALL_SESSION_EVENT_CHANGED), in);
}

int32_t ImsCallCallbackProxy::PeerDimensionsChanged(
    int32_t slotId, const ImsCallPeerDimensionsInfo &callPeerDimensionsInfo)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteRawData((const void *)&callPeerDimensionsInfo, sizeof(ImsCallPeerDimensionsInfo))) {
        TELEPHONY_LOGE("[slot%{public}d]Write callPeerDimensionsInfo fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendResponseInfo(static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_CALL_PEER_DIMENSIONS_CHANGED), in);
}

int32_t ImsCallCallbackProxy::CallDataUsageChanged(int32_t slotId, const ImsCallDataUsageInfo &callDataUsageInfo)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteRawData((const void *)&callDataUsageInfo, sizeof(ImsCallDataUsageInfo))) {
        TELEPHONY_LOGE("[slot%{public}d]Write callDataUsageInfo fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendResponseInfo(static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_CALL_DATA_USAGE_CHANGED), in);
}

int32_t ImsCallCallbackProxy::CameraCapabilitiesChanged(
    int32_t slotId, const CameraCapabilitiesInfo &cameraCapabilitiesInfo)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteRawData((const void *)&cameraCapabilitiesInfo, sizeof(CameraCapabilitiesInfo))) {
        TELEPHONY_LOGE("[slot%{public}d]Write cameraCapabilitiesInfo fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendResponseInfo(
        static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_CALL_CAMERA_CAPABILITIES_CHANGED), in);
}

int32_t ImsCallCallbackProxy::SendResponseInfo(int32_t eventId, MessageParcel &in)
{
    TELEPHONY_LOGI("SendResponseInfo eventId = %{public}d", eventId);
    MessageOption option;
    MessageParcel out;
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t error = remote->SendRequest(eventId, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
}

int32_t ImsCallCallbackProxy::WriteCommonInfo(int32_t slotId, const std::string &funcName, MessageParcel &in)
{
    if (!in.WriteInterfaceToken(ImsCallCallbackProxy::GetDescriptor())) {
        TELEPHONY_LOGE("[slot%{public}d]%{public}s:Write descriptor token fail!", slotId, funcName.c_str());
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        TELEPHONY_LOGE("[slot%{public}d]%{public}s:Write slotId fail!", slotId, funcName.c_str());
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackProxy::WriteCommonInfo(
    int32_t slotId, const std::string &funcName, MessageParcel &in, const RadioResponseInfo &info)
{
    int32_t ret = WriteCommonInfo(slotId, funcName, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteRawData((const void *)&info, sizeof(RadioResponseInfo))) {
        TELEPHONY_LOGE("[slot%{public}d]%{public}s:Write info fail!", slotId, funcName.c_str());
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackProxy::WriteSsBaseResultCommonInfo(
    int32_t slotId, const std::string &funcName, MessageParcel &in, const SsBaseResult &ssResult)
{
    int32_t ret = WriteCommonInfo(slotId, funcName, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(ssResult.index)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(ssResult.result)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(ssResult.reason)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteString(ssResult.message)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return TELEPHONY_SUCCESS;
}
} // namespace Telephony
} // namespace OHOS

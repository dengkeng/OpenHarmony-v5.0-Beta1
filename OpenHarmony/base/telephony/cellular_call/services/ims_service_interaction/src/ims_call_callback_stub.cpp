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

#include "ims_call_callback_stub.h"

#include "cellular_call_register.h"
#include "cellular_call_service.h"
#include "ims_call_client.h"
#include "ims_error.h"
#include "radio_event.h"
#include "supplement_request_cs.h"
#include "tel_event_handler.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
const int32_t MAX_SIZE = 10;
const int32_t IMS_CALL = 1;

ImsCallCallbackStub::ImsCallCallbackStub()
{
    TELEPHONY_LOGI("ImsCallCallbackStub");
    InitFuncMap();
}

void ImsCallCallbackStub::InitFuncMap()
{
    InitCallBasicFuncMap();
    InitConfigFuncMap();
    InitSupplementFuncMap();
}

void ImsCallCallbackStub::InitCallBasicFuncMap()
{
    /****************** call basic ******************/
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_DIAL)] =
        &ImsCallCallbackStub::OnDialResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_HANG_UP)] =
        &ImsCallCallbackStub::OnHangUpResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_REJECT)] =
        &ImsCallCallbackStub::OnRejectResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_ANSWER)] =
        &ImsCallCallbackStub::OnAnswerResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_HOLD)] =
        &ImsCallCallbackStub::OnHoldCallResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_UN_HOLD)] =
        &ImsCallCallbackStub::OnUnHoldCallResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_SWITCH)] =
        &ImsCallCallbackStub::OnSwitchCallResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_CALL_STATE_CHANGE)] =
        &ImsCallCallbackStub::OnCallStateChangeReportInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_LAST_CALL_FAIL_REASON)] =
        &ImsCallCallbackStub::OnLastCallFailReasonResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_CALL_CRING)] =
        &ImsCallCallbackStub::OnCallRingBackReportInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_COMBINE_CONFERENCE)] =
        &ImsCallCallbackStub::OnCombineConferenceResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_INVITE_TO_CONFERENCE)] =
        &ImsCallCallbackStub::OnInviteToConferenceResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_RECV_CALL_MEDIA_MODE_REQUEST)] =
        &ImsCallCallbackStub::OnReceiveUpdateCallMediaModeRequestInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_RECV_CALL_MEDIA_MODE_RESPONSE)] =
        &ImsCallCallbackStub::OnReceiveUpdateCallMediaModeResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_CALL_SESSION_EVENT_CHANGED)] =
        &ImsCallCallbackStub::OnCallSessionEventChangedInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_CALL_PEER_DIMENSIONS_CHANGED)] =
        &ImsCallCallbackStub::OnPeerDimensionsChangedInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_CALL_DATA_USAGE_CHANGED)] =
        &ImsCallCallbackStub::OnCallDataUsageChangedInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_CALL_CAMERA_CAPABILITIES_CHANGED)] =
        &ImsCallCallbackStub::OnCameraCapabilitiesChangedInner;
}

void ImsCallCallbackStub::InitConfigFuncMap()
{
    /****************** dtmf rtt ******************/
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_START_DTMF)] =
        &ImsCallCallbackStub::OnStartDtmfResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_SEND_DTMF)] =
        &ImsCallCallbackStub::OnSendDtmfResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_STOP_DTMF)] =
        &ImsCallCallbackStub::OnStopDtmfResponseInner;

    /****************** ims config ******************/
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_SET_SWITCH_STATUS)] =
        &ImsCallCallbackStub::OnSetImsSwitchResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_GET_SWITCH_STATUS)] =
        &ImsCallCallbackStub::OnGetImsSwitchResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_GET_CALLS_DATA)] =
        &ImsCallCallbackStub::OnGetImsCallsDataResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_SET_MUTE)] =
        &ImsCallCallbackStub::OnSetMuteResponseInner;
}

void ImsCallCallbackStub::InitSupplementFuncMap()
{
    /****************** supplement ******************/
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_SET_CALL_CLIP)] =
        &ImsCallCallbackStub::OnSetClipResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_GET_CALL_CLIP)] =
        &ImsCallCallbackStub::OnGetClipResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_GET_CALL_CLIR)] =
        &ImsCallCallbackStub::OnGetClirResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_SET_CALL_CLIR)] =
        &ImsCallCallbackStub::OnSetClirResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_GET_CALL_FORWARD)] =
        &ImsCallCallbackStub::OnGetCallTransferResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_SET_CALL_FORWARD)] =
        &ImsCallCallbackStub::OnSetCallTransferResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_GET_CALL_RESTRICTION)] =
        &ImsCallCallbackStub::OnGetCallRestrictionResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_SET_CALL_RESTRICTION)] =
        &ImsCallCallbackStub::OnSetCallRestrictionResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_GET_CALL_WAIT)] =
        &ImsCallCallbackStub::OnGetCallWaitingResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_SET_CALL_WAIT)] =
        &ImsCallCallbackStub::OnSetCallWaitingResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_GET_CALL_COLR)] =
        &ImsCallCallbackStub::OnGetColrResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_SET_CALL_COLR)] =
        &ImsCallCallbackStub::OnSetColrResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_SET_CALL_COLP)] =
        &ImsCallCallbackStub::OnSetColpResponseInner;
    requestFuncMap_[static_cast<uint32_t>(ImsCallCallbackInterfaceCode::IMS_GET_CALL_COLP)] =
        &ImsCallCallbackStub::OnGetColpResponseInner;
}

ImsCallCallbackStub::~ImsCallCallbackStub()
{
    requestFuncMap_.clear();
}

int32_t ImsCallCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    std::u16string myDescriptor = ImsCallCallbackStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (myDescriptor != remoteDescriptor) {
        TELEPHONY_LOGE("descriptor checked fail");
        return TELEPHONY_ERR_DESCRIPTOR_MISMATCH;
    }
    auto itFunc = requestFuncMap_.find(code);
    if (itFunc != requestFuncMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            return (this->*requestFunc)(data, reply);
        }
    }
    TELEPHONY_LOGI("Function not found, need check.");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t ImsCallCallbackStub::OnDialResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    auto info = static_cast<const RadioResponseInfo *>(data.ReadRawData(sizeof(RadioResponseInfo)));
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null.", slotId);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    reply.WriteInt32(DialResponse(slotId, *info));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnHangUpResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    auto info = static_cast<const RadioResponseInfo *>(data.ReadRawData(sizeof(RadioResponseInfo)));
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null.", slotId);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    reply.WriteInt32(HangUpResponse(slotId, *info));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnRejectResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    auto info = static_cast<const RadioResponseInfo *>(data.ReadRawData(sizeof(RadioResponseInfo)));
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null.", slotId);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    reply.WriteInt32(RejectWithReasonResponse(slotId, *info));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnAnswerResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    auto info = static_cast<const RadioResponseInfo *>(data.ReadRawData(sizeof(RadioResponseInfo)));
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null.", slotId);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    reply.WriteInt32(AnswerResponse(slotId, *info));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnHoldCallResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    auto info = static_cast<const RadioResponseInfo *>(data.ReadRawData(sizeof(RadioResponseInfo)));
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null.", slotId);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    reply.WriteInt32(HoldCallResponse(slotId, *info));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnUnHoldCallResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    auto info = static_cast<const RadioResponseInfo *>(data.ReadRawData(sizeof(RadioResponseInfo)));
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null.", slotId);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    reply.WriteInt32(UnHoldCallResponse(slotId, *info));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnSwitchCallResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    auto info = static_cast<const RadioResponseInfo *>(data.ReadRawData(sizeof(RadioResponseInfo)));
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null.", slotId);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    reply.WriteInt32(SwitchCallResponse(slotId, *info));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnStartDtmfResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    auto info = static_cast<const RadioResponseInfo *>(data.ReadRawData(sizeof(RadioResponseInfo)));
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null.", slotId);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    reply.WriteInt32(StartDtmfResponse(slotId, *info));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnSendDtmfResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    int32_t callIndex = data.ReadInt32();
    auto info = static_cast<const RadioResponseInfo *>(data.ReadRawData(sizeof(RadioResponseInfo)));
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null.", slotId);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    reply.WriteInt32(SendDtmfResponse(slotId, *info, callIndex));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnStopDtmfResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    auto info = static_cast<const RadioResponseInfo *>(data.ReadRawData(sizeof(RadioResponseInfo)));
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null.", slotId);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    reply.WriteInt32(StopDtmfResponse(slotId, *info));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnCallStateChangeReportInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    reply.WriteInt32(CallStateChangeReport(slotId));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnSetImsSwitchResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    auto info = static_cast<const RadioResponseInfo *>(data.ReadRawData(sizeof(RadioResponseInfo)));
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null.", slotId);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    reply.WriteInt32(SetImsSwitchResponse(slotId, *info));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnGetImsSwitchResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    auto info = static_cast<const RadioResponseInfo *>(data.ReadRawData(sizeof(RadioResponseInfo)));
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null.", slotId);
        int32_t active = data.ReadInt32();
        reply.WriteInt32(GetImsSwitchResponse(slotId, active));
        return TELEPHONY_SUCCESS;
    }
    reply.WriteInt32(GetImsSwitchResponse(slotId, *info));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnGetImsCallsDataResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    auto info = static_cast<const RadioResponseInfo *>(data.ReadRawData(sizeof(RadioResponseInfo)));
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null.", slotId);
        auto callList = std::make_shared<ImsCurrentCallList>();
        callList->callSize = data.ReadInt32();
        callList->flag = data.ReadInt32();
        int32_t len = data.ReadInt32();
        if (len < 0 || len > MAX_SIZE) {
            TELEPHONY_LOGE("ImsCallCallbackStub::OnGetImsCallsDataResponseInner callSize error");
            return TELEPHONY_ERR_FAIL;
        }
        for (int32_t i = 0; i < len; i++) {
            ImsCurrentCall call;
            call.index = data.ReadInt32();
            call.dir = data.ReadInt32();
            call.state = data.ReadInt32();
            call.mode = data.ReadInt32();
            call.mpty = data.ReadInt32();
            call.voiceDomain = data.ReadInt32();
            call.callType = static_cast<ImsCallType>(data.ReadInt32());
            data.ReadString(call.number);
            call.type = data.ReadInt32();
            data.ReadString(call.alpha);
            call.toa = data.ReadInt32();
            call.toneType = data.ReadInt32();
            call.callInitialType = data.ReadInt32();
            callList->calls.push_back(call);
        }
        reply.WriteInt32(GetImsCallsDataResponse(slotId, *callList));
        return TELEPHONY_SUCCESS;
    }
    reply.WriteInt32(GetImsCallsDataResponse(slotId, *info));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnSetMuteResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    auto info = static_cast<const MuteControlResponse *>(data.ReadRawData(sizeof(MuteControlResponse)));
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null.", slotId);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    reply.WriteInt32(SetMuteResponse(slotId, *info));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnCallRingBackReportInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    auto info = static_cast<const RingbackVoice *>(data.ReadRawData(sizeof(RingbackVoice)));
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null.", slotId);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    reply.WriteInt32(CallRingBackReport(slotId, *info));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnLastCallFailReasonResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    DisconnectedDetails details;
    details.reason = static_cast<const DisconnectedReason>(data.ReadInt32());
    details.message = data.ReadString();
    reply.WriteInt32(LastCallFailReasonResponse(slotId, details));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnSetClipResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    SsBaseResult resultInfo;
    resultInfo.index = data.ReadInt32();
    resultInfo.result = data.ReadInt32();
    resultInfo.reason = data.ReadInt32();
    resultInfo.message = data.ReadString();
    if (resultInfo.index == INVALID_INDEX) {
        reply.WriteInt32(TELEPHONY_SUCCESS);
    } else {
        reply.WriteInt32(SetClipResponse(slotId, resultInfo));
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnGetClipResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    GetClipResult result;
    result.result.index = data.ReadInt32();
    result.result.result = data.ReadInt32();
    result.result.reason = data.ReadInt32();
    result.result.message = data.ReadString();
    result.action = data.ReadInt32();
    result.clipStat = data.ReadInt32();
    if (result.result.index == INVALID_INDEX) {
        reply.WriteInt32(TELEPHONY_SUCCESS);
    } else {
        reply.WriteInt32(GetClipResponse(slotId, result));
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnGetClirResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    GetClirResult result;
    result.result.index = data.ReadInt32();
    result.result.result = data.ReadInt32();
    result.result.reason = data.ReadInt32();
    result.result.message = data.ReadString();
    result.action = data.ReadInt32();
    result.clirStat = data.ReadInt32();
    if (result.result.index == INVALID_INDEX) {
        reply.WriteInt32(TELEPHONY_SUCCESS);
    } else {
        reply.WriteInt32(GetClirResponse(slotId, result));
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnSetClirResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    SsBaseResult resultInfo;
    resultInfo.index = data.ReadInt32();
    resultInfo.result = data.ReadInt32();
    resultInfo.reason = data.ReadInt32();
    resultInfo.message = data.ReadString();
    if (resultInfo.index == INVALID_INDEX) {
        reply.WriteInt32(TELEPHONY_SUCCESS);
    } else {
        reply.WriteInt32(SetClirResponse(slotId, resultInfo));
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnGetCallTransferResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    auto cFQueryList = std::make_shared<CallForwardQueryInfoList>();
    cFQueryList->result.index = data.ReadInt32();
    cFQueryList->result.result = data.ReadInt32();
    cFQueryList->result.reason = data.ReadInt32();
    data.ReadString(cFQueryList->result.message);
    cFQueryList->callSize = data.ReadInt32();
    cFQueryList->flag = data.ReadInt32();
    int32_t len = data.ReadInt32();
    if (len < 0 || len > MAX_SIZE) {
        TELEPHONY_LOGE("ImsCallCallbackStub::OnGetCallTransferResponseInner callSize error");
        return TELEPHONY_ERR_FAIL;
    }
    for (int32_t i = 0; i < len; i++) {
        CallForwardQueryResult call;
        call.serial = data.ReadInt32();
        call.result = data.ReadInt32();
        call.status = data.ReadInt32();
        call.classx = data.ReadInt32();
        data.ReadString(call.number);
        call.type = data.ReadInt32();
        call.reason = data.ReadInt32();
        call.time = data.ReadInt32();
        call.startHour = data.ReadInt32();
        call.startMinute = data.ReadInt32();
        call.endHour = data.ReadInt32();
        call.endMinute = data.ReadInt32();
        cFQueryList->calls.push_back(call);
    }
    if (cFQueryList->result.index == INVALID_INDEX) {
        reply.WriteInt32(TELEPHONY_SUCCESS);
    } else {
        reply.WriteInt32(GetCallTransferResponse(slotId, *cFQueryList));
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnSetCallTransferResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    SsBaseResult resultInfo;
    resultInfo.index = data.ReadInt32();
    resultInfo.result = data.ReadInt32();
    resultInfo.reason = data.ReadInt32();
    resultInfo.message = data.ReadString();
    if (resultInfo.index == INVALID_INDEX) {
        reply.WriteInt32(TELEPHONY_SUCCESS);
    } else {
        reply.WriteInt32(SetCallTransferResponse(slotId, resultInfo));
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnGetCallRestrictionResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    CallRestrictionResult result;
    result.result.index = data.ReadInt32();
    result.result.result = data.ReadInt32();
    result.result.reason = data.ReadInt32();
    result.result.message = data.ReadString();
    result.status = data.ReadInt32();
    result.classCw = data.ReadInt32();
    if (result.result.index == INVALID_INDEX) {
        reply.WriteInt32(TELEPHONY_SUCCESS);
    } else {
        reply.WriteInt32(GetCallRestrictionResponse(slotId, result));
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnSetCallRestrictionResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    SsBaseResult resultInfo;
    resultInfo.index = data.ReadInt32();
    resultInfo.result = data.ReadInt32();
    resultInfo.reason = data.ReadInt32();
    resultInfo.message = data.ReadString();
    if (resultInfo.index == INVALID_INDEX) {
        reply.WriteInt32(TELEPHONY_SUCCESS);
    } else {
        reply.WriteInt32(SetCallRestrictionResponse(slotId, resultInfo));
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnGetCallWaitingResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    CallWaitResult result;
    result.result.index = data.ReadInt32();
    result.result.result = data.ReadInt32();
    result.result.reason = data.ReadInt32();
    result.result.message = data.ReadString();
    result.status = data.ReadInt32();
    result.classCw = data.ReadInt32();
    if (result.result.index == INVALID_INDEX) {
        reply.WriteInt32(TELEPHONY_SUCCESS);
    } else {
        reply.WriteInt32(GetCallWaitingResponse(slotId, result));
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnSetCallWaitingResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    SsBaseResult resultInfo;
    resultInfo.index = data.ReadInt32();
    resultInfo.result = data.ReadInt32();
    resultInfo.reason = data.ReadInt32();
    resultInfo.message = data.ReadString();
    if (resultInfo.index == INVALID_INDEX) {
        reply.WriteInt32(TELEPHONY_SUCCESS);
    } else {
        reply.WriteInt32(SetCallWaitingResponse(slotId, resultInfo));
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnSetColrResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    SsBaseResult resultInfo;
    resultInfo.index = data.ReadInt32();
    resultInfo.result = data.ReadInt32();
    resultInfo.reason = data.ReadInt32();
    resultInfo.message = data.ReadString();
    if (resultInfo.index == INVALID_INDEX) {
        reply.WriteInt32(TELEPHONY_SUCCESS);
    } else {
        reply.WriteInt32(SetColrResponse(slotId, resultInfo));
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnGetColrResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    GetColrResult result;
    result.result.index = data.ReadInt32();
    result.result.result = data.ReadInt32();
    result.result.reason = data.ReadInt32();
    result.result.message = data.ReadString();
    result.action = data.ReadInt32();
    result.colrStat = data.ReadInt32();
    if (result.result.index == INVALID_INDEX) {
        reply.WriteInt32(TELEPHONY_SUCCESS);
    } else {
        reply.WriteInt32(GetColrResponse(slotId, result));
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnSetColpResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    SsBaseResult resultInfo;
    resultInfo.index = data.ReadInt32();
    resultInfo.result = data.ReadInt32();
    resultInfo.reason = data.ReadInt32();
    resultInfo.message = data.ReadString();
    if (resultInfo.index == INVALID_INDEX) {
        reply.WriteInt32(TELEPHONY_SUCCESS);
    } else {
        reply.WriteInt32(SetColpResponse(slotId, resultInfo));
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnGetColpResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    GetColpResult result;
    result.result.index = data.ReadInt32();
    result.result.result = data.ReadInt32();
    result.result.reason = data.ReadInt32();
    result.result.message = data.ReadString();
    result.action = data.ReadInt32();
    result.colpStat = data.ReadInt32();
    if (result.result.index == INVALID_INDEX) {
        reply.WriteInt32(TELEPHONY_SUCCESS);
    } else {
        reply.WriteInt32(GetColpResponse(slotId, result));
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnCombineConferenceResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    auto info = static_cast<const RadioResponseInfo *>(data.ReadRawData(sizeof(RadioResponseInfo)));
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null.", slotId);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    reply.WriteInt32(CombineConferenceResponse(slotId, *info));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnInviteToConferenceResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    auto info = static_cast<const RadioResponseInfo *>(data.ReadRawData(sizeof(RadioResponseInfo)));
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null.", slotId);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    reply.WriteInt32(InviteToConferenceResponse(slotId, *info));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnReceiveUpdateCallMediaModeRequestInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    auto info = static_cast<const ImsCallModeReceiveInfo *>(data.ReadRawData(sizeof(ImsCallModeReceiveInfo)));
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null.", slotId);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    reply.WriteInt32(ReceiveUpdateCallMediaModeRequest(slotId, *info));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnReceiveUpdateCallMediaModeResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    auto info = static_cast<const ImsCallModeReceiveInfo *>(data.ReadRawData(sizeof(ImsCallModeReceiveInfo)));
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null.", slotId);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    reply.WriteInt32(ReceiveUpdateCallMediaModeResponse(slotId, *info));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnCallSessionEventChangedInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    auto info = static_cast<const ImsCallSessionEventInfo *>(data.ReadRawData(sizeof(ImsCallSessionEventInfo)));
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null.", slotId);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    reply.WriteInt32(CallSessionEventChanged(slotId, *info));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnPeerDimensionsChangedInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    auto info = static_cast<const ImsCallPeerDimensionsInfo *>(data.ReadRawData(sizeof(ImsCallPeerDimensionsInfo)));
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null.", slotId);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    reply.WriteInt32(PeerDimensionsChanged(slotId, *info));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnCallDataUsageChangedInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    auto info = static_cast<const ImsCallDataUsageInfo *>(data.ReadRawData(sizeof(ImsCallDataUsageInfo)));
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null.", slotId);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    reply.WriteInt32(CallDataUsageChanged(slotId, *info));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::OnCameraCapabilitiesChangedInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    auto info = static_cast<const CameraCapabilitiesInfo *>(data.ReadRawData(sizeof(CameraCapabilitiesInfo)));
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null.", slotId);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    reply.WriteInt32(CameraCapabilitiesChanged(slotId, *info));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::DialResponse(int32_t slotId, const RadioResponseInfo &info)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    return SendEvent(slotId, RadioEvent::RADIO_DIAL, info);
}

int32_t ImsCallCallbackStub::HangUpResponse(int32_t slotId, const RadioResponseInfo &info)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    return SendEvent(slotId, RadioEvent::RADIO_HANGUP_CONNECT, info);
}

int32_t ImsCallCallbackStub::RejectWithReasonResponse(int32_t slotId, const RadioResponseInfo &info)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    return SendEvent(slotId, RadioEvent::RADIO_REJECT_CALL, info);
}

int32_t ImsCallCallbackStub::AnswerResponse(int32_t slotId, const RadioResponseInfo &info)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    return SendEvent(slotId, RadioEvent::RADIO_ACCEPT_CALL, info);
}

int32_t ImsCallCallbackStub::HoldCallResponse(int32_t slotId, const RadioResponseInfo &info)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    return SendEvent(slotId, RadioEvent::RADIO_HOLD_CALL, info);
}

int32_t ImsCallCallbackStub::UnHoldCallResponse(int32_t slotId, const RadioResponseInfo &info)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    return SendEvent(slotId, RadioEvent::RADIO_ACTIVE_CALL, info);
}

int32_t ImsCallCallbackStub::SwitchCallResponse(int32_t slotId, const RadioResponseInfo &info)
{
    auto handler = DelayedSingleton<ImsCallClient>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<RadioResponseInfo> responseInfo = std::make_shared<RadioResponseInfo>();
    *responseInfo = info;
    AppExecFwk::InnerEvent::Pointer response =
        AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SWAP_CALL, responseInfo, IMS_CALL);
    bool ret = TelEventHandler::SendTelEvent(handler, response);
    if (!ret) {
        TELEPHONY_LOGE("[slot%{public}d] SendEvent failed!", slotId);
        return TELEPHONY_ERR_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::StartDtmfResponse(int32_t slotId, const RadioResponseInfo &info)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    return SendEvent(slotId, RadioEvent::RADIO_START_DTMF, info);
}

int32_t ImsCallCallbackStub::SendDtmfResponse(int32_t slotId, const RadioResponseInfo &info, int32_t callIndex)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    auto handler = DelayedSingleton<ImsCallClient>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<RadioResponseInfo> responseInfo = std::make_shared<RadioResponseInfo>();

    *responseInfo = info;
    responseInfo->flag = callIndex;
    AppExecFwk::InnerEvent::Pointer response =
        AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SEND_DTMF, responseInfo, IMS_CALL);
    bool ret = TelEventHandler::SendTelEvent(handler, response);
    if (!ret) {
        TELEPHONY_LOGE("[slot%{public}d] SendEvent failed!", slotId);
        return TELEPHONY_ERR_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::StopDtmfResponse(int32_t slotId, const RadioResponseInfo &info)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    return SendEvent(slotId, RadioEvent::RADIO_STOP_DTMF, info);
}

int32_t ImsCallCallbackStub::CallStateChangeReport(int32_t slotId)
{
    TELEPHONY_LOGD("[slot%{public}d] entry", slotId);
    auto handler = DelayedSingleton<ImsCallClient>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    bool ret = TelEventHandler::SendTelEvent(handler, RadioEvent::RADIO_IMS_CALL_STATUS_INFO);
    if (!ret) {
        TELEPHONY_LOGE("[slot%{public}d] SendEvent failed!", slotId);
        return TELEPHONY_ERR_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::GetImsCallsDataResponse(int32_t slotId, const RadioResponseInfo &info)
{
    TELEPHONY_LOGD("[slot%{public}d] entry", slotId);
    return SendEvent(slotId, RadioEvent::RADIO_IMS_GET_CALL_DATA, info);
}

int32_t ImsCallCallbackStub::GetImsCallsDataResponse(int32_t slotId, const ImsCurrentCallList &callList)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    auto handler = DelayedSingleton<ImsCallClient>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    auto imsCurrentCallList = std::make_shared<ImsCurrentCallList>();
    *imsCurrentCallList = callList;
    bool ret = TelEventHandler::SendTelEvent(handler, RadioEvent::RADIO_IMS_GET_CALL_DATA, imsCurrentCallList);
    if (!ret) {
        TELEPHONY_LOGE("[slot%{public}d] SendEvent failed!", slotId);
        return TELEPHONY_ERR_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::SetImsSwitchResponse(int32_t slotId, const RadioResponseInfo &info)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    return SendEvent(slotId, RadioEvent::RADIO_SET_IMS_SWITCH_STATUS, info);
}

int32_t ImsCallCallbackStub::GetImsSwitchResponse(int32_t slotId, const RadioResponseInfo &info)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    return SendEvent(slotId, RadioEvent::RADIO_GET_IMS_SWITCH_STATUS, info);
}

int32_t ImsCallCallbackStub::GetImsSwitchResponse(int32_t slotId, int32_t active)
{
    TELEPHONY_LOGI("[slot%{public}d] entry active:%{public}d", slotId, active);
    auto handler = DelayedSingleton<ImsCallClient>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr || handler.get() == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TelEventHandler::SendTelEvent(handler, RadioEvent::RADIO_GET_IMS_SWITCH_STATUS, active);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::SetMuteResponse(int32_t slotId, const MuteControlResponse &response)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::CallRingBackReport(int32_t slotId, const RingbackVoice &info)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    auto handler = DelayedSingleton<ImsCallClient>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    auto ringbackVoice = std::make_shared<RingbackVoice>();
    *ringbackVoice = info;
    bool ret = TelEventHandler::SendTelEvent(handler, RadioEvent::RADIO_CALL_RINGBACK_VOICE, ringbackVoice);
    if (!ret) {
        TELEPHONY_LOGE("[slot%{public}d] SendEvent failed!", slotId);
        return TELEPHONY_ERR_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::LastCallFailReasonResponse(int32_t slotId, const DisconnectedDetails &details)
{
    TELEPHONY_LOGI("[slot%{public}d] entry, reason is %{public}d", slotId, details.reason);
    auto handler = DelayedSingleton<ImsCallClient>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<DisconnectedDetails> detailsInfo = std::make_shared<DisconnectedDetails>();
    detailsInfo->reason = details.reason;
    detailsInfo->message = details.message;
    CellularCallConfig config;
    auto vecReasonInfo = config.GetImsCallDisconnectResoninfoMappingConfig(slotId);
    for (auto reasonInfo : vecReasonInfo) {
        char *p = nullptr;
        char *ptr = nullptr;
        ptr = strtok_r((char *)(reasonInfo.c_str()), "|", &p);
        int32_t tmpReason = (int32_t)std::atoi(ptr);
        int flag = false;
        while (tmpReason == static_cast<int32_t>(detailsInfo->reason)) {
            ptr = strtok_r(nullptr, "|", &p);
            if (ptr == nullptr) {
                break;
            }
            if (!flag) {
                detailsInfo->message = ptr;
                flag = true;
            } else {
                detailsInfo->reason = static_cast<DisconnectedReason>(std::atoi(ptr));
            }
        }
        if (flag) {
            break;
        }
    }
    bool ret = TelEventHandler::SendTelEvent(handler, RadioEvent::RADIO_GET_CALL_FAIL_REASON, detailsInfo);
    if (!ret) {
        TELEPHONY_LOGE("[slot%{public}d] SendEvent failed!", slotId);
        return TELEPHONY_ERR_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::SetClipResponse(int32_t slotId, const SsBaseResult &resultInfo)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    return SendEvent(slotId, RadioEvent::RADIO_SET_CALL_CLIP, resultInfo);
}

int32_t ImsCallCallbackStub::GetClipResponse(int32_t slotId, const GetClipResult &result)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    // CS fall back when IMS return failed
    if (result.result.result == IMS_ERROR_UT_CS_FALLBACK) {
        SupplementRequestCs supplementRequest;
        return supplementRequest.GetClipRequest(slotId, result.result.index);
    }
    auto handler = DelayedSingleton<ImsCallClient>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    auto clipResponse = std::make_shared<GetClipResult>();
    clipResponse->action = result.action;
    clipResponse->clipStat = result.clipStat;
    clipResponse->result.index = result.result.index;
    clipResponse->result.result = result.result.result;
    clipResponse->result.reason = result.result.reason;
    clipResponse->result.message = result.result.message;
    AppExecFwk::InnerEvent::Pointer response =
        AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_GET_CALL_CLIP, clipResponse, result.result.index);
    bool ret = TelEventHandler::SendTelEvent(handler, response);
    if (!ret) {
        TELEPHONY_LOGE("[slot%{public}d] SendEvent failed!", slotId);
        return TELEPHONY_ERR_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::GetClirResponse(int32_t slotId, const GetClirResult &result)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    // CS fall back when IMS return failed
    if (result.result.result == IMS_ERROR_UT_CS_FALLBACK) {
        SupplementRequestCs supplementRequest;
        return supplementRequest.GetClirRequest(slotId, result.result.index);
    }
    auto handler = DelayedSingleton<ImsCallClient>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    auto clirResponse = std::make_shared<GetClirResult>();
    clirResponse->action = result.action;
    clirResponse->clirStat = result.clirStat;
    clirResponse->result.index = result.result.index;
    clirResponse->result.result = result.result.result;
    clirResponse->result.reason = result.result.reason;
    clirResponse->result.message = result.result.message;
    AppExecFwk::InnerEvent::Pointer response =
        AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_GET_CALL_CLIR, clirResponse, result.result.index);
    bool ret = TelEventHandler::SendTelEvent(handler, response);
    if (!ret) {
        TELEPHONY_LOGE("[slot%{public}d] SendEvent failed!", slotId);
        return TELEPHONY_ERR_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::SetClirResponse(int32_t slotId, const SsBaseResult &resultInfo)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    // CS fall back when IMS return failed
    if (resultInfo.result == IMS_ERROR_UT_CS_FALLBACK) {
        SupplementRequestCs supplementRequest;
        SsRequestCommand ss;
        int32_t ret = GetSsRequestCommand(slotId, resultInfo.index, ss);
        if (ret != TELEPHONY_SUCCESS) {
            TELEPHONY_LOGI("[slot%{public}d] cs fall back error since haven't found the ss command", slotId);
            return ret;
        }
        return supplementRequest.SetClirRequest(slotId, ss.clirAction, resultInfo.index);
    }
    return SendEvent(slotId, RadioEvent::RADIO_SET_CALL_CLIR, resultInfo);
}

int32_t ImsCallCallbackStub::GetCallTransferResponse(int32_t slotId, const CallForwardQueryInfoList &cFQueryList)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    // CS fall back when IMS return failed
    if (cFQueryList.result.result == IMS_ERROR_UT_CS_FALLBACK) {
        SsRequestCommand ss;
        int32_t ret = GetSsRequestCommand(slotId, cFQueryList.result.index, ss);
        if (ret != TELEPHONY_SUCCESS) {
            TELEPHONY_LOGI("[slot%{public}d] cs fall back error since haven't found the ss command", slotId);
            return ret;
        }
        SupplementRequestCs supplementRequest;
        return supplementRequest.GetCallTransferRequest(slotId, ss.cfReason, cFQueryList.result.index);
    }
    auto handler = DelayedSingleton<ImsCallClient>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    auto callTransferResponse = std::make_shared<CallForwardQueryInfoList>();
    BuildCallForwardInfo(cFQueryList, *callTransferResponse);
    AppExecFwk::InnerEvent::Pointer response =
        AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_GET_CALL_FORWARD, callTransferResponse, cFQueryList.result.index);
    bool ret = TelEventHandler::SendTelEvent(handler, response);
    if (!ret) {
        TELEPHONY_LOGE("[slot%{public}d] SendEvent failed!", slotId);
        return TELEPHONY_ERR_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::SetCallTransferResponse(int32_t slotId, const SsBaseResult &resultInfo)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    // CS fall back when IMS return failed
    if (resultInfo.result == IMS_ERROR_UT_CS_FALLBACK) {
        SsRequestCommand ss;
        int32_t ret = GetSsRequestCommand(slotId, resultInfo.index, ss);
        if (ret != TELEPHONY_SUCCESS) {
            TELEPHONY_LOGI("[slot%{public}d] cs fall back error since haven't found the ss command", slotId);
            return ret;
        }
        SupplementRequestCs supplementRequest;
        CallTransferParam callTransferParam;
        callTransferParam.mode = ss.cfAction;
        callTransferParam.reason = ss.cfReason;
        callTransferParam.number = ss.number;
        callTransferParam.classx = ss.classType;
        return supplementRequest.SetCallTransferRequest(slotId, callTransferParam, resultInfo.index);
    }
    return SendEvent(slotId, RadioEvent::RADIO_SET_CALL_FORWARD, resultInfo);
}

int32_t ImsCallCallbackStub::GetCallRestrictionResponse(int32_t slotId, const CallRestrictionResult &result)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    if (result.result.result == IMS_ERROR_UT_CS_FALLBACK) {
        SsRequestCommand ss;
        int32_t ret = GetSsRequestCommand(slotId, result.result.index, ss);
        if (ret != TELEPHONY_SUCCESS) {
            TELEPHONY_LOGI("[slot%{public}d] cs fall back error since haven't found the ss command", slotId);
            return ret;
        }
        const std::string fac = ss.facility;
        SupplementRequestCs supplementRequest;
        return supplementRequest.GetCallRestrictionRequest(slotId, fac, result.result.index);
    }
    auto handler = DelayedSingleton<ImsCallClient>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    auto callRestrictionResponse = std::make_shared<CallRestrictionResult>();
    callRestrictionResponse->status = result.status;
    callRestrictionResponse->classCw = result.classCw;
    callRestrictionResponse->result.result = result.result.result;
    callRestrictionResponse->result.index = result.result.index;
    callRestrictionResponse->result.reason = result.result.reason;
    callRestrictionResponse->result.message = result.result.message;
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(
        RadioEvent::RADIO_GET_CALL_RESTRICTION, callRestrictionResponse, result.result.index);
    bool ret = TelEventHandler::SendTelEvent(handler, response);
    if (!ret) {
        TELEPHONY_LOGE("[slot%{public}d] SendEvent failed!", slotId);
        return TELEPHONY_ERR_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::SetCallRestrictionResponse(int32_t slotId, const SsBaseResult &resultInfo)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    // CS fall back when IMS return failed
    if (resultInfo.result == IMS_ERROR_UT_CS_FALLBACK) {
        SsRequestCommand ss;
        int32_t ret = GetSsRequestCommand(slotId, resultInfo.index, ss);
        if (ret != TELEPHONY_SUCCESS) {
            TELEPHONY_LOGI("[slot%{public}d] cs fall bacK error since haven't found the ss command", slotId);
            return ret;
        }
        SupplementRequestCs supplementRequest;
        return supplementRequest.SetCallRestrictionRequest(
            slotId, ss.facility, ss.enable, ss.password, resultInfo.index);
    }
    return SendEvent(slotId, RadioEvent::RADIO_SET_CALL_RESTRICTION, resultInfo);
}

int32_t ImsCallCallbackStub::GetCallWaitingResponse(int32_t slotId, const CallWaitResult &result)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    // CS fall back when IMS return failed
    if (result.result.result == IMS_ERROR_UT_CS_FALLBACK) {
        SupplementRequestCs supplementRequest;
        return supplementRequest.GetCallWaitingRequest(slotId, result.result.index);
    }
    auto handler = DelayedSingleton<ImsCallClient>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    auto callWaitResponse = std::make_shared<CallWaitResult>();
    callWaitResponse->status = result.status;
    callWaitResponse->classCw = result.classCw;
    callWaitResponse->result.result = result.result.result;
    callWaitResponse->result.index = result.result.index;
    callWaitResponse->result.reason = result.result.reason;
    callWaitResponse->result.message = result.result.message;
    AppExecFwk::InnerEvent::Pointer response =
        AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_GET_CALL_WAIT, callWaitResponse, result.result.index);
    bool ret = TelEventHandler::SendTelEvent(handler, response);
    if (!ret) {
        TELEPHONY_LOGE("[slot%{public}d] SendEvent failed!", slotId);
        return TELEPHONY_ERR_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::SetCallWaitingResponse(int32_t slotId, const SsBaseResult &resultInfo)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    // CS fall back when IMS return failed
    if (resultInfo.result == IMS_ERROR_UT_CS_FALLBACK) {
        SsRequestCommand ss;
        int32_t ret = GetSsRequestCommand(slotId, resultInfo.index, ss);
        if (ret != TELEPHONY_SUCCESS) {
            TELEPHONY_LOGI("[slot%{public}d] cs fall back error since haven't found the ss command", slotId);
            return ret;
        }
        SupplementRequestCs supplementRequest;
        return supplementRequest.SetCallWaitingRequest(slotId, ss.enable, ss.classType, resultInfo.index);
    }
    return SendEvent(slotId, RadioEvent::RADIO_SET_CALL_WAIT, resultInfo);
}

int32_t ImsCallCallbackStub::SetColrResponse(int32_t slotId, const SsBaseResult &resultInfo)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    return SendEvent(slotId, RadioEvent::RADIO_IMS_SET_COLR, resultInfo);
}

int32_t ImsCallCallbackStub::GetColrResponse(int32_t slotId, const GetColrResult &result)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    auto handler = DelayedSingleton<ImsCallClient>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    auto colrResponse = std::make_shared<GetColrResult>();
    colrResponse->action = result.action;
    colrResponse->colrStat = result.colrStat;
    colrResponse->result.result = result.result.result;
    colrResponse->result.index = result.result.index;
    colrResponse->result.reason = result.result.reason;
    colrResponse->result.message = result.result.message;
    AppExecFwk::InnerEvent::Pointer response =
        AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_IMS_GET_COLR, colrResponse, result.result.index);
    bool ret = TelEventHandler::SendTelEvent(handler, response);
    if (!ret) {
        TELEPHONY_LOGE("[slot%{public}d] SendEvent failed!", slotId);
        return TELEPHONY_ERR_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::SetColpResponse(int32_t slotId, const SsBaseResult &resultInfo)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    return SendEvent(slotId, RadioEvent::RADIO_IMS_SET_COLP, resultInfo);
}

int32_t ImsCallCallbackStub::GetColpResponse(int32_t slotId, const GetColpResult &result)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    auto handler = DelayedSingleton<ImsCallClient>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    auto colpResponse = std::make_shared<GetColpResult>();
    colpResponse->action = result.action;
    colpResponse->colpStat = result.colpStat;
    colpResponse->result.result = result.result.result;
    colpResponse->result.index = result.result.index;
    colpResponse->result.reason = result.result.reason;
    colpResponse->result.message = result.result.message;
    AppExecFwk::InnerEvent::Pointer response =
        AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_IMS_GET_COLP, colpResponse, result.result.index);
    bool ret = TelEventHandler::SendTelEvent(handler, response);
    if (!ret) {
        TELEPHONY_LOGE("[slot%{public}d] SendEvent failed!", slotId);
        return TELEPHONY_ERR_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::CombineConferenceResponse(int32_t slotId, const RadioResponseInfo &info)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    return SendEvent(slotId, RadioEvent::RADIO_COMBINE_CALL, info);
}

int32_t ImsCallCallbackStub::InviteToConferenceResponse(int32_t slotId, const RadioResponseInfo &info)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    return SendEvent(slotId, RadioEvent::RADIO_JOIN_CALL, info);
}

int32_t ImsCallCallbackStub::ReceiveUpdateCallMediaModeRequest(
    int32_t slotId, const ImsCallModeReceiveInfo &callModeRequest)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    return SendEvent(slotId, RadioEvent::RADIO_RECV_CALL_MEDIA_MODE_REQUEST, callModeRequest);
}

int32_t ImsCallCallbackStub::ReceiveUpdateCallMediaModeResponse(
    int32_t slotId, const ImsCallModeReceiveInfo &callModeResponse)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    return SendEvent(slotId, RadioEvent::RADIO_RECV_CALL_MEDIA_MODE_RESPONSE, callModeResponse);
}

int32_t ImsCallCallbackStub::CallSessionEventChanged(
    int32_t slotId, const ImsCallSessionEventInfo &callSessionEventInfo)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    auto handler = DelayedSingleton<ImsCallClient>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<ImsCallSessionEventInfo> responseInfo = std::make_shared<ImsCallSessionEventInfo>();
    *responseInfo = callSessionEventInfo;
    bool ret = TelEventHandler::SendTelEvent(handler, RadioEvent::RADIO_CALL_SESSION_EVENT_CHANGED, responseInfo);
    if (!ret) {
        TELEPHONY_LOGE("[slot%{public}d] SendEvent failed!", slotId);
        return TELEPHONY_ERR_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::PeerDimensionsChanged(
    int32_t slotId, const ImsCallPeerDimensionsInfo &callPeerDimensionsInfo)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    auto handler = DelayedSingleton<ImsCallClient>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<ImsCallPeerDimensionsInfo> responseInfo = std::make_shared<ImsCallPeerDimensionsInfo>();
    *responseInfo = callPeerDimensionsInfo;
    bool ret = TelEventHandler::SendTelEvent(handler, RadioEvent::RADIO_CALL_PEER_DIMENSIONS_CHANGED, responseInfo);
    if (!ret) {
        TELEPHONY_LOGE("[slot%{public}d] SendEvent failed!", slotId);
        return TELEPHONY_ERR_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::CallDataUsageChanged(int32_t slotId, const ImsCallDataUsageInfo &callDataUsageInfo)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    auto handler = DelayedSingleton<ImsCallClient>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<ImsCallDataUsageInfo> responseInfo = std::make_shared<ImsCallDataUsageInfo>();
    *responseInfo = callDataUsageInfo;
    bool ret = TelEventHandler::SendTelEvent(handler, RadioEvent::RADIO_CALL_DATA_USAGE_CHANGED, responseInfo);
    if (!ret) {
        TELEPHONY_LOGE("[slot%{public}d] SendEvent failed!", slotId);
        return TELEPHONY_ERR_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::CameraCapabilitiesChanged(
    int32_t slotId, const CameraCapabilitiesInfo &cameraCapabilitiesInfo)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    auto handler = DelayedSingleton<ImsCallClient>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<CameraCapabilitiesInfo> responseInfo = std::make_shared<CameraCapabilitiesInfo>();
    *responseInfo = cameraCapabilitiesInfo;
    bool ret = TelEventHandler::SendTelEvent(handler, RadioEvent::RADIO_CAMERA_CAPABILITIES_CHANGED, responseInfo);
    if (!ret) {
        TELEPHONY_LOGE("[slot%{public}d] SendEvent failed!", slotId);
        return TELEPHONY_ERR_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::GetSsRequestCommand(int32_t slotId, int32_t index, SsRequestCommand &ss)
{
    auto handler = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is null!", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return handler->GetSsRequestCommand(index, ss);
}

void ImsCallCallbackStub::BuildCallForwardInfo(
    const CallForwardQueryInfoList &cFQueryList, CallForwardQueryInfoList &cFQueryResultList)
{
    cFQueryResultList.callSize = cFQueryList.callSize;
    for (auto info : cFQueryList.calls) {
        CallForwardQueryResult call;
        call.serial = info.serial;
        call.result = info.result;
        call.status = info.status;
        call.classx = info.classx;
        call.number = info.number;
        call.type = info.type;
        call.reason = info.reason;
        call.time = info.time;
        call.startHour = info.startHour;
        call.startMinute = info.startMinute;
        call.endHour = info.endHour;
        call.endMinute = info.endMinute;
        cFQueryResultList.calls.push_back(call);
    }
    cFQueryResultList.result.result = cFQueryList.result.result;
    cFQueryResultList.result.index = cFQueryList.result.index;
    cFQueryResultList.result.reason = cFQueryList.result.reason;
    cFQueryResultList.result.message = cFQueryList.result.message;
}

int32_t ImsCallCallbackStub::SendEvent(int32_t slotId, int32_t eventId, const RadioResponseInfo &info)
{
    auto handler = DelayedSingleton<ImsCallClient>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<RadioResponseInfo> responseInfo = std::make_shared<RadioResponseInfo>();
    *responseInfo = info;
    bool ret = TelEventHandler::SendTelEvent(handler, eventId, responseInfo);
    if (!ret) {
        TELEPHONY_LOGE("[slot%{public}d] SendEvent failed!", slotId);
        return TELEPHONY_ERR_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::SendEvent(int32_t slotId, int32_t eventId, const SsBaseResult &resultInfo)
{
    auto handler = DelayedSingleton<ImsCallClient>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    auto ssResponseInfo = std::make_shared<SsBaseResult>();
    ssResponseInfo->result = resultInfo.result;
    ssResponseInfo->index = resultInfo.index;
    ssResponseInfo->reason = resultInfo.reason;
    ssResponseInfo->message = resultInfo.message;
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId, ssResponseInfo, resultInfo.index);
    bool ret = TelEventHandler::SendTelEvent(handler, response);
    if (!ret) {
        TELEPHONY_LOGE("[slot%{public}d] SendEvent failed!", slotId);
        return TELEPHONY_ERR_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallCallbackStub::SendEvent(int32_t slotId, int32_t eventId, const ImsCallModeReceiveInfo &callModeInfo)
{
    auto handler = DelayedSingleton<ImsCallClient>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<ImsCallModeReceiveInfo> info = std::make_shared<ImsCallModeReceiveInfo>();
    *info = callModeInfo;
    bool ret = TelEventHandler::SendTelEvent(handler, eventId, info);
    if (!ret) {
        TELEPHONY_LOGE("[slot%{public}d] SendEvent failed!", slotId);
        return TELEPHONY_ERR_FAIL;
    }
    return TELEPHONY_SUCCESS;
}
} // namespace Telephony
} // namespace OHOS

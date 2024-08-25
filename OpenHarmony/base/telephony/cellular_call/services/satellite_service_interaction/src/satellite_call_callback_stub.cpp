
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

#include "satellite_call_callback_stub.h"

#include "cellular_call_register.h"
#include "cellular_call_service.h"
#include "radio_event.h"
#include "satellite_call_client.h"
#include "satellite_radio_event.h"
#include "tel_event_handler.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
const int32_t MAX_SIZE = 10;

SatelliteCallCallbackStub::SatelliteCallCallbackStub()
{
    TELEPHONY_LOGI("SatelliteCallCallbackStub");
    InitFuncMap();
}

void SatelliteCallCallbackStub::InitFuncMap()
{
    InitCallBasicFuncMap();
}

void SatelliteCallCallbackStub::InitCallBasicFuncMap()
{
    /****************** call basic ******************/
    requestFuncMap_[static_cast<uint32_t>(SatelliteCallCallbackInterfaceCode::SATELLITE_DIAL)] =
        &SatelliteCallCallbackStub::OnDialResponseInner;
    requestFuncMap_[static_cast<uint32_t>(SatelliteCallCallbackInterfaceCode::SATELLITE_HANG_UP)] =
        &SatelliteCallCallbackStub::OnHangUpResponseInner;
    requestFuncMap_[static_cast<uint32_t>(SatelliteCallCallbackInterfaceCode::SATELLITE_REJECT)] =
        &SatelliteCallCallbackStub::OnRejectResponseInner;
    requestFuncMap_[static_cast<uint32_t>(SatelliteCallCallbackInterfaceCode::SATELLITE_ANSWER)] =
        &SatelliteCallCallbackStub::OnAnswerResponseInner;
    requestFuncMap_[static_cast<uint32_t>(SatelliteCallCallbackInterfaceCode::SATELLITE_CALL_STATE_CHANGE)] =
        &SatelliteCallCallbackStub::OnCallStateChangeReportInner;
    requestFuncMap_[static_cast<uint32_t>(SatelliteCallCallbackInterfaceCode::SATELLITE_GET_CALLS_DATA)] =
        &SatelliteCallCallbackStub::OnGetSatelliteCallsDataResponseInner;
}

SatelliteCallCallbackStub::~SatelliteCallCallbackStub()
{
    requestFuncMap_.clear();
}

int32_t SatelliteCallCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    std::u16string myDescriptor = SatelliteCallCallbackStub::GetDescriptor();
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

int32_t SatelliteCallCallbackStub::OnDialResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    auto info = static_cast<const RadioResponseInfo *>(data.ReadRawData(sizeof(RadioResponseInfo)));
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null.", slotId);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    reply.WriteInt32(DialSatelliteResponse(slotId, *info));
    return TELEPHONY_SUCCESS;
}

int32_t SatelliteCallCallbackStub::OnHangUpResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    auto info = static_cast<const RadioResponseInfo *>(data.ReadRawData(sizeof(RadioResponseInfo)));
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null.", slotId);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    reply.WriteInt32(HangUpSatelliteResponse(slotId, *info));
    return TELEPHONY_SUCCESS;
}

int32_t SatelliteCallCallbackStub::OnRejectResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    auto info = static_cast<const RadioResponseInfo *>(data.ReadRawData(sizeof(RadioResponseInfo)));
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null.", slotId);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    reply.WriteInt32(RejectSatelliteResponse(slotId, *info));
    return TELEPHONY_SUCCESS;
}

int32_t SatelliteCallCallbackStub::OnAnswerResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    auto info = static_cast<const RadioResponseInfo *>(data.ReadRawData(sizeof(RadioResponseInfo)));
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null.", slotId);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    reply.WriteInt32(AnswerSatelliteResponse(slotId, *info));
    return TELEPHONY_SUCCESS;
}

int32_t SatelliteCallCallbackStub::OnCallStateChangeReportInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    reply.WriteInt32(CallStateChangeReport(slotId));
    return TELEPHONY_SUCCESS;
}

int32_t SatelliteCallCallbackStub::OnGetSatelliteCallsDataResponseInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    auto info = static_cast<const RadioResponseInfo *>(data.ReadRawData(sizeof(RadioResponseInfo)));
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null.", slotId);
        auto callList = std::make_shared<SatelliteCurrentCallList>();
        callList->callSize = data.ReadInt32();
        callList->flag = data.ReadInt32();
        int32_t len = data.ReadInt32();
        if (len < 0 || len > MAX_SIZE) {
            TELEPHONY_LOGE("SatelliteCallCallbackStub::OnGetImsCallsDataResponseInner callSize error");
            return TELEPHONY_ERR_FAIL;
        }
        for (int32_t i = 0; i < len; i++) {
            SatelliteCurrentCall call;
            call.index = data.ReadInt32();
            call.dir = data.ReadInt32();
            call.state = data.ReadInt32();
            call.mode = data.ReadInt32();
            call.mpty = data.ReadInt32();
            call.voiceDomain = data.ReadInt32();
            call.callType = data.ReadInt32();
            data.ReadString(call.number);
            call.type = data.ReadInt32();
            data.ReadString(call.alpha);
            call.toa = data.ReadInt32();
            callList->calls.push_back(call);
        }
        reply.WriteInt32(GetSatelliteCallsDataResponse(slotId, *callList));
        return TELEPHONY_SUCCESS;
    }
    reply.WriteInt32(GetSatelliteCallsDataResponse(slotId, *info));
    return TELEPHONY_SUCCESS;
}

int32_t SatelliteCallCallbackStub::DialSatelliteResponse(int32_t slotId, const RadioResponseInfo &info)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    return SendEvent(slotId, SatelliteRadioEvent::SATELLITE_RADIO_DIAL, info);
}

int32_t SatelliteCallCallbackStub::HangUpSatelliteResponse(int32_t slotId, const RadioResponseInfo &info)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    return SendEvent(slotId, SatelliteRadioEvent::SATELLITE_RADIO_HANGUP, info);
}

int32_t SatelliteCallCallbackStub::RejectSatelliteResponse(int32_t slotId, const RadioResponseInfo &info)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    return SendEvent(slotId, SatelliteRadioEvent::SATELLITE_RADIO_REJECT, info);
}

int32_t SatelliteCallCallbackStub::AnswerSatelliteResponse(int32_t slotId, const RadioResponseInfo &info)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    return SendEvent(slotId, SatelliteRadioEvent::SATELLITE_RADIO_ANSWER, info);
}

int32_t SatelliteCallCallbackStub::CallStateChangeReport(int32_t slotId)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    auto handler = DelayedSingleton<SatelliteCallClient>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    bool ret = TelEventHandler::SendTelEvent(handler, SatelliteRadioEvent::SATELLITE_RADIO_CALL_STATE_CHANGED);
    if (!ret) {
        TELEPHONY_LOGE("[slot%{public}d] SendEvent failed!", slotId);
        return TELEPHONY_ERR_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t SatelliteCallCallbackStub::GetSatelliteCallsDataResponse(int32_t slotId, const RadioResponseInfo &info)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    return SendEvent(slotId, SatelliteRadioEvent::SATELLITE_RADIO_GET_CALL_DATA, info);
}

int32_t SatelliteCallCallbackStub::GetSatelliteCallsDataResponse(
    int32_t slotId, const SatelliteCurrentCallList &callList)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    auto handler = DelayedSingleton<SatelliteCallClient>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    auto satelliteCurrentCallList = std::make_shared<SatelliteCurrentCallList>();
    *satelliteCurrentCallList = callList;
    bool ret = TelEventHandler::SendTelEvent(
        handler, SatelliteRadioEvent::SATELLITE_RADIO_GET_CALL_DATA, satelliteCurrentCallList);
    if (!ret) {
        TELEPHONY_LOGE("[slot%{public}d] SendEvent failed!", slotId);
        return TELEPHONY_ERR_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t SatelliteCallCallbackStub::SendEvent(int32_t slotId, int32_t eventId, const RadioResponseInfo &info)
{
    auto handler = DelayedSingleton<SatelliteCallClient>::GetInstance()->GetHandler(slotId);
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
} // namespace Telephony
} // namespace OHOS
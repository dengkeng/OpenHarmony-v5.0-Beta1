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
 * limitations under the License.
 */

#include "satellite_call_proxy.h"

#include "cellular_call_hisysevent.h"
#include "message_option.h"
#include "message_parcel.h"
#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {
int32_t SatelliteCallProxy::Dial(const SatelliteCallInfo &callInfo, CLIRMode mode)
{
    MessageParcel in;
    if (!in.WriteInterfaceToken(SatelliteCallProxy::GetDescriptor())) {
        TELEPHONY_LOGE("[slot%{public}d]Write descriptor token fail!", callInfo.slotId);
        CellularCallHiSysEvent::WriteDialCallFaultEvent(callInfo.slotId, INVALID_PARAMETER, INVALID_PARAMETER,
            TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL, "satellite call proxy write descriptor token fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteRawData((const void *)&callInfo, sizeof(SatelliteCallInfo))) {
        TELEPHONY_LOGE("[slot%{public}d]Write callInfo fail!", callInfo.slotId);
        CellularCallHiSysEvent::WriteDialCallFaultEvent(callInfo.slotId, INVALID_PARAMETER, INVALID_PARAMETER,
            TELEPHONY_ERR_WRITE_DATA_FAIL, "satellite call proxy write data fail");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(mode)) {
        TELEPHONY_LOGE("[slot%{public}d]Write mode fail!", callInfo.slotId);
        CellularCallHiSysEvent::WriteDialCallFaultEvent(callInfo.slotId, INVALID_PARAMETER, INVALID_PARAMETER,
            TELEPHONY_ERR_WRITE_DATA_FAIL, "satellite call proxy write data fail");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d]Remote is null", callInfo.slotId);
        CellularCallHiSysEvent::WriteDialCallFaultEvent(callInfo.slotId, INVALID_PARAMETER, INVALID_PARAMETER,
            TELEPHONY_ERR_LOCAL_PTR_NULL, "satellite call proxy remote is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    MessageParcel out;
    MessageOption option;
    int32_t error =
        remote->SendRequest(static_cast<int32_t>(SatelliteCallInterfaceCode::SATELLITE_DIAL), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    TELEPHONY_LOGE("[slot%{public}d]SendRequest fail, error:%{public}d", callInfo.slotId, error);
    CellularCallHiSysEvent::WriteDialCallFaultEvent(callInfo.slotId, INVALID_PARAMETER, INVALID_PARAMETER,
        static_cast<int32_t>(CallErrorCode::CALL_ERROR_SEND_REQUEST_FAIL), "satellite call proxy send request fail");
    return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
}

int32_t SatelliteCallProxy::HangUp(int32_t slotId, int32_t index)
{
    MessageParcel in;
    if (!in.WriteInterfaceToken(SatelliteCallProxy::GetDescriptor())) {
        TELEPHONY_LOGE("[slot%{public}d]Write descriptor token fail!", slotId);
        CellularCallHiSysEvent::WriteHangUpFaultEvent(slotId, INVALID_PARAMETER,
            TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL, "HangUp satellite call proxy write descriptor token fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        TELEPHONY_LOGE("[slot%{public}d]Write mode fail!", slotId);
        CellularCallHiSysEvent::WriteDialCallFaultEvent(slotId, INVALID_PARAMETER, INVALID_PARAMETER,
            TELEPHONY_ERR_WRITE_DATA_FAIL, "satellite call proxy write data fail");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(index)) {
        TELEPHONY_LOGE("[slot%{public}d]Write mode fail!", slotId);
        CellularCallHiSysEvent::WriteDialCallFaultEvent(slotId, INVALID_PARAMETER, INVALID_PARAMETER,
            TELEPHONY_ERR_WRITE_DATA_FAIL, "satellite call proxy write data fail");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d]Remote is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    MessageParcel out;
    MessageOption option;
    int32_t error =
        remote->SendRequest(static_cast<int32_t>(SatelliteCallInterfaceCode::SATELLITE_HANG_UP), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    TELEPHONY_LOGE("[slot%{public}d]SendRequest fail, error:%{public}d", slotId, error);
    CellularCallHiSysEvent::WriteHangUpFaultEvent(slotId, INVALID_PARAMETER,
        static_cast<int32_t>(CallErrorCode::CALL_ERROR_SEND_REQUEST_FAIL), "HangUp ims call proxy send request fail");
    return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
}

int32_t SatelliteCallProxy::Reject(int32_t slotId)
{
    MessageParcel in;
    if (!in.WriteInterfaceToken(SatelliteCallProxy::GetDescriptor())) {
        TELEPHONY_LOGE("[slot%{public}d]Write descriptor token fail!", slotId);
        CellularCallHiSysEvent::WriteHangUpFaultEvent(slotId, INVALID_PARAMETER,
            TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL, "Reject satellite call proxy write descriptor token fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        TELEPHONY_LOGE("[slot%{public}d]Write reason fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d]Remote is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    MessageParcel out;
    MessageOption option;
    int32_t error =
        remote->SendRequest(static_cast<int32_t>(SatelliteCallInterfaceCode::SATELLITE_REJECT), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    TELEPHONY_LOGE("[slot%{public}d]SendRequest fail, error:%{public}d", slotId, error);
    CellularCallHiSysEvent::WriteHangUpFaultEvent(slotId, INVALID_PARAMETER,
        static_cast<int32_t>(CallErrorCode::CALL_ERROR_SEND_REQUEST_FAIL),
        "Reject satellite call proxy send request fail");
    return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
}

int32_t SatelliteCallProxy::Answer(int32_t slotId)
{
    MessageParcel in;
    if (!in.WriteInterfaceToken(SatelliteCallProxy::GetDescriptor())) {
        TELEPHONY_LOGE("[slot%{public}d]Write descriptor token fail!", slotId);
        CellularCallHiSysEvent::WriteAnswerCallFaultEvent(slotId, INVALID_PARAMETER, INVALID_PARAMETER,
            TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL, "satellite call proxy write descriptor token fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        TELEPHONY_LOGE("[slot%{public}d]Write reason fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d]Remote is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    MessageParcel out;
    MessageOption option;
    int32_t error =
        remote->SendRequest(static_cast<int32_t>(SatelliteCallInterfaceCode::SATELLITE_ANSWER), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    TELEPHONY_LOGE("[slot%{public}d]SendRequest fail, error:%{public}d", slotId, error);
    CellularCallHiSysEvent::WriteAnswerCallFaultEvent(slotId, INVALID_PARAMETER, INVALID_PARAMETER,
        static_cast<int32_t>(CallErrorCode::CALL_ERROR_SEND_REQUEST_FAIL), "satellite call proxy send request fail");
    return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
}

int32_t SatelliteCallProxy::GetSatelliteCallsDataRequest(int32_t slotId)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(SatelliteCallInterfaceCode::SATELLITE_GET_CALL_DATA));
}

int32_t SatelliteCallProxy::RegisterSatelliteCallCallback(const sptr<SatelliteCallCallbackInterface> &callback)
{
    if (callback == nullptr) {
        TELEPHONY_LOGE("callback is null!");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    MessageParcel in;
    if (!in.WriteInterfaceToken(SatelliteCallProxy::GetDescriptor())) {
        TELEPHONY_LOGE("Write descriptor token fail!");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteRemoteObject(callback->AsObject().GetRefPtr())) {
        TELEPHONY_LOGE("Write ImsCallCallbackInterface fail!");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(in, static_cast<int32_t>(SatelliteCallInterfaceCode::SATELLITE_CALL_REGISTER_CALLBACK));
}

int32_t SatelliteCallProxy::WriteCommonInfo(int32_t slotId, std::string funcName, MessageParcel &in)
{
    if (!in.WriteInterfaceToken(SatelliteCallProxy::GetDescriptor())) {
        TELEPHONY_LOGE("[slot%{public}d] %{public}s Write descriptor token fail!", slotId, funcName.c_str());
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        TELEPHONY_LOGE("[slot%{public}d] %{public}s Write slotId fail!", slotId, funcName.c_str());
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t SatelliteCallProxy::WriteCommonInfo(int32_t slotId, std::string funcName, MessageParcel &in, int32_t callType)
{
    int32_t ret = WriteCommonInfo(slotId, funcName, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(callType)) {
        TELEPHONY_LOGE("[slot%{public}d] %{public}s Write callType fail!", slotId, funcName.c_str());
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t SatelliteCallProxy::SendRequest(MessageParcel &in, int32_t eventId)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null, eventId:%{public}d", eventId);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }

    MessageParcel out;
    MessageOption option;
    int32_t error = remote->SendRequest(eventId, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    TELEPHONY_LOGE("SendRequest fail, eventId:%{public}d, error:%{public}d", eventId, error);
    return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
}

int32_t SatelliteCallProxy::SendRequest(int32_t slotId, MessageParcel &in, int32_t eventId)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d]Remote is null, eventId:%{public}d", slotId, eventId);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }

    MessageParcel out;
    MessageOption option;
    int32_t error = remote->SendRequest(eventId, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    TELEPHONY_LOGE("[slot%{public}d]SendRequest fail, eventId:%{public}d, error:%{public}d", slotId, eventId, error);
    return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
}
} // namespace Telephony
} // namespace OHOS
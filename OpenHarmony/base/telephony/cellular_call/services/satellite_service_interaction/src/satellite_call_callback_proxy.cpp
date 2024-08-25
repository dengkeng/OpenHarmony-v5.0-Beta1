/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "satellite_call_callback_proxy.h"

#include "message_option.h"
#include "message_parcel.h"

namespace OHOS {
namespace Telephony {
SatelliteCallCallbackProxy::SatelliteCallCallbackProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<SatelliteCallCallbackInterface>(impl)
{}

int32_t SatelliteCallCallbackProxy::DialSatelliteResponse(int32_t slotId, const RadioResponseInfo &info)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in, info);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendResponseInfo(static_cast<int32_t>(SatelliteCallCallbackInterfaceCode::SATELLITE_DIAL), in);
}

int32_t SatelliteCallCallbackProxy::HangUpSatelliteResponse(int32_t slotId, const RadioResponseInfo &info)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in, info);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendResponseInfo(static_cast<int32_t>(SatelliteCallCallbackInterfaceCode::SATELLITE_HANG_UP), in);
}

int32_t SatelliteCallCallbackProxy::RejectSatelliteResponse(int32_t slotId, const RadioResponseInfo &info)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in, info);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendResponseInfo(static_cast<int32_t>(SatelliteCallCallbackInterfaceCode::SATELLITE_REJECT), in);
}

int32_t SatelliteCallCallbackProxy::AnswerSatelliteResponse(int32_t slotId, const RadioResponseInfo &info)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in, info);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendResponseInfo(static_cast<int32_t>(SatelliteCallCallbackInterfaceCode::SATELLITE_ANSWER), in);
}

int32_t SatelliteCallCallbackProxy::CallStateChangeReport(int32_t slotId)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendResponseInfo(static_cast<int32_t>(SatelliteCallCallbackInterfaceCode::SATELLITE_CALL_STATE_CHANGE), in);
}

int32_t SatelliteCallCallbackProxy::GetSatelliteCallsDataResponse(int32_t slotId, const RadioResponseInfo &info)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in, info);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendResponseInfo(static_cast<int32_t>(SatelliteCallCallbackInterfaceCode::SATELLITE_GET_CALLS_DATA), in);
}

int32_t SatelliteCallCallbackProxy::GetSatelliteCallsDataResponse(
    int32_t slotId, const SatelliteCurrentCallList &callList)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(slotId)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(callList.callSize)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(callList.flag)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(static_cast<int32_t>(callList.calls.size()))) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    for (auto call : callList.calls) {
        if (!in.WriteInt32(call.index) || !in.WriteInt32(call.dir) || !in.WriteInt32(call.state) ||
            !in.WriteInt32(call.mode) || !in.WriteInt32(call.mpty) || !in.WriteInt32(call.voiceDomain) ||
            !in.WriteInt32(call.callType) || !in.WriteString(call.number) || !in.WriteInt32(call.type) ||
            !in.WriteString(call.alpha) || !in.WriteInt32(call.toa)) {
            return TELEPHONY_ERR_WRITE_DATA_FAIL;
        }
    }
    return SendResponseInfo(static_cast<int32_t>(SatelliteCallCallbackInterfaceCode::SATELLITE_GET_CALLS_DATA), in);
}

int32_t SatelliteCallCallbackProxy::SendResponseInfo(int32_t eventId, MessageParcel &in)
{
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

int32_t SatelliteCallCallbackProxy::WriteCommonInfo(int32_t slotId, const std::string &funcName, MessageParcel &in)
{
    if (!in.WriteInterfaceToken(SatelliteCallCallbackProxy::GetDescriptor())) {
        TELEPHONY_LOGE("[slot%{public}d]%{public}s:Write descriptor token fail!", slotId, funcName.c_str());
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        TELEPHONY_LOGE("[slot%{public}d]%{public}s:Write slotId fail!", slotId, funcName.c_str());
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t SatelliteCallCallbackProxy::WriteCommonInfo(
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

int32_t SatelliteCallCallbackProxy::WriteSsBaseResultCommonInfo(
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
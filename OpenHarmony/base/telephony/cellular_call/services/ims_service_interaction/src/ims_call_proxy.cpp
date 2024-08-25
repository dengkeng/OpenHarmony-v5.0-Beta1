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

#include "ims_call_proxy.h"

#include "cellular_call_hisysevent.h"
#include "message_option.h"
#include "message_parcel.h"
#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {
int32_t ImsCallProxy::Dial(const ImsCallInfo &callInfo, CLIRMode mode)
{
    MessageParcel in;
    if (!in.WriteInterfaceToken(ImsCallProxy::GetDescriptor())) {
        TELEPHONY_LOGE("[slot%{public}d]Write descriptor token fail!", callInfo.slotId);
        CellularCallHiSysEvent::WriteDialCallFaultEvent(callInfo.slotId, INVALID_PARAMETER, callInfo.videoState,
            TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL, "ims call proxy write descriptor token fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteRawData((const void *)&callInfo, sizeof(ImsCallInfo))) {
        TELEPHONY_LOGE("[slot%{public}d]Write callInfo fail!", callInfo.slotId);
        CellularCallHiSysEvent::WriteDialCallFaultEvent(callInfo.slotId, INVALID_PARAMETER, callInfo.videoState,
            TELEPHONY_ERR_WRITE_DATA_FAIL, "ims call proxy write data fail");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(mode)) {
        TELEPHONY_LOGE("[slot%{public}d]Write mode fail!", callInfo.slotId);
        CellularCallHiSysEvent::WriteDialCallFaultEvent(callInfo.slotId, INVALID_PARAMETER, callInfo.videoState,
            TELEPHONY_ERR_WRITE_DATA_FAIL, "ims call proxy write data fail");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d]Remote is null", callInfo.slotId);
        CellularCallHiSysEvent::WriteDialCallFaultEvent(callInfo.slotId, INVALID_PARAMETER, callInfo.videoState,
            TELEPHONY_ERR_LOCAL_PTR_NULL, "ims call proxy remote is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    MessageParcel out;
    MessageOption option;
    int32_t error = remote->SendRequest(static_cast<int32_t>(ImsCallInterfaceCode::IMS_DIAL), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    TELEPHONY_LOGE("[slot%{public}d]SendRequest fail, error:%{public}d", callInfo.slotId, error);
    CellularCallHiSysEvent::WriteDialCallFaultEvent(callInfo.slotId, INVALID_PARAMETER, callInfo.videoState,
        static_cast<int32_t>(CallErrorCode::CALL_ERROR_SEND_REQUEST_FAIL), "ims call proxy send request fail");
    return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
}

int32_t ImsCallProxy::HangUp(const ImsCallInfo &callInfo)
{
    MessageParcel in;
    if (!in.WriteInterfaceToken(ImsCallProxy::GetDescriptor())) {
        TELEPHONY_LOGE("[slot%{public}d]Write descriptor token fail!", callInfo.slotId);
        CellularCallHiSysEvent::WriteHangUpFaultEvent(callInfo.slotId, INVALID_PARAMETER,
            TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL, "HangUp ims call proxy write descriptor token fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteRawData((const void *)&callInfo, sizeof(ImsCallInfo))) {
        TELEPHONY_LOGE("[slot%{public}d]Write callInfo fail!", callInfo.slotId);
        CellularCallHiSysEvent::WriteHangUpFaultEvent(
            callInfo.slotId, INVALID_PARAMETER, TELEPHONY_ERR_WRITE_DATA_FAIL, "HangUp ims call proxy write data fail");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d]Remote is null", callInfo.slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    MessageParcel out;
    MessageOption option;
    int32_t error = remote->SendRequest(static_cast<int32_t>(ImsCallInterfaceCode::IMS_HANG_UP), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    TELEPHONY_LOGE("[slot%{public}d]SendRequest fail, error:%{public}d", callInfo.slotId, error);
    CellularCallHiSysEvent::WriteHangUpFaultEvent(callInfo.slotId, INVALID_PARAMETER,
        static_cast<int32_t>(CallErrorCode::CALL_ERROR_SEND_REQUEST_FAIL), "HangUp ims call proxy send request fail");
    return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
}

int32_t ImsCallProxy::RejectWithReason(const ImsCallInfo &callInfo, const ImsRejectReason &reason)
{
    MessageParcel in;
    if (!in.WriteInterfaceToken(ImsCallProxy::GetDescriptor())) {
        TELEPHONY_LOGE("[slot%{public}d]Write descriptor token fail!", callInfo.slotId);
        CellularCallHiSysEvent::WriteHangUpFaultEvent(callInfo.slotId, INVALID_PARAMETER,
            TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL, "Reject ims call proxy write descriptor token fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteRawData((const void *)&callInfo, sizeof(ImsCallInfo))) {
        TELEPHONY_LOGE("[slot%{public}d]Write callInfo fail!", callInfo.slotId);
        CellularCallHiSysEvent::WriteHangUpFaultEvent(callInfo.slotId, INVALID_PARAMETER,
            TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL, "Reject ims call proxy write data fail");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(reason)) {
        TELEPHONY_LOGE("[slot%{public}d]Write reason fail!", callInfo.slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d]Remote is null", callInfo.slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    MessageParcel out;
    MessageOption option;
    int32_t error = remote->SendRequest(static_cast<int32_t>(ImsCallInterfaceCode::IMS_REJECT_WITH_REASON), in,
        out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    TELEPHONY_LOGE("[slot%{public}d]SendRequest fail, error:%{public}d", callInfo.slotId, error);
    CellularCallHiSysEvent::WriteHangUpFaultEvent(callInfo.slotId, INVALID_PARAMETER,
        static_cast<int32_t>(CallErrorCode::CALL_ERROR_SEND_REQUEST_FAIL), "Reject ims call proxy send request fail");
    return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
}

int32_t ImsCallProxy::Answer(const ImsCallInfo &callInfo)
{
    MessageParcel in;
    if (!in.WriteInterfaceToken(ImsCallProxy::GetDescriptor())) {
        TELEPHONY_LOGE("[slot%{public}d]Write descriptor token fail!", callInfo.slotId);
        CellularCallHiSysEvent::WriteAnswerCallFaultEvent(callInfo.slotId, INVALID_PARAMETER, callInfo.videoState,
            TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL, "ims call proxy write descriptor token fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteRawData((const void *)&callInfo, sizeof(ImsCallInfo))) {
        TELEPHONY_LOGE("[slot%{public}d]Write callInfo fail!", callInfo.slotId);
        CellularCallHiSysEvent::WriteAnswerCallFaultEvent(callInfo.slotId, INVALID_PARAMETER, callInfo.videoState,
            TELEPHONY_ERR_WRITE_DATA_FAIL, "ims call proxy write data fail");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d]Remote is null", callInfo.slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    MessageParcel out;
    MessageOption option;
    int32_t error = remote->SendRequest(static_cast<int32_t>(ImsCallInterfaceCode::IMS_ANSWER), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    TELEPHONY_LOGE("[slot%{public}d]SendRequest fail, error:%{public}d", callInfo.slotId, error);
    CellularCallHiSysEvent::WriteAnswerCallFaultEvent(callInfo.slotId, INVALID_PARAMETER, callInfo.videoState,
        static_cast<int32_t>(CallErrorCode::CALL_ERROR_SEND_REQUEST_FAIL), "ims call proxy send request fail");
    return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
}

int32_t ImsCallProxy::HoldCall(int32_t slotId, int32_t callType)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in, callType);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_HOLD));
}

int32_t ImsCallProxy::UnHoldCall(int32_t slotId, int32_t callType)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in, callType);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_UN_HOLD));
}

int32_t ImsCallProxy::SwitchCall(int32_t slotId, int32_t callType)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in, callType);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_SWITCH));
}

int32_t ImsCallProxy::CombineConference(int32_t slotId)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_COMBINE_CONFERENCE));
}

int32_t ImsCallProxy::InviteToConference(int32_t slotId, const std::vector<std::string> &numberList)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteStringVector(numberList)) {
        TELEPHONY_LOGE("[slot%{public}d]Write numberList fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_INVITE_TO_CONFERENCE));
}

int32_t ImsCallProxy::KickOutFromConference(int32_t slotId, int32_t index)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(index)) {
        TELEPHONY_LOGE("[slot%{public}d]Write index fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_KICK_OUT_CONFERENCE));
}

int32_t ImsCallProxy::SendUpdateCallMediaModeRequest(const ImsCallInfo &callInfo, ImsCallType callType)
{
    MessageParcel in;
    if (!in.WriteInterfaceToken(ImsCallProxy::GetDescriptor())) {
        TELEPHONY_LOGE("[slot%{public}d]Write descriptor token fail!", callInfo.slotId);
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteRawData((const void *)&callInfo, sizeof(ImsCallInfo))) {
        TELEPHONY_LOGE("[slot%{public}d]Write callInfo fail!", callInfo.slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(static_cast<int32_t>(callType))) {
        TELEPHONY_LOGE("[slot%{public}d]Write mode fail!", callInfo.slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(
        callInfo.slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_SEND_CALL_MEDIA_MODE_REQUEST));
}

int32_t ImsCallProxy::SendUpdateCallMediaModeResponse(const ImsCallInfo &callInfo, ImsCallType callType)
{
    MessageParcel in;
    if (!in.WriteInterfaceToken(ImsCallProxy::GetDescriptor())) {
        TELEPHONY_LOGE("[slot%{public}d]Write descriptor token fail!", callInfo.slotId);
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteRawData((const void *)&callInfo, sizeof(ImsCallInfo))) {
        TELEPHONY_LOGE("[slot%{public}d]Write callInfo fail!", callInfo.slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(static_cast<int32_t>(callType))) {
        TELEPHONY_LOGE("[slot%{public}d]Write mode fail!", callInfo.slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(
        callInfo.slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_SEND_CALL_MEDIA_MODE_RESPONSE));
}

int32_t ImsCallProxy::CancelCallUpgrade(int32_t slotId, int32_t callIndex)
{
    MessageParcel in;
    if (!in.WriteInterfaceToken(ImsCallProxy::GetDescriptor())) {
        TELEPHONY_LOGE("[slot%{public}d]Write descriptor token fail!", slotId);
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        TELEPHONY_LOGE("[slot%{public}d]Write slotId fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(callIndex)) {
        TELEPHONY_LOGE("[slot%{public}d]Write callIndex fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_CANCEL_CALL_UPGRADE));
}

int32_t ImsCallProxy::RequestCameraCapabilities(int32_t slotId, int32_t callIndex)
{
    MessageParcel in;
    if (!in.WriteInterfaceToken(ImsCallProxy::GetDescriptor())) {
        TELEPHONY_LOGE("[slot%{public}d]Write descriptor token fail!", slotId);
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        TELEPHONY_LOGE("[slot%{public}d]Write slotId fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(callIndex)) {
        TELEPHONY_LOGE("[slot%{public}d]Write callIndex fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_REQUEST_CAMERA_CAPABILITIES));
}

int32_t ImsCallProxy::GetImsCallsDataRequest(int32_t slotId, int64_t lastCallsDataFlag)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt64(lastCallsDataFlag)) {
        TELEPHONY_LOGE("[slot%{public}d]Write lastCallsDataFlag fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_GET_CALL_DATA));
}

int32_t ImsCallProxy::GetLastCallFailReason(int32_t slotId)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_GET_LAST_CALL_FAIL_REASON));
}

int32_t ImsCallProxy::StartDtmf(int32_t slotId, char cDtmfCode, int32_t index)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt8(cDtmfCode)) {
        TELEPHONY_LOGE("[slot%{public}d]Write cDtmfCode fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(index)) {
        TELEPHONY_LOGE("[slot%{public}d]Write index fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_START_DTMF));
}

int32_t ImsCallProxy::SendDtmf(int32_t slotId, char cDtmfCode, int32_t index)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt8(cDtmfCode)) {
        TELEPHONY_LOGE("[slot%{public}d]Write cDtmfCode fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(index)) {
        TELEPHONY_LOGE("[slot%{public}d]Write index fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_SEND_DTMF));
}

int32_t ImsCallProxy::StopDtmf(int32_t slotId, int32_t index)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(index)) {
        TELEPHONY_LOGE("[slot%{public}d]Write index fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_STOP_DTMF));
}

int32_t ImsCallProxy::StartRtt(int32_t slotId, const std::string &msg)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteString(msg)) {
        TELEPHONY_LOGE("[slot%{public}d]Write msg fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_START_RTT));
}

int32_t ImsCallProxy::StopRtt(int32_t slotId)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_STOP_RTT));
}

int32_t ImsCallProxy::SetDomainPreferenceMode(int32_t slotId, int32_t mode)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(mode)) {
        TELEPHONY_LOGE("[slot%{public}d]Write mode fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_SET_DOMAIN_PREFERENCE_MODE));
}

int32_t ImsCallProxy::GetDomainPreferenceMode(int32_t slotId)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_GET_DOMAIN_PREFERENCE_MODE));
}

int32_t ImsCallProxy::SetImsSwitchStatus(int32_t slotId, int32_t active)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(active)) {
        TELEPHONY_LOGE("[slot%{public}d]Write active fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_SET_SWITCH_STATUS));
}

int32_t ImsCallProxy::GetImsSwitchStatus(int32_t slotId)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_GET_SWITCH_STATUS));
}

int32_t ImsCallProxy::SetImsConfig(ImsConfigItem item, const std::string &value)
{
    MessageParcel in;
    if (!in.WriteInterfaceToken(ImsCallProxy::GetDescriptor())) {
        TELEPHONY_LOGE("Write descriptor token fail!");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(item)) {
        TELEPHONY_LOGE("Write item fail!");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteString(value)) {
        TELEPHONY_LOGE("Write value fail!");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_SET_IMS_CONFIG_STRING));
}

int32_t ImsCallProxy::SetImsConfig(ImsConfigItem item, int32_t value)
{
    MessageParcel in;
    if (!in.WriteInterfaceToken(ImsCallProxy::GetDescriptor())) {
        TELEPHONY_LOGE("Write descriptor token fail!");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(item)) {
        TELEPHONY_LOGE("Write item fail!");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(value)) {
        TELEPHONY_LOGE("Write value fail!");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_SET_IMS_CONFIG_INT));
}

int32_t ImsCallProxy::GetImsConfig(ImsConfigItem item)
{
    MessageParcel in;
    if (!in.WriteInterfaceToken(ImsCallProxy::GetDescriptor())) {
        TELEPHONY_LOGE("Write descriptor token fail!");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(item)) {
        TELEPHONY_LOGE("Write item fail!");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_GET_IMS_CONFIG));
}

int32_t ImsCallProxy::SetImsFeatureValue(FeatureType type, int32_t value)
{
    MessageParcel in;
    if (!in.WriteInterfaceToken(ImsCallProxy::GetDescriptor())) {
        TELEPHONY_LOGE("Write descriptor token fail!");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(type)) {
        TELEPHONY_LOGE("Write type fail!");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(value)) {
        TELEPHONY_LOGE("Write value fail!");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_SET_IMS_FEATURE));
}

int32_t ImsCallProxy::GetImsFeatureValue(FeatureType type, int32_t &value)
{
    MessageParcel in;
    if (!in.WriteInterfaceToken(ImsCallProxy::GetDescriptor())) {
        TELEPHONY_LOGE("Write descriptor token fail!");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(type)) {
        TELEPHONY_LOGE("Write type fail!");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_GET_IMS_FEATURE));
}

int32_t ImsCallProxy::SetMute(int32_t slotId, int32_t mute)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(mute)) {
        TELEPHONY_LOGE("[slot%{public}d]Write mute fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_SET_MUTE));
}

int32_t ImsCallProxy::GetMute(int32_t slotId)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_GET_MUTE));
}

int32_t ImsCallProxy::ControlCamera(int32_t slotId, int32_t callIndex, const std::string &cameraId)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(callIndex)) {
        TELEPHONY_LOGE("Write callIndex fail!");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteString(cameraId)) {
        TELEPHONY_LOGE("Write cameraId fail!");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_CTRL_CAMERA));
}

int32_t ImsCallProxy::SetPreviewWindow(
    int32_t slotId, int32_t callIndex, const std::string &surfaceID, sptr<Surface> surface)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(callIndex)) {
        TELEPHONY_LOGE("Write callIndex fail!");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteString(surfaceID)) {
        TELEPHONY_LOGE("Write surface id fail!");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (surface != nullptr) {
        sptr<IBufferProducer> producer = surface->GetProducer();
        if (producer != nullptr) {
            in.WriteRemoteObject(producer->AsObject());
        }
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_SET_PREVIEW_WINDOW));
}

int32_t ImsCallProxy::SetDisplayWindow(
    int32_t slotId, int32_t callIndex, const std::string &surfaceID, sptr<Surface> surface)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(callIndex)) {
        TELEPHONY_LOGE("Write callIndex fail!");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteString(surfaceID)) {
        TELEPHONY_LOGE("Write surface id fail!");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (surface != nullptr) {
        sptr<IBufferProducer> producer = surface->GetProducer();
        if (producer != nullptr) {
            in.WriteRemoteObject(producer->AsObject());
        }
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_SET_DISPLAY_WINDOW));
}

int32_t ImsCallProxy::SetCameraZoom(float zoomRatio)
{
    MessageParcel in;
    if (!in.WriteInterfaceToken(ImsCallProxy::GetDescriptor())) {
        TELEPHONY_LOGE("Write descriptor token fail!");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteFloat(zoomRatio)) {
        TELEPHONY_LOGE("Write zoomRatio fail!");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_SET_CAMERA_ZOOM));
}

int32_t ImsCallProxy::SetPausePicture(int32_t slotId, int32_t callIndex, const std::string &path)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(callIndex)) {
        TELEPHONY_LOGE("Write callIndex fail!");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteString(path)) {
        TELEPHONY_LOGE("Write path fail!");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_SET_PAUSE_IMAGE));
}

int32_t ImsCallProxy::SetDeviceDirection(int32_t slotId, int32_t callIndex, int32_t rotation)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(callIndex)) {
        TELEPHONY_LOGE("Write callIndex fail!");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(rotation)) {
        TELEPHONY_LOGE("Write rotation fail!");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_SET_DEVICE_DIRECTION));
}

int32_t ImsCallProxy::SetClip(int32_t slotId, int32_t action, int32_t index)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(action)) {
        TELEPHONY_LOGE("[slot%{public}d]Write action fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(index)) {
        TELEPHONY_LOGE("[slot%{public}d]Write index fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_SET_CLIP));
}

int32_t ImsCallProxy::GetClip(int32_t slotId, int32_t index)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(index)) {
        TELEPHONY_LOGE("[slot%{public}d]Write index fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_GET_CLIP));
}

int32_t ImsCallProxy::SetClir(int32_t slotId, int32_t action, int32_t index)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(action)) {
        TELEPHONY_LOGE("[slot%{public}d]Write action fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(index)) {
        TELEPHONY_LOGE("[slot%{public}d]Write index fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_SET_CLIR));
}

int32_t ImsCallProxy::GetClir(int32_t slotId, int32_t index)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(index)) {
        TELEPHONY_LOGE("[slot%{public}d]Write index fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_GET_CLIR));
}

int32_t ImsCallProxy::SetCallTransfer(int32_t slotId, const CallTransferInfo &cfInfo, int32_t classType, int32_t index)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteRawData((const void *)&cfInfo, sizeof(CallTransferInfo))) {
        TELEPHONY_LOGE("[slot%{public}d]Write cfInfo fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(classType)) {
        TELEPHONY_LOGE("[slot%{public}d]Write classType fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(index)) {
        TELEPHONY_LOGE("[slot%{public}d]Write index fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_SET_CALL_TRANSFER));
}

int32_t ImsCallProxy::CanSetCallTransferTime(int32_t slotId, bool &result)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteBool(result)) {
        TELEPHONY_LOGE("[slot%{public}d]Write classType fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    MessageParcel out;
    MessageOption option;

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d]Remote is null", slotId);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }

    int32_t error = remote->SendRequest(static_cast<int32_t>(ImsCallInterfaceCode::IMS_CAN_SET_CALL_TRANSFER_TIME), in,
        out, option);
    if (error == ERR_NONE) {
        result = out.ReadBool();
        return out.ReadInt32();
    }
    return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
}

int32_t ImsCallProxy::GetCallTransfer(int32_t slotId, int32_t reason, int32_t index)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(reason)) {
        TELEPHONY_LOGE("[slot%{public}d]Write reason fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(index)) {
        TELEPHONY_LOGE("[slot%{public}d]Write index fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_GET_CALL_TRANSFER));
}

int32_t ImsCallProxy::SetCallRestriction(
    int32_t slotId, const std::string &fac, int32_t mode, const std::string &pw, int32_t index)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteString(fac)) {
        TELEPHONY_LOGE("[slot%{public}d]Write fac fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(mode)) {
        TELEPHONY_LOGE("[slot%{public}d]Write mode fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteString(pw)) {
        TELEPHONY_LOGE("[slot%{public}d]Write pw fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(index)) {
        TELEPHONY_LOGE("[slot%{public}d]Write index fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_SET_CALL_RESTRICTION));
}

int32_t ImsCallProxy::GetCallRestriction(int32_t slotId, const std::string &fac, int32_t index)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteString(fac)) {
        TELEPHONY_LOGE("[slot%{public}d]Write fac fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(index)) {
        TELEPHONY_LOGE("[slot%{public}d]Write index fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_GET_CALL_RESTRICTION));
}

int32_t ImsCallProxy::SetCallWaiting(int32_t slotId, bool activate, int32_t classType, int32_t index)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteBool(activate)) {
        TELEPHONY_LOGE("[slot%{public}d]Write activate fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(classType)) {
        TELEPHONY_LOGE("[slot%{public}d]Write classType fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(index)) {
        TELEPHONY_LOGE("[slot%{public}d]Write index fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_SET_CALL_WAITING));
}

int32_t ImsCallProxy::GetCallWaiting(int32_t slotId, int32_t index)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(index)) {
        TELEPHONY_LOGE("[slot%{public}d]Write index fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_GET_CALL_WAITING));
}

int32_t ImsCallProxy::SetColr(int32_t slotId, int32_t presentation, int32_t index)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(presentation)) {
        TELEPHONY_LOGE("[slot%{public}d]Write presentation fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(index)) {
        TELEPHONY_LOGE("[slot%{public}d]Write index fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_SET_COLR));
}

int32_t ImsCallProxy::GetColr(int32_t slotId, int32_t index)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(index)) {
        TELEPHONY_LOGE("[slot%{public}d]Write index fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_GET_COLR));
}

int32_t ImsCallProxy::SetColp(int32_t slotId, int32_t action, int32_t index)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(action)) {
        TELEPHONY_LOGE("[slot%{public}d]Write action fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(index)) {
        TELEPHONY_LOGE("[slot%{public}d]Write index fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_SET_COLP));
}

int32_t ImsCallProxy::GetColp(int32_t slotId, int32_t index)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteInt32(index)) {
        TELEPHONY_LOGE("[slot%{public}d]Write index fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_GET_COLP));
}

int32_t ImsCallProxy::RegisterImsCallCallback(const sptr<ImsCallCallbackInterface> &callback)
{
    if (callback == nullptr) {
        TELEPHONY_LOGE("callback is null!");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    MessageParcel in;
    if (!in.WriteInterfaceToken(ImsCallProxy::GetDescriptor())) {
        TELEPHONY_LOGE("Write descriptor token fail!");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteRemoteObject(callback->AsObject().GetRefPtr())) {
        TELEPHONY_LOGE("Write ImsCallCallbackInterface fail!");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_CALL_REGISTER_CALLBACK));
}

int32_t ImsCallProxy::UpdateImsCapabilities(int32_t slotId, const ImsCapabilityList &imsCapabilityList)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    int32_t imsCapabilitiesSize = static_cast<int32_t>(imsCapabilityList.imsCapabilities.size());
    if (!in.WriteInt32(imsCapabilitiesSize)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    for (auto imsCapability : imsCapabilityList.imsCapabilities) {
        if (!in.WriteInt32(static_cast<int32_t>(imsCapability.imsCapabilityType))) {
            TELEPHONY_LOGE("[slot%{public}d] Write imsCapabilityType fail!", slotId);
            return TELEPHONY_ERR_WRITE_DATA_FAIL;
        }
        if (!in.WriteInt32(static_cast<int32_t>(imsCapability.imsRadioTech))) {
            TELEPHONY_LOGE("[slot%{public}d] Write imsRadioTech fail!", slotId);
            return TELEPHONY_ERR_WRITE_DATA_FAIL;
        }
        if (!in.WriteBool(imsCapability.enable)) {
            TELEPHONY_LOGE("[slot%{public}d] Write enable fail!", slotId);
            return TELEPHONY_ERR_WRITE_DATA_FAIL;
        }
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_UPDATE_CAPABILITY));
}

int32_t ImsCallProxy::GetUtImpuFromNetwork(int32_t slotId, std::string &impu)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(slotId, __FUNCTION__, in);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    if (!in.WriteString(impu)) {
        TELEPHONY_LOGE("[slot%{public}d]Write impu fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(slotId, in, static_cast<int32_t>(ImsCallInterfaceCode::IMS_GET_IMPU_FROM_NETWORK));
}

int32_t ImsCallProxy::WriteCommonInfo(int32_t slotId, std::string funcName, MessageParcel &in)
{
    if (!in.WriteInterfaceToken(ImsCallProxy::GetDescriptor())) {
        TELEPHONY_LOGE("[slot%{public}d] %{public}s Write descriptor token fail!", slotId, funcName.c_str());
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        TELEPHONY_LOGE("[slot%{public}d] %{public}s Write slotId fail!", slotId, funcName.c_str());
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallProxy::WriteCommonInfo(int32_t slotId, std::string funcName, MessageParcel &in, int32_t callType)
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

int32_t ImsCallProxy::SendRequest(MessageParcel &in, int32_t eventId)
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

int32_t ImsCallProxy::SendRequest(int32_t slotId, MessageParcel &in, int32_t eventId)
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

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
#include "ims_call.h"

#include "ims_radio_event.h"

namespace OHOS {
namespace Telephony {
ImsCall::ImsCall() {}

ImsCall::~ImsCall() {}

bool ImsCall::Init()
{
    TELEPHONY_LOGI("ImsCall Init");

    if (!CreateEventLoop("ImsCallLoop")) {
        TELEPHONY_LOGE("CreateEventLoop failed");
        return false;
    }

    TELEPHONY_LOGI("Init success");
    return true;
}

int32_t ImsCall::Dial(const ImsCallInfo &callInfo, CLIRMode mode)
{
    // IMS demo send request info

    // IMS demo callback response info
    int32_t slotId = callInfo.slotId;
    RadioResponseInfo info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->DialResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::HangUp(const ImsCallInfo &callInfo)
{
    // IMS demo send request info

    // IMS demo callback response info
    int32_t slotId = callInfo.slotId;
    RadioResponseInfo info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->HangUpResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::RejectWithReason(const ImsCallInfo &callInfo, const ImsRejectReason &reason)
{
    // IMS demo send request info

    // IMS demo callback response info
    int32_t slotId = callInfo.slotId;
    RadioResponseInfo info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->RejectWithReasonResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::Answer(const ImsCallInfo &callInfo)
{
    // IMS demo send request info

    // IMS demo callback response info
    int32_t slotId = callInfo.slotId;
    RadioResponseInfo info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->AnswerResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::HoldCall(int32_t slotId, int32_t callType)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->HoldCallResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::UnHoldCall(int32_t slotId, int32_t callType)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->UnHoldCallResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::SwitchCall(int32_t slotId, int32_t callType)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->SwitchCallResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::CombineConference(int32_t slotId)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->CombineConferenceResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::InviteToConference(int32_t slotId, const std::vector<std::string> &numberList)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->InviteToConferenceResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::KickOutFromConference(int32_t slotId, int32_t index)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->HangUpResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::UpdateImsCallMode(const ImsCallInfo &callInfo, ImsCallMode mode)
{
    // IMS demo send request info

    // IMS demo callback response info
    int32_t slotId = callInfo.slotId;
    RadioResponseInfo info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->CallMediaModeResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::GetImsCallsDataRequest(int32_t slotId, int64_t lastCallsDataFlag)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->GetImsCallsDataResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::GetLastCallFailReason(int32_t slotId)
{
    // IMS demo send request info

    // IMS demo callback response info
    DisconnectedDetails details;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->LastCallFailReasonResponse(slotId, details);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::StartDtmf(int32_t slotId, char cDtmfCode, int32_t index)
{
    if (index < 0 || slotId < 0) {
        TELEPHONY_LOGE("Invalid parameter");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->StartDtmfResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::SendDtmf(int32_t slotId, char cDtmfCode, int32_t index)
{
    if (index < 0 || slotId < 0) {
        TELEPHONY_LOGE("Invalid parameter");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->SendDtmfResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::StopDtmf(int32_t slotId, int32_t index)
{
    if (index < 0 || slotId < 0) {
        TELEPHONY_LOGE("Invalid parameter");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->StopDtmfResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::StartRtt(int32_t slotId, const std::string &msg)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->StartRttResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::StopRtt(int32_t slotId)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->StopRttResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::SetDomainPreferenceMode(int32_t slotId, int32_t mode)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->SetPreModeResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::GetDomainPreferenceMode(int32_t slotId)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->GetPreModeResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::SetImsSwitchStatus(int32_t slotId, int32_t active)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->SetImsSwitchResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::GetImsSwitchStatus(int32_t slotId)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->GetImsSwitchResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::SetImsConfig(ImsConfigItem item, const std::string &value)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    int32_t slotId = 0;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->SetImsConfigResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::SetImsConfig(ImsConfigItem item, int32_t value)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    int32_t slotId = 0;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->SetImsConfigResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::GetImsConfig(ImsConfigItem item)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    int32_t slotId = 0;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->GetImsConfigResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::SetImsFeatureValue(FeatureType type, int32_t value)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    int32_t slotId = 0;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->SetImsFeatureValueResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::GetImsFeatureValue(FeatureType type, int32_t &value)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    int32_t slotId = 0;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->GetImsFeatureValueResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::SetMute(int32_t slotId, int32_t mute)
{
    if (mute < 0 || slotId < 0) {
        TELEPHONY_LOGE("Invalid parameter");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }

    // IMS demo send request info

    // IMS demo callback response info
    MuteControlResponse info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->SetMuteResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::GetMute(int32_t slotId)
{
    // IMS demo send request info

    // IMS demo callback response info
    MuteControlResponse info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->GetMuteResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::CtrlCamera(const std::u16string &cameraId, int32_t callingUid, int32_t callingPid)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    int32_t slotId = 0;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->CtrlCameraResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::SetPreviewWindow(int32_t x, int32_t y, int32_t z, int32_t width, int32_t height)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    int32_t slotId = 0;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->SetPreviewWindowResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::SetDisplayWindow(int32_t x, int32_t y, int32_t z, int32_t width, int32_t height)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    int32_t slotId = 0;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->SetDisplayWindowResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::SetCameraZoom(float zoomRatio)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    int32_t slotId = 0;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->SetCameraZoomResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::SetPauseImage(const std::u16string &path)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    int32_t slotId = 0;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->SetPauseImageResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::SetDeviceDirection(int32_t rotation)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    int32_t slotId = 0;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->SetDeviceDirectionResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::SetClip(int32_t slotId, int32_t action)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->SetClipResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::GetClip(int32_t slotId)
{
    // IMS demo send request info

    // IMS demo callback response info
    ClipResponse info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->GetClipResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::SetClir(int32_t slotId, int32_t action)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->SetClirResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::GetClir(int32_t slotId)
{
    // IMS demo send request info

    // IMS demo callback response info
    ClirResponse info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->GetClirResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::SetCallTransfer(
    int32_t slotId, int32_t reason, int32_t mode, const std::string &transferNum, int32_t classType)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->SetCallTransferResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::GetCallTransfer(int32_t slotId, int32_t reason)
{
    // IMS demo send request info

    // IMS demo callback response info
    CallTransferResponse info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->GetCallTransferResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::SetCallRestriction(int32_t slotId, const std::string &fac, int32_t mode, const std::string &pw)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->SetCallRestrictionResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::GetCallRestriction(int32_t slotId, const std::string &fac)
{
    // IMS demo send request info

    // IMS demo callback response info
    CallRestrictionResponse info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->GetCallRestrictionResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::SetCallWaiting(int32_t slotId, bool activate, int32_t classType)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->SetCallWaitingResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::GetCallWaiting(int32_t slotId)
{
    // IMS demo send request info

    // IMS demo callback response info
    CallWaitResponse info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->GetCallWaitingResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::SetColr(int32_t slotId, int32_t presentation)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->SetColrResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::GetColr(int32_t slotId)
{
    // IMS demo send request info

    // IMS demo callback response info
    ColrResponse info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->GetColrResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::SetColp(int32_t slotId, int32_t action)
{
    // IMS demo send request info

    // IMS demo callback response info
    RadioResponseInfo info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->SetColpResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::GetColp(int32_t slotId)
{
    // IMS demo send request info

    // IMS demo callback response info
    ColpResponse info;
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCallCallback is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_->GetColpResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::RegisterImsCallCallback(const sptr<ImsCallCallbackInterface> &callback)
{
    TELEPHONY_LOGI("Register IMS call callback");
    imsCallCallback_ = callback;
    return TELEPHONY_SUCCESS;
}

int32_t ImsCall::UpdateImsCapabilities(int32_t slotId, const ImsCapabilityList &imsCapabilityList)
{
    TELEPHONY_LOGI("entry");
    return TELEPHONY_SUCCESS;
}
} // namespace Telephony
} // namespace OHOS

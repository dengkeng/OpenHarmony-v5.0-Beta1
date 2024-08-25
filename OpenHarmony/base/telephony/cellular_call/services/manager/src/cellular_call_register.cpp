/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "cellular_call_register.h"

#include "cellular_call_hisysevent.h"
#include "core_manager_inner.h"
#include "hitrace_meter.h"
#include "iservice_registry.h"

namespace OHOS {
namespace Telephony {
constexpr size_t CHAR_LENG = 1;

CellularCallRegister::CellularCallRegister() : callManagerCallBack_(nullptr) {}

CellularCallRegister::~CellularCallRegister() {}

void CellularCallRegister::ReportCallsInfo(const CallsReportInfo &callsReportInfo)
{
    TELEPHONY_LOGD("ReportCallsInfo entry.");
    CallsReportInfo callsInfo = callsReportInfo;
    CallDetailInfo detailInfo;
    detailInfo.state = TelCallState::CALL_STATUS_UNKNOWN;
    std::vector<CallReportInfo>::iterator it = callsInfo.callVec.begin();
    for (; it != callsInfo.callVec.end(); ++it) {
        detailInfo.callType = (*it).callType;
        detailInfo.accountId = (*it).accountId;
        detailInfo.state = (*it).state;
        detailInfo.callMode = (*it).callMode;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportCallsInfo return, callManagerCallBack_ is nullptr, report fail!");
        if (detailInfo.state == TelCallState::CALL_STATUS_INCOMING) {
            FinishAsyncTrace(HITRACE_TAG_OHOS, "CellularCallIncoming", getpid());
        }
        return;
    }
    CoreManagerInner::GetInstance().NotifyCallStatusToNetworkSearch(
        detailInfo.accountId, static_cast<int32_t>(detailInfo.state));
    if (detailInfo.state == TelCallState::CALL_STATUS_INCOMING) {
        DelayedSingleton<CellularCallHiSysEvent>::GetInstance()->SetIncomingCallParameterInfo(
            static_cast<int32_t>(detailInfo.callType), static_cast<int32_t>(detailInfo.callMode));
        FinishAsyncTrace(HITRACE_TAG_OHOS, "CellularCallIncoming", getpid());
    }
    callManagerCallBack_->UpdateCallsReportInfo(callsReportInfo);
}

int32_t CellularCallRegister::RegisterCallManagerCallBack(const sptr<ICallStatusCallback> &callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    callManagerCallBack_ = callback;
    return TELEPHONY_SUCCESS;
}

void CellularCallRegister::ReportSingleCallInfo(const CallReportInfo &info, TelCallState callState)
{
    TELEPHONY_LOGD("ReportSingleCallInfo entry");
    CallReportInfo cellularCallReportInfo = info;
    cellularCallReportInfo.state = callState;
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportSingleCallInfo return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    callManagerCallBack_->UpdateCallReportInfo(cellularCallReportInfo);
}

int32_t CellularCallRegister::UnRegisterCallManagerCallBack()
{
    std::lock_guard<std::mutex> lock(mutex_);
    callManagerCallBack_ = nullptr;
    return TELEPHONY_SUCCESS;
}

void CellularCallRegister::ReportEventResultInfo(const CellularCallEventInfo &info)
{
    TELEPHONY_LOGI("ReportEventResultInfo entry eventId:%{public}d", info.eventId);
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportEventResultInfo return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    callManagerCallBack_->UpdateEventResultInfo(info);
}

void CellularCallRegister::ReportGetWaitingResult(const CallWaitResponse &response)
{
    TELEPHONY_LOGI("ReportGetWaitingResult result:%{public}d, status:%{public}d, class:%{public}d", response.result,
        response.status, response.classCw);
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportGetWaitingResult return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    callManagerCallBack_->UpdateGetWaitingResult(response);
}

void CellularCallRegister::ReportSetWaitingResult(int32_t result)
{
    TELEPHONY_LOGI("ReportSetWaitingResult result:%{public}d", result);
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportSetWaitingResult return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    callManagerCallBack_->UpdateSetWaitingResult(result);
}

void CellularCallRegister::ReportGetRestrictionResult(const CallRestrictionResponse &response)
{
    TELEPHONY_LOGI("ReportGetRestrictionResult result:%{public}d, status:%{public}d, class:%{public}d",
        response.result, response.status, response.classCw);
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportGetRestrictionResult return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    callManagerCallBack_->UpdateGetRestrictionResult(response);
}

void CellularCallRegister::ReportSetRestrictionResult(int32_t result)
{
    TELEPHONY_LOGI("ReportSetRestrictionResult result:%{public}d", result);
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportSetRestrictionResult return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    callManagerCallBack_->UpdateSetRestrictionResult(result);
}

void CellularCallRegister::ReportGetTransferResult(const CallTransferResponse &response)
{
    TELEPHONY_LOGI("ReportGetTransferResult result:%{public}d, status:%{public}d, class:%{public}d", response.result,
        response.status, response.classx);
    TELEPHONY_LOGI("ReportGetTransferResult type:%{public}d, reason:%{public}d, time:%{public}d",
        response.type, response.reason, response.time);
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportGetTransferResult return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    callManagerCallBack_->UpdateGetTransferResult(response);
}

void CellularCallRegister::ReportSetBarringPasswordResult(int32_t result)
{
    TELEPHONY_LOGI("Set barring password result:%{public}d", result);
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    callManagerCallBack_->UpdateSetRestrictionPasswordResult(result);
}

void CellularCallRegister::ReportSetTransferResult(int32_t result)
{
    TELEPHONY_LOGI("ReportSetTransferResult result:%{public}d", result);
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportSetTransferResult return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    callManagerCallBack_->UpdateSetTransferResult(result);
}

void CellularCallRegister::ReportGetClipResult(const ClipResponse &response)
{
    TELEPHONY_LOGI("ReportGetClipResult result:%{public}d, action:%{public}d, stat:%{public}d", response.result,
        response.action, response.clipStat);
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportGetClipResult return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    callManagerCallBack_->UpdateGetCallClipResult(response);
}

void CellularCallRegister::ReportGetClirResult(const ClirResponse &response)
{
    TELEPHONY_LOGI("ReportGetClirResult result:%{public}d, action:%{public}d, stat:%{public}d", response.result,
        response.action, response.clirStat);
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportGetClirResult return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    callManagerCallBack_->UpdateGetCallClirResult(response);
}

void CellularCallRegister::ReportSetClirResult(int32_t result)
{
    TELEPHONY_LOGI("ReportSetClirResult result:%{public}d", result);
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportSetClirResult return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    callManagerCallBack_->UpdateSetCallClirResult(result);
}

void CellularCallRegister::ReportGetImsConfigResult(const GetImsConfigResponse &response)
{
    TELEPHONY_LOGI("ReportGetImsConfigResult entry, value:%{public}d", response.value);
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportGetImsConfigResult return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    callManagerCallBack_->GetImsConfigResult(response);
}

void CellularCallRegister::ReportSetImsConfigResult(int32_t result)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportSetImsConfigResult return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    callManagerCallBack_->SetImsConfigResult(result);
}

void CellularCallRegister::ReportSetImsFeatureResult(int32_t result)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportSetImsFeatureResult return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    callManagerCallBack_->SetImsFeatureValueResult(result);
}

void CellularCallRegister::ReportGetImsFeatureResult(const GetImsFeatureValueResponse &response)
{
    TELEPHONY_LOGI("ReportGetImsFeatureResult entry, value:%{public}d", response.value);
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportGetImsFeatureResult return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    callManagerCallBack_->GetImsFeatureValueResult(response);
}

void CellularCallRegister::ReportCallRingBackResult(int32_t status)
{
    TELEPHONY_LOGI("ReportCallRingBackResult entry");
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportCallRingBackResult return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    callManagerCallBack_->UpdateRBTPlayInfo(static_cast<RBTPlayInfo>(status));
}

void CellularCallRegister::ReportCallFailReason(const DisconnectedDetails &details)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportCallFailReason return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    callManagerCallBack_->UpdateDisconnectedCause(details);
}

void CellularCallRegister::ReportGetMuteResult(const MuteControlResponse &response)
{
    TELEPHONY_LOGI("ReportGetMuteResult entry result:%{public}d, value:%{public}d", response.result, response.value);
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportMuteResult return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
}

void CellularCallRegister::ReportSetMuteResult(const MuteControlResponse &response)
{
    TELEPHONY_LOGI("ReportSetMuteResult entry result:%{public}d, value:%{public}d", response.result, response.value);
}

void CellularCallRegister::ReportInviteToConferenceResult(int32_t result)
{
    TELEPHONY_LOGI("ReportInviteToConferenceResult entry result:%{public}d", result);
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportInviteToConferenceResult return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    callManagerCallBack_->InviteToConferenceResult(result);
}

void CellularCallRegister::ReportGetCallDataResult(int32_t result)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportGetCallDataResult return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    callManagerCallBack_->GetImsCallDataResult(result);
}

void CellularCallRegister::ReportStartDtmfResult(int32_t result)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportStartDtmfResult return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    callManagerCallBack_->StartDtmfResult(result);
}

void CellularCallRegister::ReportStopDtmfResult(int32_t result)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportStopDtmfResult return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    callManagerCallBack_->StopDtmfResult(result);
}

void CellularCallRegister::ReportStartRttResult(int32_t result)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportStartRttResult return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    callManagerCallBack_->StartRttResult(result);
}

void CellularCallRegister::ReportStopRttResult(int32_t result)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportStopRttResult return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    callManagerCallBack_->StopRttResult(result);
}

void CellularCallRegister::ReportSendUssdResult(int32_t result)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportSendUssdResult return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    callManagerCallBack_->SendUssdResult(result);
}

void CellularCallRegister::ReportMmiCodeResult(const MmiCodeInfo &info)
{
    TELEPHONY_LOGI("ReportMmiCodeResult entry result:%{public}d, value:%{public}s", info.result, info.message);
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportMmiCodeResult return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    callManagerCallBack_->SendMmiCodeResult(info);
}

void CellularCallRegister::ReportSetEmergencyCallListResponse(const SetEccListResponse &response)
{
    TELEPHONY_LOGD("ReportSetEmergencyCallListResponse entry result:%{public}d, value:%{public}d", response.result,
        response.value);
}

bool CellularCallRegister::IsCallManagerCallBackRegistered()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return callManagerCallBack_ != nullptr;
}

void CellularCallRegister::ReportCloseUnFinishedUssdResult(int32_t result)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportCloseUnFinishedUssdResult return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    callManagerCallBack_->CloseUnFinishedUssdResult(result);
}

void CellularCallRegister::ReportPostDialChar(char c)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportPostDialChar return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    std::string nextDtmf(CHAR_LENG, c);
    callManagerCallBack_->ReportPostDialChar(nextDtmf);
}

void CellularCallRegister::ReportPostDialDelay(std::string str)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReportPostDialChar return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    callManagerCallBack_->ReportPostDialDelay(str);
}

void CellularCallRegister::ReceiveUpdateCallMediaModeRequest(ImsCallModeReceiveInfo &callModeInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReceiveUpdateCallMediaModeRequest return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    CallModeReportInfo response;
    response.callIndex = callModeInfo.callIndex;
    response.result = static_cast<VideoRequestResultType>(callModeInfo.result);
    ImsCallMode callMode = ConverToImsCallMode(callModeInfo.callType);
    response.callMode = callMode;
    callManagerCallBack_->ReceiveUpdateCallMediaModeRequest(response);
}

void CellularCallRegister::ReceiveUpdateCallMediaModeResponse(ImsCallModeReceiveInfo &callModeInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("ReceiveUpdateCallMediaModeResponse return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    CallModeReportInfo response;
    response.callIndex = callModeInfo.callIndex;
    response.result = static_cast<VideoRequestResultType>(callModeInfo.result);
    ImsCallMode callMode = ConverToImsCallMode(callModeInfo.callType);
    response.callMode = callMode;
    callManagerCallBack_->ReceiveUpdateCallMediaModeResponse(response);
}

void CellularCallRegister::HandleCallSessionEventChanged(ImsCallSessionEventInfo &callSessionEventInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("HandleCallSessionEventChanged return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    CallSessionReportInfo response;
    response.index = callSessionEventInfo.callIndex;
    response.eventId = static_cast<CallSessionEventId>(callSessionEventInfo.eventType);
    callManagerCallBack_->HandleCallSessionEventChanged(response);
}

void CellularCallRegister::HandlePeerDimensionsChanged(ImsCallPeerDimensionsInfo &callPeerDimensionsInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("HandlePeerDimensionsChanged return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    PeerDimensionsReportInfo response;
    response.index = callPeerDimensionsInfo.callIndex;
    response.width = callPeerDimensionsInfo.width;
    response.height = callPeerDimensionsInfo.height;
    callManagerCallBack_->HandlePeerDimensionsChanged(response);
}

void CellularCallRegister::HandleCallDataUsageChanged(ImsCallDataUsageInfo &callDataUsageInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("HandleCallDataUsageChanged return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    int64_t response = callDataUsageInfo.dataUsage;
    callManagerCallBack_->HandleCallDataUsageChanged(response);
}

void CellularCallRegister::HandleCameraCapabilitiesChanged(CameraCapabilitiesInfo &cameraCapabilitiesInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callManagerCallBack_ == nullptr) {
        TELEPHONY_LOGE("HandleCameraCapabilitiesChanged return, callManagerCallBack_ is nullptr, report fail!");
        return;
    }
    CameraCapabilitiesReportInfo response;
    response.index = cameraCapabilitiesInfo.callIndex;
    response.width = cameraCapabilitiesInfo.width;
    response.height = cameraCapabilitiesInfo.height;
    callManagerCallBack_->HandleCameraCapabilitiesChanged(response);
}

ImsCallMode CellularCallRegister::ConverToImsCallMode(ImsCallType callType)
{
    ImsCallMode callMode = ImsCallMode::CALL_MODE_AUDIO_ONLY;
    switch (callType) {
        case ImsCallType::TEL_IMS_CALL_TYPE_VOICE:
            callMode = ImsCallMode::CALL_MODE_AUDIO_ONLY;
            break;
        case ImsCallType::TEL_IMS_CALL_TYPE_VT_TX:
            callMode = ImsCallMode::CALL_MODE_SEND_ONLY;
            break;
        case ImsCallType::TEL_IMS_CALL_TYPE_VT_RX:
            callMode = ImsCallMode::CALL_MODE_RECEIVE_ONLY;
            break;
        case ImsCallType::TEL_IMS_CALL_TYPE_VT:
            callMode = ImsCallMode::CALL_MODE_SEND_RECEIVE;
            break;
        case ImsCallType::TEL_IMS_CALL_TYPE_PAUSE:
            callMode = ImsCallMode::CALL_MODE_VIDEO_PAUSED;
            break;
        default:
            TELEPHONY_LOGE("unknown callType");
            break;
    }
    return callMode;
}
} // namespace Telephony
} // namespace OHOS

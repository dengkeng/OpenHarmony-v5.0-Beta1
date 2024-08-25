/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "cellular_call_connection_cs.h"

#include "cellular_call_hisysevent.h"
#include "cellular_call_service.h"
#include "radio_event.h"
#include "standardize_utils.h"

namespace OHOS {
namespace Telephony {
int32_t CellularCallConnectionCS::DialRequest(int32_t slotId, const DialRequestStruct &dialRequest)
{
    TELEPHONY_LOGI("CellularCallConnectionCS::DialRequest start.");
    if (DelayedSingleton<CellularCallService>::GetInstance() == nullptr) {
        TELEPHONY_LOGE("DialRequest return, error type: GetInstance() is nullptr.");
        CellularCallHiSysEvent::WriteDialCallFaultEvent(
            slotId, INVALID_PARAMETER, INVALID_PARAMETER, CALL_ERR_RESOURCE_UNAVAILABLE, "cellular service is nullptr");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    auto handle = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handle == nullptr) {
        TELEPHONY_LOGE("DialRequest return, error type: handle is nullptr.");
        CellularCallHiSysEvent::WriteDialCallFaultEvent(slotId, INVALID_PARAMETER, INVALID_PARAMETER,
            CALL_ERR_RESOURCE_UNAVAILABLE, "cellular service handle is nullptr");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    UpdateCallNumber(dialRequest.phoneNum);
    CoreManagerInner::GetInstance().Dial(
        slotId, RadioEvent::RADIO_DIAL, phoneNumber_, dialRequest.clirMode, handle);
    phoneNumber_.clear();
    return TELEPHONY_SUCCESS;
}

int32_t CellularCallConnectionCS::HangUpRequest(int32_t slotId)
{
    TELEPHONY_LOGI("CellularCallConnectionCS::HangUpRequest start.");
    if (DelayedSingleton<CellularCallService>::GetInstance() == nullptr) {
        TELEPHONY_LOGE("HangUpRequest return, error type: GetInstance() is nullptr.");
        CellularCallHiSysEvent::WriteHangUpFaultEvent(
            slotId, INVALID_PARAMETER, CALL_ERR_RESOURCE_UNAVAILABLE, "cellular service is nullptr");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    auto handle = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handle == nullptr) {
        TELEPHONY_LOGE("HangUpRequest return, error type: handle is nullptr.");
        CellularCallHiSysEvent::WriteHangUpFaultEvent(
            slotId, INVALID_PARAMETER, CALL_ERR_RESOURCE_UNAVAILABLE, "cellular service handle is nullptr");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    int32_t index = GetIndex();
    CoreManagerInner::GetInstance().Hangup(slotId, RadioEvent::RADIO_HANGUP_CONNECT, index, handle);
    return TELEPHONY_SUCCESS;
}

int32_t CellularCallConnectionCS::AnswerRequest(int32_t slotId)
{
    TELEPHONY_LOGI("CellularCallConnectionCS::AnswerRequest start.");
    if (DelayedSingleton<CellularCallService>::GetInstance() == nullptr) {
        TELEPHONY_LOGE("AnswerRequest return, error type: GetInstance() is nullptr.");
        CellularCallHiSysEvent::WriteAnswerCallFaultEvent(
            slotId, INVALID_PARAMETER, INVALID_PARAMETER, CALL_ERR_RESOURCE_UNAVAILABLE, "cellular service is nullptr");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    auto handle = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handle == nullptr) {
        TELEPHONY_LOGE("AnswerRequest return, error type: handle is nullptr.");
        CellularCallHiSysEvent::WriteAnswerCallFaultEvent(slotId, INVALID_PARAMETER, INVALID_PARAMETER,
            CALL_ERR_RESOURCE_UNAVAILABLE, "cellular service handle is nullptr");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    CoreManagerInner::GetInstance().SetMute(slotId, RadioEvent::RADIO_SET_CMUT, false, handle);
    CoreManagerInner::GetInstance().Answer(slotId, RadioEvent::RADIO_ACCEPT_CALL, handle);
    return TELEPHONY_SUCCESS;
}

int32_t CellularCallConnectionCS::RejectRequest(int32_t slotId)
{
    TELEPHONY_LOGI("CellularCallConnectionCS::RejectRequest start.");
    if (DelayedSingleton<CellularCallService>::GetInstance() == nullptr) {
        TELEPHONY_LOGE("RejectRequest return, error type: GetInstance() is nullptr.");
        CellularCallHiSysEvent::WriteHangUpFaultEvent(
            slotId, INVALID_PARAMETER, CALL_ERR_RESOURCE_UNAVAILABLE, "cellular service is nullptr");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    auto handle = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handle == nullptr) {
        TELEPHONY_LOGE("RejectRequest return, error type: handle is nullptr.");
        CellularCallHiSysEvent::WriteHangUpFaultEvent(
            slotId, INVALID_PARAMETER, CALL_ERR_RESOURCE_UNAVAILABLE, "cellular service handle is nullptr");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    CoreManagerInner::GetInstance().Reject(slotId, RadioEvent::RADIO_REJECT_CALL, handle);
    return TELEPHONY_SUCCESS;
}

int32_t CellularCallConnectionCS::HoldRequest(int32_t slotId)
{
    TELEPHONY_LOGI("CellularCallConnectionCS::HoldRequest start.");
    if (DelayedSingleton<CellularCallService>::GetInstance() == nullptr) {
        TELEPHONY_LOGE("HoldRequest return, error type: GetInstance() is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    auto handle = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handle == nullptr) {
        TELEPHONY_LOGE("HoldRequest return, error type: handle is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    CoreManagerInner::GetInstance().HoldCall(slotId, RadioEvent::RADIO_HOLD_CALL, handle);
    return TELEPHONY_SUCCESS;
}

int32_t CellularCallConnectionCS::UnHoldCallRequest(int32_t slotId)
{
    TELEPHONY_LOGI("CellularCallConnectionCS::UnHoldCallRequest start.");
    if (DelayedSingleton<CellularCallService>::GetInstance() == nullptr) {
        TELEPHONY_LOGE("UnHoldCallRequest return, error type: GetInstance() is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    auto handle = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handle == nullptr) {
        TELEPHONY_LOGE("UnHoldCallRequest return, error type: handle is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    CoreManagerInner::GetInstance().UnHoldCall(slotId, RadioEvent::RADIO_ACTIVE_CALL, handle);
    return TELEPHONY_SUCCESS;
}

int32_t CellularCallConnectionCS::SwitchCallRequest(int32_t slotId)
{
    TELEPHONY_LOGI("CellularCallConnectionCS::SwitchCallRequest start.");
    if (DelayedSingleton<CellularCallService>::GetInstance() == nullptr) {
        TELEPHONY_LOGE("SwitchCallRequest return, error type: GetInstance() is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    auto handle = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handle == nullptr) {
        TELEPHONY_LOGE("SwitchCallRequest return, error type: handle is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    CoreManagerInner::GetInstance().SwitchCall(slotId, RadioEvent::RADIO_SWAP_CALL, handle);
    return TELEPHONY_SUCCESS;
}

int32_t CellularCallConnectionCS::CombineConferenceRequest(int32_t slotId, int32_t voiceCall)
{
    TELEPHONY_LOGI("CellularCallConnectionCS::CombineConferenceRequest start.");
    if (DelayedSingleton<CellularCallService>::GetInstance() == nullptr) {
        TELEPHONY_LOGE("CombineConferenceRequest return, error type: GetInstance() is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    auto handle = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handle == nullptr) {
        TELEPHONY_LOGE("CombineConferenceRequest return, error type: handle is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    CoreManagerInner::GetInstance().CombineConference(slotId, RadioEvent::RADIO_JOIN_CALL, voiceCall, handle);
    return TELEPHONY_SUCCESS;
}

int32_t CellularCallConnectionCS::SeparateConferenceRequest(int32_t slotId, int32_t index, int32_t voiceCall)
{
    TELEPHONY_LOGI("CellularCallConnectionCS::SeparateConferenceRequest start.");
    if (DelayedSingleton<CellularCallService>::GetInstance() == nullptr) {
        TELEPHONY_LOGE("SeparateConferenceRequest return, error type: GetInstance() is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    auto handle = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handle == nullptr) {
        TELEPHONY_LOGE("SeparateConferenceRequest return, error type: handle is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    CoreManagerInner::GetInstance().SeparateConference(slotId, RadioEvent::RADIO_SPLIT_CALL, index, voiceCall, handle);
    return TELEPHONY_SUCCESS;
}

int32_t CellularCallConnectionCS::CallSupplementRequest(int32_t slotId, CallSupplementType type)
{
    TELEPHONY_LOGI("CellularCallConnectionCS::CallSupplementRequest start.");
    if (DelayedSingleton<CellularCallService>::GetInstance() == nullptr) {
        TELEPHONY_LOGE("CallSupplementRequest return, error type: GetInstance() is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    auto handle = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handle == nullptr) {
        TELEPHONY_LOGE("CallSupplementRequest return, error type: handle is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    CoreManagerInner::GetInstance().CallSupplement(slotId, RadioEvent::RADIO_CALL_SUPPLEMENT, type, handle);
    return TELEPHONY_SUCCESS;
}

int32_t CellularCallConnectionCS::SendCDMAThreeWayDialRequest(int32_t slotId)
{
    TELEPHONY_LOGI("CellularCallConnectionCS::SendCDMAThreeWayDialRequest start.");
    return TELEPHONY_SUCCESS;
}

int32_t CellularCallConnectionCS::SendDtmfRequest(int32_t slotId, char cDtmfCode, int32_t index) const
{
    TELEPHONY_LOGI("CellularCallConnectionCS::SendDtmfRequest start.");
    if (DelayedSingleton<CellularCallService>::GetInstance() == nullptr) {
        TELEPHONY_LOGE("SendDtmfRequest return, error type: GetInstance() is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    auto handle = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handle == nullptr) {
        TELEPHONY_LOGE("SendDtmfRequest return, error type: handle is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    CoreManagerInner::GetInstance().SendDTMF(slotId, RadioEvent::RADIO_SEND_DTMF, cDtmfCode, index, handle);
    return TELEPHONY_SUCCESS;
}

int32_t CellularCallConnectionCS::StartDtmfRequest(int32_t slotId, char cDtmfCode, int32_t index) const
{
    TELEPHONY_LOGD("CellularCallConnectionCS::StartDtmfRequest start.");
    if (DelayedSingleton<CellularCallService>::GetInstance() == nullptr) {
        TELEPHONY_LOGE("StartDtmfRequest return, error type: GetInstance() is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    auto handle = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handle == nullptr) {
        TELEPHONY_LOGE("StartDtmfRequest return, error type: handle is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    CoreManagerInner::GetInstance().StartDTMF(slotId, RadioEvent::RADIO_START_DTMF, cDtmfCode, index, handle);
    return TELEPHONY_SUCCESS;
}

int32_t CellularCallConnectionCS::StopDtmfRequest(int32_t slotId, int32_t index) const
{
    TELEPHONY_LOGI("CellularCallConnectionCS::StopDtmfRequest start.");
    if (DelayedSingleton<CellularCallService>::GetInstance() == nullptr) {
        TELEPHONY_LOGE("StopDtmfRequest return, error type: GetInstance() is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    auto handle = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handle == nullptr) {
        TELEPHONY_LOGE("StopDtmfRequest return, error type: handle is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    CoreManagerInner::GetInstance().StopDTMF(slotId, RadioEvent::RADIO_STOP_DTMF, index, handle);
    return TELEPHONY_SUCCESS;
}

int32_t CellularCallConnectionCS::GetCsCallsDataRequest(int32_t slotId, int64_t lastCallsDataFlag)
{
    TELEPHONY_LOGD("CellularCallConnectionCS::GetCsCallsDataRequest start.");
    if (DelayedSingleton<CellularCallService>::GetInstance() == nullptr) {
        TELEPHONY_LOGE("GetCsCallsDataRequest return, error type: GetInstance() is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    auto handle = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handle == nullptr) {
        TELEPHONY_LOGE("GetCsCallsDataRequest return, error type: handle is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }

    // Implementation
    // Optional. Recommended when +CHLD command is implemented.
    CoreManagerInner::GetInstance().GetCallList(slotId, RadioEvent::RADIO_CURRENT_CALLS, handle);
    return TELEPHONY_SUCCESS;
}

int32_t CellularCallConnectionCS::GetCallFailReasonRequest(int32_t slotId) const
{
    TELEPHONY_LOGD("CellularCallConnectionCS::GetCallFailReasonRequest start.");
    if (DelayedSingleton<CellularCallService>::GetInstance() == nullptr) {
        TELEPHONY_LOGE("GetCallFailReasonRequest return, error type: GetInstance() is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    auto handle = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handle == nullptr) {
        TELEPHONY_LOGE("GetCallFailReasonRequest return, error type: handle is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    CoreManagerInner::GetInstance().GetCallFailReason(slotId, RadioEvent::RADIO_GET_CALL_FAIL_REASON, handle);
    return TELEPHONY_SUCCESS;
}

void CellularCallConnectionCS::RegisterHandler()
{
    DelayedSingleton<CellularCallService>::GetInstance()->RegisterHandler();
}

int32_t CellularCallConnectionCS::ProcessPostDialCallChar(int32_t slotId, char c)
{
    if (StandardizeUtils::IsDtmfKey(c)) {
        SendDtmfRequest(slotId, c, GetIndex());
    } else if (StandardizeUtils::IsPauseKey(c)) {
        SetPostDialCallState(PostDialCallState::POST_DIAL_CALL_PAUSE);
        auto cellularCallHandle = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
        if (cellularCallHandle == nullptr) {
            TELEPHONY_LOGE("SendDtmfRequest return, error type: handle is nullptr.");
            return CALL_ERR_RESOURCE_UNAVAILABLE;
        }
        std::shared_ptr<PostDialData> postDial = std::make_shared<PostDialData>();
        postDial->callId = GetIndex();
        postDial->isIms = false;
        cellularCallHandle->SendEvent(EVENT_EXECUTE_POST_DIAL, postDial, PAUSE_DELAY_TIME);
    } else if (StandardizeUtils::IsWaitKey(c)) {
        SetPostDialCallState(PostDialCallState::POST_DIAL_CALL_DELAY);
    }
    return TELEPHONY_SUCCESS;
}
} // namespace Telephony
} // namespace OHOS

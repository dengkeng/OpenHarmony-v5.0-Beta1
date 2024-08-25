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

#include "cellular_call_hisysevent.h"

#include <securec.h>

#include "call_manager_errors.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
// EVENT
static constexpr const char *CALL_INCOMING_FAILED_EVENT = "CALL_INCOMING_FAILED";
static constexpr const char *CALL_DIAL_FAILED_EVENT = "CALL_DIAL_FAILED";
static constexpr const char *CALL_ANSWER_FAILED_EVENT = "CALL_ANSWER_FAILED";
static constexpr const char *CALL_HANGUP_FAILED_EVENT = "CALL_HANGUP_FAILED";
static constexpr const char *DIAL_EVENT = "DIAL";
static constexpr const char *ANSWER_EVENT = "ANSWER";
static constexpr const char *HANG_UP_EVENT = "HANG_UP";
static constexpr const char *CALL_END_EXCEPTION_EVENT = "CALL_END_EXCEPTION";
static constexpr const char *FOUNDATION_RESTART_EVENT = "FOUNDATION_RESTART";
static constexpr const char *VONR_SWITCH_STATE_EVENT = "VONR_SWITCH_STATE";
static constexpr const char *CALL_MODE_SEND_REQUEST_EVENT = "CALL_MODE_SEND_REQUEST";
static constexpr const char *CALL_MODE_SEND_RESPONSE_EVENT = "CALL_MODE_SEND_RESPONSE";
static constexpr const char *CALL_MODE_RECEIVE_RESPONSE_EVENT = "CALL_MODE_RECEIVE_RESPONSE";
static constexpr const char *CALL_MODE_RECEIVE_REQUEST_EVENT = "CALL_MODE_RECEIVE_REQUEST";

// KEY
static constexpr const char *MODULE_NAME_KEY = "MODULE";
static constexpr const char *SLOT_ID_KEY = "SLOT_ID";
static constexpr const char *CALL_ID_KEY = "CALL_ID";
static constexpr const char *CALL_TYPE_KEY = "CALL_TYPE";
static constexpr const char *VIDEO_STATE_KEY = "VIDEO_STATE";
static constexpr const char *RESULT_KEY = "RESULT";
static constexpr const char *FAIL_CAUSE_KEY = "FAIL_CAUSE";
static constexpr const char *ERROR_TYPE_KEY = "ERROR_TYPE";
static constexpr const char *ERROR_MSG_KEY = "ERROR_MSG";
static constexpr const char *RESTART_COUNT_KEY = "RESTART_COUNT";
static constexpr const char *SWITCH_KEY = "SWITCH_KEY";

// VALUE
static constexpr const char *CELLULAR_CALL_MODULE = "CELLULAR_CALL";
static const int32_t INVALID_VALUE = -1;
static const int32_t CS_CALL_TYPE = 0;
static const int32_t IMS_CALL_TYPE = 1;
static const int32_t VOICE_TYPE = 0;
static const int32_t VIDEO_TYPE = 1;

void CellularCallHiSysEvent::WriteFoundationRestartFaultEvent(const int32_t count)
{
    HiWriteFaultEvent(FOUNDATION_RESTART_EVENT, RESTART_COUNT_KEY, count);
}

void CellularCallHiSysEvent::WriteCallEndBehaviorEvent(const int32_t slotId, const int32_t cause)
{
    HiWriteBehaviorEvent(CALL_END_EXCEPTION_EVENT, SLOT_ID_KEY, slotId, FAIL_CAUSE_KEY, cause);
}

void CellularCallHiSysEvent::WriteDialCallBehaviorEvent(
    const CallBehaviorParameterInfo &info, const CallResponseResult &result)
{
    int32_t type = 0;
    if (info.callType == CS_CALL_TYPE && info.videoState == VOICE_TYPE) {
        type = static_cast<int32_t>(DialCallType::CS_VOICE_DIAL);
    } else if (info.callType == IMS_CALL_TYPE && info.videoState == VOICE_TYPE) {
        type = static_cast<int32_t>(DialCallType::IMS_VOICE_DIAL);
    } else if (info.callType == IMS_CALL_TYPE && info.videoState == VIDEO_TYPE) {
        type = static_cast<int32_t>(DialCallType::IMS_VIDEO_DIAL);
    } else {
        TELEPHONY_LOGE("WriteDialCallBehaviorEvent callType is out of range!");
        return;
    }
    HiWriteBehaviorEvent(
        DIAL_EVENT, SLOT_ID_KEY, info.slotId, CALL_TYPE_KEY, type, RESULT_KEY, static_cast<int32_t>(result));
}

void CellularCallHiSysEvent::WriteHangUpCallBehaviorEvent(
    const CallBehaviorParameterInfo &info, const CallResponseResult &result)
{
    int32_t type = 0;
    if (info.callType == CS_CALL_TYPE && info.videoState == VOICE_TYPE) {
        type = static_cast<int32_t>(HangUpCallType::CS_VOICE_CALL);
    } else if (info.callType == IMS_CALL_TYPE && info.videoState == VOICE_TYPE) {
        type = static_cast<int32_t>(HangUpCallType::IMS_VOICE_CALL);
    } else if (info.callType == IMS_CALL_TYPE && info.videoState == VIDEO_TYPE) {
        type = static_cast<int32_t>(HangUpCallType::IMS_VIDEO_CALL);
    } else {
        TELEPHONY_LOGE("WriteHangUpCallBehaviorEvent callType is out of range!");
        return;
    }
    HiWriteBehaviorEvent(
        HANG_UP_EVENT, SLOT_ID_KEY, info.slotId, CALL_TYPE_KEY, type, RESULT_KEY, static_cast<int32_t>(result));
}

void CellularCallHiSysEvent::WriteAnswerCallBehaviorEvent(
    const CallBehaviorParameterInfo &info, const CallResponseResult &result)
{
    int32_t type = 0;
    if (info.incomingCallType == IMS_CALL_TYPE && info.incomingVideoState == VOICE_TYPE &&
        info.callType == IMS_CALL_TYPE && info.videoState == VOICE_TYPE) {
        type = static_cast<int32_t>(AnswerCallType::IMS_VOICE_ANSWER);
    } else if (info.incomingCallType == IMS_CALL_TYPE && info.incomingVideoState == VIDEO_TYPE &&
               info.callType == IMS_CALL_TYPE && info.videoState == VOICE_TYPE) {
        type = static_cast<int32_t>(AnswerCallType::IMS_VIDEO_TO_VOICE_ANSWER);
    } else if (info.incomingCallType == IMS_CALL_TYPE && info.incomingVideoState == VIDEO_TYPE &&
               info.callType == IMS_CALL_TYPE && info.videoState == VIDEO_TYPE) {
        type = static_cast<int32_t>(AnswerCallType::IMS_VIDEO_TO_VIDEO_ANSWER);
    } else if (info.incomingCallType == CS_CALL_TYPE && info.incomingVideoState == VOICE_TYPE &&
               info.callType == CS_CALL_TYPE && info.videoState == VOICE_TYPE) {
        type = static_cast<int32_t>(AnswerCallType::CS_VOICE_ANSWER);
    } else {
        TELEPHONY_LOGE("WriteAnswerCallBehaviorEvent callType is out of range!");
        return;
    }
    HiWriteBehaviorEvent(
        ANSWER_EVENT, SLOT_ID_KEY, info.slotId, CALL_TYPE_KEY, type, RESULT_KEY, static_cast<int32_t>(result));
}

void CellularCallHiSysEvent::WriteIncomingCallFaultEvent(const int32_t slotId, const int32_t callType,
    const int32_t videoState, const int32_t errCode, const std::string &desc)
{
    CallErrorCode value = CallErrorCode::CALL_ERROR_NONE;
    if (ErrorCodeConversion(errCode, value)) {
        HiWriteFaultEvent(CALL_INCOMING_FAILED_EVENT, MODULE_NAME_KEY, CELLULAR_CALL_MODULE, SLOT_ID_KEY, slotId,
            CALL_TYPE_KEY, callType, VIDEO_STATE_KEY, videoState, ERROR_TYPE_KEY, static_cast<int32_t>(value),
            ERROR_MSG_KEY, desc);
    } else {
        HiWriteFaultEvent(CALL_INCOMING_FAILED_EVENT, MODULE_NAME_KEY, CELLULAR_CALL_MODULE, SLOT_ID_KEY, slotId,
            CALL_TYPE_KEY, callType, VIDEO_STATE_KEY, videoState, ERROR_TYPE_KEY, errCode, ERROR_MSG_KEY, desc);
    }
}

void CellularCallHiSysEvent::WriteDialCallFaultEvent(const int32_t slotId, const int32_t callType,
    const int32_t videoState, const int32_t errorCode, const std::string &desc)
{
    CallErrorCode value = CallErrorCode::CALL_ERROR_NONE;
    if (ErrorCodeConversion(errorCode, value)) {
        HiWriteFaultEvent(CALL_DIAL_FAILED_EVENT, MODULE_NAME_KEY, CELLULAR_CALL_MODULE, SLOT_ID_KEY, slotId,
            CALL_TYPE_KEY, callType, VIDEO_STATE_KEY, videoState, ERROR_TYPE_KEY, static_cast<int32_t>(value),
            ERROR_MSG_KEY, desc);
    } else {
        HiWriteFaultEvent(CALL_DIAL_FAILED_EVENT, MODULE_NAME_KEY, CELLULAR_CALL_MODULE, SLOT_ID_KEY, slotId,
            CALL_TYPE_KEY, callType, VIDEO_STATE_KEY, videoState, ERROR_TYPE_KEY, errorCode, ERROR_MSG_KEY, desc);
    }
}

void CellularCallHiSysEvent::WriteAnswerCallFaultEvent(const int32_t slotId, const int32_t callId,
    const int32_t videoState, const int32_t errorCode, const std::string &desc)
{
    CallErrorCode value = CallErrorCode::CALL_ERROR_NONE;
    if (ErrorCodeConversion(errorCode, value)) {
        HiWriteFaultEvent(CALL_ANSWER_FAILED_EVENT, MODULE_NAME_KEY, CELLULAR_CALL_MODULE, SLOT_ID_KEY, slotId,
            CALL_ID_KEY, callId, VIDEO_STATE_KEY, videoState, ERROR_TYPE_KEY, static_cast<int32_t>(value),
            ERROR_MSG_KEY, desc);
    } else {
        HiWriteFaultEvent(CALL_ANSWER_FAILED_EVENT, MODULE_NAME_KEY, CELLULAR_CALL_MODULE, SLOT_ID_KEY, slotId,
            CALL_ID_KEY, callId, VIDEO_STATE_KEY, videoState, ERROR_TYPE_KEY, errorCode, ERROR_MSG_KEY, desc);
    }
}

void CellularCallHiSysEvent::WriteHangUpFaultEvent(
    const int32_t slotId, const int32_t callId, const int32_t errorCode, const std::string &desc)
{
    CallErrorCode value = CallErrorCode::CALL_ERROR_NONE;
    if (ErrorCodeConversion(errorCode, value)) {
        HiWriteFaultEvent(CALL_HANGUP_FAILED_EVENT, MODULE_NAME_KEY, CELLULAR_CALL_MODULE, SLOT_ID_KEY, slotId,
            CALL_ID_KEY, callId, ERROR_TYPE_KEY, static_cast<int32_t>(value), ERROR_MSG_KEY, desc);
    } else {
        HiWriteFaultEvent(CALL_HANGUP_FAILED_EVENT, MODULE_NAME_KEY, CELLULAR_CALL_MODULE, SLOT_ID_KEY, slotId,
            CALL_ID_KEY, callId, ERROR_TYPE_KEY, errorCode, ERROR_MSG_KEY, desc);
    }
}

void CellularCallHiSysEvent::WriteVoNRSwitchChangeEvent(const int32_t enable)
{
    HiWriteBehaviorEvent(VONR_SWITCH_STATE_EVENT, SWITCH_KEY, enable);
}

void CellularCallHiSysEvent::WriteImsCallModeBehaviorEvent(
    const CallModeBehaviorType type, const CallBehaviorParameterInfo &info, const int32_t requestResult)
{
    std::string imsCallModeEvent = "";
    switch (type) {
        case CallModeBehaviorType::SEND_REQUEST_EVENT:
            imsCallModeEvent = CALL_MODE_SEND_REQUEST_EVENT;
            break;
        case CallModeBehaviorType::SEND_RESPONSE_EVENT:
            imsCallModeEvent = CALL_MODE_SEND_RESPONSE_EVENT;
            break;
        case CallModeBehaviorType::RECEIVE_REQUEST_EVENT:
            imsCallModeEvent = CALL_MODE_RECEIVE_REQUEST_EVENT;
            break;
        case CallModeBehaviorType::RECEIVE_RESPONSE_EVENT:
            imsCallModeEvent = CALL_MODE_RECEIVE_RESPONSE_EVENT;
            break;
        default:
            break;
    }
    if (requestResult == INVALID_VALUE) {
        HiWriteBehaviorEvent(imsCallModeEvent, MODULE_NAME_KEY, CELLULAR_CALL_MODULE, SLOT_ID_KEY, info.slotId,
            CALL_TYPE_KEY, info.callType, VIDEO_STATE_KEY, info.videoState);
    } else {
        HiWriteBehaviorEvent(imsCallModeEvent, MODULE_NAME_KEY, CELLULAR_CALL_MODULE, SLOT_ID_KEY, info.slotId,
            CALL_TYPE_KEY, info.callType, VIDEO_STATE_KEY, info.videoState, RESULT_KEY, requestResult);
    }
}

int32_t CellularCallHiSysEvent::ErrorCodeConversion(const int32_t errCode, CallErrorCode &eventValue)
{
    if (CallDataErrorCodeConversion(errCode, eventValue) || CallInterfaceErrorCodeConversion(errCode, eventValue) ||
        TelephonyErrorCodeConversion(errCode, eventValue)) {
        return true;
    }
    return false;
}

int32_t CellularCallHiSysEvent::TelephonyErrorCodeConversion(const int32_t errCode, CallErrorCode &eventValue)
{
    switch (errCode) {
        case static_cast<int32_t>(TELEPHONY_ERR_LOCAL_PTR_NULL):
            eventValue = CallErrorCode::CALL_ERROR_CALL_LOCAL_PTR_NULL;
            break;
        case static_cast<int32_t>(TELEPHONY_ERR_ARGUMENT_INVALID):
            eventValue = CallErrorCode::CALL_ERROR_ARGUMENT_INVALID;
            break;
        case static_cast<int32_t>(TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL):
            eventValue = CallErrorCode::CALL_ERROR_IPC_CONNECT_STUB_FAIL;
            break;
        case static_cast<int32_t>(TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL):
            eventValue = CallErrorCode::CALL_ERROR_IPC_WRITE_DESCRIPTOR_TOKEN_FAIL;
            break;
        case static_cast<int32_t>(TELEPHONY_ERR_WRITE_DATA_FAIL):
            eventValue = CallErrorCode::CALL_ERROR_IPC_WRITE_DATA_FAIL;
            break;
        case static_cast<int32_t>(TELEPHONY_ERR_PERMISSION_ERR):
            eventValue = CallErrorCode::CALL_ERROR_PERMISSION_ERR;
            break;
        case static_cast<int32_t>(TELEPHONY_ERR_MEMSET_FAIL):
            eventValue = CallErrorCode::CALL_ERROR_MEMSET_FAIL;
            break;
        case static_cast<int32_t>(TELEPHONY_ERR_MEMCPY_FAIL):
            eventValue = CallErrorCode::CALL_ERROR_MEMCPY_FAIL;
            break;
        default:
            return false;
    }

    return true;
}

int32_t CellularCallHiSysEvent::CallDataErrorCodeConversion(const int32_t errCode, CallErrorCode &eventValue)
{
    switch (errCode) {
        case static_cast<int32_t>(CALL_ERR_INVALID_SLOT_ID):
            eventValue = CallErrorCode::CALL_ERROR_INVALID_SLOT_ID;
            break;
        case static_cast<int32_t>(CALL_ERR_INVALID_CALLID):
            eventValue = CallErrorCode::CALL_ERROR_INVALID_CALLID;
            break;
        case static_cast<int32_t>(CALL_ERR_PHONE_NUMBER_EMPTY):
            eventValue = CallErrorCode::CALL_ERROR_PHONE_NUMBER_EMPTY;
            break;
        case static_cast<int32_t>(CALL_ERR_NUMBER_OUT_OF_RANGE):
            eventValue = CallErrorCode::CALL_ERROR_NUMBER_OUT_OF_RANGE;
            break;
        case static_cast<int32_t>(CALL_ERR_UNSUPPORTED_NETWORK_TYPE):
            eventValue = CallErrorCode::CALL_ERROR_UNSUPPORTED_NETWORK_TYPE;
            break;
        case static_cast<int32_t>(CALL_ERR_INVALID_DIAL_SCENE):
            eventValue = CallErrorCode::CALL_ERROR_INVALID_DIAL_SCENE;
            break;
        case static_cast<int32_t>(CALL_ERR_INVALID_VIDEO_STATE):
            eventValue = CallErrorCode::CALL_ERROR_INVALID_VIDEO_STATE;
            break;
        case static_cast<int32_t>(CALL_ERR_UNKNOW_DIAL_TYPE):
            eventValue = CallErrorCode::CALL_ERROR_UNKNOW_DIAL_TYPE;
            break;
        case static_cast<int32_t>(CALL_ERR_UNKNOW_CALL_TYPE):
            eventValue = CallErrorCode::CALL_ERROR_UNKNOW_CALL_TYPE;
            break;
        case static_cast<int32_t>(CALL_ERR_CALL_OBJECT_IS_NULL):
            eventValue = CallErrorCode::CALL_ERROR_CALL_OBJECT_IS_NULL;
            break;
        default:
            return false;
    }
    return true;
}

int32_t CellularCallHiSysEvent::CallInterfaceErrorCodeConversion(const int32_t errCode, CallErrorCode &eventValue)
{
    switch (errCode) {
        case static_cast<int32_t>(CALL_ERR_DIAL_IS_BUSY):
            eventValue = CallErrorCode::CALL_ERROR_DIAL_IS_BUSY;
            break;
        case static_cast<int32_t>(CALL_ERR_ILLEGAL_CALL_OPERATION):
            eventValue = CallErrorCode::CALL_ERROR_ILLEGAL_CALL_OPERATION;
            break;
        case static_cast<int32_t>(CALL_ERR_PHONE_CALLSTATE_NOTIFY_FAILED):
            eventValue = CallErrorCode::CALL_ERROR_PHONE_CALLSTATE_NOTIFY_FAILED;
            break;
        case static_cast<int32_t>(CALL_ERR_SYSTEM_EVENT_HANDLE_FAILURE):
            eventValue = CallErrorCode::CALL_ERROR_SYSTEM_EVENT_HANDLE_FAILURE;
            break;
        case static_cast<int32_t>(CALL_ERR_CALL_COUNTS_EXCEED_LIMIT):
            eventValue = CallErrorCode::CALL_ERROR_CALL_COUNTS_EXCEED_LIMIT;
            break;
        case static_cast<int32_t>(CALL_ERR_GET_RADIO_STATE_FAILED):
            eventValue = CallErrorCode::CALL_ERROR_GET_RADIO_STATE_FAILED;
            break;
        default:
            return false;
    }

    return true;
}

void CellularCallHiSysEvent::SetCallParameterInfo(
    const int32_t slotId, const int32_t callType, const int32_t videoState)
{
    dfxSlotId_ = slotId;
    dfxCallType_ = callType;
    dfxVideoState_ = videoState;
}

void CellularCallHiSysEvent::SetIncomingCallParameterInfo(
    const int32_t incomingCallType, const int32_t incomingVideoState)
{
    dfxIncomingCallType_ = incomingCallType;
    dfxIncomingVideoState_ = incomingVideoState;
}

void CellularCallHiSysEvent::GetCallParameterInfo(CallBehaviorParameterInfo &info)
{
    info.slotId = dfxSlotId_;
    info.callType = dfxCallType_;
    info.videoState = dfxVideoState_;
    info.incomingCallType = dfxIncomingCallType_;
    info.incomingVideoState = dfxIncomingVideoState_;
}

void CellularCallHiSysEvent::SetIncomingStartTime()
{
    incomingStartTime_ =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
}

void CellularCallHiSysEvent::JudgingIncomingTimeOut(
    const int32_t slotId, const int32_t callType, const int32_t videoState)
{
    int64_t incomingEndTime =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    if ((incomingEndTime - incomingStartTime_) > NORMAL_INCOMING_TIME) {
        WriteIncomingCallFaultEvent(slotId, callType, videoState,
            static_cast<int32_t>(CallErrorCode::CALL_ERROR_INCOMING_TIME_OUT),
            "incoming time out " + std::to_string(incomingStartTime_ - incomingEndTime));
    }
}

void CellularCallHiSysEvent::SetCallForwardingInfo(const int32_t slotId, const bool enable, const std::string &number)
{
    callForwardingSlotId_ = slotId;
    callForwardingEnable_ = enable;
    callForwardingNumber_ = number;
}

void CellularCallHiSysEvent::GetCallForwardingInfo(CallForwardingInfo &info)
{
    info.slotId = callForwardingSlotId_;
    info.enable = callForwardingEnable_;

    size_t cpyLen = callForwardingNumber_.length() + 1;
    if (callForwardingNumber_.length() > static_cast<size_t>(maxNumberLen)) {
        return;
    }
    if (strcpy_s(info.number, cpyLen, callForwardingNumber_.c_str()) != EOK) {
        TELEPHONY_LOGE("strcpy_s fail.");
        return;
    }
}
} // namespace Telephony
} // namespace OHOS

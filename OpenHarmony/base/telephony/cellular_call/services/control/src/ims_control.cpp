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

#include "ims_control.h"

#include "cellular_call_hisysevent.h"
#include "cellular_call_register.h"
#include "emergency_utils.h"
#include "module_service_utils.h"
#include "securec.h"
#include "standardize_utils.h"

namespace OHOS {
namespace Telephony {
IMSControl::~IMSControl()
{
    TELEPHONY_LOGI("~IMSControl start");
    ReleaseAllConnection();
}

int32_t IMSControl::Dial(const CellularCallInfo &callInfo, bool isEcc)
{
    TELEPHONY_LOGI("Dial start");
    DelayedSingleton<CellularCallHiSysEvent>::GetInstance()->SetCallParameterInfo(
        callInfo.slotId, static_cast<int32_t>(callInfo.callType), callInfo.videoState);
    int32_t ret = DialPreJudgment(callInfo, isEcc);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    ModuleServiceUtils moduleServiceUtils;
    RegServiceState regState = moduleServiceUtils.GetPsRegState(callInfo.slotId);
    if (!(regState == RegServiceState::REG_STATE_IN_SERVICE || isEcc)) {
        TELEPHONY_LOGE("can not dial.");
        return TELEPHONY_ERR_NETWORK_NOT_IN_SERVICE;
    }
    // sip uri needs to remove separator
    std::string newPhoneNum(callInfo.phoneNum);
    StandardizeUtils standardizeUtils;
    if (newPhoneNum.find('@') != std::string::npos || newPhoneNum.find("%40") != std::string::npos) {
        newPhoneNum = standardizeUtils.RemoveSeparatorsPhoneNumber(newPhoneNum);
    }

    CLIRMode clirMode = CLIRMode::DEFAULT;
    if (IsNeedExecuteMMI(callInfo.slotId, newPhoneNum, clirMode, true)) {
        TELEPHONY_LOGI("Dial return, mmi code type.");
        return RETURN_TYPE_MMI;
    }
    return DialJudgment(callInfo.slotId, newPhoneNum, clirMode, callInfo.videoState);
}

int32_t IMSControl::DialJudgment(int32_t slotId, const std::string &phoneNum, CLIRMode &clirMode, int32_t videoState)
{
    TELEPHONY_LOGI("DialJudgment entry.");
    if (!CanCall(connectionMap_)) {
        TELEPHONY_LOGE("DialJudgment return, error type: call state error.");
        CellularCallHiSysEvent::WriteDialCallFaultEvent(
            slotId, INVALID_PARAMETER, videoState, CALL_ERR_CALL_COUNTS_EXCEED_LIMIT, "ims dial call state error");
        return CALL_ERR_CALL_COUNTS_EXCEED_LIMIT;
    }
    pendingPhoneNumber_ = phoneNum;
    // Calls can be put on hold, recovered, released, added to conversation,
    // and transferred similarly as defined in 3GPP TS 22.030 [19].
    for (auto &connection : connectionMap_) {
        if (connection.second.GetStatus() == TelCallState::CALL_STATUS_ACTIVE) {
            TELEPHONY_LOGI("DialJudgment, have connection in active state.");
            EmergencyUtils emergencyUtils;
            bool isEmergency = false;
            emergencyUtils.IsEmergencyCall(slotId, phoneNum, isEmergency);
            connection.second.SetHoldToDialInfo(phoneNum, clirMode, videoState, isEmergency);
            connection.second.SetDialFlag(true);
            // - a call can be temporarily disconnected from the ME but the connection is retained by the network
            return connection.second.SwitchCallRequest(slotId);
        }
    }
    return EncapsulateDial(slotId, phoneNum, clirMode, videoState);
}

int32_t IMSControl::EncapsulateDial(
    int32_t slotId, const std::string &phoneNum, CLIRMode &clirMode, int32_t videoState) const
{
    TELEPHONY_LOGI("EncapsulateDial start");

    ImsDialInfoStruct dialInfo;
    dialInfo.videoState = videoState;
    dialInfo.bEmergencyCall = false;
    EmergencyUtils emergencyUtils;
    emergencyUtils.IsEmergencyCall(slotId, phoneNum, dialInfo.bEmergencyCall);

    /**
     * <idx>: integer type;
     * call identification number as described in 3GPP TS 22.030 [19] subclause 4.5.5.1
     * this number can be used in +CHLD command operations
     * <dir>:
     */
    dialInfo.phoneNum = phoneNum;
    /**
     * <n> (parameter sets the adjustment for outgoing calls):
     *  0	presentation indicator is used according to the subscription of the CLIR service
     *  1	CLIR invocation
     *  2	CLIR suppression
     */
    dialInfo.clirMode = clirMode;
    /**
     * An example of voice group call service request usage:
     * ATD*17*753#500; (originate voice group call with the priority level 3)
     * OK (voice group call setup was successful)
     */

    CellularCallConnectionIMS cellularCallConnectionIms;
    return cellularCallConnectionIms.DialRequest(slotId, dialInfo);
}

int32_t IMSControl::HangUp(const CellularCallInfo &callInfo, CallSupplementType type)
{
    TELEPHONY_LOGI("HangUp start");
    switch (type) {
        case CallSupplementType::TYPE_DEFAULT: {
            auto pConnection = FindConnectionByIndex<ImsConnectionMap &, CellularCallConnectionIMS *>(
                connectionMap_, callInfo.index);
            if (pConnection == nullptr) {
                TELEPHONY_LOGE("HangUp return, error type: connection is null");
                return CALL_ERR_CALL_CONNECTION_NOT_EXIST;
            }

            if (DelayedSingleton<CellularCallRegister>::GetInstance() != nullptr) {
                DelayedSingleton<CellularCallRegister>::GetInstance()->ReportSingleCallInfo(
                    pConnection->GetCallReportInfo(), TelCallState::CALL_STATUS_DISCONNECTING);
            }
            return pConnection->HangUpRequest(callInfo.slotId, callInfo.phoneNum, callInfo.index);
        }
        case CallSupplementType::TYPE_HANG_UP_HOLD_WAIT:
            // release the second (active) call and recover the first (held) call
        case CallSupplementType::TYPE_HANG_UP_ACTIVE: {
            CellularCallConnectionIMS connection;
            return connection.CallSupplementRequest(callInfo.slotId, type);
        }
        case CallSupplementType::TYPE_HANG_UP_ALL: {
            TELEPHONY_LOGI("HangUp, hang up all call");
            CellularCallConnectionIMS connection;
            // The AT command for hanging up all calls is the same as the AT command for rejecting calls,
            // so the reject interface is reused.
            return connection.RejectRequest(callInfo.slotId, callInfo.phoneNum, callInfo.index);
        }
        default: {
            TELEPHONY_LOGE("HangUp warring, type is invalid");
            return TELEPHONY_ERR_ARGUMENT_INVALID;
        }
    }
}

int32_t IMSControl::Answer(const CellularCallInfo &callInfo)
{
    TELEPHONY_LOGI("IMSControl::Answer start");
    auto pConnection = FindConnectionByIndex<ImsConnectionMap &, CellularCallConnectionIMS *>(
        connectionMap_, callInfo.index);
    if (pConnection == nullptr) {
        TELEPHONY_LOGE("HangUp return, error type: connection is null");
        return CALL_ERR_CALL_CONNECTION_NOT_EXIST;
    }
    if (IsInState(connectionMap_, TelCallState::CALL_STATUS_HOLDING) &&
        IsInState(connectionMap_, TelCallState::CALL_STATUS_ACTIVE)) {
        TELEPHONY_LOGD("already threeway mode. hangup holding call and pickup new call");
        int32_t ret = CheckAndHangupHoldingCall();
        if (ret != TELEPHONY_SUCCESS) {
            TELEPHONY_LOGE("hangup holding call failed");
            return ret;
        }
    }

    if (IsInState(connectionMap_, TelCallState::CALL_STATUS_ACTIVE) &&
        pConnection->GetStatus() == TelCallState::CALL_STATUS_WAITING) {
        TELEPHONY_LOGI("Answer there is an active call when you call, or third party call waiting");
        auto con = FindConnectionByState<ImsConnectionMap &, CellularCallConnectionIMS *>(
            connectionMap_, TelCallState::CALL_STATUS_ACTIVE);
        if (con == nullptr) {
            TELEPHONY_LOGE("Answer return, error type: con is null, there are no active calls");
            return CALL_ERR_CALL_CONNECTION_NOT_EXIST;
        }
        return con->SwitchCallRequest(callInfo.slotId);
    }
    if (pConnection->GetStatus() == TelCallState::CALL_STATUS_ALERTING ||
        pConnection->GetStatus() == TelCallState::CALL_STATUS_INCOMING ||
        pConnection->GetStatus() == TelCallState::CALL_STATUS_WAITING) {
        return pConnection->AnswerRequest(callInfo.slotId, callInfo.phoneNum, callInfo.videoState, callInfo.index);
    }
    TELEPHONY_LOGE("IMSControl::Answer return, error type: call state error, phone not ringing.");
    return CALL_ERR_CALL_STATE;
}

int32_t IMSControl::CheckAndHangupHoldingCall()
{
    for (auto &it : connectionMap_) {
        CellularCallConnectionIMS holdConn = it.second;
        if (holdConn.GetStatus() == TelCallState::CALL_STATUS_HOLDING) {
            auto callReportInfo = holdConn.GetCallReportInfo();
            int32_t result = holdConn.HangUpRequest(callReportInfo.accountId,
                callReportInfo.accountNum, callReportInfo.index);
            if (result != TELEPHONY_SUCCESS) {
                return result;
            }
        }
    }
    return TELEPHONY_SUCCESS;
}

int32_t IMSControl::Reject(const CellularCallInfo &callInfo)
{
    TELEPHONY_LOGI("IMSControl::Reject start");
    auto pConnection =
        FindConnectionByIndex<ImsConnectionMap &, CellularCallConnectionIMS *>(connectionMap_, callInfo.index);
    if (pConnection == nullptr) {
        TELEPHONY_LOGE("IMSControl::Reject, error type: connection is null");
        return CALL_ERR_CALL_CONNECTION_NOT_EXIST;
    }
    if (!pConnection->IsRingingState()) {
        TELEPHONY_LOGE("IMSControl::Reject return, error type: call state error, phone not ringing.");
        return CALL_ERR_CALL_STATE;
    }
    if (DelayedSingleton<CellularCallRegister>::GetInstance() != nullptr) {
        DelayedSingleton<CellularCallRegister>::GetInstance()->ReportSingleCallInfo(
            pConnection->GetCallReportInfo(), TelCallState::CALL_STATUS_DISCONNECTING);
    }
    return pConnection->RejectRequest(callInfo.slotId, callInfo.phoneNum, callInfo.index);
}

int32_t IMSControl::HoldCall(int32_t slotId)
{
    TELEPHONY_LOGI("HoldCall start");
    if (IsInState(connectionMap_, TelCallState::CALL_STATUS_INCOMING)) {
        TELEPHONY_LOGE("HoldCall return, error type: call state error.");
        return CALL_ERR_CALL_STATE;
    }
    CellularCallConnectionIMS cellularCallConnectionIms;
    return cellularCallConnectionIms.HoldCallRequest(slotId);
}

int32_t IMSControl::UnHoldCall(int32_t slotId)
{
    TELEPHONY_LOGI("UnHoldCall start");
    CellularCallConnectionIMS cellularCallConnectionIms;
    return cellularCallConnectionIms.UnHoldCallRequest(slotId);
}

int32_t IMSControl::SwitchCall(int32_t slotId)
{
    TELEPHONY_LOGI("SwitchCall start");
    CellularCallConnectionIMS cellularCallConnectionIms;
    return cellularCallConnectionIms.SwitchCallRequest(slotId);
}

/**
 * Add another remote party, to which a private communication has been established using
 * the same procedures as in Section 1.3.8.1, if the number of remote parties does not then
 * exceed the maximum number allowed, which results in an active multiParty call.
 */
int32_t IMSControl::CombineConference(int32_t slotId)
{
    TELEPHONY_LOGI("CombineConference entry");
    CellularCallConnectionIMS connection;
    int32_t voiceCall = 0;
    return connection.CombineConferenceRequest(slotId, voiceCall);
}

int32_t IMSControl::HangUpAllConnection(int32_t slotId)
{
    TELEPHONY_LOGI("HangUpAllConnection entry");
    CellularCallConnectionIMS connection;
    if (connectionMap_.empty()) {
        TELEPHONY_LOGI("connectionMap_ is empty.");
        return TELEPHONY_ERROR;
    }
    for (auto &it : connectionMap_) {
        int32_t index = it.second.GetIndex();
        std::string number = it.second.GetNumber();
        connection.RejectRequest(slotId, number, index);
    }
    // The AT command for hanging up all calls is the same as the AT command for rejecting calls,
    // so the reject interface is reused.
    return TELEPHONY_SUCCESS;
}

int32_t IMSControl::InviteToConference(int32_t slotId, const std::vector<std::string> &numberList)
{
    TELEPHONY_LOGI("InviteToConference entry");
    CellularCallConnectionIMS connection;
    return connection.InviteToConferenceRequest(slotId, numberList);
}

int32_t IMSControl::KickOutFromConference(int32_t slotId, const std::string &KickOutString, int32_t index)
{
    if (KickOutString.empty()) {
        TELEPHONY_LOGW("KickOutFromConference, splitString is empty.");
    }

    auto pConnection = FindConnectionByIndex<ImsConnectionMap &, CellularCallConnectionIMS *>(connectionMap_, index);
    if (pConnection != nullptr) {
        return pConnection->KickOutFromConferenceRequest(slotId, pConnection->GetIndex());
    }

    TELEPHONY_LOGI("KickOutFromConference: connection cannot be matched, use index directly");
    CellularCallConnectionIMS connection;
    return connection.KickOutFromConferenceRequest(slotId, index);
}

int32_t IMSControl::StartRtt(int32_t slotId, const std::string &msg)
{
    TELEPHONY_LOGI("StartRtt entry");
    CellularCallConnectionIMS connection;
    return connection.StartRttRequest(slotId, msg);
}

int32_t IMSControl::StopRtt(int32_t slotId)
{
    TELEPHONY_LOGI("StopRtt entry");
    CellularCallConnectionIMS connection;
    return connection.StopRttRequest(slotId);
}

void IMSControl::ReleaseAllConnection()
{
    connectionMap_.clear();
}

ImsConnectionMap IMSControl::GetConnectionMap()
{
    return connectionMap_;
}

int32_t IMSControl::ReportImsCallsData(int32_t slotId, const ImsCurrentCallList &callInfoList)
{
    if (callInfoList.callSize <= 0 && !connectionMap_.empty()) {
        return ReportHangUpInfo(slotId);
    } else if (callInfoList.callSize > 0 && connectionMap_.empty()) {
        return ReportIncomingInfo(slotId, callInfoList);
    } else if (callInfoList.callSize > 0 && !connectionMap_.empty()) {
        return ReportUpdateInfo(slotId, callInfoList);
    }
    return TELEPHONY_ERROR;
}

int32_t IMSControl::ReportCallsData(int32_t slotId, const CallInfoList &callInfoList)
{
    return TELEPHONY_ERROR;
}

int32_t IMSControl::ReportHangUpInfo(int32_t slotId)
{
    TELEPHONY_LOGD("ReportHangUpInfo entry");
    CallsReportInfo callsReportInfo;
    for (auto &it : connectionMap_) {
        CallReportInfo reportInfo = it.second.GetCallReportInfo();
        reportInfo.state = TelCallState::CALL_STATUS_DISCONNECTED;
        reportInfo.accountId = slotId;
        callsReportInfo.callVec.push_back(reportInfo);
        GetCallFailReason(slotId, connectionMap_);
    }
    if (DelayedSingleton<CellularCallRegister>::GetInstance() == nullptr) {
        TELEPHONY_LOGE("ReportHangUpInfo return, GetInstance() is nullptr.");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    callsReportInfo.slotId = slotId;
    if (isIgnoredIncomingCall_) {
        isIgnoredIncomingCall_ = false;
    } else {
        DelayedSingleton<CellularCallRegister>::GetInstance()->ReportCallsInfo(callsReportInfo);
    }
    ReleaseAllConnection();
    return TELEPHONY_SUCCESS;
}

int32_t IMSControl::ReportIncomingInfo(int32_t slotId, const ImsCurrentCallList &imsCurrentCallInfoList)
{
    TELEPHONY_LOGI("ReportIncomingInfo entry");
    CallsReportInfo callsReportInfo;
    for (int32_t i = 0; i < imsCurrentCallInfoList.callSize; ++i) {
        CallReportInfo reportInfo = EncapsulationCallReportInfo(slotId, imsCurrentCallInfoList.calls[i]);

        CellularCallConnectionIMS connection;
        connection.SetStatus(static_cast<TelCallState>(imsCurrentCallInfoList.calls[i].state));
        connection.SetIndex(imsCurrentCallInfoList.calls[i].index);
        connection.SetNumber(imsCurrentCallInfoList.calls[i].number);
        connection.SetOrUpdateCallReportInfo(reportInfo);
        SetConnectionData(connectionMap_, imsCurrentCallInfoList.calls[i].index, connection);

        callsReportInfo.callVec.push_back(reportInfo);
    }
    if (DelayedSingleton<CellularCallRegister>::GetInstance() == nullptr) {
        TELEPHONY_LOGE("ReportIncomingInfo return, GetInstance() is nullptr.");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    callsReportInfo.slotId = slotId;
    if (!DelayedSingleton<CellularCallRegister>::GetInstance()->IsCallManagerCallBackRegistered() &&
        callsReportInfo.callVec.size() != 0 && callsReportInfo.callVec[0].state == TelCallState::CALL_STATUS_INCOMING) {
        isIgnoredIncomingCall_ = true;
    } else {
        DelayedSingleton<CellularCallRegister>::GetInstance()->ReportCallsInfo(callsReportInfo);
    }
    return TELEPHONY_SUCCESS;
}

int32_t IMSControl::ReportUpdateInfo(int32_t slotId, const ImsCurrentCallList &callInfoList)
{
    TELEPHONY_LOGD("ReportUpdateInfo entry");
    CallsReportInfo callsReportInfo;
    for (int32_t i = 0; i < callInfoList.callSize; ++i) {
        CallReportInfo reportInfo = EncapsulationCallReportInfo(slotId, callInfoList.calls[i]);
        if (callInfoList.callSize == 1 && reportInfo.state == TelCallState::CALL_STATUS_WAITING) {
            TELEPHONY_LOGI("only one call, report incoming state instead of waiting state");
            reportInfo.state = TelCallState::CALL_STATUS_INCOMING;
        }
        auto pConnection = FindConnectionByIndex<ImsConnectionMap &, CellularCallConnectionIMS *>(
            connectionMap_, callInfoList.calls[i].index);
        if (pConnection == nullptr) {
            CellularCallConnectionIMS connection;
            connection.SetOrUpdateCallReportInfo(reportInfo);
            connection.SetFlag(true);
            connection.SetIndex(callInfoList.calls[i].index);
            connection.SetNumber(callInfoList.calls[i].number);
            SetConnectionData(connectionMap_, callInfoList.calls[i].index, connection);
        } else {
            TelCallState preCallState = pConnection->GetStatus();
            pConnection->SetFlag(true);
            pConnection->SetIndex(callInfoList.calls[i].index);
            pConnection->SetNumber(callInfoList.calls[i].number);
            pConnection->SetOrUpdateCallReportInfo(reportInfo);
            TelCallState curCallState = pConnection->GetStatus();
            if (IsConnectedOut(preCallState, curCallState)) {
                pConnection->UpdateCallNumber(pendingPhoneNumber_);
                pendingPhoneNumber_.clear();
                ExecutePostDial(slotId, pConnection->GetIndex());
            }
        }
        callsReportInfo.callVec.push_back(reportInfo);
    }
    callsReportInfo.slotId = slotId;
    DeleteConnection(callsReportInfo, callInfoList);
    if (DelayedSingleton<CellularCallRegister>::GetInstance() == nullptr) {
        TELEPHONY_LOGE("ReportUpdateInfo return, GetInstance() is nullptr.");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (isIgnoredIncomingCall_) {
        isIgnoredIncomingCall_ = false;
    } else {
        DelayedSingleton<CellularCallRegister>::GetInstance()->ReportCallsInfo(callsReportInfo);
    }
    return TELEPHONY_SUCCESS;
}

CallReportInfo IMSControl::EncapsulationCallReportInfo(int32_t slotId, const ImsCurrentCall &callInfo)
{
    TELEPHONY_LOGD("EncapsulationCallReportInfo entry");
    CallReportInfo callReportInfo;
    if (memset_s(&callReportInfo, sizeof(callReportInfo), 0, sizeof(callReportInfo)) != EOK) {
        TELEPHONY_LOGE("EncapsulationCallReportInfo return, memset_s fail.");
        return callReportInfo;
    }

    StandardizeUtils standardizeUtils;
    std::string newString = standardizeUtils.FormatNumberAndToa(callInfo.number, callInfo.toa);
    size_t cpyLen = strlen(newString.c_str()) + 1;
    if (cpyLen > static_cast<size_t>(kMaxNumberLen + 1)) {
        TELEPHONY_LOGE("EncapsulationCallReportInfo return, strcpy_s fail.");
        return callReportInfo;
    }
    if (strcpy_s(callReportInfo.accountNum, cpyLen, newString.c_str()) != EOK) {
        TELEPHONY_LOGE("EncapsulationCallReportInfo return, strcpy_s fail.");
        return callReportInfo;
    }
    callReportInfo.index = callInfo.index;
    callReportInfo.accountId = slotId;
    callReportInfo.state = static_cast<TelCallState>(callInfo.state);
    callReportInfo.voiceDomain = callInfo.voiceDomain;
    callReportInfo.callType = CallType::TYPE_IMS;
    switch (callInfo.callType) {
        case ImsCallType::TEL_IMS_CALL_TYPE_VOICE:
            callReportInfo.callMode = VideoStateType::TYPE_VOICE;
            break;
        case ImsCallType::TEL_IMS_CALL_TYPE_VT_TX:
            callReportInfo.callMode = VideoStateType::TYPE_SEND_ONLY;
            break;
        case ImsCallType::TEL_IMS_CALL_TYPE_VT_RX:
            callReportInfo.callMode = VideoStateType::TYPE_RECEIVE_ONLY;
            break;
        case ImsCallType::TEL_IMS_CALL_TYPE_VT:
            callReportInfo.callMode = VideoStateType::TYPE_VIDEO;
            break;
        default:
            callReportInfo.callMode = VideoStateType::TYPE_VOICE;
            break;
    }
    callReportInfo.mpty = callInfo.mpty;
    callReportInfo.crsType = callInfo.toneType;
    callReportInfo.originalCallType = callInfo.callInitialType;
    return callReportInfo;
}

void IMSControl::DeleteConnection(CallsReportInfo &callsReportInfo, const ImsCurrentCallList &callInfoList)
{
    TELEPHONY_LOGI("DeleteConnection entry");
    auto it = connectionMap_.begin();
    while (it != connectionMap_.end()) {
        if (!it->second.GetFlag()) {
            CallReportInfo callReportInfo = it->second.GetCallReportInfo();
            callReportInfo.state = TelCallState::CALL_STATUS_DISCONNECTED;
            callsReportInfo.callVec.push_back(callReportInfo);
            connectionMap_.erase(it++);
            GetCallFailReason(callsReportInfo.slotId, connectionMap_);
        } else {
            it->second.SetFlag(false);
            ++it;
        }
    }
}

int32_t IMSControl::ExecutePostDial(int32_t slotId, int64_t callId)
{
    if (connectionMap_.empty()) {
        TELEPHONY_LOGE("connectionMap_ is empty.");
        return TELEPHONY_ERROR;
    }
    auto pConnection = FindConnectionByIndex<ImsConnectionMap &, CellularCallConnectionIMS *>(connectionMap_, callId);
    if (pConnection == nullptr) {
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    char currentChar;
    PostDialCallState state = pConnection->ProcessNextChar(slotId, currentChar);
    switch (state) {
        case PostDialCallState::POST_DIAL_CALL_STARTED:
            DelayedSingleton<CellularCallRegister>::GetInstance()->ReportPostDialChar(currentChar);
            break;
        case PostDialCallState::POST_DIAL_CALL_DELAY:
            DelayedSingleton<CellularCallRegister>::GetInstance()->ReportPostDialDelay(
                pConnection->GetLeftPostDialCallString());
            break;
        default:
            break;
    }
    return TELEPHONY_SUCCESS;
}

int32_t IMSControl::PostDialProceed(const CellularCallInfo &callInfo, const bool proceed)
{
    std::string networkAddress;
    std::string postDialString;
    StandardizeUtils standardizeUtils;
    standardizeUtils.ExtractAddressAndPostDial(callInfo.phoneNum, networkAddress, postDialString);
    auto pConnection = FindConnectionByIndex<ImsConnectionMap &, CellularCallConnectionIMS *>(connectionMap_,
        callInfo.index);
    if (pConnection == nullptr) {
        TELEPHONY_LOGE("ims pConnection is nullptr!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (proceed) {
        ExecutePostDial(callInfo.slotId, pConnection->GetIndex());
    } else {
        pConnection->SetPostDialCallState(PostDialCallState::POST_DIAL_CALL_CANCELED);
    }
    return TELEPHONY_SUCCESS;
}

int32_t IMSControl::RestoreConnection(const std::vector<CellularCallInfo> &infos, int32_t slotId)
{
    for (auto &info : infos) {
        if (info.callType == CallType::TYPE_IMS && info.slotId == slotId) {
            CellularCallConnectionIMS connectionIMS;
            connectionIMS.SetIndex(info.index);
            connectionIMS.SetNumber(info.phoneNum);
            SetConnectionData(connectionMap_, info.index, connectionIMS);
        }
    }
    return TELEPHONY_SUCCESS;
}

int32_t IMSControl::ReportHangUp(const std::vector<CellularCallInfo> &infos, int32_t slotId)
{
    CallsReportInfo callsReportInfo;
    callsReportInfo.slotId = slotId;
    for (const auto &info : infos) {
        if (info.callType == CallType::TYPE_IMS && info.slotId == slotId) {
            CallReportInfo imsCallReportInfo;
            if (memset_s(imsCallReportInfo.accountNum, kMaxNumberLen + 1, 0, kMaxNumberLen + 1) != EOK) {
                TELEPHONY_LOGE("memset_s fail");
                return TELEPHONY_ERR_MEMSET_FAIL;
            }
            if (memcpy_s(imsCallReportInfo.accountNum, kMaxNumberLen, info.phoneNum, kMaxNumberLen) != EOK) {
                TELEPHONY_LOGE("memcpy_s fail");
                return TELEPHONY_ERR_MEMCPY_FAIL;
            }
            imsCallReportInfo.index = info.index;
            imsCallReportInfo.accountId = info.slotId;
            imsCallReportInfo.callType = CallType::TYPE_IMS;
            imsCallReportInfo.callMode =
                static_cast<bool>(info.callType) ? VideoStateType::TYPE_VIDEO : VideoStateType::TYPE_VOICE;
            imsCallReportInfo.state = TelCallState::CALL_STATUS_DISCONNECTED;
            callsReportInfo.callVec.push_back(imsCallReportInfo);
        }
    }
    if (DelayedSingleton<CellularCallRegister>::GetInstance() == nullptr) {
        TELEPHONY_LOGE("CellularCallRegister instance is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    DelayedSingleton<CellularCallRegister>::GetInstance()->ReportCallsInfo(callsReportInfo);
    return TELEPHONY_SUCCESS;
}

void IMSControl::DialAfterHold(int32_t slotId)
{
    TELEPHONY_LOGI("DialAfterHold entry");
    for (auto &connection : connectionMap_) {
        if (connection.second.IsNeedToDial()) {
            ImsDialInfoStruct holdToDialInfo = connection.second.GetHoldToDialInfo();
            CellularCallConnectionIMS cellularCallConnectionIms;
            cellularCallConnectionIms.DialRequest(slotId, holdToDialInfo);
            connection.second.SetDialFlag(false);
            break;
        }
    }
}
} // namespace Telephony
} // namespace OHOS

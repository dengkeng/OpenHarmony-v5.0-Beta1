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

#include "cs_control.h"

#include "cellular_call_hisysevent.h"
#include "cellular_call_register.h"
#include "cellular_call_service.h"
#include "module_service_utils.h"
#include "securec.h"
#include "standardize_utils.h"

namespace OHOS {
namespace Telephony {

CSControl::~CSControl()
{
    ReleaseAllConnection();
}

int32_t CSControl::Dial(const CellularCallInfo &callInfo, bool isEcc)
{
    TELEPHONY_LOGI("Dial start");
    DelayedSingleton<CellularCallHiSysEvent>::GetInstance()->SetCallParameterInfo(
        callInfo.slotId, static_cast<int32_t>(callInfo.callType), callInfo.videoState);
    int32_t ret = DialPreJudgment(callInfo, isEcc);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }

    ModuleServiceUtils moduleServiceUtils;
    RegServiceState regState = moduleServiceUtils.GetCsRegState(callInfo.slotId);
    if (!(regState == RegServiceState::REG_STATE_IN_SERVICE || isEcc)) {
        TELEPHONY_LOGE("can not dial.");
        return TELEPHONY_ERR_NETWORK_NOT_IN_SERVICE;
    }
    PhoneType netType = moduleServiceUtils.GetNetworkStatus(callInfo.slotId);
    if (netType == PhoneType::PHONE_TYPE_IS_GSM) {
        return DialGsm(callInfo);
    }
    if (netType == PhoneType::PHONE_TYPE_IS_CDMA) {
        return DialCdma(callInfo);
    }
    TELEPHONY_LOGE("Dial return, net type error.");
    CellularCallHiSysEvent::WriteDialCallFaultEvent(callInfo.slotId, static_cast<int32_t>(callInfo.callType),
        callInfo.videoState, CALL_ERR_UNSUPPORTED_NETWORK_TYPE, "Network type error");
    return CALL_ERR_UNSUPPORTED_NETWORK_TYPE;
}

int32_t CSControl::DialCdma(const CellularCallInfo &callInfo)
{
    TELEPHONY_LOGI("DialCdma entry.");
    StandardizeUtils standardizeUtils;
    // Remove the phone number separator
    std::string newPhoneNum = standardizeUtils.RemoveSeparatorsPhoneNumber(callInfo.phoneNum);

    CLIRMode clirMode = CLIRMode::DEFAULT;
    if (IsNeedExecuteMMI(callInfo.slotId, newPhoneNum, clirMode, false)) {
        TELEPHONY_LOGI("DialCdma return, mmi code type.");
        return RETURN_TYPE_MMI;
    }

    if (!CanCall(connectionMap_)) {
        TELEPHONY_LOGE("CSControl::DialCdma return, error type: call state error.");
        CellularCallHiSysEvent::WriteDialCallFaultEvent(callInfo.slotId, static_cast<int32_t>(callInfo.callType),
            callInfo.videoState, CALL_ERR_CALL_COUNTS_EXCEED_LIMIT, "cs cdma dial call state error");
        return CALL_ERR_CALL_COUNTS_EXCEED_LIMIT;
    }

    if (IsInState(connectionMap_, TelCallState::CALL_STATUS_ACTIVE)) {
        TELEPHONY_LOGI("DialCdma, CDMA is have connection in active state.");
        CellularCallConnectionCS csConnection;
        return csConnection.SendCDMAThreeWayDialRequest(callInfo.slotId);
    }

    return EncapsulateDialCommon(callInfo.slotId, newPhoneNum, clirMode);
}

int32_t CSControl::DialGsm(const CellularCallInfo &callInfo)
{
    TELEPHONY_LOGI("DialGsm entry.");
    StandardizeUtils standardizeUtils;
    // Remove the phone number separator
    std::string newPhoneNum = standardizeUtils.RemoveSeparatorsPhoneNumber(callInfo.phoneNum);

    CLIRMode clirMode = CLIRMode::DEFAULT;
    if (IsNeedExecuteMMI(callInfo.slotId, newPhoneNum, clirMode, false)) {
        TELEPHONY_LOGI("DialGsm return, mmi code type.");
        return RETURN_TYPE_MMI;
    }

    if (!CanCall(connectionMap_)) {
        TELEPHONY_LOGE("DialGsm return, error type: call state error.");
        CellularCallHiSysEvent::WriteDialCallFaultEvent(callInfo.slotId, static_cast<int32_t>(callInfo.callType),
            callInfo.videoState, CALL_ERR_CALL_COUNTS_EXCEED_LIMIT, "cs gsm dial call state error");
        return CALL_ERR_CALL_COUNTS_EXCEED_LIMIT;
    }

    // Calls can be put on hold, recovered, released, added to conversation,
    // and transferred similarly as defined in 3GPP TS 22.030 [19].
    if (IsInState(connectionMap_, TelCallState::CALL_STATUS_ACTIVE)) {
        // New calls must be active, so other calls need to be hold
        TELEPHONY_LOGI("DialGsm, GSM is have connection in active state.");
        CellularCallConnectionCS pConnection;

        // Delay dialing to prevent failure to add a new call while making a multi-party call
        // Will it block the main thread or other threads? Will the reception of messages be blocked during sleep?
        // - a call can be temporarily disconnected from the ME but the connection is retained by the network
        pConnection.SwitchCallRequest(callInfo.slotId);
    }
    return EncapsulateDialCommon(callInfo.slotId, newPhoneNum, clirMode);
}

int32_t CSControl::EncapsulateDialCommon(int32_t slotId, const std::string &phoneNum, CLIRMode &clirMode)
{
    pendingPhoneNumber_ = phoneNum;
    DialRequestStruct dialRequest;
    /**
     * <idx>: integer type;
     * call identification number as described in 3GPP TS 22.030 [19] subclause 4.5.5.1
     * this number can be used in +CHLD command operations
     * <dir>:
     */
    dialRequest.phoneNum = phoneNum;

    /**
     * <n> (parameter sets the adjustment for outgoing calls):
     *  0	presentation indicator is used according to the subscription of the CLIR service
     *  1	CLIR invocation
     *  2	CLIR suppression
     */
    dialRequest.clirMode = clirMode;

    /**
     * An example of voice group call service request usage:
     * ATD*17*753#500; (originate voice group call with the priority level 3)
     * OK (voice group call setup was successful)
     */
    CellularCallConnectionCS csConnection;
    TELEPHONY_LOGI("Set Mute to false");
    if (DelayedSingleton<CellularCallService>::GetInstance() == nullptr) {
        TELEPHONY_LOGE("SetMute return, error type: GetInstance() is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    DelayedSingleton<CellularCallService>::GetInstance()->SetMute(slotId, false);
    return csConnection.DialRequest(slotId, dialRequest);
}

int32_t CSControl::HangUp(const CellularCallInfo &callInfo, CallSupplementType type)
{
    TELEPHONY_LOGI("HangUp start");
    switch (type) {
        case CallSupplementType::TYPE_DEFAULT: {
            // Match the session connection according to the phone number string
            auto pConnection = FindConnectionByIndex<CsConnectionMap &, CellularCallConnectionCS *>(
                connectionMap_, callInfo.index);
            if (pConnection == nullptr) {
                TELEPHONY_LOGE("CSControl::HangUp, error type: connection is null");
                CellularCallHiSysEvent::WriteHangUpFaultEvent(
                    callInfo.slotId, callInfo.callId, CALL_ERR_CALL_CONNECTION_NOT_EXIST, "HangUp pConnection is null");
                return CALL_ERR_CALL_CONNECTION_NOT_EXIST;
            }

            if (DelayedSingleton<CellularCallRegister>::GetInstance() != nullptr) {
                DelayedSingleton<CellularCallRegister>::GetInstance()->ReportSingleCallInfo(
                    pConnection->GetCallReportInfo(), TelCallState::CALL_STATUS_DISCONNECTING);
            }

            /**
             * The "directory number" case shall be handled with dial command D,
             * and the END case with hangup command H (or +CHUP).
             * (e.g. +CHLD: (0,1,1x,2,2x,3)).
             * NOTE: Call Hold, MultiParty and Explicit Call Transfer are only applicable to teleservice 11.
             */
            return pConnection->HangUpRequest(callInfo.slotId);
        }
        // 3GPP TS 27.007 V3.9.0 (2001-06) Call related supplementary services +CHLD
        // 3GPP TS 27.007 V3.9.0 (2001-06) 7.22 Informative examples
        case CallSupplementType::TYPE_HANG_UP_HOLD_WAIT:
        // release the second (active) call and recover the first (held) call
        case CallSupplementType::TYPE_HANG_UP_ACTIVE: {
            CellularCallConnectionCS connection;
            return connection.CallSupplementRequest(callInfo.slotId, type);
        }
        case CallSupplementType::TYPE_HANG_UP_ALL: {
            TELEPHONY_LOGI("HangUp, hang up all call");
            CellularCallConnectionCS connection;
            // The AT command for hanging up all calls is the same as the AT command for rejecting calls,
            // so the reject interface is reused.
            return connection.RejectRequest(callInfo.slotId);
        }
        default: {
            TELEPHONY_LOGE("HangUp warring, type is invalid");
            CellularCallHiSysEvent::WriteHangUpFaultEvent(
                callInfo.slotId, callInfo.callId, TELEPHONY_ERR_ARGUMENT_INVALID, "HangUp type is invalid");
            return TELEPHONY_ERR_ARGUMENT_INVALID;
        }
    }
}

int32_t CSControl::Answer(const CellularCallInfo &callInfo)
{
    auto pConnection =
        FindConnectionByIndex<CsConnectionMap &, CellularCallConnectionCS *>(connectionMap_, callInfo.index);
    if (pConnection == nullptr) {
        TELEPHONY_LOGE("Answer return, error type: connection is null");
        CellularCallHiSysEvent::WriteAnswerCallFaultEvent(callInfo.slotId, callInfo.callId, callInfo.videoState,
            CALL_ERR_CALL_CONNECTION_NOT_EXIST, "get connection data is null");
        return CALL_ERR_CALL_CONNECTION_NOT_EXIST;
    }

    if (IsInState(connectionMap_, TelCallState::CALL_STATUS_HOLDING) &&
        IsInState(connectionMap_, TelCallState::CALL_STATUS_ACTIVE)) {
        int32_t ret = CheckAndHangupHoldingCall();
        if (ret != TELEPHONY_SUCCESS) {
            TELEPHONY_LOGE("hangup holding call failed");
            return ret;
        }
    }
    /**
     * <stat> (state of the call):
     * 0 active
     * 1 held
     * 2 dialing (MO call)
     * 3 alerting (MO call)
     * 4 incoming (MT call)
     * 5 waiting (MT call)
     */
    // There is an active call when you call, or third party call waiting
    if (IsInState(connectionMap_, TelCallState::CALL_STATUS_ACTIVE) ||
        pConnection->GetStatus() == TelCallState::CALL_STATUS_WAITING) {
        TELEPHONY_LOGI("Answer there is an active call when you call, or third party call waiting");
        auto con = FindConnectionByState<CsConnectionMap &, CellularCallConnectionCS *>(
            connectionMap_, TelCallState::CALL_STATUS_ACTIVE);
        if (con != nullptr) {
            /**
             * shows commands to start the call, to switch from voice to data (In Call Modification) and to hang up
             * the call. +CMOD and +FCLASS commands indicate the current settings before dialling or answering
             * command, not that they shall be given just before D or A command.
             */
            TELEPHONY_LOGI("Answer: There is an active session currently, and it needs to hold");
            con->SwitchCallRequest(callInfo.slotId);
        } else {
            TELEPHONY_LOGE("Answer return, error type: con is null, there are no active calls");
        }
    }

    if (pConnection->GetStatus() == TelCallState::CALL_STATUS_INCOMING ||
        pConnection->GetStatus() == TelCallState::CALL_STATUS_ALERTING ||
        pConnection->GetStatus() == TelCallState::CALL_STATUS_WAITING) {
        return pConnection->AnswerRequest(callInfo.slotId);
    }

    TELEPHONY_LOGE("CSControl::Answer return, error type: call state error, phone not ringing.");
    CellularCallHiSysEvent::WriteAnswerCallFaultEvent(callInfo.slotId, callInfo.callId, callInfo.videoState,
        CALL_ERR_CALL_STATE, "call state error phone not ringing");
    return CALL_ERR_CALL_STATE;
}

int32_t CSControl::CheckAndHangupHoldingCall()
{
    for (auto &it : connectionMap_) {
        CellularCallConnectionCS holdConn = it.second;
        if (holdConn.GetStatus() == TelCallState::CALL_STATUS_HOLDING) {
            auto callReportInfo = holdConn.GetCallReportInfo();
            int32_t result = holdConn.HangUpRequest(callReportInfo.accountId);
            if (result != TELEPHONY_SUCCESS) {
                return result;
            }
        }
    }
    return TELEPHONY_SUCCESS;
}

int32_t CSControl::Reject(const CellularCallInfo &callInfo)
{
    auto pConnection =
        FindConnectionByIndex<CsConnectionMap &, CellularCallConnectionCS *>(connectionMap_, callInfo.index);
    if (pConnection == nullptr) {
        TELEPHONY_LOGE("CSControl::Reject, error type: connection is null");
        CellularCallHiSysEvent::WriteHangUpFaultEvent(
            callInfo.slotId, callInfo.callId, CALL_ERR_CALL_CONNECTION_NOT_EXIST, "Reject pConnection is null");
        return CALL_ERR_CALL_CONNECTION_NOT_EXIST;
    }

    /**
     * shows commands to start the call, to switch from voice to data (In Call Modification) and to hang up the call.
     * +CMOD and +FCLASS commands indicate the current settings before dialling or answering command,
     * not that they shall be given just before D or A command.
     */
    if (!pConnection->IsRingingState()) {
        TELEPHONY_LOGE("CSControl::Reject return, error type: call state error, phone not ringing.");
        CellularCallHiSysEvent::WriteHangUpFaultEvent(
            callInfo.slotId, callInfo.callId, CALL_ERR_CALL_STATE, "Reject call state error phone not ringing");
        return CALL_ERR_CALL_STATE;
    }
    if (DelayedSingleton<CellularCallRegister>::GetInstance() != nullptr) {
        DelayedSingleton<CellularCallRegister>::GetInstance()->ReportSingleCallInfo(
            pConnection->GetCallReportInfo(), TelCallState::CALL_STATUS_DISCONNECTING);
    }
    return pConnection->RejectRequest(callInfo.slotId);
}

int32_t CSControl::HoldCall(int32_t slotId)
{
    /**
     * When the call hold service is invoked, communication is interrupted on the traffic channel and the traffic
     * channel is released from the existing call. The traffic channel is reserved for the served mobile subscriber
     * invoking the call hold service. The served mobile subscriber can only have one call on hold at a time.
     */
    if (IsInState(connectionMap_, TelCallState::CALL_STATUS_INCOMING)) {
        TELEPHONY_LOGE("HoldCall return, error type: call state error.");
        return CALL_ERR_CALL_STATE;
    }
    CellularCallConnectionCS connection;
    return connection.HoldRequest(slotId);
}

int32_t CSControl::UnHoldCall(int32_t slotId)
{
    // A notification shall be send towards the previously held party that the call has been retrieved.
    if (IsInState(connectionMap_, TelCallState::CALL_STATUS_INCOMING)) {
        TELEPHONY_LOGE("UnHoldCall return, error type: call state error.");
        return CALL_ERR_CALL_STATE;
    }
    CellularCallConnectionCS connection;
    return connection.UnHoldCallRequest(slotId);
}

int32_t CSControl::SwitchCall(int32_t slotId)
{
    /**
     * If the served mobile subscriber is connected to an active call and has another call on hold, she can:
     * 1) Alternate from one call to the other.
     * 2) Disconnect the active call.
     * 3) Disconnect the held call.
     * 4) Disconnect both calls.
     */
    if (IsInState(connectionMap_, TelCallState::CALL_STATUS_INCOMING)) {
        TELEPHONY_LOGE("SwitchCall return, error type: call state error.");
        return CALL_ERR_CALL_STATE;
    }
    CellularCallConnectionCS connection;
    return connection.SwitchCallRequest(slotId);
}

/**
 * Explicitly choose one remote party to have a private communication with.
 * This results in that remote party being removed from the multiParty call which is placed on hold,
 * and the conversation between the served mobile subscriber and the designated remote party being a normal
 * active call. The remaining remote parties may have communication with each other in this state.
 */
int32_t CSControl::SeparateConference(int32_t slotId, const std::string &splitString, int32_t index)
{
    if (splitString.empty()) {
        TELEPHONY_LOGW("SeparateConference, splitString is empty.");
    }

    auto pConnection = FindConnectionByIndex<CsConnectionMap &, CellularCallConnectionCS *>(connectionMap_, index);
    if (pConnection != nullptr) {
        return pConnection->SeparateConferenceRequest(slotId, pConnection->GetIndex(), VOICE_CALL);
    }

    TELEPHONY_LOGI("SeparateConference: connection cannot be matched, use index directly");
    CellularCallConnectionCS connection;
    return connection.SeparateConferenceRequest(slotId, index, VOICE_CALL);
}

/**
 * Add another remote party, to which a private communication has been established using
 * the same procedures as in Section 1.3.8.1, if the number of remote parties does not then
 * exceed the maximum number allowed, which results in an active multiParty call.
 */
int32_t CSControl::CombineConference(int32_t slotId)
{
    CellularCallConnectionCS connectionCs;
    return connectionCs.CombineConferenceRequest(slotId, VOICE_CALL);
}

int32_t CSControl::HangUpAllConnection(int32_t slotId)
{
    TELEPHONY_LOGI("HangUpAllConnection entry");
    CellularCallConnectionCS connection;
    // The AT command for hanging up all calls is the same as the AT command for rejecting calls,
    // so the reject interface is reused.
    return connection.RejectRequest(slotId);
}

bool CSControl::CalculateInternationalRoaming(int32_t slotId) const
{
    bool ret = true;
    ModuleServiceUtils moduleServiceUtils;
    std::string operatorCountryIso = moduleServiceUtils.GetNetworkCountryCode(slotId);
    std::string simCountryIso = moduleServiceUtils.GetIsoCountryCode(slotId);
    ret = !operatorCountryIso.empty() && !simCountryIso.empty() && (operatorCountryIso != simCountryIso);
    if (ret) {
        if (simCountryIso == "us") {
            ret = operatorCountryIso != "vi";
        } else if (simCountryIso == "vi") {
            ret = operatorCountryIso != "us";
        }
    }
    return ret;
}

int32_t CSControl::ReportCallsData(int32_t slotId, const CallInfoList &callInfoList)
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

int32_t CSControl::ReportUpdateInfo(int32_t slotId, const CallInfoList &callInfoList)
{
    TELEPHONY_LOGD("ReportUpdateInfo entry");
    CallsReportInfo callsReportInfo;
    for (int32_t i = 0; i < callInfoList.callSize; ++i) {
        CallReportInfo reportInfo = EncapsulationCallReportInfo(slotId, callInfoList.calls[i]);
        if (callInfoList.callSize == 1 && reportInfo.state == TelCallState::CALL_STATUS_WAITING) {
            TELEPHONY_LOGI("only one call, report incoming state instead of waiting state");
            reportInfo.state = TelCallState::CALL_STATUS_INCOMING;
        }
        auto pConnection = FindConnectionByIndex<CsConnectionMap &, CellularCallConnectionCS *>(
            connectionMap_, callInfoList.calls[i].index);
        if (pConnection == nullptr) {
            CellularCallConnectionCS connection;
            connection.SetOrUpdateCallReportInfo(reportInfo);
            connection.SetFlag(true);
            connection.SetIndex(callInfoList.calls[i].index);
            connection.SetNumber(callInfoList.calls[i].number);
            SetConnectionData(connectionMap_, callInfoList.calls[i].index, connection);
        } else {
            TelCallState preCallState = pConnection->GetStatus();
            pConnection->SetFlag(true);
            pConnection->SetIndex(callInfoList.calls[i].index);
            pConnection->SetOrUpdateCallReportInfo(reportInfo);
            pConnection->SetNumber(callInfoList.calls[i].number);
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
    if (!isIgnoredIncomingCall_) {
        DelayedSingleton<CellularCallRegister>::GetInstance()->ReportCallsInfo(callsReportInfo);
    }
    return TELEPHONY_SUCCESS;
}

void CSControl::DeleteConnection(CallsReportInfo &callsReportInfo, const CallInfoList &callInfoList)
{
    auto it = connectionMap_.begin();
    while (it != connectionMap_.end()) {
        CallReportInfo callReportInfo = it->second.GetCallReportInfo();
        if (!it->second.GetFlag()) {
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

CallReportInfo CSControl::EncapsulationCallReportInfo(int32_t slotId, const CallInfo &callInfo)
{
    CallReportInfo callReportInfo;
    if (memset_s(&callReportInfo, sizeof(callReportInfo), 0, sizeof(callReportInfo)) != EOK) {
        TELEPHONY_LOGE("EncapsulationCallReportInfo return, memset_s fail.");
        return callReportInfo;
    }
    StandardizeUtils standardizeUtils;
    std::string newString = standardizeUtils.FormatNumberAndToa(callInfo.number, callInfo.type);

    /**
     * <idx>: integer type;
     * call identification number as described in 3GPP TS 22.030 [19] subclause 4.5.5.1
     * this number can be used in +CHLD command operations
     * <dir>:
     */
    size_t cpyLen = strlen(newString.c_str()) + 1;
    if (cpyLen > static_cast<size_t>(kMaxNumberLen + 1)) {
        TELEPHONY_LOGE("EncapsulationCallReportInfo return, strcpy_s fail.");
        return callReportInfo;
    }
    if (strcpy_s(callReportInfo.accountNum, cpyLen, newString.c_str()) != EOK) {
        TELEPHONY_LOGE("EncapsulationCallReportInfo return, strcpy_s fail.");
        return callReportInfo;
    }

    /**
     * <stat> (state of the call):
     * 0 active
     * 1 held
     * 2 dialing (MO call)
     * 3 alerting (MO call)
     * 4 incoming (MT call)
     * 5 waiting (MT call)
     */
    callReportInfo.index = callInfo.index;
    callReportInfo.accountId = slotId;
    callReportInfo.voiceDomain = callInfo.voiceDomain;
    callReportInfo.state = static_cast<TelCallState>(callInfo.state);
    callReportInfo.callType = CallType::TYPE_CS;
    callReportInfo.callMode = VideoStateType::TYPE_VOICE;
    callReportInfo.mpty = callInfo.mpty;
    return callReportInfo;
}

int32_t CSControl::ReportIncomingInfo(int32_t slotId, const CallInfoList &callInfoList)
{
    TELEPHONY_LOGI("ReportIncomingInfo entry");
    CallsReportInfo callsReportInfo;
    for (int32_t i = 0; i < callInfoList.callSize; ++i) {
        CallReportInfo cellularCallReportInfo = EncapsulationCallReportInfo(slotId, callInfoList.calls[i]);

        CellularCallConnectionCS connection;
        connection.SetStatus(static_cast<TelCallState>(callInfoList.calls[i].state));
        connection.SetIndex(callInfoList.calls[i].index);
        connection.SetOrUpdateCallReportInfo(cellularCallReportInfo);
        connection.SetNumber(callInfoList.calls[i].number);
        SetConnectionData(connectionMap_, callInfoList.calls[i].index, connection);

        callsReportInfo.callVec.push_back(cellularCallReportInfo);
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

int32_t CSControl::ReportHangUpInfo(int32_t slotId)
{
    TELEPHONY_LOGD("ReportHangUpInfo entry");
    CallsReportInfo callsReportInfo;
    for (auto &it : connectionMap_) {
        CallReportInfo callReportInfo = it.second.GetCallReportInfo();
        callReportInfo.state = TelCallState::CALL_STATUS_DISCONNECTED;
        callReportInfo.accountId = slotId;
        callsReportInfo.callVec.push_back(callReportInfo);
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

int32_t CSControl::ExecutePostDial(int32_t slotId, int64_t callId)
{
    if (connectionMap_.empty()) {
        TELEPHONY_LOGE("connectionMap_ is empty.");
        return TELEPHONY_ERROR;
    }
    auto pConnection = FindConnectionByIndex<CsConnectionMap &, CellularCallConnectionCS *>(connectionMap_, callId);
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

int32_t CSControl::PostDialProceed(const CellularCallInfo &callInfo, const bool proceed)
{
    std::string networkAddress;
    std::string postDialString;
    StandardizeUtils standardizeUtils;
    standardizeUtils.ExtractAddressAndPostDial(callInfo.phoneNum, networkAddress, postDialString);
    auto pConnection = FindConnectionByIndex<CsConnectionMap &, CellularCallConnectionCS *>(
        connectionMap_, callInfo.index);
    if (pConnection == nullptr) {
        TELEPHONY_LOGE("cs pConnection is nullptr!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (proceed) {
        ExecutePostDial(callInfo.slotId, pConnection->GetIndex());
    } else {
        pConnection->SetPostDialCallState(PostDialCallState::POST_DIAL_CALL_CANCELED);
    }
    return TELEPHONY_SUCCESS;
}

void CSControl::ReleaseAllConnection()
{
    connectionMap_.clear();
}

CsConnectionMap CSControl::GetConnectionMap()
{
    return connectionMap_;
}

int32_t CSControl::ReportHangUp(const std::vector<CellularCallInfo> &infos, int32_t slotId)
{
    CallsReportInfo callsReportInfo;
    callsReportInfo.slotId = slotId;
    for (const auto &info : infos) {
        if (info.callType == CallType::TYPE_CS && info.slotId == slotId) {
            CallReportInfo csCallReportInfo;
            if (memset_s(csCallReportInfo.accountNum, kMaxNumberLen + 1, 0, kMaxNumberLen + 1) != EOK) {
                TELEPHONY_LOGE("memset_s fail");
                return TELEPHONY_ERR_MEMSET_FAIL;
            }
            if (memcpy_s(csCallReportInfo.accountNum, kMaxNumberLen, info.phoneNum, kMaxNumberLen) != EOK) {
                TELEPHONY_LOGE("memcpy_s fail");
                return TELEPHONY_ERR_MEMCPY_FAIL;
            }
            csCallReportInfo.index = info.index;
            csCallReportInfo.accountId = info.slotId;
            csCallReportInfo.callType = CallType::TYPE_CS;
            csCallReportInfo.callMode = VideoStateType::TYPE_VOICE;
            csCallReportInfo.state = TelCallState::CALL_STATUS_DISCONNECTED;
            callsReportInfo.callVec.push_back(csCallReportInfo);
        }
    }
    if (DelayedSingleton<CellularCallRegister>::GetInstance() == nullptr) {
        TELEPHONY_LOGE("CellularCallRegister instance is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    DelayedSingleton<CellularCallRegister>::GetInstance()->ReportCallsInfo(callsReportInfo);
    ReleaseAllConnection();
    return TELEPHONY_SUCCESS;
}
} // namespace Telephony
} // namespace OHOS

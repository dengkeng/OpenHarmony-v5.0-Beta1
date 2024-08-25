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

#include "satellite_control.h"

#include "cellular_call_hisysevent.h"
#include "cellular_call_register.h"
#include "module_service_utils.h"
#include "securec.h"
#include "standardize_utils.h"

namespace OHOS {
namespace Telephony {

SatelliteControl::~SatelliteControl()
{
    ReleaseAllConnection();
}

int32_t SatelliteControl::Dial(const CellularCallInfo &callInfo, bool isEcc)
{
    TELEPHONY_LOGI("DialSatellite start");
    DelayedSingleton<CellularCallHiSysEvent>::GetInstance()->SetCallParameterInfo(
        callInfo.slotId, static_cast<int32_t>(callInfo.callType), callInfo.videoState);
    int32_t ret = DialPreJudgment(callInfo, false);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    StandardizeUtils standardizeUtils;
    // Remove the phone number separator
    std::string newPhoneNum = standardizeUtils.RemoveSeparatorsPhoneNumber(callInfo.phoneNum);

    CLIRMode clirMode = CLIRMode::DEFAULT;
    if (IsNeedExecuteMMI(callInfo.slotId, newPhoneNum, clirMode, false)) {
        TELEPHONY_LOGI("DialSatellite return, mmi code type.");
        return RETURN_TYPE_MMI;
    }

    if (!CanCall(connectionMap_)) {
        TELEPHONY_LOGE("DialSatellite return, error type: call state error.");
        CellularCallHiSysEvent::WriteDialCallFaultEvent(callInfo.slotId, static_cast<int32_t>(callInfo.callType),
            callInfo.videoState, CALL_ERR_CALL_COUNTS_EXCEED_LIMIT, "DSatellite dial call state error");
        return CALL_ERR_CALL_COUNTS_EXCEED_LIMIT;
    }

    return EncapsulateDialCommon(callInfo.slotId, newPhoneNum, clirMode);
}

int32_t SatelliteControl::EncapsulateDialCommon(int32_t slotId, const std::string &phoneNum, CLIRMode &clirMode)
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
    CellularCallConnectionSatellite satelliteConnection;
    return satelliteConnection.DialRequest(slotId, dialRequest);
}

int32_t SatelliteControl::HangUp(const CellularCallInfo &callInfo, CallSupplementType type)
{
    TELEPHONY_LOGI("HangUp start");
    switch (type) {
        case CallSupplementType::TYPE_DEFAULT: {
            // Match the session connection according to the phone number string
            auto pConnection = FindConnectionByIndex<SatelliteConnectionMap &, CellularCallConnectionSatellite *>(
                connectionMap_, callInfo.index);
            if (pConnection == nullptr) {
                TELEPHONY_LOGE("HangUp, error type: connection is null");
                CellularCallHiSysEvent::WriteHangUpFaultEvent(
                    callInfo.slotId, callInfo.callId, CALL_ERR_CALL_CONNECTION_NOT_EXIST, "HangUp pConnection is null");
                return CALL_ERR_CALL_CONNECTION_NOT_EXIST;
            }

            if (DelayedSingleton<CellularCallRegister>::GetInstance() != nullptr) {
                DelayedSingleton<CellularCallRegister>::GetInstance()->ReportSingleCallInfo(
                    pConnection->GetCallReportInfo(), TelCallState::CALL_STATUS_DISCONNECTING);
            }
            return pConnection->HangUpRequest(callInfo.slotId);
        }
        default: {
            TELEPHONY_LOGE("HangUp warring, type is invalid");
            CellularCallHiSysEvent::WriteHangUpFaultEvent(
                callInfo.slotId, callInfo.callId, TELEPHONY_ERR_ARGUMENT_INVALID, "HangUp type is invalid");
            return TELEPHONY_ERR_ARGUMENT_INVALID;
        }
    }
}

int32_t SatelliteControl::Answer(const CellularCallInfo &callInfo)
{
    auto pConnection = FindConnectionByIndex<SatelliteConnectionMap &, CellularCallConnectionSatellite *>(
        connectionMap_, callInfo.index);
    if (pConnection == nullptr) {
        TELEPHONY_LOGE("Answer return, error type: connection is null");
        CellularCallHiSysEvent::WriteAnswerCallFaultEvent(callInfo.slotId, callInfo.callId, callInfo.videoState,
            CALL_ERR_CALL_CONNECTION_NOT_EXIST, "get connection data is null");
        return CALL_ERR_CALL_CONNECTION_NOT_EXIST;
    }
    // There is an active call when you call, or third party call waiting
    if (IsInState(connectionMap_, TelCallState::CALL_STATUS_ACTIVE) ||
        pConnection->GetStatus() == TelCallState::CALL_STATUS_WAITING) {
        TELEPHONY_LOGI("Answer there is an active call when you call, or third party call waiting");
        auto con = FindConnectionByState<SatelliteConnectionMap &, CellularCallConnectionSatellite *>(
            connectionMap_, TelCallState::CALL_STATUS_ACTIVE);
        if (con != nullptr) {
            TELEPHONY_LOGI("Answer: There is an active session currently, and it needs to hold");
            con->HangUpRequest(callInfo.slotId);
        } else {
            TELEPHONY_LOGE("Answer return, error type: con is null, there are no active calls");
        }
    }

    if (pConnection->GetStatus() == TelCallState::CALL_STATUS_INCOMING ||
        pConnection->GetStatus() == TelCallState::CALL_STATUS_ALERTING ||
        pConnection->GetStatus() == TelCallState::CALL_STATUS_WAITING) {
        return pConnection->AnswerRequest(callInfo.slotId);
    }

    TELEPHONY_LOGE("SatelliteControl::Answer return, error type: call state error, phone not ringing.");
    CellularCallHiSysEvent::WriteAnswerCallFaultEvent(callInfo.slotId, callInfo.callId, callInfo.videoState,
        CALL_ERR_CALL_STATE, "call state error phone not ringing");
    return CALL_ERR_CALL_STATE;
}

int32_t SatelliteControl::Reject(const CellularCallInfo &callInfo)
{
    auto pConnection = FindConnectionByIndex<SatelliteConnectionMap &, CellularCallConnectionSatellite *>(
        connectionMap_, callInfo.index);
    if (pConnection == nullptr) {
        TELEPHONY_LOGE("SatelliteControl::Reject, error type: connection is null");
        CellularCallHiSysEvent::WriteHangUpFaultEvent(
            callInfo.slotId, callInfo.callId, CALL_ERR_CALL_CONNECTION_NOT_EXIST, "Reject pConnection is null");
        return CALL_ERR_CALL_CONNECTION_NOT_EXIST;
    }
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

int32_t SatelliteControl::ReportSatelliteCallsData(int32_t slotId, const SatelliteCurrentCallList &callInfoList)
{
    if (callInfoList.callSize <= 0 && !connectionMap_.empty()) {
        return ReportHungUpInfo(slotId);
    } else if (callInfoList.callSize > 0 && connectionMap_.empty()) {
        return ReportIncomingInfo(slotId, callInfoList);
    } else if (callInfoList.callSize > 0 && !connectionMap_.empty()) {
        return ReportUpdateInfo(slotId, callInfoList);
    }
    return TELEPHONY_ERROR;
}

int32_t SatelliteControl::ReportUpdateInfo(int32_t slotId, const SatelliteCurrentCallList &callInfoList)
{
    TELEPHONY_LOGD("ReportUpdateInfo entry");
    CallsReportInfo callsReportInfo;
    for (int32_t i = 0; i < callInfoList.callSize; ++i) {
        CallReportInfo reportInfo = EncapsulationCallReportInfo(slotId, callInfoList.calls[i]);

        auto pConnection = FindConnectionByIndex<SatelliteConnectionMap &, CellularCallConnectionSatellite *>(
            connectionMap_, callInfoList.calls[i].index);
        if (pConnection == nullptr) {
            CellularCallConnectionSatellite connection;
            connection.SetOrUpdateCallReportInfo(reportInfo);
            connection.SetFlag(true);
            connection.SetIndex(callInfoList.calls[i].index);
            connection.SetNumber(callInfoList.calls[i].number);
            SetConnectionData(connectionMap_, callInfoList.calls[i].index, connection);
        } else {
            pConnection->SetFlag(true);
            pConnection->SetIndex(callInfoList.calls[i].index);
            pConnection->SetOrUpdateCallReportInfo(reportInfo);
            pConnection->SetNumber(callInfoList.calls[i].number);
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

void SatelliteControl::DeleteConnection(CallsReportInfo &callsReportInfo, const SatelliteCurrentCallList &callInfoList)
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

CallReportInfo SatelliteControl::EncapsulationCallReportInfo(int32_t slotId, const SatelliteCurrentCall &callInfo)
{
    CallReportInfo callReportInfo;
    if (memset_s(&callReportInfo, sizeof(callReportInfo), 0, sizeof(callReportInfo)) != EOK) {
        TELEPHONY_LOGE("EncapsulationCallReportInfo return, memset_s fail.");
        return callReportInfo;
    }
    size_t cpyLen = strlen(callInfo.number.c_str()) + 1;
    if (cpyLen > static_cast<size_t>(kMaxNumberLen + 1)) {
        TELEPHONY_LOGE("EncapsulationCallReportInfo return, strcpy_s fail.");
        return callReportInfo;
    }
    if (strcpy_s(callReportInfo.accountNum, cpyLen, callInfo.number.c_str()) != EOK) {
        TELEPHONY_LOGE("EncapsulationCallReportInfo return, strcpy_s fail.");
        return callReportInfo;
    }
    callReportInfo.index = callInfo.index;
    callReportInfo.accountId = slotId;
    callReportInfo.voiceDomain = callInfo.voiceDomain;
    callReportInfo.state = static_cast<TelCallState>(callInfo.state);
    callReportInfo.callType = CallType::TYPE_SATELLITE;
    callReportInfo.callMode = VideoStateType::TYPE_VOICE;
    callReportInfo.mpty = callInfo.mpty;
    return callReportInfo;
}

int32_t SatelliteControl::ReportIncomingInfo(int32_t slotId, const SatelliteCurrentCallList &callInfoList)
{
    TELEPHONY_LOGI("ReportIncomingInfo entry");
    CallsReportInfo callsReportInfo;
    for (int32_t i = 0; i < callInfoList.callSize; ++i) {
        CallReportInfo cellularCallReportInfo = EncapsulationCallReportInfo(slotId, callInfoList.calls[i]);

        CellularCallConnectionSatellite connection;
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

int32_t SatelliteControl::ReportHungUpInfo(int32_t slotId)
{
    TELEPHONY_LOGD("ReportHungUpInfo entry");
    CallsReportInfo callsReportInfo;
    for (auto &it : connectionMap_) {
        CallReportInfo callReportInfo = it.second.GetCallReportInfo();
        callReportInfo.state = TelCallState::CALL_STATUS_DISCONNECTED;
        callReportInfo.accountId = slotId;
        callsReportInfo.callVec.push_back(callReportInfo);
        GetCallFailReason(slotId, connectionMap_);
    }
    if (DelayedSingleton<CellularCallRegister>::GetInstance() == nullptr) {
        TELEPHONY_LOGE("ReportHungUpInfo return, GetInstance() is nullptr.");
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

void SatelliteControl::ReleaseAllConnection()
{
    connectionMap_.clear();
}

SatelliteConnectionMap SatelliteControl::GetConnectionMap()
{
    return connectionMap_;
}

int32_t SatelliteControl::ReportHangUp(const std::vector<CellularCallInfo> &infos, int32_t slotId)
{
    CallsReportInfo callsReportInfo;
    callsReportInfo.slotId = slotId;
    for (const auto &info : infos) {
        if (info.callType == CallType::TYPE_SATELLITE && info.slotId == slotId) {
            CallReportInfo satelliteCallReportInfo;
            if (memset_s(satelliteCallReportInfo.accountNum, kMaxNumberLen + 1, 0, kMaxNumberLen + 1) != EOK) {
                TELEPHONY_LOGE("memset_s fail");
                return TELEPHONY_ERR_MEMSET_FAIL;
            }
            if (memcpy_s(satelliteCallReportInfo.accountNum, kMaxNumberLen, info.phoneNum, kMaxNumberLen) != EOK) {
                TELEPHONY_LOGE("memcpy_s fail");
                return TELEPHONY_ERR_MEMCPY_FAIL;
            }
            satelliteCallReportInfo.index = info.index;
            satelliteCallReportInfo.accountId = info.slotId;
            satelliteCallReportInfo.callType = CallType::TYPE_SATELLITE;
            satelliteCallReportInfo.callMode = VideoStateType::TYPE_VOICE;
            satelliteCallReportInfo.state = TelCallState::CALL_STATUS_DISCONNECTED;
            callsReportInfo.callVec.push_back(satelliteCallReportInfo);
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

int32_t SatelliteControl::HoldCall(int32_t slotId)
{
    return TELEPHONY_ERROR;
}

int32_t SatelliteControl::UnHoldCall(int32_t slotId)
{
    return TELEPHONY_ERROR;
}

int32_t SatelliteControl::SwitchCall(int32_t slotId)
{
    return TELEPHONY_ERROR;
}

int32_t SatelliteControl::CombineConference(int32_t slotId)
{
    return TELEPHONY_ERROR;
}

int32_t SatelliteControl::HangUpAllConnection(int32_t slotId)
{
    TELEPHONY_LOGI("HangUpAllConnection entry");
    CellularCallConnectionSatellite connection;
    // The AT command for hanging up all calls is the same as the AT command for rejecting calls,
    // so the reject interface is reused.
    connection.RejectRequest(slotId);
    return TELEPHONY_SUCCESS;
}

int32_t SatelliteControl::ReportCallsData(int32_t slotId, const CallInfoList &callInfoList)
{
    return TELEPHONY_ERROR;
}
} // namespace Telephony
} // namespace OHOS

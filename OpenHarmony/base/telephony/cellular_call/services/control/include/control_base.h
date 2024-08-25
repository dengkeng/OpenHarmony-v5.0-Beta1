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

#ifndef CELLULAR_CALL_CONTROL_BASE_H
#define CELLULAR_CALL_CONTROL_BASE_H

#include "call_manager_errors.h"
#include "event_handler.h"
#include "cellular_call_data_struct.h"
#include "telephony_log_wrapper.h"
#include "base_connection.h"
#include "tel_ril_call_parcel.h"
#include "mmi_code_utils.h"

namespace OHOS {
namespace Telephony {
class ControlBase {
public:
    /**
     * constructor
     */
    ControlBase() = default;

    /**
     * destructor
     */
    virtual ~ControlBase() = default;

    /**
     * Dial
     *
     * 27007-430_2001 6.27 Informative examples
     * 3GPP TS 22.030 [19]
     *
     * originate a voice call
     *
     * @param CellularCallInfo
     * @param bool
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t Dial(const CellularCallInfo &callInfo, bool isEcc) = 0;

    /**
     * HangUp
     *
     * 3GPP TS 27.007 V3.9.0 (2001-06) Call related supplementary services +CHLD
     * 3GPP TS 27.007 V3.9.0 (2001-06) 7.22	Informative examples
     * 3GPP TS 22.030 [19]
     *
     * release call
     *
     * @param CellularCallInfo
     * @param CallSupplementType
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t HangUp(const CellularCallInfo &callInfo, CallSupplementType type) = 0;

    /**
     * Answer
     *
     * 27007-430_2001 6.6 Alternating mode call control method
     * 3GPP TS 22.030 [19]
     *
     * Answer an incoming voice call.
     *
     * @param CellularCallInfo
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t Answer(const CellularCallInfo &callInfo) = 0;

    /**
     * Reject
     *
     * 27007-430_2001 6.6 Alternating mode call control method
     * 3GPP TS 22.030 [19]
     *
     * Reject an incoming voice call
     *
     * @param CellularCallInfo
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t Reject(const CellularCallInfo &callInfo) = 0;

    /**
     * HoldCall
     *
     * 22083-400_2001 2 Call hold
     * 3GPP TS 22.030 [3]
     * 3GPP TS 23.083 V4.2.0 (2001-04) 2 Call hold (HOLD)
     *
     * The call hold service allows a served mobile subscriber
     *
     * @param slotId
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t HoldCall(int32_t slotId) = 0;

    /**
     * UnHoldCall
     *
     * 22083-400_2001 2 Call hold
     * 3GPP TS 22.030 [3]
     *
     * Retrieve the held call.
     *
     * @param slotId
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t UnHoldCall(int32_t slotId) = 0;

    /**
     * SwitchCall
     *
     * 22083-400_2001 2 Call hold
     * 3GPP TS 22.030 [3]
     *
     * Alternate from one call to the other
     *
     * @param slotId
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t SwitchCall(int32_t slotId) = 0;

    /**
     * CombineConference
     *
     * 22084-400_2001 1.3.8.2	Managing an active multiParty call
     * 3GPP TS 22.030
     *
     * Add another remote party
     * @param slotId
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t CombineConference(int32_t slotId) = 0;

    /**
     * HangUpAllConnection
     *
     * @param slotId
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t HangUpAllConnection(int32_t slotId) = 0;

    /**
     * ReportCallsData
     *
     * @param slotId
     * @param CallInfoList
     * @returns Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t ReportCallsData(int32_t slotId, const CallInfoList &callInfoList) = 0;

    /**
     * Dial PreJudgment
     *
     * @param CellularCallInfo
     * @returns Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t DialPreJudgment(const CellularCallInfo &callInfo, bool isEcc);

    /**
     * Is Need Execute MMI
     *
     * @param slotId
     * @param std::string phoneString
     * @param CLIRMode
     * @param isNeedUseIms
     * @returns bool
     */
    bool IsNeedExecuteMMI(int32_t slotId, std::string &phoneString, CLIRMode &clirMode, bool isNeedUseIms);

    /**
     * Is Dtmf Key
     *
     * 23014-400_2001 6	Support of DTMF across the air interface
     * 3GPP TS 22.030
     *
     * @param char
     * @returns bool
     */
    bool IsDtmfKey(char c) const;

    bool IsConnectedOut(TelCallState preState, TelCallState curState);

    int32_t SetReadyToCall(int32_t slotId, bool isReadyToCall);

    /**
     * Determine whether the call can be initiated currently
     *
     * @param std::map<std::string, BaseConnection>
     * @return Returns true can to call
     */
    template<typename T>
    bool CanCall(T &&t)
    {
        unsigned int maximumCalls = 6;
        return t.size() <= maximumCalls;
    }

    /**
     * FindConnectionByState
     *
     * @param std::map<std::string, BaseConnection>
     * @param TelCallState
     * @return pointer
     */
    template<typename T1, typename T2>
    T2 FindConnectionByState(const T1 &&t1, TelCallState state) const
    {
        for (auto &it : t1) {
            T2 pConnection = &it.second;
            if (pConnection != nullptr && pConnection->GetStatus() == state) {
                return pConnection;
            }
        }
        return nullptr;
    }

    /**
     * FindConnectionByIndex
     *
     * @param std::map<std::string, BaseConnection>
     * @param index
     * @return pointer
     */
    template<typename T1, typename T2>
    T2 FindConnectionByIndex(const T1 &&t1, int32_t index) const
    {
        for (auto &it : t1) {
            T2 pConnection = &it.second;
            if (pConnection != nullptr && pConnection->GetIndex() == index) {
                return pConnection;
            }
        }
        return nullptr;
    }

    /**
     * SetConnectionData
     *
     * @param std::map<std::string, BaseConnection>
     * @param string phoneNum
     * @param BaseConnection
     * @return bool
     */
    template<typename T1, typename T2>
    bool SetConnectionData(T1 &&t1, const int32_t &key, const T2 &con)
    {
        if (!t1.insert(std::make_pair(key, con)).second) {
            TELEPHONY_LOGE("SetConnectionData, key already exists.");
            return false;
        }
        return true;
    }

    /**
     * Determines if a connection is currently in this state
     *
     * @param std::map<std::string, BaseConnection>
     * @param TelCallState
     * @return Returns true or false
     */
    template<typename T1>
    bool IsInState(T1 &&t, TelCallState state)
    {
        for (const auto &it : t) {
            auto pConnection = &it.second;
            if (pConnection != nullptr && pConnection->GetStatus() == state) {
                return true;
            }
        }
        return false;
    }

    /**
     * StartDtmf
     *
     * 23014-400_2001 6	Support of DTMF across the air interface
     * 3GPP TS 22.030
     *
     * START DTMF : Containing the digit value (0-9,A,B,C,D,*,#)
     * @param std::map<std::string, BaseConnection>
     * @param Dtmf Code
     * @param CellularCallInfo
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    template<typename T>
    int32_t StartDtmf(T &&t, char cDtmfCode, const CellularCallInfo &callInfo) const
    {
        /**
         * The messages when sent across the air interface should contain the following information:
         * a) START DTMF : Containing the digit value (0-9,A,B,C,D,*,#);
         * b) START DTMF ACKNOWLEDGE: Containing the digit value (0-9,A,B,C,D,*,#) corresponding to the DTMF tone that
         * the network applies towards the remote user;
         * c) STOP DTMF : No further info;
         * d) STOP DTMF ACKNOWLEDGE: No further info.
         * Only a single digit will be passed in each START DTMF and START DTMF ACKNOWLEDGE message
         */
        TELEPHONY_LOGD("ControlBase::StartDtmf start");
        auto pConnection = FindConnectionByIndex<T &, decltype(&t.begin()->second)>(t, callInfo.index);

        if (pConnection == nullptr) {
            TELEPHONY_LOGE("StartDtmf, error type: connection is null");
            return CALL_ERR_CALL_CONNECTION_NOT_EXIST;
        }
        if (!IsDtmfKey(cDtmfCode)) {
            TELEPHONY_LOGE("StartDtmf return, error type: cDtmfCode invalid.");
            return CALL_ERR_PARAMETER_OUT_OF_RANGE;
        }
        return pConnection->StartDtmfRequest(callInfo.slotId, cDtmfCode, pConnection->GetIndex());
    }

    /**
     * StopDtmf
     *
     * 23014-400_2001 6	Support of DTMF across the air interface
     * 3GPP TS 22.030
     *
     * STOP DTMF : No further info
     * @param std::map<std::string, BaseConnection>
     * @param CellularCallInfo
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    template<typename T>
    int32_t StopDtmf(T &&t, const CellularCallInfo &callInfo) const
    {
        /**
         * The messages when sent across the air interface should contain the following information:
         * a) START DTMF : Containing the digit value (0-9,A,B,C,D,*,#);
         * b) START DTMF ACKNOWLEDGE: Containing the digit value (0-9,A,B,C,D,*,#) corresponding to the DTMF tone that
         * the network applies towards the remote user;
         * c) STOP DTMF : No further info;
         * d) STOP DTMF ACKNOWLEDGE: No further info.
         * Only a single digit will be passed in each START DTMF and START DTMF ACKNOWLEDGE message
         */
        TELEPHONY_LOGD("ControlBase::StopDtmf start");
        auto pConnection = FindConnectionByIndex<T &, decltype(&t.begin()->second)>(t, callInfo.index);
        if (pConnection == nullptr) {
            TELEPHONY_LOGE("StopDtmf, error type: connection is null");
            return CALL_ERR_CALL_CONNECTION_NOT_EXIST;
        }
        return pConnection->StopDtmfRequest(callInfo.slotId, pConnection->GetIndex());
    }

    /**
     * SendDtmf
     *
     * 23014-400_2001 6	Support of DTMF across the air interface
     * 3GPP TS 22.030
     *
     * @param std::map<std::string, BaseConnection>
     * @param Dtmf Code
     * @param CellularCallInfo
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    template<typename T>
    int32_t SendDtmf(T &&t, char cDtmfCode, const CellularCallInfo &callInfo) const
    {
        /**
         * 3gpp 27007-430_2001
         *
         * C.2.11	DTMF and tone generation +VTS
         *
         * This command allows the transmission of DTMF tones and arbitrary tones (see note).
         * These tones may be used (for example) when announcing the start of a recording period.
         * The command is write only.
         * In this profile of commands, this command does not operate in data or fax modes of operation (+FCLASS=0,1,2
         7). NOTE 1:	D is used only for dialling.

         The string parameter of the command consists of combinations of the following separated by commas:
         1. <DTMF>. A single ASCII character in the set 0 9, #,*,A D.
         This is interpreted as a single ACSII character whose duration is set by the +VTD command.
            NOTE 2:	In GSM this operates only in voice mode.
         2. [<tone1>,<tone2>,<duration>].
         This is interpreted as a dual tone of frequencies <tone1> and <tone2>, lasting for a time <duration> (in 10
         ms multiples). NOTE 3:	This does not operate in GSM.
         3. {<DTMF>,<duration>}. This is interpreted as a DTMF tone of different duration from that mandated by the
         +VTD command. NOTE 4:	In GSM this operates only in voice mode.
         */
        TELEPHONY_LOGD("ControlBase::SendDtmf start");
        auto pConnection = FindConnectionByIndex<T &, decltype(&t.begin()->second)>(t, callInfo.index);
        if (pConnection == nullptr) {
            TELEPHONY_LOGE("SendDtmf, error type: connection is null");
            return CALL_ERR_CALL_CONNECTION_NOT_EXIST;
        }
        if (!IsDtmfKey(cDtmfCode)) {
            TELEPHONY_LOGE("SendDtmf return, error type: cDtmfCode invalid.");
            return CALL_ERR_PARAMETER_OUT_OF_RANGE;
        }
        return pConnection->SendDtmfRequest(callInfo.slotId, cDtmfCode, pConnection->GetIndex());
    }

    /**
     * GetCallFailReason
     *
     * 3GPP TS 24.008 V17.4.0 (2021-09) 10.5.4.11	Cause
     *
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    template<typename T>
    int32_t GetCallFailReason(int32_t slotId, T &&t) const
    {
        decltype(t.begin()->second) connection;
        return connection.GetCallFailReasonRequest(slotId);
    }

protected:
    bool isIgnoredIncomingCall_ = false;

private:
    /**
     * Check call with airplane mode on
     */
    bool CheckAirplaneModeScene(const CellularCallInfo &callInfo);

    /**
     * check call with activate sim
    */
    bool CheckActivateSimScene(int32_t slotId);

    /**
     * Handle call with airplane mode on
     */
    int32_t HandleEcc(const CellularCallInfo &callInfo, bool isEcc, bool isAirplaneModeOn, bool isActivateSim);

private:
    std::shared_ptr<AppExecFwk::EventRunner> eventLoop_;
    std::condition_variable cv_;
    std::mutex mutex_;
};
} // namespace Telephony
} // namespace OHOS

#endif // CELLULAR_CALL_CONTROL_BASE_H

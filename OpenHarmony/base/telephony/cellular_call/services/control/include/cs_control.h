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

#ifndef CELLULAR_CALL_CONTROL_CS_H
#define CELLULAR_CALL_CONTROL_CS_H

#include "call_manager_inner_type.h"

#include "tel_ril_call_parcel.h"
#include "cellular_call_connection_cs.h"
#include "control_base.h"

namespace OHOS {
namespace Telephony {
using CsConnectionMap = std::map<int32_t, CellularCallConnectionCS>;
class CSControl : public ControlBase {
public:
    /**
     *  new CSControl
     *
     */
    CSControl() = default;

    /**
     * ~CSControl destructor
     */
    ~CSControl();

    /**
     * CS Dial
     *
     * 27007-430_2001 6.27 Informative examples
     * 3GPP TS 22.030 [19]
     */
    int32_t Dial(const CellularCallInfo &callInfo, bool isEcc) override;

    /**
     * CSControl HangUp
     *
     * 27007-430_2001 7.13 Call related supplementary services +CHLD
     * 3GPP TS 22.030 [19]
     *
     * release the active call
     *
     * @param CellularCallInfo
     * @param CallSupplementType
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t HangUp(const CellularCallInfo &callInfo, CallSupplementType type) override;

    /**
     * CSControl Answer
     *
     * 27007-430_2001 6.6 Alternating mode call control method
     * 3GPP TS 22.030 [19]
     *
     * Answer an incoming voice call.
     *
     * @param CellularCallInfo
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t Answer(const CellularCallInfo &callInfo) override;

    /**
     * CSControl Reject
     *
     * 27007-430_2001 6.6 Alternating mode call control method
     * 3GPP TS 22.030 [19]
     *
     * Reject an incoming voice call
     *
     * @param CellularCallInfo
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t Reject(const CellularCallInfo &callInfo) override;

    /**
     * CSControl HoldCall
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
    int32_t HoldCall(int32_t slotId) override;

    /**
     * CSControl UnHoldCall
     *
     * 22083-400_2001 2 Call hold
     * 3GPP TS 22.030 [3]
     *
     * Retrieve the held call.
     *
     * @param slotId
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t UnHoldCall(int32_t slotId) override;

    /**
     * CSControl SwitchCall
     *
     * 22083-400_2001 2 Call hold
     * 3GPP TS 22.030 [3]
     *
     * Alternate from one call to the other
     *
     * @param slotId
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SwitchCall(int32_t slotId) override;

    /**
     * CSControl CombineConference
     *
     * 22084-400_2001 1.3.8.2	Managing an active multiParty call
     * 3GPP TS 22.030
     *
     * Add another remote party
     * @param slotId
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t CombineConference(int32_t slotId) override;

    /**
     * CSControl SeparateConference
     *
     * 22084-400_2001 1.3.8.2	Managing an active multiParty call
     * 3GPP TS 22.030
     *
     * Separate a remote party
     * @param slotId
     * @param std::string splitString
     * @param index
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SeparateConference(int32_t slotId, const std::string &splitString, int32_t index);

    /**
     * HangUpAllConnection
     *
     * @param slotId
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t HangUpAllConnection(int32_t slotId) override;

    /**
     * CSControl ReleaseAllConnection
     */
    void ReleaseAllConnection();

    /**
     * CSControl GetConnectionMap
     *
     * @return CsConnectionMap
     */
    CsConnectionMap GetConnectionMap();

    /**
     * CSControl ReportCallsData
     *
     * @returns Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t ReportCallsData(int32_t slotId, const CallInfoList &callInfoList) override;

    int32_t ExecutePostDial(int32_t slotId, int64_t callId);

    int32_t PostDialProceed(const CellularCallInfo &callInfo, const bool proceed);

    int32_t ReportHangUp(const std::vector<CellularCallInfo> &infos, int32_t slotId);

    /**
     * Report being hang up data
     *
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t ReportHangUpInfo(int32_t slotId);

private:
    /**
     * Calculate International Roaming
     *
     * @param slotId
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    bool CalculateInternationalRoaming(int32_t slotId) const;

    /**
     * Report Incoming info
     *
     * @param CallInfoList
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t ReportIncomingInfo(int32_t slotId, const CallInfoList &list);

    /**
     * Report update info
     *
     * @param CallInfoList
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t ReportUpdateInfo(int32_t slotId, const CallInfoList &list);

    /**
     * Encapsulation CallReportInfo
     *
     * @param callInfo
     * @return CallReportInfo
     */
    CallReportInfo EncapsulationCallReportInfo(int32_t slotId, const CallInfo &callInfo);

    /**
     * DeleteConnection Connection send
     *
     * @param CallsReportInfo
     * @param CallInfoList
     */
    void DeleteConnection(CallsReportInfo &callsResponseInfo, const CallInfoList &callInfoList);

    /**
     * Dial Cdma
     *
     * @param CellularCallInfo
     * @returns Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t DialCdma(const CellularCallInfo &callInfo);

    /**
     *  Dial Gsm
     *
     * @param CellularCallInfo
     * @returns Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t DialGsm(const CellularCallInfo &callInfo);

    /**
     * Encapsulate Dial Common
     *
     * @param std::string phoneNum
     * @param CLIRMode clirMode
     * @returns Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t EncapsulateDialCommon(int32_t slotId, const std::string &phoneNum, CLIRMode &clirMode);

    /**
     * Check if active and holding call exist, hangup all holding call
     *
     */
    int32_t CheckAndHangupHoldingCall();

private:
    CsConnectionMap connectionMap_; // save callConnection map
    std::string pendingPhoneNumber_;
    const int32_t VOICE_CALL = 0;
};
} // namespace Telephony
} // namespace OHOS

#endif // CELLULAR_CALL_CONTROL_CS_H

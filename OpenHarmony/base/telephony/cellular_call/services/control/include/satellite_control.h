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

#ifndef CELLULAR_CALL_CONTROL_SATELLITE_H
#define CELLULAR_CALL_CONTROL_SATELLITE_H

#include "call_manager_inner_type.h"
#include "cellular_call_connection_satellite.h"
#include "control_base.h"
#include "tel_ril_call_parcel.h"
#include "satellite_call_types.h"

namespace OHOS {
namespace Telephony {
using SatelliteConnectionMap = std::map<int32_t, CellularCallConnectionSatellite>;
class SatelliteControl : public ControlBase {
public:
    /**
     *  new SatelliteControl
     *
     */
    SatelliteControl() = default;

    /**
     * ~SatelliteControl destructor
     */
    ~SatelliteControl();

    /**
     *  Dial Satellite
     *
     * @param CellularCallInfo
     * @returns Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t Dial(const CellularCallInfo &callInfo, bool isEcc) override;

    /**
     * SatelliteControl HangUp
     *
     * release the active call
     *
     * @param CellularCallInfo
     * @param CallSupplementType
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t HangUp(const CellularCallInfo &callInfo, CallSupplementType type) override;

    /**
     * SatelliteControl Answer
     *
     * Answer an incoming voice call.
     *
     * @param CellularCallInfo
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t Answer(const CellularCallInfo &callInfo) override;

    /**
     * SatelliteControl Reject
     *
     * Reject an incoming voice call
     *
     * @param CellularCallInfo
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t Reject(const CellularCallInfo &callInfo) override;

    /**
     * SatelliteControl GetConnectionMap
     *
     * @return CsConnectionMap
     */
    SatelliteConnectionMap GetConnectionMap();

    /**
     * SatelliteControl ReleaseAllConnection
     */
    void ReleaseAllConnection();

    /**
     * SatelliteControl ReportSatelliteCallsData.
     *
     * @param slotId
     * @param CallInfoList
     * @returns Error Code: Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    int32_t ReportSatelliteCallsData(int32_t slotId, const SatelliteCurrentCallList &callInfoList);

    /**
     * SatelliteControl ReportCallsData
     *
     * @returns Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t ReportCallsData(int32_t slotId, const CallInfoList &callInfoList) override;

    int32_t ReportHangUp(const std::vector<CellularCallInfo> &infos, int32_t slotId);

    /**
     * HoldCall
     *
     * @param slotId
     * @return Error Code: Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    int32_t HoldCall(int32_t slotId) override;

    /**
     * UnHoldCall
     *
     * @param slotId
     * @return Error Code: Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    int32_t UnHoldCall(int32_t slotId) override;

    /**
     * SwitchCall
     *
     * @param slotId
     * @return Error Code: Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    int32_t SwitchCall(int32_t slotId) override;

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
    int32_t CombineConference(int32_t slotId) override;

    /**
     * HangUpAllConnection
     *
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t HangUpAllConnection(int32_t slotId) override;

private:
    /**
     * Report being hung up data
     *
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t ReportHungUpInfo(int32_t slotId);

    /**
     * Report Incoming info
     *
     * @param SatelliteCurrentCallList
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t ReportIncomingInfo(int32_t slotId, const SatelliteCurrentCallList &list);

    /**
     * Report update info
     *
     * @param SatelliteCurrentCallList
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t ReportUpdateInfo(int32_t slotId, const SatelliteCurrentCallList &list);

    /**
     * Encapsulation CallReportInfo
     *
     * @param SatelliteCurrentCall
     * @return CallReportInfo
     */
    CallReportInfo EncapsulationCallReportInfo(int32_t slotId, const SatelliteCurrentCall &callInfo);

    /**
     * DeleteConnection Connection send
     *
     * @param CallsReportInfo
     * @param SatelliteCurrentCallList
     */
    void DeleteConnection(CallsReportInfo &callsResponseInfo, const SatelliteCurrentCallList &callInfoList);

    /**
     * Encapsulate Dial Common
     *
     * @param std::string phoneNum
     * @param CLIRMode clirMode
     * @returns Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t EncapsulateDialCommon(int32_t slotId, const std::string &phoneNum, CLIRMode &clirMode);

private:
    SatelliteConnectionMap connectionMap_; // save callConnection map
    std::string pendingPhoneNumber_;
};
} // namespace Telephony
} // namespace OHOS

#endif // CELLULAR_CALL_CONTROL_SATELLITE_H

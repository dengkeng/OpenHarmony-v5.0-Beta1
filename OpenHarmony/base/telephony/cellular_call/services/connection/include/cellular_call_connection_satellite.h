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

#ifndef CELLULAR_CALL_CONNECTION_SATELLITE_H
#define CELLULAR_CALL_CONNECTION_SATELLITE_H

#include "base_connection.h"
#include "tel_ril_call_parcel.h"

namespace OHOS {
namespace Telephony {
class CellularCallConnectionSatellite : public BaseConnection {
public:
    /**
     * Constructor
     */
    CellularCallConnectionSatellite() = default;

    /**
     * Destructor
     */
    ~CellularCallConnectionSatellite() = default;

    /**
     * DialRequest
     *
     * @param slotId
     * @param DialRequestStruct
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t DialRequest(int32_t slotId, const DialRequestStruct &dialRequest);

    /**
     * HangUpRequest
     *
     * @param slotId
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t HangUpRequest(int32_t slotId);

    /**
     * AnswerRequest
     *
     * @param slotId
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t AnswerRequest(int32_t slotId);

    /**
     * RejectRequest
     *
     * @param slotId
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t RejectRequest(int32_t slotId);

    /**
     * SatelliteControl GetSatelliteCallsDataRequest
     *
     * 27007-430_2001 7.18 List current calls +CLCC
     * 3GPP TS 22.030 [19]
     *
     * Returns list of current calls of ME.
     *
     * @param slotId
     * @param lastCallsDataFlag
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetSatelliteCallsDataRequest(int32_t slotId, int64_t lastCallsDataFlag);

    /**
     * Get Call Fail Reason Request
     *
     * @param slotId
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetCallFailReasonRequest(int32_t slotId) const;

    /**
     * RegisterHandler
     */
    void RegisterHandler();
};
} // namespace Telephony
} // namespace OHOS

#endif // CELLULAR_CALL_CONNECTION_SATELLITE_H
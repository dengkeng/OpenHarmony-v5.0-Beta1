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

#ifndef TELEPHONY_SATELLITE_CALL_TYPES_H
#define TELEPHONY_SATELLITE_CALL_TYPES_H

#include "call_manager_errors.h"
#include "call_manager_inner_type.h"
#include "tel_ril_call_parcel.h"

namespace OHOS {
namespace Telephony {

/**
 * @brief Indicates the information of SatelliteCall.
 */
struct SatelliteCallInfo {
    /**
     * Indicates the call phone number,its initial value is 0.
     */
    char phoneNum[kMaxNumberLen] = { 0 };
    /**
     * Indicates the slotId.
     */
    int32_t slotId = 0;
    /**
     * Indicates the call index and its initial value is 0.
     */
    int32_t index = 0;
};

/**
 * @brief Indicates the call status information.
 */
struct SatelliteCurrentCall {
    /**
     * Indicates connection Index for use with, eg, AT+CHLD.
     */
    int32_t index = 0;
    /**
     * Indicates the call direction, The value 0 indicates mobile originated (MO) call,
     * and the value 1 indicates mobile terminated (MT) call.
     */
    int32_t dir = 0;
    /**
     * Indicates the call state:
     * - 0: activated state
     * - 1: holding state
     * - 2: MO call, dialing state
     * - 3: MO call, alerting state
     * - 4: MT call, incoming call state
     * - 5: MT call, call waiting state
     */
    int32_t state = 0;
    /**
     * Indicates the call mode:
     * - 0: voice call
     * - 1: data call
     * - 2: fax
     */
    int32_t mode = 0;
    /**
     * Indicates the multiparty call status:
     * - 0: not one of multiparty (conference) call parties
     * - 1: one of multiparty (conference) call parties
     */
    int32_t mpty = 0;
    /**
     * Identifies the service domain:
     * - 0: CS domain phone
     * - 1: IMS domain phone
     */
    int32_t voiceDomain = 0;
    /**
     * Indicates the call type:
     * - 0: Voice call
     * - 1: VT_TX Video call: send one-way video, two-way voice
     * - 2: VT_RX Video call: one-way receiving video, two-way voice
     * - 3: VT Video call: two-way video, two-way voice
     */
    int32_t callType = 0;
    /**
     * Indicates remote party number.
     */
    std::string number = "";
    /**
     * Indicates the type of address octet in integer format.
     */
    int32_t type = 0;
    /**
     * Indicates alphanumeric representation of <number> corresponding to the entry found in phonebook;
     */
    std::string alpha = "";
    /**
     * Indicates the type of address, eg 145 = intl.
     */
    int32_t toa = 0;
};

/**
 * @brief Indicates the call status information list.
 */
struct SatelliteCurrentCallList {
    /**
     * Indicates the size of call status information list.
     */
    int32_t callSize = 0;
    /**
     * Indicates the ID of call status information list.
     */
    int32_t flag = 0;
    /**
     * Indicates the call status information list.
     */
    std::vector<SatelliteCurrentCall> calls {};
};
} // namespace Telephony
} // namespace OHOS

#endif // TELEPHONY_SATELLITE_CALL_TYPES_H
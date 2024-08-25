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

#ifndef TELEPHONY_SATELLITE_CALL_INTERFACE_H
#define TELEPHONY_SATELLITE_CALL_INTERFACE_H

#include "cellular_call_data_struct.h"
#include "iremote_broker.h"
#include "satellite_call_callback_interface.h"
#include "satellite_call_types.h"

namespace OHOS {
namespace Telephony {
class SatelliteCallInterface : public IRemoteBroker {
public:
    /**
     * @brief Satellite dial the call interface
     *
     * @param SatelliteCallInfo Indicates the call detail information, contains phone number, slot id,
     * video state, call index
     * @param CLIRMode Indicates the CLIR mode, like default, transfer, inhibition
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t Dial(const SatelliteCallInfo &callInfo, CLIRMode mode) = 0;

    /**
     * @brief Satellite HangUp the call interface
     *
     * @param slotId Indicates the card slot index number
     * @param index Indicates the call id
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t HangUp(int32_t slotId, int32_t index) = 0;

    /**
     * @brief Satellite Reject the call with reason interface
     *
     * @param slotId Indicates the card slot index number,
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t Reject(int32_t slotId) = 0;

    /**
     * @brief Satellite Answer the call interface
     *
     * @param slotId Indicates the card slot index number,
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t Answer(int32_t slotId) = 0;

    /**
     * @brief Get Satellite Calls Data Request
     *
     * @param slotId Indicates the card slot index number,
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t GetSatelliteCallsDataRequest(int32_t slotId) = 0;

    /**
     * @brief Register CallBack ptr
     *
     * @param sptr<SatelliteCallCallbackInterface>
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t RegisterSatelliteCallCallback(const sptr<SatelliteCallCallbackInterface> &callback) = 0;

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Telephony.SatelliteCallInterface");
};
} // namespace Telephony
} // namespace OHOS

#endif // TELEPHONY_SATELLITE_CALL_INTERFACE_H
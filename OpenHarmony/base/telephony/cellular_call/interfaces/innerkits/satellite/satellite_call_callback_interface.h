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

#ifndef TELEPHONY_SATELLITE_CALL_CALLBACK_INTERFACE_H
#define TELEPHONY_SATELLITE_CALL_CALLBACK_INTERFACE_H

#include "call_manager_inner_type.h"
#include "tel_ril_call_parcel.h"
#include "iremote_broker.h"
#include "satellite_call_types.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
class SatelliteCallCallbackInterface : public IRemoteBroker {
public:
    virtual ~SatelliteCallCallbackInterface() = default;

    /**
     * @brief DialSatelliteResponse the result of dial by satellite.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param info Indicates dial action was success or failure.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t DialSatelliteResponse(int32_t slotId, const RadioResponseInfo &info) = 0;

    /**
     * @brief HangUpSatelliteResponse the result of hang up by satellite.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param info Indicates hang up action was success or failure.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t HangUpSatelliteResponse(int32_t slotId, const RadioResponseInfo &info) = 0;

    /**
     * @brief RejectSatelliteResponse the result of reject with reason by satellite.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param info Indicates reject action was success or failure.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t RejectSatelliteResponse(int32_t slotId, const RadioResponseInfo &info) = 0;

    /**
     * @brief AnswerSatelliteResponse the result of answer by satellite.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param info Indicates answer action was success or failure.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t AnswerSatelliteResponse(int32_t slotId, const RadioResponseInfo &info) = 0;

    /**
     * @brief CallStateChangeReport receive call state changed notification with slotId by satellite.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t CallStateChangeReport(int32_t slotId) = 0;

    /**
     * @brief GetSatelliteCallsDataResponse the result of get satellite calls data by satellite.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param info Indicates get action was success or failure.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t GetSatelliteCallsDataResponse(int32_t slotId, const RadioResponseInfo &info) = 0;

    /**
     * @brief GetSatelliteCallsDataResponse the result of get ims calls data by satellite.
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param callList Indicates the result of get ims current call list.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t GetSatelliteCallsDataResponse(int32_t slotId, const SatelliteCurrentCallList &callList) = 0;

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Telephony.SatelliteCallCallback");
};
} // namespace Telephony
} // namespace OHOS

#endif // TELEPHONY_SATELLITE_CALL_CALLBACK_INTERFACE_H

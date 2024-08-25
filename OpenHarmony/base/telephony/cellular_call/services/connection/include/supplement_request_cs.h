/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef CELLULAR_CALL_SUPPLEMENT_REQUEST_CS_H
#define CELLULAR_CALL_SUPPLEMENT_REQUEST_CS_H

#include "base_request.h"
#include "cellular_call_handler.h"

namespace OHOS {
namespace Telephony {
class SupplementRequestCs : BaseRequest {
public:
    /**
     * @brief GetClipRequest Get Clip Request
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param index Indicates the index of command.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    int32_t GetClipRequest(int32_t slotId, int32_t index);

    /**
     * @brief SetClirRequest Set Clir Request
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param action Indicates the action for SetClir,
     * 1, means turn on clir; 0, means turn off clir.
     * @param index Indicates the index of command.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    int32_t SetClirRequest(int32_t slotId, int32_t action, int32_t index);

    /**
     * @brief GetClirRequest Get Clir Request
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param index Indicates the index of command.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    int32_t GetClirRequest(int32_t slotId, int32_t index);

    /**
     * @brief GetCallTransferRequest Get Call Transfer Request
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param reason Indicates the reason of the get call transfer.
     * @param index Indicates the index of command.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    int32_t GetCallTransferRequest(int32_t slotId, int32_t reason, int32_t index);

    /**
     * @brief SetCallTransferRequest Set Call Transfer Request
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param callTransferParam Indicates reason/mode/transferNum/classType of the set call transfer.
     * @param index Indicates the index of command.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    int32_t SetCallTransferRequest(int32_t slotId, const CallTransferParam &callTransferParam, int32_t index);

    /**
     * @brief GetCallRestrictionRequest Get Call Restriction Request
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param fac Indicates the facility of the get call restriction.
     * @param index Indicates the index of command.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    int32_t GetCallRestrictionRequest(int32_t slotId, const std::string &fac, int32_t index);

    /**
     * @brief SetCallRestrictionRequest Set Call Restriction Request
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param fac Indicates the facility of the set call restriction.
     * @param mode Indicates the mode of the set call restriction.
     * @param pw Indicates password or "" if not required.
     * @param index Indicates the index of command.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    int32_t SetCallRestrictionRequest(
        int32_t slotId, const std::string &fac, int32_t mode, const std::string &pw, int32_t index);

    /**
     * @brief GetCallRestrictionRequest Get Call Restriction Request
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param restrictionType Indicates the facility of the get call restriction.
     * @param index Indicates the index of command.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    int32_t SetBarringPasswordRequest(int32_t slotId, const std::string &restrictionType,
        int32_t index, const char *oldPassword, const char *newPassword);

    /**
     * @brief SetCallWaitingRequest Set CallWaiting Request
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param activate Indicates the action for SetCallWaiting,
     * true, means turn on CallWaiting; false, means turn off CallWaiting.
     * @param classType Call waiting and conditions +CCWA,
     * the value was {@code ServiceClassType}, See 3GPP TS 22.083.
     * @param index Indicates the index of command.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    int32_t SetCallWaitingRequest(int32_t slotId, bool activate, int32_t classType, int32_t index);

    /**
     * @brief GetCallWaitingRequest Get Call Waiting Request
     *
     * @param slotId Indicates the card slot index number,
     * ranging from {@code 0} to the maximum card slot index number supported by the device.
     * @param index Indicates the index of command.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    int32_t GetCallWaitingRequest(int32_t slotId, int32_t index);

    /**
     * Send ussd Request
     *
     * @param msg
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SendUssdRequest(int32_t slotId, const std::string &msg);

    /**
     * SIM PIN unlock
     *
     * @param slotId The ID of SIM slot
     * @param newPin The new pin code for unlock SIM
     * @param oldPin The old pin code for unlock SIM
     * @return Returns true on success.
     */
    int32_t AlterPinPassword(int32_t slotId, std::string newPin, std::string oldPin);

    /**
     * SIM PUK unlock
     *
     * @param slotId The ID of SIM slot
     * @param newPin  The new pin code for unlock SIM
     * @param puk The puk code for unlock SIM
     * @return Returns true on success.
     */
    int32_t UnlockPuk(int32_t slotId, std::string newPin, std::string puk);

    /**
     * SIM PIN2 unlock
     *
     * @param slotId The ID of SIM slot
     * @param newPin2 The new pin2 code for unlock SIM
     * @param oldPin2 The old pin2 code for unlock SIM
     * @return Returns true on success.
     */
    int32_t AlterPin2Password(int32_t slotId, std::string newPin2, std::string oldPin2);

    /**
     * SIM PUK2 unlock
     *
     * @param slotId The ID of SIM slot
     * @param newPin2 The new pin2 code for unlock SIM
     * @param puk2 The puk2 code for unlock SIM
     * @return Returns true on success.
     */
    int32_t UnlockPuk2(int32_t slotId, std::string newPin2, std::string puk2);

    /**
     * Close Unfinished ussd
     *
     * @param slotId The ID of SIM slot
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t CloseUnFinishedUssdRequest(int32_t slotId);

private:
    /**
     * GetMMIHandler
     *
     * @return std::shared_ptr<MMIHandler>
     */
    std::shared_ptr<CellularCallHandler> GetMMIHandler(int32_t slotId) const;

private:
    ModuleServiceUtils moduleUtils_;
};
} // namespace Telephony
} // namespace OHOS
#endif // CELLULAR_CALL_SUPPLEMENT_REQUEST_CS_H

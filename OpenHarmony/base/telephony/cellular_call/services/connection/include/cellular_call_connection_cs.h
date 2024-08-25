/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef CELLULAR_CALL_CONNECTION_CS_H
#define CELLULAR_CALL_CONNECTION_CS_H

#include "tel_ril_call_parcel.h"
#include "base_connection.h"

namespace OHOS {
namespace Telephony {
class CellularCallConnectionCS : public BaseConnection {
public:
    /**
     * Constructor
     */
    CellularCallConnectionCS() = default;

    /**
     * Destructor
     */
    ~CellularCallConnectionCS() = default;

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
     * SwitchCallRequest
     *
     * @param slotId
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SwitchCallRequest(int32_t slotId);

    /**
     * HoldRequest
     *
     * @param slotId
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t HoldRequest(int32_t slotId);

    /**
     * UnHoldCallRequest
     *
     * @param slotId
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t UnHoldCallRequest(int32_t slotId);

    /**
     * CombineConferenceRequest
     *
     * @param slotId
     * @param voiceCall
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t CombineConferenceRequest(int32_t slotId, int32_t voiceCall);

    /**
     * SeparateConferenceRequest
     *
     * @param slotId
     * @param index
     * @param voiceCall
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SeparateConferenceRequest(int32_t slotId, int32_t index, int32_t voiceCall);

    /**
     * CallSupplement Request
     *
     * 22083-400_2001 2 Call hold
     * 3GPP TS 22.030 [3]
     *
     * @param slotId
     * @param CallSupplementType
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t CallSupplementRequest(int32_t slotId, CallSupplementType type);

    /**
     * CSControl GetCsCallsDataRequest
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
    int32_t GetCsCallsDataRequest(int32_t slotId, int64_t lastCallsDataFlag);

    /**
     * SendCDMAThreeWayDialRequest
     *
     * @param slotId
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SendCDMAThreeWayDialRequest(int32_t slotId);

    /**
     * SendDtmfRequest
     *
     * @param slotId
     * @param char cDtmfCode
     * @param index
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SendDtmfRequest(int32_t slotId, char cDtmfCode, int32_t index) const;

    /**
     * StartDtmfRequest
     *
     * @param slotId
     * @param char cDtmfCode
     * @param index
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t StartDtmfRequest(int32_t slotId, char cDtmfCode, int32_t index) const;

    /**
     * StopDtmfRequest
     *
     * @param slotId
     * @param index
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t StopDtmfRequest(int32_t slotId, int32_t index) const;

    /**
     * GetCallFailReasonRequest
     *
     * @param slotId
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetCallFailReasonRequest(int32_t slotId) const;

    /**
     * RegisterHandler
     */
    void RegisterHandler();

private:
    virtual int32_t ProcessPostDialCallChar(int32_t slotId, char c) override;
};
} // namespace Telephony
} // namespace OHOS

#endif // CELLULAR_CALL_CONNECTION_CS_H
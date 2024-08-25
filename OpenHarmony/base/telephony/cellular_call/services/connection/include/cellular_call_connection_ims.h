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

#ifndef CELLULAR_CALL_CONNECTION_IMS_H
#define CELLULAR_CALL_CONNECTION_IMS_H

#include "base_connection.h"
#include "module_service_utils.h"
#include "ims_call_interface.h"

namespace OHOS {
namespace Telephony {
class CellularCallConnectionIMS : public BaseConnection {
public:
    /**
     * Constructor
     */
    CellularCallConnectionIMS() = default;

    /**
     * Destructor
     */
    ~CellularCallConnectionIMS() = default;

    /**
     * Dial Request
     *
     * @param slotId
     * @param ImsDialInfoStruct
     * @return Error Code: Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    int32_t DialRequest(int32_t slotId, const ImsDialInfoStruct &dialRequest);

    /**
     * HangUp Request
     *
     * @param slotId
     * @param phoneNum
     * @param index
     * @return Error Code: Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    int32_t HangUpRequest(int32_t slotId, const std::string &phoneNum, int32_t index);

    /**
     * Answer Request
     *
     * @param slotId
     * @param phoneNum
     * @param videoState
     * @param index
     * @return Error Code: Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    int32_t AnswerRequest(int32_t slotId, const std::string &phoneNum, int32_t videoState, int32_t index);

    /**
     * Reject Request
     *
     * @param slotId
     * @param phoneNum
     * @param index
     * @return Error Code: Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    int32_t RejectRequest(int32_t slotId, const std::string &phoneNum, int32_t index);

    /**
     * HoldCall Request
     *
     * @param slotId
     * @return Error Code: Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    int32_t HoldCallRequest(int32_t slotId);

    /**
     * UnHoldCall Request
     *
     * @param slotId
     * @return Error Code: Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    int32_t UnHoldCallRequest(int32_t slotId);

    /**
     * SwitchCall Request
     *
     * @param slotId
     * @return Error Code: Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    int32_t SwitchCallRequest(int32_t slotId);

    /**
     * CombineConference Request
     *
     * @param slotId
     * @param voiceCall
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t CombineConferenceRequest(int32_t slotId, int32_t voiceCall);

    /**
     * InviteToConference Request
     *
     * @param slotId
     * @param numberList
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t InviteToConferenceRequest(int32_t slotId, const std::vector<std::string> &numberList);

    /**
     * KickOutFromConference Request
     *
     * @param slotId
     * @param index
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t KickOutFromConferenceRequest(int32_t slotId, int32_t index);

    /**
     * CallSupplement Request
     *
     * @param slotId
     * @param CallSupplementType
     * @return Error Code: Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    int32_t CallSupplementRequest(int32_t slotId, CallSupplementType type);

    /**
     * StartRtt Request
     *
     * @param slotId
     * @param msg
     * @return Error Code: Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    int32_t StartRttRequest(int32_t slotId, const std::string &msg);

    /**
     * StopRtt Request
     *
     * @param slotId
     * @return Error Code: Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    int32_t StopRttRequest(int32_t slotId);

    /**
     * GetImsCallsData Request
     *
     * @param slotId
     * @param lastCallsDataFlag
     * @return Error Code: Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    int32_t GetImsCallsDataRequest(int32_t slotId, int64_t lastCallsDataFlag);

    /**
     * Send Dtmf Request
     *
     * @param slotId
     * @param char cDtmfCode
     * @param index
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SendDtmfRequest(int32_t slotId, char cDtmfCode, int32_t index) const;

    /**
     * Start Dtmf Request
     *
     * @param slotId
     * @param char cDtmfCode
     * @param index
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t StartDtmfRequest(int32_t slotId, char cDtmfCode, int32_t index) const;

    /**
     * Stop Dtmf Request
     *
     * @param slotId
     * @param index
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t StopDtmfRequest(int32_t slotId, int32_t index) const;

    /**
     * Get Call Fail Reason Request
     *
     * @param slotId
     * @return Error Code: Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetCallFailReasonRequest(int32_t slotId) const;

    void SetHoldToDialInfo(std::string holdToDialNum, CLIRMode holdToDialClirMode, int32_t holdToDialVideoState,
        bool isEmergency);

    bool IsNeedToDial();

    void SetDialFlag(bool isNeedToDial);

    ImsDialInfoStruct GetHoldToDialInfo();

private:
    virtual int32_t ProcessPostDialCallChar(int32_t slotId, char c) override;

private:
    ModuleServiceUtils moduleUtils_;
    bool isNeedToDial_ = false;
    ImsDialInfoStruct holdToDialInfo_;
};
} // namespace Telephony
} // namespace OHOS

#endif // CELLULAR_CALL_CONNECTION_IMS_H
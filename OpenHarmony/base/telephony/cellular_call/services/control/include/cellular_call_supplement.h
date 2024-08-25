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

#ifndef CELLULAR_CALL_SUPPLEMENT_H
#define CELLULAR_CALL_SUPPLEMENT_H

#include <string>

#include "cellular_call_data_struct.h"
#include "tel_ril_call_parcel.h"
#include "tel_ril_types.h"
#include "ims_call_types.h"
#include "module_service_utils.h"
#include "supplement_request_cs.h"
#include "supplement_request_ims.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class CellularCallSupplement {
public:
    /**
     * Handle Clip mmi code
     *
     * 3GPP TS 22.030 V4.0.0 (2001-03)  6.5.6.2	Calling Line Identification Presentation (CLIP)
     * The CLIP Supplementary Service is defined in GSM 02.81[12]
     * 3GPP TS 22.030 V4.0.0 (2001-03) Annex B (normative):Codes for defined Supplementary Services
     *
     * @param slotId
     * @param MMIData
     */
    void HandleClip(int32_t slotId, const MMIData &mmiData);

    /**
     * Handle Clir mmi code
     *
     * 3GPP TS 22.081 V4.0.0 (2001-03) 2 Calling Line Identification Restriction (CLIR)
     * 3GPP TS 22.030 V4.0.0 (2001-03) Annex B (normative):Codes for defined Supplementary Services
     *
     * @param slotId
     * @param MMIData
     */
    void HandleClir(int32_t slotId, const MMIData &mmiData);

    /**
     * Handle Colr mmi code
     *
     * 3GPP TS 22.081 V4.0.0 (2001-03) 4 Connected Line Identification Restriction (COLR)
     * 3GPP TS 22.030 V4.0.0 (2001-03) Annex B (normative):Codes for defined Supplementary Services
     *
     * @param slotId
     * @param MMIData
     */
    void HandleColr(int32_t slotId, const MMIData &mmiData);

    /**
     * Handle Colp mmi code
     *
     * 3GPP TS 22.081 V4.0.0 (2001-03) 3 Connected Line Identification Presentation (COLP)
     * 3GPP TS 22.030 V4.0.0 (2001-03) Annex B (normative):Codes for defined Supplementary Services
     *
     * @param slotId
     * @param MMIData
     */
    void HandleColp(int32_t slotId, const MMIData &mmiData);

    /**
     * Handle Call Transfer mmi code
     *
     * 3GPP TS 22.030 V4.0.0 (2001-03)
     * 3GPP TS 22.030 V4.0.0 (2001-03) Annex B (normative):Codes for defined Supplementary Services
     *
     * @param slotId
     * @param MMIData
     */
    void HandleCallTransfer(int32_t slotId, const MMIData &mmiData);

    /**
     * Set Call Transfer
     *
     * 27007-430_2001 7.11 Call forwarding number and conditions +CCFC
     * 3GPP TS 22.082 [4]
     * Control of the call forwarding supplementary service
     *
     * @param slotId
     * @param CallTransferInfo
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetCallTransferInfo(int32_t slotId, const CallTransferInfo &cTInfo);

    /**
     * Confirm whether IMS can set call transfer time.
     *
     * @param slotId[in], The slot id
     * @param result[out], The result of can set or not
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t CanSetCallTransferTime(int32_t slotId, bool &result);

    /**
     * Inquire Call Transfer
     *
     * 27007-430_2001 7.11 Call forwarding number and conditions +CCFC
     * 3GPP TS 22.082 [4]
     * Control of the call forwarding supplementary service
     *
     * @param slotId
     * @param CallTransferType
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetCallTransferInfo(int32_t slotId, CallTransferType type);

    /**
     * Handle Call Restriction mmi code
     *
     * 3GPP TS 22.088 [6] 1	Barring of outgoing calls
     * 3GPP TS 22.088 [6] 2	Barring of incoming calls
     *
     * @param slotId
     * @param MMIData
     */
    void HandleCallRestriction(int32_t slotId, const MMIData &mmiData);

    /**
     * Set Call Restriction
     *
     * 27007-430_2001 7.4	Facility lock +CLCK
     * 3GPP TS 22.088 [6] 1	Barring of outgoing calls
     * 3GPP TS 22.088 [6] 2	Barring of incoming calls
     *
     * Control of the call barring supplementary service
     *
     * @param slotId
     * @param CallRestrictionInfo
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetCallRestriction(int32_t slotId, const CallRestrictionInfo &cRInfo);

    /**
     * Inquire Call Restriction
     *
     * 27007-430_2001 7.4	Facility lock +CLCK
     * 3GPP TS 22.088 [6] 1	Barring of outgoing calls
     * 3GPP TS 22.088 [6] 2	Barring of incoming calls
     *
     * Control of the call barring supplementary service
     *
     * @param slotId
     * @param CallRestrictionType
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetCallRestriction(int32_t slotId, CallRestrictionType facType);

    /**
     * Inquire Call Restriction Password
     *
     * 27007-430_2001 7.4	Facility lock +CLCK
     * 3GPP TS 22.088 [6] 1	Barring of outgoing calls
     * 3GPP TS 22.088 [6] 2	Barring of incoming calls
     *
     * Control of the call barring supplementary service
     *
     * @param slotId
     * @param CallRestrictionType
     * @param oldPassword[in] indicate the call restriction old password
     * @param newPassword[in] indicate the call restriction new password
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetBarringPassword(
        int32_t slotId, CallRestrictionType facType, const char *oldPassword, const char *newPassword);

    /**
     * Handle Call Waiting mmi code
     *
     * 27007-430_2001 7.12	Call waiting +CCWA
     * 3GPP TS 22.083 [5] 1	Call waiting (CW)
     *
     * @param slotId
     * @param MMIData
     */
    void HandleCallWaiting(int32_t slotId, const MMIData &mmiData);

    /**
     * Set Call Waiting
     *
     * 27007-430_2001 7.12	Call waiting +CCWA
     * 3GPP TS 22.083 [5] 1	Call waiting (CW)
     *
     * Control of the Call Waiting supplementary service
     *
     * @param slotId
     * @param activate
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetCallWaiting(int32_t slotId, bool activate);

    /**
     * Inquire Call Waiting
     *
     * 27007-430_2001 7.12	Call waiting +CCWA
     * 3GPP TS 22.083 [5] 1	Call waiting (CW)
     *
     * Control of the Call Waiting supplementary service
     *
     * @param slotId
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetCallWaiting(int32_t slotId);

    /**
     * Send Ussd msg
     *
     * 22.090 Unstructured Supplementary Service Data (USSD); Stage 1
     * 23.090 Unstructured Supplementary Service Data (USSD); Stage 2
     * 24.090 Unstructured Supplementary Service Data (USSD); Stage 3
     *
     * Control of the Ussd supplementary service
     *
     * @param slotId
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SendUssd(int32_t slotId, const std::string &msg);

    /**
     * Event Set Pin Puk
     *
     * @param PinPukResponse
     */
    void EventSetPinPuk(const PinPukResponse &pinPukResponse);

    /**
     * SIM PIN unlock
     *
     * @param slotId
     * @param mmiData
     * @return Returns true on success.
     */
    void AlterPinPassword(int32_t slotId, const MMIData &mmiData);

    /**
     * SIM PUK unlock
     *
     * @param slotId
     * @param mmiData
     * @return Returns true on success.
     */
    void UnlockPuk(int32_t slotId, const MMIData &mmiData);

    /**
     * SIM PIN2 unlock
     *
     * @param slotId
     * @param mmiData
     * @return Returns true on success.
     */
    void AlterPin2Password(int32_t slotId, const MMIData &mmiData);

    /**
     * SIM PUK2 unlock
     *
     * @param slotId
     * @param mmiData
     * @return Returns true on success.
     */
    void UnlockPuk2(int32_t slotId, const MMIData &mmiData);

    /**
     * Close Unfinished ussd
     *
     * Control of close Ussd supplementary service
     *
     * @param slotId
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t CloseUnFinishedUssd(int32_t slotId);

    /**
     * Get clip result
     *
     * 3GPP TS 27.007 V3.9.0 (2001-06) 7.6 Calling line identification presentation +CLIP
     *
     * @param GetClipResult
     * @param message the remain message for user which come from network
     * @param flag, {@code SS_FROM_MMI_CODE} mean the request action come from dial api
     * {@code SS_FROM_SETTING_MENU} means the request action come from setting app.
     */
    void EventGetClip(const GetClipResult &getClipResult, const std::string &message, int32_t flag);

    /**
     * Set clip result
     *
     * 3GPP TS 27.007 V3.9.0 (2001-06) 7.6 Calling line identification presentation +CLIP
     *
     * @param result
     * @param message the remain message for user which come from network
     * @param flag, {@code SS_FROM_MMI_CODE} mean the request action come from dial api
     * {@code SS_FROM_SETTING_MENU} means the request action come from setting app.
     */
    void EventSetClip(int32_t result, const std::string &message, int32_t flag);

    /**
     * Get clir result
     *
     * 3GPP TS 27.007 V3.9.0 (2001-06) 7.7 Calling line identification restriction +CLIR
     *
     * @param GetClirResult
     * @param message the remain message for user which come from network
     * @param flag, {@code SS_FROM_MMI_CODE} mean the request action come from dial api
     * {@code SS_FROM_SETTING_MENU} means the request action come from setting app.
     */
    void EventGetClir(const GetClirResult &result, const std::string &message, int32_t flag);

    /**
     * Set clir result
     *
     * 3GPP TS 27.007 V3.9.0 (2001-06) 7.7 Calling line identification restriction +CLIR
     *
     * @param result
     * @param message the remain message for user which come from network
     * @param flag, {@code SS_FROM_MMI_CODE} mean the request action come from dial api
     * {@code SS_FROM_SETTING_MENU} means the request action come from setting app.
     */
    void EventSetClir(int32_t result, const std::string &message, int32_t flag);

    /**
     * Get colr result
     *
     * 3GPP TS 27.007 V3.9.0 (2001-06) 7.31 Connected line identification restriction status +COLR
     *
     * @param GetColrResult
     * @param message the remain message for user which come from network
     * @param flag, {@code SS_FROM_MMI_CODE} mean the request action come from dial api
     * {@code SS_FROM_SETTING_MENU} means the request action come from setting app.
     */
    void EventGetColr(const GetColrResult &result, const std::string &message, int32_t flag);

    /**
     * Set colr result
     *
     * 3GPP TS 27.007 V3.9.0 (2001-06) 7.31 Connected line identification restriction status +COLR
     *
     * @param result
     * @param message the remain message for user which come from network
     * @param flag, {@code SS_FROM_MMI_CODE} mean the request action come from dial api
     * {@code SS_FROM_SETTING_MENU} means the request action come from setting app.
     */
    void EventSetColr(int32_t result, const std::string &message, int32_t flag);

    /**
     * Get colp result
     *
     * 3GPP TS 27.007 V3.9.0 (2001-06) 7.8 Connected line identification presentation +COLP
     *
     * @param GetColpResult
     * @param message the remain message for user which come from network
     * @param flag, {@code SS_FROM_MMI_CODE} mean the request action come from dial api
     * {@code SS_FROM_SETTING_MENU} means the request action come from setting app.
     */
    void EventGetColp(const GetColpResult &result, const std::string &message, int32_t flag);

    /**
     * Set colp result
     *
     * 3GPP TS 27.007 V3.9.0 (2001-06) 7.8 Connected line identification presentation +COLP
     *
     * @param result
     * @param message the remain message for user which come from network
     * @param flag, {@code SS_FROM_MMI_CODE} mean the request action come from dial api
     * {@code SS_FROM_SETTING_MENU} means the request action come from setting app.
     */
    void EventSetColp(int32_t result, const std::string &message, int32_t flag);

    /**
     * Get call restriction result
     *
     * 3GPP TS 27.007 V3.9.0 (2001-06) 7.4 Facility lock +CLCK
     *
     * @param CallRestrictionResult
     * @param message the remain message for user which come from network
     * @param flag, {@code SS_FROM_MMI_CODE} mean the request action come from dial api
     * {@code SS_FROM_SETTING_MENU} means the request action come from setting app.
     */
    void EventGetCallRestriction(const CallRestrictionResult &result, const std::string &message, int32_t flag);

    /**
     * Set call restriction result
     *
     * 3GPP TS 27.007 V3.9.0 (2001-06) 7.4 Facility lock +CLCK
     *
     * @param result
     * @param message the remain message for user which come from network
     * @param flag, {@code SS_FROM_MMI_CODE} mean the request action come from dial api
     * {@code SS_FROM_SETTING_MENU} means the request action come from setting app.
     */
    void EventSetCallRestriction(int32_t result, const std::string &message, int32_t flag);

    /**
     * Set call restriction password result
     *
     * 3GPP TS 27.007 V3.9.0 (2001-06) 7.4 Facility lock +CLCK
     *
     * @param result
     * @param message the remain message for user which come from network
     * @param flag, {@code SS_FROM_MMI_CODE} mean the request action come from dial api
     * {@code SS_FROM_SETTING_MENU} means the request action come from setting app.
     */
    void EventSetBarringPassword(int32_t result, const std::string &message, int32_t flag);
    /**
     * Get call waiting result
     *
     * 3GPP TS 27.007 V3.9.0 (2001-06) 7.12 Call waiting +CCWA
     * status: 0	not active;  1	active
     *
     * @param CallWaitResult waitingInfo
     * @param message the remain message for user which come from network
     * @param flag, {@code SS_FROM_MMI_CODE} mean the request action come from dial api
     * {@code SS_FROM_SETTING_MENU} means the request action come from setting app.
     */
    void EventGetCallWaiting(const CallWaitResult &waitingInfo, const std::string &message, int32_t flag);

    /**
     * Set call waiting result
     *
     * 3GPP TS 27.007 V3.9.0 (2001-06) 7.12 Call waiting +CCWA
     *
     * @param result
     * @param message the remain message for user which come from network
     * @param flag, {@code SS_FROM_MMI_CODE} mean the request action come from dial api
     * {@code SS_FROM_SETTING_MENU} means the request action come from setting app.
     */
    void EventSetCallWaiting(int32_t result, const std::string &message, int32_t flag);

    /**
     * Get call transfer result
     *
     * 3GPP TS 27.007 V3.9.0 (2001-06) 7.11 Call forwarding number and conditions +CCFC
     *
     * @param CallForwardQueryInfoList
     * @param message the remain message for user which come from network
     * @param flag, {@code SS_FROM_MMI_CODE} mean the request action come from dial api
     * {@code SS_FROM_SETTING_MENU} means the request action come from setting app.
     */
    void EventGetCallTransferInfo(
        const CallForwardQueryInfoList &cFQueryList, const std::string &message, int32_t flag);

    /**
     * Set call transfer result
     *
     * 3GPP TS 27.007 V3.9.0 (2001-06) 7.11 Call forwarding number and conditions +CCFC
     *
     * @param result
     * @param message the remain message for user which come from network
     * @param flag, {@code SS_FROM_MMI_CODE} mean the request action come from dial api
     * {@code SS_FROM_SETTING_MENU} means the request action come from setting app.
     */
    void EventSetCallTransferInfo(int32_t result, const std::string &message, int32_t flag);

    /**
     * Send ussd result
     *
     * 3GPP TS 3GPP TS 22.030 V16.0.0 (2020-07) 6.5 Supplementary Services Control
     *
     * @param RadioResponseInfo
     */
    void EventSendUssd(const RadioResponseInfo &responseInfo);

    /**
     * Ss notify
     *
     * @param SsNoticeInfo
     */
    void EventSsNotify(SsNoticeInfo &ssNoticeInfo);

    /**
     * Ussd notify
     *
     * @param UssdNoticeInfo
     */
    void EventUssdNotify(UssdNoticeInfo &ussdNoticeInfo);

    /**
     * Close Unfinished ussd result
     *
     * @param RadioResponseInfo
     */
    void EventCloseUnFinishedUssd(const RadioResponseInfo &responseInfo);

private:
    /**
     * Obtain ServiceCode
     *
     * @param serviceInfoB
     * @return ServiceClassType
     */
    int32_t ObtainServiceCode(const std::string &serviceInfoB);

    /**
     * Obtain ServiceCode
     *
     * @param actionString
     * @param phoneNumber
     * @param callTransferAction
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t ObtainCallTrasferAction(
        const char *actionString, const std::string &phoneNumber, CallTransferSettingType &callTransferAction);

    /**
     * Obtain Cause
     *
     * 3GPP TS 22.030 V4.0.0 (2001-03) Annex B (normative): Codes for defined Supplementary Services
     *
     * @param basicString
     * @return CallTransferType
     */
    int32_t ObtainCause(const std::string &serviceInfoC);

    /**
     * Handle get call transfer action which come from mmi code
     *
     * @param slotId
     * @param cause the call transfer type
     */
    void HandleGetCallTransfer(int32_t slotId, int32_t cause);

    /**
     * Handle set call transfer action which come from mmi code
     *
     * @param slotId
     * @param serviceCode the service class type
     * @param cause the call transfer type
     * @param phoneNumber the call transfer number
     * @param callTransferAction
     */
    void HandleSetCallTransfer(int32_t slotId, int32_t serviceCode, int32_t cause, const std::string &phoneNumber,
        CallTransferSettingType callTransferAction);

    int32_t CheckSetCallTransferInfo(const CallTransferInfo &cfInfo);
    int32_t SetCallTransferInfoByIms(
        int32_t slotId, const CallTransferInfo &cfInfo, const std::shared_ptr<SsRequestCommand> &command);
    int32_t CheckCallRestrictionType(std::string &fac, const CallRestrictionType &facType);
    int32_t SetCallRestrictionByIms(int32_t slotId, std::string &fac, int32_t mode, std::string &pw,
        const std::shared_ptr<SsRequestCommand> &command);

    /**
     * Obtain Barring Installation
     *
     * 27007-430_2001 7.4	Facility lock +CLCK
     * 3GPP TS 22.088 [6] 1	Barring of outgoing calls
     * 3GPP TS 22.088 [6] 2	Barring of incoming calls
     *
     * @param serviceInfoC
     * @return Barring type
     */
    std::string ObtainBarringInstallation(const std::string &serviceInfoC);

    /**
     * Is Phone Gsm Type
     *
     * @param slotId
     * @return bool
     */
    bool PhoneTypeGsmOrNot(int32_t slotId);

    /**
     * Confirm if need use IMS handle first
     *
     * @param slotId
     * @return bool
     */
    bool NeedUseImsToHandle(int32_t slotId);

    /**
     * Get Message
     *
     * @param MmiCodeInfo
     * @param SsNoticeInfo
     */
    void GetMessage(MmiCodeInfo &mmiCodeInfo, const SsNoticeInfo &ssNoticeInfo);

private:
    void BuildCallForwardQueryInfo(const CallForwardQueryResult &queryResult, const std::string &message, int32_t flag);
    void ReportMmiCodeMessage(int32_t result, const std::string successMsg, const std::string failedMsg);
    bool IsVaildPinOrPuk(std::string newPinOrPuk, std::string newPinOrPukCheck);

private:
    SupplementRequestCs supplementRequestCs_;
    SupplementRequestIms supplementRequestIms_;
    ModuleServiceUtils moduleServiceUtils_;
};
} // namespace Telephony
} // namespace OHOS
#endif // CELLULAR_CALL_SUPPLEMENT_H

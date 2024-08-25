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

#include "cellular_call_supplement.h"

#include "cellular_call_register.h"
#include "cellular_call_service.h"
#include "ims_error.h"
#include "mmi_code_message.h"
#include "securec.h"
#include "standardize_utils.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
const int32_t ACTIVATE_ACTION = 1;
const int32_t DEACTIVATE_ACTION = 2;
const int32_t USSD_MODE_NOTIFY = 0;
const int32_t USSD_MODE_REQUEST = 1;
const int32_t USSD_MODE_NW_RELEASE = 2;
const int32_t USSD_SUCCESS = 0;
const int32_t USSD_FAILED = 1;
const int32_t RESULT_SUCCESS = 0;
const int32_t MMI_CODE_FAILED = 1;
const int32_t PIN_PUK_MIN = 4;
const int32_t PIN_PUK_MAX = 8;
const std::string BARR_ALL_OUTGOING_CALLS = "AO";
const std::string BARR_OUTGOING_INTERNATIONAL_CALLS = "OI";
const std::string BARR_OUTGOING_INTERNATIONAL_CALLS_EXCLUDING_HOME = "OX";
const std::string BARR_ALL_INCOMING_CALLS = "AI";
const std::string BARR_INCOMING_CALLS_OUTSIDE_HOME = "IR";
const std::string ALL_BARRING_SERVICES = "AB";
const std::string ALL_OUTGOING_BARRING_SERVICES = "AG";
const std::string ALL_INCOMING_BARRING_SERVICES = "AC";

constexpr unsigned long long operator"" _hash(char const *p, size_t s)
{
    return StandardizeUtils::HashCompileTime(p);
}

void CellularCallSupplement::HandleClip(int32_t slotId, const MMIData &mmiData)
{
    const std::string interrogate = "*#";
    const std::string activate = "*";
    const std::string deactivate = "#";
    if (mmiData.actionString.empty()) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", INVALID_MMI_CODE);
        TELEPHONY_LOGE("[slot%{public}d] actionString is empty!", slotId);
        return;
    }
    auto handler = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", GENERIC_FAILURE);
        TELEPHONY_LOGE("[slot%{public}d] handler is nullptr!", slotId);
        return;
    }
    int32_t result = TELEPHONY_ERROR;
    auto utCommand = std::make_shared<SsRequestCommand>();
    int32_t index;
    handler->RequestSsRequestCommandIndex(index);
    if (mmiData.actionString == activate) {
        utCommand->action = ACTIVATE_ACTION;
        result = supplementRequestIms_.SetClipRequest(slotId, ACTIVATE_ACTION, index);
    } else if (mmiData.actionString == deactivate) {
        utCommand->action = DEACTIVATE_ACTION;
        result = supplementRequestIms_.SetClipRequest(slotId, DEACTIVATE_ACTION, index);
    } else if (mmiData.actionString == interrogate) {
        if (NeedUseImsToHandle(slotId)) {
            result = supplementRequestIms_.GetClipRequest(slotId, index);
        } else {
            result = supplementRequestCs_.GetClipRequest(slotId, index);
        }
    }
    if (result != TELEPHONY_SUCCESS) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", GENERIC_FAILURE);
    } else {
        handler->SaveSsRequestCommand(utCommand, index);
    }
}

void CellularCallSupplement::HandleClir(int32_t slotId, const MMIData &mmiData)
{
    const std::string interrogate = "*#";
    const std::string activate = "*";
    const std::string deactivate = "#";
    if (mmiData.actionString.empty()) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", INVALID_MMI_CODE);
        TELEPHONY_LOGE("[slot%{public}d] actionString is empty!", slotId);
        return;
    }
    auto handler = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", GENERIC_FAILURE);
        TELEPHONY_LOGE("[slot%{public}d] handler is nullptr!", slotId);
        return;
    }
    int32_t result = TELEPHONY_ERROR;
    auto utCommand = std::make_shared<SsRequestCommand>();
    int32_t index;
    handler->RequestSsRequestCommandIndex(index);
    if (mmiData.actionString == activate) {
        utCommand->action = ACTIVATE_ACTION;
        if (NeedUseImsToHandle(slotId)) {
            result = supplementRequestIms_.SetClirRequest(slotId, ACTIVATE_ACTION, index);
        } else {
            result = supplementRequestCs_.SetClirRequest(slotId, ACTIVATE_ACTION, index);
        }
    } else if (mmiData.actionString == deactivate) {
        utCommand->action = DEACTIVATE_ACTION;
        if (NeedUseImsToHandle(slotId)) {
            result = supplementRequestIms_.SetClirRequest(slotId, DEACTIVATE_ACTION, index);
        } else {
            result = supplementRequestCs_.SetClirRequest(slotId, DEACTIVATE_ACTION, index);
        }
    } else if (mmiData.actionString == interrogate) {
        if (NeedUseImsToHandle(slotId)) {
            result = supplementRequestIms_.GetClirRequest(slotId, index);
        } else {
            result = supplementRequestCs_.GetClirRequest(slotId, index);
        }
    }
    if (result != TELEPHONY_SUCCESS) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", GENERIC_FAILURE);
    } else {
        handler->SaveSsRequestCommand(utCommand, index);
    }
}

void CellularCallSupplement::HandleColr(int32_t slotId, const MMIData &mmiData)
{
    const std::string interrogate = "*#";
    const std::string activate = "*";
    const std::string deactivate = "#";
    if (mmiData.actionString.empty()) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", INVALID_MMI_CODE);
        TELEPHONY_LOGE("[slot%{public}d] actionString is empty!", slotId);
        return;
    }
    auto handler = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", GENERIC_FAILURE);
        TELEPHONY_LOGE("[slot%{public}d] handler is nullptr!", slotId);
        return;
    }
    int32_t result = TELEPHONY_ERROR;
    auto utCommand = std::make_shared<SsRequestCommand>();
    int32_t index;
    handler->RequestSsRequestCommandIndex(index);
    if (mmiData.actionString == activate) {
        utCommand->action = ACTIVATE_ACTION;
        if (NeedUseImsToHandle(slotId)) {
            result = supplementRequestIms_.SetColrRequest(slotId, ACTIVATE_ACTION, index);
        }
    } else if (mmiData.actionString == deactivate) {
        utCommand->action = DEACTIVATE_ACTION;
        if (NeedUseImsToHandle(slotId)) {
            result = supplementRequestIms_.SetColrRequest(slotId, DEACTIVATE_ACTION, index);
        }
    } else if (mmiData.actionString == interrogate) {
        if (NeedUseImsToHandle(slotId)) {
            result = supplementRequestIms_.GetColrRequest(slotId, index);
        }
    }
    if (result != TELEPHONY_SUCCESS) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", GENERIC_FAILURE);
    } else {
        handler->SaveSsRequestCommand(utCommand, index);
    }
}

void CellularCallSupplement::HandleColp(int32_t slotId, const MMIData &mmiData)
{
    const std::string interrogate = "*#";
    const std::string activate = "*";
    const std::string deactivate = "#";
    if (mmiData.actionString.empty()) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", INVALID_MMI_CODE);
        TELEPHONY_LOGE("[slot%{public}d] actionString is empty!", slotId);
        return;
    }
    auto handler = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", GENERIC_FAILURE);
        TELEPHONY_LOGE("[slot%{public}d] handler is nullptr!", slotId);
        return;
    }
    int32_t result = TELEPHONY_ERROR;
    auto utCommand = std::make_shared<SsRequestCommand>();
    int32_t index;
    handler->RequestSsRequestCommandIndex(index);
    if (mmiData.actionString == activate) {
        utCommand->action = ACTIVATE_ACTION;
        if (NeedUseImsToHandle(slotId)) {
            result = supplementRequestIms_.SetColpRequest(slotId, ACTIVATE_ACTION, index);
        }
    } else if (mmiData.actionString == deactivate) {
        utCommand->action = DEACTIVATE_ACTION;
        if (NeedUseImsToHandle(slotId)) {
            result = supplementRequestIms_.SetColpRequest(slotId, DEACTIVATE_ACTION, index);
        }
    } else if (mmiData.actionString == interrogate) {
        if (NeedUseImsToHandle(slotId)) {
            result = supplementRequestIms_.GetColpRequest(slotId, index);
        }
    }
    if (result != TELEPHONY_SUCCESS) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", GENERIC_FAILURE);
    } else {
        handler->SaveSsRequestCommand(utCommand, index);
    }
}

void CellularCallSupplement::HandleCallTransfer(int32_t slotId, const MMIData &mmiData)
{
    const std::string interrogate = "*#";
    int32_t serviceCode = ObtainServiceCode(mmiData.serviceInfoB);
    int32_t cause = ObtainCause(mmiData.serviceCode);
    if (!mmiData.actionString.empty() && mmiData.actionString == interrogate) {
        HandleGetCallTransfer(slotId, cause);
        return;
    }
    std::string phoneNumber = mmiData.serviceInfoA;
    if (mmiData.actionString.empty()) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", INVALID_MMI_CODE);
        TELEPHONY_LOGE("[slot%{public}d] actionString is empty!", slotId);
        return;
    }
    CallTransferSettingType callTransferAction;
    int32_t result = ObtainCallTrasferAction(mmiData.actionString.c_str(), phoneNumber, callTransferAction);
    if (result != TELEPHONY_SUCCESS) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", GENERIC_FAILURE);
        return;
    }
    HandleSetCallTransfer(slotId, serviceCode, cause, phoneNumber, callTransferAction);
}

int32_t CellularCallSupplement::ObtainServiceCode(const std::string &serviceInfoB)
{
    if (serviceInfoB.empty()) {
        TELEPHONY_LOGI("serviceInfoB is empty!");
        return NONE;
    }
    int32_t intServiceInfoB = atoi(serviceInfoB.c_str());
    switch (intServiceInfoB) {
        case ALL_TELE_SERVICES:
            return SHORT_MESSAGE_SERVICE + FAX + VOICE;
        case TELE_SERVICES:
            return VOICE;
        case ALL_DATA_TELE_SERVICES:
            return SHORT_MESSAGE_SERVICE + FAX;
        case FACSIMILE_SERVICES:
            return FAX;
        case SHORT_MESSAGE_SERVICES:
            return SHORT_MESSAGE_SERVICE;
        case ALL_TELE_SERVICES_EXCEPT_SMS:
            return FAX + VOICE;
        case ALL_BEARER_SERVICES:
            return DATA_CIRCUIT_ASYNC + DATA_CIRCUIT_SYNC;
        case ALL_ASYNC_SERVICES:
            return DEDICATED_PAD_ACCESS + DATA_CIRCUIT_ASYNC;
        case ALL_SYNC_SERVICES:
            return DEDICATED_PACKET_ACCESS + DATA_CIRCUIT_SYNC;
        case ALL_DATA_CIRCUIT_SYNC:
            return DATA_CIRCUIT_SYNC;
        case ALL_DATA_CIRCUIT_ASYNC:
            return DATA_CIRCUIT_ASYNC;
        case ALL_GPRS_BEARER_SERVICES:
            return DEDICATED_PACKET_ACCESS;
        default:
            TELEPHONY_LOGE("serviceInfoB out of range, please check!");
            return NONE;
    }
}

int32_t CellularCallSupplement::ObtainCallTrasferAction(
    const char *actionString, const std::string &phoneNumber, CallTransferSettingType &callTransferAction)
{
    // 3GPP TS 24.082 V4.0.0 (2001-03) 1 Call Forwarding Unconditional (CFU)
    // 3GPP TS 24.082 V4.0.0 (2001-03) 2 Call Forwarding on mobile subscriber Busy (CFB)
    // 3GPP TS 24.082 V4.0.0 (2001-03) 3 Call Forwarding on No Reply (CFNRy)
    // 3GPP TS 24.082 V4.0.0 (2001-03) 4 Call Forwarding on mobile subscriber Not Reachable (CFNRc)
    switch (StandardizeUtils::Hash_(actionString)) {
        case "*"_hash:
            if (phoneNumber.empty()) {
                callTransferAction = CallTransferSettingType::CALL_TRANSFER_ENABLE;
            } else {
                callTransferAction = CallTransferSettingType::CALL_TRANSFER_REGISTRATION;
            }
            break;
        case "#"_hash:
            callTransferAction = CallTransferSettingType::CALL_TRANSFER_DISABLE;
            break;
        case "**"_hash:
            callTransferAction = CallTransferSettingType::CALL_TRANSFER_REGISTRATION;
            break;
        case "##"_hash:
            callTransferAction = CallTransferSettingType::CALL_TRANSFER_ERASURE;
            break;
        default:
            TELEPHONY_LOGE("actionString out of range, please check!");
            return TELEPHONY_ERR_ARGUMENT_MISMATCH;
    }
    return TELEPHONY_SUCCESS;
}

int32_t CellularCallSupplement::ObtainCause(const std::string &actionStr)
{
    if (actionStr.empty()) {
        TELEPHONY_LOGE("actionStr is empty!");
        return TELEPHONY_ERROR;
    }

    /*
     * 3GPP TS 22.030 V4.0.0 (2001-03) Annex B (normative): Codes for defined Supplementary Services
     * CFU	                21
     * CF Busy	            67
     * CF No Reply	        61
     * CF Not Reachable 	62
     * all CF		        002
     * all conditional CF	004
     */
    switch (StandardizeUtils::Hash_(actionStr.c_str())) {
        case "21"_hash:
            return static_cast<int32_t>(CallTransferType::TRANSFER_TYPE_UNCONDITIONAL);
        case "67"_hash:
            return static_cast<int32_t>(CallTransferType::TRANSFER_TYPE_BUSY);
        case "62"_hash:
            return static_cast<int32_t>(CallTransferType::TRANSFER_TYPE_NO_REPLY);
        case "61"_hash:
            return static_cast<int32_t>(CallTransferType::TRANSFER_TYPE_NOT_REACHABLE);
        default:
            TELEPHONY_LOGE("actionStr out of range!");
            return TELEPHONY_ERROR;
    }
}

void CellularCallSupplement::HandleGetCallTransfer(int32_t slotId, int32_t cause)
{
    auto handler = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", GENERIC_FAILURE);
        TELEPHONY_LOGE("[slot%{public}d] handler is nullptr!", slotId);
        return;
    }
    auto utCommand = std::make_shared<SsRequestCommand>();
    utCommand->cfReason = cause;
    int32_t index;
    handler->RequestSsRequestCommandIndex(index);
    int32_t result = TELEPHONY_ERROR;
    if (NeedUseImsToHandle(slotId)) {
        result = supplementRequestIms_.GetCallTransferRequest(slotId, cause, index);
    } else {
        result = supplementRequestCs_.GetCallTransferRequest(slotId, cause, index);
    }
    if (result != TELEPHONY_SUCCESS) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", GENERIC_FAILURE);
    } else {
        handler->SaveSsRequestCommand(utCommand, index);
    }
}

void CellularCallSupplement::HandleSetCallTransfer(int32_t slotId, int32_t serviceCode, int32_t cause,
    const std::string &phoneNumber, CallTransferSettingType callTransferAction)
{
    auto handler = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", GENERIC_FAILURE);
        TELEPHONY_LOGE("[slot%{public}d] handler is nullptr!", slotId);
        return;
    }
    auto utCommand = std::make_shared<SsRequestCommand>();
    utCommand->cfReason = cause;
    utCommand->cfAction = static_cast<int32_t>(callTransferAction);
    utCommand->number = phoneNumber;
    int32_t index;
    handler->RequestSsRequestCommandIndex(index);
    int32_t result = TELEPHONY_ERROR;
    if (NeedUseImsToHandle(slotId)) {
        CallTransferInfo cfInfo;
        if (memcpy_s(cfInfo.transferNum, kMaxNumberLen, phoneNumber.c_str(), phoneNumber.length()) != EOK) {
            TELEPHONY_LOGE("[slot%{public}d] memcpy_s failed!", slotId);
            ReportMmiCodeMessage(MMI_CODE_FAILED, "", GENERIC_FAILURE);
            return;
        }
        cfInfo.settingType = callTransferAction;
        cfInfo.type = static_cast<CallTransferType>(cause);
        // set the time as default min, this mean the time will not use at IMS
        cfInfo.startHour = MIN_HOUR;
        cfInfo.startMinute = MIN_MINUTE;
        cfInfo.endHour = MIN_HOUR;
        cfInfo.endMinute = MIN_MINUTE;
        result = supplementRequestIms_.SetCallTransferRequest(slotId, cfInfo, serviceCode, index);
    } else {
        CallTransferParam callTransferParam;
        callTransferParam.mode = static_cast<int32_t>(callTransferAction);
        callTransferParam.reason = cause;
        callTransferParam.number = phoneNumber;
        callTransferParam.classx = serviceCode;
        result = supplementRequestCs_.SetCallTransferRequest(slotId, callTransferParam, index);
    }
    if (result != TELEPHONY_SUCCESS) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", GENERIC_FAILURE);
    } else {
        handler->SaveSsRequestCommand(utCommand, index);
    }
}

void CellularCallSupplement::HandleCallRestriction(int32_t slotId, const MMIData &mmiData)
{
    std::string infoA = mmiData.serviceInfoA;
    std::string facType = ObtainBarringInstallation(mmiData.serviceCode);
    const std::string interrogate = "*#";
    const std::string activate = "*";
    const std::string deactivate = "#";
    if (mmiData.actionString.empty()) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", INVALID_MMI_CODE);
        TELEPHONY_LOGE("[slot%{public}d] actionString is empty!", slotId);
        return;
    }
    auto handler = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", GENERIC_FAILURE);
        TELEPHONY_LOGE("[slot%{public}d] handler is nullptr!", slotId);
        return;
    }
    auto utCommand = std::make_shared<SsRequestCommand>();
    utCommand->facility = facType;
    int32_t index;
    handler->RequestSsRequestCommandIndex(index);
    int32_t result = TELEPHONY_ERROR;
    if (mmiData.actionString == interrogate) {
        if (NeedUseImsToHandle(slotId)) {
            result = supplementRequestIms_.GetCallRestrictionRequest(slotId, facType, index);
        } else {
            result = supplementRequestCs_.GetCallRestrictionRequest(slotId, facType, index);
        }
    } else if (mmiData.actionString == activate || mmiData.actionString == deactivate) {
        utCommand->enable = mmiData.actionString == activate;
        size_t cpyLen = strlen(infoA.c_str()) + 1;
        size_t maxCpyLen = sizeof(utCommand->password);
        if (strcpy_s(utCommand->password, cpyLen > maxCpyLen ? maxCpyLen : cpyLen, infoA.c_str()) != EOK) {
            TELEPHONY_LOGE("[slot%{public}d] strcpy_s fail.", slotId);
            return;
        }
        if (NeedUseImsToHandle(slotId)) {
            result = supplementRequestIms_.SetCallRestrictionRequest(
                slotId, facType, mmiData.actionString == activate, infoA, index);
        } else {
            result = supplementRequestCs_.SetCallRestrictionRequest(
                slotId, facType, mmiData.actionString == activate, infoA, index);
        }
    }
    if (result != TELEPHONY_SUCCESS) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", GENERIC_FAILURE);
    } else {
        handler->SaveSsRequestCommand(utCommand, index);
    }
}

std::string CellularCallSupplement::ObtainBarringInstallation(const std::string &serviceInfoC)
{
    if (serviceInfoC.empty()) {
        TELEPHONY_LOGE("serviceInfoC is empty!");
        return std::string();
    }

    /*
     * 27007-430_2001 7.4	Facility lock +CLCK
     *  Supplementary	Service Service	Code	SIA	SIB	SIC
     * 	22.088
     * 	BAOC	            33	                 PW	BS	-
     * 	BAOIC	            331	                 PW	BS	-
     * 	BAOIC exc home	    332	                 PW	BS	-
     * 	BAIC	            35	                 PW	BS	-
     * 	BAIC roaming	    351	                 PW	BS	-
     *  all Barring Serv.   330	                 PW	BS	-
     *  Outg. Barr. Serv.   333	                 PW	BS
     *  Inc. Barr. Serv.	353	                 PW	BS
     */
    switch (StandardizeUtils::Hash_(serviceInfoC.c_str())) {
        case "33"_hash:
            // "AO"	BAOC (Barr All Outgoing Calls) (refer 3GPP TS 22.088 [6] clause 1)
            return BARR_ALL_OUTGOING_CALLS;
        case "331"_hash:
            // "OI"	BOIC (Barr Outgoing International Calls) (refer 3GPP TS 22.088 [6] clause 1)
            return BARR_OUTGOING_INTERNATIONAL_CALLS;
        case "332"_hash:
            // "OX"	BOIC exHC (Barr Outgoing International Calls except to Home Country)
            // (refer 3GPP TS 22.088 [6] clause 1)
            return BARR_OUTGOING_INTERNATIONAL_CALLS_EXCLUDING_HOME;
        case "351"_hash:
            // "IR"	BIC Roam (Barr Incoming Calls when Roaming outside the home country)
            // (refer 3GPP TS 22.088 [6] clause 2)
            return BARR_INCOMING_CALLS_OUTSIDE_HOME;
        case "35"_hash:
            // "AI"	BAIC (Barr All Incoming Calls) (refer 3GPP TS 22.088 [6] clause 2)
            return BARR_ALL_INCOMING_CALLS;
        case "330"_hash:
            // "AB"	All Barring services (refer 3GPP TS 22.030 [19]) (applicable only for <mode>=0)
            return ALL_BARRING_SERVICES;
        case "333"_hash:
            // "AG"	All outGoing barring services (refer 3GPP TS 22.030 [19]) (applicable only for <mode>=0)
            return ALL_OUTGOING_BARRING_SERVICES;
        case "353"_hash:
            // "AC"	All inComing barring services (refer 3GPP TS 22.030 [19]) (applicable only for <mode>=0)
            return ALL_INCOMING_BARRING_SERVICES;
        default:
            TELEPHONY_LOGE("serviceInfoC out of range!");
            return std::string();
    }
}

void CellularCallSupplement::HandleCallWaiting(int32_t slotId, const MMIData &mmiData)
{
    if (mmiData.actionString.empty()) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", INVALID_MMI_CODE);
        TELEPHONY_LOGE("[slot%{public}d] actionString is empty!", slotId);
        return;
    }
    auto handler = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", GENERIC_FAILURE);
        TELEPHONY_LOGE("[slot%{public}d] handler is nullptr!", slotId);
        return;
    }
    const std::string activate = "*";
    const std::string deactivate = "#";
    const std::string interrogate = "*#";
    int32_t result = TELEPHONY_ERROR;
    int32_t classType = ObtainServiceCode(mmiData.serviceInfoA);
    auto utCommand = std::make_shared<SsRequestCommand>();
    utCommand->classType = classType;
    int32_t index;
    handler->RequestSsRequestCommandIndex(index);
    if (mmiData.actionString == activate || mmiData.actionString == deactivate) {
        utCommand->enable = mmiData.actionString == activate;
        if (NeedUseImsToHandle(slotId)) {
            result =
                supplementRequestIms_.SetCallWaitingRequest(slotId, mmiData.actionString == activate, classType, index);
        } else {
            result =
                supplementRequestCs_.SetCallWaitingRequest(slotId, mmiData.actionString == activate, classType, index);
        }
    } else if (mmiData.actionString == interrogate) {
        if (NeedUseImsToHandle(slotId)) {
            result = supplementRequestIms_.GetCallWaitingRequest(slotId, index);
        } else {
            result = supplementRequestCs_.GetCallWaitingRequest(slotId, index);
        }
    }
    if (result != TELEPHONY_SUCCESS) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", GENERIC_FAILURE);
    } else {
        handler->SaveSsRequestCommand(utCommand, index);
    }
}

void CellularCallSupplement::EventGetCallWaiting(
    const CallWaitResult &waitingInfo, const std::string &message, int32_t flag)
{
    CallWaitResponse callWaitResponse;
    callWaitResponse.result = waitingInfo.result.result;
    if (callWaitResponse.result == IMS_ERROR_UT_NO_CONNECTION) {
        callWaitResponse.result = CALL_ERR_UT_NO_CONNECTION;
    }

    /*
     * <n> (sets/shows the result code presentation status in the TA):
     * 0	disable
     * 1	enable
     */
    callWaitResponse.status = waitingInfo.status;
    callWaitResponse.classCw = waitingInfo.classCw;
    auto callRegister = DelayedSingleton<CellularCallRegister>::GetInstance();
    if (callRegister == nullptr) {
        TELEPHONY_LOGE("callRegister is null.");
        return;
    }
    if (flag == SS_FROM_MMI_CODE) {
        std::string successMessage = GET_CALL_WAITING_SUCCESS;
        CreateGetCallWaitingResultMessage(successMessage, callWaitResponse);
        ReportMmiCodeMessage(
            callWaitResponse.result, successMessage, message.empty() ? GET_CALL_WAITING_FAILED : message);
    } else {
        callRegister->ReportGetWaitingResult(callWaitResponse);
    }
}

void CellularCallSupplement::EventSetCallWaiting(int32_t result, const std::string &message, int32_t flag)
{
    auto callRegister = DelayedSingleton<CellularCallRegister>::GetInstance();
    if (callRegister == nullptr) {
        TELEPHONY_LOGE("callRegister is null.");
        return;
    }
    if (flag == SS_FROM_MMI_CODE) {
        ReportMmiCodeMessage(result, SET_CALL_WAITING_SUCCESS, message.empty() ? SET_CALL_WAITING_FAILED : message);
    } else {
        callRegister->ReportSetWaitingResult(result);
    }
}

void CellularCallSupplement::EventGetCallTransferInfo(
    const CallForwardQueryInfoList &cFQueryList, const std::string &message, int32_t flag)
{
    if (cFQueryList.result.result != TELEPHONY_SUCCESS && cFQueryList.callSize == 0) {
        CallForwardQueryResult failResult;
        failResult.result = cFQueryList.result.result;
        failResult.reason = cFQueryList.result.reason;
        BuildCallForwardQueryInfo(failResult, message, flag);
    }
    for (auto queryResult : cFQueryList.calls) {
        TELEPHONY_LOGI("data: status %{public}d, classx %{public}d, reason %{public}d", queryResult.status,
            queryResult.classx, queryResult.reason);
        if (queryResult.classx > 0 && (static_cast<uint32_t>(queryResult.classx) & ServiceClassType::VOICE) != 0) {
            BuildCallForwardQueryInfo(queryResult, message, flag);
        }
    }
}

void CellularCallSupplement::BuildCallForwardQueryInfo(
    const CallForwardQueryResult &queryResult, const std::string &message, int32_t flag)
{
    // 3GPP TS 27.007 V3.9.0 (2001-06) 7.11	Call forwarding number and conditions +CCFC
    CallTransferResponse response;
    if (memset_s(&response, sizeof(response), 0, sizeof(response)) != EOK) {
        TELEPHONY_LOGE("memset_s fail.");
        return;
    }
    // <number>: string type phone number of forwarding address in format specified by <type>
    size_t cpyLen = strlen(queryResult.number.c_str()) + 1;
    if (strcpy_s(response.number, cpyLen, queryResult.number.c_str()) != EOK) {
        TELEPHONY_LOGE(" strcpy_s fail.");
        return;
    }
    response.result = queryResult.result;
    /*
     * <status>:0	not active;    1	  active
     * */
    response.status = queryResult.status;
    /*
     * <classx> is a sum of integers each representing a class of information (default 7):
     * 1	voice (telephony)
     * 2	data (refers to all bearer services)
     * 4	fax (facsimile services)
     * 8	short message service
     * 16	data circuit sync
     * 32	data circuit async
     * 64	dedicated packet access
     * 128	dedicated PAD access
     */
    response.classx = queryResult.classx;
    // <type>: type of address octet in integer format (refer GSM 04.08 [8] subclause 10.5.4.7);
    // default 145 when dialling string includes international access code character "+", otherwise 129
    response.type = queryResult.type;
    response.reason = queryResult.reason;
    response.time = queryResult.time;
    response.startHour = queryResult.startHour;
    response.startMinute = queryResult.startMinute;
    response.endHour = queryResult.endHour;
    response.endMinute = queryResult.endMinute;
    if (flag == SS_FROM_MMI_CODE) {
        std::string successMessage = GET_CALL_TRANSFER_SUCCESS;
        CreateGetCallTransferResultMessage(successMessage, response);
        ReportMmiCodeMessage(queryResult.result, successMessage, message.empty() ? GET_CALL_TRANSFER_FAILED : message);
    } else {
        auto callRegister = DelayedSingleton<CellularCallRegister>::GetInstance();
        if (callRegister == nullptr) {
            TELEPHONY_LOGE("callRegister is null.");
            return;
        }
        callRegister->ReportGetTransferResult(response);
    }
}

void CellularCallSupplement::EventSetCallTransferInfo(int32_t result, const std::string &message, int32_t flag)
{
    auto callRegister = DelayedSingleton<CellularCallRegister>::GetInstance();
    if (callRegister == nullptr) {
        TELEPHONY_LOGE("callRegister is null.");
        return;
    }

    if (flag == SS_FROM_MMI_CODE) {
        ReportMmiCodeMessage(result, SET_CALL_TRANSFER_SUCCESS, message.empty() ? SET_CALL_TRANSFER_FAILED : message);
    } else {
        callRegister->ReportSetTransferResult(result);
    }
}

void CellularCallSupplement::EventGetCallRestriction(
    const CallRestrictionResult &result, const std::string &message, int32_t flag)
{
    auto callRegister = DelayedSingleton<CellularCallRegister>::GetInstance();
    if (callRegister == nullptr) {
        TELEPHONY_LOGE("callRegister is null.");
        return;
    }
    CallRestrictionResponse response;
    response.result = result.result.result;
    if (response.result == IMS_ERROR_UT_NO_CONNECTION) {
        response.result = CALL_ERR_UT_NO_CONNECTION;
    }

    /*
     * <status>:0	not active    1	  active
     */
    response.status = result.status;
    response.classCw = result.classCw;

    if (flag == SS_FROM_MMI_CODE) {
        std::string successMessage = GET_CALL_RESTRICTION_SUCCESS;
        CreateSuppSvcQueryResultMessage(successMessage, response.result, response.status);
        ReportMmiCodeMessage(
            result.result.result, successMessage, message.empty() ? GET_CALL_RESTRICTION_FAILED : message);
    } else {
        callRegister->ReportGetRestrictionResult(response);
    }
}

void CellularCallSupplement::EventSetCallRestriction(int32_t result, const std::string &message, int32_t flag)
{
    auto callRegister = DelayedSingleton<CellularCallRegister>::GetInstance();
    if (callRegister == nullptr) {
        TELEPHONY_LOGE("callRegister is null.");
        return;
    }
    if (flag == SS_FROM_MMI_CODE) {
        ReportMmiCodeMessage(
            result, SET_CALL_RESTRICTION_SUCCESS, message.empty() ? SET_CALL_RESTRICTION_FAILED : message);
    } else {
        callRegister->ReportSetRestrictionResult(result);
    }
}

void CellularCallSupplement::EventSetBarringPassword(int32_t result, const std::string &message, int32_t flag)
{
    auto callRegister = DelayedSingleton<CellularCallRegister>::GetInstance();
    if (callRegister == nullptr) {
        TELEPHONY_LOGE("callRegister is null.");
        return;
    }
    if (flag == SS_FROM_MMI_CODE) {
        ReportMmiCodeMessage(
            result, SET_SET_BARRING_PASSWORD_SUCCESS, message.empty() ? SET_SET_BARRING_PASSWORD_FAILED : message);
    } else {
        callRegister->ReportSetBarringPasswordResult(result);
    }
}

int32_t CellularCallSupplement::SetCallTransferInfo(int32_t slotId, const CallTransferInfo &cfInfo)
{
    int32_t result = CheckSetCallTransferInfo(cfInfo);
    RadioResponseInfo responseInfo;
    responseInfo.error = ErrType::ERR_GENERIC_FAILURE;
    if (result != TELEPHONY_SUCCESS) {
        return result;
    }
    auto handler = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is nullptr!", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    std::string dialString(cfInfo.transferNum);
    auto utCommand = std::make_shared<SsRequestCommand>();
    utCommand->flag = SS_FROM_SETTING_MENU;
    utCommand->number = dialString;
    utCommand->cfAction = static_cast<int32_t>(cfInfo.settingType);
    utCommand->cfReason = static_cast<int32_t>(cfInfo.type);
    utCommand->classType = ServiceClassType::VOICE;
    if (NeedUseImsToHandle(slotId)) {
        return SetCallTransferInfoByIms(slotId, cfInfo, utCommand);
    }

    if (!PhoneTypeGsmOrNot(slotId)) {
        TELEPHONY_LOGE("[slot%{public}d] network type is not supported!", slotId);
        return CALL_ERR_UNSUPPORTED_NETWORK_TYPE;
    }

    CallTransferParam callTransferParam;
    callTransferParam.mode = static_cast<int32_t>(cfInfo.settingType);
    callTransferParam.reason = static_cast<int32_t>(cfInfo.type);
    callTransferParam.number = dialString;
    callTransferParam.classx = ServiceClassType::VOICE;
    int32_t index;
    handler->RequestSsRequestCommandIndex(index);
    result = supplementRequestCs_.SetCallTransferRequest(slotId, callTransferParam, index);
    if (result == TELEPHONY_SUCCESS) {
        handler->SaveSsRequestCommand(utCommand, index);
    }
    return result;
}

int32_t CellularCallSupplement::CheckSetCallTransferInfo(const CallTransferInfo &cfInfo)
{
    if (strlen(cfInfo.transferNum) == 0) {
        TELEPHONY_LOGE("transferNum is empty!");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }

    /*
     * <reason>:
     * 0   unconditional
     * 1   mobile busy
     * 2   no reply
     * 3   not reachable
     * 4   all call forwarding (refer 3GPP TS 22.030 [19])
     * 5   all conditional call forwarding (refer 3GPP TS 22.030 [19])
     * <mode>:
     * 0   disable
     * 1   enable
     * 2   query status
     * 3   registration
     * 4   erasure
     */
    if (cfInfo.type > CallTransferType::TRANSFER_TYPE_NOT_REACHABLE ||
        cfInfo.type < CallTransferType::TRANSFER_TYPE_UNCONDITIONAL ||
        cfInfo.settingType > CallTransferSettingType::CALL_TRANSFER_ERASURE ||
        cfInfo.settingType < CallTransferSettingType::CALL_TRANSFER_DISABLE) {
        TELEPHONY_LOGE("parameter out of range!");
        return CALL_ERR_PARAMETER_OUT_OF_RANGE;
    }
    return TELEPHONY_SUCCESS;
}

int32_t CellularCallSupplement::SetCallTransferInfoByIms(
    int32_t slotId, const CallTransferInfo &cfInfo, const std::shared_ptr<SsRequestCommand> &command)
{
    auto handler = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    RadioResponseInfo responseInfo;
    responseInfo.error = ErrType::ERR_GENERIC_FAILURE;
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is nullptr!", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t index;
    handler->RequestSsRequestCommandIndex(index);
    int32_t result = supplementRequestIms_.SetCallTransferRequest(slotId, cfInfo, ServiceClassType::VOICE, index);
    if (result == TELEPHONY_SUCCESS) {
        handler->SaveSsRequestCommand(command, index);
    }
    return result;
}

int32_t CellularCallSupplement::CanSetCallTransferTime(int32_t slotId, bool &result)
{
    if (!moduleServiceUtils_.NeedCallImsService()) {
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    int32_t ret = TELEPHONY_SUCCESS;
    ret = supplementRequestIms_.CanSetCallTransferTime(slotId, result);
    return ret;
}

int32_t CellularCallSupplement::GetCallTransferInfo(int32_t slotId, CallTransferType type)
{
    auto handler = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is nullptr!", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t result = TELEPHONY_ERROR;
    auto utCommand = std::make_shared<SsRequestCommand>();
    utCommand->flag = SS_FROM_SETTING_MENU;
    utCommand->cfReason = static_cast<int32_t>(type);
    int32_t index;
    if (NeedUseImsToHandle(slotId)) {
        handler->RequestSsRequestCommandIndex(index);
        result = supplementRequestIms_.GetCallTransferRequest(slotId, static_cast<int32_t>(type), index);
        if (result == TELEPHONY_SUCCESS) {
            handler->SaveSsRequestCommand(utCommand, index);
        }
        return result;
    }
    if (!PhoneTypeGsmOrNot(slotId)) {
        TELEPHONY_LOGE("[slot%{public}d] network type is not supported!", slotId);
        return CALL_ERR_UNSUPPORTED_NETWORK_TYPE;
    }

    /*
     * When querying the status of a network service (<mode>=2) the response line for 'not active' case
     * (<status>=0) should be returned only if service is not active for any <class>
     */
    handler->RequestSsRequestCommandIndex(index);
    result = supplementRequestCs_.GetCallTransferRequest(slotId, static_cast<int32_t>(type), index);
    if (result == TELEPHONY_SUCCESS) {
        handler->SaveSsRequestCommand(utCommand, index);
    }
    return result;
}

bool CellularCallSupplement::PhoneTypeGsmOrNot(int32_t slotId)
{
    return moduleServiceUtils_.GetNetworkStatus(slotId) == PhoneType::PHONE_TYPE_IS_GSM;
}

bool CellularCallSupplement::NeedUseImsToHandle(int32_t slotId)
{
    return moduleServiceUtils_.NeedCallImsService() && moduleServiceUtils_.GetImsUtSupportState(slotId);
}

int32_t CellularCallSupplement::SetCallWaiting(int32_t slotId, bool activate)
{
    RadioResponseInfo responseInfo;
    responseInfo.error = ErrType::ERR_GENERIC_FAILURE;
    auto handler = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is nullptr!", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t classType = ServiceClassType::VOICE;
    CellularCallConfig config;
    classType = config.GetCallWaitingServiceClassConfig(slotId);
    int32_t result = TELEPHONY_ERROR;
    auto utCommand = std::make_shared<SsRequestCommand>();
    utCommand->flag = SS_FROM_SETTING_MENU;
    utCommand->classType = classType;
    utCommand->enable = activate;
    int32_t index;
    if (NeedUseImsToHandle(slotId)) {
        handler->RequestSsRequestCommandIndex(index);
        result = supplementRequestIms_.SetCallWaitingRequest(slotId, activate, classType, index);
        if (result == TELEPHONY_SUCCESS) {
            handler->SaveSsRequestCommand(utCommand, index);
        }
        return result;
    }
    /*
     * <n> (sets/shows the result code presentation status in the TA):
     * 0	disable
     * 1	enable
     */
    if (!PhoneTypeGsmOrNot(slotId)) {
        TELEPHONY_LOGE("[slot%{public}d] network type is not supported!", slotId);
        return CALL_ERR_UNSUPPORTED_NETWORK_TYPE;
    }
    handler->RequestSsRequestCommandIndex(index);
    result = supplementRequestCs_.SetCallWaitingRequest(slotId, activate, classType, index);
    if (result == TELEPHONY_SUCCESS) {
        handler->SaveSsRequestCommand(utCommand, index);
    }
    return result;
}

int32_t CellularCallSupplement::GetCallWaiting(int32_t slotId)
{
    auto handler = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is nullptr!", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t result = TELEPHONY_ERROR;
    auto utCommand = std::make_shared<SsRequestCommand>();
    utCommand->flag = SS_FROM_SETTING_MENU;
    int32_t index;
    if (NeedUseImsToHandle(slotId)) {
        handler->RequestSsRequestCommandIndex(index);
        result = supplementRequestIms_.GetCallWaitingRequest(slotId, index);
        if (result == TELEPHONY_SUCCESS) {
            handler->SaveSsRequestCommand(utCommand, index);
        }
        return result;
    }
    if (!PhoneTypeGsmOrNot(slotId)) {
        TELEPHONY_LOGE("[slot%{public}d] network type is not supported!", slotId);
        return CALL_ERR_UNSUPPORTED_NETWORK_TYPE;
    }
    handler->RequestSsRequestCommandIndex(index);
    result = supplementRequestCs_.GetCallWaitingRequest(slotId, index);
    if (result == TELEPHONY_SUCCESS) {
        handler->SaveSsRequestCommand(utCommand, index);
    }
    return result;
}

int32_t CellularCallSupplement::SetCallRestriction(int32_t slotId, const CallRestrictionInfo &cRInfo)
{
    RadioResponseInfo responseInfo;
    responseInfo.error = ErrType::ERR_GENERIC_FAILURE;
    std::string fac;
    int32_t result = CheckCallRestrictionType(fac, cRInfo.fac);
    if (result != TELEPHONY_SUCCESS) {
        return result;
    }
    if (cRInfo.mode < CallRestrictionMode::RESTRICTION_MODE_DEACTIVATION ||
        cRInfo.mode > CallRestrictionMode::RESTRICTION_MODE_ACTIVATION) {
        TELEPHONY_LOGE("[slot%{public}d] mode parameter out of range!", slotId);
        return CALL_ERR_PARAMETER_OUT_OF_RANGE;
    }
    auto handler = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is nullptr!", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::string info(cRInfo.password);
    auto utCommand = std::make_shared<SsRequestCommand>();
    utCommand->flag = SS_FROM_SETTING_MENU;
    utCommand->facility = fac;
    utCommand->enable = static_cast<int32_t>(cRInfo.mode);
    size_t cpyLen = strlen(info.c_str()) + 1;
    size_t maxCpyLen = sizeof(utCommand->password);
    if (strcpy_s(utCommand->password, cpyLen > maxCpyLen ? maxCpyLen : cpyLen, info.c_str()) != EOK) {
        TELEPHONY_LOGE("[slot%{public}d] strcpy_s fail.", slotId);
        return TELEPHONY_ERR_STRCPY_FAIL;
    }
    int32_t index;
    if (NeedUseImsToHandle(slotId)) {
        return SetCallRestrictionByIms(slotId, fac, static_cast<int32_t>(cRInfo.mode), info, utCommand);
    }
    if (!PhoneTypeGsmOrNot(slotId)) {
        TELEPHONY_LOGE("[slot%{public}d] network type is not supported!", slotId);
        return CALL_ERR_UNSUPPORTED_NETWORK_TYPE;
    }
    handler->RequestSsRequestCommandIndex(index);
    result =
        supplementRequestCs_.SetCallRestrictionRequest(slotId, fac, static_cast<int32_t>(cRInfo.mode), info, index);
    if (result == TELEPHONY_SUCCESS) {
        handler->SaveSsRequestCommand(utCommand, index);
    }
    return result;
}

int32_t CellularCallSupplement::SetCallRestrictionByIms(
    int32_t slotId, std::string &fac, int32_t mode, std::string &pw, const std::shared_ptr<SsRequestCommand> &command)
{
    RadioResponseInfo responseInfo;
    responseInfo.error = ErrType::ERR_GENERIC_FAILURE;
    auto handler = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is nullptr!", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t index;
    handler->RequestSsRequestCommandIndex(index);
    int32_t result = supplementRequestIms_.SetCallRestrictionRequest(slotId, fac, mode, pw, index);
    if (result == TELEPHONY_SUCCESS) {
        handler->SaveSsRequestCommand(command, index);
    }
    return result;
}

int32_t CellularCallSupplement::GetCallRestriction(int32_t slotId, CallRestrictionType facType)
{
    std::string fac;
    int32_t result = CheckCallRestrictionType(fac, facType);
    if (result != TELEPHONY_SUCCESS) {
        return result;
    }
    auto handler = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is nullptr!", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    auto utCommand = std::make_shared<SsRequestCommand>();
    utCommand->flag = SS_FROM_SETTING_MENU;
    utCommand->facility = fac;
    int32_t index;
    if (NeedUseImsToHandle(slotId)) {
        handler->RequestSsRequestCommandIndex(index);
        result = supplementRequestIms_.GetCallRestrictionRequest(slotId, fac, index);
        if (result == TELEPHONY_SUCCESS) {
            handler->SaveSsRequestCommand(utCommand, index);
        }
        return result;
    }
    if (!PhoneTypeGsmOrNot(slotId)) {
        TELEPHONY_LOGE("[slot%{public}d] network type is not supported!", slotId);
        return CALL_ERR_UNSUPPORTED_NETWORK_TYPE;
    }
    handler->RequestSsRequestCommandIndex(index);
    result = supplementRequestCs_.GetCallRestrictionRequest(slotId, fac, index);
    if (result == TELEPHONY_SUCCESS) {
        handler->SaveSsRequestCommand(utCommand, index);
    }
    return result;
}

int32_t CellularCallSupplement::SetBarringPassword(
    int32_t slotId, CallRestrictionType facType, const char *oldPassword, const char *newPassword)
{
    std::string fac;
    int32_t result = CheckCallRestrictionType(fac, facType);
    if (result != TELEPHONY_SUCCESS) {
        return result;
    }
    auto handler = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handler == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] handler is nullptr!", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    auto utCommand = std::make_shared<SsRequestCommand>();
    utCommand->flag = SS_FROM_SETTING_MENU;
    utCommand->facility = fac;
    if (!PhoneTypeGsmOrNot(slotId)) {
        TELEPHONY_LOGE("[slot%{public}d] network type is not supported!", slotId);
        return CALL_ERR_UNSUPPORTED_NETWORK_TYPE;
    }
    int32_t index;
    handler->RequestSsRequestCommandIndex(index);
    result = supplementRequestCs_.SetBarringPasswordRequest(slotId, fac, index, oldPassword, newPassword);
    if (result == TELEPHONY_SUCCESS) {
        handler->SaveSsRequestCommand(utCommand, index);
    }
    return result;
}

int32_t CellularCallSupplement::CheckCallRestrictionType(std::string &fac, const CallRestrictionType &facType)
{
    /*
     * <fac> values reserved by the present document:
     * "SC"	SIM (lock SIM/UICC card) (SIM/UICC asks password in ME power up and when this lock command issued)
     * "AO"	BAOC (Barr All Outgoing Calls) (refer 3GPP TS 22.088 [6] clause 1)
     * "OI"	BOIC (Barr Outgoing International Calls) (refer 3GPP TS 22.088 [6] clause 1)
     * "OX"	BOIC exHC (Barr Outgoing International Calls except to Home Country) (refer 3GPP TS 22.088 [6] clause 1)
     * "AI"	BAIC (Barr All Incoming Calls) (refer 3GPP TS 22.088 [6] clause 2)
     * "IR"	BIC Roam (Barr Incoming Calls when Roaming outside the home country) (refer 3GPP TS 22.088 [6] clause 2)
     * "AB"	All Barring services (refer 3GPP TS 22.030 [19]) (applicable only for <mode>=0)
     * "AG"	All outGoing barring services (refer 3GPP TS 22.030 [19]) (applicable only for <mode>=0)
     * "AC"	All inComing barring services (refer 3GPP TS 22.030 [19]) (applicable only for <mode>=0)
     */
    switch (facType) {
        case CallRestrictionType::RESTRICTION_TYPE_ALL_OUTGOING:
            fac = BARR_ALL_OUTGOING_CALLS;
            break;
        case CallRestrictionType::RESTRICTION_TYPE_INTERNATIONAL:
            fac = BARR_OUTGOING_INTERNATIONAL_CALLS;
            break;
        case CallRestrictionType::RESTRICTION_TYPE_INTERNATIONAL_EXCLUDING_HOME:
            fac = BARR_OUTGOING_INTERNATIONAL_CALLS_EXCLUDING_HOME;
            break;
        case CallRestrictionType::RESTRICTION_TYPE_ALL_INCOMING:
            fac = BARR_ALL_INCOMING_CALLS;
            break;
        case CallRestrictionType::RESTRICTION_TYPE_ROAMING_INCOMING:
            fac = BARR_INCOMING_CALLS_OUTSIDE_HOME;
            break;
        case CallRestrictionType::RESTRICTION_TYPE_ALL_CALLS:
            fac = ALL_BARRING_SERVICES;
            break;
        case CallRestrictionType::RESTRICTION_TYPE_OUTGOING_SERVICES:
            fac = ALL_OUTGOING_BARRING_SERVICES;
            break;
        case CallRestrictionType::RESTRICTION_TYPE_INCOMING_SERVICES:
            fac = ALL_INCOMING_BARRING_SERVICES;
            break;
        default:
            TELEPHONY_LOGE("parameter out of range!");
            return CALL_ERR_PARAMETER_OUT_OF_RANGE;
    }
    return TELEPHONY_SUCCESS;
}

void CellularCallSupplement::EventGetClip(const GetClipResult &getClipResult, const std::string &message, int32_t flag)
{
    ClipResponse clipResponse;
    clipResponse.result = getClipResult.result.result;
    if (clipResponse.result == IMS_ERROR_UT_NO_CONNECTION) {
        clipResponse.result = CALL_ERR_UT_NO_CONNECTION;
    }
    clipResponse.action = getClipResult.action;
    clipResponse.clipStat = getClipResult.clipStat;
    auto callRegister = DelayedSingleton<CellularCallRegister>::GetInstance();
    if (callRegister == nullptr) {
        TELEPHONY_LOGE("callRegister is null.");
        return;
    }

    if (flag == SS_FROM_MMI_CODE) {
        std::string successMessage = GET_CLIP_SUCCESS;
        CreateSuppSvcQueryResultMessage(successMessage, clipResponse.result, clipResponse.clipStat);
        ReportMmiCodeMessage(clipResponse.result, successMessage, message.empty() ? GET_CLIP_FAILED : message);
    } else {
        callRegister->ReportGetClipResult(clipResponse);
    }
}

void CellularCallSupplement::EventSetClip(int32_t result, const std::string &message, int32_t flag)
{
    if (flag == SS_FROM_MMI_CODE) {
        ReportMmiCodeMessage(result, SET_CLIP_SUCCESS, message.empty() ? SET_CLIP_FAILED : message);
    } else {
        TELEPHONY_LOGE("report the result of GetColp failed since the flag %{public}d was wrong", flag);
    }
}

void CellularCallSupplement::EventGetClir(const GetClirResult &result, const std::string &message, int32_t flag)
{
    ClirResponse response;
    // 3GPP TS 27.007 V3.9.0 (2001-06) 7.7	Calling line identification restriction +CLIR
    response.result = result.result.result;
    if (response.result == IMS_ERROR_UT_NO_CONNECTION) {
        response.result = CALL_ERR_UT_NO_CONNECTION;
    }
    response.action = result.action;
    response.clirStat = result.clirStat;
    auto callRegister = DelayedSingleton<CellularCallRegister>::GetInstance();
    if (callRegister == nullptr) {
        TELEPHONY_LOGE("callRegister is null.");
        return;
    }
    if (flag == SS_FROM_MMI_CODE) {
        std::string successMessage = GET_CLIR_SUCCESS;
        CreateGetClirResultMessage(successMessage, response);
        ReportMmiCodeMessage(response.result, successMessage, message.empty() ? GET_CLIR_FAILED : message);
    } else {
        callRegister->ReportGetClirResult(response);
    }
}

void CellularCallSupplement::EventSetClir(int32_t result, const std::string &message, int32_t flag)
{
    auto callRegister = DelayedSingleton<CellularCallRegister>::GetInstance();
    if (callRegister == nullptr) {
        TELEPHONY_LOGE("callRegister is null.");
        return;
    }
    if (flag == SS_FROM_MMI_CODE) {
        ReportMmiCodeMessage(result, SET_CLIR_SUCCESS, message.empty() ? SET_CLIR_FAILED : message);
    } else {
        callRegister->ReportSetClirResult(result);
    }
}

void CellularCallSupplement::EventGetColr(const GetColrResult &result, const std::string &message, int32_t flag)
{
    ColrResponse response;
    response.result = result.result.result;
    if (response.result == IMS_ERROR_UT_NO_CONNECTION) {
        response.result = CALL_ERR_UT_NO_CONNECTION;
    }
    response.action = result.action;
    response.colrStat = result.colrStat;
    if (flag == SS_FROM_MMI_CODE) {
        std::string successMessage = GET_COLR_SUCCESS;
        CreateSuppSvcQueryResultMessage(successMessage, response.result, response.colrStat);
        ReportMmiCodeMessage(response.result, successMessage, message.empty() ? GET_COLR_FAILED : message);
    } else {
        TELEPHONY_LOGE("report the result of GetColp failed since the flag %{public}d was wrong", flag);
    }
}

void CellularCallSupplement::EventSetColr(int32_t result, const std::string &message, int32_t flag)
{
    if (flag == SS_FROM_MMI_CODE) {
        ReportMmiCodeMessage(result, SET_COLR_SUCCESS, message.empty() ? SET_COLR_FAILED : message);
    } else {
        TELEPHONY_LOGE("report the result of GetColp failed since the flag %{public}d was wrong", flag);
    }
}

void CellularCallSupplement::EventGetColp(const GetColpResult &result, const std::string &message, int32_t flag)
{
    ColpResponse response;
    response.result = result.result.result;
    if (response.result == IMS_ERROR_UT_NO_CONNECTION) {
        response.result = CALL_ERR_UT_NO_CONNECTION;
    }
    response.action = result.action;
    response.colpStat = result.colpStat;
    if (flag == SS_FROM_MMI_CODE) {
        std::string successMessage = GET_COLP_SUCCESS;
        CreateSuppSvcQueryResultMessage(successMessage, response.result, response.colpStat);
        ReportMmiCodeMessage(response.result, successMessage, message.empty() ? GET_COLP_FAILED : message);
    } else {
        TELEPHONY_LOGE("report the result of GetColp failed since the flag %{public}d was wrong", flag);
    }
}

void CellularCallSupplement::EventSetColp(int32_t result, const std::string &message, int32_t flag)
{
    if (flag == SS_FROM_MMI_CODE) {
        ReportMmiCodeMessage(result, SET_COLP_SUCCESS, message.empty() ? SET_COLP_FAILED : message);
    } else {
        TELEPHONY_LOGE("report the result of GetColp failed since the flag %{public}d was wrong", flag);
    }
}

int32_t CellularCallSupplement::SendUssd(int32_t slotId, const std::string &msg)
{
    if (!PhoneTypeGsmOrNot(slotId)) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", GENERIC_FAILURE);
        TELEPHONY_LOGE("[slot%{public}d] network type is not supported!", slotId);
        return CALL_ERR_UNSUPPORTED_NETWORK_TYPE;
    }
    int32_t result = TELEPHONY_SUCCESS;
    result = supplementRequestCs_.SendUssdRequest(slotId, msg);
    if (result != TELEPHONY_SUCCESS) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", GENERIC_FAILURE);
    }
    return result;
}

void CellularCallSupplement::EventSendUssd(const RadioResponseInfo &responseInfo)
{
    auto callRegister = DelayedSingleton<CellularCallRegister>::GetInstance();
    if (callRegister == nullptr) {
        TELEPHONY_LOGE("callRegister is null.");
        return;
    }
    callRegister->ReportSendUssdResult(static_cast<int32_t>(responseInfo.error));
    ReportMmiCodeMessage(static_cast<int32_t>(responseInfo.error), SEND_USSD_SUCCESS, INVALID_MMI_CODE);
}

void CellularCallSupplement::EventSsNotify(SsNoticeInfo &ssNoticeInfo)
{
    MmiCodeInfo mmiCodeInfo;
    mmiCodeInfo.result = ssNoticeInfo.result;
    switch (ssNoticeInfo.requestType) {
        case static_cast<int32_t>(SsRequestType::SS_ACTIVATION):
        case static_cast<int32_t>(SsRequestType::SS_DEACTIVATION):
        case static_cast<int32_t>(SsRequestType::SS_REGISTRATION):
        case static_cast<int32_t>(SsRequestType::SS_ERASURE):
        case static_cast<int32_t>(SsRequestType::SS_INTERROGATION):
            GetMessage(mmiCodeInfo, ssNoticeInfo);
            break;
        default:
            TELEPHONY_LOGE("Invaid requestType in SS Data!");
            return;
    }

    auto callRegister = DelayedSingleton<CellularCallRegister>::GetInstance();
    if (callRegister == nullptr) {
        TELEPHONY_LOGE("callRegister is null.");
        return;
    }
    callRegister->ReportMmiCodeResult(mmiCodeInfo);
}

void CellularCallSupplement::GetMessage(MmiCodeInfo &mmiCodeInfo, const SsNoticeInfo &ssNoticeInfo)
{
    if (ssNoticeInfo.result != 0) {
        size_t cpyLen = strlen(QUERY_SS_FAILED.c_str()) + 1;
        if (strcpy_s(mmiCodeInfo.message, cpyLen, QUERY_SS_FAILED.c_str()) != EOK) {
            TELEPHONY_LOGE("strcpy_s QUERY_SS_FAILED fail.");
        }
        return;
    }
    switch (ssNoticeInfo.serviceType) {
        case (unsigned int)CallTransferType::TRANSFER_TYPE_UNCONDITIONAL: {
            size_t cpyLen = strlen(TRANSFER_UNCONDITIONAL_SUCCESS.c_str()) + 1;
            if (strcpy_s(mmiCodeInfo.message, cpyLen, TRANSFER_UNCONDITIONAL_SUCCESS.c_str()) != EOK) {
                TELEPHONY_LOGE("strcpy_s TRANSFER_UNCONDITIONAL_SUCCESS fail.");
                return;
            }
            break;
        }
        case (unsigned int)CallTransferType::TRANSFER_TYPE_BUSY: {
            size_t cpyLen = strlen(TRANSFER_BUSY_SUCCESS.c_str()) + 1;
            if (strcpy_s(mmiCodeInfo.message, cpyLen, TRANSFER_BUSY_SUCCESS.c_str()) != EOK) {
                TELEPHONY_LOGE("strcpy_s TRANSFER_BUSY_SUCCESS fail.");
                return;
            }
            break;
        }
        case (unsigned int)CallTransferType::TRANSFER_TYPE_NO_REPLY: {
            size_t cpyLen = strlen(TRANSFER_NO_REPLYL_SUCCESS.c_str()) + 1;
            if (strcpy_s(mmiCodeInfo.message, cpyLen, TRANSFER_NO_REPLYL_SUCCESS.c_str()) != EOK) {
                TELEPHONY_LOGE("strcpy_s TRANSFER_NO_REPLYL_SUCCESS fail.");
                return;
            }
            break;
        }
        case (unsigned int)CallTransferType::TRANSFER_TYPE_NOT_REACHABLE: {
            size_t cpyLen = strlen(TRANSFER_NOT_REACHABLE_SUCCESS.c_str()) + 1;
            if (strcpy_s(mmiCodeInfo.message, cpyLen, TRANSFER_NOT_REACHABLE_SUCCESS.c_str()) != EOK) {
                TELEPHONY_LOGE("strcpy_s TRANSFER_NOT_REACHABLE_SUCCESS fail.");
                return;
            }
            break;
        }
        default: {
            size_t cpyLen = strlen(QUERY_SS_SUCCESS.c_str()) + 1;
            if (strcpy_s(mmiCodeInfo.message, cpyLen, QUERY_SS_SUCCESS.c_str()) != EOK) {
                TELEPHONY_LOGE("strcpy_s QUERY_SS_SUCCESS fail.");
                return;
            }
        }
    }
}

void CellularCallSupplement::EventUssdNotify(UssdNoticeInfo &ussdNoticeInfo)
{
    MmiCodeInfo mmiCodeInfo;
    bool isUssdError = ussdNoticeInfo.m != USSD_MODE_NOTIFY && ussdNoticeInfo.m != USSD_MODE_REQUEST;
    if (!isUssdError && !ussdNoticeInfo.str.empty()) {
        mmiCodeInfo.result = USSD_SUCCESS;
        size_t cpyLen = strlen(ussdNoticeInfo.str.c_str()) + 1;
        if (strcpy_s(mmiCodeInfo.message, cpyLen, ussdNoticeInfo.str.c_str()) != EOK) {
            TELEPHONY_LOGE("strcpy_s ussdNoticeInfo.str fail.");
            return;
        }
    } else if (isUssdError && !(ussdNoticeInfo.m == USSD_MODE_NW_RELEASE)) {
        mmiCodeInfo.result = USSD_FAILED;
        size_t cpyLen = strlen(INVALID_MMI_CODE.c_str()) + 1;
        if (strcpy_s(mmiCodeInfo.message, cpyLen, INVALID_MMI_CODE.c_str()) != EOK) {
            TELEPHONY_LOGE("strcpy_s INVALID_MMI_CODE fail.");
            return;
        }
    } else {
        TELEPHONY_LOGE("Invaild ussd notify.");
    }

    auto callRegister = DelayedSingleton<CellularCallRegister>::GetInstance();
    if (callRegister == nullptr) {
        TELEPHONY_LOGE("callRegister is null.");
        return;
    }
    callRegister->ReportMmiCodeResult(mmiCodeInfo);
}

void CellularCallSupplement::EventSetPinPuk(const PinPukResponse &pinPukResponse)
{
    MmiCodeInfo mmiCodeInfo;
    mmiCodeInfo.result = pinPukResponse.result;
    std::string messageTemp = std::to_string(pinPukResponse.remain);
    size_t cpyLen = strlen(messageTemp.c_str()) + 1;
    if (strcpy_s(mmiCodeInfo.message, cpyLen, messageTemp.c_str()) != EOK) {
        TELEPHONY_LOGE("strcpy_s messageTemp fail.");
    }
    auto callRegister = DelayedSingleton<CellularCallRegister>::GetInstance();
    if (callRegister == nullptr) {
        TELEPHONY_LOGE("callRegister is null.");
        return;
    }
    callRegister->ReportMmiCodeResult(mmiCodeInfo);
}

void CellularCallSupplement::AlterPinPassword(int32_t slotId, const MMIData &mmiData)
{
    if (mmiData.actionString.empty()) {
        TELEPHONY_LOGE("[slot%{public}d] actionString is empty!", slotId);
        return;
    }

    std::string oldPin = mmiData.serviceInfoA;
    std::string newPin = mmiData.serviceInfoB;
    std::string newPinCheck = mmiData.serviceInfoC;
    if (!IsVaildPinOrPuk(newPin, newPinCheck)) {
        return;
    }
    int32_t result = TELEPHONY_SUCCESS;
    result = supplementRequestCs_.AlterPinPassword(slotId, newPin, oldPin);
    if (result != TELEPHONY_SUCCESS) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", GENERIC_FAILURE);
    }
}

void CellularCallSupplement::UnlockPuk(int32_t slotId, const MMIData &mmiData)
{
    if (mmiData.actionString.empty()) {
        TELEPHONY_LOGE("[slot%{public}d] actionString is empty!", slotId);
        return;
    }
    std::string puk = mmiData.serviceInfoA;
    std::string newPin = mmiData.serviceInfoB;
    std::string newPinCheck = mmiData.serviceInfoC;
    if (!IsVaildPinOrPuk(newPin, newPinCheck)) {
        return;
    }
    int32_t result = TELEPHONY_SUCCESS;
    result = supplementRequestCs_.UnlockPuk(slotId, newPin, puk);
    if (result != TELEPHONY_SUCCESS) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", GENERIC_FAILURE);
    }
}

void CellularCallSupplement::AlterPin2Password(int32_t slotId, const MMIData &mmiData)
{
    if (mmiData.actionString.empty()) {
        TELEPHONY_LOGE("[slot%{public}d] actionString is empty!", slotId);
        return;
    }

    std::string oldPin2 = mmiData.serviceInfoA;
    std::string newPin2 = mmiData.serviceInfoB;
    std::string newPin2Check = mmiData.serviceInfoC;
    if (!IsVaildPinOrPuk(newPin2, newPin2Check)) {
        return;
    }
    int32_t result = TELEPHONY_SUCCESS;
    result = supplementRequestCs_.AlterPin2Password(slotId, newPin2, oldPin2);
    if (result != TELEPHONY_SUCCESS) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", GENERIC_FAILURE);
    }
}

void CellularCallSupplement::UnlockPuk2(int32_t slotId, const MMIData &mmiData)
{
    if (mmiData.actionString.empty()) {
        TELEPHONY_LOGE("[slot%{public}d] actionString is empty!", slotId);
        return;
    }

    std::string puk2 = mmiData.serviceInfoA;
    std::string newPin2 = mmiData.serviceInfoB;
    std::string newPin2Check = mmiData.serviceInfoC;
    if (!IsVaildPinOrPuk(newPin2, newPin2Check)) {
        return;
    }
    int32_t result = TELEPHONY_SUCCESS;
    result = supplementRequestCs_.UnlockPuk2(slotId, newPin2, puk2);
    if (result != TELEPHONY_SUCCESS) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", GENERIC_FAILURE);
    }
}

bool CellularCallSupplement::IsVaildPinOrPuk(std::string newPinOrPuk, std::string newPinOrPukCheck)
{
    if (newPinOrPuk != newPinOrPukCheck) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", MIS_MATCH_PIN_PUK);
        return false;
    } else if (static_cast<int32_t>(newPinOrPuk.length()) < PIN_PUK_MIN ||
               static_cast<int32_t>(newPinOrPuk.length()) > PIN_PUK_MAX) {
        ReportMmiCodeMessage(MMI_CODE_FAILED, "", INVAILD_PIN_PUK);
        return false;
    } else {
        TELEPHONY_LOGI("Check Pin or Puk success.");
    }
    return true;
}

void CellularCallSupplement::ReportMmiCodeMessage(
    int32_t result, const std::string successMsg, const std::string failedMsg)
{
    MmiCodeInfo mmiCodeInfo;
    mmiCodeInfo.result = result;
    if (result == RESULT_SUCCESS) {
        size_t cpyLen = strlen(successMsg.c_str()) + 1;
        if (strcpy_s(mmiCodeInfo.message, cpyLen, successMsg.c_str()) != EOK) {
            TELEPHONY_LOGE("strcpy_s fail.");
            return;
        }
    } else {
        size_t cpyLen = strlen(failedMsg.c_str()) + 1;
        if (strcpy_s(mmiCodeInfo.message, cpyLen, failedMsg.c_str()) != EOK) {
            TELEPHONY_LOGE("strcpy_s fail.");
            return;
        }
    }
    auto callRegister = DelayedSingleton<CellularCallRegister>::GetInstance();
    if (callRegister == nullptr) {
        TELEPHONY_LOGE("callRegister is null.");
        return;
    }
    callRegister->ReportMmiCodeResult(mmiCodeInfo);
}

int32_t CellularCallSupplement::CloseUnFinishedUssd(int32_t slotId)
{
    if (!PhoneTypeGsmOrNot(slotId)) {
        TELEPHONY_LOGE("[slot%{public}d] network type is not supported!", slotId);
        return CALL_ERR_UNSUPPORTED_NETWORK_TYPE;
    }
    return supplementRequestCs_.CloseUnFinishedUssdRequest(slotId);
}

void CellularCallSupplement::EventCloseUnFinishedUssd(const RadioResponseInfo &responseInfo)
{
    auto callRegister = DelayedSingleton<CellularCallRegister>::GetInstance();
    if (callRegister == nullptr) {
        TELEPHONY_LOGE("callRegister is null.");
        return;
    }
    int32_t result = TELEPHONY_ERROR;
    if (responseInfo.error == ErrType::NONE) {
        result = TELEPHONY_SUCCESS;
    } else {
        result = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    callRegister->ReportCloseUnFinishedUssdResult(result);
}
} // namespace Telephony
} // namespace OHOS

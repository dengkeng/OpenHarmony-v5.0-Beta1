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
#include "supplement_request_cs.h"

#include "cellular_call_service.h"
#include "radio_event.h"
#include "securec.h"
#include "telephony_log_wrapper.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
int32_t SupplementRequestCs::GetClipRequest(int32_t slotId, int32_t index)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_GET_CALL_CLIP, index);
    if (response == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] response is null!", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(GetMMIHandler(slotId));
    return CoreManagerInner::GetInstance().GetClip(slotId, response);
}

int32_t SupplementRequestCs::SetClirRequest(int32_t slotId, int32_t action, int32_t index)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SET_CALL_CLIR, index);
    if (response == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] response is null!", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(GetMMIHandler(slotId));
    return CoreManagerInner::GetInstance().SetClir(slotId, action, response);
}

int32_t SupplementRequestCs::GetClirRequest(int32_t slotId, int32_t index)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_GET_CALL_CLIR, index);
    if (response == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] response is null!", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(GetMMIHandler(slotId));
    return CoreManagerInner::GetInstance().GetClir(slotId, response);
}

int32_t SupplementRequestCs::GetCallTransferRequest(int32_t slotId, int32_t reason, int32_t index)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_GET_CALL_FORWARD, index);
    if (response == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] response is null!", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(GetMMIHandler(slotId));
    return CoreManagerInner::GetInstance().GetCallTransferInfo(slotId, reason, response);
}

int32_t SupplementRequestCs::SetCallTransferRequest(
    int32_t slotId, const CallTransferParam &callTransferParam, int32_t index)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SET_CALL_FORWARD, index);
    if (response == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] response is null!", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(GetMMIHandler(slotId));
    return CoreManagerInner::GetInstance().SetCallTransferInfo(slotId, callTransferParam, response);
}

int32_t SupplementRequestCs::GetCallRestrictionRequest(int32_t slotId, const std::string &fac, int32_t index)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    AppExecFwk::InnerEvent::Pointer response =
        AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_GET_CALL_RESTRICTION, index);
    if (response == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] response is null!", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(GetMMIHandler(slotId));
    return CoreManagerInner::GetInstance().GetCallRestriction(slotId, fac, response);
}

int32_t SupplementRequestCs::SetCallRestrictionRequest(
    int32_t slotId, const std::string &fac, int32_t mode, const std::string &pw, int32_t index)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    CallRestrictionParam callRestrictionParam;
    callRestrictionParam.mode = mode;
    callRestrictionParam.fac = fac;
    size_t cpyLen = strlen(pw.c_str()) + 1;
    size_t maxCpyLen = sizeof(callRestrictionParam.password);
    if (strcpy_s(callRestrictionParam.password, cpyLen > maxCpyLen ? maxCpyLen : cpyLen, pw.c_str()) != EOK) {
        TELEPHONY_LOGE("[slot%{public}d] strcpy_s fail.", slotId);
        return TELEPHONY_ERR_STRCPY_FAIL;
    }
    AppExecFwk::InnerEvent::Pointer response =
        AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SET_CALL_RESTRICTION, index);
    if (response == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] response is null!", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(GetMMIHandler(slotId));
    return CoreManagerInner::GetInstance().SetCallRestriction(slotId, callRestrictionParam, response);
}

int32_t SupplementRequestCs::SetBarringPasswordRequest(int32_t slotId, const std::string &restrictionType,
    int32_t index, const char *oldPassword, const char *newPassword)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    AppExecFwk::InnerEvent::Pointer response =
        AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SET_CALL_RESTRICTION_PWD, index);
    if (response == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] response is null!", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(GetMMIHandler(slotId));
    return CoreManagerInner::GetInstance().SetBarringPassword(
        slotId, oldPassword, newPassword, restrictionType, response);
}

int32_t SupplementRequestCs::SetCallWaitingRequest(int32_t slotId, bool activate, int32_t classType, int32_t index)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SET_CALL_WAIT, index);
    if (response == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] response is null!", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(GetMMIHandler(slotId));
    return CoreManagerInner::GetInstance().SetCallWaiting(slotId, activate, response);
}

int32_t SupplementRequestCs::GetCallWaitingRequest(int32_t slotId, int32_t index)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_GET_CALL_WAIT, index);
    if (response == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] response is null!", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(GetMMIHandler(slotId));
    return CoreManagerInner::GetInstance().GetCallWaiting(slotId, response);
}

std::shared_ptr<CellularCallHandler> SupplementRequestCs::GetMMIHandler(int32_t slotId) const
{
    auto callService = DelayedSingleton<CellularCallService>::GetInstance();
    if (callService == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] error type: callService is nullptr.", slotId);
        return nullptr;
    }
    return callService->GetHandler(slotId);
}

int32_t SupplementRequestCs::SendUssdRequest(int32_t slotId, const std::string &msg)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    return CoreManagerInner::GetInstance().SetUssd(slotId, RadioEvent::RADIO_SET_USSD, msg, GetMMIHandler(slotId));
}

int32_t SupplementRequestCs::AlterPinPassword(int32_t slotId, std::string newPin, std::string oldPin)
{
    TELEPHONY_LOGD("[slot%{public}d] entry", slotId);
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreManagerInner::GetInstance().AlterPin(slotId, newPin, oldPin, response);
    TELEPHONY_LOGI("[slot%{public}d] result: %{public}d, remain: %{public}d", slotId, response.result, response.remain);
    if (result == TELEPHONY_SUCCESS) {
        std::shared_ptr<CellularCallHandler> ccHandler = GetMMIHandler(slotId);
        std::shared_ptr<PinPukResponse> pinResData = std::make_shared<PinPukResponse>();
        pinResData->result = response.result;
        pinResData->remain = response.remain;
        AppExecFwk::InnerEvent::Pointer msgEvent =
            AppExecFwk::InnerEvent::Get(MMIHandlerId::EVENT_SET_UNLOCK_PIN_PUK_ID, pinResData, 0);
        bool ret = ccHandler->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE);
        if (!ret) {
            TELEPHONY_LOGE("[slot%{public}d] SendEvent failed! status update failed", slotId);
            return TELEPHONY_ERR_FAIL;
        }
        return TELEPHONY_SUCCESS;
    }
    return TELEPHONY_ERROR;
}

int32_t SupplementRequestCs::UnlockPuk(int32_t slotId, std::string newPin, std::string puk)
{
    TELEPHONY_LOGD("[slot%{public}d] entry", slotId);
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreManagerInner::GetInstance().UnlockPuk(slotId, newPin, puk, response);
    TELEPHONY_LOGI("[slot%{public}d] result: %{public}d, remain: %{public}d", slotId, response.result, response.remain);
    if (result == TELEPHONY_SUCCESS) {
        std::shared_ptr<CellularCallHandler> ccHandler = GetMMIHandler(slotId);
        std::shared_ptr<PinPukResponse> pinResData = std::make_shared<PinPukResponse>();
        pinResData->result = response.result;
        pinResData->remain = response.remain;
        AppExecFwk::InnerEvent::Pointer msgEvent =
            AppExecFwk::InnerEvent::Get(MMIHandlerId::EVENT_SET_UNLOCK_PIN_PUK_ID, pinResData, 0);
        bool ret = ccHandler->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE);
        if (!ret) {
            TELEPHONY_LOGE("[slot%{public}d] SendEvent failed! status update failed", slotId);
            return TELEPHONY_ERR_FAIL;
        }
        return TELEPHONY_SUCCESS;
    }
    return TELEPHONY_ERROR;
}

int32_t SupplementRequestCs::AlterPin2Password(int32_t slotId, std::string newPin2, std::string oldPin2)
{
    TELEPHONY_LOGD("[slot%{public}d] entry", slotId);
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreManagerInner::GetInstance().AlterPin2(slotId, newPin2, oldPin2, response);
    TELEPHONY_LOGI("[slot%{public}d] result: %{public}d, remain: %{public}d", slotId, response.result, response.remain);
    if (result == TELEPHONY_SUCCESS) {
        std::shared_ptr<CellularCallHandler> ccHandler = GetMMIHandler(slotId);
        std::shared_ptr<PinPukResponse> pinResData = std::make_shared<PinPukResponse>();
        pinResData->result = response.result;
        pinResData->remain = response.remain;
        AppExecFwk::InnerEvent::Pointer msgEvent =
            AppExecFwk::InnerEvent::Get(MMIHandlerId::EVENT_SET_UNLOCK_PIN_PUK_ID, pinResData, 0);
        bool ret = ccHandler->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE);
        if (!ret) {
            TELEPHONY_LOGE("[slot%{public}d] SendEvent failed! status update failed", slotId);
            return TELEPHONY_ERR_FAIL;
        }
        return TELEPHONY_SUCCESS;
    }
    return TELEPHONY_ERROR;
}

int32_t SupplementRequestCs::UnlockPuk2(int32_t slotId, std::string newPin2, std::string puk2)
{
    TELEPHONY_LOGD("[slot%{public}d] entry", slotId);
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreManagerInner::GetInstance().UnlockPuk2(slotId, newPin2, puk2, response);
    TELEPHONY_LOGI("[slot%{public}d] result: %{public}d, remain: %{public}d", slotId, response.result, response.remain);
    if (result == TELEPHONY_SUCCESS) {
        std::shared_ptr<CellularCallHandler> ccHandler = GetMMIHandler(slotId);
        std::shared_ptr<PinPukResponse> pinResData = std::make_shared<PinPukResponse>();
        pinResData->result = response.result;
        pinResData->remain = response.remain;
        AppExecFwk::InnerEvent::Pointer msgEvent =
            AppExecFwk::InnerEvent::Get(MMIHandlerId::EVENT_SET_UNLOCK_PIN_PUK_ID, pinResData, 0);
        bool ret = ccHandler->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE);
        if (!ret) {
            TELEPHONY_LOGE("[slot%{public}d] SendEvent failed! status update failed", slotId);
            return TELEPHONY_ERR_FAIL;
        }
        return TELEPHONY_SUCCESS;
    }
    return TELEPHONY_ERROR;
}

int32_t SupplementRequestCs::CloseUnFinishedUssdRequest(int32_t slotId)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    return CoreManagerInner::GetInstance().CloseUnFinishedUssd(
        slotId, RadioEvent::RADIO_CLOSE_UNFINISHED_USSD, GetMMIHandler(slotId));
}
} // namespace Telephony
} // namespace OHOS

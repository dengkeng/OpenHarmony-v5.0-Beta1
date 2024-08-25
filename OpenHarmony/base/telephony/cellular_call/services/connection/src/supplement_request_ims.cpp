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

#include "supplement_request_ims.h"

#include "cellular_call_service.h"
#include "ims_call_client.h"
#include "radio_event.h"
#include "telephony_log_wrapper.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
int32_t SupplementRequestIms::SetClipRequest(int32_t slotId, int32_t action, int32_t index)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
    if (imsCallClient == nullptr) {
        TELEPHONY_LOGE("ImsCallClient is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    return imsCallClient->SetClip(slotId, action, index);
}

int32_t SupplementRequestIms::GetClipRequest(int32_t slotId, int32_t index)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
    if (imsCallClient == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] ImsCallClient is nullptr.", slotId);
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    return imsCallClient->GetClip(slotId, index);
}

int32_t SupplementRequestIms::SetClirRequest(int32_t slotId, int32_t action, int32_t index)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
    if (imsCallClient == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] ImsCallClient is nullptr.", slotId);
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    return imsCallClient->SetClir(slotId, action, index);
}

int32_t SupplementRequestIms::GetClirRequest(int32_t slotId, int32_t index)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
    if (imsCallClient == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] ImsCallClient is nullptr.", slotId);
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    return imsCallClient->GetClir(slotId, index);
}

int32_t SupplementRequestIms::GetCallTransferRequest(int32_t slotId, int32_t reason, int32_t index)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
    if (imsCallClient == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] ImsCallClient is nullptr.", slotId);
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    return imsCallClient->GetCallTransfer(slotId, reason, index);
}

int32_t SupplementRequestIms::SetCallTransferRequest(
    int32_t slotId, const CallTransferInfo &cfInfo, int32_t classType, int32_t index)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
    if (imsCallClient == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] ImsCallClient is nullptr.", slotId);
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    return imsCallClient->SetCallTransfer(slotId, cfInfo, classType, index);
}

int32_t SupplementRequestIms::CanSetCallTransferTime(int32_t slotId, bool &result)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
    if (imsCallClient == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] ImsCallClient is nullptr.", slotId);
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    return imsCallClient->CanSetCallTransferTime(slotId, result);
}

int32_t SupplementRequestIms::GetCallRestrictionRequest(int32_t slotId, const std::string &fac, int32_t index)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
    if (imsCallClient == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] ImsCallClient is nullptr.", slotId);
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    return imsCallClient->GetCallRestriction(slotId, fac, index);
}

int32_t SupplementRequestIms::SetCallRestrictionRequest(
    int32_t slotId, std::string &fac, int32_t mode, std::string &pw, int32_t index)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
    if (imsCallClient == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] ImsCallClient is nullptr.", slotId);
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    return imsCallClient->SetCallRestriction(slotId, fac, mode, pw, index);
}

int32_t SupplementRequestIms::SetCallWaitingRequest(int32_t slotId, bool activate, int32_t classType, int32_t index)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
    if (imsCallClient == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] ImsCallClient is nullptr.", slotId);
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    return imsCallClient->SetCallWaiting(slotId, activate, classType, index);
}

int32_t SupplementRequestIms::GetCallWaitingRequest(int32_t slotId, int32_t index)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
    if (imsCallClient == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] ImsCallClient is nullptr.", slotId);
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    return imsCallClient->GetCallWaiting(slotId, index);
}

int32_t SupplementRequestIms::SetColrRequest(int32_t slotId, int32_t presentation, int32_t index)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
    if (imsCallClient == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] ImsCallClient is nullptr.", slotId);
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    return imsCallClient->SetColr(slotId, presentation, index);
}

int32_t SupplementRequestIms::GetColrRequest(int32_t slotId, int32_t index)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
    if (imsCallClient == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] ImsCallClient is nullptr.", slotId);
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    return imsCallClient->GetColr(slotId, index);
}

int32_t SupplementRequestIms::SetColpRequest(int32_t slotId, int32_t action, int32_t index)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
    if (imsCallClient == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] ImsCallClient is nullptr.", slotId);
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    return imsCallClient->SetColp(slotId, action, index);
}

int32_t SupplementRequestIms::GetColpRequest(int32_t slotId, int32_t index)
{
    TELEPHONY_LOGI("[slot%{public}d] entry", slotId);
    auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
    if (imsCallClient == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] ImsCallClient is nullptr.", slotId);
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    return imsCallClient->GetColp(slotId, index);
}

std::shared_ptr<CellularCallHandler> SupplementRequestIms::GetMMIHandler(int32_t slotId) const
{
    auto callService = DelayedSingleton<CellularCallService>::GetInstance();
    if (callService == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] error type: callService is nullptr.", slotId);
        return nullptr;
    }
    return callService->GetHandler(slotId);
}
} // namespace Telephony
} // namespace OHOS

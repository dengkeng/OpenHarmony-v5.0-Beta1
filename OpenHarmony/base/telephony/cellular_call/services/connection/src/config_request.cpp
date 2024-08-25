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

#include "config_request.h"

#include "call_manager_errors.h"
#include "cellular_call_service.h"
#include "ims_call_client.h"
#include "radio_event.h"

namespace OHOS {
namespace Telephony {
int32_t ConfigRequest::SetDomainPreferenceModeRequest(int32_t slotId, int32_t mode)
{
    if (moduleUtils_.NeedCallImsService()) {
        TELEPHONY_LOGI("SetDomainPreferenceModeRequest, call ims service");
        if (DelayedSingleton<ImsCallClient>::GetInstance() == nullptr) {
            TELEPHONY_LOGE("ImsCallClient is nullptr.");
            return CALL_ERR_RESOURCE_UNAVAILABLE;
        }
        return DelayedSingleton<ImsCallClient>::GetInstance()->SetDomainPreferenceMode(slotId, mode);
    }

    TELEPHONY_LOGD("SetDomainPreferenceModeRequest, ims vendor service does not exist.");
    auto handle = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handle == nullptr) {
        TELEPHONY_LOGE("SetDomainPreferenceModeRequest return, error type: handle is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    CoreManagerInner::GetInstance().SetCallPreferenceMode(
        slotId, RadioEvent::RADIO_SET_CALL_PREFERENCE_MODE, mode, handle);
    return TELEPHONY_SUCCESS;
}

int32_t ConfigRequest::GetDomainPreferenceModeRequest(int32_t slotId)
{
    if (moduleUtils_.NeedCallImsService()) {
        TELEPHONY_LOGI("GetDomainPreferenceModeRequest, call ims service");
        if (DelayedSingleton<ImsCallClient>::GetInstance() == nullptr) {
            TELEPHONY_LOGE("ImsCallClient is nullptr.");
            return CALL_ERR_RESOURCE_UNAVAILABLE;
        }
        return DelayedSingleton<ImsCallClient>::GetInstance()->GetDomainPreferenceMode(slotId);
    }

    TELEPHONY_LOGD("GetDomainPreferenceModeRequest, ims vendor service does not exist.");
    auto handle = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handle == nullptr) {
        TELEPHONY_LOGE("GetDomainPreferenceModeRequest return, error type: handle is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    CoreManagerInner::GetInstance().GetCallPreferenceMode(slotId, RadioEvent::RADIO_GET_CALL_PREFERENCE_MODE, handle);
    return TELEPHONY_SUCCESS;
}

int32_t ConfigRequest::SetImsSwitchStatusRequest(int32_t slotId, bool active)
{
    auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
    if (imsCallClient == nullptr || imsCallClient->GetImsCallProxy() == nullptr) {
        TELEPHONY_LOGE("ImsCallClient is nullptr or ims service SA not exists.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    return imsCallClient->SetImsSwitchStatus(slotId, active);
}

int32_t ConfigRequest::SetVoNRSwitchStatusRequest(int32_t slotId, int32_t state)
{
    auto handle = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handle == nullptr) {
        TELEPHONY_LOGE("SetVoNRSwitchStatusRequest return, error type: handle is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    TELEPHONY_LOGD("slotId: %{public}d, switchState: %{public}d", slotId, state);
    CoreManagerInner::GetInstance().SetVoNRSwitch(slotId, state, RadioEvent::RADIO_SET_VONR_SWITCH_STATUS, handle);
    return TELEPHONY_SUCCESS;
}

int32_t ConfigRequest::GetImsSwitchStatusRequest(int32_t slotId)
{
    auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
    if (imsCallClient == nullptr || imsCallClient->GetImsCallProxy() == nullptr) {
        TELEPHONY_LOGE("ImsCallClient is nullptr or ims service SA not exists.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    return imsCallClient->GetImsSwitchStatus(slotId);
}

int32_t ConfigRequest::SetImsConfigRequest(ImsConfigItem item, const std::string &value)
{
    auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
    if (imsCallClient == nullptr || imsCallClient->GetImsCallProxy() == nullptr) {
        TELEPHONY_LOGE("ImsCallClient is nullptr or ims service SA not exists.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    return imsCallClient->SetImsConfig(item, value);
}

int32_t ConfigRequest::SetImsConfigRequest(ImsConfigItem item, int32_t value)
{
    auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
    if (imsCallClient == nullptr || imsCallClient->GetImsCallProxy() == nullptr) {
        TELEPHONY_LOGE("ImsCallClient is nullptr or ims service SA not exists.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    return imsCallClient->SetImsConfig(item, value);
}

int32_t ConfigRequest::GetImsConfigRequest(ImsConfigItem item)
{
    auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
    if (imsCallClient == nullptr || imsCallClient->GetImsCallProxy() == nullptr) {
        TELEPHONY_LOGE("ImsCallClient is nullptr or ims service SA not exists.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    return imsCallClient->GetImsConfig(item);
}

int32_t ConfigRequest::SetImsFeatureValueRequest(FeatureType type, int32_t value)
{
    auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
    if (imsCallClient == nullptr || imsCallClient->GetImsCallProxy() == nullptr) {
        TELEPHONY_LOGE("ImsCallClient is nullptr or ims service SA not exists.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    return imsCallClient->SetImsFeatureValue(type, value);
}

int32_t ConfigRequest::GetImsFeatureValueRequest(FeatureType type, int32_t &value)
{
    auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
    if (imsCallClient == nullptr || imsCallClient->GetImsCallProxy() == nullptr) {
        TELEPHONY_LOGE("ImsCallClient is nullptr or ims service SA not exists.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    return imsCallClient->GetImsFeatureValue(type, value);
}

int32_t ConfigRequest::SetMuteRequest(int32_t slotId, int32_t mute)
{
    if (moduleUtils_.NeedCallImsService()) {
        TELEPHONY_LOGI("SetMuteRequest, call ims service");
        if (DelayedSingleton<ImsCallClient>::GetInstance() == nullptr) {
            TELEPHONY_LOGE("ImsCallClient is nullptr.");
            return CALL_ERR_RESOURCE_UNAVAILABLE;
        }
        return DelayedSingleton<ImsCallClient>::GetInstance()->SetMute(slotId, mute);
    }

    TELEPHONY_LOGD("SetMuteRequest, ims vendor service does not exist.");
    auto handle = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handle == nullptr) {
        TELEPHONY_LOGE("SetMuteRequest return, error type: handle is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    CoreManagerInner::GetInstance().SetMute(slotId, RadioEvent::RADIO_SET_CMUT, mute, handle);
    return TELEPHONY_SUCCESS;
}

int32_t ConfigRequest::GetMuteRequest(int32_t slotId)
{
    if (moduleUtils_.NeedCallImsService()) {
        TELEPHONY_LOGI("GetMuteRequest, call ims service");
        if (DelayedSingleton<ImsCallClient>::GetInstance() == nullptr) {
            TELEPHONY_LOGE("ImsCallClient is nullptr.");
            return CALL_ERR_RESOURCE_UNAVAILABLE;
        }
        return DelayedSingleton<ImsCallClient>::GetInstance()->GetMute(slotId);
    }

    TELEPHONY_LOGD("GetMuteRequest, ims vendor service does not exist.");
    auto handle = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handle == nullptr) {
        TELEPHONY_LOGE("GetMuteRequest return, error type: handle is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    CoreManagerInner::GetInstance().GetMute(slotId, RadioEvent::RADIO_GET_CMUT, handle);
    return TELEPHONY_SUCCESS;
}

int32_t ConfigRequest::GetEmergencyCallListRequest(int32_t slotId)
{
    auto handle = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handle == nullptr) {
        TELEPHONY_LOGE("GetEmergencyCallListRequest return, error type: handle is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    CoreManagerInner::GetInstance().GetEmergencyCallList(slotId, RadioEvent::RADIO_GET_EMERGENCY_CALL_LIST, handle);
    return TELEPHONY_SUCCESS;
}

int32_t ConfigRequest::SetEmergencyCallListRequest(int32_t slotId, std::vector<EmergencyCall> &eccVec)
{
    TELEPHONY_LOGD("SetEmergencyCallListRequest start ");
    auto handle = DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handle == nullptr) {
        TELEPHONY_LOGE("SetEmergencyCallListRequest return, error type: handle is nullptr.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    int32_t errorCode = TELEPHONY_ERR_FAIL;
    errorCode = CoreManagerInner::GetInstance().SetEmergencyCallList(
        slotId, RadioEvent::RADIO_SET_EMERGENCY_CALL_LIST, eccVec, handle);
    if (errorCode != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("SetEmergencyCallListRequest end fail, errorCode: %{public}d", errorCode);
    }
    return errorCode;
}

int32_t ConfigRequest::UpdateImsCapabilities(int32_t slotId, const ImsCapabilityList &imsCapabilityList)
{
    auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
    if (imsCallClient == nullptr || imsCallClient->GetImsCallProxy() == nullptr) {
        TELEPHONY_LOGE("ImsCallClient is nullptr or ims service SA not exists.");
        return CALL_ERR_RESOURCE_UNAVAILABLE;
    }
    for (auto it : imsCapabilityList.imsCapabilities) {
        TELEPHONY_LOGI("ImsCapabilityType:%{public}d imsRadioTech:%{public}d enable:%{public}d", it.imsCapabilityType,
            it.imsRadioTech, it.enable);
    }
    return imsCallClient->UpdateImsCapabilities(slotId, imsCapabilityList);
}
} // namespace Telephony
} // namespace OHOS

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

#include "module_service_utils.h"

#include "cellular_call_config.h"
#include "cellular_call_register.h"
#include "ims_call_client.h"
#include "ipc_skeleton.h"
#include "string_ex.h"
#include "telephony_log_wrapper.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
bool ModuleServiceUtils::GetRadioState(int32_t slotId)
{
    int32_t ret = CoreManagerInner::GetInstance().GetRadioState(slotId);
    if (ret != ModemPowerState::CORE_SERVICE_POWER_ON) {
        TELEPHONY_LOGE("ModuleServiceUtils::GetRadioState radio off.");
        return false;
    }
    return true;
}

int32_t ModuleServiceUtils::GetAirplaneMode(bool &airplaneMode)
{
    int32_t ret = CoreManagerInner::GetInstance().GetAirplaneMode(airplaneMode);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ModuleServiceUtils::GetAirplaneMode fail.");
        return ret;
    }
    return TELEPHONY_SUCCESS;
}

int32_t ModuleServiceUtils::UpdateRadioOn(int32_t slotId)
{
    CellularCallConfig config;
    config.SetReadyToCall(slotId, false);
    int32_t ret = CoreManagerInner::GetInstance().UpdateRadioOn(slotId);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ModuleServiceUtils::UpdateRadioOn fail.");
        return ret;
    }
    return TELEPHONY_SUCCESS;
}

PhoneType ModuleServiceUtils::GetNetworkStatus(int32_t slotId)
{
    return CoreManagerInner::GetInstance().GetPhoneType(slotId);
}

std::string ModuleServiceUtils::GetIsoCountryCode(int32_t slotId)
{
    std::u16string countryCode;
    CoreManagerInner::GetInstance().GetISOCountryCodeForSim(slotId, countryCode);
    return Str16ToStr8(countryCode);
}

std::string ModuleServiceUtils::GetNetworkCountryCode(int32_t slotId)
{
    std::u16string countryCode;
    CoreManagerInner::GetInstance().GetIsoCountryCodeForNetwork(slotId, countryCode);
    return Str16ToStr8(countryCode);
}

bool ModuleServiceUtils::GetSatelliteStatus()
{
    return CoreManagerInner::GetInstance().IsSatelliteEnabled();
}

bool ModuleServiceUtils::GetImsRegistrationState(int32_t slotId)
{
    ImsRegInfo info;
    CoreManagerInner::GetInstance().GetImsRegStatus(slotId, ImsServiceType::TYPE_VOICE, info);
    return info.imsRegState == ImsRegState::IMS_REGISTERED;
}

bool ModuleServiceUtils::GetImsUtSupportState(int32_t slotId)
{
    ImsRegInfo info;
    CoreManagerInner::GetInstance().GetImsRegStatus(slotId, ImsServiceType::TYPE_UT, info);
    return info.imsRegState == ImsRegState::IMS_REGISTERED;
}

std::vector<int32_t> ModuleServiceUtils::GetSlotInfo()
{
    const int32_t slotSingle = 1;
    const int32_t slotDouble = 2;
    std::vector<int32_t> slotVector;
    if (SIM_SLOT_COUNT == slotSingle) {
        slotVector.push_back(DEFAULT_SIM_SLOT_ID);
    } else if (SIM_SLOT_COUNT == slotDouble) {
        slotVector.push_back(SIM_SLOT_0);
        slotVector.push_back(SIM_SLOT_1);
    }
    return slotVector;
}

bool ModuleServiceUtils::NeedCallImsService() const
{
    if (DelayedSingleton<ImsCallClient>::GetInstance() == nullptr) {
        TELEPHONY_LOGE("ImsCallClient is nullptr.");
        return false;
    }
    auto remoteProxy = DelayedSingleton<ImsCallClient>::GetInstance()->GetImsCallProxy();
    if (remoteProxy == nullptr) {
        TELEPHONY_LOGE("NeedCallImsService return, ims service SA not exists.");
        return false;
    }
    return true;
}

sptr<ImsCallInterface> ModuleServiceUtils::GetImsServiceRemoteObject() const
{
    if (DelayedSingleton<ImsCallClient>::GetInstance() == nullptr) {
        TELEPHONY_LOGE("ImsCallClient is nullptr.");
        return nullptr;
    }
    return DelayedSingleton<ImsCallClient>::GetInstance()->GetImsCallProxy();
}

RegServiceState ModuleServiceUtils::GetCsRegState(int32_t slotId)
{
    return static_cast<RegServiceState>(CoreManagerInner::GetInstance().GetCsRegState(slotId));
}

RegServiceState ModuleServiceUtils::GetPsRegState(int32_t slotId)
{
    return static_cast<RegServiceState>(CoreManagerInner::GetInstance().GetPsRegState(slotId));
}
} // namespace Telephony
} // namespace OHOS
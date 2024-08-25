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

#ifndef CELLULAR_CALL_MODULE_SERVICE_UTILS_H
#define CELLULAR_CALL_MODULE_SERVICE_UTILS_H

#include "iservice_registry.h"
#include "singleton.h"

#include "ims_call_interface.h"
#include "network_state.h"

namespace OHOS {
namespace Telephony {
class ModuleServiceUtils : public std::enable_shared_from_this<ModuleServiceUtils> {
public:
    /**
     * Get Cs Radio state
     *
     * @param slotId
     * @return bool
     */
    bool GetRadioState(int32_t slotId);

    /**
     * Get Network State
     *
     * @param slotId
     * @return Network State
     */
    PhoneType GetNetworkStatus(int32_t slotId);

    /**
     * Get Iso Country Code
     *
     * @param slotId
     * @return Iso Country Code
     */
    std::string GetIsoCountryCode(int32_t slotId);

    /**
     * Get net work Country Code
     *
     * @param slotId
     * @return Network Country Code
     */
    std::string GetNetworkCountryCode(int32_t slotId);

    /**
     * Get IMS Domain Registration State
     *
     * @param slotId
     * @return Whether to register
     */
    bool GetImsRegistrationState(int32_t slotId);

    /**
     * Confirm IMS support UT or not
     *
     * @param slotId
     * @return bool
     */
    bool GetImsUtSupportState(int32_t slotId);

    /**
     * Get Satellite status
     *
     * @return Satellite status
     */
    bool GetSatelliteStatus();

    /**
     * Get slot info
     *
     * @return slot id
     */
    std::vector<int32_t> GetSlotInfo();

    /**
     * Need to call ImsService
     *
     * @return bool
     */
    bool NeedCallImsService() const;

    /**
     * Get ImsService Remote Object
     *
     * @return sptr<ImsInterface>
     */
    sptr<ImsCallInterface> GetImsServiceRemoteObject() const;

    int32_t GetAirplaneMode(bool &airplaneModeOn);

    int32_t UpdateRadioOn(int32_t slotId);

    RegServiceState GetCsRegState(int32_t slotId);

    RegServiceState GetPsRegState(int32_t slotId);
};
} // namespace Telephony
} // namespace OHOS
#endif // CELLULAR_CALL_MODULE_SERVICE_UTILS_H

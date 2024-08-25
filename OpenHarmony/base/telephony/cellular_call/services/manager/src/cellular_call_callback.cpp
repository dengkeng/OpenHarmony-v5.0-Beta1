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

#include "cellular_call_callback.h"

#include "cellular_call_proxy.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
CellularCallCallback::CellularCallCallback() = default;

CellularCallCallback::~CellularCallCallback() = default;

void CellularCallCallback::ClearCellularCallList(int32_t slotId)
{
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityMgr == nullptr) {
        TELEPHONY_LOGE("ClearCellularCallList return, Get ISystemAbilityManager failed.");
        return;
    }
    auto remote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    if (remote == nullptr) {
        TELEPHONY_LOGE("ClearCellularCallList return, CellularCallService Remote service not exists.");
        return;
    }
    TELEPHONY_LOGI("HangUpAllConnection for slotId[%{public}d]", slotId);
    iface_cast<CellularCallInterface>(remote)->HangUpAllConnection(slotId);
}

void CellularCallCallback::SetReadyToCall(int32_t slotId, int32_t callType, bool isReadyToCall)
{
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityMgr == nullptr) {
        TELEPHONY_LOGE("SetReadyToCall return, Get ISystemAbilityManager failed.");
        return;
    }
    auto remote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    if (remote == nullptr) {
        TELEPHONY_LOGE("SetReadyToCall return, CellularCallService Remote service not exists.");
        return;
    }
    iface_cast<CellularCallInterface>(remote)->SetReadyToCall(slotId, callType, isReadyToCall);
}
} // namespace Telephony
} // namespace OHOS

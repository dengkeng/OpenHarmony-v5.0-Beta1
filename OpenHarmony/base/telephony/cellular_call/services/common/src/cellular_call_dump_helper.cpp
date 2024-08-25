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

#include "cellular_call_dump_helper.h"

#include "cellular_call_service.h"
#include "core_service_client.h"
#include "module_service_utils.h"
#include "standardize_utils.h"

namespace OHOS {
namespace Telephony {
bool CellularCallDumpHelper::Dump(const std::vector<std::string> &args, std::string &result) const
{
    result.clear();
    ShowHelp(result);
    ShowCellularCallInfo(result);
    return true;
}

bool CellularCallDumpHelper::WhetherHasSimCard(const int32_t slotId) const
{
    bool hasSimCard = false;
    DelayedRefSingleton<CoreServiceClient>::GetInstance().HasSimCard(slotId, hasSimCard);
    return hasSimCard;
}

void CellularCallDumpHelper::ShowHelp(std::string &result) const
{
    result.append("Usage       : dump <command> [options]\n")
        .append("Description :\n")
        .append("    -cellular_call_info      : ")
        .append("dump all cellular_call information in the system\n");
}

void CellularCallDumpHelper::ShowCellularCallInfo(std::string &result) const
{
    result.append("\n*******************CellularCallInfo*********************\n");
    result.append("CellularCallBindTime      : ")
        .append(DelayedSingleton<CellularCallService>::GetInstance()->GetBindTime())
        .append("\n");
    result.append("CellularCallEndTime       : ")
        .append(DelayedSingleton<CellularCallService>::GetInstance()->GetEndTime())
        .append("\n");
    result.append("CellularCallSpendTime     : ")
        .append(DelayedSingleton<CellularCallService>::GetInstance()->GetSpendTime())
        .append("\n");
    result.append("ServiceRunningState       : ")
        .append(std::to_string(DelayedSingleton<CellularCallService>::GetInstance()->GetServiceRunningState()))
        .append("\n");
    result.append("SrvccState                : ")
        .append(std::to_string(DelayedSingleton<CellularCallService>::GetInstance()->GetSrvccState()))
        .append("\n");

    for (int32_t i = 0; i < SIM_SLOT_COUNT; i++) {
        if (WhetherHasSimCard(i)) {
            result.append("SlotId                    : ")
                .append(std::to_string(i))
                .append("\n");
            CellularCallConfig config;
            bool imsSwitchStatus = false;
            config.GetImsSwitchStatus(i, imsSwitchStatus);
            result.append("ImsServiceRunningState    : ")
                .append(std::to_string(imsSwitchStatus))
                .append("\n");
            result.append("DomainPreferenceMode      : ")
                .append(std::to_string(config.GetPreferenceMode(i)))
                .append("\n");
            result.append("VoiceActivationState      : ")
                .append(std::to_string(config.GetForceVolteSwitchOnConfig(i)))
                .append("\n");
        }
    }
}
} // namespace Telephony
} // namespace OHOS
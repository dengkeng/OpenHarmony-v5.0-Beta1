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

#include "emergency_utils.h"

#include "shortnumberinfo.h"

#include "cellular_call_config.h"
#include "mmi_code_utils.h"
#include "module_service_utils.h"

namespace OHOS {
namespace Telephony {
int32_t EmergencyUtils::IsEmergencyCall(int32_t slotId, const std::string &phoneNum, bool &enabled)
{
    if (phoneNum.empty()) {
        TELEPHONY_LOGI("IsEmergencyCall return, phoneNum is empty.");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }

    if (phoneNum.find('@') != std::string::npos || phoneNum.find("%40") != std::string::npos) {
        TELEPHONY_LOGI("IsEmergencyCall return, phoneNum is not emergency.");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }

    if (phoneNum.front() == '+') {
        TELEPHONY_LOGI("IsEmergencyCall return, phoneNum is not emergency.");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }

    return IsEmergencyCallProcessing(slotId, phoneNum, enabled);
}

int32_t EmergencyUtils::IsEmergencyCallProcessing(int32_t slotId, const std::string &formatString, bool &enabled)
{
    enabled = true;
    TELEPHONY_LOGD("IsEmergencyCallProcessing entry.");
    CellularCallConfig config;
    ModuleServiceUtils dependDataObtain;
    std::string countryIsoCode = dependDataObtain.GetNetworkCountryCode(slotId);
    std::vector<EmergencyCall> eccCallList = config.GetEccCallList(slotId);
    std::string mcc = config.GetMcc(slotId);
    if (eccCallList.empty()) {
        TELEPHONY_LOGI("eccCallList is nullptr.");
        std::vector<std::string> eccList = { "110", "120", "119", "122", "112", "000", "911", "08", "118", "999" };
        if (std::any_of(eccList.begin(), eccList.end(), [&formatString](std::string eccNum) {
            return eccNum == formatString;
        })) {
            return TELEPHONY_ERR_SUCCESS;
        }
    } else {
        for (auto it = eccCallList.begin(); it != eccCallList.end(); it++) {
            if (mcc == it->mcc && formatString == it->eccNum) {
                TELEPHONY_LOGI("IsEmergencyCallProcessing, Complies with sim data.");
                return TELEPHONY_ERR_SUCCESS;
            }
        }
    }
    if (!countryIsoCode.empty()) {
        TELEPHONY_LOGD("IsEmergencyCallProcessing countryIsoCode is not empty");
        i18n::phonenumbers::ShortNumberInfo shortNumberInfo;
        transform(countryIsoCode.begin(), countryIsoCode.end(), countryIsoCode.begin(), ::toupper);
        enabled = shortNumberInfo.IsEmergencyNumber(formatString, countryIsoCode);
        return TELEPHONY_ERR_SUCCESS;
    }
    TELEPHONY_LOGI("IsEmergencyCallProcessing, not an emergency number.");
    enabled = false;
    return TELEPHONY_ERR_SUCCESS;
}
} // namespace Telephony
} // namespace OHOS

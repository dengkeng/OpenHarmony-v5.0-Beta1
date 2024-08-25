/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "hisysevent_adapter.h"

#include "hisysevent.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
using namespace OHOS::HiviewDFX;
void ReportEdmEvent(ReportType reportType, const std::string &apiName, const std::string &msgInfo)
{
    int ret;
    if (reportType == ReportType::EDM_FUNC_FAILED) {
        ret = HiSysEventWrite(HiSysEvent::Domain::CUSTOMIZATION_EDM, "EDM_FUNC_FAILED", HiSysEvent::EventType::FAULT,
            "APINAME", apiName, "MSG", msgInfo);
    } else {
        ret = HiSysEventWrite(HiSysEvent::Domain::CUSTOMIZATION_EDM, "EDM_FUNC_EVENT", HiSysEvent::EventType::STATISTIC,
            "APINAME", apiName);
    }

    if (ret != 0) {
        EDMLOGE("hisysevent write failed! ret %{public}d, apiName %{public}s, errMsg %{public}s", ret,
            apiName.c_str(), msgInfo.c_str());
    }
}
} // namespace EDM
} // namespace OHOS

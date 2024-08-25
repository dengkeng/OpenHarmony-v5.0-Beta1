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

#ifndef TELEPHONY_CELLULAR_CALL_MMI_CODE_UTILS_H
#define TELEPHONY_CELLULAR_CALL_MMI_CODE_UTILS_H

#include <string>
#include "cellular_call_data_struct.h"

namespace OHOS {
namespace Telephony {
// Man-Machine Interface
class MMICodeUtils {
public:
    /**
     * MMICodeUtils constructor
     */
    MMICodeUtils() = default;

    /**
     * ~MMICodeUtils destructor
     */
    ~MMICodeUtils() = default;

    /**
     * IsNeedExecuteMmi
     *
     * 3GPP TS 22.030 V4.0.0 (2001-03)  6.5.2 Structure of the MMI
     * TS 24.080 [10]
     *
     * @param analyseString
     * @param isNeedUseIms
     * @return bool
     */
    bool IsNeedExecuteMmi(const std::string &analyseString, bool isNeedUseIms);

    /**
     * ExecuteMmiCode
     *
     * 3GPP TS 22.030 V16.0.0 (2020-07) 6.5.3 Handling of supplementary services    Figure 3.5.3.2
     *
     * @param slotId
     * @return bool
     */
    bool ExecuteMmiCode(int32_t slotId);

    /**
     * GetMMIData
     *
     * @return MMIData
     */
    MMIData GetMMIData();

private:
    /**
     * RegexMatchMmi
     *
     * 3GPP TS 22.030 V4.0.0 (2001-03)  6.5.2 Structure of the MMI
     * TS 24.080 [10]
     *
     * Regex Match Mmi Code
     *
     * @param analyseString
     * @return bool
     */
    bool RegexMatchMmi(const std::string &analyseString);

private:
    MMIData mmiData_;
    bool isNeedUseIms_ = false;
};
} // namespace Telephony
} // namespace OHOS

#endif // TELEPHONY_CELLULAR_CALL_MMI_CODE_UTILS_H

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
#include <cstdint>

#include "bundle_active_account_helper.h"

namespace OHOS {
namespace DeviceUsageStats {
ErrCode BundleActiveAccountHelper::GetUserId(const int32_t uid, int32_t& userId)
{
    userId = -1;
    return ERR_OK;
}

void BundleActiveAccountHelper::GetActiveUserId(std::vector<int32_t> &activatedOsAccountIds)
{
    return;
}
}  // namespace DeviceUsageStats
}  // namespace OHOS
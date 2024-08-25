/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef COMMON_EXTERNAL_INCLUDE_EDM_OS_ACCOUNT_MANAGER_IMPL_MOCK_H
#define COMMON_EXTERNAL_INCLUDE_EDM_OS_ACCOUNT_MANAGER_IMPL_MOCK_H

#include <gmock/gmock.h>

#include "iedm_os_account_manager.h"

namespace OHOS {
namespace EDM {
class EdmOsAccountManagerImplMock : public IEdmOsAccountManager {
public:
    ~EdmOsAccountManagerImplMock() override = default;
    MOCK_METHOD(ErrCode, QueryActiveOsAccountIds, (std::vector<int32_t> &ids), (override));
    MOCK_METHOD(ErrCode, IsOsAccountExists, (int32_t id, bool &isExist), (override));
};
} // namespace EDM
} // namespace OHOS

#endif // COMMON_EXTERNAL_INCLUDE_EDM_OS_ACCOUNT_MANAGER_IMPL_MOCK_H
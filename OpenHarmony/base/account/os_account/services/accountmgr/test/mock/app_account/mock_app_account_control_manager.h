/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_MOCK_APP_ACCOUNT_MOCK_APP_ACCOUNT_CONTROL_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_MOCK_APP_ACCOUNT_MOCK_APP_ACCOUNT_CONTROL_MANAGER_H

#include "app_account_control_manager.h"
#include "mock_app_account_control_manager.h"

namespace OHOS {
namespace AccountSA {
class MockAppAccountControlManager : public AppAccountControlManager {
public:
    MockAppAccountControlManager();
    virtual ~MockAppAccountControlManager();

    ErrCode AddAccount(const std::string &name, const std::string &extraInfo, const std::string &bundleName,
        AppAccountInfo &appAccountInfo);
    ErrCode DeleteAccount(const std::string &name, const std::string &bundleName, AppAccountInfo &appAccountInfo);
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_MOCK_APP_ACCOUNT_MOCK_APP_ACCOUNT_CONTROL_MANAGER_H

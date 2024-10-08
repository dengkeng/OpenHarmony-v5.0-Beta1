/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "mock_domain_auth_callback.h"

#include "account_log_wrapper.h"
#include "os_account_manager.h"

namespace OHOS {
namespace AccountSA {
namespace {
const int32_t START_USER_ID = 100;
}

TestDomainAuthCallback::TestDomainAuthCallback(const std::shared_ptr<MockDomainAuthCallback> &callback)
    : callback_(callback)
{}

TestDomainAuthCallback::~TestDomainAuthCallback()
{}

void TestDomainAuthCallback::OnResult(const int32_t errCode, Parcel &parcel)
{
    ACCOUNT_LOGI("TestDomainAuthCallback");
    if (callback_ == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }
    int32_t localId = accountInfo_.GetLocalId();
    if (localId > START_USER_ID) {
        ErrCode errCode = OsAccountManager::RemoveOsAccount(localId);
        if (errCode != ERR_OK) {
            DomainAuthResult emptyResult = {};
            callback_->OnResult(errCode, emptyResult);
            std::unique_lock<std::mutex> lock(mutex);
            isReady = true;
            cv.notify_one();
            return;
        }
        ACCOUNT_LOGI("removeOsAccount successfully, localId: %{public}d", localId);
    }
    std::shared_ptr<DomainAuthResult> authResult(DomainAuthResult::Unmarshalling(parcel));
    callback_->OnResult(errCode, (*authResult));
    std::unique_lock<std::mutex> lock(mutex);
    isReady = true;
    cv.notify_one();
    return;
}

void TestDomainAuthCallback::SetOsAccountInfo(const OsAccountInfo &accountInfo)
{
    accountInfo_ = accountInfo;
}
}  // AccountSA
}  // OHOS
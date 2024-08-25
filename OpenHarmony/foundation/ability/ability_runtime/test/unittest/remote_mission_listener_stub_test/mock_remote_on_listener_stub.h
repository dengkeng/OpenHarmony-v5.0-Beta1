/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef UNITTEST_OHOS_ABILITY_RUNTIME_MOCK_REMOTE_ON_LISTENER_STUB_H
#define UNITTEST_OHOS_ABILITY_RUNTIME_MOCK_REMOTE_ON_LISTENER_STUB_H

#include <gmock/gmock.h>

#define private public
#include "remote_on_listener_stub.h"
#undef private

namespace OHOS {
namespace AAFwk {
class MockRemoteOnListenerStub : public RemoteOnListenerStub {
public:
    MockRemoteOnListenerStub() = default;
    virtual ~MockRemoteOnListenerStub() = default;

    MOCK_METHOD5(OnCallback, void(const uint32_t ContinueState, const std::string &srcDeviceId,
        const std::string &bundleName, const std::string &continueType, const std::string &srcBundleName));
};
}  // namespace AAFwk
}  // namespace OHOS

#endif  // UNITTEST_OHOS_ABILITY_RUNTIME_MOCK_REMOTE_ON_LISTENER_STUB_H

/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_DM_IMPL_TEST_H
#define OHOS_DM_IMPL_TEST_H

#include <gtest/gtest.h>
#include <refbase.h>

#include "device_manager.h"
#include "device_manager_callback.h"
#include "device_manager_impl.h"
#include "mock/mock_ipc_client_proxy.h"

namespace OHOS {
namespace DistributedHardware {
class DeviceManagerImplTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    std::shared_ptr<DiscoveryCallback> test_callback_ = nullptr;
    std::shared_ptr<PublishCallback> testPublishCallback_ = nullptr;
};

class DeviceDiscoveryCallback : public DiscoveryCallback {
public:
    DeviceDiscoveryCallback() : DiscoveryCallback()
    {
    }
    virtual  ~DeviceDiscoveryCallback()
    {
    }
    void OnDiscoverySuccess(uint16_t subscribeId) override;
    void OnDiscoveryFailed(uint16_t subscribeId, int32_t failedReason) override;
    void OnDeviceFound(uint16_t subscribeId, const DmDeviceInfo &deviceInfo) override;
};

class DevicePublishCallback : public PublishCallback {
public:
    DevicePublishCallback() : PublishCallback()
    {
    }
    virtual ~DevicePublishCallback()
    {
    }
    void OnPublishResult(int32_t publishId, int32_t failedReason) override;
};
} // namespace DistributedHardware
} // namespace OHOS

#endif // OHOS_DM_IMPL_TEST_H

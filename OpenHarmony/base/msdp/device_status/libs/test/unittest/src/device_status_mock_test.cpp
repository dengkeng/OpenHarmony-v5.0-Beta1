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

#include <cstdio>
#include <dlfcn.h>
#include <gtest/gtest.h>

#include "accesstoken_kit.h"
#include "devicestatus_data_define.h"
#include "devicestatus_define.h"
#define private public
#include "devicestatus_data_parse.h"
#include "devicestatus_msdp_mock.h"
#undef private
#include "devicestatus_msdp_interface.h"
#include "devicestatus_msdp_mock.h"
#include "devicestatus_msdp_client_impl.h"
#include "sensor_data_callback.h"

#undef LOG_TAG
#define LOG_TAG "DeviceStatusMsdpMocKTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
std::shared_ptr<DeviceStatusMsdpMock> g_testMock;
#ifdef __aarch64__
const std::string DEVICESTATUS_MOCK_LIB_PATH { "/system/lib64/libdevicestatus_mock.z.so" };
#else
const std::string DEVICESTATUS_MOCK_LIB_PATH { "/system/lib/libdevicestatus_mock.z.so" };
#endif
} // namespace

class DeviceStatusMsdpMocKTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    int32_t LoadMockLibrary(const std::shared_ptr<MsdpAlgoHandle> &mockHandler);
    int32_t UnloadMockLibrary(const std::shared_ptr<MsdpAlgoHandle> &mockHandler);
};

void DeviceStatusMsdpMocKTest::SetUpTestCase()
{
    g_testMock = std::make_shared<DeviceStatusMsdpMock>();
}

void DeviceStatusMsdpMocKTest::TearDownTestCase()
{
    g_testMock = nullptr;
}

void DeviceStatusMsdpMocKTest::SetUp() {}

void DeviceStatusMsdpMocKTest::TearDown() {}

int32_t DeviceStatusMsdpMocKTest::LoadMockLibrary(const std::shared_ptr<MsdpAlgoHandle> &mockHandler)
{
    FI_HILOGI("Enter");
    if (mockHandler == nullptr) {
        FI_HILOGE("mockHandler is nullptr");
        return RET_ERR;
    }
    if (mockHandler->handle != nullptr) {
        FI_HILOGE("handle has exists");
        return RET_OK;
    }

    std::string dlName = DEVICESTATUS_MOCK_LIB_PATH;
    char libRealPath[PATH_MAX] = { 0 };
    if (realpath(dlName.c_str(), libRealPath) == nullptr) {
        FI_HILOGE("Get absolute algoPath is error, errno:%{public}d", errno);
        return RET_ERR;
    }

    mockHandler->handle = dlopen(libRealPath, RTLD_LAZY);
    if (mockHandler->handle == nullptr) {
        FI_HILOGE("Cannot load library error:%{public}s", dlerror());
        return RET_ERR;
    }

    mockHandler->create = reinterpret_cast<IMsdp* (*)()>(dlsym(mockHandler->handle, "Create"));
    mockHandler->destroy = reinterpret_cast<void *(*)(IMsdp*)>(dlsym(mockHandler->handle, "Destroy"));
    if (mockHandler->create == nullptr || mockHandler->destroy == nullptr) {
        FI_HILOGE("%{public}s dlsym create or destroy failed", dlName.c_str());
        dlclose(mockHandler->handle);
        mockHandler->Clear();
        return RET_ERR;
    }
    return RET_OK;
}

int32_t DeviceStatusMsdpMocKTest::UnloadMockLibrary(const std::shared_ptr<MsdpAlgoHandle> &mockHandler)
{
    FI_HILOGI("Enter");
    if (mockHandler == nullptr) {
        FI_HILOGE("mockHandler is nullptr");
        return RET_ERR;
    }
    if (mockHandler->handle == nullptr) {
        FI_HILOGE("handle is nullptr");
        return RET_ERR;
    }

    if (mockHandler->pAlgorithm != nullptr) {
        mockHandler->destroy(mockHandler->pAlgorithm);
        mockHandler->pAlgorithm = nullptr;
    }
    dlclose(mockHandler->handle);
    mockHandler->Clear();
    return RET_OK;
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest001
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(g_testMock->Init());
    auto callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(g_testMock->RegisterCallback(callback) == ERR_OK);
    EXPECT_TRUE(g_testMock->UnregisterCallback() == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest002
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(g_testMock->Init());
    auto callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(g_testMock->RegisterCallback(callback) == ERR_OK);
    EXPECT_TRUE(g_testMock->Enable(Type::TYPE_INVALID) == ERR_OK);
    EXPECT_TRUE(g_testMock->Disable(Type::TYPE_INVALID) == ERR_OK);
    EXPECT_TRUE(g_testMock->UnregisterCallback() == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest003
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(g_testMock->Init());
    auto callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(g_testMock->RegisterCallback(callback) == ERR_OK);
    EXPECT_TRUE(g_testMock->Enable(Type::TYPE_ABSOLUTE_STILL) == ERR_OK);
    EXPECT_TRUE(g_testMock->Disable(Type::TYPE_ABSOLUTE_STILL) == ERR_OK);
    EXPECT_TRUE(g_testMock->UnregisterCallback() == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest004
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(g_testMock->Init());
    auto callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(g_testMock->RegisterCallback(callback) == ERR_OK);
    EXPECT_TRUE(g_testMock->Enable(Type::TYPE_HORIZONTAL_POSITION) == ERR_OK);
    EXPECT_TRUE(g_testMock->Disable(Type::TYPE_HORIZONTAL_POSITION) == ERR_OK);
    EXPECT_TRUE(g_testMock->UnregisterCallback() == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest005
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(g_testMock->Init());
    auto callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(g_testMock->RegisterCallback(callback) == ERR_OK);
    EXPECT_TRUE(g_testMock->Enable(Type::TYPE_VERTICAL_POSITION) == ERR_OK);
    EXPECT_TRUE(g_testMock->Disable(Type::TYPE_VERTICAL_POSITION) == ERR_OK);
    EXPECT_TRUE(g_testMock->UnregisterCallback() == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest006
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(g_testMock->Init());
    auto callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(g_testMock->RegisterCallback(callback) == ERR_OK);
    EXPECT_TRUE(g_testMock->Enable(Type::TYPE_LID_OPEN) == ERR_OK);
    EXPECT_TRUE(g_testMock->Disable(Type::TYPE_LID_OPEN) == ERR_OK);
    EXPECT_TRUE(g_testMock->UnregisterCallback() == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest007
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(g_testMock->Init());
    auto callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(g_testMock->RegisterCallback(callback) == ERR_OK);
    EXPECT_TRUE(g_testMock->Enable(Type::TYPE_MAX) == ERR_OK);
    EXPECT_TRUE(g_testMock->Disable(Type::TYPE_MAX) == ERR_OK);
    EXPECT_TRUE(g_testMock->UnregisterCallback() == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest008
 * @tc.desc: test devicestatus DisableCount
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(g_testMock->Init());
    auto callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(g_testMock->RegisterCallback(callback) == ERR_OK);
    EXPECT_TRUE(g_testMock->Enable(Type::TYPE_HORIZONTAL_POSITION) == ERR_OK);
    EXPECT_TRUE(g_testMock->Disable(Type::TYPE_HORIZONTAL_POSITION) == ERR_OK);
    EXPECT_TRUE(g_testMock->UnregisterCallback() == ERR_OK);
    EXPECT_TRUE(g_testMock->DisableCount(Type::TYPE_HORIZONTAL_POSITION) == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest009
 * @tc.desc: test devicestatus NotifyMsdpImpl
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_FALSE(g_testMock->NotifyMsdpImpl({}) == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest010
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_testMock->InitTimer();
    g_testMock->StartThread();
    std::make_unique<std::thread>(&DeviceStatusMsdpMock::LoopingThreadEntry, g_testMock)->detach();
    constexpr int32_t TIMER_INTERVAL = 3;
    int32_t ret = g_testMock->SetTimerInterval(TIMER_INTERVAL);
    g_testMock->CloseTimer();
    EXPECT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest011
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_testMock->InitTimer();
    g_testMock->StartThread();
    std::make_unique<std::thread>(&DeviceStatusMsdpMock::LoopingThreadEntry, g_testMock)->detach();
    constexpr int32_t TIMER_INTERVAL = -1;
    int32_t ret = g_testMock->SetTimerInterval(TIMER_INTERVAL);
    g_testMock->CloseTimer();
    EXPECT_TRUE(ret == RET_ERR);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest012
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest012, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_testMock->InitTimer();
    g_testMock->StartThread();
    std::make_unique<std::thread>(&DeviceStatusMsdpMock::LoopingThreadEntry, g_testMock)->detach();
    constexpr int32_t TIMER_INTERVAL = 0;
    int32_t ret = g_testMock->SetTimerInterval(TIMER_INTERVAL);
    g_testMock->CloseTimer();
    EXPECT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest013
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest013, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_testMock->InitTimer();
    g_testMock->StartThread();
    std::make_unique<std::thread>(&DeviceStatusMsdpMock::LoopingThreadEntry, g_testMock)->detach();
    constexpr int32_t TIMER_INTERVAL = 0;
    int32_t ret = g_testMock->SetTimerInterval(TIMER_INTERVAL);
    EXPECT_TRUE(ret == ERR_OK);
    g_testMock->TimerCallback();
    ret = g_testMock->GetDeviceStatusData();
    g_testMock->CloseTimer();
    EXPECT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest014
 * @tc.desc: test devicestatus NotifyMsdpImpl
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest014, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_testMock->GetCallbackImpl() = nullptr;
    EXPECT_FALSE(g_testMock->NotifyMsdpImpl({}) == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest015
 * @tc.desc: test devicestatus NotifyMsdpImpl
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest015, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(g_testMock->RegisterCallback(callback) == ERR_OK);
    EXPECT_FALSE(g_testMock->NotifyMsdpImpl({TYPE_INVALID, VALUE_INVALID}) == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest016
 * @tc.desc: test devicestatus NotifyMsdpImpl
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest016, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_testMock->dataParse_ = nullptr;
    int32_t ret = g_testMock->GetDeviceStatusData();
    EXPECT_TRUE(ret == RET_ERR);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest017
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest017, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    constexpr int32_t TIMER_INTERVAL = 0;
    int32_t ret = g_testMock->SetTimerInterval(TIMER_INTERVAL);
    EXPECT_TRUE(ret == RET_ERR);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest018
 * @tc.desc: test devicestatus RegisterCallback
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest018, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MsdpAlgoHandle> mock = std::make_shared<MsdpAlgoHandle>();
    int32_t ret = LoadMockLibrary(mock);
    ASSERT_EQ(ret, RET_OK);
    ASSERT_NE(mock->handle, nullptr);
    mock->pAlgorithm = mock->create();

    std::shared_ptr<DeviceStatusMsdpClientImpl> callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(mock->pAlgorithm->RegisterCallback(callback) == ERR_OK);
    EXPECT_TRUE(mock->pAlgorithm->UnregisterCallback() == ERR_OK);

    ret = UnloadMockLibrary(mock);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest019
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest019, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_testMock->TimerCallback();
    constexpr int32_t TIMER_INTERVAL = 0;
    FI_HILOGI("Test the abnormal branch.");
    int32_t ret = g_testMock->SetTimerInterval(TIMER_INTERVAL);
    g_testMock->CloseTimer();
    EXPECT_TRUE(ret == RET_ERR);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS

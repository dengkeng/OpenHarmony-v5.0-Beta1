/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "manage_inject_device.h"
#include "msg_head.h"
#include "processing_touch_screen_device.h"
#include "proto.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class ProcessingTouchScreenDeviceTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name:Test_TransformJsonDataToInputData
 * @tc.desc:Verify ManageInjectDevice function TransformJsonData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingTouchScreenDeviceTest, Test_TransformJsonDataToInputData, TestSize.Level1)
{
    const std::string path = "/data/json/Test_TransformTouchScreenJsonDataToInputData.json";
    std::string launchDeviceCmd = "vuinput launch touchscreen & ";
    std::string closeDeviceCmd = "vuinput close all";
    FILE* startDevice = popen(launchDeviceCmd.c_str(), "rw");
    if (!startDevice) {
        ASSERT_TRUE(false) << "Start device failed";
    }
    pclose(startDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::string jsonBuffer = ReadJsonFile(path);
    if (jsonBuffer.empty()) {
        ASSERT_TRUE(false) << "Read file failed" << path;
    }
    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(DataInit(jsonBuffer, false));
    FILE* closeDeviceCom = popen(closeDeviceCmd.c_str(), "rw");
    if (!closeDeviceCom) {
        ASSERT_TRUE(false) << "Close device failed";
    }
    pclose(closeDeviceCom);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name:Test_TransformJsonDataToInputDataEventsIsEmpty
 * @tc.desc:Verify ManageInjectDevice function TransformJsonData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingTouchScreenDeviceTest, Test_TransformJsonDataToInputDataEventsIsEmpty, TestSize.Level1)
{
    const std::string path = "/data/json/Test_TransformJsonDataToInputDataEventsIsEmpty.json";
    std::string launchDeviceCmd = "vuinput start touchscreen & ";
    std::string closeDeviceCmd = "vuinput close all";
    FILE* launchDevice = popen(launchDeviceCmd.c_str(), "rw");
    if (!launchDevice) {
        ASSERT_TRUE(false) << "Start device failed";
    }
    pclose(launchDevice);
    std::string jsonBuff = ReadJsonFile(path);
    if (jsonBuff.empty()) {
        ASSERT_TRUE(false) << "Read file failed" << path;
    }
    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(DataInit(jsonBuff, false));

    FILE* offDevice = popen(closeDeviceCmd.c_str(), "rw");
    if (!offDevice) {
        ASSERT_TRUE(false) << "Close device failed";
    }
    pclose(offDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name:Test_TransformJsonDataToInputDataSingleEventsIsEmpty
 * @tc.desc:Verify ManageInjectDevice function TransformJsonData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingTouchScreenDeviceTest, Test_TransformJsonDataToInputDataSingleEventsIsEmpty, TestSize.Level1)
{
    const std::string path = "/data/json/Test_TransformJsonDataToInputDataSingleEventsIsEmpty.json";
    std::string beginDeviceCmd = "vuinput start touchscreen & ";
    std::string closeDeviceCmd = "vuinput close all";
    FILE* beginDevice = popen(beginDeviceCmd.c_str(), "rw");
    if (!beginDevice) {
        ASSERT_TRUE(false) << "Start device failed";
    }
    pclose(beginDevice);
    std::string jsonSize = ReadJsonFile(path);
    if (jsonSize.empty()) {
        ASSERT_TRUE(false) << "Read file failed" << path;
    }
    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(DataInit(jsonSize, false));
    FILE* closeDeviceCommand = popen(closeDeviceCmd.c_str(), "rw");
    if (!closeDeviceCommand) {
        ASSERT_TRUE(false) << "Close device failed";
    }
    pclose(closeDeviceCommand);
    std::this_thread::sleep_for(std::chrono::seconds(2));
    EXPECT_EQ(ret, RET_ERR);
}
} // namespace MMI
} // namespace OHOS
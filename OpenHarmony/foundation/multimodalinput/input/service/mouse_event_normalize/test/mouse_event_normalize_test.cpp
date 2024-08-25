/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <cstdio>
#include <gtest/gtest.h>

#include "libinput.h"
#include "mouse_event_normalize.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
}
class MouseEventNormalizeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

private:
    int32_t prePointerSpeed_ { 5 };
    int32_t prePrimaryButton_ { 0 };
    int32_t preScrollRows_ { 3 };
    int32_t preTouchpadPointerSpeed_ { 9 };
    int32_t preRightClickType_ { 1 };
    bool preScrollSwitch_ { true };
    bool preScrollDirection_ { true };
    bool preTapSwitch_ { true };
};

void MouseEventNormalizeTest::SetUpTestCase(void)
{
}

void MouseEventNormalizeTest::TearDownTestCase(void)
{
}

void MouseEventNormalizeTest::SetUp()
{
    prePointerSpeed_ = MouseEventHdr->GetPointerSpeed();
    prePrimaryButton_ = MouseEventHdr->GetMousePrimaryButton();
    preScrollRows_ = MouseEventHdr->GetMouseScrollRows();
    MouseEventHdr->GetTouchpadPointerSpeed(preTouchpadPointerSpeed_);
    MouseEventHdr->GetTouchpadRightClickType(preRightClickType_);
    MouseEventHdr->GetTouchpadScrollSwitch(preScrollSwitch_);
    MouseEventHdr->GetTouchpadScrollDirection(preScrollDirection_);
    MouseEventHdr->GetTouchpadTapSwitch(preTapSwitch_);
}

void MouseEventNormalizeTest::TearDown()
{
    MouseEventHdr->SetPointerSpeed(prePointerSpeed_);
    MouseEventHdr->SetMousePrimaryButton(prePrimaryButton_);
    MouseEventHdr->SetMouseScrollRows(preScrollRows_);
    MouseEventHdr->SetTouchpadPointerSpeed(preTouchpadPointerSpeed_);
    MouseEventHdr->SetTouchpadRightClickType(preRightClickType_);
    MouseEventHdr->SetTouchpadScrollSwitch(preScrollSwitch_);
    MouseEventHdr->SetTouchpadScrollDirection(preScrollDirection_);
    MouseEventHdr->SetTouchpadTapSwitch(preTapSwitch_);
}

/**
 * @tc.name: MouseEventNormalizeTest_GetDisplayId()_001
 * @tc.desc: Test GetDisplayId()
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_GetDisplayId_001, TestSize.Level1)
{
    int32_t idNames = -1;
    ASSERT_EQ(MouseEventHdr->GetDisplayId(), idNames);
}

/**
 * @tc.name: MouseEventNormalizeTest_GetPointerEvent_002
 * @tc.desc: Test GetPointerEvent()
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_GetPointerEvent_002, TestSize.Level1)
{
    ASSERT_EQ(MouseEventHdr->GetPointerEvent(), nullptr);
}

/**
 * @tc.name: MouseEventNormalizeTest_OnEvent_003
 * @tc.desc: Test OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_OnEvent_003, TestSize.Level1)
{
    libinput_event *event = nullptr;
    int idNames = -1;
    ASSERT_EQ(MouseEventHdr->OnEvent(event), idNames);
}

/**
 * @tc.name: MouseEventNormalizeTest_NormalizeMoveMouse_004
 * @tc.desc: Test NormalizeMoveMouse
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_NormalizeMoveMouse_004, TestSize.Level1)
{
    bool isNormalize = false;
    int32_t offsetX = 0;
    int32_t offsetY = 0;
    ASSERT_EQ(MouseEventHdr->NormalizeMoveMouse(offsetX, offsetY), isNormalize);
}

/**
 * @tc.name: MouseEventNormalizeTest_Dump_005
 * @tc.desc: Test Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_Dump_005, TestSize.Level1)
{
    std::vector<std::string> args;
    std::vector<std::string> idNames;
    int32_t fd = 0;
    MouseEventHdr->Dump(fd, args);
    ASSERT_EQ(args, idNames);
}

/**
 * @tc.name: MouseEventNormalizeTest_SetPointerSpeed_006
 * @tc.desc: Test SetPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_SetPointerSpeed_006, TestSize.Level1)
{
    int32_t idNames = 0;
    int32_t speed = 2;
    ASSERT_EQ(MouseEventHdr->SetPointerSpeed(speed), idNames);
}

/**
 * @tc.name: MouseEventNormalizeTest_GetPointerSpeed_007
 * @tc.desc: Test GetPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_GetPointerSpeed_007, TestSize.Level1)
{
    int32_t speed = 2;
    MouseEventHdr->SetPointerSpeed(speed);
    int32_t idNames = 2;
    ASSERT_EQ(MouseEventHdr->GetPointerSpeed(), idNames);
}

/**
 * @tc.name: MouseEventNormalizeTest_SetPointerLocation_008
 * @tc.desc: Test SetPointerLocation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_SetPointerLocation_008, TestSize.Level1)
{
    int32_t idNames = -1;
    int32_t x = 0;
    int32_t y = 0;
    ASSERT_EQ(MouseEventHdr->SetPointerLocation(x, y), idNames);
}

/**
 * @tc.name: MouseEventNormalizeTest_SetMousePrimaryButton_009
 * @tc.desc: Test SetMousePrimaryButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_SetMousePrimaryButton_009, TestSize.Level1)
{
    int32_t primaryButton = 1;
    ASSERT_TRUE(MouseEventHdr->SetMousePrimaryButton(primaryButton) == RET_OK);
}

/**
 * @tc.name: MouseEventNormalizeTest_GetMousePrimaryButton_010
 * @tc.desc: Test GetMousePrimaryButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_GetMousePrimaryButton_010, TestSize.Level1)
{
    int32_t primaryButton = 1;
    MouseEventHdr->SetMousePrimaryButton(primaryButton);
    int32_t primaryButtonRes = 1;
    ASSERT_TRUE(MouseEventHdr->GetMousePrimaryButton() == primaryButtonRes);
}

/**
 * @tc.name: MouseEventNormalizeTest_SetMouseScrollRows_011
 * @tc.desc: Test SetMouseScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_SetMouseScrollRows_011, TestSize.Level1)
{
    int32_t rows = 1;
    ASSERT_TRUE(MouseEventHdr->SetMouseScrollRows(rows) == RET_OK);
}

/**
 * @tc.name: MouseEventNormalizeTest_GetMouseScrollRows_012
 * @tc.desc: Test GetMouseScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_GetMouseScrollRows_012, TestSize.Level1)
{
    int32_t rows = 50;
    MouseEventHdr->SetMouseScrollRows(rows);
    int32_t newRows = 50;
    ASSERT_TRUE(MouseEventHdr->GetMouseScrollRows() == newRows);
}

/**
 * @tc.name: MouseEventNormalizeTest_SetTouchpadScrollSwitch_013
 * @tc.desc: Test SetTouchpadScrollSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_SetTouchpadScrollSwitch_013, TestSize.Level1)
{
    bool flag = false;
    ASSERT_TRUE(MouseEventHdr->SetTouchpadScrollSwitch(flag) == RET_OK);
}

/**
 * @tc.name: MouseEventNormalizeTest_GetTouchpadScrollSwitch_014
 * @tc.desc: Test GetTouchpadScrollSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_GetTouchpadScrollSwitch_014, TestSize.Level1)
{
    bool flag = true;
    MouseEventHdr->SetTouchpadScrollSwitch(flag);
    bool newFlag = true;
    ASSERT_TRUE(MouseEventHdr->GetTouchpadScrollSwitch(flag) == RET_OK);
    ASSERT_TRUE(flag == newFlag);
}

/**
 * @tc.name: MouseEventNormalizeTest_SetTouchpadScrollDirection_015
 * @tc.desc: Test SetTouchpadScrollDirection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_SetTouchpadScrollDirection_015, TestSize.Level1)
{
    bool state = false;
    ASSERT_TRUE(MouseEventHdr->SetTouchpadScrollDirection(state) == RET_OK);
}

/**
 * @tc.name: MouseEventNormalizeTest_GetTouchpadScrollDirection_016
 * @tc.desc: Test GetTouchpadScrollDirection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_GetTouchpadScrollDirection_016, TestSize.Level1)
{
    bool state = true;
    MouseEventHdr->SetTouchpadScrollDirection(state);
    bool newState = true;
    ASSERT_TRUE(MouseEventHdr->GetTouchpadScrollDirection(state) == RET_OK);
    ASSERT_TRUE(state == newState);
}

/**
 * @tc.name: MouseEventNormalizeTest_SetTouchpadTapSwitch_017
 * @tc.desc: Test SetTouchpadTapSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_SetTouchpadTapSwitch_017, TestSize.Level1)
{
    bool flag = false;
    ASSERT_TRUE(MouseEventHdr->SetTouchpadTapSwitch(flag) == RET_OK);
}

/**
 * @tc.name: MouseEventNormalizeTest_GetTouchpadTapSwitch_018
 * @tc.desc: Test GetTouchpadTapSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_GetTouchpadTapSwitch_018, TestSize.Level1)
{
    bool flag = true;
    MouseEventHdr->SetTouchpadTapSwitch(flag);
    bool newFlag = true;
    ASSERT_TRUE(MouseEventHdr->GetTouchpadTapSwitch(flag) == RET_OK);
    ASSERT_TRUE(flag == newFlag);
}

/**
 * @tc.name: MouseEventNormalizeTest_SetTouchpadPointerSpeed_019
 * @tc.desc: Test SetTouchpadPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_SetTouchpadPointerSpeed_019, TestSize.Level1)
{
    int32_t speed = 3;
    ASSERT_TRUE(MouseEventHdr->SetTouchpadPointerSpeed(speed) == RET_OK);
}

/**
 * @tc.name: MouseEventNormalizeTest_GetTouchpadPointerSpeed_020
 * @tc.desc: Test GetTouchpadPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_GetTouchpadPointerSpeed_020, TestSize.Level1)
{
    int32_t speed = 8;
    MouseEventHdr->SetTouchpadPointerSpeed(speed);
    int32_t newSpeed = 4;
    ASSERT_TRUE(MouseEventHdr->GetTouchpadPointerSpeed(newSpeed) == RET_OK);
    ASSERT_TRUE(speed == newSpeed);
}

/**
 * @tc.name: MouseEventNormalizeTest_SetTouchpadPointerSpeed_021
 * @tc.desc: Test SetTouchpadPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_SetTouchpadPointerSpeed_021, TestSize.Level1)
{
    int32_t speed = 3;
    ASSERT_TRUE(MouseEventHdr->SetTouchpadPointerSpeed(speed) == RET_OK);
}

/**
 * @tc.name: MouseEventNormalizeTest_GetTouchpadPointerSpeed_022
 * @tc.desc: Test GetTouchpadPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_GetTouchpadPointerSpeed_022, TestSize.Level1)
{
    int32_t speed = 8;
    MouseEventHdr->SetTouchpadPointerSpeed(speed);
    int32_t newSpeed = 4;
    ASSERT_TRUE(MouseEventHdr->GetTouchpadPointerSpeed(newSpeed) == RET_OK);
    ASSERT_TRUE(speed == newSpeed);
}

/**
 * @tc.name: MouseEventNormalizeTest_SetTouchpadRightClickType_023
 * @tc.desc: Test SetTouchpadRightClickType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_SetTouchpadRightClickType_023, TestSize.Level1)
{
    int32_t type = 3;
    ASSERT_TRUE(MouseEventHdr->SetTouchpadRightClickType(type) == RET_OK);
}

/**
 * @tc.name: MouseEventNormalizeTest_GetTouchpadRightClickType_024
 * @tc.desc: Test GetTouchpadRightClickType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_GetTouchpadRightClickType_024, TestSize.Level1)
{
    int32_t type = 1;
    MouseEventHdr->SetTouchpadRightClickType(type);
    int32_t newType = 2;
    ASSERT_TRUE(MouseEventHdr->GetTouchpadRightClickType(newType) == RET_OK);
    ASSERT_TRUE(type == newType);
}
}
}
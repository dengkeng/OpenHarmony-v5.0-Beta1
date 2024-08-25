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

#include <list>
#include <string>
#include <utility>
#include <vector>

#include "gtest/gtest.h"

#define private public
#define protected public
#include "mock_touch_event_target.h"
#include "test/mock/base/mock_task_executor.h"
#include "test/mock/core/common/mock_container.h"

#include "base/geometry/ng/offset_t.h"
#include "base/geometry/offset.h"
#include "base/geometry/point.h"
#include "base/geometry/rect.h"
#include "base/log/log_wrapper.h"
#include "base/memory/ace_type.h"
#include "base/memory/referenced.h"
#include "core/common/ace_engine.h"
#include "core/components/ability_component/ability_component.h"
#include "core/components/ability_component/render_ability_component.h"
#include "core/components/box/render_box.h"
#include "core/components/common/layout/constants.h"
#include "core/components_ng/base/frame_node.h"
#include "core/components_ng/event/focus_hub.h"
#include "core/components_ng/gestures/recognizers/gesture_recognizer.h"
#include "core/components_ng/gestures/recognizers/swipe_recognizer.h"
#include "core/components_ng/manager/select_overlay/select_overlay_manager.h"
#include "core/components_ng/pattern/button/button_event_hub.h"
#include "core/components_v2/inspector/inspector_constants.h"
#include "core/event/ace_events.h"
#include "core/event/axis_event.h"
#include "core/event/key_event.h"
#include "core/event/mouse_event.h"
#include "core/event/touch_event.h"
#include "core/pipeline/base/element_register.h"
#include "core/pipeline/pipeline_context.h"
#include "core/pipeline_ng/pipeline_context.h"
#include "frameworks/core/animation/animatable_properties.h"
#include "frameworks/core/common/event_manager.h"
#include "frameworks/core/common/font_manager.h"
#include "frameworks/core/common/manager_interface.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS::Ace::NG {
namespace {
const std::string CTRL = "Ctrl";
const std::string SHIFT = "shift";
const std::string ALT = "alt";
const std::string CTRLSHIFT = "Ctrl + shift";
const std::string MOUSE = "mouse";
const std::string MOUSE_EVENT = "mouse_event";
const std::string MOUSE_EVENT_2 = "mouse_event_2";

const std::string CHARACTER_C = "C";
const std::string CHARACTER_A = "A";
const std::string CHARACTER_V = "V";
const std::string CHARACTER_Z = "Z";
const std::string CHARACTER_EIGHT = "8";
const std::string CHARACTER_X = "X";

const std::string SHORT_CUT_VALUE_X = "X";
const std::string SHORT_CUT_VALUE_Y = "Y";
const std::string SHORT_CUT_VALUE_Z = "Z";
const std::string SHORT_CUT_VALUE_A = "A";
const std::string SHORT_CUT_VALUE_C = "C";
const std::string SHORT_CUT_VALUE_V = "V";

constexpr int32_t NUM_CTRL_VALUE = 1;
constexpr int32_t NUM_SHIFT_VALUE = 2;
constexpr int32_t NUM_ALT_VALUE = 4;

constexpr int32_t NODEID = 1;
constexpr int32_t NODEID_2 = 2;
constexpr int32_t NODEID_3 = 3;

enum class CtrlKeysBit {
    CTRL = 1,
    SHIFT = 2,
    ALT = 4,
};

RefPtr<MockTaskExecutor> MOCK_TASK_EXECUTOR;
const int32_t CONTAINER_INSTANCE_ID = 777;
} // namespace

class EventManagerTestNg : public testing::Test {
public:
    static void SetUpTestSuite();
    static void TearDownTestSuite();
};

void EventManagerTestNg::SetUpTestSuite()
{
    MockContainer::SetUp();
    MockContainer::Current()->pipelineContext_ = nullptr;
    MOCK_TASK_EXECUTOR = AceType::MakeRefPtr<MockTaskExecutor>();
}

void EventManagerTestNg::TearDownTestSuite()
{
    MockContainer::TearDown();
}

/**
 * @tc.name: EventManagerTest001
 * @tc.desc: Test OnDragStart
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest001, TestSize.Level1)
{
    auto eventManager = AceType::MakeRefPtr<EventManager>();

    bool isCtrlC = eventManager->IsSystemKeyboardShortcut(CHARACTER_C, NUM_CTRL_VALUE);
    bool isCtrlA = eventManager->IsSystemKeyboardShortcut(CHARACTER_A, NUM_CTRL_VALUE);
    bool isCtrlV = eventManager->IsSystemKeyboardShortcut(CHARACTER_V, NUM_CTRL_VALUE);
    bool isCtrl8 = eventManager->IsSystemKeyboardShortcut(CHARACTER_EIGHT, NUM_CTRL_VALUE);
    bool isCtrlX = eventManager->IsSystemKeyboardShortcut(CHARACTER_X, NUM_CTRL_VALUE);
    bool isShiftC = eventManager->IsSystemKeyboardShortcut(CHARACTER_C, NUM_SHIFT_VALUE);
    bool isShiftA = eventManager->IsSystemKeyboardShortcut(CHARACTER_A, NUM_SHIFT_VALUE);
    bool isShiftV = eventManager->IsSystemKeyboardShortcut(CHARACTER_V, NUM_SHIFT_VALUE);
    bool isShift8 = eventManager->IsSystemKeyboardShortcut(CHARACTER_EIGHT, NUM_SHIFT_VALUE);
    bool isShiftX = eventManager->IsSystemKeyboardShortcut(CHARACTER_X, NUM_SHIFT_VALUE);
    bool isAltC = eventManager->IsSystemKeyboardShortcut(CHARACTER_C, NUM_ALT_VALUE);
    bool isAltA = eventManager->IsSystemKeyboardShortcut(CHARACTER_A, NUM_ALT_VALUE);
    bool isAltV = eventManager->IsSystemKeyboardShortcut(CHARACTER_V, NUM_ALT_VALUE);
    bool isAlt8 = eventManager->IsSystemKeyboardShortcut(CHARACTER_EIGHT, NUM_ALT_VALUE);
    bool isAltX = eventManager->IsSystemKeyboardShortcut(CHARACTER_X, NUM_ALT_VALUE);
    bool isCtrlShiftC = eventManager->IsSystemKeyboardShortcut(CHARACTER_C, (NUM_CTRL_VALUE + NUM_SHIFT_VALUE));
    bool isCtrlShiftA = eventManager->IsSystemKeyboardShortcut(CHARACTER_A, (NUM_CTRL_VALUE + NUM_SHIFT_VALUE));
    bool isCtrlShiftV = eventManager->IsSystemKeyboardShortcut(CHARACTER_V, (NUM_CTRL_VALUE + NUM_SHIFT_VALUE));
    bool isCtrlShift8 = eventManager->IsSystemKeyboardShortcut(CHARACTER_EIGHT, (NUM_CTRL_VALUE + NUM_SHIFT_VALUE));
    bool isCtrlShiftX = eventManager->IsSystemKeyboardShortcut(CHARACTER_X, (NUM_CTRL_VALUE + NUM_SHIFT_VALUE));

    EXPECT_TRUE(isCtrlC);
    EXPECT_TRUE(isCtrlA);
    EXPECT_TRUE(isCtrlV);
    EXPECT_FALSE(isCtrl8);
    EXPECT_TRUE(isCtrlX);
    EXPECT_FALSE(isShiftC);
    EXPECT_FALSE(isShiftA);
    EXPECT_FALSE(isShiftV);
    EXPECT_FALSE(isShift8);
    EXPECT_FALSE(isShiftX);
    EXPECT_FALSE(isAltC);
    EXPECT_FALSE(isAltA);
    EXPECT_FALSE(isAltV);
    EXPECT_FALSE(isAlt8);
    EXPECT_FALSE(isAltX);
    EXPECT_FALSE(isCtrlShiftC);
    EXPECT_FALSE(isCtrlShiftA);
    EXPECT_FALSE(isCtrlShiftV);
    EXPECT_FALSE(isCtrlShift8);
    EXPECT_FALSE(isCtrlShiftX);
}

/**
 * @tc.name: EventManagerTest002
 * @tc.desc: Test OnDragStart
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest002, TestSize.Level1)
{
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    KeyEvent event;
    auto frameNodeCtrl = FrameNode::GetOrCreateFrameNode(CTRL, NODEID, nullptr);
    auto frameNodeShift = FrameNode::GetOrCreateFrameNode(SHIFT, NODEID, nullptr);
    auto frameNodeAlt = FrameNode::GetOrCreateFrameNode(ALT, NODEID, nullptr);
    auto frameNodeCtrlShift = FrameNode::GetOrCreateFrameNode(CTRLSHIFT, NODEID, nullptr);
    frameNodeCtrl->SetActive(true);
    frameNodeShift->SetActive(true);
    frameNodeAlt->SetActive(true);
    frameNodeCtrlShift->SetActive(true);

    auto eventHubCtrl = frameNodeCtrl->GetEventHub<NG::EventHub>();
    auto eventHubShift = frameNodeShift->GetEventHub<NG::EventHub>();
    auto eventHubAlt = frameNodeAlt->GetEventHub<NG::EventHub>();
    auto eventHubCtrlShift = frameNodeCtrlShift->GetEventHub<NG::EventHub>();

    eventManager->AddKeyboardShortcutNode(WeakPtr<NG::FrameNode>(frameNodeCtrl));
    eventManager->AddKeyboardShortcutNode(WeakPtr<NG::FrameNode>(frameNodeShift));
    eventManager->AddKeyboardShortcutNode(WeakPtr<NG::FrameNode>(frameNodeAlt));
    eventManager->AddKeyboardShortcutNode(WeakPtr<NG::FrameNode>(frameNodeCtrlShift));
    eventHubCtrl->SetKeyboardShortcut(CHARACTER_C, (NUM_CTRL_VALUE + NUM_SHIFT_VALUE + NUM_ALT_VALUE), []() {});
    event.code = KeyCode::KEY_C;
    event.action = KeyAction::DOWN;
    event.pressedCodes.emplace_back(KeyCode::KEY_CTRL_LEFT);
    event.pressedCodes.emplace_back(KeyCode::KEY_SHIFT_LEFT);
    event.pressedCodes.emplace_back(KeyCode::KEY_ALT_LEFT);
    event.pressedCodes.emplace_back(KeyCode::KEY_C);
    eventManager->DispatchKeyboardShortcut(event);
    EXPECT_EQ(event.action, KeyAction::DOWN);
    eventHubShift->SetKeyboardShortcut(CHARACTER_A, (NUM_CTRL_VALUE + NUM_SHIFT_VALUE), []() {});
    event.code = KeyCode::KEY_A;
    event.action = KeyAction::DOWN;
    event.pressedCodes.emplace_back(KeyCode::KEY_CTRL_LEFT);
    event.pressedCodes.emplace_back(KeyCode::KEY_SHIFT_LEFT);
    event.pressedCodes.emplace_back(KeyCode::KEY_A);
    eventManager->DispatchKeyboardShortcut(event);
    EXPECT_EQ(event.action, KeyAction::DOWN);
    eventHubAlt->SetKeyboardShortcut(CHARACTER_A, (NUM_CTRL_VALUE + NUM_ALT_VALUE), []() {});
    event.code = KeyCode::KEY_V;
    event.action = KeyAction::DOWN;
    event.pressedCodes.emplace_back(KeyCode::KEY_CTRL_LEFT);
    event.pressedCodes.emplace_back(KeyCode::KEY_V);
    eventManager->DispatchKeyboardShortcut(event);
    EXPECT_EQ(event.action, KeyAction::DOWN);
}

/**
 * @tc.name: EventManagerTest003
 * @tc.desc: Test OnDragStart
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest003, TestSize.Level1)
{
    auto eventManager = AceType::MakeRefPtr<EventManager>();

    auto frameNodeCtrl = FrameNode::GetOrCreateFrameNode(CTRL, NUM_CTRL_VALUE, nullptr);
    eventManager->AddKeyboardShortcutNode(WeakPtr<NG::FrameNode>(frameNodeCtrl));
    eventManager->AddKeyboardShortcutNode(WeakPtr<NG::FrameNode>(frameNodeCtrl));
    eventManager->AddKeyboardShortcutNode(WeakPtr<NG::FrameNode>(frameNodeCtrl));
    auto frameNodeShift = FrameNode::GetOrCreateFrameNode(SHIFT, NUM_SHIFT_VALUE, nullptr);
    eventManager->AddKeyboardShortcutNode(WeakPtr<NG::FrameNode>(frameNodeShift));
    auto frameNodeAlt = FrameNode::GetOrCreateFrameNode(ALT, NUM_ALT_VALUE, nullptr);
    eventManager->AddKeyboardShortcutNode(WeakPtr<NG::FrameNode>(frameNodeAlt));
    auto frameNodeCtrlShift = FrameNode::GetOrCreateFrameNode(CTRLSHIFT, (NUM_CTRL_VALUE + NUM_SHIFT_VALUE), nullptr);
    eventManager->AddKeyboardShortcutNode(WeakPtr<NG::FrameNode>(frameNodeCtrlShift));

    auto eventHubCtrl = frameNodeCtrl->GetEventHub<NG::EventHub>();
    auto eventHubShift = frameNodeShift->GetEventHub<NG::EventHub>();
    auto eventHubAlt = frameNodeAlt->GetEventHub<NG::EventHub>();
    auto eventHubCtrlShift = frameNodeCtrlShift->GetEventHub<NG::EventHub>();

    eventHubCtrl->SetKeyboardShortcut(CHARACTER_C, NUM_CTRL_VALUE, []() {});
    eventHubShift->SetKeyboardShortcut(CHARACTER_A, NUM_SHIFT_VALUE, []() {});
    eventHubAlt->SetKeyboardShortcut(CHARACTER_V, NUM_ALT_VALUE, []() {});
    eventHubCtrlShift->SetKeyboardShortcut(CHARACTER_Z, (NUM_CTRL_VALUE + NUM_SHIFT_VALUE), []() {});

    bool isShortcutNodeCtrlC = eventManager->IsSameKeyboardShortcutNode(CHARACTER_C, NUM_CTRL_VALUE);
    EXPECT_TRUE(isShortcutNodeCtrlC);
    bool isShortcutNodeCtrlEIGHT = eventManager->IsSameKeyboardShortcutNode(CHARACTER_EIGHT, NUM_CTRL_VALUE);
    EXPECT_FALSE(isShortcutNodeCtrlEIGHT);
    bool isShortcutNodeShiftC = eventManager->IsSameKeyboardShortcutNode(CHARACTER_C, NUM_SHIFT_VALUE);
    EXPECT_FALSE(isShortcutNodeShiftC);
    bool isShortcutNodeShiftEight = eventManager->IsSameKeyboardShortcutNode(CHARACTER_EIGHT, NUM_SHIFT_VALUE);
    EXPECT_FALSE(isShortcutNodeShiftEight);
    bool isShortcutNodeAltC = eventManager->IsSameKeyboardShortcutNode(CHARACTER_C, NUM_ALT_VALUE);
    EXPECT_FALSE(isShortcutNodeAltC);
    bool isShortcutNodeAltEight = eventManager->IsSameKeyboardShortcutNode(CHARACTER_EIGHT, NUM_ALT_VALUE);
    EXPECT_FALSE(isShortcutNodeAltEight);
    bool isShortcutComposeC = eventManager->IsSameKeyboardShortcutNode(CHARACTER_C, (NUM_CTRL_VALUE + NUM_SHIFT_VALUE));
    EXPECT_FALSE(isShortcutComposeC);
    bool isShortcutComposeEight =
        eventManager->IsSameKeyboardShortcutNode(CHARACTER_EIGHT, (NUM_CTRL_VALUE + NUM_SHIFT_VALUE));
    EXPECT_FALSE(isShortcutComposeEight);
}

/**
 * @tc.name: EventManagerTest004
 * @tc.desc: Test OnDragStart
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest004, TestSize.Level1)
{
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    auto frameNodeone = FrameNode::GetOrCreateFrameNode(CTRL, NODEID, nullptr);

    eventManager->AddKeyboardShortcutNode(WeakPtr<NG::FrameNode>(frameNodeone));
    eventManager->AddKeyboardShortcutNode(WeakPtr<NG::FrameNode>(frameNodeone));
    ASSERT_NE(frameNodeone, nullptr);

    auto frameNodetwo = FrameNode::GetOrCreateFrameNode(SHIFT, NODEID, nullptr);
    eventManager->AddKeyboardShortcutNode(WeakPtr<NG::FrameNode>(frameNodetwo));
    ASSERT_NE(frameNodetwo, nullptr);
}

/**
 * @tc.name: EventManagerTest005
 * @tc.desc: Test OnDragStart
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest005, TestSize.Level1)
{
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    auto frameNodeone = FrameNode::GetOrCreateFrameNode(CTRL, NODEID, nullptr);
    eventManager->AddKeyboardShortcutNode(WeakPtr<NG::FrameNode>(frameNodeone));

    eventManager->DelKeyboardShortcutNode(frameNodeone->GetId());
    ASSERT_NE(frameNodeone, nullptr);

    auto frameNodetwo = FrameNode::GetOrCreateFrameNode(SHIFT, NODEID, nullptr);
    eventManager->DelKeyboardShortcutNode(frameNodetwo->GetId());
    ASSERT_NE(frameNodetwo, nullptr);
}

/**
 * @tc.name: EventManagerTest006
 * @tc.desc: Test GetKeyboardShortcutKeys
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest006, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. Call GetKeyboardShortcutKeys with keys.size() > KEYS_MAX_VALUE.
     * @tc.expected: Value of ret is 0.
     */
    std::vector<ModifierKey> keys { ModifierKey::ALT, ModifierKey::CTRL, ModifierKey::SHIFT, ModifierKey::SHIFT };
    auto ret = eventManager->GetKeyboardShortcutKeys(keys);
    ASSERT_EQ(ret, 0);

    /**
     * @tc.steps: step3. Call GetKeyboardShortcutKeys with keys CTRL SHIFT ALT.
     * @tc.expected: Value of ret is CTRL | SHIFT | ALT.
     */
    keys.pop_back();
    ret = eventManager->GetKeyboardShortcutKeys(keys);
    uint8_t target = static_cast<uint8_t>(CtrlKeysBit::CTRL) | static_cast<uint8_t>(CtrlKeysBit::SHIFT) |
                     static_cast<uint8_t>(CtrlKeysBit::ALT);
    ASSERT_EQ(ret, target);

    /**
     * @tc.steps: step4. Call GetKeyboardShortcutKeys with keys CTRL CTRL.
     * @tc.expected: Value of ret is 0.
     */
    keys = std::vector<ModifierKey>({ ModifierKey::CTRL, ModifierKey::CTRL });
    ret = eventManager->GetKeyboardShortcutKeys(keys);
    ASSERT_EQ(ret, 0);

    /**
     * @tc.steps: step5. Call GetKeyboardShortcutKeys with keys SHIFT SHIFT.
     * @tc.expected: Value of ret is 0.
     */
    keys = std::vector<ModifierKey>({ ModifierKey::SHIFT, ModifierKey::SHIFT });
    ret = eventManager->GetKeyboardShortcutKeys(keys);
    ASSERT_EQ(ret, 0);

    /**
     * @tc.steps: step6. Call GetKeyboardShortcutKeys with keys SHIFT SHIFT.
     * @tc.expected: Value of ret is 0.
     */
    keys = std::vector<ModifierKey>({ ModifierKey::ALT, ModifierKey::ALT });
    ret = eventManager->GetKeyboardShortcutKeys(keys);
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: EventManagerTest007
 * @tc.desc: Test IsSystemKeyboardShortcut
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest007, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. Call IsSystemKeyboardShortcut with CTRL C.
     * @tc.expected: retFlag is true.
     */
    std::string value = SHORT_CUT_VALUE_C;
    uint8_t keys = static_cast<uint8_t>(CtrlKeysBit::CTRL);
    auto retFlag = eventManager->IsSystemKeyboardShortcut(value, keys);
    ASSERT_TRUE(retFlag);

    /**
     * @tc.steps: step2. Call IsSystemKeyboardShortcut with CTRL A.
     * @tc.expected: retFlag is true.
     */
    value = SHORT_CUT_VALUE_A;
    retFlag = eventManager->IsSystemKeyboardShortcut(value, keys);
    ASSERT_TRUE(retFlag);

    /**
     * @tc.steps: step3. Call IsSystemKeyboardShortcut with CTRL V.
     * @tc.expected: retFlag is true.
     */
    value = SHORT_CUT_VALUE_V;
    retFlag = eventManager->IsSystemKeyboardShortcut(value, keys);
    ASSERT_TRUE(retFlag);

    /**
     * @tc.steps: step4. Call IsSystemKeyboardShortcut with CTRL X.
     * @tc.expected: retFlag is true.
     */
    value = SHORT_CUT_VALUE_X;
    retFlag = eventManager->IsSystemKeyboardShortcut(value, keys);
    ASSERT_TRUE(retFlag);

    /**
     * @tc.steps: step5. Call IsSystemKeyboardShortcut with CTRL Y.
     * @tc.expected: retFlag is true.
     */
    value = SHORT_CUT_VALUE_Y;
    retFlag = eventManager->IsSystemKeyboardShortcut(value, keys);
    ASSERT_TRUE(retFlag);

    /**
     * @tc.steps: step6. Call IsSystemKeyboardShortcut with CTRL Z.
     * @tc.expected: retFlag is true.
     */
    value = SHORT_CUT_VALUE_Z;
    retFlag = eventManager->IsSystemKeyboardShortcut(value, keys);
    ASSERT_TRUE(retFlag);

    /**
     * @tc.steps: step6. Call IsSystemKeyboardShortcut with CTRL SHIFT Z.
     * @tc.expected: retFlag is true.
     */
    value = SHORT_CUT_VALUE_Z;
    keys = static_cast<uint8_t>(CtrlKeysBit::CTRL) + static_cast<uint8_t>(CtrlKeysBit::SHIFT);
    retFlag = eventManager->IsSystemKeyboardShortcut(value, keys);
    ASSERT_TRUE(retFlag);

    /**
     * @tc.steps: step6. Call IsSystemKeyboardShortcut with CTRL SHIFT A.
     * @tc.expected: retFlag is false.
     */
    value = SHORT_CUT_VALUE_A;
    keys = static_cast<uint8_t>(CtrlKeysBit::CTRL) + static_cast<uint8_t>(CtrlKeysBit::SHIFT);
    retFlag = eventManager->IsSystemKeyboardShortcut(value, keys);
    ASSERT_FALSE(retFlag);
}

/**
 * @tc.name: EventManagerTest009
 * @tc.desc: Test ClearResults
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest009, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. Add KeyboardShortcutNode
     * @tc.expected: keyboardShortcutNode_.size() > 0.
     */
    auto frameNodeShift = FrameNode::GetOrCreateFrameNode(SHIFT, NUM_SHIFT_VALUE, nullptr);
    frameNodeShift->eventHub_->SetKeyboardShortcut(SHORT_CUT_VALUE_A, static_cast<int>(CtrlKeysBit::SHIFT), []() {});
    eventManager->AddKeyboardShortcutNode(WeakPtr<NG::FrameNode>(frameNodeShift));
    ASSERT_GT(eventManager->keyboardShortcutNode_.size(), 0);

    /**
     * @tc.steps: step3. Call ClearResults
     * @tc.expected: keyboardShortcutNode_.size() = 0.
     */
    eventManager->ClearResults();
    ASSERT_EQ(eventManager->keyboardShortcutNode_.size(), 0);
}

/**
 * @tc.name: EventManagerTest010
 * @tc.desc: Test TouchTest with FrameNode
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest010, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. Create FrameNode and Call TouchTest with needAppend false
     * @tc.expected: touchTestResults_ has the touchPoint.id of instance
     */
    TouchEvent touchPoint;
    touchPoint.id = 0;
    touchPoint.type = TouchType::DOWN;

    const int nodeId = 10001;
    auto frameNode = FrameNode::GetOrCreateFrameNode(V2::LOCATION_BUTTON_ETS_TAG, nodeId, nullptr);
    TouchRestrict touchRestrict;
    Offset offset;
    EXPECT_EQ(eventManager->touchTestResults_.count(touchPoint.id), 0);
    eventManager->TouchTest(touchPoint, frameNode, touchRestrict, offset, 0, false);
    EXPECT_GT(eventManager->touchTestResults_.count(touchPoint.id), 0);

    /**
     * @tc.steps: step2. Create FrameNode and Call TouchTest with needAppend true
     * @tc.expected: touchTestResults_ has the touchPoint.id of instance
     */
    eventManager->touchTestResults_.erase(touchPoint.id);
    EXPECT_EQ(eventManager->touchTestResults_.count(touchPoint.id), 0);
    eventManager->TouchTest(touchPoint, frameNode, touchRestrict, offset, 0, true);
    EXPECT_GT(eventManager->touchTestResults_.count(touchPoint.id), 0);

    /**
     * @tc.steps: step3. Create GestureScope.
     * @tc.expected: GestureScope is not null.
     */
    size_t touchId = 100;
    RefPtr<GestureScope> scope = AceType::MakeRefPtr<GestureScope>(touchId);
    ASSERT_NE(scope, nullptr);
    eventManager->refereeNG_->gestureScopes_.insert(std::make_pair(touchId, scope));
    ASSERT_TRUE(eventManager->refereeNG_->QueryAllDone(touchId));
}

/**
 * @tc.name: EventManagerTest011
 * @tc.desc: Test TouchTest with FrameNode
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest011, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. Create FrameNode and Call TouchTest
     * @tc.expected: touchTestResults_ has the touchPoint.id of instance
     */
    AxisEvent axisEvent;
    axisEvent.sourceType = SourceType::TOUCH;

    const int nodeId = 10002;
    auto frameNode = FrameNode::GetOrCreateFrameNode(V2::LOCATION_BUTTON_ETS_TAG, nodeId, nullptr);
    TouchRestrict touchRestrict;

    EXPECT_EQ(eventManager->axisTouchTestResults_.count(axisEvent.id), 0);
    eventManager->TouchTest(axisEvent, frameNode, touchRestrict);
    EXPECT_GT(eventManager->axisTouchTestResults_.count(axisEvent.id), 0);
}

/**
 * @tc.name: EventManagerTest012
 * @tc.desc: Test HandleGlobalEventNG
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest012, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. Create FrameNode and Call TouchTest to add touchTestResults_[touchPoint.id]
     * @tc.expected: touchTestResults_ has the touchPoint.id of instance
     */
    TouchEvent touchPoint;
    touchPoint.type = TouchType::DOWN;

    const int nodeId = 10003;
    auto frameNode = FrameNode::GetOrCreateFrameNode(V2::LOCATION_BUTTON_ETS_TAG, nodeId, nullptr);
    TouchRestrict touchRestrict;
    Offset offset;

    eventManager->TouchTest(touchPoint, frameNode, touchRestrict, offset, 0, true);
    EXPECT_GT(eventManager->touchTestResults_.count(touchPoint.id), 0);

    /**
     * @tc.steps: step3. Create FrameNode and Call TouchTest to add touchTestResults_[touchPoint.id]
     * @tc.expected: selectOverlayManager->touchTestResults_ is empty for do not have specific event
     */
    auto selectOverlayManager = AceType::MakeRefPtr<SelectOverlayManager>(frameNode);
    NG::OffsetF rootOffset;
    eventManager->HandleGlobalEventNG(touchPoint, selectOverlayManager, rootOffset);
    EXPECT_EQ(selectOverlayManager->touchTestResults_.size(), 0);
}

/**
 * @tc.name: EventManagerTest013
 * @tc.desc: Test HandleOutOfRectCallback
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest013, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. Create rectCallbackList
     * @tc.expected: touchTestResults_ has the touchPoint.id of instance
     */
    Point point(10, 20);
    point.SetSourceType(SourceType::TOUCH);

    auto rectGetCallback1 = [](std::vector<Rect>& rectList) -> void { rectList.push_back(Rect()); };
    auto rectGetCallback2 = [](std::vector<Rect>& rectList) -> void { rectList.push_back(Rect(0, 0, 100, 100)); };

    auto touchCallback = []() -> void {};
    auto mouseCallback = []() -> void {};
    std::vector<RectCallback> rectCallbackList { RectCallback(rectGetCallback1, touchCallback, mouseCallback),
        RectCallback(rectGetCallback2, touchCallback, mouseCallback) };

    /**
     * @tc.steps: step3. Call HandleOutOfRectCallback with SourceType::TOUCH
     * @tc.expected: rectCallbackList.size() is 1
     */
    eventManager->HandleOutOfRectCallback(point, rectCallbackList);
    EXPECT_EQ(rectCallbackList.size(), 1);

    /**
     * @tc.steps: step4. Call HandleOutOfRectCallback with SourceType::MOUSE
     * @tc.expected: rectCallbackList.size() is 0
     */
    point.SetSourceType(SourceType::MOUSE);
    rectCallbackList = vector<RectCallback>({ RectCallback(rectGetCallback1, touchCallback, mouseCallback) });
    eventManager->HandleOutOfRectCallback(point, rectCallbackList);
    EXPECT_TRUE(rectCallbackList.empty());
}

/**
 * @tc.name: EventManagerTest014
 * @tc.desc: Test DispatchTouchEvent
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest014, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. Create TouchEvent and Call DispatchTouchEvent
     * @tc.expected: retFlag is false
     */
    AxisEvent event;
    event.action = AxisAction::BEGIN;

    auto retFlag = eventManager->DispatchTouchEvent(event);
    EXPECT_FALSE(retFlag);

    /**
     * @tc.steps: step3. Create FrameNode and Call TouchTest to add axisTouchTestResults_
     * @tc.expected: touchTestResults_ has the touchPoint.id of instance
     */
    event.action = AxisAction::END;

    const int nodeId = 10004;
    auto frameNode = FrameNode::GetOrCreateFrameNode(V2::LOCATION_BUTTON_ETS_TAG, nodeId, nullptr);
    TouchRestrict touchRestrict;

    eventManager->TouchTest(event, frameNode, touchRestrict);
    EXPECT_GT(eventManager->axisTouchTestResults_.count(event.id), 0);

    /**
     * @tc.steps: step4. Call DispatchTouchEvent
     * @tc.expected: touchTestResults_ has the touchPoint.id of instance
     */
    retFlag = eventManager->DispatchTouchEvent(event);
    EXPECT_TRUE(retFlag);

    /**
     * @tc.steps: step5. Create AxisEvent and Call DispatchTouchEvent
     * @tc.expected: retFlag is false
     */
    event.action = AxisAction::BEGIN;
    Container::SetCurrentUsePartialUpdate(true);
    AceForwardCompatibility::isNewPipeline_ = true;
    eventManager->DispatchTouchEvent(event);
    auto container = Container::Current();
    container->useNewPipeline_ = true;
    ASSERT_NE(container, nullptr);
    retFlag = Container::IsCurrentUseNewPipeline();
    EXPECT_TRUE(retFlag);
}

/**
 * @tc.name: EventManagerTest015
 * @tc.desc: Test DispatchTabIndexEventNG
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest015, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. Create frameNodes
     * @tc.expected: retFlag is false
     */
    const int mainNodeId = 10006;
    auto mainNode = FrameNode::GetOrCreateFrameNode(V2::LOCATION_BUTTON_ETS_TAG, mainNodeId, nullptr);

    /**
     * @tc.steps: step3. Call DispatchTabIndexEventNG
     * @tc.expected: retFlag is false
     */
    KeyEvent event;
    auto retFlag = eventManager->DispatchTabIndexEventNG(event, mainNode);
    ASSERT_FALSE(retFlag);
}

/**
 * @tc.name: EventManagerTest016
 * @tc.desc: Test DispatchKeyEventNG
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest016, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. Create frameNodes
     * @tc.expected: retFlag is false
     */
    const int focusNodeId = 10007;
    auto focusNode = FrameNode::GetOrCreateFrameNode(V2::LOCATION_BUTTON_ETS_TAG, focusNodeId, nullptr);
    focusNode->eventHub_ = AceType::MakeRefPtr<ButtonEventHub>();
    focusNode->eventHub_->GetOrCreateFocusHub(FocusType::NODE);
    ASSERT_NE(focusNode->GetFocusHub(), nullptr);

    /**
     * @tc.steps: step3. Call DispatchKeyEventNG
     * @tc.expected: retFlag is false
     */
    KeyEvent event;
    auto retFlag = eventManager->DispatchKeyEventNG(event, focusNode);
    ASSERT_FALSE(retFlag);
}

/**
 * @tc.name: EventManagerTest017
 * @tc.desc: Test MouseTest (frameNode)
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest017, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. Call MouseTest with MouseAction::WINDOW_LEAVE
     * @tc.expected: currHoverTestResults_ is empty
     */
    MouseEvent event;
    const int nodeId = 10008;
    auto frameNode = FrameNode::GetOrCreateFrameNode(V2::LOCATION_BUTTON_ETS_TAG, nodeId, nullptr);
    TouchRestrict touchRestrict;

    event.action = MouseAction::WINDOW_LEAVE;
    auto hoverEventTarget = AceType::MakeRefPtr<HoverEventTarget>(V2::LOCATION_BUTTON_ETS_TAG, nodeId);
    eventManager->currHoverTestResults_.push_back(hoverEventTarget);
    ASSERT_FALSE(eventManager->currHoverTestResults_.empty());
    eventManager->MouseTest(event, frameNode, touchRestrict);
    ASSERT_TRUE(eventManager->currHoverTestResults_.empty());

    /**
     * @tc.steps: step3. Call MouseTest with MouseAction::WINDOW_ENTER
     * @tc.expected: lastHoverTestResults_ is empty
     */
    event.action = MouseAction::WINDOW_ENTER;
    eventManager->lastHoverTestResults_.push_back(hoverEventTarget);
    ASSERT_FALSE(eventManager->lastHoverTestResults_.empty());
    eventManager->MouseTest(event, frameNode, touchRestrict);
    ASSERT_TRUE(eventManager->lastHoverTestResults_.empty());

    /**
     * @tc.steps: step4. Call MouseTest with MouseAction::HOVER
     * @tc.expected: lastHoverTestResults_ is empty and currHoverTestResults_ is empty
     */
    event.action = MouseAction::HOVER;
    eventManager->lastHoverTestResults_.push_back(hoverEventTarget);
    eventManager->MouseTest(event, frameNode, touchRestrict);
    ASSERT_TRUE(eventManager->lastHoverTestResults_.empty());
    ASSERT_TRUE(eventManager->currHoverTestResults_.empty());
}

/**
 * @tc.name: EventManagerTest018
 * @tc.desc: Test DispatchMouseEventNG
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest018, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. Call DispatchMouseEventNG
     * @tc.expected: currHoverTestResults_ is empty
     */
    MouseEvent event;
    event.action = MouseAction::PRESS;
    event.button = MouseButton::LEFT_BUTTON;
    event.pullAction = MouseAction::MOVE;

    auto mouseEventTarget = AceType::MakeRefPtr<MouseEventTarget>(MOUSE, NODEID);
    eventManager->pressMouseTestResults_.push_back(mouseEventTarget);
    eventManager->currMouseTestResults_.push_back(mouseEventTarget);

    auto retFlag = eventManager->DispatchMouseEventNG(event);
    ASSERT_FALSE(retFlag);

    /**
     * @tc.steps: step2. Call DispatchMouseEventNG
     * @tc.expected: currHoverTestResults_ is empty
     */
    event.action = MouseAction::RELEASE;
    event.button = MouseButton::LEFT_BUTTON;
    event.pullAction = MouseAction::MOVE;
    retFlag = eventManager->DispatchMouseEventNG(event);
    ASSERT_FALSE(retFlag);

    /**
     * @tc.steps: step3. Call DispatchMouseEventNG
     * @tc.expected: currHoverTestResults_ is empty
     */
    event.action = MouseAction::MOVE;
    event.button = MouseButton::LEFT_BUTTON;
    event.pullAction = MouseAction::PULL_UP;
    retFlag = eventManager->DispatchMouseEventNG(event);
    ASSERT_FALSE(retFlag);

    /**
     * @tc.steps: step4. Call DispatchMouseEventNG
     * @tc.expected: currHoverTestResults_ not empty
     */
    event.action = MouseAction::MOVE;
    event.button = MouseButton::LEFT_BUTTON;
    event.pullAction = MouseAction::PULL_UP;

    auto mouseTestResult = AceType::MakeRefPtr<MouseEventTarget>(CTRL, NODEID);
    eventManager->currMouseTestResults_.push_back(mouseTestResult);

    retFlag = eventManager->DispatchMouseEventNG(event);
    ASSERT_FALSE(retFlag);
}

/**
 * @tc.name: EventManagerTest019
 * @tc.desc: Test DispatchMouseHoverEventNG
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest019, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. Call DispatchMouseHoverEventNG with lastHoverTestResults != currHoverTestResults
     * @tc.expected: retFlag is true
     */
    MouseEvent event;
    auto hoverEventTarget = AceType::MakeRefPtr<HoverEventTarget>(MOUSE, NODEID);
    auto hoverEventTarget2 = AceType::MakeRefPtr<HoverEventTarget>(MOUSE_EVENT, NODEID_2);
    auto hoverEventTarget3 = AceType::MakeRefPtr<HoverEventTarget>(MOUSE_EVENT_2, NODEID_3);
    eventManager->lastHoverTestResults_.push_back(hoverEventTarget);
    eventManager->currHoverTestResults_.push_back(hoverEventTarget2);
    eventManager->currHoverTestResults_.push_back(hoverEventTarget3);
    eventManager->currHoverTestResults_.push_back(hoverEventTarget);
    eventManager->lastHoverDispatchLength_++;

    auto retFlag = eventManager->DispatchMouseHoverEventNG(event);
    ASSERT_TRUE(retFlag);

    /**
     * @tc.steps: step2. Call DispatchMouseHoverEventNG with lastHoverTestResults == currHoverTestResults
     * @tc.expected: retFlag is true
     */
    eventManager->lastHoverTestResults_.clear();
    eventManager->lastHoverTestResults_.push_back(hoverEventTarget);
    eventManager->currHoverTestResults_.clear();
    eventManager->currHoverTestResults_.push_back(hoverEventTarget);

    retFlag = eventManager->DispatchMouseHoverEventNG(event);
    ASSERT_TRUE(retFlag);
}

/**
 * @tc.name: EventManagerTest020
 * @tc.desc: Test DispatchAxisEventNG
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest020, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. Call DispatchAxisEventNG with horizontalAxis verticalAxis pinchAxisScale = 0
     * @tc.expected: retFlag is false
     */
    AxisEvent event;
    event.horizontalAxis = 0;
    event.verticalAxis = 0;
    event.pinchAxisScale = 0;
    auto retFlag = eventManager->DispatchAxisEventNG(event);
    ASSERT_FALSE(retFlag);

    /**
     * @tc.steps: step3. Call DispatchAxisEventNG with axisTestResults_ empty
     * @tc.expected: retFlag is false
     */
    event.horizontalAxis = 1;
    retFlag = eventManager->DispatchAxisEventNG(event);
    ASSERT_TRUE(retFlag);

    /**
     * @tc.steps: step4. Call DispatchAxisEventNG with axisTestResults_ not empty
     * @tc.expected: retFlag is false
     */
    auto axisEventTarget = AceType::MakeRefPtr<AxisEventTarget>();
    auto onAxisCallback = [](AxisInfo&) -> void {};
    axisEventTarget->SetOnAxisCallback(onAxisCallback);

    eventManager->axisTestResults_.push_back(axisEventTarget);
    retFlag = eventManager->DispatchAxisEventNG(event);
    ASSERT_TRUE(retFlag);
}

/**
 * @tc.name: EventManagerTest021
 * @tc.desc: Test DispatchAxisEventNG
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest021, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. AddKeyboardShortcutNode to eventManager
     */
    const int nodeIdCtrlShift = 10010;
    auto frameNodeCtrlShift = FrameNode::GetOrCreateFrameNode(CTRL, nodeIdCtrlShift, nullptr);
    frameNodeCtrlShift->SetActive(true);
    frameNodeCtrlShift->eventHub_->SetEnabled(true);
    const uint8_t ctrlShift = static_cast<uint8_t>(CtrlKeysBit::CTRL) + static_cast<uint8_t>(CtrlKeysBit::SHIFT);
    frameNodeCtrlShift->eventHub_->SetKeyboardShortcut(CHARACTER_A, ctrlShift, []() {});
    eventManager->AddKeyboardShortcutNode(frameNodeCtrlShift);

    const int nodeIdCtrlAlt = 10011;
    auto frameNodeCtrlAlt = FrameNode::GetOrCreateFrameNode(CTRL, nodeIdCtrlAlt, nullptr);
    frameNodeCtrlAlt->SetActive(true);
    frameNodeCtrlAlt->eventHub_->SetEnabled(true);
    const uint8_t ctrlAlt = static_cast<uint8_t>(CtrlKeysBit::CTRL) + static_cast<uint8_t>(CtrlKeysBit::ALT);
    frameNodeCtrlAlt->eventHub_->SetKeyboardShortcut(CHARACTER_A, ctrlAlt, []() {});
    eventManager->AddKeyboardShortcutNode(frameNodeCtrlAlt);

    const int nodeIdAltShift = 10012;
    auto frameNodeAltShift = FrameNode::GetOrCreateFrameNode(ALT, nodeIdAltShift, nullptr);
    frameNodeAltShift->SetActive(true);
    frameNodeAltShift->eventHub_->SetEnabled(true);
    const uint8_t altShift = static_cast<uint8_t>(CtrlKeysBit::SHIFT) + static_cast<uint8_t>(CtrlKeysBit::ALT);
    frameNodeAltShift->eventHub_->SetKeyboardShortcut(CHARACTER_A, altShift, []() {});
    eventManager->AddKeyboardShortcutNode(frameNodeAltShift);

    /**
     * @tc.steps: step3. call DispatchKeyboardShortcut
     * @tc.expected: AddKeyboardShortcutDoubleKeys calls.
     */
    KeyEvent event;
    event.action = KeyAction::DOWN;
    eventManager->DispatchKeyboardShortcut(event);
    ASSERT_EQ(frameNodeCtrlShift->GetEventHub<NG::EventHub>()->GetKeyboardShortcut().back().keys, ctrlShift);
    ASSERT_EQ(frameNodeCtrlAlt->GetEventHub<NG::EventHub>()->GetKeyboardShortcut().back().keys, ctrlAlt);
    ASSERT_EQ(frameNodeAltShift->GetEventHub<NG::EventHub>()->GetKeyboardShortcut().back().keys, altShift);
}

/**
 * @tc.name: EventManagerTest022
 * @tc.desc: Test DispatchAxisEventNG
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest022, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. AddKeyboardShortcutNode to eventManager
     */
    const int nodeIdCtrl = 10013;
    auto frameNodeCtrl = FrameNode::GetOrCreateFrameNode(CTRL, nodeIdCtrl, nullptr);
    frameNodeCtrl->SetActive(true);
    frameNodeCtrl->eventHub_->SetEnabled(true);
    const uint8_t ctrl = static_cast<uint8_t>(CtrlKeysBit::CTRL);
    frameNodeCtrl->eventHub_->SetKeyboardShortcut(CHARACTER_A, ctrl, []() {});
    eventManager->AddKeyboardShortcutNode(frameNodeCtrl);

    const int nodeIdAlt = 10014;
    auto frameNodeAlt = FrameNode::GetOrCreateFrameNode(ALT, nodeIdAlt, nullptr);
    frameNodeAlt->SetActive(true);
    frameNodeAlt->eventHub_->SetEnabled(true);
    const uint8_t alt = static_cast<uint8_t>(CtrlKeysBit::ALT);
    frameNodeAlt->eventHub_->SetKeyboardShortcut(CHARACTER_A, alt, []() {});
    eventManager->AddKeyboardShortcutNode(frameNodeAlt);

    const int nodeIdShift = 10015;
    auto frameNodeShift = FrameNode::GetOrCreateFrameNode(SHIFT, nodeIdShift, nullptr);
    frameNodeShift->SetActive(true);
    frameNodeShift->eventHub_->SetEnabled(true);
    const uint8_t shift = static_cast<uint8_t>(CtrlKeysBit::SHIFT);
    frameNodeShift->eventHub_->SetKeyboardShortcut(CHARACTER_A, shift, []() {});
    eventManager->AddKeyboardShortcutNode(frameNodeShift);

    /**
     * @tc.steps: step3. call DispatchKeyboardShortcut
     * @tc.expected: AddKeyboardShortcutSingleKey is called.
     */
    KeyEvent event;
    event.action = KeyAction::DOWN;
    eventManager->DispatchKeyboardShortcut(event);
    ASSERT_EQ(frameNodeCtrl->GetEventHub<NG::EventHub>()->GetKeyboardShortcut().back().keys, ctrl);
    ASSERT_EQ(frameNodeAlt->GetEventHub<NG::EventHub>()->GetKeyboardShortcut().back().keys, alt);
    ASSERT_EQ(frameNodeShift->GetEventHub<NG::EventHub>()->GetKeyboardShortcut().back().keys, shift);
}

/**
 * @tc.name: EventManagerTest023
 * @tc.desc: Test DispatchTouchEvent
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest023, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);
    AceEngine& aceEngine = AceEngine::Get();
    aceEngine.AddContainer(CONTAINER_INSTANCE_ID, MockContainer::container_);
    /**
     * @tc.steps: step2. Call DispatchTouchEvent with TouchType::DOWN and
                        touchTestResults_ empty;
     * @tc.expected: ret is false
     */
    TouchEvent event;
    event.type = TouchType::DOWN;
    auto ret = eventManager->DispatchTouchEvent(event);
    EXPECT_FALSE(ret);

    /**
     * @tc.steps: step3. Call DispatchTouchEvent with TouchType::DOWN and
                        touchTestResults_ has element;
     * @tc.expected: ret is true
     */
    TouchTestResult touchTestResults;
    auto eventTarget = AceType::MakeRefPtr<MockTouchEventTarget>();
    touchTestResults.push_back(eventTarget);
    eventManager->touchTestResults_.emplace(event.id, touchTestResults);
    ret = eventManager->DispatchTouchEvent(event);
    EXPECT_TRUE(ret);

    /**
     * @tc.steps: step4. Call DispatchTouchEvent with TouchType::UP and
                        touchTestResults_ has element;
     * @tc.expected: ret is true
     */
    event.type = TouchType::UP;
    ret = eventManager->DispatchTouchEvent(event);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: EventManagerTest024
 * @tc.desc: Test DispatchTouchEvent
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest024, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    auto currentHoverNodeId = ElementRegister::GetInstance()->MakeUniqueId();
    auto currentHoverNode = FrameNode::GetOrCreateFrameNode(CTRL, currentHoverNodeId, nullptr);
    eventManager->currHoverNode_ = currentHoverNode;
    auto lastHoverNodeId = ElementRegister::GetInstance()->MakeUniqueId();
    auto lastHoverNode = FrameNode::GetOrCreateFrameNode(SHIFT, lastHoverNodeId, nullptr);
    eventManager->lastHoverNode_ = lastHoverNode;

    /**
     * @tc.steps: step2. Call DispatchMouseHoverAnimationNG with MouseAction::PRESS;
     * @tc.expected: ret is false
     */
    MouseEvent event;
    event.button = MouseButton::NONE_BUTTON;
    event.action = MouseAction::PRESS;
    eventManager->DispatchMouseHoverAnimationNG(event);
    EXPECT_NE(eventManager->currHoverNode_.Upgrade(), nullptr);

    /**
     * @tc.steps: step3. Call DispatchMouseHoverAnimationNG with MouseAction::RELEASE;
     * @tc.expected: ret is false
     */
    event.action = MouseAction::RELEASE;
    eventManager->DispatchMouseHoverAnimationNG(event);
    EXPECT_NE(eventManager->currHoverNode_.Upgrade(), nullptr);

    /**
     * @tc.steps: step4. Call DispatchMouseHoverAnimationNG with MouseAction::MOVE;
     * @tc.expected: ret is false
     */
    event.action = MouseAction::MOVE;
    eventManager->DispatchMouseHoverAnimationNG(event);
    EXPECT_NE(eventManager->currHoverNode_.Upgrade(), nullptr);

    /**
     * @tc.steps: step5. Call DispatchMouseHoverAnimationNG with MouseAction::WINDOW_ENTER;
     * @tc.expected: ret is false
     */
    event.action = MouseAction::WINDOW_ENTER;
    eventManager->DispatchMouseHoverAnimationNG(event);
    EXPECT_NE(eventManager->currHoverNode_.Upgrade(), nullptr);

    /**
     * @tc.steps: step6. Call DispatchMouseHoverAnimationNG with MouseAction::WINDOW_LEAVE;
     * @tc.expected: ret is false
     */
    event.action = MouseAction::WINDOW_LEAVE;
    eventManager->DispatchMouseHoverAnimationNG(event);
    EXPECT_NE(eventManager->currHoverNode_.Upgrade(), nullptr);
}

/**
 * @tc.name: EventManagerTest025
 * @tc.desc: Test FlushTouchEventsBegin
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest025, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    auto resultId = ElementRegister::GetInstance()->MakeUniqueId();
    TouchTestResult touchTestResults;
    touchTestResults.push_back(AceType::MakeRefPtr<MockTouchEventTarget>());
    eventManager->touchTestResults_.emplace(resultId, touchTestResults);

    TouchEvent event {};
    event.id = resultId;
    std::list<TouchEvent> touchEvents { event };
    eventManager->FlushTouchEventsBegin(touchEvents);
    EXPECT_NE(eventManager->touchTestResults_.find(event.id), eventManager->touchTestResults_.end());
}

/**
 * @tc.name: EventManagerTest026
 * @tc.desc: Test FlushTouchEventsBegin
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest026, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    auto resultId = ElementRegister::GetInstance()->MakeUniqueId();
    TouchTestResult touchTestResults;
    touchTestResults.push_back(AceType::MakeRefPtr<MockTouchEventTarget>());
    eventManager->touchTestResults_.emplace(resultId, touchTestResults);

    TouchEvent event {};
    event.id = resultId;
    std::list<TouchEvent> touchEvents { event };
    eventManager->FlushTouchEventsEnd(touchEvents);
    EXPECT_NE(eventManager->touchTestResults_.find(event.id), eventManager->touchTestResults_.end());
}

/**
 * @tc.name: EventManagerTest027
 * @tc.desc: Test FlushTouchEventsBegin
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest027, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    AxisEvent axisEvent;
    axisEvent.x = 1;
    axisEvent.y = 2;
    axisEvent.sourceType = SourceType::TOUCH;
    auto nodeId = ElementRegister::GetInstance()->MakeUniqueId();
    auto frameNode = FrameNode::GetOrCreateFrameNode(V2::LOCATION_BUTTON_ETS_TAG, nodeId, nullptr);
    eventManager->AxisTest(axisEvent, frameNode);
    EXPECT_NE(frameNode, nullptr);
}

/**
 * @tc.name: EventManagerTest028
 * @tc.desc: Test DispatchTouchEvent:hoverNodeCur and hoverNodePre both null
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest028, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    eventManager->currHoverNode_ = FrameNode::GetOrCreateFrameNode(CTRL, 0, nullptr);
    eventManager->lastHoverNode_ = FrameNode::GetOrCreateFrameNode(CTRL, 0, nullptr);

    /**
     * @tc.steps: step2. Call DispatchMouseHoverAnimationNG with MouseAction::PRESS;
     * @tc.expected: ret is false
     */
    MouseEvent event;
    event.button = MouseButton::NONE_BUTTON;
    event.action = MouseAction::PRESS;
    eventManager->DispatchMouseHoverAnimationNG(event);
    EXPECT_EQ(eventManager->currHoverNode_.Upgrade(), nullptr);

    /**
     * @tc.steps: step3. Call DispatchMouseHoverAnimationNG with MouseAction::RELEASE;
     * @tc.expected: ret is false
     */
    event.action = MouseAction::RELEASE;
    eventManager->DispatchMouseHoverAnimationNG(event);
    EXPECT_EQ(eventManager->currHoverNode_.Upgrade(), nullptr);

    /**
     * @tc.steps: step4. Call DispatchMouseHoverAnimationNG with MouseAction::MOVE;
     * @tc.expected: ret is false
     */
    event.action = MouseAction::MOVE;
    eventManager->DispatchMouseHoverAnimationNG(event);
    EXPECT_EQ(eventManager->currHoverNode_.Upgrade(), nullptr);

    /**
     * @tc.steps: step5. Call DispatchMouseHoverAnimationNG with MouseAction::WINDOW_ENTER;
     * @tc.expected: ret is false
     */
    event.action = MouseAction::WINDOW_ENTER;
    eventManager->DispatchMouseHoverAnimationNG(event);
    EXPECT_EQ(eventManager->currHoverNode_.Upgrade(), nullptr);

    /**
     * @tc.steps: step6. Call DispatchMouseHoverAnimationNG with MouseAction::WINDOW_LEAVE;
     * @tc.expected: ret is false
     */
    event.action = MouseAction::WINDOW_LEAVE;
    eventManager->DispatchMouseHoverAnimationNG(event);
    EXPECT_EQ(eventManager->currHoverNode_.Upgrade(), nullptr);

    /**
     * @tc.steps: step6. Call DispatchMouseHoverAnimationNG with MouseAction::HOVER;
     * @tc.expected: ret is false
     */
    event.action = MouseAction::HOVER;
    eventManager->DispatchMouseHoverAnimationNG(event);
    EXPECT_EQ(eventManager->currHoverNode_.Upgrade(), nullptr);
}

/**
 * @tc.name: EventManagerTest029
 * @tc.desc: Test TouchTest
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest029, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    TouchEvent touchPoint;
    touchPoint.id = 100;
    touchPoint.type = TouchType::DOWN;

    TouchRestrict touchRestrict;
    Offset offset;

    /**
     * @tc.steps: step1. Create renderNode.
     * @tc.expected: renderNode is not null.
     */
    auto animatablePoperties = AceType::MakeRefPtr<OHOS::Ace::AnimatableProperties>();
    auto renderNode = AceType::DynamicCast<RenderNode>(animatablePoperties);

    /**
     * @tc.steps: step2. Call TouchTest with MouseAction::PRESS;
     * @tc.expected: ret is false
     */
    eventManager->TouchTest(touchPoint, renderNode, touchRestrict, offset, 0, true);
    auto findIt = eventManager->touchTestResults_.find(touchPoint.id);
    EXPECT_EQ(findIt, eventManager->touchTestResults_.end());
}

/**
 * @tc.name: EventManagerTest032
 * @tc.desc: Test DispatchAxisEvent
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest032, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    AxisEvent axisEvent;
    axisEvent.horizontalAxis = 0;
    axisEvent.verticalAxis = 0;
    axisEvent.pinchAxisScale = 1.0f;

    /**
     * @tc.steps: step2. Call AxisTest with SourceType::TOUCH.
     * @tc.expected: eventManager->axisNode_.Upgrade() is not null.
     */
    bool retFlag = eventManager->DispatchAxisEvent(axisEvent);
    ASSERT_TRUE(retFlag);
}

/**
 * @tc.name: EventManagerTest033
 * @tc.desc: Test DumpEvent
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest033, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. Call DumpEvent.
     * @tc.expected: eventManager->axisNode_.Upgrade() is not null.
     */
    eventManager->DumpEvent();
    std::list<std::pair<int32_t, std::string>> dumpList;
    eventManager->eventTree_.Dump(dumpList, 0);
    ASSERT_TRUE(dumpList.empty());
}

/**
 * @tc.name: EventManagerTest034
 * @tc.desc: Test DispatchMouseEvent
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest034, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. Call DispatchMouseEvent.
     * @tc.expected: retFlag is false.
     */
    MouseEvent event;
    event.action = MouseAction::PRESS;
    bool retFlag = eventManager->DispatchMouseEvent(event);
    ASSERT_TRUE(retFlag);
}

/**
 * @tc.name: EventManagerTest0351
 * @tc.desc: Test DispatchMouseHoverAnimation in MouseAction::PRESS branches
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest0351, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. Call DispatchMouseEvent.
     * @tc.expected: hoverNodeCur is not null.
     */
    MouseEvent event;
    event.action = MouseAction::PRESS;
    eventManager->DispatchMouseHoverAnimation(event);
    auto hoverNodeCur = eventManager->mouseHoverNode_.Upgrade();
    EXPECT_EQ(hoverNodeCur, nullptr);
}

/**
 * @tc.name: EventManagerTest0352
 * @tc.desc: Test DispatchMouseHoverAnimation in MouseAction::RELEASE branches
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest0352, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. Call DispatchMouseEvent.
     * @tc.expected: hoverNodeCur is not null.
     */
    MouseEvent event;
    event.action = MouseAction::RELEASE;
    eventManager->DispatchMouseHoverAnimation(event);
    auto hoverNodeCur = eventManager->mouseHoverNode_.Upgrade();
    EXPECT_EQ(hoverNodeCur, nullptr);
}

/**
 * @tc.name: EventManagerTest0353
 * @tc.desc: Test DispatchMouseHoverAnimation in MouseAction::WINDOW_ENTER branches
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest0353, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. Call DispatchMouseEvent.
     * @tc.expected: hoverNodeCur is not null.
     */
    MouseEvent event;
    event.action = MouseAction::WINDOW_ENTER;
    eventManager->DispatchMouseHoverAnimation(event);
    auto hoverNodeCur = eventManager->mouseHoverNode_.Upgrade();
    EXPECT_EQ(hoverNodeCur, nullptr);
}

/**
 * @tc.name: EventManagerTest0354
 * @tc.desc: Test DispatchMouseHoverAnimation in MouseAction::WINDOW_LEAVE branches
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest0354, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. Call DispatchMouseEvent.
     * @tc.expected: hoverNodeCur is not null.
     */
    MouseEvent event;
    event.action = MouseAction::WINDOW_LEAVE;
    eventManager->DispatchMouseHoverAnimation(event);
    auto hoverNodeCur = eventManager->mouseHoverNode_.Upgrade();
    EXPECT_EQ(hoverNodeCur, nullptr);
}

/**
 * @tc.name: EventManagerTest0355
 * @tc.desc: Test DispatchMouseHoverAnimation in MouseButton::NONE_BUTTON and MouseAction::MOVE branches
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest0355, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. Call DispatchMouseEvent.
     * @tc.expected: hoverNodeCur is not null.
     */
    MouseEvent event;
    event.button = MouseButton::NONE_BUTTON;
    event.action = MouseAction::MOVE;
    eventManager->DispatchMouseHoverAnimation(event);
    auto hoverNodeCur = eventManager->mouseHoverNode_.Upgrade();
    EXPECT_EQ(hoverNodeCur, nullptr);
}

/**
 * @tc.name: EventManagerTest0356
 * @tc.desc: Test DispatchMouseHoverAnimation in MouseAction::MOVE branches
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest0356, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. Call DispatchMouseEvent.
     * @tc.expected: hoverNodeCur is not null.
     */
    MouseEvent event;
    event.action = MouseAction::MOVE;
    eventManager->DispatchMouseHoverAnimation(event);
    auto hoverNodeCur = eventManager->mouseHoverNode_.Upgrade();
    EXPECT_EQ(hoverNodeCur, nullptr);
}

/**
 * @tc.name: EventManagerTest0357
 * @tc.desc: Test DispatchMouseHoverAnimation in MouseButton::NONE_BUTTON branches
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest0357, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. Call DispatchMouseEvent.
     * @tc.expected: hoverNodeCur is not null.
     */
    MouseEvent event;
    event.button = MouseButton::NONE_BUTTON;
    eventManager->DispatchMouseHoverAnimation(event);
    auto hoverNodeCur = eventManager->mouseHoverNode_.Upgrade();
    EXPECT_EQ(hoverNodeCur, nullptr);
}

/**
 * @tc.name: EventManagerTest036
 * @tc.desc: Test DispatchMouseHoverEvent
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest036, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. Call DispatchMouseHoverEvent.
     * @tc.expected: retFlag is true.
     */
    MouseEvent event;
    bool retFlag = eventManager->DispatchMouseHoverEvent(event);
    ASSERT_TRUE(retFlag);
}

/**
 * @tc.name: PanRecognizerAxisDirection001
 * @tc.desc: Test GetAxisDirection() of PanRecognizer.
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, PanRecognizerAxisDirection001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create pan recognizers.
     * @tc.expected: recognizers is not null and axis direction is correct.
     */
    auto panHorizontal = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::HORIZONTAL }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panHorizontal, nullptr);
    EXPECT_EQ(panHorizontal->GetAxisDirection(), Axis::HORIZONTAL);

    auto panVertical = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::VERTICAL }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panVertical, nullptr);
    EXPECT_EQ(panVertical->GetAxisDirection(), Axis::VERTICAL);

    auto panLeft = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::LEFT }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panLeft, nullptr);
    EXPECT_EQ(panLeft->GetAxisDirection(), Axis::HORIZONTAL);

    auto panRight = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::RIGHT }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panRight, nullptr);
    EXPECT_EQ(panRight->GetAxisDirection(), Axis::HORIZONTAL);

    auto panUp = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::UP }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panUp, nullptr);
    EXPECT_EQ(panUp->GetAxisDirection(), Axis::VERTICAL);

    auto panDown = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::DOWN }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panDown, nullptr);
    EXPECT_EQ(panDown->GetAxisDirection(), Axis::VERTICAL);

    auto panFree = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::ALL }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panFree, nullptr);
    EXPECT_EQ(panFree->GetAxisDirection(), Axis::FREE);
}

/**
 * @tc.name: SwipeRecognizerAxisDirection001
 * @tc.desc: Test GetAxisDirection() of SwipeRecognizer.
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, SwipeRecognizerAxisDirection001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create swipe recognizers.
     * @tc.expected: recognizers is not null and axis direction is correct.
     */
    auto swipeHorizontal = AceType::MakeRefPtr<SwipeRecognizer>(1, SwipeDirection { SwipeDirection::HORIZONTAL }, 0.0);
    ASSERT_NE(swipeHorizontal, nullptr);
    EXPECT_EQ(swipeHorizontal->GetAxisDirection(), Axis::HORIZONTAL);

    auto swipeVertical = AceType::MakeRefPtr<SwipeRecognizer>(1, SwipeDirection { SwipeDirection::VERTICAL }, 0.0);
    ASSERT_NE(swipeVertical, nullptr);
    EXPECT_EQ(swipeVertical->GetAxisDirection(), Axis::VERTICAL);

    auto swipeFree = AceType::MakeRefPtr<SwipeRecognizer>(1, SwipeDirection { SwipeDirection::ALL }, 0.0);
    ASSERT_NE(swipeFree, nullptr);
    EXPECT_EQ(swipeFree->GetAxisDirection(), Axis::FREE);
}

/**
 * @tc.name: ExclusiveRecognizerAxisDirection001
 * @tc.desc: Test GetAxisDirection() of ExclusiveRecognizer.
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, ExclusiveRecognizerAxisDirection001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create pan recognizers.
     * @tc.expected: recognizers is not null and axis direction is correct.
     */
    auto panHorizontal1 = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::HORIZONTAL }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panHorizontal1, nullptr);
    auto panHorizontal2 = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::HORIZONTAL }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panHorizontal2, nullptr);

    auto panVertical1 = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::VERTICAL }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panVertical1, nullptr);
    auto panVertical2 = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::VERTICAL }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panVertical2, nullptr);

    auto panFree1 = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::ALL }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panFree1, nullptr);
    auto panFree2 = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::ALL }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panFree2, nullptr);

    /**
     * @tc.steps: step2. Create exclusive recognizers.
     * @tc.expected: recognizers is not null and axis direction is correct.
     */
    std::vector<RefPtr<NGGestureRecognizer>> recognizers;
    recognizers.clear();
    recognizers.emplace_back(panHorizontal1);
    recognizers.emplace_back(panHorizontal2);
    auto exclusiveDoubleHorizontal = AceType::MakeRefPtr<ExclusiveRecognizer>(recognizers);
    ASSERT_NE(exclusiveDoubleHorizontal, nullptr);
    EXPECT_EQ(exclusiveDoubleHorizontal->GetAxisDirection(), Axis::HORIZONTAL);

    recognizers.clear();
    recognizers.emplace_back(panVertical1);
    recognizers.emplace_back(panVertical2);
    auto exclusiveDoubleVertical = AceType::MakeRefPtr<ExclusiveRecognizer>(recognizers);
    ASSERT_NE(exclusiveDoubleVertical, nullptr);
    EXPECT_EQ(exclusiveDoubleVertical->GetAxisDirection(), Axis::VERTICAL);

    recognizers.clear();
    recognizers.emplace_back(panFree1);
    recognizers.emplace_back(panFree2);
    auto exclusiveDoubleFree = AceType::MakeRefPtr<ExclusiveRecognizer>(recognizers);
    ASSERT_NE(exclusiveDoubleFree, nullptr);
    EXPECT_EQ(exclusiveDoubleFree->GetAxisDirection(), Axis::FREE);

    recognizers.clear();
    recognizers.emplace_back(panHorizontal1);
    recognizers.emplace_back(panVertical1);
    auto exclusiveHorizontalVertical = AceType::MakeRefPtr<ExclusiveRecognizer>(recognizers);
    ASSERT_NE(exclusiveHorizontalVertical, nullptr);
    EXPECT_EQ(exclusiveHorizontalVertical->GetAxisDirection(), Axis::FREE);

    recognizers.clear();
    recognizers.emplace_back(panHorizontal1);
    recognizers.emplace_back(panFree1);
    auto exclusiveHorizontalFree = AceType::MakeRefPtr<ExclusiveRecognizer>(recognizers);
    ASSERT_NE(exclusiveHorizontalFree, nullptr);
    EXPECT_EQ(exclusiveHorizontalFree->GetAxisDirection(), Axis::FREE);

    recognizers.clear();
    recognizers.emplace_back(panVertical1);
    recognizers.emplace_back(panFree1);
    auto exclusiveVerticalFree = AceType::MakeRefPtr<ExclusiveRecognizer>(recognizers);
    ASSERT_NE(exclusiveVerticalFree, nullptr);
    EXPECT_EQ(exclusiveVerticalFree->GetAxisDirection(), Axis::FREE);
}

/**
 * @tc.name: ParallelRecognizerAxisDirection001
 * @tc.desc: Test GetAxisDirection() of ParallelRecognizer.
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, ParallelRecognizerAxisDirection001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create pan recognizers.
     * @tc.expected: recognizers is not null and axis direction is correct.
     */
    auto panHorizontal1 = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::HORIZONTAL }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panHorizontal1, nullptr);
    auto panHorizontal2 = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::HORIZONTAL }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panHorizontal2, nullptr);

    auto panVertical1 = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::VERTICAL }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panVertical1, nullptr);
    auto panVertical2 = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::VERTICAL }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panVertical2, nullptr);

    auto panFree1 = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::ALL }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panFree1, nullptr);
    auto panFree2 = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::ALL }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panFree2, nullptr);

    /**
     * @tc.steps: step2. Create parallel recognizers.
     * @tc.expected: recognizers is not null and axis direction is correct.
     */
    std::vector<RefPtr<NGGestureRecognizer>> recognizers;
    recognizers.clear();
    recognizers.emplace_back(panHorizontal1);
    recognizers.emplace_back(panHorizontal2);
    auto parallelDoubleHorizontal = AceType::MakeRefPtr<ParallelRecognizer>(recognizers);
    ASSERT_NE(parallelDoubleHorizontal, nullptr);
    EXPECT_EQ(parallelDoubleHorizontal->GetAxisDirection(), Axis::HORIZONTAL);

    recognizers.clear();
    recognizers.emplace_back(panVertical1);
    recognizers.emplace_back(panVertical2);
    auto parallelDoubleVertical = AceType::MakeRefPtr<ParallelRecognizer>(recognizers);
    ASSERT_NE(parallelDoubleVertical, nullptr);
    EXPECT_EQ(parallelDoubleVertical->GetAxisDirection(), Axis::VERTICAL);

    recognizers.clear();
    recognizers.emplace_back(panFree1);
    recognizers.emplace_back(panFree2);
    auto parallelDoubleFree = AceType::MakeRefPtr<ParallelRecognizer>(recognizers);
    ASSERT_NE(parallelDoubleFree, nullptr);
    EXPECT_EQ(parallelDoubleFree->GetAxisDirection(), Axis::FREE);

    recognizers.clear();
    recognizers.emplace_back(panHorizontal1);
    recognizers.emplace_back(panVertical1);
    auto parallelHorizontalVertical = AceType::MakeRefPtr<ParallelRecognizer>(recognizers);
    ASSERT_NE(parallelHorizontalVertical, nullptr);
    EXPECT_EQ(parallelHorizontalVertical->GetAxisDirection(), Axis::FREE);

    recognizers.clear();
    recognizers.emplace_back(panHorizontal1);
    recognizers.emplace_back(panFree1);
    auto parallelHorizontalFree = AceType::MakeRefPtr<ParallelRecognizer>(recognizers);
    ASSERT_NE(parallelHorizontalFree, nullptr);
    EXPECT_EQ(parallelHorizontalFree->GetAxisDirection(), Axis::FREE);

    recognizers.clear();
    recognizers.emplace_back(panVertical1);
    recognizers.emplace_back(panFree1);
    auto parallelVerticalFree = AceType::MakeRefPtr<ParallelRecognizer>(recognizers);
    ASSERT_NE(parallelVerticalFree, nullptr);
    EXPECT_EQ(parallelVerticalFree->GetAxisDirection(), Axis::FREE);
}

/**
 * @tc.name: SequenceRecognizerAxisDirection001
 * @tc.desc: Test GetAxisDirection() of SequenceRecognizer.
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, SequenceRecognizerAxisDirection001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create pan recognizers.
     * @tc.expected: recognizers is not null and axis direction is correct.
     */
    auto panHorizontal1 = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::HORIZONTAL }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panHorizontal1, nullptr);
    auto panHorizontal2 = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::HORIZONTAL }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panHorizontal2, nullptr);

    auto panVertical1 = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::VERTICAL }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panVertical1, nullptr);
    auto panVertical2 = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::VERTICAL }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panVertical2, nullptr);

    auto panFree1 = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::ALL }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panFree1, nullptr);
    auto panFree2 = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::ALL }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panFree2, nullptr);

    /**
     * @tc.steps: step2. Create sequence recognizers.
     * @tc.expected: recognizers is not null and axis direction is correct.
     */
    std::vector<RefPtr<NGGestureRecognizer>> recognizers;
    recognizers.clear();
    recognizers.emplace_back(panHorizontal1);
    recognizers.emplace_back(panHorizontal2);
    auto sequenceDoubleHorizontal = AceType::MakeRefPtr<SequencedRecognizer>(recognizers);
    ASSERT_NE(sequenceDoubleHorizontal, nullptr);
    EXPECT_EQ(sequenceDoubleHorizontal->GetAxisDirection(), Axis::HORIZONTAL);

    recognizers.clear();
    recognizers.emplace_back(panVertical1);
    recognizers.emplace_back(panVertical2);
    auto sequenceDoubleVertical = AceType::MakeRefPtr<SequencedRecognizer>(recognizers);
    ASSERT_NE(sequenceDoubleVertical, nullptr);
    EXPECT_EQ(sequenceDoubleVertical->GetAxisDirection(), Axis::VERTICAL);

    recognizers.clear();
    recognizers.emplace_back(panFree1);
    recognizers.emplace_back(panFree2);
    auto sequenceDoubleFree = AceType::MakeRefPtr<SequencedRecognizer>(recognizers);
    ASSERT_NE(sequenceDoubleFree, nullptr);
    EXPECT_EQ(sequenceDoubleFree->GetAxisDirection(), Axis::FREE);

    recognizers.clear();
    recognizers.emplace_back(panHorizontal1);
    recognizers.emplace_back(panVertical1);
    auto sequenceHorizontalVertical = AceType::MakeRefPtr<SequencedRecognizer>(recognizers);
    ASSERT_NE(sequenceHorizontalVertical, nullptr);
    EXPECT_EQ(sequenceHorizontalVertical->GetAxisDirection(), Axis::FREE);

    recognizers.clear();
    recognizers.emplace_back(panHorizontal1);
    recognizers.emplace_back(panFree1);
    auto sequenceHorizontalFree = AceType::MakeRefPtr<SequencedRecognizer>(recognizers);
    ASSERT_NE(sequenceHorizontalFree, nullptr);
    EXPECT_EQ(sequenceHorizontalFree->GetAxisDirection(), Axis::FREE);

    recognizers.clear();
    recognizers.emplace_back(panVertical1);
    recognizers.emplace_back(panFree1);
    auto sequenceVerticalFree = AceType::MakeRefPtr<SequencedRecognizer>(recognizers);
    ASSERT_NE(sequenceVerticalFree, nullptr);
    EXPECT_EQ(sequenceVerticalFree->GetAxisDirection(), Axis::FREE);
}

/**
 * @tc.name: HasDifferentDirectionGesture001
 * @tc.desc: Test HasDifferentDirectionGesture() of EventManager.
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, HasDifferentDirectionGesture001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create pan recognizers.
     * @tc.expected: recognizers is not null and axis direction is correct.
     */
    auto panHorizontal1 = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::HORIZONTAL }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panHorizontal1, nullptr);
    auto panHorizontal2 = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::HORIZONTAL }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panHorizontal2, nullptr);

    auto panVertical1 = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::VERTICAL }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panVertical1, nullptr);
    auto panVertical2 = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::VERTICAL }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panVertical2, nullptr);

    auto panFree1 = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::ALL }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panFree1, nullptr);
    auto panFree2 = AceType::MakeRefPtr<PanRecognizer>(
        DEFAULT_PAN_FINGER, PanDirection { PanDirection::ALL }, DEFAULT_PAN_DISTANCE.ConvertToPx());
    ASSERT_NE(panFree2, nullptr);

    /**
     * @tc.steps: step2. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);
    TouchTestResult hitTestResult;

    /**
     * @tc.steps: step3. Add 2 horizontal recognizer to axisTouchTestResults_
     * @tc.expected: axisTouchTestResults_->HasDifferentDirectionGesture() is false.
     */
    hitTestResult.clear();
    eventManager->axisTouchTestResults_.clear();
    hitTestResult.emplace_back(panHorizontal1);
    hitTestResult.emplace_back(panHorizontal2);
    eventManager->axisTouchTestResults_[MOUSE_BASE_ID] = std::move(hitTestResult);
    EXPECT_FALSE(eventManager->HasDifferentDirectionGesture());

    /**
     * @tc.steps: step4. Add 2 vertical recognizer to axisTouchTestResults_
     * @tc.expected: axisTouchTestResults_->HasDifferentDirectionGesture() is false.
     */
    hitTestResult.clear();
    eventManager->axisTouchTestResults_.clear();
    hitTestResult.emplace_back(panVertical1);
    hitTestResult.emplace_back(panVertical2);
    eventManager->axisTouchTestResults_[MOUSE_BASE_ID] = std::move(hitTestResult);
    EXPECT_FALSE(eventManager->HasDifferentDirectionGesture());

    /**
     * @tc.steps: step5. Add horizontal and vertical recognizer to axisTouchTestResults_
     * @tc.expected: axisTouchTestResults_->HasDifferentDirectionGesture() is true.
     */
    hitTestResult.clear();
    eventManager->axisTouchTestResults_.clear();
    hitTestResult.emplace_back(panHorizontal1);
    hitTestResult.emplace_back(panVertical1);
    eventManager->axisTouchTestResults_[MOUSE_BASE_ID] = std::move(hitTestResult);
    EXPECT_TRUE(eventManager->HasDifferentDirectionGesture());

    /**
     * @tc.steps: step6. Add horizontal and free recognizer to axisTouchTestResults_
     * @tc.expected: axisTouchTestResults_->HasDifferentDirectionGesture() is true.
     */
    hitTestResult.clear();
    eventManager->axisTouchTestResults_.clear();
    hitTestResult.emplace_back(panHorizontal1);
    hitTestResult.emplace_back(panFree1);
    eventManager->axisTouchTestResults_[MOUSE_BASE_ID] = std::move(hitTestResult);
    EXPECT_TRUE(eventManager->HasDifferentDirectionGesture());

    /**
     * @tc.steps: step6. Add vertical and free recognizer to axisTouchTestResults_
     * @tc.expected: axisTouchTestResults_->HasDifferentDirectionGesture() is true.
     */
    hitTestResult.clear();
    eventManager->axisTouchTestResults_.clear();
    hitTestResult.emplace_back(panVertical1);
    hitTestResult.emplace_back(panFree1);
    eventManager->axisTouchTestResults_[MOUSE_BASE_ID] = std::move(hitTestResult);
    EXPECT_TRUE(eventManager->HasDifferentDirectionGesture());

    /**
     * @tc.steps: step6. Add free and free recognizer to axisTouchTestResults_
     * @tc.expected: axisTouchTestResults_->HasDifferentDirectionGesture() is true.
     */
    hitTestResult.clear();
    eventManager->axisTouchTestResults_.clear();
    hitTestResult.emplace_back(panFree1);
    hitTestResult.emplace_back(panFree2);
    eventManager->axisTouchTestResults_[MOUSE_BASE_ID] = std::move(hitTestResult);
    EXPECT_TRUE(eventManager->HasDifferentDirectionGesture());
}

/**
 * @tc.name: EventManagerTest038
 * @tc.desc: Test DispatchRotationEvent
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest038, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. Call DispatchRotationEvent.
     * @tc.expected: ret is false.
     */
    RotationEvent event;
    event.value = 0.1;
    auto animatablePoperties = AceType::MakeRefPtr<OHOS::Ace::AnimatableProperties>();
    auto renderNode = AceType::DynamicCast<RenderNode>(animatablePoperties);
    const RefPtr<RenderNode> requestNode = nullptr;
    auto ret = eventManager->DispatchRotationEvent(event, renderNode, requestNode);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: EventManagerTest039
 * @tc.desc: Test PostEventDispatchTouchEvent
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest039, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);
    AceEngine& aceEngine = AceEngine::Get();
    aceEngine.AddContainer(CONTAINER_INSTANCE_ID, MockContainer::container_);

    /**
     * @tc.steps: step2. Call PostEventDispatchTouchEvent with event.
     * @tc.expected: ret is true
     */
    TouchEvent event;
    event.type = TouchType::DOWN;
    TouchTestResult touchTestResults;
    auto eventTarget = AceType::MakeRefPtr<MockTouchEventTarget>();
    touchTestResults.push_back(eventTarget);
    eventManager->postEventTouchTestResults_.emplace(event.id, touchTestResults);
    auto ret = eventManager->PostEventDispatchTouchEvent(event);
    EXPECT_TRUE(ret);

    /**
    * @tc.steps: step3. Call PostEventDispatchTouchEvent event.
    * @tc.expected: ret is true
    */
    event.type = TouchType::UP;
    touchTestResults.push_back(eventTarget);
    eventManager->postEventTouchTestResults_.emplace(event.id, touchTestResults);
    ret = eventManager->PostEventDispatchTouchEvent(event);
    EXPECT_TRUE(ret);

    /**
    * @tc.steps: step4. Call PostEventDispatchTouchEvent event.
    * @tc.expected: ret is true
    */
    event.type = TouchType::CANCEL;
    touchTestResults.push_back(eventTarget);
    eventManager->postEventTouchTestResults_.emplace(event.id, touchTestResults);
    ret = eventManager->PostEventDispatchTouchEvent(event);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: EventManagerTest040
 * @tc.desc: Test DispatchMouseEvent
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest040, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. Call DispatchMouseEvent.
     * @tc.expected: retFlag is true.
     */
    MouseEvent event;
    event.action = MouseAction::MOVE;
    bool retFlag = eventManager->DispatchMouseEvent(event);
    ASSERT_TRUE(retFlag);
}

/**
 * @tc.name: EventManagerTest041
 * @tc.desc: Test HandleGlobalEventNG
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest041, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. Create FrameNode and Call TouchTest to add touchTestResults_[touchPoint.id].
     * @tc.expected: touchTestResults_ has the touchPoint.id of instance.
     */
    TouchEvent touchPoint;
    touchPoint.id = 1000;
    touchPoint.type = TouchType::DOWN;

    const int nodeId = 10003;
    auto frameNode = FrameNode::GetOrCreateFrameNode(V2::LOCATION_BUTTON_ETS_TAG, nodeId, nullptr);
    TouchRestrict touchRestrict;
    Offset offset;

    eventManager->TouchTest(touchPoint, frameNode, touchRestrict, offset, 0, true);
    EXPECT_GT(eventManager->touchTestResults_.count(touchPoint.id), 0);
    TouchTestResult touchTestResults;
    auto eventTarget = AceType::MakeRefPtr<MockTouchEventTarget>();
    touchTestResults.push_back(eventTarget);
    eventManager->touchTestResults_.emplace(touchPoint.id, touchTestResults);

    /**
     * @tc.steps: step3. Create FrameNode and Call HandleGlobalEventNG.
     * @tc.expected: touchTestResults_.size() is equal to 1.
     */
    auto selectOverlayManager = AceType::MakeRefPtr<SelectOverlayManager>(frameNode);
    NG::OffsetF rootOffset;
    eventManager->HandleGlobalEventNG(touchPoint, selectOverlayManager, rootOffset);
    EXPECT_EQ(eventManager->touchTestResults_.size(), 1);
}

/**
 * @tc.name: EventManagerTest042
 * @tc.desc: Test DispatchMouseHoverAnimation in MouseButton::NONE_BUTTON branches
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest042, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);

    /**
     * @tc.steps: step2. Call DispatchMouseHoverAnimation with event.
     * @tc.expected: hoverNodeCur is null.
     */
    MouseEvent event;
    event.button = MouseButton::NONE_BUTTON;
    eventManager->DispatchMouseHoverAnimation(event);
    auto hoverNodeCur = eventManager->mouseHoverNode_.Upgrade();
    EXPECT_EQ(hoverNodeCur, nullptr);
}

/**
 * @tc.name: EventManagerTest043
 * @tc.desc: Test DispatchTouchEvent
 * @tc.type: FUNC
 */
HWTEST_F(EventManagerTestNg, EventManagerTest043, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create EventManager.
     * @tc.expected: eventManager is not null.
     */
    auto eventManager = AceType::MakeRefPtr<EventManager>();
    ASSERT_NE(eventManager, nullptr);
    AceEngine& aceEngine = AceEngine::Get();
    aceEngine.AddContainer(CONTAINER_INSTANCE_ID, MockContainer::container_);

    /**
     * @tc.steps: step2. Call DispatchTouchEvent with TouchType::DOWN.
     * @tc.expected: ret is false.
     */
    TouchEvent event;
    event.type = TouchType::DOWN;
    auto ret = eventManager->DispatchTouchEvent(event);
    EXPECT_FALSE(ret);

    /**
     * @tc.steps: step3. Call DispatchTouchEvent with TouchType::DOWN and
                        touchTestResults_ has element;
     * @tc.expected: ret is true
     */
    TouchTestResult touchTestResults;
    auto eventTarget = AceType::MakeRefPtr<MockTouchEventTarget>();
    touchTestResults.push_back(eventTarget);
    eventManager->touchTestResults_.emplace(event.id, touchTestResults);
    ret = eventManager->DispatchTouchEvent(event);
    EXPECT_TRUE(ret);

    /**
     * @tc.steps: step4. Call DispatchTouchEvent with TouchType::PULL_MOVE and
                        touchTestResults_ has element;
     * @tc.expected: ret is true
     */
    event.type = TouchType::PULL_MOVE;
    ret = eventManager->DispatchTouchEvent(event);
    EXPECT_TRUE(ret);

    /**
     * @tc.steps: step5. Call DispatchTouchEvent with TouchType::PULL_MOVE and
                        touchTestResults_ has element;
     * @tc.expected: ret is false.
     */
    event.pullType = TouchType::PULL_MOVE;
    ret = eventManager->DispatchTouchEvent(event);
    EXPECT_FALSE(ret);
}
} // namespace OHOS::Ace::NG

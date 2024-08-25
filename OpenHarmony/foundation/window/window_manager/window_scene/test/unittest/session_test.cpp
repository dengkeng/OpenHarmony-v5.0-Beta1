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

#include <gtest/gtest.h>
#include <regex>
#include <pointer_event.h>
#include <ui/rs_surface_node.h>

#include "mock/mock_session_stage.h"
#include "mock/mock_window_event_channel.h"
#include "mock/mock_pattern_detach_callback.h"
#include "session/host/include/extension_session.h"
#include "session/host/include/move_drag_controller.h"
#include "session/host/include/scene_session.h"
#include "session_manager/include/scene_session_manager.h"
#include "session/host/include/session.h"
#include "session_info.h"
#include "key_event.h"
#include "wm_common.h"
#include "window_manager_hilog.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
namespace {
const std::string UNDEFINED = "undefined";
constexpr HiviewDFX::HiLogLabel LABEL = {LOG_CORE, HILOG_DOMAIN_WINDOW, "WindowSessionTest"};
}

class TestWindowEventChannel : public IWindowEventChannel {
public:
    WSError TransferKeyEvent(const std::shared_ptr<MMI::KeyEvent>& keyEvent) override;
    WSError TransferPointerEvent(const std::shared_ptr<MMI::PointerEvent>& pointerEvent) override;
    WSError TransferFocusActiveEvent(bool isFocusActive) override;
    WSError TransferKeyEventForConsumed(const std::shared_ptr<MMI::KeyEvent>& keyEvent, bool& isConsumed,
        bool isPreImeEvent = false) override;
    WSError TransferKeyEventForConsumedAsync(const std::shared_ptr<MMI::KeyEvent>& keyEvent, bool isPreImeEvent,
        const sptr<IRemoteObject>& listener) override;
    WSError TransferFocusState(bool focusState) override;
    WSError TransferBackpressedEventForConsumed(bool& isConsumed) override;
    WSError TransferSearchElementInfo(int64_t elementId, int32_t mode, int64_t baseParent,
        std::list<Accessibility::AccessibilityElementInfo>& infos) override;
    WSError TransferSearchElementInfosByText(int64_t elementId, const std::string& text, int64_t baseParent,
        std::list<Accessibility::AccessibilityElementInfo>& infos) override;
    WSError TransferFindFocusedElementInfo(int64_t elementId, int32_t focusType, int64_t baseParent,
        Accessibility::AccessibilityElementInfo& info) override;
    WSError TransferFocusMoveSearch(int64_t elementId, int32_t direction, int64_t baseParent,
        Accessibility::AccessibilityElementInfo& info) override;
    WSError TransferExecuteAction(int64_t elementId, const std::map<std::string, std::string>& actionArguments,
        int32_t action, int64_t baseParent) override;
    WSError TransferAccessibilityHoverEvent(float pointX, float pointY, int32_t sourceType, int32_t eventType,
        int64_t timeMs) override;

    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    };
};

WSError TestWindowEventChannel::TransferKeyEvent(const std::shared_ptr<MMI::KeyEvent>& keyEvent)
{
    return WSError::WS_OK;
}

WSError TestWindowEventChannel::TransferPointerEvent(const std::shared_ptr<MMI::PointerEvent>& pointerEvent)
{
    return WSError::WS_OK;
}

WSError TestWindowEventChannel::TransferFocusActiveEvent(bool isFocusActive)
{
    return WSError::WS_OK;
}

WSError TestWindowEventChannel::TransferKeyEventForConsumed(
    const std::shared_ptr<MMI::KeyEvent>& keyEvent, bool& isConsumed, bool isPreImeEvent)
{
    return WSError::WS_OK;
}

WSError TestWindowEventChannel::TransferKeyEventForConsumedAsync(const std::shared_ptr<MMI::KeyEvent>& keyEvent,
    bool isPreImeEvent, const sptr<IRemoteObject>& listener)
{
    return WSError::WS_OK;
}

WSError TestWindowEventChannel::TransferFocusState(bool foucsState)
{
    return WSError::WS_OK;
}

WSError TestWindowEventChannel::TransferBackpressedEventForConsumed(bool& isConsumed)
{
    return WSError::WS_OK;
}

WSError TestWindowEventChannel::TransferSearchElementInfo(int64_t elementId, int32_t mode, int64_t baseParent,
    std::list<Accessibility::AccessibilityElementInfo>& infos)
{
    return WSError::WS_OK;
}

WSError TestWindowEventChannel::TransferSearchElementInfosByText(int64_t elementId, const std::string& text,
    int64_t baseParent, std::list<Accessibility::AccessibilityElementInfo>& infos)
{
    return WSError::WS_OK;
}

WSError TestWindowEventChannel::TransferFindFocusedElementInfo(int64_t elementId, int32_t focusType, int64_t baseParent,
    Accessibility::AccessibilityElementInfo& info)
{
    return WSError::WS_OK;
}

WSError TestWindowEventChannel::TransferFocusMoveSearch(int64_t elementId, int32_t direction, int64_t baseParent,
    Accessibility::AccessibilityElementInfo& info)
{
    return WSError::WS_OK;
}

WSError TestWindowEventChannel::TransferExecuteAction(int64_t elementId,
    const std::map<std::string, std::string>& actionArguments, int32_t action, int64_t baseParent)
{
    return WSError::WS_OK;
}

WSError TestWindowEventChannel::TransferAccessibilityHoverEvent(float pointX, float pointY, int32_t sourceType,
    int32_t eventType, int64_t timeMs)
{
    return WSError::WS_OK;
}

class WindowSessionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    WSError TransferSearchElementInfo(bool isChannelNull);
    WSError TransferSearchElementInfosByText(bool isChannelNull);
    WSError TransferFindFocusedElementInfo(bool isChannelNull);
    WSError TransferFocusMoveSearch(bool isChannelNull);
    WSError TransferExecuteAction(bool isChannelNull);
    int32_t GetTaskCount();
    sptr<SceneSessionManager> ssm_;

private:
    RSSurfaceNode::SharedPtr CreateRSSurfaceNode();
    sptr<Session> session_ = nullptr;
};

void WindowSessionTest::SetUpTestCase()
{
}

void WindowSessionTest::TearDownTestCase()
{
}

void WindowSessionTest::SetUp()
{
    SessionInfo info;
    info.abilityName_ = "testSession1";
    info.moduleName_ = "testSession2";
    info.bundleName_ = "testSession3";
    session_ = new (std::nothrow) Session(info);
    session_->surfaceNode_ = CreateRSSurfaceNode();
    EXPECT_NE(nullptr, session_);
    ssm_ = new SceneSessionManager();
    session_->SetEventHandler(ssm_->taskScheduler_->GetEventHandler(), ssm_->eventHandler_);
    auto isScreenLockedCallback = [this]() {
        return ssm_->IsScreenLocked();
    };
    session_->RegisterIsScreenLockedCallback(isScreenLockedCallback);
}

void WindowSessionTest::TearDown()
{
    session_ = nullptr;
}

RSSurfaceNode::SharedPtr WindowSessionTest::CreateRSSurfaceNode()
{
    struct RSSurfaceNodeConfig rsSurfaceNodeConfig;
    rsSurfaceNodeConfig.SurfaceNodeName = "WindowSessionTestSurfaceNode";
    auto surfaceNode = RSSurfaceNode::Create(rsSurfaceNodeConfig);
    return surfaceNode;
}


WSError WindowSessionTest::TransferSearchElementInfo(bool isChannelNull)
{
    int64_t elementId = 0;
    int32_t mode = 0;
    int64_t baseParent = 0;
    std::list<Accessibility::AccessibilityElementInfo> infos;
    if (isChannelNull) {
        return session_->TransferSearchElementInfo(elementId, mode, baseParent, infos);
    } else {
        session_->windowEventChannel_ = new TestWindowEventChannel();
        return session_->TransferSearchElementInfo(elementId, mode, baseParent, infos);
    }
}

WSError WindowSessionTest::TransferSearchElementInfosByText(bool isChannelNull)
{
    int64_t elementId = 0;
    std::string text;
    int64_t baseParent = 0;
    std::list<Accessibility::AccessibilityElementInfo> infos;
    if (isChannelNull) {
        return session_->TransferSearchElementInfosByText(elementId, text, baseParent, infos);
    } else {
        session_->windowEventChannel_ = new TestWindowEventChannel();
        return session_->TransferSearchElementInfosByText(elementId, text, baseParent, infos);
    }
}

WSError WindowSessionTest::TransferFindFocusedElementInfo(bool isChannelNull)
{
    int64_t elementId = 0;
    int32_t focusType = 0;
    int64_t baseParent = 0;
    Accessibility::AccessibilityElementInfo info;
    if (isChannelNull) {
        return session_->TransferFindFocusedElementInfo(elementId, focusType, baseParent, info);
    } else {
        session_->windowEventChannel_ = new TestWindowEventChannel();
        return session_->TransferFindFocusedElementInfo(elementId, focusType, baseParent, info);
    }
}

WSError WindowSessionTest::TransferFocusMoveSearch(bool isChannelNull)
{
    int64_t elementId = 0;
    int32_t direction = 0;
    int64_t baseParent = 0;
    Accessibility::AccessibilityElementInfo info;
    if (isChannelNull) {
        return session_->TransferFocusMoveSearch(elementId, direction, baseParent, info);
    } else {
        session_->windowEventChannel_ = new TestWindowEventChannel();
        return session_->TransferFocusMoveSearch(elementId, direction, baseParent, info);
    }
}

WSError WindowSessionTest::TransferExecuteAction(bool isChannelNull)
{
    int64_t elementId = 0;
    std::map<std::string, std::string> actionArguments;
    int32_t action = 0;
    int64_t baseParent = 0;
    if (isChannelNull) {
        return session_->TransferExecuteAction(elementId, actionArguments, action, baseParent);
    } else {
        session_->windowEventChannel_ = new TestWindowEventChannel();
        return session_->TransferExecuteAction(elementId, actionArguments, action, baseParent);
    }
}

int32_t WindowSessionTest::GetTaskCount()
{
    std::string dumpInfo = session_->handler_->GetEventRunner()->GetEventQueue()->DumpCurrentQueueSize();
    std::regex pattern("\\d+");
    std::smatch matches;
    int32_t taskNum = 0;
    while (std::regex_search(dumpInfo, matches, pattern)) {
        taskNum += std::stoi(matches.str());
        dumpInfo = matches.suffix();
    }
    return taskNum;
}

namespace {
/**
 * @tc.name: TransferSearchElementInfo01
 * @tc.desc: windowEventChannel_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferSearchElementInfo01, Function | SmallTest | Level2)
{
    WLOGFI("TransferSearchElementInfo01 begin!");
    ASSERT_NE(session_, nullptr);
    ASSERT_EQ(WSError::WS_OK, TransferSearchElementInfo(false));
    WLOGFI("TransferSearchElementInfo01 end!");
}

/**
 * @tc.name: TransferSearchElementInfo02
 * @tc.desc: windowEventChannel_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferSearchElementInfo02, Function | SmallTest | Level2)
{
    WLOGFI("TransferSearchElementInfo02 begin!");
    ASSERT_NE(session_, nullptr);
    ASSERT_EQ(WSError::WS_ERROR_NULLPTR, TransferSearchElementInfo(true));
    WLOGFI("TransferSearchElementInfo02 end!");
}

/**
 * @tc.name: TransferSearchElementInfosByText01
 * @tc.desc: windowEventChannel_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferSearchElementInfosByText01, Function | SmallTest | Level2)
{
    WLOGFI("TransferSearchElementInfosByText01 begin!");
    ASSERT_NE(session_, nullptr);
    ASSERT_EQ(WSError::WS_OK, TransferSearchElementInfosByText(false));
    WLOGFI("TransferSearchElementInfosByText01 end!");
}

/**
 * @tc.name: TransferSearchElementInfosByText02
 * @tc.desc: windowEventChannel_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferSearchElementInfosByText02, Function | SmallTest | Level2)
{
    WLOGFI("TransferSearchElementInfosByText02 begin!");
    ASSERT_NE(session_, nullptr);
    ASSERT_EQ(WSError::WS_ERROR_NULLPTR, TransferSearchElementInfosByText(true));
    WLOGFI("TransferSearchElementInfosByText02 end!");
}

/**
 * @tc.name: TransferFindFocusedElementInfo01
 * @tc.desc: windowEventChannel_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferFindFocusedElementInfo01, Function | SmallTest | Level2)
{
    WLOGFI("TransferFindFocusedElementInfo01 begin!");
    ASSERT_NE(session_, nullptr);
    ASSERT_EQ(WSError::WS_OK, TransferFindFocusedElementInfo(false));
    WLOGFI("TransferFindFocusedElementInfo01 end!");
}

/**
 * @tc.name: TransferFindFocusedElementInfo02
 * @tc.desc: windowEventChannel_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferFindFocusedElementInfo02, Function | SmallTest | Level2)
{
    WLOGFI("TransferFindFocusedElementInfo02 begin!");
    ASSERT_NE(session_, nullptr);
    ASSERT_EQ(WSError::WS_ERROR_NULLPTR, TransferFindFocusedElementInfo(true));
    WLOGFI("TransferFindFocusedElementInfo02 end!");
}

/**
 * @tc.name: TransferFocusMoveSearch01
 * @tc.desc: windowEventChannel_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferFocusMoveSearch01, Function | SmallTest | Level2)
{
    WLOGFI("TransferFocusMoveSearch01 begin!");
    ASSERT_NE(session_, nullptr);
    ASSERT_EQ(WSError::WS_OK, TransferFocusMoveSearch(false));
    WLOGFI("TransferFocusMoveSearch01 end!");
}

/**
 * @tc.name: TransferFocusMoveSearch02
 * @tc.desc: windowEventChannel_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferFocusMoveSearch02, Function | SmallTest | Level2)
{
    WLOGFI("TransferFocusMoveSearch02 begin!");
    ASSERT_NE(session_, nullptr);
    ASSERT_EQ(WSError::WS_ERROR_NULLPTR, TransferFocusMoveSearch(true));
    WLOGFI("TransferFocusMoveSearch02 end!");
}

/**
 * @tc.name: TransferExecuteAction01
 * @tc.desc: windowEventChannel_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferExecuteAction01, Function | SmallTest | Level2)
{
    WLOGFI("TransferExecuteAction01 begin!");
    ASSERT_NE(session_, nullptr);
    ASSERT_EQ(WSError::WS_OK, TransferExecuteAction(false));
    WLOGFI("TransferExecuteAction01 end!");
}

/**
 * @tc.name: TransferExecuteAction02
 * @tc.desc: windowEventChannel_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferExecuteAction02, Function | SmallTest | Level2)
{
    WLOGFI("TransferExecuteAction02 begin!");
    ASSERT_NE(session_, nullptr);
    ASSERT_EQ(WSError::WS_ERROR_NULLPTR, TransferExecuteAction(true));
    WLOGFI("TransferExecuteAction02 end!");
}

/**
 * @tc.name: SetForceTouchable
 * @tc.desc: SetForceTouchable
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetForceTouchable, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    bool touchable = false;
    session_->SetForceTouchable(touchable);
    ASSERT_EQ(session_->forceTouchable_, touchable);
}

/**
 * @tc.name: SetActive01
 * @tc.desc: set session active
 * @tc.type: FUNC
 * @tc.require: #I6JLSI
 */
HWTEST_F(WindowSessionTest, SetActive01, Function | SmallTest | Level2)
{
    sptr<ISession> sessionToken = nullptr;
    sptr<SessionStageMocker> mockSessionStage = new(std::nothrow) SessionStageMocker();
    EXPECT_NE(nullptr, mockSessionStage);
    EXPECT_CALL(*(mockSessionStage), SetActive(_)).WillOnce(Return(WSError::WS_OK));
    EXPECT_CALL(*(mockSessionStage), UpdateRect(_, _, _)).Times(0).WillOnce(Return(WSError::WS_OK));
    session_->sessionStage_ = mockSessionStage;
    ASSERT_EQ(WSError::WS_ERROR_INVALID_SESSION, session_->SetActive(true));

    sptr<WindowEventChannelMocker> mockEventChannel = new(std::nothrow) WindowEventChannelMocker(mockSessionStage);
    EXPECT_NE(nullptr, mockEventChannel);
    auto surfaceNode = CreateRSSurfaceNode();
    SystemSessionConfig sessionConfig;
    sptr<WindowSessionProperty> property = new (std::nothrow) WindowSessionProperty();
    ASSERT_NE(nullptr, property);
    ASSERT_EQ(WSError::WS_OK, session_->Connect(mockSessionStage,
            mockEventChannel, surfaceNode, sessionConfig, property));
    ASSERT_EQ(WSError::WS_OK, session_->SetActive(true));
    ASSERT_EQ(false, session_->isActive_);

    session_->UpdateSessionState(SessionState::STATE_FOREGROUND);
    ASSERT_EQ(WSError::WS_OK, session_->SetActive(true));
    ASSERT_EQ(true, session_->isActive_);
}

/**
 * @tc.name: UpdateRect01
 * @tc.desc: update rect
 * @tc.type: FUNC
 * @tc.require: #I6JLSI
 */
HWTEST_F(WindowSessionTest, UpdateRect01, Function | SmallTest | Level2)
{
    sptr<ISession> sessionToken = nullptr;
    sptr<SessionStageMocker> mockSessionStage = new(std::nothrow) SessionStageMocker();
    EXPECT_NE(nullptr, mockSessionStage);
    session_->sessionStage_ = mockSessionStage;
    EXPECT_CALL(*(mockSessionStage), UpdateRect(_, _, _)).Times(0).WillOnce(Return(WSError::WS_OK));

    WSRect rect = {0, 0, 0, 0};
    ASSERT_EQ(WSError::WS_ERROR_INVALID_SESSION, session_->UpdateRect(rect, SizeChangeReason::UNDEFINED));
    sptr<WindowEventChannelMocker> mockEventChannel = new(std::nothrow) WindowEventChannelMocker(mockSessionStage);
    EXPECT_NE(nullptr, mockEventChannel);
    SystemSessionConfig sessionConfig;
    sptr<WindowSessionProperty> property = new (std::nothrow) WindowSessionProperty();
    ASSERT_NE(nullptr, property);
    ASSERT_EQ(WSError::WS_OK, session_->Connect(mockSessionStage,
            mockEventChannel, nullptr, sessionConfig, property));

    rect = {0, 0, 100, 100};
    EXPECT_CALL(*(mockSessionStage), UpdateRect(_, _, _)).Times(1).WillOnce(Return(WSError::WS_OK));
    ASSERT_EQ(WSError::WS_OK, session_->UpdateRect(rect, SizeChangeReason::UNDEFINED));
    ASSERT_EQ(rect, session_->winRect_);
}

/**
 * @tc.name: IsSessionValid01
 * @tc.desc: check func IsSessionValid
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, IsSessionValid01, Function | SmallTest | Level2)
{
    session_->state_ = SessionState::STATE_DISCONNECT;
    ASSERT_FALSE(session_->IsSessionValid());
    session_->state_ = SessionState::STATE_CONNECT;
    ASSERT_TRUE(session_->IsSessionValid());
}

/**
 * @tc.name: SetSessionProperty01
 * @tc.desc: SetSessionProperty
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetSessionProperty01, Function | SmallTest | Level2)
{
    ASSERT_EQ(session_->SetSessionProperty(nullptr), WSError::WS_OK);
}

/**
 * @tc.name: Connect01
 * @tc.desc: check func Connect
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, Connect01, Function | SmallTest | Level2)
{
    auto surfaceNode = CreateRSSurfaceNode();
    session_->state_ = SessionState::STATE_CONNECT;
    SystemSessionConfig systemConfig;
    sptr<WindowSessionProperty> property = new (std::nothrow) WindowSessionProperty();
    ASSERT_NE(nullptr, property);
    auto result = session_->Connect(nullptr, nullptr, nullptr, systemConfig, property);
    ASSERT_EQ(result, WSError::WS_ERROR_INVALID_SESSION);

    session_->state_ = SessionState::STATE_DISCONNECT;
    result = session_->Connect(nullptr, nullptr, nullptr, systemConfig, property);
    ASSERT_EQ(result, WSError::WS_ERROR_NULLPTR);

    sptr<SessionStageMocker> mockSessionStage = new(std::nothrow) SessionStageMocker();
    EXPECT_NE(nullptr, mockSessionStage);
    result = session_->Connect(mockSessionStage, nullptr, surfaceNode, systemConfig, property);
    ASSERT_EQ(result, WSError::WS_ERROR_NULLPTR);

    sptr<TestWindowEventChannel> testWindowEventChannel = new(std::nothrow) TestWindowEventChannel();
    EXPECT_NE(nullptr, testWindowEventChannel);
    result = session_->Connect(mockSessionStage, testWindowEventChannel, surfaceNode, systemConfig, property);
    ASSERT_EQ(result, WSError::WS_OK);
}

/**
 * @tc.name: Reconnect01
 * @tc.desc: check func Reconnect01
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, Reconnect01, Function | SmallTest | Level2)
{
    auto surfaceNode = CreateRSSurfaceNode();

    sptr<WindowSessionProperty> property = new (std::nothrow) WindowSessionProperty();
    ASSERT_NE(nullptr, property);
    auto result = session_->Reconnect(nullptr, nullptr, nullptr, property);
    ASSERT_EQ(result, WSError::WS_ERROR_NULLPTR);

    sptr<SessionStageMocker> mockSessionStage = new (std::nothrow) SessionStageMocker();
    EXPECT_NE(nullptr, mockSessionStage);
    result = session_->Reconnect(mockSessionStage, nullptr, surfaceNode, property);
    ASSERT_EQ(result, WSError::WS_ERROR_NULLPTR);

    sptr<TestWindowEventChannel> testWindowEventChannel = new (std::nothrow) TestWindowEventChannel();
    EXPECT_NE(nullptr, testWindowEventChannel);
    result = session_->Reconnect(mockSessionStage, testWindowEventChannel, surfaceNode, nullptr);
    ASSERT_EQ(result, WSError::WS_ERROR_NULLPTR);

    result = session_->Reconnect(nullptr, testWindowEventChannel, surfaceNode, property);
    ASSERT_EQ(result, WSError::WS_ERROR_NULLPTR);

    result = session_->Reconnect(mockSessionStage, testWindowEventChannel, surfaceNode, property);
    ASSERT_EQ(result, WSError::WS_OK);
}

/**
 * @tc.name: Foreground01
 * @tc.desc: check func Foreground
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, Foreground01, Function | SmallTest | Level2)
{
    session_->state_ = SessionState::STATE_DISCONNECT;
    sptr<WindowSessionProperty> property = new(std::nothrow) WindowSessionProperty();
    ASSERT_NE(nullptr, property);
    auto result = session_->Foreground(property);
    ASSERT_EQ(result, WSError::WS_ERROR_INVALID_SESSION);

    session_->state_ = SessionState::STATE_CONNECT;
    session_->isActive_ = true;
    result = session_->Foreground(property);
    ASSERT_EQ(result, WSError::WS_OK);

    session_->isActive_ = false;
    ASSERT_EQ(result, WSError::WS_OK);
}

/**
 * @tc.name: Background01
 * @tc.desc: check func Background
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, Background01, Function | SmallTest | Level2)
{
    session_->state_ = SessionState::STATE_CONNECT;
    auto result = session_->Background();
    ASSERT_EQ(result, WSError::WS_ERROR_INVALID_SESSION);

    session_->state_ = SessionState::STATE_INACTIVE;
    result = session_->Background();
    ASSERT_EQ(result, WSError::WS_OK);
    ASSERT_EQ(session_->state_, SessionState::STATE_BACKGROUND);
}

/**
 * @tc.name: Disconnect01
 * @tc.desc: check func Disconnect
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, Disconnect01, Function | SmallTest | Level2)
{
    session_->state_ = SessionState::STATE_CONNECT;
    auto result = session_->Disconnect();
    ASSERT_EQ(result, WSError::WS_OK);
    ASSERT_EQ(session_->state_, SessionState::STATE_DISCONNECT);

    session_->state_ = SessionState::STATE_BACKGROUND;
    result = session_->Disconnect();
    ASSERT_EQ(result, WSError::WS_OK);
    ASSERT_EQ(session_->state_, SessionState::STATE_DISCONNECT);
}

/**
 * @tc.name: TerminateSessionNew01
 * @tc.desc: check func TerminateSessionNew
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TerminateSessionNew01, Function | SmallTest | Level2)
{
    int resultValue = 0;
    NotifyTerminateSessionFuncNew callback =
        [&resultValue](const SessionInfo& info, bool needStartCaller, bool isFromBroker) {
        resultValue = 1;
    };

    bool needStartCaller = false;
    bool isFromBroker = false;
    sptr<AAFwk::SessionInfo> info = new (std::nothrow)AAFwk::SessionInfo();
    session_->terminateSessionFuncNew_ = nullptr;
    session_->TerminateSessionNew(info, needStartCaller, isFromBroker);
    ASSERT_EQ(resultValue, 0);

    ASSERT_EQ(WSError::WS_ERROR_INVALID_SESSION,
              session_->TerminateSessionNew(nullptr, needStartCaller, isFromBroker));
}

/**
 * @tc.name: TerminateSessionNew02
 * @tc.desc: terminateSessionFuncNew_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TerminateSessionNew02, Function | SmallTest | Level2)
{
    int res = 0;
    int resultValue = 0;
    NotifyTerminateSessionFuncNew callback =
        [&resultValue](const SessionInfo& info, bool needStartCaller, bool isFromBroker) {
        resultValue = 1;
    };

    bool needStartCaller = true;
    bool isFromBroker = true;
    sptr<AAFwk::SessionInfo> info = new (std::nothrow)AAFwk::SessionInfo();
    session_->SetTerminateSessionListenerNew(callback);
    session_->TerminateSessionNew(info, needStartCaller, isFromBroker);
    res++;
    ASSERT_EQ(res, 1);
}

/**
 * @tc.name: SetSessionRect
 * @tc.desc: check func SetSessionRect
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetSessionRect, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    WSRect rect = { 0, 0, 320, 240}; // width: 320, height: 240
    session_->SetSessionRect(rect);
    ASSERT_EQ(rect, session_->winRect_);
}

/**
 * @tc.name: GetSessionRect
 * @tc.desc: check func GetSessionRect
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, GetSessionRect, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    WSRect rect = { 0, 0, 320, 240}; // width: 320, height: 240
    session_->SetSessionRect(rect);
    ASSERT_EQ(rect, session_->GetSessionRect());
}

/**
 * @tc.name: CheckDialogOnForeground
 * @tc.desc: check func CheckDialogOnForeground
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, CheckDialogOnForeground, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->dialogVec_.clear();
    ASSERT_EQ(false, session_->CheckDialogOnForeground());
    SessionInfo info;
    info.abilityName_ = "dialogAbilityName";
    info.moduleName_ = "dialogModuleName";
    info.bundleName_ = "dialogBundleName";
    sptr<Session> dialogSession = new (std::nothrow) Session(info);
    ASSERT_NE(dialogSession, nullptr);
    dialogSession->state_ = SessionState::STATE_INACTIVE;
    session_->dialogVec_.push_back(dialogSession);
    ASSERT_EQ(false, session_->CheckDialogOnForeground());
    session_->dialogVec_.clear();
}

/**
 * @tc.name: IsTopDialog
 * @tc.desc: check func IsTopDialog
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, IsTopDialog, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->dialogVec_.clear();
    SessionInfo info;
    info.abilityName_ = "testSession1";
    info.moduleName_ = "testSession2";
    info.bundleName_ = "testSession3";

    sptr<Session> dialogSession1 = new (std::nothrow) Session(info);
    ASSERT_NE(dialogSession1, nullptr);
    dialogSession1->persistentId_ = 33;
    dialogSession1->SetParentSession(session_);
    dialogSession1->state_ = SessionState::STATE_ACTIVE;
    session_->dialogVec_.push_back(dialogSession1);

    sptr<Session> dialogSession2 = new (std::nothrow) Session(info);
    ASSERT_NE(dialogSession2, nullptr);
    dialogSession2->persistentId_ = 34;
    dialogSession2->SetParentSession(session_);
    dialogSession2->state_ = SessionState::STATE_ACTIVE;
    session_->dialogVec_.push_back(dialogSession2);

    sptr<Session> dialogSession3 = new (std::nothrow) Session(info);
    ASSERT_NE(dialogSession3, nullptr);
    dialogSession3->persistentId_ = 35;
    dialogSession3->SetParentSession(session_);
    dialogSession3->state_ = SessionState::STATE_INACTIVE;
    session_->dialogVec_.push_back(dialogSession3);

    ASSERT_EQ(false, dialogSession3->IsTopDialog());
    ASSERT_EQ(true, dialogSession2->IsTopDialog());
    ASSERT_EQ(false, dialogSession1->IsTopDialog());
    session_->dialogVec_.clear();
}

/**
 * @tc.name: NotifyDestroy
 * @tc.desc: check func NotifyDestroy
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, NotifyDestroy, Function | SmallTest | Level2)
{
    sptr<SessionStageMocker> mockSessionStage = new(std::nothrow) SessionStageMocker();
    ASSERT_NE(mockSessionStage, nullptr);
    session_->sessionStage_ = mockSessionStage;
    EXPECT_CALL(*(mockSessionStage), NotifyDestroy()).Times(1).WillOnce(Return(WSError::WS_OK));
    ASSERT_EQ(WSError::WS_OK, session_->NotifyDestroy());
    session_->sessionStage_ = nullptr;
    ASSERT_EQ(WSError::WS_ERROR_NULLPTR, session_->NotifyDestroy());
}

/**
 * @tc.name: RaiseToAppTop01
 * @tc.desc: RaiseToAppTop
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, RaiseToAppTop01, Function | SmallTest | Level2)
{
    SessionInfo info;
    info.abilityName_ = "testSession1";
    info.bundleName_ = "testSession3";
    sptr<SceneSession> scensession = new (std::nothrow) SceneSession(info, nullptr);
    EXPECT_NE(scensession, nullptr);
    auto result = scensession->RaiseToAppTop();
    ASSERT_EQ(result, WSError::WS_OK);

    sptr<SceneSession::SessionChangeCallback> scensessionchangeCallBack =
        new (std::nothrow) SceneSession::SessionChangeCallback();
    EXPECT_NE(scensessionchangeCallBack, nullptr);
    scensession->RegisterSessionChangeCallback(scensessionchangeCallBack);
    result = scensession->RaiseToAppTop();
    ASSERT_EQ(result, WSError::WS_OK);

    NotifyRaiseToTopFunc onRaiseToTop_ = []() {};
    scensessionchangeCallBack->onRaiseToTop_ = onRaiseToTop_;
    result = scensession->RaiseToAppTop();
    ASSERT_EQ(result, WSError::WS_OK);
}

/**
 * @tc.name: UpdateSessionRect01
 * @tc.desc: UpdateSessionRect
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, UpdateSessionRect01, Function | SmallTest | Level2)
{
    SessionInfo info;
    info.abilityName_ = "testSession1";
    info.bundleName_ = "testSession3";
    sptr<SceneSession> scensession = new (std::nothrow) SceneSession(info, nullptr);
    EXPECT_NE(scensession, nullptr);
    WSRect rect = {0, 0, 320, 240}; // width: 320, height: 240
    auto result = scensession->UpdateSessionRect(rect, SizeChangeReason::RESIZE);
    ASSERT_EQ(result, WSError::WS_OK);

    sptr<SceneSession::SessionChangeCallback> scensessionchangeCallBack =
        new (std::nothrow) SceneSession::SessionChangeCallback();
    EXPECT_NE(scensessionchangeCallBack, nullptr);
    scensession->RegisterSessionChangeCallback(scensessionchangeCallBack);
    result = scensession->UpdateSessionRect(rect, SizeChangeReason::RESIZE);
    ASSERT_EQ(result, WSError::WS_OK);

    int resultValue = 0;
    NotifySessionRectChangeFunc onRectChange_ = [&resultValue](const WSRect &rect, const SizeChangeReason& reason)
    { resultValue = 1; };
    scensessionchangeCallBack->onRectChange_ = onRectChange_;
    result = scensession->UpdateSessionRect(rect, SizeChangeReason::RESIZE);
    ASSERT_EQ(result, WSError::WS_OK);
}

/**
 * @tc.name: OnSessionEvent01
 * @tc.desc: OnSessionEvent
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, OnSessionEvent01, Function | SmallTest | Level2)
{
    SessionInfo info;
    info.abilityName_ = "testSession1";
    info.bundleName_ = "testSession3";
    sptr<SceneSession> scensession = new (std::nothrow) SceneSession(info, nullptr);
    EXPECT_NE(scensession, nullptr);
    auto result = scensession->OnSessionEvent(SessionEvent::EVENT_MINIMIZE);
    ASSERT_EQ(result, WSError::WS_OK);

    sptr<SceneSession::SessionChangeCallback> scensessionchangeCallBack =
        new (std::nothrow) SceneSession::SessionChangeCallback();
    EXPECT_NE(scensessionchangeCallBack, nullptr);
    scensession->RegisterSessionChangeCallback(scensessionchangeCallBack);
    result = scensession->OnSessionEvent(SessionEvent::EVENT_MINIMIZE);
    ASSERT_EQ(result, WSError::WS_OK);

    int resultValue = 0;
    NotifySessionEventFunc onSessionEvent_ = [&resultValue](int32_t eventId, SessionEventParam param)
    { resultValue = 1; };
    scensessionchangeCallBack->OnSessionEvent_ = onSessionEvent_;
    result = scensession->OnSessionEvent(SessionEvent::EVENT_MINIMIZE);
    ASSERT_EQ(result, WSError::WS_OK);
}

/**
 * @tc.name: ConsumeMoveEvent01
 * @tc.desc: ConsumeMoveEvent, abnormal scene
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, ConsumeMoveEvent01, Function | SmallTest | Level2)
{
    SessionInfo info;
    info.abilityName_ = "testSession1";
    info.bundleName_ = "testSession3";
    sptr<SceneSession> sceneSession = new (std::nothrow) SceneSession(info, nullptr);
    sceneSession->moveDragController_ = new MoveDragController(1);
    EXPECT_NE(sceneSession, nullptr);
    ASSERT_TRUE(sceneSession->moveDragController_);
    sceneSession->moveDragController_->InitMoveDragProperty();
    WSRect originalRect = { 100, 100, 1000, 1000 };

    std::shared_ptr<MMI::PointerEvent> pointerEvent = nullptr;
    auto result = sceneSession->moveDragController_->ConsumeMoveEvent(pointerEvent, originalRect);
    ASSERT_FALSE(result);

    pointerEvent = MMI::PointerEvent::Create();
    ASSERT_TRUE(pointerEvent);
    pointerEvent->SetPointerId(1);
    sceneSession->moveDragController_->moveDragProperty_.pointerId_ = 0;
    result = sceneSession->moveDragController_->ConsumeMoveEvent(pointerEvent, originalRect);
    ASSERT_FALSE(result);

    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetButtonId(MMI::PointerEvent::MOUSE_BUTTON_RIGHT);
    result = sceneSession->moveDragController_->ConsumeMoveEvent(pointerEvent, originalRect);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: ConsumeMoveEvent02
 * @tc.desc: ConsumeMoveEvent, normal secne
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, ConsumeMoveEvent02, Function | SmallTest | Level2)
{
    SessionInfo info;
    info.abilityName_ = "testSession1";
    info.bundleName_ = "testSession3";
    sptr<SceneSession> sceneSession = new (std::nothrow) SceneSession(info, nullptr);
    EXPECT_NE(sceneSession, nullptr);
    sceneSession->moveDragController_ = new MoveDragController(1);
    ASSERT_TRUE(sceneSession->moveDragController_);
    sceneSession->moveDragController_->InitMoveDragProperty();
    WSRect originalRect = { 100, 100, 1000, 1000 };
    sceneSession->moveDragController_->isStartMove_ = true;
    std::shared_ptr<MMI::PointerEvent> pointerEvent = MMI::PointerEvent::Create();
    ASSERT_TRUE(pointerEvent);
    pointerEvent->SetAgentWindowId(1);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    MMI::PointerEvent::PointerItem pointerItem;
    pointerItem.SetPointerId(0);
    pointerEvent->AddPointerItem(pointerItem);

    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_MOVE);
    pointerItem.SetDisplayX(115);
    pointerItem.SetDisplayY(500);
    pointerItem.SetWindowX(15);
    pointerItem.SetWindowY(400);
    auto result = sceneSession->moveDragController_->ConsumeMoveEvent(pointerEvent, originalRect);
    ASSERT_EQ(result, true);

    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_MOVE);
    pointerItem.SetDisplayX(145);
    pointerItem.SetDisplayY(550);
    result = sceneSession->moveDragController_->ConsumeMoveEvent(pointerEvent, originalRect);
    ASSERT_EQ(result, true);

    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_MOVE);
    pointerItem.SetDisplayX(175);
    pointerItem.SetDisplayY(600);
    result = sceneSession->moveDragController_->ConsumeMoveEvent(pointerEvent, originalRect);
    ASSERT_EQ(result, true);

    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_UP);
    pointerItem.SetDisplayX(205);
    pointerItem.SetDisplayY(650);
    result = sceneSession->moveDragController_->ConsumeMoveEvent(pointerEvent, originalRect);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: ConsumeDragEvent01
 * @tc.desc: ConsumeDragEvent, abnormal scene
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, ConsumeDragEvent01, Function | SmallTest | Level2)
{
    SessionInfo info;
    info.abilityName_ = "testSession1";
    info.bundleName_ = "testSession3";
    sptr<SceneSession> sceneSession = new (std::nothrow) SceneSession(info, nullptr);
    EXPECT_NE(sceneSession, nullptr);
    sceneSession->moveDragController_ = new MoveDragController(1);
    ASSERT_TRUE(sceneSession->moveDragController_);
    sceneSession->moveDragController_->InitMoveDragProperty();
    WSRect originalRect = { 100, 100, 1000, 1000 };
    SystemSessionConfig sessionConfig;

    std::shared_ptr<MMI::PointerEvent> pointerEvent = nullptr;
    sptr<WindowSessionProperty> property = nullptr;
    auto result = sceneSession->moveDragController_->ConsumeDragEvent(pointerEvent, originalRect, property,
        sessionConfig);
    ASSERT_EQ(result, false);

    pointerEvent = MMI::PointerEvent::Create();
    ASSERT_TRUE(pointerEvent);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_UP);
    property = new WindowSessionProperty();
    sceneSession->moveDragController_->isStartDrag_ = false;
    result = sceneSession->moveDragController_->ConsumeDragEvent(pointerEvent, originalRect, property, sessionConfig);
    ASSERT_EQ(result, false);

    pointerEvent->SetPointerId(1);
    sceneSession->moveDragController_->moveDragProperty_.pointerId_ = 0;
    sceneSession->moveDragController_->isStartDrag_ = true;
    result = sceneSession->moveDragController_->ConsumeDragEvent(pointerEvent, originalRect, property, sessionConfig);
    ASSERT_EQ(result, false);

    pointerEvent->SetPointerId(0);
    result = sceneSession->moveDragController_->ConsumeDragEvent(pointerEvent, originalRect, property, sessionConfig);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: ConsumeDragEvent02
 * @tc.desc: ConsumeDragEvent, normal scene
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, ConsumeDragEvent02, Function | SmallTest | Level2)
{
    SessionInfo info;
    info.abilityName_ = "testSession1";
    info.bundleName_ = "testSession3";
    sptr<SceneSession> sceneSession = new (std::nothrow) SceneSession(info, nullptr);
    sceneSession->moveDragController_ = new MoveDragController(1);
    ASSERT_TRUE(sceneSession->moveDragController_);
    sceneSession->moveDragController_->InitMoveDragProperty();
    WSRect originalRect = { 100, 100, 1000, 1000 };
    sptr<WindowSessionProperty> property = new WindowSessionProperty();
    property->SetWindowMode(WindowMode::WINDOW_MODE_FLOATING);
    property->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    SystemSessionConfig sessionConfig;
    sessionConfig.isSystemDecorEnable_ = true;
    sessionConfig.backgroundswitch = true;
    sessionConfig.decorModeSupportInfo_ = WindowModeSupport::WINDOW_MODE_SUPPORT_ALL;
    std::shared_ptr<MMI::PointerEvent> pointerEvent = MMI::PointerEvent::Create();
    ASSERT_TRUE(pointerEvent);
    pointerEvent->SetAgentWindowId(1);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    MMI::PointerEvent::PointerItem pointerItem;
    pointerItem.SetPointerId(0);
    pointerEvent->AddPointerItem(pointerItem);

    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_DOWN);
    pointerItem.SetDisplayX(100);
    pointerItem.SetDisplayY(100);
    pointerItem.SetWindowX(0);
    pointerItem.SetWindowY(0);
    auto result = sceneSession->moveDragController_->ConsumeDragEvent(pointerEvent, originalRect, property,
        sessionConfig);
    ASSERT_EQ(result, true);

    sceneSession->moveDragController_->aspectRatio_ = 0.0f;
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_MOVE);
    pointerItem.SetDisplayX(150);
    pointerItem.SetDisplayY(150);
    result = sceneSession->moveDragController_->ConsumeDragEvent(pointerEvent, originalRect, property, sessionConfig);
    ASSERT_EQ(result, true);

    sceneSession->moveDragController_->aspectRatio_ = 1.0f;
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_MOVE);
    pointerItem.SetDisplayX(200);
    pointerItem.SetDisplayY(200);
    result = sceneSession->moveDragController_->ConsumeDragEvent(pointerEvent, originalRect, property, sessionConfig);
    ASSERT_EQ(result, true);

    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_UP);
    pointerItem.SetDisplayX(250);
    pointerItem.SetDisplayY(250);
    result = sceneSession->moveDragController_->ConsumeDragEvent(pointerEvent, originalRect, property, sessionConfig);
    ASSERT_EQ(result, true);
}

/**
 * @tc.name: ConsumeDragEvent03
 * @tc.desc: ConsumeDragEvent, normal scene
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, ConsumeDragEvent03, Function | SmallTest | Level2)
{
    SessionInfo info;
    info.abilityName_ = "testSession1";
    info.bundleName_ = "testSession3";
    sptr<SceneSession> sceneSession = new (std::nothrow) SceneSession(info, nullptr);
    EXPECT_NE(sceneSession, nullptr);
    sceneSession->moveDragController_ = new MoveDragController(1);
    ASSERT_TRUE(sceneSession->moveDragController_);
    sceneSession->moveDragController_->InitMoveDragProperty();
    WSRect originalRect = { 100, 100, 1000, 1000 };
    sptr<WindowSessionProperty> property = new WindowSessionProperty();
    property->SetWindowMode(WindowMode::WINDOW_MODE_FLOATING);
    property->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    SystemSessionConfig sessionConfig;
    sessionConfig.isSystemDecorEnable_ = true;
    sessionConfig.backgroundswitch = true;
    sessionConfig.decorModeSupportInfo_ = WindowModeSupport::WINDOW_MODE_SUPPORT_ALL;
    std::shared_ptr<MMI::PointerEvent> pointerEvent = MMI::PointerEvent::Create();
    ASSERT_TRUE(pointerEvent);
    pointerEvent->SetAgentWindowId(1);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_DOWN);
    MMI::PointerEvent::PointerItem pointerItem;
    pointerItem.SetPointerId(0);
    pointerEvent->AddPointerItem(pointerItem);

    // LEFT_TOP
    pointerItem.SetWindowX(0);
    pointerItem.SetWindowY(0);
    auto result = sceneSession->moveDragController_->ConsumeDragEvent(pointerEvent, originalRect, property,
        sessionConfig);
    ASSERT_EQ(result, true);

    // RIGHT_TOP
    pointerItem.SetWindowX(1000);
    pointerItem.SetWindowY(0);
    result = sceneSession->moveDragController_->ConsumeDragEvent(pointerEvent, originalRect, property, sessionConfig);
    ASSERT_EQ(result, true);

    // RIGHT_BOTTOM
    pointerItem.SetWindowX(1000);
    pointerItem.SetWindowY(1000);
    result = sceneSession->moveDragController_->ConsumeDragEvent(pointerEvent, originalRect, property, sessionConfig);
    ASSERT_EQ(result, true);

    // LEFT_BOTTOM
    pointerItem.SetWindowX(0);
    pointerItem.SetWindowY(1000);
    result = sceneSession->moveDragController_->ConsumeDragEvent(pointerEvent, originalRect, property, sessionConfig);
    ASSERT_EQ(result, true);
}

/**
 * @tc.name: ConsumeDragEvent04
 * @tc.desc: ConsumeDragEvent, normal scene
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, ConsumeDragEvent04, Function | SmallTest | Level2)
{
    SessionInfo info;
    info.abilityName_ = "testSession1";
    info.bundleName_ = "testSession3";
    sptr<SceneSession> sceneSession = new (std::nothrow) SceneSession(info, nullptr);
    EXPECT_NE(sceneSession, nullptr);
    sceneSession->moveDragController_ = new MoveDragController(1);
    ASSERT_TRUE(sceneSession->moveDragController_);
    sceneSession->moveDragController_->InitMoveDragProperty();
    WSRect originalRect = { 100, 100, 1000, 1000 };
    sptr<WindowSessionProperty> property = new WindowSessionProperty();
    property->SetWindowMode(WindowMode::WINDOW_MODE_FLOATING);
    property->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    SystemSessionConfig sessionConfig;
    sessionConfig.isSystemDecorEnable_ = true;
    sessionConfig.backgroundswitch = true;
    sessionConfig.decorModeSupportInfo_ = WindowModeSupport::WINDOW_MODE_SUPPORT_ALL;
    std::shared_ptr<MMI::PointerEvent> pointerEvent = MMI::PointerEvent::Create();
    ASSERT_TRUE(pointerEvent);
    pointerEvent->SetAgentWindowId(1);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_DOWN);
    MMI::PointerEvent::PointerItem pointerItem;
    pointerItem.SetPointerId(0);
    pointerEvent->AddPointerItem(pointerItem);

    // LEFT
    pointerItem.SetWindowX(0);
    pointerItem.SetWindowY(500);
    auto result = sceneSession->moveDragController_->ConsumeDragEvent(pointerEvent, originalRect, property,
        sessionConfig);
    ASSERT_EQ(result, true);

    // TOP
    pointerItem.SetWindowX(500);
    pointerItem.SetWindowY(0);
    result = sceneSession->moveDragController_->ConsumeDragEvent(pointerEvent, originalRect, property, sessionConfig);
    ASSERT_EQ(result, true);

    // RIGHT
    pointerItem.SetWindowX(1000);
    pointerItem.SetWindowY(500);
    result = sceneSession->moveDragController_->ConsumeDragEvent(pointerEvent, originalRect, property, sessionConfig);
    ASSERT_EQ(result, true);

    // BOTTOM
    pointerItem.SetWindowX(500);
    pointerItem.SetWindowY(1000);
    result = sceneSession->moveDragController_->ConsumeDragEvent(pointerEvent, originalRect, property, sessionConfig);
    ASSERT_EQ(result, true);
}

/**
 * @tc.name: GetWindowId01
 * @tc.desc: GetWindowId, normal scene
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, GetWindowId, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    ASSERT_EQ(0, session_->GetWindowId());
}

/**
 * @tc.name: GetVisible01
 * @tc.desc: GetVisible, normal scene
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, GetVisible, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    ASSERT_EQ(WSError::WS_OK, session_->SetVisible(false));
    session_->state_ = SessionState::STATE_CONNECT;
    if (!session_->GetVisible()) {
        ASSERT_EQ(false, session_->GetVisible());
    }
}

/**
 * @tc.name: IsActive01
 * @tc.desc: IsActive, normal scene
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, IsActive, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->isActive_ = false;
    if (!session_->IsActive()) {
        ASSERT_EQ(false, session_->IsActive());
    }
}

/**
 * @tc.name: IsSessionForeground01
 * @tc.desc: IsSessionForeground, normal scene
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, IsSessionForeground, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->state_ = SessionState::STATE_FOREGROUND;
    ASSERT_EQ(true, session_->IsSessionForeground());
    session_->state_ = SessionState::STATE_ACTIVE;
    ASSERT_EQ(true, session_->IsSessionForeground());
    session_->state_ = SessionState::STATE_INACTIVE;
    ASSERT_EQ(false, session_->IsSessionForeground());
    session_->state_ = SessionState::STATE_BACKGROUND;
    ASSERT_EQ(false, session_->IsSessionForeground());
    session_->state_ = SessionState::STATE_DISCONNECT;
    ASSERT_EQ(false, session_->IsSessionForeground());
    session_->state_ = SessionState::STATE_CONNECT;
    ASSERT_EQ(false, session_->IsSessionForeground());
}

/**
 * @tc.name: SetFocusable01
 * @tc.desc: SetFocusable, normal scene
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetFocusable, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->state_ = SessionState::STATE_DISCONNECT;
    ASSERT_EQ(WSError::WS_OK, session_->SetFocusable(false));
}

/**
 * @tc.name: GetSnapshot
 * @tc.desc: GetSnapshot Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, GetSnapshot, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->state_ = SessionState::STATE_DISCONNECT;
    std::shared_ptr<Media::PixelMap> snapshot = session_->Snapshot();
    ASSERT_EQ(snapshot, session_->GetSnapshot());
}

/**
 * @tc.name: NotifyActivation
 * @tc.desc: NotifyActivation Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, NotifyActivation, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->state_ = SessionState::STATE_DISCONNECT;
    session_->NotifyActivation();

    ASSERT_EQ(WSError::WS_OK, session_->SetFocusable(false));
}

/**
 * @tc.name: NotifyForeground
 * @tc.desc: NotifyForeground Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, NotifyForeground, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->state_ = SessionState::STATE_DISCONNECT;
    session_->NotifyForeground();

    ASSERT_EQ(WSError::WS_OK, session_->SetFocusable(false));
}

/**
 * @tc.name: NotifyBackground
 * @tc.desc: NotifyBackground Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, NotifyBackground, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->state_ = SessionState::STATE_DISCONNECT;
    session_->NotifyBackground();

    ASSERT_EQ(WSError::WS_OK, session_->SetFocusable(false));
}

/**
 * @tc.name: NotifyExtensionDied
 * @tc.desc: NotifyExtensionDied Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, NotifyExtensionDied, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->state_ = SessionState::STATE_DISCONNECT;
    session_->NotifyExtensionDied();

    ASSERT_EQ(WSError::WS_OK, session_->SetFocusable(false));
}

/**
 * @tc.name: NotifyExtensionTimeout
 * @tc.desc: NotifyExtensionTimeout Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, NotifyExtensionTimeout, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->state_ = SessionState::STATE_DISCONNECT;
    session_->NotifyExtensionTimeout(3);

    ASSERT_EQ(WSError::WS_OK, session_->SetFocusable(false));
}

/**
 * @tc.name: SetAspectRatio
 * @tc.desc: SetAspectRatio Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetAspectRatio, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->state_ = SessionState::STATE_DISCONNECT;
    ASSERT_EQ(WSError::WS_OK, session_->SetAspectRatio(0.1f));
}

/**
 * @tc.name: UpdateSessionTouchable
 * @tc.desc: UpdateSessionTouchable Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, UpdateSessionTouchable, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    session_->state_ = SessionState::STATE_DISCONNECT;
    session_->UpdateSessionTouchable(false);

    ASSERT_EQ(WSError::WS_OK, session_->SetFocusable(false));
}

/**
 * @tc.name: SetFocusable02
 * @tc.desc: others
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetFocusable02, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    session_->state_ = SessionState::STATE_FOREGROUND;
    session_->sessionInfo_.isSystem_ = false;

    ASSERT_EQ(WSError::WS_OK, session_->SetFocusable(true));
}

/**
 * @tc.name: GetFocusable01
 * @tc.desc: property_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, GetFocusable01, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->property_ = new WindowSessionProperty();
    ASSERT_EQ(true, session_->GetFocusable());
}

/**
 * @tc.name: GetFocusable02
 * @tc.desc: property_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, GetFocusable02, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->property_ = nullptr;
    ASSERT_EQ(true, session_->GetFocusable());
}

/**
 * @tc.name: SetNeedNotify
 * @tc.desc: SetNeedNotify Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetNeedNotify, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->state_ = SessionState::STATE_DISCONNECT;
    session_->SetNeedNotify(false);

    ASSERT_EQ(WSError::WS_OK, session_->SetFocusable(false));
}

/**
 * @tc.name: NeedNotify
 * @tc.desc: NeedNotify Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, NeedNotify, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->state_ = SessionState::STATE_DISCONNECT;
    session_->SetNeedNotify(true);
    ASSERT_EQ(true, session_->NeedNotify());
}

/**
 * @tc.name: SetTouchable01
 * @tc.desc: IsSessionValid() return false
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetTouchable01, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->state_ = SessionState::STATE_DISCONNECT;
    session_->sessionInfo_.isSystem_ = true;
    ASSERT_EQ(WSError::WS_ERROR_INVALID_SESSION, session_->SetTouchable(false));
}

/**
 * @tc.name: SetTouchable02
 * @tc.desc: IsSessionValid() return true
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetTouchable02, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->state_ = SessionState::STATE_FOREGROUND;
    session_->sessionInfo_.isSystem_ = false;
    ASSERT_EQ(WSError::WS_OK, session_->SetTouchable(false));
}

/**
 * @tc.name: SetSessionInfoLockedState01
 * @tc.desc: IsSessionValid() return false
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetSessionInfoLockedState01, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->SetSessionInfoLockedState(false);
    ASSERT_EQ(false, session_->sessionInfo_.lockedState);
}

/**
 * @tc.name: SetSessionInfoLockedState02
 * @tc.desc: IsSessionValid() return true
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetSessionInfoLockedState02, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->SetSessionInfoLockedState(true);
    ASSERT_EQ(true, session_->sessionInfo_.lockedState);
}

/**
 * @tc.name: GetCallingPid
 * @tc.desc: GetCallingPid Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, GetCallingPid, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->SetCallingPid(111);
    ASSERT_EQ(111, session_->GetCallingPid());
}

/**
 * @tc.name: GetCallingUid
 * @tc.desc: GetCallingUid Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, GetCallingUid, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->SetCallingUid(111);
    ASSERT_EQ(111, session_->GetCallingUid());
}

/**
 * @tc.name: GetAbilityToken
 * @tc.desc: GetAbilityToken Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, GetAbilityToken, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->SetAbilityToken(nullptr);
    ASSERT_EQ(nullptr, session_->GetAbilityToken());
}

/**
 * @tc.name: SetBrightness01
 * @tc.desc: property_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetBrightness01, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->state_ = SessionState::STATE_DISCONNECT;
    session_->property_ = nullptr;
    ASSERT_EQ(WSError::WS_ERROR_NULLPTR, session_->SetBrightness(0.1f));
}

/**
 * @tc.name: SetBrightness02
 * @tc.desc: property_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetBrightness02, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->state_ = SessionState::STATE_DISCONNECT;
    session_->property_ = new WindowSessionProperty();
    ASSERT_EQ(WSError::WS_OK, session_->SetBrightness(0.1f));
}

/**
 * @tc.name: UpdateHotRect
 * @tc.desc: UpdateHotRect Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, UpdateHotRect, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    WSRect rect;
    rect.posX_ = 0;
    rect.posY_ = 0;
    rect.width_ = 0;
    rect.height_ = 0;

    WSRectF newRect;
    const float outsideBorder = 4.0f * 1.5f;
    const size_t outsideBorderCount = 2;
    newRect.posX_ = rect.posX_ - outsideBorder;
    newRect.posY_ = rect.posY_ - outsideBorder;
    newRect.width_ = rect.width_ + outsideBorder * outsideBorderCount;
    newRect.height_ = rect.height_ + outsideBorder * outsideBorderCount;

    ASSERT_EQ(newRect, session_->UpdateHotRect(rect));
}

/**
 * @tc.name: SetTerminateSessionListener
 * @tc.desc: SetTerminateSessionListener Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetTerminateSessionListener, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->state_ = SessionState::STATE_DISCONNECT;
    NotifyTerminateSessionFunc func = nullptr;
    session_->SetTerminateSessionListener(func);

    ASSERT_EQ(WSError::WS_OK, session_->SetFocusable(false));
}

/**
 * @tc.name: TerminateSessionTotal01
 * @tc.desc: abilitySessionInfo is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TerminateSessionTotal01, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    ASSERT_EQ(WSError::WS_ERROR_INVALID_SESSION,
            session_->TerminateSessionTotal(nullptr, TerminateType::CLOSE_AND_KEEP_MULTITASK));
}

/**
 * @tc.name: TerminateSessionTotal02
 * @tc.desc: abilitySessionInfo is not nullptr, isTerminating is true
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TerminateSessionTotal02, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    sptr<AAFwk::SessionInfo> abilitySessionInfo = new AAFwk::SessionInfo();
    session_->isTerminating = true;
    ASSERT_EQ(WSError::WS_ERROR_INVALID_OPERATION,
            session_->TerminateSessionTotal(abilitySessionInfo, TerminateType::CLOSE_AND_KEEP_MULTITASK));
}

/**
 * @tc.name: TerminateSessionTotal03
 * @tc.desc: abilitySessionInfo is not nullptr, isTerminating is false
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TerminateSessionTotal03, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    sptr<AAFwk::SessionInfo> abilitySessionInfo = new AAFwk::SessionInfo();
    session_->isTerminating = false;
    ASSERT_EQ(WSError::WS_OK,
            session_->TerminateSessionTotal(abilitySessionInfo, TerminateType::CLOSE_AND_KEEP_MULTITASK));
}

/**
 * @tc.name: SetTerminateSessionListenerTotal
 * @tc.desc: SetTerminateSessionListenerTotal Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetTerminateSessionListenerTotal, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->state_ = SessionState::STATE_DISCONNECT;
    NotifyTerminateSessionFuncTotal func = nullptr;
    session_->SetTerminateSessionListenerTotal(func);

    ASSERT_EQ(WSError::WS_OK, session_->SetFocusable(false));
}

/**
 * @tc.name: SetSessionLabel
 * @tc.desc: SetSessionLabel Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetSessionLabel, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->state_ = SessionState::STATE_DISCONNECT;
    session_->updateSessionLabelFunc_ = nullptr;
    ASSERT_EQ(WSError::WS_OK, session_->SetSessionLabel("SetSessionLabel Test"));
}

/**
 * @tc.name: SetUpdateSessionLabelListener
 * @tc.desc: SetUpdateSessionLabelListener Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetUpdateSessionLabelListener, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->state_ = SessionState::STATE_DISCONNECT;
    NofitySessionLabelUpdatedFunc func = nullptr;
    session_->SetUpdateSessionLabelListener(func);

    ASSERT_EQ(WSError::WS_OK, session_->SetFocusable(false));
}

/**
 * @tc.name: SetPendingSessionToForegroundListener
 * @tc.desc: SetPendingSessionToForegroundListener Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetPendingSessionToForegroundListener, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->state_ = SessionState::STATE_DISCONNECT;
    NotifyPendingSessionToForegroundFunc func = nullptr;
    session_->SetPendingSessionToForegroundListener(func);

    ASSERT_EQ(WSError::WS_OK, session_->SetFocusable(false));
}

/**
 * @tc.name: PendingSessionToBackgroundForDelegator
 * @tc.desc: PendingSessionToBackgroundForDelegator Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, PendingSessionToBackgroundForDelegator, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->SetPendingSessionToBackgroundForDelegatorListener(nullptr);
    ASSERT_EQ(WSError::WS_OK, session_->PendingSessionToBackgroundForDelegator());
}

/**
 * @tc.name: NotifyScreenshot
 * @tc.desc: NotifyScreenshot Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, NotifyScreenshot, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->sessionStage_ = nullptr;
    session_->NotifyScreenshot();

    session_->property_ = new WindowSessionProperty();
    ASSERT_EQ(WSError::WS_OK, session_->SetFocusable(false));
}

/**
 * @tc.name: SetParentSession
 * @tc.desc: SetParentSession Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetParentSession, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    SessionInfo info;
    info.abilityName_ = "testSession1";
    info.moduleName_ = "testSession2";
    info.bundleName_ = "testSession3";
    sptr<Session> session = new (std::nothrow) Session(info);
    session_->SetParentSession(session);

    session_->property_ = new WindowSessionProperty();
    ASSERT_EQ(WSError::WS_OK, session_->SetFocusable(false));
}

/**
 * @tc.name: BindDialogToParentSession
 * @tc.desc: BindDialogToParentSession Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, BindDialogToParentSession, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    SessionInfo info;
    info.abilityName_ = "testSession1";
    info.moduleName_ = "testSession2";
    info.bundleName_ = "testSession3";
    sptr<Session> session = new (std::nothrow) Session(info);
    session_->BindDialogToParentSession(session);

    session_->property_ = new WindowSessionProperty();
    ASSERT_EQ(WSError::WS_OK, session_->SetFocusable(false));
}

/**
 * @tc.name: RemoveDialogToParentSession
 * @tc.desc: RemoveDialogToParentSession Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, RemoveDialogToParentSession, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    SessionInfo info;
    info.abilityName_ = "testSession1";
    info.moduleName_ = "testSession2";
    info.bundleName_ = "testSession3";
    sptr<Session> session = new (std::nothrow) Session(info);
    session_->RemoveDialogToParentSession(session);

    session_->property_ = new WindowSessionProperty();
    ASSERT_EQ(WSError::WS_OK, session_->SetFocusable(false));
}

/**
 * @tc.name: TransferPointerEvent01
 * @tc.desc: !IsSystemSession() && !IsSessionValid() is true
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferPointerEvent01, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    session_->sessionInfo_.isSystem_ = false;
    session_->state_ = SessionState::STATE_DISCONNECT;

    std::shared_ptr<MMI::PointerEvent> pointerEvent = MMI::PointerEvent::Create();
    ASSERT_EQ(WSError::WS_ERROR_INVALID_SESSION, session_->TransferPointerEvent(pointerEvent));
}

/**
 * @tc.name: TransferPointerEvent02
 * @tc.desc: pointerEvent is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferPointerEvent02, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->sessionInfo_.isSystem_ = true;

    std::shared_ptr<MMI::PointerEvent> pointerEvent = nullptr;
    ASSERT_EQ(WSError::WS_ERROR_NULLPTR, session_->TransferPointerEvent(pointerEvent));
}

/**
 * @tc.name: TransferPointerEvent03
 * @tc.desc: WindowType is WINDOW_TYPE_APP_MAIN_WINDOW, CheckDialogOnForeground() is true
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferPointerEvent03, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    session_->sessionInfo_.isSystem_ = true;

    std::shared_ptr<MMI::PointerEvent> pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    session_->property_ = new WindowSessionProperty();
    session_->property_->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);

    SessionInfo info;
    info.abilityName_ = "dialogAbilityName";
    info.moduleName_ = "dialogModuleName";
    info.bundleName_ = "dialogBundleName";
    sptr<Session> dialogSession = new (std::nothrow) Session(info);
    ASSERT_NE(dialogSession, nullptr);
    dialogSession->state_ = SessionState::STATE_ACTIVE;
    session_->dialogVec_.push_back(dialogSession);

    ASSERT_EQ(WSError::WS_ERROR_NULLPTR, session_->TransferPointerEvent(pointerEvent));
}

/**
 * @tc.name: TransferPointerEvent04
 * @tc.desc: parentSession_ && parentSession_->CheckDialogOnForeground() is true
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferPointerEvent04, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    session_->sessionInfo_.isSystem_ = true;

    std::shared_ptr<MMI::PointerEvent> pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    session_->property_ = new WindowSessionProperty();
    session_->property_->SetWindowType(WindowType::WINDOW_TYPE_APP_SUB_WINDOW);

    SessionInfo info;
    info.abilityName_ = "dialogAbilityName";
    info.moduleName_ = "dialogModuleName";
    info.bundleName_ = "dialogBundleName";
    sptr<Session> dialogSession = new (std::nothrow) Session(info);
    ASSERT_NE(dialogSession, nullptr);
    dialogSession->state_ = SessionState::STATE_ACTIVE;
    session_->dialogVec_.push_back(dialogSession);
    session_->parentSession_ = session_;

    ASSERT_EQ(WSError::WS_ERROR_INVALID_PERMISSION, session_->TransferPointerEvent(pointerEvent));
}

/**
 * @tc.name: TransferPointerEvent05
 * @tc.desc: windowEventChannel_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferPointerEvent05, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    session_->sessionInfo_.isSystem_ = true;

    std::shared_ptr<MMI::PointerEvent> pointerEvent = MMI::PointerEvent::Create();

    session_->property_ = new WindowSessionProperty();
    session_->property_->SetWindowType(WindowType::WINDOW_TYPE_SCENE_BOARD);

    ASSERT_EQ(WSError::WS_ERROR_NULLPTR, session_->TransferPointerEvent(pointerEvent));
}

/**
 * @tc.name: TransferKeyEvent01
 * @tc.desc: !IsSystemSession() && !IsSessionVaild() is true
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferKeyEvent01, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    session_->sessionInfo_.isSystem_ = false;
    session_->state_ = SessionState::STATE_DISCONNECT;
    
    std::shared_ptr<MMI::KeyEvent> keyEvent = MMI::KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ASSERT_EQ(WSError::WS_ERROR_NULLPTR, session_->TransferKeyEvent(keyEvent));
}

/**
 * @tc.name: TransferKeyEvent02
 * @tc.desc: keyEvent is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferKeyEvent02, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    session_->sessionInfo_.isSystem_ = true;

    std::shared_ptr<MMI::KeyEvent> keyEvent = MMI::KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ASSERT_EQ(WSError::WS_ERROR_NULLPTR, session_->TransferKeyEvent(keyEvent));
}

/**
 * @tc.name: TransferKeyEvent03
 * @tc.desc: WindowType is WINDOW_TYPE_APP_MAIN_WINDOW, CheckDialogOnForeground() is true
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferKeyEvent03, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    session_->sessionInfo_.isSystem_ = true;

    auto keyEvent = MMI::KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    session_->property_ = new WindowSessionProperty();
    session_->property_->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);

    SessionInfo info;
    info.abilityName_ = "dialogAbilityName";
    info.moduleName_ = "dialogModuleName";
    info.bundleName_ = "dialogBundleName";
    sptr<Session> dialogSession = new (std::nothrow) Session(info);
    ASSERT_NE(dialogSession, nullptr);
    dialogSession->state_ = SessionState::STATE_ACTIVE;
    session_->dialogVec_.push_back(dialogSession);

    ASSERT_EQ(WSError::WS_ERROR_NULLPTR, session_->TransferKeyEvent(keyEvent));
}

/**
 * @tc.name: TransferKeyEvent04
 * @tc.desc: parentSession_ && parentSession_->CheckDialogOnForeground() is true
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferKeyEvent04, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    session_->sessionInfo_.isSystem_ = true;

    auto keyEvent = MMI::KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    session_->property_ = new WindowSessionProperty();
    session_->property_->SetWindowType(WindowType::WINDOW_TYPE_APP_SUB_WINDOW);

    SessionInfo info;
    info.abilityName_ = "dialogAbilityName";
    info.moduleName_ = "dialogModuleName";
    info.bundleName_ = "dialogBundleName";
    sptr<Session> dialogSession = new (std::nothrow) Session(info);
    ASSERT_NE(dialogSession, nullptr);
    dialogSession->state_ = SessionState::STATE_ACTIVE;
    session_->dialogVec_.push_back(dialogSession);
    session_->parentSession_ = session_;

    ASSERT_EQ(WSError::WS_ERROR_NULLPTR, session_->TransferKeyEvent(keyEvent));
}

/**
 * @tc.name: TransferKeyEvent05
 * @tc.desc: windowEventChannel_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferKeyEvent05, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    session_->sessionInfo_.isSystem_ = true;

    auto keyEvent = MMI::KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    session_->property_ = new WindowSessionProperty();
    session_->property_->SetWindowType(WindowType::WINDOW_TYPE_SCENE_BOARD);

    ASSERT_EQ(WSError::WS_ERROR_NULLPTR, session_->TransferKeyEvent(keyEvent));
}

/**
 * @tc.name: TransferBackPressedEventForConsumed01
 * @tc.desc: windowEventChannel_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferBackPressedEventForConsumed01, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    session_->windowEventChannel_ = nullptr;

    bool isConsumed = false;
    ASSERT_EQ(WSError::WS_ERROR_NULLPTR, session_->TransferBackPressedEventForConsumed(isConsumed));
}

/**
 * @tc.name: TransferBackPressedEventForConsumed02
 * @tc.desc: windowEventChannel_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferBackPressedEventForConsumed02, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    session_->windowEventChannel_ = new TestWindowEventChannel();

    bool isConsumed = false;
    ASSERT_EQ(WSError::WS_OK, session_->TransferBackPressedEventForConsumed(isConsumed));
}

/**
 * @tc.name: TransferKeyEventForConsumed01
 * @tc.desc: windowEventChannel_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferKeyEventForConsumed01, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    session_->windowEventChannel_ = nullptr;

    auto keyEvent = MMI::KeyEvent::Create();
    bool isConsumed = false;
    ASSERT_EQ(WSError::WS_ERROR_NULLPTR, session_->TransferKeyEventForConsumed(keyEvent, isConsumed));
}

/**
 * @tc.name: TransferKeyEventForConsumed02
 * @tc.desc: windowEventChannel_ is not nullptr, keyEvent is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferKeyEventForConsumed02, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    session_->windowEventChannel_ = new TestWindowEventChannel();

    std::shared_ptr<MMI::KeyEvent> keyEvent = nullptr;
    bool isConsumed = false;
    ASSERT_EQ(WSError::WS_ERROR_NULLPTR, session_->TransferKeyEventForConsumed(keyEvent, isConsumed));
}

/**
 * @tc.name: TransferKeyEventForConsumed03
 * @tc.desc: windowEventChannel_ is not nullptr, keyEvent is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferKeyEventForConsumed03, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    session_->windowEventChannel_ = new TestWindowEventChannel();

    std::shared_ptr<MMI::KeyEvent> keyEvent = MMI::KeyEvent::Create();
    bool isConsumed = false;
    ASSERT_EQ(WSError::WS_OK, session_->TransferKeyEventForConsumed(keyEvent, isConsumed));
}

/**
 * @tc.name: TransferFocusActiveEvent01
 * @tc.desc: windowEventChannel_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferFocusActiveEvent01, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    session_->windowEventChannel_ = nullptr;

    ASSERT_EQ(WSError::WS_ERROR_NULLPTR, session_->TransferFocusActiveEvent(false));
}

/**
 * @tc.name: TransferFocusActiveEvent02
 * @tc.desc: windowEventChannel_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferFocusActiveEvent02, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    session_->windowEventChannel_ = new TestWindowEventChannel();

    ASSERT_EQ(WSError::WS_OK, session_->TransferFocusActiveEvent(false));
}

/**
 * @tc.name: TransferFocusStateEvent01
 * @tc.desc: windowEventChannel_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferFocusStateEvent01, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    session_->windowEventChannel_ = nullptr;

    ASSERT_EQ(WSError::WS_ERROR_NULLPTR, session_->TransferFocusStateEvent(false));
}

/**
 * @tc.name: TransferFocusStateEvent02
 * @tc.desc: windowEventChannel_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, TransferFocusStateEvent02, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    session_->windowEventChannel_ = new TestWindowEventChannel();

    ASSERT_EQ(WSError::WS_OK, session_->TransferFocusStateEvent(false));
}

/**
 * @tc.name: Snapshot01
 * @tc.desc: ret is false
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, Snapshot01, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    session_->surfaceNode_ = nullptr;

    ASSERT_EQ(nullptr, session_->Snapshot());
}

/**
 * @tc.name: SetSessionStateChangeListenser
 * @tc.desc: SetSessionStateChangeListenser Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetSessionStateChangeListenser, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    NotifySessionStateChangeFunc func = nullptr;
    session_->SetSessionStateChangeListenser(func);

    session_->state_ = SessionState::STATE_DISCONNECT;
    ASSERT_EQ(WSError::WS_OK, session_->SetFocusable(false));
}

/**
 * @tc.name: SetSessionFocusableChangeListener
 * @tc.desc: SetSessionFocusableChangeListener Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetSessionFocusableChangeListener, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    NotifySessionFocusableChangeFunc func = [](const bool isFocusable)
    {
    };
    session_->SetSessionFocusableChangeListener(func);

    session_->state_ = SessionState::STATE_DISCONNECT;
    ASSERT_EQ(WSError::WS_OK, session_->SetFocusable(false));
}

/**
 * @tc.name: SetSessionTouchableChangeListener
 * @tc.desc: SetSessionTouchableChangeListener Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetSessionTouchableChangeListener, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    NotifySessionTouchableChangeFunc func = [](const bool touchable)
    {
    };
    session_->SetSessionTouchableChangeListener(func);

    session_->state_ = SessionState::STATE_DISCONNECT;
    ASSERT_EQ(WSError::WS_OK, session_->SetFocusable(false));
}

/**
 * @tc.name: SetSessionInfoLockedStateChangeListener
 * @tc.desc: SetSessionInfoLockedStateChangeListener Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetSessionInfoLockedStateChangeListener, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    NotifySessionTouchableChangeFunc func = [](const bool lockedState)
    {
    };
    session_->SetSessionInfoLockedStateChangeListener(func);

    session_->SetSessionInfoLockedState(true);
    ASSERT_EQ(true, session_->sessionInfo_.lockedState);
}

/**
 * @tc.name: SetClickListener
 * @tc.desc: SetClickListener Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetClickListener, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    NotifyClickFunc func = nullptr;
    session_->SetClickListener(func);

    session_->state_ = SessionState::STATE_DISCONNECT;
    ASSERT_EQ(WSError::WS_OK, session_->SetFocusable(false));
}

/**
 * @tc.name: UpdateFocus01
 * @tc.desc: isFocused_ equal isFocused
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, UpdateFocus01, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    bool isFocused = session_->isFocused_;
    ASSERT_EQ(WSError::WS_DO_NOTHING, session_->UpdateFocus(isFocused));
}

/**
 * @tc.name: UpdateFocus02
 * @tc.desc: isFocused_ not equal isFocused, IsSessionValid() return false
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, UpdateFocus02, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    session_->sessionInfo_.isSystem_ = true;

    bool isFocused = session_->isFocused_;
    ASSERT_EQ(WSError::WS_OK, session_->UpdateFocus(!isFocused));
}

/**
 * @tc.name: UpdateWindowMode01
 * @tc.desc: IsSessionValid() return false
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, UpdateWindowMode01, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    session_->property_ = nullptr;

    ASSERT_EQ(WSError::WS_ERROR_NULLPTR, session_->UpdateWindowMode(WindowMode::WINDOW_MODE_UNDEFINED));
}

/**
 * @tc.name: NotifyForegroundInteractiveStatus
 * @tc.desc: NotifyForegroundInteractiveStatus Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, NotifyForegroundInteractiveStatus, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);

    session_->sessionStage_ = nullptr;
    bool interactive = true;
    session_->NotifyForegroundInteractiveStatus(interactive);

    sptr<SessionStageMocker> mockSessionStage = new(std::nothrow) SessionStageMocker();
    ASSERT_NE(mockSessionStage, nullptr);
    session_->sessionStage_ = mockSessionStage;
    session_->state_ = SessionState::STATE_FOREGROUND;
    interactive = false;
    session_->NotifyForegroundInteractiveStatus(interactive);

    session_->state_ = SessionState::STATE_DISCONNECT;
    ASSERT_EQ(WSError::WS_OK, session_->SetFocusable(false));
}

/**
 * @tc.name: SetEventHandler001
 * @tc.desc: SetEventHandler Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetEventHandler001, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    int res = 0;
    std::shared_ptr<AppExecFwk::EventHandler> handler = nullptr;
    session_->SetEventHandler(handler);
    ASSERT_EQ(res, 0);
}

/**
 * @tc.name: PostTask002
 * @tc.desc: PostTask Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, PostTask002, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    int32_t persistentId = 0;
    sptr<WindowSessionProperty> property = new (std::nothrow) WindowSessionProperty();
    if (property == nullptr) {
        return;
    }
    property->SetPersistentId(persistentId);
    int32_t res = session_->GetPersistentId();
    ASSERT_EQ(res, 0);
}

/**
 * @tc.name: GetSurfaceNode003
 * @tc.desc: GetSurfaceNode Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, GetSurfaceNode003, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->surfaceNode_ = nullptr;
    std::shared_ptr<RSSurfaceNode> res = session_->GetSurfaceNode();
    ASSERT_EQ(res, nullptr);
}

/**
 * @tc.name: GetLeashWinSurfaceNode004
 * @tc.desc: GetLeashWinSurfaceNode Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, GetLeashWinSurfaceNode004, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->leashWinSurfaceNode_ = nullptr;
    std::shared_ptr<RSSurfaceNode> res = session_->GetLeashWinSurfaceNode();
    ASSERT_EQ(res, nullptr);
}

/**
 * @tc.name: SetSessionInfoAncoSceneState005
 * @tc.desc: SetSessionInfoAncoSceneState Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetSessionInfoAncoSceneState005, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    int res = 0;
    int32_t ancoSceneState = 0;
    session_->SetSessionInfoAncoSceneState(ancoSceneState);
    ASSERT_EQ(res, 0);
}

/**
 * @tc.name: SetSessionInfoTime006
 * @tc.desc: SetSessionInfoTime Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetSessionInfoTime006, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    int res = 0;
    std::string time = "";
    session_->SetSessionInfoTime(time);
    ASSERT_EQ(res, 0);
}

/**
 * @tc.name: SetSessionInfoAbilityInfo007
 * @tc.desc: SetSessionInfoAbilityInfo Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetSessionInfoAbilityInfo007, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    int res = 0;
    std::shared_ptr<AppExecFwk::AbilityInfo> abilityInfo = nullptr;
    session_->SetSessionInfoAbilityInfo(abilityInfo);
    ASSERT_EQ(res, 0);
}

/**
 * @tc.name: SetSessionInfoWant008
 * @tc.desc: SetSessionInfoWant Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetSessionInfoWant008, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    int res = 0;
    std::shared_ptr<AAFwk::Want> want = nullptr;
    session_->SetSessionInfoWant(want);
    ASSERT_EQ(res, 0);
}

/**
 * @tc.name: SetSessionInfoPersistentId009
 * @tc.desc: SetSessionInfoPersistentId Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetSessionInfoPersistentId009, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    int res = 0;
    int32_t persistentId = 0;
    session_->SetSessionInfoPersistentId(persistentId);
    ASSERT_EQ(res, 0);
}

/**
 * @tc.name: SetSessionInfoCallerPersistentId010
 * @tc.desc: SetSessionInfoCallerPersistentId Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetSessionInfoCallerPersistentId010, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    int res = 0;
    int32_t callerPersistentId = 0;
    session_->SetSessionInfoCallerPersistentId(callerPersistentId);
    ASSERT_EQ(res, 0);
}

/**
 * @tc.name: PostExportTask011
 * @tc.desc: PostExportTask Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, PostExportTask011, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    int32_t persistentId = 0;
    sptr<WindowSessionProperty> property = new (std::nothrow) WindowSessionProperty();
    if (property == nullptr) {
        return;
    }
    property->SetPersistentId(persistentId);
    int32_t ret = session_->GetPersistentId();
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: GetPersistentId012
 * @tc.desc: GetPersistentId Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, GetPersistentId012, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    int32_t persistentId = 0;
    sptr<WindowSessionProperty> property = new (std::nothrow) WindowSessionProperty();
    if (property == nullptr) {
        return;
    }
    property->SetPersistentId(persistentId);
    int32_t ret = session_->GetPersistentId();
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: SetLeashWinSurfaceNode013
 * @tc.desc: SetLeashWinSurfaceNode Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetLeashWinSurfaceNode013, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    auto leashWinSurfaceNode = WindowSessionTest::CreateRSSurfaceNode();
    session_->SetLeashWinSurfaceNode(leashWinSurfaceNode);
    ASSERT_EQ(session_->leashWinSurfaceNode_, leashWinSurfaceNode);
}

/**
 * @tc.name: SetSessionInfoContinueState014
 * @tc.desc: SetSessionInfoContinueState Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetSessionInfoContinueState014, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    enum ContinueState state;
    state = CONTINUESTATE_UNKNOWN;
    session_->SetSessionInfoContinueState(state);
    ASSERT_EQ(session_->sessionInfo_.continueState, state);
}

/**
 * @tc.name: SetSessionInfoIsClearSession015
 * @tc.desc: SetSessionInfoIsClearSession return false
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetSessionInfoIsClearSession015, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->SetSessionInfoIsClearSession(false);
    ASSERT_EQ(false, session_->sessionInfo_.isClearSession);
}

/**
 * @tc.name: SetSessionInfoIsClearSession016
 * @tc.desc: SetSessionInfoIsClearSession return true
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetSessionInfoIsClearSession016, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->SetSessionInfoIsClearSession(true);
    ASSERT_EQ(true, session_->sessionInfo_.isClearSession);
}

/**
 * @tc.name: SetSessionInfoAffinity017
 * @tc.desc: SetSessionInfoAffinity
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetSessionInfoAffinity017, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    std::string affinity = "setSessionIofoAffinity";
    session_->SetSessionInfoAffinity(affinity);
    ASSERT_EQ(affinity, session_->sessionInfo_.sessionAffinity);
}

/**
 * @tc.name: SetSessionInfo018
 * @tc.desc: SetSessionInfo
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetSessionInfo018, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    SessionInfo info;
    info.want = nullptr;
    info.callerToken_ = nullptr;
    info.requestCode = 1;
    info.callerPersistentId_ = 1;
    info.callingTokenId_ = 1;
    info.uiAbilityId_ = 1;
    info.startSetting = nullptr;
    info.continueSessionId_ = "";
    session_->SetSessionInfo(info);
    ASSERT_EQ(nullptr, session_->sessionInfo_.want);
    ASSERT_EQ(nullptr, session_->sessionInfo_.callerToken_);
    ASSERT_EQ(1, session_->sessionInfo_.requestCode);
    ASSERT_EQ(1, session_->sessionInfo_.callerPersistentId_);
    ASSERT_EQ(1, session_->sessionInfo_.callingTokenId_);
    ASSERT_EQ(1, session_->sessionInfo_.uiAbilityId_);
    ASSERT_EQ("", session_->sessionInfo_.continueSessionId_);
    ASSERT_EQ(nullptr, session_->sessionInfo_.startSetting);
}

/**
 * @tc.name: SetScreenId019
 * @tc.desc: SetScreenId
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetScreenId019, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    uint64_t screenId = 0;
    session_->SetScreenId(screenId);
    ASSERT_EQ(0, session_->sessionInfo_.screenId_);
}

/**
 * @tc.name: RegisterLifecycleListener020
 * @tc.desc: RegisterLifecycleListener
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, RegisterLifecycleListener020, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    const std::shared_ptr<ILifecycleListener>& listener = nullptr;
    bool ret = session_->RegisterLifecycleListener(listener);
    ASSERT_EQ(false, ret);
}

/**
 * @tc.name: UnregisterLifecycleListener021
 * @tc.desc: UnregisterLifecycleListener
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, UnregisterLifecycleListener021, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    const std::shared_ptr<ILifecycleListener>& listener = nullptr;
    bool ret = session_->UnregisterLifecycleListener(listener);
    ASSERT_EQ(false, ret);
}

/**
 * @tc.name: NotifyActivation022
 * @tc.desc: NotifyActivation
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, NotifyActivation022, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->NotifyActivation();
    uint64_t screenId = 0;
    session_->SetScreenId(screenId);
    ASSERT_EQ(0, session_->sessionInfo_.screenId_);
}

/**
 * @tc.name: NotifyConnect023
 * @tc.desc: NotifyConnect
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, NotifyConnect023, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->NotifyConnect();
    uint64_t screenId = 0;
    session_->SetScreenId(screenId);
    ASSERT_EQ(0, session_->sessionInfo_.screenId_);
}

/**
 * @tc.name: NotifyForeground024
 * @tc.desc: NotifyForeground
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, NotifyForeground024, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->NotifyForeground();
    uint64_t screenId = 0;
    session_->SetScreenId(screenId);
    ASSERT_EQ(0, session_->sessionInfo_.screenId_);
}

/**
 * @tc.name: NotifyBackground025
 * @tc.desc: NotifyBackground
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, NotifyBackground025, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->NotifyBackground();
    uint64_t screenId = 0;
    session_->SetScreenId(screenId);
    ASSERT_EQ(0, session_->sessionInfo_.screenId_);
}

/**
 * @tc.name: NotifyDisconnect026
 * @tc.desc: NotifyDisconnect
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, NotifyDisconnect026, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->NotifyDisconnect();
    uint64_t screenId = 0;
    session_->SetScreenId(screenId);
    ASSERT_EQ(0, session_->sessionInfo_.screenId_);
}

/**
 * @tc.name: NotifyExtensionDied027
 * @tc.desc: NotifyExtensionDied
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, NotifyExtensionDied027, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->NotifyExtensionDied();
    uint64_t screenId = 0;
    session_->SetScreenId(screenId);
    ASSERT_EQ(0, session_->sessionInfo_.screenId_);
}

/**
 * @tc.name: GetAspectRatio028
 * @tc.desc: GetAspectRatio
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, GetAspectRatio028, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    float ret = session_->aspectRatio_;
    float res = 0.0f;
    ASSERT_EQ(ret, res);
}

/**
 * @tc.name: SetAspectRatio029
 * @tc.desc: SetAspectRatio
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetAspectRatio029, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    float radio = 2.0f;
    WSError ERR = session_->SetAspectRatio(radio);
    float ret = session_->aspectRatio_;
    ASSERT_EQ(ret, radio);
    ASSERT_EQ(ERR, WSError::WS_OK);
}

/**
 * @tc.name: GetSessionState030
 * @tc.desc: GetSessionState
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, GetSessionState030, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    SessionState state = session_->GetSessionState();
    ASSERT_EQ(state, session_->state_);
}

/**
 * @tc.name: SetSessionState031
 * @tc.desc: SetSessionState
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetSessionState031, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    SessionState state = SessionState::STATE_CONNECT;
    session_->SetSessionState(state);
    ASSERT_EQ(state, session_->state_);
}

/**
 * @tc.name: UpdateSessionState32
 * @tc.desc: UpdateSessionState
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, UpdateSessionState32, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    SessionState state = SessionState::STATE_CONNECT;
    session_->UpdateSessionState(state);
    ASSERT_EQ(session_->state_, SessionState::STATE_CONNECT);
}

/**
 * @tc.name: GetTouchable33
 * @tc.desc: GetTouchable
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, GetTouchable33, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    bool res = session_->GetTouchable();
    ASSERT_EQ(true, res);
}

/**
 * @tc.name: SetSystemTouchable34
 * @tc.desc: SetSystemTouchable
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetSystemTouchable34, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    bool touchable = false;
    session_->SetSystemTouchable(touchable);
    ASSERT_EQ(session_->systemTouchable_, touchable);
}

/**
 * @tc.name: GetSystemTouchable35
 * @tc.desc: GetSystemTouchable
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, GetSystemTouchable35, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    bool res = session_->GetSystemTouchable();
    ASSERT_EQ(res, true);
}

/**
 * @tc.name: SetVisible36
 * @tc.desc: SetVisible
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetVisible36, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    bool isVisible = false;
    ASSERT_EQ(WSError::WS_OK, session_->SetVisible(isVisible));
}

/**
 * @tc.name: GetVisible37
 * @tc.desc: GetVisible
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, GetVisible37, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    if (!session_->GetVisible()) {
        ASSERT_EQ(false, session_->GetVisible());
    }
}

/**
 * @tc.name: SetVisibilityState38
 * @tc.desc: SetVisibilityState
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetVisibilityState38, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    WindowVisibilityState state { WINDOW_VISIBILITY_STATE_NO_OCCLUSION};
    ASSERT_EQ(WSError::WS_OK, session_->SetVisibilityState(state));
    ASSERT_EQ(state, session_->visibilityState_);
}

/**
 * @tc.name: GetVisibilityState39
 * @tc.desc: GetVisibilityState
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, GetVisibilityState39, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    WindowVisibilityState state { WINDOW_LAYER_STATE_MAX};
    ASSERT_EQ(state, session_->GetVisibilityState());
}

/**
 * @tc.name: SetDrawingContentState40
 * @tc.desc: SetDrawingContentState
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetDrawingContentState40, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    bool isRSDrawing = false;
    ASSERT_EQ(WSError::WS_OK, session_->SetDrawingContentState(isRSDrawing));
    ASSERT_EQ(false, session_->isRSDrawing_);
}

/**
 * @tc.name: GetDrawingContentState41
 * @tc.desc: GetDrawingContentState
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, GetDrawingContentState41, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    bool res = session_->GetDrawingContentState();
    ASSERT_EQ(res, false);
}

/**
 * @tc.name: GetBrightness42
 * @tc.desc: GetBrightness
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, GetBrightness42, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->state_ = SessionState::STATE_DISCONNECT;
    session_->property_ = nullptr;
    ASSERT_EQ(UNDEFINED_BRIGHTNESS, session_->GetBrightness());
}

/**
 * @tc.name: IsActive43
 * @tc.desc: IsActive
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, IsActive43, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    bool res = session_->IsActive();
    ASSERT_EQ(res, false);
}

/**
 * @tc.name: IsSystemSession44
 * @tc.desc: IsSystemSession
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, IsSystemSession44, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    bool res = session_->IsSystemSession();
    ASSERT_EQ(res, false);
}

/**
 * @tc.name: Hide45
 * @tc.desc: Hide
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, Hide45, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    auto result = session_->Hide();
    ASSERT_EQ(result, WSError::WS_OK);
}

/**
 * @tc.name: Show46
 * @tc.desc: Show
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, Show46, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    sptr<WindowSessionProperty> property = new (std::nothrow) WindowSessionProperty();
    ASSERT_NE(nullptr, property);
    auto result = session_->Show(property);
    ASSERT_EQ(result, WSError::WS_OK);
}

/**
 * @tc.name: IsSystemActive47
 * @tc.desc: IsSystemActive
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, IsSystemActive47, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    bool res = session_->IsSystemActive();
    ASSERT_EQ(res, false);
}

/**
 * @tc.name: SetSystemActive48
 * @tc.desc: SetSystemActive
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetSystemActive48, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    bool systemActive = false;
    session_->SetSystemActive(systemActive);
    ASSERT_EQ(systemActive, session_->isSystemActive_);
}

/**
 * @tc.name: IsTerminated49
 * @tc.desc: IsTerminated
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, IsTerminated49, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->state_ = SessionState::STATE_DISCONNECT;
    bool res = session_->IsTerminated();
    ASSERT_EQ(true, res);
    session_->state_ = SessionState::STATE_FOREGROUND;
    res = session_->IsTerminated();
    ASSERT_EQ(false, res);
    session_->state_ = SessionState::STATE_ACTIVE;
    res = session_->IsTerminated();
    ASSERT_EQ(false, res);
    session_->state_ = SessionState::STATE_INACTIVE;
    res = session_->IsTerminated();
    ASSERT_EQ(false, res);
    session_->state_ = SessionState::STATE_BACKGROUND;
    res = session_->IsTerminated();
    ASSERT_EQ(false, res);
    session_->state_ = SessionState::STATE_CONNECT;
    res = session_->IsTerminated();
    ASSERT_EQ(false, res);
}

/**
 * @tc.name: SetSystemActive48
 * @tc.desc: SetSystemActive
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetChangeSessionVisibilityWithStatusBarEventListener, Function | SmallTest | Level2)
{
    int resultValue = 0;
    NotifyChangeSessionVisibilityWithStatusBarFunc func1 = [&resultValue](SessionInfo& info, const bool visible) {
        resultValue = 1;
    };
    NotifyChangeSessionVisibilityWithStatusBarFunc func2 = [&resultValue](SessionInfo& info, const bool visible) {
        resultValue = 2;
    };

    session_->SetChangeSessionVisibilityWithStatusBarEventListener(func1);
    ASSERT_NE(session_->changeSessionVisibilityWithStatusBarFunc_, nullptr);

    SessionInfo info;
    session_->changeSessionVisibilityWithStatusBarFunc_(info, true);
    ASSERT_EQ(resultValue, 1);

    session_->SetChangeSessionVisibilityWithStatusBarEventListener(func2);
    ASSERT_NE(session_->changeSessionVisibilityWithStatusBarFunc_, nullptr);
    session_->changeSessionVisibilityWithStatusBarFunc_(info, true);
    ASSERT_EQ(resultValue, 2);
}

/**
 * @tc.name: SetAttachState01
 * @tc.desc: SetAttachState Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetAttachState01, Function | SmallTest | Level2)
{
    session_->SetAttachState(false);
    ASSERT_EQ(session_->isAttach_, false);
}

/**
 * @tc.name: SetAttachState02
 * @tc.desc: SetAttachState Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetAttachState02, Function | SmallTest | Level2)
{
    int32_t persistentId = 123;
    sptr<PatternDetachCallbackMocker> detachCallback = new PatternDetachCallbackMocker();
    session_->persistentId_ = persistentId;
    session_->SetAttachState(true);
    session_->RegisterDetachCallback(detachCallback);
    session_->SetAttachState(false);
    Mock::VerifyAndClearExpectations(&detachCallback);
    ASSERT_EQ(session_->isAttach_, false);
}

/**
 * @tc.name: RegisterDetachCallback01
 * @tc.desc: RegisterDetachCallback Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, RegisterDetachCallback01, Function | SmallTest | Level2)
{
    sptr<IPatternDetachCallback> detachCallback;
    session_->RegisterDetachCallback(detachCallback);
    ASSERT_EQ(session_->detachCallback_, detachCallback);
}

/**
 * @tc.name: RegisterDetachCallback02
 * @tc.desc: RegisterDetachCallback Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, RegisterDetachCallback02, Function | SmallTest | Level2)
{
    sptr<IPatternDetachCallback> detachCallback;
    session_->RegisterDetachCallback(detachCallback);
    ASSERT_EQ(session_->detachCallback_, detachCallback);
    sptr<IPatternDetachCallback> detachCallback2;
    session_->RegisterDetachCallback(detachCallback2);
    ASSERT_EQ(session_->detachCallback_, detachCallback2);
}

/**
 * @tc.name: RegisterDetachCallback03
 * @tc.desc: RegisterDetachCallback Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, RegisterDetachCallback03, Function | SmallTest | Level2)
{
    int32_t persistentId = 123;
    sptr<PatternDetachCallbackMocker> detachCallback = new PatternDetachCallbackMocker();
    EXPECT_CALL(*detachCallback, OnPatternDetach(persistentId)).Times(1);
    session_->persistentId_ = persistentId;
    session_->SetAttachState(true);
    session_->SetAttachState(false);
    session_->RegisterDetachCallback(detachCallback);
    Mock::VerifyAndClearExpectations(&detachCallback);
}

/**
 * @tc.name: SetContextTransparentFunc
 * @tc.desc: SetContextTransparentFunc Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetContextTransparentFunc, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->SetContextTransparentFunc(nullptr);
    ASSERT_EQ(session_->contextTransparentFunc_, nullptr);
    NotifyContextTransparentFunc func = [](){};
    session_->SetContextTransparentFunc(func);
    ASSERT_NE(session_->contextTransparentFunc_, nullptr);
}

/**
 * @tc.name: NeedCheckContextTransparent
 * @tc.desc: NeedCheckContextTransparent Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, NeedCheckContextTransparent, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->SetContextTransparentFunc(nullptr);
    ASSERT_EQ(session_->NeedCheckContextTransparent(), false);
    NotifyContextTransparentFunc func = [](){};
    session_->SetContextTransparentFunc(func);
    ASSERT_EQ(session_->NeedCheckContextTransparent(), true);
}

/**
 * @tc.name: SetShowRecent001
 * @tc.desc: Exist detect task when in recent.
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetShowRecent001, Function | SmallTest | Level2)
{
    std::string taskName = "wms:WindowStateDetect" + std::to_string(session_->persistentId_);
    auto task = [](){};
    int64_t delayTime = 3000;
    session_->handler_->PostTask(task, taskName, delayTime);
    int32_t beforeTaskNum = GetTaskCount();

    session_->SetShowRecent(true);
    ASSERT_EQ(beforeTaskNum, GetTaskCount());
    session_->handler_->RemoveTask(taskName);
}

/**
 * @tc.name: SetShowRecent002
 * @tc.desc: SetShowRecent:showRecent is false, showRecent_ is false.
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetShowRecent002, Function | SmallTest | Level2)
{
    std::string taskName = "wms:WindowStateDetect" + std::to_string(session_->persistentId_);
    auto task = [](){};
    int64_t delayTime = 3000;
    session_->handler_->PostTask(task, taskName, delayTime);
    session_->showRecent_ = false;
    int32_t beforeTaskNum = GetTaskCount();

    session_->SetShowRecent(false);
    ASSERT_EQ(beforeTaskNum, GetTaskCount());
    session_->handler_->RemoveTask(taskName);
}

/**
 * @tc.name: SetShowRecent003
 * @tc.desc: SetShowRecent:showRecent is false, showRecent_ is true, detach task.
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetShowRecent003, Function | SmallTest | Level2)
{
    std::string taskName = "wms:WindowStateDetect" + std::to_string(session_->persistentId_);
    auto task = [](){};
    int64_t delayTime = 3000;
    session_->handler_->PostTask(task, taskName, delayTime);
    session_->showRecent_ = true;
    session_->isAttach_ = false;
    int32_t beforeTaskNum = GetTaskCount();

    session_->SetShowRecent(false);
    ASSERT_EQ(beforeTaskNum, GetTaskCount());
    session_->handler_->RemoveTask(taskName);
}

/**
 * @tc.name: CreateDetectStateTask001
 * @tc.desc: Create detection task when there are no pre_existing tasks.
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, CreateDetectStateTask001, Function | SmallTest | Level2)
{
    std::string taskName = "wms:WindowStateDetect" + std::to_string(session_->persistentId_);
    DetectTaskInfo detectTaskInfo;
    detectTaskInfo.taskState = DetectTaskState::NO_TASK;
    int32_t beforeTaskNum = GetTaskCount();
    session_->SetDetectTaskInfo(detectTaskInfo);
    session_->CreateDetectStateTask(false, WindowMode::WINDOW_MODE_FULLSCREEN);

    ASSERT_NE(beforeTaskNum + 1, GetTaskCount());
    ASSERT_NE(DetectTaskState::ATTACH_TASK, session_->GetDetectTaskInfo().taskState);
    session_->handler_->RemoveTask(taskName);
}

/**
 * @tc.name: CreateDetectStateTask002
 * @tc.desc: Detect state when window mode changed.
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, CreateDetectStateTask002, Function | SmallTest | Level2)
{
    std::string taskName = "wms:WindowStateDetect" + std::to_string(session_->persistentId_);
    auto task = [](){};
    int64_t delayTime = 3000;
    session_->handler_->PostTask(task, taskName, delayTime);
    int32_t beforeTaskNum = GetTaskCount();

    DetectTaskInfo detectTaskInfo;
    detectTaskInfo.taskState = DetectTaskState::DETACH_TASK;
    detectTaskInfo.taskWindowMode = WindowMode::WINDOW_MODE_FULLSCREEN;
    session_->SetDetectTaskInfo(detectTaskInfo);
    session_->CreateDetectStateTask(true, WindowMode::WINDOW_MODE_SPLIT_SECONDARY);

    ASSERT_NE(beforeTaskNum - 1, GetTaskCount());
    ASSERT_NE(DetectTaskState::ATTACH_TASK, session_->GetDetectTaskInfo().taskState);
    ASSERT_EQ(WindowMode::WINDOW_MODE_FULLSCREEN, session_->GetDetectTaskInfo().taskWindowMode);
    session_->handler_->RemoveTask(taskName);
}

/**
 * @tc.name: CreateDetectStateTask003
 * @tc.desc: Detect sup and down tree tasks fo the same type.
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, CreateDetectStateTask003, Function | SmallTest | Level2)
{
    std::string taskName = "wms:WindowStateDetect" + std::to_string(session_->persistentId_);
    DetectTaskInfo detectTaskInfo;
    detectTaskInfo.taskState = DetectTaskState::DETACH_TASK;
    detectTaskInfo.taskWindowMode = WindowMode::WINDOW_MODE_FULLSCREEN;
    int32_t beforeTaskNum = GetTaskCount();
    session_->SetDetectTaskInfo(detectTaskInfo);
    session_->CreateDetectStateTask(false, WindowMode::WINDOW_MODE_SPLIT_SECONDARY);

    ASSERT_NE(beforeTaskNum + 1, GetTaskCount());
    ASSERT_EQ(DetectTaskState::DETACH_TASK, session_->GetDetectTaskInfo().taskState);
    session_->handler_->RemoveTask(taskName);
}

/**
 * @tc.name: CreateDetectStateTask004
 * @tc.desc: Detection tasks under the same window mode.
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, CreateDetectStateTask004, Function | SmallTest | Level2)
{
    std::string taskName = "wms:WindowStateDetect" + std::to_string(session_->persistentId_);
    DetectTaskInfo detectTaskInfo;
    int32_t beforeTaskNum = GetTaskCount();
    detectTaskInfo.taskState = DetectTaskState::DETACH_TASK;
    detectTaskInfo.taskWindowMode = WindowMode::WINDOW_MODE_FULLSCREEN;
    session_->SetDetectTaskInfo(detectTaskInfo);
    session_->CreateDetectStateTask(true, WindowMode::WINDOW_MODE_FULLSCREEN);

    ASSERT_NE(beforeTaskNum + 1, GetTaskCount());
    ASSERT_NE(DetectTaskState::NO_TASK, session_->GetDetectTaskInfo().taskState);
    session_->handler_->RemoveTask(taskName);
}

/**
 * @tc.name: GetAttachState001
 * @tc.desc: GetAttachState001
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, GetAttachState001, Function | SmallTest | Level2)
{
    std::string taskName = "wms:WindowStateDetect" + std::to_string(session_->persistentId_);
    session_->SetAttachState(false);
    bool isAttach = session_->GetAttachState();
    ASSERT_EQ(false, isAttach);
    session_->handler_->RemoveTask(taskName);
}

/**
 * @tc.name: UpdateSizeChangeReason
 * @tc.desc: UpdateSizeChangeReason UpdateDensity
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, UpdateSizeChangeReason, Function | SmallTest | Level2)
{
    SizeChangeReason reason = SizeChangeReason{1};
    ASSERT_EQ(session_->UpdateSizeChangeReason(reason), WSError::WS_OK);
}

/**
 * @tc.name: SetPendingSessionActivationEventListener
 * @tc.desc: SetPendingSessionActivationEventListener
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetPendingSessionActivationEventListener, Function | SmallTest | Level2)
{
    int resultValue = 0;
    NotifyPendingSessionActivationFunc callback = [&resultValue](const SessionInfo& info) {
        resultValue = 1;
    };

    sptr<AAFwk::SessionInfo> info = new (std::nothrow)AAFwk::SessionInfo();
    session_->SetPendingSessionActivationEventListener(callback);
    NotifyTerminateSessionFunc callback1 = [&resultValue](const SessionInfo& info) {
        resultValue = 2;
    };
    session_->SetTerminateSessionListener(callback1);
    LifeCycleTaskType taskType = LifeCycleTaskType{0};
    session_->RemoveLifeCycleTask(taskType);
    ASSERT_EQ(resultValue, 0);
}

/**
 * @tc.name: SetSessionIcon
 * @tc.desc: SetSessionIcon UpdateDensity
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetSessionIcon, Function | SmallTest | Level2)
{
    std::shared_ptr<Media::PixelMap> icon;
    session_->SetSessionIcon(icon);
    ASSERT_EQ(session_->Clear(), WSError::WS_OK);
    session_->SetSessionSnapshotListener(nullptr);
    ASSERT_EQ(session_->PendingSessionToForeground(), WSError::WS_OK);
}

/**
 * @tc.name: SetRaiseToAppTopForPointDownFunc
 * @tc.desc: SetRaiseToAppTopForPointDownFunc Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetRaiseToAppTopForPointDownFunc, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->SetRaiseToAppTopForPointDownFunc(nullptr);
    session_->RaiseToAppTopForPointDown();
    session_->HandlePointDownDialog();
    session_->ClearDialogVector();

    session_->SetBufferAvailableChangeListener(nullptr);
    session_->UnregisterSessionChangeListeners();
    session_->SetSessionStateChangeNotifyManagerListener(nullptr);
    session_->SetSessionInfoChangeNotifyManagerListener(nullptr);
    session_->NotifyFocusStatus(true);

    session_->SetRequestFocusStatusNotifyManagerListener(nullptr);
    session_->SetNotifyUIRequestFocusFunc(nullptr);
    session_->SetNotifyUILostFocusFunc(nullptr);
    session_->UnregisterSessionChangeListeners();
    ASSERT_EQ(WSError::WS_OK, session_->PendingSessionToBackgroundForDelegator());
}

/**
 * @tc.name: NotifyCloseExistPipWindow
 * @tc.desc: check func NotifyCloseExistPipWindow
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, NotifyCloseExistPipWindow, Function | SmallTest | Level2)
{
    sptr<SessionStageMocker> mockSessionStage = new(std::nothrow) SessionStageMocker();
    ASSERT_NE(mockSessionStage, nullptr);
    ManagerState key = ManagerState{0};
    session_->GetStateFromManager(key);
    session_->NotifyUILostFocus();
    session_->SetSystemSceneBlockingFocus(true);
    session_->GetBlockingFocus();
    session_->sessionStage_ = mockSessionStage;
    EXPECT_CALL(*(mockSessionStage), NotifyCloseExistPipWindow()).Times(1).WillOnce(Return(WSError::WS_OK));
    ASSERT_EQ(WSError::WS_OK, session_->NotifyCloseExistPipWindow());
    session_->sessionStage_ = nullptr;
    ASSERT_EQ(WSError::WS_ERROR_NULLPTR, session_->NotifyCloseExistPipWindow());
}

/**
 * @tc.name: SetSystemConfig
 * @tc.desc: SetSystemConfig Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetSystemConfig, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    SystemSessionConfig systemConfig;
    session_->SetSystemConfig(systemConfig);
    float snapshotScale = 0.5;
    session_->SetSnapshotScale(snapshotScale);
    session_->ProcessBackEvent();
    session_->NotifyOccupiedAreaChangeInfo(nullptr);
    session_->UpdateMaximizeMode(true);
    ASSERT_EQ(session_->GetZOrder(), 0);

    session_->SetUINodeId(0);
    session_->GetUINodeId();
    session_->SetShowRecent(true);
    session_->GetShowRecent();
    session_->SetBufferAvailable(true);

    session_->SetNeedSnapshot(true);
    session_->SetFloatingScale(0.5);
    ASSERT_EQ(session_->GetFloatingScale(), 0.5f);
    session_->SetScale(50, 100, 50, 100);
    session_->GetScaleX();
    session_->GetScaleY();
    session_->GetPivotX();
    session_->GetPivotY();
    session_->SetSCBKeepKeyboard(true);
    session_->GetSCBKeepKeyboardFlag();
    ASSERT_EQ(WSError::WS_OK, session_->MarkProcessed(11));
}

/**
 * @tc.name: SetOffset
 * @tc.desc: SetOffset Test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, SetOffset, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->SetOffset(50, 100);
    session_->GetOffsetX();
    session_->GetOffsetY();
    WSRectF bounds;
    session_->SetBounds(bounds);
    session_->GetBounds();
    session_->TransferAccessibilityHoverEvent(50, 100, 50, 50, 500);
    session_->UpdateTitleInTargetPos(true, 100);
    session_->SetNotifySystemSessionPointerEventFunc(nullptr);
    session_->SetNotifySystemSessionKeyEventFunc(nullptr);
    ASSERT_EQ(session_->GetBufferAvailable(), false);
}

/**
 * @tc.name: ResetSessionConnectState
 * @tc.desc: ResetSessionConnectState
 * @tc.type: FUNC
 */
HWTEST_F(WindowSessionTest, ResetSessionConnectState, Function | SmallTest | Level2)
{
    ASSERT_NE(session_, nullptr);
    session_->ResetSessionConnectState();
    ASSERT_EQ(session_->state_, SessionState::STATE_DISCONNECT);
    ASSERT_EQ(session_->GetCallingPid(), -1);
}
}
} // namespace Rosen
} // namespace OHOS

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

#include <gtest/gtest.h>
#include <parameters.h>
#include "ability_context_impl.h"
#include "display_info.h"
#include "display_manager.h"
#include "mock_session.h"
#include "window_session_impl.h"
#include "mock_uicontent.h"
#include "window_scene_session_impl.h"
#include "mock_window_adapter.h"
#include "singleton_mocker.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
using Mocker = SingletonMocker<WindowAdapter, MockWindowAdapter>;
uint32_t MaxWith = 32;
class MockWindowChangeListener : public IWindowChangeListener {
public:
    MOCK_METHOD3(OnSizeChange,
        void(Rect rect, WindowSizeChangeReason reason, const std::shared_ptr<RSTransaction> &rsTransaction));
};

class MockWindowLifeCycleListener : public IWindowLifeCycle {
public:
    MOCK_METHOD0(AfterForeground, void(void));
    MOCK_METHOD0(AfterBackground, void(void));
    MOCK_METHOD0(AfterFocused, void(void));
    MOCK_METHOD0(AfterUnfocused, void(void));
    MOCK_METHOD1(ForegroundFailed, void(int32_t));
    MOCK_METHOD0(AfterActive, void(void));
    MOCK_METHOD0(AfterInactive, void(void));
    MOCK_METHOD0(AfterResumed, void(void));
    MOCK_METHOD0(AfterPaused, void(void));
};

class WindowSceneSessionImplTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    std::shared_ptr<AbilityRuntime::AbilityContext> abilityContext_;
    std::unique_ptr<Mocker> m = std::make_unique<Mocker>();

private:
    RSSurfaceNode::SharedPtr CreateRSSurfaceNode();
};

void WindowSceneSessionImplTest::SetUpTestCase() {}

void WindowSceneSessionImplTest::TearDownTestCase() {}

void WindowSceneSessionImplTest::SetUp()
{
    abilityContext_ = std::make_shared<AbilityRuntime::AbilityContextImpl>();
}

void WindowSceneSessionImplTest::TearDown()
{
    abilityContext_ = nullptr;
}

RSSurfaceNode::SharedPtr WindowSceneSessionImplTest::CreateRSSurfaceNode()
{
    struct RSSurfaceNodeConfig rsSurfaceNodeConfig;
    rsSurfaceNodeConfig.SurfaceNodeName = "startingWindowTestSurfaceNode";
    auto surfaceNode = RSSurfaceNode::Create(rsSurfaceNodeConfig, RSSurfaceNodeType::DEFAULT);
    return surfaceNode;
}

namespace {
/**
 * @tc.name: CreateWindowAndDestroy01
 * @tc.desc: Create window and destroy window
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, CreateWindowAndDestroy01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    ASSERT_NE(nullptr, option);
    option->SetWindowName("CreateWindow01");
    sptr<WindowSceneSessionImpl> window = new WindowSceneSessionImpl(option);

    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);

    ASSERT_EQ(WMError::WM_OK, window->Create(abilityContext_, session));
    ASSERT_EQ(WMError::WM_ERROR_REPEAT_OPERATION, window->Create(abilityContext_, session));
    window->property_->SetPersistentId(1);
    ASSERT_EQ(WMError::WM_OK, window->Destroy(false));
    ASSERT_EQ(WMError::WM_OK, window->Create(abilityContext_, session));
}

/**
 * @tc.name: CreateWindowAndDestroy02
 * @tc.desc: Create window and destroy window
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, CreateWindowAndDestroy02, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    ASSERT_NE(nullptr, option);
    option->SetWindowName("CreateWindow01");
    sptr<WindowSceneSessionImpl> window = new WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    std::string identityToken = "testToken";
    window->Create(abilityContext_, session);
    ASSERT_EQ(WMError::WM_ERROR_REPEAT_OPERATION, window->Create(abilityContext_, session, identityToken));
    window->property_->SetPersistentId(1);
    window->Destroy(false);
    ASSERT_EQ(WMError::WM_ERROR_REPEAT_OPERATION, window->Create(abilityContext_, session, identityToken));
}

/**
 * @tc.name: CreateAndConnectSpecificSession01
 * @tc.desc: CreateAndConnectSpecificSession
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, CreateAndConnectSpecificSession01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("CreateAndConnectSpecificSession01");
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);

    windowscenesession->SetWindowType(WindowType::APP_MAIN_WINDOW_BASE);
    if (windowscenesession->CreateAndConnectSpecificSession() == WMError::WM_ERROR_NULLPTR)
    {
        ASSERT_EQ(WMError::WM_ERROR_NULLPTR, windowscenesession->CreateAndConnectSpecificSession());
    }
    windowscenesession->property_->SetPersistentId(102);
    windowscenesession->property_->SetParentPersistentId(100);
    windowscenesession->property_->SetParentId(100);
    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);

    ASSERT_EQ(WMError::WM_OK, windowscenesession->Create(abilityContext_, session));
}

/**
 * @tc.name: CreateAndConnectSpecificSession02
 * @tc.desc: CreateAndConnectSpecificSession
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, CreateAndConnectSpecificSession02, Function | SmallTest | Level2)
{
    sptr<WindowOption> option_ = new (std::nothrow) WindowOption();
    option_->SetWindowTag(WindowTag::SUB_WINDOW);
    option_->SetWindowName("ChildWindow0002");
    sptr<WindowSceneSessionImpl> parentscenesession_ = new (std::nothrow) WindowSceneSessionImpl(option_);
    ASSERT_NE(nullptr, parentscenesession_);
    
    SessionInfo sessionInfo_ = { "CreateTestBundle0", "CreateTestModule0", "CreateTestAbility0" };
    sptr<SessionMocker> session_ = new (std::nothrow) SessionMocker(sessionInfo_);
    ASSERT_NE(nullptr, session_);
    ASSERT_EQ(WMError::WM_OK, parentscenesession_->Create(abilityContext_, session_));
    parentscenesession_->property_->SetPersistentId(103);
    parentscenesession_->property_->SetParentPersistentId(102);
    parentscenesession_->property_->SetParentId(102);
    parentscenesession_->property_->type_ = WindowType::APP_MAIN_WINDOW_BASE;
    parentscenesession_->hostSession_ = session_;

    parentscenesession_->property_->type_ = WindowType::APP_SUB_WINDOW_BASE;
    if (parentscenesession_->CreateAndConnectSpecificSession() == WMError::WM_OK) {
        ASSERT_EQ(WMError::WM_OK, parentscenesession_->CreateAndConnectSpecificSession());
    }
}

/**
 * @tc.name: CreateAndConnectSpecificSession03
 * @tc.desc: CreateAndConnectSpecificSession
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, CreateAndConnectSpecificSession03, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowTag(WindowTag::SUB_WINDOW);
    option->SetWindowName("ChildWindow0003");
    option->SetExtensionTag(true);
    sptr<WindowSceneSessionImpl> parentSceneSession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, parentSceneSession);
    
    SessionInfo sessionInfo = { "CreateTestBundle0", "CreateTestModule0", "CreateTestAbility0" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    ASSERT_EQ(WMError::WM_OK, parentSceneSession->Create(abilityContext_, session));

    parentSceneSession->property_->SetParentPersistentId(102);
    parentSceneSession->property_->SetParentId(102);
    parentSceneSession->property_->type_ = WindowType::APP_MAIN_WINDOW_BASE;
    parentSceneSession->hostSession_ = session;

    parentSceneSession->property_->type_ = WindowType::APP_SUB_WINDOW_BASE;
    if (parentSceneSession->CreateAndConnectSpecificSession() == WMError::WM_OK) {
        ASSERT_EQ(WMError::WM_OK, parentSceneSession->CreateAndConnectSpecificSession());
    }
}

/**
 * @tc.name: CreateAndConnectSpecificSession04
 * @tc.desc: CreateAndConnectSpecificSession
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, CreateAndConnectSpecificSession04, Function | SmallTest | Level2)
{
    sptr<WindowOption> option_ = new (std::nothrow) WindowOption();
    option_->SetWindowTag(WindowTag::SUB_WINDOW);
    option_->SetWindowName("ChildSubWindow0004");
    sptr<WindowSceneSessionImpl> parentscenesession_ = new (std::nothrow) WindowSceneSessionImpl(option_);
    ASSERT_NE(nullptr, parentscenesession_);
    
    SessionInfo sessionInfo_ = { "CreateTestBundle4", "CreateTestModule4", "CreateTestAbility4" };
    sptr<SessionMocker> session_ = new (std::nothrow) SessionMocker(sessionInfo_);
    ASSERT_NE(nullptr, session_);
    ASSERT_EQ(WMError::WM_OK, parentscenesession_->Create(abilityContext_, session_));

    parentscenesession_->property_->SetPersistentId(104);
    parentscenesession_->property_->SetParentPersistentId(103);
    parentscenesession_->property_->SetParentId(103);
    parentscenesession_->property_->type_ = WindowType::APP_MAIN_WINDOW_BASE;
    parentscenesession_->hostSession_ = session_;

    parentscenesession_->property_->type_ = WindowType::APP_SUB_WINDOW_BASE;
    if (parentscenesession_->CreateAndConnectSpecificSession() == WMError::WM_OK) {
        ASSERT_EQ(WMError::WM_OK, parentscenesession_->CreateAndConnectSpecificSession());
    }
}

/**
 * @tc.name: CreateAndConnectSpecificSession05
 * @tc.desc: CreateAndConnectSpecificSession
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, CreateAndConnectSpecificSession05, Function | SmallTest | Level2)
{
    sptr<WindowOption> option_ = new (std::nothrow) WindowOption();
    option_->SetWindowTag(WindowTag::SUB_WINDOW);
    option_->SetWindowName("ChildSubSubWindow0005");
    sptr<WindowSceneSessionImpl> parentscenesession_ = new (std::nothrow) WindowSceneSessionImpl(option_);
    ASSERT_NE(nullptr, parentscenesession_);
    
    SessionInfo sessionInfo_ = { "CreateTestBundle5", "CreateTestModule5", "CreateTestAbility5" };
    sptr<SessionMocker> session_ = new (std::nothrow) SessionMocker(sessionInfo_);
    ASSERT_NE(nullptr, session_);
    ASSERT_EQ(WMError::WM_OK, parentscenesession_->Create(abilityContext_, session_));

    parentscenesession_->property_->SetParentPersistentId(104);
    parentscenesession_->property_->SetParentId(104);
    parentscenesession_->property_->type_ = WindowType::APP_MAIN_WINDOW_BASE;
    parentscenesession_->hostSession_ = session_;

    parentscenesession_->property_->type_ = WindowType::APP_SUB_WINDOW_BASE;
    if (parentscenesession_->CreateAndConnectSpecificSession() == WMError::WM_OK) {
        ASSERT_NE(WMError::WM_OK, parentscenesession_->CreateAndConnectSpecificSession());
    }
}

/**
 * @tc.name: CreateAndConnectSpecificSession06
 * @tc.desc: CreateAndConnectSpecificSession
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, CreateAndConnectSpecificSession06, Function | SmallTest | Level2)
{
    sptr<WindowOption> option_ = new (std::nothrow) WindowOption();
    option_->SetWindowTag(WindowTag::SYSTEM_WINDOW);
    option_->SetWindowName("ChildWindow0006");
    sptr<WindowSceneSessionImpl> parentscenesession_ = new (std::nothrow) WindowSceneSessionImpl(option_);
    ASSERT_NE(nullptr, parentscenesession_);
    
    SessionInfo sessionInfo_ = { "CreateTestBundle6", "CreateTestModule6", "CreateTestAbility6" };
    sptr<SessionMocker> session_ = new (std::nothrow) SessionMocker(sessionInfo_);
    ASSERT_NE(nullptr, session_);
    ASSERT_EQ(WMError::WM_OK, parentscenesession_->Create(abilityContext_, session_));
    
    parentscenesession_->property_->SetPersistentId(105);
    parentscenesession_->property_->SetParentPersistentId(102);
    parentscenesession_->property_->SetParentId(102);
    parentscenesession_->property_->type_ = WindowType::APP_MAIN_WINDOW_BASE;
    parentscenesession_->hostSession_ = session_;

    parentscenesession_->property_->type_ = WindowType::SYSTEM_WINDOW_BASE;
    if (parentscenesession_->CreateAndConnectSpecificSession() == WMError::WM_OK) {
        ASSERT_EQ(WMError::WM_OK, parentscenesession_->CreateAndConnectSpecificSession());
    }
}

/**
 * @tc.name: CreateAndConnectSpecificSession07
 * @tc.desc: CreateAndConnectSpecificSession
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, CreateAndConnectSpecificSession07, Function | SmallTest | Level2)
{
    sptr<WindowOption> option_ = new (std::nothrow) WindowOption();
    option_->SetWindowTag(WindowTag::SUB_WINDOW);
    option_->SetWindowName("ChildWindow0007");
    sptr<WindowSceneSessionImpl> parentscenesession_ = new (std::nothrow) WindowSceneSessionImpl(option_);
    ASSERT_NE(nullptr, parentscenesession_);
    
    SessionInfo sessionInfo_ = { "CreateTestBundle7", "CreateTestModule7", "CreateTestAbility7" };
    sptr<SessionMocker> session_ = new (std::nothrow) SessionMocker(sessionInfo_);
    ASSERT_NE(nullptr, session_);
    ASSERT_EQ(WMError::WM_OK, parentscenesession_->Create(abilityContext_, session_));
    
    parentscenesession_->property_->SetPersistentId(106);
    parentscenesession_->property_->SetParentPersistentId(105);
    parentscenesession_->property_->SetParentId(105);
    parentscenesession_->property_->type_ = WindowType::SYSTEM_WINDOW_BASE;
    parentscenesession_->hostSession_ = session_;

    parentscenesession_->property_->type_ = WindowType::SYSTEM_SUB_WINDOW_BASE;
    if (parentscenesession_->CreateAndConnectSpecificSession() == WMError::WM_OK) {
        ASSERT_EQ(WMError::WM_OK, parentscenesession_->CreateAndConnectSpecificSession());
    }
}

/**
 * @tc.name: CreateAndConnectSpecificSession08
 * @tc.desc: CreateAndConnectSpecificSession
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, CreateAndConnectSpecificSession08, Function | SmallTest | Level2)
{
    sptr<WindowOption> option_ = new (std::nothrow) WindowOption();
    option_->SetWindowTag(WindowTag::SUB_WINDOW);
    option_->SetWindowName("ChildWindow0008");
    sptr<WindowSceneSessionImpl> parentscenesession_ = new (std::nothrow) WindowSceneSessionImpl(option_);
    ASSERT_NE(nullptr, parentscenesession_);
    
    SessionInfo sessionInfo_ = { "CreateTestBundle8", "CreateTestModule8", "CreateTestAbility8" };
    sptr<SessionMocker> session_ = new (std::nothrow) SessionMocker(sessionInfo_);
    ASSERT_NE(nullptr, session_);
    ASSERT_EQ(WMError::WM_OK, parentscenesession_->Create(abilityContext_, session_));
    
    parentscenesession_->property_->SetPersistentId(107);
    parentscenesession_->property_->SetParentPersistentId(106);
    parentscenesession_->property_->SetParentId(106);
    parentscenesession_->property_->type_ = WindowType::SYSTEM_SUB_WINDOW_BASE;
    parentscenesession_->hostSession_ = session_;

    parentscenesession_->property_->type_ = WindowType::SYSTEM_SUB_WINDOW_BASE;
    if (parentscenesession_->CreateAndConnectSpecificSession() == WMError::WM_ERROR_INVALID_TYPE) {
        ASSERT_EQ(WMError::WM_ERROR_INVALID_TYPE, parentscenesession_->CreateAndConnectSpecificSession());
    }
}

/**
 * @tc.name: RecoverAndReconnectSceneSession
 * @tc.desc: RecoverAndReconnectSceneSession
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, RecoverAndReconnectSceneSession, Function | SmallTest | Level2)
{
    GTEST_LOG_(INFO) << "WindowSceneSessionImplTest: RecoverAndReconnectSceneSession start";
    sptr<WindowOption> option = new WindowOption();
    option->SetWindowName("RecoverAndReconnectSceneSession");
    sptr<WindowSceneSessionImpl> windowSceneSession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowSceneSession);

    ASSERT_EQ(WMError::WM_ERROR_NULLPTR, windowSceneSession->RecoverAndReconnectSceneSession());
    GTEST_LOG_(INFO) << "WindowSceneSessionImplTest: RecoverAndReconnectSceneSession end";
}

/**
 * @tc.name: IsValidSystemWindowType01
 * @tc.desc: IsValidSystemWindowType
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, IsValidSystemWindowType01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("IsValidSystemWindowType01");
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);
    ASSERT_FALSE(!windowscenesession->IsValidSystemWindowType(WindowType::WINDOW_TYPE_SYSTEM_ALARM_WINDOW));
    ASSERT_FALSE(!windowscenesession->IsValidSystemWindowType(WindowType::WINDOW_TYPE_INPUT_METHOD_FLOAT));
    ASSERT_FALSE(!windowscenesession->IsValidSystemWindowType(WindowType::WINDOW_TYPE_FLOAT_CAMERA));
    ASSERT_FALSE(!windowscenesession->IsValidSystemWindowType(WindowType::WINDOW_TYPE_DIALOG));
    ASSERT_FALSE(!windowscenesession->IsValidSystemWindowType(WindowType::WINDOW_TYPE_FLOAT));
    ASSERT_FALSE(!windowscenesession->IsValidSystemWindowType(WindowType::WINDOW_TYPE_SCREENSHOT));
    ASSERT_FALSE(!windowscenesession->IsValidSystemWindowType(WindowType::WINDOW_TYPE_GLOBAL_SEARCH));
    ASSERT_FALSE(!windowscenesession->IsValidSystemWindowType(WindowType::WINDOW_TYPE_VOICE_INTERACTION));
    ASSERT_FALSE(!windowscenesession->IsValidSystemWindowType(WindowType::WINDOW_TYPE_POINTER));
    ASSERT_FALSE(!windowscenesession->IsValidSystemWindowType(WindowType::WINDOW_TYPE_TOAST));
    ASSERT_TRUE(!windowscenesession->IsValidSystemWindowType(WindowType::WINDOW_TYPE_DOCK_SLICE));
    ASSERT_TRUE(!windowscenesession->IsValidSystemWindowType(WindowType::WINDOW_TYPE_APP_LAUNCHING));
}

/*
 * @tc.name: InvalidWindow
 * @tc.desc: InvalidWindow test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, InvalidWindow, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("InvalidWindow");
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, window->MoveTo(0, 0));
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, window->Resize(0, 0));
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, window->SetBackgroundColor(std::string("???")));
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, window->SetTransparent(false));
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, window->Show(2, false));
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, window->Resize(2, 2));
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, window->Minimize());
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, window->Maximize());
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, window->MaximizeFloating());
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, window->Recover());
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, window->MaximizeFloating());
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, window->SetGlobalMaximizeMode(MaximizeMode::MODE_AVOID_SYSTEM_BAR));
}

/**
 * @tc.name: FindParentSessionByParentId01
 * @tc.desc: FindParentSessionByParentId
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, FindParentSessionByParentId01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowTag(WindowTag::MAIN_WINDOW);
    option->SetWindowName("FindParentSessionByParentId01");
    sptr<WindowSceneSessionImpl> parentscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, parentscenesession);
    
    parentscenesession->SetWindowType(WindowType::WINDOW_TYPE_DIALOG);
    ASSERT_TRUE(parentscenesession->FindMainWindowWithContext() == nullptr);
    parentscenesession->SetWindowType(WindowType::ABOVE_APP_SYSTEM_WINDOW_END);
    ASSERT_TRUE(parentscenesession->FindMainWindowWithContext() == nullptr);

    parentscenesession->property_->SetPersistentId(1112);
    parentscenesession->property_->SetParentId(1000);
    parentscenesession->property_->SetParentPersistentId(1000);
    parentscenesession->property_->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);

    ASSERT_EQ(WMError::WM_OK, parentscenesession->Create(abilityContext_, session));
    parentscenesession->hostSession_ = session;
    ASSERT_TRUE(nullptr != parentscenesession->FindParentSessionByParentId(1112));
}

/**
 * @tc.name: FindMainWindowWithContext01
 * @tc.desc: FindMainWindowWithContext
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, FindMainWindowWithContext01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowTag(WindowTag::MAIN_WINDOW);
    option->SetWindowName("FindMainWindowWithContext01");
    sptr<WindowSceneSessionImpl> parentscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, parentscenesession);
    
    parentscenesession->SetWindowType(WindowType::WINDOW_TYPE_DIALOG);
    ASSERT_TRUE(parentscenesession->FindMainWindowWithContext() == nullptr);
    parentscenesession->SetWindowType(WindowType::ABOVE_APP_SYSTEM_WINDOW_END);
    ASSERT_TRUE(parentscenesession->FindMainWindowWithContext() == nullptr);

    parentscenesession->property_->SetPersistentId(1002);
    parentscenesession->property_->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);

    ASSERT_EQ(WMError::WM_OK, parentscenesession->Create(abilityContext_, session));
    parentscenesession->hostSession_ = session;
    ASSERT_TRUE(nullptr != parentscenesession->FindParentSessionByParentId(1002));
    
    sptr<WindowOption> option_ = new (std::nothrow) WindowOption();
    option_->SetWindowTag(WindowTag::MAIN_WINDOW);
    option_->SetWindowName("FindMainWindowWithContext02");
    sptr<WindowSceneSessionImpl> parentscenesession_ = new (std::nothrow) WindowSceneSessionImpl(option_);
    ASSERT_NE(nullptr, parentscenesession_);

    SessionInfo sessionInfo_ = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session_ = new (std::nothrow) SessionMocker(sessionInfo_);
    ASSERT_NE(nullptr, session_);
    ASSERT_EQ(WMError::WM_OK, parentscenesession_->Create(abilityContext_, session_));

    parentscenesession_->hostSession_ = session_;
    parentscenesession_->property_->type_ = WindowType::WINDOW_TYPE_DIALOG;
    ASSERT_FALSE(parentscenesession_->FindMainWindowWithContext() == nullptr);
}

/**
 * @tc.name: DisableAppWindowDecor01
 * @tc.desc: DisableAppWindowDecor
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, DisableAppWindowDecor01, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("Connect01");
    sptr<WindowSessionImpl> windowession = new (std::nothrow) WindowSessionImpl(option);
    ASSERT_NE(nullptr, windowession);

    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);

    ASSERT_NE(nullptr, session);
    std::shared_ptr<AbilityRuntime::Context> context;
    ASSERT_EQ(WMError::WM_OK, windowession->Create(context, session));

    windowession->UpdateDecorEnable(false);
    windowession->windowSystemConfig_.isSystemDecorEnable_ = false;

    windowession->property_->SetWindowType(WindowType::WINDOW_TYPE_FLOAT);
    windowession->DisableAppWindowDecor();
    ASSERT_FALSE(windowession->IsDecorEnable());
    windowession->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    windowession->DisableAppWindowDecor();
}

/**
 * @tc.name: HandleBackEvent01
 * @tc.desc: HandleBackEvent
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, HandleBackEvent01, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("HandleBackEvent01");
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);

    windowscenesession->uiContent_ = std::make_unique<Ace::UIContentMocker>();
    ASSERT_EQ(WSError::WS_OK, windowscenesession->HandleBackEvent());
}

/**
 * @tc.name: RaiseToAppTop01
 * @tc.desc: RaiseToAppTop
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, RaiseToAppTop01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("RaiseToAppTop01");
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);

    windowscenesession->property_->SetPersistentId(6);
    windowscenesession->property_->SetParentPersistentId(6);
    windowscenesession->property_->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    ASSERT_EQ(WmErrorCode::WM_ERROR_INVALID_CALLING, windowscenesession->RaiseToAppTop());

    windowscenesession->property_->SetWindowType(WindowType::WINDOW_TYPE_APP_SUB_WINDOW);
    windowscenesession->state_ = WindowState::STATE_HIDDEN;
    ASSERT_EQ(WmErrorCode::WM_ERROR_STATE_ABNORMALLY, windowscenesession->RaiseToAppTop());

    windowscenesession->state_ = WindowState::STATE_SHOWN;
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    windowscenesession->hostSession_ = session;
    ASSERT_EQ(WmErrorCode::WM_OK, windowscenesession->RaiseToAppTop());
}

/**
 * @tc.name: Resize01
 * @tc.desc: Resize
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, Resize01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("Resize01");
    option->SetWindowMode(WindowMode::WINDOW_MODE_FLOATING);
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);

    windowscenesession->property_->SetPersistentId(888);
    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    windowscenesession->hostSession_ = session;
    Rect rect = {2, 2, 2, 2};
    windowscenesession->property_->SetWindowRect(rect);
    windowscenesession->property_->SetWindowType(WindowType::WINDOW_TYPE_FLOAT_CAMERA);
    windowscenesession->state_ = WindowState::STATE_FROZEN;
    windowscenesession->hostSession_ = session;
    windowscenesession->Resize(1, 1);
}

/**
 * @tc.name: Resize02
 * @tc.desc: Resize
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, Resize02, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("Resize02");
    option->SetWindowType(WindowType::WINDOW_TYPE_FLOAT);
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);

    windowscenesession->property_->SetPersistentId(888);
    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    windowscenesession->state_ = WindowState::STATE_FROZEN;
    windowscenesession->hostSession_ = session;

    windowscenesession->SetDefaultProperty();
    ASSERT_EQ(WMError::WM_OK, windowscenesession->Resize(1, 1));

    windowscenesession->property_->SetWindowMode(WindowMode::WINDOW_MODE_FULLSCREEN);
    ASSERT_EQ(WMError::WM_ERROR_INVALID_OPERATION, windowscenesession->Resize(1, 1));
}

/**
 * @tc.name: MoveTo01
 * @tc.desc: MoveTo
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, MoveTo01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("MoveTo01");
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);

    windowscenesession->property_->SetPersistentId(1);
    windowscenesession->state_ = WindowState::STATE_HIDDEN;
    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    windowscenesession->hostSession_ = session;
    ASSERT_EQ(WMError::WM_OK, windowscenesession->MoveTo(2, 2));
}

/**
 * @tc.name: Minimize01
 * @tc.desc: Minimize
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, Minimize01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("Minimize01");
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);

    windowscenesession->property_->SetPersistentId(1);
    windowscenesession->property_->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    windowscenesession->hostSession_ = session;
    ASSERT_EQ(WMError::WM_OK, windowscenesession->Minimize());
}

/**
 * @tc.name: StartMove01
 * @tc.desc: StartMove
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, StartMove01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("StartMove01");
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);
    windowscenesession->property_->SetPersistentId(1);
    // show with null session

    windowscenesession->property_->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    windowscenesession->hostSession_ = session;
    windowscenesession->StartMove();
    ASSERT_NE(nullptr, session);
}

/**
 * @tc.name: Close01
 * @tc.desc: Close
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, Close01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("Close01");
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);
    windowscenesession->property_->SetPersistentId(1);
    windowscenesession->property_->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    windowscenesession->hostSession_ = session;
    ASSERT_EQ(WMError::WM_OK, windowscenesession->Close());
}

/**
 * @tc.name: Close02
 * @tc.desc: Close
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, Close02, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("Close02");
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);
    windowscenesession->property_->SetPersistentId(-1);
    windowscenesession->property_->SetParentPersistentId(-1);
    windowscenesession->property_->SetPersistentId(1);
    windowscenesession->property_->SetWindowType(WindowType::WINDOW_TYPE_APP_SUB_WINDOW);
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
}

/**
 * @tc.name: SetActive01
 * @tc.desc: SetActive
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SetActive01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("SetActive01");
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);
    windowscenesession->property_->SetPersistentId(1);
    windowscenesession->property_->SetWindowType(WindowType::WINDOW_TYPE_APP_SUB_WINDOW);
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);

    windowscenesession->hostSession_ = session;
    ASSERT_EQ(WSError::WS_OK, windowscenesession->SetActive(false));
    ASSERT_EQ(WSError::WS_OK, windowscenesession->SetActive(true));
}

/**
 * @tc.name: Recover01
 * @tc.desc: Recover
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, Recover01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("Recover01");
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);

    windowscenesession->property_->SetPersistentId(1);
    windowscenesession->property_->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    windowscenesession->hostSession_ = session;
    ASSERT_EQ(WMError::WM_OK, windowscenesession->Recover());
}

/**
 * @tc.name: Maximize01
 * @tc.desc: Maximize
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, Maximize01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("Maximize01");
    option->SetWindowType(WindowType::WINDOW_TYPE_APP_SUB_WINDOW);
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);
    windowscenesession->property_->SetPersistentId(1);
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    windowscenesession->hostSession_ = session;
    ASSERT_EQ(WMError::WM_OK, windowscenesession->Maximize());
}

/**
 * @tc.name: Hide01
 * @tc.desc: Hide session
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, Hide01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("Hide01");
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);
    window->property_->SetPersistentId(1);
    // show with null session
    ASSERT_EQ(WMError::WM_ERROR_NULLPTR, window->Hide(2, false, false));

    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->hostSession_ = session;
    ASSERT_EQ(WMError::WM_OK, window->Hide(2, false, false));
    ASSERT_EQ(WMError::WM_OK, window->Hide(2, false, false));

    window->state_ = WindowState::STATE_CREATED;
    ASSERT_EQ(WMError::WM_OK, window->Hide(2, false, false));
    window->state_ = WindowState::STATE_SHOWN;
    window->property_->type_ = WindowType::APP_SUB_WINDOW_BASE;
    ASSERT_EQ(WMError::WM_OK, window->Hide(2, false, false));

    window->property_->type_ = WindowType::APP_SUB_WINDOW_BASE;
    if (window->Destroy(false) == WMError::WM_OK) {
        ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, window->Destroy(false));
    }
}

/**
 * @tc.name: Show01
 * @tc.desc: Show session
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, Show01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("Show01");
    option->SetDisplayId(0);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);
    window->property_->SetPersistentId(1);

    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);

    window->hostSession_ = session;
    ASSERT_EQ(WMError::WM_OK, window->Show(2, false));

    window->state_ = WindowState::STATE_CREATED;
    ASSERT_EQ(WMError::WM_OK, window->Show(2, false));
    ASSERT_EQ(WMError::WM_OK, window->Destroy(false));
}

/**
 * @tc.name: SetBackgroundColor01
 * @tc.desc: test SetBackgroundColor withow uiContent
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SetBackgroundColor01, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("SetBackgroundColor01");
    option->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    option->SetWindowMode(WindowMode::WINDOW_MODE_FULLSCREEN);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    std::unique_ptr<Mocker> m = std::make_unique<Mocker>();
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);

    std::shared_ptr<AbilityRuntime::Context> context;
    ASSERT_EQ(WMError::WM_OK, window->Create(context, session));

    window->property_->SetPersistentId(1);
    window->Show();
}

/*
 * @tc.name: SetTransparent
 * @tc.desc: SetTransparent test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SetTransparent, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("SetTransparent");
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, window->SetTransparent(true));
    window->property_->SetPersistentId(1);
    window->property_->SetWindowType(WindowType::APP_SUB_WINDOW_BASE);
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->hostSession_ = session;
    window->uiContent_ = std::make_unique<Ace::UIContentMocker>();
    window->SetBackgroundColor(333);
    if (window->SetTransparent(true) == WMError::WM_OK) {
        ASSERT_EQ(WMError::WM_OK, window->SetTransparent(true));
    }
}

/*
 * @tc.name: SetAspectRatio
 * @tc.desc: SetAspectRatio test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SetAspectRatio, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("SetAspectRatio");
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    window->property_->SetWindowType(WindowType::APP_SUB_WINDOW_BASE);
    ASSERT_EQ(WMError::WM_ERROR_NULLPTR, window->SetAspectRatio(0.1));

    window->property_->SetPersistentId(1);
    window->property_->SetDisplayId(3);
    WindowLimits windowLimits = { 3, 3, 3, 3, 2.0, 2.0 };
    window->property_->SetWindowLimits(windowLimits);
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->hostSession_ = session;
    ASSERT_EQ(WMError::WM_OK, window->SetAspectRatio(0.1));
}

/*
 * @tc.name: ResetAspectRatio
 * @tc.desc: ResetAspectRatio test GetAvoidAreaByType
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, ResetAspectRatio, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("ResetAspectRatio");
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    window->property_->SetWindowType(WindowType::APP_SUB_WINDOW_BASE);
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->hostSession_ = session;
    ASSERT_EQ(WMError::WM_OK, window->ResetAspectRatio());
}

/*
 * @tc.name: GetAvoidAreaByType
 * @tc.desc: GetAvoidAreaByType test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, GetAvoidAreaByType, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowMode(WindowMode::WINDOW_MODE_PIP);
    option->SetWindowName("GetAvoidAreaByType");
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);

    window->property_->SetPersistentId(1);
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    AvoidArea avoidarea;
    ASSERT_EQ(WMError::WM_ERROR_NULLPTR, window->GetAvoidAreaByType(AvoidAreaType::TYPE_CUTOUT, avoidarea));
}

/*
 * @tc.name: Immersive
 * @tc.desc: Immersive01 test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, Immersive, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowMode(WindowMode::WINDOW_MODE_PIP);
    option->SetWindowName("Immersive");
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);


    ASSERT_EQ(WMError::WM_ERROR_NULLPTR, window->SetLayoutFullScreen(false));
    ASSERT_EQ(WMError::WM_ERROR_NULLPTR, window->SetFullScreen(false));
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->hostSession_ = session;
 
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, window->SetFullScreen(false));
    ASSERT_EQ(false, window->IsLayoutFullScreen());
    ASSERT_EQ(false, window->IsFullScreen());
}

/*
 * @tc.name: SystemBarProperty
 * @tc.desc: SystemBarProperty01 test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SystemBarProperty, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("SystemBarProperty");
    option->SetWindowMode(WindowMode::WINDOW_MODE_PIP);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);

    SystemBarProperty property = SystemBarProperty();
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW,
        window->SetSystemBarProperty(WindowType::WINDOW_TYPE_STATUS_BAR, property));
}

/*
 * @tc.name: SystemBarProperty02
 * @tc.desc: SystemBarProperty02 test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SystemBarProperty02, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("SystemBarProperty02");
    ASSERT_NE(nullptr, option);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);

    window->state_ = WindowState::STATE_SHOWN;
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->property_->SetPersistentId(1);
    window->hostSession_ = session;

    SystemBarProperty property;
    ASSERT_EQ(WMError::WM_OK, window->SetSystemBarProperty(WindowType::WINDOW_TYPE_STATUS_BAR, property));
    ASSERT_FALSE(window->property_->GetSystemBarProperty()[WindowType::WINDOW_TYPE_STATUS_BAR].enableAnimation_);

    property.enableAnimation_ = false;
    ASSERT_EQ(WMError::WM_OK, window->SetSystemBarProperty(WindowType::WINDOW_TYPE_STATUS_BAR, property));
    ASSERT_FALSE(window->property_->GetSystemBarProperty()[WindowType::WINDOW_TYPE_STATUS_BAR].enableAnimation_);
}

/*
 * @tc.name: SystemBarProperty03
 * @tc.desc: SystemBarProperty03 test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SystemBarProperty03, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("SystemBarProperty03");
    ASSERT_NE(nullptr, option);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);

    window->state_ = WindowState::STATE_SHOWN;
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->property_->SetPersistentId(1);
    window->hostSession_ = session;

    SystemBarProperty property;
    property.enableAnimation_ = true;
    ASSERT_EQ(WMError::WM_OK, window->SetSystemBarProperty(WindowType::WINDOW_TYPE_STATUS_BAR, property));
    ASSERT_TRUE(window->property_->GetSystemBarProperty()[WindowType::WINDOW_TYPE_STATUS_BAR].enableAnimation_);
}

/*
 * @tc.name: SystemBarProperty04
 * @tc.desc: SystemBarProperty04 test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SystemBarProperty04, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("SystemBarProperty04");
    ASSERT_NE(nullptr, option);
    option->SetWindowMode(WindowMode::WINDOW_MODE_PIP);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);

    SystemBarProperty property;
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW,
        window->SetSpecificBarProperty(WindowType::WINDOW_TYPE_STATUS_BAR, property));
}

/*
 * @tc.name: SystemBarProperty05
 * @tc.desc: SystemBarProperty05 test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SystemBarProperty05, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("SystemBarProperty05");
    ASSERT_NE(nullptr, option);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);

    window->state_ = WindowState::STATE_SHOWN;
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->property_->SetPersistentId(1);
    window->hostSession_ = session;

    SystemBarProperty property;
    ASSERT_EQ(WMError::WM_OK, window->SetSpecificBarProperty(WindowType::WINDOW_TYPE_STATUS_BAR, property));
    ASSERT_FALSE(window->property_->GetSystemBarProperty()[WindowType::WINDOW_TYPE_STATUS_BAR].enableAnimation_);

    property.enableAnimation_ = false;
    ASSERT_EQ(WMError::WM_OK, window->SetSpecificBarProperty(WindowType::WINDOW_TYPE_STATUS_BAR, property));
    ASSERT_FALSE(window->property_->GetSystemBarProperty()[WindowType::WINDOW_TYPE_STATUS_BAR].enableAnimation_);
}

/*
 * @tc.name: SystemBarProperty06
 * @tc.desc: SystemBarProperty06 test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SystemBarProperty06, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("SystemBarProperty06");
    ASSERT_NE(nullptr, option);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);

    window->state_ = WindowState::STATE_SHOWN;
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->property_->SetPersistentId(1);
    window->hostSession_ = session;

    SystemBarProperty property;
    property.enableAnimation_ = true;
    ASSERT_EQ(WMError::WM_OK, window->SetSpecificBarProperty(WindowType::WINDOW_TYPE_STATUS_BAR, property));
    ASSERT_TRUE(window->property_->GetSystemBarProperty()[WindowType::WINDOW_TYPE_STATUS_BAR].enableAnimation_);
}

/*
 * @tc.name: SystemBarProperty07
 * @tc.desc: SystemBarProperty07 test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SystemBarProperty07, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("SystemBarProperty07");
    ASSERT_NE(nullptr, option);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);

    window->state_ = WindowState::STATE_SHOWN;
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->property_->SetPersistentId(1);
    ASSERT_EQ(WMError::WM_OK, window->Create(abilityContext_, session));
    window->hostSession_ = session;

    SystemBarProperty property;
    ASSERT_EQ(WMError::WM_OK, window->SetSystemBarProperty(WindowType::WINDOW_TYPE_STATUS_BAR, property));
    ASSERT_EQ(SystemBarSettingFlag::DEFAULT_SETTING,
        window->GetSystemBarPropertyByType(WindowType::WINDOW_TYPE_STATUS_BAR).settingFlag_);
    
    property.enable_ = false;
    property.settingFlag_ = SystemBarSettingFlag::ENABLE_SETTING;
    ASSERT_EQ(WMError::WM_OK, window->SetSystemBarProperty(WindowType::WINDOW_TYPE_STATUS_BAR, property));
    ASSERT_EQ(SystemBarSettingFlag::ENABLE_SETTING,
        window->GetSystemBarPropertyByType(WindowType::WINDOW_TYPE_STATUS_BAR).settingFlag_);
    
    property.backgroundColor_ = 0xB3000000;
    property.settingFlag_ = SystemBarSettingFlag::COLOR_SETTING;
    ASSERT_EQ(WMError::WM_OK, window->SetSystemBarProperty(WindowType::WINDOW_TYPE_STATUS_BAR, property));
    ASSERT_EQ(SystemBarSettingFlag::COLOR_SETTING,
        window->GetSystemBarPropertyByType(WindowType::WINDOW_TYPE_STATUS_BAR).settingFlag_);
    
    property.enable_ = true;
    property.backgroundColor_ = 0x4C000000;
    property.settingFlag_ = SystemBarSettingFlag::COLOR_SETTING;
    ASSERT_EQ(WMError::WM_OK, window->SetSystemBarProperty(WindowType::WINDOW_TYPE_STATUS_BAR, property));
}

/*
 * @tc.name: SpecificBarProperty
 * @tc.desc: SpecificBarProperty01 test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SpecificBarProperty, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("SpecificBarProperty");
    option->SetWindowMode(WindowMode::WINDOW_MODE_PIP);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);

    SystemBarProperty property = SystemBarProperty();
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW,
        window->SetSpecificBarProperty(WindowType::WINDOW_TYPE_STATUS_BAR, property));
    if (window->property_ == nullptr) {
        ASSERT_EQ(WMError::WM_ERROR_NULLPTR,
            window->SetSpecificBarProperty(WindowType::WINDOW_TYPE_STATUS_BAR, property));
    }
}

/*
 * @tc.name: NotifySpecificWindowSessionProperty
 * @tc.desc: NotifySpecificWindowSessionProperty01 test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, NotifySpecificWindowSessionProperty, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowMode(WindowMode::WINDOW_MODE_PIP);
    option->SetWindowName("NotifySpecificWindowSessionProperty");
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);

    SystemBarProperty property = SystemBarProperty();
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW,
        window->NotifySpecificWindowSessionProperty(WindowType::WINDOW_TYPE_STATUS_BAR, property));
    window->property_->SetPersistentId(190);
    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->hostSession_ = session;
    window->state_ = WindowState::STATE_HIDDEN;
    ASSERT_EQ(WMError::WM_OK,
        window->NotifySpecificWindowSessionProperty(WindowType::WINDOW_TYPE_STATUS_BAR, property));
    window->state_ = WindowState::STATE_SHOWN;
    ASSERT_EQ(WMError::WM_OK,
        window->NotifySpecificWindowSessionProperty(WindowType::WINDOW_TYPE_STATUS_BAR, property));
}

/*
 * @tc.name: LimitCameraFloatWindowMininumSize
 * @tc.desc: LimitCameraFloatWindowMininumSize01 test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, LimitCameraFloatWindowMininumSize, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowMode(WindowMode::WINDOW_MODE_PIP);
    option->SetWindowName("LimitCameraFloatWindowMininumSize");
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    uint32_t width = 33;
    uint32_t height = 31;
    float vpr = 0.0f;
    window->LimitCameraFloatWindowMininumSize(width, height, vpr);
}

/*
 * @tc.name: NotifyWindowNeedAvoid
 * @tc.desc: NotifyWindowNeedAvoid test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, NotifyWindowNeedAvoid, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("NotifyWindowNeedAvoid");
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, window->NotifyWindowNeedAvoid(false));

    window->state_ = WindowState::STATE_SHOWN;
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->property_->SetPersistentId(190);
    window->hostSession_ = session;
    ASSERT_EQ(WMError::WM_OK, window->NotifyWindowNeedAvoid(false));
}

/*
 * @tc.name: SetLayoutFullScreenByApiVersion
 * @tc.desc: SetLayoutFullScreenByApiVersion test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SetLayoutFullScreenByApiVersion, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("SetLayoutFullScreenByApiVersion");
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, window->SetLayoutFullScreenByApiVersion(false));
    window->state_ = WindowState::STATE_SHOWN;
    window->property_->SetPersistentId(190);
    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->hostSession_ = session;
    ASSERT_EQ(WMError::WM_OK, window->SetLayoutFullScreenByApiVersion(false));
}

/*
 * @tc.name: SetGlobalMaximizeMode
 * @tc.desc: SetGlobalMaximizeMode test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SetGlobalMaximizeMode, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("SetGlobalMaximizeMode");
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, window->SetGlobalMaximizeMode(MaximizeMode::MODE_RECOVER));

    window->state_ = WindowState::STATE_SHOWN;
    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->property_->SetPersistentId(190);
    window->hostSession_ = session;
    window->property_->SetWindowType(WindowType::APP_SUB_WINDOW_BASE);
    ASSERT_EQ(WMError::WM_ERROR_INVALID_PARAM, window->SetGlobalMaximizeMode(MaximizeMode::MODE_RECOVER));

    window->property_->SetWindowType(WindowType::APP_MAIN_WINDOW_BASE);
    ASSERT_EQ(WMError::WM_OK, window->SetGlobalMaximizeMode(MaximizeMode::MODE_RECOVER));
}

/*
 * @tc.name: CheckParmAndPermission
 * @tc.desc: CheckParmAndPermission test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, CheckParmAndPermission, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    window->property_->SetWindowName("CheckParmAndPermission");
    window->property_->SetWindowType(WindowType::SYSTEM_SUB_WINDOW_BASE);

    auto surfaceNode = window->GetSurfaceNode();
    if (surfaceNode == nullptr) {
        ASSERT_EQ(WMError::WM_ERROR_NULLPTR, window->CheckParmAndPermission());
    } else {
        ASSERT_EQ(WMError::WM_OK, window->CheckParmAndPermission());
        window->property_->SetWindowType(WindowType::WINDOW_TYPE_APP_SUB_WINDOW);
        ASSERT_EQ(WMError::WM_OK, window->CheckParmAndPermission());
    }
}

/*
 * @tc.name: SetBackdropBlurStyle
 * @tc.desc: SetBackdropBlurStyle test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SetBackdropBlurStyle, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    window->property_->SetWindowName("SetBackdropBlurStyle");
    window->property_->SetWindowType(WindowType::SYSTEM_SUB_WINDOW_BASE);
    window->property_->SetDisplayId(3);

    auto surfaceNode = window->GetSurfaceNode();
    if (surfaceNode == nullptr) {
        ASSERT_EQ(WMError::WM_ERROR_NULLPTR, window->CheckParmAndPermission());
        ASSERT_EQ(WMError::WM_ERROR_NULLPTR, window->SetBackdropBlurStyle(WindowBlurStyle::WINDOW_BLUR_OFF));
    } else {
    ASSERT_EQ(WMError::WM_OK, window->SetBackdropBlurStyle(WindowBlurStyle::WINDOW_BLUR_OFF));
    ASSERT_EQ(WMError::WM_ERROR_INVALID_PARAM, window->SetBackdropBlurStyle(WindowBlurStyle::WINDOW_BLUR_THICK));
    }
}

/*
 * @tc.name: SetTurnScreenOn
 * @tc.desc: SetTurnScreenOn test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SetTurnScreenOn, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    window->property_->SetWindowName("SetTurnScreenOn");
    window->property_->SetWindowType(WindowType::SYSTEM_SUB_WINDOW_BASE);
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, window->SetTurnScreenOn(false));

    window->property_->SetPersistentId(1);
    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->hostSession_ = session;
    window->SetTurnScreenOn(false);
}

/*
 * @tc.name: SetBlur
 * @tc.desc: SetBlur test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SetBlur, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    window->property_->SetWindowName("SetBlur");

    auto surfaceNode = window->GetSurfaceNode();
    if (surfaceNode == nullptr) {
    ASSERT_EQ(WMError::WM_ERROR_NULLPTR, window->CheckParmAndPermission());
    } else {
    window->property_->SetWindowType(WindowType::SYSTEM_SUB_WINDOW_BASE);
    ASSERT_EQ(WMError::WM_ERROR_INVALID_PARAM, window->SetBlur(-1.0));
    ASSERT_EQ(WMError::WM_OK, window->SetBlur(1.0));
    }
}

/*
 * @tc.name: SetKeepScreenOn
 * @tc.desc: SetKeepScreenOn test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SetKeepScreenOn, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    window->property_->SetWindowName("SetKeepScreenOn");
    window->property_->SetWindowType(WindowType::SYSTEM_SUB_WINDOW_BASE);
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, window->SetKeepScreenOn(false));

    window->property_->SetPersistentId(1);
    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->hostSession_ = session;
    window->SetKeepScreenOn(false);
    ASSERT_FALSE(window->IsKeepScreenOn());
}

/*
 * @tc.name: SetPrivacyMode
 * @tc.desc: SetPrivacyMode test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SetPrivacyMode, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    window->property_->SetWindowName("SetPrivacyMode");
    window->property_->SetWindowType(WindowType::SYSTEM_SUB_WINDOW_BASE);
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, window->SetPrivacyMode(false));

    window->property_->SetPersistentId(1);
    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->hostSession_ = session;
    if (WMError::WM_OK == window->SetPrivacyMode(false)) {
    ASSERT_EQ(WMError::WM_OK, window->SetPrivacyMode(false));
    ASSERT_EQ(false, window->IsPrivacyMode());
    }else if (WMError::WM_DO_NOTHING == window->SetPrivacyMode(false)) {
    ASSERT_EQ(WMError::WM_DO_NOTHING, window->SetPrivacyMode(false));
    }
}

/*
 * @tc.name: IsPrivacyMode
 * @tc.desc: IsPrivacyMode test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, IsPrivacyModec, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    window->property_->SetWindowName("IsPrivacyModec");
    window->property_->SetWindowType(WindowType::SYSTEM_SUB_WINDOW_BASE);
    window->SetPrivacyMode(false);
}

/*
 * @tc.name: SetSystemPrivacyMode
 * @tc.desc: SetSystemPrivacyMode test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SetSystemPrivacyMode, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    window->property_->SetWindowName("SetSystemPrivacyMode");
    window->property_->SetWindowType(WindowType::SYSTEM_SUB_WINDOW_BASE);
    window->SetSystemPrivacyMode(false);
    ASSERT_EQ(false, window->property_->GetSystemPrivacyMode());
}

/*
 * @tc.name: SetSnapshotSkip
 * @tc.desc: SetSnapshotSkip test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SetSnapshotSkip, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    window->property_->SetWindowName("SetSnapshotSkip");
    window->property_->SetWindowType(WindowType::ABOVE_APP_SYSTEM_WINDOW_BASE);
    window->property_->SetPersistentId(1);
    auto surfaceNode_mocker = CreateRSSurfaceNode();
    if (surfaceNode_mocker != nullptr) {
    ASSERT_NE(nullptr, surfaceNode_mocker);
    }

    window->surfaceNode_ = surfaceNode_mocker;
    auto surfaceNode = window->GetSurfaceNode();

    if (surfaceNode != nullptr) {
    ASSERT_EQ(WMError::WM_OK, window->SetSnapshotSkip(false));
    } else {
    ASSERT_EQ(nullptr, surfaceNode);
    }
}

/*
 * @tc.name: SetLayoutFullScreen
 * @tc.desc: SetLayoutFullScreen test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SetLayoutFullScreen, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    window->property_->SetWindowName("SetLayoutFullScreen");
    window->property_->SetWindowType(WindowType::SYSTEM_SUB_WINDOW_BASE);
    window->SetLayoutFullScreen(false);

    window->property_->SetPersistentId(1);
    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->hostSession_ = session;
    ASSERT_EQ(WMError::WM_OK, window->SetLayoutFullScreen(false));
    ASSERT_EQ(false, window->IsLayoutFullScreen());
}

/*
 * @tc.name: SetFullScreen
 * @tc.desc: SetFullScreen test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SetFullScreen, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    window->property_->SetWindowName("SetFullScreen");
    window->property_->SetWindowType(WindowType::SYSTEM_SUB_WINDOW_BASE);
    window->SetFullScreen(false);
    window->property_->SetPersistentId(1);
    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->hostSession_ = session;

    ASSERT_EQ(WMError::WM_OK, window->SetFullScreen(false));
    ASSERT_EQ(false, window->IsFullScreen());
}

/*
 * @tc.name: SetShadowOffsetX
 * @tc.desc: SetShadowOffsetX test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SetShadowOffsetX, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    window->property_->SetWindowName("SetKeepScreenOn");
    window->property_->SetWindowType(WindowType::SYSTEM_SUB_WINDOW_BASE);
    auto surfaceNode = window->GetSurfaceNode();
    if (surfaceNode == nullptr) {
        ASSERT_EQ(WMError::WM_ERROR_NULLPTR, window->CheckParmAndPermission());
    } else {
        ASSERT_EQ(WMError::WM_OK, window->SetShadowOffsetX(1.0));
    }
}

/*
 * @tc.name: SetShadowOffsetY
 * @tc.desc: SetShadowOffsetY test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SetShadowOffsetY, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    window->property_->SetWindowName("SetShadowOffsetY");
    window->property_->SetWindowType(WindowType::SYSTEM_SUB_WINDOW_BASE);

    auto surfaceNode = window->GetSurfaceNode();
    if (surfaceNode == nullptr) {
        ASSERT_EQ(WMError::WM_ERROR_NULLPTR, window->CheckParmAndPermission());
    } else {
        ASSERT_EQ(WMError::WM_OK, window->SetShadowOffsetY(1.0));
    }
}

/*
 * @tc.name: SetBackdropBlur
 * @tc.desc: SetBackdropBlur test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SetBackdropBlur, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    window->property_->SetWindowName("SetBackdropBlur");
    window->property_->SetWindowType(WindowType::SYSTEM_SUB_WINDOW_BASE);

    auto surfaceNode = window->GetSurfaceNode();
    if (surfaceNode == nullptr) {
        ASSERT_EQ(WMError::WM_ERROR_NULLPTR, window->CheckParmAndPermission());
    } else {
        ASSERT_EQ(WMError::WM_ERROR_INVALID_PARAM, window->SetBackdropBlur(-1.0));
        ASSERT_EQ(WMError::WM_OK, window->SetBackdropBlur(1.0));
    }
}

/*
 * @tc.name: SetShadowColor
 * @tc.desc: SetShadowColor test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SetShadowColor, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    window->property_->SetWindowName("SetShadowColor");
    window->property_->SetWindowType(WindowType::SYSTEM_SUB_WINDOW_BASE);

    auto surfaceNode = window->GetSurfaceNode();
    if (surfaceNode == nullptr) {
        ASSERT_EQ(WMError::WM_ERROR_NULLPTR, window->CheckParmAndPermission());
    }else {
        ASSERT_EQ(WMError::WM_ERROR_INVALID_PARAM, window->SetShadowColor("111ff22ee44"));
        ASSERT_EQ(WMError::WM_OK, window->SetShadowColor("#ff22ee44"));
        ASSERT_EQ(WMError::WM_OK, window->SetShadowColor("#000999"));
    }
}

/*
 * @tc.name: SetCornerRadius
 * @tc.desc: SetCornerRadius test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SetCornerRadius, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    window->property_->SetWindowName("SetCornerRadius");
    window->property_->SetWindowType(WindowType::SYSTEM_SUB_WINDOW_BASE);

    auto surfaceNode = window->GetSurfaceNode();
    if (surfaceNode == nullptr) {
        ASSERT_EQ(WMError::WM_ERROR_NULLPTR, window->SetCornerRadius(1.0));
    } else {
        ASSERT_EQ(WMError::WM_OK, window->SetCornerRadius(1.0));
    }
}

/*
 * @tc.name: SetShadowRadius
 * @tc.desc: SetShadowRadius test
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SetShadowRadius, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    window->property_->SetWindowName("SetShadowRadius");
    window->property_->SetWindowType(WindowType::SYSTEM_SUB_WINDOW_BASE);

    auto surfaceNode = window->GetSurfaceNode();
    if (surfaceNode == nullptr) {
        ASSERT_EQ(WMError::WM_ERROR_NULLPTR, window->CheckParmAndPermission());
    } else {
        ASSERT_EQ(WMError::WM_ERROR_INVALID_PARAM, window->SetShadowRadius(-1.0));
        ASSERT_EQ(WMError::WM_OK, window->SetShadowRadius(1.0));
    }
}

/**
 * @tc.name: SetTransform01
 * @tc.desc: set transform
 * @tc.type: FUNC
 * @tc.require:issueI7IJVV
 */
HWTEST_F(WindowSceneSessionImplTest, SetTransform01, Function | SmallTest | Level3)
{
    std::unique_ptr<Mocker> m = std::make_unique<Mocker>();
    sptr<WindowOption> option = new WindowOption();
    option->SetWindowName("SetTransform01");
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);
    window->property_->SetPersistentId(1);
    Transform trans_;
    window->SetTransform(trans_);
    ASSERT_TRUE(trans_ == window->GetTransform());
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, window->Destroy(false));
}

/**
 * @tc.name: RegisterAnimationTransitionController01
 * @tc.desc: RegisterAnimationTransitionController
 * @tc.type: FUNC
 * @tc.require:issueI7IJVV
 */
HWTEST_F(WindowSceneSessionImplTest, RegisterAnimationTransitionController01, Function | SmallTest | Level3)
{
    std::unique_ptr<Mocker> m = std::make_unique<Mocker>();
    sptr<WindowOption> option = new WindowOption();
    option->SetWindowName("RegisterAnimationTransitionController01");
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);
    window->property_->SetPersistentId(1);
    ASSERT_EQ(WMError::WM_ERROR_NULLPTR, window->RegisterAnimationTransitionController(nullptr));
}

/**
 * @tc.name: SetNeedDefaultAnimation01
 * @tc.desc: SetNeedDefaultAnimation
 * @tc.type: FUNC
 * @tc.require:issueI7IJVV
 */
HWTEST_F(WindowSceneSessionImplTest, SetNeedDefaultAnimation01, Function | SmallTest | Level3)
{
    std::unique_ptr<Mocker> m = std::make_unique<Mocker>();
    sptr<WindowOption> option = new WindowOption();
    option->SetWindowName("SetNeedDefaultAnimation01");
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);
    auto ret = true;
    window->property_->SetPersistentId(1);

    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->hostSession_ = session;
    window->SetNeedDefaultAnimation(false);
    ASSERT_TRUE(ret);
}

/**
 * @tc.desc: UpdateSurfaceNodeAfterCustomAnimation01
 * @tc.desc: UpdateSurfaceNodeAfterCustomAnimation
 * @tc.type: FUNC
 * @tc.require:issueI7IJVV
 */
HWTEST_F(WindowSceneSessionImplTest, UpdateSurfaceNodeAfterCustomAnimation, Function | SmallTest | Level3)
{
    std::unique_ptr<Mocker> m = std::make_unique<Mocker>();
    sptr<WindowOption> option = new WindowOption();
    option->SetWindowName("UpdateSurfaceNodeAfterCustomAnimation");
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);

    window->property_->SetPersistentId(1);

    window->UpdateSurfaceNodeAfterCustomAnimation(false);
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, window->UpdateSurfaceNodeAfterCustomAnimation(false));
    window->property_->SetPersistentId(1);
    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->hostSession_ = session;
    window->property_->SetWindowType(WindowType::WINDOW_TYPE_APP_SUB_WINDOW);
    ASSERT_EQ(WMError::WM_ERROR_INVALID_OPERATION, window->UpdateSurfaceNodeAfterCustomAnimation(false));
}

/**
 * @tc.name: SetAlpha01
 * @tc.desc: SetAlpha
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SetAlpha01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("SetAlpha01");
    option->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);

    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);

    ASSERT_NE(nullptr, windowscenesession);
    windowscenesession->property_->SetPersistentId(11);
    windowscenesession->property_->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);

    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, windowscenesession->SetAlpha(1.0));
    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);

    ASSERT_EQ(WMError::WM_OK, windowscenesession->Create(abilityContext_, session));
    windowscenesession->hostSession_ = session;

    auto surfaceNode = windowscenesession->GetSurfaceNode();
    if (surfaceNode == nullptr) {
        ASSERT_EQ(WMError::WM_ERROR_NULLPTR, windowscenesession->CheckParmAndPermission());
    } else {
        ASSERT_EQ(WMError::WM_OK, windowscenesession->SetAlpha(1.0));
    }
}

/**
 * @tc.name: DestroySubWindow01
 * @tc.desc: DestroySubWindow
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, DestroySubWindow01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("DestroySubWindow");
    option->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);

    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);

    ASSERT_NE(nullptr, windowscenesession);
    int ret = 0;
    windowscenesession->DestroySubWindow();
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UpdateFloatingWindowSizeBySizeLimits01
 * @tc.desc: UpdateFloatingWindowSizeBySizeLimits
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, UpdateFloatingWindowSizeBySizeLimits01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("DestroySubWindow");
    option->SetWindowType(WindowType::WINDOW_TYPE_FLOAT_CAMERA);

    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);
    int ret = 0;
    windowscenesession->UpdateFloatingWindowSizeBySizeLimits(MaxWith, MaxWith);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UpdateAnimationFlagProperty01
 * @tc.desc: UpdateAnimationFlagProperty
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, UpdateAnimationFlagProperty01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("DestroySubWindow");
    option->SetWindowType(WindowType::SYSTEM_WINDOW_BASE);
    
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW,  windowscenesession->UpdateAnimationFlagProperty(false));
}

/**
 * @tc.name: UpdateWindowModeImmediately01
 * @tc.desc: UpdateWindowModeImmediately
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, UpdateWindowModeImmediately01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("DestroySubWindow");
    option->SetWindowType(WindowType::SYSTEM_WINDOW_BASE);

    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);
    ASSERT_EQ(WMError::WM_OK, windowscenesession->UpdateWindowModeImmediately(WindowMode::WINDOW_MODE_UNDEFINED));
    windowscenesession->state_ = WindowState::STATE_CREATED;
    ASSERT_EQ(WMError::WM_OK, windowscenesession->UpdateWindowModeImmediately(WindowMode::WINDOW_MODE_UNDEFINED));
}

/**
 * @tc.name: UpdateWindowMode01
 * @tc.desc: UpdateWindowMode
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, UpdateWindowMode01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("DestroySubWindow");
    option->SetWindowType(WindowType::SYSTEM_WINDOW_BASE);

    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);
    ASSERT_EQ(WSError::WS_ERROR_INVALID_WINDOW,
              windowscenesession->UpdateWindowMode(WindowMode::WINDOW_MODE_FULLSCREEN));
    windowscenesession->state_ = WindowState::STATE_CREATED;
    ASSERT_EQ(WSError::WS_ERROR_INVALID_WINDOW,
              windowscenesession->UpdateWindowMode(WindowMode::WINDOW_MODE_FULLSCREEN));

    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    windowscenesession->hostSession_ = session;
    ASSERT_EQ(WSError::WS_ERROR_INVALID_WINDOW,
              windowscenesession->UpdateWindowMode(WindowMode::WINDOW_MODE_FULLSCREEN));
}

/**
 * @tc.name: UpdateWindowMode02
 * @tc.desc: UpdateWindowMode
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, UpdateWindowMode02, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("DestroySubWindow");
    option->SetWindowType(WindowType::SYSTEM_WINDOW_BASE);

    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);
    ASSERT_EQ(WSError::WS_ERROR_INVALID_WINDOW,
              windowscenesession->UpdateWindowMode(WindowMode::WINDOW_MODE_FULLSCREEN));
    windowscenesession->state_ = WindowState::STATE_CREATED;
    ASSERT_EQ(WSError::WS_ERROR_INVALID_WINDOW,
              windowscenesession->UpdateWindowMode(WindowMode::WINDOW_MODE_FULLSCREEN));

    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    windowscenesession->hostSession_ = session;
    ASSERT_EQ(WSError::WS_ERROR_INVALID_WINDOW,
              windowscenesession->UpdateWindowMode(WindowMode::WINDOW_MODE_FULLSCREEN));
    windowscenesession->property_->SetPersistentId(1);
    ASSERT_EQ(WSError::WS_OK,
              windowscenesession->UpdateWindowMode(WindowMode::WINDOW_MODE_FULLSCREEN));
}

/**
 * @tc.name: RemoveWindowFlag01
 * @tc.desc: RemoveWindowFlag
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, RemoveWindowFlag01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("DestroySubWindow");
    option->SetWindowType(WindowType::SYSTEM_WINDOW_BASE);

    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW,
              windowscenesession->RemoveWindowFlag(WindowFlag::WINDOW_FLAG_NEED_AVOID));
    windowscenesession->state_ = WindowState::STATE_CREATED;
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW,
              windowscenesession->RemoveWindowFlag(WindowFlag::WINDOW_FLAG_NEED_AVOID));

    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    windowscenesession->hostSession_ = session;
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW,
              windowscenesession->RemoveWindowFlag(WindowFlag::WINDOW_FLAG_NEED_AVOID));
}

/**
 * @tc.name: GetConfigurationFromAbilityInfo01
 * @tc.desc: GetConfigurationFromAbilityInfo
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, GetConfigurationFromAbilityInfo01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("GetConfigurationFromAbilityInfo");
    option->SetWindowType(WindowType::SYSTEM_WINDOW_BASE);
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);
    int ret = 0;
    windowscenesession->GetConfigurationFromAbilityInfo();
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: PreProcessCreate01
 * @tc.desc: PreProcessCreate
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, PreProcessCreate01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("PreProcessCreate");
    option->SetWindowType(WindowType::SYSTEM_WINDOW_BASE);
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);
    int ret = 0;
    windowscenesession->PreProcessCreate();
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: SetDefaultProperty01
 * @tc.desc: SetDefaultProperty
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SetDefaultProperty01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("PreProcessCreate");
    option->SetWindowType(WindowType::SYSTEM_WINDOW_BASE);
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);
    int ret = 0;
    windowscenesession->SetDefaultProperty();
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: UpdateConfiguration01
 * @tc.desc: UpdateConfiguration
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, UpdateConfiguration01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("PreProcessCreate");
    option->SetWindowType(WindowType::SYSTEM_WINDOW_BASE);
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);
    int ret = 0;
    std::shared_ptr<AppExecFwk::Configuration> configuration;
    windowscenesession->UpdateConfiguration(configuration);
    windowscenesession->uiContent_ = std::make_unique<Ace::UIContentMocker>();
    windowscenesession->UpdateConfiguration(configuration);
    ASSERT_EQ(ret, 0);
}


/**
 * @tc.name: UpdateConfigurationForAll01
 * @tc.desc: UpdateConfigurationForAll
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, UpdateConfigurationForAll01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("UpdateConfigurationForAll");
    option->SetWindowType(WindowType::SYSTEM_WINDOW_BASE);
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);
    int ret = 0;
    std::shared_ptr<AppExecFwk::Configuration> configuration;
    windowscenesession->UpdateConfigurationForAll(configuration);
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: GetTopWindowWithContext01
 * @tc.desc: GetTopWindowWithContext
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, GetTopWindowWithContext01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("GetTopWindowWithContext");
    option->SetWindowType(WindowType::SYSTEM_WINDOW_BASE);
    std::shared_ptr<AbilityRuntime::Context> context;
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);
    if (windowscenesession->GetTopWindowWithContext(context) == nullptr) {
        ASSERT_EQ(nullptr, windowscenesession->GetTopWindowWithContext(context));
    }
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    ASSERT_EQ(WMError::WM_OK, windowscenesession->Create(abilityContext_, session));
    windowscenesession->GetTopWindowWithContext(context);
}

/**
 * @tc.name: GetMainWindowWithContext01
 * @tc.desc: GetMainWindowWithContext
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, GetMainWindowWithContext01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("GetMainWindowWithContext");
    option->SetWindowType(WindowType::SYSTEM_WINDOW_BASE);
    std::shared_ptr<AbilityRuntime::Context> context;
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);
    if (windowscenesession->GetMainWindowWithContext(context) == nullptr) {
        ASSERT_EQ(nullptr, windowscenesession->GetMainWindowWithContext(context));
    }
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    ASSERT_EQ(WMError::WM_OK, windowscenesession->Create(abilityContext_, session));
    windowscenesession->GetMainWindowWithContext(context);
}

/**
 * @tc.name: NotifyMemoryLevel01
 * @tc.desc: NotifyMemoryLevel
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, NotifyMemoryLevel01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("NotifyMemoryLevel");
    option->SetWindowType(WindowType::SYSTEM_WINDOW_BASE);
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);
    std::shared_ptr<AppExecFwk::Configuration> configuration;
    windowscenesession->NotifyMemoryLevel(2);
    ASSERT_EQ(WMError::WM_ERROR_NULLPTR, windowscenesession->NotifyMemoryLevel(2));
    windowscenesession->uiContent_ = std::make_unique<Ace::UIContentMocker>();
    ASSERT_EQ(WMError::WM_OK, windowscenesession->NotifyMemoryLevel(2));
}

/**
 * @tc.name: GetSystemSizeLimits01
 * @tc.desc: GetSystemSizeLimits
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, GetSystemSizeLimits01, Function | SmallTest | Level2)
{
    constexpr uint32_t minMainWidth = 10;
    constexpr uint32_t minMainHeight = 20;
    constexpr uint32_t minSubWidth = 30;
    constexpr uint32_t minSubHeight = 40;
    constexpr uint32_t displayWidth = 100;
    constexpr uint32_t displayHeight = 100;
    constexpr float displayVpr = 1;

    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("GetSystemSizeLimits01");
    option->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);

    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);

    ASSERT_NE(nullptr, windowscenesession);
    windowscenesession->windowSystemConfig_.miniWidthOfMainWindow_ = minMainWidth;
    windowscenesession->windowSystemConfig_.miniHeightOfMainWindow_ = minMainHeight;
    windowscenesession->windowSystemConfig_.miniWidthOfSubWindow_ = minSubWidth;
    windowscenesession->windowSystemConfig_.miniHeightOfSubWindow_ = minSubHeight;
    
    WindowLimits limits = windowscenesession->GetSystemSizeLimits(displayWidth, displayHeight, displayVpr);
    ASSERT_EQ(limits.minWidth_, minMainWidth);
    ASSERT_EQ(limits.minHeight_, minMainHeight);

    windowscenesession->SetWindowType(WindowType::WINDOW_TYPE_APP_SUB_WINDOW);
    limits = windowscenesession->GetSystemSizeLimits(displayWidth, displayHeight, displayVpr);
    ASSERT_EQ(limits.minWidth_, minMainWidth);
    ASSERT_EQ(limits.minHeight_, minMainHeight);

    windowscenesession->SetWindowType(WindowType::SYSTEM_WINDOW_BASE);
    limits = windowscenesession->GetSystemSizeLimits(displayWidth, displayHeight, displayVpr);
    ASSERT_EQ(limits.minWidth_, minMainWidth);
    ASSERT_EQ(limits.minHeight_, minMainHeight);
}

/**
 * @tc.name: DumpSessionElementInfo
 * @tc.desc: DumpSessionElementInfo 1: params num
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, DumpSessionElementInfo1, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("DumpSessionElementInfo1");
    option->SetWindowType(WindowType::SYSTEM_WINDOW_BASE);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);
    std::vector<std::string> params;
    params.push_back("-h");
    window->DumpSessionElementInfo(params);
    window->uiContent_ = std::make_unique<Ace::UIContentMocker>();
    ASSERT_EQ(WMError::WM_OK, window->NotifyMemoryLevel(2));
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, window->Destroy(false));
}

/**
 * @tc.name: DumpSessionElementInfo
 * @tc.desc: DumpSessionElementInfo2
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, DumpSessionElementInfo2, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("DumpSessionElementInfo2");
    option->SetWindowType(WindowType::SYSTEM_WINDOW_BASE);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);
    std::vector<std::string> params;
    params.push_back("-h");
    window->DumpSessionElementInfo(params);
    params.push_back("-s");
    window->uiContent_ = std::make_unique<Ace::UIContentMocker>();
    window->DumpSessionElementInfo(params);
    ASSERT_EQ(WMError::WM_OK, window->NotifyMemoryLevel(2));
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, window->Destroy(false));
}

/**
 * @tc.name: DumpSessionElementInfo
 * @tc.desc: DumpSessionElementInfo3
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, DumpSessionElementInfo3, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("DumpSessionElementInfo3");
    option->SetWindowType(WindowType::SYSTEM_WINDOW_BASE);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);
    std::vector<std::string> params;
    params.push_back("-s");
    window->DumpSessionElementInfo(params);
    window->uiContent_ = std::make_unique<Ace::UIContentMocker>();
    ASSERT_EQ(WMError::WM_OK, window->NotifyMemoryLevel(2));
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, window->Destroy(false));
}

/**
 * @tc.name: DisableAppWindowDecor02
 * @tc.desc: DisableAppWindowDecor
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, DisableAppWindowDecor02, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("DisableAppWindowDecor02");
    option->SetWindowType(WindowType::SYSTEM_WINDOW_BASE);
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);
    int ret = 0;
    windowscenesession->DisableAppWindowDecor();
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: RaiseAboveTarget01
 * @tc.desc: RaiseAboveTarget
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, RaiseAboveTarget01, Function | SmallTest | Level2)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: RaiseAboveTarget01 start";
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("RaiseAboveTarget01");
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);

    ASSERT_EQ(WmErrorCode::WM_ERROR_INVALID_PARENT,windowscenesession->RaiseAboveTarget(0));
    GTEST_LOG_(INFO) << "JpegDecoderTest: RaiseAboveTarget01 end";
}

/**
 * @tc.name: FindParentSessionByParentId02
 * @tc.desc: FindParentSessionByParentId
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, FindParentSessionByParentId02, Function | SmallTest | Level2)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: RaiseAboveTarget01 start";
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowTag(WindowTag::MAIN_WINDOW);
    option->SetWindowName("FindParentSessionByParentId02");
    sptr<WindowSceneSessionImpl> parentscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, parentscenesession);

    parentscenesession->FindParentSessionByParentId(-1);
    GTEST_LOG_(INFO) << "JpegDecoderTest: RaiseAboveTarget01 end";
}

/**
 * @tc.name: GetConfigurationFromAbilityInfo02
 * @tc.desc: GetConfigurationFromAbilityInfo
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, GetConfigurationFromAbilityInfo02, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("GetConfigurationFromAbilityInfo02");
    option->SetWindowType(WindowType::SYSTEM_WINDOW_BASE);
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);
    int ret = 0;
    windowscenesession->GetConfigurationFromAbilityInfo();
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: NotifyWindowSessionProperty01
 * @tc.desc: NotifyWindowSessionProperty
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, NotifyWindowSessionProperty01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("NotifyWindowSessionProperty01");
    option->SetWindowType(WindowType::SYSTEM_WINDOW_BASE);
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);
    int ret = 0;
    windowscenesession->NotifyWindowSessionProperty();
    ASSERT_EQ(ret, 0);
}

HWTEST_F(WindowSceneSessionImplTest, IsTransparent01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("IsTransparent01");
    option->SetWindowType(WindowType::SYSTEM_WINDOW_BASE);
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);
    int ret = 0;
    windowscenesession->IsTransparent();
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: SetTransparent02
 * @tc.desc: SetTransparent
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SetTransparent02, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("SetTransparent02");
    option->SetWindowType(WindowType::SYSTEM_WINDOW_BASE);
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);
    int ret = 0;
    bool isTransparent = false;
    windowscenesession->SetTransparent(isTransparent);
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: Snapshot01
 * @tc.desc: Snapshot
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, Snapshot01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("GetConfigurationFromAbilityInfo");
    option->SetWindowType(WindowType::SYSTEM_WINDOW_BASE);
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);
    int ret = 0;
    windowscenesession->Snapshot();
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: BindDialogTarget01
 * @tc.desc: BindDialogTarget
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, BindDialogTarget01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("GetConfigurationFromAbilityInfo");
    option->SetWindowType(WindowType::SYSTEM_WINDOW_BASE);
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    sptr<IRemoteObject> targetToken;
    windowscenesession->BindDialogTarget(targetToken);
    ASSERT_NE(nullptr, windowscenesession);
}

/**
 * @tc.name: NotifySessionForeground
 * @tc.desc: NotifySessionForeground
 * @tc.type: FUNC
*/
HWTEST_F(WindowSceneSessionImplTest, NotifySessionForeground, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("GetConfigurationFromAbilityInfo");
    option->SetWindowType(WindowType::SYSTEM_WINDOW_BASE);
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);

    uint32_t reason = 1;
    bool withAnimation = true;
    windowscenesession->NotifySessionForeground(reason, withAnimation);
}

/**
 * @tc.name: NotifySessionBackground
 * @tc.desc: NotifySessionBackground
 * @tc.type: FUNC
*/
HWTEST_F(WindowSceneSessionImplTest, NotifySessionBackground, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("GetConfigurationFromAbilityInfo");
    option->SetWindowType(WindowType::SYSTEM_WINDOW_BASE);
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);

    uint32_t reason = 1;
    bool withAnimation = true;
    bool isFromInnerkits = true;
    windowscenesession->NotifySessionBackground(reason, withAnimation, isFromInnerkits);
}

/**
 * @tc.name: NotifyPrepareClosePiPWindow01
 * @tc.desc: NotifyPrepareClosePiPWindow
 * @tc.type: FUNC
*/
HWTEST_F(WindowSceneSessionImplTest, NotifyPrepareClosePiPWindow01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("pip_window");
    option->SetWindowType(WindowType::WINDOW_TYPE_PIP);
    sptr<WindowSceneSessionImpl> windowscenesession = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, windowscenesession);
    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    windowscenesession->hostSession_ = session;
    ASSERT_EQ(WMError::WM_OK, windowscenesession->NotifyPrepareClosePiPWindow());
}

/**
 * @tc.name: SetDefaultDensityEnabled01
 * @tc.desc: normal test
 * @tc.type: FUNC
*/
HWTEST_F(WindowSceneSessionImplTest, SetDefaultDensityEnabled01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("SetDefaultDensityEnabled01");
    option->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);

    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->property_->SetPersistentId(1);
    window->hostSession_ = session;
    window->state_ = WindowState::STATE_SHOWN;
    window->property_->SetDisplayId(0);

    WindowSceneSessionImpl::windowSessionMap_.insert(std::make_pair(window->GetWindowName(),
        std::pair<uint64_t, sptr<WindowSessionImpl>>(window->GetWindowId(), window)));
    ASSERT_EQ(WMError::WM_OK, window->SetDefaultDensityEnabled(true));
    ASSERT_EQ(true, window->GetDefaultDensityEnabled());
    WindowSceneSessionImpl::windowSessionMap_.erase(window->GetWindowName());
}

/**
 * @tc.name: SetDefaultDensityEnabled02
 * @tc.desc: window session is invalid
 * @tc.type: FUNC
*/
HWTEST_F(WindowSceneSessionImplTest, SetDefaultDensityEnabled02, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("SetDefaultDensityEnabled02");
    option->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);
    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->property_->SetPersistentId(1);
    window->state_ = WindowState::STATE_SHOWN;
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, window->SetDefaultDensityEnabled(true));
}

/**
 * @tc.name: SetDefaultDensityEnabled03
 * @tc.desc: not app main window
 * @tc.type: FUNC
*/
HWTEST_F(WindowSceneSessionImplTest, SetDefaultDensityEnabled03, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("SetDefaultDensityEnabled03");
    option->SetWindowType(WindowType::WINDOW_TYPE_APP_SUB_WINDOW);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);
    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->property_->SetPersistentId(1);
    window->hostSession_ = session;
    window->state_ = WindowState::STATE_SHOWN;
    ASSERT_EQ(WMError::WM_ERROR_INVALID_CALLING, window->SetDefaultDensityEnabled(true));
}

/**
 * @tc.name: SetDefaultDensityEnabled04
 * @tc.desc: isDefaultDensityEnabled_ not change
 * @tc.type: FUNC
*/
HWTEST_F(WindowSceneSessionImplTest, SetDefaultDensityEnabled04, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("SetDefaultDensityEnabled04");
    option->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);
    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->property_->SetPersistentId(1);
    window->hostSession_ = session;
    window->state_ = WindowState::STATE_SHOWN;
    ASSERT_EQ(WMError::WM_OK, window->SetDefaultDensityEnabled(false));
}

/**
 * @tc.name: GetDefaultDensityEnabled01
 * @tc.desc: normal test
 * @tc.type: FUNC
*/
HWTEST_F(WindowSceneSessionImplTest, GetDefaultDensityEnabled01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("GetDefaultDensityEnabled01");
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    window->isDefaultDensityEnabled_ = true;
    ASSERT_EQ(true, window->GetDefaultDensityEnabled());
}

/**
 * @tc.name: GetDefaultDensityEnabled02
 * @tc.desc: test default value
 * @tc.type: FUNC
*/
HWTEST_F(WindowSceneSessionImplTest, GetDefaultDensityEnabled02, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("GetDefaultDensityEnabled02");
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_EQ(false, window->GetDefaultDensityEnabled());
}

/**
 * @tc.name: GetVirtualPixelRatio01
 * @tc.desc: main window isDefaultDensityEnabled_ true
 * @tc.type: FUNC
*/
HWTEST_F(WindowSceneSessionImplTest, GetVirtualPixelRatio01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("GetVirtualPixelRatio01");
    option->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);

    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->property_->SetPersistentId(1);
    window->hostSession_ = session;
    window->state_ = WindowState::STATE_SHOWN;
    window->property_->SetDisplayId(0);

    window->isDefaultDensityEnabled_ = true;
    sptr<DisplayInfo> displayInfo = new DisplayInfo();
    auto defautDensity = 1.0f;
    auto density = 2.0f;
    displayInfo->SetDefaultVirtualPixelRatio(defautDensity);
    displayInfo->SetVirtualPixelRatio(density);
    ASSERT_EQ(defautDensity, window->GetVirtualPixelRatio(displayInfo));
}

/**
 * @tc.name: GetVirtualPixelRatio02
 * @tc.desc: main window isDefaultDensityEnabled_ false
 * @tc.type: FUNC
*/
HWTEST_F(WindowSceneSessionImplTest, GetVirtualPixelRatio02, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("GetVirtualPixelRatio02");
    option->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);

    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->property_->SetPersistentId(1);
    window->hostSession_ = session;
    window->state_ = WindowState::STATE_SHOWN;
    window->property_->SetDisplayId(0);

    window->isDefaultDensityEnabled_ = false;
    sptr<DisplayInfo> displayInfo = new DisplayInfo();
    auto defautDensity = 1.0f;
    auto density = 2.0f;
    displayInfo->SetDefaultVirtualPixelRatio(defautDensity);
    displayInfo->SetVirtualPixelRatio(density);
    ASSERT_EQ(density, window->GetVirtualPixelRatio(displayInfo));
}

/**
 * @tc.name: GetVirtualPixelRatio03
 * @tc.desc: sub window isDefaultDensityEnabled_ true
 * @tc.type: FUNC
*/
HWTEST_F(WindowSceneSessionImplTest, GetVirtualPixelRatio03, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("GetVirtualPixelRatio03");
    option->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);

    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->property_->SetPersistentId(1);
    window->hostSession_ = session;
    window->state_ = WindowState::STATE_SHOWN;
    window->property_->SetDisplayId(0);

    window->isDefaultDensityEnabled_ = true;
    sptr<DisplayInfo> displayInfo = new DisplayInfo();
    auto defautDensity = 1.0f;
    auto density = 2.0f;
    displayInfo->SetDefaultVirtualPixelRatio(defautDensity);
    displayInfo->SetVirtualPixelRatio(density);

    sptr<WindowOption> subOption = new (std::nothrow) WindowOption();
    subOption->SetWindowName("GetVirtualPixelRatio03SubWindow");
    subOption->SetWindowType(WindowType::WINDOW_TYPE_APP_SUB_WINDOW);
    sptr<WindowSceneSessionImpl> subWindow = new (std::nothrow) WindowSceneSessionImpl(subOption);
    ASSERT_NE(nullptr, subWindow);
    subWindow->property_->SetParentPersistentId(window->GetWindowId());

    WindowSceneSessionImpl::windowSessionMap_.insert(std::make_pair(window->GetWindowName(),
        std::pair<uint64_t, sptr<WindowSessionImpl>>(window->GetWindowId(), window)));
    ASSERT_EQ(defautDensity, subWindow->GetVirtualPixelRatio(displayInfo));
    WindowSceneSessionImpl::windowSessionMap_.erase(window->GetWindowName());
}

/**
 * @tc.name: GetVirtualPixelRatio04
 * @tc.desc: sub window isDefaultDensityEnabled_ false
 * @tc.type: FUNC
*/
HWTEST_F(WindowSceneSessionImplTest, GetVirtualPixelRatio04, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("GetVirtualPixelRatio04");
    option->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);

    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->property_->SetPersistentId(1);
    window->hostSession_ = session;
    window->state_ = WindowState::STATE_SHOWN;
    window->property_->SetDisplayId(0);

    window->isDefaultDensityEnabled_ = false;
    sptr<DisplayInfo> displayInfo = new DisplayInfo();
    auto defautDensity = 1.0f;
    auto density = 2.0f;
    displayInfo->SetDefaultVirtualPixelRatio(defautDensity);
    displayInfo->SetVirtualPixelRatio(density);

    sptr<WindowOption> subOption = new (std::nothrow) WindowOption();
    subOption->SetWindowName("GetVirtualPixelRatio04SubWindow");
    subOption->SetWindowType(WindowType::WINDOW_TYPE_APP_SUB_WINDOW);
    sptr<WindowSceneSessionImpl> subWindow = new (std::nothrow) WindowSceneSessionImpl(subOption);
    ASSERT_NE(nullptr, subWindow);
    subWindow->property_->SetParentPersistentId(window->GetWindowId());

    WindowSceneSessionImpl::windowSessionMap_.insert(std::make_pair(window->GetWindowName(),
        std::pair<uint64_t, sptr<WindowSessionImpl>>(window->GetWindowId(), window)));
    ASSERT_EQ(density, subWindow->GetVirtualPixelRatio(displayInfo));
    WindowSceneSessionImpl::windowSessionMap_.erase(window->GetWindowName());
}

/**
 * @tc.name: GetWindowLimits01
 * @tc.desc: GetWindowLimits
 * @tc.type: FUNC
*/
HWTEST_F(WindowSceneSessionImplTest, GetWindowLimits01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("GetWindowLimits01");

    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);

    WindowLimits windowLimits = {1000, 1000, 1000, 1000, 0.0f, 0.0f};
    window->property_->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    window->property_->SetWindowLimits(windowLimits);
    window->property_->SetPersistentId(1);
    window->state_ = WindowState::STATE_HIDDEN;
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->hostSession_ = session;

    WindowLimits windowSizeLimits;
    window->GetWindowLimits(windowSizeLimits);
}

/**
 * @tc.name: SetWindowLimits01
 * @tc.desc: SetWindowLimits
 * @tc.type: FUNC
*/
HWTEST_F(WindowSceneSessionImplTest, SetWindowLimits01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("SetWindowLimits01");

    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);
    window->property_->SetDisplayId(0);
    window->property_->SetPersistentId(888);
    window->property_->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    window->state_ = WindowState::STATE_FROZEN;
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->hostSession_ = session;
    auto display = SingletonContainer::Get<DisplayManager>().GetDisplayById(window->property_->GetDisplayId());
    ASSERT_NE(nullptr, display);
    display->GetDisplayInfo()->SetVirtualPixelRatio(1.0f);

    WindowLimits windowLimits = {1000, 1000, 1000, 1000, 0.0f, 0.0f};
    if (WMError::WM_OK == window->SetWindowLimits(windowLimits)) {
        WindowLimits windowSizeLimits = window->property_->GetWindowLimits();
        ASSERT_EQ(windowSizeLimits.maxWidth_, 1000);
        ASSERT_EQ(windowSizeLimits.maxHeight_, 1000);
        ASSERT_EQ(windowSizeLimits.minWidth_, 1000);
        ASSERT_EQ(windowSizeLimits.minHeight_, 1000);
    }
}

/**
 * @tc.name: AdjustKeyboardLayout01
 * @tc.desc: adjust keyboard layout
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, AdjustKeyboardLayout01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("AdjustKeyboardLayout01");
    option->SetDisplayId(0);

    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);

    window->property_->SetPersistentId(123);
    window->property_->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    window->state_ = WindowState::STATE_FROZEN;
    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->hostSession_ = session;

    KeyboardLayoutParams params;
    params.gravity_ = WindowGravity::WINDOW_GRAVITY_FLOAT;
    params.LandscapeKeyboardRect_ = {1, 2, 3, 4};
    params.PortraitKeyboardRect_ = {1, 2, 3, 4};
    params.LandscapePanelRect_ = {1, 2, 3, 4};
    params.PortraitPanelRect_ = {1, 2, 3, 4};
    ASSERT_EQ(WMError::WM_OK, window->AdjustKeyboardLayout(params));
}
/**
 * @tc.name: HideNonSecureWindows01
 * @tc.desc: HideNonSecureWindows
 * @tc.type: FUNC
*/
HWTEST_F(WindowSceneSessionImplTest, HideNonSecureWindows01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("HideNonSecureWindows01");

    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);

    ASSERT_EQ(WMError::WM_OK, window->HideNonSecureWindows(true));
}

/**
 * @tc.name: Maximize01
 * @tc.desc: test errorCode
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, Maximize02, Function | SmallTest | Level2)
{
    sptr option = new (std::nothrow) WindowOption();
    option->SetWindowName("Maximize02");
    option->SetDisplayId(0);

    sptr window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);

    window->property_->SetWindowName("Maximize02");
    window->property_->SetWindowType(WindowType::WINDOW_TYPE_APP_SUB_WINDOW);
    window->property_->SetPersistentId(2);

    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->hostSession_ = session;

    MaximizeLayoutOption layoutOption;
    // not support subWinodw call
    ASSERT_EQ(WMError::WM_ERROR_INVALID_CALLING, window->Maximize(layoutOption));

    // window not support fullscreen
    window->property_->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    window->SetRequestModeSupportInfo(WindowModeSupport::WINDOW_MODE_SUPPORT_FLOATING);
    window->Maximize(layoutOption);
}

/**
 * @tc.name: Maximize02
 * @tc.desc: test maximizeLayoutOption
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, Maximize03, Function | SmallTest | Level2)
{
    sptr option = new (std::nothrow) WindowOption();
    option->SetWindowName("Maximize03");
    option->SetDisplayId(0);

    sptr window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);

    window->property_->SetWindowName("Maximize03");
    window->property_->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    window->property_->SetPersistentId(2);

    SessionInfo sessionInfo = {"CreateTestBundle", "CreateTestModule", "CreateTestAbility"};
    sptr session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->hostSession_ = session;

    ASSERT_NE(nullptr, window);
    MaximizeLayoutOption layoutOption;
    // dock can not be hide from maximize interface!
    layoutOption.dock = ShowType::FORBIDDEN;
    auto ret = window->Maximize(layoutOption);
    ASSERT_EQ(WMError::WM_ERROR_INVALID_PARAM, ret);
    layoutOption.dock = ShowType::HIDE;
    layoutOption.decor = ShowType::HIDE;
    ASSERT_NE(WMError::WM_ERROR_INVALID_PARAM, window->Maximize(layoutOption));
    layoutOption.dock = ShowType::HIDE;
    layoutOption.decor = ShowType::SHOW;
    ASSERT_NE(WMError::WM_ERROR_INVALID_PARAM, window->Maximize(layoutOption));
}

/**
 * @tc.name: GetTitleButtonVisible01
 * @tc.desc: GetTitleButtonVisible
 * @tc.type: FUNC
*/
HWTEST_F(WindowSceneSessionImplTest, GetTitleButtonVisible01, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("GetTitleButtonVisible01");
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);
    uint32_t modeSupportInfo = 1 | (1 << 1) | (1 << 2);
    window->property_->SetModeSupportInfo(modeSupportInfo);
    window->property_->SetWindowMode(WindowMode::WINDOW_MODE_FLOATING);
    // show Maximize, Minimize, Split buttons.
    window->windowTitleVisibleFlags_ = { false, false, false };
    bool hideMaximizeButton = false;
    bool hideMinimizeButton = false;
    bool hideSplitButton = false;
    window->GetTitleButtonVisible(true, hideMaximizeButton, hideMinimizeButton, hideSplitButton);
    ASSERT_EQ(hideMaximizeButton, true);
    ASSERT_EQ(hideMinimizeButton, true);
    ASSERT_EQ(hideSplitButton, true);
}

/**
 * @tc.name: GetTitleButtonVisible02
 * @tc.desc: GetTitleButtonVisible
 * @tc.type: FUNC
*/
HWTEST_F(WindowSceneSessionImplTest, GetTitleButtonVisible02, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("GetTitleButtonVisible02");
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);
    // only not support WINDOW_MODE_SUPPORT_SPLIT
    uint32_t modeSupportInfo = 1 | (1 << 1);
    window->property_->SetModeSupportInfo(modeSupportInfo);
    window->property_->SetWindowMode(WindowMode::WINDOW_MODE_FLOATING);
    // show Maximize, Minimize, Split buttons.
    window->windowTitleVisibleFlags_ = { true, true, true };
    bool hideMaximizeButton = false;
    bool hideMinimizeButton = false;
    bool hideSplitButton = false;
    window->GetTitleButtonVisible(true, hideMaximizeButton, hideMinimizeButton, hideSplitButton);
    ASSERT_EQ(hideMaximizeButton, false);
    ASSERT_EQ(hideMinimizeButton, false);
    ASSERT_EQ(hideSplitButton, false);
}

/**
 * @tc.name: GetTitleButtonVisible03
 * @tc.desc: GetTitleButtonVisible
 * @tc.type: FUNC
*/
HWTEST_F(WindowSceneSessionImplTest, GetTitleButtonVisible03, Function | SmallTest | Level2)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("GetTitleButtonVisible03");
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);
    // only not support WINDOW_MODE_SUPPORT_SPLIT
    uint32_t modeSupportInfo = 1 | (1 << 1) | (1 << 2);
    window->property_->SetModeSupportInfo(modeSupportInfo);
    window->property_->SetWindowMode(WindowMode::WINDOW_MODE_FLOATING);
    // show Maximize, Minimize, Split buttons.
    window->windowTitleVisibleFlags_ = { false, false, false };
    bool hideMaximizeButton = true;
    bool hideMinimizeButton = true;
    bool hideSplitButton = true;
    window->GetTitleButtonVisible(false, hideMaximizeButton, hideMinimizeButton, hideSplitButton);
    ASSERT_EQ(hideMaximizeButton, true);
    ASSERT_EQ(hideMinimizeButton, true);
    ASSERT_EQ(hideSplitButton, true);
}

/**
 * @tc.name: SetTitleButtonVisible01
 * @tc.desc: SetTitleButtonVisible
 * @tc.type: FUNC
*/
HWTEST_F(WindowSceneSessionImplTest, SetTitleButtonVisible01, Function | SmallTest | Level2)
{
    GTEST_LOG_(INFO) << "WindowSessionImplTest: SetTitleButtonVisible01 start";
    sptr<WindowOption> option = new WindowOption();
    ASSERT_NE(option, nullptr);
    option->SetWindowName("SetTitleButtonVisible");
    sptr<WindowSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(window, nullptr);
    window->property_->SetWindowType(WindowType::WINDOW_TYPE_APP_SUB_WINDOW);
    WMError res = window->SetTitleButtonVisible(false, false, false);
    ASSERT_EQ(res, WMError::WM_ERROR_INVALID_CALLING);
    GTEST_LOG_(INFO) << "WindowSessionImplTest: SetTitleButtonVisible01 end";
}

/**
 * @tc.name: SetTitleButtonVisible02
 * @tc.desc: SetTitleButtonVisible
 * @tc.type: FUNC
*/
HWTEST_F(WindowSceneSessionImplTest, SetTitleButtonVisible02, Function | SmallTest | Level2)
{
    GTEST_LOG_(INFO) << "WindowSessionImplTest: SetTitleButtonVisible02 start";
    sptr<WindowOption> option = new WindowOption();
    ASSERT_NE(option, nullptr);
    option->SetWindowName("SetTitleButtonVisible");
    sptr<WindowSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(window, nullptr);
    window->property_->SetWindowType(WindowType::APP_MAIN_WINDOW_BASE);
    WMError res = window->SetTitleButtonVisible(false, false, false);
    ASSERT_EQ(res, WMError::WM_ERROR_INVALID_WINDOW);
    GTEST_LOG_(INFO) << "WindowSessionImplTest: SetTitleButtonVisible02 end";
}

/**
 * @tc.name: SetTitleButtonVisible03
 * @tc.desc: SetTitleButtonVisible
 * @tc.type: FUNC
*/
HWTEST_F(WindowSceneSessionImplTest, SetTitleButtonVisible03, Function | SmallTest | Level2)
{
    GTEST_LOG_(INFO) << "WindowSessionImplTest: SetTitleButtonVisible03 start";
    sptr option = new WindowOption();
    ASSERT_NE(option, nullptr);
    option->SetWindowName("SetTitleButtonVisible");
    sptr window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(window, nullptr);
    window->property_->SetWindowType(WindowType::APP_MAIN_WINDOW_BASE);
    window->property_->SetWindowMode(WindowMode::WINDOW_MODE_FLOATING);
    window->uiContent_ = std::make_unique<Ace::UIContentMocker>();
    WMError res = window->SetTitleButtonVisible(false, false, false);
    std::string deviceType = system::GetParameter("const.product.devicetype", "unknown");
    if (deviceType == "phone") {
        ASSERT_EQ(res, WMError::WM_ERROR_INVALID_WINDOW);
    }
    if (deviceType == "2in1") {
        ASSERT_EQ(res, WMError::WM_OK);
    }
    GTEST_LOG_(INFO) << "WindowSessionImplTest: SetTitleButtonVisible03 end";
}

/**
 * @tc.name: SyncDestroyAndDisconnectSpecificSession
 * @tc.desc: SyncDestroyAndDisconnectSpecificSession test
 * @tc.type: FUNC
*/
HWTEST_F(WindowSceneSessionImplTest, SyncDestroyAndDisconnectSpecificSession, Function | SmallTest | Level2)
{
    GTEST_LOG_(INFO) << "WindowSessionImplTest: SyncDestroyAndDisconnectSpecificSession start";
    sptr option = new WindowOption();
    ASSERT_NE(option, nullptr);
    option->SetWindowName("SyncDestroyAndDisconnectSpecificSession");
    sptr window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(window, nullptr);
    window->property_->SetWindowType(WindowType::APP_MAIN_WINDOW_BASE);
    window->property_->SetWindowMode(WindowMode::WINDOW_MODE_FLOATING);
    window->uiContent_ = std::make_unique<Ace::UIContentMocker>();
    WMError res = window->SetTitleButtonVisible(false, false, false);
    std::string deviceType = system::GetParameter("const.product.devicetype", "unknown");
    if (deviceType == "phone") {
        ASSERT_EQ(res, WMError::WM_ERROR_INVALID_WINDOW);
    }
    if (deviceType == "2in1") {
        ASSERT_EQ(res, WMError::WM_OK);
    }
    GTEST_LOG_(INFO) << "WindowSessionImplTest: SetTitleButtonVisible03 end";
}

/**
 * @tc.name: SetGrayScale01
 * @tc.desc: SetGrayScale
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SetGrayScale01, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("SetGrayScale01");
    ASSERT_NE(nullptr, option);
    option->SetWindowMode(WindowMode::WINDOW_MODE_PIP);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);

    constexpr float grayScale = 0.5f;
    ASSERT_EQ(WMError::WM_ERROR_INVALID_WINDOW, window->SetGrayScale(grayScale));
}

/**
 * @tc.name: SetGrayScale02
 * @tc.desc: SetGrayScale
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SetGrayScale02, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("SetGrayScale02");
    ASSERT_NE(nullptr, option);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);

    window->state_ = WindowState::STATE_SHOWN;
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->property_->SetPersistentId(1);
    window->hostSession_ = session;
    window->uiContent_ = std::make_unique<Ace::UIContentMocker>();

    std::vector<WindowType> types = { WindowType::WINDOW_TYPE_APP_MAIN_WINDOW,
                                      WindowType::WINDOW_TYPE_APP_SUB_WINDOW,
                                      WindowType::SYSTEM_WINDOW_BASE };
    for (WindowType type : types) {
        window->SetWindowType(type);
        float grayScale = -0.001f;
        ASSERT_EQ(WMError::WM_ERROR_INVALID_PARAM, window->SetGrayScale(grayScale));
        grayScale = 1.001f;
        ASSERT_EQ(WMError::WM_ERROR_INVALID_PARAM, window->SetGrayScale(grayScale));
    }
}

/**
 * @tc.name: SetGrayScale03
 * @tc.desc: SetGrayScale
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, SetGrayScale03, Function | SmallTest | Level3)
{
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    option->SetWindowName("SetGrayScale03");
    ASSERT_NE(nullptr, option);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);

    window->state_ = WindowState::STATE_SHOWN;
    SessionInfo sessionInfo = { "CreateTestBundle", "CreateTestModule", "CreateTestAbility" };
    sptr<SessionMocker> session = new (std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    window->property_->SetPersistentId(1);
    window->hostSession_ = session;
    window->uiContent_ = std::make_unique<Ace::UIContentMocker>();

    std::vector<WindowType> types = { WindowType::WINDOW_TYPE_APP_MAIN_WINDOW,
                                      WindowType::WINDOW_TYPE_APP_SUB_WINDOW,
                                      WindowType::SYSTEM_WINDOW_BASE };
    for (WindowType type : types) {
        window->SetWindowType(type);
        float grayScale = 0.0f;
        ASSERT_EQ(WMError::WM_OK, window->SetGrayScale(grayScale));
        grayScale = 1.0f;
        ASSERT_EQ(WMError::WM_OK, window->SetGrayScale(grayScale));
        grayScale = 0.5f;
        ASSERT_EQ(WMError::WM_OK, window->SetGrayScale(grayScale));
    }
}

/**
 * @tc.name: TestGetUIContentWithId
 * @tc.desc: Get uicontent with id
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, TestGetUIContentWithId, Function | SmallTest | Level2)
{
    GTEST_LOG_(INFO) << "WindowSceneSessionImplTest: TestGetUIContentWithId start";
    sptr<WindowOption> option = new WindowOption();
    ASSERT_NE(nullptr, option);
    option->SetWindowName("TestGetUIContentWithId");
    sptr<WindowSceneSessionImpl> window = new WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);
    window->property_->SetPersistentId(102);

    SessionInfo sessionInfo = { "CreateTestBundle", "TestGetUIContentWithId", "CreateTestAbility" };
    sptr<SessionMocker> session = new(std::nothrow) SessionMocker(sessionInfo);
    ASSERT_NE(nullptr, session);
    ASSERT_EQ(WMError::WM_OK, window->Create(nullptr, session));
    window->uiContent_ = std::make_unique<Ace::UIContentMocker>();
}

/**
 * @tc.name: Test01
 * @tc.desc: Test01
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, Test01, Function | SmallTest | Level3)
{
    WindowLimits windowLimits = {3, 3, 3, 3, 2.0, 2.0};
    ASSERT_EQ(windowLimits.IsEmpty(), false);
    Rect rect = {2, 2, 2, 2};
    Rect rect1 = {2, 2, 2, 2};
    ASSERT_EQ(rect.IsInsideOf(rect1), true);
    TitleButtonRect titleButtonRect = {3, 3, 3, 3};
    TitleButtonRect titleButtonRect1 = {3, 3, 3, 3};
    ASSERT_EQ(titleButtonRect.IsUninitializedRect(), false);
    ASSERT_EQ(titleButtonRect.IsInsideOf(titleButtonRect1), true);
    AvoidArea avoidArea;
    AvoidArea avoidArea1;
    ASSERT_EQ((avoidArea != avoidArea1), false);
    ASSERT_EQ((titleButtonRect == titleButtonRect1), true);
    ASSERT_EQ((titleButtonRect != titleButtonRect1), false);
    Transform transform;
    Transform transform1;
    ASSERT_EQ((transform != transform1), false);
}

/**
 * @tc.name: RegisterSessionRecoverListenerInputMethodFloat
 * @tc.desc: Register session recover listener
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, RegisterSessionRecoverListenerInputMethodFloat, Function | SmallTest | Level2)
{
    GTEST_LOG_(INFO) << "WindowSceneSessionImplTest: RegisterSessionRecoverListenerInputMethodFloat start";
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    ASSERT_NE(nullptr, option);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);
    ASSERT_NE(nullptr, window->property_);
    window->property_->SetWindowType(WindowType::WINDOW_TYPE_INPUT_METHOD_FLOAT);
    window->RegisterSessionRecoverListener(false);
}
 
/**
 * @tc.name: RegisterSessionRecoverListenerNonDefaultCollaboratorType01
 * @tc.desc: Register session recover listener
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, RegisterSessionRecoverListenerNonDefaultCollaboratorType01,
    Function | SmallTest | Level2)
{
    GTEST_LOG_(INFO) << "WindowSceneSessionImplTest: RegisterSessionRecoverListenerNonDefaultCollaboratorType start";
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    ASSERT_NE(nullptr, option);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);
    ASSERT_NE(nullptr, window->property_);
    window->property_->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    window->property_->SetCollaboratorType(CollaboratorType::OTHERS_TYPE);
    window->RegisterSessionRecoverListener(false); // false is main window
}

/**
 * @tc.name: RegisterSessionRecoverListenerNonDefaultCollaboratorType02
 * @tc.desc: Register session recover listener
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, RegisterSessionRecoverListenerNonDefaultCollaboratorType02,
    Function | SmallTest | Level2)
{
    GTEST_LOG_(INFO) << "WindowSceneSessionImplTest: RegisterSessionRecoverListenerNonDefaultCollaboratorType start";
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    ASSERT_NE(nullptr, option);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);
    ASSERT_NE(nullptr, window->property_);
    window->property_->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    window->property_->SetCollaboratorType(CollaboratorType::OTHERS_TYPE);
    window->RegisterSessionRecoverListener(true); // true is sub window
}

/**
 * @tc.name: RegisterSessionRecoverListenerSuccess01
 * @tc.desc: Register session recover listener
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, RegisterSessionRecoverListenerSuccess01, Function | SmallTest | Level2)
{
    GTEST_LOG_(INFO) << "WindowSceneSessionImplTest: RegisterSessionRecoverListenerSuccess start";
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    ASSERT_NE(nullptr, option);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);
    ASSERT_NE(nullptr, window->property_);
    window->property_->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    window->property_->SetCollaboratorType(CollaboratorType::DEFAULT_TYPE);
    window->RegisterSessionRecoverListener(false); // false is main window
}

/**
 * @tc.name: RegisterSessionRecoverListenerSuccess02
 * @tc.desc: Register session recover listener
 * @tc.type: FUNC
 */
HWTEST_F(WindowSceneSessionImplTest, RegisterSessionRecoverListenerSuccess02, Function | SmallTest | Level2)
{
    GTEST_LOG_(INFO) << "WindowSceneSessionImplTest: RegisterSessionRecoverListenerSuccess start";
    sptr<WindowOption> option = new (std::nothrow) WindowOption();
    ASSERT_NE(nullptr, option);
    sptr<WindowSceneSessionImpl> window = new (std::nothrow) WindowSceneSessionImpl(option);
    ASSERT_NE(nullptr, window);
    ASSERT_NE(nullptr, window->property_);
    window->property_->SetWindowType(WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    window->property_->SetCollaboratorType(CollaboratorType::DEFAULT_TYPE);
    window->RegisterSessionRecoverListener(true); // true is sub window
}
}
} // namespace Rosen
} // namespace OHOS

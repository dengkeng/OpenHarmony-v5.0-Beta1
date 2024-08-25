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

#include "iremote_object_mocker.h"
#include "screen_session_manager_client.h"
#include "zidl/screen_session_manager_proxy.h"
#include "display_manager.h"
#include "window_manager_hilog.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
namespace {
    constexpr HiviewDFX::HiLogLabel LABEL = {LOG_CORE, HILOG_DOMAIN_DISPLAY, "ScreenSessionManagerClientTest"};
}
class DmPrivateWindowListener : public DisplayManager::IPrivateWindowListener {
public:
    void OnPrivateWindow(bool hasPrivate) {WLOGFI("IPrivateWindowListener hasPrivatewindow: %{public}u", hasPrivate);}
};
class DmPrivateWindowListChangeListener : public DisplayManager::IPrivateWindowListChangeListener {
public:
    void OnPrivateWindowListChange(DisplayId displayId, std::vector<std::string> privacyWindowList)
    {
        WLOGFI("IPrivateWindowListChangeListener displayId: %{public}" PRIu64".", displayId);
        std::string concatenatedString;
        std::vector<std::string> result = privacyWindowList;
        for (const auto& window : result) {
            concatenatedString.append(window);
            concatenatedString.append("  ");
        }
        WLOGFI("privacyWindowList: %{public}s", concatenatedString.c_str());
        callback_(privacyWindowList);
    }
    void setCallback(std::function<void(std::vector<std::string>)> callback)
    {
        callback_ = callback;
    }
private:
    std::function<void(std::vector<std::string>)> callback_;
};
class ScreenSessionManagerClientTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;
    ScreenSessionManagerClient* screenSessionManagerClient_;
};

void ScreenSessionManagerClientTest::SetUp()
{
    screenSessionManagerClient_ = &ScreenSessionManagerClient::GetInstance();
}

void ScreenSessionManagerClientTest::TearDown()
{
    screenSessionManagerClient_ = nullptr;
}

/**
 * @tc.name: RegisterScreenConnectionListener
 * @tc.desc: RegisterScreenConnectionListener test
 * @tc.type: FUNC
 */
HWTEST_F(ScreenSessionManagerClientTest, RegisterScreenConnectionListener, Function | SmallTest | Level2)
{
    IScreenConnectionListener* listener = nullptr;
    screenSessionManagerClient_->RegisterScreenConnectionListener(listener);
    EXPECT_EQ(screenSessionManagerClient_->screenConnectionListener_, nullptr);
}

/**
 * @tc.name: GetScreenSession
 * @tc.desc: GetScreenSession test
 * @tc.type: FUNC
 */
HWTEST_F(ScreenSessionManagerClientTest, GetScreenSession, Function | SmallTest | Level2)
{
    ScreenId screenId = 0;
    sptr<ScreenSession> screenSession = nullptr;
    screenSession = screenSessionManagerClient_->GetScreenSession(screenId);
    EXPECT_EQ(screenSession, nullptr);

    screenSession = new ScreenSession(0, ScreenProperty(), 0);
    screenSessionManagerClient_->screenSessionMap_.emplace(screenId, screenSession);

    auto screenSession2 = screenSessionManagerClient_->GetScreenSession(screenId);
    EXPECT_EQ(screenSession2, screenSession);

    screenSessionManagerClient_->screenSessionMap_.clear();
    screenSession = screenSessionManagerClient_->GetScreenSession(screenId);
    EXPECT_EQ(screenSession, nullptr);
}

/**
 * @tc.name: OnScreenConnectionChanged01
 * @tc.desc: OnScreenConnectionChanged test
 * @tc.type: FUNC
 */
HWTEST_F(ScreenSessionManagerClientTest, OnScreenConnectionChanged01, Function | SmallTest | Level2)
{
    EXPECT_EQ(screenSessionManagerClient_->screenSessionManager_, nullptr);
    sptr<IRemoteObject> iRemoteObjectMocker = new IRemoteObjectMocker();
    screenSessionManagerClient_->screenSessionManager_ = new ScreenSessionManagerProxy(iRemoteObjectMocker);
    EXPECT_NE(screenSessionManagerClient_->screenSessionManager_, nullptr);

    ScreenId screenId = 0;
    ScreenEvent screenEvent = ScreenEvent::CONNECTED;
    ScreenId rsId = 0;
    std::string name;
    screenSessionManagerClient_->OnScreenConnectionChanged(screenId, screenEvent, rsId, name);
    sptr<ScreenSession> screenSession = screenSessionManagerClient_->GetScreenSession(screenId);
    EXPECT_NE(screenSession, nullptr);
}

/**
 * @tc.name: OnScreenConnectionChanged02
 * @tc.desc: OnScreenConnectionChanged test
 * @tc.type: FUNC
 */
HWTEST_F(ScreenSessionManagerClientTest, OnScreenConnectionChanged02, Function | SmallTest | Level2)
{
    EXPECT_NE(screenSessionManagerClient_->screenSessionManager_, nullptr);

    ScreenId screenId = 0;
    ScreenEvent screenEvent = ScreenEvent::DISCONNECTED;
    ScreenId rsId = 0;
    std::string name;
    screenSessionManagerClient_->OnScreenConnectionChanged(screenId, screenEvent, rsId, name);
    sptr<ScreenSession> screenSession = screenSessionManagerClient_->GetScreenSession(screenId);
    EXPECT_EQ(screenSession, nullptr);
}

/**
 * @tc.name: CheckIfNeedConnectScreen01
 * @tc.desc: CheckIfNeedConnectScreen test
 * @tc.type: FUNC
 */
HWTEST_F(ScreenSessionManagerClientTest, CheckIfNeedConnectScreen01, Function | SmallTest | Level2)
{
    EXPECT_NE(screenSessionManagerClient_->screenSessionManager_, nullptr);

    ScreenId screenId = 0;
    ScreenId rsId = 0;
    std::string name = "HiCar";
    screenSessionManagerClient_->screenSessionManager_->GetScreenProperty(screenId).SetScreenType(ScreenType::VIRTUAL);
    bool result = screenSessionManagerClient_->CheckIfNeedConnectScreen(screenId, rsId, name);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: CheckIfNeedConnectScreen02
 * @tc.desc: CheckIfNeedConnectScreen test
 * @tc.type: FUNC
 */
HWTEST_F(ScreenSessionManagerClientTest, CheckIfNeedConnectScreen02, Function | SmallTest | Level2)
{
    EXPECT_NE(screenSessionManagerClient_->screenSessionManager_, nullptr);

    ScreenId screenId = 0;
    ScreenId rsId = SCREEN_ID_INVALID;
    std::string name;
    screenSessionManagerClient_->screenSessionManager_->GetScreenProperty(screenId).SetScreenType(ScreenType::VIRTUAL);
    bool result = screenSessionManagerClient_->CheckIfNeedConnectScreen(screenId, rsId, name);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: CheckIfNeedConnectScreen03
 * @tc.desc: CheckIfNeedConnectScreen test
 * @tc.type: FUNC
 */
HWTEST_F(ScreenSessionManagerClientTest, CheckIfNeedConnectScreen03, Function | SmallTest | Level2)
{
    EXPECT_NE(screenSessionManagerClient_->screenSessionManager_, nullptr);

    ScreenId screenId = 0;
    ScreenId rsId = 0;
    std::string name;
    screenSessionManagerClient_->screenSessionManager_->GetScreenProperty(screenId).SetScreenType(ScreenType::REAL);
    bool result = screenSessionManagerClient_->CheckIfNeedConnectScreen(screenId, rsId, name);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: OnPowerStatusChanged
 * @tc.desc: OnPowerStatusChanged test
 * @tc.type: FUNC
 */
HWTEST_F(ScreenSessionManagerClientTest, OnPowerStatusChanged, Function | SmallTest | Level2)
{
    EXPECT_NE(screenSessionManagerClient_->screenSessionManager_, nullptr);
    ScreenId screenId = 0;
    sptr<ScreenSession> screenSession = new ScreenSession(0, ScreenProperty(), 0);
    screenSessionManagerClient_->screenSessionMap_.emplace(screenId, screenSession);
    DisplayPowerEvent event = DisplayPowerEvent::WAKE_UP;
    EventStatus status = EventStatus::BEGIN;
    PowerStateChangeReason reason = PowerStateChangeReason::STATE_CHANGE_REASON_ACCESS;
    screenSessionManagerClient_->OnPowerStatusChanged(event, status, reason);
    sptr<ScreenSession> screenSession1 = screenSessionManagerClient_->GetScreenSession(screenId);
    EXPECT_NE(screenSession1, nullptr);
}

/**
 * @tc.name: GetAllScreensProperties
 * @tc.desc: GetAllScreensProperties test
 * @tc.type: FUNC
 */
HWTEST_F(ScreenSessionManagerClientTest, GetAllScreensProperties, Function | SmallTest | Level2)
{
    EXPECT_NE(screenSessionManagerClient_->screenSessionManager_, nullptr);
    screenSessionManagerClient_->screenSessionMap_.clear();
    ScreenId screenId = 0;
    sptr<ScreenSession> screenSession = new ScreenSession(screenId, ScreenProperty(), 0);
    screenSessionManagerClient_->screenSessionMap_.emplace(screenId, screenSession);
    EXPECT_EQ(1, screenSessionManagerClient_->GetAllScreensProperties().size());
}

/**
 * @tc.name: SetPrivacyStateByDisplayId01
 * @tc.desc: SetPrivacyStateByDisplayId01 test
 * @tc.type: FUNC
 */
HWTEST_F(ScreenSessionManagerClientTest, SetPrivacyStateByDisplayId01, Function | SmallTest | Level2)
{
    EXPECT_NE(screenSessionManagerClient_->screenSessionManager_, nullptr);
    screenSessionManagerClient_->screenSessionManager_ = nullptr;
    EXPECT_EQ(screenSessionManagerClient_->screenSessionManager_, nullptr);
    screenSessionManagerClient_->ConnectToServer();
    EXPECT_NE(screenSessionManagerClient_->screenSessionManager_, nullptr);

    sptr<DisplayManager::IPrivateWindowListener> displayListener_ = new DmPrivateWindowListener();
    DisplayManager::GetInstance().RegisterPrivateWindowListener(displayListener_);
    
    DisplayId id = 0;
    bool hasPrivate = true;
    screenSessionManagerClient_->SetPrivacyStateByDisplayId(id, hasPrivate);

    bool result = false;
    screenSessionManagerClient_->screenSessionManager_->HasPrivateWindow(id, result);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: SetPrivacyStateByDisplayId02
 * @tc.desc: SetPrivacyStateByDisplayId02 test
 * @tc.type: FUNC
 */
HWTEST_F(ScreenSessionManagerClientTest, SetPrivacyStateByDisplayId02, Function | SmallTest | Level2)
{
    EXPECT_NE(screenSessionManagerClient_->screenSessionManager_, nullptr);
    DisplayId id = 0;
    bool hasPrivate = false;
    screenSessionManagerClient_->SetPrivacyStateByDisplayId(id, hasPrivate);
    bool result = true;
    screenSessionManagerClient_->screenSessionManager_->HasPrivateWindow(id, result);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: SetScreenPrivacyWindowList
 * @tc.desc: SetScreenPrivacyWindowList test
 * @tc.type: FUNC
 */
HWTEST_F(ScreenSessionManagerClientTest, SetScreenPrivacyWindowList, Function | SmallTest | Level2)
{
    screenSessionManagerClient_->screenSessionManager_ = nullptr;
    EXPECT_EQ(screenSessionManagerClient_->screenSessionManager_, nullptr);
    screenSessionManagerClient_->ConnectToServer();
    EXPECT_NE(screenSessionManagerClient_->screenSessionManager_, nullptr);

    DisplayId id = 0;
    std::vector<std::string> privacyWindowList{"win0", "win1"};
    std::vector<std::string> privacyWindowList2{"win0"};
    sptr<DisplayManager::IPrivateWindowListChangeListener> listener_ = new DmPrivateWindowListChangeListener();
    listener_->setCallback([privacyWindowList, privacyWindowList2](std::vector<std::string> windowList)
    {
        EXPECT_EQ(windowList, privacyWindowList);
        EXPECT_NE(windowList, privacyWindowList2);
    });
    DisplayManager::GetInstance().RegisterPrivateWindowListChangeListener(listener_);

    screenSessionManagerClient_->SetScreenPrivacyWindowList(id, privacyWindowList);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
}

/**
 * @tc.name: GetFoldDisplayMode01
 * @tc.desc: GetFoldDisplayMode test
 * @tc.type: FUNC
 */
HWTEST_F(ScreenSessionManagerClientTest, GetFoldDisplayMode01, Function | SmallTest | Level2)
{
    EXPECT_NE(screenSessionManagerClient_->screenSessionManager_, nullptr);
    EXPECT_NE(FoldDisplayMode::FULL, screenSessionManagerClient_->GetFoldDisplayMode());
    EXPECT_NE(FoldStatus::FOLDED, screenSessionManagerClient_->GetFoldStatus());
    EXPECT_EQ(0, screenSessionManagerClient_->GetCurvedCompressionArea());
}

/**
 * @tc.name: GetFoldDisplayMode02
 * @tc.desc: GetFoldDisplayMode test
 * @tc.type: FUNC
 */
HWTEST_F(ScreenSessionManagerClientTest, GetFoldDisplayMode02, Function | SmallTest | Level2)
{
    screenSessionManagerClient_->screenSessionManager_ = nullptr;
    ScreenId screenId = 0;
    bool foldToExpand = true;
    DMRect area;
    screenSessionManagerClient_->GetPhyScreenProperty(screenId);
    screenSessionManagerClient_->UpdateAvailableArea(screenId, area);
    screenSessionManagerClient_->NotifyFoldToExpandCompletion(foldToExpand);
    EXPECT_EQ(FoldDisplayMode::UNKNOWN, screenSessionManagerClient_->GetFoldDisplayMode());
    EXPECT_EQ(FoldStatus::UNKNOWN, screenSessionManagerClient_->GetFoldStatus());
    EXPECT_EQ(0, screenSessionManagerClient_->GetCurvedCompressionArea());
}

/**
 * @tc.name: UpdateScreenRotationProperty
 * @tc.desc: UpdateScreenRotationProperty test
 * @tc.type: FUNC
 */
HWTEST_F(ScreenSessionManagerClientTest, UpdateScreenRotationProperty, Function | SmallTest | Level2)
{
    ScreenId screenId = 0;
    ScreenId displayNodeScreenId = 0;
    sptr<ScreenSession> screenSession = new ScreenSession(0, ScreenProperty(), 0);
    screenSessionManagerClient_->screenSessionMap_.emplace(screenId, screenSession);
    DMRect area;
    bool foldToExpand = true;
    RRect bounds;
    bounds.rect_.width_ = 1344;
    bounds.rect_.height_ = 2772;
    float rotation = 90;
    float scaleX = 1.0;
    float scaleY = 1.0;
    screenSessionManagerClient_->UpdateScreenRotationProperty(screenId, bounds, rotation);
    screenSessionManagerClient_->SetDisplayNodeScreenId(screenId, displayNodeScreenId);
    screenSessionManagerClient_->GetPhyScreenProperty(screenId);
    screenSessionManagerClient_->UpdateAvailableArea(screenId, area);
    screenSessionManagerClient_->NotifyFoldToExpandCompletion(foldToExpand);
    screenSessionManagerClient_->GetScreenSnapshot(screenId, scaleX, scaleY);
    sptr<ScreenSession> screenSession1 = screenSessionManagerClient_->GetScreenSession(screenId);
    EXPECT_NE(screenSession1, nullptr);
}

/**
 * @tc.name: GetScreenSnapshot
 * @tc.desc: GetScreenSnapshot test
 * @tc.type: FUNC
 */
HWTEST_F(ScreenSessionManagerClientTest, GetScreenSnapshot, Function | SmallTest | Level2)
{
    screenSessionManagerClient_->screenSessionMap_.clear();
    ScreenId screenId = 0;
    ScreenId displayNodeScreenId = 0;
    float scaleX = 1.0;
    float scaleY = 1.0;
    RRect bounds;
    bounds.rect_.width_ = 1344;
    bounds.rect_.height_ = 2772;
    float rotation = 90;
    screenSessionManagerClient_->UpdateScreenRotationProperty(screenId, bounds, rotation);
    screenSessionManagerClient_->SetDisplayNodeScreenId(screenId, displayNodeScreenId);
    std::shared_ptr<Media::PixelMap> res = screenSessionManagerClient_->GetScreenSnapshot(screenId, scaleX, scaleY);
    EXPECT_EQ(nullptr, res);
}

/**
 * @tc.name: GetDeviceScreenConfig
 * @tc.desc: GetDeviceScreenConfig test
 * @tc.type: FUNC
 */
HWTEST_F(ScreenSessionManagerClientTest, GetDeviceScreenConfig, Function | SmallTest | Level2)
{
    DeviceScreenConfig deviceScreenConfig = screenSessionManagerClient_->GetDeviceScreenConfig();
    EXPECT_FALSE(deviceScreenConfig.rotationPolicy_.empty());
}
} // namespace Rosen
} // namespace OHOS

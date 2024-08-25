/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#define private public
#include "app_mgr_service_inner.h"
#include "app_running_record.h"
#include "remote_client_manager.h"
#undef private
#include "ability_manager_errors.h"
#include "app_scheduler.h"
#include "appspawn_util.h"
#include "event_handler.h"
#include "hilog_tag_wrapper.h"
#include "hilog_wrapper.h"
#include "ipc_skeleton.h"
#include "mock_ability_token.h"
#include "mock_app_scheduler.h"
#include "mock_bundle_manager.h"
#include "mock_configuration_observer.h"
#include "mock_iapp_state_callback.h"
#include "mock_native_token.h"
#include "mock_render_scheduler.h"
#include "mock_sa_call.h"
#include "parameters.h"
#include "render_state_observer_stub.h"
#include "window_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t RECORD_ID = 1;
constexpr int32_t APP_DEBUG_INFO_PID = 0;
constexpr int32_t APP_DEBUG_INFO_UID = 0;
}
static int recordId_ = 0;
class AppMgrServiceInnerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    void InitAppInfo(const std::string& deviceName, const std::string& abilityName,
        const std::string& appName, const std::string& bundleName, const std::string& moduleName);

public:
    std::shared_ptr<AbilityInfo> abilityInfo_;
    std::shared_ptr<ApplicationInfo> applicationInfo_;
};

class RenderStateObserverMock : public RenderStateObserverStub {
public:
    RenderStateObserverMock() = default;
    virtual ~RenderStateObserverMock() = default;
    void OnRenderStateChanged(const RenderStateData &renderStateData) override
    {}
};

void AppMgrServiceInnerTest::InitAppInfo(const std::string& deviceName,
    const std::string& abilityName, const std::string& appName, const std::string& bundleName,
    const std::string& moduleName)
{
    ApplicationInfo applicationInfo;
    applicationInfo.name = appName;
    applicationInfo.bundleName = bundleName;
    applicationInfo_ = std::make_shared<ApplicationInfo>(applicationInfo);

    AbilityInfo abilityInfo;
    abilityInfo.visible = true;
    abilityInfo.applicationName = appName;
    abilityInfo.type = AbilityType::EXTENSION;
    abilityInfo.name = abilityName;
    abilityInfo.bundleName = bundleName;
    abilityInfo.moduleName = moduleName;
    abilityInfo.deviceId = deviceName;
    abilityInfo_ = std::make_shared<AbilityInfo>(abilityInfo);
}

void AppMgrServiceInnerTest::SetUpTestCase(void)
{
    MockNativeToken::SetNativeToken();
}

void AppMgrServiceInnerTest::TearDownTestCase(void)
{}

void AppMgrServiceInnerTest::SetUp()
{
    // init test app info
    std::string deviceName = "device";
    std::string abilityName = "ServiceAbility";
    std::string appName = "hiservcie";
    std::string bundleName = "com.ix.hiservcie";
    std::string moduleName = "entry";
    InitAppInfo(deviceName, abilityName, appName, bundleName, moduleName);
}

void AppMgrServiceInnerTest::TearDown()
{}

/**
 * @tc.name: PointerDeviceCallback_0100
 * @tc.desc: set parameter, expect config update
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, PointerDeviceCallback_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "PointerDeviceCallback_0100 start");

    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    std::string key = AAFwk::GlobalConfigurationKey::INPUT_POINTER_DEVICE;
    auto context = new (std::nothrow) std::weak_ptr<AppMgrServiceInner>(appMgrServiceInner);
    std::shared_ptr<AppExecFwk::Configuration> config = nullptr;
    std::string value;

    // invalid parameter value
    appMgrServiceInner->PointerDeviceEventCallback(key.c_str(), "false", context);
    config = appMgrServiceInner->GetConfiguration();
    EXPECT_NE(config, nullptr);

    TAG_LOGI(AAFwkTag::TEST, "PointerDeviceCallback_0100 end");
}

/**
 * @tc.name: PointerDeviceCallback_0200
 * @tc.desc: set parameter, expect config update
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, PointerDeviceCallback_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "PointerDeviceCallback_0200 start");

    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    std::string key = AAFwk::GlobalConfigurationKey::INPUT_POINTER_DEVICE;
    auto context = new (std::nothrow) std::weak_ptr<AppMgrServiceInner>(appMgrServiceInner);
    std::shared_ptr<AppExecFwk::Configuration> config = nullptr;
    std::string value;

    // invalid parameter value
    appMgrServiceInner->PointerDeviceEventCallback(key.c_str(), "true", context);
    config = appMgrServiceInner->GetConfiguration();
    EXPECT_NE(config, nullptr);

    TAG_LOGI(AAFwkTag::TEST, "PointerDeviceCallback_0200 end");
}

/**
 * @tc.name: PointerDeviceCallback_0300
 * @tc.desc: set parameter, expect config update
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, PointerDeviceCallback_0300, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "PointerDeviceCallback_0300 start");

    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    std::string key = AAFwk::GlobalConfigurationKey::INPUT_POINTER_DEVICE;
    auto context = new (std::nothrow) std::weak_ptr<AppMgrServiceInner>(appMgrServiceInner);
    std::shared_ptr<AppExecFwk::Configuration> config = nullptr;
    std::string value;

    // invalid parameter value
    appMgrServiceInner->PointerDeviceEventCallback("invalid_key", "false", context);
    config = appMgrServiceInner->GetConfiguration();
    EXPECT_NE(config, nullptr);

    TAG_LOGI(AAFwkTag::TEST, "PointerDeviceCallback_0300 end");
}

/**
 * @tc.name: PointerDeviceCallback_0400
 * @tc.desc: set parameter, expect config update
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, PointerDeviceCallback_0400, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "PointerDeviceCallback_0400 start");

    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    std::string key = AAFwk::GlobalConfigurationKey::INPUT_POINTER_DEVICE;
    auto context = new (std::nothrow) std::weak_ptr<AppMgrServiceInner>(appMgrServiceInner);
    std::shared_ptr<AppExecFwk::Configuration> config = nullptr;
    std::string value;

    // invalid parameter value
    appMgrServiceInner->PointerDeviceEventCallback(key.c_str(), "invalid", context);
    config = appMgrServiceInner->GetConfiguration();
    EXPECT_NE(config, nullptr);

    TAG_LOGI(AAFwkTag::TEST, "PointerDeviceCallback_0400 end");
}

/**
 * @tc.name: PointerDeviceWatchParameter_0100
 * @tc.desc: set parameter, expect config update
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, PointerDeviceWatchParameter_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "PointerDeviceWatchParameter_0100 start");

    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    std::string key = AAFwk::GlobalConfigurationKey::INPUT_POINTER_DEVICE;
    std::shared_ptr<AppExecFwk::Configuration> config = nullptr;
    std::string value;

    appMgrServiceInner->AddWatchParameter();
    sleep(1);

    // invalid parameter value
    system::SetParameter(key.c_str(), "invalid");
    sleep(1);
    config = appMgrServiceInner->GetConfiguration();
    EXPECT_NE(config, nullptr);

    TAG_LOGI(AAFwkTag::TEST, "PointerDeviceWatchParameter_0100 end");
}

/**
 * @tc.name: PointerDeviceWatchParameter_0200
 * @tc.desc: set parameter, expect config update
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, PointerDeviceWatchParameter_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "PointerDeviceWatchParameter_0200 start");

    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    std::string key = AAFwk::GlobalConfigurationKey::INPUT_POINTER_DEVICE;
    std::shared_ptr<AppExecFwk::Configuration> config = nullptr;
    std::string value;

    appMgrServiceInner->AddWatchParameter();
    sleep(1);

    // set "input.pointer.device" to false
    system::SetParameter(key.c_str(), "false");
    sleep(1);
    config = appMgrServiceInner->GetConfiguration();
    EXPECT_NE(config, nullptr);

    TAG_LOGI(AAFwkTag::TEST, "PointerDeviceWatchParameter_0200 end");
}

/**
 * @tc.name: PointerDeviceWatchParameter_0300
 * @tc.desc: set parameter, expect config update
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, PointerDeviceWatchParameter_0300, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "PointerDeviceWatchParameter_0300 start");

    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    std::string key = AAFwk::GlobalConfigurationKey::INPUT_POINTER_DEVICE;
    std::shared_ptr<AppExecFwk::Configuration> config = nullptr;
    std::string value;

    appMgrServiceInner->AddWatchParameter();
    sleep(1);

    // set "input.pointer.device" to true
    system::SetParameter(key.c_str(), "true");
    sleep(1);
    config = appMgrServiceInner->GetConfiguration();
    EXPECT_NE(config, nullptr);

    TAG_LOGI(AAFwkTag::TEST, "PointerDeviceWatchParameter_0300 end");
}

/**
 * @tc.name: PointerDeviceUpdateConfig_0100
 * @tc.desc: set parameter, expect config update
 * @tc.type: FUNC
 * @tc.require: I581UL
 */
HWTEST_F(AppMgrServiceInnerTest, PointerDeviceUpdateConfig_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "PointerDeviceUpdateConfig_0100 start");

    AAFwk::IsMockSaCall::IsMockSaCallWithPermission();
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    std::shared_ptr<AppExecFwk::Configuration> config;
    std::string value;
    int32_t result;

    appMgrServiceInner->InitGlobalConfiguration();
    config = appMgrServiceInner->GetConfiguration();
    EXPECT_NE(config, nullptr);
    value = config->GetItem(AAFwk::GlobalConfigurationKey::INPUT_POINTER_DEVICE);
    EXPECT_TRUE((value == "true") || (value == "false"));

    // config didn't change
    result = appMgrServiceInner->UpdateConfiguration(*config);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    Configuration changeConfig;
    if (value == "true") {
        changeConfig.AddItem(AAFwk::GlobalConfigurationKey::INPUT_POINTER_DEVICE, "false");
        result = appMgrServiceInner->UpdateConfiguration(changeConfig);
        EXPECT_EQ(result, ERR_OK);
        config = appMgrServiceInner->GetConfiguration();
        EXPECT_NE(config, nullptr);
        value = config->GetItem(AAFwk::GlobalConfigurationKey::INPUT_POINTER_DEVICE);
        EXPECT_EQ(value, "false");
    } else {
        changeConfig.AddItem(AAFwk::GlobalConfigurationKey::INPUT_POINTER_DEVICE, "true");
        result = appMgrServiceInner->UpdateConfiguration(changeConfig);
        EXPECT_EQ(result, ERR_PERMISSION_DENIED);
        config = appMgrServiceInner->GetConfiguration();
        EXPECT_NE(config, nullptr);
        value = config->GetItem(AAFwk::GlobalConfigurationKey::INPUT_POINTER_DEVICE);
        EXPECT_EQ(value, "true");
    }

    TAG_LOGI(AAFwkTag::TEST, "PointerDeviceUpdateConfig_0100 end");
}

/**
 * @tc.name: PreStartNWebSpawnProcess_001
 * @tc.desc: prestart nwebspawn process.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, PreStartNWebSpawnProcess_001, TestSize.Level0)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    int callingPid = IPCSkeleton::GetCallingPid();
    int ret = appMgrServiceInner->PreStartNWebSpawnProcess(callingPid);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.name: PreStartNWebSpawnProcess_002
 * @tc.desc: prestart nwebspawn process.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, PreStartNWebSpawnProcess_002, TestSize.Level0)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    int callingPid = 0;
    int ret = appMgrServiceInner->PreStartNWebSpawnProcess(callingPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: LoadAbility_001
 * @tc.desc: load ability.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, LoadAbility_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "LoadAbility_001 start");
    OHOS::sptr<IRemoteObject> token = sptr<IRemoteObject>(new (std::nothrow) MockAbilityToken());
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->LoadAbility(token, nullptr, abilityInfo_, applicationInfo_, nullptr, 0);

    auto appMgrServiceInner1 = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner1, nullptr);

    appMgrServiceInner1->remoteClientManager_->SetBundleManagerHelper(nullptr);
    appMgrServiceInner1->LoadAbility(token, nullptr, abilityInfo_, applicationInfo_, nullptr, 0);

    auto appMgrServiceInner2 = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner2, nullptr);

    appMgrServiceInner2->LoadAbility(token, nullptr, abilityInfo_, applicationInfo_, nullptr, 0);
    TAG_LOGI(AAFwkTag::TEST, "LoadAbility_001 end");
}

/**
 * @tc.name: CheckLoadAbilityConditions_001
 * @tc.desc: check load ability conditions.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, CheckLoadAbilityConditions_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckLoadAbilityConditions_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    OHOS::sptr<IRemoteObject> token = sptr<IRemoteObject>(new (std::nothrow) MockAbilityToken());

    appMgrServiceInner->CheckLoadAbilityConditions(nullptr, nullptr, nullptr);

    appMgrServiceInner->CheckLoadAbilityConditions(nullptr, abilityInfo_, nullptr);

    appMgrServiceInner->CheckLoadAbilityConditions(nullptr, nullptr, applicationInfo_);

    appMgrServiceInner->CheckLoadAbilityConditions(token, nullptr, nullptr);

    appMgrServiceInner->CheckLoadAbilityConditions(token, abilityInfo_, nullptr);

    appMgrServiceInner->CheckLoadAbilityConditions(nullptr, abilityInfo_, applicationInfo_);

    appMgrServiceInner->CheckLoadAbilityConditions(token, nullptr, applicationInfo_);

    appMgrServiceInner->CheckLoadAbilityConditions(token, abilityInfo_, applicationInfo_);

    EXPECT_NE(appMgrServiceInner, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "CheckLoadAbilityConditions_001 end");
}

/**
 * @tc.name: MakeProcessName_001
 * @tc.desc: make process name.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, MakeProcessName_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "MakeProcessName_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    HapModuleInfo hapModuleInfo;
    hapModuleInfo.moduleName = "module789";
    std::string processName = "test_processName";
    appMgrServiceInner->MakeProcessName(nullptr, nullptr, hapModuleInfo, 1, processName);
    appMgrServiceInner->MakeProcessName(nullptr, applicationInfo_, hapModuleInfo, 1, processName);
    appMgrServiceInner->MakeProcessName(abilityInfo_, nullptr, hapModuleInfo, 1, processName);
    appMgrServiceInner->MakeProcessName(abilityInfo_, applicationInfo_, hapModuleInfo, 1, processName);

    EXPECT_NE(appMgrServiceInner, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "MakeProcessName_001 end");
}

/**
 * @tc.name: MakeProcessName_002
 * @tc.desc: make process name.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, MakeProcessName_002, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "MakeProcessName_002 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    HapModuleInfo hapModuleInfo;
    hapModuleInfo.moduleName = "module789";
    std::string processName = "test_processName";
    appMgrServiceInner->MakeProcessName(nullptr, hapModuleInfo, processName);
    appMgrServiceInner->MakeProcessName(applicationInfo_, hapModuleInfo, processName);
    hapModuleInfo.isStageBasedModel = false;
    hapModuleInfo.process = "";
    appMgrServiceInner->MakeProcessName(applicationInfo_, hapModuleInfo, processName);

    hapModuleInfo.isStageBasedModel = true;
    hapModuleInfo.process = "";
    appMgrServiceInner->MakeProcessName(applicationInfo_, hapModuleInfo, processName);

    hapModuleInfo.isStageBasedModel = false;
    hapModuleInfo.process = "test_process";
    appMgrServiceInner->MakeProcessName(applicationInfo_, hapModuleInfo, processName);

    hapModuleInfo.isStageBasedModel = true;
    hapModuleInfo.process = "test_process";
    appMgrServiceInner->MakeProcessName(applicationInfo_, hapModuleInfo, processName);

    hapModuleInfo.isStageBasedModel = false;
    applicationInfo_->process = "";
    appMgrServiceInner->MakeProcessName(applicationInfo_, hapModuleInfo, processName);

    hapModuleInfo.isStageBasedModel = false;
    applicationInfo_->process = "test_process";
    appMgrServiceInner->MakeProcessName(applicationInfo_, hapModuleInfo, processName);

    EXPECT_NE(appMgrServiceInner, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "MakeProcessName_002 end");
}

/**
 * @tc.name: GetBundleAndHapInfo_001
 * @tc.desc: get bundle and hapInfo.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, GetBundleAndHapInfo_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "GetBundleAndHapInfo_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    BundleInfo bundleInfo;
    HapModuleInfo hapModuleInfo;
    appMgrServiceInner->GetBundleAndHapInfo(*abilityInfo_, applicationInfo_, bundleInfo, hapModuleInfo, 1);

    appMgrServiceInner->remoteClientManager_->SetBundleManagerHelper(nullptr);
    appMgrServiceInner->GetBundleAndHapInfo(*abilityInfo_, applicationInfo_, bundleInfo, hapModuleInfo, 1);
    TAG_LOGI(AAFwkTag::TEST, "GetBundleAndHapInfo_001 end");
}

/**
 * @tc.name: AttachApplication_001
 * @tc.desc: attach application.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, AttachApplication_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "AttachApplication_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->AttachApplication(0, nullptr);

    appMgrServiceInner->AttachApplication(1, nullptr);

    sptr<MockAppScheduler> mockAppScheduler = new (std::nothrow) MockAppScheduler();
    sptr<IAppScheduler> client = iface_cast<IAppScheduler>(mockAppScheduler.GetRefPtr());
    appMgrServiceInner->AttachApplication(1, client);
    TAG_LOGI(AAFwkTag::TEST, "AttachApplication_001 end");
}

/**
 * @tc.name: LaunchApplication_001
 * @tc.desc: launch application.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, LaunchApplication_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "LaunchApplication_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->LaunchApplication(nullptr);

    BundleInfo info;
    std::string processName = "test_processName";
    std::shared_ptr<AppRunningRecord> appRecord =
        appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, info);
    recordId_ += 1;
    appMgrServiceInner->LaunchApplication(appRecord);

    appRecord->SetState(ApplicationState::APP_STATE_FOREGROUND);
    appMgrServiceInner->LaunchApplication(appRecord);

    appRecord->SetState(ApplicationState::APP_STATE_CREATE);
    appMgrServiceInner->LaunchApplication(appRecord);

    appRecord->SetEmptyKeepAliveAppState(true);
    appRecord->SetKeepAliveEnableState(false);
    appMgrServiceInner->LaunchApplication(appRecord);

    appRecord->SetKeepAliveEnableState(true);
    appRecord->SetEmptyKeepAliveAppState(false);
    appMgrServiceInner->LaunchApplication(appRecord);

    appRecord->SetKeepAliveEnableState(true);
    appRecord->SetEmptyKeepAliveAppState(true);
    appMgrServiceInner->LaunchApplication(appRecord);

    appRecord->SetKeepAliveEnableState(false);
    appRecord->SetEmptyKeepAliveAppState(false);
    appMgrServiceInner->LaunchApplication(appRecord);

    Want want;
    appRecord->SetSpecifiedAbilityFlagAndWant(-1, want, "");
    appMgrServiceInner->LaunchApplication(appRecord);

    appRecord->SetSpecifiedAbilityFlagAndWant(1, want, "");
    appMgrServiceInner->LaunchApplication(appRecord);

    appMgrServiceInner->configuration_ = nullptr;
    appMgrServiceInner->LaunchApplication(appRecord);
    TAG_LOGI(AAFwkTag::TEST, "LaunchApplication_001 end");
}

/**
 * @tc.name: AddAbilityStageDone_001
 * @tc.desc: add ability stage done.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, AddAbilityStageDone_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "AddAbilityStageDone_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->AddAbilityStageDone(99);

    BundleInfo info;
    std::string processName = "test_processName";
    appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, info);
    recordId_ += 1;

    appMgrServiceInner->AddAbilityStageDone(recordId_);
    TAG_LOGI(AAFwkTag::TEST, "AddAbilityStageDone_001 end");
}

/**
 * @tc.name: ApplicationForegrounded_001
 * @tc.desc: application foregrounded.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, ApplicationForegrounded_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "ApplicationForegrounded_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->ApplicationForegrounded(99);

    BundleInfo info;
    std::string processName = "test_processName";
    appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, info);
    recordId_ += 1;

    appMgrServiceInner->ApplicationForegrounded(recordId_);
    TAG_LOGI(AAFwkTag::TEST, "ApplicationForegrounded_001 end");
}

/**
 * @tc.name: ApplicationForegrounded_002
 * @tc.desc: application foregrounded.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, ApplicationForegrounded_002, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "ApplicationForegrounded_002 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    BundleInfo info;
    std::string processName = "test_processName";
    auto record = appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, info);
    record->SetUpdateStateFromService(true);
    recordId_ += 1;

    appMgrServiceInner->ApplicationForegrounded(recordId_);
    TAG_LOGI(AAFwkTag::TEST, "ApplicationForegrounded_002 end");
}

/**
 * @tc.name: ApplicationForegrounded_003
 * @tc.desc: application foregrounded.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, ApplicationForegrounded_003, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "ApplicationForegrounded_003 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    BundleInfo info;
    std::string processName = "test_processName";
    auto record = appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, info);
    recordId_ += 1;
    record->SetUpdateStateFromService(true);
    auto record2 = appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, info);
    recordId_ += 1;
    std::shared_ptr<PriorityObject> priorityObject = std::make_shared<PriorityObject>();
    std::string callerBundleName = "callerBundleName";
    priorityObject->SetPid(1);
    record2->priorityObject_ = priorityObject;
    record2->mainBundleName_ = callerBundleName;
    record->SetCallerPid(1);

    appMgrServiceInner->ApplicationForegrounded(--recordId_);
    TAG_LOGI(AAFwkTag::TEST, "ApplicationForegrounded_003 end");
}

/**
 * @tc.name: ApplicationBackgrounded_001
 * @tc.desc: application backgrounded.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, ApplicationBackgrounded_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "ApplicationBackgrounded_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    appMgrServiceInner->Init();

    appMgrServiceInner->ApplicationBackgrounded(99);

    BundleInfo info;
    std::string processName = "test_processName";
    auto appRecord =
        appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, info);
    EXPECT_NE(appRecord, nullptr);
    recordId_ += 1;

    appMgrServiceInner->ApplicationBackgrounded(recordId_);

    appRecord->SetState(ApplicationState::APP_STATE_FOREGROUND);
    appMgrServiceInner->ApplicationBackgrounded(recordId_);

    TAG_LOGI(AAFwkTag::TEST, "ApplicationBackgrounded_001 end");
}

/**
 * @tc.name: ApplicationTerminated_001
 * @tc.desc: application terminated.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, ApplicationTerminated_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "ApplicationTerminated_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->ApplicationTerminated(99);

    BundleInfo info;
    std::string processName = "test_processName";
    auto appRecord =
        appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, info);
    EXPECT_NE(appRecord, nullptr);
    recordId_ += 1;

    appMgrServiceInner->ApplicationTerminated(recordId_);

    appRecord->SetKeepAliveEnableState(false);
    appRecord->SetEmptyKeepAliveAppState(true);
    appMgrServiceInner->ApplicationTerminated(recordId_);

    appRecord->SetKeepAliveEnableState(true);
    appRecord->SetEmptyKeepAliveAppState(false);
    appMgrServiceInner->ApplicationTerminated(recordId_);

    appRecord->SetKeepAliveEnableState(true);
    appRecord->SetEmptyKeepAliveAppState(true);
    appMgrServiceInner->ApplicationTerminated(recordId_);

    appRecord->SetKeepAliveEnableState(false);
    appRecord->SetEmptyKeepAliveAppState(false);
    appMgrServiceInner->ApplicationTerminated(recordId_);

    appRecord->SetState(ApplicationState::APP_STATE_FOREGROUND);
    appMgrServiceInner->ApplicationTerminated(recordId_);

    appRecord->SetState(ApplicationState::APP_STATE_BACKGROUND);
    appMgrServiceInner->ApplicationTerminated(recordId_);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->ApplicationTerminated(recordId_);

    TAG_LOGI(AAFwkTag::TEST, "ApplicationTerminated_001 end");
}

/**
 * @tc.name: KillApplication_001
 * @tc.desc: kill application.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, KillApplication_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "KillApplication_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    std::string bundleName = "test_bundleName";
    appMgrServiceInner->KillApplication(bundleName);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->KillApplication(bundleName);

    TAG_LOGI(AAFwkTag::TEST, "KillApplication_001 end");
}

/**
 * @tc.name: KillApplicationByUid_001
 * @tc.desc: kill application by uid.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, KillApplicationByUid_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "KillApplicationByUid_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    std::string bundleName = "test_bundleName";
    appMgrServiceInner->KillApplicationByUid(bundleName, 0);

    appMgrServiceInner->remoteClientManager_->SetBundleManagerHelper(nullptr);
    appMgrServiceInner->KillApplicationByUid(bundleName, 0);

    appMgrServiceInner->remoteClientManager_ = nullptr;
    appMgrServiceInner->KillApplicationByUid(bundleName, 0);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->KillApplicationByUid(bundleName, 0);

    TAG_LOGI(AAFwkTag::TEST, "KillApplicationByUid_001 end");
}

/**
 * @tc.name: KillApplicationSelf_001
 * @tc.desc: kill application self.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, KillApplicationSelf_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "KillApplicationSelf_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    EXPECT_EQ(appMgrServiceInner->KillApplicationSelf(), ERR_INVALID_VALUE);

    appMgrServiceInner->appRunningManager_ = nullptr;
    EXPECT_EQ(appMgrServiceInner->KillApplicationSelf(), ERR_NO_INIT);

    TAG_LOGI(AAFwkTag::TEST, "KillApplicationSelf_001 end");
}

/**
 * @tc.name: KillApplicationByUserId_001
 * @tc.desc: kill application by user id.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, KillApplicationByUserId_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "KillApplicationByUserId_001 start");
    AAFwk::IsMockSaCall::IsMockSaCallWithPermission();
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    std::string bundleName = "test_bundleName";
    int result = appMgrServiceInner->KillApplicationByUserId(bundleName, 0);
    EXPECT_EQ(result, 0);

    appMgrServiceInner->remoteClientManager_->SetBundleManagerHelper(nullptr);
    appMgrServiceInner->KillApplicationByUserId(bundleName, 0);
    EXPECT_EQ(result, 0);

    appMgrServiceInner->remoteClientManager_ = nullptr;
    appMgrServiceInner->KillApplicationByUserId(bundleName, 0);
    EXPECT_EQ(result, 0);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->KillApplicationByUserId(bundleName, 0);
    EXPECT_EQ(result, 0);

    TAG_LOGI(AAFwkTag::TEST, "KillApplicationByUserId_001 end");
}

/**
 * @tc.name: KillApplicationByUserIdLocked_001
 * @tc.desc: kill application by user id locked.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, KillApplicationByUserIdLocked_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "KillApplicationByUserIdLocked_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    std::string bundleName = "test_bundleName";
    int result = appMgrServiceInner->KillApplicationByUserIdLocked(bundleName, 0);
    EXPECT_EQ(result, 0);

    appMgrServiceInner->remoteClientManager_->SetBundleManagerHelper(nullptr);
    appMgrServiceInner->KillApplicationByUserIdLocked(bundleName, 0);
    EXPECT_EQ(result, 0);

    appMgrServiceInner->remoteClientManager_ = nullptr;
    appMgrServiceInner->KillApplicationByUserIdLocked(bundleName, 0);
    EXPECT_EQ(result, 0);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->KillApplicationByUserIdLocked(bundleName, 0);
    EXPECT_EQ(result, 0);

    TAG_LOGI(AAFwkTag::TEST, "KillApplicationByUserIdLocked_001 end");
}

/**
 * @tc.name: ClearUpApplicationData_001
 * @tc.desc: clear up application data.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, ClearUpApplicationData_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "ClearUpApplicationData_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    std::string bundleName = "test_bundleName";
    appMgrServiceInner->ClearUpApplicationData(bundleName, 0, 0);

    TAG_LOGI(AAFwkTag::TEST, "ClearUpApplicationData_001 end");
}

/**
 * @tc.name: ClearUpApplicationDataByUserId_001
 * @tc.desc: clear up application data by user id.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, ClearUpApplicationDataByUserId_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "ClearUpApplicationDataByUserId_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    std::string bundleName = "test_bundleName";
    appMgrServiceInner->ClearUpApplicationDataByUserId(bundleName, 0, 0, 0);
    appMgrServiceInner->ClearUpApplicationDataByUserId(bundleName, 1, 0, 0);
    appMgrServiceInner->ClearUpApplicationDataByUserId(bundleName, 1, 1, 0);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->ClearUpApplicationDataByUserId(bundleName, 1, 1, 0);

    appMgrServiceInner->remoteClientManager_->SetBundleManagerHelper(nullptr);
    appMgrServiceInner->ClearUpApplicationDataByUserId(bundleName, 1, 1, 0);

    TAG_LOGI(AAFwkTag::TEST, "ClearUpApplicationDataByUserId_001 end");
}

/**
 * @tc.name: GetAllRunningProcesses_001
 * @tc.desc: get all running processes.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, GetAllRunningProcesses_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "GetAllRunningProcesses_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    std::vector<RunningProcessInfo> info;
    appMgrServiceInner->GetAllRunningProcesses(info);

    TAG_LOGI(AAFwkTag::TEST, "GetAllRunningProcesses_001 end");
}

/**
 * @tc.name: GetProcessRunningInfosByUserId_001
 * @tc.desc: get process running infos by user id.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, GetProcessRunningInfosByUserId_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "GetProcessRunningInfosByUserId_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    std::vector<RunningProcessInfo> info;
    appMgrServiceInner->GetProcessRunningInfosByUserId(info, 0);

    TAG_LOGI(AAFwkTag::TEST, "GetProcessRunningInfosByUserId_001 end");
}

/**
 * @tc.name: GetAllRenderProcesses_001
 * @tc.desc: get all render processes.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, GetAllRenderProcesses_001, TestSize.Level0)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    std::vector<RenderProcessInfo> info;
    appMgrServiceInner->GetAllRenderProcesses(info);
}

/**
 * @tc.name: NotifyMemoryLevel_001
 * @tc.desc: notify memory level.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, NotifyMemoryLevel_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "NotifyMemoryLevel_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    std::vector<RunningProcessInfo> info;
    int result = appMgrServiceInner->NotifyMemoryLevel(0);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    result = appMgrServiceInner->NotifyMemoryLevel(1);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    result = appMgrServiceInner->NotifyMemoryLevel(2);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    result = appMgrServiceInner->NotifyMemoryLevel(3);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    appMgrServiceInner->appRunningManager_ = nullptr;
    result = appMgrServiceInner->NotifyMemoryLevel(3);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    TAG_LOGI(AAFwkTag::TEST, "NotifyMemoryLevel_001 end");
}

/**
 * @tc.name: KillProcessByPid_001
 * @tc.desc: kill process by pid.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, KillProcessByPid_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "KillProcessByPid_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    int result = appMgrServiceInner->KillProcessByPid(0, "KillProcessByPid_001");
    EXPECT_EQ(result, AAFwk::ERR_KILL_PROCESS_NOT_EXIST);

    result = appMgrServiceInner->KillProcessByPid(1, "KillProcessByPid_001");
    EXPECT_EQ(result, 0);

    TAG_LOGI(AAFwkTag::TEST, "KillProcessByPid_001 end");
}

/**
 * @tc.name: KillProcessByPid_002
 * @tc.desc: kill process by pid.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, KillProcessByPid_002, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "KillProcessByPid_002 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    int pid = 0;
    std::string processName = "test_processName";
    std::shared_ptr<AppRunningRecord> appRecord =
        std::make_shared<AppRunningRecord>(applicationInfo_, ++recordId_, processName);
    auto appRunningManager = std::make_shared<AppRunningManager>();
    auto priorityObject = std::make_shared<PriorityObject>();
    priorityObject->SetPid(0);
    appRecord->priorityObject_ = priorityObject;
    appRunningManager->appRunningRecordMap_.emplace(recordId_, appRecord);

    int result = appMgrServiceInner->KillProcessByPid(pid, "KillProcessByPid_002");
    EXPECT_EQ(result, AAFwk::ERR_KILL_PROCESS_NOT_EXIST);

    TAG_LOGI(AAFwkTag::TEST, "KillProcessByPid_002 end");
}

/**
 * @tc.name: GetAllPids_001
 * @tc.desc: get all pids.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, GetAllPids_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "GetAllPids_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    std::list<pid_t> pids;
    bool result = appMgrServiceInner->GetAllPids(pids);
    EXPECT_FALSE(result);

    pids.push_back(1);
    result = appMgrServiceInner->GetAllPids(pids);
    EXPECT_TRUE(result);

    std::string appName = "test_appName";
    std::string processName = "test_processName";
    appMgrServiceInner->appProcessManager_->AddAppToRecentList(appName, processName, 0, 0);
    result = appMgrServiceInner->GetAllPids(pids);
    EXPECT_TRUE(result);

    TAG_LOGI(AAFwkTag::TEST, "GetAllPids_001 end");
}

/**
 * @tc.name: ProcessExist_001
 * @tc.desc: process exist.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, ProcessExist_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "ProcessExist_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    pid_t pid = 0;
    bool result = appMgrServiceInner->ProcessExist(pid);
    EXPECT_FALSE(result);

    TAG_LOGI(AAFwkTag::TEST, "ProcessExist_001 end");
}

/**
 * @tc.name: CreateAppRunningRecord_001
 * @tc.desc: create app running record.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, CreateAppRunningRecord_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "CreateAppRunningRecord_001 start");
    OHOS::sptr<IRemoteObject> token = sptr<IRemoteObject>(new (std::nothrow) MockAbilityToken());
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    BundleInfo bundleInfo;
    HapModuleInfo hapModuleInfo;
    std::shared_ptr<AAFwk::Want> want;
    std::string processName = "test_processName";

    std::shared_ptr<AppRunningRecord> appRecord = appMgrServiceInner->CreateAppRunningRecord(nullptr, nullptr,
        nullptr, nullptr, "", bundleInfo, hapModuleInfo, nullptr, 0);
    EXPECT_EQ(appRecord, nullptr);

    appRecord = appMgrServiceInner->CreateAppRunningRecord(token, nullptr,
        nullptr, nullptr, "", bundleInfo, hapModuleInfo, nullptr, 0);
    EXPECT_EQ(appRecord, nullptr);

    appRecord = appMgrServiceInner->CreateAppRunningRecord(token, nullptr,
        applicationInfo_, nullptr, "", bundleInfo, hapModuleInfo, nullptr, 0);
    EXPECT_EQ(appRecord, nullptr);

    appRecord = appMgrServiceInner->CreateAppRunningRecord(token, nullptr,
        applicationInfo_, abilityInfo_, "", bundleInfo, hapModuleInfo, nullptr, 0);
    EXPECT_EQ(appRecord, nullptr);

    appRecord = appMgrServiceInner->CreateAppRunningRecord(token, nullptr,
        applicationInfo_, abilityInfo_, processName, bundleInfo, hapModuleInfo, nullptr, 0);
    EXPECT_NE(appRecord, nullptr);

    appRecord = appMgrServiceInner->CreateAppRunningRecord(token, nullptr,
        applicationInfo_, abilityInfo_, processName, bundleInfo, hapModuleInfo, nullptr, 0);
    EXPECT_NE(appRecord, nullptr);

    appRecord = appMgrServiceInner->CreateAppRunningRecord(token, nullptr,
        applicationInfo_, abilityInfo_, processName, bundleInfo, hapModuleInfo, nullptr, 0);
    EXPECT_NE(appRecord, nullptr);

    std::shared_ptr<AppRunningRecord> appRecord1 = appMgrServiceInner->CreateAppRunningRecord(token, nullptr,
        nullptr, abilityInfo_, processName, bundleInfo, hapModuleInfo, want, 0);
    EXPECT_EQ(appRecord1, nullptr);

    std::shared_ptr<AppRunningRecord> appRecord2 = appMgrServiceInner->CreateAppRunningRecord(token, nullptr,
        applicationInfo_, abilityInfo_, processName, bundleInfo, hapModuleInfo, want, 0);
    EXPECT_NE(appRecord2, nullptr);

    want = std::make_shared<Want>();
    const std::string COLD_START = "coldStart";
    want->SetParam(COLD_START, true);
    std::shared_ptr<AppRunningRecord> appRecord3 = appMgrServiceInner->CreateAppRunningRecord(token, nullptr,
        applicationInfo_, abilityInfo_, processName, bundleInfo, hapModuleInfo, want, 0);
    EXPECT_NE(appRecord3, nullptr);

    want->SetParam(COLD_START, false);
    std::shared_ptr<AppRunningRecord> appRecord4 = appMgrServiceInner->CreateAppRunningRecord(token, nullptr,
        applicationInfo_, abilityInfo_, processName, bundleInfo, hapModuleInfo, want, 0);
    EXPECT_NE(appRecord4, nullptr);

    appMgrServiceInner->appRunningManager_ = nullptr;
    std::shared_ptr<AppRunningRecord> appRecord5 = appMgrServiceInner->CreateAppRunningRecord(token, nullptr,
        applicationInfo_, abilityInfo_, processName, bundleInfo, hapModuleInfo, want, 0);
    EXPECT_EQ(appRecord5, nullptr);

    appMgrServiceInner->appRunningManager_ = nullptr;
    want->SetParam("multiThread", false);
    std::shared_ptr<AppRunningRecord> appRecord6 = appMgrServiceInner->CreateAppRunningRecord(token, nullptr,
        applicationInfo_, abilityInfo_, processName, bundleInfo, hapModuleInfo, want, 0);
    EXPECT_EQ(appRecord6, nullptr);

    TAG_LOGI(AAFwkTag::TEST, "CreateAppRunningRecord_001 end");
}

/**
 * @tc.name: TerminateAbility_001
 * @tc.desc: terminate ability.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, TerminateAbility_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "TerminateAbility_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->TerminateAbility(nullptr, true);
    appMgrServiceInner->TerminateAbility(nullptr, false);

    OHOS::sptr<IRemoteObject> token = sptr<IRemoteObject>(new (std::nothrow) MockAbilityToken());
    appMgrServiceInner->TerminateAbility(token, true);
    appMgrServiceInner->TerminateAbility(token, false);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->TerminateAbility(token, true);

    TAG_LOGI(AAFwkTag::TEST, "TerminateAbility_001 end");
}

/**
 * @tc.name: UpdateAbilityState_001
 * @tc.desc: update ability state.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, UpdateAbilityState_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "UpdateAbilityState_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->UpdateAbilityState(nullptr, AbilityState::ABILITY_STATE_CREATE);

    OHOS::sptr<IRemoteObject> token = sptr<IRemoteObject>(new (std::nothrow) MockAbilityToken());
    appMgrServiceInner->UpdateAbilityState(token, AbilityState::ABILITY_STATE_CREATE);

    BundleInfo bundleInfo;
    HapModuleInfo hapModuleInfo;
    std::shared_ptr<AAFwk::Want> want;
    std::string processName = "test_processName";
    std::shared_ptr<AppRunningRecord> appRecord = appMgrServiceInner->CreateAppRunningRecord(token, nullptr,
        applicationInfo_, nullptr, processName, bundleInfo, hapModuleInfo, want, 0);
    EXPECT_NE(appRecord, nullptr);
    appMgrServiceInner->UpdateAbilityState(token, AbilityState::ABILITY_STATE_CREATE);

    OHOS::sptr<IRemoteObject> token1 = sptr<IRemoteObject>(new (std::nothrow) MockAbilityToken());
    std::shared_ptr<AppRunningRecord> appRecord1 = appMgrServiceInner->CreateAppRunningRecord(token1, nullptr,
        applicationInfo_, abilityInfo_, processName, bundleInfo, hapModuleInfo, want, 0);
    EXPECT_NE(appRecord1, nullptr);

    appMgrServiceInner->UpdateAbilityState(token1, AbilityState::ABILITY_STATE_READY);
    appMgrServiceInner->UpdateAbilityState(token1, AbilityState::ABILITY_STATE_CREATE);

    auto abilityRecord1 =
        appMgrServiceInner->GetAppRunningRecordByAbilityToken(token1)->GetAbilityRunningRecordByToken(token1);
    abilityRecord1->SetState(AbilityState::ABILITY_STATE_TERMINATED);
    appMgrServiceInner->UpdateAbilityState(token1, AbilityState::ABILITY_STATE_TERMINATED);

    abilityRecord1->SetState(AbilityState::ABILITY_STATE_CONNECTED);
    appMgrServiceInner->UpdateAbilityState(token1, AbilityState::ABILITY_STATE_CONNECTED);

    abilityRecord1->SetState(AbilityState::ABILITY_STATE_DISCONNECTED);
    appMgrServiceInner->UpdateAbilityState(token1, AbilityState::ABILITY_STATE_DISCONNECTED);

    abilityRecord1->SetState(AbilityState::ABILITY_STATE_END);
    appMgrServiceInner->UpdateAbilityState(token1, AbilityState::ABILITY_STATE_END);

    abilityRecord1->SetState(AbilityState::ABILITY_STATE_BACKGROUND);
    appMgrServiceInner->UpdateAbilityState(token1, AbilityState::ABILITY_STATE_BACKGROUND);

    OHOS::sptr<IRemoteObject> token2 = sptr<IRemoteObject>(new (std::nothrow) MockAbilityToken());
    abilityInfo_->type = AbilityType::SERVICE;
    std::shared_ptr<AppRunningRecord> appRecord2 = appMgrServiceInner->CreateAppRunningRecord(token2, nullptr,
        applicationInfo_, abilityInfo_, processName, bundleInfo, hapModuleInfo, want, 0);
    EXPECT_NE(appRecord2, nullptr);
    appMgrServiceInner->UpdateAbilityState(token2, AbilityState::ABILITY_STATE_CREATE);

    auto abilityRecord2 =
        appMgrServiceInner->GetAppRunningRecordByAbilityToken(token2)->GetAbilityRunningRecordByToken(token2);
    abilityRecord2->SetState(AbilityState::ABILITY_STATE_TERMINATED);
    appMgrServiceInner->UpdateAbilityState(token2, AbilityState::ABILITY_STATE_TERMINATED);

    abilityRecord2->SetState(AbilityState::ABILITY_STATE_CONNECTED);
    appMgrServiceInner->UpdateAbilityState(token2, AbilityState::ABILITY_STATE_CONNECTED);

    abilityRecord2->SetState(AbilityState::ABILITY_STATE_DISCONNECTED);
    appMgrServiceInner->UpdateAbilityState(token2, AbilityState::ABILITY_STATE_DISCONNECTED);

    abilityRecord2->SetState(AbilityState::ABILITY_STATE_END);
    appMgrServiceInner->UpdateAbilityState(token2, AbilityState::ABILITY_STATE_END);

    abilityRecord2->SetState(AbilityState::ABILITY_STATE_BACKGROUND);
    appMgrServiceInner->UpdateAbilityState(token2, AbilityState::ABILITY_STATE_BACKGROUND);

    TAG_LOGI(AAFwkTag::TEST, "UpdateAbilityState_001 end");
}

/**
 * @tc.name: UpdateExtensionState_001
 * @tc.desc: update extension state.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, UpdateExtensionState_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "UpdateExtensionState_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->UpdateExtensionState(nullptr, ExtensionState::EXTENSION_STATE_CREATE);

    OHOS::sptr<IRemoteObject> token = sptr<IRemoteObject>(new (std::nothrow) MockAbilityToken());
    appMgrServiceInner->UpdateExtensionState(token, ExtensionState::EXTENSION_STATE_CREATE);

    BundleInfo bundleInfo;
    HapModuleInfo hapModuleInfo;
    std::shared_ptr<AAFwk::Want> want;
    std::string processName = "test_processName";
    std::shared_ptr<AppRunningRecord> appRecord = appMgrServiceInner->CreateAppRunningRecord(token, nullptr,
        applicationInfo_, abilityInfo_, processName, bundleInfo, hapModuleInfo, want, 0);
    EXPECT_NE(appRecord, nullptr);
    appMgrServiceInner->UpdateExtensionState(token, ExtensionState::EXTENSION_STATE_CREATE);

    TAG_LOGI(AAFwkTag::TEST, "UpdateExtensionState_001 end");
}

/**
 * @tc.name: OpenAppSpawnConnection_001
 * @tc.desc: open app spawn connection.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, OpenAppSpawnConnection_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "OpenAppSpawnConnection_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->remoteClientManager_->SetSpawnClient(nullptr);
    auto errorCode = appMgrServiceInner->OpenAppSpawnConnection();
    EXPECT_EQ(errorCode, ERR_APPEXECFWK_BAD_APPSPAWN_CLIENT);

    appMgrServiceInner->remoteClientManager_ = nullptr;
    auto errorCode1 = appMgrServiceInner->OpenAppSpawnConnection();
    EXPECT_EQ(errorCode1, ERR_INVALID_VALUE);

    TAG_LOGI(AAFwkTag::TEST, "OpenAppSpawnConnection_001 end");
}

/**
 * @tc.name: CloseAppSpawnConnection_001
 * @tc.desc: close app spawn connection.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, CloseAppSpawnConnection_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "CloseAppSpawnConnection_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->CloseAppSpawnConnection();

    appMgrServiceInner->remoteClientManager_ = nullptr;
    appMgrServiceInner->CloseAppSpawnConnection();

    TAG_LOGI(AAFwkTag::TEST, "CloseAppSpawnConnection_001 end");
}

/**
 * @tc.name: QueryAppSpawnConnectionState_001
 * @tc.desc: query app spawn connection.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, QueryAppSpawnConnectionState_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "QueryAppSpawnConnectionState_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    auto connectionState = appMgrServiceInner->QueryAppSpawnConnectionState();
    EXPECT_EQ(connectionState, SpawnConnectionState::STATE_NOT_CONNECT);

    appMgrServiceInner->remoteClientManager_->SetSpawnClient(nullptr);
    connectionState = appMgrServiceInner->QueryAppSpawnConnectionState();
    EXPECT_EQ(connectionState, SpawnConnectionState::STATE_NOT_CONNECT);


    appMgrServiceInner->remoteClientManager_ = nullptr;
    connectionState = appMgrServiceInner->QueryAppSpawnConnectionState();
    EXPECT_EQ(connectionState, SpawnConnectionState::STATE_NOT_CONNECT);

    TAG_LOGI(AAFwkTag::TEST, "QueryAppSpawnConnectionState_001 end");
}

/**
 * @tc.name: SetAppSpawnClient_001
 * @tc.desc: set app spawn client.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, SetAppSpawnClient_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "SetAppSpawnClient_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    std::shared_ptr<AppSpawnClient> spawnClient;
    appMgrServiceInner->SetAppSpawnClient(spawnClient);

    appMgrServiceInner->remoteClientManager_ = nullptr;
    appMgrServiceInner->SetAppSpawnClient(spawnClient);

    TAG_LOGI(AAFwkTag::TEST, "SetAppSpawnClient_001 end");
}

/**
 * @tc.name: SetBundleManager_001
 * @tc.desc: set bundle manager.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, SetBundleManager_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "SetBundleManager_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    std::shared_ptr<BundleMgrHelper> bundleManager;
    appMgrServiceInner->SetBundleManagerHelper(bundleManager);

    appMgrServiceInner->remoteClientManager_ = nullptr;
    appMgrServiceInner->SetBundleManagerHelper(bundleManager);

    TAG_LOGI(AAFwkTag::TEST, "SetBundleManager_001 end");
}

/**
 * @tc.name: RegisterAppStateCallback_001
 * @tc.desc: register app state call back.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, RegisterAppStateCallback_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "RegisterAppStateCallback_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->RegisterAppStateCallback(nullptr);

    sptr<IAppStateCallback> callback;
    appMgrServiceInner->RegisterAppStateCallback(callback);

    TAG_LOGI(AAFwkTag::TEST, "RegisterAppStateCallback_001 end");
}

/**
 * @tc.name: AbilityBehaviorAnalysis_001
 * @tc.desc: ability behavior analysis.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, AbilityBehaviorAnalysis_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityBehaviorAnalysis_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->AbilityBehaviorAnalysis(nullptr, nullptr, 0, 0, 0);

    OHOS::sptr<IRemoteObject> token = sptr<IRemoteObject>(new (std::nothrow) MockAbilityToken());
    appMgrServiceInner->AbilityBehaviorAnalysis(token, nullptr, 0, 0, 0);

    BundleInfo bundleInfo;
    HapModuleInfo hapModuleInfo;
    std::shared_ptr<AAFwk::Want> want;
    std::string processName = "test_processName";
    std::shared_ptr<AppRunningRecord> appRecord = appMgrServiceInner->CreateAppRunningRecord(token, nullptr,
        applicationInfo_, abilityInfo_, processName, bundleInfo, hapModuleInfo, want, 0);
    EXPECT_NE(appRecord, nullptr);
    appMgrServiceInner->AbilityBehaviorAnalysis(token, nullptr, 0, 0, 0);

    OHOS::sptr<IRemoteObject> preToken = sptr<IRemoteObject>(new (std::nothrow) MockAbilityToken());
    appMgrServiceInner->AbilityBehaviorAnalysis(token, preToken, 0, 0, 0);

    TAG_LOGI(AAFwkTag::TEST, "AbilityBehaviorAnalysis_001 end");
}

/**
 * @tc.name: KillProcessByAbilityToken_001
 * @tc.desc: kill process by ability token.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, KillProcessByAbilityToken_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "KillProcessByAbilityToken_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->KillProcessByAbilityToken(nullptr);

    OHOS::sptr<IRemoteObject> token = sptr<IRemoteObject>(new (std::nothrow) MockAbilityToken());
    appMgrServiceInner->KillProcessByAbilityToken(token);

    BundleInfo bundleInfo;
    HapModuleInfo hapModuleInfo;
    std::shared_ptr<AAFwk::Want> want;
    std::string processName = "test_processName";
    std::shared_ptr<AppRunningRecord> appRecord = appMgrServiceInner->CreateAppRunningRecord(token, nullptr,
        applicationInfo_, abilityInfo_, processName, bundleInfo, hapModuleInfo, want, 0);
    EXPECT_NE(appRecord, nullptr);
    appMgrServiceInner->KillProcessByAbilityToken(token);

    appRecord->SetKeepAliveEnableState(true);
    appRecord->SetEmptyKeepAliveAppState(true);
    appMgrServiceInner->KillProcessByAbilityToken(token);

    TAG_LOGI(AAFwkTag::TEST, "KillProcessByAbilityToken_001 end");
}

/**
 * @tc.name: KillProcessesByUserId_001
 * @tc.desc: kill process by user id.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, KillProcessesByUserId_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "KillProcessesByUserId_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->KillProcessesByUserId(0);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->KillProcessesByUserId(0);

    TAG_LOGI(AAFwkTag::TEST, "KillProcessesByUserId_001 end");
}

/**
 * @tc.name: StartAbility_001
 * @tc.desc: start ability.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, StartAbility_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "StartAbility_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    HapModuleInfo hapModuleInfo;
    std::shared_ptr<AAFwk::Want> want;
    std::shared_ptr<AppRunningRecord> appRecord;
    appMgrServiceInner->StartAbility(nullptr, nullptr, abilityInfo_, nullptr, hapModuleInfo, nullptr, 0);
    appMgrServiceInner->StartAbility(nullptr, nullptr, abilityInfo_, appRecord, hapModuleInfo, nullptr, 0);
    appMgrServiceInner->StartAbility(nullptr, nullptr, abilityInfo_, appRecord, hapModuleInfo, want, 0);

    OHOS::sptr<IRemoteObject> token = sptr<IRemoteObject>(new (std::nothrow) MockAbilityToken());
    OHOS::sptr<IRemoteObject> preToken = sptr<IRemoteObject>(new (std::nothrow) MockAbilityToken());
    appMgrServiceInner->StartAbility(token, nullptr, abilityInfo_, appRecord, hapModuleInfo, want, 0);
    appMgrServiceInner->StartAbility(nullptr, preToken, abilityInfo_, appRecord, hapModuleInfo, want, 0);
    appMgrServiceInner->StartAbility(token, preToken, abilityInfo_, appRecord, hapModuleInfo, want, 0);

    BundleInfo bundleInfo;
    std::string processName = "test_processName";
    appRecord = appMgrServiceInner->CreateAppRunningRecord(token, nullptr,
        applicationInfo_, abilityInfo_, processName, bundleInfo, hapModuleInfo, want, 0);
    EXPECT_NE(appRecord, nullptr);
    appMgrServiceInner->StartAbility(token, nullptr, abilityInfo_, appRecord, hapModuleInfo, want, 0);
    appMgrServiceInner->StartAbility(token, preToken, abilityInfo_, appRecord, hapModuleInfo, want, 0);

    abilityInfo_->applicationInfo.name = "hiservcie";
    abilityInfo_->applicationInfo.bundleName = "com.ix.hiservcie";
    appMgrServiceInner->StartAbility(token, preToken, abilityInfo_, appRecord, hapModuleInfo, want, 0);

    TAG_LOGI(AAFwkTag::TEST, "StartAbility_001 end");
}

/**
 * @tc.name: GetAppRunningRecordByAbilityToken_001
 * @tc.desc: get app running record by ability token.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, GetAppRunningRecordByAbilityToken_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "GetAppRunningRecordByAbilityToken_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    OHOS::sptr<IRemoteObject> token = sptr<IRemoteObject>(new (std::nothrow) MockAbilityToken());
    appMgrServiceInner->GetAppRunningRecordByAbilityToken(token);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->GetAppRunningRecordByAbilityToken(token);

    TAG_LOGI(AAFwkTag::TEST, "GetAppRunningRecordByAbilityToken_001 end");
}

/**
 * @tc.name: AbilityTerminated_001
 * @tc.desc: ability terminated.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, AbilityTerminated_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityTerminated_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->AbilityTerminated(nullptr);

    OHOS::sptr<IRemoteObject> token = sptr<IRemoteObject>(new (std::nothrow) MockAbilityToken());
    appMgrServiceInner->AbilityTerminated(token);

    BundleInfo bundleInfo;
    HapModuleInfo hapModuleInfo;
    std::shared_ptr<AAFwk::Want> want;
    std::string processName = "test_processName";
    std::shared_ptr<AppRunningRecord> appRecord = appMgrServiceInner->CreateAppRunningRecord(token, nullptr,
        applicationInfo_, abilityInfo_, processName, bundleInfo, hapModuleInfo, want, 0);
    EXPECT_NE(appRecord, nullptr);
    appMgrServiceInner->AbilityTerminated(token);

    TAG_LOGI(AAFwkTag::TEST, "AbilityTerminated_001 end");
}

/**
 * @tc.name: GetAppRunningRecordByAppRecordId_001
 * @tc.desc: get app running record by app record id.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, GetAppRunningRecordByAppRecordId_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "GetAppRunningRecordByAppRecordId_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->GetAppRunningRecordByAppRecordId(0);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->GetAppRunningRecordByAppRecordId(0);

    TAG_LOGI(AAFwkTag::TEST, "GetAppRunningRecordByAppRecordId_001 end");
}

/**
 * @tc.name: OnAppStateChanged_001
 * @tc.desc: on app state changed.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, OnAppStateChanged_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "OnAppStateChanged_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->OnAppStateChanged(nullptr, ApplicationState::APP_STATE_CREATE, true, false);
    appMgrServiceInner->OnAppStateChanged(nullptr, ApplicationState::APP_STATE_CREATE, false, false);

    BundleInfo bundleInfo;
    std::string processName = "test_processName";
    std::shared_ptr<AppRunningRecord> appRecord =
        appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, bundleInfo);
    EXPECT_NE(appRecord, nullptr);
    appMgrServiceInner->OnAppStateChanged(appRecord, ApplicationState::APP_STATE_CREATE, true, false);

    sptr<MockAppStateCallback> mockCallback(new MockAppStateCallback());
    EXPECT_CALL(*mockCallback, OnAppStateChanged(_)).Times(2);
    sptr<IAppStateCallback> callback1 = iface_cast<IAppStateCallback>(mockCallback);
    appMgrServiceInner->appStateCallbacks_.push_back(callback1);
    appMgrServiceInner->OnAppStateChanged(appRecord, ApplicationState::APP_STATE_CREATE, true, false);

    sptr<IAppStateCallback> callback;
    appMgrServiceInner->appStateCallbacks_.push_back(callback);
    appMgrServiceInner->OnAppStateChanged(appRecord, ApplicationState::APP_STATE_CREATE, true, false);

    TAG_LOGI(AAFwkTag::TEST, "OnAppStateChanged_001 end");
}

/**
 * @tc.name: OnAbilityStateChanged_001
 * @tc.desc: on ability state changed.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, OnAbilityStateChanged_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "OnAbilityStateChanged_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->OnAbilityStateChanged(nullptr, AbilityState::ABILITY_STATE_CREATE);

    sptr<IRemoteObject> token = new MockAbilityToken();
    std::shared_ptr<AbilityRunningRecord> abilityRunningRecord =
        std::make_shared<AbilityRunningRecord>(abilityInfo_, token, 0);
    appMgrServiceInner->OnAbilityStateChanged(abilityRunningRecord, AbilityState::ABILITY_STATE_CREATE);

    sptr<MockAppStateCallback> mockCallback(new MockAppStateCallback());
    EXPECT_CALL(*mockCallback, OnAbilityRequestDone(_, _)).Times(2);
    sptr<IAppStateCallback> callback1 = iface_cast<IAppStateCallback>(mockCallback);
    appMgrServiceInner->appStateCallbacks_.push_back(callback1);
    appMgrServiceInner->OnAbilityStateChanged(abilityRunningRecord, AbilityState::ABILITY_STATE_CREATE);

    sptr<IAppStateCallback> callback;
    appMgrServiceInner->appStateCallbacks_.push_back(callback);
    appMgrServiceInner->OnAbilityStateChanged(abilityRunningRecord, AbilityState::ABILITY_STATE_CREATE);

    TAG_LOGI(AAFwkTag::TEST, "OnAbilityStateChanged_001 end");
}

/**
 * @tc.name: StartProcess_001
 * @tc.desc: start process.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, StartProcess_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "StartProcess_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    BundleInfo bundleInfo;
    std::string appName = "test_appName";
    std::string processName = "test_processName";
    std::string bundleName = "test_bundleName";
    sptr<IRemoteObject> token = new MockAbilityToken();
    std::shared_ptr<AppRunningRecord> appRecord =
        appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, bundleInfo);
    EXPECT_NE(appRecord, nullptr);
    appMgrServiceInner->StartProcess(appName, processName, 0, nullptr, 0, bundleInfo, bundleName, 0);
    appMgrServiceInner->StartProcess(appName, processName, 0, appRecord, 0, bundleInfo, bundleName, 0);

    TAG_LOGI(AAFwkTag::TEST, "StartProcess_001 end");
}

/**
 * @tc.name: RemoveAppFromRecentList_001
 * @tc.desc: remove app from recent list.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, RemoveAppFromRecentList_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "RemoveAppFromRecentList_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    std::string appName = "test_appName";
    std::string processName = "test_processName";
    appMgrServiceInner->RemoveAppFromRecentList(appName, processName);

    appMgrServiceInner->AddAppToRecentList(appName, processName, 0, 0);
    appMgrServiceInner->RemoveAppFromRecentList(appName, processName);

    appMgrServiceInner->ClearRecentAppList();
    BundleInfo bundleInfo;
    std::string appName1 = "hiservcie";
    std::string processName1 = "hiservcie_processName";
    std::shared_ptr<AppRunningRecord> appRecord =
        appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName1, bundleInfo);

    pid_t pid = 123;
    appMgrServiceInner->AddAppToRecentList(appName1, processName1, pid, 0);
    appRecord->SetKeepAliveEnableState(true);
    appRecord->SetEmptyKeepAliveAppState(true);
    appMgrServiceInner->RemoveAppFromRecentList(appName1, processName1);
    appRecord->SetKeepAliveEnableState(false);
    appRecord->SetEmptyKeepAliveAppState(false);
    appMgrServiceInner->RemoveAppFromRecentList(appName1, processName1);

    TAG_LOGI(AAFwkTag::TEST, "RemoveAppFromRecentList_001 end");
}

/**
 * @tc.name: ClearRecentAppList_001
 * @tc.desc: clear recent list.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, ClearRecentAppList_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "ClearRecentAppList_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->ClearRecentAppList();
    std::list<const std::shared_ptr<AppTaskInfo>> list = appMgrServiceInner->GetRecentAppList();
    EXPECT_EQ(list.size(), 0);

    TAG_LOGI(AAFwkTag::TEST, "ClearRecentAppList_001 end");
}

/**
 * @tc.name: OnRemoteDied_001
 * @tc.desc: on remote died.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, OnRemoteDied_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "OnRemoteDied_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    sptr<IRemoteObject> remoteObject;
    appMgrServiceInner->OnRemoteDied(remoteObject, true);
    appMgrServiceInner->OnRemoteDied(remoteObject, false);

    TAG_LOGI(AAFwkTag::TEST, "OnRemoteDied_001 end");
}

/**
 * @tc.name: ClearAppRunningData_001
 * @tc.desc: clear app running data.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, ClearAppRunningData_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "ClearAppRunningData_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->ClearAppRunningData(nullptr, true);
    TAG_LOGI(AAFwkTag::TEST, "ClearAppRunningData_001 end");
}

/**
 * @tc.name: ClearAppRunningData_002
 * @tc.desc: clear app running data.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, ClearAppRunningData_002, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "ClearAppRunningData_002 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    BundleInfo info;
    std::string processName = "test_processName";
    std::shared_ptr<AppRunningRecord> appRecord =
        appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, info);
    appMgrServiceInner->ClearAppRunningData(appRecord, true);
    TAG_LOGI(AAFwkTag::TEST, "ClearAppRunningData_002 end");
}

/**
 * @tc.name: ClearAppRunningData_003
 * @tc.desc: clear app running data.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, ClearAppRunningData_003, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "ClearAppRunningData_003 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    BundleInfo info;
    std::string processName = "test_processName";
    std::shared_ptr<AppRunningRecord> appRecord =
        appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, info);
    appMgrServiceInner->ClearAppRunningData(appRecord, false);
    TAG_LOGI(AAFwkTag::TEST, "ClearAppRunningData_003 end");
}

/**
 * @tc.name: ClearAppRunningData_004
 * @tc.desc: clear app running data.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, ClearAppRunningData_004, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "ClearAppRunningData_004 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->ClearAppRunningData(nullptr, false);
    TAG_LOGI(AAFwkTag::TEST, "ClearAppRunningData_004 end");
}

/**
 * @tc.name: HandleTimeOut_001
 * @tc.desc: handle time out.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, HandleTimeOut_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "HandleTimeOut_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    AAFwk::EventWrap innerEvent(0);
    appMgrServiceInner->HandleTimeOut(innerEvent);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->HandleTimeOut(innerEvent);

    TAG_LOGI(AAFwkTag::TEST, "HandleTimeOut_001 end");
}

/**
 * @tc.name: HandleAbilityAttachTimeOut_001
 * @tc.desc: handle ability attach time out.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, HandleAbilityAttachTimeOut_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "HandleAbilityAttachTimeOut_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->HandleAbilityAttachTimeOut(nullptr);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->HandleAbilityAttachTimeOut(nullptr);

    TAG_LOGI(AAFwkTag::TEST, "HandleAbilityAttachTimeOut_001 end");
}

/**
 * @tc.name: PrepareTerminate_001
 * @tc.desc: prepare terminate.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, PrepareTerminate_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "PrepareTerminate_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->PrepareTerminate(nullptr);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->PrepareTerminate(nullptr);

    TAG_LOGI(AAFwkTag::TEST, "PrepareTerminate_001 end");
}

/**
 * @tc.name: HandleTerminateApplicationTimeOut_001
 * @tc.desc: handle terminate application time out.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, HandleTerminateApplicationTimeOut_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "HandleTerminateApplicationTimeOut_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->HandleTerminateApplicationTimeOut(0);

    BundleInfo bundleInfo;
    std::string appName = "test_appName";
    std::string processName = "test_processName";
    std::string bundleName = "test_bundleName";
    sptr<IRemoteObject> token = new MockAbilityToken();
    std::shared_ptr<AppRunningRecord> appRecord =
        appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, bundleInfo);
    EXPECT_NE(appRecord, nullptr);
    appRecord->eventId_ = 0;
    appMgrServiceInner->HandleTerminateApplicationTimeOut(0);

    pid_t pid = 1;
    appRecord->GetPriorityObject()->SetPid(pid);
    appMgrServiceInner->HandleTerminateApplicationTimeOut(0);

    appMgrServiceInner->taskHandler_ = nullptr;
    appMgrServiceInner->HandleTerminateApplicationTimeOut(0);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->HandleTerminateApplicationTimeOut(0);

    TAG_LOGI(AAFwkTag::TEST, "HandleTerminateApplicationTimeOut_001 end");
}

/**
 * @tc.name: HandleAddAbilityStageTimeOut_001
 * @tc.desc: handle add ability stage time out.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, HandleAddAbilityStageTimeOut_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "HandleAddAbilityStageTimeOut_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->HandleAddAbilityStageTimeOut(0);

    BundleInfo bundleInfo;
    std::string appName = "test_appName";
    std::string processName = "test_processName";
    std::string bundleName = "test_bundleName";
    sptr<IRemoteObject> token = new MockAbilityToken();
    std::shared_ptr<AppRunningRecord> appRecord =
        appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, bundleInfo);
    EXPECT_NE(appRecord, nullptr);
    appRecord->eventId_ = 0;
    appMgrServiceInner->HandleAddAbilityStageTimeOut(0);

    appRecord->specifiedRequestId_ = 1;
    appMgrServiceInner->HandleAddAbilityStageTimeOut(0);

    sptr<IStartSpecifiedAbilityResponse> response;
    appMgrServiceInner->startSpecifiedAbilityResponse_ = response;
    appMgrServiceInner->HandleAddAbilityStageTimeOut(0);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->HandleAddAbilityStageTimeOut(0);

    TAG_LOGI(AAFwkTag::TEST, "HandleAddAbilityStageTimeOut_001 end");
}

/**
 * @tc.name: GetRunningProcessInfoByToken_001
 * @tc.desc: get running process info by token.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, GetRunningProcessInfoByToken_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "GetRunningProcessInfoByToken_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    AppExecFwk::RunningProcessInfo info;
    appMgrServiceInner->GetRunningProcessInfoByToken(nullptr, info);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->GetRunningProcessInfoByToken(nullptr, info);

    TAG_LOGI(AAFwkTag::TEST, "GetRunningProcessInfoByToken_001 end");
}

/**
 * @tc.name: GetRunningProcessInfoByPid_001
 * @tc.desc: get running process info by pid.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, GetRunningProcessInfoByPid_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "GetRunningProcessInfoByPid_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    AppExecFwk::RunningProcessInfo info;
    appMgrServiceInner->GetRunningProcessInfoByPid(0, info);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->GetRunningProcessInfoByPid(0, info);

    TAG_LOGI(AAFwkTag::TEST, "GetRunningProcessInfoByPid_001 end");
}

/**
 * @tc.name: CheckGetRunningInfoPermission_001
 * @tc.desc: check get running info permission.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, CheckGetRunningInfoPermission_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckGetRunningInfoPermission_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->CheckGetRunningInfoPermission();

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->CheckGetRunningInfoPermission();

    TAG_LOGI(AAFwkTag::TEST, "CheckGetRunningInfoPermission_001 end");
}

/**
 * @tc.name: IsMemorySizeSufficent_001
 * @tc.desc: check get running info permission.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, IsMemorySizeSufficent_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "IsMemorySizeSufficent start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->IsMemorySizeSufficent();

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->IsMemorySizeSufficent();

    TAG_LOGI(AAFwkTag::TEST, "IsMemorySizeSufficent_001 end");
}

/**
 * @tc.name: LoadResidentProcess_001
 * @tc.desc: load resident process.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, LoadResidentProcess_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "LoadResidentProcess_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    std::vector<BundleInfo> infos;
    appMgrServiceInner->LoadResidentProcess(infos);

    TAG_LOGI(AAFwkTag::TEST, "LoadResidentProcess_001 end");
}

/**
 * @tc.name: StartResidentProcess_001
 * @tc.desc: start resident process.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, StartResidentProcess_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "StartResidentProcess_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    std::vector<BundleInfo> infos;
    appMgrServiceInner->StartResidentProcess(infos, 0, true);

    BundleInfo info;
    infos.push_back(info);

    BundleInfo info1;
    info1.applicationInfo.process = "";
    infos.push_back(info1);

    BundleInfo info2;
    info2.applicationInfo.process = "test_process";
    infos.push_back(info2);
    appMgrServiceInner->StartResidentProcess(infos, 0, true);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->StartResidentProcess(infos, 0, true);

    TAG_LOGI(AAFwkTag::TEST, "StartResidentProcess_001 end");
}

/**
 * @tc.name: StartEmptyResidentProcess_001
 * @tc.desc: start empty resident process.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, StartEmptyResidentProcess_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "StartEmptyResidentProcess_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    BundleInfo info;
    info.applicationInfo = *applicationInfo_;
    std::string processName = "test_process";
    appMgrServiceInner->StartEmptyResidentProcess(info, processName, 0, true);

    appMgrServiceInner->StartEmptyResidentProcess(info, processName, 1, true);

    appMgrServiceInner->StartEmptyResidentProcess(info, "", 0, true);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->StartEmptyResidentProcess(info, processName, 0, true);

    appMgrServiceInner->remoteClientManager_ = nullptr;
    appMgrServiceInner->StartEmptyResidentProcess(info, processName, 0, true);

    TAG_LOGI(AAFwkTag::TEST, "StartEmptyResidentProcess_001 end");
}

/**
 * @tc.name: CheckRemoteClient_001
 * @tc.desc: check remote client.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, CheckRemoteClient_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckRemoteClient_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->CheckRemoteClient();

    appMgrServiceInner->remoteClientManager_->SetSpawnClient(nullptr);
    appMgrServiceInner->CheckRemoteClient();

    appMgrServiceInner->remoteClientManager_->SetBundleManagerHelper(nullptr);
    appMgrServiceInner->CheckRemoteClient();

    appMgrServiceInner->remoteClientManager_ = nullptr;
    appMgrServiceInner->CheckRemoteClient();

    TAG_LOGI(AAFwkTag::TEST, "CheckRemoteClient_001 end");
}

/**
 * @tc.name: RestartResidentProcess_001
 * @tc.desc: restart resident process.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, RestartResidentProcess_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "RestartResidentProcess_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->RestartResidentProcess(nullptr);

    std::shared_ptr<AppRunningRecord> appRecord;
    appMgrServiceInner->RestartResidentProcess(appRecord);

    BundleInfo bundleInfo;
    std::string processName = "test_processName";
    appRecord =
        appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, bundleInfo);
    EXPECT_NE(appRecord, nullptr);
    appRecord->mainBundleName_ = "com.ohos.settings";
    appMgrServiceInner->RestartResidentProcess(appRecord);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->RestartResidentProcess(appRecord);

    appMgrServiceInner->remoteClientManager_ = nullptr;
    appMgrServiceInner->RestartResidentProcess(appRecord);

    TAG_LOGI(AAFwkTag::TEST, "RestartResidentProcess_001 end");
}

/**
 * @tc.name: NotifyAppStatusByCallerUid_001
 * @tc.desc: notify app status by caller uid.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, NotifyAppStatusByCallerUid_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "NotifyAppStatusByCallerUid_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    std::string bundleName = "test_bundle_name";
    std::string eventData = "test_event_data";
    appMgrServiceInner->NotifyAppStatusByCallerUid(bundleName, 0, 0, eventData);

    TAG_LOGI(AAFwkTag::TEST, "NotifyAppStatusByCallerUid_001 end");
}

/**
 * @tc.name: RegisterApplicationStateObserver_001
 * @tc.desc: register application state observer.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, RegisterApplicationStateObserver_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "RegisterApplicationStateObserver_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    sptr<IApplicationStateObserver> observer;
    std::vector<std::string> bundleNameList;
    appMgrServiceInner->RegisterApplicationStateObserver(observer, bundleNameList);

    TAG_LOGI(AAFwkTag::TEST, "RegisterApplicationStateObserver_001 end");
}

/**
 * @tc.name: UnregisterApplicationStateObserver_001
 * @tc.desc: unregister application state observer.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, UnregisterApplicationStateObserver_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "UnregisterApplicationStateObserver_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    sptr<IApplicationStateObserver> observer;
    appMgrServiceInner->UnregisterApplicationStateObserver(observer);

    TAG_LOGI(AAFwkTag::TEST, "UnregisterApplicationStateObserver_001 end");
}

/**
 * @tc.name: GetForegroundApplications_001
 * @tc.desc: get foreground applications.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, GetForegroundApplications_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "GetForegroundApplications_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    std::vector<AppStateData> list;
    appMgrServiceInner->GetForegroundApplications(list);

    TAG_LOGI(AAFwkTag::TEST, "GetForegroundApplications_001 end");
}

/**
 * @tc.name: StartUserTestProcess_001
 * @tc.desc: start user test process.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, StartUserTestProcess_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "StartUserTestProcess_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    AAFwk::Want want;
    sptr<IRemoteObject> observer;
    BundleInfo bundleInfo;
    appMgrServiceInner->StartUserTestProcess(want, nullptr, bundleInfo, 0);

    appMgrServiceInner->StartUserTestProcess(want, observer, bundleInfo, 0);

    std::string bundle_name = "test_bundle_name";
    want.SetParam("-b", bundle_name);
    appMgrServiceInner->StartUserTestProcess(want, observer, bundleInfo, 0);

    std::string moduleName = "test_module_name";
    want.SetParam("-m", moduleName);
    HapModuleInfo hapModuleInfo;
    hapModuleInfo.moduleName = moduleName;
    bundleInfo.hapModuleInfos.push_back(hapModuleInfo);
    appMgrServiceInner->StartUserTestProcess(want, observer, bundleInfo, 0);

    appMgrServiceInner->remoteClientManager_ = nullptr;
    appMgrServiceInner->StartUserTestProcess(want, observer, bundleInfo, 0);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->StartUserTestProcess(want, observer, bundleInfo, 0);

    TAG_LOGI(AAFwkTag::TEST, "StartUserTestProcess_001 end");
}

/**
 * @tc.name: GetHapModuleInfoForTestRunner_001
 * @tc.desc: get hap module info for test runner.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, GetHapModuleInfoForTestRunner_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "GetHapModuleInfoForTestRunner_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    AAFwk::Want want;
    sptr<IRemoteObject> observer;
    BundleInfo bundleInfo;
    HapModuleInfo hapModuleInfo;
    appMgrServiceInner->GetHapModuleInfoForTestRunner(want, nullptr, bundleInfo, hapModuleInfo);

    appMgrServiceInner->GetHapModuleInfoForTestRunner(want, observer, bundleInfo, hapModuleInfo);

    hapModuleInfo.moduleName = "test_module_name";
    bundleInfo.hapModuleInfos.push_back(hapModuleInfo);
    appMgrServiceInner->GetHapModuleInfoForTestRunner(want, observer, bundleInfo, hapModuleInfo);

    bundleInfo.hapModuleInfos.back().isModuleJson = true;
    appMgrServiceInner->GetHapModuleInfoForTestRunner(want, observer, bundleInfo, hapModuleInfo);

    std::string testmoduleName = "test_XXX";
    want.SetParam("-m", testmoduleName);
    appMgrServiceInner->GetHapModuleInfoForTestRunner(want, observer, bundleInfo, hapModuleInfo);

    std::string moduleName = "test_module_name";
    want.SetParam("-m", moduleName);
    appMgrServiceInner->GetHapModuleInfoForTestRunner(want, observer, bundleInfo, hapModuleInfo);

    TAG_LOGI(AAFwkTag::TEST, "GetHapModuleInfoForTestRunner_001 end");
}

/**
 * @tc.name: UserTestAbnormalFinish_001
 * @tc.desc: user test abnormal finish.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, UserTestAbnormalFinish_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "UserTestAbnormalFinish_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    sptr<IRemoteObject> observer;
    std::string msg = "testmsg";
    appMgrServiceInner->UserTestAbnormalFinish(nullptr, "");
    appMgrServiceInner->UserTestAbnormalFinish(nullptr, msg);
    appMgrServiceInner->UserTestAbnormalFinish(observer, "");
    appMgrServiceInner->UserTestAbnormalFinish(observer, msg);

    TAG_LOGI(AAFwkTag::TEST, "UserTestAbnormalFinish_001 end");
}

/**
 * @tc.name: StartEmptyProcess_001
 * @tc.desc: start empty process.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, StartEmptyProcess_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "StartEmptyProcess_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    AAFwk::Want want;
    sptr<IRemoteObject> observer;
    BundleInfo info;
    HapModuleInfo hapModuleInfo;
    std::string processName = "test_processName";
    appMgrServiceInner->StartEmptyProcess(want, nullptr, info, "", 0);
    appMgrServiceInner->StartEmptyProcess(want, observer, info, "", 0);
    appMgrServiceInner->StartEmptyProcess(want, observer, info, processName, 0);

    info.applicationInfo = *applicationInfo_;
    appMgrServiceInner->StartEmptyProcess(want, observer, info, processName, 0);

    want.SetParam("coldStart", true);
    appMgrServiceInner->StartEmptyProcess(want, observer, info, processName, 0);

    appMgrServiceInner->remoteClientManager_ = nullptr;
    appMgrServiceInner->StartEmptyProcess(want, observer, info, processName, 0);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->StartEmptyProcess(want, observer, info, processName, 0);

    TAG_LOGI(AAFwkTag::TEST, "StartEmptyProcess_001 end");
}

/**
 * @tc.name: FinishUserTest_001
 * @tc.desc: finish user test.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, FinishUserTest_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "FinishUserTest_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    pid_t pid = 0;
    appMgrServiceInner->FinishUserTest("", 0, "", pid);

    std::string msg = "testmsg";
    std::string bundleName = "test_bundle_name";
    appMgrServiceInner->FinishUserTest("", 0, bundleName, pid);
    appMgrServiceInner->FinishUserTest(msg, 0, "", pid);
    appMgrServiceInner->FinishUserTest(msg, 0, bundleName, pid);

    BundleInfo bundleInfo;
    HapModuleInfo hapModuleInfo;
    std::shared_ptr<AAFwk::Want> want;
    sptr<IRemoteObject> token = new MockAbilityToken();
    std::string processName = "test_processName";
    std::shared_ptr<AppRunningRecord> appRecord = appMgrServiceInner->CreateAppRunningRecord(token, nullptr,
        applicationInfo_, abilityInfo_, processName, bundleInfo, hapModuleInfo, want, 0);
    EXPECT_NE(appRecord, nullptr);
    pid = appRecord->GetPriorityObject()->GetPid();
    appMgrServiceInner->FinishUserTest(msg, 0, bundleName, pid);

    std::shared_ptr<UserTestRecord> record = std::make_shared<UserTestRecord>();
    appRecord->SetUserTestInfo(record);
    appMgrServiceInner->FinishUserTest(msg, 0, bundleName, pid);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->FinishUserTest(msg, 0, bundleName, pid);

    TAG_LOGI(AAFwkTag::TEST, "FinishUserTest_001 end");
}

/**
 * @tc.name: FinishUserTestLocked_001
 * @tc.desc: finish user test locked.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, FinishUserTestLocked_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "FinishUserTestLocked_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->FinishUserTestLocked("", 0, nullptr);

    std::shared_ptr<AppRunningRecord> appRecord;
    appMgrServiceInner->FinishUserTestLocked("", 0, appRecord);

    std::string msg = "testmsg";
    appMgrServiceInner->FinishUserTestLocked(msg, 0, nullptr);
    appMgrServiceInner->FinishUserTestLocked(msg, 0, appRecord);

    BundleInfo bundleInfo;
    std::string processName = "test_processName";
    appRecord =
        appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, bundleInfo);
    EXPECT_NE(appRecord, nullptr);
    std::shared_ptr<UserTestRecord> record = std::make_shared<UserTestRecord>();
    appRecord->SetUserTestInfo(record);
    appMgrServiceInner->FinishUserTestLocked(msg, 0, appRecord);

    record->isFinished = true;
    appRecord->SetUserTestInfo(record);
    appMgrServiceInner->FinishUserTestLocked(msg, 0, appRecord);

    record->observer = nullptr;
    appRecord->SetUserTestInfo(record);
    appMgrServiceInner->FinishUserTestLocked(msg, 0, appRecord);

    TAG_LOGI(AAFwkTag::TEST, "FinishUserTestLocked_001 end");
}

/**
 * @tc.name: StartSpecifiedAbility_001
 * @tc.desc: start specified ability.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, StartSpecifiedAbility_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "StartSpecifiedAbility_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    AAFwk::Want want;
    AbilityInfo abilityInfo;
    appMgrServiceInner->StartSpecifiedAbility(want, abilityInfo);

    appMgrServiceInner->StartSpecifiedAbility(want, *abilityInfo_);

    abilityInfo_->applicationInfo = *applicationInfo_;
    appMgrServiceInner->StartSpecifiedAbility(want, *abilityInfo_);

    appMgrServiceInner->remoteClientManager_->SetBundleManagerHelper(nullptr);
    appMgrServiceInner->StartSpecifiedAbility(want, *abilityInfo_);

    appMgrServiceInner->remoteClientManager_ = nullptr;
    appMgrServiceInner->StartSpecifiedAbility(want, *abilityInfo_);

    TAG_LOGI(AAFwkTag::TEST, "StartSpecifiedAbility_001 end");
}

/**
 * @tc.name: RegisterStartSpecifiedAbilityResponse_001
 * @tc.desc: register start specified ability response.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, RegisterStartSpecifiedAbilityResponse_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "RegisterStartSpecifiedAbilityResponse_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->RegisterStartSpecifiedAbilityResponse(nullptr);

    sptr<IStartSpecifiedAbilityResponse> response;
    appMgrServiceInner->RegisterStartSpecifiedAbilityResponse(response);

    TAG_LOGI(AAFwkTag::TEST, "RegisterStartSpecifiedAbilityResponse_001 end");
}

/**
 * @tc.name: ScheduleAcceptWantDone_001
 * @tc.desc: schedule accept want done.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, ScheduleAcceptWantDone_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "ScheduleAcceptWantDone_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    AAFwk::Want want;
    std::string flag = "test_flag";
    appMgrServiceInner->ScheduleAcceptWantDone(0, want, flag);

    BundleInfo bundleInfo;
    std::string processName = "test_processName";
    std::shared_ptr<AppRunningRecord> appRecord =
        appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, bundleInfo);
    appMgrServiceInner->ScheduleAcceptWantDone(appRecord->GetRecordId(), want, flag);

    sptr<IStartSpecifiedAbilityResponse> response;
    appMgrServiceInner->RegisterStartSpecifiedAbilityResponse(response);
    appMgrServiceInner->ScheduleAcceptWantDone(appRecord->GetRecordId(), want, flag);

    TAG_LOGI(AAFwkTag::TEST, "ScheduleAcceptWantDone_001 end");
}

/**
 * @tc.name: HandleStartSpecifiedAbilityTimeOut_001
 * @tc.desc: handle start specified ability time out.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, HandleStartSpecifiedAbilityTimeOut_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "HandleStartSpecifiedAbilityTimeOut_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->HandleStartSpecifiedAbilityTimeOut(0);

    BundleInfo bundleInfo;
    std::string appName = "test_appName";
    std::string processName = "test_processName";
    std::string bundleName = "test_bundleName";
    sptr<IRemoteObject> token = new MockAbilityToken();
    std::shared_ptr<AppRunningRecord> appRecord =
        appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, bundleInfo);
    EXPECT_NE(appRecord, nullptr);
    appRecord->eventId_ = 0;
    appMgrServiceInner->HandleStartSpecifiedAbilityTimeOut(0);

    appRecord->specifiedRequestId_ = 1;
    appMgrServiceInner->HandleStartSpecifiedAbilityTimeOut(0);

    sptr<IStartSpecifiedAbilityResponse> response;
    appMgrServiceInner->startSpecifiedAbilityResponse_ = response;
    appMgrServiceInner->HandleStartSpecifiedAbilityTimeOut(0);

    appRecord->specifiedRequestId_ = -1;
    appMgrServiceInner->HandleStartSpecifiedAbilityTimeOut(0);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->HandleStartSpecifiedAbilityTimeOut(0);

    TAG_LOGI(AAFwkTag::TEST, "HandleStartSpecifiedAbilityTimeOut_001 end");
}

/**
 * @tc.name: UpdateConfiguration_001
 * @tc.desc: update configuration.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, UpdateConfiguration_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "UpdateConfiguration_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    Configuration config;
    appMgrServiceInner->UpdateConfiguration(config);

    auto testLanguge = "ch-zh";
    config.AddItem(AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE, testLanguge);
    appMgrServiceInner->UpdateConfiguration(config);

    auto appRunningRecordMap = appMgrServiceInner->appRunningManager_->appRunningRecordMap_;
    for (const auto& item : appRunningRecordMap) {
        const auto& appRecord = item.second;
        if (appRecord) {
            appRecord->appLifeCycleDeal_ = nullptr;
        }
    }
    appMgrServiceInner->UpdateConfiguration(config);

    sptr<MockConfigurationObserver> observer(new (std::nothrow) MockConfigurationObserver());
    appMgrServiceInner->configurationObservers_.push_back(observer);
    sptr<IConfigurationObserver> observer1;
    appMgrServiceInner->configurationObservers_.push_back(observer1);
    appMgrServiceInner->configurationObservers_.push_back(nullptr);
    appMgrServiceInner->UpdateConfiguration(config);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->UpdateConfiguration(config);

    TAG_LOGI(AAFwkTag::TEST, "UpdateConfiguration_001 end");
}

/**
 * @tc.name: RegisterConfigurationObserver_001
 * @tc.desc: register configuration observer.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, RegisterConfigurationObserver_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "RegisterConfigurationObserver_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->configurationObservers_.clear();

    appMgrServiceInner->RegisterConfigurationObserver(nullptr);

    sptr<MockConfigurationObserver> observer(new (std::nothrow) MockConfigurationObserver());
    appMgrServiceInner->RegisterConfigurationObserver(observer);
    appMgrServiceInner->RegisterConfigurationObserver(observer);

    TAG_LOGI(AAFwkTag::TEST, "RegisterConfigurationObserver_001 end");
}

/**
 * @tc.name: UnregisterConfigurationObserver_001
 * @tc.desc: unregister configuration observer.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, UnregisterConfigurationObserver_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "UnregisterConfigurationObserver_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->configurationObservers_.clear();

    appMgrServiceInner->UnregisterConfigurationObserver(nullptr);

    sptr<MockConfigurationObserver> observer(new (std::nothrow) MockConfigurationObserver());
    appMgrServiceInner->UnregisterConfigurationObserver(observer);

    appMgrServiceInner->RegisterConfigurationObserver(observer);
    appMgrServiceInner->UnregisterConfigurationObserver(observer);

    TAG_LOGI(AAFwkTag::TEST, "UnregisterConfigurationObserver_001 end");
}

/**
 * @tc.name: InitGlobalConfiguration_001
 * @tc.desc: init global configuration.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, InitGlobalConfiguration_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "InitGlobalConfiguration_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->InitGlobalConfiguration();

    appMgrServiceInner->configuration_ = nullptr;
    appMgrServiceInner->InitGlobalConfiguration();

    TAG_LOGI(AAFwkTag::TEST, "InitGlobalConfiguration_001 end");
}

/**
 * @tc.name: KillApplicationByRecord_001
 * @tc.desc: kill application by record.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, KillApplicationByRecord_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "KillApplicationByRecord_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    std::shared_ptr<AppRunningRecord> appRecord = nullptr;
    BundleInfo bundleInfo;
    std::string processName = "test_processName";
    std::shared_ptr<AppRunningRecord> appRecord1 =
        appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, bundleInfo);
    EXPECT_NE(appRecord1, nullptr);
    appMgrServiceInner->KillApplicationByRecord(appRecord);
    appMgrServiceInner->KillApplicationByRecord(appRecord1);

    appMgrServiceInner->taskHandler_ = nullptr;
    appMgrServiceInner->KillApplicationByRecord(appRecord);
    appMgrServiceInner->KillApplicationByRecord(appRecord1);

    TAG_LOGI(AAFwkTag::TEST, "KillApplicationByRecord_001 end");
}

/**
 * @tc.name: SendHiSysEvent_001
 * @tc.desc: send hi sys event.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, SendHiSysEvent_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "SendHiSysEvent_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->SendHiSysEvent(0, 0);

    BundleInfo bundleInfo;
    std::string processName = "test_processName";
    std::shared_ptr<AppRunningRecord> appRecord =
        appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, bundleInfo);
    EXPECT_NE(appRecord, nullptr);
    appRecord->eventId_ = 0;
    appMgrServiceInner->SendHiSysEvent(0, 0);
    appMgrServiceInner->SendHiSysEvent(1, 0);
    appMgrServiceInner->SendHiSysEvent(2, 0);
    appMgrServiceInner->SendHiSysEvent(3, 0);
    appMgrServiceInner->SendHiSysEvent(4, 0);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->SendHiSysEvent(0, 0);

    TAG_LOGI(AAFwkTag::TEST, "SendHiSysEvent_001 end");
}

/**
 * @tc.name: GetAbilityRecordsByProcessID_001
 * @tc.desc: get ability records by process id.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, GetAbilityRecordsByProcessID_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "GetAbilityRecordsByProcessID_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    std::vector<sptr<IRemoteObject>> tokens;
    appMgrServiceInner->GetAbilityRecordsByProcessID(0, tokens);

    BundleInfo bundleInfo;
    std::string processName = "test_processName";
    std::shared_ptr<AppRunningRecord> appRecord =
        appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, bundleInfo);
    EXPECT_NE(appRecord, nullptr);
    int pid = appRecord->GetPriorityObject()->GetPid();
    appMgrServiceInner->GetAbilityRecordsByProcessID(pid, tokens);

    TAG_LOGI(AAFwkTag::TEST, "GetAbilityRecordsByProcessID_001 end");
}

/**
 * @tc.name: GetApplicationInfoByProcessID_001
 * @tc.desc: get applicationInfo by process id.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, GetApplicationInfoByProcessID_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "GetApplicationInfoByProcessID_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    ApplicationInfo application;
    bool debug = false;
    appMgrServiceInner->GetApplicationInfoByProcessID(0, application, debug);

    BundleInfo bundleInfo;
    std::string processName = "test_processName";
    std::shared_ptr<AppRunningRecord> appRecord =
        appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, bundleInfo);
    EXPECT_NE(appRecord, nullptr);
    int pid = appRecord->GetPriorityObject()->GetPid();
    appMgrServiceInner->GetApplicationInfoByProcessID(pid, application, debug);

    appRecord->appInfo_ = nullptr;
    appMgrServiceInner->GetApplicationInfoByProcessID(pid, application, debug);

    TAG_LOGI(AAFwkTag::TEST, "GetApplicationInfoByProcessID_001 end");
}

/**
 * @tc.name: NotifyAppMgrRecordExitReason_001
 * @tc.desc: NotifyAppMgrRecordExitReason.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, NotifyAppMgrRecordExitReason_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "NotifyAppMgrRecordExitReason_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    int32_t reason = 0;
    int32_t pid = 1;
    std::string exitMsg = "JsError";
    auto ret = appMgrServiceInner->NotifyAppMgrRecordExitReason(reason, pid, exitMsg);
    EXPECT_NE(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "NotifyAppMgrRecordExitReason_001 end");
}

/**
 * @tc.name: VerifyProcessPermission_001
 * @tc.desc: verify process permission.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, VerifyProcessPermission_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "VerifyProcessPermission_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->VerifyProcessPermission("");

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->VerifyProcessPermission("");

    TAG_LOGI(AAFwkTag::TEST, "VerifyProcessPermission_001 end");
}

/**
 * @tc.name: VerifyAPL_001
 * @tc.desc: verify APL.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, VerifyAPL_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "VerifyAPL_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->VerifyAPL();

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->VerifyAPL();

    TAG_LOGI(AAFwkTag::TEST, "VerifyAPL_001 end");
}

/**
 * @tc.name: VerifyAccountPermission_001
 * @tc.desc: verify account permission.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, VerifyAccountPermission_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "VerifyAccountPermission_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    std::string permissionName = "test_permissionName";
    appMgrServiceInner->VerifyAccountPermission(permissionName, 0);

    TAG_LOGI(AAFwkTag::TEST, "VerifyAccountPermission_001 end");
}

/**
 * @tc.name: PreStartNWebSpawnProcess_003
 * @tc.desc: prestart nwebspawn process.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, PreStartNWebSpawnProcess_003, TestSize.Level0)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    int callingPid = 1;
    appMgrServiceInner->remoteClientManager_->nwebSpawnClient_ = nullptr;
    int ret = appMgrServiceInner->PreStartNWebSpawnProcess(callingPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: StartRenderProcess_001
 * @tc.desc: start render process.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, StartRenderProcess_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "StartRenderProcess_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    pid_t hostPid = 0;
    std::string renderParam = "test_renderParam";
    pid_t renderPid = 0;
    int ret = appMgrServiceInner->StartRenderProcess(hostPid, "", 0, 0, 0, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    ret = appMgrServiceInner->StartRenderProcess(hostPid, "", 0, 0, 1, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    ret = appMgrServiceInner->StartRenderProcess(hostPid, "", 0, 1, 0, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    ret = appMgrServiceInner->StartRenderProcess(hostPid, "", 0, 1, 1, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    ret = appMgrServiceInner->StartRenderProcess(hostPid, "", 1, 0, 0, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    ret = appMgrServiceInner->StartRenderProcess(hostPid, "", 1, 0, 1, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    ret = appMgrServiceInner->StartRenderProcess(hostPid, "", 1, 1, 0, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    ret = appMgrServiceInner->StartRenderProcess(hostPid, "", 1, 1, 1, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    ret = appMgrServiceInner->StartRenderProcess(hostPid, renderParam, 0, 0, 0, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    ret = appMgrServiceInner->StartRenderProcess(hostPid, renderParam, 0, 0, 1, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    ret = appMgrServiceInner->StartRenderProcess(hostPid, renderParam, 0, 1, 0, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    ret = appMgrServiceInner->StartRenderProcess(hostPid, renderParam, 0, 1, 1, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    ret = appMgrServiceInner->StartRenderProcess(hostPid, renderParam, 1, 0, 0, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    ret = appMgrServiceInner->StartRenderProcess(hostPid, renderParam, 1, 0, 1, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    ret = appMgrServiceInner->StartRenderProcess(hostPid, renderParam, 1, 1, 0, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    ret = appMgrServiceInner->StartRenderProcess(hostPid, renderParam, 1, 1, 1, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);

    TAG_LOGI(AAFwkTag::TEST, "StartRenderProcess_001 end");
}

/**
 * @tc.name: StartRenderProcess_002
 * @tc.desc: start render process.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, StartRenderProcess_002, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "StartRenderProcess_002 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    pid_t hostPid1 = 1;
    std::string renderParam = "test_renderParam";
    pid_t renderPid = 0;
    int ret = appMgrServiceInner->StartRenderProcess(hostPid1, "", 0, 0, 0, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    ret = appMgrServiceInner->StartRenderProcess(hostPid1, "", 0, 0, 1, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    ret = appMgrServiceInner->StartRenderProcess(hostPid1, "", 0, 1, 0, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    ret = appMgrServiceInner->StartRenderProcess(hostPid1, "", 0, 1, 1, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    ret = appMgrServiceInner->StartRenderProcess(hostPid1, "", 1, 0, 0, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    ret = appMgrServiceInner->StartRenderProcess(hostPid1, "", 1, 0, 1, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    ret = appMgrServiceInner->StartRenderProcess(hostPid1, "", 1, 1, 0, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    ret = appMgrServiceInner->StartRenderProcess(hostPid1, "", 1, 1, 1, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    ret = appMgrServiceInner->StartRenderProcess(hostPid1, renderParam, 0, 0, 0, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    ret = appMgrServiceInner->StartRenderProcess(hostPid1, renderParam, 0, 0, 1, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    ret = appMgrServiceInner->StartRenderProcess(hostPid1, renderParam, 0, 1, 0, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);

    ret = appMgrServiceInner->StartRenderProcess(hostPid1, renderParam, 0, 1, 1, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);

    ret = appMgrServiceInner->StartRenderProcess(hostPid1, renderParam, 1, 0, 0, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    ret = appMgrServiceInner->StartRenderProcess(hostPid1, renderParam, 1, 0, 1, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    ret = appMgrServiceInner->StartRenderProcess(hostPid1, renderParam, 1, 1, 0, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);

    ret = appMgrServiceInner->StartRenderProcess(hostPid1, renderParam, 1, 1, 1, renderPid);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "StartRenderProcess_002 end");
}

/**
 * @tc.name: AttachRenderProcess_001
 * @tc.desc: attach render process.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, AttachRenderProcess_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "AttachRenderProcess_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    pid_t pid = 0;
    sptr<IRenderScheduler> scheduler;
    appMgrServiceInner->AttachRenderProcess(pid, scheduler);
    TAG_LOGI(AAFwkTag::TEST, "AttachRenderProcess_001 end");
}

/**
 * @tc.name: AttachRenderProcess_002
 * @tc.desc: attach render process.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, AttachRenderProcess_002, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "AttachRenderProcess_002 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    pid_t pid = 1;
    sptr<IRenderScheduler> scheduler;
    appMgrServiceInner->AttachRenderProcess(pid, scheduler);
    TAG_LOGI(AAFwkTag::TEST, "AttachRenderProcess_002 end");
}

/**
 * @tc.name: BuildStartFlags_001
 * @tc.desc: build start flags.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, BuildStartFlags_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "BuildStartFlags_001 start");

    AAFwk::Want want;
    AbilityInfo abilityInfo;
    AppspawnUtil::BuildStartFlags(want, abilityInfo);

    want.SetParam("coldStart", true);
    want.SetParam("ohos.dlp.params.index", 1);
    abilityInfo.extensionAbilityType = ExtensionAbilityType::BACKUP;
    uint32_t result = AppspawnUtil::BuildStartFlags(want, abilityInfo);
    EXPECT_EQ(result, 7);

    TAG_LOGI(AAFwkTag::TEST, "BuildStartFlags_001 end");
}

/**
 * @tc.name: RegisterFocusListener_001
 * @tc.desc: register focus listener.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, RegisterFocusListener_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "RegisterFocusListener_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->RegisterFocusListener();

    appMgrServiceInner->focusListener_ = nullptr;
    appMgrServiceInner->RegisterFocusListener();

    TAG_LOGI(AAFwkTag::TEST, "RegisterFocusListener_001 end");
}

/**
 * @tc.name: HandleFocused_001
 * @tc.desc: handle focused.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, HandleFocused_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "HandleFocused_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    sptr<Rosen::FocusChangeInfo> focusChangeInfo;
    appMgrServiceInner->HandleFocused(focusChangeInfo);

    pid_t pid = 1;
    focusChangeInfo = new Rosen::FocusChangeInfo();
    appMgrServiceInner->HandleFocused(focusChangeInfo);

    focusChangeInfo->pid_ = pid;
    appMgrServiceInner->HandleFocused(focusChangeInfo);

    BundleInfo bundleInfo;
    std::string processName = "test_processName";
    std::shared_ptr<AppRunningRecord> appRecord =
        appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, bundleInfo);
    EXPECT_NE(appRecord, nullptr);
    appRecord->GetPriorityObject()->SetPid(pid);
    appMgrServiceInner->HandleFocused(focusChangeInfo);

    TAG_LOGI(AAFwkTag::TEST, "HandleFocused_001 end");
}

/**
 * @tc.name: HandleUnfocused_001
 * @tc.desc: handle unfocused.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, HandleUnfocused_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "HandleUnfocused_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    sptr<Rosen::FocusChangeInfo> focusChangeInfo;
    appMgrServiceInner->HandleUnfocused(focusChangeInfo);

    pid_t pid = 1;
    focusChangeInfo = new Rosen::FocusChangeInfo();
    appMgrServiceInner->HandleUnfocused(focusChangeInfo);

    focusChangeInfo->pid_ = pid;
    appMgrServiceInner->HandleUnfocused(focusChangeInfo);

    BundleInfo bundleInfo;
    std::string processName = "test_processName";
    std::shared_ptr<AppRunningRecord> appRecord =
        appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, bundleInfo);
    EXPECT_NE(appRecord, nullptr);
    appRecord->GetPriorityObject()->SetPid(pid);
    appMgrServiceInner->HandleUnfocused(focusChangeInfo);

    TAG_LOGI(AAFwkTag::TEST, "HandleUnfocused_001 end");
}

/**
 * @tc.name: GetAppRunningStateByBundleName_001
 * @tc.desc: get app running state by bundle name.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, GetAppRunningStateByBundleName_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "GetAppRunningStateByBundleName_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    std::string bundleName = "test_bundleName";
    appMgrServiceInner->GetAppRunningStateByBundleName(bundleName);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->GetAppRunningStateByBundleName(bundleName);

    TAG_LOGI(AAFwkTag::TEST, "GetAppRunningStateByBundleName_001 end");
}

/**
 * @tc.name: NotifyLoadRepairPatch_001
 * @tc.desc: notify load repair patch.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, NotifyLoadRepairPatch_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "NotifyLoadRepairPatch_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    std::string bundleName = "test_bundleName";
    sptr<IQuickFixCallback> callback;
    appMgrServiceInner->NotifyLoadRepairPatch(bundleName, callback);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->NotifyLoadRepairPatch(bundleName, callback);

    TAG_LOGI(AAFwkTag::TEST, "NotifyLoadRepairPatch_001 end");
}

/**
 * @tc.name: NotifyHotReloadPage_001
 * @tc.desc: notify hot reload page.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, NotifyHotReloadPage_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "NotifyHotReloadPage_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    std::string bundleName = "test_bundleName";
    sptr<IQuickFixCallback> callback;
    appMgrServiceInner->NotifyHotReloadPage(bundleName, callback);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->NotifyHotReloadPage(bundleName, callback);

    TAG_LOGI(AAFwkTag::TEST, "NotifyHotReloadPage_001 end");
}

/**
 * @tc.name: SetContinuousTaskProcess_001
 * @tc.desc: set continuous task process.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
HWTEST_F(AppMgrServiceInnerTest, SetContinuousTaskProcess_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "SetContinuousTaskProcess_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    int32_t ret = appMgrServiceInner->SetContinuousTaskProcess(0, true);
    EXPECT_EQ(ret, 0);

    BundleInfo bundleInfo;
    std::string processName = "test_processName";
    std::shared_ptr<AppRunningRecord> appRecord =
        appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, bundleInfo);
    EXPECT_NE(appRecord, nullptr);
    appRecord->GetPriorityObject()->SetPid(0);
    ret = appMgrServiceInner->SetContinuousTaskProcess(0, true);
    EXPECT_EQ(ret, 0);

    appMgrServiceInner->appRunningManager_ = nullptr;
    ret = appMgrServiceInner->SetContinuousTaskProcess(0, true);
    EXPECT_EQ(ret, ERR_INVALID_OPERATION);

    TAG_LOGI(AAFwkTag::TEST, "SetContinuousTaskProcess_001 end");
}
#endif

/**
 * @tc.name: NotifyUnLoadRepairPatch_001
 * @tc.desc: notify unload repair patch.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, NotifyUnLoadRepairPatch_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "NotifyUnLoadRepairPatch_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    std::string bundleName = "test_bundleName";
    sptr<IQuickFixCallback> callback;
    appMgrServiceInner->NotifyUnLoadRepairPatch(bundleName, callback);

    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->NotifyUnLoadRepairPatch(bundleName, callback);

    TAG_LOGI(AAFwkTag::TEST, "NotifyUnLoadRepairPatch_001 end");
}

/**
 * @tc.name: SetCurrentUserId_001
 * @tc.desc: set current userId.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, SetCurrentUserId_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "SetCurrentUserId_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    int userId = 0;
    appMgrServiceInner->SetCurrentUserId(userId);
    EXPECT_EQ(appMgrServiceInner->currentUserId_, userId);

    TAG_LOGI(AAFwkTag::TEST, "SetCurrentUserId_001 end");
}

/**
 * @tc.name: GetProcessMemoryByPid_001
 * @tc.desc: Get memorySize by pid.
 * @tc.type: FUNC
 * @tc.require: issueI76JBF
 */
HWTEST_F(AppMgrServiceInnerTest, GetProcessMemoryByPid_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "GetProcessMemoryByPid_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    int32_t pid = 0;
    int32_t memorySize = 0;
    int32_t ret = appMgrServiceInner->GetProcessMemoryByPid(pid, memorySize);
    EXPECT_EQ(ret, ERR_OK);

    TAG_LOGI(AAFwkTag::TEST, "GetProcessMemoryByPid_001 end");
}

/**
 * @tc.name: GetRunningProcessInformation_001
 * @tc.desc: Get application processes information list by bundleName.
 * @tc.type: FUNC
 * @tc.require: issueI76JBF
 */
HWTEST_F(AppMgrServiceInnerTest, GetRunningProcessInformation_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "GetRunningProcessInformation_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    std::string bundleName = "testBundleName";
    int32_t userId = 100;
    std::vector<RunningProcessInfo> info;
    int32_t ret = appMgrServiceInner->GetRunningProcessInformation(bundleName, userId, info);
    EXPECT_EQ(ret, ERR_OK);

    appMgrServiceInner->remoteClientManager_ = nullptr;
    ret = appMgrServiceInner->GetRunningProcessInformation(bundleName, userId, info);
    EXPECT_EQ(ret, ERR_NO_INIT);

    appMgrServiceInner->appRunningManager_ = nullptr;
    ret = appMgrServiceInner->GetRunningProcessInformation(bundleName, userId, info);
    EXPECT_EQ(ret, ERR_NO_INIT);

    TAG_LOGI(AAFwkTag::TEST, "GetRunningProcessInformation_001 end");
}

/**
 * @tc.name: GetBundleNameByPid_001
 * @tc.desc: get bundle name by Pid.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, GetBundleNameByPid_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetBundleNameByPid_001 start");

    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    int32_t pid = 0;
    std::string name = "test_name";
    int32_t uid = 0;
    auto ret  = appMgrServiceInner->GetBundleNameByPid(pid, name, uid);
    EXPECT_EQ(ret, ERR_INVALID_OPERATION);

    TAG_LOGI(AAFwkTag::TEST, "GetBundleNameByPid_001 end");
}

/**
 * @tc.name: GetBundleNameByPid_002
 * @tc.desc: get bundle name by Pid.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, GetBundleNameByPid_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetBundleNameByPid_002 start");

    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    BundleInfo info;
    std::string processName = "test_processName";
    appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, info);
    int32_t pid = 0;
    std::string name = "test_name";
    int32_t uid = 0;
    auto ret  = appMgrServiceInner->GetBundleNameByPid(pid, name, uid);
    EXPECT_EQ(ret, ERR_OK);

    TAG_LOGI(AAFwkTag::TEST, "GetBundleNameByPid_002 end");
}

/**
 * @tc.name: AppRecoveryNotifyApp_001
 * @tc.desc: AppRecovery NotifyApp.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, AppRecoveryNotifyApp_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AppRecoveryNotifyApp_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    int32_t pid = 0;
    std::string bundleName = "com.is.hiserice";
    appMgrServiceInner->AppRecoveryNotifyApp(pid, bundleName, FaultDataType::RESOURCE_CONTROL, "appRecovery");
    appMgrServiceInner->AppRecoveryNotifyApp(pid, bundleName, FaultDataType::APP_FREEZE, "recovery");
    TAG_LOGI(AAFwkTag::TEST, "AppRecoveryNotifyApp_001 end");
}

/**
 * @tc.name: NotifyAppFault_001
 * @tc.desc: Notify AppFault.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, NotifyAppFault_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "NotifyAppFault_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    FaultData faultData1;
    faultData1.errorObject.name = "1234";
    faultData1.timeoutMarkers = "456";
    int32_t ret1 = appMgrServiceInner->NotifyAppFault(faultData1);
    EXPECT_EQ(ret1, ERR_INVALID_VALUE);
}

/**
 * @tc.name: TimeoutNotifyApp_001
 * @tc.desc: Timeout Notify App.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, TimeoutNotifyApp_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "TimeoutNotifyApp_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    int32_t pid = 0;
    int32_t uid = 0;
    std::string bundleName = "test_processName";
    FaultData faultData;
    faultData.errorObject.name = "1234";
    faultData.faultType = FaultDataType::APP_FREEZE;
    appMgrServiceInner->TimeoutNotifyApp(pid, uid, bundleName, faultData);
    TAG_LOGI(AAFwkTag::TEST, "TimeoutNotifyApp_001 end");
}

/**
 * @tc.name: NotifyAppFaultBySA_001
 * @tc.desc: Notify Fault Data By SA
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, NotifyAppFaultBySA_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "NotifyAppFaultBySA_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    AppFaultDataBySA faultData;
    faultData.pid = 8142;
    faultData.errorObject.name = "appRecovery";
    int32_t ret = appMgrServiceInner->NotifyAppFaultBySA(faultData);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "NotifyAppFaultBySA_001 end");
}

/**
 * @tc.name: RegisterAppDebugListener_001
 * @tc.desc: Test the status of RegisterAppDebugListener.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, RegisterAppDebugListener_001, TestSize.Level0)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    sptr<IAppDebugListener> listener = nullptr;
    appMgrServiceInner->appDebugManager_ = std::make_shared<AppDebugManager>();
    auto result = appMgrServiceInner->RegisterAppDebugListener(listener);
    EXPECT_EQ(result, ERR_INVALID_DATA);
    appMgrServiceInner->appDebugManager_ = nullptr;
    result = appMgrServiceInner->RegisterAppDebugListener(listener);
    EXPECT_EQ(result, ERR_NO_INIT);
}

/**
 * @tc.name: UnregisterAppDebugListener_001
 * @tc.desc: Test the status of UnregisterAppDebugListener.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, UnregisterAppDebugListener_001, TestSize.Level0)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    sptr<IAppDebugListener> listener = nullptr;
    appMgrServiceInner->appDebugManager_ = std::make_shared<AppDebugManager>();
    auto result = appMgrServiceInner->UnregisterAppDebugListener(listener);
    EXPECT_EQ(result, ERR_INVALID_DATA);
    appMgrServiceInner->appDebugManager_ = nullptr;
    result = appMgrServiceInner->UnregisterAppDebugListener(listener);
    EXPECT_EQ(result, ERR_NO_INIT);
}

/**
 * @tc.name: AttachAppDebug_001
 * @tc.desc: Test the status of AttachAppDebug.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, AttachAppDebug_001, TestSize.Level0)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    std::string bundleName;
    appMgrServiceInner->appRunningManager_ = std::make_shared<AppRunningManager>();
    appMgrServiceInner->appDebugManager_ = std::make_shared<AppDebugManager>();
    auto result = appMgrServiceInner->AttachAppDebug(bundleName);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AttachAppDebug_002
 * @tc.desc: Test the status of AttachAppDebug, check nullptr AppRunningManager.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, AttachAppDebug_002, TestSize.Level0)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    std::string bundleName;
    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->appDebugManager_ = std::make_shared<AppDebugManager>();
    auto result = appMgrServiceInner->AttachAppDebug(bundleName);
    EXPECT_EQ(result, ERR_NO_INIT);
}

/**
 * @tc.name: DetachAppDebug_001
 * @tc.desc: Test the status of DetachAppDebug.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, DetachAppDebug_001, TestSize.Level0)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    std::string bundleName;
    appMgrServiceInner->appRunningManager_ = std::make_shared<AppRunningManager>();
    appMgrServiceInner->appDebugManager_ = std::make_shared<AppDebugManager>();
    auto result = appMgrServiceInner->DetachAppDebug(bundleName);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: DetachAppDebug_002
 * @tc.desc: Test the status of DetachAppDebug, check nullptr AppRunningManager.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, DetachAppDebug_002, TestSize.Level0)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    std::string bundleName;
    appMgrServiceInner->appRunningManager_ = nullptr;
    appMgrServiceInner->appDebugManager_ = std::make_shared<AppDebugManager>();
    auto result = appMgrServiceInner->DetachAppDebug(bundleName);
    EXPECT_EQ(result, ERR_NO_INIT);
}

/**
 * @tc.name: SetAppWaitingDebug_001
 * @tc.desc: Test function SetAppWaitingDebug.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, SetAppWaitingDebug_001, TestSize.Level0)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    std::string bundleName("test");
    auto result = appMgrServiceInner->SetAppWaitingDebug(bundleName, false);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: CancelAppWaitingDebug_001
 * @tc.desc: Test function CancelAppWaitingDebug.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, CancelAppWaitingDebug_001, TestSize.Level0)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    auto result = appMgrServiceInner->CancelAppWaitingDebug();
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: GetWaitingDebugApp_001
 * @tc.desc: Test function GetWaitingDebugApp.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, GetWaitingDebugApp_001, TestSize.Level0)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    std::vector<std::string> debugInfoList;
    auto result = appMgrServiceInner->GetWaitingDebugApp(debugInfoList);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: RegisterAbilityDebugResponse_001
 * @tc.desc: Test the status of RegisterAbilityDebugResponse.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, RegisterAbilityDebugResponse_001, TestSize.Level0)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    sptr<IAbilityDebugResponse> response = nullptr;
    appMgrServiceInner->RegisterAbilityDebugResponse(response);
    EXPECT_TRUE(appMgrServiceInner != nullptr);
}

/**
 * @tc.name: NotifyAbilitysDebugChange_001
 * @tc.desc: Test the status of NotifyAbilitysDebugChange.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, NotifyAbilitysDebugChange_001, TestSize.Level0)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    std::string bundleName;
    bool isAppDebug = true;
    appMgrServiceInner->appRunningManager_ = std::make_shared<AppRunningManager>();
    appMgrServiceInner->appDebugManager_ = std::make_shared<AppDebugManager>();
    auto result = appMgrServiceInner->NotifyAbilitysDebugChange(bundleName, isAppDebug);
    EXPECT_EQ(result, ERR_NO_INIT);
}

/**
 * @tc.name: ProcessAppDebug_001
 * @tc.desc: Test the status of ProcessAppDebug.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, ProcessAppDebug_001, TestSize.Level0)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    appMgrServiceInner->appRunningManager_ = std::make_shared<AppRunningManager>();
    std::shared_ptr<ApplicationInfo> info = std::make_shared<ApplicationInfo>();
    int32_t recordId = RECORD_ID;
    std::string processName = "processName";
    std::shared_ptr<AppRunningRecord> appRecord = std::make_shared<AppRunningRecord>(info, recordId, processName);
    bool isDebugStart = true;
    appRecord->SetDebugApp(false);
    appMgrServiceInner->ProcessAppDebug(appRecord, isDebugStart);
    EXPECT_EQ(appRecord->IsDebugApp(), true);
}

/**
 * @tc.name: MakeAppDebugInfo_001
 * @tc.desc: Test the status of MakeAppDebugInfo.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, MakeAppDebugInfo_001, TestSize.Level0)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    appMgrServiceInner->appRunningManager_ = std::make_shared<AppRunningManager>();
    std::shared_ptr<ApplicationInfo> info = std::make_shared<ApplicationInfo>();
    int32_t recordId = RECORD_ID;
    std::string processName = "processName";
    std::shared_ptr<AppRunningRecord> appRecord = std::make_shared<AppRunningRecord>(info, recordId, processName);
    bool isDebugStart = true;
    appRecord->SetDebugApp(false);
    auto appDebugInfo = appMgrServiceInner->MakeAppDebugInfo(appRecord, isDebugStart);
    EXPECT_EQ(appDebugInfo.bundleName, "");
    EXPECT_EQ(appDebugInfo.pid, APP_DEBUG_INFO_PID);
    EXPECT_EQ(appDebugInfo.uid, APP_DEBUG_INFO_UID);
    EXPECT_EQ(appDebugInfo.isDebugStart, true);
}

/**
 * @tc.name: ChangeAppGcState_001
 * @tc.desc: Change app Gc state
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, ChangeAppGcState_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "ChangeAppGcState_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    int32_t pid = 0;
    int32_t state = 0;
    int32_t ret = appMgrServiceInner->ChangeAppGcState(pid, state);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "ChangeAppGcState_001 end");
}

/**
 * @tc.name: SendReStartProcessEvent_001
 * @tc.desc: Change app Gc state
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, SendReStartProcessEvent_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SendReStartProcessEvent_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    AAFwk::EventInfo eventInfo;
    appMgrServiceInner->SendReStartProcessEvent(eventInfo, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "SendReStartProcessEvent_001 end");
}

/**
 * @tc.name: SendReStartProcessEvent_002
 * @tc.desc: Change app Gc state
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, SendReStartProcessEvent_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SendReStartProcessEvent_002 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    AAFwk::EventInfo eventInfo;
    BundleInfo info;
    std::string processName = "test_processName";
    auto record = appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, info);
    recordId_ += 1;
    int64_t restartTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::
        system_clock::now().time_since_epoch()).count();
    int64_t killedTime = restartTime - 3000;
    appMgrServiceInner->killedPorcessMap_.emplace(killedTime, processName);
    appMgrServiceInner->SendReStartProcessEvent(eventInfo, record);
    TAG_LOGI(AAFwkTag::TEST, "SendReStartProcessEvent_002 end");
}

/**
 * @tc.name: SendReStartProcessEvent_003
 * @tc.desc: Change app Gc state
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, SendReStartProcessEvent_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SendReStartProcessEvent_003 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    AAFwk::EventInfo eventInfo;
    eventInfo.bundleName = "bundleName";
    eventInfo.callerBundleName = "callerBundleName";
    BundleInfo info;
    std::string processName = "test_processName";
    auto record = appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, info);
    recordId_ += 1;
    int64_t restartTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::
        system_clock::now().time_since_epoch()).count();
    int64_t killedTime = restartTime - 1000;
    appMgrServiceInner->killedPorcessMap_.emplace(killedTime, processName);
    appMgrServiceInner->SendReStartProcessEvent(eventInfo, record);
    TAG_LOGI(AAFwkTag::TEST, "SendReStartProcessEvent_003 end");
}

/**
 * @tc.name: SendReStartProcessEvent_004
 * @tc.desc: Change app Gc state
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, SendReStartProcessEvent_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SendReStartProcessEvent_004 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    AAFwk::EventInfo eventInfo;
    BundleInfo info;
    std::string processName = "test_processName";
    eventInfo.bundleName = "bundleName";
    eventInfo.callerBundleName = "bundleName";
    eventInfo.callerProcessName = processName;
    auto record = appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, info);
    recordId_ += 1;
    int64_t restartTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::
        system_clock::now().time_since_epoch()).count();
    int64_t killedTime = restartTime - 1000;
    appMgrServiceInner->killedPorcessMap_.emplace(killedTime, processName);
    appMgrServiceInner->SendReStartProcessEvent(eventInfo, record);
    TAG_LOGI(AAFwkTag::TEST, "SendReStartProcessEvent_004 end");
}

/**
 * @tc.name: SendReStartProcessEvent_005
 * @tc.desc: Change app Gc state
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, SendReStartProcessEvent_005, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "SendReStartProcessEvent_005 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    AAFwk::EventInfo eventInfo;
    BundleInfo info;
    std::string processName = "test_processName";
    eventInfo.bundleName = "bundleName";
    eventInfo.callerBundleName = "bundleName";
    eventInfo.callerProcessName = "processName";
    auto record = appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, info);
    recordId_ += 1;
    int64_t restartTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::
        system_clock::now().time_since_epoch()).count();
    int64_t killedTime = restartTime - 1000;
    appMgrServiceInner->killedPorcessMap_.emplace(killedTime, processName);
    appMgrServiceInner->SendReStartProcessEvent(eventInfo, record);
    TAG_LOGI(AAFwkTag::TEST, "SendReStartProcessEvent_005 end");
}

/**
 * @tc.name: SendAppLaunchEvent_001
 * @tc.desc: launch application.
 * @tc.type: FUNC
 * @tc.require: issueI5W4S7
 */
HWTEST_F(AppMgrServiceInnerTest, SendAppLaunchEvent_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "SendAppLaunchEvent_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->SendAppLaunchEvent(nullptr);
    BundleInfo info;
    std::string processName = "test_processName";
    std::shared_ptr<AppRunningRecord> appRecord =
        appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, info);
    recordId_ += 1;
    std::shared_ptr<AppRunningRecord> appRecord2 =
        appMgrServiceInner->appRunningManager_->CreateAppRunningRecord(applicationInfo_, processName, info);
    recordId_ += 1;
    appRecord->SetState(ApplicationState::APP_STATE_CREATE);
    appRecord->SetKeepAliveEnableState(false);
    appRecord->SetEmptyKeepAliveAppState(false);
    Want want;
    appRecord->SetSpecifiedAbilityFlagAndWant(-1, want, "");
    appMgrServiceInner->SendAppLaunchEvent(appRecord);
    appRecord->SetCallerPid(appRecord2->GetPriorityObject()->GetPid());
    appMgrServiceInner->SendAppLaunchEvent(appRecord);
    appRecord->appInfo_ = nullptr;
    appRecord2->appInfo_ = nullptr;
    appMgrServiceInner->SendAppLaunchEvent(appRecord);
    TAG_LOGI(AAFwkTag::TEST, "SendAppLaunchEvent_001 end");
}
HWTEST_F(AppMgrServiceInnerTest, IsMainProcess_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "IsMainProcess_001 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    HapModuleInfo hapModuleInfo;
    hapModuleInfo.moduleName = "module123";
    applicationInfo_->process = "";
    EXPECT_EQ(appMgrServiceInner->IsMainProcess(nullptr, hapModuleInfo), true);
    EXPECT_EQ(appMgrServiceInner->IsMainProcess(applicationInfo_, hapModuleInfo), true);
    hapModuleInfo.process = "processName1";
    EXPECT_EQ(appMgrServiceInner->IsMainProcess(applicationInfo_, hapModuleInfo), false);
    hapModuleInfo.process = applicationInfo_->bundleName;
    EXPECT_EQ(appMgrServiceInner->IsMainProcess(applicationInfo_, hapModuleInfo), true);
    applicationInfo_->process = "processName2";
    EXPECT_EQ(appMgrServiceInner->IsMainProcess(applicationInfo_, hapModuleInfo), false);
    hapModuleInfo.process = "processName2";
    EXPECT_EQ(appMgrServiceInner->IsMainProcess(applicationInfo_, hapModuleInfo), true);
    applicationInfo_->process = "";

    TAG_LOGI(AAFwkTag::TEST, "IsMainProcess_001 end");
}

/**
 * @tc.name: InitWindowVisibilityChangedListener_001
 * @tc.desc: init windowVisibilityChangedListener
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, InitWindowVisibilityChangedListener_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InitWindowVisibilityChangedListener_001 start" ;
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->InitWindowVisibilityChangedListener();
    EXPECT_NE(appMgrServiceInner->windowVisibilityChangedListener_, nullptr);
    GTEST_LOG_(INFO) << "InitWindowVisibilityChangedListener_001 end";
}

/**
 * @tc.name: FreeWindowVisibilityChangedListener_001
 * @tc.desc: free windowVisibilityChangedListener
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, FreeWindowVisibilityChangedListener_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FreeWindowVisibilityChangedListener_001 start";
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    appMgrServiceInner->FreeWindowVisibilityChangedListener();
    EXPECT_EQ(appMgrServiceInner->windowVisibilityChangedListener_, nullptr);
    GTEST_LOG_(INFO) << "FreeWindowVisibilityChangedListener_001 end";
}

/**
 * @tc.name: HandleWindowVisibilityChanged_001
 * @tc.desc: handle window visibility changed
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, HandleWindowVisibilityChanged_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleWindowVisibilityChanged_001 start";
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);

    std::vector<sptr<Rosen::WindowVisibilityInfo>> visibilityInfos;
    appMgrServiceInner->HandleWindowVisibilityChanged(visibilityInfos);
    EXPECT_NE(appMgrServiceInner, nullptr);
    GTEST_LOG_(INFO) << "HandleWindowVisibilityChanged_001 end";
}

/**
 * @tc.name: IsApplicationRunning_001
 * @tc.desc: Obtain application running status through bundleName.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, IsApplicationRunning_001, TestSize.Level1)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    std::string bundleName = "com.is.hiserice";
    std::string processName = "test_processName";
    bool isRunning = false;
    auto appRecord = std::make_shared<AppRunningRecord>(applicationInfo_, ++recordId_, processName);
    EXPECT_NE(appRecord, nullptr);
    appRecord->mainBundleName_ = "com.is.hiserice";
    appMgrServiceInner->appRunningManager_->appRunningRecordMap_.emplace(recordId_, appRecord);
    int32_t ret = appMgrServiceInner->IsApplicationRunning(bundleName, isRunning);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(isRunning);
}

/**
 * @tc.name: IsApplicationRunning_002
 * @tc.desc: Not passing in bundleName, unable to obtain application running status.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, IsApplicationRunning_002, TestSize.Level1)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    std::string bundleName = "com.is.hiserice";
    std::string processName = "test_processName";
    bool isRunning = false;
    auto appRecord = std::make_shared<AppRunningRecord>(applicationInfo_, ++recordId_, processName);
    EXPECT_NE(appRecord, nullptr);
    appMgrServiceInner->appRunningManager_->appRunningRecordMap_.emplace(recordId_, appRecord);
    int32_t ret = appMgrServiceInner->IsApplicationRunning(bundleName, isRunning);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(isRunning);
}

/**
 * @tc.name: RegisterAbilityForegroundStateObserver_0100
 * @tc.desc: Verify it when observer is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, RegisterAbilityForegroundStateObserver_0100, TestSize.Level0)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    auto res = appMgrServiceInner->RegisterAbilityForegroundStateObserver(nullptr);
    EXPECT_EQ(res, ERR_INVALID_VALUE);
}

/**
 * @tc.name: UnregisterAbilityForegroundStateObserver_0100
 * @tc.desc: Verify it when observer is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, UnregisterAbilityForegroundStateObserver_0100, TestSize.Level0)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    EXPECT_NE(appMgrServiceInner, nullptr);
    auto res = appMgrServiceInner->UnregisterAbilityForegroundStateObserver(nullptr);
    EXPECT_EQ(res, ERR_INVALID_VALUE);
}

/**
 * @tc.name: RegisterAppForegroundStateObserver_0100
 * @tc.desc: Test the return when observer is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, RegisterAppForegroundStateObserver_0100, TestSize.Level1)
{
    sptr<IAppForegroundStateObserver> observer = nullptr;
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    auto res = appMgrServiceInner->RegisterAppForegroundStateObserver(observer);
    EXPECT_EQ(ERR_INVALID_VALUE, res);
}

/**
 * @tc.name: UnregisterAppForegroundStateObserver_0100
 * @tc.desc: Test the return when observer is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, UnregisterAppForegroundStateObserver_0100, TestSize.Level1)
{
    sptr<IAppForegroundStateObserver> observer = nullptr;
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    auto res = appMgrServiceInner->RegisterAppForegroundStateObserver(observer);
    EXPECT_EQ(ERR_INVALID_VALUE, res);
}

/**
 * @tc.name: RegisterStateStateObserver_0100
 * @tc.desc: Test unregister by nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, RegisterRenderStateObserver_0100, TestSize.Level1)
{
    sptr<IRenderStateObserver> observer = nullptr;
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    auto res = appMgrServiceInner->RegisterRenderStateObserver(observer);
    EXPECT_EQ(ERR_INVALID_VALUE, res);
}


/**
 * @tc.name: RegisterStateStateObserver_0200
 * @tc.desc: Test unregister without permission.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, RegisterRenderStateObserver_0200, TestSize.Level1)
{
    AAFwk::IsMockSaCall::IsMockSaCallWithPermission();
    sptr<IRenderStateObserver> observer = new (std::nothrow) RenderStateObserverMock();
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    auto res = appMgrServiceInner->RegisterRenderStateObserver(observer);
    EXPECT_EQ(ERR_OK, res);
}

/**
 * @tc.name: UnregisterRenderStateObserver_0100
 * @tc.desc: Test unregister by nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, UnregisterRenderStateObserver_0100, TestSize.Level1)
{
    sptr<IRenderStateObserver> observer = nullptr;
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    auto res = appMgrServiceInner->RegisterRenderStateObserver(observer);
    EXPECT_EQ(ERR_INVALID_VALUE, res);
}

/**
 * @tc.name: UnregisterRenderStateObserver_0200
 * @tc.desc: Test unregister without permission.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, UnregisterRenderStateObserver_0200, TestSize.Level1)
{
    AAFwk::IsMockSaCall::IsMockSaCallWithPermission();
    sptr<IRenderStateObserver> observer = new (std::nothrow) RenderStateObserverMock();
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    auto res = appMgrServiceInner->RegisterRenderStateObserver(observer);
    EXPECT_EQ(ERR_OK, res);
}

/**
 * @tc.name: GetAllUIExtensionRootHostPid_0100
 * @tc.desc: Get all ui extension root host pid.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, GetAllUIExtensionRootHostPid_0100, TestSize.Level1)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    ASSERT_NE(appMgrServiceInner, nullptr);
    pid_t pid = 0;
    std::vector<pid_t> hostPids;
    auto ret = appMgrServiceInner->GetAllUIExtensionRootHostPid(pid, hostPids);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: GetAllUIExtensionProviderPid_0100
 * @tc.desc: Get all ui extension provider pid.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, GetAllUIExtensionProviderPid_0100, TestSize.Level1)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    ASSERT_NE(appMgrServiceInner, nullptr);
    pid_t hostPid = 0;
    std::vector<pid_t> providerPids;
    auto ret = appMgrServiceInner->GetAllUIExtensionProviderPid(hostPid, providerPids);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: AddUIExtensionLauncherItem_0100
 * @tc.desc: Add ui extension launcher item.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, AddUIExtensionLauncherItem_0100, TestSize.Level1)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    ASSERT_NE(appMgrServiceInner, nullptr);

    std::shared_ptr<AAFwk::Want> want = std::make_shared<AAFwk::Want>();
    ASSERT_NE(want, nullptr);
    want->SetParam("ability.want.params.uiExtensionAbilityId", 1);
    want->SetParam("ability.want.params.uiExtensionRootHostPid", 1000);

    std::shared_ptr<ApplicationInfo> appInfo = std::make_shared<ApplicationInfo>();
    ASSERT_NE(appInfo, nullptr);
    int32_t recordId = 0;
    std::string processName = "";
    std::shared_ptr<AppRunningRecord> appRecord = std::make_shared<AppRunningRecord>(appInfo, recordId, processName);
    ASSERT_NE(appRecord, nullptr);
    appRecord->GetPriorityObject()->SetPid(1001);

    sptr<IRemoteObject> token = sptr<IRemoteObject>(new (std::nothrow) MockAbilityToken());

    appMgrServiceInner->AddUIExtensionLauncherItem(want, appRecord, token);
    // check want param has been erased.
    EXPECT_EQ(want->HasParameter("ability.want.params.uiExtensionAbilityId"), false);
    EXPECT_EQ(want->HasParameter("ability.want.params.uiExtensionRootHostPid"), false);
    appMgrServiceInner->RemoveUIExtensionLauncherItem(appRecord, token);
}

/**
 * @tc.name: PreloadApplication_0100
 * @tc.desc: Preload Application.
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerTest, PreloadApplication_0100, TestSize.Level1)
{
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    ASSERT_NE(appMgrServiceInner, nullptr);

    std::string bundleName = "com.acts.preloadtest";
    int32_t userId = 100;
    PreloadMode preloadMode = PreloadMode::PRE_MAKE;
    int32_t appIndex = 0;
    int32_t ret = appMgrServiceInner->PreloadApplication(bundleName, userId, preloadMode, appIndex);
    EXPECT_EQ(ret, ERR_PERMISSION_DENIED);
}
} // namespace AppExecFwk
} // namespace OHOS

/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#define private public
#include "app_running_record.h"
#include "app_mgr_service_inner.h"
#include "iservice_registry.h"
#undef private

#include <unistd.h>
#include <gtest/gtest.h>
#include "iremote_object.h"
#include "refbase.h"
#include "mock_ability_token.h"
#include "mock_app_scheduler.h"
#include "mock_app_spawn_client.h"
#include "bundle_mgr_interface.h"
#include "mock_bundle_installer_service.h"
#include "mock_bundle_manager_service.h"
#include "mock_system_ability_manager.h"

using namespace testing::ext;
using testing::_;
using testing::Return;
using testing::SetArgReferee;
using ::testing::DoAll;

namespace OHOS {
namespace AppExecFwk {
namespace {
const int32_t INDEX_NUM_1 = 1;
const int32_t INDEX_NUM_2 = 2;
const int32_t INDEX_NUM_3 = 3;
const int32_t PID_MAX = 0x8000;
constexpr int32_t BUNDLE_MGR_SERVICE_SYS_ABILITY_ID = 401;
sptr<MockBundleInstallerService> mockBundleInstaller = new (std::nothrow) MockBundleInstallerService();
sptr<MockBundleManagerService> mockBundleMgr = new (std::nothrow) MockBundleManagerService();
}  // namespace
class AmsRecentAppListTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void MockBundleInstallerAndSA();
    void MockBundleInstaller();
    sptr<ISystemAbilityManager> iSystemAbilityMgr_ = nullptr;
    sptr<AppExecFwk::MockSystemAbilityManager> mockSystemAbility_ = nullptr;

protected:
    const std::shared_ptr<AbilityInfo> GetAbilityInfoByIndex(const int32_t index) const;
    const std::shared_ptr<ApplicationInfo> GetApplicationByIndex(const int32_t index) const;
    const std::shared_ptr<AppRunningRecord> GetAppRunningRecordByIndex(const int32_t index) const;
    void StartProcessSuccess(const int32_t index) const;

    std::shared_ptr<AppMgrServiceInner> serviceInner_;
    sptr<MockAbilityToken> mockToken_;
};

void AmsRecentAppListTest::SetUpTestCase()
{}

void AmsRecentAppListTest::TearDownTestCase()
{}

void AmsRecentAppListTest::SetUp()
{
    serviceInner_.reset(new (std::nothrow) AppMgrServiceInner());
    serviceInner_->Init();
    mockSystemAbility_ = new (std::nothrow) AppExecFwk::MockSystemAbilityManager();
    iSystemAbilityMgr_ = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = mockSystemAbility_;
}

void AmsRecentAppListTest::TearDown()
{
    SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = iSystemAbilityMgr_;
}

void AmsRecentAppListTest::MockBundleInstallerAndSA()
{
    auto mockGetBundleInstaller = []() { return mockBundleInstaller; };
    auto mockGetSystemAbility = [bms = mockBundleMgr, saMgr = iSystemAbilityMgr_](int32_t systemAbilityId) {
        if (systemAbilityId == BUNDLE_MGR_SERVICE_SYS_ABILITY_ID) {
            return bms->AsObject();
        } else {
            return saMgr->GetSystemAbility(systemAbilityId);
        }
    };
    EXPECT_CALL(*mockBundleMgr, GetBundleInstaller()).WillOnce(testing::Invoke(mockGetBundleInstaller));
    EXPECT_CALL(*mockSystemAbility_, GetSystemAbility(testing::_))
        .WillOnce(testing::Invoke(mockGetSystemAbility))
        .WillRepeatedly(testing::Invoke(mockGetSystemAbility));
}

void AmsRecentAppListTest::MockBundleInstaller()
{
    auto mockGetBundleInstaller = []() { return mockBundleInstaller; };
    EXPECT_CALL(*mockBundleMgr, GetBundleInstaller()).WillOnce(testing::Invoke(mockGetBundleInstaller));
}

const std::shared_ptr<AbilityInfo> AmsRecentAppListTest::GetAbilityInfoByIndex(const int32_t index) const
{
    std::shared_ptr<AbilityInfo> abilityInfo = std::make_shared<AbilityInfo>();
    abilityInfo->name = "test_ability" + std::to_string(index);
    abilityInfo->applicationName = "com.ohos.test.helloworld" + std::to_string(index);
    abilityInfo->applicationInfo.bundleName = "com.ohos.test.helloworld" + std::to_string(index);
    return abilityInfo;
}

const std::shared_ptr<ApplicationInfo> AmsRecentAppListTest::GetApplicationByIndex(const int32_t index) const
{
    std::shared_ptr<ApplicationInfo> appInfo = std::make_shared<ApplicationInfo>();
    appInfo->name = "com.ohos.test.helloworld" + std::to_string(index);
    appInfo->bundleName = "com.ohos.test.helloworld" + std::to_string(index);
    return appInfo;
}

const std::shared_ptr<AppRunningRecord> AmsRecentAppListTest::GetAppRunningRecordByIndex(const int32_t index) const
{
    auto appInfo = GetApplicationByIndex(index);
    BundleInfo bundleInfo;
    bundleInfo.appId = "com.ohos.test.helloworld_code123";

    auto appRecord = serviceInner_->appRunningManager_->CheckAppRunningRecordIsExist(
        appInfo->name, appInfo->name, appInfo->uid, bundleInfo);

    EXPECT_NE(nullptr, appRecord);
    return appRecord;
}

void AmsRecentAppListTest::StartProcessSuccess(const int32_t index) const
{
    pid_t pid = PID_MAX - index;
    auto abilityInfo = GetAbilityInfoByIndex(index);
    auto appInfo = GetApplicationByIndex(index);
    sptr<IRemoteObject> token = new (std::nothrow) MockAbilityToken();
    MockAppSpawnClient* mockClientPtr = new (std::nothrow) MockAppSpawnClient();
    EXPECT_TRUE(mockClientPtr);

    // mock start process success, and pid is right.
    EXPECT_CALL(*mockClientPtr, StartProcess(_, _)).Times(1).WillOnce(DoAll(SetArgReferee<1>(pid), Return(ERR_OK)));
    serviceInner_->SetAppSpawnClient(std::unique_ptr<MockAppSpawnClient>(mockClientPtr));

    serviceInner_->LoadAbility(token, nullptr, abilityInfo, appInfo, nullptr, 0);
    return;
}

/*
 * Feature: Ams
 * Function: RecentAppList
 * SubFunction: create
 * FunctionPoints: Add app to RecentAppList when start a new process success.
 * EnvConditions: RecentAppList is empty.
 * CaseDescription: Verity ams can add app to RecentAppList success when start a new process success.
 */
HWTEST_F(AmsRecentAppListTest, Create_001, TestSize.Level1)
{
    MockBundleInstallerAndSA();
    EXPECT_CALL(*mockBundleMgr, GetHapModuleInfo(testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(true))
        .WillRepeatedly(testing::Return(true));
    // get the recent app list before test.
    EXPECT_TRUE(serviceInner_->GetRecentAppList().empty());

    for (int32_t index = INDEX_NUM_1; index <= INDEX_NUM_3; index++) {
        StartProcessSuccess(index);
        EXPECT_EQ(index, static_cast<int32_t>(serviceInner_->GetRecentAppList().size()));
    }
}

/*
 * Feature: Ams
 * Function: RecentAppList
 * SubFunction: create
 * FunctionPoints: The size of RecentAppList remains the same when start a new process failed.
 * EnvConditions: RecentAppList is empty.
 * CaseDescription: Verity ams can not add app to RecentAppList when start a new process failed.
 */
HWTEST_F(AmsRecentAppListTest, Create_002, TestSize.Level1)
{
    MockBundleInstaller();
    EXPECT_CALL(*mockBundleMgr, GetHapModuleInfo(testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(true))
        .WillRepeatedly(testing::Return(true));
    auto abilityInfo = GetAbilityInfoByIndex(1);
    auto appInfo = GetApplicationByIndex(INDEX_NUM_1);
    sptr<IRemoteObject> token = new (std::nothrow) MockAbilityToken();
    EXPECT_TRUE(serviceInner_->GetRecentAppList().empty());

    // mock start process failed.
    MockAppSpawnClient* mockClientPtr = new (std::nothrow) MockAppSpawnClient();
    EXPECT_TRUE(mockClientPtr);

    EXPECT_CALL(*mockClientPtr, StartProcess(_, _)).WillOnce(Return(ERR_APPEXECFWK_ASSEMBLE_START_MSG_FAILED));
    serviceInner_->SetAppSpawnClient(std::unique_ptr<MockAppSpawnClient>(mockClientPtr));
    serviceInner_->LoadAbility(token, nullptr, abilityInfo, appInfo, nullptr, 0);
    EXPECT_TRUE(serviceInner_->GetRecentAppList().empty());
}

/*
 * Feature: Ams
 * Function: RecentAppList
 * SubFunction: create
 * FunctionPoints: The size of RecentAppList remains the same when start an already exist process.
 * EnvConditions: RecentAppList is empty.
 * CaseDescription: Verity ams can not add app to RecentAppList when start an already exist process.
 */
HWTEST_F(AmsRecentAppListTest, Create_003, TestSize.Level1)
{
    MockBundleInstaller();
    EXPECT_CALL(*mockBundleMgr, GetHapModuleInfo(testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(true))
        .WillRepeatedly(testing::Return(true));
    EXPECT_TRUE(serviceInner_->GetRecentAppList().empty());

    pid_t pid = INDEX_NUM_1;
    auto abilityInfo = GetAbilityInfoByIndex(INDEX_NUM_1);
    auto appInfo = GetApplicationByIndex(INDEX_NUM_1);
    sptr<IRemoteObject> token = new (std::nothrow) MockAbilityToken();
    MockAppSpawnClient* mockClientPtr = new (std::nothrow) MockAppSpawnClient();
    EXPECT_TRUE(mockClientPtr);

    // mock start process success, and pid is right.
    EXPECT_CALL(*mockClientPtr, StartProcess(_, _)).Times(1).WillOnce(DoAll(SetArgReferee<1>(pid), Return(ERR_OK)));
    serviceInner_->SetAppSpawnClient(std::unique_ptr<MockAppSpawnClient>(mockClientPtr));

    serviceInner_->LoadAbility(token, nullptr, abilityInfo, appInfo, nullptr, 0);
    EXPECT_EQ(INDEX_NUM_1, static_cast<int32_t>(serviceInner_->GetRecentAppList().size()));

    // Load ability1, start process 1 again.
    serviceInner_->LoadAbility(token, nullptr, abilityInfo, appInfo, nullptr, 0);
    EXPECT_EQ(INDEX_NUM_1, static_cast<int32_t>(serviceInner_->GetRecentAppList().size()));
}

/*
 * Feature: Ams
 * Function: RecentAppList
 * SubFunction: update
 * FunctionPoints: Remove app from RecentAppList when app terminated.
 * EnvConditions: RecentAppList has application.
 * CaseDescription: Verity ams can remove app from RecentAppList when app terminated.
 */
HWTEST_F(AmsRecentAppListTest, Update_001, TestSize.Level1)
{
    MockBundleInstaller();
    EXPECT_CALL(*mockBundleMgr, GetHapModuleInfo(testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(true))
        .WillRepeatedly(testing::Return(true));
    StartProcessSuccess(INDEX_NUM_1);
    EXPECT_EQ(INDEX_NUM_1, static_cast<int32_t>(serviceInner_->GetRecentAppList().size()));
    auto appRecord = GetAppRunningRecordByIndex(INDEX_NUM_1);
    appRecord->SetState(ApplicationState::APP_STATE_BACKGROUND);
    sptr<MockAppScheduler> mockAppScheduler = new (std::nothrow) MockAppScheduler();
    sptr<IAppScheduler> client = iface_cast<IAppScheduler>(mockAppScheduler.GetRefPtr());
    appRecord->SetApplicationClient(client);
    serviceInner_->ApplicationTerminated(appRecord->GetRecordId());
    EXPECT_TRUE(serviceInner_->GetRecentAppList().empty());
}

/*
 * Feature: Ams
 * Function: RecentAppList
 * SubFunction: update
 * FunctionPoints: Remove app from RecentAppList when app died.
 * EnvConditions: RecentAppList has application.
 * CaseDescription: Verity ams can remove app from RecentAppList when app died.
 */
HWTEST_F(AmsRecentAppListTest, Update_002, TestSize.Level1)
{
    MockBundleInstaller();
    EXPECT_CALL(*mockBundleMgr, GetHapModuleInfo(testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(true))
        .WillRepeatedly(testing::Return(true));
    StartProcessSuccess(INDEX_NUM_1);
    EXPECT_EQ(INDEX_NUM_1, static_cast<int32_t>(serviceInner_->GetRecentAppList().size()));
    auto appRecord = GetAppRunningRecordByIndex(INDEX_NUM_1);

    sptr<MockAppScheduler> mockAppScheduler = new (std::nothrow) MockAppScheduler();
    sptr<IAppScheduler> client = iface_cast<IAppScheduler>(mockAppScheduler.GetRefPtr());
    appRecord->SetApplicationClient(client);
    sptr<IRemoteObject> object = client->AsObject();
    wptr<IRemoteObject> app = object;
    serviceInner_->OnRemoteDied(app);
    EXPECT_TRUE(serviceInner_->GetRecentAppList().empty());
}

/*
 * Feature: Ams
 * Function: RecentAppList
 * SubFunction: update
 * FunctionPoints: Push app front.
 * EnvConditions: RecentAppList has application.
 * CaseDescription: Verity ams can push app front when app is foregrounded.
 */
HWTEST_F(AmsRecentAppListTest, Update_003, TestSize.Level1)
{
    MockBundleInstaller();
    EXPECT_CALL(*mockBundleMgr, GetHapModuleInfo(testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(true))
        .WillRepeatedly(testing::Return(true));
    for (int32_t index = INDEX_NUM_1; index <= INDEX_NUM_3; index++) {
        StartProcessSuccess(index);
        EXPECT_EQ(index, static_cast<int32_t>(serviceInner_->GetRecentAppList().size()));
    }

    for (int32_t index = INDEX_NUM_1; index <= INDEX_NUM_3; index++) {
        auto appRecord = GetAppRunningRecordByIndex(index);
        appRecord->SetUpdateStateFromService(true);
        serviceInner_->ApplicationForegrounded(appRecord->GetRecordId());
        auto appTaskInfo = serviceInner_->GetRecentAppList().front();
        EXPECT_NE(nullptr, appTaskInfo);
        EXPECT_EQ(appRecord->GetRecordId(), appTaskInfo->GetRecordId());
    }
}

/*
 * Feature: Ams
 * Function: RecentAppList
 * SubFunction: remove
 * FunctionPoints: Remove app from RecentAppList.
 * EnvConditions: RecentAppList has application.
 * CaseDescription: Verity ams can remove app from RecentAppList when call RemoveAppFromRecentList.
 */
HWTEST_F(AmsRecentAppListTest, Remove_001, TestSize.Level1)
{
    MockBundleInstaller();
    EXPECT_CALL(*mockBundleMgr, GetHapModuleInfo(testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(true))
        .WillRepeatedly(testing::Return(true));
    StartProcessSuccess(INDEX_NUM_1);
    EXPECT_EQ(INDEX_NUM_1, static_cast<int32_t>(serviceInner_->GetRecentAppList().size()));
    auto appInfo = GetApplicationByIndex(INDEX_NUM_1);

    sptr<MockAppScheduler> mockAppScheduler = new MockAppScheduler();
    sptr<IAppScheduler> client = iface_cast<IAppScheduler>(mockAppScheduler.GetRefPtr());
    auto appRecord = GetAppRunningRecordByIndex(INDEX_NUM_1);
    appRecord->SetApplicationClient(client);
    EXPECT_CALL(*mockAppScheduler, ScheduleProcessSecurityExit()).Times(1);

    serviceInner_->RemoveAppFromRecentList(appInfo->name, appInfo->bundleName);
    EXPECT_TRUE(serviceInner_->GetRecentAppList().empty());
}

/*
 * Feature: Ams
 * Function: RecentAppList
 * SubFunction: remove
 * FunctionPoints: Remove app from RecentAppList.
 * EnvConditions: RecentAppList has application.
 * CaseDescription: Verity ams can not remove app from RecentAppList when app name is not correct.
 */
HWTEST_F(AmsRecentAppListTest, Remove_002, TestSize.Level1)
{
    MockBundleInstaller();
    EXPECT_CALL(*mockBundleMgr, GetHapModuleInfo(testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(true))
        .WillRepeatedly(testing::Return(true));
    StartProcessSuccess(INDEX_NUM_1);
    EXPECT_EQ(INDEX_NUM_1, static_cast<int32_t>(serviceInner_->GetRecentAppList().size()));

    auto appInfo = GetApplicationByIndex(INDEX_NUM_2);
    serviceInner_->RemoveAppFromRecentList(appInfo->name, appInfo->bundleName);
    EXPECT_EQ(INDEX_NUM_1, static_cast<int32_t>(serviceInner_->GetRecentAppList().size()));
}

/*
 * Feature: Ams
 * Function: RecentAppList
 * SubFunction: remove
 * FunctionPoints: Remove app from RecentAppList.
 * EnvConditions: RecentAppList has application.
 * CaseDescription: Verity ams can not remove app from RecentAppList when app name is empty.
 */
HWTEST_F(AmsRecentAppListTest, Remove_003, TestSize.Level1)
{
    MockBundleInstaller();
    EXPECT_CALL(*mockBundleMgr, GetHapModuleInfo(testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(true))
        .WillRepeatedly(testing::Return(true));
    StartProcessSuccess(INDEX_NUM_1);
    EXPECT_EQ(INDEX_NUM_1, static_cast<int32_t>(serviceInner_->GetRecentAppList().size()));

    serviceInner_->RemoveAppFromRecentList("", "");
    EXPECT_EQ(INDEX_NUM_1, static_cast<int32_t>(serviceInner_->GetRecentAppList().size()));
}

/*
 * Feature: Ams
 * Function: RecentAppList
 * SubFunction: clear
 * FunctionPoints: Clear RecentAppList.
 * EnvConditions: RecentAppList has application.
 * CaseDescription: Verity ams can clear RecentAppList when call ClearRecentAppList.
 */
HWTEST_F(AmsRecentAppListTest, Clear_001, TestSize.Level1)
{
    MockBundleInstaller();
    EXPECT_CALL(*mockBundleMgr, GetHapModuleInfo(testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(true))
        .WillRepeatedly(testing::Return(true));
    StartProcessSuccess(INDEX_NUM_1);
    EXPECT_EQ(INDEX_NUM_1, static_cast<int32_t>(serviceInner_->GetRecentAppList().size()));

    sptr<MockAppScheduler> mockAppScheduler = new MockAppScheduler();
    sptr<IAppScheduler> client = iface_cast<IAppScheduler>(mockAppScheduler.GetRefPtr());
    auto appRecord = GetAppRunningRecordByIndex(INDEX_NUM_1);
    appRecord->SetApplicationClient(client);
    EXPECT_CALL(*mockAppScheduler, ScheduleProcessSecurityExit()).Times(1);

    serviceInner_->ClearRecentAppList();
    EXPECT_TRUE(!serviceInner_->GetRecentAppList().empty());
}

/*
 * Feature: Ams
 * Function: RecentAppList
 * SubFunction: clear
 * FunctionPoints: Clear RecentAppList.
 * EnvConditions: RecentAppList has application.
 * CaseDescription: Verity ams can clear RecentAppList when RecentAppList is empty.
 */
HWTEST_F(AmsRecentAppListTest, Clear_002, TestSize.Level1)
{
    EXPECT_TRUE(serviceInner_->GetRecentAppList().empty());
    serviceInner_->ClearRecentAppList();
    EXPECT_TRUE(serviceInner_->GetRecentAppList().empty());
}

/*
 * Feature: Ams
 * Function: PushAppFront
 * SubFunction: PushAppFront
 * FunctionPoints: PushAppFront.
 * EnvConditions: app has application.
 * CaseDescription: Verity ams can PushAppFront when App is not empty.
 */
HWTEST_F(AmsRecentAppListTest, PushAppFront_001, TestSize.Level1)
{
    EXPECT_TRUE(serviceInner_->GetRecentAppList().empty());
    pid_t pid = INDEX_NUM_1;
    auto abilityInfo = GetAbilityInfoByIndex(INDEX_NUM_1);
    auto appInfo = GetApplicationByIndex(INDEX_NUM_1);
    sptr<IRemoteObject> token = new (std::nothrow) MockAbilityToken();
    MockAppSpawnClient* mockClientPtr = new (std::nothrow) MockAppSpawnClient();
    EXPECT_TRUE(mockClientPtr);

    EXPECT_CALL(*mockClientPtr, StartProcess(_, _)).Times(1).WillOnce(DoAll(SetArgReferee<1>(pid), Return(ERR_OK)));
    serviceInner_->SetAppSpawnClient(std::unique_ptr<MockAppSpawnClient>(mockClientPtr));

    serviceInner_->LoadAbility(token, nullptr, abilityInfo, appInfo, nullptr, 0);
    EXPECT_EQ(INDEX_NUM_1, static_cast<int32_t>(serviceInner_->GetRecentAppList().size()));
    auto appRecord = GetAppRunningRecordByIndex(INDEX_NUM_1);
    serviceInner_->PushAppFront(appRecord->GetRecordId());
    EXPECT_NE(nullptr, serviceInner_->GetAppTaskInfoById(appRecord->GetRecordId()));
}
}  // namespace AppExecFwk
}  // namespace OHOS

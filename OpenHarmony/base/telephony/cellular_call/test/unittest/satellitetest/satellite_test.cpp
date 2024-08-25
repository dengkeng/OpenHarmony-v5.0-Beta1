/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "satellite_test.h"

#define private public
#define protected public
#include "cellular_call_config.h"
#include "cellular_call_handler.h"
#include "cellular_call_proxy.h"
#include "cellular_call_register.h"
#include "cellular_call_service.h"
#include "tel_ril_call_parcel.h"
#include "satellite_call_client.h"
#include "securec.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
const int32_t SIM1_SLOTID = 0;
const int32_t SIM2_SLOTID = 1;
const int32_t INVALID_SLOTID = 10;
const std::string PHONE_NUMBER = "0000000";

void SatelliteTest::SetUpTestCase(void)
{
    // step 3: Set Up Test Case
}

void SatelliteTest::TearDownTestCase(void)
{
    // step 3: Tear Down Test Case
}

void SatelliteTest::SetUp(void)
{
    // step 3: input testcase setup step
}

void SatelliteTest::TearDown(void)
{
    // step 3: input testcase teardown step
}

/**
 * @tc.number   Satellite_call_test_001
 * @tc.name     Test the corresponding functions by entering commands, such as 300 -- SetCallPreferenceMode, 301 --
 *              GetCallPreferenceMode, etc
 * @tc.desc     Function test
 */
HWTEST_F(SatelliteTest, Satellite_call_test_001, Function | MediumTest | Level0)
{
    std::cout << "HWTEST_F Satellite_call_test_001";
    AccessToken token;
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto remote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(remote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(remote);
    ASSERT_TRUE(telephonyService != nullptr);
}

/**
 * @tc.number   Satellite_call_test_002
 * @tc.name     Test the corresponding functions by entering commands, such as 300 -- SetCallPreferenceMode, 301 --
 *              GetCallPreferenceMode, etc
 * @tc.desc     Function test
 */
HWTEST_F(SatelliteTest, Satellite_call_test_002, Function | MediumTest | Level1)
{
    std::cout << "HWTEST_F Satellite_call_test_002";
    AccessToken token;
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto remote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(remote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(remote);
    ASSERT_TRUE(telephonyService != nullptr);
}

/**
 * @tc.number   Satellite_call_DialCall_0001
 * @tc.name     Test for SetClip function by Satellite
 * @tc.desc     Function test
 */
HWTEST_F(SatelliteTest, Satellite_call_DialCall_0001, Function | MediumTest | Level2)
{
    AccessToken token;
    TELEPHONY_LOGI("Satellite_call_DialCall_0001 entry");
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto hangUpCallRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(hangUpCallRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(hangUpCallRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = TestDialCallBySatellite(SIM1_SLOTID, PHONE_NUMBER);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = TestDialCallBySatellite(INVALID_SLOTID, PHONE_NUMBER);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = TestDialCallBySatellite(SIM2_SLOTID, PHONE_NUMBER);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = TestDialCallBySatellite(INVALID_SLOTID, PHONE_NUMBER);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
}

/**
 * @tc.number   Satellite_call_HangUpCall_0001
 * @tc.name     Test for HangUp function by Satellite
 * @tc.desc     Function test
 */
HWTEST_F(SatelliteTest, Satellite_call_HangUpCall_0001, Function | MediumTest | Level2)
{
    AccessToken token;
    TELEPHONY_LOGI("Satellite_call_HangUpCall_0001 entry");
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto hangUpCallRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(hangUpCallRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(hangUpCallRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        CellularCallInfo callInfo;
        int32_t ret = InitCellularCallInfo(SIM1_SLOTID, PHONE_NUMBER, callInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->HangUp(callInfo, CallSupplementType::TYPE_DEFAULT);
        EXPECT_GE(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        CellularCallInfo callInfo;
        int32_t ret = InitCellularCallInfo(SIM2_SLOTID, PHONE_NUMBER, callInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->HangUp(callInfo, CallSupplementType::TYPE_DEFAULT);
        EXPECT_GE(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   Satellite_call_AnswerCall_0001
 * @tc.name     Test for answer function by Satellite
 * @tc.desc     Function test
 */
HWTEST_F(SatelliteTest, Satellite_call_AnswerCall_0001, Function | MediumTest | Level2)
{
    AccessToken token;
    TELEPHONY_LOGI("Satellite_call_AnswerCall_0001 entry");
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto answerCallRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(answerCallRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(answerCallRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        CellularCallInfo callInfo;
        int32_t ret = InitCellularCallInfo(SIM1_SLOTID, PHONE_NUMBER, callInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->Answer(callInfo);
        EXPECT_GE(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        CellularCallInfo callInfo;
        int32_t ret = InitCellularCallInfo(SIM2_SLOTID, PHONE_NUMBER, callInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->Answer(callInfo);
        EXPECT_GE(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   Satellite_call_RejectCall_0001
 * @tc.name     Test for reject function by tatellite
 * @tc.desc     Function test
 */
HWTEST_F(SatelliteTest, Satellite_call_RejectCall_0001, Function | MediumTest | Level2)
{
    AccessToken token;
    TELEPHONY_LOGI("Satellite_call_RejectCall_0001 entry");
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto rejectCallRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(rejectCallRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(rejectCallRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        CellularCallInfo callInfo;
        int32_t ret = InitCellularCallInfo(SIM1_SLOTID, PHONE_NUMBER, callInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->Reject(callInfo);
        EXPECT_GE(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        CellularCallInfo callInfo;
        int32_t ret = InitCellularCallInfo(SIM2_SLOTID, PHONE_NUMBER, callInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->Reject(callInfo);
        EXPECT_GE(ret, TELEPHONY_SUCCESS);
    }
}
} // namespace Telephony
} // namespace OHOS

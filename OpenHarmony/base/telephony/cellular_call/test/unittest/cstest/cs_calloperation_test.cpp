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

#include "cs_test.h"

#define PRIVATE public
#define PROTECTED public
#include "cellular_call_callback.h"
#include "cellular_call_handler.h"
#include "cellular_call_proxy.h"
#include "cellular_call_register.h"
#include "cellular_call_service.h"
#include "cellular_call_supplement.h"
#include "config_request.h"
#include "core_service_client.h"
#include "cs_control.h"
#include "tel_ril_call_parcel.h"
#include "operator_config_types.h"
#include "radio_event.h"
#include "securec.h"
#include "sim_state_type.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
const int32_t SIM1_SLOTID = 0;
const int32_t SIM2_SLOTID = 1;
const int32_t INVALID_SLOTID = 0xFF;
const std::string PHONE_NUMBER = "0000000";
const std::string PHONE_NUMBER_SECOND = "1111111";
const std::string PHONE_NUMBER_THIRD = "2222222";

/**
 * @tc.number   cellular_call_DialCall_0001
 * @tc.name     Test for SetClip function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_DialCall_0001, Function | MediumTest | Level2)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM1_SLOTID, "*30#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM2_SLOTID, "*30#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_DialCall_0002
 * @tc.name     Test for SetClip function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_DialCall_0002, Function | MediumTest | Level2)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM1_SLOTID, "#30#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM2_SLOTID, "#30#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_DialCall_0003
 * @tc.name     Test for getClip function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_DialCall_0003, Function | MediumTest | Level2)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM1_SLOTID, "*#30#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM2_SLOTID, "*#30#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_DialCall_0004
 * @tc.name     Test for SetClir function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_DialCall_0004, Function | MediumTest | Level2)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM1_SLOTID, "*31#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM2_SLOTID, "*31#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_DialCall_0005
 * @tc.name     Test for SetClir function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_DialCall_0005, Function | MediumTest | Level2)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM1_SLOTID, "#31#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM2_SLOTID, "#31#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_DialCall_0006
 * @tc.name     Test for GetClir function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_DialCall_0006, Function | MediumTest | Level2)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM1_SLOTID, "*#31#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM2_SLOTID, "*#31#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_DialCall_0007
 * @tc.name     Test for SetCallTransfer function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_DialCall_0007, Function | MediumTest | Level2)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM1_SLOTID, "*21#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM2_SLOTID, "*21#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_DialCall_0008
 * @tc.name     Test for SetCallTransfer function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_DialCall_0008, Function | MediumTest | Level2)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM1_SLOTID, "#21#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM2_SLOTID, "#21#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_DialCall_0009
 * @tc.name     Test for GetCallTransfer function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_DialCall_0009, Function | MediumTest | Level2)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM1_SLOTID, "*#21#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM2_SLOTID, "*#21#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_DialCall_0010
 * @tc.name     Test for SetCallRestriction function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_DialCall_0010, Function | MediumTest | Level2)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM1_SLOTID, "*33#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM2_SLOTID, "*33#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_DialCall_0011
 * @tc.name     Test for SetCallRestriction function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_DialCall_0011, Function | MediumTest | Level2)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM1_SLOTID, "#33#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM2_SLOTID, "#33#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_DialCall_0012
 * @tc.name     Test for GetCallRestriction function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_DialCall_0012, Function | MediumTest | Level2)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM1_SLOTID, "*#33#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM2_SLOTID, "*#33#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_DialCall_0013
 * @tc.name     Test for SetCallWaiting function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_DialCall_0013, Function | MediumTest | Level2)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM1_SLOTID, "*43#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM2_SLOTID, "*43#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_DialCall_0014
 * @tc.name     Test for SetCallWaiting function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_DialCall_0014, Function | MediumTest | Level2)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM1_SLOTID, "#43#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM2_SLOTID, "#43#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_DialCall_0015
 * @tc.name     Test for GetCallWaiting function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_DialCall_0015, Function | MediumTest | Level2)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM1_SLOTID, "*#43#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM2_SLOTID, "*#43#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_DialCall_0016
 * @tc.name     Test for AlterPinPassword function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_DialCall_0016, Function | MediumTest | Level2)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM1_SLOTID, "*04#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM2_SLOTID, "*04#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_DialCall_0017
 * @tc.name     Test for UnlockPuk function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_DialCall_0017, Function | MediumTest | Level2)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM1_SLOTID, "*05#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM2_SLOTID, "*05#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_DialCall_0018
 * @tc.name     Test for AlterPin2Password function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_DialCall_0018, Function | MediumTest | Level2)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM1_SLOTID, "*042#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM2_SLOTID, "*042#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_DialCall_0019
 * @tc.name     Test for UnlockPuk2 function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_DialCall_0019, Function | MediumTest | Level2)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM1_SLOTID, "*052#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM2_SLOTID, "*052#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_DialCall_0020
 * @tc.name     Test for SendUssd function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_DialCall_0020, Function | MediumTest | Level2)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM1_SLOTID, "*4444#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = TestDialCallByCs(SIM2_SLOTID, "*4444#");
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_DialCall_0021
 * @tc.name     Test for dial function with invalid slot by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_DialCall_0021, Function | MediumTest | Level2)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = TestDialCallByCs(INVALID_SLOTID, PHONE_NUMBER);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = TestDialCallByCs(INVALID_SLOTID, PHONE_NUMBER);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
}

/**
 * @tc.number   cellular_call_HangUpCall_0001
 * @tc.name     Test for HangUp function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_HangUpCall_0001, Function | MediumTest | Level2)
{
    AccessToken token;
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto hangUpCallRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(hangUpCallRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(hangUpCallRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    CellularCallInfo hangUpCallInfo;
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = InitCellularCallInfo(SIM1_SLOTID, PHONE_NUMBER, hangUpCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->HangUp(hangUpCallInfo, CallSupplementType::TYPE_DEFAULT);
        EXPECT_EQ(ret, CALL_ERR_CALL_CONNECTION_NOT_EXIST);
        ret = telephonyService->HangUp(hangUpCallInfo, CallSupplementType::TYPE_HANG_UP_ACTIVE);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = InitCellularCallInfo(SIM2_SLOTID, PHONE_NUMBER, hangUpCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->HangUp(hangUpCallInfo, CallSupplementType::TYPE_DEFAULT);
        EXPECT_EQ(ret, CALL_ERR_CALL_CONNECTION_NOT_EXIST);
        ret = telephonyService->HangUp(hangUpCallInfo, CallSupplementType::TYPE_HANG_UP_ACTIVE);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_HangUpCall_0002
 * @tc.name     Test for HangUp function with invalid slot by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_HangUpCall_0002, Function | MediumTest | Level2)
{
    AccessToken token;
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto hangUpCallRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(hangUpCallRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(hangUpCallRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (HasSimCard(SIM1_SLOTID)) {
        CellularCallInfo hangUpCallInfo;
        int32_t ret = InitCellularCallInfo(INVALID_SLOTID, PHONE_NUMBER, hangUpCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->HangUp(hangUpCallInfo, CallSupplementType::TYPE_DEFAULT);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        CellularCallInfo hangUpCallInfo;
        int32_t ret = InitCellularCallInfo(INVALID_SLOTID, PHONE_NUMBER, hangUpCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->HangUp(hangUpCallInfo, CallSupplementType::TYPE_DEFAULT);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
}

/**
 * @tc.number   cellular_call_AnswerCall_0001
 * @tc.name     Test for answer function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_AnswerCall_0001, Function | MediumTest | Level2)
{
    AccessToken token;
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
        CellularCallInfo answerCallInfo;
        int32_t ret = InitCellularCallInfo(SIM1_SLOTID, PHONE_NUMBER, answerCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->Answer(answerCallInfo);
        EXPECT_EQ(ret, CALL_ERR_CALL_CONNECTION_NOT_EXIST);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        CellularCallInfo answerCallInfo;
        int32_t ret = InitCellularCallInfo(SIM2_SLOTID, PHONE_NUMBER, answerCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->Answer(answerCallInfo);
        EXPECT_EQ(ret, CALL_ERR_CALL_CONNECTION_NOT_EXIST);
    }
}

/**
 * @tc.number   cellular_call_AnswerCall_0002
 * @tc.name     Test for answer function with invalid slot by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_AnswerCall_0002, Function | MediumTest | Level2)
{
    AccessToken token;
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto answerCallRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(answerCallRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(answerCallRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (HasSimCard(SIM1_SLOTID)) {
        CellularCallInfo answerCallInfo;
        int32_t ret = InitCellularCallInfo(INVALID_SLOTID, PHONE_NUMBER, answerCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->Answer(answerCallInfo);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        CellularCallInfo answerCallInfo;
        int32_t ret = InitCellularCallInfo(INVALID_SLOTID, PHONE_NUMBER, answerCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->Answer(answerCallInfo);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
}

/**
 * @tc.number   cellular_call_RejectCall_0001
 * @tc.name     Test for reject function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_RejectCall_0001, Function | MediumTest | Level2)
{
    AccessToken token;
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
        CellularCallInfo rejectCallInfo;
        int32_t ret = InitCellularCallInfo(SIM1_SLOTID, PHONE_NUMBER, rejectCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->Reject(rejectCallInfo);
        EXPECT_EQ(ret, CALL_ERR_CALL_CONNECTION_NOT_EXIST);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        CellularCallInfo rejectCallInfo;
        int32_t ret = InitCellularCallInfo(SIM2_SLOTID, PHONE_NUMBER, rejectCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->Reject(rejectCallInfo);
        EXPECT_EQ(ret, CALL_ERR_CALL_CONNECTION_NOT_EXIST);
    }
}

/**
 * @tc.number   cellular_call_RejectCall_0002
 * @tc.name     Test for reject function with invalid slot by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_RejectCall_0002, Function | MediumTest | Level2)
{
    AccessToken token;
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto rejectCallRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(rejectCallRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(rejectCallRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (HasSimCard(SIM1_SLOTID)) {
        CellularCallInfo rejectCallInfo;
        int32_t ret = InitCellularCallInfo(INVALID_SLOTID, PHONE_NUMBER, rejectCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->Reject(rejectCallInfo);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        CellularCallInfo rejectCallInfo;
        int32_t ret = InitCellularCallInfo(INVALID_SLOTID, PHONE_NUMBER, rejectCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->Reject(rejectCallInfo);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
}

/**
 * @tc.number   cellular_call_HoldCall_0001
 * @tc.name     Test for hold call function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_HoldCall_0001, Function | MediumTest | Level2)
{
    AccessToken token;
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto holdCallRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(holdCallRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(holdCallRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        CellularCallInfo holdCallInfo;
        int32_t ret = InitCellularCallInfo(SIM1_SLOTID, PHONE_NUMBER, holdCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->HoldCall(holdCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        CellularCallInfo holdCallInfo;
        int32_t ret = InitCellularCallInfo(SIM2_SLOTID, PHONE_NUMBER, holdCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->HoldCall(holdCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_HoldCall_0002
 * @tc.name     Test for hold function with invalid slot by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_HoldCall_0002, Function | MediumTest | Level2)
{
    AccessToken token;
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto holdCallRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(holdCallRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(holdCallRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (HasSimCard(SIM1_SLOTID)) {
        CellularCallInfo holdCallInfo;
        int32_t ret = InitCellularCallInfo(INVALID_SLOTID, PHONE_NUMBER, holdCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->HoldCall(holdCallInfo);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        CellularCallInfo holdCallInfo;
        int32_t ret = InitCellularCallInfo(INVALID_SLOTID, PHONE_NUMBER, holdCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->HoldCall(holdCallInfo);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
}

/**
 * @tc.number   cellular_call_UnHoldCall_0001
 * @tc.name     Test for unhold call function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_UnHoldCall_0001, Function | MediumTest | Level2)
{
    AccessToken token;
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto unHoldCallRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(unHoldCallRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(unHoldCallRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        CellularCallInfo unHoldCallInfo;
        int32_t ret = InitCellularCallInfo(SIM1_SLOTID, PHONE_NUMBER, unHoldCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->UnHoldCall(unHoldCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        CellularCallInfo unHoldCallInfo;
        int32_t ret = InitCellularCallInfo(SIM2_SLOTID, PHONE_NUMBER, unHoldCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->UnHoldCall(unHoldCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_UnHoldCall_0002
 * @tc.name     Test for unhold function with invalid slot by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_UnHoldCall_0002, Function | MediumTest | Level2)
{
    AccessToken token;
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto unHoldCallRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(unHoldCallRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(unHoldCallRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (HasSimCard(SIM1_SLOTID)) {
        CellularCallInfo unHoldCallInfo;
        int32_t ret = InitCellularCallInfo(INVALID_SLOTID, PHONE_NUMBER, unHoldCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->UnHoldCall(unHoldCallInfo);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        CellularCallInfo unHoldCallInfo;
        int32_t ret = InitCellularCallInfo(INVALID_SLOTID, PHONE_NUMBER, unHoldCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->UnHoldCall(unHoldCallInfo);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
}

/**
 * @tc.number   cellular_call_SwitchCall_0001
 * @tc.name     Test for switch call function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_SwitchCall_0001, Function | MediumTest | Level2)
{
    AccessToken token;
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto switchCallRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(switchCallRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(switchCallRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        CellularCallInfo switchCallInfo;
        int32_t ret = InitCellularCallInfo(SIM1_SLOTID, PHONE_NUMBER, switchCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->SwitchCall(switchCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        CellularCallInfo switchCallInfo;
        int32_t ret = InitCellularCallInfo(SIM2_SLOTID, PHONE_NUMBER, switchCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->SwitchCall(switchCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_SwitchCall_0002
 * @tc.name     Test for switch function with invalid slot by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_SwitchCall_0002, Function | MediumTest | Level2)
{
    AccessToken token;
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto switchCallRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(switchCallRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(switchCallRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (HasSimCard(SIM1_SLOTID)) {
        CellularCallInfo switchCallInfo;
        int32_t ret = InitCellularCallInfo(INVALID_SLOTID, PHONE_NUMBER, switchCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->SwitchCall(switchCallInfo);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        CellularCallInfo switchCallInfo;
        int32_t ret = InitCellularCallInfo(INVALID_SLOTID, PHONE_NUMBER, switchCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->SwitchCall(switchCallInfo);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
}

/**
 * @tc.number   cellular_call_CombineConference_0001
 * @tc.name     Test for combineConference function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_CombineConference_0001, Function | MediumTest | Level2)
{
    AccessToken token;
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto combineRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(combineRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(combineRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        CellularCallInfo conferenceCallInfo;
        int32_t ret = InitCellularCallInfo(SIM1_SLOTID, PHONE_NUMBER, conferenceCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->CombineConference(conferenceCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        CellularCallInfo conferenceCallInfo;
        int32_t ret = InitCellularCallInfo(SIM2_SLOTID, PHONE_NUMBER, conferenceCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->CombineConference(conferenceCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_CombineConference_0002
 * @tc.name     Test for combineConference function with invalid slot by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_CombineConference_0002, Function | MediumTest | Level2)
{
    AccessToken token;
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto combineRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(combineRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(combineRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (HasSimCard(SIM1_SLOTID)) {
        CellularCallInfo conferenceCallInfo;
        int32_t ret = InitCellularCallInfo(INVALID_SLOTID, PHONE_NUMBER, conferenceCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->CombineConference(conferenceCallInfo);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        CellularCallInfo conferenceCallInfo;
        int32_t ret = InitCellularCallInfo(INVALID_SLOTID, PHONE_NUMBER, conferenceCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->CombineConference(conferenceCallInfo);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
}

/**
 * @tc.number   cellular_call_SeparateConference_0001
 * @tc.name     Test for separateConference function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_SeparateConference_0001, Function | MediumTest | Level2)
{
    AccessToken token;
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto separateRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(separateRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(separateRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        CellularCallInfo callInfo;
        int32_t ret = InitCellularCallInfo(SIM1_SLOTID, PHONE_NUMBER, callInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->SeparateConference(callInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        CellularCallInfo callInfo;
        int32_t ret = InitCellularCallInfo(SIM2_SLOTID, PHONE_NUMBER, callInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->SeparateConference(callInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_SeparateConference_0002
 * @tc.name     Test for separateConference function with invalid slot by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_SeparateConference_0002, Function | MediumTest | Level2)
{
    AccessToken token;
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto separateRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(separateRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(separateRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (HasSimCard(SIM1_SLOTID)) {
        CellularCallInfo separateCallInfo;
        int32_t ret = InitCellularCallInfo(INVALID_SLOTID, PHONE_NUMBER, separateCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->SeparateConference(separateCallInfo);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        CellularCallInfo separateCallInfo;
        int32_t ret = InitCellularCallInfo(INVALID_SLOTID, PHONE_NUMBER, separateCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->SeparateConference(separateCallInfo);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
}

/**
 * @tc.number   cellular_call_KickOutFromConference_0001
 * @tc.name     Test for separateConference function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_KickOutFromConference_0001, Function | MediumTest | Level2)
{
    AccessToken token;
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto kickOutRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(kickOutRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(kickOutRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        CellularCallInfo kickOutCallInfo;
        int32_t ret = InitCellularCallInfo(SIM1_SLOTID, PHONE_NUMBER, kickOutCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->KickOutFromConference(kickOutCallInfo);
        EXPECT_EQ(ret, CALL_ERR_CALL_CONNECTION_NOT_EXIST);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        CellularCallInfo kickOutCallInfo;
        int32_t ret = InitCellularCallInfo(SIM2_SLOTID, PHONE_NUMBER, kickOutCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->KickOutFromConference(kickOutCallInfo);
        EXPECT_EQ(ret, CALL_ERR_CALL_CONNECTION_NOT_EXIST);
    }
}

/**
 * @tc.number   cellular_call_KickOutFromConference_0002
 * @tc.name     Test for KickOutFromConference function with invalid slot by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_KickOutFromConference_0002, Function | MediumTest | Level2)
{
    AccessToken token;
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto kickOutRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(kickOutRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(kickOutRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (HasSimCard(SIM1_SLOTID)) {
        CellularCallInfo kickOutCallInfo;
        int32_t ret = InitCellularCallInfo(INVALID_SLOTID, PHONE_NUMBER, kickOutCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->KickOutFromConference(kickOutCallInfo);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        CellularCallInfo kickOutCallInfo;
        int32_t ret = InitCellularCallInfo(INVALID_SLOTID, PHONE_NUMBER, kickOutCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->KickOutFromConference(kickOutCallInfo);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
}

/**
 * @tc.number   cellular_call_HangUpAllConnection_0001
 * @tc.name     Test for hangup all connection function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_HangUpAllConnection_0001, Function | MediumTest | Level2)
{
    AccessToken token;
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto hangUpAllConRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(hangUpAllConRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(hangUpAllConRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = telephonyService->HangUpAllConnection();
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = telephonyService->HangUpAllConnection();
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_StartDtmf_0001
 * @tc.name     Test for startDtmf function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_StartDtmf_0001, Function | MediumTest | Level2)
{
    AccessToken token;
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto startDtmfRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(startDtmfRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(startDtmfRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        CellularCallInfo callInfo;
        int32_t ret = InitCellularCallInfo(SIM1_SLOTID, PHONE_NUMBER, callInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        char code = '1';
        ret = telephonyService->StartDtmf(code, callInfo);
        EXPECT_EQ(ret, CALL_ERR_CALL_CONNECTION_NOT_EXIST);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        CellularCallInfo callInfo;
        int32_t ret = InitCellularCallInfo(SIM2_SLOTID, PHONE_NUMBER, callInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        char code = '1';
        ret = telephonyService->StartDtmf(code, callInfo);
        EXPECT_EQ(ret, CALL_ERR_CALL_CONNECTION_NOT_EXIST);
    }
}

/**
 * @tc.number   cellular_call_StartDtmf_0002
 * @tc.name     Test for startDtmf function with invalid slot by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_StartDtmf_0002, Function | MediumTest | Level2)
{
    AccessToken token;
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto startDtmfRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(startDtmfRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(startDtmfRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    CellularCallInfo callInfo;
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = InitCellularCallInfo(INVALID_SLOTID, PHONE_NUMBER, callInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        char code = '1';
        ret = telephonyService->StartDtmf(code, callInfo);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = InitCellularCallInfo(INVALID_SLOTID, PHONE_NUMBER, callInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        char code = '1';
        ret = telephonyService->StartDtmf(code, callInfo);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
}

/**
 * @tc.number   cellular_call_StopDtmf_0001
 * @tc.name     Test for stopDtmf function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_StopDtmf_0001, Function | MediumTest | Level2)
{
    AccessToken token;
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto stopDtmfRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(stopDtmfRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(stopDtmfRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        CellularCallInfo callInfo;
        int32_t ret = InitCellularCallInfo(SIM1_SLOTID, PHONE_NUMBER, callInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->StopDtmf(callInfo);
        EXPECT_EQ(ret, CALL_ERR_CALL_CONNECTION_NOT_EXIST);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        CellularCallInfo callInfo;
        int32_t ret = InitCellularCallInfo(SIM2_SLOTID, PHONE_NUMBER, callInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->StopDtmf(callInfo);
        EXPECT_EQ(ret, CALL_ERR_CALL_CONNECTION_NOT_EXIST);
    }
}

/**
 * @tc.number   cellular_call_StopDtmf_0002
 * @tc.name     Test for stopDtmf function with invalid slot by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_StopDtmf_0002, Function | MediumTest | Level2)
{
    AccessToken token;
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto stopDtmfRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(stopDtmfRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(stopDtmfRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (HasSimCard(SIM1_SLOTID)) {
        CellularCallInfo stopDtmfCallInfo;
        int32_t ret = InitCellularCallInfo(INVALID_SLOTID, PHONE_NUMBER, stopDtmfCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->StopDtmf(stopDtmfCallInfo);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        CellularCallInfo stopDtmfCallInfo;
        int32_t ret = InitCellularCallInfo(INVALID_SLOTID, PHONE_NUMBER, stopDtmfCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        ret = telephonyService->StopDtmf(stopDtmfCallInfo);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
}

/**
 * @tc.number   cellular_call_SendDtmf_0001
 * @tc.name     Test for sendDtmf function by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_SendDtmf_0001, Function | MediumTest | Level2)
{
    AccessToken token;
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto sendDtmfRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(sendDtmfRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(sendDtmfRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        CellularCallInfo sendDtmfCallInfo;
        int32_t ret = InitCellularCallInfo(SIM1_SLOTID, PHONE_NUMBER, sendDtmfCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        char code = '1';
        ret = telephonyService->SendDtmf(code, sendDtmfCallInfo);
        EXPECT_EQ(ret, CALL_ERR_CALL_CONNECTION_NOT_EXIST);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        CellularCallInfo sendDtmfCallInfo;
        int32_t ret = InitCellularCallInfo(SIM2_SLOTID, PHONE_NUMBER, sendDtmfCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        char code = '1';
        ret = telephonyService->SendDtmf(code, sendDtmfCallInfo);
        EXPECT_EQ(ret, CALL_ERR_CALL_CONNECTION_NOT_EXIST);
    }
}

/**
 * @tc.number   cellular_call_SendDtmf_0002
 * @tc.name     Test for sendDtmf function with invalid slot by cs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_SendDtmf_0002, Function | MediumTest | Level2)
{
    AccessToken token;
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto sendDtmfRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(sendDtmfRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(sendDtmfRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (HasSimCard(SIM1_SLOTID)) {
        CellularCallInfo sendDtmfCallInfo;
        int32_t ret = InitCellularCallInfo(INVALID_SLOTID, PHONE_NUMBER, sendDtmfCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        char code = '1';
        ret = telephonyService->SendDtmf(code, sendDtmfCallInfo);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        CellularCallInfo sendDtmfCallInfo;
        int32_t ret = InitCellularCallInfo(INVALID_SLOTID, PHONE_NUMBER, sendDtmfCallInfo);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
        char code = '1';
        ret = telephonyService->SendDtmf(code, sendDtmfCallInfo);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
}
} // namespace Telephony
} // namespace OHOS

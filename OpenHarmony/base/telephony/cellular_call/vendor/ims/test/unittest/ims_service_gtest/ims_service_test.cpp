/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "ims_service_test.h"

#include "core_service_client.h"
#include "ims_call_client.h"
#include "ims_core_service_client.h"
#include "ims_sms_client.h"
#include "ims_sms_types.h"
#include "securec.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

using namespace testing::ext;

namespace OHOS {
namespace Telephony {
const char PHONE_NUMBER[6] = "00000";
const int32_t DEFAULT_SLOTID = 0;
const int32_t SIM_SLOT_ID_1 = 1;
const int32_t DEFAULT_STATE = 0;
const int32_t DEFAULT_INDEX = 0;
const int32_t CALL_TYPE_IMS = 1;
const int32_t DEFAULT_MODE = 0;
const int32_t DEFAULT_TRANSFER_TYPE = 0;
const bool DEFAULT_ACTIVE = true;
const ImsConfigItem DEFAULT_ITEM = ITEM_VIDEO_QUALITY;
const FeatureType DEFAULT_FEATURE_TYPE = TYPE_VOICE_OVER_LTE;
const std::string RTT_MSG = "000";

sptr<ImsCallInterface> ImsServiceTest::imsCallPtr_ = nullptr;
sptr<ImsSmsInterface> ImsServiceTest::imsSmsPtr_ = nullptr;
sptr<ImsCoreServiceInterface> ImsServiceTest::imsCoreServicePtr_ = nullptr;

ImsCallInfo ImsServiceTest::callInfoForSlot0_ = {};
ImsCallInfo ImsServiceTest::callInfoForSlot1_ = {};
void ImsServiceTest::SetUpTestCase()
{
    Init();
    TELEPHONY_LOGI("----------ImsSerivce gtest start ------------");
}

void ImsServiceTest::TearDownTestCase()
{
    TELEPHONY_LOGI("----------ImsSerivce gtest end ------------");
}

void ImsServiceTest::SetUp() {}

void ImsServiceTest::TearDown() {}

void ImsServiceTest::Init()
{
    if (strcpy_s(callInfoForSlot0_.phoneNum, sizeof(PHONE_NUMBER), PHONE_NUMBER) != EOK) {
        TELEPHONY_LOGE("Init strcpy_s phoneNum failed!");
    }
    imsCallPtr_ = DelayedSingleton<ImsCallClient>::GetInstance()->GetImsCallProxy();
    imsSmsPtr_ = DelayedSingleton<ImsSmsClient>::GetInstance()->GetImsSmsProxy();
    imsCoreServicePtr_ = DelayedSingleton<ImsCoreServiceClient>::GetInstance()->GetImsCoreServiceProxy();

    callInfoForSlot0_.slotId = DEFAULT_SLOTID;
    callInfoForSlot0_.index = DEFAULT_INDEX;
    callInfoForSlot0_.videoState = DEFAULT_STATE;

    if (strcpy_s(callInfoForSlot1_.phoneNum, sizeof(PHONE_NUMBER), PHONE_NUMBER) != EOK) {
        TELEPHONY_LOGE("Init strcpy_s phoneNum failed!");
    }
    callInfoForSlot1_.slotId = SIM_SLOT_ID_1;
    callInfoForSlot1_.index = DEFAULT_INDEX;
    callInfoForSlot1_.videoState = DEFAULT_STATE;
}

bool HasSimCard(int32_t slotId)
{
    bool hasSimCard = false;
    DelayedRefSingleton<CoreServiceClient>::GetInstance().HasSimCard(slotId, hasSimCard);
    return hasSimCard;
}

int32_t ImsServiceTest::InitConditionCheck()
{
    if (CoreServiceClient::GetInstance().GetProxy() == nullptr) {
        TELEPHONY_LOGE("connect coreService server failed or haven't insert sim card!");
        return TELEPHONY_ERROR;
    }
    int32_t ret = TELEPHONY_ERROR;
    if (imsCallPtr_ == nullptr) {
        TELEPHONY_LOGE("imsCallPtr is nullptr, Init Failed!");
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
        return TELEPHONY_ERROR;
    }
}
/**
 * @tc.number   Telephony_ImsService_DIAL_001
 * @tc.name     Dial by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_DIAL_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    if (memset_s(&callInfoForSlot0_, sizeof(callInfoForSlot0_), 0, sizeof(callInfoForSlot0_)) == EOK) {
        ret = TELEPHONY_SUCCESS;
    }
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
    CLIRMode mode = CLIRMode::DEFAULT;
    ret = imsCallPtr_->Dial(callInfoForSlot0_, mode);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_DIAL_002
 * @tc.name     Dial by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_DIAL_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    if (memset_s(&callInfoForSlot1_, sizeof(callInfoForSlot1_), 0, sizeof(callInfoForSlot1_)) == EOK) {
        ret = TELEPHONY_SUCCESS;
    }
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
    CLIRMode mode = CLIRMode::DEFAULT;
    ret = imsCallPtr_->Dial(callInfoForSlot1_, mode);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_HangUP_001
 * @tc.name     Hang Up by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_HangUP_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    if (memset_s(&callInfoForSlot0_, sizeof(callInfoForSlot0_), 0, sizeof(callInfoForSlot0_)) == EOK) {
        ret = TELEPHONY_SUCCESS;
    }
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
    ret = imsCallPtr_->HangUp(callInfoForSlot0_);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_HangUP_002
 * @tc.name     Hang Up by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_HangUP_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    if (memset_s(&callInfoForSlot1_, sizeof(callInfoForSlot1_), 0, sizeof(callInfoForSlot1_)) == EOK) {
        ret = TELEPHONY_SUCCESS;
    }
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
    ret = imsCallPtr_->HangUp(callInfoForSlot1_);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_RejectWithReason_001
 * @tc.name     Reject by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_RejectWithReason_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    if (memset_s(&callInfoForSlot0_, sizeof(callInfoForSlot0_), 0, sizeof(callInfoForSlot0_)) == EOK) {
        ret = TELEPHONY_SUCCESS;
    }
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
    ret = imsCallPtr_->RejectWithReason(callInfoForSlot0_, ImsRejectReason::USER_DECLINE);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_RejectWithReason_002
 * @tc.name     Reject by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_RejectWithReason_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    if (memset_s(&callInfoForSlot1_, sizeof(callInfoForSlot1_), 0, sizeof(callInfoForSlot1_)) == EOK) {
        ret = TELEPHONY_SUCCESS;
    }
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
    ret = imsCallPtr_->RejectWithReason(callInfoForSlot1_, ImsRejectReason::USER_DECLINE);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_Answer_001
 * @tc.name     Answer by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_Answer_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    if (memset_s(&callInfoForSlot0_, sizeof(callInfoForSlot0_), 0, sizeof(callInfoForSlot0_)) == EOK) {
        ret = TELEPHONY_SUCCESS;
    }
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
    ret = imsCallPtr_->Answer(callInfoForSlot0_);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_Answer_002
 * @tc.name     Answer by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_Answer_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    if (memset_s(&callInfoForSlot1_, sizeof(callInfoForSlot1_), 0, sizeof(callInfoForSlot1_)) == EOK) {
        ret = TELEPHONY_SUCCESS;
    }
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
    ret = imsCallPtr_->Answer(callInfoForSlot1_);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_HoldCall_001
 * @tc.name     Hold Call by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_HoldCall_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->HoldCall(DEFAULT_SLOTID, CALL_TYPE_IMS);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_HoldCall_002
 * @tc.name     Hold Call by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_HoldCall_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->HoldCall(SIM_SLOT_ID_1, CALL_TYPE_IMS);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_UnHoldCall_001
 * @tc.name     Un Hold Call by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_UnHoldCall_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->UnHoldCall(DEFAULT_SLOTID, CALL_TYPE_IMS);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_UnHoldCall_002
 * @tc.name     Un Hold Call by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_UnHoldCall_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->UnHoldCall(SIM_SLOT_ID_1, CALL_TYPE_IMS);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SwitchCall_001
 * @tc.name     Switch Call by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SwitchCall_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->SwitchCall(DEFAULT_SLOTID, CALL_TYPE_IMS);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SwitchCall_002
 * @tc.name     Switch Call by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SwitchCall_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->SwitchCall(SIM_SLOT_ID_1, CALL_TYPE_IMS);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_CombineConference_001
 * @tc.name     Combine Conference by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_CombineConference_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->CombineConference(DEFAULT_SLOTID);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_CombineConference_002
 * @tc.name     Combine Conference by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_CombineConference_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->CombineConference(SIM_SLOT_ID_1);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_InviteToConference_001
 * @tc.name     Invite To Conference by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_InviteToConference_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    std::vector<std::string> numberList;
    numberList.push_back(PHONE_NUMBER);
    ret = imsCallPtr_->InviteToConference(DEFAULT_SLOTID, numberList);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_InviteToConference_002
 * @tc.name     Invite To Conference by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_InviteToConference_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    std::vector<std::string> numberList;
    numberList.push_back(PHONE_NUMBER);
    ret = imsCallPtr_->InviteToConference(SIM_SLOT_ID_1, numberList);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_KickOutFromConference_001
 * @tc.name     Kick Out From Conference by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_KickOutFromConference_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    int32_t index = 1;
    int32_t ret = imsCallPtr_->KickOutFromConference(DEFAULT_SLOTID, index);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_KickOutFromConference_002
 * @tc.name     Kick Out From Conference by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_KickOutFromConference_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    int32_t index = 1;
    int32_t ret = imsCallPtr_->KickOutFromConference(SIM_SLOT_ID_1, index);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_UpdateImsCallMode_001
 * @tc.name     Update Ims Call Mode by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_UpdateImsCallMode_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    if (memset_s(&callInfoForSlot0_, sizeof(callInfoForSlot0_), 0, sizeof(callInfoForSlot0_)) == EOK) {
        ret = TELEPHONY_SUCCESS;
    }
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
    ret = imsCallPtr_->UpdateImsCallMode(callInfoForSlot0_, static_cast<ImsCallMode>(DEFAULT_MODE));
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_UpdateImsCallMode_002
 * @tc.name     Update Ims Call Mode by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_UpdateImsCallMode_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    if (memset_s(&callInfoForSlot1_, sizeof(callInfoForSlot1_), 0, sizeof(callInfoForSlot1_)) == EOK) {
        ret = TELEPHONY_SUCCESS;
    }
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
    ret = imsCallPtr_->UpdateImsCallMode(callInfoForSlot1_, static_cast<ImsCallMode>(DEFAULT_MODE));
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_StartDtmf_001
 * @tc.name     Start Dtmf by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_StartDtmf_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    char dtmfCode = '#';
    ret = imsCallPtr_->StartDtmf(DEFAULT_SLOTID, dtmfCode, DEFAULT_INDEX);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_StartDtmf_002
 * @tc.name     Start Dtmf by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_StartDtmf_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    char dtmfCode = '#';
    ret = imsCallPtr_->StartDtmf(SIM_SLOT_ID_1, dtmfCode, DEFAULT_INDEX);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SendDtmf_001
 * @tc.name     Send Dtmf by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SendDtmf_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    char dtmfCode = '#';
    ret = imsCallPtr_->SendDtmf(DEFAULT_SLOTID, dtmfCode, DEFAULT_INDEX);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SendDtmf_002
 * @tc.name     Send Dtmf by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SendDtmf_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    char dtmfCode = '#';
    ret = imsCallPtr_->SendDtmf(SIM_SLOT_ID_1, dtmfCode, DEFAULT_INDEX);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_StopDtmf_0001
 * @tc.name     Stop Dtmf by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_StopDtmf_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->StopDtmf(DEFAULT_SLOTID, DEFAULT_INDEX);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_StopDtmf_0002
 * @tc.name     Stop Dtmf by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_StopDtmf_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->StopDtmf(SIM_SLOT_ID_1, DEFAULT_INDEX);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_StartRtt_001
 * @tc.name     Start Rtt by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_StartRtt_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->StartRtt(DEFAULT_SLOTID, RTT_MSG);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_StartRtt_002
 * @tc.name     Start Rtt by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_StartRtt_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->StartRtt(SIM_SLOT_ID_1, RTT_MSG);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_StopRtt_001
 * @tc.name     Stop Rtt by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_StopRtt_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->StopRtt(DEFAULT_SLOTID);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_StopRtt_002
 * @tc.name     Stop Rtt by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_StopRtt_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->StopRtt(SIM_SLOT_ID_1);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SetDomainPreferenceMode_001
 * @tc.name     Set Domain Preference Mode by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SetDomainPreferenceMode_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->SetDomainPreferenceMode(DEFAULT_SLOTID, DEFAULT_MODE);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SetDomainPreferenceMode_002
 * @tc.name     Set Domain Preference Mode by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SetDomainPreferenceMode_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->SetDomainPreferenceMode(SIM_SLOT_ID_1, DEFAULT_MODE);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_GetDomainPreferenceMode_001
 * @tc.name     Get Domain Preference Mode by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_GetDomainPreferenceMode_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->GetDomainPreferenceMode(DEFAULT_SLOTID);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_GetDomainPreferenceMode_002
 * @tc.name     Get Domain Preference Mode by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_GetDomainPreferenceMode_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->GetDomainPreferenceMode(SIM_SLOT_ID_1);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SetImsSwitchStatus_001
 * @tc.name     Set Ims Switch Status by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SetImsSwitchStatus_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->SetImsSwitchStatus(DEFAULT_SLOTID, DEFAULT_ACTIVE);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SetImsSwitchStatus_002
 * @tc.name     Set Ims Switch Status by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SetImsSwitchStatus_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->SetImsSwitchStatus(SIM_SLOT_ID_1, DEFAULT_ACTIVE);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_GetImsSwitchStatus_001
 * @tc.name     Get Ims Switch Status by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_GetImsSwitchStatus_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->GetImsSwitchStatus(DEFAULT_SLOTID);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_GetImsSwitchStatus_002
 * @tc.name     Get Ims Switch Status by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_GetImsSwitchStatus_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->GetImsSwitchStatus(SIM_SLOT_ID_1);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SetImsConfigString_001
 * @tc.name     Set Ims Config String by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SetImsConfigString_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    std::string value = "0";
    ret = imsCallPtr_->SetImsConfig(DEFAULT_ITEM, value);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SetImsConfigInt_001
 * @tc.name     Set Ims Config Int by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SetImsConfigInt_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    int32_t value = 0;
    ret = imsCallPtr_->SetImsConfig(DEFAULT_ITEM, value);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_GetImsConfig_001
 * @tc.name     Get Ims Config by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_GetImsConfig_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->GetImsConfig(DEFAULT_ITEM);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SetImsFeatureValue_001
 * @tc.name     Set Ims Feature Value by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SetImsFeatureValue_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    int32_t value = 0;
    ret = imsCallPtr_->SetImsFeatureValue(DEFAULT_FEATURE_TYPE, value);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_GetImsFeatureValue_001
 * @tc.name     Get Ims Feature Value by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_GetImsFeatureValue_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    int32_t value;
    ret = imsCallPtr_->GetImsFeatureValue(DEFAULT_FEATURE_TYPE, value);
    TELEPHONY_LOGI("Ims Feature Value:%{public}d", value);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SetMute_001
 * @tc.name     Set Mute by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SetMute_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    int32_t mute = 0;
    ret = imsCallPtr_->SetMute(DEFAULT_SLOTID, mute);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SetMute_002
 * @tc.name     Set Mute by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SetMute_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    int32_t mute = 0;
    ret = imsCallPtr_->SetMute(SIM_SLOT_ID_1, mute);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_GetMute_001
 * @tc.name     Get Mute by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_GetMute_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->GetMute(DEFAULT_SLOTID);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}
/**
 * @tc.number   Telephony_ImsService_GetMute_002
 * @tc.name     Get Mute by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_GetMute_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->GetMute(SIM_SLOT_ID_1);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_CtrlCamera_001
 * @tc.name     Ctrl Camera by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_CtrlCamera_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    std::u16string cameraId = u"cameraId";
    int32_t callingUid = 0;
    int32_t callingPid = 0;
    ret = imsCallPtr_->CtrlCamera(cameraId, callingUid, callingPid);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SetPreviewWindow_001
 * @tc.name     Set Preview Window by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SetPreviewWindow_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    int32_t x = 0;
    int32_t y = 0;
    int32_t z = 0;
    int32_t width = 0;
    int32_t height = 0;
    ret = imsCallPtr_->SetPreviewWindow(x, y, z, width, height);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SetDisplayWindow_001
 * @tc.name     Set Display Window by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SetDisplayWindow_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    int32_t x = 0;
    int32_t y = 0;
    int32_t z = 0;
    int32_t width = 0;
    int32_t height = 0;
    ret = imsCallPtr_->SetDisplayWindow(x, y, z, width, height);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SetCameraZoom_001
 * @tc.name     Set Camera Zoom by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SetCameraZoom_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    float zoomRatio = 1.0;
    ret = imsCallPtr_->SetCameraZoom(zoomRatio);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SetPauseImage_001
 * @tc.name     Set Pause Image by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SetPauseImage_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    std::u16string path = u"path";
    ret = imsCallPtr_->SetPauseImage(path);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SetDeviceDirection_001
 * @tc.name     Set Device Direction by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SetDeviceDirection_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    int32_t rotation = 0;
    ret = imsCallPtr_->SetDeviceDirection(rotation);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_GetClip_001
 * @tc.name     Get Clip by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_GetClip_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->GetClip(DEFAULT_SLOTID);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_GetClip_002
 * @tc.name     Get Clip by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_GetClip_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->GetClip(SIM_SLOT_ID_1);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SetClir_001
 * @tc.name     Set Clip by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SetClir_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    int32_t action = 0;
    ret = imsCallPtr_->SetClir(DEFAULT_SLOTID, action);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SetClir_002
 * @tc.name     Set Clip by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SetClir_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    int32_t action = 0;
    ret = imsCallPtr_->SetClir(SIM_SLOT_ID_1, action);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_GetClir_001
 * @tc.name     Get Clir by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_GetClir_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->GetClir(DEFAULT_SLOTID);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_GetClir_002
 * @tc.name     Get Clir by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_GetClir_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->GetClir(SIM_SLOT_ID_1);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SetCallTransfer_001
 * @tc.name     Set Call Transfer by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SetCallTransfer_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    std::string transferNum = "000000";
    int32_t classType = 1;
    ret = imsCallPtr_->SetCallTransfer(DEFAULT_SLOTID, DEFAULT_TRANSFER_TYPE, DEFAULT_MODE, transferNum, classType);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SetCallTransfer_002
 * @tc.name     Set Call Transfer by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SetCallTransfer_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    std::string transferNum = "000000";
    int32_t classType = 1;
    ret = imsCallPtr_->SetCallTransfer(SIM_SLOT_ID_1, DEFAULT_TRANSFER_TYPE, DEFAULT_MODE, transferNum, classType);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_GetCallTransfer_001
 * @tc.name     Get Call Transfer by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_GetCallTransfer_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    if (imsCallPtr_ == nullptr) {
        TELEPHONY_LOGE("imsCallPtr is nullptr, Init Failed!");
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
        return;
    }
    ret = imsCallPtr_->GetCallTransfer(DEFAULT_SLOTID, DEFAULT_TRANSFER_TYPE);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_GetCallTransfer_002
 * @tc.name     Get Call Transfer by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_GetCallTransfer_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->GetCallTransfer(SIM_SLOT_ID_1, DEFAULT_TRANSFER_TYPE);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SetCallRestriction_001
 * @tc.name     Set Call Restriction by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SetCallRestriction_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    std::string fac = "AO";
    std::string password = "000000";
    ret = imsCallPtr_->SetCallRestriction(DEFAULT_SLOTID, fac, DEFAULT_MODE, password);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SetCallRestriction_002
 * @tc.name     Set Call Restriction by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SetCallRestriction_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    std::string fac = "AO";
    std::string password = "000000";
    ret = imsCallPtr_->SetCallRestriction(SIM_SLOT_ID_1, fac, DEFAULT_MODE, password);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_GetCallRestriction_001
 * @tc.name     Get Call Restriction by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_GetCallRestriction_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    std::string facType = "AO";
    ret = imsCallPtr_->GetCallRestriction(DEFAULT_SLOTID, facType);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_GetCallRestriction_002
 * @tc.name     Get Call Restriction by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_GetCallRestriction_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    std::string facType = "AO";
    ret = imsCallPtr_->GetCallRestriction(SIM_SLOT_ID_1, facType);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SetCallWaiting_001
 * @tc.name     Set Call Waiting by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SetCallWaiting_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->SetCallWaiting(DEFAULT_SLOTID, DEFAULT_ACTIVE, ServiceClassType::VOICE);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SetCallWaiting_002
 * @tc.name     Set Call Waiting by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SetCallWaiting_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->SetCallWaiting(SIM_SLOT_ID_1, DEFAULT_ACTIVE, ServiceClassType::VOICE);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_GetCallWaiting_001
 * @tc.name     Get Call Waiting by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_GetCallWaiting_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->GetCallWaiting(DEFAULT_SLOTID);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_GetCallWaiting_002
 * @tc.name     Get Call Waiting by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_GetCallWaiting_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCallPtr_->GetCallWaiting(SIM_SLOT_ID_1);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SetSmsConfig_001
 * @tc.name     Set Sms Config by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SetSmsConfig_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    int32_t imsSmsConfig = 1;
    ret = imsSmsPtr_->ImsSetSmsConfig(DEFAULT_SLOTID, imsSmsConfig);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SetSmsConfig_002
 * @tc.name     Set Sms Config by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SetSmsConfig_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    int32_t imsSmsConfig = 1;
    ret = imsSmsPtr_->ImsSetSmsConfig(SIM_SLOT_ID_1, imsSmsConfig);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_GetSmsConfig_001
 * @tc.name     Get Sms Config by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_GetSmsConfig_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsSmsPtr_->ImsGetSmsConfig(DEFAULT_SLOTID);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_GetSmsConfig_002
 * @tc.name     Get Sms Config by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_GetSmsConfig_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsSmsPtr_->ImsGetSmsConfig(SIM_SLOT_ID_1);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SendMessage_001
 * @tc.name     Send Message by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SendMessage_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    int32_t refld = 1;
    ImsMessageInfo imsMessageInfo;
    imsMessageInfo.refId = refld;
    ret = imsSmsPtr_->ImsSendMessage(DEFAULT_SLOTID, imsMessageInfo);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_SendMessage_002
 * @tc.name     Send Message by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_SendMessage_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    int32_t refld = 1;
    ImsMessageInfo imsMessageInfo;
    imsMessageInfo.refId = refld;
    ret = imsSmsPtr_->ImsSendMessage(SIM_SLOT_ID_1, imsMessageInfo);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_GetImsRegistrationStatus_001
 * @tc.name     Get Ims Registration Status by Ims Service for slot 0
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_GetImsRegistrationStatus_001, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(DEFAULT_SLOTID)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCoreServicePtr_->GetImsRegistrationStatus(DEFAULT_SLOTID);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_ImsService_GetImsRegistrationStatus_002
 * @tc.name     Get Ims Registration Status by Ims Service for slot 1
 * @tc.desc     Function test
 */
HWTEST_F(ImsServiceTest, Telephony_ImsService_GetImsRegistrationStatus_002, Function | MediumTest | Level1)
{
    if ((ImsServiceTest::InitConditionCheck() != TELEPHONY_SUCCESS) || !HasSimCard(SIM_SLOT_ID_1)) {
        return;
    }
    int32_t ret = TELEPHONY_ERROR;
    ret = imsCoreServicePtr_->GetImsRegistrationStatus(SIM_SLOT_ID_1);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}
} // namespace Telephony
} // namespace OHOS

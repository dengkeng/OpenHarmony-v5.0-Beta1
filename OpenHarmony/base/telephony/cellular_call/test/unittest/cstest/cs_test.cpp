/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#define private public
#define protected public
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
const int32_t INVALID_HANG_UP_TYPE = -1;
const int32_t SUCCESS_RESULT = 0;
const int32_t ERROR_RESULT = 1;
const std::string PHONE_NUMBER = "0000000";
const std::string PHONE_NUMBER_SECOND = "1111111";
const std::string PHONE_NUMBER_THIRD = "2222222";
const int32_t CELLULAR_CALL_SUCCESS = 0;
const int32_t CELLULAR_CALL_ERROR = -1;
const int32_t USSD_MODE_NOTIFY = 0;

bool CsTest::HasSimCard(int32_t slotId)
{
    bool hasSimCard = false;
    DelayedRefSingleton<CoreServiceClient>::GetInstance().HasSimCard(slotId, hasSimCard);
    return hasSimCard;
}

void CsTest::SetUpTestCase(void)
{
    // step 3: Set Up Test Case
}

void CsTest::TearDownTestCase(void)
{
    // step 3: Tear Down Test Case
}

void CsTest::SetUp(void)
{
    // step 3: input testcase setup step
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::DIAL)] = &CsTest::Dial;
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::HANG_UP)] = &CsTest::HangUp;
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::REJECT)] = &CsTest::Reject;
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::ANSWER)] = &CsTest::Answer;
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::HOLD_CALL)] = &CsTest::HoldCall;
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::UN_HOLD_CALL)] = &CsTest::UnHoldCall;
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::SWITCH_CALL)] = &CsTest::SwitchCall;
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::EMERGENCY_CALL)] = &CsTest::IsEmergencyPhoneNumber;
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::COMBINE_CONFERENCE)] = &CsTest::CombineConference;
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::SEPARATE_CONFERENCE)] = &CsTest::SeparateConference;
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::INVITE_TO_CONFERENCE)] =
        &CsTest::InviteToConference;
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::KICK_OUT_CONFERENCE)] =
        &CsTest::KickOutFromConference;
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::HANG_UP_ALL_CONNECTION)] =
        &CsTest::HangUpAllConnection;
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::REGISTER_CALLBACK)] =
        &CsTest::RegisterCallBack;
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::UNREGISTER_CALLBACK)] =
        &CsTest::UnRegisterCallBack;
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::START_DTMF)] = &CsTest::StartDtmf;
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::STOP_DTMF)] = &CsTest::StopDtmf;
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::SEND_DTMF)] = &CsTest::SendDtmf;
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::START_RTT)] = &CsTest::StartRtt;
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::STOP_RTT)] = &CsTest::StopRtt;
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::SET_CALL_TRANSFER)] =
        &CsTest::SetCallTransferInfo;
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::GET_CALL_TRANSFER)] =
        &CsTest::GetCallTransferInfo;
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::SET_CALL_WAITING)] =
        &CsTest::SetCallWaiting;
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::GET_CALL_WAITING)] =
        &CsTest::GetCallWaiting;
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::SET_CALL_RESTRICTION)] =
        &CsTest::SetCallRestriction;
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::GET_CALL_RESTRICTION)] =
        &CsTest::GetCallRestriction;
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::SET_CALL_RESTRICTION_PWD)] =
        &CsTest::SetCallRestrictionPassword;
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::SET_MUTE)] = &CsTest::SetMute;
    requestFuncMap_[static_cast<int32_t>(CellularCallInterfaceCode::GET_MUTE)] = &CsTest::GetMute;
}

void CsTest::TearDown(void)
{
    // step 3: input testcase teardown step
}

int32_t CsTest::Dial(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test Dial entry.\n";
    CellularCallInfo callInfo;
    if (memset_s(&callInfo, sizeof(callInfo), 0, sizeof(callInfo)) != EOK) {
        std::cout << "CellularCallService return, memset_s failed. \n";
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    std::cout << "please enter the phone number:";
    std::cin >> callInfo.phoneNum;
    callInfo.videoState = 1;
    int32_t slotId = 0;
    std::cout << "please enter the slotId:(0   1)";
    std::cin >> slotId;
    callInfo.slotId = slotId;
    return telephonyService->Dial(callInfo);
}

int32_t CsTest::HangUp(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test HangUp entry.\n";
    CellularCallInfo callInfo;
    if (InitCallInfo(callInfo) != CELLULAR_CALL_SUCCESS) {
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    std::cout << "please enter the connect index:";
    std::cin >> callInfo.index;
    std::cout << "please enter the type:";
    int32_t type;
    std::cin >> type;
    return telephonyService->HangUp(callInfo, static_cast<CallSupplementType>(type));
}

int32_t CsTest::Answer(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test Answer entry.\n";
    CellularCallInfo callInfo;
    if (InitCallInfo(callInfo) != CELLULAR_CALL_SUCCESS) {
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    return telephonyService->Answer(callInfo);
}

int32_t CsTest::Reject(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test Reject entry.\n";
    CellularCallInfo callInfo;
    if (InitCallInfo(callInfo) != CELLULAR_CALL_SUCCESS) {
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    std::cout << "please enter the connect index:";
    std::cin >> callInfo.index;
    return telephonyService->Reject(callInfo);
}

int32_t CsTest::HoldCall(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test HoldCall entry.\n";
    CellularCallInfo callInfo;
    if (InitCallInfo(callInfo) != CELLULAR_CALL_SUCCESS) {
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    return telephonyService->HoldCall(callInfo);
}

int32_t CsTest::UnHoldCall(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test UnHoldCall entry.\n";
    CellularCallInfo callInfo;
    if (InitCallInfo(callInfo) != CELLULAR_CALL_SUCCESS) {
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    return telephonyService->UnHoldCall(callInfo);
}

int32_t CsTest::SwitchCall(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test SwitchCall entry.\n";
    CellularCallInfo callInfo;
    if (InitCallInfo(callInfo) != CELLULAR_CALL_SUCCESS) {
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    return telephonyService->SwitchCall(callInfo);
}

int32_t CsTest::IsEmergencyPhoneNumber(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test IsEmergencyPhoneNumber entry.\n";
    std::string phoneNum;
    std::cout << "input phoneNum: ";
    std::cin >> phoneNum;
    std::cout << "input slotId: ";
    int32_t slotId = 0;
    std::cin >> slotId;
    bool enabled = false;
    telephonyService->IsEmergencyPhoneNumber(slotId, phoneNum, enabled);
    return enabled;
}

int32_t CsTest::CombineConference(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test CombineConference entry." << std::endl;
    CellularCallInfo callInfo;
    if (InitCallInfo(callInfo) != CELLULAR_CALL_SUCCESS) {
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    return telephonyService->CombineConference(callInfo);
}

int32_t CsTest::SeparateConference(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test SeparateConference entry." << std::endl;
    CellularCallInfo callInfo;
    if (InitCallInfo(callInfo) != CELLULAR_CALL_SUCCESS) {
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    std::cout << "please enter the need split index:";
    std::cin >> callInfo.index;
    return telephonyService->SeparateConference(callInfo);
}

int32_t CsTest::InviteToConference(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test InviteToConference entry." << std::endl;
    std::vector<std::string> numberList;
    std::cout << "please enter the invite phone number:";
    std::string phoneNum;
    std::cin >> phoneNum;
    numberList.push_back(phoneNum);
    std::cout << "please enter the slotId:";
    int32_t slotId = 0;
    return telephonyService->InviteToConference(slotId, numberList);
}

int32_t CsTest::KickOutFromConference(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test KickOutFromConference entry." << std::endl;
    CellularCallInfo callInfo;
    if (InitCallInfo(callInfo) != CELLULAR_CALL_SUCCESS) {
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    std::cout << "please enter the need kick out index:";
    std::cin >> callInfo.index;
    return telephonyService->KickOutFromConference(callInfo);
}

int32_t CsTest::HangUpAllConnection(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test HangUpAllConnection entry." << std::endl;
    return telephonyService->HangUpAllConnection();
}

int32_t CsTest::RegisterCallBack(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test RegisterCallBack entry.\n";
    return CELLULAR_CALL_SUCCESS;
}

int32_t CsTest::UnRegisterCallBack(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test UnRegisterCallBack entry.\n";
    return telephonyService->UnRegisterCallManagerCallBack();
}

int32_t CsTest::StartDtmf(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test StartDtmf entry." << std::endl;
    CellularCallInfo callInfo;
    if (InitCallInfo(callInfo) != CELLULAR_CALL_SUCCESS) {
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    std::cout << "please enter the index:";
    std::cin >> callInfo.index;
    char cDtmfCode;
    std::cout << "please enter the Dtmf code:";
    std::cin >> cDtmfCode;
    return telephonyService->StartDtmf(cDtmfCode, callInfo);
}

int32_t CsTest::StopDtmf(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test StopDtmf entry." << std::endl;
    CellularCallInfo callInfo;
    if (InitCallInfo(callInfo) != CELLULAR_CALL_SUCCESS) {
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    std::cout << "please enter the index:";
    std::cin >> callInfo.index;
    return telephonyService->StopDtmf(callInfo);
}

int32_t CsTest::SendDtmf(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test SendDtmf entry." << std::endl;
    CellularCallInfo callInfo;
    if (InitCallInfo(callInfo) != CELLULAR_CALL_SUCCESS) {
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    std::cout << "please enter the index:";
    std::cin >> callInfo.index;
    char cDtmfCode;
    std::cout << "please enter the Dtmf code:";
    std::cin >> cDtmfCode;
    return telephonyService->SendDtmf(cDtmfCode, callInfo);
}

int32_t CsTest::StartRtt(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test StartRtt entry." << std::endl;
    std::string msg;
    std::cout << "please enter the send msg:";
    std::cin >> msg;
    int32_t slotId;
    std::cout << "please enter the slotId:";
    std::cin >> slotId;
    return telephonyService->StartRtt(slotId, msg);
}

int32_t CsTest::StopRtt(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test StopRtt entry." << std::endl;
    int32_t slotId;
    std::cout << "please enter the slotId:";
    std::cin >> slotId;
    return telephonyService->StopRtt(slotId);
}

int32_t CsTest::SetCallTransferInfo(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test SetCallTransferInfoInfo entry.\n";
    int32_t slotId = 0;
    std::cout << "please enter the slotId:(0   1)";
    std::cin >> slotId;
    CallTransferInfo callTransferInfo;
    std::cout << "please enter the transfer type(0 - 5):";
    int32_t type = 0;
    std::cin >> type;
    callTransferInfo.type = static_cast<CallTransferType>(type);
    std::cout << "please enter the transfer setting type(0 - 4):";
    int32_t settingType = 0;
    std::cin >> settingType;
    callTransferInfo.settingType = static_cast<CallTransferSettingType>(settingType);
    std::cout << "please enter the phone number:";
    std::cin >> callTransferInfo.transferNum;
    return telephonyService->SetCallTransferInfo(slotId, callTransferInfo);
}

int32_t CsTest::GetCallTransferInfo(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test GetCallTransferInfo entry.\n";
    int32_t slotId = 0;
    std::cout << "please enter the slotId:(0   1)";
    std::cin >> slotId;
    std::cout << "please enter the transfer type(0 - 5):";
    int32_t type = 0;
    std::cin >> type;
    return telephonyService->GetCallTransferInfo(slotId, static_cast<CallTransferType>(type));
}

int32_t CsTest::SetCallWaiting(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test SetCallWaiting entry.\n";
    bool activate = true;
    int32_t slotId = 0;
    std::cout << "please enter the slotId:(0   1)";
    std::cin >> slotId;
    return telephonyService->SetCallWaiting(slotId, activate);
}

int32_t CsTest::GetCallWaiting(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test GetCallWaiting entry.\n";
    int32_t slotId = 0;
    std::cout << "please enter the slotId:(0   1)";
    std::cin >> slotId;
    return telephonyService->GetCallWaiting(slotId);
}

int32_t CsTest::SetCallRestriction(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test SetCallRestriction entry.\n";
    int32_t slotId = 0;
    std::cout << "please enter the slotId:(0   1)";
    std::cin >> slotId;
    CallRestrictionInfo info;
    std::cout << "please enter the fac(0 - 4):";
    int32_t fac = 0;
    std::cin >> fac;
    info.fac = static_cast<CallRestrictionType>(fac);
    std::cout << "please enter the phone password:";
    std::cin >> info.password;
    std::cout << "please enter the mode:";
    int32_t mode = 0;
    std::cin >> mode;
    info.mode = static_cast<CallRestrictionMode>(mode);
    return telephonyService->SetCallRestriction(slotId, info);
}

int32_t CsTest::GetCallRestriction(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test GetCallRestriction entry.\n";
    int32_t slotId = 0;
    std::cout << "please enter the slotId:(0   1)";
    std::cin >> slotId;
    std::cout << "please enter the fac(0 - 4):";
    int32_t facType = 0;
    std::cin >> facType;
    return telephonyService->GetCallRestriction(slotId, static_cast<CallRestrictionType>(facType));
}

int32_t CsTest::SetCallRestrictionPassword(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test SetCallRestrictionPassword entry.\n";
    int32_t slotId = 0;
    std::cout << "please enter the slotId:(0   1)";
    std::cin >> slotId;
    std::cout << "please enter the fac(0 - 4):";
    int32_t fac = 0;
    std::cin >> fac;
    CallRestrictionType facType = static_cast<CallRestrictionType>(fac);
    std::cout << "please enter the old password:";
    char oldPassword[kMaxNumberLen + 1] = { 0 };
    std::cin >> oldPassword;
    std::cout << "please enter the new password:";
    char newPassword[kMaxNumberLen + 1] = { 0 };
    std::cin >> newPassword;
    int32_t ret = telephonyService->SetCallRestrictionPassword(slotId, facType, oldPassword, newPassword);
    (void)memset_s(oldPassword, sizeof(oldPassword), 0, sizeof(oldPassword));
    (void)memset_s(newPassword, sizeof(newPassword), 0, sizeof(newPassword));
    return ret;
}

int32_t CsTest::SetMute(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test SetMute entry.\n";
    int32_t slotId = 0;
    std::cout << "please enter the slotId:(0   1)";
    std::cin >> slotId;
    std::cout << "please enter the mute(0 - 1):";
    int32_t mute = -1;
    std::cin >> mute;
    return telephonyService->SetMute(slotId, mute);
}

int32_t CsTest::GetMute(const sptr<CellularCallInterface> &telephonyService) const
{
    std::cout << "test GetMute entry.\n";
    int32_t slotId = 0;
    std::cout << "please enter the slotId:(0   1)";
    std::cin >> slotId;
    return telephonyService->GetMute(slotId);
}

void CsTest::JudgeIsEmergencyPhoneNumber()
{
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto remote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(remote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(remote);
    ASSERT_TRUE(telephonyService != nullptr);

    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    bool enabled = false;
    int32_t successCode = 1;
    if (HasSimCard(SIM1_SLOTID)) {
        telephonyService->IsEmergencyPhoneNumber(SIM1_SLOTID, "499", enabled);
        EXPECT_NE(enabled, successCode);
        telephonyService->IsEmergencyPhoneNumber(SIM1_SLOTID, "443", enabled);
        EXPECT_NE(enabled, successCode);
        telephonyService->IsEmergencyPhoneNumber(SIM1_SLOTID, "356", enabled);
        EXPECT_NE(enabled, successCode);
        telephonyService->IsEmergencyPhoneNumber(SIM1_SLOTID, "975", enabled);
        EXPECT_NE(enabled, successCode);
        telephonyService->IsEmergencyPhoneNumber(SIM1_SLOTID, "783", enabled);
        EXPECT_NE(enabled, successCode);
        telephonyService->IsEmergencyPhoneNumber(SIM1_SLOTID, "350", enabled);
        EXPECT_NE(enabled, successCode);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        telephonyService->IsEmergencyPhoneNumber(SIM2_SLOTID, "499", enabled);
        EXPECT_NE(enabled, successCode);
        telephonyService->IsEmergencyPhoneNumber(SIM2_SLOTID, "443", enabled);
        EXPECT_NE(enabled, successCode);
        telephonyService->IsEmergencyPhoneNumber(SIM2_SLOTID, "356", enabled);
        EXPECT_NE(enabled, successCode);
        telephonyService->IsEmergencyPhoneNumber(SIM2_SLOTID, "975", enabled);
        EXPECT_NE(enabled, successCode);
        telephonyService->IsEmergencyPhoneNumber(SIM2_SLOTID, "783", enabled);
        EXPECT_NE(enabled, successCode);
        telephonyService->IsEmergencyPhoneNumber(SIM2_SLOTID, "350", enabled);
        EXPECT_NE(enabled, successCode);
    }
}

int32_t CsTest::InputNumForInterface(const sptr<CellularCallInterface> &telephonyService) const
{
    int32_t ret = -1;
    bool loopFlag = true;
    int32_t InputNumber = 0;
    int32_t returnNum = 1000; // end loop variable value
    while (loopFlag) {
        std::cout << "\n**********Unit Test Start**********\n"
                     "Usage: please input a cmd num:\n"
                     "1:Dial\n2:HangUp\n3:Reject\n4:Answer\n5:HoldCall\n6:UnHoldCall\n7:SwitchCall\n"
                     "8:IsEmergencyPhoneNumber\n10:CombineConference\n11:SeparateConference\n12:InviteToConference\n"
                     "13:KickOutFromConference\n14:HangUpAllConnection\n"
                     "17:RegisterCallBack\n18:UnRegisterCallBack\n100:StartDtmf\n101:StopDtmf\n102:SendDtmf\n"
                     "104:StartRtt\n105:StopRtt\n200:SetCallTransferInfo\n201:GetCallTransferInfo\n"
                     "203:SetCallWaiting\n204:GetCallWaiting\n205:SetCallRestriction\n"
                     "206:GetCallRestriction\n208:SetCallRestrictionPassword\n309:SetMute\n310:GetMute\n"
                     "1000:Exit\n"
                     "***********************************\n"
                     "Your choice: ";
        std::cin >> InputNumber;
        if (InputNumber == returnNum) {
            std::cout << "exiting...\n";
            break;
        }
        auto itFunc = requestFuncMap_.find(InputNumber);
        if (itFunc != requestFuncMap_.end()) {
            auto requestFunc = itFunc->second;
            if (requestFunc != nullptr) {
                ret = (this->*requestFunc)(telephonyService);
            }
        }
        if (ret != CELLULAR_CALL_SUCCESS) {
            std::cout << "this execution did not return a successful value, please check.\n";
            return ret;
        }
    }
    return CELLULAR_CALL_SUCCESS;
}

int32_t CsTest::InitCallInfo(CellularCallInfo &callInfo) const
{
    if (memset_s(&callInfo, sizeof(callInfo), 0, sizeof(callInfo)) != EOK) {
        std::cout << "CellularCallService return, memset_s failed. \n";
        return CELLULAR_CALL_ERROR;
    }

    std::cout << "please enter the phone number:";
    std::cin >> callInfo.phoneNum;
    callInfo.videoState = 1;
    std::cout << "please enter the call type(0:CS  1:IMS):";
    int32_t callType = 0;
    std::cin >> callType;
    callInfo.callType = static_cast<CallType>(callType);
    int32_t slotId = 0;
    std::cout << "please enter the slotId:(0   1)";
    std::cin >> slotId;
    callInfo.slotId = slotId;
    return CELLULAR_CALL_SUCCESS;
}

/**
 * @tc.number   cellular_call_cs_test_001
 * @tc.name     Test the corresponding functions by entering commands, such as 1 -- Dial, 2 -- Hangup, 3 -- Reject, etc
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_cs_test_001, Function | MediumTest | Level0)
{
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto remote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(remote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(remote);
    ASSERT_TRUE(telephonyService != nullptr);
    std::cout << "HWTEST_F cellular_call_cs_test_001";
}

/**
 * @tc.number   cellular_call_cs_test_002
 * @tc.name     Test the corresponding functions by entering commands, such as 1 -- Dial, 2 -- Hangup, 3 -- Reject, etc
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_cs_test_002, Function | MediumTest | Level1)
{
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto remote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(remote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(remote);
    ASSERT_TRUE(telephonyService != nullptr);
    std::cout << "HWTEST_F cellular_call_cs_test_002";
}

/**
 * @tc.number   Telephony_CallManager_SetEmergencyCallList_0101
 * @tc.name     SetEmergencyCallList "443,356,789",test SetEmergencyCallList(),return success
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_SetEmergencyCallList_0101, Function | MediumTest | Level3)
{
    AccessToken token;
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto emergencyRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(emergencyRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(emergencyRemote);
    ASSERT_TRUE(telephonyService != nullptr);

    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }

    std::vector<EmergencyCall> eccVec;
    EmergencyCall temp0 = { "499", "460", EccType::TYPE_CATEGORY, SimpresentType::TYPE_NO_CARD,
        AbnormalServiceType::TYPE_ALL };
    EmergencyCall temp1 = { "443", "460", EccType::TYPE_POLICE, SimpresentType::TYPE_NO_CARD,
        AbnormalServiceType::TYPE_ALL };
    EmergencyCall temp2 = { "356", "460", EccType::TYPE_AMBULANCE, SimpresentType::TYPE_NO_CARD,
        AbnormalServiceType::TYPE_ALL };
    EmergencyCall temp3 = { "783", "460", EccType::TYPE_FIRE, SimpresentType::TYPE_NO_CARD,
        AbnormalServiceType::TYPE_ALL };
    EmergencyCall temp4 = { "975", "460", EccType::TYPE_SEA, SimpresentType::TYPE_HAS_CARD,
        AbnormalServiceType::TYPE_ONLY_CS };
    EmergencyCall temp5 = { "350", "460", EccType::TYPE_MOUNTAIN, SimpresentType::TYPE_HAS_CARD,
        AbnormalServiceType::TYPE_ALL };
    eccVec.push_back(temp0);
    eccVec.push_back(temp1);
    eccVec.push_back(temp2);
    eccVec.push_back(temp3);
    eccVec.push_back(temp4);
    eccVec.push_back(temp5);
    if (HasSimCard(SIM1_SLOTID)) {
        EXPECT_EQ(telephonyService->SetEmergencyCallList(SIM1_SLOTID, eccVec), 0);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        EXPECT_EQ(telephonyService->SetEmergencyCallList(SIM2_SLOTID, eccVec), 0);
    }
    JudgeIsEmergencyPhoneNumber();
}

HWTEST_F(CsTest, cellular_call_IsOperatorConfigEmergencyCallList_0001, Function | MediumTest | Level3)
{
    AccessToken token;
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto operatorRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(operatorRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(operatorRemote);
    ASSERT_TRUE(telephonyService != nullptr);

    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    OperatorConfig opc;
    if (HasSimCard(SIM1_SLOTID)) {
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetOperatorConfigs(SIM1_SLOTID, opc);
        if (opc.stringArrayValue.find(KEY_EMERGENCY_CALL_STRING_ARRAY) != opc.stringArrayValue.end()) {
            for (auto number : opc.stringArrayValue[KEY_EMERGENCY_CALL_STRING_ARRAY]) {
                bool enabled = false;
                int32_t errorCode = telephonyService->IsEmergencyPhoneNumber(SIM1_SLOTID, number, enabled);
                EXPECT_EQ(TELEPHONY_SUCCESS, errorCode);
            }
        }
    }
    if (HasSimCard(SIM2_SLOTID)) {
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetOperatorConfigs(SIM2_SLOTID, opc);
        if (opc.stringArrayValue.find(KEY_EMERGENCY_CALL_STRING_ARRAY) != opc.stringArrayValue.end()) {
            for (auto number : opc.stringArrayValue[KEY_EMERGENCY_CALL_STRING_ARRAY]) {
                bool enabled = false;
                int32_t errorCode = telephonyService->IsEmergencyPhoneNumber(SIM2_SLOTID, number, enabled);
                EXPECT_EQ(TELEPHONY_SUCCESS, errorCode);
            }
        }
    }
}

/**
 * @tc.number   cellular_call_GetDomainPreferenceMode_0001
 * @tc.name     Test for GetDomainPreferenceMode function by invalid slotId
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_GetDomainPreferenceMode_0001, Function | MediumTest | Level3)
{
    AccessToken token;
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto domainPrefModeRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(domainPrefModeRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(domainPrefModeRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = telephonyService->GetDomainPreferenceMode(INVALID_SLOTID);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = telephonyService->GetDomainPreferenceMode(INVALID_SLOTID);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
}

/**
 * @tc.number   cellular_call_GetDomainPreferenceMode_0002
 * @tc.name     Test for GetDomainPreferenceMode function by valid slotId
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_GetDomainPreferenceMode_0002, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto domainPrefModeRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(domainPrefModeRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(domainPrefModeRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = telephonyService->GetDomainPreferenceMode(SIM1_SLOTID);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = telephonyService->GetDomainPreferenceMode(SIM2_SLOTID);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_GetMute_0001
 * @tc.name     Test for GetMute function by invalid slotId
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_GetMute_0001, Function | MediumTest | Level3)
{
    AccessToken token;
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto getMuteRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(getMuteRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(getMuteRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = telephonyService->GetMute(INVALID_SLOTID);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = telephonyService->GetMute(INVALID_SLOTID);
        EXPECT_EQ(ret, CALL_ERR_INVALID_SLOT_ID);
    }
}

/**
 * @tc.number   cellular_call_GetMute_0002
 * @tc.name     Test for GetMute function by valid slotId
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_GetMute_0002, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto getMuteRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(getMuteRemote != nullptr);
    auto telephonyService = iface_cast<CellularCallInterface>(getMuteRemote);
    ASSERT_TRUE(telephonyService != nullptr);
    if (HasSimCard(SIM1_SLOTID)) {
        int32_t ret = telephonyService->GetMute(SIM1_SLOTID);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
    if (HasSimCard(SIM2_SLOTID)) {
        int32_t ret = telephonyService->GetMute(SIM2_SLOTID);
        EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_CsControl_0001
 * @tc.name     Test for CsControl
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_CsControl_0001, Function | MediumTest | Level3)
{
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto csControlRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(csControlRemote != nullptr);
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    auto csControl = std::make_shared<CSControl>();
    CellularCallInfo cellularCallInfo;
    bool enabled = false;
    EXPECT_EQ(InitCellularCallInfo(INVALID_SLOTID, PHONE_NUMBER, cellularCallInfo), TELEPHONY_SUCCESS);
    EXPECT_EQ(csControl->Dial(cellularCallInfo, enabled), CALL_ERR_GET_RADIO_STATE_FAILED);
    EXPECT_EQ(InitCellularCallInfo(INVALID_SLOTID, "", cellularCallInfo), TELEPHONY_SUCCESS);
    EXPECT_EQ(csControl->Dial(cellularCallInfo, enabled), CALL_ERR_PHONE_NUMBER_EMPTY);
    for (int32_t slotId = 0; slotId < SIM_SLOT_COUNT; slotId++) {
        if (!HasSimCard(slotId)) {
            continue;
        }
        EXPECT_EQ(InitCellularCallInfo(slotId, "*30#", cellularCallInfo), TELEPHONY_SUCCESS);
        EXPECT_EQ(csControl->DialCdma(cellularCallInfo), CALL_ERR_RESOURCE_UNAVAILABLE);
        EXPECT_EQ(csControl->DialGsm(cellularCallInfo), CALL_ERR_RESOURCE_UNAVAILABLE);
        EXPECT_EQ(InitCellularCallInfo(slotId, "#30#", cellularCallInfo), TELEPHONY_SUCCESS);
        EXPECT_EQ(csControl->DialGsm(cellularCallInfo), CALL_ERR_RESOURCE_UNAVAILABLE);
        EXPECT_EQ(InitCellularCallInfo(slotId, PHONE_NUMBER, cellularCallInfo), TELEPHONY_SUCCESS);
        EXPECT_EQ(csControl->DialCdma(cellularCallInfo), CALL_ERR_RESOURCE_UNAVAILABLE);
        EXPECT_EQ(csControl->Dial(cellularCallInfo, enabled), CALL_ERR_GET_RADIO_STATE_FAILED);
        ASSERT_FALSE(csControl->CalculateInternationalRoaming(slotId));
        EXPECT_NE(csControl->DialCdma(cellularCallInfo), TELEPHONY_SUCCESS);
        EXPECT_EQ(csControl->DialGsm(cellularCallInfo), CALL_ERR_RESOURCE_UNAVAILABLE);
        EXPECT_NE(csControl->Answer(cellularCallInfo), CALL_ERR_RESOURCE_UNAVAILABLE);
        EXPECT_EQ(InitCellularCallInfo(slotId, PHONE_NUMBER_SECOND, cellularCallInfo), TELEPHONY_SUCCESS);
        EXPECT_NE(csControl->Answer(cellularCallInfo), CALL_ERR_CALL_STATE);
        EXPECT_EQ(InitCellularCallInfo(slotId, PHONE_NUMBER_THIRD, cellularCallInfo), TELEPHONY_SUCCESS);
        EXPECT_NE(csControl->Answer(cellularCallInfo), CALL_ERR_CALL_STATE);
        EXPECT_NE(csControl->Reject(cellularCallInfo), CALL_ERR_CALL_STATE);
        EXPECT_EQ(InitCellularCallInfo(slotId, PHONE_NUMBER, cellularCallInfo), TELEPHONY_SUCCESS);
        EXPECT_EQ(csControl->SeparateConference(slotId, PHONE_NUMBER, 1), CALL_ERR_RESOURCE_UNAVAILABLE);
        EXPECT_EQ(csControl->SeparateConference(slotId, "", 1), CALL_ERR_RESOURCE_UNAVAILABLE);
        EXPECT_NE(csControl->HangUp(cellularCallInfo, CallSupplementType::TYPE_DEFAULT), CALL_ERR_RESOURCE_UNAVAILABLE);
        EXPECT_EQ(csControl->HangUp(cellularCallInfo, CallSupplementType::TYPE_HANG_UP_ACTIVE),
            CALL_ERR_RESOURCE_UNAVAILABLE);
        EXPECT_EQ(
            csControl->HangUp(cellularCallInfo, CallSupplementType::TYPE_HANG_UP_ALL), CALL_ERR_RESOURCE_UNAVAILABLE);
        EXPECT_EQ(csControl->HangUp(cellularCallInfo, static_cast<CallSupplementType>(INVALID_HANG_UP_TYPE)),
            TELEPHONY_ERR_ARGUMENT_INVALID);
    }
}

/**
 * @tc.number   cellular_call_CsControl_0002
 * @tc.name     Test for CsControl
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_CsControl_0002, Function | MediumTest | Level3)
{
    auto csControl = std::make_shared<CSControl>();
    CellularCallInfo cellularCallInfo;
    for (int32_t slotId = 0; slotId < SIM_SLOT_COUNT; slotId++) {
        if (!HasSimCard(slotId)) {
            continue;
        }
        CallInfoList callList;
        callList.callSize = 0;
        EXPECT_EQ(csControl->ReportCallsData(slotId, callList), TELEPHONY_ERROR);
        EXPECT_NE(csControl->ReportUpdateInfo(slotId, callList), TELEPHONY_SUCCESS);
        CallInfo callInfo;
        callList.callSize = 1;
        callInfo.number = PHONE_NUMBER;
        callInfo.index = 1;
        callInfo.state = static_cast<int32_t>(TelCallState::CALL_STATUS_INCOMING);
        callList.calls.push_back(callInfo);
        EXPECT_EQ(csControl->ReportCallsData(slotId, callList), TELEPHONY_SUCCESS);
        callList.callSize = 2;
        callInfo.state = static_cast<int32_t>(TelCallState::CALL_STATUS_ACTIVE);
        callInfo.number = PHONE_NUMBER_SECOND;
        callInfo.index = 2;
        callList.calls.push_back(callInfo);
        callList.callSize = 3;
        callInfo.state = static_cast<int32_t>(TelCallState::CALL_STATUS_DISCONNECTED);
        callInfo.number = PHONE_NUMBER_THIRD;
        callInfo.index = 3;
        callList.calls.push_back(callInfo);
        callList.callSize = 0;
        EXPECT_EQ(csControl->ReportCallsData(slotId, callList), TELEPHONY_SUCCESS);
        EXPECT_NE(csControl->ReportCallsData(slotId, callList), TELEPHONY_SUCCESS);
        EXPECT_NE(csControl->Reject(cellularCallInfo), CALL_ERR_RESOURCE_UNAVAILABLE);
        EXPECT_NE(csControl->HoldCall(slotId), CALL_ERR_CALL_STATE);
        EXPECT_NE(csControl->UnHoldCall(slotId), CALL_ERR_CALL_STATE);
        EXPECT_NE(csControl->SwitchCall(slotId), CALL_ERR_CALL_STATE);
    }
}

/**
 * @tc.number   cellular_call_CellularCallConnectionCS_0001
 * @tc.name     Test for CellularCallConnectionCS
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_CellularCallConnectionCS_0001, Function | MediumTest | Level3)
{
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto remote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(remote != nullptr);
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }

    for (int32_t slotId = 0; slotId < SIM_SLOT_COUNT; slotId++) {
        if (!HasSimCard(slotId)) {
            continue;
        }
        CellularCallConnectionCS csConnection;
        EXPECT_EQ(csConnection.SendDtmfRequest(slotId, '1', 1), CALL_ERR_RESOURCE_UNAVAILABLE);
        EXPECT_EQ(csConnection.StartDtmfRequest(slotId, '1', 1), CALL_ERR_RESOURCE_UNAVAILABLE);
        EXPECT_EQ(csConnection.StopDtmfRequest(slotId, 1), CALL_ERR_RESOURCE_UNAVAILABLE);
        EXPECT_EQ(csConnection.GetCsCallsDataRequest(slotId, 1), CALL_ERR_RESOURCE_UNAVAILABLE);
        EXPECT_EQ(csConnection.GetCallFailReasonRequest(slotId), CALL_ERR_RESOURCE_UNAVAILABLE);
        MMICodeUtils utils;
        ASSERT_FALSE(utils.IsNeedExecuteMmi("", false));
        ASSERT_FALSE(utils.ExecuteMmiCode(slotId));
    }
}

/**
 * @tc.number   cellular_call_CellularCallRegister_0001
 * @tc.name     Test for CellularCallRegister
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_CellularCallRegister_0001, Function | MediumTest | Level3)
{
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(systemAbilityMgr != nullptr);
    auto cellularCallRemote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
    ASSERT_TRUE(cellularCallRemote != nullptr);
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    auto callRegister = DelayedSingleton<CellularCallRegister>::GetInstance();
    ASSERT_TRUE(callRegister != nullptr);
    CellularCallEventInfo callEvent;
    callRegister->ReportEventResultInfo(callEvent);
    CallWaitResponse waitResponse;
    callRegister->ReportGetWaitingResult(waitResponse);
    callRegister->ReportSetWaitingResult(ERROR_RESULT);
    CallRestrictionResponse restrictionResponse;
    callRegister->ReportGetRestrictionResult(restrictionResponse);
    callRegister->ReportSetRestrictionResult(ERROR_RESULT);
    callRegister->ReportSetBarringPasswordResult(ERROR_RESULT);
    CallTransferResponse transferResponse;
    callRegister->ReportGetTransferResult(transferResponse);
    callRegister->ReportSetTransferResult(ERROR_RESULT);
    ClipResponse clipResponse;
    callRegister->ReportGetClipResult(clipResponse);
    ClirResponse clirResponse;
    callRegister->ReportGetClirResult(clirResponse);
    callRegister->ReportSetClirResult(ERROR_RESULT);
    callRegister->ReportCallRingBackResult(ERROR_RESULT);
    DisconnectedDetails details;
    callRegister->ReportCallFailReason(details);
    MuteControlResponse muteResponse;
    callRegister->ReportSetMuteResult(muteResponse);
    callRegister->ReportGetMuteResult(muteResponse);
    callRegister->ReportInviteToConferenceResult(ERROR_RESULT);
    callRegister->ReportGetCallDataResult(ERROR_RESULT);
    callRegister->ReportStartDtmfResult(ERROR_RESULT);
    callRegister->ReportStopDtmfResult(ERROR_RESULT);
    callRegister->ReportStartRttResult(ERROR_RESULT);
    callRegister->ReportStopRttResult(ERROR_RESULT);
    callRegister->ReportSendUssdResult(ERROR_RESULT);
    SetEccListResponse eccListResponse;
    callRegister->ReportSetEmergencyCallListResponse(eccListResponse);
    MmiCodeInfo mmiInfo;
    callRegister->ReportMmiCodeResult(mmiInfo);
    ASSERT_FALSE(callRegister->IsCallManagerCallBackRegistered());
}

/**
 * @tc.number   cellular_call_CellularCallRegister_0002
 * @tc.name     Test for CellularCallRegister
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_CellularCallRegister_0002, Function | MediumTest | Level3)
{
    auto callRegister = DelayedSingleton<CellularCallRegister>::GetInstance();
    CallReportInfo callRepotInfo;
    callRepotInfo.callType = CallType::TYPE_CS;
    callRepotInfo.accountId = INVALID_SLOTID;
    callRepotInfo.state = TelCallState::CALL_STATUS_INCOMING;
    callRepotInfo.callMode = VideoStateType::TYPE_VOICE;
    CallsReportInfo calls;
    calls.slotId = INVALID_SLOTID;
    calls.callVec.push_back(callRepotInfo);
    callRegister->ReportCallsInfo(calls);
    callRegister->ReportSingleCallInfo(callRepotInfo, TelCallState::CALL_STATUS_INCOMING);
    EXPECT_EQ(callRegister->RegisterCallManagerCallBack(nullptr), TELEPHONY_SUCCESS);
    EXPECT_EQ(callRegister->UnRegisterCallManagerCallBack(), TELEPHONY_SUCCESS);
}

/**
 * @tc.number   cellular_call_SupplementRequestCs_0001
 * @tc.name     Test for SupplementRequestCs
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_SupplementRequestCs_0001, Function | MediumTest | Level3)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }

    for (int32_t slotId = 0; slotId < SIM_SLOT_COUNT; slotId++) {
        if (!HasSimCard(slotId)) {
            continue;
        }
        SupplementRequestCs request;
        std::string fac = "fac";
        std::string pw = "test";
        int32_t index = 1;
        int32_t mode = 1;
        int32_t classType = 1;
        const char *oldPassword = "oldpwd";
        const char *newPassword = "newpwd";
        bool active = true;
        CallTransferParam param;
        EXPECT_NE(request.GetCallRestrictionRequest(slotId, fac, index), TELEPHONY_SUCCESS);
        EXPECT_NE(request.SetCallRestrictionRequest(slotId, fac, mode, pw, index), TELEPHONY_SUCCESS);
        EXPECT_NE(request.SetBarringPasswordRequest(slotId, fac, index, oldPassword, newPassword), TELEPHONY_SUCCESS);
        EXPECT_NE(request.GetCallWaitingRequest(slotId, index), TELEPHONY_SUCCESS);
        EXPECT_NE(request.SetCallWaitingRequest(slotId, active, classType, index), TELEPHONY_SUCCESS);
        EXPECT_NE(request.GetClipRequest(slotId, index), TELEPHONY_SUCCESS);
        EXPECT_NE(request.GetClirRequest(slotId, index), TELEPHONY_SUCCESS);
        EXPECT_NE(request.SetClirRequest(slotId, mode, index), TELEPHONY_SUCCESS);
        EXPECT_NE(request.GetCallTransferRequest(slotId, mode, index), TELEPHONY_SUCCESS);
        EXPECT_NE(request.SetCallTransferRequest(slotId, param, index), TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_ConfigRequest_0001
 * @tc.name     Test for ConfigRequest
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_ConfigRequest_0001, Function | MediumTest | Level3)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }

    for (int32_t slotId = 0; slotId < SIM_SLOT_COUNT; slotId++) {
        if (!HasSimCard(slotId)) {
            continue;
        }
        ConfigRequest config;
        int32_t mode = 1;
        EXPECT_NE(config.SetDomainPreferenceModeRequest(slotId, mode), TELEPHONY_SUCCESS);
        EXPECT_NE(config.GetDomainPreferenceModeRequest(slotId), TELEPHONY_SUCCESS);
        EXPECT_NE(config.SetMuteRequest(slotId, mode), TELEPHONY_SUCCESS);
        EXPECT_NE(config.GetMuteRequest(slotId), TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_CellularCallSupplement_0001
 * @tc.name     Test for CellularCallSupplement
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_CellularCallSupplement_0001, Function | MediumTest | Level3)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }

    for (int32_t slotId = 0; slotId < SIM_SLOT_COUNT; slotId++) {
        if (!HasSimCard(slotId)) {
            continue;
        }
        MMIData mmiData;
        CellularCallSupplement supplement;
        mmiData.actionString = "";
        supplement.AlterPinPassword(slotId, mmiData);
        supplement.AlterPin2Password(slotId, mmiData);
        supplement.UnlockPuk(slotId, mmiData);
        supplement.UnlockPuk2(slotId, mmiData);
        mmiData.actionString = "test";
        mmiData.serviceInfoA = "infoA";
        mmiData.serviceInfoB = "infoB";
        mmiData.serviceInfoC = "infoC";
        supplement.AlterPinPassword(slotId, mmiData);
        supplement.AlterPin2Password(slotId, mmiData);
        supplement.UnlockPuk(slotId, mmiData);
        supplement.UnlockPuk2(slotId, mmiData);
        mmiData.serviceInfoC = "infoB";
        supplement.AlterPinPassword(slotId, mmiData);
        supplement.AlterPin2Password(slotId, mmiData);
        supplement.UnlockPuk(slotId, mmiData);
        supplement.UnlockPuk2(slotId, mmiData);
        ASSERT_FALSE(supplement.IsVaildPinOrPuk("B", "B"));
        EXPECT_NE(supplement.SendUssd(slotId, "test"), TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_CellularCallSupplement_0002
 * @tc.name     Test for CellularCallSupplement
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_CellularCallSupplement_0002, Function | MediumTest | Level3)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }

    for (int32_t slotId = 0; slotId < SIM_SLOT_COUNT; slotId++) {
        if (!HasSimCard(slotId)) {
            continue;
        }
        CellularCallSupplement supplement;
        supplement.ObtainBarringInstallation("33");
        supplement.ObtainBarringInstallation("331");
        supplement.ObtainBarringInstallation("332");
        supplement.ObtainBarringInstallation("351");
        supplement.ObtainBarringInstallation("35");
        supplement.ObtainBarringInstallation("330");
        supplement.ObtainBarringInstallation("333");
        supplement.ObtainBarringInstallation("353");
        supplement.ObtainBarringInstallation("1000");

        EXPECT_NE(supplement.ObtainServiceCode("10"), TELEPHONY_SUCCESS);
        EXPECT_NE(supplement.ObtainServiceCode("11"), TELEPHONY_SUCCESS);
        EXPECT_NE(supplement.ObtainServiceCode("12"), TELEPHONY_SUCCESS);
        EXPECT_NE(supplement.ObtainServiceCode("13"), TELEPHONY_SUCCESS);
        EXPECT_NE(supplement.ObtainServiceCode("16"), TELEPHONY_SUCCESS);
        EXPECT_NE(supplement.ObtainServiceCode("19"), TELEPHONY_SUCCESS);
        EXPECT_NE(supplement.ObtainServiceCode("20"), TELEPHONY_SUCCESS);
        EXPECT_NE(supplement.ObtainServiceCode("21"), TELEPHONY_SUCCESS);
        EXPECT_NE(supplement.ObtainServiceCode("22"), TELEPHONY_SUCCESS);
        EXPECT_NE(supplement.ObtainServiceCode("24"), TELEPHONY_SUCCESS);
        EXPECT_NE(supplement.ObtainServiceCode("25"), TELEPHONY_SUCCESS);
        EXPECT_NE(supplement.ObtainServiceCode("99"), TELEPHONY_SUCCESS);
        EXPECT_EQ(supplement.ObtainServiceCode("100"), TELEPHONY_SUCCESS);

        EXPECT_EQ(supplement.ObtainCause("21"), TELEPHONY_SUCCESS);
        EXPECT_NE(supplement.ObtainCause("61"), TELEPHONY_SUCCESS);
        EXPECT_NE(supplement.ObtainCause("62"), TELEPHONY_SUCCESS);
        EXPECT_NE(supplement.ObtainCause("67"), TELEPHONY_SUCCESS);
        EXPECT_EQ(supplement.ObtainCause("99"), TELEPHONY_ERROR);
    }
}

/**
 * @tc.number   cellular_call_CellularCallSupplement_0003
 * @tc.name     Test for CellularCallSupplement
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_CellularCallSupplement_0003, Function | MediumTest | Level3)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }

    for (int32_t slotId = 0; slotId < SIM_SLOT_COUNT; slotId++) {
        if (!HasSimCard(slotId)) {
            continue;
        }
        CellularCallSupplement supplement;
        std::string action = "*";
        std::string number = "";
        CallTransferSettingType type;
        EXPECT_EQ(supplement.ObtainCallTrasferAction(action.c_str(), number, type), TELEPHONY_SUCCESS);
        EXPECT_EQ(supplement.ObtainCallTrasferAction(action.c_str(), PHONE_NUMBER, type), TELEPHONY_SUCCESS);
        action = "#";
        EXPECT_EQ(supplement.ObtainCallTrasferAction(action.c_str(), number, type), TELEPHONY_SUCCESS);
        action = "**";
        EXPECT_EQ(supplement.ObtainCallTrasferAction(action.c_str(), number, type), TELEPHONY_SUCCESS);
        action = "##";
        EXPECT_EQ(supplement.ObtainCallTrasferAction(action.c_str(), number, type), TELEPHONY_SUCCESS);
        action = "*#";
        EXPECT_NE(supplement.ObtainCallTrasferAction(action.c_str(), number, type), TELEPHONY_SUCCESS);
    }
}

/**
 * @tc.number   cellular_call_CellularCallHandler_0001
 * @tc.name     Test for CellularCallHandler
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_CellularCallHandler_0001, Function | MediumTest | Level3)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }

    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    CellularCallHandler firstHandler { subscriberInfo };
    for (int32_t slotId = 0; slotId < SIM_SLOT_COUNT; slotId++) {
        if (!HasSimCard(slotId)) {
            continue;
        }
        firstHandler.SetSlotId(slotId);
        auto event = AppExecFwk::InnerEvent::Get(0);
        auto rilRadioResponse = std::make_shared<RadioResponseInfo>();
        rilRadioResponse->error = ErrType::ERR_GENERIC_FAILURE;
        firstHandler.CellularCallIncomingStartTrace(static_cast<int32_t>(TelCallState::CALL_STATUS_INCOMING));
        firstHandler.CellularCallIncomingFinishTrace(static_cast<int32_t>(TelCallState::CALL_STATUS_INCOMING));
        firstHandler.GetCsCallsDataResponse(event);
        firstHandler.GetCsCallsDataRequest(event);
        firstHandler.GetMMIResponse(event);
        auto ringbackResponse = std::make_shared<RingbackVoice>();
        ringbackResponse->status = ERROR_RESULT;
        auto ringbackEvent = AppExecFwk::InnerEvent::Get(0, ringbackResponse);
        firstHandler.CallRingBackVoiceResponse(event);
        firstHandler.CallRingBackVoiceResponse(ringbackEvent);
        auto srvccStatus = std::make_shared<SrvccStatus>();
        srvccStatus->status = SrvccState::SRVCC_NONE;
        auto srvccEvent1 = AppExecFwk::InnerEvent::Get(0, srvccStatus);
        firstHandler.UpdateSrvccStateReport(event);
        firstHandler.UpdateSrvccStateReport(srvccEvent1);
        srvccStatus->status = SrvccState::COMPLETED;
        auto srvccEvent2 = AppExecFwk::InnerEvent::Get(0, srvccStatus);
        firstHandler.UpdateSrvccStateReport(srvccEvent2);
        firstHandler.UpdateRsrvccStateReport(event);
        firstHandler.GetCallFailReasonResponse(event);
        firstHandler.GetEmergencyCallListResponse(event);
        firstHandler.ReportEccChanged(event);
        firstHandler.SetEmergencyCallListResponse(event);
        firstHandler.SendUssdResponse(event);
        ASSERT_EQ(firstHandler.GetSlotId(), slotId);
    }
}

/**
 * @tc.number   cellular_call_CellularCallHandler_0002
 * @tc.name     Test for CellularCallHandler
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_CellularCallHandler_0002, Function | MediumTest | Level3)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }

    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    CellularCallHandler secondHandler { subscriberInfo };
    for (int32_t slotId = 0; slotId < SIM_SLOT_COUNT; slotId++) {
        if (!HasSimCard(slotId)) {
            continue;
        }
        secondHandler.SetSlotId(slotId);
        auto event = AppExecFwk::InnerEvent::Get(0);
        auto rilRadioResponse = std::make_shared<RadioResponseInfo>();
        rilRadioResponse->error = ErrType::ERR_GENERIC_FAILURE;
        secondHandler.CommonResultResponse(event);
        auto rejectEvent = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_REJECT_CALL, rilRadioResponse);
        secondHandler.CommonResultResponse(rejectEvent);
        auto supplementEvent = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_CALL_SUPPLEMENT, rilRadioResponse);
        secondHandler.CommonResultResponse(supplementEvent);

        rilRadioResponse->error = ErrType::NONE;
        auto hangupConnectEvent = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_HANGUP_CONNECT, rilRadioResponse);
        secondHandler.CommonResultResponse(hangupConnectEvent);
        auto acceptEvent = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_ACCEPT_CALL, rilRadioResponse);
        secondHandler.CommonResultResponse(acceptEvent);
        auto splitNoErrorEvent = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SPLIT_CALL, rilRadioResponse);
        secondHandler.CommonResultResponse(splitNoErrorEvent);

        auto ssResult = std::make_shared<SsBaseResult>();
        ssResult->index = INVALID_INDEX;
        ssResult->result = SUCCESS_RESULT;
        auto errorEvent = AppExecFwk::InnerEvent::Get(0, ssResult);
        secondHandler.SetCallRestrictionResponse(event);
        secondHandler.SetCallRestrictionResponse(errorEvent);
        secondHandler.SetBarringPasswordResponse(event);
        secondHandler.SetCallTransferInfoResponse(event);
        secondHandler.SetCallWaitingResponse(event);
        secondHandler.SetClipResponse(event);
        secondHandler.SetClirResponse(event);
        secondHandler.SetColpResponse(event);
        secondHandler.SetColrResponse(event);

        auto responseEvent = AppExecFwk::InnerEvent::Get(0, rilRadioResponse);
        secondHandler.SetMuteResponse(event);
        secondHandler.SetMuteResponse(responseEvent);
        secondHandler.GetMuteResponse(event);
        secondHandler.GetMuteResponse(responseEvent);
        ASSERT_EQ(secondHandler.GetSlotId(), slotId);
    }
}

/**
 * @tc.number   cellular_call_CellularCallHandler_0003
 * @tc.name     Test for CellularCallHandler
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_CellularCallHandler_0003, Function | MediumTest | Level3)
{
    if (!HasSimCard(SIM1_SLOTID) && !HasSimCard(SIM2_SLOTID)) {
        return;
    }
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    CellularCallHandler thirdhandler { subscriberInfo };
    for (int32_t slotId = 0; slotId < SIM_SLOT_COUNT; slotId++) {
        if (!HasSimCard(slotId)) {
            continue;
        }
        thirdhandler.SetSlotId(slotId);
        auto event = AppExecFwk::InnerEvent::Get(0);
        auto ussdNoticeResponse = std::make_shared<UssdNoticeInfo>();
        ussdNoticeResponse->m = USSD_MODE_NOTIFY;
        ussdNoticeResponse->str = "tdd test";
        auto successEvent = AppExecFwk::InnerEvent::Get(0, ussdNoticeResponse);
        thirdhandler.UssdNotifyResponse(event);
        thirdhandler.UssdNotifyResponse(successEvent);
        ussdNoticeResponse->str = "";
        auto errorEvent = AppExecFwk::InnerEvent::Get(0, ussdNoticeResponse);
        thirdhandler.UssdNotifyResponse(errorEvent);

        auto ssNoticeResponse = std::make_shared<SsNoticeInfo>();
        ssNoticeResponse->result = ERROR_RESULT;
        auto defaultEvent = AppExecFwk::InnerEvent::Get(0, ssNoticeResponse);
        thirdhandler.SsNotifyResponse(event);
        thirdhandler.SsNotifyResponse(defaultEvent);
        ssNoticeResponse->requestType = SUCCESS_RESULT;
        auto noticeErrorEvent = AppExecFwk::InnerEvent::Get(0, ssNoticeResponse);
        thirdhandler.SsNotifyResponse(noticeErrorEvent);
        ssNoticeResponse->result = SUCCESS_RESULT;
        auto noticeDefaultEvent = AppExecFwk::InnerEvent::Get(0, ssNoticeResponse);
        thirdhandler.SsNotifyResponse(noticeDefaultEvent);
        ssNoticeResponse->serviceType = static_cast<int32_t>(CallTransferType::TRANSFER_TYPE_UNCONDITIONAL);
        auto noticeUnconditinalEvent = AppExecFwk::InnerEvent::Get(0, ssNoticeResponse);
        thirdhandler.SsNotifyResponse(noticeUnconditinalEvent);
        ssNoticeResponse->serviceType = static_cast<int32_t>(CallTransferType::TRANSFER_TYPE_BUSY);
        auto noticeBusyEvent = AppExecFwk::InnerEvent::Get(0, ssNoticeResponse);
        thirdhandler.SsNotifyResponse(noticeBusyEvent);
        ssNoticeResponse->serviceType = static_cast<int32_t>(CallTransferType::TRANSFER_TYPE_NO_REPLY);
        auto noticeNoReplyEvent = AppExecFwk::InnerEvent::Get(0, ssNoticeResponse);
        thirdhandler.SsNotifyResponse(noticeNoReplyEvent);
        ssNoticeResponse->serviceType = static_cast<int32_t>(CallTransferType::TRANSFER_TYPE_NOT_REACHABLE);
        auto noticeNotReachableEvent = AppExecFwk::InnerEvent::Get(0, ssNoticeResponse);
        thirdhandler.SsNotifyResponse(noticeNotReachableEvent);
        ASSERT_EQ(thirdhandler.GetSlotId(), slotId);
    }
}

/**
 * @tc.number   cellular_call_TestDump_0001
 * @tc.name     TestDump
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_TestDump_0001, Function | MediumTest | Level3)
{
    std::vector<std::u16string> emptyArgs = {};
    std::vector<std::u16string> args = { u"test", u"test1" };
    EXPECT_GE(DelayedSingleton<CellularCallService>::GetInstance()->Dump(-1, args), 0);
    EXPECT_GE(DelayedSingleton<CellularCallService>::GetInstance()->Dump(0, emptyArgs), 0);
    EXPECT_GE(DelayedSingleton<CellularCallService>::GetInstance()->Dump(0, args), 0);
}

/**
 * @tc.number   cellular_call_ModuleServiceUtils_0001
 * @tc.name     ModuleServiceUtils
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_ModuleServiceUtils_0001, Function | MediumTest | Level3)
{
    ModuleServiceUtils moduleServiceUtils;
    bool airplaneModeOn = false;
    moduleServiceUtils.GetCsRegState(SIM1_SLOTID);
    moduleServiceUtils.GetPsRegState(SIM1_SLOTID);
    EXPECT_NE(moduleServiceUtils.GetAirplaneMode(airplaneModeOn), TELEPHONY_SUCCESS);
    EXPECT_NE(moduleServiceUtils.UpdateRadioOn(SIM1_SLOTID), TELEPHONY_SUCCESS);
}

/**
 * @tc.number   cellular_call_CellularCallConfig_0001
 * @tc.name     CellularCallConfig
 * @tc.desc     Function test
 */
HWTEST_F(CsTest, cellular_call_CellularCallConfig_0001, Function | MediumTest | Level3)
{
    CellularCallConfig CellularCallConfig;
    bool isReadyToCall = false;
    bool csType = 0;
    CellularCallConfig.SetReadyToCall(SIM1_SLOTID, isReadyToCall);
    CellularCallCallback cellularCallCallback;
    cellularCallCallback.SetReadyToCall(SIM1_SLOTID, csType, isReadyToCall);
    EXPECT_EQ(CellularCallConfig.IsReadyToCall(SIM1_SLOTID), TELEPHONY_SUCCESS);
}
} // namespace Telephony
} // namespace OHOS

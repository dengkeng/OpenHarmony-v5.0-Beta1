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

#ifndef TELEPHONY_CS_TEST_H
#define TELEPHONY_CS_TEST_H
#include <securec.h>

#include "accesstoken_kit.h"
#include "call_manager_errors.h"
#include "cellular_call_data_struct.h"
#include "cellular_call_interface.h"
#include "cellular_call_ipc_interface_code.h"
#include "gtest/gtest.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "token_setproc.h"

namespace OHOS {
namespace Telephony {
using namespace Security::AccessToken;
using Security::AccessToken::AccessTokenID;

inline HapInfoParams testInfoParams = {
    .bundleName = "tel_cellular_call_cs_gtest",
    .userID = 1,
    .instIndex = 0,
    .appIDDesc = "test",
};

inline PermissionDef testPermPlaceCallDef = {
    .permissionName = "ohos.permission.CONNECT_CELLULAR_CALL_SERVICE",
    .bundleName = "tel_cellular_call_cs_gtest",
    .grantMode = 1, // SYSTEM_GRANT
    .label = "label",
    .labelId = 1,
    .description = "Test cellular call",
    .descriptionId = 1,
    .availableLevel = APL_SYSTEM_BASIC,
};

inline PermissionStateFull testPlaceCallState = {
    .grantFlags = { 2 }, // PERMISSION_USER_SET
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .isGeneral = true,
    .permissionName = "ohos.permission.CONNECT_CELLULAR_CALL_SERVICE",
    .resDeviceID = { "local" },
};

inline HapPolicyParams testPolicyParams = {
    .apl = APL_SYSTEM_BASIC,
    .domain = "test.domain",
    .permList = { testPermPlaceCallDef },
    .permStateList = { testPlaceCallState },
};

class AccessToken {
public:
    AccessToken()
    {
        currentID_ = GetSelfTokenID();
        AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(testInfoParams, testPolicyParams);
        accessID_ = tokenIdEx.tokenIdExStruct.tokenID;
        SetSelfTokenID(accessID_);
    }
    ~AccessToken()
    {
        AccessTokenKit::DeleteToken(accessID_);
        SetSelfTokenID(currentID_);
    }

private:
    AccessTokenID currentID_ = 0;
    AccessTokenID accessID_ = 0;
};

class CsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    int32_t Dial(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t HangUp(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t Answer(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t Reject(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t HoldCall(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t UnHoldCall(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t SwitchCall(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t IsEmergencyPhoneNumber(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t CombineConference(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t SeparateConference(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t InviteToConference(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t KickOutFromConference(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t HangUpAllConnection(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t UpdateImsCallMode(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t RegisterCallBack(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t UnRegisterCallBack(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t StartDtmf(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t StopDtmf(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t SendDtmf(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t StartRtt(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t StopRtt(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t SetCallTransferInfo(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t GetCallTransferInfo(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t SetCallWaiting(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t GetCallWaiting(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t SetCallRestriction(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t GetCallRestriction(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t SetCallRestrictionPassword(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t SetMute(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t GetMute(const sptr<CellularCallInterface> &telephonyService) const;
    int32_t InputNumForInterface(const sptr<CellularCallInterface> &telephonyService) const;
    void JudgeIsEmergencyPhoneNumber();
    bool HasSimCard(int32_t slotId);
    int32_t InitCellularCallInfo(int32_t accountId, std::string phonenumber, CellularCallInfo &callInfo)
    {
        callInfo.accountId = accountId;
        callInfo.slotId = accountId;
        callInfo.index = accountId;
        callInfo.callType = CallType::TYPE_CS;
        callInfo.videoState = 0; // 0 means audio
        if (memset_s(callInfo.phoneNum, kMaxNumberLen, 0, kMaxNumberLen) != EOK) {
            return TELEPHONY_ERR_MEMSET_FAIL;
        }
        if (phonenumber.length() > static_cast<size_t>(kMaxNumberLen)) {
            return CALL_ERR_NUMBER_OUT_OF_RANGE;
        }
        if (memcpy_s(callInfo.phoneNum, kMaxNumberLen, phonenumber.c_str(), phonenumber.length()) != EOK) {
            return TELEPHONY_ERR_MEMCPY_FAIL;
        }
        return TELEPHONY_SUCCESS;
    };

    int32_t TestDialCallByCs(int32_t slotId, std::string code)
    {
        AccessToken token;
        auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (systemAbilityMgr == nullptr) {
            return TELEPHONY_ERR_FAIL;
        }
        auto remote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
        if (remote == nullptr) {
            return TELEPHONY_ERR_FAIL;
        }
        auto telephonyService = iface_cast<CellularCallInterface>(remote);
        if (telephonyService == nullptr) {
            return TELEPHONY_ERR_FAIL;
        }
        CellularCallInfo callInfo;
        int32_t ret = TELEPHONY_SUCCESS;
        ret = InitCellularCallInfo(slotId, code, callInfo);
        if (ret != TELEPHONY_SUCCESS) {
            return ret;
        }
        // close ims, make this time use cs to test
        ret = telephonyService->SetImsSwitchStatus(slotId, false);
        if (ret != TELEPHONY_SUCCESS) {
            return ret;
        }
        ret = telephonyService->Dial(callInfo);
        return ret;
    };

private:
    int32_t InitCallInfo(CellularCallInfo &callInfo) const;

private:
    using RequestFuncType = int32_t (CsTest::*)(const sptr<CellularCallInterface> &telephonyService) const;
    std::map<int32_t, RequestFuncType> requestFuncMap_;
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_CS_TEST_H

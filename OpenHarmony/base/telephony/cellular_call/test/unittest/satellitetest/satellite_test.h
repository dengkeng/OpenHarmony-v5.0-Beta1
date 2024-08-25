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

#ifndef TELEPHONY_SATELLITE_TEST_H
#define TELEPHONY_SATELLITE_TEST_H
#include <securec.h>

#include "accesstoken_kit.h"
#include "call_manager_errors.h"
#include "cellular_call_handler.h"
#include "cellular_call_interface.h"
#include "cellular_call_ipc_interface_code.h"
#include "core_manager_inner.h"
#include "core_service_client.h"
#include "gtest/gtest.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "telephony_log_wrapper.h"
#include "telephony_permission.h"
#include "token_setproc.h"

namespace OHOS {
namespace Telephony {
using namespace Security::AccessToken;
using Security::AccessToken::AccessTokenID;

inline HapInfoParams testInfoParams = {
    .bundleName = "tel_cellular_call_Satellite_gtest",
    .userID = 1,
    .instIndex = 0,
    .appIDDesc = "test",
    .isSystemApp = true,
};

inline PermissionDef testConnectSatelliteServiceDef = {
    .permissionName = "ohos.permission.CONNECT_SATELLITE_SERVICE",
    .bundleName = "tel_cellular_call_Satellite_gtest",
    .grantMode = 1, // SYSTEM_GRANT
    .label = "label",
    .labelId = 1,
    .description = "Test cellular call",
    .descriptionId = 1,
    .availableLevel = APL_SYSTEM_BASIC,
};

inline PermissionStateFull testConnectSatelliteServiceState = {
    .grantFlags = { 2 }, // PERMISSION_USER_SET
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .isGeneral = true,
    .permissionName = "ohos.permission.CONNECT_SATELLITE_SERVICE",
    .resDeviceID = { "local" },
};

inline PermissionDef testPermPlaceCallDef = {
    .permissionName = "ohos.permission.CONNECT_CELLULAR_CALL_SERVICE",
    .bundleName = "tel_cellular_call_Satellite_gtest",
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

inline PermissionDef testGetTelephonyStateDef = {
    .permissionName = "ohos.permission.GET_TELEPHONY_STATE",
    .bundleName = "tel_cellular_call_Satellite_gtest",
    .grantMode = 1, // SYSTEM_GRANT
    .label = "label",
    .labelId = 1,
    .description = "Test cellular call",
    .descriptionId = 1,
    .availableLevel = APL_SYSTEM_BASIC,
};

inline PermissionStateFull testGetTelephonyState = {
    .grantFlags = { 2 }, // PERMISSION_USER_SET
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .isGeneral = true,
    .permissionName = "ohos.permission.GET_TELEPHONY_STATE",
    .resDeviceID = { "local" },
};

inline HapPolicyParams testPolicyParams = {
    .apl = APL_SYSTEM_BASIC,
    .domain = "test.domain",
    .permList = { testPermPlaceCallDef, testConnectSatelliteServiceDef, testGetTelephonyStateDef },
    .permStateList = { testPlaceCallState, testConnectSatelliteServiceState, testGetTelephonyState },
};

class AccessToken {
public:
    AccessToken()
    {
        currentID_ = GetSelfTokenID();
        AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(testInfoParams, testPolicyParams);
        accessID_ = tokenIdEx.tokenIdExStruct.tokenID;
        SetSelfTokenID(tokenIdEx.tokenIDEx);
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

class SatelliteTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    bool HasSimCard(int32_t slotId)
    {
        bool hasSimCard = false;
        DelayedRefSingleton<CoreServiceClient>::GetInstance().HasSimCard(slotId, hasSimCard);
        return hasSimCard;
    }

    int32_t InitCellularCallInfo(int32_t accountId, std::string phonenumber, CellularCallInfo &callInfo)
    {
        callInfo.accountId = accountId;
        callInfo.slotId = accountId;
        callInfo.index = 0;
        callInfo.callType = CallType::TYPE_SATELLITE;
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

    int32_t TestDialCallBySatellite(int32_t slotId, std::string code)
    {
        AccessToken token;
        auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (saMgr == nullptr) {
            return TELEPHONY_ERR_FAIL;
        }
        auto remote = saMgr->CheckSystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID);
        if (remote == nullptr) {
            return TELEPHONY_ERR_FAIL;
        }
        auto telephonyService = iface_cast<CellularCallInterface>(remote);
        if (telephonyService == nullptr) {
            return TELEPHONY_ERR_FAIL;
        }
        CellularCallInfo SatelliteCellularCallInfo;
        int32_t ret = TELEPHONY_SUCCESS;
        ret = InitCellularCallInfo(slotId, code, SatelliteCellularCallInfo);
        if (ret != TELEPHONY_SUCCESS) {
            return ret;
        }
        ret = telephonyService->Dial(SatelliteCellularCallInfo);
        return ret;
    };
};
} // namespace Telephony
} // namespace OHOS

#endif // TELEPHONY_SATELLITE_TEST_H

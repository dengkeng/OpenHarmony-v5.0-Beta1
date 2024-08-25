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
#define private public
#define protected public

#include "cellular_call_config.h"
#include "cellular_call_connection_satellite.h"
#include "cellular_call_handler.h"
#include "cellular_call_proxy.h"
#include "cellular_call_register.h"
#include "cellular_call_service.h"
#include "gtest/gtest.h"
#include "tel_ril_call_parcel.h"
#include "satellite_call_client.h"
#include "satellite_control.h"
#include "satellite_test.h"
#include "securec.h"
#include "standardize_utils.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

namespace {
const int32_t SIM1_SLOTID = 0;
const int32_t SIM2_SLOTID = 1;
const std::string PHONE_NUMBER = "00000000";
} // namespace

class BranchTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    int32_t InitCellularCallInfo(int32_t accountId, std::string phonenumber, CellularCallInfo &callInfo);
};

void BranchTest::SetUpTestCase()
{
    std::cout << "---------- CellularCallService start ------------" << std::endl;
}

void BranchTest::TearDownTestCase() {}

void BranchTest::SetUp() {}

void BranchTest::TearDown() {}

int32_t BranchTest::InitCellularCallInfo(int32_t accountId, std::string phonenumber, CellularCallInfo &callInfo)
{
    callInfo.accountId = accountId;
    callInfo.slotId = accountId;
    callInfo.index = accountId;
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
}

/**
 * @tc.number   Telephony_CellularCallSatelliteControl_001
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallSatelliteControl_001, Function | MediumTest | Level3)
{
    AccessToken token;
    SatelliteControl satelliteControl;
    CellularCallInfo cellularCallInfo;
    std::vector<CellularCallInfo> infos;
    infos.emplace_back(cellularCallInfo);
    CellularCallInfo cellularCallInfo_new;
    int32_t invalidSupType = -1;
    InitCellularCallInfo(SIM1_SLOTID, PHONE_NUMBER, cellularCallInfo);

    satelliteControl.Dial(cellularCallInfo, true);
    cellularCallInfo_new.slotId = 1;
    satelliteControl.Dial(cellularCallInfo_new, true);
    cellularCallInfo_new.callType = CallType::TYPE_SATELLITE;
    infos.emplace_back(cellularCallInfo_new);
    satelliteControl.HangUp(cellularCallInfo, CallSupplementType::TYPE_DEFAULT);
    satelliteControl.HangUp(cellularCallInfo, CallSupplementType::TYPE_HANG_UP_HOLD_WAIT);
    satelliteControl.HangUp(cellularCallInfo, CallSupplementType::TYPE_HANG_UP_ACTIVE);
    satelliteControl.HangUp(cellularCallInfo, CallSupplementType::TYPE_HANG_UP_ALL);
    satelliteControl.HangUp(cellularCallInfo, static_cast<CallSupplementType>(invalidSupType));
    satelliteControl.Answer(cellularCallInfo);
    satelliteControl.Reject(cellularCallInfo);
    satelliteControl.ReportHangUp(infos, SIM2_SLOTID);
    satelliteControl.HoldCall(SIM1_SLOTID);
    satelliteControl.UnHoldCall(SIM1_SLOTID);
    satelliteControl.SwitchCall(SIM1_SLOTID);
    satelliteControl.CombineConference(SIM1_SLOTID);
    CallInfoList callInfoList;
    satelliteControl.ReportCallsData(SIM1_SLOTID, callInfoList);
    SatelliteCurrentCallList satellitecallInfoList;
    satelliteControl.ReportHungUpInfo(SIM1_SLOTID);
    satelliteControl.ReportIncomingInfo(SIM1_SLOTID, satellitecallInfoList);
    satelliteControl.ReportUpdateInfo(SIM1_SLOTID, satellitecallInfoList);
    SatelliteCurrentCall CallInfo;
    satelliteControl.EncapsulationCallReportInfo(SIM1_SLOTID, CallInfo);
    CallsReportInfo callsReportInfo;
    satelliteControl.DeleteConnection(callsReportInfo, satellitecallInfoList);
    satelliteControl.HangUpAllConnection(SIM1_SLOTID);
    CLIRMode mode = DEFAULT;
    satelliteControl.EncapsulateDialCommon(SIM1_SLOTID, PHONE_NUMBER, mode);
    satelliteControl.ReportSatelliteCallsData(SIM1_SLOTID, satellitecallInfoList);
}

/**
 * @tc.number   Telephony_CellularCallConnectionSatellite_001
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallConnectionSatellite_001, Function | MediumTest | Level3)
{
    AccessToken token;
    CellularCallConnectionSatellite callConn;
    DialRequestStruct dialRequest;
    callConn.DialRequest(SIM1_SLOTID, dialRequest);
    callConn.HangUpRequest(SIM1_SLOTID);
    callConn.AnswerRequest(SIM1_SLOTID);
    callConn.RejectRequest(SIM1_SLOTID);
    callConn.GetSatelliteCallsDataRequest(SIM1_SLOTID, 0);
    callConn.GetCallFailReasonRequest(SIM1_SLOTID);
}

/**
 * @tc.number   Telephony_CellularCallService_001
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallService_001, Function | MediumTest | Level3)
{
    CellularCallService callService;
    CellularCallInfo satelliteCallInfo = { .callType = CallType::TYPE_SATELLITE };
    callService.Dial(satelliteCallInfo);
    callService.HangUp(satelliteCallInfo, CallSupplementType::TYPE_HANG_UP_HOLD_WAIT);
    callService.Reject(satelliteCallInfo);
    callService.Answer(satelliteCallInfo);
    callService.HoldCall(satelliteCallInfo);
    callService.UnHoldCall(satelliteCallInfo);
    callService.SwitchCall(satelliteCallInfo);

    callService.GetSatelliteControl(SIM1_SLOTID);

    std::shared_ptr<SatelliteControl> satelliteControl;
    callService.SetSatelliteControl(SIM1_SLOTID, satelliteControl);
}
} // namespace Telephony
} // namespace OHOS

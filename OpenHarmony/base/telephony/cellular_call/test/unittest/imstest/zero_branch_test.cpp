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
#include "cellular_call_connection_ims.h"
#include "cellular_call_handler.h"
#include "cellular_call_proxy.h"
#include "cellular_call_register.h"
#include "cellular_call_service.h"
#include "cellular_call_supplement.h"
#include "config_request.h"
#include "control_base.h"
#include "cs_control.h"
#include "gtest/gtest.h"
#include "tel_ril_call_parcel.h"
#include "ims_call_callback_proxy.h"
#include "ims_call_callback_stub.h"
#include "ims_call_client.h"
#include "ims_control.h"
#include "ims_error.h"
#include "ims_test.h"
#include "securec.h"
#include "cellular_call_hisysevent.h"
#include "standardize_utils.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

namespace {
const int32_t INVALID_SLOTID = 2;
const int32_t SIM1_SLOTID = 0;
const int32_t SIM2_SLOTID = 1;
const int32_t ACTIVATE_ACTION = 1;
const std::string PHONE_NUMBER = "00000000";
const int32_t DEFAULT_INDEX = 1;
} // namespace

class DemoHandler : public AppExecFwk::EventHandler {
public:
    explicit DemoHandler(std::shared_ptr<AppExecFwk::EventRunner> &runner) : AppExecFwk::EventHandler(runner) {}
    virtual ~DemoHandler() {}
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event) {}
};

class BranchTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    int32_t InitCellularCallInfo(int32_t accountId, std::string phonenumber, CellularCallInfo &callInfo);
    void InitImsCallInfoList(ImsCurrentCallList &callInfoList, int32_t num);
    void InitCsCallInfoList(CallInfoList &callInfoList, int32_t num);
    void MakeCallInfoParcelData(bool isError, MessageParcel &data);
};

void BranchTest::SetUpTestCase()
{
    std::cout << "---------- CellularCallService start ------------" << std::endl;
    DelayedSingleton<CellularCallService>::GetInstance()->Init();
    DelayedSingleton<ImsCallClient>::GetInstance()->Init();
}

void BranchTest::TearDownTestCase() {}

void BranchTest::SetUp() {}

void BranchTest::TearDown() {}

int32_t BranchTest::InitCellularCallInfo(int32_t accountId, std::string phonenumber, CellularCallInfo &callInfo)
{
    callInfo.accountId = accountId;
    callInfo.slotId = accountId;
    callInfo.index = accountId;
    callInfo.callType = CallType::TYPE_IMS;
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

void BranchTest::InitImsCallInfoList(ImsCurrentCallList &callInfoList, int32_t num)
{
    callInfoList.callSize = num;
    ImsCurrentCall call;
    int32_t callStateSum = 6;
    for (int32_t i = 0; i < num; ++i) {
        call.index = i;
        call.state = i % callStateSum;
        callInfoList.calls.push_back(call);
    }
}

void BranchTest::MakeCallInfoParcelData(bool isError, MessageParcel &data)
{
    if (isError) {
        int32_t errorSize = 0;
        data.WriteInt32(errorSize);
    } else {
        CellularCallInfo callInfo;
        callInfo.slotId = -1;
        int32_t size = 1;
        data.WriteInt32(size);
        data.WriteRawData(static_cast<const void *>(&callInfo), sizeof(CellularCallInfo));
    }
}

void BranchTest::InitCsCallInfoList(CallInfoList &callInfoList, int32_t num)
{
    callInfoList.callSize = num;
    CallInfo call;
    int32_t callStateSum = 9;
    for (int32_t i = 0; i < num; ++i) {
        call.index = i;
        call.state = i % callStateSum;
        callInfoList.calls.push_back(call);
    }
}

/**
 * @tc.number   Telephony_CellularCallConfig_001
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallConfig_001, Function | MediumTest | Level3)
{
    AccessToken token;
    CellularCallConfig config;
    config.SetDomainPreferenceMode(SIM1_SLOTID, 1);
    config.SetDomainPreferenceMode(SIM1_SLOTID, -1);
    config.GetDomainPreferenceMode(SIM1_SLOTID);
    bool enabled = false;
    config.SetImsSwitchStatus(INVALID_SLOTID, enabled);
    config.SetImsSwitchStatus(SIM1_SLOTID, enabled);
    config.volteSupported_[SIM1_SLOTID] = true;
    config.volteSupported_[INVALID_SLOTID] = true;
    config.volteProvisioningSupported_[SIM1_SLOTID] = true;
    config.volteProvisioningSupported_[INVALID_SLOTID] = true;
    config.SetImsSwitchStatus(INVALID_SLOTID, enabled);
    config.SetImsSwitchStatus(SIM1_SLOTID, true);
    config.volteSupported_[SIM1_SLOTID] = enabled;
    config.volteSupported_[INVALID_SLOTID] = enabled;
    config.volteProvisioningSupported_[SIM1_SLOTID] = enabled;
    config.volteProvisioningSupported_[INVALID_SLOTID] = enabled;
    config.GetImsSwitchStatus(SIM1_SLOTID, enabled);
    config.saveImsSwitchStatusToLocalForPowerOn(SIM1_SLOTID);
    config.saveImsSwitchStatusToLocal(SIM1_SLOTID, true);
    config.GetImsSwitchStatus(SIM1_SLOTID, enabled);
    int32_t state = 0;
    config.SetVoNRSwitchStatus(SIM1_SLOTID, state);
    config.SetVoNRSwitchStatus(INVALID_SLOTID, state);
    config.GetVoNRSwitchStatus(SIM1_SLOTID, state);
    config.GetVoNRSwitchStatus(SIM2_SLOTID, state);
    config.GetDomainPreferenceModeResponse(SIM1_SLOTID, 1);
    config.GetImsSwitchStatusResponse(SIM1_SLOTID, 1);
    config.GetPreferenceMode(SIM1_SLOTID);
    std::string value = "";
    config.SetImsConfig(ImsConfigItem::ITEM_VIDEO_QUALITY, value);
    config.SetImsConfig(ImsConfigItem::ITEM_VIDEO_QUALITY, 1);
    config.GetImsConfig(ImsConfigItem::ITEM_VIDEO_QUALITY);
    config.SetImsFeatureValue(FeatureType::TYPE_VOICE_OVER_LTE, 1);
    config.GetImsFeatureValue(FeatureType::TYPE_VOICE_OVER_LTE);
    config.HandleFactoryReset(0);
    config.HandleFactoryReset(1);
}

/**
 * @tc.number   Telephony_CellularCallConfig_002
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallConfig_002, Function | MediumTest | Level3)
{
    AccessToken token;
    CellularCallConfig config;
    config.SetMute(SIM1_SLOTID, 0);
    config.GetMute(SIM1_SLOTID);
    config.GetEmergencyCallList(SIM1_SLOTID);
    std::vector<EmergencyCall> eccVec = {};
    config.SetEmergencyCallList(SIM1_SLOTID, eccVec);
    config.SetTempMode(SIM1_SLOTID);
    config.InitModeActive();
    EmergencyInfoList eccList;
    config.UpdateEmergencyCallFromRadio(SIM1_SLOTID, eccList);
    config.GetEccCallList(SIM1_SLOTID);
    config.GetMcc(SIM1_SLOTID);
    config.SetReadyToCall(SIM1_SLOTID, true);
    config.SetReadyToCall(INVALID_SLOTID, true);
    config.IsReadyToCall(SIM1_SLOTID);
    config.IsReadyToCall(INVALID_SLOTID);

    config.HandleSimStateChanged(SIM1_SLOTID);
    config.HandleSetLteImsSwitchResult(SIM1_SLOTID, ErrType::NONE);
    config.HandleSetVoNRSwitchResult(SIM1_SLOTID, ErrType::NONE);
    config.HandleSimRecordsLoaded(SIM1_SLOTID);
    config.HandleOperatorConfigChanged(SIM1_SLOTID);
    OperatorConfig poc;
    config.ParseAndCacheOperatorConfigs(SIM1_SLOTID, poc);
    config.UpdateImsCapabilities(SIM1_SLOTID, true);
    bool enabled = false;
    config.ChangeImsSwitchWithOperatorConfig(SIM1_SLOTID, true);
    config.SaveImsSwitch(SIM1_SLOTID, true);
    config.IsUtProvisioned(SIM1_SLOTID);
    config.utProvisioningSupported_[SIM1_SLOTID] = true;
    config.IsUtProvisioned(SIM1_SLOTID);
    config.utProvisioningSupported_[SIM1_SLOTID] = enabled;
    config.ResetImsSwitch(SIM1_SLOTID);
    config.HandleSimAccountLoaded(SIM1_SLOTID);
}

/**
 * @tc.number   Telephony_CellularCallSupplement_001
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallSupplement_001, Function | MediumTest | Level3)
{
    AccessToken token;
    CellularCallSupplement callSup;
    MMIData mmiDataEmp = {};
    MMIData mmiDataAct = { .actionString = "*" };
    MMIData mmiDataDeact = { .actionString = "#" };
    MMIData mmiDataInterrogate = { .actionString = "*#" };
    callSup.HandleClip(SIM1_SLOTID, mmiDataEmp);
    callSup.HandleClip(SIM1_SLOTID, mmiDataAct);
    callSup.HandleClip(SIM1_SLOTID, mmiDataDeact);
    callSup.HandleClip(SIM1_SLOTID, mmiDataInterrogate);
    callSup.HandleClir(SIM1_SLOTID, mmiDataEmp);
    callSup.HandleClir(SIM1_SLOTID, mmiDataAct);
    callSup.HandleClir(SIM1_SLOTID, mmiDataDeact);
    callSup.HandleClir(SIM1_SLOTID, mmiDataInterrogate);
    callSup.HandleColr(SIM1_SLOTID, mmiDataEmp);
    callSup.HandleColr(SIM1_SLOTID, mmiDataAct);
    callSup.HandleColr(SIM1_SLOTID, mmiDataDeact);
    callSup.HandleColr(SIM1_SLOTID, mmiDataInterrogate);
    callSup.HandleColp(SIM1_SLOTID, mmiDataEmp);
    callSup.HandleColp(SIM1_SLOTID, mmiDataAct);
    callSup.HandleColp(SIM1_SLOTID, mmiDataDeact);
    callSup.HandleColp(SIM1_SLOTID, mmiDataInterrogate);
    callSup.HandleCallTransfer(SIM1_SLOTID, mmiDataEmp);
    callSup.HandleCallTransfer(SIM1_SLOTID, mmiDataInterrogate);
    callSup.HandleCallTransfer(SIM1_SLOTID, mmiDataAct);
    callSup.HandleCallRestriction(SIM1_SLOTID, mmiDataEmp);
    callSup.HandleCallRestriction(SIM1_SLOTID, mmiDataAct);
    callSup.HandleCallRestriction(SIM1_SLOTID, mmiDataDeact);
    callSup.HandleCallRestriction(SIM1_SLOTID, mmiDataInterrogate);
    callSup.HandleCallWaiting(SIM1_SLOTID, mmiDataEmp);
    callSup.HandleCallWaiting(SIM1_SLOTID, mmiDataAct);
    callSup.HandleCallWaiting(SIM1_SLOTID, mmiDataDeact);
}

/**
 * @tc.number   Telephony_CellularCallSupplement_002
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallSupplement_002, Function | MediumTest | Level3)
{
    AccessToken token;
    CellularCallSupplement callSup;
    callSup.SendUssd(SIM1_SLOTID, "*#21#");
    PinPukResponse pinPuk;
    callSup.EventSetPinPuk(pinPuk);
    MMIData mmiDataPin = { .serviceInfoA = "1234", .serviceInfoB = "1111", .serviceInfoC = "1111" };
    callSup.AlterPinPassword(SIM1_SLOTID, mmiDataPin);
    callSup.UnlockPuk(SIM1_SLOTID, mmiDataPin);
    callSup.AlterPin2Password(SIM1_SLOTID, mmiDataPin);
    callSup.UnlockPuk2(SIM1_SLOTID, mmiDataPin);
    mmiDataPin = { .serviceInfoA = "1234", .serviceInfoB = "1111", .serviceInfoC = "1112" };
    callSup.AlterPinPassword(SIM1_SLOTID, mmiDataPin);
    callSup.UnlockPuk(SIM1_SLOTID, mmiDataPin);
    callSup.AlterPin2Password(SIM1_SLOTID, mmiDataPin);
    callSup.UnlockPuk2(SIM1_SLOTID, mmiDataPin);
    mmiDataPin = { .serviceInfoA = "1234", .serviceInfoB = "1111", .serviceInfoC = "111111111" };
    callSup.AlterPinPassword(SIM1_SLOTID, mmiDataPin);
    callSup.UnlockPuk(SIM1_SLOTID, mmiDataPin);
    callSup.AlterPin2Password(SIM1_SLOTID, mmiDataPin);
    callSup.UnlockPuk2(SIM1_SLOTID, mmiDataPin);
    callSup.CloseUnFinishedUssd(SIM1_SLOTID);
    GetClipResult getClipResult;
    std::string message = "";
    callSup.EventGetClip(getClipResult, message, 0);
    callSup.EventGetClip(getClipResult, message, 1);
    callSup.EventSetClip(0, message, 0);
    callSup.EventSetClip(0, message, 1);
    GetClirResult getClirResult;
    callSup.EventGetClir(getClirResult, message, 0);
    callSup.EventGetClir(getClirResult, message, 1);
    callSup.EventSetClir(0, message, 0);
    callSup.EventSetClir(0, message, 1);
    GetColrResult getColrResult;
    callSup.EventGetColr(getColrResult, message, 0);
    callSup.EventGetColr(getColrResult, message, 1);
    callSup.EventSetColr(0, message, 0);
    callSup.EventSetColr(0, message, 1);
}

/**
 * @tc.number   Telephony_CellularCallSupplement_003
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallSupplement_003, Function | MediumTest | Level3)
{
    AccessToken token;
    CellularCallSupplement callSup;
    GetColpResult getColpResult;
    std::string message = "";
    callSup.EventGetColp(getColpResult, message, 0);
    callSup.EventGetColp(getColpResult, message, 1);
    callSup.EventSetColp(0, message, 0);
    callSup.EventSetColp(0, message, 1);
    CallRestrictionResult callResResult;
    callSup.EventGetCallRestriction(callResResult, message, 0);
    callSup.EventGetCallRestriction(callResResult, message, 1);
    callResResult.status = 1;
    callSup.EventGetCallRestriction(callResResult, message, 0);
    callResResult.result.result = 1;
    callSup.EventGetCallRestriction(callResResult, message, 0);
    callSup.EventSetCallRestriction(0, message, 0);
    callSup.EventSetCallRestriction(0, message, 1);
    callSup.EventSetBarringPassword(0, message, 0);
    callSup.EventSetBarringPassword(0, message, 1);
    callSup.EventSetCallWaiting(0, message, 0);
    callSup.EventSetCallWaiting(0, message, 1);
    CallForwardQueryInfoList cFQueryList;
    callSup.EventGetCallTransferInfo(cFQueryList, message, 0);
    CallForwardQueryResult queryResult;
    callSup.BuildCallForwardQueryInfo(queryResult, message, 0);
    callSup.BuildCallForwardQueryInfo(queryResult, message, 1);
    queryResult.classx = 1;
    callSup.BuildCallForwardQueryInfo(queryResult, message, 0);
    queryResult.status = 1;
    callSup.BuildCallForwardQueryInfo(queryResult, message, 0);
    queryResult.reason = 2;
    callSup.BuildCallForwardQueryInfo(queryResult, message, 0);
    callSup.EventSetCallTransferInfo(0, message, 0);
    callSup.EventSetCallTransferInfo(0, message, 1);
    RadioResponseInfo responseInfo;
    callSup.EventSendUssd(responseInfo);
    SsNoticeInfo ssNoticeInfo;
    callSup.EventSsNotify(ssNoticeInfo);
    UssdNoticeInfo ussdNoticeInfo;
    callSup.EventUssdNotify(ussdNoticeInfo);
    RadioResponseInfo response;
    callSup.EventCloseUnFinishedUssd(response);
    callSup.GetCallTransferInfo(SIM1_SLOTID, CallTransferType::TRANSFER_TYPE_UNCONDITIONAL);
    callSup.GetCallTransferInfo(SIM2_SLOTID, CallTransferType::TRANSFER_TYPE_UNCONDITIONAL);
}

/**
 * @tc.number   Telephony_CellularCallSupplement_004
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallSupplement_004, Function | MediumTest | Level3)
{
    AccessToken token;
    CellularCallSupplement callSup;
    CallWaitResult waitingInfo;
    std::string message = "";
    callSup.EventGetCallWaiting(waitingInfo, message, 0);
    callSup.EventGetCallWaiting(waitingInfo, message, 1);
    waitingInfo.status =1;
    callSup.EventGetCallWaiting(waitingInfo, message, 0);
    waitingInfo.classCw =1;
    callSup.EventGetCallWaiting(waitingInfo, message, 0);
    waitingInfo.classCw =4;
    callSup.EventGetCallWaiting(waitingInfo, message, 0);
    waitingInfo.classCw =8;
    callSup.EventGetCallWaiting(waitingInfo, message, 0);
    waitingInfo.classCw =16;
    callSup.EventGetCallWaiting(waitingInfo, message, 0);
    waitingInfo.classCw =32;
    callSup.EventGetCallWaiting(waitingInfo, message, 0);
    waitingInfo.classCw =64;
    callSup.EventGetCallWaiting(waitingInfo, message, 0);
    waitingInfo.classCw =128;
    callSup.EventGetCallWaiting(waitingInfo, message, 0);
    CallTransferInfo cfInfo;
    callSup.SetCallTransferInfo(SIM1_SLOTID, cfInfo);
    strcpy_s(cfInfo.transferNum, kMaxNumberLen + 1, "111");
    callSup.SetCallTransferInfo(SIM1_SLOTID, cfInfo);
    callSup.SetCallTransferInfo(SIM2_SLOTID, cfInfo);
    auto utCommand = std::make_shared<SsRequestCommand>();
    callSup.SetCallTransferInfoByIms(SIM1_SLOTID, cfInfo, utCommand);
    callSup.SetCallTransferInfoByIms(SIM2_SLOTID, cfInfo, utCommand);
    bool activate = false;
    callSup.SetCallWaiting(SIM1_SLOTID, activate);
    callSup.SetCallWaiting(SIM2_SLOTID, activate);
    callSup.GetCallWaiting(SIM1_SLOTID);
    callSup.GetCallWaiting(SIM2_SLOTID);
    CallRestrictionInfo crInfo;
    callSup.SetCallRestriction(SIM1_SLOTID, crInfo);
    callSup.SetCallRestriction(SIM2_SLOTID, crInfo);
    auto crCommand = std::make_shared<SsRequestCommand>();
    std::string info(crInfo.password);
    std::string fac("AO");
    callSup.SetCallRestrictionByIms(SIM1_SLOTID, fac, static_cast<int32_t>(crInfo.mode), info, crCommand);
    callSup.SetCallRestrictionByIms(SIM2_SLOTID, fac, static_cast<int32_t>(crInfo.mode), info, crCommand);
    callSup.GetCallRestriction(SIM1_SLOTID, CallRestrictionType::RESTRICTION_TYPE_ALL_INCOMING);
    callSup.GetCallRestriction(SIM2_SLOTID, CallRestrictionType::RESTRICTION_TYPE_ALL_INCOMING);
    callSup.SetBarringPassword(SIM1_SLOTID, CallRestrictionType::RESTRICTION_TYPE_ALL_INCOMING, "1111", "0000");
    callSup.SetBarringPassword(SIM2_SLOTID, CallRestrictionType::RESTRICTION_TYPE_ALL_INCOMING, "1111", "0000");
}

/**
 * @tc.number   Telephony_CellularCallSupplement_005
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallSupplement_005, Function | MediumTest | Level3)
{
    AccessToken token;
    CellularCallSupplement callSup;
    MMIData mmiDataEmp = {};
    MMIData mmiDataAct = { .actionString = "*" };
    MMIData mmiDataDeact = { .actionString = "#" };
    MMIData mmiDataInterrogate = { .actionString = "*#" };
    callSup.HandleClip(SIM2_SLOTID, mmiDataEmp);
    callSup.HandleClip(SIM2_SLOTID, mmiDataAct);
    callSup.HandleClip(SIM2_SLOTID, mmiDataDeact);
    callSup.HandleClip(SIM2_SLOTID, mmiDataInterrogate);
    callSup.HandleColr(SIM2_SLOTID, mmiDataEmp);
    callSup.HandleColr(SIM2_SLOTID, mmiDataAct);
    callSup.HandleColr(SIM2_SLOTID, mmiDataDeact);
    callSup.HandleColr(SIM2_SLOTID, mmiDataInterrogate);
    callSup.HandleColp(SIM2_SLOTID, mmiDataEmp);
    callSup.HandleColp(SIM2_SLOTID, mmiDataAct);
    callSup.HandleColp(SIM2_SLOTID, mmiDataDeact);
    callSup.HandleColp(SIM2_SLOTID, mmiDataInterrogate);
    callSup.HandleCallTransfer(SIM2_SLOTID, mmiDataEmp);
    callSup.HandleCallTransfer(SIM2_SLOTID, mmiDataInterrogate);
    callSup.HandleCallTransfer(SIM2_SLOTID, mmiDataAct);
    callSup.HandleCallRestriction(SIM2_SLOTID, mmiDataEmp);
    callSup.HandleCallRestriction(SIM2_SLOTID, mmiDataAct);
    callSup.HandleCallRestriction(SIM2_SLOTID, mmiDataDeact);
    callSup.HandleCallRestriction(SIM2_SLOTID, mmiDataInterrogate);
    callSup.HandleCallWaiting(SIM2_SLOTID, mmiDataEmp);
    callSup.HandleCallWaiting(SIM2_SLOTID, mmiDataAct);
    callSup.HandleCallWaiting(SIM2_SLOTID, mmiDataDeact);
    bool enable = false;
    callSup.CanSetCallTransferTime(SIM1_SLOTID, enable);
}

/**
 * @tc.number   Telephony_CellularCallCsControl_001
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallCsControl_001, Function | MediumTest | Level3)
{
    AccessToken token;
    CSControl csControl;
    CellularCallInfo cellularCallInfo;
    InitCellularCallInfo(SIM1_SLOTID, PHONE_NUMBER, cellularCallInfo);
    CallInfoList callInfoList;
    csControl.ReportCallsData(SIM1_SLOTID, callInfoList);
    csControl.connectionMap_.insert(std::make_pair(1, CellularCallConnectionCS()));
    csControl.ReportCallsData(SIM1_SLOTID, callInfoList);
    csControl.connectionMap_.insert(std::make_pair(1, CellularCallConnectionCS()));
    InitCsCallInfoList(callInfoList, 5);
    csControl.ReportCallsData(SIM1_SLOTID, callInfoList);
    csControl.connectionMap_.clear();
    csControl.ReportCallsData(SIM1_SLOTID, callInfoList);
    bool enabled = false;
    csControl.Dial(cellularCallInfo, enabled);
    csControl.DialCdma(cellularCallInfo);
    csControl.DialGsm(cellularCallInfo);
    csControl.CalculateInternationalRoaming(SIM1_SLOTID);
    csControl.Answer(cellularCallInfo);
    csControl.Reject(cellularCallInfo);
    csControl.SeparateConference(SIM1_SLOTID, PHONE_NUMBER, 1);
    csControl.SeparateConference(SIM1_SLOTID, "", 1);
    int32_t invlaidCallType = -1;
    csControl.HangUp(cellularCallInfo, CallSupplementType::TYPE_DEFAULT);
    csControl.HangUp(cellularCallInfo, CallSupplementType::TYPE_HANG_UP_ACTIVE);
    csControl.HangUp(cellularCallInfo, CallSupplementType::TYPE_HANG_UP_ALL);
    csControl.HangUp(cellularCallInfo, static_cast<CallSupplementType>(invlaidCallType));
    csControl.HoldCall(SIM1_SLOTID);
    csControl.UnHoldCall(SIM1_SLOTID);
    csControl.SwitchCall(SIM1_SLOTID);
    csControl.CombineConference(SIM1_SLOTID);
    csControl.HangUpAllConnection(SIM1_SLOTID);
    csControl.GetConnectionMap();
    csControl.ReportHangUpInfo(SIM1_SLOTID);
    csControl.ReportIncomingInfo(SIM1_SLOTID, callInfoList);
    csControl.ReportUpdateInfo(SIM1_SLOTID, callInfoList);
    CallInfo callInfo;
    csControl.EncapsulationCallReportInfo(SIM1_SLOTID, callInfo);
    std::string phoneNum = "00000000";
    CLIRMode clirMode = CLIRMode::DEFAULT;
    csControl.EncapsulateDialCommon(SIM1_SLOTID, phoneNum, clirMode);
    CallsReportInfo callsReportInfo;
    csControl.DeleteConnection(callsReportInfo, callInfoList);
    csControl.ReleaseAllConnection();
}

/**
 * @tc.number   Telephony_CellularCallCsControl_002
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallCsControl_002, Function | MediumTest | Level3)
{
    AccessToken token;
    CSControl csControl;
    CellularCallInfo cellularCallInfo;
    InitCellularCallInfo(SIM1_SLOTID, PHONE_NUMBER, cellularCallInfo);
    CellularCallInfo cellularCallInfo_new;
    cellularCallInfo_new.callType = CallType::TYPE_CS;
    std::vector<CellularCallInfo> infos;
    bool enabled = false;
    infos.emplace_back(cellularCallInfo);
    infos.emplace_back(cellularCallInfo_new);
    csControl.PostDialProceed(cellularCallInfo, true);
    csControl.PostDialProceed(cellularCallInfo, enabled);
    csControl.ExecutePostDial(SIM1_SLOTID, 0);
    csControl.connectionMap_.insert(std::make_pair(1, CellularCallConnectionCS()));
    cellularCallInfo.index = 1;
    csControl.Answer(cellularCallInfo);
    csControl.PostDialProceed(cellularCallInfo, true);
    csControl.ExecutePostDial(SIM1_SLOTID, 0);
    csControl.ExecutePostDial(SIM1_SLOTID, 1);
    csControl.connectionMap_.clear();
    for (uint16_t i = 0; i <= 7; ++i) {
        csControl.connectionMap_.insert(std::make_pair(i, CellularCallConnectionCS()));
    }
    csControl.DialCdma(cellularCallInfo);
    csControl.DialGsm(cellularCallInfo);
    csControl.connectionMap_.clear();
    csControl.ReportHangUp(infos, SIM1_SLOTID);
}

/**
 * @tc.number   Telephony_CellularCallImsControl_001
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallImsControl_001, Function | MediumTest | Level3)
{
    AccessToken token;
    IMSControl imsControl;
    CellularCallInfo cellularCallInfo;
    std::vector<CellularCallInfo> infos;
    infos.emplace_back(cellularCallInfo);
    CellularCallInfo cellularCallInfo_new;
    bool enabled = false;
    int32_t invalidSupType = -1;
    ImsCurrentCallList ImsCallList;
    InitCellularCallInfo(SIM1_SLOTID, PHONE_NUMBER, cellularCallInfo);
    imsControl.ReportImsCallsData(SIM1_SLOTID, ImsCallList);
    InitImsCallInfoList(ImsCallList, 5);
    imsControl.ReportImsCallsData(SIM1_SLOTID, ImsCallList);
    imsControl.Dial(cellularCallInfo, true);
    cellularCallInfo_new.slotId = 1;
    imsControl.Dial(cellularCallInfo_new, true);
    cellularCallInfo_new.callType = CallType::TYPE_IMS;
    infos.emplace_back(cellularCallInfo_new);
    imsControl.HangUp(cellularCallInfo, CallSupplementType::TYPE_DEFAULT);
    imsControl.HangUp(cellularCallInfo, CallSupplementType::TYPE_HANG_UP_HOLD_WAIT);
    imsControl.HangUp(cellularCallInfo, CallSupplementType::TYPE_HANG_UP_ACTIVE);
    imsControl.HangUp(cellularCallInfo, CallSupplementType::TYPE_HANG_UP_ALL);
    imsControl.HangUp(cellularCallInfo, static_cast<CallSupplementType>(invalidSupType));
    imsControl.Answer(cellularCallInfo);
    imsControl.Reject(cellularCallInfo);
    imsControl.PostDialProceed(cellularCallInfo, true);
    imsControl.PostDialProceed(cellularCallInfo, enabled);
    imsControl.RestoreConnection(infos, SIM1_SLOTID);
    imsControl.RestoreConnection(infos, SIM2_SLOTID);
    imsControl.ReportHangUp(infos, SIM1_SLOTID);
    imsControl.ReportHangUp(infos, SIM2_SLOTID);
    imsControl.HoldCall(SIM1_SLOTID);
    imsControl.UnHoldCall(SIM1_SLOTID);
    imsControl.SwitchCall(SIM1_SLOTID);
    imsControl.CombineConference(SIM1_SLOTID);
    std::vector<std::string> numberList;
    imsControl.InviteToConference(SIM1_SLOTID, numberList);
    std::string kickOutStr = "";
    imsControl.KickOutFromConference(SIM1_SLOTID, kickOutStr, 0);
    kickOutStr = "111";
    imsControl.KickOutFromConference(SIM1_SLOTID, kickOutStr, 0);
    imsControl.HangUpAllConnection(SIM1_SLOTID);
    CLIRMode clirMode = CLIRMode::DEFAULT;
    int32_t videoState = 0;
    imsControl.DialJudgment(SIM1_SLOTID, PHONE_NUMBER, clirMode, videoState);
    imsControl.EncapsulateDial(SIM1_SLOTID, PHONE_NUMBER, clirMode, videoState);
}

/**
 * @tc.number   Telephony_CellularCallImsControl_002
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallImsControl_002, Function | MediumTest | Level3)
{
    AccessToken token;
    IMSControl imsControl;
    ImsCurrentCallList ImsCallList;
    imsControl.ReportImsCallsData(SIM1_SLOTID, ImsCallList);
    InitImsCallInfoList(ImsCallList, 5);
    imsControl.ReportImsCallsData(SIM1_SLOTID, ImsCallList);
    CallInfoList callInfoList;
    imsControl.ReportCallsData(SIM1_SLOTID, callInfoList);
    imsControl.ReportHangUpInfo(SIM1_SLOTID);
    imsControl.ReportIncomingInfo(SIM1_SLOTID, ImsCallList);
    imsControl.ReportUpdateInfo(SIM1_SLOTID, ImsCallList);
    ImsCurrentCall ImsCallInfo;
    imsControl.EncapsulationCallReportInfo(SIM1_SLOTID, ImsCallInfo);
    CallsReportInfo callsReportInfo;
    imsControl.DeleteConnection(callsReportInfo, ImsCallList);
    imsControl.ReleaseAllConnection();
    imsControl.DialAfterHold(SIM1_SLOTID);
    std::string msg = "";
    imsControl.StartRtt(SIM1_SLOTID, msg);
    imsControl.StopRtt(SIM1_SLOTID);
    imsControl.GetConnectionMap();
    imsControl.ReleaseAllConnection();
}

/**
 * @tc.number   Telephony_ImsVideoCallControl_001
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_ImsVideoCallControl_001, Function | MediumTest | Level3)
{
    AccessToken token;
    auto imsVideoCallControl = DelayedSingleton<ImsVideoCallControl>::GetInstance();
    std::string cameraId = "";
    imsVideoCallControl->ControlCamera(SIM1_SLOTID, DEFAULT_INDEX, cameraId);
    std::string surfaceId = "";
    imsVideoCallControl->SetPreviewWindow(SIM1_SLOTID, DEFAULT_INDEX, surfaceId, nullptr);
    imsVideoCallControl->SetDisplayWindow(SIM1_SLOTID, DEFAULT_INDEX, surfaceId, nullptr);
    imsVideoCallControl->SetCameraZoom(1.0);
    std::string path = "";
    imsVideoCallControl->SetPausePicture(SIM1_SLOTID, DEFAULT_INDEX, path);
    imsVideoCallControl->SetDeviceDirection(SIM1_SLOTID, DEFAULT_INDEX, 0);
    CellularCallInfo cellularCallInfo;
    InitCellularCallInfo(SIM1_SLOTID, PHONE_NUMBER, cellularCallInfo);
    imsVideoCallControl->SendUpdateCallMediaModeRequest(cellularCallInfo, ImsCallMode::CALL_MODE_AUDIO_ONLY);
    imsVideoCallControl->SendUpdateCallMediaModeResponse(cellularCallInfo, ImsCallMode::CALL_MODE_AUDIO_ONLY);
    imsVideoCallControl->CancelCallUpgrade(SIM1_SLOTID, DEFAULT_INDEX);
    imsVideoCallControl->RequestCameraCapabilities(SIM1_SLOTID, DEFAULT_INDEX);
}

/**
 * @tc.number   Telephony_CellularCallConnectionIms_001
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallConnectionIms_001, Function | MediumTest | Level3)
{
    AccessToken token;
    CellularCallConnectionIMS callConn;
    ImsDialInfoStruct dialRequest;
    callConn.DialRequest(SIM1_SLOTID, dialRequest);
    callConn.HangUpRequest(SIM1_SLOTID, PHONE_NUMBER, 0);
    callConn.AnswerRequest(SIM1_SLOTID, PHONE_NUMBER, 0, 0);
    callConn.RejectRequest(SIM1_SLOTID, PHONE_NUMBER, 0);
    callConn.HoldCallRequest(SIM1_SLOTID);
    callConn.UnHoldCallRequest(SIM1_SLOTID);
    callConn.SwitchCallRequest(SIM1_SLOTID);
    callConn.CombineConferenceRequest(SIM1_SLOTID, 0);
    std::vector<std::string> numberList = {};
    callConn.InviteToConferenceRequest(SIM1_SLOTID, numberList);
    callConn.KickOutFromConferenceRequest(SIM1_SLOTID, 0);
    callConn.CallSupplementRequest(SIM1_SLOTID, CallSupplementType::TYPE_DEFAULT);
    std::string msg = "";
    callConn.StartRttRequest(SIM1_SLOTID, msg);
    callConn.StopRttRequest(SIM1_SLOTID);
    callConn.GetImsCallsDataRequest(SIM1_SLOTID, 0);
    callConn.SendDtmfRequest(SIM1_SLOTID, '*', 0);
    callConn.StartDtmfRequest(SIM1_SLOTID, '*', 0);
    callConn.StopDtmfRequest(SIM1_SLOTID, 0);
    callConn.GetCallFailReasonRequest(SIM1_SLOTID);
}

/**
 * @tc.number   Telephony_CellularCallConfigRequest_001
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallConfigRequest_001, Function | MediumTest | Level3)
{
    AccessToken token;
    ConfigRequest configReq;
    configReq.SetDomainPreferenceModeRequest(SIM1_SLOTID, 1);
    configReq.GetDomainPreferenceModeRequest(SIM1_SLOTID);
    configReq.SetDomainPreferenceModeRequest(SIM2_SLOTID, 1);
    configReq.GetDomainPreferenceModeRequest(SIM2_SLOTID);
    bool enabled = false;
    configReq.SetImsSwitchStatusRequest(SIM1_SLOTID, enabled);
    configReq.GetImsSwitchStatusRequest(SIM1_SLOTID);
    int32_t state = 0;
    configReq.SetVoNRSwitchStatusRequest(SIM1_SLOTID, state);
    configReq.SetVoNRSwitchStatusRequest(SIM2_SLOTID, state);
    std::string value = "";
    configReq.SetImsConfigRequest(ImsConfigItem::ITEM_VIDEO_QUALITY, value);
    configReq.SetImsConfigRequest(ImsConfigItem::ITEM_VIDEO_QUALITY, 1);
    configReq.GetImsConfigRequest(ImsConfigItem::ITEM_VIDEO_QUALITY);
    configReq.SetImsFeatureValueRequest(FeatureType::TYPE_VOICE_OVER_LTE, 1);
    int32_t imsFeature = 0;
    configReq.GetImsFeatureValueRequest(FeatureType::TYPE_VOICE_OVER_LTE, imsFeature);
    configReq.SetMuteRequest(SIM1_SLOTID, 0);
    configReq.GetMuteRequest(SIM1_SLOTID);
    configReq.SetMuteRequest(SIM2_SLOTID, 0);
    configReq.GetMuteRequest(SIM2_SLOTID);
    std::vector<EmergencyCall> eccVec = {};
    configReq.GetEmergencyCallListRequest(SIM1_SLOTID);
    configReq.SetEmergencyCallListRequest(SIM1_SLOTID, eccVec);
    configReq.GetEmergencyCallListRequest(SIM2_SLOTID);
    configReq.SetEmergencyCallListRequest(SIM2_SLOTID, eccVec);
    ImsCapabilityList imsCapabilityList;
    configReq.UpdateImsCapabilities(SIM1_SLOTID, imsCapabilityList);
}

/**
 * @tc.number   Telephony_CellularCallStub_001
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallStub_001, Function | MediumTest | Level3)
{
    AccessToken token;
    CellularCallService callStub;
    MessageParcel reply;

    MessageParcel dialErrorData;
    MakeCallInfoParcelData(true, dialErrorData);
    callStub.OnDialInner(dialErrorData, reply);
    MessageParcel dialData;
    MakeCallInfoParcelData(false, dialData);
    callStub.OnDialInner(dialData, reply);

    MessageParcel hangUpErrorData;
    MakeCallInfoParcelData(true, hangUpErrorData);
    callStub.OnHangUpInner(hangUpErrorData, reply);
    MessageParcel hangUpData;
    MakeCallInfoParcelData(false, hangUpData);
    hangUpData.WriteInt32(1);
    callStub.OnHangUpInner(hangUpData, reply);

    MessageParcel rejectErrorData;
    MakeCallInfoParcelData(true, rejectErrorData);
    callStub.OnRejectInner(rejectErrorData, reply);
    MessageParcel rejectData;
    MakeCallInfoParcelData(false, rejectData);
    callStub.OnRejectInner(rejectData, reply);

    MessageParcel answerErrorData;
    MakeCallInfoParcelData(true, answerErrorData);
    callStub.OnAnswerInner(answerErrorData, reply);
    MessageParcel answerData;
    MakeCallInfoParcelData(false, answerData);
    callStub.OnAnswerInner(answerData, reply);

    MessageParcel holdErrorData;
    MakeCallInfoParcelData(true, holdErrorData);
    callStub.OnHoldCallInner(holdErrorData, reply);
    MessageParcel holdData;
    MakeCallInfoParcelData(false, answerData);
    callStub.OnHoldCallInner(holdData, reply);

    MessageParcel unholdErrorData;
    MakeCallInfoParcelData(true, unholdErrorData);
    callStub.OnUnHoldCallInner(unholdErrorData, reply);
    MessageParcel unholdData;
    MakeCallInfoParcelData(false, unholdData);
    callStub.OnUnHoldCallInner(unholdData, reply);

    MessageParcel switchCallErrorData;
    MakeCallInfoParcelData(true, switchCallErrorData);
    callStub.OnSwitchCallInner(switchCallErrorData, reply);
    MessageParcel switchCallData;
    MakeCallInfoParcelData(false, switchCallData);
    callStub.OnSwitchCallInner(switchCallData, reply);
}

/**
 * @tc.number   Telephony_CellularCallStub_002
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallStub_002, Function | MediumTest | Level3)
{
    AccessToken token;
    CellularCallService callStub;
    MessageParcel reply;
    int32_t size = 1;

    MessageParcel combineErrorData;
    MakeCallInfoParcelData(true, combineErrorData);
    callStub.OnCombineConferenceInner(combineErrorData, reply);
    MessageParcel combineData;
    MakeCallInfoParcelData(false, combineData);
    callStub.OnCombineConferenceInner(combineData, reply);

    MessageParcel separateErrorData;
    MakeCallInfoParcelData(true, separateErrorData);
    callStub.OnSeparateConferenceInner(separateErrorData, reply);
    MessageParcel separateData;
    MakeCallInfoParcelData(false, separateData);
    callStub.OnSeparateConferenceInner(separateData, reply);

    MessageParcel kickOutErrorData;
    MakeCallInfoParcelData(true, kickOutErrorData);
    callStub.OnKickOutFromConferenceInner(kickOutErrorData, reply);
    MessageParcel kickOutData;
    MakeCallInfoParcelData(false, kickOutData);
    callStub.OnKickOutFromConferenceInner(kickOutData, reply);

    MessageParcel stopDtmfErrorData;
    MakeCallInfoParcelData(true, stopDtmfErrorData);
    callStub.OnStopDtmfInner(stopDtmfErrorData, reply);
    MessageParcel stopDtmfData;
    MakeCallInfoParcelData(false, stopDtmfData);
    callStub.OnStopDtmfInner(stopDtmfData, reply);

    MessageParcel postDialErrorData;
    MakeCallInfoParcelData(true, postDialErrorData);
    callStub.OnPostDialProceedInner(postDialErrorData, reply);
    MessageParcel postDialData;
    MakeCallInfoParcelData(false, postDialData);
    postDialData.WriteBool(false);
    callStub.OnPostDialProceedInner(postDialData, reply);

    MessageParcel cameraData;
    cameraData.WriteInt32(size);
    callStub.OnControlCameraInner(cameraData, reply);
}

/**
 * @tc.number   Telephony_CellularCallStub_003
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallStub_003, Function | MediumTest | Level3)
{
    AccessToken token;
    CellularCallService callStub;
    CellularCallInfo callInfo;
    callInfo.slotId = -1;
    int32_t errorSize = -1;
    int32_t size = 1;
    MessageParcel reply;

    MessageParcel hangUpAllData;
    hangUpAllData.WriteInt32(size);
    callStub.OnHangUpAllConnectionInner(hangUpAllData, reply);
    MessageParcel startDtmfData;
    startDtmfData.WriteInt32(size);
    startDtmfData.WriteInt8('1');
    startDtmfData.WriteRawData((const void *)&callInfo, sizeof(CellularCallInfo));
    callStub.OnStartDtmfInner(startDtmfData, reply);
    MessageParcel sendDtmfData;
    sendDtmfData.WriteInt32(size);
    sendDtmfData.WriteInt8('1');
    sendDtmfData.WriteRawData((const void *)&callInfo, sizeof(CellularCallInfo));
    callStub.OnSendDtmfInner(sendDtmfData, reply);
    MessageParcel emergencyData;
    emergencyData.WriteInt32(size);
    emergencyData.WriteInt32(errorSize);
    callStub.OnIsEmergencyPhoneNumberInner(emergencyData, reply);
    MessageParcel setReadyData;
    setReadyData.WriteInt32(errorSize);
    callStub.OnSetReadyToCallInner(setReadyData, reply);
    MessageParcel setCallTransferData;
    setCallTransferData.WriteInt32(size);
    setCallTransferData.WriteInt32(errorSize);
    callStub.OnSetCallTransferInner(setCallTransferData, reply);
    MessageParcel canSetTimerData;
    canSetTimerData.WriteInt32(size);
    canSetTimerData.WriteInt32(errorSize);
    callStub.OnCanSetCallTransferTimeInner(canSetTimerData, reply);
    MessageParcel getCallTransferData;
    getCallTransferData.WriteInt32(size);
    getCallTransferData.WriteInt32(errorSize);
    callStub.OnGetCallTransferInner(getCallTransferData, reply);
    MessageParcel setCallWaitData;
    setCallWaitData.WriteInt32(size);
    setCallWaitData.WriteInt32(errorSize);
    callStub.OnSetCallWaitingInner(setCallWaitData, reply);
    MessageParcel getCallWaitData;
    getCallWaitData.WriteInt32(size);
    getCallWaitData.WriteInt32(errorSize);
    callStub.OnGetCallWaitingInner(getCallWaitData, reply);
}

/**
 * @tc.number   Telephony_CellularCallStub_004
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallStub_004, Function | MediumTest | Level3)
{
    AccessToken token;
    CellularCallService callStub;
    int32_t errorSize = -1;
    int32_t size = 1;
    MessageParcel reply;

    MessageParcel setCallRestData;
    setCallRestData.WriteInt32(size);
    setCallRestData.WriteInt32(errorSize);
    callStub.OnSetCallRestrictionInner(setCallRestData, reply);
    MessageParcel getCallRestData;
    getCallRestData.WriteInt32(size);
    getCallRestData.WriteInt32(errorSize);
    callStub.OnGetCallRestrictionInner(getCallRestData, reply);
    MessageParcel setCallRestPwdData;
    setCallRestPwdData.WriteInt32(size);
    setCallRestPwdData.WriteInt32(errorSize);
    callStub.OnSetCallRestrictionPasswordInner(setCallRestPwdData, reply);
    MessageParcel setDomainData;
    setDomainData.WriteInt32(size);
    setDomainData.WriteInt32(errorSize);
    callStub.OnSetDomainPreferenceModeInner(setDomainData, reply);
    MessageParcel getDomainData;
    getDomainData.WriteInt32(size);
    getDomainData.WriteInt32(errorSize);
    callStub.OnGetDomainPreferenceModeInner(getDomainData, reply);
    MessageParcel setImsSwitchData;
    setImsSwitchData.WriteInt32(size);
    setImsSwitchData.WriteInt32(errorSize);
    callStub.OnSetImsSwitchStatusInner(setImsSwitchData, reply);
    MessageParcel getImsSwitchData;
    getImsSwitchData.WriteInt32(size);
    getImsSwitchData.WriteInt32(errorSize);
    callStub.OnGetImsSwitchStatusInner(getImsSwitchData, reply);
    MessageParcel setVonrData;
    setVonrData.WriteInt32(size);
    setVonrData.WriteInt32(errorSize);
    callStub.OnSetVoNRStateInner(setVonrData, reply);
    MessageParcel getVonrData;
    getVonrData.WriteInt32(size);
    getVonrData.WriteInt32(errorSize);
    callStub.OnGetVoNRStateInner(getVonrData, reply);
    MessageParcel setconfigData;
    setconfigData.WriteInt32(size);
    setconfigData.WriteInt32(errorSize);
    callStub.OnSetImsConfigStringInner(setconfigData, reply);
}

/**
 * @tc.number   Telephony_CellularCallStub_005
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallStub_005, Function | MediumTest | Level3)
{
    AccessToken token;
    CellularCallService callStub;
    int32_t errorSize = -1;
    int32_t size = 1;
    MessageParcel reply;

    MessageParcel setconfigData;
    setconfigData.WriteInt32(size);
    setconfigData.WriteInt32(errorSize);
    callStub.OnSetImsConfigIntInner(setconfigData, reply);
    MessageParcel getconfigData;
    getconfigData.WriteInt32(size);
    getconfigData.WriteInt32(errorSize);
    callStub.OnGetImsConfigInner(getconfigData, reply);
    MessageParcel setFeatureData;
    setFeatureData.WriteInt32(size);
    setFeatureData.WriteInt32(errorSize);
    callStub.OnSetImsFeatureValueInner(setFeatureData, reply);
    MessageParcel getFeatureData;
    getFeatureData.WriteInt32(size);
    getFeatureData.WriteInt32(errorSize);
    callStub.OnGetImsFeatureValueInner(getFeatureData, reply);
    MessageParcel setMuteData;
    setMuteData.WriteInt32(size);
    setMuteData.WriteInt32(errorSize);
    callStub.OnSetMuteInner(setMuteData, reply);
    MessageParcel getMuteData;
    getMuteData.WriteInt32(size);
    getMuteData.WriteInt32(errorSize);
    callStub.OnGetMuteInner(getMuteData, reply);
    MessageParcel closeUssdData;
    closeUssdData.WriteInt32(size);
    closeUssdData.WriteInt32(errorSize);
    callStub.OnCloseUnFinishedUssdInner(closeUssdData, reply);
    MessageParcel clearCallsData;
    MakeCallInfoParcelData(false, clearCallsData);
    callStub.OnClearAllCallsInner(clearCallsData, reply);
}

/**
 * @tc.number   Telephony_CellularCallStub_006
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallStub_006, Function | MediumTest | Level3)
{
    AccessToken token;
    CellularCallService callStub;
    int32_t errorSize = -1;
    int32_t size = 1;
    MessageParcel reply;
    MessageParcel setPreviewData;
    setPreviewData.WriteInt32(errorSize);
    callStub.OnSetPreviewWindowInner(setPreviewData, reply);
    MessageParcel setDisplayData;
    setDisplayData.WriteInt32(errorSize);
    callStub.OnSetDisplayWindowInner(setDisplayData, reply);
    MessageParcel setCameraData;
    setCameraData.WriteInt32(errorSize);
    callStub.OnSetCameraZoomInner(setCameraData, reply);
    MessageParcel setImageData;
    setImageData.WriteInt32(errorSize);
    callStub.OnSetPausePictureInner(setImageData, reply);
    MessageParcel setDirectionData;
    setDirectionData.WriteInt32(errorSize);
    callStub.OnSetDeviceDirectionInner(setDirectionData, reply);

    MessageParcel setEmergencyData;
    setEmergencyData.WriteInt32(size);
    setEmergencyData.WriteInt32(errorSize);
    setEmergencyData.WriteInt32(size);
    if (setEmergencyData.WriteString("123") && setEmergencyData.WriteString("456") &&
        setEmergencyData.WriteInt32(size) && setEmergencyData.WriteInt32(size) && setEmergencyData.WriteInt32(size)) {
        callStub.OnSetEmergencyCallList(setEmergencyData, reply);
    }

    MessageParcel registerData;
    registerData.WriteInt32(size);
    callStub.OnRegisterCallBackInner(registerData, reply);
    MessageParcel unRegisterData;
    unRegisterData.WriteInt32(errorSize);
    callStub.OnUnRegisterCallBackInner(unRegisterData, reply);
    MessageParcel inviteData;
    registerData.WriteInt32(size);
    inviteData.WriteInt32(errorSize);
    callStub.OnInviteToConferenceInner(inviteData, reply);
    MessageParcel startRttData;
    startRttData.WriteInt32(size);
    startRttData.WriteInt32(errorSize);
    startRttData.WriteString("1");
    callStub.OnStartRttInner(startRttData, reply);
    MessageParcel stopRttData;
    stopRttData.WriteInt32(size);
    stopRttData.WriteInt32(errorSize);
    callStub.OnStopRttInner(stopRttData, reply);
}

/**
 * @tc.number   Telephony_CellularCallStub_007
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallStub_007, Function | MediumTest | Level3)
{
    AccessToken token;
    CellularCallService callStub;
    int32_t size = 1;
    MessageParcel reply;
    MessageParcel callMediaModeRequestData;
    MakeCallInfoParcelData(false, callMediaModeRequestData);
    ImsCallMode requestMode = ImsCallMode::CALL_MODE_AUDIO_ONLY;
    callMediaModeRequestData.WriteInt32(static_cast<int32_t>(requestMode));
    callStub.OnSendUpdateCallMediaModeRequestInner(callMediaModeRequestData, reply);

    MessageParcel callMediaModeResponseData;
    MakeCallInfoParcelData(false, callMediaModeResponseData);
    ImsCallMode responseMode = ImsCallMode::CALL_MODE_AUDIO_ONLY;
    callMediaModeResponseData.WriteInt32(static_cast<int32_t>(responseMode));
    callStub.OnSendUpdateCallMediaModeResponseInner(callMediaModeResponseData, reply);

    MessageParcel callUpgradeData;
    callUpgradeData.WriteInt32(size);
    callUpgradeData.WriteInt32(SIM1_SLOTID);
    callUpgradeData.WriteInt32(DEFAULT_INDEX);
    callStub.OnCancelCallUpgradeInner(callUpgradeData, reply);

    MessageParcel cameraCapabilitiesData;
    cameraCapabilitiesData.WriteInt32(size);
    cameraCapabilitiesData.WriteInt32(SIM1_SLOTID);
    cameraCapabilitiesData.WriteInt32(DEFAULT_INDEX);
    callStub.OnRequestCameraCapabilitiesInner(cameraCapabilitiesData, reply);
}

/**
 * @tc.number   Telephony_CellularCallService_001
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallService_001, Function | MediumTest | Level3)
{
    // AccessToken token;
    CellularCallService cellularCall;
    std::vector<std::u16string> args = { u"1", u"2" };
    cellularCall.Dump(-1, args);
    cellularCall.Dump(1, args);
    cellularCall.GetServiceRunningState();
    cellularCall.GetBindTime();
    cellularCall.GetEndTime();
    cellularCall.GetSpendTime();

    CellularCallInfo csCallInfo = { .callType = CallType::TYPE_CS };
    CellularCallInfo imsCallInfo = { .callType = CallType::TYPE_IMS };
    CellularCallInfo errCallInfo = { .callType = CallType::TYPE_ERR_CALL };
    cellularCall.Dial(csCallInfo);
    cellularCall.Dial(imsCallInfo);
    cellularCall.Dial(errCallInfo);

    cellularCall.HangUp(csCallInfo, CallSupplementType::TYPE_HANG_UP_HOLD_WAIT);
    cellularCall.HangUp(imsCallInfo, CallSupplementType::TYPE_HANG_UP_HOLD_WAIT);
    cellularCall.HangUp(errCallInfo, CallSupplementType::TYPE_HANG_UP_HOLD_WAIT);

    cellularCall.Reject(csCallInfo);
    cellularCall.Reject(imsCallInfo);
    cellularCall.Reject(errCallInfo);

    cellularCall.Answer(csCallInfo);
    cellularCall.Answer(imsCallInfo);
    cellularCall.Answer(errCallInfo);

    cellularCall.HoldCall(csCallInfo);
    cellularCall.HoldCall(imsCallInfo);
    cellularCall.HoldCall(errCallInfo);

    cellularCall.UnHoldCall(csCallInfo);
    cellularCall.UnHoldCall(imsCallInfo);
    cellularCall.UnHoldCall(errCallInfo);

    cellularCall.SwitchCall(csCallInfo);
    cellularCall.SwitchCall(imsCallInfo);
    cellularCall.SwitchCall(errCallInfo);

    bool enabled = false;
    std::string phoneNum = "000";
    cellularCall.IsEmergencyPhoneNumber(INVALID_SLOTID, phoneNum, enabled);
    cellularCall.IsEmergencyPhoneNumber(SIM1_SLOTID, phoneNum, enabled);
}

/**
 * @tc.number   Telephony_CellularCallService_002
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallService_002, Function | MediumTest | Level3)
{
    // AccessToken token;
    CellularCallService cellularCall;
    CellularCallInfo csCallInfo = { .callType = CallType::TYPE_CS };
    CellularCallInfo imsCallInfo = { .callType = CallType::TYPE_IMS };
    CellularCallInfo errCallInfo = { .callType = CallType::TYPE_ERR_CALL };
    EmergencyCall ecc;
    std::vector<EmergencyCall> eccVec;
    eccVec.push_back(ecc);
    cellularCall.SetEmergencyCallList(SIM1_SLOTID, eccVec);
    cellularCall.CombineConference(csCallInfo);
    cellularCall.CombineConference(imsCallInfo);
    cellularCall.CombineConference(errCallInfo);

    cellularCall.SeparateConference(csCallInfo);
    cellularCall.SeparateConference(imsCallInfo);
    cellularCall.SeparateConference(errCallInfo);

    std::vector<std::string> numberList = { "111", "222" };
    cellularCall.InviteToConference(SIM1_SLOTID, numberList);
    cellularCall.KickOutFromConference(csCallInfo);
    cellularCall.KickOutFromConference(imsCallInfo);
    cellularCall.KickOutFromConference(errCallInfo);
    cellularCall.HangUpAllConnection();
    cellularCall.HangUpAllConnection(SIM1_SLOTID);

    cellularCall.SetReadyToCall(SIM1_SLOTID, 0, true);
    cellularCall.SetReadyToCall(SIM1_SLOTID, 1, true);
    cellularCall.SetReadyToCall(SIM1_SLOTID, 3, true);
    cellularCall.StartDtmf('*', csCallInfo);
    cellularCall.StartDtmf('*', imsCallInfo);
    cellularCall.StartDtmf('*', errCallInfo);
    cellularCall.StopDtmf(csCallInfo);
    cellularCall.StopDtmf(imsCallInfo);
    cellularCall.StopDtmf(errCallInfo);

    cellularCall.PostDialProceed(csCallInfo, true);
    cellularCall.PostDialProceed(imsCallInfo, true);
    cellularCall.PostDialProceed(errCallInfo, true);
    cellularCall.SendDtmf('*', csCallInfo);
    cellularCall.SendDtmf('*', imsCallInfo);
    cellularCall.SendDtmf('*', errCallInfo);
    std::string msg = "";
    cellularCall.StartRtt(SIM1_SLOTID, msg);
    cellularCall.StopRtt(SIM1_SLOTID);
}

/**
 * @tc.number   Telephony_CellularCallService_003
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallService_003, Function | MediumTest | Level3)
{
    AccessToken token;
    CellularCallService cellularCall;
    CallTransferInfo cTInfoDisable = { .settingType = CallTransferSettingType::CALL_TRANSFER_DISABLE };
    CallTransferInfo cTInfoEnable = { .settingType = CallTransferSettingType::CALL_TRANSFER_ENABLE };
    cellularCall.SetCallTransferInfo(SIM1_SLOTID, cTInfoDisable);
    cellularCall.SetCallTransferInfo(SIM1_SLOTID, cTInfoEnable);
    bool result = false;
    cellularCall.CanSetCallTransferTime(SIM1_SLOTID, result);
    cellularCall.GetCallTransferInfo(SIM1_SLOTID, CallTransferType::TRANSFER_TYPE_UNCONDITIONAL);
    cellularCall.SetCallWaiting(SIM1_SLOTID, true);
    cellularCall.GetCallWaiting(SIM1_SLOTID);
    CallRestrictionInfo crInfo;
    cellularCall.SetCallRestriction(SIM1_SLOTID, crInfo);
    cellularCall.GetCallRestriction(SIM1_SLOTID, CallRestrictionType::RESTRICTION_TYPE_ALL_INCOMING);
    std::string password = "1111";
    cellularCall.SetCallRestrictionPassword(
        SIM1_SLOTID, CallRestrictionType::RESTRICTION_TYPE_ALL_INCOMING, password.c_str(), password.c_str());
    cellularCall.SetDomainPreferenceMode(SIM1_SLOTID, 1);
    cellularCall.GetDomainPreferenceMode(SIM1_SLOTID);
    cellularCall.SetImsSwitchStatus(SIM1_SLOTID, true);
    bool enabled = false;
    cellularCall.GetImsSwitchStatus(SIM1_SLOTID, enabled);
    std::string value = "";
    cellularCall.SetImsConfig(SIM1_SLOTID, ImsConfigItem::ITEM_VIDEO_QUALITY, value);
    int32_t state = 0;
    cellularCall.SetVoNRState(SIM1_SLOTID, state);
    cellularCall.GetVoNRState(SIM1_SLOTID, state);
    cellularCall.SetImsConfig(SIM1_SLOTID, ImsConfigItem::ITEM_VIDEO_QUALITY, 1);
    cellularCall.GetImsConfig(SIM1_SLOTID, ImsConfigItem::ITEM_VIDEO_QUALITY);
    cellularCall.SetImsFeatureValue(SIM1_SLOTID, FeatureType::TYPE_VOICE_OVER_LTE, 1);
    cellularCall.GetImsFeatureValue(SIM1_SLOTID, FeatureType::TYPE_VOICE_OVER_LTE);
    std::string cameraId = "";
    cellularCall.ControlCamera(SIM1_SLOTID, DEFAULT_INDEX, cameraId);
    std::string surfaceId = "";
    cellularCall.SetPreviewWindow(SIM1_SLOTID, DEFAULT_INDEX, surfaceId, nullptr);
    cellularCall.SetDisplayWindow(SIM1_SLOTID, DEFAULT_INDEX, surfaceId, nullptr);
    cellularCall.SetCameraZoom(1.0);
    std::string path = "";
    cellularCall.SetPausePicture(SIM1_SLOTID, DEFAULT_INDEX, path);
    cellularCall.SetDeviceDirection(SIM1_SLOTID, DEFAULT_INDEX, 0);
    CellularCallInfo cellularCallInfo;
    InitCellularCallInfo(SIM1_SLOTID, PHONE_NUMBER, cellularCallInfo);
    cellularCall.SendUpdateCallMediaModeRequest(cellularCallInfo, ImsCallMode::CALL_MODE_AUDIO_ONLY);
    cellularCall.SendUpdateCallMediaModeResponse(cellularCallInfo, ImsCallMode::CALL_MODE_AUDIO_ONLY);
    cellularCall.CancelCallUpgrade(SIM1_SLOTID, DEFAULT_INDEX);
    cellularCall.RequestCameraCapabilities(SIM1_SLOTID, DEFAULT_INDEX);
}

/**
 * @tc.number   Telephony_CellularCallService_004
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallService_004, Function | MediumTest | Level3)
{
    // AccessToken token;
    CellularCallService cellularCall;
    cellularCall.SetMute(SIM1_SLOTID, 0);
    cellularCall.GetMute(SIM1_SLOTID);
    cellularCall.CloseUnFinishedUssd(SIM1_SLOTID);
    std::vector<CellularCallInfo> infos = {};
    cellularCall.ClearAllCalls(infos);
    cellularCall.IsNeedIms(SIM1_SLOTID);
    cellularCall.GetCsControl(SIM1_SLOTID);
    cellularCall.GetImsControl(SIM1_SLOTID);
    std::shared_ptr<CSControl> csControl;
    cellularCall.SetCsControl(SIM1_SLOTID, csControl);
    std::shared_ptr<IMSControl> imsControl;
    cellularCall.SetImsControl(SIM1_SLOTID, imsControl);
    cellularCall.GetHandler(SIM1_SLOTID);
    cellularCall.SetSrvccState(SrvccState::SRVCC_NONE);
    cellularCall.GetSrvccState();
    cellularCall.RegisterHandler();
#ifdef CALL_MANAGER_AUTO_START_OPTIMIZE
    cellularCall.StartCallManagerService();
#endif
    cellularCall.Init();
    cellularCall.RegisterCoreServiceHandler();
    cellularCall.CreateHandler();
    cellularCall.SendEventRegisterHandler();

    cellularCall.IsValidSlotId(SIM1_SLOTID);
    CellularCallInfo imsCallInfo = { .callType = CallType::TYPE_IMS };
    CellularCallInfo csCallInfo = { .callType = CallType::TYPE_CS };
    cellularCall.UseImsForEmergency(imsCallInfo, true);
    cellularCall.HandleCallManagerException();
    cellularCall.HandleCellularControlException(imsCallInfo);
    cellularCall.HandleCellularControlException(csCallInfo);
    cellularCall.HangUpWithCellularCallRestart(infos);
    cellularCall.SetControl(imsCallInfo);
    cellularCall.SetControl(csCallInfo);

    sptr<ICallStatusCallback> callback;
    cellularCall.RegisterCallManagerCallBack(callback);
    cellularCall.UnRegisterCallManagerCallBack();
    cellularCall.HandlerResetUnRegister();
    cellularCall.OnStop();
}

/**
 * @tc.number	Telephony_CellularCallSupplementRequestIms_001
 * @tc.name 	Test error branch
 * @tc.desc 	Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallSupplementRequestIms_001, Function | MediumTest | Level3)
{
    SupplementRequestIms SRequestIms;
    CallTransferInfo CTransferInfo;
    std::string fac = "";
    SRequestIms.SetClipRequest(SIM1_SLOTID, ACTIVATE_ACTION, 0);
    SRequestIms.GetClipRequest(SIM1_SLOTID, 0);
    SRequestIms.SetClirRequest(SIM1_SLOTID, ACTIVATE_ACTION, 0);
    SRequestIms.GetClirRequest(SIM1_SLOTID, 0);
    SRequestIms.GetCallTransferRequest(SIM1_SLOTID, 0, 0);
    SRequestIms.SetCallTransferRequest(SIM1_SLOTID, CTransferInfo, ACTIVATE_ACTION, 0);
    SRequestIms.GetCallRestrictionRequest(SIM1_SLOTID, fac, 0);
    std::string pw = "";
    SRequestIms.SetCallRestrictionRequest(SIM1_SLOTID, fac, 0, pw, 0);
    SRequestIms.SetCallWaitingRequest(SIM1_SLOTID, true, 0, 0);
    SRequestIms.GetCallWaitingRequest(SIM1_SLOTID, 0);
    SRequestIms.SetColrRequest(SIM1_SLOTID, 0, 0);
    SRequestIms.GetColrRequest(SIM1_SLOTID, 0);
    SRequestIms.SetColpRequest(SIM1_SLOTID, 0, 0);
    SRequestIms.GetColpRequest(SIM1_SLOTID, 0);
    SRequestIms.GetMMIHandler(SIM1_SLOTID);
}

/**
 * @tc.number	Telephony_CellularCallbaseconnection_001
 * @tc.name 	Test error branch
 * @tc.desc 	Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallbaseconnection_001, Function | MediumTest | Level3)
{
    BaseConnection BConnection;
    char c = ' ';
    BConnection.postDialCalltate_ = PostDialCallState::POST_DIAL_CALL_CANCELED;
    BConnection.ProcessNextChar(SIM1_SLOTID, c);
    BConnection.GetLeftPostDialCallString();
    BConnection.postDialCallString_ = "111111";
    BConnection.ProcessNextChar(SIM1_SLOTID, c);
    BConnection.postDialCalltate_ = PostDialCallState::POST_DIAL_CALL_NOT_STARTED;
    BConnection.ProcessNextChar(SIM1_SLOTID, c);
    BConnection.GetLeftPostDialCallString();
}
/**
 * @tc.number   Telephony_CellularCallHiSysEvent_001
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallHiSysEvent_001, Function | MediumTest | Level3)
{
    // AccessToken token;
    std::shared_ptr<CellularCallHiSysEvent> cellularCallHiSysEvent = std::make_shared<CellularCallHiSysEvent>();
    std::string desc;
    cellularCallHiSysEvent->WriteFoundationRestartFaultEvent(2);
    CallBehaviorParameterInfo Info = { .callType = 1 };
    CallResponseResult result = CallResponseResult::COMMAND_FAILURE;
    cellularCallHiSysEvent->WriteDialCallBehaviorEvent(Info, result);
    result = CallResponseResult::COMMAND_SUCCESS;
    cellularCallHiSysEvent->WriteDialCallBehaviorEvent(Info, result);
    Info = { .callType = 0 };
    cellularCallHiSysEvent->WriteDialCallBehaviorEvent(Info, result);
    Info = { .callType = 1 };
    result = CallResponseResult::COMMAND_FAILURE;
    cellularCallHiSysEvent->WriteHangUpCallBehaviorEvent(Info, result);
    result = CallResponseResult::COMMAND_SUCCESS;
    cellularCallHiSysEvent->WriteHangUpCallBehaviorEvent(Info, result);
    Info = { .callType = 0 };
    cellularCallHiSysEvent->WriteHangUpCallBehaviorEvent(Info, result);
    cellularCallHiSysEvent->WriteIncomingCallFaultEvent(
        0, 0, 0, static_cast<int32_t>(TELEPHONY_ERR_MEMCPY_FAIL), desc);
    cellularCallHiSysEvent->WriteIncomingCallFaultEvent(0, 0, 0, -1, desc);
    cellularCallHiSysEvent->JudgingIncomingTimeOut(0, 0, 0);
    CallForwardingInfo cfInfo;
    cellularCallHiSysEvent->GetCallForwardingInfo(cfInfo);
}

/**
 * @tc.number   Telephony_CellularCallHiSysEvent_002
 * @tc.name     Test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallHiSysEvent_002, Function | MediumTest | Level3)
{
    // AccessToken token;
    std::shared_ptr<CellularCallHiSysEvent> cellularCallHiSysEvent = std::make_shared<CellularCallHiSysEvent>();
    CallErrorCode eventValue;
    cellularCallHiSysEvent->TelephonyErrorCodeConversion(-1, eventValue);
    cellularCallHiSysEvent->TelephonyErrorCodeConversion(
        static_cast<int32_t>(TELEPHONY_ERR_LOCAL_PTR_NULL), eventValue);
    cellularCallHiSysEvent->TelephonyErrorCodeConversion(
        static_cast<int32_t>(TELEPHONY_ERR_ARGUMENT_INVALID), eventValue);
    cellularCallHiSysEvent->TelephonyErrorCodeConversion(
        static_cast<int32_t>(TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL), eventValue);
    cellularCallHiSysEvent->TelephonyErrorCodeConversion(
        static_cast<int32_t>(TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL), eventValue);
    cellularCallHiSysEvent->TelephonyErrorCodeConversion(
        static_cast<int32_t>(TELEPHONY_ERR_WRITE_DATA_FAIL), eventValue);
    cellularCallHiSysEvent->TelephonyErrorCodeConversion(
        static_cast<int32_t>(TELEPHONY_ERR_PERMISSION_ERR), eventValue);
    cellularCallHiSysEvent->TelephonyErrorCodeConversion(static_cast<int32_t>(TELEPHONY_ERR_MEMSET_FAIL), eventValue);
    cellularCallHiSysEvent->TelephonyErrorCodeConversion(static_cast<int32_t>(TELEPHONY_ERR_MEMCPY_FAIL), eventValue);
    cellularCallHiSysEvent->CallDataErrorCodeConversion(-1, eventValue);
    cellularCallHiSysEvent->CallDataErrorCodeConversion(static_cast<int32_t>(CALL_ERR_INVALID_SLOT_ID), eventValue);
    cellularCallHiSysEvent->CallDataErrorCodeConversion(static_cast<int32_t>(CALL_ERR_INVALID_CALLID), eventValue);
    cellularCallHiSysEvent->CallDataErrorCodeConversion(static_cast<int32_t>(CALL_ERR_PHONE_NUMBER_EMPTY), eventValue);
    cellularCallHiSysEvent->CallDataErrorCodeConversion(
        static_cast<int32_t>(CALL_ERR_NUMBER_OUT_OF_RANGE), eventValue);
    cellularCallHiSysEvent->CallDataErrorCodeConversion(
        static_cast<int32_t>(CALL_ERR_UNSUPPORTED_NETWORK_TYPE), eventValue);
    cellularCallHiSysEvent->CallDataErrorCodeConversion(static_cast<int32_t>(CALL_ERR_INVALID_DIAL_SCENE), eventValue);
    cellularCallHiSysEvent->CallDataErrorCodeConversion(
        static_cast<int32_t>(CALL_ERR_INVALID_VIDEO_STATE), eventValue);
    cellularCallHiSysEvent->CallDataErrorCodeConversion(static_cast<int32_t>(CALL_ERR_UNKNOW_DIAL_TYPE), eventValue);
    cellularCallHiSysEvent->CallDataErrorCodeConversion(static_cast<int32_t>(CALL_ERR_UNKNOW_CALL_TYPE), eventValue);
    cellularCallHiSysEvent->CallDataErrorCodeConversion(
        static_cast<int32_t>(CALL_ERR_CALL_OBJECT_IS_NULL), eventValue);
    cellularCallHiSysEvent->CallInterfaceErrorCodeConversion(-1, eventValue);
    cellularCallHiSysEvent->CallInterfaceErrorCodeConversion(static_cast<int32_t>(CALL_ERR_DIAL_IS_BUSY), eventValue);
    cellularCallHiSysEvent->CallInterfaceErrorCodeConversion(
        static_cast<int32_t>(CALL_ERR_ILLEGAL_CALL_OPERATION), eventValue);
    cellularCallHiSysEvent->CallInterfaceErrorCodeConversion(
        static_cast<int32_t>(CALL_ERR_PHONE_CALLSTATE_NOTIFY_FAILED), eventValue);
    cellularCallHiSysEvent->CallInterfaceErrorCodeConversion(
        static_cast<int32_t>(CALL_ERR_SYSTEM_EVENT_HANDLE_FAILURE), eventValue);
    cellularCallHiSysEvent->CallInterfaceErrorCodeConversion(
        static_cast<int32_t>(CALL_ERR_CALL_COUNTS_EXCEED_LIMIT), eventValue);
    cellularCallHiSysEvent->CallInterfaceErrorCodeConversion(
        static_cast<int32_t>(CALL_ERR_GET_RADIO_STATE_FAILED), eventValue);
}

/**
 * @tc.number	Telephony_CellularCallConnectionCs_001
 * @tc.name 	Test error branch
 * @tc.desc 	Function test
 */
HWTEST_F(BranchTest, Telephony_CellularCallConnectionCs_001, Function | MediumTest | Level3)
{
    CellularCallConnectionCS cellularCallConnectionCS;
    DialRequestStruct dialRequestStruct;
    cellularCallConnectionCS.DialRequest(SIM2_SLOTID, dialRequestStruct);
    cellularCallConnectionCS.HangUpRequest(SIM2_SLOTID);
    cellularCallConnectionCS.AnswerRequest(SIM2_SLOTID);
    cellularCallConnectionCS.AnswerRequest(SIM1_SLOTID);
    cellularCallConnectionCS.RejectRequest(SIM2_SLOTID);
    cellularCallConnectionCS.HoldRequest(SIM2_SLOTID);
    cellularCallConnectionCS.UnHoldCallRequest(SIM2_SLOTID);
    cellularCallConnectionCS.SwitchCallRequest(SIM2_SLOTID);
    cellularCallConnectionCS.CombineConferenceRequest(SIM2_SLOTID, 0);
    cellularCallConnectionCS.SeparateConferenceRequest(SIM2_SLOTID, 0, 0);
    cellularCallConnectionCS.CallSupplementRequest(SIM2_SLOTID, CallSupplementType::TYPE_DEFAULT);
    char cDtmfCode = ' ';
    cellularCallConnectionCS.SendDtmfRequest(SIM2_SLOTID, cDtmfCode, 0);
    cellularCallConnectionCS.StartDtmfRequest(SIM2_SLOTID, cDtmfCode, 0);
    cellularCallConnectionCS.StopDtmfRequest(SIM2_SLOTID, 0);
    cellularCallConnectionCS.GetCsCallsDataRequest(SIM2_SLOTID, 0);
    cellularCallConnectionCS.GetCallFailReasonRequest(SIM2_SLOTID);
    cellularCallConnectionCS.ProcessPostDialCallChar(SIM1_SLOTID, cDtmfCode);
}

/**
 * @tc.number	Telephony_SupplementRequestCs_001
 * @tc.name 	Test error branch
 * @tc.desc 	Function test
 */
HWTEST_F(BranchTest, Telephony_SupplementRequestCs_001, Function | MediumTest | Level3)
{
    SupplementRequestCs supplementRequestCs;
    std::string msg = "11111";
    supplementRequestCs.SendUssdRequest(SIM1_SLOTID, msg);
    supplementRequestCs.CloseUnFinishedUssdRequest(SIM1_SLOTID);
}

/**
 * @tc.number	Telephony_StandardizeUtils_001
 * @tc.name 	Test error branch
 * @tc.desc 	Function test
 */
HWTEST_F(BranchTest, Telephony_StandardizeUtils_001, Function | MediumTest | Level3)
{
    StandardizeUtils standardizeUtils;
    std::string phoneString = {0};
    std::string networkAddress = "1111111";
    std::string postDial = "11111111";
    standardizeUtils.RemoveSeparatorsPhoneNumber(phoneString);
    phoneString = "1111111,123321";
    standardizeUtils.ExtractAddressAndPostDial(phoneString, networkAddress, postDial);
    standardizeUtils.Split(phoneString, ",");
}

/**
 * @tc.number	Telephony_MmiCodeUtils_001
 * @tc.name 	Test error branch
 * @tc.desc 	Function test
 */
HWTEST_F(BranchTest, Telephony_MmiCodeUtils_001, Function | MediumTest | Level3)
{
    MMICodeUtils mmiCodeUtils;
    bool enable = false;
    mmiCodeUtils.IsNeedExecuteMmi("111111#", enable);
    mmiCodeUtils.isNeedUseIms_ = true;
    mmiCodeUtils.ExecuteMmiCode(SIM1_SLOTID);
    mmiCodeUtils.isNeedUseIms_ = false;
    mmiCodeUtils.mmiData_.serviceCode = "11111";
    mmiCodeUtils.ExecuteMmiCode(SIM1_SLOTID);
    mmiCodeUtils.mmiData_.serviceCode.clear();
    mmiCodeUtils.mmiData_.fullString = "11111";
    mmiCodeUtils.ExecuteMmiCode(SIM1_SLOTID);
    mmiCodeUtils.mmiData_.fullString.clear();
    mmiCodeUtils.mmiData_.dialString = "11111#";
    mmiCodeUtils.RegexMatchMmi("111111#");
}
} // namespace Telephony
} // namespace OHOS
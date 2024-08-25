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

#include "registercallmanagercallback_fuzzer.h"

#include <cstddef>
#include <cstdint>
#define private public
#include "addcellularcalltoken_fuzzer.h"
#include "cellular_call_register.h"
#include "cellular_call_service.h"
#include "tel_ril_call_parcel.h"
#include "radio_event.h"
#include "securec.h"
#include "system_ability_definition.h"

using namespace OHOS::Telephony;
namespace OHOS {
static bool g_isInited = false;
constexpr int32_t SLOT_NUM = 2;
constexpr int32_t BOOL_NUM = 2;
constexpr int32_t CALL_STATE_NUM = 8;
constexpr int32_t EVENT_ID_NUM = 20;

bool IsServiceInited()
{
    if (!g_isInited) {
        DelayedSingleton<CellularCallService>::GetInstance()->OnStart();
    }
    if (!g_isInited && (static_cast<int32_t>(DelayedSingleton<CellularCallService>::GetInstance()->state_) ==
                           static_cast<int32_t>(ServiceRunningState::STATE_RUNNING))) {
        g_isInited = true;
    }
    return g_isInited;
}

void ReportCallsInfo(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    std::shared_ptr<CellularCallRegister> cellularCallRegister = DelayedSingleton<CellularCallRegister>::GetInstance();
    CallsReportInfo callsReportInfo;
    callsReportInfo.slotId = static_cast<int32_t>(size % SLOT_NUM);
    CallReportInfo callReportInfo;
    std::string number(reinterpret_cast<const char *>(data), size);
    int32_t length = number.length() > kMaxNumberLen ? kMaxNumberLen : number.length();
    if (memcpy_s(callReportInfo.accountNum, kMaxNumberLen, number.c_str(), length) != EOK) {
        return;
    }
    sptr<ICallStatusCallback> callback = nullptr;
    TelCallState callState = static_cast<TelCallState>(size % CALL_STATE_NUM);
    CellularCallEventInfo info;
    info.eventType = CellularCallEventType::EVENT_REQUEST_RESULT_TYPE;
    info.eventId = static_cast<RequestResultEventId>(size % EVENT_ID_NUM);
    CallWaitResponse response;
    response.classCw = static_cast<int32_t>(size);
    response.result = static_cast<int32_t>(size % BOOL_NUM);
    response.status = static_cast<int32_t>(size % BOOL_NUM);
    int32_t result = static_cast<int32_t>(size % BOOL_NUM);
    CallRestrictionResponse callRestrictionResponse;
    callRestrictionResponse.classCw = static_cast<int32_t>(size);
    callRestrictionResponse.result = static_cast<int32_t>(size % BOOL_NUM);
    callRestrictionResponse.status = static_cast<int32_t>(size % BOOL_NUM);

    cellularCallRegister->ReportCallsInfo(callsReportInfo);
    cellularCallRegister->RegisterCallManagerCallBack(callback);
    cellularCallRegister->ReportSingleCallInfo(callReportInfo, callState);
    cellularCallRegister->UnRegisterCallManagerCallBack();
    cellularCallRegister->ReportEventResultInfo(info);
    cellularCallRegister->ReportGetWaitingResult(response);
    cellularCallRegister->ReportSetWaitingResult(result);
    cellularCallRegister->ReportGetRestrictionResult(callRestrictionResponse);
    cellularCallRegister->ReportSetBarringPasswordResult(result);
}

void ReportSetRestrictionResult(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    std::shared_ptr<CellularCallRegister> cellularCallRegister = DelayedSingleton<CellularCallRegister>::GetInstance();
    int32_t result = static_cast<int32_t>(size % BOOL_NUM);
    CallTransferResponse callTransferResponse;
    callTransferResponse.result = static_cast<int32_t>(size);
    callTransferResponse.status = static_cast<int32_t>(size);
    callTransferResponse.classx = static_cast<int32_t>(size);
    callTransferResponse.type = static_cast<int32_t>(size);
    callTransferResponse.time = static_cast<int32_t>(size);
    callTransferResponse.reason = static_cast<int32_t>(size);
    std::string number(reinterpret_cast<const char *>(data), size);
    int32_t length = number.length() > kMaxNumberLen ? kMaxNumberLen : number.length();
    if (memcpy_s(callTransferResponse.number, kMaxNumberLen, number.c_str(), length) != EOK) {
        return;
    }
    ClipResponse clipResponse;
    clipResponse.action = static_cast<int32_t>(size);
    clipResponse.result = static_cast<int32_t>(size);
    clipResponse.clipStat = static_cast<int32_t>(size);
    ClirResponse clirResponse;
    clirResponse.clirStat = static_cast<int32_t>(size);
    clirResponse.action = static_cast<int32_t>(size);
    clirResponse.result = static_cast<int32_t>(size);
    GetImsConfigResponse getImsConfigResponse;
    getImsConfigResponse.result = static_cast<int32_t>(size);
    getImsConfigResponse.value = static_cast<int32_t>(size);

    cellularCallRegister->ReportSetRestrictionResult(result);
    cellularCallRegister->ReportGetTransferResult(callTransferResponse);
    cellularCallRegister->ReportSetTransferResult(result);
    cellularCallRegister->ReportGetClipResult(clipResponse);
    cellularCallRegister->ReportGetClirResult(clirResponse);
    cellularCallRegister->ReportSetClirResult(result);
    cellularCallRegister->ReportGetImsConfigResult(getImsConfigResponse);
    cellularCallRegister->ReportSetImsConfigResult(result);
    cellularCallRegister->ReportSetImsFeatureResult(result);
}

void ReportSetImsConfigResult(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    std::shared_ptr<CellularCallRegister> cellularCallRegister = DelayedSingleton<CellularCallRegister>::GetInstance();
    int32_t result = static_cast<int32_t>(size % BOOL_NUM);
    GetImsFeatureValueResponse getImsFeatureValueResponse;
    getImsFeatureValueResponse.result = static_cast<int32_t>(size);
    getImsFeatureValueResponse.value = static_cast<int32_t>(size);
    GetLteEnhanceModeResponse getLteEnhanceModeResponse;
    getLteEnhanceModeResponse.result = static_cast<int32_t>(size);
    getLteEnhanceModeResponse.value = static_cast<int32_t>(size);
    DisconnectedDetails details;
    std::string number(reinterpret_cast<const char *>(data), size);
    details.message = number;
    details.reason = static_cast<DisconnectedReason>(size);
    MuteControlResponse muteControlResponse;
    muteControlResponse.result = static_cast<int32_t>(size);
    muteControlResponse.value = static_cast<int32_t>(size);
    SetEccListResponse setEccListResponse;
    setEccListResponse.result = static_cast<int32_t>(size);
    setEccListResponse.value = static_cast<int32_t>(size);
    MmiCodeInfo mmiCodeInfo;
    mmiCodeInfo.result = static_cast<int32_t>(size);
    int32_t length = number.length() > kMaxNumberLen ? kMaxNumberLen : number.length();
    if (memcpy_s(mmiCodeInfo.message, kMaxNumberLen, number.c_str(), length) != EOK) {
        return;
    }

    cellularCallRegister->ReportGetImsFeatureResult(getImsFeatureValueResponse);
    cellularCallRegister->ReportCallRingBackResult(result);
    cellularCallRegister->ReportCallFailReason(details);
    cellularCallRegister->ReportGetMuteResult(muteControlResponse);
    cellularCallRegister->ReportSetMuteResult(muteControlResponse);
    cellularCallRegister->ReportInviteToConferenceResult(result);
    cellularCallRegister->ReportGetCallDataResult(result);
    cellularCallRegister->ReportStartDtmfResult(result);
    cellularCallRegister->ReportStopDtmfResult(result);
    cellularCallRegister->ReportStartRttResult(result);
    cellularCallRegister->ReportStopRttResult(result);
    cellularCallRegister->ReportSendUssdResult(result);
    cellularCallRegister->ReportMmiCodeResult(mmiCodeInfo);
    cellularCallRegister->ReportSetEmergencyCallListResponse(setEccListResponse);
    cellularCallRegister->IsCallManagerCallBackRegistered();
}

void ReportUpdateCallMediaMode(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    std::shared_ptr<CellularCallRegister> cellularCallRegister = DelayedSingleton<CellularCallRegister>::GetInstance();
    ImsCallModeReceiveInfo reportCallModeInfo;
    reportCallModeInfo.callIndex = static_cast<int32_t>(size);
    reportCallModeInfo.result = static_cast<ImsCallModeRequestResult>(size);
    reportCallModeInfo.callType = static_cast<ImsCallType>(static_cast<int32_t>(size % BOOL_NUM));
    cellularCallRegister->ReceiveUpdateCallMediaModeRequest(reportCallModeInfo);
    cellularCallRegister->ReceiveUpdateCallMediaModeResponse(reportCallModeInfo);
}

void ReportCallSessionEventChanged(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    std::shared_ptr<CellularCallRegister> cellularCallRegister = DelayedSingleton<CellularCallRegister>::GetInstance();
    ImsCallSessionEventInfo reportCallSessionInfo;
    reportCallSessionInfo.callIndex = static_cast<int32_t>(size);
    reportCallSessionInfo.eventType = static_cast<VideoCallEventType>(static_cast<int32_t>(size % BOOL_NUM));
    cellularCallRegister->HandleCallSessionEventChanged(reportCallSessionInfo);
}

void ReportPeerDimensionsChanged(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    std::shared_ptr<CellularCallRegister> cellularCallRegister = DelayedSingleton<CellularCallRegister>::GetInstance();
    ImsCallPeerDimensionsInfo reportCallPeerDimensionsInfo;
    reportCallPeerDimensionsInfo.callIndex = static_cast<int32_t>(size);
    reportCallPeerDimensionsInfo.width = static_cast<int32_t>(size);
    reportCallPeerDimensionsInfo.height = static_cast<int32_t>(size);
    cellularCallRegister->HandlePeerDimensionsChanged(reportCallPeerDimensionsInfo);
}

void ReportCallDataUsageChanged(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    std::shared_ptr<CellularCallRegister> cellularCallRegister = DelayedSingleton<CellularCallRegister>::GetInstance();
    ImsCallDataUsageInfo reportCallDataUsageInfo;
    reportCallDataUsageInfo.callIndex = static_cast<int32_t>(size);
    reportCallDataUsageInfo.dataUsage = static_cast<int64_t>(size);
    cellularCallRegister->HandleCallDataUsageChanged(reportCallDataUsageInfo);
}

void ReportCameraCapabilitiesChanged(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    std::shared_ptr<CellularCallRegister> cellularCallRegister = DelayedSingleton<CellularCallRegister>::GetInstance();
    CameraCapabilitiesInfo reportCameraCapabilitiesInfo;
    reportCameraCapabilitiesInfo.callIndex = static_cast<int32_t>(size);
    reportCameraCapabilitiesInfo.width = static_cast<int32_t>(size);
    reportCameraCapabilitiesInfo.height = static_cast<int32_t>(size);
    cellularCallRegister->HandleCameraCapabilitiesChanged(reportCameraCapabilitiesInfo);
}

void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    ReportCallsInfo(data, size);
    ReportSetRestrictionResult(data, size);
    ReportSetImsConfigResult(data, size);
    ReportUpdateCallMediaMode(data, size);
    ReportCallSessionEventChanged(data, size);
    ReportPeerDimensionsChanged(data, size);
    ReportCallDataUsageChanged(data, size);
    ReportCameraCapabilitiesChanged(data, size);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::AddCellularCallTokenFuzzer token;
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}

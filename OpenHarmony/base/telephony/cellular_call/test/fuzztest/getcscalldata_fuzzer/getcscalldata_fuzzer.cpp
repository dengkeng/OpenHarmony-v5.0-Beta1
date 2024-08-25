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

#include "getcscalldata_fuzzer.h"

#include <cstddef>
#include <cstdint>
#define private public
#include "addcellularcalltoken_fuzzer.h"
#include "cellular_call_handler.h"
#include "cellular_call_service.h"
#include "tel_ril_call_parcel.h"
#include "radio_event.h"
#include "securec.h"
#include "system_ability_definition.h"

using namespace OHOS::Telephony;
namespace OHOS {
static bool g_isInited = false;
constexpr int32_t SLOT_NUM = 2;
constexpr int32_t STATE_NUM = 9;

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

void GetCsCallData(std::shared_ptr<CellularCallHandler> handle, AppExecFwk::InnerEvent::Pointer event,
    const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    std::string number(reinterpret_cast<const char *>(data), size);
    CallInfo info;
    CallInfoList infoList;
    info.number = number;
    infoList.calls.push_back(info);
    int32_t state = static_cast<int32_t>(size % STATE_NUM);
    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);

    handle->GetCsCallData(event);
    handle->GetImsCallData(event);
    handle->GetSatelliteCallData(event);
    handle->ImsCallStatusInfoReport(event);
    handle->SatelliteCallStatusInfoReport(event);
    handle->CellularCallIncomingStartTrace(state);
    handle->GetCsCallsDataResponse(event);
    handle->GetImsCallsDataResponse(event);
    handle->GetSatelliteCallsDataResponse(event);
    handle->DialResponse(event);
    handle->DialSatelliteResponse(event);
    handle->SendDtmfResponse(event);
    handle->StartDtmfResponse(event);
    handle->SimStateChangeReport(event);
    handle->SimRecordsLoadedReport(event);
    handle->StopDtmfResponse(event);
    handle->SetSlotId(slotId);
    handle->GetSlotId();
    handle->CurrentTimeMillis();
    handle->GetCsCallsDataRequest(event);
    handle->GetImsCallsDataRequest(event);
    handle->GetSatelliteCallsDataRequest(event);
    handle->ReportCsCallsData(infoList);
}

void RegisterHandler(std::shared_ptr<CellularCallHandler> handle, AppExecFwk::InnerEvent::Pointer event,
    const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    std::string number(reinterpret_cast<const char *>(data), size);
    ImsCurrentCall info;
    ImsCurrentCallList infoList;
    info.number = number;
    infoList.calls.push_back(info);

    SatelliteCurrentCall satelliteInfo;
    SatelliteCurrentCallList satelliteInfoList;
    satelliteInfo.number = number;
    satelliteInfoList.calls.push_back(satelliteInfo);

    handle->RegisterHandler(event);
    handle->SetDomainPreferenceModeResponse(event);
    handle->GetDomainPreferenceModeResponse(event);
    handle->SetImsSwitchStatusResponse(event);
    handle->GetImsSwitchStatusResponse(event);
    handle->UssdNotifyResponse(event);
    handle->SetMuteResponse(event);
    handle->GetMuteResponse(event);
    handle->GetEmergencyCallListResponse(event);
    handle->SetEmergencyCallListResponse(event);
    handle->CallRingBackVoiceResponse(event);
    handle->GetCallFailReasonResponse(event);
    handle->UpdateSrvccStateReport(event);
    handle->ReportEccChanged(event);
    handle->SrvccStateCompleted();
    handle->GetMMIResponse(event);
    handle->GetCallWaitingResponse(event);
    handle->GetClirResponse(event);
    handle->ReportImsCallsData(infoList);
    handle->ReportSatelliteCallsData(satelliteInfoList);
    handle->SetClirResponse(event);
    handle->GetClipResponse(event);
    handle->SetCallTransferInfoResponse(event);
    handle->GetCallRestrictionResponse(event);
    handle->SetCallRestrictionResponse(event);
    handle->SetBarringPasswordResponse(event);
    handle->SendUssdResponse(event);
    handle->SendUnlockPinPukResponse(event);
    handle->HandleOperatorConfigChanged(event);
    handle->UpdateRsrvccStateReport(event);
    handle->SetVoNRSwitchStatusResponse(event);
}

void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    RadioEvent radioEvent = static_cast<RadioEvent>(size);
    std::shared_ptr<CellularCallHandler> handle =
        DelayedSingleton<CellularCallService>::GetInstance()->GetHandler(slotId);
    if (handle == nullptr) {
        return;
    }
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(radioEvent);
    GetCsCallData(handle, std::move(event), data, size);
    event = AppExecFwk::InnerEvent::Get(radioEvent);
    RegisterHandler(handle, std::move(event), data, size);
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

/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "satellitecallback_fuzzer.h"

#include <cstddef>
#include <cstdint>
#define private public
#include "addcellularcalltoken_fuzzer.h"
#include "cellular_call_service.h"
#include "satellite_call_callback_stub.h"
#include "satellite_call_client.h"
#include "satellite_call_proxy.h"
#include "securec.h"
#include "system_ability_definition.h"
#include "telephony_types.h"

using namespace OHOS::Telephony;
namespace OHOS {
static bool g_isInited = false;
constexpr int32_t SERVICE_STATE_RUNNING = 1;
constexpr int32_t BOOL_NUM = 2;
constexpr int32_t SERIAL_NUM = 3;
constexpr int32_t ERROR_NUM = 15;
constexpr int32_t TYPE_NUM = 5;

bool IsServiceInited()
{
    auto service = DelayedSingleton<CellularCallService>::GetInstance();
    if (service == nullptr) {
        return g_isInited;
    }
    if (service->GetServiceRunningState() != SERVICE_STATE_RUNNING) {
        service->OnStart();
    }

    if (!g_isInited && service->GetServiceRunningState() == SERVICE_STATE_RUNNING) {
        g_isInited = true;
    }
    return g_isInited;
}

void OnRemoteRequest(const uint8_t *data, size_t size, sptr<SatelliteCallCallbackStub> &stub)
{
    MessageParcel dataMessageParcel;
    if (!dataMessageParcel.WriteInterfaceToken(SatelliteCallCallbackStub::GetDescriptor())) {
        return;
    }
    int32_t slotId = ERROR_NUM;
    dataMessageParcel.WriteInt32(slotId);
    uint32_t code = static_cast<uint32_t>(size);
    MessageParcel reply;
    MessageOption option;
    stub->OnRemoteRequest(code, dataMessageParcel, reply, option);
}

void TestSatelliteCallCallbackFunction(const uint8_t *data, size_t size, sptr<SatelliteCallCallbackStub> &stub)
{
    int32_t slotId = ERROR_NUM;
    RadioResponseInfo rilRadioResponse;
    rilRadioResponse.flag = static_cast<int32_t>(size % BOOL_NUM);
    rilRadioResponse.serial = static_cast<int32_t>(size % SERIAL_NUM);
    rilRadioResponse.error = static_cast<ErrType>(size % ERROR_NUM);
    rilRadioResponse.type = static_cast<ResponseTypes>(size % TYPE_NUM);
    MessageParcel answerData;
    MessageParcel answerReply;
    answerData.WriteInt32(slotId);
    stub->OnAnswerResponseInner(answerData, answerReply);

    MessageParcel dialData;
    MessageParcel dialReply;
    dialData.WriteInt32(slotId);
    stub->OnDialResponseInner(dialData, dialReply);

    MessageParcel hangupData;
    MessageParcel hangupReply;
    hangupData.WriteInt32(slotId);
    stub->OnHangUpResponseInner(hangupData, hangupReply);

    MessageParcel rejectData;
    MessageParcel rejectReply;
    rejectData.WriteInt32(slotId);
    stub->OnRejectResponseInner(rejectData, rejectReply);

    MessageParcel satelliteCallsData;
    MessageParcel satelliteCallsReply;
    slotId = ERROR_NUM;
    satelliteCallsData.WriteInt32(slotId);
    satelliteCallsData.WriteRawData((const void *)&rilRadioResponse, sizeof(RadioResponseInfo));
    stub->OnGetSatelliteCallsDataResponseInner(satelliteCallsData, satelliteCallsReply);

    MessageParcel callData;
    MessageParcel callReply;
    callData.WriteInt32(slotId);
    stub->OnCallStateChangeReportInner(callData, callReply);
}

void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    if (!IsServiceInited()) {
        return;
    }

    sptr<SatelliteCallCallbackStub> stub = (std::make_unique<SatelliteCallCallbackStub>()).release();
    if (stub == nullptr) {
        return;
    }

    OnRemoteRequest(data, size, stub);
    TestSatelliteCallCallbackFunction(data, size, stub);
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

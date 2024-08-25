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
#include "satellitecallrequest_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "addcellularcalltoken_fuzzer.h"
#include "cellular_call_connection_satellite.h"
#include "cellular_call_data_struct.h"
#include "system_ability_definition.h"

using namespace OHOS::Telephony;
namespace OHOS {
constexpr int32_t SLOT_NUM = 2;

void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    auto cellularCallConnectionSatellite = std::make_unique<CellularCallConnectionSatellite>().release();
    std::string phoneNum(reinterpret_cast<const char *>(data), size);
    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    int64_t lastCallsDataFlag = static_cast<int64_t>(size);
    DialRequestStruct dialRequest;
    dialRequest.phoneNum = phoneNum;
    cellularCallConnectionSatellite->DialRequest(slotId, dialRequest);
    cellularCallConnectionSatellite->HangUpRequest(slotId);
    cellularCallConnectionSatellite->AnswerRequest(slotId);
    cellularCallConnectionSatellite->RejectRequest(slotId);
    cellularCallConnectionSatellite->GetSatelliteCallsDataRequest(slotId, lastCallsDataFlag);
    cellularCallConnectionSatellite->GetCallFailReasonRequest(slotId);
    return;
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

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

#include "satelliteclient_fuzzer.h"

#include <cstddef>
#include <cstdint>
#define private public
#include "addcellularcalltoken_fuzzer.h"
#include "cellular_call_service.h"
#include "satellite_call_client.h"
#include "satellite_call_proxy.h"
#include "securec.h"
#include "system_ability_definition.h"

using namespace OHOS::Telephony;
namespace OHOS {
static bool g_isInited = false;
constexpr int32_t SERVICE_STATE_RUNNING = 1;
const uint32_t TELEPHONY_SATELLITE_SYS_ABILITY_ID = 4012;
enum {
    NUM_ONE = 1,
    NUM_TWO,
    NUM_THREE,
    NUM_FOUR,
    NUM_FIVE,
    NUM_SIX,
    NUM_SEVEN,
    NUM_EIGHT,
};

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

void TestSatelliteCallClientWithCallInfo(
    const uint8_t *data, size_t size, const std::shared_ptr<SatelliteCallClient> &satelliteCallClient)
{
    SatelliteCallInfo callInfo;
    if (memset_s(&callInfo, sizeof(struct SatelliteCallInfo), 0x00, sizeof(struct SatelliteCallInfo)) != EOK) {
        return;
    }
    size_t length = std::min(static_cast<size_t>(sizeof(callInfo.phoneNum) - 1), size);
    std::string number(reinterpret_cast<const char *>(data), length);
    int32_t mode = static_cast<int32_t>(size % NUM_THREE);
    int32_t slotId = static_cast<int32_t>(size % NUM_TWO);
    int32_t index = static_cast<int32_t>(size % NUM_THREE);
    if (strcpy_s(callInfo.phoneNum, sizeof(callInfo.phoneNum), number.c_str()) != EOK) {
        return;
    }
    callInfo.slotId = slotId;
    callInfo.index = index;
    satelliteCallClient->Dial(callInfo, static_cast<CLIRMode>(mode));
    satelliteCallClient->HangUp(slotId, index);
    satelliteCallClient->Answer(slotId);
    satelliteCallClient->Reject(slotId);

    int32_t callType = static_cast<int32_t>(size % NUM_TWO);
    satelliteCallClient->GetSatelliteCallsDataRequest(slotId, callType);
}

void TestSatelliteCallProxyWithCallInfo(const uint8_t *data, size_t size, const sptr<SatelliteCallInterface> &proxy)
{
    SatelliteCallInfo callInfo;
    if (memset_s(&callInfo, sizeof(struct SatelliteCallInfo), 0x00, sizeof(struct SatelliteCallInfo)) != EOK) {
        return;
    }
    size_t length = std::min(static_cast<size_t>(sizeof(callInfo.phoneNum) - 1), size);
    std::string number(reinterpret_cast<const char *>(data), length);
    int32_t mode = static_cast<int32_t>(size % NUM_THREE);
    int32_t slotId = static_cast<int32_t>(size % NUM_TWO);
    int32_t index = static_cast<int32_t>(size % NUM_THREE);
    if (strcpy_s(callInfo.phoneNum, sizeof(callInfo.phoneNum), number.c_str()) != EOK) {
        return;
    }
    callInfo.slotId = slotId;
    callInfo.index = index;

    proxy->Dial(callInfo, static_cast<CLIRMode>(mode));
    proxy->HangUp(slotId, index);
    proxy->Answer(slotId);
    proxy->Reject(slotId);

    proxy->GetSatelliteCallsDataRequest(slotId);
}

void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    auto satelliteCallClient = DelayedSingleton<SatelliteCallClient>::GetInstance();
    if (satelliteCallClient == nullptr) {
        return;
    }
    if (!IsServiceInited()) {
        return;
    }
    TestSatelliteCallClientWithCallInfo(data, size, satelliteCallClient);

    auto managerPtr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (managerPtr == nullptr) {
        return;
    }
    auto remoteObjectPtr = managerPtr->CheckSystemAbility(TELEPHONY_SATELLITE_SYS_ABILITY_ID);
    if (remoteObjectPtr == nullptr) {
        return;
    }
    sptr<SatelliteCallInterface> proxy = iface_cast<SatelliteCallInterface>(remoteObjectPtr);
    if (proxy == nullptr) {
        return;
    }
    TestSatelliteCallProxyWithCallInfo(data, size, proxy);
    proxy.clear();
    proxy = nullptr;
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

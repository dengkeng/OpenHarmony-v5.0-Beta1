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

#include "setorupdatecallreportinfo_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "addcellularcalltoken_fuzzer.h"
#include "base_connection.h"
#include "securec.h"
#include "system_ability_definition.h"

using namespace OHOS::Telephony;
namespace OHOS {
constexpr int32_t SLOT_NUM = 2;
constexpr int32_t BOOL_NUM = 2;
constexpr size_t MAX_NUMBER_LEN = 99;

void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    auto baseConnection = std::make_shared<BaseConnection>();
    int32_t accountId = static_cast<int32_t>(size % SLOT_NUM);
    int32_t index = static_cast<int32_t>(size);
    int32_t flag = static_cast<int32_t>(size % BOOL_NUM);
    int32_t voiceDomain = static_cast<int32_t>(size % BOOL_NUM);
    std::string phoneNum = "000000000";
    std::string tempNum(reinterpret_cast<const char *>(data), size);
    if (strlen(tempNum.c_str()) <= MAX_NUMBER_LEN) {
        phoneNum = tempNum;
    }
    size_t length = strlen(phoneNum.c_str()) + 1;
    CallReportInfo callReportInfo;
    callReportInfo.index = index;
    callReportInfo.accountId = accountId;
    callReportInfo.callType = CallType::TYPE_CS;
    callReportInfo.callMode = VideoStateType::TYPE_VIDEO;
    callReportInfo.state = TelCallState::CALL_STATUS_ACTIVE;
    callReportInfo.voiceDomain = voiceDomain;
    if (strcpy_s(callReportInfo.accountNum, length, phoneNum.c_str()) != EOK) {
        return;
    }
    baseConnection->SetOrUpdateCallReportInfo(callReportInfo);
    baseConnection->GetStatus();
    baseConnection->IsRingingState();
    baseConnection->SetFlag(flag);
    baseConnection->GetFlag();
    baseConnection->SetIndex(index);
    baseConnection->GetIndex();
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

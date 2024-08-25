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

#include "devicegetcachestub_fuzzer.h"

#include "singleton.h"

#define private public
#include "devicestatus_service.h"
#include "message_parcel.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

namespace OHOS {

void DeviceStatusGetCacheFuzzTest(const uint8_t* data, size_t size)
{
    const std::u16string FORMMGR_DEVICE_TOKEN { u"ohos.msdp.Idevicestatus" };
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_DEVICE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<DeviceStatusService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(Msdp::DeviceInterfaceCode::DEVICESTATUS_GETCACHE), datas, reply, option);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    OHOS::DeviceStatusGetCacheFuzzTest(data, size);
    return 0;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS

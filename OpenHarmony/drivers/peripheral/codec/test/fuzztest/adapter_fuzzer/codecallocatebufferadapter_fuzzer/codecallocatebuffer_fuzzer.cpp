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

#include "codecallocatebuffer_fuzzer.h"
#include "codeccommon_fuzzer.h"

namespace OHOS {
namespace Codec {
bool CodecAllocateBuffer(const uint8_t *data, size_t size)
{
    bool result = Preconditions();
    if (!result) {
        HDF_LOGE("%{public}s: Preconditions failed", __func__);
        return false;
    }

    struct OmxCodecBuffer buffer;
    FillDataOmxCodecBuffer(&buffer);
    int32_t ret =
        g_component->AllocateBuffer(g_component, *(reinterpret_cast<uint32_t *>(const_cast<uint8_t *>(data))), &buffer);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: AllocateBuffer failed", __func__);
    }

    if (buffer.buffer != nullptr) {
        OsalMemFree(buffer.buffer);
    }

    result = Destroy();
    if (!result) {
        HDF_LOGE("%{public}s: Destroy failed", __func__);
    }

    return (result && ret == HDF_SUCCESS);
}
} // namespace Codec
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Codec::CodecAllocateBuffer(data, size);
    return 0;
}
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

#include "unlock_fuzzer.h"

#include <cstring>
#include <securec.h>

#include "power_mgr_client_adapter_impl.h"

using namespace OHOS::NWeb;

namespace OHOS {
    bool UnLockFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }
        std::shared_ptr<OHOS::PowerMgr::RunningLock> lock;
        RunningLockAdapterImpl runningLockAdapter(lock);
        runningLockAdapter.UnLock();
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::UnLockFuzzTest(data, size);
    return 0;
}

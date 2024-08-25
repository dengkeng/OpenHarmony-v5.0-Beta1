/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "setdisplaybind_fuzzer.h"

#include "securec.h"

#include "input_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "SetDisplayBindFuzzTest"

namespace OHOS {
namespace MMI {
template<class T>
size_t GetObject(T &object, const uint8_t *data, size_t size)
{
    size_t objectSize = sizeof(object);
    if (objectSize > size) {
        return 0;
    }
    errno_t ret = memcpy_s(&object, objectSize, data, objectSize);
    if (ret != EOK) {
        return 0;
    }
    return objectSize;
}

void SetDisplayBindFuzzTest(const uint8_t* data, size_t size)
{
    size_t startPos = 0;
    int32_t deviceId;
    startPos += GetObject<int32_t>(deviceId, data + startPos, size - startPos);
    int32_t displayId;
    startPos += GetObject<int32_t>(displayId, data + startPos, size - startPos);
    std::string msg(reinterpret_cast<const char*>(data), size);
    MMI_HILOGD("SetDisplayBind start");
    InputManager::GetInstance()->SetDisplayBind(deviceId, displayId, msg);
}
} // MMI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::MMI::SetDisplayBindFuzzTest(data, size);
    return 0;
}


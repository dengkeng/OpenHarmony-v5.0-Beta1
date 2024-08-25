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

#ifndef AV_HARDWARE_MEMORY_H
#define AV_HARDWARE_MEMORY_H

#include <mutex>
#include "buffer/avallocator.h"
#include "buffer/avbuffer.h"

namespace OHOS {
namespace Media {
class AVHardwareMemory : public AVMemory {
public:
    AVHardwareMemory();
    ~AVHardwareMemory() override;
    MemoryType GetMemoryType() override;
    int32_t GetFileDescriptor() override;
    MemoryFlag GetMemoryFlag() override;

private:
    Status Init() override;
    Status Init(MessageParcel &parcel) override;
    bool WriteToMessageParcel(MessageParcel &parcel) override;
    bool ReadFromMessageParcel(MessageParcel &parcel) override;
    Status MapMemoryAddr();
    std::mutex mutex_;
    int32_t fd_;
    bool isStartSync_;
    MemoryFlag memFlag_;
};
} // namespace Media
} // namespace OHOS
#endif // AV_HARDWARE_MEMORY_H
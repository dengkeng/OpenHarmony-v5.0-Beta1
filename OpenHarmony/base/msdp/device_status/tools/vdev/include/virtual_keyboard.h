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

#ifndef VIRTUAL_KEYBOARD_H
#define VIRTUAL_KEYBOARD_H

#include "virtual_device.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class VirtualKeyboard final : public VirtualDevice {
public:
    static VirtualKeyboard *GetDevice();
    ~VirtualKeyboard() = default;
    DISALLOW_COPY_AND_MOVE(VirtualKeyboard);

    int32_t Down(int32_t key);
    int32_t Up(int32_t key);

private:
    explicit VirtualKeyboard(const std::string &name);

private:
    static VirtualKeyboard *device_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // VIRTUAL_KEYBOARD_H
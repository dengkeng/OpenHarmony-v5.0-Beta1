/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef USB_PORT_H
#define USB_PORT_H

#include <string>
#include <vector>
#include "usb_common.h"

namespace OHOS {
namespace USB {
struct UsbPortStatus {
    int32_t currentMode;
    int32_t currentPowerRole;
    int32_t currentDataRole;
};
struct UsbPort {
    int32_t id;
    int32_t supportedModes;
    UsbPortStatus usbPortStatus;
};
} // namespace USB
} // namespace OHOS
#endif // USB_PORT_H

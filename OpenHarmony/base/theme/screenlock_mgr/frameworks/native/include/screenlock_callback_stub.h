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

#ifndef SCREENLOCK_CALLBACK_STUB_H
#define SCREENLOCK_CALLBACK_STUB_H

#include <cstdint>

#include "iremote_stub.h"
#include "screenlock_callback_interface.h"
#include "visibility.h"

namespace OHOS {
namespace ScreenLock {
class ScreenLockCallbackStub : public IRemoteStub<ScreenLockCallbackInterface> {
public:
    SCREENLOCK_API ScreenLockCallbackStub() = default;
    SCREENLOCK_API ~ScreenLockCallbackStub() override;
    SCREENLOCK_API void OnCallBack(int32_t screenLockResult) override;
    SCREENLOCK_API int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) override;
};
} // namespace ScreenLock
} // namespace OHOS
#endif // SCREENLOCK_CALLBACK_STUB_H

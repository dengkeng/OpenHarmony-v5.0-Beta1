/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_STATUS_BAR_DELEGATE_STUB_H
#define OHOS_ABILITY_RUNTIME_STATUS_BAR_DELEGATE_STUB_H

#include <vector>

#include <iremote_object.h>
#include <iremote_stub.h>

#include "nocopyable.h"
#include "status_bar_delegate_interface.h"

namespace OHOS {
namespace AbilityRuntime {
class StatusBarDelegateStub : public IRemoteStub<IStatusBarDelegate> {
public:
    StatusBarDelegateStub();
    virtual ~StatusBarDelegateStub() = default;

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    DISALLOW_COPY_AND_MOVE(StatusBarDelegateStub);

    int32_t HandleCheckIfStatusBarItemExists(MessageParcel &data, MessageParcel &reply);
    int32_t HandleAttachPidToStatusBarItem(MessageParcel &data, MessageParcel &reply);

    using StatusBarDelegateStubFunc = int (StatusBarDelegateStub::*)(MessageParcel &data, MessageParcel &reply);
    std::vector<StatusBarDelegateStubFunc> vecMemberFunc_;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_AUTO_STARTUP_CALLBACK_STUB_H

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
#ifndef SEC_COMP_MOCK_SYSTEM_ABILITY_IF_MANAGER_CLINET_INCLUDE_H
#define SEC_COMP_MOCK_SYSTEM_ABILITY_IF_MANAGER_CLINET_INCLUDE_H
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "mock_app_mgr_proxy.h"

namespace OHOS {
class MockIRemoteObject : public virtual RefBase {
public:
    bool AddDeathRecipient(const sptr<IPCObjectProxy::DeathRecipient>& recipient)
    {
        (void)recipient;
        return addResult;
    }
    bool addResult = true;
};

template <typename INTERFACE> inline sptr<INTERFACE> iface_cast(const sptr<MockIRemoteObject> &object)
{
    if (object == nullptr) {
        return nullptr;
    }
    const std::u16string descriptor = INTERFACE::GetDescriptor();
    if (descriptor == u"ohos.appexecfwk.mock.AppMgr") {
        return static_cast<INTERFACE *>(MockAppMgrProxy::g_MockAppMgrProxy);
    }
    return nullptr;
}

class ISystemAbilityManager : public IRemoteBroker {
public:
    virtual sptr<MockIRemoteObject> GetSystemAbility(int32_t systemAbilityId) = 0;
    virtual int32_t UnloadSystemAbility(int32_t systemAbilityId) = 0;
};
}  // namespace OHOS
#endif  // SEC_COMP_MOCK_SYSTEM_ABILITY_IF_MANAGER_CLINET_INCLUDE_H

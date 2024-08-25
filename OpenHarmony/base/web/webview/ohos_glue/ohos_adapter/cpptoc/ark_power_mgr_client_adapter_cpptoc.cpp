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

#include "ohos_adapter/cpptoc/ark_power_mgr_client_adapter_cpptoc.h"

#include "ohos_adapter/cpptoc/ark_running_lock_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

ark_running_lock_adapter_t* ARK_WEB_CALLBACK ark_power_mgr_client_adapter_create_running_lock(
    struct _ark_power_mgr_client_adapter_t* self, const ArkWebString* name, uint32_t type)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    ARK_WEB_CPPTOC_CHECK_PARAM(name, NULL);

    // Execute
    ArkWebRefPtr<ArkRunningLockAdapter> _retval =
        ArkPowerMgrClientAdapterCppToC::Get(self)->CreateRunningLock(*name, type);

    // Return type: refptr_same
    return ArkRunningLockAdapterCppToC::Invert(_retval);
}

} // namespace

ArkPowerMgrClientAdapterCppToC::ArkPowerMgrClientAdapterCppToC()
{
    GetStruct()->create_running_lock = ark_power_mgr_client_adapter_create_running_lock;
}

ArkPowerMgrClientAdapterCppToC::~ArkPowerMgrClientAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkPowerMgrClientAdapterCppToC, ArkPowerMgrClientAdapter,
    ark_power_mgr_client_adapter_t>::kBridgeType = ARK_POWER_MGR_CLIENT_ADAPTER;

} // namespace OHOS::ArkWeb

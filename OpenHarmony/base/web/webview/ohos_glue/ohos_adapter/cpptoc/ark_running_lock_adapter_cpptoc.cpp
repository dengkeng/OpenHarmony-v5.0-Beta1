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

#include "ohos_adapter/cpptoc/ark_running_lock_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

bool ARK_WEB_CALLBACK ark_running_lock_adapter_is_used(struct _ark_running_lock_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkRunningLockAdapterCppToC::Get(self)->IsUsed();
}

int32_t ARK_WEB_CALLBACK ark_running_lock_adapter_lock(struct _ark_running_lock_adapter_t* self, uint32_t timeOutMs)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkRunningLockAdapterCppToC::Get(self)->Lock(timeOutMs);
}

int32_t ARK_WEB_CALLBACK ark_running_lock_adapter_un_lock(struct _ark_running_lock_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkRunningLockAdapterCppToC::Get(self)->UnLock();
}

} // namespace

ArkRunningLockAdapterCppToC::ArkRunningLockAdapterCppToC()
{
    GetStruct()->is_used = ark_running_lock_adapter_is_used;
    GetStruct()->lock = ark_running_lock_adapter_lock;
    GetStruct()->un_lock = ark_running_lock_adapter_un_lock;
}

ArkRunningLockAdapterCppToC::~ArkRunningLockAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkRunningLockAdapterCppToC, ArkRunningLockAdapter,
    ark_running_lock_adapter_t>::kBridgeType = ARK_RUNNING_LOCK_ADAPTER;

} // namespace OHOS::ArkWeb

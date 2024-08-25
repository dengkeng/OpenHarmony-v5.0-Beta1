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

#include "ohos_adapter/cpptoc/ark_vsync_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

uint32_t ARK_WEB_CALLBACK ark_vsync_adapter_request_vsync(struct _ark_vsync_adapter_t* self, void* data, void* cb)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(data, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(cb, 0);

    // Execute
    return ArkVSyncAdapterCppToC::Get(self)->RequestVsync(data, cb);
}

int64_t ARK_WEB_CALLBACK ark_vsync_adapter_get_vsync_period(struct _ark_vsync_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkVSyncAdapterCppToC::Get(self)->GetVSyncPeriod();
}

void ARK_WEB_CALLBACK ark_vsync_adapter_set_frame_rate_linker_enable(struct _ark_vsync_adapter_t* self, bool enabled)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkVSyncAdapterCppToC::Get(self)->SetFrameRateLinkerEnable(enabled);
}

void ARK_WEB_CALLBACK ark_vsync_adapter_set_frame_preferred_rate(
    struct _ark_vsync_adapter_t* self, int32_t preferredRate)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkVSyncAdapterCppToC::Get(self)->SetFramePreferredRate(preferredRate);
}

void ARK_WEB_CALLBACK ark_vsync_adapter_set_on_vsync_callback(
    struct _ark_vsync_adapter_t* self, void (*callback)())
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkVSyncAdapterCppToC::Get(self)->SetOnVsyncCallback(callback);
}

} // namespace

ArkVSyncAdapterCppToC::ArkVSyncAdapterCppToC()
{
    GetStruct()->request_vsync = ark_vsync_adapter_request_vsync;
    GetStruct()->get_vsync_period = ark_vsync_adapter_get_vsync_period;
    GetStruct()->set_frame_rate_linker_enable = ark_vsync_adapter_set_frame_rate_linker_enable;
    GetStruct()->set_frame_preferred_rate = ark_vsync_adapter_set_frame_preferred_rate;
    GetStruct()->set_on_vsync_callback = ark_vsync_adapter_set_on_vsync_callback;
}

ArkVSyncAdapterCppToC::~ArkVSyncAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkVSyncAdapterCppToC, ArkVSyncAdapter, ark_vsync_adapter_t>::kBridgeType =
    ARK_VSYNC_ADAPTER;

} // namespace OHOS::ArkWeb

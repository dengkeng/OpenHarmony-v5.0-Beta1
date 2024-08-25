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

#include "ohos_adapter/cpptoc/ark_capability_data_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

int32_t ARK_WEB_CALLBACK ark_capability_data_adapter_get_max_width(struct _ark_capability_data_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkCapabilityDataAdapterCppToC::Get(self)->GetMaxWidth();
}

int32_t ARK_WEB_CALLBACK ark_capability_data_adapter_get_max_height(struct _ark_capability_data_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkCapabilityDataAdapterCppToC::Get(self)->GetMaxHeight();
}

int32_t ARK_WEB_CALLBACK ark_capability_data_adapter_get_maxframe_rate(struct _ark_capability_data_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkCapabilityDataAdapterCppToC::Get(self)->GetMaxframeRate();
}

} // namespace

ArkCapabilityDataAdapterCppToC::ArkCapabilityDataAdapterCppToC()
{
    GetStruct()->get_max_width = ark_capability_data_adapter_get_max_width;
    GetStruct()->get_max_height = ark_capability_data_adapter_get_max_height;
    GetStruct()->get_maxframe_rate = ark_capability_data_adapter_get_maxframe_rate;
}

ArkCapabilityDataAdapterCppToC::~ArkCapabilityDataAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkCapabilityDataAdapterCppToC, ArkCapabilityDataAdapter,
    ark_capability_data_adapter_t>::kBridgeType = ARK_CAPABILITY_DATA_ADAPTER;

} // namespace OHOS::ArkWeb

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

#include "ohos_adapter/cpptoc/ark_buffer_info_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

int64_t ARK_WEB_CALLBACK ark_buffer_info_adapter_get_presentation_time_us(struct _ark_buffer_info_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkBufferInfoAdapterCppToC::Get(self)->GetPresentationTimeUs();
}

int32_t ARK_WEB_CALLBACK ark_buffer_info_adapter_get_size(struct _ark_buffer_info_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkBufferInfoAdapterCppToC::Get(self)->GetSize();
}

int32_t ARK_WEB_CALLBACK ark_buffer_info_adapter_get_offset(struct _ark_buffer_info_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkBufferInfoAdapterCppToC::Get(self)->GetOffset();
}

} // namespace

ArkBufferInfoAdapterCppToC::ArkBufferInfoAdapterCppToC()
{
    GetStruct()->get_presentation_time_us = ark_buffer_info_adapter_get_presentation_time_us;
    GetStruct()->get_size = ark_buffer_info_adapter_get_size;
    GetStruct()->get_offset = ark_buffer_info_adapter_get_offset;
}

ArkBufferInfoAdapterCppToC::~ArkBufferInfoAdapterCppToC() {}

template<>
ArkWebBridgeType
    ArkWebCppToCRefCounted<ArkBufferInfoAdapterCppToC, ArkBufferInfoAdapter, ark_buffer_info_adapter_t>::kBridgeType =
        ARK_BUFFER_INFO_ADAPTER;

} // namespace OHOS::ArkWeb

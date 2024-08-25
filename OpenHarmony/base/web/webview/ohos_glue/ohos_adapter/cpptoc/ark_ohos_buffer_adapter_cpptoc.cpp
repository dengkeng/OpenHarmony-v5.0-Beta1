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

#include "ohos_adapter/cpptoc/ark_ohos_buffer_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

uint8_t* ARK_WEB_CALLBACK ark_ohos_buffer_adapter_get_addr(struct _ark_ohos_buffer_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    return ArkOhosBufferAdapterCppToC::Get(self)->GetAddr();
}

uint32_t ARK_WEB_CALLBACK ark_ohos_buffer_adapter_get_buffer_size(struct _ark_ohos_buffer_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkOhosBufferAdapterCppToC::Get(self)->GetBufferSize();
}

} // namespace

ArkOhosBufferAdapterCppToC::ArkOhosBufferAdapterCppToC()
{
    GetStruct()->get_addr = ark_ohos_buffer_adapter_get_addr;
    GetStruct()->get_buffer_size = ark_ohos_buffer_adapter_get_buffer_size;
}

ArkOhosBufferAdapterCppToC::~ArkOhosBufferAdapterCppToC() {}

template<>
ArkWebBridgeType
    ArkWebCppToCRefCounted<ArkOhosBufferAdapterCppToC, ArkOhosBufferAdapter, ark_ohos_buffer_adapter_t>::kBridgeType =
        ARK_OHOS_BUFFER_ADAPTER;

} // namespace OHOS::ArkWeb

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

#include "ohos_adapter/cpptoc/ark_flowbuffer_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

void ARK_WEB_CALLBACK ark_flowbuffer_adapter_start_performance_boost(struct _ark_flowbuffer_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkFlowbufferAdapterCppToC::Get(self)->StartPerformanceBoost();
}

void* ARK_WEB_CALLBACK ark_flowbuffer_adapter_create_ashmem(
    struct _ark_flowbuffer_adapter_t* self, size_t size, int mapType, int* fd)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    ARK_WEB_CPPTOC_CHECK_PARAM(fd, NULL);

    // Execute
    return ArkFlowbufferAdapterCppToC::Get(self)->CreateAshmem(size, mapType, *fd);
}

void* ARK_WEB_CALLBACK ark_flowbuffer_adapter_create_ashmem_with_fd(
    struct _ark_flowbuffer_adapter_t* self, const int fd, size_t size, int mapType)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    return ArkFlowbufferAdapterCppToC::Get(self)->CreateAshmemWithFd(fd, size, mapType);
}

} // namespace

ArkFlowbufferAdapterCppToC::ArkFlowbufferAdapterCppToC()
{
    GetStruct()->start_performance_boost = ark_flowbuffer_adapter_start_performance_boost;
    GetStruct()->create_ashmem = ark_flowbuffer_adapter_create_ashmem;
    GetStruct()->create_ashmem_with_fd = ark_flowbuffer_adapter_create_ashmem_with_fd;
}

ArkFlowbufferAdapterCppToC::~ArkFlowbufferAdapterCppToC() {}

template<>
ArkWebBridgeType
    ArkWebCppToCRefCounted<ArkFlowbufferAdapterCppToC, ArkFlowbufferAdapter, ark_flowbuffer_adapter_t>::kBridgeType =
        ARK_FLOWBUFFER_ADAPTER;

} // namespace OHOS::ArkWeb

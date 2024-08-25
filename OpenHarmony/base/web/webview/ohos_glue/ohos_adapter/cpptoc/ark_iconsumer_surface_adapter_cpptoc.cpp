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

#include "ohos_adapter/cpptoc/ark_iconsumer_surface_adapter_cpptoc.h"

#include "ohos_adapter/cpptoc/ark_surface_buffer_adapter_cpptoc.h"
#include "ohos_adapter/ctocpp/ark_ibuffer_consumer_listener_adapter_ctocpp.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

int32_t ARK_WEB_CALLBACK ark_iconsumer_surface_adapter_register_consumer_listener(
    struct _ark_iconsumer_surface_adapter_t* self, ark_ibuffer_consumer_listener_adapter_t* listener)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkIConsumerSurfaceAdapterCppToC::Get(self)->RegisterConsumerListener(
        ArkIBufferConsumerListenerAdapterCToCpp::Invert(listener));
}

int32_t ARK_WEB_CALLBACK ark_iconsumer_surface_adapter_release_buffer(
    struct _ark_iconsumer_surface_adapter_t* self, ark_surface_buffer_adapter_t* buffer, int32_t fence)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkIConsumerSurfaceAdapterCppToC::Get(self)->ReleaseBuffer(
        ArkSurfaceBufferAdapterCppToC::Revert(buffer), fence);
}

int32_t ARK_WEB_CALLBACK ark_iconsumer_surface_adapter_set_user_data(
    struct _ark_iconsumer_surface_adapter_t* self, const ArkWebString* key, const ArkWebString* val)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(key, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(val, 0);

    // Execute
    return ArkIConsumerSurfaceAdapterCppToC::Get(self)->SetUserData(*key, *val);
}

int32_t ARK_WEB_CALLBACK ark_iconsumer_surface_adapter_set_queue_size(
    struct _ark_iconsumer_surface_adapter_t* self, uint32_t queueSize)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkIConsumerSurfaceAdapterCppToC::Get(self)->SetQueueSize(queueSize);
}

} // namespace

ArkIConsumerSurfaceAdapterCppToC::ArkIConsumerSurfaceAdapterCppToC()
{
    GetStruct()->register_consumer_listener = ark_iconsumer_surface_adapter_register_consumer_listener;
    GetStruct()->release_buffer = ark_iconsumer_surface_adapter_release_buffer;
    GetStruct()->set_user_data = ark_iconsumer_surface_adapter_set_user_data;
    GetStruct()->set_queue_size = ark_iconsumer_surface_adapter_set_queue_size;
}

ArkIConsumerSurfaceAdapterCppToC::~ArkIConsumerSurfaceAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkIConsumerSurfaceAdapterCppToC, ArkIConsumerSurfaceAdapter,
    ark_iconsumer_surface_adapter_t>::kBridgeType = ARK_ICONSUMER_SURFACE_ADAPTER;

} // namespace OHOS::ArkWeb

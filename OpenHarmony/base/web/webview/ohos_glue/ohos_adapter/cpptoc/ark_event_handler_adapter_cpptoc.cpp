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

#include "ohos_adapter/cpptoc/ark_event_handler_adapter_cpptoc.h"

#include "ohos_adapter/ctocpp/ark_event_handler_fdlistener_adapter_ctocpp.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

bool ARK_WEB_CALLBACK ark_event_handler_adapter_add_file_descriptor_listener(struct _ark_event_handler_adapter_t* self,
    int32_t fileDescriptor, uint32_t events, ark_event_handler_fdlistener_adapter_t* listener)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkEventHandlerAdapterCppToC::Get(self)->AddFileDescriptorListener(
        fileDescriptor, events, ArkEventHandlerFDListenerAdapterCToCpp::Invert(listener));
}

void ARK_WEB_CALLBACK ark_event_handler_adapter_remove_file_descriptor_listener(
    struct _ark_event_handler_adapter_t* self, int32_t fileDescriptor)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkEventHandlerAdapterCppToC::Get(self)->RemoveFileDescriptorListener(fileDescriptor);
}

} // namespace

ArkEventHandlerAdapterCppToC::ArkEventHandlerAdapterCppToC()
{
    GetStruct()->add_file_descriptor_listener = ark_event_handler_adapter_add_file_descriptor_listener;
    GetStruct()->remove_file_descriptor_listener = ark_event_handler_adapter_remove_file_descriptor_listener;
}

ArkEventHandlerAdapterCppToC::~ArkEventHandlerAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkEventHandlerAdapterCppToC, ArkEventHandlerAdapter,
    ark_event_handler_adapter_t>::kBridgeType = ARK_EVENT_HANDLER_ADAPTER;

} // namespace OHOS::ArkWeb

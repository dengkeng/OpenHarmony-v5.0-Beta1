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

#include "ohos_adapter/cpptoc/ark_net_proxy_adapter_cpptoc.h"

#include "ohos_adapter/ctocpp/ark_net_proxy_event_callback_adapter_ctocpp.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

void ARK_WEB_CALLBACK ark_net_proxy_adapter_reg_net_proxy_event(
    struct _ark_net_proxy_adapter_t* self, ark_net_proxy_event_callback_adapter_t* eventCallback)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkNetProxyAdapterCppToC::Get(self)->RegNetProxyEvent(ArkNetProxyEventCallbackAdapterCToCpp::Invert(eventCallback));
}

bool ARK_WEB_CALLBACK ark_net_proxy_adapter_start_listen(struct _ark_net_proxy_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkNetProxyAdapterCppToC::Get(self)->StartListen();
}

void ARK_WEB_CALLBACK ark_net_proxy_adapter_stop_listen(struct _ark_net_proxy_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkNetProxyAdapterCppToC::Get(self)->StopListen();
}

void ARK_WEB_CALLBACK ark_net_proxy_adapter_get_property(struct _ark_net_proxy_adapter_t* self, ArkWebString* host,
    uint16_t* port, ArkWebString* pacUrl, ArkWebString* exclusion)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(host, );

    ARK_WEB_CPPTOC_CHECK_PARAM(port, );

    ARK_WEB_CPPTOC_CHECK_PARAM(pacUrl, );

    ARK_WEB_CPPTOC_CHECK_PARAM(exclusion, );

    // Execute
    ArkNetProxyAdapterCppToC::Get(self)->GetProperty(*host, *port, *pacUrl, *exclusion);
}

} // namespace

ArkNetProxyAdapterCppToC::ArkNetProxyAdapterCppToC()
{
    GetStruct()->reg_net_proxy_event = ark_net_proxy_adapter_reg_net_proxy_event;
    GetStruct()->start_listen = ark_net_proxy_adapter_start_listen;
    GetStruct()->stop_listen = ark_net_proxy_adapter_stop_listen;
    GetStruct()->get_property = ark_net_proxy_adapter_get_property;
}

ArkNetProxyAdapterCppToC::~ArkNetProxyAdapterCppToC() {}

template<>
ArkWebBridgeType
    ArkWebCppToCRefCounted<ArkNetProxyAdapterCppToC, ArkNetProxyAdapter, ark_net_proxy_adapter_t>::kBridgeType =
        ARK_NET_PROXY_ADAPTER;

} // namespace OHOS::ArkWeb

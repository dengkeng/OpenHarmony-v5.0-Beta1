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

#include "ohos_adapter/ctocpp/ark_net_proxy_event_callback_adapter_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
void ArkNetProxyEventCallbackAdapterCToCpp::Changed(
    const ArkWebString& host, const uint16_t& port, const ArkWebString& pacUrl, const ArkWebStringVector& exclusionList)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_net_proxy_event_callback_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, changed, );

    // Execute
    _struct->changed(_struct, &host, &port, &pacUrl, &exclusionList);
}

ArkNetProxyEventCallbackAdapterCToCpp::ArkNetProxyEventCallbackAdapterCToCpp() {}

ArkNetProxyEventCallbackAdapterCToCpp::~ArkNetProxyEventCallbackAdapterCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkNetProxyEventCallbackAdapterCToCpp, ArkNetProxyEventCallbackAdapter,
    ark_net_proxy_event_callback_adapter_t>::kBridgeType = ARK_NET_PROXY_EVENT_CALLBACK_ADAPTER;

} // namespace OHOS::ArkWeb

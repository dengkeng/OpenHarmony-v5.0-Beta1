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

#include "ohos_adapter/cpptoc/ark_net_connect_adapter_cpptoc.h"

#include "ohos_adapter/ctocpp/ark_net_conn_callback_ctocpp.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

int32_t ARK_WEB_CALLBACK ark_net_connect_adapter_register_net_conn_callback(
    struct _ark_net_connect_adapter_t* self, ark_net_conn_callback_t* cb)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkNetConnectAdapterCppToC::Get(self)->RegisterNetConnCallback(ArkNetConnCallbackCToCpp::Invert(cb));
}

int32_t ARK_WEB_CALLBACK ark_net_connect_adapter_unregister_net_conn_callback(
    struct _ark_net_connect_adapter_t* self, int32_t id)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkNetConnectAdapterCppToC::Get(self)->UnregisterNetConnCallback(id);
}

int32_t ARK_WEB_CALLBACK ark_net_connect_adapter_get_default_net_connect(
    struct _ark_net_connect_adapter_t* self, uint32_t* type, uint32_t* netConnectSubtype)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(type, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(netConnectSubtype, 0);

    // Execute
    return ArkNetConnectAdapterCppToC::Get(self)->GetDefaultNetConnect(*type, *netConnectSubtype);
}

ArkWebStringVector ARK_WEB_CALLBACK ark_net_connect_adapter_get_dns_servers(struct _ark_net_connect_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_vector_default);

    // Execute
    return ArkNetConnectAdapterCppToC::Get(self)->GetDnsServers();
}

} // namespace

ArkNetConnectAdapterCppToC::ArkNetConnectAdapterCppToC()
{
    GetStruct()->register_net_conn_callback = ark_net_connect_adapter_register_net_conn_callback;
    GetStruct()->unregister_net_conn_callback = ark_net_connect_adapter_unregister_net_conn_callback;
    GetStruct()->get_default_net_connect = ark_net_connect_adapter_get_default_net_connect;
    GetStruct()->get_dns_servers = ark_net_connect_adapter_get_dns_servers;
}

ArkNetConnectAdapterCppToC::~ArkNetConnectAdapterCppToC() {}

template<>
ArkWebBridgeType
    ArkWebCppToCRefCounted<ArkNetConnectAdapterCppToC, ArkNetConnectAdapter, ark_net_connect_adapter_t>::kBridgeType =
        ARK_NET_CONNECT_ADAPTER;

} // namespace OHOS::ArkWeb

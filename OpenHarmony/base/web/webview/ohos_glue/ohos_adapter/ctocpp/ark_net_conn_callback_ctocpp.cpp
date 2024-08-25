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

#include "ohos_adapter/ctocpp/ark_net_conn_callback_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
int32_t ArkNetConnCallbackCToCpp::NetAvailable()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_net_conn_callback_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, net_available, 0);

    // Execute
    return _struct->net_available(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkNetConnCallbackCToCpp::NetCapabilitiesChange(
    const uint32_t& netConnectType, const uint32_t& netConnectSubtype)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_net_conn_callback_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, net_capabilities_change, 0);

    // Execute
    return _struct->net_capabilities_change(_struct, &netConnectType, &netConnectSubtype);
}

ARK_WEB_NO_SANITIZE
int32_t ArkNetConnCallbackCToCpp::NetConnectionPropertiesChange()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_net_conn_callback_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, net_connection_properties_change, 0);

    // Execute
    return _struct->net_connection_properties_change(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkNetConnCallbackCToCpp::NetUnavailable()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_net_conn_callback_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, net_unavailable, 0);

    // Execute
    return _struct->net_unavailable(_struct);
}

ArkNetConnCallbackCToCpp::ArkNetConnCallbackCToCpp() {}

ArkNetConnCallbackCToCpp::~ArkNetConnCallbackCToCpp() {}

template<>
ArkWebBridgeType
    ArkWebCToCppRefCounted<ArkNetConnCallbackCToCpp, ArkNetConnCallback, ark_net_conn_callback_t>::kBridgeType =
        ARK_NET_CONN_CALLBACK;

} // namespace OHOS::ArkWeb

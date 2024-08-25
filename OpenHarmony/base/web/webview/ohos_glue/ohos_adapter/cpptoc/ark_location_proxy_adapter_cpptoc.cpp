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

#include "ohos_adapter/cpptoc/ark_location_proxy_adapter_cpptoc.h"

#include "ohos_adapter/cpptoc/ark_location_request_config_cpptoc.h"
#include "ohos_adapter/ctocpp/ark_location_callback_adapter_ctocpp.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

int32_t ARK_WEB_CALLBACK ark_location_proxy_adapter_start_locating(struct _ark_location_proxy_adapter_t* self,
    ark_location_request_config_t* requestConfig, ark_location_callback_adapter_t* callback)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkLocationProxyAdapterCppToC::Get(self)->StartLocating(
        ArkLocationRequestConfigCppToC::Revert(requestConfig), ArkLocationCallbackAdapterCToCpp::Invert(callback));
}

bool ARK_WEB_CALLBACK ark_location_proxy_adapter_stop_locating(
    struct _ark_location_proxy_adapter_t* self, int32_t callbackId)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkLocationProxyAdapterCppToC::Get(self)->StopLocating(callbackId);
}

bool ARK_WEB_CALLBACK ark_location_proxy_adapter_enable_ability(
    struct _ark_location_proxy_adapter_t* self, bool isEnabled)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkLocationProxyAdapterCppToC::Get(self)->EnableAbility(isEnabled);
}

bool ARK_WEB_CALLBACK ark_location_proxy_adapter_is_location_enabled(struct _ark_location_proxy_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkLocationProxyAdapterCppToC::Get(self)->IsLocationEnabled();
}

} // namespace

ArkLocationProxyAdapterCppToC::ArkLocationProxyAdapterCppToC()
{
    GetStruct()->start_locating = ark_location_proxy_adapter_start_locating;
    GetStruct()->stop_locating = ark_location_proxy_adapter_stop_locating;
    GetStruct()->enable_ability = ark_location_proxy_adapter_enable_ability;
    GetStruct()->is_location_enabled = ark_location_proxy_adapter_is_location_enabled;
}

ArkLocationProxyAdapterCppToC::~ArkLocationProxyAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkLocationProxyAdapterCppToC, ArkLocationProxyAdapter,
    ark_location_proxy_adapter_t>::kBridgeType = ARK_LOCATION_PROXY_ADAPTER;

} // namespace OHOS::ArkWeb

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

#include "ohos_adapter/cpptoc/ark_display_manager_adapter_cpptoc.h"

#include "ohos_adapter/cpptoc/ark_display_adapter_cpptoc.h"
#include "ohos_adapter/ctocpp/ark_display_listener_adapter_ctocpp.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

uint64_t ARK_WEB_CALLBACK ark_display_manager_adapter_get_default_display_id(
    struct _ark_display_manager_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkDisplayManagerAdapterCppToC::Get(self)->GetDefaultDisplayId();
}

ark_display_adapter_t* ARK_WEB_CALLBACK ark_display_manager_adapter_get_default_display(
    struct _ark_display_manager_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkDisplayAdapter> _retval = ArkDisplayManagerAdapterCppToC::Get(self)->GetDefaultDisplay();

    // Return type: refptr_same
    return ArkDisplayAdapterCppToC::Invert(_retval);
}

uint32_t ARK_WEB_CALLBACK ark_display_manager_adapter_register_display_listener(
    struct _ark_display_manager_adapter_t* self, ark_display_listener_adapter_t* listener)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkDisplayManagerAdapterCppToC::Get(self)->RegisterDisplayListener(
        ArkDisplayListenerAdapterCToCpp::Invert(listener));
}

bool ARK_WEB_CALLBACK ark_display_manager_adapter_unregister_display_listener(
    struct _ark_display_manager_adapter_t* self, uint32_t id)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkDisplayManagerAdapterCppToC::Get(self)->UnregisterDisplayListener(id);
}

bool ARK_WEB_CALLBACK ark_display_manager_adapter_is_default_portrait(struct _ark_display_manager_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkDisplayManagerAdapterCppToC::Get(self)->IsDefaultPortrait();
}

} // namespace

ArkDisplayManagerAdapterCppToC::ArkDisplayManagerAdapterCppToC()
{
    GetStruct()->get_default_display_id = ark_display_manager_adapter_get_default_display_id;
    GetStruct()->get_default_display = ark_display_manager_adapter_get_default_display;
    GetStruct()->register_display_listener = ark_display_manager_adapter_register_display_listener;
    GetStruct()->unregister_display_listener = ark_display_manager_adapter_unregister_display_listener;
    GetStruct()->is_default_portrait = ark_display_manager_adapter_is_default_portrait;
}

ArkDisplayManagerAdapterCppToC::~ArkDisplayManagerAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkDisplayManagerAdapterCppToC, ArkDisplayManagerAdapter,
    ark_display_manager_adapter_t>::kBridgeType = ARK_DISPLAY_MANAGER_ADAPTER;

} // namespace OHOS::ArkWeb

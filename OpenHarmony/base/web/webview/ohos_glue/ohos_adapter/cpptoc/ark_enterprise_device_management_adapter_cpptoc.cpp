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

#include "ohos_adapter/cpptoc/ark_enterprise_device_management_adapter_cpptoc.h"

#include "ohos_adapter/ctocpp/ark_edm_policy_changed_event_callback_adapter_ctocpp.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

int32_t ARK_WEB_CALLBACK ark_enterprise_device_management_adapter_get_policies(
    struct _ark_enterprise_device_management_adapter_t* self, ArkWebString* policies)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(policies, 0);

    // Execute
    return ArkEnterpriseDeviceManagementAdapterCppToC::Get(self)->GetPolicies(*policies);
}

void ARK_WEB_CALLBACK ark_enterprise_device_management_adapter_regist_policy_change_event_callback(
    struct _ark_enterprise_device_management_adapter_t* self,
    ark_edm_policy_changed_event_callback_adapter_t* eventCallback)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkEnterpriseDeviceManagementAdapterCppToC::Get(self)->RegistPolicyChangeEventCallback(
        ArkEdmPolicyChangedEventCallbackAdapterCToCpp::Invert(eventCallback));
}

bool ARK_WEB_CALLBACK ark_enterprise_device_management_adapter_start_observe_policy_change(
    struct _ark_enterprise_device_management_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkEnterpriseDeviceManagementAdapterCppToC::Get(self)->StartObservePolicyChange();
}

bool ARK_WEB_CALLBACK ark_enterprise_device_management_adapter_stop_observe_policy_change(
    struct _ark_enterprise_device_management_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkEnterpriseDeviceManagementAdapterCppToC::Get(self)->StopObservePolicyChange();
}

} // namespace

ArkEnterpriseDeviceManagementAdapterCppToC::ArkEnterpriseDeviceManagementAdapterCppToC()
{
    GetStruct()->get_policies = ark_enterprise_device_management_adapter_get_policies;
    GetStruct()->regist_policy_change_event_callback =
        ark_enterprise_device_management_adapter_regist_policy_change_event_callback;
    GetStruct()->start_observe_policy_change = ark_enterprise_device_management_adapter_start_observe_policy_change;
    GetStruct()->stop_observe_policy_change = ark_enterprise_device_management_adapter_stop_observe_policy_change;
}

ArkEnterpriseDeviceManagementAdapterCppToC::~ArkEnterpriseDeviceManagementAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkEnterpriseDeviceManagementAdapterCppToC,
    ArkEnterpriseDeviceManagementAdapter, ark_enterprise_device_management_adapter_t>::kBridgeType =
    ARK_ENTERPRISE_DEVICE_MANAGEMENT_ADAPTER;

} // namespace OHOS::ArkWeb

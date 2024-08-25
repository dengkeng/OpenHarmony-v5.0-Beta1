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

#include "ohos_adapter/cpptoc/ark_system_properties_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

bool ARK_WEB_CALLBACK ark_system_properties_adapter_get_resource_use_hap_path_enable(
    struct _ark_system_properties_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->GetResourceUseHapPathEnable();
}

ArkWebString ARK_WEB_CALLBACK ark_system_properties_adapter_get_device_info_product_model(
    struct _ark_system_properties_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_default);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->GetDeviceInfoProductModel();
}

ArkWebString ARK_WEB_CALLBACK ark_system_properties_adapter_get_device_info_brand(
    struct _ark_system_properties_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_default);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->GetDeviceInfoBrand();
}

int32_t ARK_WEB_CALLBACK ark_system_properties_adapter_get_device_info_major_version(
    struct _ark_system_properties_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->GetDeviceInfoMajorVersion();
}

int32_t ARK_WEB_CALLBACK ark_system_properties_adapter_get_product_device_type(
    struct _ark_system_properties_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->GetProductDeviceType();
}

bool ARK_WEB_CALLBACK ark_system_properties_adapter_get_web_optimization_value(
    struct _ark_system_properties_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->GetWebOptimizationValue();
}

bool ARK_WEB_CALLBACK ark_system_properties_adapter_is_advanced_security_mode(
    struct _ark_system_properties_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->IsAdvancedSecurityMode();
}

ArkWebString ARK_WEB_CALLBACK ark_system_properties_adapter_get_user_agent_osname(
    struct _ark_system_properties_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_default);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->GetUserAgentOSName();
}

int32_t ARK_WEB_CALLBACK ark_system_properties_adapter_get_software_major_version(
    struct _ark_system_properties_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->GetSoftwareMajorVersion();
}

int32_t ARK_WEB_CALLBACK ark_system_properties_adapter_get_software_senior_version(
    struct _ark_system_properties_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->GetSoftwareSeniorVersion();
}

ArkWebString ARK_WEB_CALLBACK ark_system_properties_adapter_get_netlog_mode(
    struct _ark_system_properties_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_default);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->GetNetlogMode();
}

bool ARK_WEB_CALLBACK ark_system_properties_adapter_get_trace_debug_enable(
    struct _ark_system_properties_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->GetTraceDebugEnable();
}

ArkWebString ARK_WEB_CALLBACK ark_system_properties_adapter_get_site_isolation_mode(
    struct _ark_system_properties_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_default);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->GetSiteIsolationMode();
}

int32_t ARK_WEB_CALLBACK ark_system_properties_adapter_get_flow_buf_max_fd(
    struct _ark_system_properties_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->GetFlowBufMaxFd();
}

bool ARK_WEB_CALLBACK ark_system_properties_adapter_get_oopgpuenable(struct _ark_system_properties_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->GetOOPGPUEnable();
}

void ARK_WEB_CALLBACK ark_system_properties_adapter_set_oopgpudisable(struct _ark_system_properties_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkSystemPropertiesAdapterCppToC::Get(self)->SetOOPGPUDisable();
}

void ARK_WEB_CALLBACK ark_system_properties_adapter_attach_sys_prop_observer(
    struct _ark_system_properties_adapter_t* self, int32_t key, void* observer)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(observer, );

    // Execute
    ArkSystemPropertiesAdapterCppToC::Get(self)->AttachSysPropObserver(key, observer);
}

void ARK_WEB_CALLBACK ark_system_properties_adapter_detach_sys_prop_observer(
    struct _ark_system_properties_adapter_t* self, int32_t key, void* observer)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(observer, );

    // Execute
    ArkSystemPropertiesAdapterCppToC::Get(self)->DetachSysPropObserver(key, observer);
}

bool ARK_WEB_CALLBACK ark_system_properties_adapter_get_bool_parameter(
    struct _ark_system_properties_adapter_t* self, ArkWebString key, bool defaultValue)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->GetBoolParameter(key, defaultValue);
}

ArkFrameRateSettingAdapterVector ARK_WEB_CALLBACK ark_system_properties_adapter_get_ltpoconfig(
    struct _ark_system_properties_adapter_t* self, const ArkWebString* settingName)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_frame_rate_setting_adapter_vector_default);

    ARK_WEB_CPPTOC_CHECK_PARAM(settingName, ark_frame_rate_setting_adapter_vector_default);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->GetLTPOConfig(*settingName);
}
} // namespace

ArkSystemPropertiesAdapterCppToC::ArkSystemPropertiesAdapterCppToC()
{
    GetStruct()->get_resource_use_hap_path_enable = ark_system_properties_adapter_get_resource_use_hap_path_enable;
    GetStruct()->get_device_info_product_model = ark_system_properties_adapter_get_device_info_product_model;
    GetStruct()->get_device_info_brand = ark_system_properties_adapter_get_device_info_brand;
    GetStruct()->get_device_info_major_version = ark_system_properties_adapter_get_device_info_major_version;
    GetStruct()->get_product_device_type = ark_system_properties_adapter_get_product_device_type;
    GetStruct()->get_web_optimization_value = ark_system_properties_adapter_get_web_optimization_value;
    GetStruct()->is_advanced_security_mode = ark_system_properties_adapter_is_advanced_security_mode;
    GetStruct()->get_user_agent_osname = ark_system_properties_adapter_get_user_agent_osname;
    GetStruct()->get_software_major_version = ark_system_properties_adapter_get_software_major_version;
    GetStruct()->get_software_senior_version = ark_system_properties_adapter_get_software_senior_version;
    GetStruct()->get_netlog_mode = ark_system_properties_adapter_get_netlog_mode;
    GetStruct()->get_trace_debug_enable = ark_system_properties_adapter_get_trace_debug_enable;
    GetStruct()->get_site_isolation_mode = ark_system_properties_adapter_get_site_isolation_mode;
    GetStruct()->get_flow_buf_max_fd = ark_system_properties_adapter_get_flow_buf_max_fd;
    GetStruct()->get_oopgpuenable = ark_system_properties_adapter_get_oopgpuenable;
    GetStruct()->set_oopgpudisable = ark_system_properties_adapter_set_oopgpudisable;
    GetStruct()->attach_sys_prop_observer = ark_system_properties_adapter_attach_sys_prop_observer;
    GetStruct()->detach_sys_prop_observer = ark_system_properties_adapter_detach_sys_prop_observer;
    GetStruct()->get_bool_parameter = ark_system_properties_adapter_get_bool_parameter;
    GetStruct()->get_ltpoconfig = ark_system_properties_adapter_get_ltpoconfig;
}

ArkSystemPropertiesAdapterCppToC::~ArkSystemPropertiesAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkSystemPropertiesAdapterCppToC, ArkSystemPropertiesAdapter,
    ark_system_properties_adapter_t>::kBridgeType = ARK_SYSTEM_PROPERTIES_ADAPTER;

} // namespace OHOS::ArkWeb

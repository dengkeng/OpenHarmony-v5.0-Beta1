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

#include "ohos_adapter/cpptoc/ark_location_instance_cpptoc.h"

#include "ohos_adapter/cpptoc/ark_location_proxy_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_location_request_config_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

ark_location_instance_t* ark_location_instance_get_instance()
{
    // Execute
    ArkWebRefPtr<ArkLocationInstance> _retval = ArkLocationInstance::GetInstance();

    // Return type: refptr_same
    return ArkLocationInstanceCppToC::Invert(_retval);
}

namespace {

ark_location_proxy_adapter_t* ARK_WEB_CALLBACK ark_location_instance_create_location_proxy_adapter(
    struct _ark_location_instance_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkLocationProxyAdapter> _retval = ArkLocationInstanceCppToC::Get(self)->CreateLocationProxyAdapter();

    // Return type: refptr_same
    return ArkLocationProxyAdapterCppToC::Invert(_retval);
}

ark_location_request_config_t* ARK_WEB_CALLBACK ark_location_instance_create_location_request_config(
    struct _ark_location_instance_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkLocationRequestConfig> _retval =
        ArkLocationInstanceCppToC::Get(self)->CreateLocationRequestConfig();

    // Return type: refptr_same
    return ArkLocationRequestConfigCppToC::Invert(_retval);
}

} // namespace

ArkLocationInstanceCppToC::ArkLocationInstanceCppToC()
{
    GetStruct()->create_location_proxy_adapter = ark_location_instance_create_location_proxy_adapter;
    GetStruct()->create_location_request_config = ark_location_instance_create_location_request_config;
}

ArkLocationInstanceCppToC::~ArkLocationInstanceCppToC() {}

template<>
ArkWebBridgeType
    ArkWebCppToCRefCounted<ArkLocationInstanceCppToC, ArkLocationInstance, ark_location_instance_t>::kBridgeType =
        ARK_LOCATION_INSTANCE;

} // namespace OHOS::ArkWeb

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

ARK_WEB_EXPORT ark_location_instance_t* ark_location_instance_get_instance_static()
{
    ARK_WEB_CPPTOC_DV_LOG();

    return OHOS::ArkWeb::ark_location_instance_get_instance();
}

#ifdef __cplusplus
}
#endif // __cplusplus

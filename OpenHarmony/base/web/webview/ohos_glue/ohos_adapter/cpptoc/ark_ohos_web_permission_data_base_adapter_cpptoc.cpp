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

#include "ohos_adapter/cpptoc/ark_ohos_web_permission_data_base_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

bool ARK_WEB_CALLBACK ark_ohos_web_permission_data_base_adapter_exist_permission_by_origin(
    struct _ark_ohos_web_permission_data_base_adapter_t* self, const ArkWebString* origin, const int32_t* key)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    ARK_WEB_CPPTOC_CHECK_PARAM(origin, false);

    ARK_WEB_CPPTOC_CHECK_PARAM(key, false);

    // Execute
    return ArkOhosWebPermissionDataBaseAdapterCppToC::Get(self)->ExistPermissionByOrigin(*origin, *key);
}

bool ARK_WEB_CALLBACK ark_ohos_web_permission_data_base_adapter_get_permission_result_by_origin(
    struct _ark_ohos_web_permission_data_base_adapter_t* self, const ArkWebString* origin, const int32_t* key,
    bool* result)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    ARK_WEB_CPPTOC_CHECK_PARAM(origin, false);

    ARK_WEB_CPPTOC_CHECK_PARAM(key, false);

    ARK_WEB_CPPTOC_CHECK_PARAM(result, false);

    // Execute
    return ArkOhosWebPermissionDataBaseAdapterCppToC::Get(self)->GetPermissionResultByOrigin(*origin, *key, *result);
}

void ARK_WEB_CALLBACK ark_ohos_web_permission_data_base_adapter_set_permission_by_origin(
    struct _ark_ohos_web_permission_data_base_adapter_t* self, const ArkWebString* origin, const int32_t* key,
    bool result)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(origin, );

    ARK_WEB_CPPTOC_CHECK_PARAM(key, );

    // Execute
    ArkOhosWebPermissionDataBaseAdapterCppToC::Get(self)->SetPermissionByOrigin(*origin, *key, result);
}

void ARK_WEB_CALLBACK ark_ohos_web_permission_data_base_adapter_clear_permission_by_origin(
    struct _ark_ohos_web_permission_data_base_adapter_t* self, const ArkWebString* origin, const int32_t* key)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(origin, );

    ARK_WEB_CPPTOC_CHECK_PARAM(key, );

    // Execute
    ArkOhosWebPermissionDataBaseAdapterCppToC::Get(self)->ClearPermissionByOrigin(*origin, *key);
}

void ARK_WEB_CALLBACK ark_ohos_web_permission_data_base_adapter_clear_all_permission(
    struct _ark_ohos_web_permission_data_base_adapter_t* self, const int32_t* key)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(key, );

    // Execute
    ArkOhosWebPermissionDataBaseAdapterCppToC::Get(self)->ClearAllPermission(*key);
}

void ARK_WEB_CALLBACK ark_ohos_web_permission_data_base_adapter_get_origins_by_permission(
    struct _ark_ohos_web_permission_data_base_adapter_t* self, const int32_t* key, ArkWebStringVector* origins)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(key, );

    ARK_WEB_CPPTOC_CHECK_PARAM(origins, );

    // Execute
    ArkOhosWebPermissionDataBaseAdapterCppToC::Get(self)->GetOriginsByPermission(*key, *origins);
}

} // namespace

ArkOhosWebPermissionDataBaseAdapterCppToC::ArkOhosWebPermissionDataBaseAdapterCppToC()
{
    GetStruct()->exist_permission_by_origin = ark_ohos_web_permission_data_base_adapter_exist_permission_by_origin;
    GetStruct()->get_permission_result_by_origin =
        ark_ohos_web_permission_data_base_adapter_get_permission_result_by_origin;
    GetStruct()->set_permission_by_origin = ark_ohos_web_permission_data_base_adapter_set_permission_by_origin;
    GetStruct()->clear_permission_by_origin = ark_ohos_web_permission_data_base_adapter_clear_permission_by_origin;
    GetStruct()->clear_all_permission = ark_ohos_web_permission_data_base_adapter_clear_all_permission;
    GetStruct()->get_origins_by_permission = ark_ohos_web_permission_data_base_adapter_get_origins_by_permission;
}

ArkOhosWebPermissionDataBaseAdapterCppToC::~ArkOhosWebPermissionDataBaseAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkOhosWebPermissionDataBaseAdapterCppToC, ArkOhosWebPermissionDataBaseAdapter,
    ark_ohos_web_permission_data_base_adapter_t>::kBridgeType = ARK_OHOS_WEB_PERMISSION_DATA_BASE_ADAPTER;

} // namespace OHOS::ArkWeb

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

#include "ohos_adapter/cpptoc/ark_ohos_web_data_base_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

bool ARK_WEB_CALLBACK ark_ohos_web_data_base_adapter_exist_http_auth_credentials(
    struct _ark_ohos_web_data_base_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkOhosWebDataBaseAdapterCppToC::Get(self)->ExistHttpAuthCredentials();
}

void ARK_WEB_CALLBACK ark_ohos_web_data_base_adapter_delete_http_auth_credentials(
    struct _ark_ohos_web_data_base_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkOhosWebDataBaseAdapterCppToC::Get(self)->DeleteHttpAuthCredentials();
}

void ARK_WEB_CALLBACK ark_ohos_web_data_base_adapter_save_http_auth_credentials(
    struct _ark_ohos_web_data_base_adapter_t* self, const ArkWebString* host, const ArkWebString* realm,
    const ArkWebString* username, const char* password)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(host, );

    ARK_WEB_CPPTOC_CHECK_PARAM(realm, );

    ARK_WEB_CPPTOC_CHECK_PARAM(username, );

    ARK_WEB_CPPTOC_CHECK_PARAM(password, );

    // Execute
    ArkOhosWebDataBaseAdapterCppToC::Get(self)->SaveHttpAuthCredentials(*host, *realm, *username, password);
}

void ARK_WEB_CALLBACK ark_ohos_web_data_base_adapter_get_http_auth_credentials(
    struct _ark_ohos_web_data_base_adapter_t* self, const ArkWebString* host, const ArkWebString* realm,
    ArkWebString* username, char* password, uint32_t passwordSize)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(host, );

    ARK_WEB_CPPTOC_CHECK_PARAM(realm, );

    ARK_WEB_CPPTOC_CHECK_PARAM(username, );

    ARK_WEB_CPPTOC_CHECK_PARAM(password, );

    // Execute
    ArkOhosWebDataBaseAdapterCppToC::Get(self)->GetHttpAuthCredentials(
        *host, *realm, *username, password, passwordSize);
}

} // namespace

ArkOhosWebDataBaseAdapterCppToC::ArkOhosWebDataBaseAdapterCppToC()
{
    GetStruct()->exist_http_auth_credentials = ark_ohos_web_data_base_adapter_exist_http_auth_credentials;
    GetStruct()->delete_http_auth_credentials = ark_ohos_web_data_base_adapter_delete_http_auth_credentials;
    GetStruct()->save_http_auth_credentials = ark_ohos_web_data_base_adapter_save_http_auth_credentials;
    GetStruct()->get_http_auth_credentials = ark_ohos_web_data_base_adapter_get_http_auth_credentials;
}

ArkOhosWebDataBaseAdapterCppToC::~ArkOhosWebDataBaseAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkOhosWebDataBaseAdapterCppToC, ArkOhosWebDataBaseAdapter,
    ark_ohos_web_data_base_adapter_t>::kBridgeType = ARK_OHOS_WEB_DATA_BASE_ADAPTER;

} // namespace OHOS::ArkWeb

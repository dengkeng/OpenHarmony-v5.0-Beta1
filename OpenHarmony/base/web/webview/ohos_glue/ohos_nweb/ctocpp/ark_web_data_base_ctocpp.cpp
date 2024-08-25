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

#include "ohos_nweb/ctocpp/ark_web_data_base_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
void ArkWebDataBaseCToCpp::ClearAllPermission(int type, bool incognito)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_data_base_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, clear_all_permission, );

    // Execute
    _struct->clear_all_permission(_struct, type, incognito);
}

ARK_WEB_NO_SANITIZE
void ArkWebDataBaseCToCpp::GetHttpAuthCredentials(const ArkWebString& host, const ArkWebString& realm,
    ArkWebString& user_name, char* password, uint32_t password_size)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_data_base_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_http_auth_credentials, );

    // Execute
    _struct->get_http_auth_credentials(_struct, &host, &realm, &user_name, password, password_size);
}

ARK_WEB_NO_SANITIZE
void ArkWebDataBaseCToCpp::SaveHttpAuthCredentials(
    const ArkWebString& host, const ArkWebString& realm, const ArkWebString& user_name, const char* password)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_data_base_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, save_http_auth_credentials, );

    // Execute
    _struct->save_http_auth_credentials(_struct, &host, &realm, &user_name, password);
}

ARK_WEB_NO_SANITIZE
bool ArkWebDataBaseCToCpp::ExistHttpAuthCredentials()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_data_base_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, exist_http_auth_credentials, false);

    // Execute
    return _struct->exist_http_auth_credentials(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebDataBaseCToCpp::DeleteHttpAuthCredentials()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_data_base_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, delete_http_auth_credentials, );

    // Execute
    _struct->delete_http_auth_credentials(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebStringVector ArkWebDataBaseCToCpp::GetOriginsByPermission(int type, bool incognito)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_data_base_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_vector_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_origins_by_permission, ark_web_string_vector_default);

    // Execute
    return _struct->get_origins_by_permission(_struct, type, incognito);
}

ARK_WEB_NO_SANITIZE
bool ArkWebDataBaseCToCpp::GetPermissionByOrigin(const ArkWebString& origin, int type, bool& result, bool incognito)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_data_base_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_permission_by_origin, false);

    // Execute
    return _struct->get_permission_by_origin(_struct, &origin, type, &result, incognito);
}

ARK_WEB_NO_SANITIZE
int ArkWebDataBaseCToCpp::SetPermissionByOrigin(const ArkWebString& origin, int type, bool result, bool incognito)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_data_base_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_permission_by_origin, 0);

    // Execute
    return _struct->set_permission_by_origin(_struct, &origin, type, result, incognito);
}

ARK_WEB_NO_SANITIZE
bool ArkWebDataBaseCToCpp::ExistPermissionByOrigin(const ArkWebString& origin, int type, bool incognito)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_data_base_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, exist_permission_by_origin, false);

    // Execute
    return _struct->exist_permission_by_origin(_struct, &origin, type, incognito);
}

ARK_WEB_NO_SANITIZE
int ArkWebDataBaseCToCpp::ClearPermissionByOrigin(const ArkWebString& origin, int type, bool incognito)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_data_base_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, clear_permission_by_origin, 0);

    // Execute
    return _struct->clear_permission_by_origin(_struct, &origin, type, incognito);
}

ArkWebDataBaseCToCpp::ArkWebDataBaseCToCpp() {}

ArkWebDataBaseCToCpp::~ArkWebDataBaseCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebDataBaseCToCpp, ArkWebDataBase, ark_web_data_base_t>::kBridgeType =
    ARK_WEB_DATA_BASE;

} // namespace OHOS::ArkWeb

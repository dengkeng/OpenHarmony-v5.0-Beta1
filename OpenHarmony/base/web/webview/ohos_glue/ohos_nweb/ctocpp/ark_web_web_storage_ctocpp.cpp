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

#include "ohos_nweb/ctocpp/ark_web_web_storage_ctocpp.h"

#include "ohos_nweb/cpptoc/ark_web_long_value_callback_cpptoc.h"
#include "ohos_nweb/cpptoc/ark_web_web_storage_origin_vector_value_callback_cpptoc.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
ArkWebWebStorageOriginVector ArkWebWebStorageCToCpp::GetOrigins()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_web_storage_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_web_storage_origin_vector_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_origins1, ark_web_web_storage_origin_vector_default);

    // Execute
    return _struct->get_origins1(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebWebStorageCToCpp::GetOrigins(ArkWebRefPtr<ArkWebWebStorageOriginVectorValueCallback> callback)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_web_storage_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_origins2, );

    // Execute
    _struct->get_origins2(_struct, ArkWebWebStorageOriginVectorValueCallbackCppToC::Invert(callback));
}

ARK_WEB_NO_SANITIZE
long ArkWebWebStorageCToCpp::GetOriginQuota(const ArkWebString& origin)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_web_storage_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_origin_quota1, 0);

    // Execute
    return _struct->get_origin_quota1(_struct, &origin);
}

ARK_WEB_NO_SANITIZE
void ArkWebWebStorageCToCpp::GetOriginQuota(const ArkWebString& origin, ArkWebRefPtr<ArkWebLongValueCallback> callback)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_web_storage_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_origin_quota2, );

    // Execute
    _struct->get_origin_quota2(_struct, &origin, ArkWebLongValueCallbackCppToC::Invert(callback));
}

ARK_WEB_NO_SANITIZE
long ArkWebWebStorageCToCpp::GetOriginUsage(const ArkWebString& origin)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_web_storage_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_origin_usage1, 0);

    // Execute
    return _struct->get_origin_usage1(_struct, &origin);
}

ARK_WEB_NO_SANITIZE
void ArkWebWebStorageCToCpp::GetOriginUsage(const ArkWebString& origin, ArkWebRefPtr<ArkWebLongValueCallback> callback)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_web_storage_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_origin_usage2, );

    // Execute
    _struct->get_origin_usage2(_struct, &origin, ArkWebLongValueCallbackCppToC::Invert(callback));
}

ARK_WEB_NO_SANITIZE
int ArkWebWebStorageCToCpp::DeleteOrigin(const ArkWebString& origin)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_web_storage_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, delete_origin, 0);

    // Execute
    return _struct->delete_origin(_struct, &origin);
}

ARK_WEB_NO_SANITIZE
void ArkWebWebStorageCToCpp::DeleteAllData(bool incognito_mode)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_web_storage_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, delete_all_data, );

    // Execute
    _struct->delete_all_data(_struct, incognito_mode);
}

ArkWebWebStorageCToCpp::ArkWebWebStorageCToCpp() {}

ArkWebWebStorageCToCpp::~ArkWebWebStorageCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebWebStorageCToCpp, ArkWebWebStorage, ark_web_web_storage_t>::kBridgeType =
    ARK_WEB_WEB_STORAGE;

} // namespace OHOS::ArkWeb

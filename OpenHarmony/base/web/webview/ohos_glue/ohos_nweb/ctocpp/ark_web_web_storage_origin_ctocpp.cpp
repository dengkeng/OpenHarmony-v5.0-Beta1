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

#include "ohos_nweb/ctocpp/ark_web_web_storage_origin_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
long ArkWebWebStorageOriginCToCpp::GetQuota()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_web_storage_origin_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_quota, 0);

    // Execute
    return _struct->get_quota(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebWebStorageOriginCToCpp::SetQuota(long quota)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_web_storage_origin_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_quota, );

    // Execute
    _struct->set_quota(_struct, quota);
}

ARK_WEB_NO_SANITIZE
long ArkWebWebStorageOriginCToCpp::GetUsage()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_web_storage_origin_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_usage, 0);

    // Execute
    return _struct->get_usage(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebWebStorageOriginCToCpp::SetUsage(long usage)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_web_storage_origin_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_usage, );

    // Execute
    _struct->set_usage(_struct, usage);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebWebStorageOriginCToCpp::GetOrigin()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_web_storage_origin_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_origin, ark_web_string_default);

    // Execute
    return _struct->get_origin(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebWebStorageOriginCToCpp::SetOrigin(const ArkWebString& origin)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_web_storage_origin_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_origin, );

    // Execute
    _struct->set_origin(_struct, &origin);
}

ArkWebWebStorageOriginCToCpp::ArkWebWebStorageOriginCToCpp() {}

ArkWebWebStorageOriginCToCpp::~ArkWebWebStorageOriginCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebWebStorageOriginCToCpp, ArkWebWebStorageOrigin,
    ark_web_web_storage_origin_t>::kBridgeType = ARK_WEB_WEB_STORAGE_ORIGIN;

} // namespace OHOS::ArkWeb

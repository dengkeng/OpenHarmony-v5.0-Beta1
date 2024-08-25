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

#include "ohos_adapter/cpptoc/ark_access_token_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

bool ARK_WEB_CALLBACK ark_access_token_adapter_verify_access_token(
    struct _ark_access_token_adapter_t* self, const ArkWebString* permissionName)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    ARK_WEB_CPPTOC_CHECK_PARAM(permissionName, false);

    // Execute
    return ArkAccessTokenAdapterCppToC::Get(self)->VerifyAccessToken(*permissionName);
}

} // namespace

ArkAccessTokenAdapterCppToC::ArkAccessTokenAdapterCppToC()
{
    GetStruct()->verify_access_token = ark_access_token_adapter_verify_access_token;
}

ArkAccessTokenAdapterCppToC::~ArkAccessTokenAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkAccessTokenAdapterCppToC, ArkAccessTokenAdapter,
    ark_access_token_adapter_t>::kBridgeType = ARK_ACCESS_TOKEN_ADAPTER;

} // namespace OHOS::ArkWeb

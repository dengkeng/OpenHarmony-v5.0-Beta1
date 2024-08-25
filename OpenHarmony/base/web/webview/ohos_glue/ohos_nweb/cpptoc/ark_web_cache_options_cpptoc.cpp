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

#include "ohos_nweb/cpptoc/ark_web_cache_options_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

ArkWebStringMap ARK_WEB_CALLBACK ark_web_cache_options_get_response_headers(struct _ark_web_cache_options_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_map_default);

    // Execute
    return ArkWebCacheOptionsCppToC::Get(self)->GetResponseHeaders();
}

bool ARK_WEB_CALLBACK ark_web_cache_options_is_module(struct _ark_web_cache_options_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkWebCacheOptionsCppToC::Get(self)->IsModule();
}

bool ARK_WEB_CALLBACK ark_web_cache_options_is_top_level(struct _ark_web_cache_options_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkWebCacheOptionsCppToC::Get(self)->IsTopLevel();
}

} // namespace

ArkWebCacheOptionsCppToC::ArkWebCacheOptionsCppToC()
{
    GetStruct()->get_response_headers = ark_web_cache_options_get_response_headers;
    GetStruct()->is_module = ark_web_cache_options_is_module;
    GetStruct()->is_top_level = ark_web_cache_options_is_top_level;
}

ArkWebCacheOptionsCppToC::~ArkWebCacheOptionsCppToC() {}

template<>
ArkWebBridgeType
    ArkWebCppToCRefCounted<ArkWebCacheOptionsCppToC, ArkWebCacheOptions, ark_web_cache_options_t>::kBridgeType =
        ARK_WEB_CACHE_OPTIONS;

} // namespace OHOS::ArkWeb

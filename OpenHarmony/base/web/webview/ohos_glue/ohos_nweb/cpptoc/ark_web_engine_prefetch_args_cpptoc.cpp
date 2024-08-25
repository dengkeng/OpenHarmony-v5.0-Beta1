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

#include "ohos_nweb/cpptoc/ark_web_engine_prefetch_args_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

ArkWebString ARK_WEB_CALLBACK ark_web_engine_prefetch_args_get_url(struct _ark_web_engine_prefetch_args_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_default);

    // Execute
    return ArkWebEnginePrefetchArgsCppToC::Get(self)->GetUrl();
}

ArkWebString ARK_WEB_CALLBACK ark_web_engine_prefetch_args_get_method(struct _ark_web_engine_prefetch_args_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_default);

    // Execute
    return ArkWebEnginePrefetchArgsCppToC::Get(self)->GetMethod();
}

ArkWebString ARK_WEB_CALLBACK ark_web_engine_prefetch_args_get_form_data(struct _ark_web_engine_prefetch_args_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_default);

    // Execute
    return ArkWebEnginePrefetchArgsCppToC::Get(self)->GetFormData();
}

} // namespace

ArkWebEnginePrefetchArgsCppToC::ArkWebEnginePrefetchArgsCppToC()
{
    GetStruct()->get_url = ark_web_engine_prefetch_args_get_url;
    GetStruct()->get_method = ark_web_engine_prefetch_args_get_method;
    GetStruct()->get_form_data = ark_web_engine_prefetch_args_get_form_data;
}

ArkWebEnginePrefetchArgsCppToC::~ArkWebEnginePrefetchArgsCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkWebEnginePrefetchArgsCppToC, ArkWebEnginePrefetchArgs,
    ark_web_engine_prefetch_args_t>::kBridgeType = ARK_WEB_ENGINE_PREFETCH_ARGS;

} // namespace OHOS::ArkWeb

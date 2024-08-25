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

#include "ohos_adapter/cpptoc/ark_ohos_init_web_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

void* ARK_WEB_CALLBACK ark_ohos_init_web_adapter_get_run_web_inited_callback(struct _ark_ohos_init_web_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    return ArkOhosInitWebAdapterCppToC::Get(self)->GetRunWebInitedCallback();
}

void ARK_WEB_CALLBACK ark_ohos_init_web_adapter_set_run_web_inited_callback(
    struct _ark_ohos_init_web_adapter_t* self, void* callback)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(callback, );

    // Execute
    ArkOhosInitWebAdapterCppToC::Get(self)->SetRunWebInitedCallback(callback);
}

} // namespace

ArkOhosInitWebAdapterCppToC::ArkOhosInitWebAdapterCppToC()
{
    GetStruct()->get_run_web_inited_callback = ark_ohos_init_web_adapter_get_run_web_inited_callback;
    GetStruct()->set_run_web_inited_callback = ark_ohos_init_web_adapter_set_run_web_inited_callback;
}

ArkOhosInitWebAdapterCppToC::~ArkOhosInitWebAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkOhosInitWebAdapterCppToC, ArkOhosInitWebAdapter,
    ark_ohos_init_web_adapter_t>::kBridgeType = ARK_OHOS_INIT_WEB_ADAPTER;

} // namespace OHOS::ArkWeb

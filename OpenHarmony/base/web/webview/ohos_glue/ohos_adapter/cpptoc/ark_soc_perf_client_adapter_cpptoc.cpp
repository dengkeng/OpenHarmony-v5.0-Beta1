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

#include "ohos_adapter/cpptoc/ark_soc_perf_client_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

void ARK_WEB_CALLBACK ark_soc_perf_client_adapter_apply_soc_perf_config_by_id(
    struct _ark_soc_perf_client_adapter_t* self, int32_t id)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkSocPerfClientAdapterCppToC::Get(self)->ApplySocPerfConfigById(id);
}

void ARK_WEB_CALLBACK ark_soc_perf_client_adapter_apply_soc_perf_config_by_id_ex(
    struct _ark_soc_perf_client_adapter_t* self, int32_t id, bool onOffTag)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkSocPerfClientAdapterCppToC::Get(self)->ApplySocPerfConfigByIdEx(id, onOffTag);
}

} // namespace

ArkSocPerfClientAdapterCppToC::ArkSocPerfClientAdapterCppToC()
{
    GetStruct()->apply_soc_perf_config_by_id = ark_soc_perf_client_adapter_apply_soc_perf_config_by_id;
    GetStruct()->apply_soc_perf_config_by_id_ex = ark_soc_perf_client_adapter_apply_soc_perf_config_by_id_ex;
}

ArkSocPerfClientAdapterCppToC::~ArkSocPerfClientAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkSocPerfClientAdapterCppToC, ArkSocPerfClientAdapter,
    ark_soc_perf_client_adapter_t>::kBridgeType = ARK_SOC_PERF_CLIENT_ADAPTER;

} // namespace OHOS::ArkWeb

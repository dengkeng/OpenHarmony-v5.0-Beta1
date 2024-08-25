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

#include "ohos_adapter/cpptoc/ark_datashare_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

int ARK_WEB_CALLBACK ark_datashare_adapter_open_data_share_uri_for_read(
    struct _ark_datashare_adapter_t* self, const ArkWebString* uriStr)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(uriStr, 0);

    // Execute
    return ArkDatashareAdapterCppToC::Get(self)->OpenDataShareUriForRead(*uriStr);
}

ArkWebString ARK_WEB_CALLBACK ark_datashare_adapter_get_file_display_name(
    struct _ark_datashare_adapter_t* self, const ArkWebString* uriStr)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_default);

    ARK_WEB_CPPTOC_CHECK_PARAM(uriStr, ark_web_string_default);

    // Execute
    return ArkDatashareAdapterCppToC::Get(self)->GetFileDisplayName(*uriStr);
}

ArkWebString ARK_WEB_CALLBACK ark_datashare_adapter_get_real_path(
    struct _ark_datashare_adapter_t* self, const ArkWebString* uriStr)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_default);

    ARK_WEB_CPPTOC_CHECK_PARAM(uriStr, ark_web_string_default);

    // Execute
    return ArkDatashareAdapterCppToC::Get(self)->GetRealPath(*uriStr);
}

} // namespace

ArkDatashareAdapterCppToC::ArkDatashareAdapterCppToC()
{
    GetStruct()->open_data_share_uri_for_read = ark_datashare_adapter_open_data_share_uri_for_read;
    GetStruct()->get_file_display_name = ark_datashare_adapter_get_file_display_name;
    GetStruct()->get_real_path = ark_datashare_adapter_get_real_path;
}

ArkDatashareAdapterCppToC::~ArkDatashareAdapterCppToC() {}

template<>
ArkWebBridgeType
    ArkWebCppToCRefCounted<ArkDatashareAdapterCppToC, ArkDatashareAdapter, ark_datashare_adapter_t>::kBridgeType =
        ARK_DATASHARE_ADAPTER;

} // namespace OHOS::ArkWeb

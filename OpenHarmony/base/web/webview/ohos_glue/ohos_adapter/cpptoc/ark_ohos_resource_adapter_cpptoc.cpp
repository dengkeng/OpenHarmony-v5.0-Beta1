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

#include "ohos_adapter/cpptoc/ark_ohos_resource_adapter_cpptoc.h"

#include "ohos_adapter/cpptoc/ark_ohos_file_mapper_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

bool ARK_WEB_CALLBACK ark_ohos_resource_adapter_get_raw_file_data(
    struct _ark_ohos_resource_adapter_t* self, const ArkWebString* rawFile, size_t* len, uint8_t** dest, bool isSys)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    ARK_WEB_CPPTOC_CHECK_PARAM(rawFile, false);

    ARK_WEB_CPPTOC_CHECK_PARAM(len, false);

    ARK_WEB_CPPTOC_CHECK_PARAM(dest, false);

    // Execute
    return ArkOhosResourceAdapterCppToC::Get(self)->GetRawFileData(*rawFile, *len, dest, isSys);
}

ark_ohos_file_mapper_t* ARK_WEB_CALLBACK ark_ohos_resource_adapter_get_raw_file_mapper(
    struct _ark_ohos_resource_adapter_t* self, const ArkWebString* rawFile, bool isSys)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    ARK_WEB_CPPTOC_CHECK_PARAM(rawFile, NULL);

    // Execute
    ArkWebRefPtr<ArkOhosFileMapper> _retval =
        ArkOhosResourceAdapterCppToC::Get(self)->GetRawFileMapper(*rawFile, isSys);

    // Return type: refptr_same
    return ArkOhosFileMapperCppToC::Invert(_retval);
}

bool ARK_WEB_CALLBACK ark_ohos_resource_adapter_is_raw_file_exist(
    struct _ark_ohos_resource_adapter_t* self, const ArkWebString* rawFile, bool isSys)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    ARK_WEB_CPPTOC_CHECK_PARAM(rawFile, false);

    // Execute
    return ArkOhosResourceAdapterCppToC::Get(self)->IsRawFileExist(*rawFile, isSys);
}

bool ARK_WEB_CALLBACK ark_ohos_resource_adapter_get_raw_file_last_mod_time1(
    struct _ark_ohos_resource_adapter_t* self, const ArkWebString* rawFile, uint16_t* date, uint16_t* time, bool isSys)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    ARK_WEB_CPPTOC_CHECK_PARAM(rawFile, false);

    ARK_WEB_CPPTOC_CHECK_PARAM(date, false);

    ARK_WEB_CPPTOC_CHECK_PARAM(time, false);

    // Execute
    return ArkOhosResourceAdapterCppToC::Get(self)->GetRawFileLastModTime(*rawFile, *date, *time, isSys);
}

bool ARK_WEB_CALLBACK ark_ohos_resource_adapter_get_raw_file_last_mod_time2(
    struct _ark_ohos_resource_adapter_t* self, const ArkWebString* rawFile, time_t* time, bool isSys)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    ARK_WEB_CPPTOC_CHECK_PARAM(rawFile, false);

    ARK_WEB_CPPTOC_CHECK_PARAM(time, false);

    // Execute
    return ArkOhosResourceAdapterCppToC::Get(self)->GetRawFileLastModTime(*rawFile, *time, isSys);
}

} // namespace

ArkOhosResourceAdapterCppToC::ArkOhosResourceAdapterCppToC()
{
    GetStruct()->get_raw_file_data = ark_ohos_resource_adapter_get_raw_file_data;
    GetStruct()->get_raw_file_mapper = ark_ohos_resource_adapter_get_raw_file_mapper;
    GetStruct()->is_raw_file_exist = ark_ohos_resource_adapter_is_raw_file_exist;
    GetStruct()->get_raw_file_last_mod_time1 = ark_ohos_resource_adapter_get_raw_file_last_mod_time1;
    GetStruct()->get_raw_file_last_mod_time2 = ark_ohos_resource_adapter_get_raw_file_last_mod_time2;
}

ArkOhosResourceAdapterCppToC::~ArkOhosResourceAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkOhosResourceAdapterCppToC, ArkOhosResourceAdapter,
    ark_ohos_resource_adapter_t>::kBridgeType = ARK_OHOS_RESOURCE_ADAPTER;

} // namespace OHOS::ArkWeb

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

#include "ohos_adapter/cpptoc/ark_ohos_file_mapper_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

int32_t ARK_WEB_CALLBACK ark_ohos_file_mapper_get_fd(struct _ark_ohos_file_mapper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkOhosFileMapperCppToC::Get(self)->GetFd();
}

int32_t ARK_WEB_CALLBACK ark_ohos_file_mapper_get_offset(struct _ark_ohos_file_mapper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkOhosFileMapperCppToC::Get(self)->GetOffset();
}

ArkWebString ARK_WEB_CALLBACK ark_ohos_file_mapper_get_file_name(struct _ark_ohos_file_mapper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_default);

    // Execute
    return ArkOhosFileMapperCppToC::Get(self)->GetFileName();
}

bool ARK_WEB_CALLBACK ark_ohos_file_mapper_is_compressed(struct _ark_ohos_file_mapper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkOhosFileMapperCppToC::Get(self)->IsCompressed();
}

void* ARK_WEB_CALLBACK ark_ohos_file_mapper_get_data_ptr(struct _ark_ohos_file_mapper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    return ArkOhosFileMapperCppToC::Get(self)->GetDataPtr();
}

size_t ARK_WEB_CALLBACK ark_ohos_file_mapper_get_data_len(struct _ark_ohos_file_mapper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkOhosFileMapperCppToC::Get(self)->GetDataLen();
}

bool ARK_WEB_CALLBACK ark_ohos_file_mapper_unzip_data(struct _ark_ohos_file_mapper_t* self, uint8_t** dest, size_t* len)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    ARK_WEB_CPPTOC_CHECK_PARAM(dest, false);

    ARK_WEB_CPPTOC_CHECK_PARAM(len, false);

    // Execute
    return ArkOhosFileMapperCppToC::Get(self)->UnzipData(dest, *len);
}

} // namespace

ArkOhosFileMapperCppToC::ArkOhosFileMapperCppToC()
{
    GetStruct()->get_fd = ark_ohos_file_mapper_get_fd;
    GetStruct()->get_offset = ark_ohos_file_mapper_get_offset;
    GetStruct()->get_file_name = ark_ohos_file_mapper_get_file_name;
    GetStruct()->is_compressed = ark_ohos_file_mapper_is_compressed;
    GetStruct()->get_data_ptr = ark_ohos_file_mapper_get_data_ptr;
    GetStruct()->get_data_len = ark_ohos_file_mapper_get_data_len;
    GetStruct()->unzip_data = ark_ohos_file_mapper_unzip_data;
}

ArkOhosFileMapperCppToC::~ArkOhosFileMapperCppToC() {}

template<>
ArkWebBridgeType
    ArkWebCppToCRefCounted<ArkOhosFileMapperCppToC, ArkOhosFileMapper, ark_ohos_file_mapper_t>::kBridgeType =
        ARK_OHOS_FILE_MAPPER;

} // namespace OHOS::ArkWeb

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

#include "ohos_adapter/ctocpp/ark_buffer_request_config_adapter_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
int32_t ArkBufferRequestConfigAdapterCToCpp::GetWidth()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_buffer_request_config_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_width, 0);

    // Execute
    return _struct->get_width(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkBufferRequestConfigAdapterCToCpp::GetHeight()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_buffer_request_config_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_height, 0);

    // Execute
    return _struct->get_height(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkBufferRequestConfigAdapterCToCpp::GetStrideAlignment()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_buffer_request_config_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_stride_alignment, 0);

    // Execute
    return _struct->get_stride_alignment(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkBufferRequestConfigAdapterCToCpp::GetFormat()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_buffer_request_config_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_format, 0);

    // Execute
    return _struct->get_format(_struct);
}

ARK_WEB_NO_SANITIZE
uint64_t ArkBufferRequestConfigAdapterCToCpp::GetUsage()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_buffer_request_config_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_usage, 0);

    // Execute
    return _struct->get_usage(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkBufferRequestConfigAdapterCToCpp::GetTimeout()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_buffer_request_config_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_timeout, 0);

    // Execute
    return _struct->get_timeout(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkBufferRequestConfigAdapterCToCpp::GetColorGamut()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_buffer_request_config_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_color_gamut, 0);

    // Execute
    return _struct->get_color_gamut(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkBufferRequestConfigAdapterCToCpp::GetTransformType()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_buffer_request_config_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_transform_type, 0);

    // Execute
    return _struct->get_transform_type(_struct);
}

ArkBufferRequestConfigAdapterCToCpp::ArkBufferRequestConfigAdapterCToCpp() {}

ArkBufferRequestConfigAdapterCToCpp::~ArkBufferRequestConfigAdapterCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkBufferRequestConfigAdapterCToCpp, ArkBufferRequestConfigAdapter,
    ark_buffer_request_config_adapter_t>::kBridgeType = ARK_BUFFER_REQUEST_CONFIG_ADAPTER;

} // namespace OHOS::ArkWeb

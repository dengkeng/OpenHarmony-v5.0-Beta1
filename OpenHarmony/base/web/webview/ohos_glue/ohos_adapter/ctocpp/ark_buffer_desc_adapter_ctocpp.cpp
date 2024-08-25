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

#include "ohos_adapter/ctocpp/ark_buffer_desc_adapter_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
uint8_t* ArkBufferDescAdapterCToCpp::GetBuffer()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_buffer_desc_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, nullptr);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_buffer, nullptr);

    // Execute
    return _struct->get_buffer(_struct);
}

ARK_WEB_NO_SANITIZE
size_t ArkBufferDescAdapterCToCpp::GetBufLength()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_buffer_desc_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_buf_length, 0);

    // Execute
    return _struct->get_buf_length(_struct);
}

ARK_WEB_NO_SANITIZE
size_t ArkBufferDescAdapterCToCpp::GetDataLength()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_buffer_desc_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_data_length, 0);

    // Execute
    return _struct->get_data_length(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkBufferDescAdapterCToCpp::SetBuffer(uint8_t* buffer)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_buffer_desc_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_buffer, );

    // Execute
    _struct->set_buffer(_struct, buffer);
}

ARK_WEB_NO_SANITIZE
void ArkBufferDescAdapterCToCpp::SetBufLength(size_t bufLength)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_buffer_desc_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_buf_length, );

    // Execute
    _struct->set_buf_length(_struct, bufLength);
}

ARK_WEB_NO_SANITIZE
void ArkBufferDescAdapterCToCpp::SetDataLength(size_t dataLength)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_buffer_desc_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_data_length, );

    // Execute
    _struct->set_data_length(_struct, dataLength);
}

ArkBufferDescAdapterCToCpp::ArkBufferDescAdapterCToCpp() {}

ArkBufferDescAdapterCToCpp::~ArkBufferDescAdapterCToCpp() {}

template<>
ArkWebBridgeType
    ArkWebCToCppRefCounted<ArkBufferDescAdapterCToCpp, ArkBufferDescAdapter, ark_buffer_desc_adapter_t>::kBridgeType =
        ARK_BUFFER_DESC_ADAPTER;

} // namespace OHOS::ArkWeb

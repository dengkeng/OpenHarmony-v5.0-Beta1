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

#include "ohos_adapter/ctocpp/ark_decoder_format_adapter_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
int32_t ArkDecoderFormatAdapterCToCpp::GetWidth()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_decoder_format_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_width, 0);

    // Execute
    return _struct->get_width(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkDecoderFormatAdapterCToCpp::GetHeight()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_decoder_format_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_height, 0);

    // Execute
    return _struct->get_height(_struct);
}

ARK_WEB_NO_SANITIZE
double ArkDecoderFormatAdapterCToCpp::GetFrameRate()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_decoder_format_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_frame_rate, 0);

    // Execute
    return _struct->get_frame_rate(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkDecoderFormatAdapterCToCpp::SetWidth(int32_t width)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_decoder_format_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_width, );

    // Execute
    _struct->set_width(_struct, width);
}

ARK_WEB_NO_SANITIZE
void ArkDecoderFormatAdapterCToCpp::SetHeight(int32_t height)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_decoder_format_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_height, );

    // Execute
    _struct->set_height(_struct, height);
}

ARK_WEB_NO_SANITIZE
void ArkDecoderFormatAdapterCToCpp::SetFrameRate(double frameRate)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_decoder_format_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_frame_rate, );

    // Execute
    _struct->set_frame_rate(_struct, frameRate);
}

ArkDecoderFormatAdapterCToCpp::ArkDecoderFormatAdapterCToCpp() {}

ArkDecoderFormatAdapterCToCpp::~ArkDecoderFormatAdapterCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkDecoderFormatAdapterCToCpp, ArkDecoderFormatAdapter,
    ark_decoder_format_adapter_t>::kBridgeType = ARK_DECODER_FORMAT_ADAPTER;

} // namespace OHOS::ArkWeb

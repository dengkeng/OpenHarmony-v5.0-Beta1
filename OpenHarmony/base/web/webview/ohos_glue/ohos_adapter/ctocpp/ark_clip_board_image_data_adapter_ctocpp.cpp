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

#include "ohos_adapter/ctocpp/ark_clip_board_image_data_adapter_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
int32_t ArkClipBoardImageDataAdapterCToCpp::GetColorType()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_clip_board_image_data_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_color_type, 0);

    // Execute
    return _struct->get_color_type(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkClipBoardImageDataAdapterCToCpp::GetAlphaType()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_clip_board_image_data_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_alpha_type, 0);

    // Execute
    return _struct->get_alpha_type(_struct);
}

ARK_WEB_NO_SANITIZE
uint32_t* ArkClipBoardImageDataAdapterCToCpp::GetData()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_clip_board_image_data_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, nullptr);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_data, nullptr);

    // Execute
    return _struct->get_data(_struct);
}

ARK_WEB_NO_SANITIZE
size_t ArkClipBoardImageDataAdapterCToCpp::GetDataSize()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_clip_board_image_data_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_data_size, 0);

    // Execute
    return _struct->get_data_size(_struct);
}

ARK_WEB_NO_SANITIZE
size_t ArkClipBoardImageDataAdapterCToCpp::GetRowBytes()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_clip_board_image_data_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_row_bytes, 0);

    // Execute
    return _struct->get_row_bytes(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkClipBoardImageDataAdapterCToCpp::GetWidth()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_clip_board_image_data_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_width, 0);

    // Execute
    return _struct->get_width(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkClipBoardImageDataAdapterCToCpp::GetHeight()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_clip_board_image_data_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_height, 0);

    // Execute
    return _struct->get_height(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkClipBoardImageDataAdapterCToCpp::SetColorType(int32_t color)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_clip_board_image_data_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_color_type, );

    // Execute
    _struct->set_color_type(_struct, color);
}

ARK_WEB_NO_SANITIZE
void ArkClipBoardImageDataAdapterCToCpp::SetAlphaType(int32_t alpha)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_clip_board_image_data_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_alpha_type, );

    // Execute
    _struct->set_alpha_type(_struct, alpha);
}

ARK_WEB_NO_SANITIZE
void ArkClipBoardImageDataAdapterCToCpp::SetData(uint32_t* data)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_clip_board_image_data_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_data, );

    // Execute
    _struct->set_data(_struct, data);
}

ARK_WEB_NO_SANITIZE
void ArkClipBoardImageDataAdapterCToCpp::SetDataSize(size_t size)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_clip_board_image_data_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_data_size, );

    // Execute
    _struct->set_data_size(_struct, size);
}

ARK_WEB_NO_SANITIZE
void ArkClipBoardImageDataAdapterCToCpp::SetRowBytes(size_t rowBytes)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_clip_board_image_data_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_row_bytes, );

    // Execute
    _struct->set_row_bytes(_struct, rowBytes);
}

ARK_WEB_NO_SANITIZE
void ArkClipBoardImageDataAdapterCToCpp::SetWidth(int32_t width)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_clip_board_image_data_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_width, );

    // Execute
    _struct->set_width(_struct, width);
}

ARK_WEB_NO_SANITIZE
void ArkClipBoardImageDataAdapterCToCpp::SetHeight(int32_t height)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_clip_board_image_data_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_height, );

    // Execute
    _struct->set_height(_struct, height);
}

ArkClipBoardImageDataAdapterCToCpp::ArkClipBoardImageDataAdapterCToCpp() {}

ArkClipBoardImageDataAdapterCToCpp::~ArkClipBoardImageDataAdapterCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkClipBoardImageDataAdapterCToCpp, ArkClipBoardImageDataAdapter,
    ark_clip_board_image_data_adapter_t>::kBridgeType = ARK_CLIP_BOARD_IMAGE_DATA_ADAPTER;

} // namespace OHOS::ArkWeb

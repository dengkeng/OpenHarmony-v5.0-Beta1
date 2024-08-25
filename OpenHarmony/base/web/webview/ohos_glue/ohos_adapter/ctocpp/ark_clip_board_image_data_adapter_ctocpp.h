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

#ifndef ARK_CLIP_BOARD_IMAGE_DATA_ADAPTER_CTOCPP_H_
#define ARK_CLIP_BOARD_IMAGE_DATA_ADAPTER_CTOCPP_H_
#pragma once

#include "ohos_adapter/capi/ark_pasteboard_client_adapter_capi.h"
#include "ohos_adapter/include/ark_pasteboard_client_adapter.h"

#include "base/ctocpp/ark_web_ctocpp_ref_counted.h"

namespace OHOS::ArkWeb {

// Wrap a C structure with a C++ class.
// This class may be instantiated and accessed wrapper-side only.
class ArkClipBoardImageDataAdapterCToCpp : public ArkWebCToCppRefCounted<ArkClipBoardImageDataAdapterCToCpp,
                                               ArkClipBoardImageDataAdapter, ark_clip_board_image_data_adapter_t> {
public:
    ArkClipBoardImageDataAdapterCToCpp();
    virtual ~ArkClipBoardImageDataAdapterCToCpp();

    // ArkClipBoardImageDataAdapter methods.
    int32_t GetColorType() override;

    int32_t GetAlphaType() override;

    uint32_t* GetData() override;

    size_t GetDataSize() override;

    size_t GetRowBytes() override;

    int32_t GetWidth() override;

    int32_t GetHeight() override;

    void SetColorType(int32_t color) override;

    void SetAlphaType(int32_t alpha) override;

    void SetData(uint32_t* data) override;

    void SetDataSize(size_t size) override;

    void SetRowBytes(size_t rowBytes) override;

    void SetWidth(int32_t width) override;

    void SetHeight(int32_t height) override;
};

} // namespace OHOS::ArkWeb

#endif // ARK_CLIP_BOARD_IMAGE_DATA_ADAPTER_CTOCPP_H_

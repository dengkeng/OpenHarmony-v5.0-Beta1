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

#ifndef ARK_DECODER_FORMAT_ADAPTER_CTOCPP_H_
#define ARK_DECODER_FORMAT_ADAPTER_CTOCPP_H_
#pragma once

#include "ohos_adapter/capi/ark_media_codec_decoder_adapter_capi.h"
#include "ohos_adapter/include/ark_media_codec_decoder_adapter.h"

#include "base/ctocpp/ark_web_ctocpp_ref_counted.h"

namespace OHOS::ArkWeb {

// Wrap a C structure with a C++ class.
// This class may be instantiated and accessed wrapper-side only.
class ArkDecoderFormatAdapterCToCpp : public ArkWebCToCppRefCounted<ArkDecoderFormatAdapterCToCpp,
                                          ArkDecoderFormatAdapter, ark_decoder_format_adapter_t> {
public:
    ArkDecoderFormatAdapterCToCpp();
    virtual ~ArkDecoderFormatAdapterCToCpp();

    // ArkDecoderFormatAdapter methods.
    int32_t GetWidth() override;

    int32_t GetHeight() override;

    double GetFrameRate() override;

    void SetWidth(int32_t width) override;

    void SetHeight(int32_t height) override;

    void SetFrameRate(double frameRate) override;
};

} // namespace OHOS::ArkWeb

#endif // ARK_DECODER_FORMAT_ADAPTER_CTOCPP_H_

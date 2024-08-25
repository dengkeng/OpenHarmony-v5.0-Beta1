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

#ifndef ARK_MEDIA_CODEC_DECODER_ADAPTER_CPPTOC_H_
#define ARK_MEDIA_CODEC_DECODER_ADAPTER_CPPTOC_H_
#pragma once

#include "ohos_adapter/capi/ark_media_codec_decoder_adapter_capi.h"
#include "ohos_adapter/include/ark_media_codec_decoder_adapter.h"

#include "base/cpptoc/ark_web_cpptoc_ref_counted.h"

namespace OHOS::ArkWeb {

// Wrap a C++ class with a C structure.
// This class may be instantiated and accessed DLL-side only.
class ArkMediaCodecDecoderAdapterCppToC : public ArkWebCppToCRefCounted<ArkMediaCodecDecoderAdapterCppToC,
                                              ArkMediaCodecDecoderAdapter, ark_media_codec_decoder_adapter_t> {
public:
    ArkMediaCodecDecoderAdapterCppToC();
    virtual ~ArkMediaCodecDecoderAdapterCppToC();
};

} // namespace OHOS::ArkWeb

#endif // ARK_MEDIA_CODEC_DECODER_ADAPTER_CPPTOC_H_

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

#ifndef ARK_AUDIO_ENC_INFO_ADAPTER_CTOCPP_H_
#define ARK_AUDIO_ENC_INFO_ADAPTER_CTOCPP_H_
#pragma once

#include "ohos_adapter/capi/ark_screen_capture_adapter_capi.h"
#include "ohos_adapter/include/ark_screen_capture_adapter.h"

#include "base/ctocpp/ark_web_ctocpp_ref_counted.h"

namespace OHOS::ArkWeb {

// Wrap a C structure with a C++ class.
// This class may be instantiated and accessed wrapper-side only.
class ArkAudioEncInfoAdapterCToCpp : public ArkWebCToCppRefCounted<ArkAudioEncInfoAdapterCToCpp, ArkAudioEncInfoAdapter,
                                         ark_audio_enc_info_adapter_t> {
public:
    ArkAudioEncInfoAdapterCToCpp();
    virtual ~ArkAudioEncInfoAdapterCToCpp();

    // ArkAudioEncInfoAdapter methods.
    int32_t GetAudioBitrate() override;

    int32_t GetAudioCodecformat() override;
};

} // namespace OHOS::ArkWeb

#endif // ARK_AUDIO_ENC_INFO_ADAPTER_CTOCPP_H_

/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef AVCODEC_SAMPLE_VIDEO_ENCODER_H
#define AVCODEC_SAMPLE_VIDEO_ENCODER_H

#include "native_avcodec_videoencoder.h"
#include "sample_info.h"

namespace OHOS {
namespace MediaAVCodec {
namespace Sample {
class VideoEncoder {
public:
    VideoEncoder() = default;
    ~VideoEncoder();
    
    int32_t Create(const std::string &codecMime);
    int32_t Config(SampleInfo &sampleInfo, CodecUserData *codecUserData);
    int32_t Start();
    int32_t PushInputData(CodecBufferInfo &info);
    int32_t NotifyEndOfStream();
    int32_t FreeOutputData(uint32_t bufferIndex);
    int32_t Stop();
    int32_t Release();

private:
    int32_t SetCallback(CodecUserData *codecUserData);
    int32_t Configure(const SampleInfo &sampleInfo);
    int32_t GetSurface(SampleInfo &sampleInfo);

    OH_AVCodec *encoder_ = nullptr;
    bool isAVBufferMode_;
};
} // Sample
} // MediaAVCodec
} // OHOS
#endif // AVCODEC_SAMPLE_VIDEO_ENCODER_H
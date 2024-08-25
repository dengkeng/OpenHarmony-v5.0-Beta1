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

#ifndef FOUNDATION_ACE_FRAMEWORKS_BASE_IMAGE_ACE_IMAGE_PACKER_H
#define FOUNDATION_ACE_FRAMEWORKS_BASE_IMAGE_ACE_IMAGE_PACKER_H

#include "base/memory/ace_type.h"

namespace OHOS::Ace {
struct PackOption {
    /**
     * Specify the file format of the output image.
     */
    std::string format;
    /**
     * Hint to the compression quality, 0-100.
     * Larger values indicate higher image quality but usually take up larger sizes.
     */
    uint8_t quality = 100;

    /**
     * Hint to how many images will be packed into the image file.
     */
    uint32_t numberHint = 1;
};
class PixelMap;

class ACE_EXPORT ImagePacker : public AceType {
    DECLARE_ACE_TYPE(ImagePacker, AceType)
public:
    static RefPtr<ImagePacker> Create();

    virtual uint32_t StartPacking(uint8_t* data, uint32_t maxSize, const PackOption& option) = 0;
    virtual uint32_t StartPacking(const std::string& filePath, const PackOption& option) = 0;
    virtual uint32_t AddImage(PixelMap& pixelMap) = 0;
    virtual uint32_t FinalizePacking(int64_t& packedSize) = 0;
};
} // namespace OHOS::Ace

#endif // FOUNDATION_ACE_FRAMEWORKS_BASE_IMAGE_ACE_IMAGE_PACKER_H

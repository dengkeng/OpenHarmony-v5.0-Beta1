/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "display_test.h"
#include "buffer_handle.h"
namespace OHOS {
namespace HDI {
namespace Display {
namespace TEST {
void SetUint32(uint32_t& dst, uint32_t value)
{
    uint8_t* data = reinterpret_cast<uint8_t *>(&dst);
    for (uint8_t i = 0; i < sizeof(uint32_t); i++) {
        *(data + i) = (value >> ((sizeof(uint32_t) - i - 1) * BITS_PER_BYTE)) & 0xff;
    }
}

void SetPixel(const BufferHandle& handle, int x, int y, uint32_t color)
{
    const int32_t PIXEL_BYTES = 4;
    DISPLAY_TEST_CHK_RETURN_NOT_VALUE((handle.format <= 0),
        DISPLAY_TEST_LOGE("CheckPixel do not support format %{public}d", handle.format));
    DISPLAY_TEST_CHK_RETURN_NOT_VALUE((handle.virAddr == nullptr),
        DISPLAY_TEST_LOGE("CheckPixel viraddr is null must map it"));
    DISPLAY_TEST_CHK_RETURN_NOT_VALUE((x < 0 || x >= handle.width),
        DISPLAY_TEST_LOGE("CheckPixel invalid parameter x:%{public}d width:%{public}d", x, handle.width));
    DISPLAY_TEST_CHK_RETURN_NOT_VALUE((y < 0 || y >= handle.height),
        DISPLAY_TEST_LOGE("CheckPixel invalid parameter y:%{public}d height:%{public}d", y, handle.height));

    int32_t position = y * handle.width + x;
    if ((position * PIXEL_BYTES) > handle.size) {
        DISPLAY_TEST_LOGE("the pixel position outside\n");
    }
    uint32_t* pixel = reinterpret_cast<uint32_t *>(handle.virAddr) + position;
    DISPLAY_TEST_CHK_RETURN_NOT_VALUE((pixel == nullptr), DISPLAY_TEST_LOGE("get pixel failed"));
    SetUint32(*pixel, color);
}

void ClearColor(const BufferHandle& handle, uint32_t color)
{
    for (int32_t x = 0; x < handle.width; x++) {
        for (int32_t y = 0; y < handle.height; y++) {
            SetPixel(handle, x, y, color);
        }
    }
}
} // OHOS
} // HDI
} // Display
} // TEST

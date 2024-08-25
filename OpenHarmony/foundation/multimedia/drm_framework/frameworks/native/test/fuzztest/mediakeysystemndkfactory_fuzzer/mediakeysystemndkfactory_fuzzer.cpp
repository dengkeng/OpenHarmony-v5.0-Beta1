/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <string>
#include <refbase.h>
#include <securec.h>
#include "drm_log.h"
#include "native_drm_common.h"
#include "native_drm_base.h"
#include "native_drm_object.h"
#include "native_mediakeysystem.h"
#include "mediakeysystemndkfactory_fuzzer.h"

using namespace std;
using namespace OHOS;
using namespace DrmStandard;

namespace OHOS {
namespace DrmStandard {
MediaKeySystemFactoryNdkFuzzer::MediaKeySystemFactoryNdkFuzzer() {}

MediaKeySystemFactoryNdkFuzzer::~MediaKeySystemFactoryNdkFuzzer() {}

void MediaKeySystemFactoryNdkFuzzer::GetUuid()
{
    if (OH_MediaKeySystem_IsSupported("com.clearplay.drm")) {
        uuid = "com.clearplay.drm";
    } else if (OH_MediaKeySystem_IsSupported("com.wiseplay.drm")) {
        uuid = "com.wiseplay.drm";
    }
}

void MediaKeySystemFactoryNdkFuzzer::IsWisePlay()
{
    if (OH_MediaKeySystem_IsSupported("com.wiseplay.drm")) {
        wisePlay = true;
    }
}

bool MediaKeySystemFactoryNdkFuzzer::FuzzTestSystemFactoryNdk(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < sizeof(int32_t)) {
        return false;
    }
    uuid.assign(reinterpret_cast<const char *>(rawData), size);
    OH_MediaKeySystem_IsSupported(uuid.c_str());
    mimeType.assign(reinterpret_cast<const char *>(rawData), size);
    OH_MediaKeySystem_IsSupported2(uuid.c_str(), mimeType.c_str());
    const int32_t number = 5;
    DRM_ContentProtectionLevel randomSet[number] = {
        CONTENT_PROTECTION_LEVEL_UNKNOWN,
        CONTENT_PROTECTION_LEVEL_SW_CRYPTO,
        CONTENT_PROTECTION_LEVEL_HW_CRYPTO,
        CONTENT_PROTECTION_LEVEL_ENHANCED_HW_CRYPTO,
        CONTENT_PROTECTION_LEVEL_MAX
    };
    int32_t randomNumber = (static_cast<int32_t>(*rawData)) % number;
    OH_MediaKeySystem_IsSupported3(uuid.c_str(), mimeType.c_str(), randomSet[randomNumber]);
    OH_MediaKeySystem_IsSupported3(uuid.c_str(), mimeType.c_str(), CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    mediaKeySystem = reinterpret_cast<MediaKeySystem *>(rawData);
    Drm_ErrCode ret = OH_MediaKeySystem_Create(uuid.c_str(), &mediaKeySystem);
    if (ret == DRM_ERR_OK) {
        OH_MediaKeySystem_Destroy(mediaKeySystem);
    }
    return true;
}
} // namespace DrmStandard

bool FuzzSystemFactoryNdk(uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return true;
    }
    MediaKeySystemFactoryNdkFuzzer testMediaSystemFactory;
    return testMediaSystemFactory.FuzzTestSystemFactoryNdk(data, size);
}
} // namesapce OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzSystemFactoryNdk(data, size);
    return 0;
}
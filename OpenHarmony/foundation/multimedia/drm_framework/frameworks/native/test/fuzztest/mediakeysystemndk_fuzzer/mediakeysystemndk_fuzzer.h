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


#ifndef DRM_MEDIAKEYSYSTEMNDK_FUZZER_H
#define DRM_MEDIAKEYSYSTEMNDK_FUZZER_H

#include "native_drm_common.h"
#include "native_drm_base.h"
#include "native_drm_object.h"
#include "native_mediakeysystem.h"
#define FUZZ_PROJECT_NAME "mediakeysystemndk_fuzzer"

namespace OHOS {
namespace DrmStandard {
class MediaKeySystemNdkFuzzer : public NoCopyable {
private:
    bool wisePlay = false;

public:
    MediaKeySystemNdkFuzzer();
    ~MediaKeySystemNdkFuzzer();
    bool FuzzTestMediaKeySystemConfigurationNdk(uint8_t *rawData, size_t size);
    bool FuzzTestMediaKeySystemGetNdk(uint8_t *rawData, size_t size);
    bool FuzzTestMediaKeySystemDeviceCertificateNdk(uint8_t *rawData, size_t size);
    bool FuzzTestMediaKeySystemCertificateOperationNdk(uint8_t *rawData, size_t size);
    bool FuzzTestMediaKeySystemLicenseOperationNdk(uint8_t *rawData, size_t size);
    void GetUuid();
    void Init();
    void Deinitialize();
    void IsWisePlay();
    void GenerateDeviceCertificate();
    void GenerateLicense();
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    std::string uuid;
    std::string mimeType;
    DRM_ContentProtectionLevel ContentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
};
} // namespace DrmStandard
bool FuzzMediaKeySystemNdk(uint8_t *data, size_t size);
} // namesapce OHOS

#endif // DRM_MEDIAKEYSYSTEMNDK_FUZZER_H
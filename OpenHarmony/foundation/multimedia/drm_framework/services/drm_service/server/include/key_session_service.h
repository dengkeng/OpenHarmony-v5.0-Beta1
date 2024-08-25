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

#ifndef OHOS_DRM_KEY_SESSION_SERVICE_H
#define OHOS_DRM_KEY_SESSION_SERVICE_H

#include <iostream>
#include <refbase.h>
#include "drm_dfx_utils.h"
#include "drm_dfx.h"
#include "drm_log.h"
#include "drm_host_manager.h"
#include "key_session_service_stub.h"

#include "media_key_session_proxy.h"
#include "media_decrypt_module_proxy.h"
#include "media_key_system_factory_proxy.h"
#include "media_key_system_proxy.h"
#include "media_decrypt_module_service.h"

namespace OHOS {
namespace DrmStandard {
using namespace OHOS::HDI::Drm::V1_0;
using namespace OHOS::HDI;

class IMediaKeySessionServiceOperatorsCallback;

class MediaKeySessionService : public MediaKeySessionServiceStub, public IMediaKeySessionCallback {
public:
    explicit MediaKeySessionService(sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession> hdiMediaKeySession);
    explicit MediaKeySessionService(sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession> hdiMediaKeySession,
        StatisticsInfo statisticsInfo);
    ~MediaKeySessionService();
    int32_t Release() override;
    int32_t CreateMediaDecryptModule(sptr<IMediaDecryptModuleService> &decryptModule) override;
    int32_t SetMediaKeySessionServiceOperatorsCallback(wptr<IMediaKeySessionServiceOperatorsCallback> callback);
    int32_t CloseMediaKeySessionServiceByCallback();
    int32_t GenerateMediaKeyRequest(IMediaKeySessionService::MediaKeyRequestInfo &licenseRequestInfo,
        IMediaKeySessionService::MediaKeyRequest &licenseRequest) override;
    int32_t ProcessMediaKeyResponse(std::vector<uint8_t> &licenseId, std::vector<uint8_t> &licenseResponse) override;
    int32_t GenerateOfflineReleaseRequest(std::vector<uint8_t> &licenseId,
        std::vector<uint8_t> &releaseRequest) override;
    int32_t ProcessOfflineReleaseResponse(std::vector<uint8_t> &licenseId,
        std::vector<uint8_t> &releaseResponse) override;
    int32_t CheckMediaKeyStatus(std::map<std::string, std::string> &licenseStatus) override;
    int32_t RestoreOfflineMediaKeys(std::vector<uint8_t> &licenseId) override;
    int32_t ClearMediaKeys() override;
    int32_t GetContentProtectionLevel(IMediaKeySessionService::ContentProtectionLevel *securityLevel) override;
    int32_t RequireSecureDecoderModule(std::string &mimeType, bool *status) override;
    int32_t SetCallback(sptr<IMediaKeySessionServiceCallback> &callback) override;

    // for hdi callback
    int32_t SendEvent(OHOS::HDI::Drm::V1_0::EventType eventType, int32_t extra,
        const std::vector<uint8_t> &data) override;
    int32_t SendEventKeyChange(
        const std::map<std::vector<uint8_t>, OHOS::HDI::Drm::V1_0::MediaKeySessionKeyStatus> &keyStatus,
        bool hasNewGoodLicense) override;

private:
    std::mutex sessionMutex_;
    sptr<IMediaKeySessionServiceCallback> callback_;
    wptr<IMediaKeySessionServiceOperatorsCallback> sessionOperatorsCallback_;
    sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession> hdiMediaKeySession_;
    StatisticsInfo statisticsInfo_;
    std::string generationResult_;
    std::string mediaKeyType_;
    uint32_t generationDuration_ = 0;
};

class IMediaKeySessionServiceOperatorsCallback : public virtual RefBase {
public:
    IMediaKeySessionServiceOperatorsCallback() = default;
    virtual ~IMediaKeySessionServiceOperatorsCallback() = default;
    virtual int32_t CloseMediaKeySessionService(sptr<MediaKeySessionService> sessionService) = 0;
};
} // DrmStandard
} // OHOS

#endif // OHOS_DRM_KEY_SESSION_SERVICE_H

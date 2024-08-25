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

#ifndef OHOS_DRM_MEDIA_KEY_SYSTEM_SERVICE_PROXY_H
#define OHOS_DRM_MEDIA_KEY_SYSTEM_SERVICE_PROXY_H

#include <hilog/log.h>
#include "iremote_proxy.h"
#include "i_mediakeysystem_service.h"

namespace OHOS {
namespace DrmStandard {
class MediaKeySystemServiceProxy : public IRemoteProxy<IMediaKeySystemService> {
public:
    explicit MediaKeySystemServiceProxy(const sptr<IRemoteObject> &impl);
    virtual ~MediaKeySystemServiceProxy() = default;
    int32_t Release() override;

    int32_t GetConfigurationString(std::string &configName, std::string &value) override;
    int32_t SetConfigurationString(std::string &configName, std::string &value) override;
    int32_t GetConfigurationByteArray(std::string &configName, std::vector<uint8_t> &value) override;
    int32_t SetConfigurationByteArray(std::string &configName, std::vector<uint8_t> &value) override;
    int32_t GetMaxContentProtectionLevel(IMediaKeySessionService::ContentProtectionLevel *securityLevel) override;

    int32_t CreateMediaKeySession(IMediaKeySessionService::ContentProtectionLevel securityLevel,
        sptr<IMediaKeySessionService> &keySessionProxy) override;
    int32_t GetStatistics(std::vector<IMediaKeySystemService::MetircKeyValue> &metrics) override;
    int32_t GetCertificateStatus(IMediaKeySystemService::CertificateStatus *certStatue) override;

    int32_t GenerateKeySystemRequest(std::vector<uint8_t> &request, std::string &defaultUrl) override;
    int32_t ProcessKeySystemResponse(const std::vector<uint8_t> &response) override;

    int32_t GetOfflineMediaKeyIds(std::vector<std::vector<uint8_t>> &licenseIds) override;
    int32_t GetOfflineMediaKeyStatus(std::vector<uint8_t> &licenseId,
        IMediaKeySessionService::OfflineMediaKeyStatus &status) override;
    int32_t ClearOfflineMediaKeys(std::vector<uint8_t> &licenseId) override;
    int32_t SetListenerObject(const sptr<IRemoteObject> &object) override;
    int32_t SetCallback(sptr<IMeidaKeySystemServiceCallback> &callback) override;

private:
    static inline BrokerDelegator<MediaKeySystemServiceProxy> delegator_;
};
} // DrmStandard
} // OHOS

#endif // OHOS_DRM_MEDIA_KEY_SYSTEM_SERVICE_PROXY_H

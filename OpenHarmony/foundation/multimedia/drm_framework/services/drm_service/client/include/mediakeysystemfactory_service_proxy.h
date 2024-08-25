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

#ifndef OHOS_DRM_MEDIA_KEY_SYSTEM_FACTORY_SERVICE_PROXY_H
#define OHOS_DRM_MEDIA_KEY_SYSTEM_FACTORY_SERVICE_PROXY_H

#include <hilog/log.h>
#include "iremote_proxy.h"
#include "i_mediakeysystemfactory_service.h"

namespace OHOS {
namespace DrmStandard {
class MediaKeySystemFactoryServiceProxy : public IRemoteProxy<IMediaKeySystemFactoryService> {
public:
    explicit MediaKeySystemFactoryServiceProxy(const sptr<IRemoteObject> &impl);
    virtual ~MediaKeySystemFactoryServiceProxy() = default;
    int32_t IsMediaKeySystemSupported(std::string &uuid, bool *isSurpported) override;
    int32_t IsMediaKeySystemSupported(std::string &uuid, std::string &mimeType, bool *isSurpported) override;
    int32_t IsMediaKeySystemSupported(std::string &uuid, std::string &mimeType, int32_t securityLevel,
        bool *isSurpported) override;
    int32_t GetMediaKeySystemName(std::map<std::string, std::string> &keySystemNames) override;
    int32_t GetMediaKeySystemUuid(std::string &name, std::string &uuid) override;
    int32_t CreateMediaKeySystem(std::string &uuid, sptr<IMediaKeySystemService> &mediaKeySystemProxy) override;
    int32_t SetListenerObject(const sptr<IRemoteObject> &object) override;

private:
    static inline BrokerDelegator<MediaKeySystemFactoryServiceProxy> delegator_;
};
} // DrmStandard
} // OHOS

#endif // OHOS_DRM_MEDIA_KEY_SYSTEM_FACTORY_SERVICE_PROXY_H

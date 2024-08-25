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

#ifndef OHOS_DRM_MEDIA_DECRYPT_MODULE_SERVICE_PROXY_H
#define OHOS_DRM_MEDIA_DECRYPT_MODULE_SERVICE_PROXY_H

#include "i_mediadecryptmodule_service.h"
#include "remote_request_code.h"
#include "iremote_proxy.h"
#include "drm_log.h"

namespace OHOS {
namespace DrmStandard {
class MediaDecryptModuleServiceProxy : public IRemoteProxy<IMediaDecryptModuleService> {
public:
    explicit MediaDecryptModuleServiceProxy(const sptr<IRemoteObject> &impl);
    virtual ~MediaDecryptModuleServiceProxy() = default;
    int32_t Release() override;
    int32_t SetListenerObject(const sptr<IRemoteObject> &object) override;
    int32_t DecryptMediaData(bool secureDecodrtState, IMediaDecryptModuleService::CryptInfo &cryptInfo,
        IMediaDecryptModuleService::DrmBuffer &srcBuffer, IMediaDecryptModuleService::DrmBuffer &dstBuffer) override;

private:
    static inline BrokerDelegator<MediaDecryptModuleServiceProxy> delegator_;
    int32_t ProcessDrmBuffer(MessageParcel &data, IMediaDecryptModuleService::DrmBuffer &srcBuffer,
        IMediaDecryptModuleService::DrmBuffer &dstBuffer);
};
} // DrmStandard
} // OHOS

#endif // OHOS_DRM_MEDIA_KEY_SYSTEM_SERVICE_PROXY_H
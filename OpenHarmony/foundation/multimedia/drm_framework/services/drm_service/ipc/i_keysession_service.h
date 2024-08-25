/*
 * Copyright (c) 2023  Huawei Device Co., Ltd.
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

#ifndef OHOS_DRM_IKEY_SESSION_H
#define OHOS_DRM_IKEY_SESSION_H

#include "iremote_broker.h"
#include "drm_types.h"
#include "i_mediadecryptmodule_service.h"
#include "i_keysession_service_callback.h"

namespace OHOS {
namespace DrmStandard {
class IMediaKeySessionService : public IRemoteBroker {
public:
    enum ListenerType {
        LISTENER_DRM_EVENT = 200,
        LISTENER_PROVISION_REQUIRED = 201,
        LISTENER_KEY_REQUIRED = 202,
        LISTENER_KEY_EXPIRED = 203,
        LISTENER_VENDOR_DEFINED = 204,
        LISTENER_KEYSESSION_RECLAIMED = 205,
        LISTENER_EXPIRATION_UPDATE = 206,
        LISTENER_KEY_CHANGE = 207,
        LISTENER_KEYSESSION_LOST = 208,
    };

    enum MediaKeyType {
        LICENSETYPE_OFFLINE = 0,
        LICENSETYPE_ONLINE,
    };

    enum OfflineMediaKeyStatus {
        OFFLINELICENSESTATUS_UNKNOWN = 0,
        OFFLINELICENSESTATUS_USABLE = 1,
        OFFLINELICENSESTATUS_INACTIVE = 2,
    };

    enum RequestType {
        REQUEST_TYPE_UNKNOWN = 0,
        REQUEST_TYPE_INITIAL = 1,
        REQUEST_TYPE_RENEWAL = 2,
        REQUEST_TYPE_RELEASE = 3,
        REQUEST_TYPE_NONE = 4,
        REQUEST_TYPE_UPDATE = 5,
    };

    enum ContentProtectionLevel {
        CONTENT_PROTECTION_LEVEL_UNKNOWN = 0,
        CONTENT_PROTECTION_LEVEL_SW_CRYPTO = 1,
        CONTENT_PROTECTION_LEVEL_HW_CRYPTO = 2,
        CONTENT_PROTECTION_LEVEL_ENHANCED_HW = 3,
        CONTENT_PROTECTION_LEVEL_MAX = 4,
    };

    struct OptionalData {
        std::string name;
        std::string value;
    };

    struct MediaKeyRequestInfo {
        MediaKeyType mediaKeyType;
        std::string mimeType;
        std::vector<uint8_t> initData;
        std::map<std::string, std::string> optionalData;
    };

    struct MediaKeyRequest {
        RequestType requestType;
        std::vector<uint8_t> mData;
        std::string mDefaultURL;
    };

    virtual ~IMediaKeySessionService() = default;
    virtual int32_t Release() = 0;
    virtual int32_t CreateMediaDecryptModule(sptr<IMediaDecryptModuleService> &decryptModule) = 0;
    virtual int32_t GenerateMediaKeyRequest(MediaKeyRequestInfo &licenseRequestInfo, MediaKeyRequest &licenseInfo) = 0;
    virtual int32_t ProcessMediaKeyResponse(std::vector<uint8_t> &licenseId, std::vector<uint8_t> &licenseResponse) = 0;
    virtual int32_t GenerateOfflineReleaseRequest(std::vector<uint8_t> &licenseId,
        std::vector<uint8_t> &releaseRequest) = 0;
    virtual int32_t ProcessOfflineReleaseResponse(std::vector<uint8_t> &licenseId,
        std::vector<uint8_t> &releaseReponse) = 0;
    virtual int32_t CheckMediaKeyStatus(std::map<std::string, std::string> &licenseStatus) = 0;
    virtual int32_t RestoreOfflineMediaKeys(std::vector<uint8_t> &licenseId) = 0;
    virtual int32_t ClearMediaKeys() = 0;
    virtual int32_t GetContentProtectionLevel(IMediaKeySessionService::ContentProtectionLevel *securityLevel) = 0;
    virtual int32_t RequireSecureDecoderModule(std::string &mimeType, bool *status) = 0;
    virtual int32_t SetListenerObject(const sptr<IRemoteObject> &object) = 0;
    virtual int32_t SetCallback(sptr<IMediaKeySessionServiceCallback> &callback) = 0;
    DECLARE_INTERFACE_DESCRIPTOR(u"IMediaKeySessionService");
};
} // DrmStandard
} // OHOS


#endif // OHOS_DRM_IKEY_SESSION_H_
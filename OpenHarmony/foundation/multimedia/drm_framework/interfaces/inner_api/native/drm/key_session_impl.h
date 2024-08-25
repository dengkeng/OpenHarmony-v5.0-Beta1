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
#ifndef OHOS_DRM_KEY_SESSION_IMPL_H_
#define OHOS_DRM_KEY_SESSION_IMPL_H_

#include <cstring>
#include <map>
#include <unordered_map>
#include "nocopyable.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "i_keysession_service.h"
#include "i_keysession_service_callback.h"
#include "drm_listener_stub.h"
#include "key_session_service_callback_stub.h"
#include "drm_death_recipient.h"

namespace OHOS {
namespace DrmStandard {
namespace MediaKeySessionEvent {
const std::string EVENT_STR_KEY_NEEDED = "keyRequired";
const std::string EVENT_STR_KEY_EXPIRED = "keyExpired";
const std::string EVENT_STR_EXPIRATION_UPDATED = "expirationUpdate";
const std::string EVENT_STR_KEY_CHANGED = "keysChange";
const std::string EVENT_STR_VENDOR_DEFINED = "vendorDefined";
}

class MediaKeySessionImplCallback : public RefBase {
public:
    MediaKeySessionImplCallback() = default;
    virtual ~MediaKeySessionImplCallback() = default;
    virtual void SendEvent(const std::string &event, int32_t extra, const std::vector<uint8_t> &data) = 0;
    virtual void SendEventKeyChanged(std::map<std::vector<uint8_t>, MediaKeySessionKeyStatus> statusTable,
        bool hasNewGoodLicense) = 0;
};

class MediaKeySessionImpl : public RefBase {
public:
    explicit MediaKeySessionImpl(sptr<IMediaKeySessionService> &keySession);
    ~MediaKeySessionImpl();
    int32_t Release();
    int32_t Init();

    int32_t GenerateMediaKeyRequest(IMediaKeySessionService::MediaKeyRequestInfo &licenseRequestInfo,
        IMediaKeySessionService::MediaKeyRequest &licenseRequest);
    int32_t ProcessMediaKeyResponse(std::vector<uint8_t> &licenseId, std::vector<uint8_t> &licenseResponse);
    int32_t GenerateOfflineReleaseRequest(std::vector<uint8_t> &licenseId, std::vector<uint8_t> &releaseRequest);
    int32_t ProcessOfflineReleaseResponse(std::vector<uint8_t> &licenseId, std::vector<uint8_t> &releaseReponse);
    int32_t CheckMediaKeyStatus(std::map<std::string, std::string> &licenseStatus);
    int32_t RestoreOfflineMediaKeys(std::vector<uint8_t> &licenseId);

    int32_t ClearMediaKeys();

    int32_t GetContentProtectionLevel(IMediaKeySessionService::ContentProtectionLevel *securityLevel);

    sptr<IMediaKeySessionService> GetMediaKeySessionServiceProxy();
    sptr<MediaKeySessionImplCallback> GetApplicationCallback();
    int32_t SetCallback(const sptr<MediaKeySessionImplCallback> &callback);

    int32_t RequireSecureDecoderModule(std::string &mimeType, bool *status);

private:
    int32_t CreateListenerObject();
    void MediaKeySessionServerDied(pid_t pid);
    sptr<MediaKeySessionImplCallback> keySessionApplicationCallback_;
    sptr<IMediaKeySessionServiceCallback> keySessionServiceCallback_;
    sptr<OHOS::DrmStandard::IMediaKeySessionService> keySessionServiceProxy_;
    std::mutex mutex_;
    sptr<DrmDeathRecipient> deathRecipient_ = nullptr;
    sptr<DrmListenerStub> listenerStub_ = nullptr;
};

class MediaKeySessionServiceCallback : public MediaKeySessionServiceCallbackStub {
public:
    MediaKeySessionServiceCallback() : keySessionImpl_(nullptr)
    {
        InitEventMap();
    };
    explicit MediaKeySessionServiceCallback(const sptr<MediaKeySessionImpl> &keySessionImpl)
        : keySessionImpl_(keySessionImpl)
    {
        InitEventMap();
    }

    ~MediaKeySessionServiceCallback()
    {
        keySessionImpl_ = nullptr;
    }

    void InitEventMap();
    std::string GetEventName(DrmEventType event);
    int32_t SendEvent(DrmEventType event, int32_t extra, const std::vector<uint8_t> data) override;
    int32_t SendEventKeyChanged(std::map<std::vector<uint8_t>, MediaKeySessionKeyStatus> statusTable,
        bool hasNewGoodLicense) override;

private:
    sptr<MediaKeySessionImpl> keySessionImpl_;
    std::unordered_map<int32_t, std::string> eventMap_;
};
} // DrmStandard
} // OHOS


#endif
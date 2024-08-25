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

#ifndef NATIVE_DRM_OBJECT_H
#define NATIVE_DRM_OBJECT_H

#include <stdint.h>
#include <stdio.h>
#include "native_drm_err.h"
#include "native_drm_base.h"
#include "native_drm_common.h"

#include "key_session_impl.h"
#include "media_key_system_impl.h"
#include "media_key_system_factory_impl.h"
#include "native_mediakeysystem.h"
#include "native_mediakeysession.h"

namespace OHOS {
namespace DrmStandard {
class MediaKeySystemCallbackCapi;
class MediaKeySessionCallbackCapi;

struct MediaKeySystemObject : public MediaKeySystem {
    explicit MediaKeySystemObject(const OHOS::sptr<OHOS::DrmStandard::MediaKeySystemImpl> &impl) : systemImpl_(impl) {}
    ~MediaKeySystemObject() = default;

    const OHOS::sptr<OHOS::DrmStandard::MediaKeySystemImpl> systemImpl_ = nullptr;
    OHOS::sptr<OHOS::DrmStandard::MediaKeySystemCallbackCapi> systemCallback_ = nullptr;
};

struct MediaKeySessionObject : public MediaKeySession {
    explicit MediaKeySessionObject(const OHOS::sptr<OHOS::DrmStandard::MediaKeySessionImpl> &impl) : sessionImpl_(impl)
    {}
    ~MediaKeySessionObject() = default;

    const OHOS::sptr<OHOS::DrmStandard::MediaKeySessionImpl> sessionImpl_ = nullptr;
    OHOS::sptr<MediaKeySessionCallbackCapi> sessionCallback_ = nullptr;
};

class MediaKeySystemCallbackCapi : public MediaKeySystemImplCallback {
public:
    MediaKeySystemCallbackCapi() : system_(nullptr), callback_(nullptr), systemCallback_(nullptr)
    {
        DRM_INFO_LOG("MediaKeySystemCallbackCapi.");
        InitEventMap();
    }

    void InitEventMap()
    {
        eventMap_.insert({ static_cast<std::string>(MediaKeySystemEvent::EVENT_STR_PROVISION_REQUIRED),
            EVENT_PROVISION_REQUIRED });
    }

    virtual ~MediaKeySystemCallbackCapi()
    {
        DRM_INFO_LOG("~MediaKeySystemCallbackCapi.");
    }

    void SetCallbackReference(MediaKeySystem_Callback callback)
    {
        DRM_INFO_LOG("MediaKeySystemCallbackCapi SetCallbackReference.");
        std::lock_guard<std::mutex> lock(mutex_);
        callback_ = callback;
    }

    void SetCallbackReference(MediaKeySystem *system, OH_MediaKeySystem_Callback systemCallback)
    {
        DRM_INFO_LOG("MediaKeySystemCallbackCapi SetCallbackReference.");
        std::lock_guard<std::mutex> lock(mutex_);
        system_ = system;
        systemCallback_ = systemCallback;
    }

    void ClearCallbackReference()
    {
        DRM_INFO_LOG("MediaKeySystemCallbackCapi ClearCallbackReference.");
        std::lock_guard<std::mutex> lock(mutex_);
        system_ = nullptr;
        callback_ = nullptr;
        systemCallback_ = nullptr;
    }

    void SendEvent(const std::string &event, int32_t extra, const std::vector<uint8_t> &data) override
    {
        DRM_INFO_LOG("MediaKeySystemCallbackCapi SendEvent.");
        std::lock_guard<std::mutex> lock(mutex_);
        DRM_CHECK_AND_RETURN_LOG((callback_ != nullptr) || (systemCallback_ != nullptr),
            "hasn't register any callback of %{public}s event", event.c_str());

        if (eventMap_.find(event) == eventMap_.end()) {
            DRM_ERR_LOG("MediaKeySystemCallbackCapi SendEvent failed, not find this event type.");
            return;
        }

        unsigned char *dataInfo = nullptr;
        if (data.size() != 0) {
            dataInfo = (unsigned char *)malloc(data.size());
            DRM_CHECK_AND_RETURN_LOG(dataInfo != nullptr, "malloc faild!");
            errno_t ret = memcpy_s(dataInfo, data.size(), data.data(), data.size());
            DRM_CHECK_AND_RETURN_LOG(ret == EOK, "memcpy_s faild!");
        }

        if (callback_ != nullptr) {
            callback_(eventMap_[event], dataInfo, data.size(), std::to_string(extra).data());
        }
        if (systemCallback_ != nullptr) {
            systemCallback_(system_, eventMap_[event], dataInfo, data.size(), std::to_string(extra).data());
        }

        if (dataInfo != nullptr) {
            free(dataInfo);
            dataInfo = nullptr;
        }
    }

private:
    MediaKeySystem *system_ = nullptr;
    MediaKeySystem_Callback callback_ = nullptr;
    OH_MediaKeySystem_Callback systemCallback_ = nullptr;
    std::mutex mutex_;
    std::unordered_map<std::string, DRM_EventType> eventMap_;
};

class MediaKeySessionCallbackCapi : public MediaKeySessionImplCallback {
public:
    MediaKeySessionCallbackCapi() : session_(nullptr), callback_({}), sessionCallback_({})
    {
        DRM_INFO_LOG("MediaKeySessionCallbackCapi.");
        InitEventMap();
    }

    void InitEventMap()
    {
        eventMap_.insert({ static_cast<std::string>(MediaKeySessionEvent::EVENT_STR_EXPIRATION_UPDATED),
            EVENT_EXPIRATION_UPDATE });
        eventMap_.insert(
            { static_cast<std::string>(MediaKeySessionEvent::EVENT_STR_KEY_EXPIRED), EVENT_KEY_EXPIRED });
        eventMap_.insert(
            { static_cast<std::string>(MediaKeySessionEvent::EVENT_STR_KEY_NEEDED), EVENT_KEY_REQUIRED });
        eventMap_.insert(
            { static_cast<std::string>(MediaKeySessionEvent::EVENT_STR_VENDOR_DEFINED), EVENT_VENDOR_DEFINED });
    }

    virtual ~MediaKeySessionCallbackCapi()
    {
        DRM_INFO_LOG("~MediaKeySessionCallbackCapi.");
    }

    void SetCallbackReference(MediaKeySession_Callback callback)
    {
        DRM_INFO_LOG("MediaKeySessionCallbackCapi SetCallbackReference.");
        std::lock_guard<std::mutex> lock(mutex_);
        callback_ = callback;
    }

    void SetCallbackReference(MediaKeySession *session, OH_MediaKeySession_Callback sessionCallback)
    {
        DRM_INFO_LOG("MediaKeySessionCallbackCapi SetCallbackReference.");
        std::lock_guard<std::mutex> lock(mutex_);
        session_ = session;
        sessionCallback_ = sessionCallback;
    }

    void ClearCallbackReference()
    {
        DRM_INFO_LOG("MediaKeySessionCallbackCapi ClearCallbackReference.");
        std::lock_guard<std::mutex> lock(mutex_);
        session_ = nullptr;
        callback_ = {};
        sessionCallback_ = {};
    }

    void SendEvent(const std::string &event, int32_t extra, const std::vector<uint8_t> &data) override
    {
        DRM_INFO_LOG("MediaKeySessionCallbackCapi SendEvent.");
        std::lock_guard<std::mutex> lock(mutex_);
        DRM_CHECK_AND_RETURN_LOG((callback_.eventCallback != nullptr) || (sessionCallback_.eventCallback != nullptr),
            "hasn't register any callback of %{public}s event", event.c_str());
        if (eventMap_.find(event) == eventMap_.end()) {
            DRM_ERR_LOG("MediaKeySystemCallbackCapi SendEvent failed, not find this event type.");
            return;
        }

        unsigned char *dataInfo = nullptr;
        if (data.size() != 0) {
            dataInfo = (unsigned char *)malloc(data.size());
            DRM_CHECK_AND_RETURN_LOG(dataInfo != nullptr, "malloc faild!");
            errno_t ret = memcpy_s(dataInfo, data.size(), data.data(), data.size());
            DRM_CHECK_AND_RETURN_LOG(ret == EOK, "memcpy_s faild!");
        }

        if (callback_.eventCallback != nullptr) {
            callback_.eventCallback(eventMap_[event], dataInfo, data.size(), std::to_string(extra).data());
        }
        if (sessionCallback_.eventCallback != nullptr) {
            sessionCallback_.eventCallback(
                session_, eventMap_[event], dataInfo, data.size(), std::to_string(extra).data());
        }

        if (dataInfo != nullptr) {
            free(dataInfo);
            dataInfo = nullptr;
        }
    }

    void SendEventKeyChanged(std::map<std::vector<uint8_t>, MediaKeySessionKeyStatus> statusTable,
        bool hasNewGoodLicense) override
    {
        DRM_INFO_LOG("MediaKeySessionCallbackCapi SendEventKeyChanged.");
        std::lock_guard<std::mutex> lock(mutex_);
        DRM_CHECK_AND_RETURN_LOG((callback_.keyChangeCallback != nullptr) ||
            (sessionCallback_.keyChangeCallback != nullptr), "hasn't register any callback of KeyChanged event!");

        static std::unordered_map<MediaKeySessionKeyStatus, std::string> KeyStatusStringMap {
            {MediaKeySessionKeyStatus::MEDIA_KEY_SESSION_KEY_STATUS_USABLE, "USABLE"},
            {MediaKeySessionKeyStatus::MEDIA_KEY_SESSION_KEY_STATUS_EXPIRED, "EXPIRED"},
            {MediaKeySessionKeyStatus::MEDIA_KEY_SESSION_KEY_STATUS_OUTPUT_NOT_ALLOWED, "OUTPUT_NOT_ALLOWED"},
            {MediaKeySessionKeyStatus::MEDIA_KEY_SESSION_KEY_STATUS_PENDING, "PENDING"},
            {MediaKeySessionKeyStatus::MEDIA_KEY_SESSION_KEY_STATUS_INTERNAL_ERROR, "INTERNAL_ERROR"},
            {MediaKeySessionKeyStatus::MEDIA_KEY_SESSION_KEY_STATUS_USABLE_IN_FUTURE, "USABLE_IN_FUTURE"},
        };

        uint32_t tableCount = statusTable.size();
        DRM_CHECK_AND_RETURN_LOG(tableCount <= MAX_KEY_INFO_COUNT, "DRM_KeysInfo has not enough space!");

        DRM_KeysInfo info;
        info.keysInfoCount = tableCount;
        uint32_t index = 0;
        for (auto &item : statusTable) {
            uint32_t keyIdSize = item.first.size();
            DRM_CHECK_AND_RETURN_LOG(keyIdSize <= MAX_KEY_ID_LEN, "DRM_KeysInfo keyId has not enough space!");
            errno_t ret = memset_s(info.keyId[index], MAX_KEY_ID_LEN, 0x00, MAX_KEY_ID_LEN);
            DRM_CHECK_AND_RETURN_LOG(ret == EOK, "memset_s keyId failed!");
            ret = memcpy_s(info.keyId[index], keyIdSize, item.first.data(), keyIdSize);
            DRM_CHECK_AND_RETURN_LOG(ret == EOK, "memcpy_s keyId failed!");

            std::string keyStatus = KeyStatusStringMap[item.second];
            uint32_t statusSize = keyStatus.size();
            DRM_CHECK_AND_RETURN_LOG(statusSize <= MAX_KEY_STATUS_VALUE_LEN,
                "DRM_KeysInfo statusValue has not enough space!");
            ret = memset_s(info.statusValue[index], MAX_KEY_STATUS_VALUE_LEN, 0x00, MAX_KEY_STATUS_VALUE_LEN);
            DRM_CHECK_AND_RETURN_LOG(ret == EOK, "memset_s statusValue failed!");
            ret = memcpy_s(info.statusValue[index], statusSize, keyStatus.data(), statusSize);
            DRM_CHECK_AND_RETURN_LOG(ret == EOK, "memcpy_s statusValue failed!");

            index++;
        }
        if (callback_.keyChangeCallback != nullptr) {
            callback_.keyChangeCallback(&info, hasNewGoodLicense);
        }
        if (sessionCallback_.keyChangeCallback != nullptr) {
            sessionCallback_.keyChangeCallback(session_, &info, hasNewGoodLicense);
        }
    }

private:
    struct MediaKeySession *session_ = nullptr;
    struct MediaKeySession_Callback callback_ = {};
    struct OH_MediaKeySession_Callback sessionCallback_ = {};
    std::mutex mutex_;
    std::unordered_map<std::string, DRM_EventType> eventMap_;
};
} // DrmStandard
} // OHOS

#endif // NATIVE_DRM_OBJECT_H

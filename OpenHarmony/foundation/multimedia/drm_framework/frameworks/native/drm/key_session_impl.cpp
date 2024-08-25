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

#include "key_session_impl.h"
#include "drm_log.h"
#include "drm_error_code.h"
#include "drm_trace.h"

namespace OHOS {
namespace DrmStandard {

MediaKeySessionImpl::MediaKeySessionImpl(sptr<IMediaKeySessionService> &keySession)
    : keySessionServiceCallback_(nullptr), keySessionServiceProxy_(keySession)
{
    DRM_DEBUG_LOG("MediaKeySessionImpl: 0x%{public}06" PRIXPTR "MediaKeySessionImpl Instances create",
        FAKE_POINTER(this));

    sptr<IRemoteObject> object = keySessionServiceProxy_->AsObject();
    pid_t pid = 0;
    deathRecipient_ = new(std::nothrow) DrmDeathRecipient(pid);
    DRM_CHECK_AND_RETURN_LOG(deathRecipient_ != nullptr, "failed to new DrmDeathRecipient.");

    deathRecipient_->SetNotifyCb(
        std::bind(&MediaKeySessionImpl::MediaKeySessionServerDied, this, std::placeholders::_1));
    bool result = object->AddDeathRecipient(deathRecipient_);
    if (!result) {
        DRM_ERR_LOG("failed to add deathRecipient");
        return;
    }

    CreateListenerObject();
}

int32_t MediaKeySessionImpl::CreateListenerObject()
{
    DRM_INFO_LOG("MediaKeySessionImpl::CreateListenerObject");
    listenerStub_ = new(std::nothrow) DrmListenerStub();
    DRM_CHECK_AND_RETURN_RET_LOG(listenerStub_ != nullptr, DRM_MEMORY_ERROR,
        "failed to new DrmListenerStub object");
    DRM_CHECK_AND_RETURN_RET_LOG(keySessionServiceProxy_ != nullptr, DRM_MEMORY_ERROR,
        "Drm service does not exist.");

    sptr<IRemoteObject> object = listenerStub_->AsObject();
    DRM_CHECK_AND_RETURN_RET_LOG(object != nullptr, DRM_MEMORY_ERROR, "listener object is nullptr.");

    return keySessionServiceProxy_->SetListenerObject(object);
}

MediaKeySessionImpl::~MediaKeySessionImpl()
{
    DRM_INFO_LOG("MediaKeySessionImpl::~MediaKeySessionImpl enter.");
    keySessionServiceProxy_ = nullptr;
    keySessionServiceCallback_ = nullptr;
    DRM_DEBUG_LOG("MediaKeySessionImpl: 0x%{public}06" PRIXPTR "MediaKeySessionImpl Instances release",
        FAKE_POINTER(this));
}

void MediaKeySessionImpl::MediaKeySessionServerDied(pid_t pid)
{
    DRM_ERR_LOG("MediaKeySession server has died, pid:%{public}d!", pid);

    if (keySessionServiceProxy_ != nullptr && keySessionServiceProxy_->AsObject() != nullptr) {
        (void)keySessionServiceProxy_->AsObject()->RemoveDeathRecipient(deathRecipient_);
        keySessionServiceProxy_ = nullptr;
    }
    listenerStub_ = nullptr;
    deathRecipient_ = nullptr;
}

int32_t MediaKeySessionImpl::Release()
{
    DRM_INFO_LOG("MediaKeySessionImpl Release enter.");
    int32_t errCode = DRM_UNKNOWN_ERROR;
    if (keySessionServiceProxy_) {
        errCode = keySessionServiceProxy_->Release();
        if (errCode != DRM_OK) {
            DRM_ERR_LOG("Failed to Release key session!, %{public}d", errCode);
        }
    } else {
        DRM_ERR_LOG("MediaKeySessionServiceProxy_ == nullptr");
    }
    keySessionServiceProxy_ = nullptr;
    keySessionServiceCallback_ = nullptr;
    DRM_INFO_LOG("MediaKeySessionImpl Release exit.");
    return errCode;
}

int32_t MediaKeySessionImpl::GenerateMediaKeyRequest(IMediaKeySessionService::MediaKeyRequestInfo &licenseRequestInfo,
    IMediaKeySessionService::MediaKeyRequest &licenseRequest)
{
    DrmTrace trace("MediaKeySessionImpl::GenerateMediaKeyRequest");
    DRM_INFO_LOG("MediaKeySessionImpl::GenerateMediaKeyRequest enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t retCode = DRM_OK;
    if (keySessionServiceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySessionImpl::GenerateMediaKeyRequest keySessionServiceProxy_ is null");
        return DRM_SERVICE_ERROR;
    }
    retCode = keySessionServiceProxy_->GenerateMediaKeyRequest(licenseRequestInfo, licenseRequest);
    if (retCode != DRM_OK) {
        DRM_ERR_LOG("MediaKeySessionImpl::GenerateMediaKeyRequest failed, retCode: %{public}d", retCode);
        return DRM_SERVICE_ERROR;
    }
    DRM_INFO_LOG("MediaKeySessionImpl::GenerateMediaKeyRequest exit");
    return DRM_OK;
}

int32_t MediaKeySessionImpl::ProcessMediaKeyResponse(std::vector<uint8_t> &licenseId,
    std::vector<uint8_t> &licenseResponse)
{
    DrmTrace trace("MediaKeySessionImpl::ProcessMediaKeyResponse");
    DRM_INFO_LOG("MediaKeySessionImpl::ProcessMediaKeyResponse enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t retCode = DRM_OK;

    if (keySessionServiceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySessionImpl::ProcessMediaKeyResponse keySessionServiceProxy_ is null");
        return DRM_SERVICE_ERROR;
    }
    retCode = keySessionServiceProxy_->ProcessMediaKeyResponse(licenseId, licenseResponse);
    if (retCode != DRM_OK) {
        DRM_ERR_LOG("MediaKeySessionImpl::ProcessMediaKeyResponse failed, retCode: %{public}d", retCode);
        return DRM_SERVICE_ERROR;
    }

    DRM_INFO_LOG("MediaKeySessionImpl::ProcessMediaKeyResponse exit");
    return DRM_OK;
}

int32_t MediaKeySessionImpl::GenerateOfflineReleaseRequest(std::vector<uint8_t> &licenseId,
    std::vector<uint8_t> &releaseRequest)
{
    DRM_INFO_LOG("MediaKeySessionImpl::GenerateOfflineReleaseRequest enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t retCode = DRM_OK;
    if (keySessionServiceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySessionImpl::GenerateOfflineReleaseRequest keySessionServiceProxy_ is null");
        return DRM_SERVICE_ERROR;
    }

    retCode = keySessionServiceProxy_->GenerateOfflineReleaseRequest(licenseId, releaseRequest);
    if (retCode != DRM_OK) {
        DRM_ERR_LOG("MediaKeySessionImpl::GenerateOfflineReleaseRequest failed, retCode: %{public}d", retCode);
        return DRM_SERVICE_ERROR;
    }

    DRM_INFO_LOG("MediaKeySessionImpl::GenerateOfflineReleaseRequest exit");
    return DRM_OK;
}

int32_t MediaKeySessionImpl::ProcessOfflineReleaseResponse(std::vector<uint8_t> &licenseId,
    std::vector<uint8_t> &releaseResponse)
{
    DRM_INFO_LOG("MediaKeySessionImpl::ProcessOfflineReleaseResponse enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t retCode = DRM_OK;

    if (keySessionServiceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySessionImpl::ProcessOfflineReleaseResponse keySessionServiceProxy_ is null");
        return DRM_SERVICE_ERROR;
    }
    retCode = keySessionServiceProxy_->ProcessOfflineReleaseResponse(licenseId, releaseResponse);
    if (retCode != DRM_OK) {
        DRM_ERR_LOG("MediaKeySessionImpl::ProcessOfflineReleaseResponse failed, retCode: %{public}d", retCode);
        return DRM_SERVICE_ERROR;
    }
    DRM_INFO_LOG("MediaKeySessionImpl::ProcessOfflineReleaseResponse exit");
    return DRM_OK;
}

int32_t MediaKeySessionImpl::GetContentProtectionLevel(IMediaKeySessionService::ContentProtectionLevel *securityLevel)
{
    DRM_INFO_LOG("MediaKeySessionImpl::GetContentProtectionLevel enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t retCode = DRM_OK;

    if (keySessionServiceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySessionImpl::GetContentProtectionLevel serviceProxy_ is null");
        return DRM_SERVICE_ERROR;
    }
    retCode = keySessionServiceProxy_->GetContentProtectionLevel(
        (IMediaKeySessionService::ContentProtectionLevel *)securityLevel);
    if (retCode != DRM_OK) {
        DRM_ERR_LOG("MediaKeySessionImpl::GetContentProtectionLevel failed, retCode: %{public}d", retCode);
        return DRM_SERVICE_ERROR;
    }
    DRM_INFO_LOG("MediaKeySessionImpl::GetContentProtectionLevel exit.");
    return DRM_OK;
}

int32_t MediaKeySessionImpl::CheckMediaKeyStatus(std::map<std::string, std::string> &licenseStatus)
{
    DRM_INFO_LOG("MediaKeySessionImpl::CheckMediaKeyStatus enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t retCode = DRM_OK;

    if (keySessionServiceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySessionImpl::CheckMediaKeyStatus keySessionServiceProxy_ is null");
        return DRM_SERVICE_ERROR;
    }
    retCode = keySessionServiceProxy_->CheckMediaKeyStatus(licenseStatus);
    if (retCode != DRM_OK) {
        DRM_ERR_LOG("MediaKeySessionImpl::CheckMediaKeyStatus failed, retCode: %{public}d", retCode);
        return DRM_SERVICE_ERROR;
    }
    DRM_INFO_LOG("MediaKeySessionImpl::CheckMediaKeyStatus exit");
    return DRM_OK;
}

int32_t MediaKeySessionImpl::RestoreOfflineMediaKeys(std::vector<uint8_t> &licenseId)
{
    DRM_ERR_LOG("MediaKeySessionImpl::RestoreOfflineMediaKeys enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t retCode = DRM_OK;

    if (keySessionServiceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySessionImpl::RestoreOfflineMediaKeys keySessionServiceProxy_ is null");
        return DRM_SERVICE_ERROR;
    }
    retCode = keySessionServiceProxy_->RestoreOfflineMediaKeys(licenseId);
    if (retCode != DRM_OK) {
        DRM_ERR_LOG("MediaKeySessionImpl::RestoreOfflineMediaKeys failed, retCode: %{public}d", retCode);
        return DRM_SERVICE_ERROR;
    }
    DRM_INFO_LOG("MediaKeySessionImpl::RestoreOfflineMediaKeys exit");
    return DRM_OK;
}

int32_t MediaKeySessionImpl::ClearMediaKeys()
{
    DRM_INFO_LOG("MediaKeySessionImpl::ClearMediaKeys enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t retCode = DRM_OK;

    if (keySessionServiceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySessionImpl::ClearMediaKeys keySessionServiceProxy_ is null");
        return DRM_SERVICE_ERROR;
    }
    retCode = keySessionServiceProxy_->ClearMediaKeys();
    if (retCode != DRM_OK) {
        DRM_ERR_LOG("MediaKeySessionImpl::ClearMediaKeys failed, retCode: %{public}d", retCode);
        return DRM_SERVICE_ERROR;
    }
    DRM_INFO_LOG("MediaKeySessionImpl::ClearMediaKeys exit");
    return DRM_OK;
}

int32_t MediaKeySessionImpl::RequireSecureDecoderModule(std::string &mimeType, bool *status)
{
    DRM_INFO_LOG("MediaKeySessionImpl::RequireSecureDecoderModule enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t retCode = DRM_OK;

    if (keySessionServiceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySessionImpl::RequireSecureDecoderModule keySessionServiceProxy_ is null");
        return DRM_SERVICE_ERROR;
    }
    retCode = keySessionServiceProxy_->RequireSecureDecoderModule(mimeType, status);
    if (retCode != DRM_OK) {
        DRM_ERR_LOG("status: %{public}d", *status);
        return retCode;
    }
    DRM_INFO_LOG("MediaKeySessionImpl::RequireSecureDecoderModule exit.");
    return DRM_OK;
}

sptr<IMediaKeySessionService> MediaKeySessionImpl::GetMediaKeySessionServiceProxy()
{
    DRM_INFO_LOG("MediaKeySessionImpl::GetMediaKeySessionServiceProxy enter.");
    if (keySessionServiceProxy_ != nullptr) {
        DRM_DEBUG_LOG("MediaKeySessionImpl MediaKeySessionServiceProxy is not nullptr");
    }
    DRM_INFO_LOG("MediaKeySessionImpl::GetMediaKeySessionServiceProxy exit.");
    return keySessionServiceProxy_;
}

sptr<MediaKeySessionImplCallback> MediaKeySessionImpl::GetApplicationCallback()
{
    DRM_INFO_LOG("MediaKeySessionImpl::GetApplicationCallback enter.");
    return keySessionApplicationCallback_;
}

int32_t MediaKeySessionImpl::SetCallback(const sptr<MediaKeySessionImplCallback> &callback)
{
    DRM_DEBUG_LOG("MediaKeySessionImpl:0x%{public}06" PRIXPTR " SetCallback in", FAKE_POINTER(this));
    DRM_CHECK_AND_RETURN_RET_LOG(callback != nullptr, DRM_INVALID_ARG, "callback is nullptr");
    keySessionApplicationCallback_ = callback;

    int32_t errCode = DRM_ERROR;
    keySessionServiceCallback_ = new (std::nothrow) MediaKeySessionServiceCallback(this);
    if (keySessionServiceCallback_ == nullptr) {
        DRM_ERR_LOG("MediaKeySessionImpl:: MediaKeySessionServiceCallback alloc failed.");
        return errCode;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (keySessionServiceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySessionImpl::SetCallback keySessionServiceProxy_ is null");
        return DRM_SERVICE_ERROR;
    }
    errCode = keySessionServiceProxy_->SetCallback(keySessionServiceCallback_);
    if (errCode != DRM_OK) {
        DRM_ERR_LOG("MediaKeySessionImpl::SetCallback failed, retCode: %{public}d", errCode);
        return DRM_SERVICE_ERROR;
    }
    DRM_INFO_LOG("MediaKeySessionImpl::SetCallback exit.");
    return errCode;
}

void MediaKeySessionServiceCallback::InitEventMap()
{
    DRM_INFO_LOG("KeySessionImpl::InitEventMap");
    eventMap_[static_cast<int32_t>(DRM_EVENT_KEY_NEEDED)] = MediaKeySessionEvent::EVENT_STR_KEY_NEEDED;
    eventMap_[static_cast<int32_t>(DRM_EVENT_KEY_EXPIRED)] = MediaKeySessionEvent::EVENT_STR_KEY_EXPIRED;
    eventMap_[static_cast<int32_t>(DRM_EVENT_EXPIRATION_UPDATED)] = MediaKeySessionEvent::EVENT_STR_EXPIRATION_UPDATED;
    eventMap_[static_cast<int32_t>(DRM_EVENT_KEY_CHANGED)] = MediaKeySessionEvent::EVENT_STR_KEY_CHANGED;
    eventMap_[static_cast<int32_t>(DRM_EVENT_VENDOR_DEFINED)] = MediaKeySessionEvent::EVENT_STR_VENDOR_DEFINED;
}

std::string MediaKeySessionServiceCallback::GetEventName(DrmEventType event)
{
    DRM_INFO_LOG("MediaKeySessionServiceCallback::GetEventName");
    std::string eventName = "";
    int32_t eventType = static_cast<int32_t>(event);
    if (eventMap_.find(eventType) == eventMap_.end()) {
        return eventName;
    }
    return eventMap_[eventType];
}

int32_t MediaKeySessionServiceCallback::SendEvent(DrmEventType event, int32_t extra, const std::vector<uint8_t> data)
{
    DRM_INFO_LOG("MediaKeySessionServiceCallback SendEvent");
    std::string eventName = GetEventName(event);
    if (keySessionImpl_ != nullptr && eventName.length() != 0) {
        sptr<MediaKeySessionImplCallback> applicationCallback = keySessionImpl_->GetApplicationCallback();
        if (applicationCallback != nullptr) {
            applicationCallback->SendEvent(eventName, extra, data);
            return DRM_OK;
        }
    }
    DRM_ERR_LOG("MediaKeySessionServiceCallback:: SendEvent failed.");
    return DRM_ERROR;
}

int32_t MediaKeySessionServiceCallback::SendEventKeyChanged(
    std::map<std::vector<uint8_t>, MediaKeySessionKeyStatus> statusTable, bool hasNewGoodLicense)
{
    DRM_INFO_LOG("MediaKeySessionServiceCallback::SendEventKeyChanged enter.");
    if (keySessionImpl_ != nullptr) {
        sptr<MediaKeySessionImplCallback> callback = keySessionImpl_->GetApplicationCallback();
        if (callback != nullptr) {
            callback->SendEventKeyChanged(statusTable, hasNewGoodLicense);
            return DRM_OK;
        }
    }
    DRM_ERR_LOG("MediaKeySessionServiceCallback:: SendEventKeyChanged failed.");
    return DRM_ERROR;
}
} // DrmStandard
} // OHOS
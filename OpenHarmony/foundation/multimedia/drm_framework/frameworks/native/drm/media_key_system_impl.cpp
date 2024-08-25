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

#include "media_key_system_impl.h"
#include "i_mediakeysystem_service.h"
#include "drm_error_code.h"
#include "drm_trace.h"
#include "napi_param_utils.h"

namespace OHOS {
namespace DrmStandard {
MediaKeySystemImpl::MediaKeySystemImpl(sptr<IMediaKeySystemService> &mediaKeysystem) : serviceProxy_(mediaKeysystem)
{
    DRM_DEBUG_LOG("MediaKeySystemImpl:0x %{public}06" PRIXPTR "MediaKeySystemImpl Instances create",
        FAKE_POINTER(this));

    sptr<IRemoteObject> object = serviceProxy_->AsObject();
    pid_t pid = 0;
    deathRecipient_ = new(std::nothrow) DrmDeathRecipient(pid);
    DRM_CHECK_AND_RETURN_LOG(deathRecipient_ != nullptr, "failed to new DrmDeathRecipient.");

    deathRecipient_->SetNotifyCb(
        std::bind(&MediaKeySystemImpl::MediaKeySystemServerDied, this, std::placeholders::_1));
    bool result = object->AddDeathRecipient(deathRecipient_);
    if (!result) {
        DRM_ERR_LOG("failed to add deathRecipient");
        return;
    }

    CreateListenerObject();
}

MediaKeySystemImpl::~MediaKeySystemImpl()
{
    serviceProxy_ = nullptr;
}

void MediaKeySystemImpl::MediaKeySystemServerDied(pid_t pid)
{
    DRM_ERR_LOG("MediaKeySystem server has died, pid:%{public}d!", pid);

    if (serviceProxy_ != nullptr && serviceProxy_->AsObject() != nullptr) {
        (void)serviceProxy_->AsObject()->RemoveDeathRecipient(deathRecipient_);
        serviceProxy_ = nullptr;
    }
    listenerStub_ = nullptr;
    deathRecipient_ = nullptr;
}

int32_t MediaKeySystemImpl::CreateListenerObject()
{
    DRM_INFO_LOG("MediaKeySystemImpl::CreateListenerObject");
    listenerStub_ = new(std::nothrow) DrmListenerStub();
    DRM_CHECK_AND_RETURN_RET_LOG(listenerStub_ != nullptr, DRM_MEMORY_ERROR,
        "failed to new DrmListenerStub object");
    DRM_CHECK_AND_RETURN_RET_LOG(serviceProxy_ != nullptr, DRM_MEMORY_ERROR,
        "Drm service does not exist.");

    sptr<IRemoteObject> object = listenerStub_->AsObject();
    DRM_CHECK_AND_RETURN_RET_LOG(object != nullptr, DRM_MEMORY_ERROR, "listener object is nullptr.");

    return serviceProxy_->SetListenerObject(object);
}

int32_t MediaKeySystemImpl::Release()
{
    DRM_INFO_LOG("MediaKeySystemImpl::Release enter.");
    int32_t errCode = DRM_UNKNOWN_ERROR;
    if (serviceProxy_ != nullptr) {
        errCode = serviceProxy_->Release();
        if (errCode != DRM_OK) {
            DRM_ERR_LOG("Failed to Release keySystem!, %{public}d", errCode);
            return errCode;
        }
        serviceProxy_ = nullptr;
    } else {
        DRM_ERR_LOG("serviceProxy_ is nullptr");
        return errCode;
    }
    DRM_INFO_LOG("MediaKeySystemImpl::Release exit.");
    return DRM_OK;
}

int32_t MediaKeySystemImpl::GenerateKeySystemRequest(std::vector<uint8_t> &request, std::string &defaultUrl)
{
    DrmTrace trace("MediaKeySystemImpl::GenerateKeySystemRequest");
    DRM_INFO_LOG("MediaKeySystemImpl::GenerateKeySystemRequest enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t ret = DRM_OK;

    if (serviceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySystemImpl::GenerateKeySystemRequest serviceProxy_ is null");
        return DRM_SERVICE_ERROR;
    }
    ret = serviceProxy_->GenerateKeySystemRequest(request, defaultUrl);
    if (ret != DRM_OK) {
        DRM_ERR_LOG("MediaKeySystemImpl::GenerateKeySystemRequest failed, ret: %{public}d", ret);
        return DRM_SERVICE_ERROR;
    }
    DRM_INFO_LOG("MediaKeySystemImpl::GenerateKeySystemRequest exit.");
    return DRM_OK;
}

int32_t MediaKeySystemImpl::ProcessKeySystemResponse(const std::vector<uint8_t> &response)
{
    DrmTrace trace("MediaKeySystemImpl::ProcessKeySystemResponse");
    DRM_INFO_LOG("MediaKeySystemImpl::ProcessKeySystemResponse enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t ret = DRM_OK;

    if (serviceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySystemImpl::ProcessKeySystemResponse serviceProxy_ is null");
        return DRM_SERVICE_ERROR;
    }
    ret = serviceProxy_->ProcessKeySystemResponse(response);
    if (ret != DRM_OK) {
        DRM_ERR_LOG("MediaKeySystemImpl::ProcessKeySystemResponse failed, ret: %{public}d", ret);
        return DRM_SERVICE_ERROR;
    }
    DRM_INFO_LOG("MediaKeySystemImpl::ProcessKeySystemResponse exit.");
    return DRM_OK;
}

int32_t MediaKeySystemImpl::SetConfigurationString(std::string &configName, std::string &value)
{
    DRM_INFO_LOG("MediaKeySystemImpl::SetConfiguration enter, configName:%{public}s, value:%{public}s.",
        configName.c_str(), value.c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t ret = DRM_OK;

    if (serviceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySystemImpl::SetConfiguration serviceProxy_ is null");
        return DRM_SERVICE_ERROR;
    }
    ret = serviceProxy_->SetConfigurationString(configName, value);
    if (ret != DRM_OK) {
        DRM_ERR_LOG("MediaKeySystemImpl::SetConfiguration failed, ret: %{public}d", ret);
        return DRM_SERVICE_ERROR;
    }
    DRM_INFO_LOG("MediaKeySystemImpl::SetConfiguration exit.");
    return DRM_OK;
}

int32_t MediaKeySystemImpl::GetConfigurationString(std::string &configName, std::string &value)
{
    DRM_INFO_LOG("MediaKeySystemImpl::GetConfiguration enter, configName:%{public}s.", configName.c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t ret = DRM_OK;

    if (serviceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySystemImpl::GetConfiguration serviceProxy_ is null");
        return DRM_SERVICE_ERROR;
    }
    ret = serviceProxy_->GetConfigurationString(configName, value);
    if (ret != DRM_OK) {
        DRM_ERR_LOG("MediaKeySystemImpl::GetConfiguration failed, ret: %{public}d", ret);
        return DRM_SERVICE_ERROR;
    }

    DRM_INFO_LOG("MediaKeySystemImpl::GetConfiguration exit, value:%{public}s.", value.c_str());
    return DRM_OK;
}

int32_t MediaKeySystemImpl::SetConfigurationByteArray(std::string &configName, std::vector<uint8_t> &value)
{
    DRM_INFO_LOG("MediaKeySystemImpl::SetConfiguration enter, configName:%{public}s.", configName.c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t ret = DRM_OK;

    if (serviceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySystemImpl::SetConfiguration serviceProxy_ is null");
        return DRM_SERVICE_ERROR;
    }
    ret = serviceProxy_->SetConfigurationByteArray(configName, value);
    if (ret != DRM_OK) {
        DRM_ERR_LOG("MediaKeySystemImpl::SetConfiguration failed, ret: %{public}d", ret);
        return DRM_SERVICE_ERROR;
    }
    DRM_INFO_LOG("MediaKeySystemImpl::SetConfiguration exit.");
    return DRM_OK;
}

int32_t MediaKeySystemImpl::GetConfigurationByteArray(std::string &configName, std::vector<uint8_t> &value)
{
    DRM_INFO_LOG("MediaKeySystemImpl::GetConfiguration enter, configName:%{public}s.", configName.c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t ret = DRM_OK;

    if (serviceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySystemImpl::GetConfiguration serviceProxy_ is null");
        return DRM_SERVICE_ERROR;
    }
    ret = serviceProxy_->GetConfigurationByteArray(configName, value);
    if (ret != DRM_OK) {
        DRM_ERR_LOG("MediaKeySystemImpl::GetConfiguration failed, ret: %{public}d", ret);
        return DRM_SERVICE_ERROR;
    }

    return DRM_OK;
}

int32_t MediaKeySystemImpl::CreateMediaKeySession(IMediaKeySessionService::ContentProtectionLevel securityLevel,
    sptr<MediaKeySessionImpl> *keySessionImpl)
{
    DrmTrace trace("MediaKeySystemImpl::CreateMediaKeySession");
    DRM_INFO_LOG("MediaKeySystemImpl::CreateMediaKeySession enter.");
    sptr<IMediaKeySessionService> keySessionProxy = nullptr;
    sptr<MediaKeySessionImpl> localMediaKeySessionImpl = nullptr;
    int32_t ret = DRM_OK;
    /* To determine if any members in the keySession list have been destroyed,
    *  the keySessionNumber needs to be reduced by one
    */
    for (size_t i = 0; i < keySessionVec.size(); i++) {
        /* In the case of initial and complete destruction,
		*  all members of the keySession list are null pointers
		*/
        if (keySessionNumber > 0 && keySessionVec[i]->GetMediaKeySessionServiceProxy() == nullptr) {
            keySessionNumber--;
            keySessionVec.erase(keySessionVec.begin() + i);
        }
    }
    if (serviceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySystemImpl:: serviceProxy_ == nullptr");
        return DRM_SERVICE_FATAL_ERROR;
    }

    ret = serviceProxy_->CreateMediaKeySession(securityLevel, keySessionProxy);
    if (ret == DRM_OK) {
        if (keySessionProxy != nullptr) {
            localMediaKeySessionImpl = new (std::nothrow) MediaKeySessionImpl(keySessionProxy);
            if (localMediaKeySessionImpl == nullptr) {
                DRM_ERR_LOG("Failed to new MediaKeySessionImpl");
                return DRM_SERVICE_FATAL_ERROR;
            }
            if (keySessionNumber >= KEY_SESSION_MAX_NUMBER) {
                DRM_ERR_LOG("The number of MediaKeySession is greater than 64");
                return DRM_MAX_SESSION_NUM_REACHED;
            }
            keySessionNumber++;
        } else {
            DRM_ERR_LOG("Failed to CreateMediaKeySessionImpl with session is null");
            return DRM_UNKNOWN_ERROR;
        }
    } else {
        DRM_ERR_LOG("Failed to get session object from mediakeysystem service!, %{public}d", ret);
        return DRM_SERVICE_FATAL_ERROR;
    }
    *keySessionImpl = localMediaKeySessionImpl;
    keySessionVec.push_back(localMediaKeySessionImpl);
    DRM_INFO_LOG("MediaKeySystemImpl::CreateMediaKeySession exit.");
    return DRM_OK;
}

int32_t MediaKeySystemImpl::GetStatistics(std::vector<IMediaKeySystemService::MetircKeyValue> &metrics)
{
    DRM_INFO_LOG("MediaKeySystemImpl::GetStatistics enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t ret = DRM_OK;

    if (serviceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySystemImpl::GetStatistics serviceProxy_ is null");
        return DRM_SERVICE_ERROR;
    }
    ret = serviceProxy_->GetStatistics(metrics);
    if (ret != DRM_OK) {
        DRM_ERR_LOG("MediaKeySystemImpl::GetStatistics failed, ret: %{public}d", ret);
        return DRM_SERVICE_ERROR;
    }
    DRM_INFO_LOG("MediaKeySystemImpl::GetStatistics exit.");
    return DRM_OK;
}

int32_t MediaKeySystemImpl::GetMaxContentProtectionLevel(IMediaKeySessionService::ContentProtectionLevel *securityLevel)
{
    DRM_INFO_LOG("MediaKeySystemImpl::GetMaxContentProtectionLevel enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t ret = DRM_OK;

    if (serviceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySystemImpl::GetMaxContentProtectionLevel serviceProxy_ is null");
        return DRM_SERVICE_ERROR;
    }
    ret =
        serviceProxy_->GetMaxContentProtectionLevel((IMediaKeySessionService::ContentProtectionLevel *)securityLevel);
    DRM_ERR_LOG("MediaKeySystemImpl::GetMaxContentProtectionLevel 277");
    if (ret != DRM_OK) {
        DRM_ERR_LOG("MediaKeySystemImpl::GetMaxContentProtectionLevel failed, ret: %{public}d", ret);
        return DRM_SERVICE_ERROR;
    }
    DRM_INFO_LOG("MediaKeySystemImpl::GetMaxContentProtectionLevel exit.");
    return DRM_OK;
}

int32_t MediaKeySystemImpl::GetOfflineMediaKeyIds(std::vector<std::vector<uint8_t>> &licenseIds)
{
    DRM_INFO_LOG("MediaKeySystemImpl::GetOfflineMediaKeyIds enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t ret = DRM_OK;

    if (serviceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySystemImpl::GetOfflineMediaKeyIds serviceProxy_ is null");
        return DRM_SERVICE_ERROR;
    }
    ret = serviceProxy_->GetOfflineMediaKeyIds(licenseIds);
    if (ret != DRM_OK) {
        DRM_ERR_LOG("MediaKeySystemImpl::GetOfflineMediaKeyIds failed, ret: %{public}d", ret);
        return DRM_SERVICE_ERROR;
    }
    DRM_INFO_LOG("MediaKeySystemImpl::GetOfflineMediaKeyIds exit");
    return DRM_OK;
}

int32_t MediaKeySystemImpl::GetOfflineMediaKeyStatus(std::vector<uint8_t> &licenseId,
    IMediaKeySessionService::OfflineMediaKeyStatus &status)
{
    DRM_INFO_LOG("MediaKeySystemImpl::GetOfflineMediaKeyStatus enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t ret = DRM_OK;

    if (serviceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySystemImpl::GetOfflineMediaKeyStatus serviceProxy_ is null");
        return DRM_SERVICE_ERROR;
    }
    ret = serviceProxy_->GetOfflineMediaKeyStatus(licenseId, status);
    if (ret != DRM_OK) {
        DRM_ERR_LOG("MediaKeySystemImpl::GetOfflineMediaKeyStatus failed, ret: %{public}d", ret);
        return DRM_SERVICE_ERROR;
    }
    DRM_INFO_LOG("MediaKeySystemImpl::GetOfflineMediaKeyStatus exit.");
    return DRM_OK;
}

int32_t MediaKeySystemImpl::ClearOfflineMediaKeys(std::vector<uint8_t> &licenseId)
{
    DRM_INFO_LOG("MediaKeySystemImpl::ClearOfflineMediaKeys enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t ret = DRM_OK;
    if (serviceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySystemImpl::ClearOfflineMediaKeys serviceProxy_ is null");
        return DRM_SERVICE_ERROR;
    }
    ret = serviceProxy_->ClearOfflineMediaKeys(licenseId);
    if (ret != DRM_OK) {
        DRM_ERR_LOG("MediaKeySystemImpl::ClearOfflineMediaKeys failed, ret: %{public}d", ret);
        return DRM_SERVICE_ERROR;
    }
    DRM_INFO_LOG("MediaKeySystemImpl::ClearOfflineMediaKeys exit");
    return DRM_OK;
}

int32_t MediaKeySystemImpl::GetCertificateStatus(IMediaKeySystemService::CertificateStatus *certStatus)
{
    DRM_INFO_LOG("MediaKeySystemImpl::GetCertificateStatus enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t ret = DRM_OK;

    if (serviceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySystemImpl::GetCertificateStatus serviceProxy_ is null");
        return DRM_SERVICE_ERROR;
    }
    ret = serviceProxy_->GetCertificateStatus((IMediaKeySystemService::CertificateStatus *)certStatus);
    DRM_ERR_LOG("MediaKeySystemImpl::GetCertificateStatus 277");
    if (ret != DRM_OK) {
        DRM_ERR_LOG("MediaKeySystemImpl::GetCertificateStatus failed, ret: %{public}d", ret);
        return DRM_SERVICE_ERROR;
    }
    DRM_INFO_LOG("MediaKeySystemImpl::GetCertificateStatus exit.");
    return DRM_OK;
}

int32_t MediaKeySystemImpl::SetCallback(const sptr<MediaKeySystemImplCallback> &callback)
{
    DRM_DEBUG_LOG("MediaKeySystemImpl:0x%{public}06" PRIXPTR " SetCallback in", FAKE_POINTER(this));
    DRM_CHECK_AND_RETURN_RET_LOG(callback != nullptr, DRM_INVALID_ARG, "callback is nullptr");
    mediaKeySystemApplicationCallback_ = callback;

    int32_t ret = DRM_ERROR;
    serviceCallback_ = new (std::nothrow) MediaKeySystemCallback(this);
    if (serviceCallback_ == nullptr) {
        DRM_ERR_LOG("MediaKeySystemImpl:: MediaKeySystemCallback alloc failed.");
        return ret;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (serviceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySystemImpl::SetCallback serviceProxy_ is null");
        return DRM_SERVICE_ERROR;
    }
    ret = serviceProxy_->SetCallback(serviceCallback_);
    if (ret != DRM_OK) {
        DRM_ERR_LOG("MediaKeySystemImpl::SetCallback failed, ret: %{public}d", ret);
        return DRM_SERVICE_ERROR;
    }
    DRM_INFO_LOG("MediaKeySystemImpl::SetCallback exit.");
    return ret;
}

sptr<MediaKeySystemImplCallback> MediaKeySystemImpl::GetApplicationCallback()
{
    DRM_INFO_LOG("MediaKeySystemImpl GetApplicationCallback");
    return mediaKeySystemApplicationCallback_;
}

MediaKeySystemCallback::~MediaKeySystemCallback()
{
    DRM_INFO_LOG("MediaKeySystemCallback ~MediaKeySystemCallback");
    systemImpl_ = nullptr;
}

void MediaKeySystemCallback::InitEventMap()
{
    DRM_INFO_LOG("MediaKeySystemCallback InitEventMap");
    eventMap_[static_cast<int32_t>(DRM_EVENT_PROVISION_REQUIRED)] = MediaKeySystemEvent::EVENT_STR_PROVISION_REQUIRED;
}

std::string MediaKeySystemCallback::GetEventName(DrmEventType event)
{
    DRM_INFO_LOG("MediaKeySystemCallback GetEventName");
    std::string eventName = "";
    int32_t eventType = static_cast<int32_t>(event);
    if (eventMap_.find(eventType) == eventMap_.end()) {
        return eventName;
    }
    return eventMap_[eventType];
}

int32_t MediaKeySystemCallback::SendEvent(DrmEventType event, int32_t extra, const std::vector<uint8_t> data)
{
    DRM_INFO_LOG("MediaKeySystemCallback SendEvent");
    std::string eventName = GetEventName(event);
    if (systemImpl_ != nullptr && eventName.length() != 0) {
        sptr<MediaKeySystemImplCallback> applicationCallback = systemImpl_->GetApplicationCallback();
        if (applicationCallback != nullptr) {
            applicationCallback->SendEvent(eventName, extra, data);
            return DRM_OK;
        }
    }
    DRM_ERR_LOG("MediaKeySystemCallback:: SendEvent failed.");
    return DRM_ERROR;
}
} // namespace DrmStandard
} // namespace OHOS
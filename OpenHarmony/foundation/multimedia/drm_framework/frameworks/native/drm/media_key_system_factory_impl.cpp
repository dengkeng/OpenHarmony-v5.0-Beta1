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

#include "media_key_system_factory_impl.h"
#include "i_mediakeysystem_service.h"
#include "drm_error_code.h"
#include "napi_param_utils.h"

namespace OHOS {
namespace DrmStandard {
using namespace OHOS::HiviewDFX;
sptr<MediaKeySystemFactoryImpl> MediaKeySystemFactoryImpl::mediaKeySystemFactoryImpl_;
MediaKeySystemFactoryImpl::MediaKeySystemFactoryImpl()
{
    DRM_DEBUG_LOG("MediaKeySystemFactoryImpl:0x%{public}06" PRIXPTR "MediaKeySystemFactoryImpl Instances create",
        FAKE_POINTER(this));
    #ifdef ENABLE_DRM_SYSEVENT_CONTROL
    traceId_ = HiTraceChain::Begin("MediaKeySystemFactory", HITRACE_FLAG_DEFAULT);
    #endif
    Init();
}

MediaKeySystemFactoryImpl::~MediaKeySystemFactoryImpl()
{
    DRM_INFO_LOG("MediaKeySystemFactoryImpl::~MediaKeySystemFactoryImpl enter.");
    #ifdef ENABLE_DRM_SYSEVENT_CONTROL
    HiTraceChain::End(traceId_);
    #endif
    serviceProxy_ = nullptr;
    DRM_INFO_LOG("MediaKeySystemFactoryImpl::~MediaKeySystemFactoryImpl exit.");
    deathRecipient_ = nullptr;
}

sptr<MediaKeySystemFactoryImpl> &MediaKeySystemFactoryImpl::GetInstance()
{
    DRM_INFO_LOG("MediaKeySystemFactoryImpl::GetInstance enter.");
    if (MediaKeySystemFactoryImpl::mediaKeySystemFactoryImpl_ == nullptr) {
        DRM_DEBUG_LOG("Initializing MediaKeySystemFactoryImpl for first time!");
        MediaKeySystemFactoryImpl::mediaKeySystemFactoryImpl_ = new (std::nothrow) MediaKeySystemFactoryImpl();
        if (MediaKeySystemFactoryImpl::mediaKeySystemFactoryImpl_ == nullptr) {
            DRM_ERR_LOG("MediaKeySystemFactoryImpl::GetInstance failed to new MediaKeySystemFactoryImpl");
        }
    }
    DRM_INFO_LOG("MediaKeySystemFactoryImpl::GetInstance exit.");
    return MediaKeySystemFactoryImpl::mediaKeySystemFactoryImpl_;
}

int32_t MediaKeySystemFactoryImpl::CreateListenerObject()
{
    DRM_INFO_LOG("MediaKeySystemFactoryImpl::CreateListenerObject");
    listenerStub_ = new(std::nothrow) DrmListenerStub();
    DRM_CHECK_AND_RETURN_RET_LOG(listenerStub_ != nullptr, DRM_MEMORY_ERROR,
        "failed to new DrmListenerStub object");
    DRM_CHECK_AND_RETURN_RET_LOG(serviceProxy_ != nullptr, DRM_MEMORY_ERROR,
        "Drm service does not exist.");

    sptr<IRemoteObject> object = listenerStub_->AsObject();
    DRM_CHECK_AND_RETURN_RET_LOG(object != nullptr, DRM_MEMORY_ERROR, "listener object is nullptr.");

    return serviceProxy_->SetListenerObject(object);
}

void MediaKeySystemFactoryImpl::Init()
{
    DRM_INFO_LOG("MediaKeySystemFactoryImpl::Init enter.");
    sptr<IRemoteObject> object = nullptr;

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        DRM_ERR_LOG("Failed to get System ability manager");
        return;
    }
    object = samgr->GetSystemAbility(MEDIA_KEY_SYSTEM_SERVICE_ID);
    if (object == nullptr) {
        DRM_ERR_LOG("MediaKeySystemFactoryImpl::GetSystemAbility() is failed.");
        return;
    }
    serviceProxy_ = iface_cast<IMediaKeySystemFactoryService>(object);
    if (serviceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySystemFactoryImpl::init serviceProxy_ is null.");
        return;
    }
    pid_t pid = 0;
    deathRecipient_ = new (std::nothrow) DrmDeathRecipient(pid);
    DRM_CHECK_AND_RETURN_LOG(deathRecipient_ != nullptr, "failed to new DrmDeathRecipient!");
    deathRecipient_->SetNotifyCb(
        std::bind(&MediaKeySystemFactoryImpl::MediaKeySystemFactoryServerDied, this, std::placeholders::_1));
    bool result = object->AddDeathRecipient(deathRecipient_);
    if (!result) {
        DRM_ERR_LOG("failed to add deathRecipient");
    }
    #ifdef ENABLE_DRM_SYSEVENT_CONTROL
    HiTraceChain::SetId(traceId_);
    #endif
    CreateListenerObject();
    DRM_INFO_LOG("MediaKeySystemFactoryImpl::Init exit.");
}

void MediaKeySystemFactoryImpl::MediaKeySystemFactoryServerDied(pid_t pid)
{
    DRM_ERR_LOG("MediaKeySystemFactoryServerDied has died, pid:%{public}d!", pid);
    if (serviceProxy_ != nullptr && serviceProxy_->AsObject() != nullptr) {
        (void)serviceProxy_->AsObject()->RemoveDeathRecipient(deathRecipient_);
        serviceProxy_ = nullptr;
    }
    listenerStub_ = nullptr;
    deathRecipient_ = nullptr;
}

bool MediaKeySystemFactoryImpl::IsMediaKeySystemSupported(std::string &uuid)
{
    DRM_INFO_LOG("MediaKeySystemFactoryImpl::IsMediaKeySystemSupported enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t ret = DRM_OK;
    bool isSurpported = false;
    if (serviceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySystemFactoryImpl::IsMediaKeySystemSupported serviceProxy_ is null");
        return isSurpported;
    }
    ret = serviceProxy_->IsMediaKeySystemSupported(uuid, &isSurpported);
    if (ret != DRM_OK) {
        DRM_ERR_LOG("MediaKeySystemFactoryImpl::IsMediaKeySystemSupported failed, ret: %{public}d", ret);
    }
    DRM_INFO_LOG("MediaKeySystemFactoryImpl::IsMediaKeySystemSupported exit.");

    return isSurpported;
}

bool MediaKeySystemFactoryImpl::IsMediaKeySystemSupported(std::string &uuid, std::string &mimeType)
{
    DRM_INFO_LOG("MediaKeySystemFactoryImpl::IsMediaKeySystemSupported enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t ret = DRM_OK;
    bool isSurpported = false;

    if (serviceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySystemFactoryImpl::IsMediaKeySystemSupported serviceProxy_ is null");
        return isSurpported;
    }
    ret = serviceProxy_->IsMediaKeySystemSupported(uuid, mimeType, &isSurpported);
    if (ret != DRM_OK) {
        DRM_ERR_LOG("MediaKeySystemFactoryImpl::IsMediaKeySystemSupported failed, ret: %{public}d", ret);
    }
    DRM_INFO_LOG("MediaKeySystemFactoryImpl::IsMediaKeySystemSupported exit.");

    return isSurpported;
}

bool MediaKeySystemFactoryImpl::IsMediaKeySystemSupported(std::string &uuid, std::string &mimeType,
    IMediaKeySessionService::ContentProtectionLevel securityLevel)
{
    DRM_INFO_LOG("MediaKeySystemFactoryImpl::IsMediaKeySystemSupported enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t ret = DRM_OK;
    bool isSurpported = false;

    if (serviceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySystemFactoryImpl::IsMediaKeySystemSupported serviceProxy_ is null");
        return isSurpported;
    }
    ret = serviceProxy_->IsMediaKeySystemSupported(uuid, mimeType, securityLevel, &isSurpported);
    if (ret != DRM_OK) {
        DRM_ERR_LOG("MediaKeySystemFactoryImpl::IsMediaKeySystemSupported failed, ret: %{public}d", ret);
    }
    DRM_INFO_LOG("MediaKeySystemFactoryImpl::IsMediaKeySystemSupported exit.");

    return isSurpported;
}

int32_t MediaKeySystemFactoryImpl::GetMediaKeySystemName(std::map<std::string, std::string> &keySystemNames)
{
    DRM_INFO_LOG("MediaKeySystemFactoryImpl::GetMediaKeySystemName enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t ret = DRM_OK;
    if (serviceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySystemFactoryImpl::GetMediaKeySystemName serviceProxy_ is null");
        return DRM_SERVICE_ERROR;
    }
    ret = serviceProxy_->GetMediaKeySystemName(keySystemNames);
    if (ret != DRM_OK) {
        DRM_ERR_LOG("MediaKeySystemFactoryImpl::GetMediaKeySystemName failed, ret: %{public}d", ret);
        return ret;
    }
    DRM_INFO_LOG("MediaKeySystemFactoryImpl::GetMediaKeySystemName exit.");
    return DRM_OK;
}

int32_t MediaKeySystemFactoryImpl::GetMediaKeySystemUuid(std::string &name, std::string &uuid)
{
    DRM_INFO_LOG("MediaKeySystemFactoryImpl::GetMediaKeySystemUuid enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t ret = DRM_OK;
    if (serviceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySystemFactoryImpl::GetMediaKeySystemUuid serviceProxy_ is null");
        return DRM_SERVICE_ERROR;
    }
    ret = serviceProxy_->GetMediaKeySystemUuid(name, uuid);
    if (ret != DRM_OK) {
        DRM_ERR_LOG("MediaKeySystemFactoryImpl::GetMediaKeySystemUuid failed, ret: %{public}d", ret);
        return ret;
    }
    DRM_INFO_LOG("MediaKeySystemFactoryImpl::GetMediaKeySystemUuid exit.");
    return DRM_OK;
}
int32_t MediaKeySystemFactoryImpl::CreateMediaKeySystem(std::string &uuid, sptr<MediaKeySystemImpl> *mediaKeySystemImpl)
{
    DRM_INFO_LOG("MediaKeySystemFactoryImpl:: CreateMediaKeySystem enter.");
    sptr<IMediaKeySystemService> mediaKeySystemProxy = nullptr;
    sptr<MediaKeySystemImpl> localMediaKeySystemImpl = nullptr;
    int32_t ret = DRM_OK;
    if (mediaKeySystemImpl == nullptr) {
        DRM_ERR_LOG("MediaKeySystemImpl:: mediaKeySystemImpl is nullptr");
        return DRM_INVALID_PARAM;
    }
    if (serviceProxy_ == nullptr) {
        DRM_ERR_LOG("MediaKeySystemFactoryImpl:: serviceProxy_ == nullptr");
        return DRM_SERVICE_FATAL_ERROR;
    }

    ret = serviceProxy_->CreateMediaKeySystem(uuid, mediaKeySystemProxy);
    if (ret == DRM_OK) {
        if (mediaKeySystemProxy != nullptr) {
            localMediaKeySystemImpl = new (std::nothrow) MediaKeySystemImpl(mediaKeySystemProxy);
            if (localMediaKeySystemImpl == nullptr) {
                DRM_ERR_LOG("Failed to new MediaKeySystemImpl");
                return DRM_SERVICE_FATAL_ERROR;
            }
            keySystemNumber++;
            if (keySystemNumber > KEY_SYSTEM_MAX_NUMBER) {
                keySystemNumber--;
                DRM_ERR_LOG("The number of MediaKeySystem is greater than 64");
                return DRM_MAX_SYSTEM_NUM_REACHED;
            }
        } else {
            DRM_ERR_LOG("mediaKeySystemProxy is nullptr");
            return DRM_UNKNOWN_ERROR;
        }
    } else {
        DRM_ERR_LOG("Failed to get session object from mediakeysystem service!, %{public}d", ret);
        return DRM_SERVICE_FATAL_ERROR;
    }
    *mediaKeySystemImpl = localMediaKeySystemImpl;
    DRM_DEBUG_LOG("current keySystemNumber: %{public}d.", keySystemNumber);
    DRM_INFO_LOG("MediaKeySystemFactoryImpl:: CreateMediaKeySystem exit.");
    return DRM_OK;
}
} // namespace DrmStandard
} // namespace OHOS
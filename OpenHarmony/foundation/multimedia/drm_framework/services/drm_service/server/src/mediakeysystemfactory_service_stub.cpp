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

#include <codecvt>
#include "ipc_skeleton.h"
#include "xcollie/xcollie.h"
#include "xcollie/xcollie_define.h"
#include "drm_error_code.h"
#include "drm_log.h"
#include "mediakeysystemfactory_service_stub.h"

namespace {
constexpr uint32_t MAX_LISTNER_NUM = 64;
}

namespace OHOS {
namespace DrmStandard {
MediaKeySystemFactoryServiceStub::MediaKeySystemFactoryServiceStub()
{
    deathRecipientMap_.clear();
    DRM_DEBUG_LOG("0x%{public}06" PRIXPTR " Instances create", (POINTER_MASK & reinterpret_cast<uintptr_t>(this)));
}

MediaKeySystemFactoryServiceStub::~MediaKeySystemFactoryServiceStub()
{
    DRM_DEBUG_LOG("0x%{public}06" PRIXPTR " Instances destroy", (POINTER_MASK & reinterpret_cast<uintptr_t>(this)));
}

void MediaKeySystemFactoryServiceStub::MediaKeySystemFactoryClientDied(pid_t pid)
{
    DRM_ERR_LOG("MediaKeySystemFactory client has died, pid:%{public}d", pid);
    if (clientListenerMap_.find(pid) != clientListenerMap_.end()) {
        if (clientListenerMap_[pid] != nullptr && clientListenerMap_[pid]->AsObject() != nullptr &&
            deathRecipientMap_.find(pid) != deathRecipientMap_.end() && deathRecipientMap_[pid] != nullptr) {
            (void)clientListenerMap_[pid]->AsObject()->RemoveDeathRecipient(deathRecipientMap_[pid]);
        }
        deathRecipientMap_.erase(pid);
        clientListenerMap_.erase(pid);
    }
    DistroyForClientDied(pid);
}

int32_t MediaKeySystemFactoryServiceStub::SetListenerObject(const sptr<IRemoteObject> &object)
{
    pid_t pid = IPCSkeleton::GetCallingPid();
    if (clientListenerMap_.find(pid) != clientListenerMap_.end()) {
        if (clientListenerMap_[pid] != nullptr && clientListenerMap_[pid]->AsObject() != nullptr &&
            deathRecipientMap_.find(pid) != deathRecipientMap_.end() && deathRecipientMap_[pid] != nullptr) {
            (void)clientListenerMap_[pid]->AsObject()->RemoveDeathRecipient(deathRecipientMap_[pid]);
        }
        deathRecipientMap_.erase(pid);
        clientListenerMap_.erase(pid);
    }
    DRM_CHECK_AND_RETURN_RET_LOG(clientListenerMap_.size() < MAX_LISTNER_NUM,
        DRM_OPERATION_NOT_ALLOWED, "the number of listeners exceeds MAX_LISTNER_NUM: 64");
    DRM_CHECK_AND_RETURN_RET_LOG(object != nullptr, DRM_MEMORY_ERROR, "set listener object is nullptr");
    sptr<IDrmListener> clientListener = iface_cast<IDrmListener>(object);
    DRM_CHECK_AND_RETURN_RET_LOG(
        clientListener != nullptr, DRM_MEMORY_ERROR, "failed to convert IDrmListener");
    sptr<DrmDeathRecipient> deathRecipient = new (std::nothrow) DrmDeathRecipient(pid);
    DRM_CHECK_AND_RETURN_RET_LOG(deathRecipient != nullptr, DRM_MEMORY_ERROR, "failed to new DrmDeathRecipient");
    deathRecipient->SetNotifyCb(
        std::bind(&MediaKeySystemFactoryServiceStub::MediaKeySystemFactoryClientDied, this, std::placeholders::_1));
    if (clientListener->AsObject() != nullptr) {
        (void)clientListener->AsObject()->AddDeathRecipient(deathRecipient);
    }
    DRM_DEBUG_LOG("MediaKeySystem client pid:%{public}d", pid);
    deathRecipientMap_[pid] = deathRecipient;
    clientListenerMap_[pid] = clientListener;
    return DRM_OK;
}

static int32_t ProcessMediaKeySystemSupportedRequest(MediaKeySystemFactoryServiceStub *stub, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    int32_t paramNum = data.ReadInt32();
    bool isSurpported = false;

    DRM_CHECK_AND_RETURN_RET_LOG((paramNum <= (int32_t)ARGS_NUM_THREE) && (paramNum >= (int32_t)ARGS_NUM_ONE),
        IPC_STUB_WRITE_PARCEL_ERR, "MediaKeySystemFactoryServiceStub paramNum is invalid");
    std::string uuid = data.ReadString();
    if (paramNum == ARGS_NUM_ONE) {
        int32_t ret = stub->IsMediaKeySystemSupported(uuid, &isSurpported);
        DRM_CHECK_AND_RETURN_RET_LOG(ret == DRM_OK, ret, "IsMediaKeySystemSupported faild, errCode:%{public}d", ret);
        DRM_CHECK_AND_RETURN_RET_LOG(reply.WriteBool(isSurpported), IPC_STUB_WRITE_PARCEL_ERR,
            "MediaKeySystemFactoryServiceStub Write isSurpported failed.");
        return ret;
    }
    std::string mimeType = data.ReadString();
    if (paramNum == ARGS_NUM_TWO) {
        int32_t ret = stub->IsMediaKeySystemSupported(uuid, mimeType, &isSurpported);
        DRM_CHECK_AND_RETURN_RET_LOG(ret == DRM_OK, ret, "IsMediaKeySystemSupported faild, errCode:%{public}d", ret);
        DRM_CHECK_AND_RETURN_RET_LOG(reply.WriteBool(isSurpported), IPC_STUB_WRITE_PARCEL_ERR,
            "MediaKeySystemFactoryServiceStub Write isSurpported failed.");
        return ret;
    }

    int32_t securityLevel = data.ReadInt32();
    if (paramNum == ARGS_NUM_THREE) {
        int32_t ret = stub->IsMediaKeySystemSupported(uuid, mimeType, securityLevel, &isSurpported);
        DRM_CHECK_AND_RETURN_RET_LOG(ret == DRM_OK, ret, "IsMediaKeySystemSupported faild, errCode:%{public}d", ret);
        DRM_CHECK_AND_RETURN_RET_LOG(reply.WriteBool(isSurpported), IPC_STUB_WRITE_PARCEL_ERR,
            "MediaKeySystemFactoryServiceStub Write isSurpported failed.");
        return ret;
    }
    return DRM_OK;
}

static int32_t ProcessSetListenerObject(MediaKeySystemFactoryServiceStub *stub, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    DRM_INFO_LOG("MediaKeySystemFactoryServiceStub ProcessSetListenerObject.");
    (void)reply;
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    int32_t errCode = stub->SetListenerObject(object);
    DRM_CHECK_AND_RETURN_RET_LOG(errCode == DRM_OK, errCode,
        "ProcessSetListenerObject faild, errCode:%{public}d", errCode);
    DRM_INFO_LOG("MediaKeySystemFactoryServiceStub ProcessSetListenerObject exit.");
    return errCode;
}

static int32_t ProcessGetMediaKeySystemName(MediaKeySystemFactoryServiceStub *stub, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    DRM_INFO_LOG("MediaKeySystemFactoryServiceStub ProcessGetMediaKeySystemName enter.");
    std::map<std::string, std::string> mediaKeySystemNames;
    int32_t ret = stub->GetMediaKeySystemName(mediaKeySystemNames);
    DRM_CHECK_AND_RETURN_RET_LOG(ret == DRM_OK, ret, "GetMediaKeySystemName faild, errCode:%{public}d", ret);
    reply.WriteInt32(mediaKeySystemNames.size());
    for (auto mediaKeySystemName : mediaKeySystemNames) {
        DRM_CHECK_AND_RETURN_RET_LOG(reply.WriteString(mediaKeySystemName.first), IPC_STUB_WRITE_PARCEL_ERR,
            "MediaKeySystemFactoryServiceStub ProcessGetMediaKeySystemName failed.");
        DRM_CHECK_AND_RETURN_RET_LOG(reply.WriteString(mediaKeySystemName.second), IPC_STUB_WRITE_PARCEL_ERR,
            "MediaKeySystemFactoryServiceStub ProcessGetMediaKeySystemName failed.");
    }
    DRM_INFO_LOG("MediaKeySystemFactoryServiceStub ProcessGetMediaKeySystemName exit.");
    return DRM_OK;
}

static int32_t ProcessGetMediaKeySystemUuid(MediaKeySystemFactoryServiceStub *stub, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    DRM_INFO_LOG("MediaKeySystemFactoryServiceStub ProcessGetMediaKeySystemUuid enter.");
    std::string name = data.ReadString();
    std::string uuid;
    int32_t ret = stub->GetMediaKeySystemUuid(name, uuid);
    DRM_CHECK_AND_RETURN_RET_LOG(ret == DRM_OK, ret, "ProcessGetMediaKeySystemUuid faild, errCode:%{public}d", ret);
    if (!reply.WriteString(uuid)) {
        DRM_ERR_LOG("MediaKeySystemServiceStub ProcessGetMediaKeySystemUuid write value failed.");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    DRM_INFO_LOG("MediaKeySystemFactoryServiceStub ProcessGetMediaKeySystemUuid exit.");
    return DRM_OK;
}

int32_t MediaKeySystemFactoryServiceStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        DRM_DEBUG_LOG("MediaKeySystemFactoryServiceStub: ReadInterfaceToken failed.");
        return -1;
    }

    switch (code) {
        case MEDIA_KEY_SYSTEM_FACTORY_IS_MEDIA_KEY_SYSTEM_SURPPORTED: {
            DRM_INFO_LOG("MediaKeySystemFactoryServiceStub IS_MEDIA_KEY_SYSTEM_SURPPORTED enter.");
            int32_t ret = ProcessMediaKeySystemSupportedRequest(this, data, reply, option);
            DRM_INFO_LOG("MediaKeySystemFactoryServiceStub IS_MEDIA_KEY_SYSTEM_SURPPORTED exit.");
            return ret;
        }
        case MEDIA_KEY_SYSTEM_FACTORY_CREATE_MEDIA_KEYSYSTEM: {
            DRM_INFO_LOG("MediaKeySystemFactoryServiceStub CREATE_MEDIA_KEYSYSTEM enter.");
            sptr<IMediaKeySystemService> mediaKeysystemProxy = nullptr;
            std::string uuid = data.ReadString();
            int32_t errCode = CreateMediaKeySystem(uuid, mediaKeysystemProxy);
            if (errCode != ERR_NONE) {
                DRM_ERR_LOG("MediaKeySystemFactoryServiceStub CreateMediaKeySystem failed : %{public}d", errCode);
                return errCode;
            }
            if (!reply.WriteRemoteObject(mediaKeysystemProxy->AsObject())) {
                DRM_ERR_LOG("MediaKeySystemFactoryServiceStub CreateMediaKeySystem Write MediaKeySession obj failed.");
                return IPC_STUB_WRITE_PARCEL_ERR;
            }
            DRM_INFO_LOG("MediaKeySystemFactoryServiceStub CREATE_MEDIA_KEYSYSTEM exit.");
            return errCode;
        }
        case MEDIA_KEY_SYSTEM_FACTORY_SET_LISTENER_OBJ: {
            DRM_INFO_LOG("MediaKeySystemFactoryServiceStub MEDIA_KEY_SYSTEM_FACTORY_SET_LISTENER_OBJ enter.");
            int32_t ret = ProcessSetListenerObject(this, data, reply, option);
            DRM_INFO_LOG("MediaKeySystemFactoryServiceStub MEDIA_KEY_SYSTEM_FACTORY_SET_LISTENER_OBJ exit.");
            return ret;
        }
        case MEDIA_KEY_SYSTEM_FACTORY_GET_MEDIA_KEYSYSTEM_NAME: {
            DRM_INFO_LOG("MediaKeySystemFactoryServiceStub MEDIA_KEY_SYSTEM_FACTORY_GST_MEDIA_KEYSYSTEM_NAME enter.");
            int32_t ret = ProcessGetMediaKeySystemName(this, data, reply, option);
            DRM_INFO_LOG("MediaKeySystemFactoryServiceStub MEDIA_KEY_SYSTEM_FACTORY_GST_MEDIA_KEYSYSTEM_NAME exit.");
            return ret;
        }
        case MEDIA_KEY_SYSTEM_FACTORY_GET_MEDIA_KEYSYSTEM_UUID: {
            DRM_INFO_LOG("MediaKeySystemFactoryServiceStub MEDIA_KEY_SYSTEM_FACTORY_GET_MEDIA_KEYSYSTEM_UUID enter.");
            int32_t ret = ProcessGetMediaKeySystemUuid(this, data, reply, option);
            DRM_INFO_LOG("MediaKeySystemFactoryServiceStub MEDIA_KEY_SYSTEM_FACTORY_GET_MEDIA_KEYSYSTEM_UUID exit.");
            return ret;
        }
    }
    return DRM_OK;
}
} // namespace DrmStandard
} // namespace OHOS

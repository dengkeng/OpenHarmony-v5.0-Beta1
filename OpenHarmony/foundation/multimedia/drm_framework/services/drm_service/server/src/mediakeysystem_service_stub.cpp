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

#include "mediakeysystem_service_stub.h"
#include "drm_error_code.h"
#include "drm_log.h"
#include "ipc_skeleton.h"
#include "xcollie/xcollie.h"
#include "xcollie/xcollie_define.h"

namespace OHOS {
namespace DrmStandard {
using ProcessRemoteRequestFunc = int32_t (*)(MediaKeySystemServiceStub *stub, MessageParcel &data, MessageParcel &reply,
    MessageOption &option);

struct ProcessRemoteRequestFuncArray {
    OHOS::DrmStandard::MediaKeySystemServiceRequestCode requestCode;
    ProcessRemoteRequestFunc processFunc;
};

static int32_t ProcessCreatekeySession(MediaKeySystemServiceStub *stub, MessageParcel &data, MessageParcel &reply,
    MessageOption &option);

static int32_t ProcessKeySystemRequest(MediaKeySystemServiceStub *stub, MessageParcel &data, MessageParcel &reply,
    MessageOption &option);

static int32_t ProcessKeySystemResponse(MediaKeySystemServiceStub *stub, MessageParcel &data, MessageParcel &reply,
    MessageOption &option);

static int32_t ProcessSetConfigurationString(MediaKeySystemServiceStub *stub, MessageParcel &data, MessageParcel &reply,
    MessageOption &option);

static int32_t ProcessGetConfigurationString(MediaKeySystemServiceStub *stub, MessageParcel &data, MessageParcel &reply,
    MessageOption &option);

static int32_t ProcessSetConfigurationByteArray(MediaKeySystemServiceStub *stub, MessageParcel &data,
    MessageParcel &reply, MessageOption &option);

static int32_t ProcessGetConfigurationByteArray(MediaKeySystemServiceStub *stub, MessageParcel &data,
    MessageParcel &reply, MessageOption &option);

static int32_t ProcessGetMetircs(MediaKeySystemServiceStub *stub, MessageParcel &data, MessageParcel &reply,
    MessageOption &option);

static int32_t ProcessReleaseKeySystem(MediaKeySystemServiceStub *stub, MessageParcel &data, MessageParcel &reply,
    MessageOption &option);

static int32_t ProcessGetMaxContentProtectionLevel(MediaKeySystemServiceStub *stub, MessageParcel &data,
    MessageParcel &reply, MessageOption &option);

static int32_t ProcessGetCertificateStatus(MediaKeySystemServiceStub *stub, MessageParcel &data, MessageParcel &reply,
    MessageOption &option);

static int32_t ProcessGetOfflineLMediaKeyIds(MediaKeySystemServiceStub *stub, MessageParcel &data, MessageParcel &reply,
    MessageOption &option);

static int32_t ProcessGetOfflineMediaKeyStatus(MediaKeySystemServiceStub *stub, MessageParcel &data,
    MessageParcel &reply, MessageOption &option);

static int32_t ProcessRemoveOfflineLMediaKey(MediaKeySystemServiceStub *stub, MessageParcel &data, MessageParcel &reply,
    MessageOption &option);

static int32_t ProcessSetListenerObject(MediaKeySystemServiceStub *stub, MessageParcel &data, MessageParcel &reply,
    MessageOption &option);

static int32_t ProcessSetCallabck(MediaKeySystemServiceStub *stub, MessageParcel &data, MessageParcel &reply,
    MessageOption &option);

static struct ProcessRemoteRequestFuncArray g_mediaKeySystemServiceStubRequestProcessFunc[] = {
    {MEDIA_KEY_SYSTEM_CREATE_KEY_SESSION, ProcessCreatekeySession},
    {MEDIA_KEY_SYSTEM_GENERATE_KEYSYSTEM_REQUEST, ProcessKeySystemRequest},
    {MEDIA_KEY_SYSTEM_PROCESS_KEYSYSTEM_RESPONSE, ProcessKeySystemResponse},
    {MEDIA_KEY_SYSTEM_SETCONFIGURATION_STRING, ProcessSetConfigurationString},
    {MEDIA_KEY_SYSTEM_GETCONFIGURATION_STRING, ProcessGetConfigurationString},
    {MEDIA_KEY_SYSTEM_SETCONFIGURATION_BYTEARRAY, ProcessSetConfigurationByteArray},
    {MEDIA_KEY_SYSTEM_GETCONFIGURATION_BYTEARRAY, ProcessGetConfigurationByteArray},
    {MEDIA_KEY_SYSTEM_GETMETRIC, ProcessGetMetircs},
    {MEDIA_KEY_SYSTEM_RELEASE, ProcessReleaseKeySystem},
    {MEDIA_KEY_SYSTEM_GETMAXSECURITYLEVEL, ProcessGetMaxContentProtectionLevel},
    {MEDIA_KEY_SYSTEM_GETCERTIFICATESTATUS, ProcessGetCertificateStatus},
    {MEDIA_KEY_SYSTEM_GET_OFFLINELICENSEIDS, ProcessGetOfflineLMediaKeyIds},
    {MEDIA_KEY_SYSTEM_GET_OFFLINEKEY_STATUS, ProcessGetOfflineMediaKeyStatus},
    {MEDIA_KEY_SYSTEM_REMOVE_OFFLINELICENSE, ProcessRemoveOfflineLMediaKey},
    {MEDIA_KEY_SYSTEM_SET_LISTENER_OBJ, ProcessSetListenerObject},
    {MEDIA_KEY_SYSTEM_SETCALLBACK, ProcessSetCallabck},
};

MediaKeySystemServiceStub::MediaKeySystemServiceStub()
{
    DRM_DEBUG_LOG("0x%{public}06" PRIXPTR " Instances create", (POINTER_MASK & reinterpret_cast<uintptr_t>(this)));
}

MediaKeySystemServiceStub::~MediaKeySystemServiceStub()
{
    DRM_DEBUG_LOG("0x%{public}06" PRIXPTR " Instances destroy", (POINTER_MASK & reinterpret_cast<uintptr_t>(this)));
    sptr<DrmDeathRecipient> deathRecipient_ = nullptr;
    sptr<IDrmListener> clientListener_ = nullptr;
}

static int32_t ProcessCreatekeySession(MediaKeySystemServiceStub *stub, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    DRM_INFO_LOG("MediaKeySystemServiceStub MEDIA_KEY_SYSTEM_CREATE_KEY_SESSION enter.");
    sptr<IMediaKeySessionService> keySessionServiceProxy = nullptr;
    const int32_t securityLevel = data.ReadInt32();
    int32_t errCode = stub->CreateMediaKeySession((IMediaKeySessionService::ContentProtectionLevel)securityLevel,
        keySessionServiceProxy);
    DRM_CHECK_AND_RETURN_RET_LOG(errCode == DRM_OK, errCode, "CreateMediaKeySession faild, errCode:%{public}d",
        errCode);

    if (!reply.WriteRemoteObject(keySessionServiceProxy->AsObject())) {
        DRM_ERR_LOG("MediaKeySystemServiceStub CreateMediaKeySession Write MediaKeySession obj failed.");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    DRM_INFO_LOG("MediaKeySystemServiceStub MEDIA_KEY_SYSTEM_CREATE_KEY_SESSION exit.");
    return errCode;
}

static int32_t ProcessKeySystemRequest(MediaKeySystemServiceStub *stub, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    DRM_INFO_LOG("MediaKeySystemServiceStub MEDIA_KEY_SYSTEM_GENERATE_KEYSYSTEM_REQUEST enter.");
    std::vector<uint8_t> request;
    std::string defaultUrl;
    int32_t ret = stub->GenerateKeySystemRequest(request, defaultUrl);
    DRM_CHECK_AND_RETURN_RET_LOG(ret == DRM_OK, ret, "ProcessKeySystemRequest faild, errCode:%{public}d", ret);
    if (!reply.WriteString(defaultUrl)) {
        DRM_ERR_LOG("MediaKeySystemServiceStub Write GenerateKeySystemRequest failed.");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteInt32(request.size())) {
        DRM_ERR_LOG("MediaKeySystemServiceStub Write request size failed.");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    DRM_CHECK_AND_RETURN_RET_LOG(request.size() < REQUEST_MAX_LEN, DRM_MEMORY_ERROR,
        "The size of request is too large.");
    if (request.size() != 0) {
        if (!reply.WriteBuffer(request.data(), request.size())) {
            DRM_ERR_LOG("MediaKeySystemServiceStub RestoreOfflineMediaKeys write request failed.");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
    }

    DRM_INFO_LOG("MediaKeySystemServiceStub MEDIA_KEY_SYSTEM_GENERATE_KEYSYSTEM_REQUEST exit.");
    return ret;
}

static int32_t ProcessKeySystemResponse(MediaKeySystemServiceStub *stub, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    DRM_INFO_LOG("MediaKeySystemServiceStub MEDIA_KEY_SYSTEM_PROCESS_KEYSYSTEM_RESPONSE enter.");
    std::vector<uint8_t> response;
    int32_t responseSize = data.ReadInt32();
    DRM_CHECK_AND_RETURN_RET_LOG(responseSize < RESPONSE_MAX_LEN, DRM_MEMORY_ERROR,
        "The size of response is too large.");
    if (responseSize != 0) {
        const uint8_t *responseBuf = static_cast<const uint8_t *>(data.ReadBuffer(responseSize));
        if (responseBuf == nullptr) {
            DRM_ERR_LOG("MediaKeySystemServiceStub::ProcessOfflineReleaseResponse read response failed.");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        response.assign(responseBuf, responseBuf + responseSize);
    }
    int32_t ret = stub->ProcessKeySystemResponse(response);
    DRM_CHECK_AND_RETURN_RET_LOG(ret == DRM_OK, ret, "ProcessKeySystemResponse faild, errCode:%{public}d", ret);
    DRM_INFO_LOG("MediaKeySystemServiceStub MEDIA_KEY_SYSTEM_PROCESS_KEYSYSTEM_RESPONSE exit.");
    return ret;
}

static int32_t ProcessSetConfigurationString(MediaKeySystemServiceStub *stub, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    DRM_INFO_LOG("MediaKeySystemServiceStub MEDIA_KEY_SYSTEM_SETCONFIGURATION enter.");
    std::string configName = data.ReadString();
    std::string value = data.ReadString();
    int32_t ret = stub->SetConfigurationString(configName, value);
    DRM_CHECK_AND_RETURN_RET_LOG(ret == DRM_OK, ret, "ProcessSetConfigurationString faild, errCode:%{public}d", ret);
    DRM_INFO_LOG("MediaKeySystemServiceStub MEDIA_KEY_SYSTEM_SETCONFIGURATION exit.");
    return ret;
}

static int32_t ProcessGetConfigurationString(MediaKeySystemServiceStub *stub, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    DRM_INFO_LOG("MediaKeySystemServiceStub MEDIA_KEY_SYSTEM_GETCONFIGURATION enter.");
    std::string configName = data.ReadString();
    std::string value;
    int32_t ret = stub->GetConfigurationString(configName, value);
    DRM_CHECK_AND_RETURN_RET_LOG(ret == DRM_OK, ret, "ProcessGetConfigurationString faild, errCode:%{public}d", ret);
    if (!reply.WriteString(value)) {
        DRM_ERR_LOG("MediaKeySystemServiceStub ProcessGetConfigurationString write value failed.");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    DRM_INFO_LOG("MediaKeySystemServiceStub MEDIA_KEY_SYSTEM_GETCONFIGURATION exit.");
    return ret;
}

static int32_t ProcessSetConfigurationByteArray(MediaKeySystemServiceStub *stub, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    DRM_INFO_LOG("MediaKeySystemServiceStub MEDIA_KEY_SYSTEM_SETCONFIGURATION enter.");
    std::string configName = data.ReadString();
    std::vector<uint8_t> value;
    int32_t valueSize = data.ReadInt32();
    DRM_CHECK_AND_RETURN_RET_LOG(valueSize < RESPONSE_MAX_LEN, DRM_MEMORY_ERROR,
        "The size of configurate value is too large.");
    if (valueSize != 0) {
        const uint8_t *valueBuf = static_cast<const uint8_t *>(data.ReadBuffer(valueSize));
        if (valueBuf == nullptr) {
            DRM_ERR_LOG("MediaKeySystemServiceStub::ProcessSetConfigurationByteArray read value failed.");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        value.assign(valueBuf, valueBuf + valueSize);
    }
    int32_t ret = stub->SetConfigurationByteArray(configName, value);
    DRM_CHECK_AND_RETURN_RET_LOG(ret == DRM_OK, ret, "ProcessSetConfigurationByteArray faild, errCode:%{public}d", ret);
    DRM_INFO_LOG("MediaKeySystemServiceStub MEDIA_KEY_SYSTEM_SETCONFIGURATION exit.");
    return ret;
}

static int32_t ProcessGetConfigurationByteArray(MediaKeySystemServiceStub *stub, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    DRM_INFO_LOG("MediaKeySystemServiceStub MEDIA_KEY_SYSTEM_GETCONFIGURATION enter.");
    std::string configName = data.ReadString();
    std::vector<uint8_t> value;
    int32_t ret = stub->GetConfigurationByteArray(configName, value);
    DRM_CHECK_AND_RETURN_RET_LOG(ret == DRM_OK, ret, "ProcessGetConfigurationByteArray faild, errCode:%{public}d", ret);
    if (!reply.WriteInt32(value.size())) {
        DRM_ERR_LOG("MediaKeySystemServiceStub Write value size failed.");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    DRM_CHECK_AND_RETURN_RET_LOG(value.size() < RESPONSE_MAX_LEN, DRM_MEMORY_ERROR,
        "The size of configurate value is too large.");
    if (value.size() != 0) {
        if (!reply.WriteBuffer(value.data(), value.size())) {
            DRM_ERR_LOG("MediaKeySystemServiceStub ProcessGetConfigurationByteArray write value failed.");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
    }
    DRM_INFO_LOG("MediaKeySystemServiceStub MEDIA_KEY_SYSTEM_GETCONFIGURATION exit.");
    return ret;
}

static int32_t ProcessGetMetircs(MediaKeySystemServiceStub *stub, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    DRM_INFO_LOG("MediaKeySystemServiceStub MEDIA_KEY_SYSTEM_GETMETRIC enter.");
    std::vector<IMediaKeySystemService::MetircKeyValue> metrics;
    int32_t ret = stub->GetStatistics(metrics);
    DRM_CHECK_AND_RETURN_RET_LOG(ret == DRM_OK, ret, "ProcessGetMetircs faild, errCode:%{public}d", ret);
    reply.WriteInt32(metrics.size());
    for (auto info : metrics) {
        reply.WriteString(info.name);
        reply.WriteString(info.value);
    }
    DRM_INFO_LOG("MediaKeySystemServiceStub MEDIA_KEY_SYSTEM_GETMETRIC exit.");
    return ret;
}

static int32_t ProcessReleaseKeySystem(MediaKeySystemServiceStub *stub, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    DRM_INFO_LOG("MediaKeySystemServiceStub KEY_SESSION_RELEASE enter.");
    int32_t ret = stub->Release();
    DRM_CHECK_AND_RETURN_RET_LOG(ret == DRM_OK, ret, "ProcessReleaseKeySystem faild, errCode:%{public}d", ret);
    DRM_INFO_LOG("MediaKeySystemServiceStub KEY_SESSION_RELEASE exit.");
    return ret;
}

static int32_t ProcessGetMaxContentProtectionLevel(MediaKeySystemServiceStub *stub, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    DRM_INFO_LOG("MediaKeySystemServiceStub MEDIA_KEY_SYSTEM_GETMAXSECURITYLEVEL enter.");
    IMediaKeySessionService::ContentProtectionLevel securityLevel =
        IMediaKeySessionService::CONTENT_PROTECTION_LEVEL_UNKNOWN;
    int32_t ret = stub->GetMaxContentProtectionLevel(&securityLevel);
    DRM_CHECK_AND_RETURN_RET_LOG(ret == DRM_OK, ret, "ProcessGetMaxContentProtectionLevel faild, errCode:%{public}d",
        ret);
    if (!reply.WriteInt32(securityLevel)) {
        DRM_ERR_LOG("MediaKeySystemServiceStub Write ProcessGetMaxContentProtectionLevel failed.");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    DRM_INFO_LOG("MediaKeySystemServiceStub MEDIA_KEY_SYSTEM_GETMAXSECURITYLEVEL exit.");
    return ret;
}

static int32_t ProcessGetCertificateStatus(MediaKeySystemServiceStub *stub, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    DRM_INFO_LOG("MediaKeySystemServiceStub MEDIA_KEY_SYSTEM_GETCERTIFICATESTATUS enter.");
    IMediaKeySystemService::CertificateStatus certStatus = IMediaKeySystemService::CERT_STATUS_PROVISIONED;
    int32_t ret = stub->GetCertificateStatus(&certStatus);
    DRM_CHECK_AND_RETURN_RET_LOG(ret == DRM_OK, ret, "ProcessGetCertificateStatus faild, errCode:%{public}d", ret);
    if (!reply.WriteInt32(certStatus)) {
        DRM_ERR_LOG("MediaKeySystemServiceStub ProcessGetCertificateStatus write certStatus failed.");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    DRM_INFO_LOG("MediaKeySystemServiceStub MEDIA_KEY_SYSTEM_GETCERTIFICATESTATUS exit.");
    return ret;
}

static int32_t ProcessGetOfflineLMediaKeyIds(MediaKeySystemServiceStub *stub, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    DRM_INFO_LOG("MediaKeySystemServiceStub MEDIA_KEY_SYSTEM_GET_OFFLINELICENSEIDS enter.");
    std::vector<std::vector<uint8_t>> licenseIds;
    int32_t ret = stub->GetOfflineMediaKeyIds(licenseIds);
    DRM_CHECK_AND_RETURN_RET_LOG(ret == DRM_OK, ret, "ProcessGetOfflineLMediaKeyIds faild, errCode:%{public}d", ret);
    reply.WriteInt32(licenseIds.size());
    if (licenseIds.size() == 0) {
        DRM_DEBUG_LOG("MediaKeySystemServiceStub MEDIA_KEY_SYSTEM_GET_OFFLINELICENSEIDS licenseIds is empty.");
        return ret;
    }
    for (auto licenseId : licenseIds) {
        uint32_t licenseIdSize = licenseId.size();
        reply.WriteInt32(licenseIdSize);
        if (licenseIdSize == 0 || licenseIdSize > LICENSEID_MAX_LEN) {
            continue;
        }
        if (!reply.WriteBuffer(licenseId.data(), licenseId.size())) {
            DRM_ERR_LOG("MediaKeySystemServiceStub ProcessGetOfflineLMediaKeyIds write licenseId failed.");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
    }

    DRM_INFO_LOG("MediaKeySystemServiceStub MEDIA_KEY_SYSTEM_GET_OFFLINELICENSEIDS exit.");
    return ret;
}

static int32_t ProcessGetOfflineMediaKeyStatus(MediaKeySystemServiceStub *stub, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    DRM_INFO_LOG("MediaKeySystemServiceStub MEDIA_KEY_SYSTEM_GET_OFFLINEKEY_STATUS enter.");
    std::vector<uint8_t> licenseId;
    int32_t licenseIdSize = data.ReadInt32();
    DRM_CHECK_AND_RETURN_RET_LOG(licenseIdSize < LICENSEID_MAX_LEN, DRM_MEMORY_ERROR,
        "The size of licenseId is too large.");
    if (licenseIdSize != 0) {
        const uint8_t *licenseIdBuf = static_cast<const uint8_t *>(data.ReadBuffer(licenseIdSize));
        if (licenseIdBuf == nullptr) {
            DRM_ERR_LOG("MediaKeySystemServiceStub::ProcessGetOfflineMediaKeyStatus read licenseId failed.");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        licenseId.assign(licenseIdBuf, licenseIdBuf + licenseIdSize);
    }
    IMediaKeySessionService::OfflineMediaKeyStatus status;
    int32_t ret = stub->GetOfflineMediaKeyStatus(licenseId, status);
    DRM_CHECK_AND_RETURN_RET_LOG(ret == DRM_OK, ret, "ProcessGetOfflineMediaKeyStatus faild, errCode:%{public}d", ret);
    if (!reply.WriteInt32((int32_t)status)) {
        DRM_ERR_LOG("MediaKeySystemServiceStub Write state failed.");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    DRM_INFO_LOG("MediaKeySystemServiceStub MEDIA_KEY_SYSTEM_GET_OFFLINEKEY_STATUS exit.");
    return ret;
}

static int32_t ProcessRemoveOfflineLMediaKey(MediaKeySystemServiceStub *stub, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    DRM_INFO_LOG("MediaKeySystemServiceStub MEDIA_KEY_SYSTEM_REMOVE_OFFLINELICENSE enter.");
    std::vector<uint8_t> licenseId;
    int32_t licenseIdSize = data.ReadInt32();
    DRM_CHECK_AND_RETURN_RET_LOG(licenseIdSize < LICENSEID_MAX_LEN, DRM_MEMORY_ERROR,
        "The size of licenseId is too large.");
    if (licenseIdSize != 0) {
        const uint8_t *licenseIdBuf = static_cast<const uint8_t *>(data.ReadBuffer(licenseIdSize));
        if (licenseIdBuf == nullptr) {
            DRM_ERR_LOG("MediaKeySystemServiceStub::ProcessRemoveOfflineLMediaKey read licenseId failed.");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        licenseId.assign(licenseIdBuf, licenseIdBuf + licenseIdSize);
    }
    int32_t ret = stub->ClearOfflineMediaKeys(licenseId);
    DRM_CHECK_AND_RETURN_RET_LOG(ret == DRM_OK, ret, "ProcessRemoveOfflineLMediaKey faild, errCode:%{public}d", ret);
    DRM_INFO_LOG("MediaKeySystemServiceStub MEDIA_KEY_SYSTEM_REMOVE_OFFLINELICENSE exit.");
    return ret;
}

void MediaKeySystemServiceStub::MediaKeySystemClientDied(pid_t pid)
{
    DRM_ERR_LOG("MediaKeySystemService client has died, pid:%{public}d", pid);
}

int32_t MediaKeySystemServiceStub::SetListenerObject(const sptr<IRemoteObject> &object)
{
    pid_t pid = IPCSkeleton::GetCallingPid();
    if (clientListener_ != nullptr && clientListener_->AsObject() != nullptr && deathRecipient_ != nullptr) {
        DRM_DEBUG_LOG("This MediaKeySystemServiceStub has already set listener!");
        (void)clientListener_->AsObject()->RemoveDeathRecipient(deathRecipient_);
        deathRecipient_ = nullptr;
        clientListener_ = nullptr;
    }

    DRM_CHECK_AND_RETURN_RET_LOG(object != nullptr, DRM_MEMORY_ERROR, "set listener object is nullptr");
    sptr<IDrmListener> clientListener_ = iface_cast<IDrmListener>(object);
    DRM_CHECK_AND_RETURN_RET_LOG(
        clientListener_ != nullptr, DRM_MEMORY_ERROR, "failed to convert IDrmListener");
    deathRecipient_ = new (std::nothrow) DrmDeathRecipient(pid);
    DRM_CHECK_AND_RETURN_RET_LOG(deathRecipient_ != nullptr, DRM_MEMORY_ERROR, "failed to new DrmDeathRecipient");
    deathRecipient_->SetNotifyCb(
        std::bind(&MediaKeySystemServiceStub::MediaKeySystemClientDied, this, std::placeholders::_1));
    if (clientListener_->AsObject() != nullptr) {
        (void)clientListener_->AsObject()->AddDeathRecipient(deathRecipient_);
    }
    DRM_DEBUG_LOG("MediaKeySystem client pid:%{public}d", pid);
    return DRM_OK;
}

static int32_t ProcessSetListenerObject(MediaKeySystemServiceStub *stub, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    DRM_INFO_LOG("MediaKeySystemServiceStub ProcessSetListenerObject.");
    (void)reply;
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    int32_t errCode = stub->SetListenerObject(object);
    DRM_CHECK_AND_RETURN_RET_LOG(errCode == DRM_OK, errCode,
        "ProcessSetListenerObject faild, errCode:%{public}d", errCode);
    DRM_INFO_LOG("MediaKeySystemServiceStub ProcessSetListenerObject exit.");
    return errCode;
}

static int32_t ProcessSetCallabck(MediaKeySystemServiceStub *stub, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    DRM_INFO_LOG("MediaKeySystemServiceStub SetCallback enter.");
    auto remoteObject = data.ReadRemoteObject();
    if (remoteObject == nullptr) {
        DRM_ERR_LOG("MediaKeySystemServiceStub SetCallback remote is null");
        return IPC_STUB_INVALID_DATA_ERR;
    }
    auto callback = iface_cast<IMeidaKeySystemServiceCallback>(remoteObject);
    if (callback == nullptr) {
        DRM_ERR_LOG("MediaKeySystemServiceStub SetCallback cast nullptr");
        return IPC_STUB_INVALID_DATA_ERR;
    }
    int32_t errCode = stub->SetCallback(callback);
    DRM_CHECK_AND_RETURN_RET_LOG(errCode == DRM_OK, errCode, "ProcessSetCallabck faild, errCode:%{public}d", errCode);
    DRM_INFO_LOG("MediaKeySystemServiceStub SetCallback exit.");
    return errCode;
}

int32_t MediaKeySystemServiceStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    DRM_CHECK_AND_RETURN_RET_LOG(data.ReadInterfaceToken() == GetDescriptor(), -1,
        "MediaKeySystemServiceStub: ReadInterfaceToken failed.");
    DRM_INFO_LOG("OnRemoteRequest, cmd = %{public}u", code);

    DRM_CHECK_AND_RETURN_RET_LOG((code >= MEDIA_KEY_SYSTEM_CREATE_KEY_SESSION) &&
        (code <= MEDIA_KEY_SYSTEM_SETCALLBACK),
        IPCObjectStub::OnRemoteRequest(code, data, reply, option),
        "code not match, need check MediaKeySystemServiceStub");

    return g_mediaKeySystemServiceStubRequestProcessFunc[code].processFunc(this, data, reply, option);
}
} // namespace DrmStandard
} // namespace OHOS
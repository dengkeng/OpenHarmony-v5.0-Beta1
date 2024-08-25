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

#include "mediakeysystem_service_proxy.h"
#include "remote_request_code.h"
#include "drm_log.h"
#include "drm_error_code.h"

namespace OHOS {
namespace DrmStandard {
MediaKeySystemServiceProxy::MediaKeySystemServiceProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IMediaKeySystemService>(impl)
{
    DRM_DEBUG_LOG("MediaKeySystemServiceProxy Initialized.");
}

int32_t MediaKeySystemServiceProxy::SetListenerObject(const sptr<IRemoteObject> &object)
{
    DRM_INFO_LOG("MediaKeySystemServiceProxy SetListenerObject.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    (void)data.WriteRemoteObject(object);
    int error = Remote()->SendRequest(MEDIA_KEY_SYSTEM_SET_LISTENER_OBJ, data, reply, option);
    if (error != ERR_NONE) {
        DRM_ERR_LOG("Set listener obj failed, error: %{public}d", error);
        return IPC_PROXY_ERR;
    }
    DRM_INFO_LOG("MediaKeySystemServiceProxy SetListenerObject exit.");
    return reply.ReadInt32();
}

int32_t MediaKeySystemServiceProxy::Release()
{
    DRM_INFO_LOG("MediaKeySystemServiceProxy::Release enter.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy Release Write interface token failed.");
        return IPC_PROXY_ERR;
    }
    int32_t ret = Remote()->SendRequest(MEDIA_KEY_SYSTEM_RELEASE, data, reply, option);
    if (ret != ERR_NONE) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy Release failed, ret: %{public}d", ret);
        return ret;
    }
    DRM_INFO_LOG("MediaKeySystemServiceProxy::Release exit.");
    return ret;
}

int32_t MediaKeySystemServiceProxy::GenerateKeySystemRequest(std::vector<uint8_t> &request, std::string &defaultUrl)
{
    DRM_INFO_LOG("MediaKeySystemServiceProxy::GenerateKeySystemRequest enter.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(MediaKeySystemServiceProxy::GetDescriptor())) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy GenerateKeySystemRequest Write interface token failed.");
        return IPC_PROXY_ERR;
    }

    int32_t ret = Remote()->SendRequest(MEDIA_KEY_SYSTEM_GENERATE_KEYSYSTEM_REQUEST, data, reply, option);
    if (ret != ERR_NONE) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy::GenerateKeySystemRequest failed, ret: %{public}d", ret);
        return ret;
    }

    defaultUrl = reply.ReadString();
    int32_t requestSize = reply.ReadInt32();
    if (requestSize != 0) {
        const uint8_t *requestBuf = static_cast<const uint8_t *>(reply.ReadBuffer(requestSize));
        if (requestBuf == nullptr) {
            DRM_ERR_LOG("MediaKeySessionServiceStub::ProcessOfflineReleaseResponse read response failed.");
            return IPC_PROXY_ERR;
        }
        request.assign(requestBuf, requestBuf + requestSize);
    }
    DRM_INFO_LOG("MediaKeySystemServiceProxy::GenerateKeySystemRequest exit.");
    return ret;
}

int32_t MediaKeySystemServiceProxy::ProcessKeySystemResponse(const std::vector<uint8_t> &response)
{
    DRM_INFO_LOG("MediaKeySystemServiceProxy::ProcessKeySystemResponse enter.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy ProcessKeySystemResponse Write interface token failed.");
        return IPC_PROXY_ERR;
    }

    if (!data.WriteInt32(response.size())) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy ProcessKeySystemResponse Write response size failed.");
        return IPC_PROXY_ERR;
    }
    DRM_CHECK_AND_RETURN_RET_LOG(response.size() < RESPONSE_MAX_LEN, DRM_MEMORY_ERROR,
        "The size of response is too large.");
    if (response.size() != 0) {
        if (!data.WriteBuffer(response.data(), response.size())) {
            DRM_ERR_LOG("MediaKeySystemServiceProxy RestoreOfflineMediaKeys write response failed.");
            return IPC_PROXY_ERR;
        }
    }

    int32_t ret = Remote()->SendRequest(MEDIA_KEY_SYSTEM_PROCESS_KEYSYSTEM_RESPONSE, data, reply, option);
    if (ret != ERR_NONE) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy ProcessKeySystemResponse failed, ret: %{public}d", ret);
        return ret;
    }

    DRM_INFO_LOG("MediaKeySystemServiceProxy::ProcessKeySystemResponse exit.");
    return ret;
}

int32_t MediaKeySystemServiceProxy::GetMaxContentProtectionLevel(
    IMediaKeySessionService::ContentProtectionLevel *securityLevel)
{
    DRM_INFO_LOG("MediaKeySystemServiceProxy::GetMaxContentProtectionLevel enter.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(MediaKeySystemServiceProxy::GetDescriptor())) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy GetMaxContentProtectionLevel Write interface token failed.");
        return IPC_PROXY_ERR;
    }

    int32_t ret = Remote()->SendRequest(MEDIA_KEY_SYSTEM_GETMAXSECURITYLEVEL, data, reply, option);
    if (ret != ERR_NONE) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy GetMaxContentProtectionLevel failed, ret: %{public}d", ret);
        return ret;
    }

    *securityLevel = (IMediaKeySessionService::ContentProtectionLevel)reply.ReadInt32();

    DRM_INFO_LOG("MediaKeySystemServiceProxy::GetMaxContentProtectionLevel exit.");
    return ret;
}

int32_t MediaKeySystemServiceProxy::GetCertificateStatus(IMediaKeySystemService::CertificateStatus *certStatus)
{
    DRM_INFO_LOG("MediaKeySystemServiceProxy::GetCertificateStatus enter.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(MediaKeySystemServiceProxy::GetDescriptor())) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy GetCertificateStatus Write interface token failed.");
        return IPC_PROXY_ERR;
    }

    int32_t ret = Remote()->SendRequest(MEDIA_KEY_SYSTEM_GETCERTIFICATESTATUS, data, reply, option);
    if (ret != ERR_NONE) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy GetCertificateStatus failed, ret: %{public}d", ret);
        return ret;
    }

    *certStatus = (IMediaKeySystemService::CertificateStatus)reply.ReadInt32();

    DRM_INFO_LOG("MediaKeySystemServiceProxy::GetCertificateStatus exit.");
    return ret;
}

int32_t MediaKeySystemServiceProxy::SetConfigurationString(std::string &configName, std::string &value)
{
    DRM_INFO_LOG("MediaKeySystemServiceProxy::SetConfiguration enter, configName:%{public}s, value:%{public}s.",
        configName.c_str(), value.c_str());
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy SetConfiguration Write interface token failed.");
        return IPC_PROXY_ERR;
    }

    if (!data.WriteString(configName)) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy SetConfiguration Write configName failed.");
        return IPC_PROXY_ERR;
    }
    if (!data.WriteString(value)) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy SetConfiguration Write value failed.");
        return IPC_PROXY_ERR;
    }

    int32_t ret = Remote()->SendRequest(MEDIA_KEY_SYSTEM_SETCONFIGURATION_STRING, data, reply, option);
    if (ret != ERR_NONE) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy SetConfiguration failed, ret: %{public}d", ret);
        return ret;
    }

    DRM_INFO_LOG("MediaKeySystemServiceProxy::SetConfiguration exit.");
    return ret;
}

int32_t MediaKeySystemServiceProxy::GetConfigurationString(std::string &configName, std::string &value)
{
    DRM_INFO_LOG("MediaKeySystemServiceProxy::GetConfiguration enter, configName:%{public}s.", configName.c_str());
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy GetConfiguration Write interface token failed.");
        return IPC_PROXY_ERR;
    }

    if (!data.WriteString(configName)) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy GetConfiguration Write configName failed.");
        return IPC_PROXY_ERR;
    }

    int32_t ret = Remote()->SendRequest(MEDIA_KEY_SYSTEM_GETCONFIGURATION_STRING, data, reply, option);
    if (ret != ERR_NONE) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy GetConfiguration failed, ret: %{public}d", ret);
        return ret;
    }

    value = reply.ReadString();

    DRM_INFO_LOG("MediaKeySystemServiceProxy::GetConfiguration exit.");
    return ret;
}

int32_t MediaKeySystemServiceProxy::SetConfigurationByteArray(std::string &configName, std::vector<uint8_t> &value)
{
    DRM_INFO_LOG("MediaKeySystemServiceProxy::SetConfiguration enter, configName:%{public}s.", configName.c_str());
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy SetConfiguration Write interface token failed.");
        return IPC_PROXY_ERR;
    }

    if (!data.WriteString(configName)) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy SetConfiguration Write configName failed.");
        return IPC_PROXY_ERR;
    }

    if (!data.WriteInt32(value.size())) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy SetConfiguration Write value.size size failed.");
        return IPC_PROXY_ERR;
    }
    DRM_CHECK_AND_RETURN_RET_LOG(value.size() < DATA_MAX_LEN, DRM_MEMORY_ERROR,
        "The size of configuration value is too large.");
    if (value.size() != 0) {
        if (!data.WriteBuffer(value.data(), value.size())) {
            DRM_ERR_LOG("MediaKeySystemServiceProxy SetConfiguration write value failed.");
            return IPC_PROXY_ERR;
        }
    }

    int32_t ret = Remote()->SendRequest(MEDIA_KEY_SYSTEM_SETCONFIGURATION_BYTEARRAY, data, reply, option);
    if (ret != ERR_NONE) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy SetConfiguration failed, ret: %{public}d", ret);
        return ret;
    }

    DRM_INFO_LOG("MediaKeySystemServiceProxy::SetConfiguration exit.");
    return ret;
}

int32_t MediaKeySystemServiceProxy::GetConfigurationByteArray(std::string &configName, std::vector<uint8_t> &value)
{
    DRM_INFO_LOG("MediaKeySystemServiceProxy::GetConfiguration enter, configName:%{public}s.", configName.c_str());
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy GetConfiguration Write interface token failed.");
        return IPC_PROXY_ERR;
    }

    if (!data.WriteString(configName)) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy GetConfiguration Write configName failed.");
        return IPC_PROXY_ERR;
    }

    int32_t ret = Remote()->SendRequest(MEDIA_KEY_SYSTEM_GETCONFIGURATION_BYTEARRAY, data, reply, option);
    if (ret != ERR_NONE) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy GetConfiguration failed, ret: %{public}d", ret);
        return ret;
    }

    int32_t configSize = reply.ReadInt32();
    DRM_CHECK_AND_RETURN_RET_LOG(configSize < DATA_MAX_LEN, DRM_MEMORY_ERROR,
        "The size of configuration value is too large.");
    if (configSize != 0) {
        const uint8_t *valueBuf = static_cast<const uint8_t *>(reply.ReadBuffer(configSize));
        if (valueBuf == nullptr) {
            DRM_ERR_LOG("MediaKeySystemServiceProxy::GetConfigurationByteArray read response failed.");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        value.assign(valueBuf, valueBuf + configSize);
    }

    DRM_INFO_LOG("MediaKeySystemServiceProxy::GetConfiguration exit.");
    return ret;
}

int32_t MediaKeySystemServiceProxy::CreateMediaKeySession(IMediaKeySessionService::ContentProtectionLevel securityLevel,
    sptr<IMediaKeySessionService> &keySessionProxy)
{
    DRM_INFO_LOG("MediaKeySystemServiceProxy::CreateMediaKeySession enter, securityLevel:%{public}d.", securityLevel);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy CreateMediaKeySession Write interface token failed.");
        return IPC_PROXY_ERR;
    }
    if (!data.WriteInt32(securityLevel)) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy CreateMediaKeySession Write securityLevel failed.");
        return IPC_PROXY_ERR;
    }

    int32_t ret = Remote()->SendRequest(MEDIA_KEY_SYSTEM_CREATE_KEY_SESSION, data, reply, option);
    if (ret != ERR_NONE) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy::CreateMediaKeySession failed, ret: %{public}d", ret);
        return ret;
    }

    auto remoteObject = reply.ReadRemoteObject();
    if (remoteObject != nullptr) {
        keySessionProxy = iface_cast<IMediaKeySessionService>(remoteObject);
    } else {
        DRM_ERR_LOG("MediaKeySystemServiceProxy CreateMediaKeySession keySessionProxy is nullptr");
        ret = IPC_PROXY_ERR;
    }
    DRM_INFO_LOG("MediaKeySystemServiceProxy::CreateMediaKeySession exit.");
    return ret;
}

int32_t MediaKeySystemServiceProxy::GetStatistics(std::vector<IMediaKeySystemService::MetircKeyValue> &metrics)
{
    DRM_INFO_LOG("MediaKeySystemServiceProxy::GetStatistics enter.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy GetStatistics  Write interface token failed.");
        return IPC_PROXY_ERR;
    }

    int32_t ret = Remote()->SendRequest(MEDIA_KEY_SYSTEM_GETMETRIC, data, reply, option);
    if (ret != ERR_NONE) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy::GetStatistics failed, ret: %{public}d", ret);
        return ret;
    }
    int32_t metricsSize = reply.ReadInt32();
    for (int32_t i = 0; i < metricsSize; i++) {
        IMediaKeySystemService::MetircKeyValue keyValue;
        keyValue.name = reply.ReadString();
        keyValue.value = reply.ReadString();
        metrics.push_back(keyValue);
    }
    DRM_INFO_LOG("MediaKeySystemServiceProxy::GetStatistics exit.");
    return ret;
}

int32_t MediaKeySystemServiceProxy::GetOfflineMediaKeyIds(std::vector<std::vector<uint8_t>> &licenseIds)
{
    DRM_INFO_LOG("MediaKeySystemServiceProxy::GetOfflineMediaKeyIds enter.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(MediaKeySystemServiceProxy::GetDescriptor())) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy GetOfflineMediaKeyIds Write interface token failed.");
        return IPC_PROXY_ERR;
    }
    int32_t ret = Remote()->SendRequest(MEDIA_KEY_SYSTEM_GET_OFFLINELICENSEIDS, data, reply, option);
    if (ret != ERR_NONE) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy::GetOfflineMediaKeyIds failed, ret: %{public}d", ret);
        return ret;
    }
    int32_t licenseIdsSize = reply.ReadInt32();
    for (int32_t i = 0; i < licenseIdsSize; i++) {
        int32_t licenseIdSize = reply.ReadInt32();
        if (licenseIdSize == 0 || licenseIdSize > LICENSEID_MAX_LEN) {
            continue;
        }
        std::vector<uint8_t> licenseId;
        const uint8_t *licenseIdBuf = static_cast<const uint8_t *>(reply.ReadBuffer(licenseIdSize));
        if (licenseIdBuf == nullptr) {
            DRM_ERR_LOG("MediaKeySystemServiceProxy::GetOfflineMediaKeyIds ReadBuffer failed.");
            return IPC_PROXY_ERR;
        }
        licenseId.assign(licenseIdBuf, licenseIdBuf + licenseIdSize);
        licenseIds.push_back(licenseId);
    }
    DRM_INFO_LOG("MediaKeySystemServiceProxy::GetOfflineMediaKeyIds exit.");
    return ret;
}

int32_t MediaKeySystemServiceProxy::GetOfflineMediaKeyStatus(std::vector<uint8_t> &licenseId,
    IMediaKeySessionService::OfflineMediaKeyStatus &status)
{
    DRM_INFO_LOG("MediaKeySystemServiceProxy::GetOfflineMediaKeyStatus enter.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(MediaKeySystemServiceProxy::GetDescriptor())) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy GetOfflineMediaKeyStatus Write interface token failed.");
        return IPC_PROXY_ERR;
    }
    if (!data.WriteInt32(licenseId.size())) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy GetOfflineMediaKeyStatus Write licenseId size failed.");
        return IPC_PROXY_ERR;
    }
    DRM_CHECK_AND_RETURN_RET_LOG(licenseId.size() < LICENSEID_MAX_LEN, DRM_MEMORY_ERROR,
        "The size of licenseId is too large.");
    if (licenseId.size() != 0) {
        if (!data.WriteBuffer(licenseId.data(), licenseId.size())) {
            DRM_ERR_LOG("MediaKeySystemServiceProxy GetOfflineMediaKeyStatus write licenseId failed.");
            return IPC_PROXY_ERR;
        }
    }

    int32_t ret = Remote()->SendRequest(MEDIA_KEY_SYSTEM_GET_OFFLINEKEY_STATUS, data, reply, option);
    if (ret != ERR_NONE) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy::GetOfflineMediaKeyStatus failed, ret: %{public}d", ret);
        return ret;
    }
    status = (IMediaKeySessionService::OfflineMediaKeyStatus)reply.ReadInt32();
    DRM_INFO_LOG("MediaKeySystemServiceProxy::GetOfflineMediaKeyStatus exit.");
    return ret;
}

int32_t MediaKeySystemServiceProxy::ClearOfflineMediaKeys(std::vector<uint8_t> &licenseId)
{
    DRM_INFO_LOG("MediaKeySystemServiceProxy::ClearOfflineMediaKeys enter.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(MediaKeySystemServiceProxy::GetDescriptor())) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy ClearOfflineMediaKeys Write interface token failed.");
        return IPC_PROXY_ERR;
    }

    if (!data.WriteInt32(licenseId.size())) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy RestoreOfflineMediaKeys Write licenseId size failed.");
        return IPC_PROXY_ERR;
    }
    DRM_CHECK_AND_RETURN_RET_LOG(licenseId.size() < LICENSEID_MAX_LEN, DRM_MEMORY_ERROR,
        "The size of licenseId is too large.");
    if (licenseId.size() != 0) {
        if (!data.WriteBuffer(licenseId.data(), licenseId.size())) {
            DRM_ERR_LOG("MediaKeySystemServiceProxy ClearOfflineMediaKeys write licenseId failed.");
            return IPC_PROXY_ERR;
        }
    }

    int32_t ret = Remote()->SendRequest(MEDIA_KEY_SYSTEM_REMOVE_OFFLINELICENSE, data, reply, option);
    if (ret != ERR_NONE) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy::ClearOfflineMediaKeys failed, ret: %{public}d", ret);
        return ret;
    }

    DRM_INFO_LOG("MediaKeySystemServiceProxy::ClearOfflineMediaKeys exit.");
    return ret;
}

int32_t MediaKeySystemServiceProxy::SetCallback(sptr<IMeidaKeySystemServiceCallback> &callback)
{
    DRM_INFO_LOG("MediaKeySystemServiceProxy::SetCallback enter.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    DRM_CHECK_AND_RETURN_RET_LOG(callback != nullptr, IPC_PROXY_ERR, "callback is nullptr");

    bool result = data.WriteInterfaceToken(GetDescriptor());
    DRM_CHECK_AND_RETURN_RET_LOG(result, IPC_PROXY_ERR, "Write interface token failed.");
    result = data.WriteRemoteObject(callback->AsObject());
    DRM_CHECK_AND_RETURN_RET_LOG(result, IPC_PROXY_ERR, "write CameraServiceCallback obj failed.");

    int32_t ret = Remote()->SendRequest(MEDIA_KEY_SYSTEM_SETCALLBACK, data, reply, option);
    if (ret != ERR_NONE) {
        DRM_ERR_LOG("MediaKeySystemServiceProxy SetCallback failed, ret: %{public}d", ret);
    }
    return ret;
}
} // DrmStandard
} // OHOS
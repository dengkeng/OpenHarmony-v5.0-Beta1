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

#include "key_session_service_proxy.h"
#include "drm_log.h"
#include "remote_request_code.h"
#include "drm_error_code.h"

namespace OHOS {
namespace DrmStandard {
MediaKeySessionServiceProxy::MediaKeySessionServiceProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IMediaKeySessionService>(impl)
{
    DRM_INFO_LOG("MediaKeySessionServiceProxy::MediaKeySessionServiceProxy Initialized");
}

int32_t MediaKeySessionServiceProxy::CreateMediaDecryptModule(sptr<IMediaDecryptModuleService> &decryptModule)
{
    DRM_INFO_LOG("MediaKeySessionServiceProxy::CreateMediaDecryptModule enter.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy CreateMediaDecryptModule Write interface token failed.");
        return IPC_PROXY_ERR;
    }

    int32_t ret = MediaKeySessionServiceProxy::Remote()->SendRequest(CREATE_MEDIA_DECRYPT_MODULE, data, reply, option);
    if (ret != ERR_NONE) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy::CreateMediaDecryptModule failed, ret: %{public}d", ret);
        return ret;
    }

    auto remoteObject = reply.ReadRemoteObject();
    if (remoteObject != nullptr) {
        decryptModule = iface_cast<IMediaDecryptModuleService>(remoteObject);
    } else {
        DRM_ERR_LOG("MediaKeySessionServiceProxy CreateMediaDecryptModule decryptModule is nullptr");
        ret = IPC_PROXY_ERR;
    }
    DRM_INFO_LOG("MediaKeySessionServiceProxy::CreateMediaDecryptModule exit.");
    return ret;
}

int32_t MediaKeySessionServiceProxy::GetContentProtectionLevel(
    IMediaKeySessionService::ContentProtectionLevel *securityLevel)
{
    DRM_INFO_LOG("MediaKeySessionServiceProxy::GetContentProtectionLevel enter.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(MediaKeySessionServiceProxy::GetDescriptor())) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy GetContentProtectionLevel Write interface token failed.");
        return IPC_PROXY_ERR;
    }

    int32_t ret = Remote()->SendRequest(MEDIA_KEY_SESSION_GETSECURITYLEVEL, data, reply, option);
    if (ret != ERR_NONE) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy GetContentProtectionLevel failed, ret: %{public}d", ret);
        return ret;
    }

    *securityLevel = (IMediaKeySessionService::ContentProtectionLevel)reply.ReadInt32();

    DRM_INFO_LOG("MediaKeySessionServiceProxy::GetContentProtectionLevel exit.");
    return ret;
}

int32_t MediaKeySessionServiceProxy::Release()
{
    DRM_INFO_LOG("MediaKeySessionServiceProxy::Release enter.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy Release Write interface token failed.");
        return IPC_PROXY_ERR;
    }
    int32_t ret = MediaKeySessionServiceProxy::Remote()->SendRequest(KEY_SESSION_RELEASE, data, reply, option);
    if (ret != ERR_NONE) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy Release failed, ret: %{public}d", ret);
    }
    DRM_INFO_LOG("MediaKeySessionServiceProxy::Release exit.");
    return ret;
}

int32_t MediaKeySessionServiceProxy::GenerateMediaKeyRequest(
    IMediaKeySessionService::MediaKeyRequestInfo &licenseRequestInfo,
    IMediaKeySessionService::MediaKeyRequest &licenseRequest)
{
    DRM_INFO_LOG("MediaKeySessionServiceProxy::GenerateMediaKeyRequest enter.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(MediaKeySessionServiceProxy::GetDescriptor())) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy GenerateMediaKeyRequest Write interface token failed.");
        return IPC_PROXY_ERR;
    }

    if (!data.WriteInt32(licenseRequestInfo.optionalData.size())) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy GenerateMediaKeyRequest Write optionalData.size failed.");
        return IPC_PROXY_ERR;
    }
    DRM_CHECK_AND_RETURN_RET_LOG(licenseRequestInfo.optionalData.size() < DATA_MAX_LEN, DRM_MEMORY_ERROR,
        "The size of optionalData is too large.");
    for (auto optionalData : licenseRequestInfo.optionalData) {
        data.WriteString(optionalData.first);
        data.WriteString(optionalData.second);
    }
    if (!data.WriteInt32(licenseRequestInfo.mediaKeyType)) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy GenerateMediaKeyRequest Write licenseType failed.");
        return IPC_PROXY_ERR;
    }
    if (!data.WriteString(licenseRequestInfo.mimeType)) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy GenerateMediaKeyRequest Write mimeType failed.");
        return IPC_PROXY_ERR;
    }
    if (!data.WriteInt32(licenseRequestInfo.initData.size())) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy GenerateMediaKeyRequest Write initData.size failed.");
        return IPC_PROXY_ERR;
    }
    DRM_CHECK_AND_RETURN_RET_LOG(licenseRequestInfo.initData.size() < DATA_MAX_LEN, DRM_MEMORY_ERROR,
        "The size of initData is too large.");
    if (licenseRequestInfo.initData.size() != 0) {
        if (!data.WriteBuffer(licenseRequestInfo.initData.data(), licenseRequestInfo.initData.size())) {
            DRM_ERR_LOG("MediaKeySessionServiceProxy GenerateMediaKeyRequest Write initData.size failed.");
            return IPC_PROXY_ERR;
        }
    }
    int32_t ret = MediaKeySessionServiceProxy::Remote()->SendRequest(MEDIA_KEY_SESSION_GENERATE_LICENSE_REQUEST, data,
        reply, option);
    if (ret != ERR_NONE) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy::GenerateMediaKeyRequest failed, ret: %{public}d", ret);
        return ret;
    }
    licenseRequest.mDefaultURL = reply.ReadString();
    licenseRequest.requestType = (IMediaKeySessionService::RequestType)reply.ReadInt32();
    int32_t dataSize = reply.ReadInt32();
    DRM_CHECK_AND_RETURN_RET_LOG(dataSize < DATA_MAX_LEN, DRM_MEMORY_ERROR, "The size of initData is too large.");
    if (dataSize != 0) {
        const uint8_t *mDataBuf = static_cast<const uint8_t *>(reply.ReadBuffer(dataSize));
        if (mDataBuf == nullptr) {
            DRM_ERR_LOG("MediaKeySystemServiceProxy::GenerateMediaKeyRequest read licenseRequest.mData failed.");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        licenseRequest.mData.assign(mDataBuf, mDataBuf + dataSize);
    }
    DRM_INFO_LOG("MediaKeySessionServiceProxy::GenerateMediaKeyRequest exit.");
    return ret;
}

int32_t MediaKeySessionServiceProxy::ProcessMediaKeyResponse(std::vector<uint8_t> &licenseId,
    std::vector<uint8_t> &licenseResponse)
{
    DRM_INFO_LOG("MediaKeySessionServiceProxy::ProcessMediaKeyResponse enter.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(MediaKeySessionServiceProxy::GetDescriptor())) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy ProcessMediaKeyResponse Write interface token failed.");
        return IPC_PROXY_ERR;
    }
    if (!data.WriteInt32(licenseResponse.size())) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy ProcessMediaKeyResponse Write licenseResponse size failed.");
        return IPC_PROXY_ERR;
    }
    DRM_CHECK_AND_RETURN_RET_LOG(licenseResponse.size() < RESPONSE_MAX_LEN, DRM_MEMORY_ERROR,
        "The size of response is too large.");
    if (licenseResponse.size() != 0) {
        if (!data.WriteBuffer(licenseResponse.data(), licenseResponse.size())) {
            DRM_ERR_LOG("MediaKeySessionServiceProxy ProcessMediaKeyResponse write licenseResponse failed.");
            return IPC_PROXY_ERR;
        }
    }
    int32_t ret = MediaKeySessionServiceProxy::Remote()->SendRequest(MEDIA_KEY_SESSION_PROCESS_LICENSE_RESPONSE, data,
        reply, option);
    if (ret != ERR_NONE) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy::ProcessMediaKeyResponse failed, ret: %{public}d", ret);
        return ret;
    }
    int32_t licenseIdSize = reply.ReadInt32();
    DRM_CHECK_AND_RETURN_RET_LOG(licenseIdSize < LICENSEID_MAX_LEN, DRM_MEMORY_ERROR,
        "The size of licenseId is too large.");
    if (licenseIdSize != 0) {
        const uint8_t *licenseIdBuf = static_cast<const uint8_t *>(reply.ReadBuffer(licenseIdSize));
        if (licenseIdBuf == nullptr) {
            DRM_ERR_LOG("MediaKeySystemServiceProxy::ProcessMediaKeyResponse read licenseId failed.");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        licenseId.assign(licenseIdBuf, licenseIdBuf + licenseIdSize);
    }

    DRM_INFO_LOG("MediaKeySessionServiceProxy::ProcessMediaKeyResponse exit.");
    return ret;
}

int32_t MediaKeySessionServiceProxy::GenerateOfflineReleaseRequest(std::vector<uint8_t> &licenseId,
    std::vector<uint8_t> &releaseRequest)
{
    DRM_INFO_LOG("MediaKeySessionServiceProxy::GenerateOfflineReleaseRequest enter.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(MediaKeySessionServiceProxy::GetDescriptor())) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy GenerateOfflineReleaseRequest Write interface token failed.");
        return IPC_PROXY_ERR;
    }
    if (!data.WriteInt32(licenseId.size())) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy GenerateOfflineReleaseRequest Write licenseId size failed.");
        return IPC_PROXY_ERR;
    }
    DRM_CHECK_AND_RETURN_RET_LOG(licenseId.size() < LICENSEID_MAX_LEN, DRM_MEMORY_ERROR,
        "The size of licenseId is too large.");
    if (licenseId.size() != 0) {
        if (!data.WriteBuffer(licenseId.data(), licenseId.size())) {
            DRM_ERR_LOG("MediaKeySessionServiceProxy ProcessMediaKeyResponse write licenseId failed.");
            return IPC_PROXY_ERR;
        }
    }

    int32_t ret = MediaKeySessionServiceProxy::Remote()->SendRequest(MEDIA_KEY_SESSION_GENERATE_OFFLINE_RELEASE_REQUEST,
        data, reply, option);
    if (ret != ERR_NONE) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy::GenerateOfflineReleaseRequest failed, ret: %{public}d", ret);
        return ret;
    }
    int32_t requestSize = reply.ReadInt32();
    DRM_CHECK_AND_RETURN_RET_LOG(requestSize < REQUEST_MAX_LEN, DRM_MEMORY_ERROR, "The size of request is too large.");
    if (requestSize != 0) {
        const uint8_t *requestBuf = static_cast<const uint8_t *>(reply.ReadBuffer(requestSize));
        if (requestBuf == nullptr) {
            DRM_ERR_LOG("MediaKeySystemServiceProxy::ProcessMediaKeyResponse read licenseId failed.");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        releaseRequest.assign(requestBuf, requestBuf + requestSize);
    }
    DRM_INFO_LOG("MediaKeySessionServiceProxy::GenerateOfflineReleaseRequest exit.");
    return ret;
}

int32_t MediaKeySessionServiceProxy::ProcessOfflineReleaseResponse(std::vector<uint8_t> &licenseId,
    std::vector<uint8_t> &releaseReponse)
{
    DRM_INFO_LOG("MediaKeySessionServiceProxy::ProcessOfflineReleaseResponse enter.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(MediaKeySessionServiceProxy::GetDescriptor())) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy ProcessOfflineReleaseResponse Write interface token failed.");
        return IPC_PROXY_ERR;
    }

    if (!data.WriteInt32(licenseId.size())) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy ProcessOfflineReleaseResponse Write licenseId size failed.");
        return IPC_PROXY_ERR;
    }
    DRM_CHECK_AND_RETURN_RET_LOG(licenseId.size() < LICENSEID_MAX_LEN, DRM_MEMORY_ERROR,
        "The size of licenseId is too large.");
    if (licenseId.size() != 0) {
        if (!data.WriteBuffer(licenseId.data(), licenseId.size())) {
            DRM_ERR_LOG("MediaKeySessionServiceProxy ProcessOfflineReleaseResponse write licenseId failed.");
            return IPC_PROXY_ERR;
        }
    }
    if (!data.WriteInt32(releaseReponse.size())) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy ProcessOfflineReleaseResponse Write releaseReponse size failed.");
        return IPC_PROXY_ERR;
    }
    DRM_CHECK_AND_RETURN_RET_LOG(releaseReponse.size() < RESPONSE_MAX_LEN, DRM_MEMORY_ERROR,
        "The size of response is too large.");
    if (releaseReponse.size() != 0) {
        if (!data.WriteBuffer(releaseReponse.data(), releaseReponse.size())) {
            DRM_ERR_LOG("MediaKeySessionServiceProxy ProcessOfflineReleaseResponse write releaseReponse failed.");
            return IPC_PROXY_ERR;
        }
    }
    int32_t ret = MediaKeySessionServiceProxy::Remote()->SendRequest(MEDIA_KEY_SESSION_PROCESS_OFFLINE_RELEASE_RESPONSE,
        data, reply, option);
    if (ret != ERR_NONE) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy::ProcessOfflineReleaseResponse failed, ret: %{public}d", ret);
        return ret;
    }

    DRM_INFO_LOG("MediaKeySessionServiceProxy::ProcessOfflineReleaseResponse exit.");
    return ret;
}

int32_t MediaKeySessionServiceProxy::CheckMediaKeyStatus(std::map<std::string, std::string> &licenseStatus)
{
    DRM_INFO_LOG("MediaKeySessionServiceProxy::GenerateOfflineReleaseRequest enter.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(MediaKeySessionServiceProxy::GetDescriptor())) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy GenerateOfflineReleaseRequest Write interface token failed.");
        return IPC_PROXY_ERR;
    }

    int32_t ret = MediaKeySessionServiceProxy::Remote()->SendRequest(MEDIA_KEY_SESSION_GENERATE_CHECK_LICENSE_STATUS,
        data, reply, option);
    if (ret != ERR_NONE) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy::GenerateOfflineReleaseRequest failed, ret: %{public}d", ret);
        return ret;
    }
    int32_t licenseStatusMapSize = reply.ReadInt32();
    for (int32_t i = 0; i < licenseStatusMapSize; i++) {
        std::string name = reply.ReadString();
        std::string status = reply.ReadString();
        licenseStatus.insert(std::make_pair(name, status));
    }
    DRM_INFO_LOG("MediaKeySessionServiceProxy::GenerateOfflineReleaseRequest exit.");
    return ret;
}

int32_t MediaKeySessionServiceProxy::RestoreOfflineMediaKeys(std::vector<uint8_t> &licenseId)
{
    DRM_INFO_LOG("MediaKeySessionServiceProxy::RestoreOfflineMediaKeys enter.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(MediaKeySessionServiceProxy::GetDescriptor())) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy RestoreOfflineMediaKeys Write interface token failed.");
        return IPC_PROXY_ERR;
    }

    if (!data.WriteInt32(licenseId.size())) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy RestoreOfflineMediaKeys Write licenseId size failed.");
        return IPC_PROXY_ERR;
    }
    DRM_CHECK_AND_RETURN_RET_LOG(licenseId.size() < LICENSEID_MAX_LEN, DRM_MEMORY_ERROR,
        "The size of licenseId is too large.");
    if (licenseId.size() != 0) {
        if (!data.WriteBuffer(licenseId.data(), licenseId.size())) {
            DRM_ERR_LOG("MediaKeySessionServiceProxy RestoreOfflineMediaKeys write licenseId failed.");
            return IPC_PROXY_ERR;
        }
    }

    int32_t ret =
        MediaKeySessionServiceProxy::Remote()->SendRequest(MEDIA_KEY_SESSION_RESTORE_OFFLINEKEYS, data, reply, option);
    if (ret != ERR_NONE) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy::RestoreOfflineMediaKeys failed, ret: %{public}d", ret);
        return ret;
    }

    DRM_INFO_LOG("MediaKeySessionServiceProxy::RestoreOfflineMediaKeys exit.");
    return ret;
}

int32_t MediaKeySessionServiceProxy::ClearMediaKeys()
{
    DRM_INFO_LOG("MediaKeySessionServiceProxy::ClearMediaKeys enter.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(MediaKeySessionServiceProxy::GetDescriptor())) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy ClearMediaKeys Write interface token failed.");
        return IPC_PROXY_ERR;
    }

    int32_t ret =
        MediaKeySessionServiceProxy::Remote()->SendRequest(MEDIA_KEY_SESSION_REMOVE_LICENSE, data, reply, option);
    if (ret != ERR_NONE) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy::ClearMediaKeys failed, ret: %{public}d", ret);
        return ret;
    }

    DRM_INFO_LOG("MediaKeySessionServiceProxy::ClearMediaKeys exit.");
    return ret;
}

int32_t MediaKeySessionServiceProxy::RequireSecureDecoderModule(std::string &mimeType, bool *status)
{
    DRM_INFO_LOG("MediaKeySessionServiceProxy::RequireSecureDecoderModule enter.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy RequireSecureDecoderModule Write interface token failed.");
        return IPC_PROXY_ERR;
    }

    if (!data.WriteString(mimeType)) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy RequireSecureDecoderModule Write response failed.");
        return IPC_PROXY_ERR;
    }

    int32_t ret = Remote()->SendRequest(MEDIA_KEY_SESSION_REQUIRE_SECURE_DECODER, data, reply, option);
    if (ret != ERR_NONE) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy RequireSecureDecoderModule failed, ret: %{public}d", ret);
        return ret;
    }
    *status = reply.ReadBool();

    DRM_INFO_LOG("MediaKeySessionServiceProxy::RequireSecureDecoderModule exit.");
    return ret;
}

int32_t MediaKeySessionServiceProxy::SetListenerObject(const sptr<IRemoteObject> &object)
{
    DRM_INFO_LOG("MediaKeySessionServiceProxy::RequireSecureDecoderModule enter.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    (void)data.WriteRemoteObject(object);
    int error = Remote()->SendRequest(MEDIA_KEY_SESSION_SET_LISTENER_OBJ, data, reply, option);
    if (error != ERR_NONE) {
        DRM_ERR_LOG("Set listener obj failed, error: %{public}d", error);
        return IPC_PROXY_ERR;
    }
    DRM_INFO_LOG("MediaKeySessionServiceProxy::RequireSecureDecoderModule exit.");
    return reply.ReadInt32();
}

int32_t MediaKeySessionServiceProxy::SetCallback(sptr<IMediaKeySessionServiceCallback> &callback)
{
    DRM_INFO_LOG("MediaKeySessionServiceProxy::SetCallback enter.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (callback == nullptr) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy SetCallback callback is null");
        return IPC_PROXY_ERR;
    }

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy SetCallback Write interface token failed.");
        return IPC_PROXY_ERR;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy SetCallback write CameraServiceCallback obj failed.");
        return IPC_PROXY_ERR;
    }

    int32_t ret = Remote()->SendRequest(MEDIA_KEY_SESSION_SET_CALLBACK, data, reply, option);
    if (ret != ERR_NONE) {
        DRM_ERR_LOG("MediaKeySessionServiceProxy SetCallback failed, ret: %{public}d", ret);
    }
    return ret;
}
} // DrmStandard
} // OHOS
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

#include "ashmem.h"
#include "drm_error_code.h"
#include "media_decrypt_module_service_proxy.h"

namespace OHOS {
namespace DrmStandard {
MediaDecryptModuleServiceProxy::MediaDecryptModuleServiceProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IMediaDecryptModuleService>(impl)
{
    DRM_DEBUG_LOG("MediaDecryptModuleServiceProxy::MediaKeySystemServiceProxy Initialized.");
}

int32_t MediaDecryptModuleServiceProxy::Release()
{
    DRM_INFO_LOG("MediaDecryptModuleServiceProxy::Release enter.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DRM_ERR_LOG("MediaDecryptModuleServiceProxy Release Write interface token failed.");
        return IPC_PROXY_ERR;
    }

    int32_t ret = Remote()->SendRequest(DECRYPT_MODULE_RELEASE, data, reply, option);
    if (ret != ERR_NONE) {
        DRM_ERR_LOG("MediaDecryptModuleServiceProxy::Release failed, ret: %{public}d", ret);
        return ret;
    }

    DRM_INFO_LOG("MediaDecryptModuleServiceProxy::Release exit.");
    return ret;
}

int32_t MediaDecryptModuleServiceProxy::SetListenerObject(const sptr<IRemoteObject> &object)
{
    DRM_INFO_LOG("MediaDecryptModuleServiceProxy::SetListenerObject enter.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    (void)data.WriteRemoteObject(object);
    int error = Remote()->SendRequest(DECRYPT_MODULE_SET_LISTENER_OBJ, data, reply, option);
    if (error != ERR_NONE) {
        DRM_ERR_LOG("Set listener obj failed, error: %{public}d", error);
        return IPC_PROXY_ERR;
    }
    DRM_INFO_LOG("MediaDecryptModuleServiceProxy::SetListenerObject exit.");
    return reply.ReadInt32();
}

int32_t MediaDecryptModuleServiceProxy::ProcessDrmBuffer(MessageParcel &data,
    IMediaDecryptModuleService::DrmBuffer &srcBuffer, IMediaDecryptModuleService::DrmBuffer &dstBuffer)
{
    DRM_CHECK_AND_RETURN_RET_LOG(data.WriteUint32(srcBuffer.bufferType), IPC_PROXY_ERR,
        "MediaDecryptModuleServiceProxy DecryptMediaData Write srcBuffer.bufferType failed.");
    DRM_CHECK_AND_RETURN_RET_LOG(data.WriteFileDescriptor(srcBuffer.fd), IPC_PROXY_ERR,
        "MediaDecryptModuleServiceProxy DecryptMediaData Write srcBuffer.fd failed.");
    DRM_CHECK_AND_RETURN_RET_LOG(data.WriteUint32(srcBuffer.bufferLen), IPC_PROXY_ERR,
        "MediaDecryptModuleServiceProxy DecryptMediaData Write srcBuffer.bufferLen failed.");
    DRM_CHECK_AND_RETURN_RET_LOG(data.WriteUint32(srcBuffer.allocLen), IPC_PROXY_ERR,
        "MediaDecryptModuleServiceProxy DecryptMediaData Write srcBuffer.allocLen failed.");
    DRM_CHECK_AND_RETURN_RET_LOG(data.WriteUint32(srcBuffer.filledLen), IPC_PROXY_ERR,
        "MediaDecryptModuleServiceProxy DecryptMediaData Write srcBuffer.filledLen failed.");
    DRM_CHECK_AND_RETURN_RET_LOG(data.WriteUint32(srcBuffer.offset), IPC_PROXY_ERR,
        "MediaDecryptModuleServiceProxy DecryptMediaData Write srcBuffer.offset failed.");
    DRM_CHECK_AND_RETURN_RET_LOG(data.WriteUint32(srcBuffer.sharedMemType), IPC_PROXY_ERR,
        "MediaDecryptModuleServiceProxy DecryptMediaData Write srcBuffer.sharedMemType failed.");

    DRM_CHECK_AND_RETURN_RET_LOG(data.WriteUint32(dstBuffer.bufferType), IPC_PROXY_ERR,
        "MediaDecryptModuleServiceProxy DecryptMediaData Write dstBuffer.bufferType failed.");
    DRM_CHECK_AND_RETURN_RET_LOG(data.WriteFileDescriptor(dstBuffer.fd), IPC_PROXY_ERR,
        "MediaDecryptModuleServiceProxy DecryptMediaData Write dstBuffer.fd failed.");
    DRM_CHECK_AND_RETURN_RET_LOG(data.WriteUint32(dstBuffer.bufferLen), IPC_PROXY_ERR,
        "MediaDecryptModuleServiceProxy DecryptMediaData Write dstBuffer.bufferLen failed.");
    DRM_CHECK_AND_RETURN_RET_LOG(data.WriteUint32(dstBuffer.allocLen), IPC_PROXY_ERR,
        "MediaDecryptModuleServiceProxy DecryptMediaData Write dstBuffer.allocLen failed.");
    DRM_CHECK_AND_RETURN_RET_LOG(data.WriteUint32(dstBuffer.filledLen), IPC_PROXY_ERR,
        "MediaDecryptModuleServiceProxy DecryptMediaData Write dstBuffer.filledLen failed.");
    DRM_CHECK_AND_RETURN_RET_LOG(data.WriteUint32(dstBuffer.offset), IPC_PROXY_ERR,
        "MediaDecryptModuleServiceProxy DecryptMediaData Write dstBuffer.offset failed.");
    DRM_CHECK_AND_RETURN_RET_LOG(data.WriteUint32(dstBuffer.sharedMemType), IPC_PROXY_ERR,
        "MediaDecryptModuleServiceProxy DecryptMediaData Write dstBuffer.sharedMemType failed.");
    return DRM_OK;
}

int32_t MediaDecryptModuleServiceProxy::DecryptMediaData(bool secureDecodrtState,
    IMediaDecryptModuleService::CryptInfo &cryptInfo, IMediaDecryptModuleService::DrmBuffer &srcBuffer,
    IMediaDecryptModuleService::DrmBuffer &dstBuffer)
{
    DRM_INFO_LOG("MediaDecryptModuleServiceProxy::DecryptMediaData enter.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    DRM_CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), IPC_PROXY_ERR,
        "MediaDecryptModuleServiceProxy DecryptMediaData Write interface token failed.");

    DRM_CHECK_AND_RETURN_RET_LOG(data.WriteBool(secureDecodrtState), IPC_PROXY_ERR,
        "MediaDecryptModuleServiceProxy DecryptMediaData Write secureDecodrtState failed.");

    DRM_CHECK_AND_RETURN_RET_LOG(data.WriteUint32(cryptInfo.type), IPC_PROXY_ERR,
        "MediaDecryptModuleServiceProxy DecryptMediaData Write cryptInfo.type failed.");

    DRM_CHECK_AND_RETURN_RET_LOG(data.WriteUint32(cryptInfo.keyId.size()), IPC_PROXY_ERR,
        "MediaDecryptModuleServiceProxy DecryptMediaData Write cryptInfo.keyId size failed.");
    DRM_CHECK_AND_RETURN_RET_LOG(cryptInfo.keyId.size() < KEYID_MAX_LEN, DRM_MEMORY_ERROR,
        "The size of keyId is too large.");
    if (cryptInfo.keyId.size() != 0) {
        DRM_CHECK_AND_RETURN_RET_LOG(data.WriteBuffer(cryptInfo.keyId.data(), cryptInfo.keyId.size()), IPC_PROXY_ERR,
            "MediaDecryptModuleServiceProxy DecryptMediaData Write cryptInfo.keyId failed.");
    }

    DRM_CHECK_AND_RETURN_RET_LOG(data.WriteUint32(cryptInfo.iv.size()), IPC_PROXY_ERR,
        "MediaDecryptModuleServiceProxy DecryptMediaData Write cryptInfo.iv size failed.");
    DRM_CHECK_AND_RETURN_RET_LOG(cryptInfo.iv.size() < IV_MAX_LEN, DRM_MEMORY_ERROR, "The size of iv is too large.");

    if (cryptInfo.iv.size() != 0) {
        DRM_CHECK_AND_RETURN_RET_LOG(data.WriteBuffer(cryptInfo.iv.data(), cryptInfo.iv.size()), IPC_PROXY_ERR,
            "MediaDecryptModuleServiceProxy DecryptMediaData Write cryptInfo.iv failed.");
    }

    DRM_CHECK_AND_RETURN_RET_LOG(data.WriteUint32(cryptInfo.pattern.encryptBlocks), IPC_PROXY_ERR,
        "MediaDecryptModuleServiceProxy DecryptMediaData Write cryptInfo.pattern.encryptBlocks failed.");

    DRM_CHECK_AND_RETURN_RET_LOG(data.WriteUint32(cryptInfo.pattern.skipBlocks), IPC_PROXY_ERR,
        "MediaDecryptModuleServiceProxy DecryptMediaData Write cryptInfo.pattern.skipBlocks failed.");

    DRM_CHECK_AND_RETURN_RET_LOG(data.WriteUint32(cryptInfo.subSample.size()), IPC_PROXY_ERR,
        "MediaDecryptModuleServiceProxy DecryptMediaData Write cryptInfo.subSample size failed.");
    for (size_t i = 0; i < cryptInfo.subSample.size(); i++) {
        DRM_CHECK_AND_RETURN_RET_LOG(data.WriteUint32(cryptInfo.subSample[i].clearHeaderLen), IPC_PROXY_ERR,
            "MediaDecryptModuleServiceProxy DecryptMediaData Write cryptInfo.subSample.clearHeaderLen failed.");

        DRM_CHECK_AND_RETURN_RET_LOG(data.WriteUint32(cryptInfo.subSample[i].payLoadLen), IPC_PROXY_ERR,
            "MediaDecryptModuleServiceProxy DecryptMediaData Write cryptInfo.subSample.payLoadLen failed.");
    }
    int32_t ret = ProcessDrmBuffer(data, srcBuffer, dstBuffer);
    DRM_CHECK_AND_RETURN_RET_LOG(ret == DRM_OK, IPC_PROXY_ERR,
        "MediaDecryptModuleServiceProxy DecryptMediaData failed, ret: %{public}d", ret);

    ret = Remote()->SendRequest(DECRYPT_MODULE_DECRYPT_DATA, data, reply, option);
    DRM_CHECK_AND_RETURN_RET_LOG(ret == ERR_NONE, IPC_PROXY_ERR,
        "MediaDecryptModuleServiceProxy DecryptMediaData failed, ret: %{public}d", ret);

    DRM_INFO_LOG("MediaDecryptModuleServiceProxy::DecryptMediaData exit.");
    return ret;
}
} // DrmStandard
} // OHOS
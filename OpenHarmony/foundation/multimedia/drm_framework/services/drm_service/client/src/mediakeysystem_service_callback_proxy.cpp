/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "mediakeysystem_service_callback_proxy.h"
#include "drm_log.h"
#include "remote_request_code.h"

namespace OHOS {
namespace DrmStandard {
MediaKeySystemServiceCallbackProxy::MediaKeySystemServiceCallbackProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IMeidaKeySystemServiceCallback>(impl) {};

int32_t MediaKeySystemServiceCallbackProxy::SendEvent(DrmEventType event, int32_t extra,
    const std::vector<uint8_t> data)
{
    MessageParcel parcelData;
    MessageParcel reply;
    MessageOption option;
    DRM_INFO_LOG("MediaKeySystemServiceCallbackProxy SendEvent called, event:%{public}d", event);
    if (!parcelData.WriteInterfaceToken(GetDescriptor())) {
        DRM_ERR_LOG("MediaKeySystemServiceCallbackProxy SendEvent Write interface token failed.");
        return IPC_PROXY_ERR;
    }
    if (!parcelData.WriteInt32(event)) {
        DRM_ERR_LOG("MediaKeySystemServiceCallbackProxy SendEvent Write event failed.");
        return IPC_PROXY_ERR;
    }
    if (!parcelData.WriteInt32(extra)) {
        DRM_ERR_LOG("MediaKeySystemServiceCallbackProxy SendEvent Write extra failed.");
        return IPC_PROXY_ERR;
    }
    if (!parcelData.WriteUint32(data.size())) {
        DRM_ERR_LOG("MediaKeySystemServiceCallbackProxy SendEvent Write data size failed.");
        return IPC_PROXY_ERR;
    }
    for (auto item : data) {
        if (!parcelData.WriteUint8(item)) {
            DRM_ERR_LOG("MediaKeySystemServiceCallbackProxy SendEvent Write data failed.");
            return IPC_PROXY_ERR;
        }
    }
    int32_t error = Remote()->SendRequest(MEDIA_KEY_SYSTEM_SERVICE_CALLBACK_SEND_EVENT, parcelData, reply, option);
    if (error != ERR_NONE) {
        DRM_ERR_LOG("MediaKeySystemServiceCallbackProxy SendEvent failed, error: %{public}d", error);
    }
    return error;
}
} // namespace DrmStandard
} // namespace OHOS
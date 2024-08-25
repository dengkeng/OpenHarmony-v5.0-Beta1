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

#include "mediakeysystem_service_callback_stub.h"
#include "remote_request_code.h"
#include "drm_log.h"
#include "drm_error_code.h"

namespace OHOS {
namespace DrmStandard {
int32_t MeidaKeySystemServiceCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    int32_t errCode = DRM_ERROR;

    if (data.ReadInterfaceToken() != GetDescriptor()) {
        return errCode;
    }
    switch (code) {
        case MEDIA_KEY_SYSTEM_SERVICE_CALLBACK_SEND_EVENT:
            errCode = MeidaKeySystemServiceCallbackStub::HandleSendEvent(data);
            break;
        default:
            DRM_ERR_LOG("MeidaKeySystemServiceCallbackStub request code %{public}u not handled", code);
            errCode = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
    }
    return errCode;
}

int32_t MeidaKeySystemServiceCallbackStub::HandleSendEvent(MessageParcel &data)
{
    DRM_INFO_LOG("MeidaKeySystemServiceCallbackStub HandleSendEvent enter.");
    int32_t event = data.ReadInt32();
    int32_t extra = data.ReadInt32();
    uint32_t dataSize = data.ReadUint32();
    DRM_CHECK_AND_RETURN_RET_LOG(dataSize < DATA_MAX_LEN, DRM_MEMORY_ERROR,
        "The size of event data is too large.");
    std::vector<uint8_t> customizedData;
    for (uint32_t i = 0; i < dataSize; i++) {
        customizedData.emplace_back(data.ReadUint8());
    }
    DrmEventType eventType = static_cast<DrmEventType>(event);
    return SendEvent(eventType, extra, customizedData);
}
} // namespace DrmStandard
} // namespace OHOS

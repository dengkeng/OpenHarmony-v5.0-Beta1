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

#ifndef OHOS_DRM_I_MEDIA_KEY_SYSTEM_FACTORY_SERVICE_H
#define OHOS_DRM_I_MEDIA_KEY_SYSTEM_FACTORY_SERVICE_H

#include "i_mediakeysystem_service.h"
#include "ipc_types.h"
#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"

namespace OHOS {
namespace DrmStandard {
const size_t ARGS_NUM_ONE = 1;
const size_t ARGS_NUM_TWO = 2;
const size_t ARGS_NUM_THREE = 3;

class IMediaKeySystemFactoryService : public IRemoteBroker {
public:
    struct MediaKeySystemMapInfo {
        std::string name;
        std::string uuid;
    };

    virtual ~IMediaKeySystemFactoryService() = default;
    virtual int32_t IsMediaKeySystemSupported(std::string &uuid, bool *isSurpported) = 0;
    virtual int32_t IsMediaKeySystemSupported(std::string &uuid, std::string &mimeType, bool *isSurpported) = 0;
    virtual int32_t IsMediaKeySystemSupported(std::string &uuid, std::string &mimeType, int32_t securityLevel,
        bool *isSurpported) = 0;
    virtual int32_t GetMediaKeySystemName(std::map<std::string, std::string> &keySystemNames) = 0;
    virtual int32_t GetMediaKeySystemUuid(std::string &name, std::string &uuid) = 0;
    virtual int32_t CreateMediaKeySystem(std::string &uuid, sptr<IMediaKeySystemService> &mediaKeySystemProxy) = 0;
    virtual int32_t SetListenerObject(const sptr<IRemoteObject> &object) = 0;

    DECLARE_INTERFACE_DESCRIPTOR(u"IMediaKeySystemSystemFactoryService");
};
} // DrmStandard
} // OHOS
#endif // OHOS_DRM_I_MEDIA_KEY_SYSTEM_FACTORY_SERVICE_H

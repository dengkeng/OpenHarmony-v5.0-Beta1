/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_I_AV_SENDER_ENGINE_CALLBACK_H
#define OHOS_I_AV_SENDER_ENGINE_CALLBACK_H

#include "av_trans_errno.h"
#include "av_trans_message.h"
#include "av_trans_types.h"

namespace OHOS {
namespace DistributedHardware {
/**
 * @brief AV sender engine callback interface.
 *
 * AV sender engine callback is used to receive the engine state change events and message notification.
 *
 * @since 1.0
 * @version 1.0
 */
class IAVSenderEngineCallback {
public:
    /**
     * @brief Destructor.
     * @return No return value.
     */
    virtual ~IAVSenderEngineCallback() = default;

    /**
     * @brief Report the engine state change events to the distributed service.
     * @param event  event content.
     * @return Returns DH_AVT_SUCCESS(0) if successful, otherwise returns other error code.
     */
    virtual int32_t OnSenderEvent(const AVTransEvent &event) = 0;

    /**
     * @brief Report the engine message to the distributed service.
     * @param message  message content.
     * @return Returns DH_AVT_SUCCESS(0) if successful, otherwise returns other error code.
     */
    virtual int32_t OnMessageReceived(const std::shared_ptr<AVTransMessage> &message) = 0;
};
} // DistributedHardware
} // OHOS
#endif // OHOS_I_AV_SENDER_ENGINE_CALLBACK_H
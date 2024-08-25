/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "ims_sms.h"

#include "ims_radio_event.h"
#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {
ImsSms::ImsSms() {}

ImsSms::~ImsSms() {}

bool ImsSms::Init()
{
    TELEPHONY_LOGI("ImsSms Init");

    if (!CreateEventLoop("ImsSmsLoop")) {
        TELEPHONY_LOGE("ImsSms::CreateEventLoop failed");
        return false;
    }
    TELEPHONY_LOGI("ImsSms:Init success");
    return true;
}

int32_t ImsSms::ImsSendMessage(int32_t slotId, const ImsMessageInfo &imsMessageInfo)
{
    // IMS demo send request info

    // IMS demo callback response info
    std::lock_guard<std::mutex> lock(mutex_);
    SendSmsResultInfo result;
    if (imsSmsCallback_ == nullptr) {
        TELEPHONY_LOGE("imsSmsCallback_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsSmsCallback_->ImsSendMessageResponse(slotId, result);
    return TELEPHONY_SUCCESS;
}

int32_t ImsSms::ImsSetSmsConfig(int32_t slotId, int32_t imsSmsConfig)
{
    // IMS demo send request info

    // IMS demo callback response info
    std::lock_guard<std::mutex> lock(mutex_);
    RadioResponseInfo info;
    if (imsSmsCallback_ == nullptr) {
        TELEPHONY_LOGE("imsSmsCallback_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsSmsCallback_->ImsSetSmsConfigResponse(slotId, info);
    return TELEPHONY_SUCCESS;
}

int32_t ImsSms::ImsGetSmsConfig(int32_t slotId)
{
    // IMS demo send request info

    // IMS demo callback response info
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t imsSmsConfig = 0;
    if (imsSmsCallback_ == nullptr) {
        TELEPHONY_LOGE("imsSmsCallback_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsSmsCallback_->ImsGetSmsConfigResponse(slotId, imsSmsConfig);
    return TELEPHONY_SUCCESS;
}

int32_t ImsSms::RegisterImsSmsCallback(const sptr<ImsSmsCallbackInterface> &callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    imsSmsCallback_ = callback;
    return TELEPHONY_SUCCESS;
}
} // namespace Telephony
} // namespace OHOS

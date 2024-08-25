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

#include "ims_test_handler.h"

#include "ims_call_client.h"
#include "ims_core_service_client.h"
#include "ims_sms_client.h"
#include "singleton.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
const int32_t DEFAULT_SLOT_ID = 0;

void ImsTestHandler::RegisterImsCall()
{
    std::shared_ptr<ImsCallClient> imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
    if (imsCallClient != nullptr) {
        imsCallClient->RegisterImsCallCallbackHandler(DEFAULT_SLOT_ID, shared_from_this());
    }
}

void ImsTestHandler::RegisterImsSms()
{
    std::shared_ptr<ImsSmsClient> imsSmsClient = DelayedSingleton<ImsSmsClient>::GetInstance();
    if (imsSmsClient != nullptr) {
        imsSmsClient->RegisterImsSmsCallbackHandler(DEFAULT_SLOT_ID, shared_from_this());
    }
}

void ImsTestHandler::RegisterImsCoreService()
{
    std::shared_ptr<ImsCoreServiceClient> imsCoreServiceClient = DelayedSingleton<ImsCoreServiceClient>::GetInstance();
    if (imsCoreServiceClient != nullptr) {
        imsCoreServiceClient->RegisterImsCoreServiceCallbackHandler(DEFAULT_SLOT_ID, shared_from_this());
    }
}

void ImsTestHandler::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGE("ImsTestHandler::ProcessEvent!");
}
} // namespace Telephony
} // namespace OHOS
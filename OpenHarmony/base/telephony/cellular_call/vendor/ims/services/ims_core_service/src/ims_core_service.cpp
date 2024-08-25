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
#include "ims_core_service.h"

#include "ims_radio_event.h"
#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {
bool g_registerResult = SystemAbility::MakeAndRegisterAbility(DelayedSingleton<ImsCoreService>::GetInstance().get());

ImsCoreService::ImsCoreService()
    : SystemAbility(TELEPHONY_IMS_SYS_ABILITY_ID, true), state_(ServiceRunningState::STATE_STOPPED), imsCall_(nullptr),
      imsSms_(nullptr)
{}

ImsCoreService::~ImsCoreService()
{
    if (imsCall_ != nullptr) {
        delete imsCall_;
        imsCall_ = nullptr;
    }
    if (imsSms_ != nullptr) {
        delete imsSms_;
        imsSms_ = nullptr;
    }
    state_ = ServiceRunningState::STATE_STOPPED;
}

void ImsCoreService::OnStart()
{
    TELEPHONY_LOGI("OnStart");
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        TELEPHONY_LOGI("ImsCoreService is already running");
        return;
    }
    if (!Init()) {
        TELEPHONY_LOGE("ImsCoreService init fail.");
        return;
    }
    bool ret = Publish(DelayedSingleton<ImsCoreService>::GetInstance().get());
    if (!ret) {
        TELEPHONY_LOGE("ImsCoreService publish failed!");
        return;
    }
    TELEPHONY_LOGI("ImsCoreService start success.");
    state_ = ServiceRunningState::STATE_RUNNING;
}

void ImsCoreService::OnStop()
{
    TELEPHONY_LOGI("OnStop");
    state_ = ServiceRunningState::STATE_STOPPED;
}

bool ImsCoreService::Init()
{
    if (!CreateEventLoop("ImsCoreServiceLoop")) {
        TELEPHONY_LOGE("ImsCoreService::CreateEventLoop failed");
        return false;
    }
    if (!InitSubService()) {
        TELEPHONY_LOGE("Init Subservice failed");
        return false;
    }
    TELEPHONY_LOGI("ImsCoreService:Init success");
    return true;
}

bool ImsCoreService::InitSubService()
{
    imsCall_ = new ImsCall();
    if (imsCall_ == nullptr) {
        TELEPHONY_LOGE("create ImsCall object failed!");
        return false;
    }
    if (!imsCall_->Init()) {
        TELEPHONY_LOGE("Ims call service init failed");
        return false;
    }

    imsSms_ = new ImsSms();
    if (imsSms_ == nullptr) {
        TELEPHONY_LOGE("create ImsSms object failed!");
        return false;
    }
    if (!imsSms_->Init()) {
        TELEPHONY_LOGE("Ims sms service init failed");
        return false;
    }

    TELEPHONY_LOGI("create ImsSms object success!");
    return true;
}

int32_t ImsCoreService::GetImsRegistrationStatus(int32_t slotId)
{
    // IMS demo send request info

    // IMS demo callback response info
    ImsRegistrationStatus imsRegStatus;
    if (imsCoreServiceCallback_ == nullptr) {
        TELEPHONY_LOGE("imsCoreServiceCallback_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCoreServiceCallback_->GetImsRegistrationStatusResponse(slotId, imsRegStatus);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCoreService::RegisterImsCoreServiceCallback(const sptr<ImsCoreServiceCallbackInterface> &callback)
{
    TELEPHONY_LOGI("Register IMS coreservice callback");
    imsCoreServiceCallback_ = callback;
    return TELEPHONY_SUCCESS;
}

sptr<IRemoteObject> ImsCoreService::GetProxyObjectPtr(ImsServiceProxyType proxyType)
{
    switch (proxyType) {
        case ImsServiceProxyType::PROXY_IMS_CALL:
            if (imsCall_ == nullptr) {
                break;
            }
            TELEPHONY_LOGI("GetProxyObjectPtr success! proxyType:%{public}d", proxyType);
            return imsCall_->AsObject().GetRefPtr();
        case ImsServiceProxyType::PROXY_IMS_SMS:
            if (imsSms_ == nullptr) {
                break;
            }
            TELEPHONY_LOGI("GetProxyObjectPtr success! proxyType:%{public}d", proxyType);
            return imsSms_->AsObject().GetRefPtr();
        default:
            break;
    }

    TELEPHONY_LOGE("GetProxyObjectPtr failed! proxyType:%{public}d", proxyType);
    return nullptr;
}
} // namespace Telephony
} // namespace OHOS

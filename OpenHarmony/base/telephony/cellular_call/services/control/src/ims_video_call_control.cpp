/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "ims_video_call_control.h"

#include "cellular_call_hisysevent.h"
#include "ims_call_client.h"
#include "securec.h"

namespace OHOS {
namespace Telephony {
const int32_t INVALID_VALUE = -1;

ImsVideoCallControl::ImsVideoCallControl()
{
    TELEPHONY_LOGD("ImsVideoCallControl start");
}

ImsVideoCallControl::~ImsVideoCallControl()
{
    TELEPHONY_LOGD("~ImsVideoCallControl start");
}

int32_t ImsVideoCallControl::ControlCamera(int32_t slotId, int32_t callIndex, const std::string &cameraId)
{
    if (moduleUtils_.NeedCallImsService()) {
        auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
        if (imsCallClient == nullptr || imsCallClient->GetImsCallProxy() == nullptr) {
            TELEPHONY_LOGE("ImsCallClient is nullptr or ims service SA not exists.");
            return CALL_ERR_RESOURCE_UNAVAILABLE;
        }
        return imsCallClient->ControlCamera(slotId, callIndex, cameraId);
    }
    TELEPHONY_LOGI("ims vendor service does not exist.");
    return TELEPHONY_ERROR;
}

int32_t ImsVideoCallControl::SetPreviewWindow(
    int32_t slotId, int32_t callIndex, const std::string &surfaceID, sptr<Surface> surface)
{
    if (moduleUtils_.NeedCallImsService()) {
        auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
        if (imsCallClient == nullptr || imsCallClient->GetImsCallProxy() == nullptr) {
            TELEPHONY_LOGE("ImsCallClient is nullptr or ims service SA not exists.");
            return CALL_ERR_RESOURCE_UNAVAILABLE;
        }
        return imsCallClient->SetPreviewWindow(slotId, callIndex, surfaceID, surface);
    }
    TELEPHONY_LOGI("ims vendor service does not exist.");
    return TELEPHONY_ERROR;
}

int32_t ImsVideoCallControl::SetDisplayWindow(
    int32_t slotId, int32_t callIndex, const std::string &surfaceID, sptr<Surface> surface)
{
    if (moduleUtils_.NeedCallImsService()) {
        auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
        if (imsCallClient == nullptr || imsCallClient->GetImsCallProxy() == nullptr) {
            TELEPHONY_LOGE("ImsCallClient is nullptr or ims service SA not exists.");
            return CALL_ERR_RESOURCE_UNAVAILABLE;
        }
        return imsCallClient->SetDisplayWindow(slotId, callIndex, surfaceID, surface);
    }
    TELEPHONY_LOGI("ims vendor service does not exist.");
    return TELEPHONY_ERROR;
}

int32_t ImsVideoCallControl::SetCameraZoom(float zoomRatio)
{
    if (moduleUtils_.NeedCallImsService()) {
        auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
        if (imsCallClient == nullptr || imsCallClient->GetImsCallProxy() == nullptr) {
            TELEPHONY_LOGE("ImsCallClient is nullptr or ims service SA not exists.");
            return CALL_ERR_RESOURCE_UNAVAILABLE;
        }
        return imsCallClient->SetCameraZoom(zoomRatio);
    }
    TELEPHONY_LOGI("ims vendor service does not exist.");
    return TELEPHONY_ERROR;
}

int32_t ImsVideoCallControl::SetPausePicture(int32_t slotId, int32_t callIndex, const std::string &path)
{
    if (moduleUtils_.NeedCallImsService()) {
        auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
        if (imsCallClient == nullptr || imsCallClient->GetImsCallProxy() == nullptr) {
            TELEPHONY_LOGE("ImsCallClient is nullptr or ims service SA not exists.");
            return CALL_ERR_RESOURCE_UNAVAILABLE;
        }
        return imsCallClient->SetPausePicture(slotId, callIndex, path);
    }
    TELEPHONY_LOGI("ims vendor service does not exist.");
    return TELEPHONY_ERROR;
}

int32_t ImsVideoCallControl::SetDeviceDirection(int32_t slotId, int32_t callIndex, int32_t rotation)
{
    if (moduleUtils_.NeedCallImsService()) {
        auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
        if (imsCallClient == nullptr || imsCallClient->GetImsCallProxy() == nullptr) {
            TELEPHONY_LOGE("ImsCallClient is nullptr or ims service SA not exists.");
            return CALL_ERR_RESOURCE_UNAVAILABLE;
        }
        return imsCallClient->SetDeviceDirection(slotId, callIndex, rotation);
    }
    TELEPHONY_LOGI("ims vendor service does not exist.");
    return TELEPHONY_ERROR;
}

int32_t ImsVideoCallControl::SendUpdateCallMediaModeRequest(const CellularCallInfo &callInfo, ImsCallMode mode)
{
    if (moduleUtils_.NeedCallImsService()) {
        TELEPHONY_LOGI("call ims service");
        struct CallBehaviorParameterInfo info = { 0 };
        auto callHiSysEvent = DelayedSingleton<CellularCallHiSysEvent>::GetInstance();
        if (callHiSysEvent == nullptr) {
            TELEPHONY_LOGE("CellularCallHiSysEvent is null.");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        callHiSysEvent->GetCallParameterInfo(info);
        info.videoState = static_cast<ImsCallMode>(mode);
        CellularCallHiSysEvent::WriteImsCallModeBehaviorEvent(
            CallModeBehaviorType::SEND_REQUEST_EVENT, info, INVALID_VALUE);
        ImsCallInfo imsCallInfo;
        if (memset_s(&imsCallInfo, sizeof(imsCallInfo), 0, sizeof(imsCallInfo)) != EOK) {
            TELEPHONY_LOGE("return, memset_s error.");
            return TELEPHONY_ERR_MEMSET_FAIL;
        }
        if (static_cast<int32_t>(strlen(callInfo.phoneNum) + 1) > kMaxNumberLen) {
            return TELEPHONY_ERR_STRCPY_FAIL;
        }
        errno_t result = strcpy_s(imsCallInfo.phoneNum, strlen(callInfo.phoneNum) + 1, callInfo.phoneNum);
        if (result != EOK) {
            TELEPHONY_LOGE("return, strcpy_s fail.");
            return TELEPHONY_ERR_STRCPY_FAIL;
        }
        imsCallInfo.slotId = callInfo.slotId;
        imsCallInfo.index = callInfo.index;
        imsCallInfo.videoState = callInfo.videoState;
        auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
        if (imsCallClient == nullptr || imsCallClient->GetImsCallProxy() == nullptr) {
            TELEPHONY_LOGE("ImsCallClient is nullptr or ims service SA not exists.");
            return CALL_ERR_RESOURCE_UNAVAILABLE;
        }
        ImsCallType imsCallType = ConverToImsCallType(mode);
        return imsCallClient->SendUpdateCallMediaModeRequest(imsCallInfo, imsCallType);
    }
    TELEPHONY_LOGI("ims vendor service does not exist.");
    return TELEPHONY_ERROR;
}

int32_t ImsVideoCallControl::SendUpdateCallMediaModeResponse(const CellularCallInfo &callInfo, ImsCallMode mode)
{
    if (moduleUtils_.NeedCallImsService()) {
        TELEPHONY_LOGI("call ims service");
        struct CallBehaviorParameterInfo info = { 0 };
        auto callHiSysEvent = DelayedSingleton<CellularCallHiSysEvent>::GetInstance();
        if (callHiSysEvent == nullptr) {
            TELEPHONY_LOGE("CellularCallHiSysEvent is null.");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        callHiSysEvent->GetCallParameterInfo(info);
        info.videoState = static_cast<ImsCallMode>(mode);
        CellularCallHiSysEvent::WriteImsCallModeBehaviorEvent(
            CallModeBehaviorType::SEND_RESPONSE_EVENT, info, INVALID_VALUE);
        ImsCallInfo imsCallInfo;
        if (memset_s(&imsCallInfo, sizeof(imsCallInfo), 0, sizeof(imsCallInfo)) != EOK) {
            TELEPHONY_LOGE("return, memset_s error.");
            return TELEPHONY_ERR_MEMSET_FAIL;
        }
        if (static_cast<int32_t>(strlen(callInfo.phoneNum) + 1) > kMaxNumberLen) {
            return TELEPHONY_ERR_STRCPY_FAIL;
        }
        errno_t result = strcpy_s(imsCallInfo.phoneNum, strlen(callInfo.phoneNum) + 1, callInfo.phoneNum);
        if (result != EOK) {
            TELEPHONY_LOGE("return, strcpy_s fail.");
            return TELEPHONY_ERR_STRCPY_FAIL;
        }
        imsCallInfo.slotId = callInfo.slotId;
        imsCallInfo.index = callInfo.index;
        imsCallInfo.videoState = callInfo.videoState;
        auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
        if (imsCallClient == nullptr || imsCallClient->GetImsCallProxy() == nullptr) {
            TELEPHONY_LOGE("ImsCallClient is nullptr or ims service SA not exists.");
            return CALL_ERR_RESOURCE_UNAVAILABLE;
        }
        ImsCallType imsCallType = ConverToImsCallType(mode);
        return imsCallClient->SendUpdateCallMediaModeResponse(imsCallInfo, imsCallType);
    }
    TELEPHONY_LOGI("ims vendor service does not exist.");
    return TELEPHONY_ERROR;
}

int32_t ImsVideoCallControl::CancelCallUpgrade(int32_t slotId, int32_t callIndex)
{
    if (moduleUtils_.NeedCallImsService()) {
        auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
        if (imsCallClient == nullptr || imsCallClient->GetImsCallProxy() == nullptr) {
            TELEPHONY_LOGE("ImsCallClient is nullptr or ims service SA not exists.");
            return CALL_ERR_RESOURCE_UNAVAILABLE;
        }
        return imsCallClient->CancelCallUpgrade(slotId, callIndex);
    }
    TELEPHONY_LOGI("ims vendor service does not exist.");
    return TELEPHONY_ERROR;
}

int32_t ImsVideoCallControl::RequestCameraCapabilities(int32_t slotId, int32_t callIndex)
{
    if (moduleUtils_.NeedCallImsService()) {
        auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
        if (imsCallClient == nullptr || imsCallClient->GetImsCallProxy() == nullptr) {
            TELEPHONY_LOGE("ImsCallClient is nullptr or ims service SA not exists.");
            return CALL_ERR_RESOURCE_UNAVAILABLE;
        }
        return imsCallClient->RequestCameraCapabilities(slotId, callIndex);
    }
    TELEPHONY_LOGI("ims vendor service does not exist.");
    return TELEPHONY_ERROR;
}

ImsCallType ImsVideoCallControl::ConverToImsCallType(ImsCallMode mode)
{
    ImsCallType callType = ImsCallType::TEL_IMS_CALL_TYPE_VOICE;
    switch (mode) {
        case ImsCallMode::CALL_MODE_AUDIO_ONLY:
            callType = ImsCallType::TEL_IMS_CALL_TYPE_VOICE;
            break;
        case ImsCallMode::CALL_MODE_RECEIVE_ONLY:
            callType = ImsCallType::TEL_IMS_CALL_TYPE_VT_RX;
            break;
        case ImsCallMode::CALL_MODE_SEND_ONLY:
            callType = ImsCallType::TEL_IMS_CALL_TYPE_VT_TX;
            break;
        case ImsCallMode::CALL_MODE_SEND_RECEIVE:
            callType = ImsCallType::TEL_IMS_CALL_TYPE_VT;
            break;
        case ImsCallMode::CALL_MODE_VIDEO_PAUSED:
            callType = ImsCallType::TEL_IMS_CALL_TYPE_PAUSE;
            break;
        default:
            callType = ImsCallType::TEL_IMS_CALL_TYPE_VOICE;
    }
    return callType;
}
} // namespace Telephony
} // namespace OHOS
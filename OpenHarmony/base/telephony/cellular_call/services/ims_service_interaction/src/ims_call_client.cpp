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

#include "ims_call_client.h"

#include "cellular_call_hisysevent.h"
#include "ims_call_callback_stub.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
ImsCallClient::ImsCallClient() = default;

ImsCallClient::~ImsCallClient()
{
    UnInit();
}

void ImsCallClient::Init()
{
    TELEPHONY_LOGI("Init start");
    if (IsConnect()) {
        TELEPHONY_LOGE("Init, IsConnect return true");
        return;
    }

    GetImsCallProxy();
    if (imsCallProxy_ == nullptr) {
        TELEPHONY_LOGE("Init, get ims call proxy failed!");
    }

    statusChangeListener_ = new (std::nothrow) SystemAbilityListener();
    if (statusChangeListener_ == nullptr) {
        TELEPHONY_LOGE("Init, failed to create statusChangeListener.");
        return;
    }
    auto managerPtr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (managerPtr == nullptr) {
        TELEPHONY_LOGE("Init, get system ability manager error.");
        return;
    }
    int32_t ret = managerPtr->SubscribeSystemAbility(TELEPHONY_IMS_SYS_ABILITY_ID, statusChangeListener_);
    if (ret) {
        TELEPHONY_LOGE("Init, failed to subscribe sa:%{public}d", TELEPHONY_IMS_SYS_ABILITY_ID);
        return;
    }
    TELEPHONY_LOGI("Init successfully");
}

void ImsCallClient::UnInit()
{
    Clean();
    if (statusChangeListener_ != nullptr) {
        statusChangeListener_.clear();
        statusChangeListener_ = nullptr;
    }
    handlerMap_.clear();
}

sptr<ImsCallInterface> ImsCallClient::GetImsCallProxy()
{
    Utils::UniqueWriteGuard<Utils::RWLock> guard(rwClientLock_);
    if (imsCallProxy_ != nullptr) {
        return imsCallProxy_;
    }
    auto managerPtr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (managerPtr == nullptr) {
        TELEPHONY_LOGE("GetImsCallProxy return, get system ability manager error.");
        return nullptr;
    }
    auto remoteObjectPtr = managerPtr->CheckSystemAbility(TELEPHONY_IMS_SYS_ABILITY_ID);
    if (remoteObjectPtr == nullptr) {
        TELEPHONY_LOGE("GetImsCallProxy return, remote service not exists.");
        return nullptr;
    }
    imsCoreServiceProxy_ = iface_cast<ImsCoreServiceInterface>(remoteObjectPtr);
    if (imsCoreServiceProxy_ == nullptr) {
        TELEPHONY_LOGE("GetImsCallProxy return, imsCoreServiceProxy_ is nullptr.");
        return nullptr;
    }
    sptr<IRemoteObject> imsCallRemoteObjectPtr = imsCoreServiceProxy_->GetProxyObjectPtr(PROXY_IMS_CALL);
    if (imsCallRemoteObjectPtr == nullptr) {
        TELEPHONY_LOGE("GetImsCallProxy return, ImsCallRemoteObjectPtr is nullptr.");
        return nullptr;
    }

    imsCallProxy_ = iface_cast<ImsCallInterface>(imsCallRemoteObjectPtr);
    if (imsCallProxy_ == nullptr) {
        TELEPHONY_LOGE("GetImsCallProxy return, iface_cast<imsCallProxy_> failed!");
        return nullptr;
    }
    // register callback
    RegisterImsCallCallback();
    TELEPHONY_LOGI("GetImsCallProxy success.");
    return imsCallProxy_;
}

bool ImsCallClient::IsConnect() const
{
    return (imsCallProxy_ != nullptr);
}

int32_t ImsCallClient::RegisterImsCallCallback()
{
    if (imsCallProxy_ == nullptr) {
        TELEPHONY_LOGE("imsCallProxy_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCallCallback_ = (std::make_unique<ImsCallCallbackStub>()).release();
    if (imsCallCallback_ == nullptr) {
        TELEPHONY_LOGE("RegisterImsCallCallback return, make unique error.");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t ret = imsCallProxy_->RegisterImsCallCallback(imsCallCallback_);
    if (ret) {
        TELEPHONY_LOGE("RegisterImsCallCallback return, register callback error.");
        return TELEPHONY_ERR_FAIL;
    }
    TELEPHONY_LOGI("RegisterImsCallCallback success.");
    return TELEPHONY_SUCCESS;
}

int32_t ImsCallClient::RegisterImsCallCallbackHandler(
    int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (handler == nullptr) {
        TELEPHONY_LOGE("RegisterImsCallCallbackHandler return, handler is null.");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    handlerMap_.insert(std::make_pair(slotId, handler));
    TELEPHONY_LOGI("RegisterImsCallCallbackHandler success.");
    return TELEPHONY_SUCCESS;
}

std::shared_ptr<AppExecFwk::EventHandler> ImsCallClient::GetHandler(int32_t slotId)
{
    return handlerMap_[slotId];
}

int32_t ImsCallClient::Dial(const ImsCallInfo &callInfo, CLIRMode mode)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        CellularCallHiSysEvent::WriteDialCallFaultEvent(callInfo.slotId, INVALID_PARAMETER, callInfo.videoState,
            TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL, "ipc reconnect failed");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->Dial(callInfo, mode);
}

int32_t ImsCallClient::HangUp(const ImsCallInfo &callInfo)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        CellularCallHiSysEvent::WriteHangUpFaultEvent(
            callInfo.slotId, INVALID_PARAMETER, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL, "HangUp ims ipc reconnect failed");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->HangUp(callInfo);
}

int32_t ImsCallClient::Reject(const ImsCallInfo &callInfo)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        CellularCallHiSysEvent::WriteHangUpFaultEvent(
            callInfo.slotId, INVALID_PARAMETER, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL, "Reject ims ipc reconnect failed");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->RejectWithReason(callInfo, ImsRejectReason::USER_DECLINE);
}

int32_t ImsCallClient::RejectWithReason(const ImsCallInfo &callInfo, const ImsRejectReason &reason)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->RejectWithReason(callInfo, reason);
}

int32_t ImsCallClient::Answer(const ImsCallInfo &callInfo)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        CellularCallHiSysEvent::WriteAnswerCallFaultEvent(callInfo.slotId, INVALID_PARAMETER, callInfo.videoState,
            TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL, "answer ims ipc reconnect failed");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->Answer(callInfo);
}

int32_t ImsCallClient::HoldCall(int32_t slotId, int32_t callType)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->HoldCall(slotId, callType);
}

int32_t ImsCallClient::UnHoldCall(int32_t slotId, int32_t callType)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->UnHoldCall(slotId, callType);
}

int32_t ImsCallClient::SwitchCall(int32_t slotId, int32_t callType)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->SwitchCall(slotId, callType);
}

int32_t ImsCallClient::CombineConference(int32_t slotId)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->CombineConference(slotId);
}

int32_t ImsCallClient::InviteToConference(int32_t slotId, const std::vector<std::string> &numberList)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->InviteToConference(slotId, numberList);
}

int32_t ImsCallClient::KickOutFromConference(int32_t slotId, int32_t index)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->KickOutFromConference(slotId, index);
}

int32_t ImsCallClient::SendUpdateCallMediaModeRequest(const ImsCallInfo &callInfo, ImsCallType callType)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->SendUpdateCallMediaModeRequest(callInfo, callType);
}

int32_t ImsCallClient::SendUpdateCallMediaModeResponse(const ImsCallInfo &callInfo, ImsCallType callType)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->SendUpdateCallMediaModeResponse(callInfo, callType);
}

int32_t ImsCallClient::CancelCallUpgrade(int32_t slotId, int32_t callIndex)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->CancelCallUpgrade(slotId, callIndex);
}

int32_t ImsCallClient::RequestCameraCapabilities(int32_t slotId, int32_t callIndex)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->RequestCameraCapabilities(slotId, callIndex);
}

int32_t ImsCallClient::GetImsCallsDataRequest(int32_t slotId, int64_t lastCallsDataFlag)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->GetImsCallsDataRequest(slotId, lastCallsDataFlag);
}

int32_t ImsCallClient::GetLastCallFailReason(int32_t slotId)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->GetLastCallFailReason(slotId);
}

int32_t ImsCallClient::StartDtmf(int32_t slotId, char cDtmfCode, int32_t index)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->StartDtmf(slotId, cDtmfCode, index);
}

int32_t ImsCallClient::SendDtmf(int32_t slotId, char cDtmfCode, int32_t index)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->SendDtmf(slotId, cDtmfCode, index);
}

int32_t ImsCallClient::StopDtmf(int32_t slotId, int32_t index)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->StopDtmf(slotId, index);
}

int32_t ImsCallClient::StartRtt(int32_t slotId, const std::string &msg)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->StartRtt(slotId, msg);
}

int32_t ImsCallClient::StopRtt(int32_t slotId)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->StopRtt(slotId);
}

int32_t ImsCallClient::SetDomainPreferenceMode(int32_t slotId, int32_t mode)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->SetDomainPreferenceMode(slotId, mode);
}

int32_t ImsCallClient::GetDomainPreferenceMode(int32_t slotId)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->GetDomainPreferenceMode(slotId);
}

int32_t ImsCallClient::SetImsSwitchStatus(int32_t slotId, int32_t active)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->SetImsSwitchStatus(slotId, active);
}

int32_t ImsCallClient::GetImsSwitchStatus(int32_t slotId)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->GetImsSwitchStatus(slotId);
}

int32_t ImsCallClient::SetImsConfig(ImsConfigItem item, const std::string &value)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->SetImsConfig(item, value);
}

int32_t ImsCallClient::SetImsConfig(ImsConfigItem item, int32_t value)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->SetImsConfig(item, value);
}

int32_t ImsCallClient::GetImsConfig(ImsConfigItem item)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->GetImsConfig(item);
}

int32_t ImsCallClient::SetImsFeatureValue(FeatureType type, int32_t value)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->SetImsFeatureValue(type, value);
}

int32_t ImsCallClient::GetImsFeatureValue(FeatureType type, int32_t &value)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->GetImsFeatureValue(type, value);
}

int32_t ImsCallClient::SetMute(int32_t slotId, int32_t mute)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->SetMute(slotId, mute);
}

int32_t ImsCallClient::GetMute(int32_t slotId)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->GetMute(slotId);
}

int32_t ImsCallClient::ControlCamera(int32_t slotId, int32_t callIndex, const std::string &cameraId)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->ControlCamera(slotId, callIndex, cameraId);
}

int32_t ImsCallClient::SetPreviewWindow(
    int32_t slotId, int32_t callIndex, const std::string &surfaceID, sptr<Surface> surface)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->SetPreviewWindow(slotId, callIndex, surfaceID, surface);
}

int32_t ImsCallClient::SetDisplayWindow(
    int32_t slotId, int32_t callIndex, const std::string &surfaceID, sptr<Surface> surface)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->SetDisplayWindow(slotId, callIndex, surfaceID, surface);
}

int32_t ImsCallClient::SetCameraZoom(float zoomRatio)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->SetCameraZoom(zoomRatio);
}

int32_t ImsCallClient::SetPausePicture(int32_t slotId, int32_t callIndex, const std::string &path)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->SetPausePicture(slotId, callIndex, path);
}

int32_t ImsCallClient::SetDeviceDirection(int32_t slotId, int32_t callIndex, int32_t rotation)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->SetDeviceDirection(slotId, callIndex, rotation);
}

int32_t ImsCallClient::SetClip(int32_t slotId, int32_t action, int32_t index)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->SetClip(slotId, action, index);
}

int32_t ImsCallClient::GetClip(int32_t slotId, int32_t index)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->GetClip(slotId, index);
}

int32_t ImsCallClient::SetClir(int32_t slotId, int32_t action, int32_t index)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->SetClir(slotId, action, index);
}

int32_t ImsCallClient::GetClir(int32_t slotId, int32_t index)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->GetClir(slotId, index);
}

int32_t ImsCallClient::SetCallTransfer(int32_t slotId, const CallTransferInfo &cfInfo, int32_t classType, int32_t index)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->SetCallTransfer(slotId, cfInfo, classType, index);
}

int32_t ImsCallClient::CanSetCallTransferTime(int32_t slotId, bool &result)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("[slot%{public}d] ipc reconnect failed!", slotId);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->CanSetCallTransferTime(slotId, result);
}

int32_t ImsCallClient::GetCallTransfer(int32_t slotId, int32_t reason, int32_t index)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->GetCallTransfer(slotId, reason, index);
}

int32_t ImsCallClient::SetCallRestriction(
    int32_t slotId, const std::string &fac, int32_t mode, const std::string &pw, int32_t index)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->SetCallRestriction(slotId, fac, mode, pw, index);
}

int32_t ImsCallClient::GetCallRestriction(int32_t slotId, const std::string &fac, int32_t index)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->GetCallRestriction(slotId, fac, index);
}

int32_t ImsCallClient::SetCallWaiting(int32_t slotId, bool activate, int32_t classType, int32_t index)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->SetCallWaiting(slotId, activate, classType, index);
}

int32_t ImsCallClient::GetCallWaiting(int32_t slotId, int32_t index)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->GetCallWaiting(slotId, index);
}

int32_t ImsCallClient::SetColr(int32_t slotId, int32_t presentation, int32_t index)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->SetColr(slotId, presentation, index);
}

int32_t ImsCallClient::GetColr(int32_t slotId, int32_t index)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->GetColr(slotId, index);
}

int32_t ImsCallClient::SetColp(int32_t slotId, int32_t action, int32_t index)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->SetColp(slotId, action, index);
}

int32_t ImsCallClient::GetColp(int32_t slotId, int32_t index)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->GetColp(slotId, index);
}

int32_t ImsCallClient::ReConnectService()
{
    if (imsCallProxy_ == nullptr) {
        TELEPHONY_LOGI("try to reconnect ims call service now...");
        GetImsCallProxy();
        if (imsCallProxy_ == nullptr) {
            TELEPHONY_LOGE("Connect service failed");
            return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
        }
    }
    return TELEPHONY_SUCCESS;
}

void ImsCallClient::Clean()
{
    Utils::UniqueWriteGuard<Utils::RWLock> guard(rwClientLock_);
    if (imsCoreServiceProxy_ != nullptr) {
        imsCoreServiceProxy_.clear();
        imsCoreServiceProxy_ = nullptr;
    }
    if (imsCallProxy_ != nullptr) {
        imsCallProxy_.clear();
        imsCallProxy_ = nullptr;
    }
    if (imsCallCallback_ != nullptr) {
        imsCallCallback_.clear();
        imsCallCallback_ = nullptr;
    }
}

void ImsCallClient::SystemAbilityListener::OnAddSystemAbility(int32_t systemAbilityId,
    const std::string& deviceId)
{
    TELEPHONY_LOGI("SA:%{public}d is added!", systemAbilityId);
    if (!CheckInputSysAbilityId(systemAbilityId)) {
        TELEPHONY_LOGE("add SA:%{public}d is invalid!", systemAbilityId);
        return;
    }

    auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
    if (imsCallClient->IsConnect()) {
        TELEPHONY_LOGE("SA:%{public}d already connected!", systemAbilityId);
        return;
    }

    imsCallClient->Clean();
    int32_t res = imsCallClient->ReConnectService();
    if (res != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("SA:%{public}d reconnect service failed!", systemAbilityId);
        return;
    }
    TELEPHONY_LOGI("SA:%{public}d reconnect service successfully!", systemAbilityId);
}

void ImsCallClient::SystemAbilityListener::OnRemoveSystemAbility(int32_t systemAbilityId,
    const std::string& deviceId)
{
    TELEPHONY_LOGI("SA:%{public}d is removed!", systemAbilityId);
    auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
    if (!imsCallClient->IsConnect()) {
        return;
    }

    imsCallClient->Clean();
}

int32_t ImsCallClient::UpdateImsCapabilities(int32_t slotId, const ImsCapabilityList &imsCapabilityList)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->UpdateImsCapabilities(slotId, imsCapabilityList);
}

int32_t ImsCallClient::GetUtImpuFromNetwork(int32_t slotId, std::string &impu)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("[slot%{public}d]ipc reconnect failed!", slotId);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return imsCallProxy_->GetUtImpuFromNetwork(slotId, impu);
}
} // namespace Telephony
} // namespace OHOS

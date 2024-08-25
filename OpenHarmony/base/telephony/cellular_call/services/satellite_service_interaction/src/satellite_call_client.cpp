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

#include "satellite_call_client.h"

#include "cellular_call_hisysevent.h"
#include "iservice_registry.h"
#include "satellite_call_callback_stub.h"
#include "system_ability_definition.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
SatelliteCallClient::SatelliteCallClient() = default;

SatelliteCallClient::~SatelliteCallClient()
{
    UnInit();
}

void SatelliteCallClient::Init()
{
    TELEPHONY_LOGI("Init start");
    if (IsConnect()) {
        TELEPHONY_LOGE("Init, IsConnect return true");
        return;
    }

    GetSatelliteCallProxy();
    if (satelliteCallProxy_ == nullptr) {
        TELEPHONY_LOGE("Init, get satellite call proxy failed!");
        return;
    }
    TELEPHONY_LOGI("Init successfully");
}

void SatelliteCallClient::UnInit()
{
    Clean();
    handlerMap_.clear();
}

sptr<SatelliteCallInterface> SatelliteCallClient::GetSatelliteCallProxy()
{
    Utils::UniqueWriteGuard<Utils::RWLock> guard(rwClientLock_);
    if (satelliteCallProxy_ != nullptr) {
        return satelliteCallProxy_;
    }
    auto managerPtr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (managerPtr == nullptr) {
        TELEPHONY_LOGE("GetSatelliteCallProxy return, get system ability manager error.");
        return nullptr;
    }
    auto remoteObjectPtr = managerPtr->CheckSystemAbility(TELEPHONY_SATELLITE_SERVICE_ABILITY_ID);
    if (remoteObjectPtr == nullptr) {
        TELEPHONY_LOGE("GetSatelliteCallProxy return, remote service not exists.");
        return nullptr;
    }
    satelliteServiceProxy_ = iface_cast<ISatelliteService>(remoteObjectPtr);
    if (satelliteServiceProxy_ == nullptr) {
        TELEPHONY_LOGE("GetSatelliteCallProxy return, satelliteServiceProxy_ is nullptr.");
        return nullptr;
    }
    sptr<IRemoteObject> satelliteCallRemoteObjectPtr = satelliteServiceProxy_->GetProxyObjectPtr(PROXY_SATELLITE_CALL);
    if (satelliteCallRemoteObjectPtr == nullptr) {
        TELEPHONY_LOGE("GetProxyObjectPtr return, satelliteCallRemoteObjectPtr is nullptr.");
        return nullptr;
    }
    satelliteCallProxy_ = iface_cast<SatelliteCallInterface>(satelliteCallRemoteObjectPtr);
    RegisterSatelliteCallCallback();
    return satelliteCallProxy_;
}

bool SatelliteCallClient::IsConnect() const
{
    return (satelliteCallProxy_ != nullptr);
}

int32_t SatelliteCallClient::RegisterSatelliteCallCallback()
{
    if (satelliteCallProxy_ == nullptr) {
        TELEPHONY_LOGE("satelliteCallProxy_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    satelliteCallCallback_ = (std::make_unique<SatelliteCallCallbackStub>()).release();
    if (satelliteCallCallback_ == nullptr) {
        TELEPHONY_LOGE("RegisterSatelliteCallCallback return, make unique error.");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t ret = satelliteCallProxy_->RegisterSatelliteCallCallback(satelliteCallCallback_);
    if (ret) {
        TELEPHONY_LOGE("RegisterSatelliteCallCallback return, register callback error.");
        return TELEPHONY_ERR_FAIL;
    }
    TELEPHONY_LOGI("RegisterSatelliteCallCallback success.");
    ;
    return TELEPHONY_SUCCESS;
}

int32_t SatelliteCallClient::RegisterSatelliteCallCallbackHandler(
    int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (handler == nullptr) {
        TELEPHONY_LOGE("RegisterSatelliteCallCallbackHandler return, handler is null.");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    handlerMap_.insert(std::make_pair(slotId, handler));
    TELEPHONY_LOGI("RegisterSatelliteCallCallbackHandler success.");
    return TELEPHONY_SUCCESS;
}

std::shared_ptr<AppExecFwk::EventHandler> SatelliteCallClient::GetHandler(int32_t slotId)
{
    return handlerMap_[slotId];
}

int32_t SatelliteCallClient::Dial(const SatelliteCallInfo &callInfo, CLIRMode mode)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        CellularCallHiSysEvent::WriteDialCallFaultEvent(callInfo.slotId, INVALID_PARAMETER, INVALID_PARAMETER,
            TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL, "ipc reconnect failed");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return satelliteCallProxy_->Dial(callInfo, mode);
}

int32_t SatelliteCallClient::HangUp(int32_t slotId, int32_t index)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        CellularCallHiSysEvent::WriteHangUpFaultEvent(
            slotId, INVALID_PARAMETER, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL, "HangUp satellite ipc reconnect failed");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return satelliteCallProxy_->HangUp(slotId, index);
}

int32_t SatelliteCallClient::Reject(int32_t slotId)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        CellularCallHiSysEvent::WriteHangUpFaultEvent(
            slotId, INVALID_PARAMETER, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL, "Reject satellite ipc reconnect failed");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return satelliteCallProxy_->Reject(slotId);
}

int32_t SatelliteCallClient::Answer(int32_t slotId)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        CellularCallHiSysEvent::WriteAnswerCallFaultEvent(slotId, INVALID_PARAMETER, INVALID_PARAMETER,
            TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL, "answer satellite ipc reconnect failed");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return satelliteCallProxy_->Answer(slotId);
}

int32_t SatelliteCallClient::GetSatelliteCallsDataRequest(int32_t slotId, int64_t lastCallsDataFlag)
{
    if (ReConnectService() != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ipc reconnect failed!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return satelliteCallProxy_->GetSatelliteCallsDataRequest(slotId);
}

int32_t SatelliteCallClient::ReConnectService()
{
    if (satelliteCallProxy_ == nullptr) {
        TELEPHONY_LOGI("try to reconnect satellite call service now...");
        GetSatelliteCallProxy();
        if (satelliteCallProxy_ == nullptr) {
            TELEPHONY_LOGE("Connect service failed");
            return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
        }
    }
    return TELEPHONY_SUCCESS;
}

void SatelliteCallClient::Clean()
{
    Utils::UniqueWriteGuard<Utils::RWLock> guard(rwClientLock_);
    if (satelliteCallProxy_ != nullptr) {
        satelliteCallProxy_.clear();
        satelliteCallProxy_ = nullptr;
    }
    if (satelliteCallCallback_ != nullptr) {
        satelliteCallCallback_.clear();
        satelliteCallCallback_ = nullptr;
    }
}
} // namespace Telephony
} // namespace OHOS
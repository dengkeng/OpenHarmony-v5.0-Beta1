/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "cellular_call_service.h"

#include "cellular_call_callback.h"
#include "cellular_call_dump_helper.h"
#include "cellular_call_hisysevent.h"
#include "common_event.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "emergency_utils.h"
#include "ims_call_client.h"
#include "ims_video_call_control.h"
#include "module_service_utils.h"
#include "radio_event.h"
#include "satellite_call_client.h"
#include "securec.h"
#include "string_ex.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Telephony {
const uint32_t CONNECT_MAX_TRY_COUNT = 20;
const uint32_t CONNECT_CORE_SERVICE_WAIT_TIME = 2000; // ms
const uint32_t TELEPHONY_SATELLITE_SYS_ABILITY_ID = 4012;
bool g_registerResult =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<CellularCallService>::GetInstance().get());

CellularCallService::CellularCallService() : SystemAbility(TELEPHONY_CELLULAR_CALL_SYS_ABILITY_ID, true)
{
    state_ = ServiceRunningState::STATE_STOPPED;
}

CellularCallService::~CellularCallService()
{
    state_ = ServiceRunningState::STATE_STOPPED;
    if (statusChangeListener_ != nullptr) {
        statusChangeListener_.clear();
        statusChangeListener_ = nullptr;
    }
}

bool CellularCallService::Init()
{
    TELEPHONY_LOGD("CellularCallService::Init start");
    CreateHandler();
    SendEventRegisterHandler();
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    callManagerListener_ = new (std::nothrow) SystemAbilityStatusChangeListener();
    if (samgrProxy == nullptr || callManagerListener_ == nullptr) {
        TELEPHONY_LOGE("samgrProxy or callManagerListener_ is nullptr");
    } else {
        int32_t ret = samgrProxy->SubscribeSystemAbility(TELEPHONY_CALL_MANAGER_SYS_ABILITY_ID, callManagerListener_);
        TELEPHONY_LOGI("SubscribeSystemAbility TELEPHONY_CALL_MANAGER_SYS_ABILITY_ID result:%{public}d", ret);
    }
    // connect ims_service
    DelayedSingleton<ImsCallClient>::GetInstance()->Init();
    TELEPHONY_LOGD("CellularCallService::Init, init success");
    return true;
}

void CellularCallService::OnStart()
{
    TELEPHONY_LOGD("CellularCallService OnStart");
    bindTime_ =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        TELEPHONY_LOGE("CellularCallService::OnStart return, has already started.");
        return;
    }
    if (!Init()) {
        TELEPHONY_LOGE("CellularCallService::OnStart return, failed to init service.");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    bool ret = Publish(DelayedSingleton<CellularCallService>::GetInstance().get());
    if (!ret) {
        TELEPHONY_LOGE("CellularCallService::OnStart Publish failed!");
    }
    endTime_ =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    TELEPHONY_LOGD("CellularCallService start success.");
}

void CellularCallService::OnStop()
{
    TELEPHONY_LOGD("CellularCallService stop service");
    DelayedSingleton<ImsCallClient>::GetInstance()->UnInit();
    state_ = ServiceRunningState::STATE_STOPPED;
    HandlerResetUnRegister();
}

void CellularCallService::RegisterHandler()
{
    TELEPHONY_LOGD("connect core service Register Handler start");
    networkSearchCallBack_ = (std::make_unique<CellularCallCallback>()).release();
    for (uint32_t i = 0; i < CONNECT_MAX_TRY_COUNT; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(CONNECT_CORE_SERVICE_WAIT_TIME));
        if (CoreManagerInner::GetInstance().IsInitFinished()) {
            TELEPHONY_LOGD("connect core service Register Handler start");
            RegisterCoreServiceHandler();
            CoreManagerInner::GetInstance().RegisterCellularCallObject(networkSearchCallBack_);
            break;
        }
        TELEPHONY_LOGW("connect core service Register Handler null or not init");
    }
    TELEPHONY_LOGD("connect core service Register Handler end");
}

void CellularCallService::CreateHandler()
{
    ModuleServiceUtils obtain;
    std::vector<int32_t> slotVector = obtain.GetSlotInfo();
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriberInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);
    for (const auto &it : slotVector) {
        auto handler = std::make_shared<CellularCallHandler>(subscriberInfo);
        TELEPHONY_LOGI("setSlotId:%{public}d", it);
        handler->SetSlotId(it);
        handler->RegisterImsCallCallbackHandler();
        handlerMap_.insert(std::make_pair(it, handler));
        auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        statusChangeListener_ = new (std::nothrow) SystemAbilityStatusChangeListener(handler);
        if (samgrProxy == nullptr || statusChangeListener_ == nullptr) {
            TELEPHONY_LOGE("samgrProxy or statusChangeListener_ is nullptr");
        } else {
            int32_t retSubCommnetEvent =
                samgrProxy->SubscribeSystemAbility(COMMON_EVENT_SERVICE_ID, statusChangeListener_);
            TELEPHONY_LOGI("SubscribeSystemAbility COMMON_EVENT_SERVICE_ID result:%{public}d", retSubCommnetEvent);
            int32_t retSubSateEvent =
                samgrProxy->SubscribeSystemAbility(TELEPHONY_SATELLITE_SYS_ABILITY_ID, statusChangeListener_);
            TELEPHONY_LOGI(
                "SubscribeSystemAbility TELEPHONY_SATELLITE_SYS_ABILITY_ID result:%{public}d", retSubSateEvent);
        }
    }
}

void CellularCallService::HandlerResetUnRegister()
{
    TELEPHONY_LOGI("HandlerResetUnRegister");
    for (const auto &it : handlerMap_) {
        int32_t slot = it.first;
        auto handler = it.second;
        if (handler != nullptr) {
            handler.reset();
        }
        CoreManagerInner &coreInner = CoreManagerInner::GetInstance();
        coreInner.UnRegisterCoreNotify(slot, handler, RadioEvent::RADIO_AVAIL);
        coreInner.UnRegisterCoreNotify(slot, handler, RadioEvent::RADIO_NOT_AVAIL);
        coreInner.UnRegisterCoreNotify(slot, handler, RadioEvent::RADIO_SIM_RECORDS_LOADED);
        coreInner.UnRegisterCoreNotify(slot, handler, RadioEvent::RADIO_SIM_ACCOUNT_LOADED);
        coreInner.UnRegisterCoreNotify(slot, handler, RadioEvent::RADIO_CALL_STATUS_INFO);
        coreInner.UnRegisterCoreNotify(slot, handler, RadioEvent::RADIO_CALL_USSD_NOTICE);
        coreInner.UnRegisterCoreNotify(slot, handler, RadioEvent::RADIO_CALL_SS_NOTICE);
        coreInner.UnRegisterCoreNotify(slot, handler, RadioEvent::RADIO_CALL_RINGBACK_VOICE);
        coreInner.UnRegisterCoreNotify(slot, handler, RadioEvent::RADIO_CALL_EMERGENCY_NUMBER_REPORT);
        coreInner.UnRegisterCoreNotify(slot, handler, RadioEvent::RADIO_CALL_SRVCC_STATUS);
        coreInner.UnRegisterCoreNotify(slot, handler, RadioEvent::RADIO_CALL_RSRVCC_STATUS);
        coreInner.UnRegisterCoreNotify(slot, handler, RadioEvent::RADIO_RESIDENT_NETWORK_CHANGE);
        coreInner.UnRegisterCoreNotify(slot, handler, RadioEvent::RADIO_PS_CONNECTION_ATTACHED);
        coreInner.UnRegisterCoreNotify(slot, handler, RadioEvent::RADIO_PS_CONNECTION_DETACHED);
        coreInner.UnRegisterCoreNotify(slot, handler, RadioEvent::RADIO_RIL_ADAPTER_HOST_DIED);
        coreInner.UnRegisterCoreNotify(slot, handler, RadioEvent::RADIO_FACTORY_RESET);
#ifdef CALL_MANAGER_AUTO_START_OPTIMIZE
        coreInner.UnRegisterCoreNotify(slot, handler, RadioEvent::RADIO_STATE_CHANGED);
#endif
        if (GetCsControl(slot) != nullptr) {
            GetCsControl(slot)->ReleaseAllConnection();
        }
        if (GetImsControl(slot) != nullptr) {
            GetImsControl(slot)->ReleaseAllConnection();
        }
    }
}

void CellularCallService::RegisterCoreServiceHandler()
{
    TELEPHONY_LOGI("RegisterCoreServiceHandle");
    for (const auto &it : handlerMap_) {
        int32_t slot = it.first;
        auto handler = it.second;
        if (handler != nullptr) {
            CoreManagerInner &coreInner = CoreManagerInner::GetInstance();
            coreInner.RegisterCoreNotify(slot, handler, RadioEvent::RADIO_AVAIL, nullptr);
            coreInner.RegisterCoreNotify(slot, handler, RadioEvent::RADIO_NOT_AVAIL, nullptr);
            coreInner.RegisterCoreNotify(slot, handler, RadioEvent::RADIO_SIM_STATE_CHANGE, nullptr);
            coreInner.RegisterCoreNotify(slot, handler, RadioEvent::RADIO_SIM_RECORDS_LOADED, nullptr);
            coreInner.RegisterCoreNotify(slot, handler, RadioEvent::RADIO_SIM_ACCOUNT_LOADED, nullptr);
            coreInner.RegisterCoreNotify(slot, handler, RadioEvent::RADIO_CALL_STATUS_INFO, nullptr);
            coreInner.RegisterCoreNotify(slot, handler, RadioEvent::RADIO_CALL_USSD_NOTICE, nullptr);
            coreInner.RegisterCoreNotify(slot, handler, RadioEvent::RADIO_CALL_SS_NOTICE, nullptr);
            coreInner.RegisterCoreNotify(slot, handler, RadioEvent::RADIO_CALL_EMERGENCY_NUMBER_REPORT, nullptr);
            coreInner.RegisterCoreNotify(slot, handler, RadioEvent::RADIO_CALL_RINGBACK_VOICE, nullptr);
            coreInner.RegisterCoreNotify(slot, handler, RadioEvent::RADIO_CALL_SRVCC_STATUS, nullptr);
            coreInner.RegisterCoreNotify(slot, handler, RadioEvent::RADIO_CALL_RSRVCC_STATUS, nullptr);
            coreInner.RegisterCoreNotify(slot, handler, RadioEvent::RADIO_RESIDENT_NETWORK_CHANGE, nullptr);
            coreInner.RegisterCoreNotify(slot, handler, RadioEvent::RADIO_PS_CONNECTION_ATTACHED, nullptr);
            coreInner.RegisterCoreNotify(slot, handler, RadioEvent::RADIO_PS_CONNECTION_DETACHED, nullptr);
            coreInner.RegisterCoreNotify(slot, handler, RadioEvent::RADIO_RIL_ADAPTER_HOST_DIED, nullptr);
            coreInner.RegisterCoreNotify(slot, handler, RadioEvent::RADIO_FACTORY_RESET, nullptr);
#ifdef CALL_MANAGER_AUTO_START_OPTIMIZE
            coreInner.RegisterCoreNotify(slot, handler, RadioEvent::RADIO_STATE_CHANGED, nullptr);
            coreInner.GetRadioState(slot, RadioEvent::RADIO_GET_STATUS, handler);
#endif
        }
        CellularCallConfig config;
        config.InitModeActive();
        if (config.GetDomainPreferenceMode(slot) != TELEPHONY_SUCCESS) {
            TELEPHONY_LOGW("RegisterCoreServiceHandler, GetDomainPreferenceMode request fail");
        }
        if (config.GetEmergencyCallList(it.first) != TELEPHONY_SUCCESS) {
            TELEPHONY_LOGW("RegisterCoreServiceHandler, GetEmergencyCallList request fail");
        }
    }
}

void CellularCallService::SendEventRegisterHandler()
{
    int64_t delayTime = 1000;
    int32_t slot = DEFAULT_SIM_SLOT_ID;
    auto handler = handlerMap_[slot];
    if (handler == nullptr) {
        TELEPHONY_LOGE("SendEventRegisterHandler return, handler is nullptr");
        return;
    }
    handler->SendEvent(handler->REGISTER_HANDLER_ID, delayTime, CellularCallHandler::Priority::HIGH);
}

int32_t CellularCallService::Dump(int32_t fd, const std::vector<std::u16string> &args)
{
    if (fd < 0) {
        TELEPHONY_LOGE("dump fd invalid");
        return TELEPHONY_ERR_FAIL;
    }
    std::vector<std::string> argsInStr;
    for (const auto &arg : args) {
        argsInStr.emplace_back(Str16ToStr8(arg));
    }
    std::string result;
    CellularCallDumpHelper dumpHelper;
    if (dumpHelper.Dump(argsInStr, result)) {
        int32_t ret = dprintf(fd, "%s", result.c_str());
        if (ret < 0) {
            TELEPHONY_LOGE("dprintf to dump fd failed");
            return TELEPHONY_ERR_FAIL;
        }
        return TELEPHONY_SUCCESS;
    }
    TELEPHONY_LOGW("dumpHelper failed");
    return TELEPHONY_ERR_FAIL;
}

int32_t CellularCallService::GetServiceRunningState()
{
    return static_cast<int32_t>(state_);
}

std::string CellularCallService::GetBindTime()
{
    std::ostringstream oss;
    oss << bindTime_;
    return oss.str();
}

std::string CellularCallService::GetEndTime()
{
    std::ostringstream oss;
    oss << endTime_;
    return oss.str();
}

std::string CellularCallService::GetSpendTime()
{
    spendTime_ = endTime_ - bindTime_;
    std::ostringstream oss;
    oss << spendTime_;
    return oss.str();
}

int32_t CellularCallService::Dial(const CellularCallInfo &callInfo)
{
    if (!IsValidSlotId(callInfo.slotId)) {
        TELEPHONY_LOGE("CellularCallService::Dial return, invalid slot id");
        CellularCallHiSysEvent::WriteDialCallFaultEvent(callInfo.accountId, static_cast<int32_t>(callInfo.callType),
            callInfo.videoState, CALL_ERR_INVALID_SLOT_ID, "invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    if (srvccState_ == SrvccState::STARTED) {
        CellularCallHiSysEvent::WriteDialCallFaultEvent(callInfo.accountId, static_cast<int32_t>(callInfo.callType),
            callInfo.videoState, static_cast<int32_t>(CallErrorCode::CALL_ERROR_UNEXPECTED_SRVCC_STATE),
            "srvccState_ is STARTED");
        return TELEPHONY_ERR_FAIL;
    }
    bool isEcc = false;
    IsEmergencyPhoneNumber(callInfo.slotId, callInfo.phoneNum, isEcc);
    ModuleServiceUtils moduleServiceUtils;
    bool satelliteStatusOn = moduleServiceUtils.GetSatelliteStatus();
    if (satelliteStatusOn) {
        auto satelliteControl = GetSatelliteControl(callInfo.slotId);
        if (satelliteControl == nullptr) {
            TELEPHONY_LOGI("CellularCallService::Dial satelliteControl dial");
            satelliteControl = std::make_shared<SatelliteControl>();
            if (satelliteControl == nullptr) {
                TELEPHONY_LOGE("CellularCallService::Dial return, satelliteControl create fail");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            SetSatelliteControl(callInfo.slotId, satelliteControl);
        }
        return satelliteControl->Dial(callInfo, isEcc);
    }
    return DialNormalCall(callInfo, isEcc);
}

int32_t CellularCallService::DialNormalCall(const CellularCallInfo &callInfo, bool isEcc)
{
    bool useImsForEmergency = UseImsForEmergency(callInfo, isEcc);
    if (IsNeedIms(callInfo.slotId) || useImsForEmergency) {
        auto imsControl = GetImsControl(callInfo.slotId);
        if (imsControl == nullptr) {
            TELEPHONY_LOGI("CellularCallService::Dial ims dial");
            imsControl = std::make_shared<IMSControl>();
            if (imsControl == nullptr) {
                TELEPHONY_LOGE("CellularCallService::Dial return, imsControl create fail");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            SetImsControl(callInfo.slotId, imsControl);
        }
        return imsControl->Dial(callInfo, isEcc);
    }

    auto csControl = GetCsControl(callInfo.slotId);
    if (csControl == nullptr) {
        csControl = std::make_shared<CSControl>();
        if (csControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::Dial return, csControl create fail");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        SetCsControl(callInfo.slotId, csControl);
    }
    return csControl->Dial(callInfo, isEcc);
}

int32_t CellularCallService::HangUp(const CellularCallInfo &callInfo, CallSupplementType type)
{
    DelayedSingleton<CellularCallHiSysEvent>::GetInstance()->SetCallParameterInfo(
        callInfo.slotId, static_cast<int32_t>(callInfo.callType), callInfo.videoState);
    if (!IsValidSlotId(callInfo.slotId)) {
        TELEPHONY_LOGE("CellularCallService::HangUp return, invalid slot id");
        CellularCallHiSysEvent::WriteHangUpFaultEvent(
            callInfo.slotId, callInfo.callId, CALL_ERR_INVALID_SLOT_ID, "HangUp invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    if (srvccState_ == SrvccState::STARTED) {
        CellularCallHiSysEvent::WriteHangUpFaultEvent(callInfo.slotId, callInfo.callId,
            static_cast<int32_t>(CallErrorCode::CALL_ERROR_UNEXPECTED_SRVCC_STATE), "HangUp srvccState_ is STARTED");
        return TELEPHONY_ERR_FAIL;
    }
    if (CallType::TYPE_SATELLITE == callInfo.callType) {
        auto satelliteControl = GetSatelliteControl(callInfo.slotId);
        if (satelliteControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::HangUp return, satelliteControl is nullptr");
            CellularCallHiSysEvent::WriteHangUpFaultEvent(
                callInfo.slotId, callInfo.callId, TELEPHONY_ERR_LOCAL_PTR_NULL, "HangUp satelliteControl is nullptr");
            HandleCellularControlException(callInfo);
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return satelliteControl->HangUp(callInfo, type);
    } else if (CallType::TYPE_CS == callInfo.callType) {
        auto csControl = GetCsControl(callInfo.slotId);
        if (csControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::HangUp return, csControl is nullptr");
            CellularCallHiSysEvent::WriteHangUpFaultEvent(
                callInfo.slotId, callInfo.callId, TELEPHONY_ERR_LOCAL_PTR_NULL, "HangUp csControl is nullptr");
            HandleCellularControlException(callInfo);
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return csControl->HangUp(callInfo, type);
    } else if (CallType::TYPE_IMS == callInfo.callType) {
        auto imsControl = GetImsControl(callInfo.slotId);
        if (imsControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::HangUp return, imsControl is nullptr");
            CellularCallHiSysEvent::WriteHangUpFaultEvent(
                callInfo.slotId, callInfo.callId, TELEPHONY_ERR_LOCAL_PTR_NULL, "HangUp imsControl is nullptr");
            HandleCellularControlException(callInfo);
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return imsControl->HangUp(callInfo, type);
    }
    TELEPHONY_LOGE("CellularCallService::HangUp return, call type error.");
    CellularCallHiSysEvent::WriteHangUpFaultEvent(
        callInfo.slotId, callInfo.callId, TELEPHONY_ERR_ARGUMENT_INVALID, "HangUp call type error");
    return TELEPHONY_ERR_ARGUMENT_INVALID;
}

int32_t CellularCallService::Reject(const CellularCallInfo &callInfo)
{
    DelayedSingleton<CellularCallHiSysEvent>::GetInstance()->SetCallParameterInfo(
        callInfo.slotId, static_cast<int32_t>(callInfo.callType), callInfo.videoState);
    if (!IsValidSlotId(callInfo.slotId)) {
        TELEPHONY_LOGE("CellularCallService::Reject return, invalid slot id");
        CellularCallHiSysEvent::WriteHangUpFaultEvent(
            callInfo.slotId, callInfo.callId, TELEPHONY_ERR_ARGUMENT_INVALID, "Reject call type error");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    if (srvccState_ == SrvccState::STARTED) {
        CellularCallHiSysEvent::WriteHangUpFaultEvent(callInfo.slotId, callInfo.callId,
            static_cast<int32_t>(CallErrorCode::CALL_ERROR_UNEXPECTED_SRVCC_STATE), "Reject srvccState_ is STARTED");
        return TELEPHONY_ERR_FAIL;
    }
    if (CallType::TYPE_SATELLITE == callInfo.callType) {
        auto satelliteControl = GetSatelliteControl(callInfo.slotId);
        if (satelliteControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::Reject return, satelliteControl is nullptr");
            CellularCallHiSysEvent::WriteHangUpFaultEvent(
                callInfo.slotId, callInfo.callId, TELEPHONY_ERR_LOCAL_PTR_NULL, "Reject satelliteControl is nullptr");
            HandleCellularControlException(callInfo);
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return satelliteControl->Reject(callInfo);
    } else if (CallType::TYPE_CS == callInfo.callType) {
        auto csControl = GetCsControl(callInfo.slotId);
        if (csControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::Reject return, csControl is nullptr");
            CellularCallHiSysEvent::WriteHangUpFaultEvent(
                callInfo.slotId, callInfo.callId, TELEPHONY_ERR_LOCAL_PTR_NULL, "Reject csControl is nullptr");
            HandleCellularControlException(callInfo);
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return csControl->Reject(callInfo);
    } else if (CallType::TYPE_IMS == callInfo.callType) {
        auto imsControl = GetImsControl(callInfo.slotId);
        if (imsControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::Reject return, imsControl is nullptr");
            CellularCallHiSysEvent::WriteHangUpFaultEvent(
                callInfo.slotId, callInfo.callId, TELEPHONY_ERR_LOCAL_PTR_NULL, "Reject imsControl is nullptr");
            HandleCellularControlException(callInfo);
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return imsControl->Reject(callInfo);
    }
    TELEPHONY_LOGE("CellularCallService::Reject return, call type error.");
    CellularCallHiSysEvent::WriteHangUpFaultEvent(
        callInfo.slotId, callInfo.callId, TELEPHONY_ERR_ARGUMENT_INVALID, "Reject call type error");
    return TELEPHONY_ERR_ARGUMENT_INVALID;
}

int32_t CellularCallService::Answer(const CellularCallInfo &callInfo)
{
    DelayedSingleton<CellularCallHiSysEvent>::GetInstance()->SetCallParameterInfo(
        callInfo.slotId, static_cast<int32_t>(callInfo.callType), callInfo.videoState);

    if (!IsValidSlotId(callInfo.slotId)) {
        TELEPHONY_LOGE("CellularCallService::Answer return, invalid slot id");
        CellularCallHiSysEvent::WriteAnswerCallFaultEvent(
            callInfo.slotId, callInfo.callId, callInfo.videoState, CALL_ERR_INVALID_SLOT_ID, "invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    if (srvccState_ == SrvccState::STARTED) {
        CellularCallHiSysEvent::WriteAnswerCallFaultEvent(callInfo.slotId, callInfo.callId, callInfo.videoState,
            static_cast<int32_t>(CallErrorCode::CALL_ERROR_UNEXPECTED_SRVCC_STATE), "srvccState_ is STARTED");
        return TELEPHONY_ERR_FAIL;
    }
    if (CallType::TYPE_SATELLITE == callInfo.callType) {
        auto satelliteControl = GetSatelliteControl(callInfo.slotId);
        if (satelliteControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::Answer return, satelliteControl is nullptr");
            CellularCallHiSysEvent::WriteAnswerCallFaultEvent(callInfo.slotId, callInfo.callId, callInfo.videoState,
                TELEPHONY_ERR_LOCAL_PTR_NULL, "satelliteControl is nullptr");
            HandleCellularControlException(callInfo);
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return satelliteControl->Answer(callInfo);
    } else if (CallType::TYPE_CS == callInfo.callType) {
        auto csControl = GetCsControl(callInfo.slotId);
        if (csControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::Answer return, csControl is nullptr");
            CellularCallHiSysEvent::WriteAnswerCallFaultEvent(callInfo.slotId, callInfo.callId, callInfo.videoState,
                TELEPHONY_ERR_LOCAL_PTR_NULL, "csControl is nullptr");
            HandleCellularControlException(callInfo);
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return csControl->Answer(callInfo);
    } else if (CallType::TYPE_IMS == callInfo.callType) {
        auto imsControl = GetImsControl(callInfo.slotId);
        if (imsControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::Answer return, imsControl is nullptr");
            CellularCallHiSysEvent::WriteAnswerCallFaultEvent(callInfo.slotId, callInfo.callId, callInfo.videoState,
                TELEPHONY_ERR_LOCAL_PTR_NULL, "imsControl is nullptr");
            HandleCellularControlException(callInfo);
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return imsControl->Answer(callInfo);
    }
    TELEPHONY_LOGE("CellularCallService::Answer return, call type error.");
    CellularCallHiSysEvent::WriteAnswerCallFaultEvent(
        callInfo.slotId, callInfo.callId, callInfo.videoState, TELEPHONY_ERR_LOCAL_PTR_NULL, "call type error");
    return TELEPHONY_ERR_ARGUMENT_INVALID;
}

int32_t CellularCallService::RegisterCallManagerCallBack(const sptr<ICallStatusCallback> &callback)
{
    if (DelayedSingleton<CellularCallRegister>::GetInstance() == nullptr) {
        TELEPHONY_LOGE("CellularCallService::RegisterCallManagerCallBack return, instance is nullptr.");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return DelayedSingleton<CellularCallRegister>::GetInstance()->RegisterCallManagerCallBack(callback);
}

int32_t CellularCallService::UnRegisterCallManagerCallBack()
{
    if (DelayedSingleton<CellularCallRegister>::GetInstance() == nullptr) {
        TELEPHONY_LOGE("CellularCallService::UnRegisterCallManagerCallBack return, instance is nullptr.");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return DelayedSingleton<CellularCallRegister>::GetInstance()->UnRegisterCallManagerCallBack();
}

int32_t CellularCallService::HoldCall(const CellularCallInfo &callInfo)
{
    if (!IsValidSlotId(callInfo.slotId)) {
        TELEPHONY_LOGE("CellularCallService::HoldCall return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    if (srvccState_ == SrvccState::STARTED) {
        return TELEPHONY_ERR_FAIL;
    }
    if (CallType::TYPE_SATELLITE == callInfo.callType) {
        auto satelliteControl = GetSatelliteControl(callInfo.slotId);
        if (satelliteControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::HoldCall return, satelliteControl is nullptr");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return satelliteControl->HoldCall(callInfo.slotId);
    } else if (CallType::TYPE_IMS == callInfo.callType) {
        auto imsControl = GetImsControl(callInfo.slotId);
        if (imsControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::HoldCall return, imsControl is nullptr");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return imsControl->HoldCall(callInfo.slotId);
    } else if (CallType::TYPE_CS == callInfo.callType) {
        auto csControl = GetCsControl(callInfo.slotId);
        if (csControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::HoldCall return, csControl is nullptr");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return csControl->HoldCall(callInfo.slotId);
    }
    TELEPHONY_LOGE("CellularCallService::HoldCall return, call type error.");
    return TELEPHONY_ERR_ARGUMENT_INVALID;
}

int32_t CellularCallService::UnHoldCall(const CellularCallInfo &callInfo)
{
    if (!IsValidSlotId(callInfo.slotId)) {
        TELEPHONY_LOGE("CellularCallService::UnHoldCall return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    if (srvccState_ == SrvccState::STARTED) {
        return TELEPHONY_ERR_FAIL;
    }
    if (CallType::TYPE_SATELLITE == callInfo.callType) {
        auto satelliteControl = GetSatelliteControl(callInfo.slotId);
        if (satelliteControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::HoldCall return, satelliteControl is nullptr");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return satelliteControl->UnHoldCall(callInfo.slotId);
    } else if (CallType::TYPE_IMS == callInfo.callType) {
        auto imsControl = GetImsControl(callInfo.slotId);
        if (imsControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::UnHoldCall return, imsControl is nullptr");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return imsControl->UnHoldCall(callInfo.slotId);
    } else if (CallType::TYPE_CS == callInfo.callType) {
        auto csControl = GetCsControl(callInfo.slotId);
        if (csControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::UnHoldCall return, csControl is nullptr");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return csControl->UnHoldCall(callInfo.slotId);
    }
    TELEPHONY_LOGE("CellularCallService::UnHoldCall return, call type error.");
    return TELEPHONY_ERR_ARGUMENT_INVALID;
}

int32_t CellularCallService::SwitchCall(const CellularCallInfo &callInfo)
{
    if (!IsValidSlotId(callInfo.slotId)) {
        TELEPHONY_LOGE("CellularCallService::SwitchCall return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    if (srvccState_ == SrvccState::STARTED) {
        return TELEPHONY_ERR_FAIL;
    }
    if (CallType::TYPE_SATELLITE == callInfo.callType) {
        auto satelliteControl = GetSatelliteControl(callInfo.slotId);
        if (satelliteControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::HoldCall return, satelliteControl is nullptr");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return satelliteControl->UnHoldCall(callInfo.slotId);
    } else if (CallType::TYPE_IMS == callInfo.callType) {
        auto imsControl = GetImsControl(callInfo.slotId);
        if (imsControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::SwitchCall return, imsControl is nullptr");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return imsControl->SwitchCall(callInfo.slotId);
    } else if (CallType::TYPE_CS == callInfo.callType) {
        auto csControl = GetCsControl(callInfo.slotId);
        if (csControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::SwitchCall return, csControl is nullptr");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return csControl->SwitchCall(callInfo.slotId);
    }
    TELEPHONY_LOGE("CellularCallService::SwitchCall return, call type error.");
    return TELEPHONY_ERR_ARGUMENT_INVALID;
}

int32_t CellularCallService::CombineConference(const CellularCallInfo &callInfo)
{
    if (!IsValidSlotId(callInfo.slotId)) {
        TELEPHONY_LOGE("CellularCallService::CombineConference return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    if (srvccState_ == SrvccState::STARTED) {
        return TELEPHONY_ERR_FAIL;
    }
    if (CallType::TYPE_IMS == callInfo.callType) {
        auto imsControl = GetImsControl(callInfo.slotId);
        if (imsControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::CombineConference return, imsControl is nullptr");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return imsControl->CombineConference(callInfo.slotId);
    } else if (CallType::TYPE_CS == callInfo.callType) {
        auto csControl = GetCsControl(callInfo.slotId);
        if (csControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::CombineConference return, csControl is nullptr");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return csControl->CombineConference(callInfo.slotId);
    }
    TELEPHONY_LOGE("CellularCallService::CombineConference return, call type error.");
    return TELEPHONY_ERR_ARGUMENT_INVALID;
}

int32_t CellularCallService::SeparateConference(const CellularCallInfo &callInfo)
{
    if (!IsValidSlotId(callInfo.slotId)) {
        TELEPHONY_LOGE("CellularCallService::SeparateConference return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    if (CallType::TYPE_CS == callInfo.callType) {
        auto csControl = GetCsControl(callInfo.slotId);
        if (csControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::SeparateConference return, csControl is nullptr");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return csControl->SeparateConference(callInfo.slotId, callInfo.phoneNum, callInfo.index);
    }
    TELEPHONY_LOGE("CellularCallService::SeparateConference return, call type error.");
    return TELEPHONY_ERR_ARGUMENT_INVALID;
}

int32_t CellularCallService::InviteToConference(int32_t slotId, const std::vector<std::string> &numberList)
{
    auto control = GetImsControl(slotId);
    if (control == nullptr) {
        TELEPHONY_LOGE("CellularCallService::InviteToConference return, control is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return control->InviteToConference(slotId, numberList);
}

int32_t CellularCallService::KickOutFromConference(const CellularCallInfo &callInfo)
{
    if (!IsValidSlotId(callInfo.slotId)) {
        TELEPHONY_LOGE("CellularCallService::KickOutFromConference return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    if (CallType::TYPE_IMS == callInfo.callType) {
        auto imsControl = GetImsControl(callInfo.slotId);
        if (imsControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::KickOutFromConference return, imsControl is nullptr");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return imsControl->KickOutFromConference(callInfo.slotId, callInfo.phoneNum, callInfo.index);
    } else if (CallType::TYPE_CS == callInfo.callType) {
        auto csControl = GetCsControl(callInfo.slotId);
        if (csControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::KickOutFromConference return, csControl is nullptr");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return csControl->HangUp(callInfo, CallSupplementType::TYPE_DEFAULT);
    }
    TELEPHONY_LOGE("CellularCallService::KickOutFromConference return, call type error.");
    return TELEPHONY_ERR_ARGUMENT_INVALID;
}

int32_t CellularCallService::HangUpAllConnection()
{
    ModuleServiceUtils obtain;
    std::vector<int32_t> slotVector = obtain.GetSlotInfo();
    for (const auto &it : slotVector) {
        if (GetCsControl(it)) {
            GetCsControl(it)->HangUpAllConnection(it);
        }
        if (GetImsControl(it)) {
            GetImsControl(it)->HangUpAllConnection(it);
        }
    }
    return TELEPHONY_SUCCESS;
}

int32_t CellularCallService::SetReadyToCall(int32_t slotId, int32_t callType, bool isReadyToCall)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CellularCallService::SetReadyToCall return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    if (callType == static_cast<int32_t>(CallType::TYPE_CS) && GetCsControl(slotId) != nullptr) {
        GetCsControl(slotId)->SetReadyToCall(slotId, isReadyToCall);
    }
    if (callType == static_cast<int32_t>(CallType::TYPE_IMS) && GetImsControl(slotId) != nullptr) {
        GetImsControl(slotId)->SetReadyToCall(slotId, isReadyToCall);
    }
    return TELEPHONY_SUCCESS;
}

int32_t CellularCallService::HangUpAllConnection(int32_t slotId)
{
    if (GetCsControl(slotId)) {
        GetCsControl(slotId)->HangUpAllConnection(slotId);
    }
    if (GetImsControl(slotId)) {
        GetImsControl(slotId)->HangUpAllConnection(slotId);
    }
    return TELEPHONY_SUCCESS;
}

int32_t CellularCallService::SendUpdateCallMediaModeRequest(const CellularCallInfo &callInfo, ImsCallMode mode)
{
    auto videoCallControl = DelayedSingleton<ImsVideoCallControl>::GetInstance();
    if (videoCallControl == nullptr) {
        TELEPHONY_LOGE("videoCallControl is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return videoCallControl->SendUpdateCallMediaModeRequest(callInfo, mode);
}

int32_t CellularCallService::SendUpdateCallMediaModeResponse(const CellularCallInfo &callInfo, ImsCallMode mode)
{
    auto videoCallControl = DelayedSingleton<ImsVideoCallControl>::GetInstance();
    if (videoCallControl == nullptr) {
        TELEPHONY_LOGE("videoCallControl is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return videoCallControl->SendUpdateCallMediaModeResponse(callInfo, mode);
}

int32_t CellularCallService::CancelCallUpgrade(int32_t slotId, int32_t callIndex)
{
    auto videoCallControl = DelayedSingleton<ImsVideoCallControl>::GetInstance();
    if (videoCallControl == nullptr) {
        TELEPHONY_LOGE("videoCallControl is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return videoCallControl->CancelCallUpgrade(slotId, callIndex);
}

int32_t CellularCallService::RequestCameraCapabilities(int32_t slotId, int32_t callIndex)
{
    auto videoCallControl = DelayedSingleton<ImsVideoCallControl>::GetInstance();
    if (videoCallControl == nullptr) {
        TELEPHONY_LOGE("videoCallControl is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return videoCallControl->RequestCameraCapabilities(slotId, callIndex);
}

int32_t CellularCallService::StartDtmf(char cDtmfCode, const CellularCallInfo &callInfo)
{
    if (!IsValidSlotId(callInfo.slotId)) {
        TELEPHONY_LOGE("CellularCallService::StartDtmf return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    if (srvccState_ == SrvccState::STARTED) {
        return TELEPHONY_ERR_FAIL;
    }
    if (CallType::TYPE_IMS == callInfo.callType) {
        auto imsControl = GetImsControl(callInfo.slotId);
        if (imsControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::StartDtmf return, imsControl is nullptr");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return imsControl->StartDtmf(imsControl->GetConnectionMap(), cDtmfCode, callInfo);
    } else if (CallType::TYPE_CS == callInfo.callType) {
        auto csControl = GetCsControl(callInfo.slotId);
        if (csControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::StartDtmf return, csControl is nullptr");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return csControl->StartDtmf(csControl->GetConnectionMap(), cDtmfCode, callInfo);
    }
    TELEPHONY_LOGE("CellularCallService::StartDtmf return, call type error.");
    return TELEPHONY_ERR_ARGUMENT_INVALID;
}

int32_t CellularCallService::StopDtmf(const CellularCallInfo &callInfo)
{
    if (!IsValidSlotId(callInfo.slotId)) {
        TELEPHONY_LOGE("CellularCallService::StopDtmf return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    if (srvccState_ == SrvccState::STARTED) {
        return TELEPHONY_ERR_FAIL;
    }
    if (CallType::TYPE_IMS == callInfo.callType) {
        auto imsControl = GetImsControl(callInfo.slotId);
        if (imsControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::StopDtmf return, imsControl is nullptr");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return imsControl->StopDtmf(imsControl->GetConnectionMap(), callInfo);
    } else if (CallType::TYPE_CS == callInfo.callType) {
        auto csControl = GetCsControl(callInfo.slotId);
        if (csControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::StopDtmf return, csControl is nullptr");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return csControl->StopDtmf(csControl->GetConnectionMap(), callInfo);
    }
    TELEPHONY_LOGE("CellularCallService::StopDtmf return, call type error.");
    return TELEPHONY_ERR_ARGUMENT_INVALID;
}

int32_t CellularCallService::PostDialProceed(const CellularCallInfo &callInfo, const bool proceed)
{
    if (!IsValidSlotId(callInfo.slotId)) {
        TELEPHONY_LOGE("CellularCallService::PostDialProceed return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    if (srvccState_ == SrvccState::STARTED) {
        TELEPHONY_LOGE("CellularCallService::PostDialProceed srvccState_ is started");
        return TELEPHONY_ERR_FAIL;
    }
    if (callInfo.callType == CallType::TYPE_IMS) {
        auto imsControl = GetImsControl(callInfo.slotId);
        if (imsControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::PostDialProceed return, imsControl is nullptr");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return imsControl->PostDialProceed(callInfo, proceed);
    } else if (callInfo.callType == CallType::TYPE_CS) {
        auto csControl = GetCsControl(callInfo.slotId);
        if (csControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::PostDialProceed return, csControl is nullptr");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return csControl->PostDialProceed(callInfo, proceed);
    }
    TELEPHONY_LOGE("CellularCallService::PostDialProceed return, call type error.");
    return TELEPHONY_ERR_ARGUMENT_INVALID;
}

int32_t CellularCallService::SendDtmf(char cDtmfCode, const CellularCallInfo &callInfo)
{
    if (!IsValidSlotId(callInfo.slotId)) {
        TELEPHONY_LOGE("CellularCallService::SendDtmf return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    if (srvccState_ == SrvccState::STARTED) {
        return TELEPHONY_ERR_FAIL;
    }
    if (CallType::TYPE_IMS == callInfo.callType) {
        auto imsControl = GetImsControl(callInfo.slotId);
        if (imsControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::SendDtmf return, imsControl is nullptr");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return imsControl->SendDtmf(imsControl->GetConnectionMap(), cDtmfCode, callInfo);
    } else if (CallType::TYPE_CS == callInfo.callType) {
        auto csControl = GetCsControl(callInfo.slotId);
        if (csControl == nullptr) {
            TELEPHONY_LOGE("CellularCallService::SendDtmf return, csControl is nullptr");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return csControl->SendDtmf(csControl->GetConnectionMap(), cDtmfCode, callInfo);
    }
    TELEPHONY_LOGE("CellularCallService::SendDtmf return, call type error.");
    return TELEPHONY_ERR_ARGUMENT_INVALID;
}

int32_t CellularCallService::StartRtt(int32_t slotId, const std::string &msg)
{
    auto control = GetImsControl(slotId);
    if (control == nullptr) {
        TELEPHONY_LOGE("CellularCallService::StartRtt return, control is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return control->StartRtt(slotId, msg);
}

int32_t CellularCallService::StopRtt(int32_t slotId)
{
    auto control = GetImsControl(slotId);
    if (control == nullptr) {
        TELEPHONY_LOGE("CellularCallService::StopRtt return, control is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return control->StopRtt(slotId);
}

int32_t CellularCallService::SetCallTransferInfo(int32_t slotId, const CallTransferInfo &cTInfo)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CellularCallService::SetCallTransferInfo return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    CellularCallSupplement cellularCallSupplement;
    if (cTInfo.settingType == CallTransferSettingType::CALL_TRANSFER_DISABLE) {
        DelayedSingleton<CellularCallHiSysEvent>::GetInstance()->SetCallForwardingInfo(
            slotId, false, cTInfo.transferNum);
    } else if (cTInfo.settingType == CallTransferSettingType::CALL_TRANSFER_ENABLE) {
        DelayedSingleton<CellularCallHiSysEvent>::GetInstance()->SetCallForwardingInfo(
            slotId, true, cTInfo.transferNum);
    }
    return cellularCallSupplement.SetCallTransferInfo(slotId, cTInfo);
}

int32_t CellularCallService::CanSetCallTransferTime(int32_t slotId, bool &result)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    CellularCallSupplement cellularCallSupplement;
    return cellularCallSupplement.CanSetCallTransferTime(slotId, result);
}

int32_t CellularCallService::GetCallTransferInfo(int32_t slotId, CallTransferType type)
{
    TELEPHONY_LOGD("CellularCallService::GetCallTransferInfo");
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CellularCallService::GetCallTransferInfo return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    CellularCallSupplement cellularCallSupplement;
    return cellularCallSupplement.GetCallTransferInfo(slotId, type);
}

std::shared_ptr<CSControl> CellularCallService::GetCsControl(int32_t slotId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("return nullptr, invalid slot id");
        return nullptr;
    }
    return csControlMap_[slotId];
}

std::shared_ptr<IMSControl> CellularCallService::GetImsControl(int32_t slotId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("return nullptr, invalid slot id");
        return nullptr;
    }
    return imsControlMap_[slotId];
}

std::shared_ptr<SatelliteControl> CellularCallService::GetSatelliteControl(int32_t slotId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    return satelliteControlMap_[slotId];
}

void CellularCallService::SetCsControl(int32_t slotId, const std::shared_ptr<CSControl> &csControl)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("invalid slot id, return");
        return;
    }
    csControlMap_[slotId] = csControl;
}

void CellularCallService::SetImsControl(int32_t slotId, const std::shared_ptr<IMSControl> &imsControl)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("invalid slot id, return");
        return;
    }
    imsControlMap_[slotId] = imsControl;
}

void CellularCallService::SetSatelliteControl(int32_t slotId, const std::shared_ptr<SatelliteControl> &satelliteControl)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("invalid slot id, return");
        return;
    }
    satelliteControlMap_[slotId] = satelliteControl;
}

int32_t CellularCallService::SetCallWaiting(int32_t slotId, bool activate)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CellularCallService::SetCallWaiting return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    CellularCallSupplement cellularCallSupplement;
    return cellularCallSupplement.SetCallWaiting(slotId, activate);
}

int32_t CellularCallService::GetCallWaiting(int32_t slotId)
{
    TELEPHONY_LOGD("CellularCallService::GetCallWaiting");
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CellularCallService::GetCallWaiting return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    CellularCallSupplement cellularCallSupplement;
    return cellularCallSupplement.GetCallWaiting(slotId);
}

int32_t CellularCallService::SetCallRestriction(int32_t slotId, const CallRestrictionInfo &crInfo)
{
    TELEPHONY_LOGD("CellularCallService::SetCallRestriction");
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CellularCallService::SetCallRestriction return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    CellularCallSupplement cellularCallSupplement;
    return cellularCallSupplement.SetCallRestriction(slotId, crInfo);
}

int32_t CellularCallService::GetCallRestriction(int32_t slotId, CallRestrictionType facType)
{
    TELEPHONY_LOGD("CellularCallService::GetCallRestriction");
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CellularCallService::GetCallRestriction return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    CellularCallSupplement cellularCallSupplement;
    return cellularCallSupplement.GetCallRestriction(slotId, facType);
}

int32_t CellularCallService::SetCallRestrictionPassword(
    int32_t slotId, CallRestrictionType facType, const char *oldPassword, const char *newPassword)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    CellularCallSupplement cellularCallSupplement;
    return cellularCallSupplement.SetBarringPassword(slotId, facType, oldPassword, newPassword);
}

int32_t CellularCallService::IsEmergencyPhoneNumber(int32_t slotId, const std::string &phoneNum, bool &enabled)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CellularCallService::IsEmergencyPhoneNumber return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    EmergencyUtils emergencyUtils;
    return emergencyUtils.IsEmergencyCall(slotId, phoneNum, enabled);
}

int32_t CellularCallService::SetEmergencyCallList(int32_t slotId, std::vector<EmergencyCall> &eccVec)
{
    TELEPHONY_LOGD("CellularCallService::SetEmergencyCallList start");
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CellularCallService::SetMute return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    CellularCallConfig config;
    return config.SetEmergencyCallList(slotId, eccVec);
}

int32_t CellularCallService::SetDomainPreferenceMode(int32_t slotId, int32_t mode)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CellularCallService::SetDomainPreferenceMode return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    CellularCallConfig config;
    return config.SetDomainPreferenceMode(slotId, mode);
}

int32_t CellularCallService::GetDomainPreferenceMode(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CellularCallService::GetDomainPreferenceMode return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    CellularCallConfig config;
    return config.GetDomainPreferenceMode(slotId);
}

int32_t CellularCallService::SetImsSwitchStatus(int32_t slotId, bool active)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CellularCallService::SetImsSwitchStatus return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    CellularCallConfig config;
    return config.SetImsSwitchStatus(slotId, active);
}

int32_t CellularCallService::GetImsSwitchStatus(int32_t slotId, bool &enabled)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CellularCallService::GetImsSwitchStatus return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    CellularCallConfig config;
    return config.GetImsSwitchStatus(slotId, enabled);
}

int32_t CellularCallService::SetVoNRState(int32_t slotId, int32_t state)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CellularCallService::SetVoNRState return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    CellularCallConfig config;
    return config.SetVoNRSwitchStatus(slotId, state);
}

int32_t CellularCallService::GetVoNRState(int32_t slotId, int32_t &state)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CellularCallService::GetVoNRState return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    CellularCallConfig config;
    return config.GetVoNRSwitchStatus(slotId, state);
}

int32_t CellularCallService::SetImsConfig(int32_t slotId, ImsConfigItem item, const std::string &value)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CellularCallService::SetImsConfig return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    CellularCallConfig config;
    return config.SetImsConfig(item, value);
}

int32_t CellularCallService::SetImsConfig(int32_t slotId, ImsConfigItem item, int32_t value)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CellularCallService::SetImsConfig return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    CellularCallConfig config;
    return config.SetImsConfig(item, value);
}

int32_t CellularCallService::GetImsConfig(int32_t slotId, ImsConfigItem item)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CellularCallService::GetImsConfig return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    CellularCallConfig config;
    return config.GetImsConfig(item);
}

int32_t CellularCallService::SetImsFeatureValue(int32_t slotId, FeatureType type, int32_t value)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CellularCallService::SetImsFeatureValue return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    CellularCallConfig config;
    return config.SetImsFeatureValue(type, value);
}

int32_t CellularCallService::GetImsFeatureValue(int32_t slotId, FeatureType type)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CellularCallService::GetImsFeatureValue return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    CellularCallConfig config;
    return config.GetImsFeatureValue(type);
}

bool CellularCallService::IsValidSlotId(int32_t slotId) const
{
    const int32_t slotSingle = 1;
    const int32_t slotDouble = 2;
    if (SIM_SLOT_COUNT == slotSingle) {
        return slotId == DEFAULT_SIM_SLOT_ID;
    } else if (SIM_SLOT_COUNT == slotDouble) {
        return slotId == SIM_SLOT_0 || slotId == SIM_SLOT_1;
    }
    return false;
}

bool CellularCallService::IsNeedIms(int32_t slotId) const
{
    ModuleServiceUtils moduleUtils;
    CellularCallConfig config;
    bool imsRegState = moduleUtils.GetImsRegistrationState(slotId);
    bool imsServiceConnected = moduleUtils.NeedCallImsService();
    int32_t preferenceMode = config.GetPreferenceMode(slotId);
    bool imsSwitchStatus = false;
    config.GetImsSwitchStatus(slotId, imsSwitchStatus);
    TELEPHONY_LOGI("IsNeedIms state:%{public}d, mode:%{public}d, status:%{public}d, connected:%{public}d", imsRegState,
        preferenceMode, imsSwitchStatus, imsServiceConnected);
    if (imsRegState && preferenceMode != DomainPreferenceMode::CS_VOICE_ONLY && imsSwitchStatus &&
        imsServiceConnected) {
        return true;
    }
    return false;
}

std::shared_ptr<CellularCallHandler> CellularCallService::GetHandler(int32_t slotId)
{
    return handlerMap_[slotId];
}

int32_t CellularCallService::ControlCamera(int32_t slotId, int32_t index, const std::string &cameraId)
{
    auto videoCallControl = DelayedSingleton<ImsVideoCallControl>::GetInstance();
    if (videoCallControl == nullptr) {
        TELEPHONY_LOGE("videoCallControl is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return videoCallControl->ControlCamera(slotId, index, cameraId);
}

int32_t CellularCallService::SetPreviewWindow(
    int32_t slotId, int32_t index, const std::string &surfaceId, sptr<Surface> surface)
{
    auto videoCallControl = DelayedSingleton<ImsVideoCallControl>::GetInstance();
    if (videoCallControl == nullptr) {
        TELEPHONY_LOGE("videoCallControl is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return videoCallControl->SetPreviewWindow(slotId, index, surfaceId, surface);
}

int32_t CellularCallService::SetDisplayWindow(
    int32_t slotId, int32_t index, const std::string &surfaceId, sptr<Surface> surface)
{
    auto videoCallControl = DelayedSingleton<ImsVideoCallControl>::GetInstance();
    if (videoCallControl == nullptr) {
        TELEPHONY_LOGE("videoCallControl is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return videoCallControl->SetDisplayWindow(slotId, index, surfaceId, surface);
}

int32_t CellularCallService::SetCameraZoom(float zoomRatio)
{
    auto videoCallControl = DelayedSingleton<ImsVideoCallControl>::GetInstance();
    if (videoCallControl == nullptr) {
        TELEPHONY_LOGE("videoCallControl is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return videoCallControl->SetCameraZoom(zoomRatio);
}

int32_t CellularCallService::SetPausePicture(int32_t slotId, int32_t index, const std::string &path)
{
    auto videoCallControl = DelayedSingleton<ImsVideoCallControl>::GetInstance();
    if (videoCallControl == nullptr) {
        TELEPHONY_LOGE("videoCallControl is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return videoCallControl->SetPausePicture(slotId, index, path);
}

int32_t CellularCallService::SetDeviceDirection(int32_t slotId, int32_t callIndex, int32_t rotation)
{
    auto videoCallControl = DelayedSingleton<ImsVideoCallControl>::GetInstance();
    if (videoCallControl == nullptr) {
        TELEPHONY_LOGE("videoCallControl is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return videoCallControl->SetDeviceDirection(slotId, callIndex, rotation);
}

int32_t CellularCallService::SetMute(int32_t slotId, int32_t mute)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CellularCallService::SetMute return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    CellularCallConfig config;
    return config.SetMute(slotId, mute);
}

int32_t CellularCallService::GetMute(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CellularCallService::GetMute return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    CellularCallConfig config;
    return config.GetMute(slotId);
}

int32_t CellularCallService::CloseUnFinishedUssd(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CellularCallService::CloseUnFinishedUssd return, invalid slot id");
        return CALL_ERR_INVALID_SLOT_ID;
    }
    CellularCallSupplement cellularCallSupplement;
    return cellularCallSupplement.CloseUnFinishedUssd(slotId);
}

int32_t CellularCallService::SetControl(const CellularCallInfo &info)
{
    if (info.callType == CallType::TYPE_CS) {
        auto csControl = GetCsControl(info.slotId);
        if (csControl == nullptr) {
            TELEPHONY_LOGI("GetCsControl csControl is nullptr");
            csControl = std::make_shared<CSControl>();
            if (csControl == nullptr) {
                TELEPHONY_LOGE("csControl is nullptr");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            SetCsControl(info.slotId, csControl);
        }
    }
    if (info.callType == CallType::TYPE_IMS) {
        auto imsControl = GetImsControl(info.slotId);
        if (imsControl == nullptr) {
            TELEPHONY_LOGI("GetImsControl imsControl is nullptr");
            imsControl = std::make_shared<IMSControl>();
            if (imsControl == nullptr) {
                TELEPHONY_LOGE("imsControl is nullptr");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            SetImsControl(info.slotId, imsControl);
        }
    }
    return TELEPHONY_SUCCESS;
}

int32_t CellularCallService::ClearAllCalls(const std::vector<CellularCallInfo> &infos)
{
    if (infos.empty()) {
        TELEPHONY_LOGE("CellularCallService::ClearAllCalls infos is empty");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    for (auto &info : infos) {
        if (SetControl(info) != TELEPHONY_SUCCESS) {
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
    }
    HangUpWithCellularCallRestart(infos);
    return TELEPHONY_SUCCESS;
}

void CellularCallService::SetSrvccState(int32_t srvccState)
{
    srvccState_ = srvccState;
}

int32_t CellularCallService::GetSrvccState()
{
    return srvccState_;
}

bool CellularCallService::UseImsForEmergency(const CellularCallInfo &callInfo, bool isEcc)
{
    ModuleServiceUtils moduleUtils;
    CellularCallConfig config;
    if (isEcc && moduleUtils.NeedCallImsService() && config.GetImsPreferForEmergencyConfig(callInfo.slotId)) {
        return true;
    }
    return false;
}

void CellularCallService::HandleCallManagerException()
{
    ModuleServiceUtils obtain;
    std::vector<int32_t> slotVector = obtain.GetSlotInfo();
    for (const auto &it : slotVector) {
        auto csControl = GetCsControl(it);
        if (csControl != nullptr) {
            csControl->HangUpAllConnection(it);
        }
        auto imsControl = GetImsControl(it);
        if (imsControl != nullptr) {
            imsControl->HangUpAllConnection(it);
        }
    }
}

void CellularCallService::HangUpWithCellularCallRestart(const std::vector<CellularCallInfo> &infos)
{
    ModuleServiceUtils obtain;
    std::vector<int32_t> slotVector = obtain.GetSlotInfo();
    for (const auto &it : slotVector) {
        auto csControl = GetCsControl(it);
        if (csControl != nullptr) {
            csControl->ReportHangUp(infos, it);
            csControl->HangUpAllConnection(it);
        }
        auto imsControl = GetImsControl(it);
        if (imsControl != nullptr) {
            imsControl->ReportHangUp(infos, it);
            imsControl->RestoreConnection(infos, it);
            imsControl->HangUpAllConnection(it);
            imsControl->ReleaseAllConnection();
        }
    }
}

void CellularCallService::HandleCellularControlException(const CellularCallInfo &callInfo)
{
    TELEPHONY_LOGI("HandleCellularControlException entry");
    CallsReportInfo callsReportInfo;
    CallReportInfo reportInfo = EncapsulationCallReportInfo(callInfo);
    callsReportInfo.callVec.push_back(reportInfo);
    if (DelayedSingleton<CellularCallRegister>::GetInstance() == nullptr) {
        TELEPHONY_LOGE("HandleCellularControlException return, GetInstance() is nullptr.");
        return;
    }
    callsReportInfo.slotId = callInfo.slotId;
    DelayedSingleton<CellularCallRegister>::GetInstance()->ReportCallsInfo(callsReportInfo);
}

CallReportInfo CellularCallService::EncapsulationCallReportInfo(const CellularCallInfo &callInfo)
{
    TELEPHONY_LOGD("EncapsulationCallReportInfo entry");
    CallReportInfo callReportInfo;
    if (memset_s(&callReportInfo, sizeof(callReportInfo), 0, sizeof(callReportInfo)) != EOK) {
        TELEPHONY_LOGE("EncapsulationCallReportInfo return, memset_s fail.");
        return callReportInfo;
    }

    size_t cpyLen = strlen(callInfo.phoneNum) + 1;
    if (cpyLen > static_cast<size_t>(kMaxNumberLen + 1)) {
        TELEPHONY_LOGE("EncapsulationCallReportInfo return, strcpy_s fail.");
        return callReportInfo;
    }
    if (strcpy_s(callReportInfo.accountNum, cpyLen, callInfo.phoneNum) != EOK) {
        TELEPHONY_LOGE("EncapsulationCallReportInfo return, strcpy_s fail.");
        return callReportInfo;
    }
    callReportInfo.index = callInfo.index;
    callReportInfo.accountId = callInfo.slotId;
    callReportInfo.state = TelCallState::CALL_STATUS_DISCONNECTED;
    callReportInfo.callType = callInfo.callType;
    return callReportInfo;
}

CellularCallService::SystemAbilityStatusChangeListener::SystemAbilityStatusChangeListener(
    std::shared_ptr<CellularCallHandler> &cellularCallHandler)
    : cellularCallHandler_(cellularCallHandler)
{}

void CellularCallService::SystemAbilityStatusChangeListener::OnAddSystemAbility(
    int32_t systemAbilityId, const std::string &deviceId)
{
    if (systemAbilityId != COMMON_EVENT_SERVICE_ID && systemAbilityId != TELEPHONY_SATELLITE_SYS_ABILITY_ID) {
        TELEPHONY_LOGE("systemAbilityId is not COMMON_EVENT_SERVICE_ID or TELEPHONY_SATELLITE_SYS_ABILITY_ID");
        return;
    }
    if (cellularCallHandler_ == nullptr) {
        TELEPHONY_LOGE("COMMON_EVENT_SERVICE_ID cellularCallHandler_ is nullptr");
        return;
    }
    if (systemAbilityId == COMMON_EVENT_SERVICE_ID) {
        bool subscribeResult = EventFwk::CommonEventManager::SubscribeCommonEvent(cellularCallHandler_);
        TELEPHONY_LOGI("subscribeResult = %{public}d", subscribeResult);
    } else if (systemAbilityId == TELEPHONY_SATELLITE_SYS_ABILITY_ID) {
        DelayedSingleton<SatelliteCallClient>::GetInstance()->Init();
        cellularCallHandler_->RegisterSatelliteCallCallbackHandler();
    }
}

void CellularCallService::SystemAbilityStatusChangeListener::OnRemoveSystemAbility(
    int32_t systemAbilityId, const std::string &deviceId)
{
    switch (systemAbilityId) {
        case TELEPHONY_CALL_MANAGER_SYS_ABILITY_ID: {
            auto cellularCallRegister = DelayedSingleton<CellularCallRegister>::GetInstance();
            if (cellularCallRegister != nullptr) {
                cellularCallRegister->UnRegisterCallManagerCallBack();
            }
            auto cellularCallService = DelayedSingleton<CellularCallService>::GetInstance();
            if (cellularCallService == nullptr) {
                TELEPHONY_LOGE("cellularCallService is nullptr");
                return;
            }
            cellularCallService->HandleCallManagerException();
            count_++;
            CellularCallHiSysEvent::WriteFoundationRestartFaultEvent(count_);
            break;
        }
        case COMMON_EVENT_SERVICE_ID: {
            if (cellularCallHandler_ == nullptr) {
                TELEPHONY_LOGE("cellularCallHandler_ is nullptr");
                return;
            }
            bool unSubscribeResult = EventFwk::CommonEventManager::UnSubscribeCommonEvent(cellularCallHandler_);
            TELEPHONY_LOGI("unSubscribeResult = %{public}d", unSubscribeResult);
            break;
        }
        case TELEPHONY_SATELLITE_SYS_ABILITY_ID: {
            DelayedSingleton<SatelliteCallClient>::GetInstance()->UnInit();
            break;
        }
        default:
            TELEPHONY_LOGE("systemAbilityId is invalid");
            break;
    }
}

#ifdef CALL_MANAGER_AUTO_START_OPTIMIZE
void CellularCallService::StartCallManagerService()
{
    sptr<ISystemAbilityManager> managerPtr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (managerPtr == nullptr) {
        TELEPHONY_LOGE("GetSystemAbilityManager failed!");
        return;
    }

    sptr<IRemoteObject> iRemoteObjectPtr = managerPtr->GetSystemAbility(TELEPHONY_CALL_MANAGER_SYS_ABILITY_ID);
    if (iRemoteObjectPtr == nullptr) {
        TELEPHONY_LOGE("GetSystemAbility failed!");
    }
}
#endif
} // namespace Telephony
} // namespace OHOS

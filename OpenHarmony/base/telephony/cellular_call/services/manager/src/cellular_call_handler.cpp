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

#include "cellular_call_handler.h"

#include "cellular_call_config.h"
#include "cellular_call_hisysevent.h"
#include "cellular_call_service.h"
#include "hitrace_meter.h"
#include "tel_ril_call_parcel.h"
#include "tel_ril_types.h"
#include "ims_call_client.h"
#include "operator_config_types.h"
#include "radio_event.h"
#include "resource_utils.h"
#include "satellite_call_client.h"
#include "satellite_radio_event.h"
#include "securec.h"

namespace OHOS {
namespace Telephony {
const uint32_t GET_CS_CALL_DATA_ID = 10001;
const uint32_t GET_IMS_CALL_DATA_ID = 10002;
const uint32_t OPERATOR_CONFIG_CHANGED_ID = 10004;
const uint32_t GET_SATELLITE_CALL_DATA_ID = 10005;
const int64_t DELAY_TIME = 100;
const int32_t MAX_REQUEST_COUNT = 50;
// message was null, mean report the default message to user which have been define at CellularCallSupplement
const std::string DEFAULT_NULL_MESSAGE = "";

CellularCallHandler::CellularCallHandler(const EventFwk::CommonEventSubscribeInfo &subscriberInfo)
    : TelEventHandler("CellularCallHandler"), CommonEventSubscriber(subscriberInfo)
{
    InitBasicFuncMap();
    InitConfigFuncMap();
    InitSupplementFuncMap();
    InitActiveReportFuncMap();
    InitSatelliteCallFuncMap();
}

void CellularCallHandler::InitBasicFuncMap()
{
    requestFuncMap_[RadioEvent::RADIO_DIAL] = &CellularCallHandler::DialResponse;
    requestFuncMap_[RadioEvent::RADIO_HANGUP_CONNECT] = &CellularCallHandler::CommonResultResponse;
    requestFuncMap_[RadioEvent::RADIO_REJECT_CALL] = &CellularCallHandler::CommonResultResponse;
    requestFuncMap_[RadioEvent::RADIO_ACCEPT_CALL] = &CellularCallHandler::CommonResultResponse;
    requestFuncMap_[RadioEvent::RADIO_HOLD_CALL] = &CellularCallHandler::CommonResultResponse;
    requestFuncMap_[RadioEvent::RADIO_ACTIVE_CALL] = &CellularCallHandler::CommonResultResponse;
    requestFuncMap_[RadioEvent::RADIO_SWAP_CALL] = &CellularCallHandler::SwapCallResponse;
    requestFuncMap_[RadioEvent::RADIO_COMBINE_CALL] = &CellularCallHandler::CommonResultResponse;
    requestFuncMap_[RadioEvent::RADIO_JOIN_CALL] = &CellularCallHandler::CommonResultResponse;
    requestFuncMap_[RadioEvent::RADIO_SPLIT_CALL] = &CellularCallHandler::CommonResultResponse;
    requestFuncMap_[RadioEvent::RADIO_CALL_SUPPLEMENT] = &CellularCallHandler::CommonResultResponse;
    requestFuncMap_[RadioEvent::RADIO_SEND_DTMF] = &CellularCallHandler::SendDtmfResponse;
    requestFuncMap_[RadioEvent::RADIO_START_DTMF] = &CellularCallHandler::StartDtmfResponse;
    requestFuncMap_[RadioEvent::RADIO_STOP_DTMF] = &CellularCallHandler::StopDtmfResponse;
    requestFuncMap_[RadioEvent::RADIO_CURRENT_CALLS] = &CellularCallHandler::GetCsCallsDataResponse;
    requestFuncMap_[RadioEvent::RADIO_GET_CALL_FAIL_REASON] = &CellularCallHandler::GetCallFailReasonResponse;
    requestFuncMap_[RadioEvent::RADIO_RECV_CALL_MEDIA_MODE_REQUEST] =
        &CellularCallHandler::ReceiveUpdateCallMediaModeRequest;
    requestFuncMap_[RadioEvent::RADIO_RECV_CALL_MEDIA_MODE_RESPONSE] =
        &CellularCallHandler::ReceiveUpdateCallMediaModeResponse;
    requestFuncMap_[RadioEvent::RADIO_CALL_SESSION_EVENT_CHANGED] = &CellularCallHandler::HandleCallSessionEventChanged;
    requestFuncMap_[RadioEvent::RADIO_CALL_PEER_DIMENSIONS_CHANGED] =
        &CellularCallHandler::HandlePeerDimensionsChanged;
    requestFuncMap_[RadioEvent::RADIO_CALL_DATA_USAGE_CHANGED] = &CellularCallHandler::HandleCallDataUsageChanged;
    requestFuncMap_[RadioEvent::RADIO_CAMERA_CAPABILITIES_CHANGED] =
        &CellularCallHandler::HandleCameraCapabilitiesChanged;

    requestFuncMap_[GET_CS_CALL_DATA_ID] = &CellularCallHandler::GetCsCallsDataRequest;
    requestFuncMap_[GET_IMS_CALL_DATA_ID] = &CellularCallHandler::GetImsCallsDataRequest;
    requestFuncMap_[REGISTER_HANDLER_ID] = &CellularCallHandler::RegisterHandler;
    requestFuncMap_[MMIHandlerId::EVENT_MMI_Id] = &CellularCallHandler::GetMMIResponse;
    requestFuncMap_[DtmfHandlerId::EVENT_EXECUTE_POST_DIAL] = &CellularCallHandler::ExecutePostDial;

    requestFuncMap_[RadioEvent::RADIO_IMS_GET_CALL_DATA] = &CellularCallHandler::GetImsCallsDataResponse;
}

void CellularCallHandler::InitConfigFuncMap()
{
    requestFuncMap_[RadioEvent::RADIO_SET_CMUT] = &CellularCallHandler::SetMuteResponse;
    requestFuncMap_[RadioEvent::RADIO_GET_CMUT] = &CellularCallHandler::GetMuteResponse;
    requestFuncMap_[RadioEvent::RADIO_SET_CALL_PREFERENCE_MODE] = &CellularCallHandler::SetDomainPreferenceModeResponse;
    requestFuncMap_[RadioEvent::RADIO_GET_CALL_PREFERENCE_MODE] = &CellularCallHandler::GetDomainPreferenceModeResponse;
    requestFuncMap_[RadioEvent::RADIO_SET_IMS_SWITCH_STATUS] = &CellularCallHandler::SetImsSwitchStatusResponse;
    requestFuncMap_[RadioEvent::RADIO_GET_IMS_SWITCH_STATUS] = &CellularCallHandler::GetImsSwitchStatusResponse;
    requestFuncMap_[RadioEvent::RADIO_SET_VONR_SWITCH_STATUS] = &CellularCallHandler::SetVoNRSwitchStatusResponse;
    requestFuncMap_[RadioEvent::RADIO_SET_EMERGENCY_CALL_LIST] = &CellularCallHandler::SetEmergencyCallListResponse;
    requestFuncMap_[RadioEvent::RADIO_GET_EMERGENCY_CALL_LIST] = &CellularCallHandler::GetEmergencyCallListResponse;
    requestFuncMap_[OPERATOR_CONFIG_CHANGED_ID] = &CellularCallHandler::HandleOperatorConfigChanged;
}

void CellularCallHandler::InitSupplementFuncMap()
{
    requestFuncMap_[RadioEvent::RADIO_GET_CALL_WAIT] = &CellularCallHandler::GetCallWaitingResponse;
    requestFuncMap_[RadioEvent::RADIO_SET_CALL_WAIT] = &CellularCallHandler::SetCallWaitingResponse;
    requestFuncMap_[RadioEvent::RADIO_GET_CALL_FORWARD] = &CellularCallHandler::GetCallTransferResponse;
    requestFuncMap_[RadioEvent::RADIO_SET_CALL_FORWARD] = &CellularCallHandler::SetCallTransferInfoResponse;
    requestFuncMap_[RadioEvent::RADIO_GET_CALL_CLIP] = &CellularCallHandler::GetClipResponse;
    requestFuncMap_[RadioEvent::RADIO_SET_CALL_CLIP] = &CellularCallHandler::SetClipResponse;
    requestFuncMap_[RadioEvent::RADIO_GET_CALL_CLIR] = &CellularCallHandler::GetClirResponse;
    requestFuncMap_[RadioEvent::RADIO_SET_CALL_CLIR] = &CellularCallHandler::SetClirResponse;
    requestFuncMap_[RadioEvent::RADIO_IMS_GET_COLR] = &CellularCallHandler::GetColrResponse;
    requestFuncMap_[RadioEvent::RADIO_IMS_SET_COLR] = &CellularCallHandler::SetColrResponse;
    requestFuncMap_[RadioEvent::RADIO_IMS_GET_COLP] = &CellularCallHandler::GetColpResponse;
    requestFuncMap_[RadioEvent::RADIO_IMS_SET_COLP] = &CellularCallHandler::SetColpResponse;
    requestFuncMap_[RadioEvent::RADIO_GET_CALL_RESTRICTION] = &CellularCallHandler::GetCallRestrictionResponse;
    requestFuncMap_[RadioEvent::RADIO_SET_CALL_RESTRICTION] = &CellularCallHandler::SetCallRestrictionResponse;
    requestFuncMap_[RadioEvent::RADIO_SET_CALL_RESTRICTION_PWD] = &CellularCallHandler::SetBarringPasswordResponse;
    requestFuncMap_[RadioEvent::RADIO_SET_USSD] = &CellularCallHandler::SendUssdResponse;
    requestFuncMap_[MMIHandlerId::EVENT_SET_UNLOCK_PIN_PUK_ID] = &CellularCallHandler::SendUnlockPinPukResponse;
    requestFuncMap_[RadioEvent::RADIO_CLOSE_UNFINISHED_USSD] = &CellularCallHandler::CloseUnFinishedUssdResponse;
}

void CellularCallHandler::InitActiveReportFuncMap()
{
    requestFuncMap_[RadioEvent::RADIO_CALL_STATUS_INFO] = &CellularCallHandler::CsCallStatusInfoReport;
    requestFuncMap_[RadioEvent::RADIO_IMS_CALL_STATUS_INFO] = &CellularCallHandler::ImsCallStatusInfoReport;
    requestFuncMap_[RadioEvent::RADIO_AVAIL] = &CellularCallHandler::GetCsCallData;
    requestFuncMap_[RadioEvent::RADIO_NOT_AVAIL] = &CellularCallHandler::GetCsCallData;
    requestFuncMap_[RadioEvent::RADIO_CALL_USSD_NOTICE] = &CellularCallHandler::UssdNotifyResponse;
    requestFuncMap_[RadioEvent::RADIO_CALL_RINGBACK_VOICE] = &CellularCallHandler::CallRingBackVoiceResponse;
    requestFuncMap_[RadioEvent::RADIO_CALL_SRVCC_STATUS] = &CellularCallHandler::UpdateSrvccStateReport;
    requestFuncMap_[RadioEvent::RADIO_CALL_SS_NOTICE] = &CellularCallHandler::SsNotifyResponse;
    requestFuncMap_[RadioEvent::RADIO_CALL_EMERGENCY_NUMBER_REPORT] = &CellularCallHandler::ReportEccChanged;
    requestFuncMap_[RadioEvent::RADIO_SIM_STATE_CHANGE] = &CellularCallHandler::SimStateChangeReport;
    requestFuncMap_[RadioEvent::RADIO_SIM_RECORDS_LOADED] = &CellularCallHandler::SimRecordsLoadedReport;
    requestFuncMap_[RadioEvent::RADIO_SIM_ACCOUNT_LOADED] = &CellularCallHandler::SimAccountLoadedReport;
    requestFuncMap_[RadioEvent::RADIO_CALL_RSRVCC_STATUS] = &CellularCallHandler::UpdateRsrvccStateReport;
    requestFuncMap_[RadioEvent::RADIO_RESIDENT_NETWORK_CHANGE] = &CellularCallHandler::ResidentNetworkChangeReport;
    requestFuncMap_[RadioEvent::RADIO_PS_CONNECTION_ATTACHED] = &CellularCallHandler::NetworkStateChangeReport;
    requestFuncMap_[RadioEvent::RADIO_PS_CONNECTION_DETACHED] = &CellularCallHandler::NetworkStateChangeReport;
    requestFuncMap_[RadioEvent::RADIO_RIL_ADAPTER_HOST_DIED] = &CellularCallHandler::OnRilAdapterHostDied;
    requestFuncMap_[RadioEvent::RADIO_FACTORY_RESET] = &CellularCallHandler::FactoryReset;
#ifdef CALL_MANAGER_AUTO_START_OPTIMIZE
    requestFuncMap_[RadioEvent::RADIO_GET_STATUS] = &CellularCallHandler::GetRadioStateProcess;
    requestFuncMap_[RadioEvent::RADIO_STATE_CHANGED] = &CellularCallHandler::RadioStateChangeProcess;
#endif
}

void CellularCallHandler::InitSatelliteCallFuncMap()
{
    requestFuncMap_[SatelliteRadioEvent::SATELLITE_RADIO_CALL_STATE_CHANGED] =
        &CellularCallHandler::SatelliteCallStatusInfoReport;
    requestFuncMap_[SatelliteRadioEvent::SATELLITE_RADIO_DIAL] = &CellularCallHandler::DialSatelliteResponse;
    requestFuncMap_[SatelliteRadioEvent::SATELLITE_RADIO_HANGUP] = &CellularCallHandler::CommonResultResponse;
    requestFuncMap_[SatelliteRadioEvent::SATELLITE_RADIO_ANSWER] = &CellularCallHandler::CommonResultResponse;
    requestFuncMap_[SatelliteRadioEvent::SATELLITE_RADIO_REJECT] = &CellularCallHandler::CommonResultResponse;
    requestFuncMap_[SatelliteRadioEvent::SATELLITE_RADIO_GET_CALL_DATA] =
        &CellularCallHandler::GetSatelliteCallsDataResponse;
    requestFuncMap_[GET_SATELLITE_CALL_DATA_ID] = &CellularCallHandler::GetSatelliteCallsDataRequest;
}

void CellularCallHandler::RegisterImsCallCallbackHandler()
{
    // Register IMS
    std::shared_ptr<ImsCallClient> imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
    if (imsCallClient != nullptr) {
        imsCallClient->RegisterImsCallCallbackHandler(slotId_, shared_from_this());
    }
}

void CellularCallHandler::RegisterSatelliteCallCallbackHandler()
{
    // Register Satellite
    std::shared_ptr<SatelliteCallClient> satelliteCallClient = DelayedSingleton<SatelliteCallClient>::GetInstance();
    if (satelliteCallClient != nullptr) {
        satelliteCallClient->RegisterSatelliteCallCallbackHandler(slotId_, shared_from_this());
    }
}

void CellularCallHandler::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] event is null", slotId_);
        return;
    }

    uint32_t eventId = event->GetInnerEventId();
    TELEPHONY_LOGD("[slot%{public}d] eventId = %{public}d", slotId_, eventId);

    auto itFunc = requestFuncMap_.find(event->GetInnerEventId());
    if (itFunc != requestFuncMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            return (this->*requestFunc)(event);
        }
    }
    TELEPHONY_LOGI("[slot%{public}d] Function not found, need check.", slotId_);
}

void CellularCallHandler::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    EventFwk::Want want = data.GetWant();
    std::string action = want.GetAction();
    TELEPHONY_LOGI("[slot%{public}d] action=%{public}s code=%{public}d", slotId_, action.c_str(), data.GetCode());
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED) {
        int32_t slotId = want.GetIntParam(BROADCAST_ARG_SLOT_ID, DEFAULT_SIM_SLOT_ID);
        if (slotId_ != slotId) {
            return;
        }
        this->SendEvent(OPERATOR_CONFIG_CHANGED_ID, DELAY_TIME, Priority::HIGH);
    }
}

void CellularCallHandler::GetCsCallData(const AppExecFwk::InnerEvent::Pointer &event)
{
    this->SendEvent(GET_CS_CALL_DATA_ID, 0, Priority::HIGH);
}

void CellularCallHandler::GetImsCallData(const AppExecFwk::InnerEvent::Pointer &event)
{
    this->SendEvent(GET_IMS_CALL_DATA_ID, 0, Priority::HIGH);
}

void CellularCallHandler::GetSatelliteCallData(const AppExecFwk::InnerEvent::Pointer &event)
{
    this->SendEvent(GET_SATELLITE_CALL_DATA_ID, 0, Priority::HIGH);
}

void CellularCallHandler::CellularCallIncomingStartTrace(const int32_t state)
{
    if (state == static_cast<int32_t>(TelCallState::CALL_STATUS_INCOMING)) {
        StartAsyncTrace(HITRACE_TAG_OHOS, "CellularCallIncoming", getpid());
    }
}

void CellularCallHandler::CellularCallIncomingFinishTrace(const int32_t state)
{
    if (state == static_cast<int32_t>(TelCallState::CALL_STATUS_INCOMING)) {
        FinishAsyncTrace(HITRACE_TAG_OHOS, "CellularCallIncoming", getpid());
    }
}

void CellularCallHandler::ReportCsCallsData(const CallInfoList &callInfoList)
{
    auto serviceInstance = DelayedSingleton<CellularCallService>::GetInstance();
    if (serviceInstance == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] serviceInstance is null", slotId_);
        return;
    }
    auto csControl = serviceInstance->GetCsControl(slotId_);
    CallInfo callInfo;
    std::vector<CallInfo>::const_iterator it = callInfoList.calls.begin();
    for (; it != callInfoList.calls.end(); ++it) {
        callInfo.state = (*it).state;
    }
    TELEPHONY_LOGI("[slot%{public}d] callInfoList.callSize:%{public}d", slotId_, callInfoList.callSize);
    CellularCallIncomingStartTrace(callInfo.state);
    if (callInfoList.callSize == 0) {
        if (isInCsRedial_) {
            TELEPHONY_LOGI("[slot%{public}d] Ignore hangup during cs redial", slotId_);
            isInCsRedial_ = false;
            return;
        }
        if (csControl == nullptr) {
            TELEPHONY_LOGE("[slot%{public}d] cs_control is null", slotId_);
            CellularCallIncomingFinishTrace(callInfo.state);
            return;
        }
        if (csControl->ReportCallsData(slotId_, callInfoList) != TELEPHONY_SUCCESS) {
            CellularCallIncomingFinishTrace(callInfo.state);
        }
        serviceInstance->SetCsControl(slotId_, nullptr);
        return;
    }
    if (isInCsRedial_) {
        TELEPHONY_LOGI("[slot%{public}d] Ignore cs call state change during cs redial", slotId_);
        return;
    }
    if (callInfoList.callSize == 1) {
        if (csControl == nullptr) {
            csControl = std::make_shared<CSControl>();
            serviceInstance->SetCsControl(slotId_, csControl);
        }
    }
    if (csControl == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] cs_control is null", slotId_);
        CellularCallIncomingFinishTrace(callInfo.state);
        return;
    }
    if (csControl->ReportCallsData(slotId_, callInfoList) != TELEPHONY_SUCCESS) {
        CellularCallIncomingFinishTrace(callInfo.state);
    }
}

void CellularCallHandler::ReportImsCallsData(const ImsCurrentCallList &imsCallInfoList)
{
    auto serviceInstance = DelayedSingleton<CellularCallService>::GetInstance();
    if (serviceInstance == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] serviceInstance is null", slotId_);
        return;
    }
    ImsCurrentCall imsCallInfo;
    std::vector<ImsCurrentCall>::const_iterator it = imsCallInfoList.calls.begin();
    for (; it != imsCallInfoList.calls.end(); ++it) {
        imsCallInfo.state = (*it).state;
    }
    TELEPHONY_LOGD("[slot%{public}d] imsCallInfoList.callSize:%{public}d", slotId_, imsCallInfoList.callSize);
    CellularCallIncomingStartTrace(imsCallInfo.state);
    auto imsControl = serviceInstance->GetImsControl(slotId_);
    if (imsCallInfoList.callSize == 0) {
        if (imsControl == nullptr) {
            TELEPHONY_LOGE("[slot%{public}d] ims_control is null", slotId_);
            return;
        }
        if (imsControl->ReportImsCallsData(slotId_, imsCallInfoList) != TELEPHONY_SUCCESS) {
            CellularCallIncomingFinishTrace(imsCallInfo.state);
        }
        serviceInstance->SetImsControl(slotId_, nullptr);
        return;
    }
    if (srvccState_ == SrvccState::STARTED) {
        TELEPHONY_LOGI("[slot%{public}d] Ignore to report ims call state change during srvcc", slotId_);
        return;
    }
    if (imsCallInfoList.callSize == 1) {
        if (imsControl == nullptr) {
            imsControl = std::make_shared<IMSControl>();
            serviceInstance->SetImsControl(slotId_, imsControl);
        }
    }
    if (imsControl == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] ims_control is null", slotId_);
        CellularCallIncomingFinishTrace(imsCallInfo.state);
        return;
    }
    if (imsControl->ReportImsCallsData(slotId_, imsCallInfoList) != TELEPHONY_SUCCESS) {
        CellularCallIncomingFinishTrace(imsCallInfo.state);
    }
}

void CellularCallHandler::GetCsCallsDataResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    // Returns list of current calls of ME. If command succeeds but no calls are available,
    // no information response is sent to TE. Refer subclause 9.2 for possible <err> values.
    auto callInfoList = event->GetSharedObject<CallInfoList>();
    if (callInfoList == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] Cannot get the callInfoList, need to get rilResponseInfo", slotId_);
        auto rilResponseInfo = event->GetSharedObject<RadioResponseInfo>();
        if (rilResponseInfo == nullptr) {
            TELEPHONY_LOGE("[slot%{public}d] callInfoList and rilResponseInfo are null", slotId_);
            return;
        }
        if (rilResponseInfo->error == ErrType::NONE) {
            TELEPHONY_LOGE("[slot%{public}d] Failed to query the call list but no reason!", slotId_);
            return;
        }
        CellularCallEventInfo eventInfo;
        eventInfo.eventType = CellularCallEventType::EVENT_REQUEST_RESULT_TYPE;
        eventInfo.eventId = RequestResultEventId::RESULT_GET_CURRENT_CALLS_FAILED;
        if (registerInstance_ == nullptr) {
            TELEPHONY_LOGE("[slot%{public}d] registerInstance_ is null", slotId_);
            return;
        }
        registerInstance_->ReportEventResultInfo(eventInfo);
        return;
    }
    ReportCsCallsData(*callInfoList);
}

void CellularCallHandler::GetImsCallsDataResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    // Returns list of current calls of ME. If command succeeds but no calls are available,
    // no information response is sent to TE. Refer subclause 9.2 for possible <err> values.
    auto imsCallInfoList = event->GetSharedObject<ImsCurrentCallList>();
    if (imsCallInfoList == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] Cannot get the imsCallInfoList, need to get rilResponseInfo", slotId_);
        auto rilResponseInfo = event->GetSharedObject<RadioResponseInfo>();
        if (rilResponseInfo == nullptr) {
            TELEPHONY_LOGE("[slot%{public}d] callInfoList and rilResponseInfo are null", slotId_);
            return;
        }
        if (rilResponseInfo->error == ErrType::NONE) {
            TELEPHONY_LOGE("[slot%{public}d] Failed to query the call list but no reason!", slotId_);
            return;
        }
        if (registerInstance_ == nullptr) {
            TELEPHONY_LOGE("[slot%{public}d] registerInstance_ is null", slotId_);
            return;
        }
        registerInstance_->ReportGetCallDataResult(static_cast<int32_t>(rilResponseInfo->error));
        return;
    }
    ReportImsCallsData(*imsCallInfoList);
}

void CellularCallHandler::DialResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto result = event->GetSharedObject<RadioResponseInfo>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }
    struct CallBehaviorParameterInfo info = { 0 };
    auto callHiSysEvent = DelayedSingleton<CellularCallHiSysEvent>::GetInstance();
    if (callHiSysEvent == nullptr) {
        TELEPHONY_LOGE("CellularCallHiSysEvent is null.");
        return;
    }
    callHiSysEvent->GetCallParameterInfo(info);
    if (result->error != ErrType::NONE) {
        TELEPHONY_LOGE("[slot%{public}d] dial error:%{public}d", slotId_, result->error);
        CellularCallEventInfo eventInfo;
        eventInfo.eventType = CellularCallEventType::EVENT_REQUEST_RESULT_TYPE;

        /*
         * 3GPP TS 27.007 V3.9.0 (2001-06)
         * If ME has succeeded in establishing a logical link between application protocols and external interface,
         * it will send CONNECT message to the TE. Otherwise, the NO CARRIER response will be returned.
         */
        if (result->error == ErrType::ERR_CMD_NO_CARRIER) {
            eventInfo.eventId = RequestResultEventId::RESULT_DIAL_NO_CARRIER;
        } else {
            eventInfo.eventId = RequestResultEventId::RESULT_DIAL_SEND_FAILED;
        }
        if (registerInstance_ == nullptr) {
            TELEPHONY_LOGE("[slot%{public}d] registerInstance_ is null", slotId_);
            return;
        }
        registerInstance_->ReportEventResultInfo(eventInfo);
        CellularCallHiSysEvent::WriteDialCallBehaviorEvent(info, CallResponseResult::COMMAND_FAILURE);
    } else {
        CellularCallHiSysEvent::WriteDialCallBehaviorEvent(info, CallResponseResult::COMMAND_SUCCESS);
    }
}

void CellularCallHandler::DialSatelliteResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto result = event->GetSharedObject<RadioResponseInfo>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }
    struct CallBehaviorParameterInfo satelliteCallInfo = { 0 };
    auto callHiSysEvent = DelayedSingleton<CellularCallHiSysEvent>::GetInstance();
    if (callHiSysEvent == nullptr) {
        TELEPHONY_LOGE("CellularCallHiSysEvent is null.");
        return;
    }
    callHiSysEvent->GetCallParameterInfo(satelliteCallInfo);
    if (result->error != ErrType::NONE) {
        TELEPHONY_LOGE("[slot%{public}d] dial error:%{public}d", slotId_, result->error);
        CellularCallEventInfo eventInfo;
        eventInfo.eventType = CellularCallEventType::EVENT_REQUEST_RESULT_TYPE;

        if (result->error == ErrType::ERR_CMD_NO_CARRIER) {
            eventInfo.eventId = RequestResultEventId::RESULT_DIAL_NO_CARRIER;
        } else {
            eventInfo.eventId = RequestResultEventId::RESULT_DIAL_SEND_FAILED;
        }
        if (registerInstance_ == nullptr) {
            TELEPHONY_LOGE("[slot%{public}d] registerInstance_ is null", slotId_);
            return;
        }
        registerInstance_->ReportEventResultInfo(eventInfo);
        CellularCallHiSysEvent::WriteDialCallBehaviorEvent(satelliteCallInfo, CallResponseResult::COMMAND_FAILURE);
    } else {
        CellularCallHiSysEvent::WriteDialCallBehaviorEvent(satelliteCallInfo, CallResponseResult::COMMAND_SUCCESS);
    }
}

void CellularCallHandler::GetSatelliteCallsDataResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto satelliteCallInfoList = event->GetSharedObject<SatelliteCurrentCallList>();
    if (satelliteCallInfoList == nullptr) {
        TELEPHONY_LOGE(
            "[slot%{public}d] Cannot get the SatelliteCurrentCallList, need to get rilResponseInfo", slotId_);
        auto rilResponseInfo = event->GetSharedObject<RadioResponseInfo>();
        if (rilResponseInfo == nullptr) {
            TELEPHONY_LOGE("[slot%{public}d] SatelliteCurrentCallList and rilResponseInfo are null", slotId_);
            return;
        }
        if (rilResponseInfo->error == ErrType::NONE) {
            TELEPHONY_LOGE("[slot%{public}d] Failed to query the call list but no reason!", slotId_);
            return;
        }
        CellularCallEventInfo eventInfo;
        eventInfo.eventType = CellularCallEventType::EVENT_REQUEST_RESULT_TYPE;
        eventInfo.eventId = RequestResultEventId::RESULT_GET_CURRENT_CALLS_FAILED;
        if (registerInstance_ == nullptr) {
            TELEPHONY_LOGE("[slot%{public}d] registerInstance_ is null", slotId_);
            return;
        }
        registerInstance_->ReportEventResultInfo(eventInfo);
        return;
    }
    ReportSatelliteCallsData(*satelliteCallInfoList);
}

void CellularCallHandler::ReportSatelliteCallsData(const SatelliteCurrentCallList &callInfoList)
{
    auto serviceInstance = DelayedSingleton<CellularCallService>::GetInstance();
    if (serviceInstance == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] serviceInstance is null", slotId_);
        return;
    }
    auto satelliteControl = serviceInstance->GetSatelliteControl(slotId_);
    SatelliteCurrentCall callInfo;
    std::vector<SatelliteCurrentCall>::const_iterator it = callInfoList.calls.begin();
    for (; it != callInfoList.calls.end(); ++it) {
        callInfo.state = (*it).state;
    }
    TELEPHONY_LOGI("[slot%{public}d] callInfoList.callSize:%{public}d", slotId_, callInfoList.callSize);
    CellularCallIncomingStartTrace(callInfo.state);
    if (callInfoList.callSize == 0) {
        if (satelliteControl == nullptr) {
            TELEPHONY_LOGE("[slot%{public}d] satelliteControl is null", slotId_);
            CellularCallIncomingFinishTrace(callInfo.state);
            return;
        }
        if (satelliteControl->ReportSatelliteCallsData(slotId_, callInfoList) != TELEPHONY_SUCCESS) {
            CellularCallIncomingFinishTrace(callInfo.state);
        }
        serviceInstance->SetSatelliteControl(slotId_, nullptr);
        return;
    }
    if (callInfoList.callSize == 1) {
        if (satelliteControl == nullptr) {
            satelliteControl = std::make_shared<SatelliteControl>();
            serviceInstance->SetSatelliteControl(slotId_, satelliteControl);
        }
    }
    if (satelliteControl == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] satelliteControl is null", slotId_);
        CellularCallIncomingFinishTrace(callInfo.state);
        return;
    }
    if (satelliteControl->ReportSatelliteCallsData(slotId_, callInfoList) != TELEPHONY_SUCCESS) {
        CellularCallIncomingFinishTrace(callInfo.state);
    }
}

void CellularCallHandler::CommonResultEventHandling(
    const AppExecFwk::InnerEvent::Pointer &event, CellularCallEventInfo &eventInfo)
{
    eventInfo.eventType = CellularCallEventType::EVENT_REQUEST_RESULT_TYPE;
    switch (event->GetInnerEventId()) {
        case RadioEvent::RADIO_HANGUP_CONNECT:
            eventInfo.eventId = RequestResultEventId::RESULT_END_SEND_FAILED;
            break;
        case RadioEvent::RADIO_REJECT_CALL:
            eventInfo.eventId = RequestResultEventId::RESULT_REJECT_SEND_FAILED;
            break;
        case RadioEvent::RADIO_ACCEPT_CALL:
            eventInfo.eventId = RequestResultEventId::RESULT_ACCEPT_SEND_FAILED;
            break;
        case RadioEvent::RADIO_HOLD_CALL:
            eventInfo.eventId = RequestResultEventId::RESULT_HOLD_SEND_FAILED;
            break;
        case RadioEvent::RADIO_ACTIVE_CALL:
            eventInfo.eventId = RequestResultEventId::RESULT_ACTIVE_SEND_FAILED;
            break;
        case RadioEvent::RADIO_SWAP_CALL:
            eventInfo.eventId = RequestResultEventId::RESULT_SWAP_SEND_FAILED;
            break;
        case RadioEvent::RADIO_COMBINE_CALL:
        case RadioEvent::RADIO_JOIN_CALL:
            eventInfo.eventId = RequestResultEventId::RESULT_COMBINE_SEND_FAILED;
            break;
        case RadioEvent::RADIO_SPLIT_CALL:
            eventInfo.eventId = RequestResultEventId::RESULT_SPLIT_SEND_FAILED;
            break;
        case RadioEvent::RADIO_CALL_SUPPLEMENT:
            eventInfo.eventId = RequestResultEventId::RESULT_SUPPLEMENT_SEND_FAILED;
            break;
        default:
            break;
    }
}

void CellularCallHandler::CommonResultResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto result = event->GetSharedObject<RadioResponseInfo>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }
    struct CallBehaviorParameterInfo info = { 0 };
    auto callHiSysEvent = DelayedSingleton<CellularCallHiSysEvent>::GetInstance();
    if (callHiSysEvent == nullptr) {
        TELEPHONY_LOGE("CellularCallHiSysEvent is null.");
        return;
    }
    callHiSysEvent->GetCallParameterInfo(info);
    if (result->error != ErrType::NONE) {
        CellularCallEventInfo eventInfo;
        eventInfo.eventId = RequestResultEventId::INVALID_REQUEST_RESULT_EVENT_ID;
        CommonResultEventHandling(event, eventInfo);
        if (eventInfo.eventId == RequestResultEventId::RESULT_END_SEND_FAILED ||
            eventInfo.eventId == RequestResultEventId::RESULT_REJECT_SEND_FAILED) {
            CellularCallHiSysEvent::WriteHangUpCallBehaviorEvent(info, CallResponseResult::COMMAND_FAILURE);
        } else if (eventInfo.eventId == RequestResultEventId::RESULT_ACCEPT_SEND_FAILED) {
            CellularCallHiSysEvent::WriteAnswerCallBehaviorEvent(info, CallResponseResult::COMMAND_FAILURE);
        } else {
            TELEPHONY_LOGW("[slot%{public}d] eventId is:%{public}d, not within the scope of processing", slotId_,
                eventInfo.eventId);
        }
        if (registerInstance_ == nullptr) {
            TELEPHONY_LOGE("[slot%{public}d] registerInstance_ is null", slotId_);
            return;
        }
        registerInstance_->ReportEventResultInfo(eventInfo);
        return;
    }
    uint32_t id = event->GetInnerEventId();
    if (id == RadioEvent::RADIO_HANGUP_CONNECT || id == RadioEvent::RADIO_REJECT_CALL) {
        CellularCallHiSysEvent::WriteHangUpCallBehaviorEvent(info, CallResponseResult::COMMAND_SUCCESS);
    } else if (id == RadioEvent::RADIO_ACCEPT_CALL) {
        CellularCallHiSysEvent::WriteAnswerCallBehaviorEvent(info, CallResponseResult::COMMAND_SUCCESS);
    } else {
        TELEPHONY_LOGW("[slot%{public}d] id is:%{public}d, not within the scope of processing", slotId_, id);
    }
}

void CellularCallHandler::ExecutePostDial(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto postDialData = event->GetSharedObject<PostDialData>();
    if (postDialData == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] postDialData is null", slotId_);
        return;
    }
    auto serviceInstance = DelayedSingleton<CellularCallService>::GetInstance();
    if (serviceInstance == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] serviceInstance is null", slotId_);
        return;
    }
    int64_t callId = postDialData->callId;
    if (postDialData->isIms) {
        auto imsControl = serviceInstance->GetImsControl(slotId_);
        if (imsControl == nullptr) {
            TELEPHONY_LOGE("[slot%{public}d] imsControl is null", slotId_);
            return;
        }
        imsControl->ExecutePostDial(slotId_, callId);
    } else {
        auto csControl = serviceInstance->GetCsControl(slotId_);
        if (csControl == nullptr) {
            TELEPHONY_LOGE("[slot%{public}d] csControl is null", slotId_);
            return;
        }
        csControl->ExecutePostDial(slotId_, callId);
    }
}

void CellularCallHandler::SwapCallResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto result = event->GetSharedObject<RadioResponseInfo>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }
    if (result->error != ErrType::NONE) {
        CellularCallEventInfo eventInfo;
        eventInfo.eventId = RequestResultEventId::INVALID_REQUEST_RESULT_EVENT_ID;
        CommonResultEventHandling(event, eventInfo);
        if (registerInstance_ == nullptr) {
            TELEPHONY_LOGE("[slot%{public}d] registerInstance_ is null", slotId_);
            return;
        }
        registerInstance_->ReportEventResultInfo(eventInfo);
        return;
    }
    auto serviceInstence = DelayedSingleton<CellularCallService>::GetInstance();
    if (serviceInstence == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] registerInstance_ is null", slotId_);
        return;
    }
    auto callType = event->GetParam();
    if (callType == static_cast<int32_t>(CallType::TYPE_IMS)) {
        std::shared_ptr<IMSControl> imsControl = serviceInstence->GetImsControl(slotId_);
        if (imsControl == nullptr) {
            TELEPHONY_LOGE("[slot%{public}d] imsControl is null", slotId_);
            return;
        }
        imsControl->DialAfterHold(slotId_);
    }
}

void CellularCallHandler::SendDtmfResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto result = event->GetSharedObject<RadioResponseInfo>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }

    std::shared_ptr<PostDialData> postDial = std::make_shared<PostDialData>();
    postDial->callId = result->flag;
    postDial->isIms = event->GetParam() == static_cast<int32_t>(CallType::TYPE_IMS);
    this->SendEvent(EVENT_EXECUTE_POST_DIAL, postDial, DELAY_TIME);

    CellularCallEventInfo eventInfo;
    eventInfo.eventType = CellularCallEventType::EVENT_REQUEST_RESULT_TYPE;
    if (result->error != ErrType::NONE) {
        eventInfo.eventId = RequestResultEventId::RESULT_SEND_DTMF_FAILED;
    } else {
        eventInfo.eventId = RequestResultEventId::RESULT_SEND_DTMF_SUCCESS;
    }
    if (registerInstance_ == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] registerInstance_ is null", slotId_);
        return;
    }
    registerInstance_->ReportEventResultInfo(eventInfo);
}

void CellularCallHandler::StartDtmfResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto result = event->GetSharedObject<RadioResponseInfo>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }
    if (registerInstance_ == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] registerInstance_ is null", slotId_);
        return;
    }
    registerInstance_->ReportStartDtmfResult(static_cast<int32_t>(result->error));
}

void CellularCallHandler::SimStateChangeReport(const AppExecFwk::InnerEvent::Pointer &event)
{
    CellularCallConfig config;
    config.HandleSimStateChanged(slotId_);
}

void CellularCallHandler::FactoryReset(const AppExecFwk::InnerEvent::Pointer &event)
{
    CellularCallConfig config;
    config.HandleFactoryReset(slotId_);
}

void CellularCallHandler::SimRecordsLoadedReport(const AppExecFwk::InnerEvent::Pointer &event)
{
    CellularCallConfig config;
    config.HandleSimRecordsLoaded(slotId_);
}

void CellularCallHandler::SimAccountLoadedReport(const AppExecFwk::InnerEvent::Pointer &event)
{
    CellularCallConfig config;
    config.HandleSimAccountLoaded(slotId_);
}

void CellularCallHandler::ResidentNetworkChangeReport(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("ResidentNetworkChangeReport event is nullptr slotId:%{public}d!", slotId_);
        return;
    }
    auto result = event->GetSharedObject<std::string>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }
    CellularCallConfig config;
    config.HandleResidentNetworkChange(slotId_, *result);
}

void CellularCallHandler::NetworkStateChangeReport(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkStateChangeReport event is nullptr slotId:%{public}d!", slotId_);
        return;
    }
    CellularCallConfig config;
    config.HandleNetworkStateChange(slotId_);
}

void CellularCallHandler::StopDtmfResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto result = event->GetSharedObject<RadioResponseInfo>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }
    if (registerInstance_ == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] registerInstance_ is null", slotId_);
        return;
    }
    registerInstance_->ReportStopDtmfResult(static_cast<int32_t>(result->error));
}

void CellularCallHandler::ReceiveUpdateCallMediaModeRequest(const AppExecFwk::InnerEvent::Pointer &event)
{
    struct CallBehaviorParameterInfo info = { 0 };
    auto callHiSysEvent = DelayedSingleton<CellularCallHiSysEvent>::GetInstance();
    if (callHiSysEvent == nullptr) {
        TELEPHONY_LOGE("CellularCallHiSysEvent is null.");
        return;
    }
    callHiSysEvent->GetCallParameterInfo(info);
    auto result = event->GetSharedObject<ImsCallModeReceiveInfo>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }
    if (registerInstance_ == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] registerInstance_ is null", slotId_);
        return;
    }
    registerInstance_->ReceiveUpdateCallMediaModeRequest(*result);
    int32_t requestResult = static_cast<ImsCallModeRequestResult>(result->result);
    CellularCallHiSysEvent::WriteImsCallModeBehaviorEvent(
        CallModeBehaviorType::RECEIVE_REQUEST_EVENT, info, requestResult);
}

void CellularCallHandler::ReceiveUpdateCallMediaModeResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    struct CallBehaviorParameterInfo info = { 0 };
    auto callHiSysEvent = DelayedSingleton<CellularCallHiSysEvent>::GetInstance();
    if (callHiSysEvent == nullptr) {
        TELEPHONY_LOGE("CellularCallHiSysEvent is null.");
        return;
    }
    callHiSysEvent->GetCallParameterInfo(info);
    auto result = event->GetSharedObject<ImsCallModeReceiveInfo>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }
    if (registerInstance_ == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] registerInstance_ is null", slotId_);
        return;
    }
    registerInstance_->ReceiveUpdateCallMediaModeResponse(*result);
    info.videoState = static_cast<ImsCallType>(result->callType);
    int32_t requestResult = static_cast<ImsCallModeRequestResult>(result->result);
    CellularCallHiSysEvent::WriteImsCallModeBehaviorEvent(
        CallModeBehaviorType::RECEIVE_RESPONSE_EVENT, info, requestResult);
}

void CellularCallHandler::HandleCallSessionEventChanged(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto result = event->GetSharedObject<ImsCallSessionEventInfo>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }
    if (registerInstance_ == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] registerInstance_ is null", slotId_);
        return;
    }
    registerInstance_->HandleCallSessionEventChanged(*result);
}

void CellularCallHandler::HandlePeerDimensionsChanged(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto result = event->GetSharedObject<ImsCallPeerDimensionsInfo>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }
    if (registerInstance_ == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] registerInstance_ is null", slotId_);
        return;
    }
    registerInstance_->HandlePeerDimensionsChanged(*result);
}

void CellularCallHandler::HandleCallDataUsageChanged(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto result = event->GetSharedObject<ImsCallDataUsageInfo>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }
    if (registerInstance_ == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] registerInstance_ is null", slotId_);
        return;
    }
    registerInstance_->HandleCallDataUsageChanged(*result);
}

void CellularCallHandler::HandleCameraCapabilitiesChanged(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto result = event->GetSharedObject<CameraCapabilitiesInfo>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }
    if (registerInstance_ == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] registerInstance_ is null", slotId_);
        return;
    }
    registerInstance_->HandleCameraCapabilitiesChanged(*result);
}

void CellularCallHandler::SetSlotId(int32_t id)
{
    slotId_ = id;
}

int32_t CellularCallHandler::GetSlotId()
{
    return slotId_;
}

int64_t CellularCallHandler::CurrentTimeMillis()
{
    int64_t timems =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    return timems;
}

void CellularCallHandler::GetCsCallsDataRequest(const AppExecFwk::InnerEvent::Pointer &event)
{
    lastCallsDataFlag_ = CurrentTimeMillis();
    CellularCallConnectionCS connectionCs;
    connectionCs.GetCsCallsDataRequest(slotId_, lastCallsDataFlag_);
}

void CellularCallHandler::GetImsCallsDataRequest(const AppExecFwk::InnerEvent::Pointer &event)
{
    lastCallsDataFlag_ = CurrentTimeMillis();
    CellularCallConnectionIMS connectionIms;
    connectionIms.GetImsCallsDataRequest(slotId_, lastCallsDataFlag_);
}

void CellularCallHandler::GetSatelliteCallsDataRequest(const AppExecFwk::InnerEvent::Pointer &event)
{
    lastCallsDataFlag_ = CurrentTimeMillis();
    CellularCallConnectionSatellite connectionSatellite;
    connectionSatellite.GetSatelliteCallsDataRequest(slotId_, lastCallsDataFlag_);
}

void CellularCallHandler::RegisterHandler(const AppExecFwk::InnerEvent::Pointer &event)
{
    CellularCallConnectionCS connectionCs;
    connectionCs.RegisterHandler();
}

void CellularCallHandler::SetDomainPreferenceModeResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto info = event->GetSharedObject<RadioResponseInfo>();
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null", slotId_);
        return;
    }
    CellularCallEventInfo eventInfo;
    eventInfo.eventType = CellularCallEventType::EVENT_REQUEST_RESULT_TYPE;
    if (info->error != ErrType::NONE) {
        eventInfo.eventId = RequestResultEventId::RESULT_SET_CALL_PREFERENCE_MODE_FAILED;
    } else {
        eventInfo.eventId = RequestResultEventId::RESULT_SET_CALL_PREFERENCE_MODE_SUCCESS;

        CellularCallConfig config;
        config.SetTempMode(slotId_);
    }
    if (registerInstance_ == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] registerInstance_ is null", slotId_);
        return;
    }
    registerInstance_->ReportEventResultInfo(eventInfo);
}

void CellularCallHandler::GetDomainPreferenceModeResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto mode = event->GetSharedObject<int32_t>();
    if (mode == nullptr) {
        TELEPHONY_LOGI("[slot%{public}d] mode is null", slotId_);
        return;
    }
    CellularCallConfig config;
    config.GetDomainPreferenceModeResponse(slotId_, *mode);
}

void CellularCallHandler::SetImsSwitchStatusResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto info = event->GetSharedObject<RadioResponseInfo>();
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null", slotId_);
        return;
    }
    if (registerInstance_ == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] registerInstance_ is null", slotId_);
        return;
    }
    CellularCallConfig config;
    config.HandleSetLteImsSwitchResult(slotId_, info->error);
}

void CellularCallHandler::GetImsSwitchStatusResponse(const AppExecFwk::InnerEvent::Pointer &event) {}

void CellularCallHandler::SetVoNRSwitchStatusResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto info = event->GetSharedObject<RadioResponseInfo>();
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null", slotId_);
        return;
    }
    CellularCallConfig config;
    config.HandleSetVoNRSwitchResult(slotId_, info->error);
}

void CellularCallHandler::CsCallStatusInfoReport(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (srvccState_ == SrvccState::STARTED) {
        TELEPHONY_LOGI("[slot%{public}d] Ignore to report cs call state change cause by srvcc started", slotId_);
        return;
    }
    GetCsCallData(event);
}

void CellularCallHandler::ImsCallStatusInfoReport(const AppExecFwk::InnerEvent::Pointer &event)
{
    GetImsCallData(event);
}

void CellularCallHandler::SatelliteCallStatusInfoReport(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (srvccState_ == SrvccState::STARTED) {
        TELEPHONY_LOGI("[slot%{public}d] Ignore to report satellite call state change cause by srvcc started", slotId_);
        return;
    }
    GetSatelliteCallData(event);
}

void CellularCallHandler::UssdNotifyResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto result = event->GetSharedObject<UssdNoticeInfo>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }
    CellularCallSupplement supplement;
    supplement.EventUssdNotify(*result);
}

void CellularCallHandler::SetMuteResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto info = event->GetSharedObject<RadioResponseInfo>();
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null", slotId_);
        return;
    }
    MuteControlResponse response;
    if (registerInstance_ == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] registerInstance_ is null", slotId_);
        return;
    }
    response.result = static_cast<int32_t>(info->error);
    registerInstance_->ReportSetMuteResult(response);
}

void CellularCallHandler::GetMuteResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    MuteControlResponse response;
    auto mute = event->GetSharedObject<int32_t>();
    if (mute == nullptr) {
        TELEPHONY_LOGI("[slot%{public}d] mute is null", slotId_);
        auto info = event->GetSharedObject<RadioResponseInfo>();
        if (info == nullptr) {
            TELEPHONY_LOGE("[slot%{public}d] info is null", slotId_);
            return;
        }
        response.result = static_cast<int32_t>(info->error);
    } else {
        response.result = static_cast<int32_t>(ErrType::NONE);
        response.value = *mute;
    }
    if (registerInstance_ == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] registerInstance_ is null", slotId_);
        return;
    }
    registerInstance_->ReportGetMuteResult(response);
}

void CellularCallHandler::GetEmergencyCallListResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto eccList = event->GetSharedObject<EmergencyInfoList>();
    if (eccList == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] eccList is null", slotId_);
        return;
    }
    CellularCallConfig config;
    config.UpdateEmergencyCallFromRadio(slotId_, *eccList);
}

void CellularCallHandler::SetEmergencyCallListResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto info = event->GetSharedObject<RadioResponseInfo>();
    if (info == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] info is null", slotId_);
        return;
    }
    if (registerInstance_ == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] registerInstance_ is null", slotId_);
        return;
    }
    SetEccListResponse response;
    response.result = static_cast<int32_t>(info->error);
    registerInstance_->ReportSetEmergencyCallListResponse(response);
}

void CellularCallHandler::CallRingBackVoiceResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto ringBackVoice = event->GetSharedObject<RingbackVoice>();
    if (ringBackVoice == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] ringBackVoice is null", slotId_);
        return;
    }
    if (registerInstance_ == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] registerInstance_ is null", slotId_);
        return;
    }
    registerInstance_->ReportCallRingBackResult(ringBackVoice->status);
}

void CellularCallHandler::GetCallFailReasonResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (registerInstance_ == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] registerInstance_ is null", slotId_);
        return;
    }
    auto reason = event->GetSharedObject<int32_t>();
    DisconnectedDetails details;
    if (reason == nullptr) {
        auto info = event->GetSharedObject<DisconnectedDetails>();
        if (info == nullptr) {
            TELEPHONY_LOGE("[slot%{public}d] info is null", slotId_);
            return;
        }
        details.reason = static_cast<DisconnectedReason>(info->reason);
        details.message = (info->message.c_str() == nullptr) ? "" : info->message;
    } else {
        details.reason = static_cast<DisconnectedReason>(*reason);
        details.message = "";
    }

    if (details.message.empty()) {
        std::string callFailedMessageName = "";
        bool ret =
            ResourceUtils::Get().GetCallFailedMessageName(static_cast<int32_t>(details.reason), callFailedMessageName);
        if (!ret) {
            TELEPHONY_LOGE("[slot%{public}d] Get call failed message failed!", slotId_);
            return;
        }
        ResourceUtils::Get().GetStringValueByName(callFailedMessageName, details.message);
    }
    CellularCallHiSysEvent::WriteCallEndBehaviorEvent(slotId_, static_cast<int32_t>(details.reason));
    registerInstance_->ReportCallFailReason(details);
}

void CellularCallHandler::UpdateSrvccStateReport(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto srvccStatus = event->GetSharedObject<SrvccStatus>();
    if (srvccStatus == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] srvccStatus is null", slotId_);
        return;
    }
    TELEPHONY_LOGI("[slot%{public}d] srvccStatus is %{public}d", slotId_, srvccStatus->status);
    srvccState_ = srvccStatus->status;
    auto serviceInstance_ = DelayedSingleton<CellularCallService>::GetInstance();
    if (registerInstance_ == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] registerInstance_ is null", slotId_);
        return;
    }
    serviceInstance_->SetSrvccState(srvccState_);
    if (srvccState_ != SrvccState::COMPLETED) {
        TELEPHONY_LOGE("[slot%{public}d] srvccState_ != SrvccState::COMPLETED", slotId_);
        return;
    }
    SrvccStateCompleted();
}

void CellularCallHandler::ReportEccChanged(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto emergencyInfoList = event->GetSharedObject<EmergencyInfoList>();
    if (emergencyInfoList == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] emergencyInfoList is null", slotId_);
        return;
    }
    CellularCallConfig config;
    auto calls = emergencyInfoList->calls;
    if (calls.size() > 0 && static_cast<uint32_t>(calls.back().total) != calls.size()) {
        TELEPHONY_LOGE("[slot%{public}d] data error", slotId_);
        auto endCall = calls.back();
        if (endCall.index < endCall.total) {
            return;
        }
        TELEPHONY_LOGI("[slot%{public}d] try query", slotId_);
        config.GetEmergencyCallList(slotId_);
        return;
    }
    config.UpdateEmergencyCallFromRadio(slotId_, *emergencyInfoList);
}

void CellularCallHandler::SrvccStateCompleted()
{
    if (srvccState_ != SrvccState::COMPLETED) {
        TELEPHONY_LOGE("[slot%{public}d] srvccState_ != SrvccState::COMPLETED", slotId_);
        return;
    }
    auto serviceInstance_ = DelayedSingleton<CellularCallService>::GetInstance();
    if (serviceInstance_ == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] registerInstance_ is null", slotId_);
        return;
    }
    auto csControl = serviceInstance_->GetCsControl(slotId_);
    if (csControl != nullptr) {
        TELEPHONY_LOGI("[slot%{public}d] CsControl ReleaseAllConnection", slotId_);
        csControl->ReleaseAllConnection();
        serviceInstance_->SetCsControl(slotId_, nullptr);
    } else {
        TELEPHONY_LOGI("[slot%{public}d] CsControl is null", slotId_);
        csControl = std::make_shared<CSControl>();
        serviceInstance_->SetCsControl(slotId_, csControl);
    }
    auto imsControl = serviceInstance_->GetImsControl(slotId_);
    if (imsControl != nullptr) {
        TELEPHONY_LOGI("[slot%{public}d] ImsControl ReleaseAllConnection", slotId_);
        imsControl->ReleaseAllConnection();
        serviceInstance_->SetImsControl(slotId_, nullptr);
    } else {
        TELEPHONY_LOGI("[slot%{public}d] imsControl is null", slotId_);
    }
    srvccState_ = SrvccState::SRVCC_NONE;
}

void CellularCallHandler::GetMMIResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<MMICodeUtils> mmiCodeUtils = event->GetUniqueObject<MMICodeUtils>();
    if (mmiCodeUtils == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] mmiCodeUtils is null", slotId_);
        return;
    }
    mmiCodeUtils->ExecuteMmiCode(slotId_);
}

void CellularCallHandler::GetCallWaitingResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto result = event->GetSharedObject<CallWaitResult>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }
    int32_t flag = SS_FROM_MMI_CODE;
    int32_t ret = ConfirmAndRemoveSsRequestCommand(result->result.index, flag);
    if (ret != TELEPHONY_SUCCESS) {
        return;
    }
    CellularCallSupplement supplement;
    supplement.EventGetCallWaiting(*result, result->result.message, flag);
}

void CellularCallHandler::SetCallWaitingResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto result = event->GetSharedObject<SsBaseResult>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }
    int32_t flag = SS_FROM_MMI_CODE;
    int32_t ret = ConfirmAndRemoveSsRequestCommand(result->index, flag);
    if (ret != TELEPHONY_SUCCESS) {
        return;
    }
    CellularCallSupplement supplement;
    if (result->result != TELEPHONY_SUCCESS) {
        result->result = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    supplement.EventSetCallWaiting(result->result, result->message, flag);
}

void CellularCallHandler::GetClirResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto getClirResult = event->GetSharedObject<GetClirResult>();
    if (getClirResult == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] getClirResult is null", slotId_);
        return;
    }
    int32_t flag = SS_FROM_MMI_CODE;
    int32_t ret = ConfirmAndRemoveSsRequestCommand(getClirResult->result.index, flag);
    if (ret != TELEPHONY_SUCCESS) {
        return;
    }
    CellularCallSupplement supplement;
    supplement.EventGetClir(*getClirResult, getClirResult->result.message, flag);
}

void CellularCallHandler::SetClirResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto result = event->GetSharedObject<SsBaseResult>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }
    int32_t flag = SS_FROM_MMI_CODE;
    int32_t ret = ConfirmAndRemoveSsRequestCommand(result->index, flag);
    if (ret != TELEPHONY_SUCCESS) {
        return;
    }
    CellularCallSupplement supplement;
    supplement.EventSetClir(result->result, result->message, flag);
}

void CellularCallHandler::GetClipResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto getClipResult = event->GetSharedObject<GetClipResult>();
    if (getClipResult == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] getClipResult is null", slotId_);
        return;
    }
    int32_t flag = SS_FROM_MMI_CODE;
    int32_t ret = ConfirmAndRemoveSsRequestCommand(getClipResult->result.index, flag);
    if (ret != TELEPHONY_SUCCESS) {
        return;
    }
    CellularCallSupplement supplement;
    supplement.EventGetClip(*getClipResult, getClipResult->result.message, flag);
}

void CellularCallHandler::SetClipResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto result = event->GetSharedObject<SsBaseResult>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }
    int32_t flag = SS_FROM_MMI_CODE;
    int32_t ret = ConfirmAndRemoveSsRequestCommand(result->index, flag);
    if (ret != TELEPHONY_SUCCESS) {
        return;
    }
    CellularCallSupplement supplement;
    supplement.EventSetClip(result->result, result->message, flag);
}

void CellularCallHandler::GetColrResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto colrResult = event->GetSharedObject<GetColrResult>();
    if (colrResult == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] colrResult is null", slotId_);
        return;
    }
    int32_t flag = SS_FROM_MMI_CODE;
    int32_t ret = ConfirmAndRemoveSsRequestCommand(colrResult->result.index, flag);
    if (ret != TELEPHONY_SUCCESS) {
        return;
    }
    CellularCallSupplement supplement;
    supplement.EventGetColr(*colrResult, colrResult->result.message, flag);
}

void CellularCallHandler::SetColrResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto result = event->GetSharedObject<SsBaseResult>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }
    int32_t flag = SS_FROM_MMI_CODE;
    int32_t ret = ConfirmAndRemoveSsRequestCommand(result->index, flag);
    if (ret != TELEPHONY_SUCCESS) {
        return;
    }
    CellularCallSupplement supplement;
    supplement.EventSetColr(result->result, result->message, flag);
}

void CellularCallHandler::GetColpResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto colpResult = event->GetSharedObject<GetColpResult>();
    if (colpResult == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] colpResult is null", slotId_);
        return;
    }
    int32_t flag = SS_FROM_MMI_CODE;
    int32_t ret = ConfirmAndRemoveSsRequestCommand(colpResult->result.index, flag);
    if (ret != TELEPHONY_SUCCESS) {
        return;
    }
    CellularCallSupplement supplement;
    supplement.EventGetColp(*colpResult, colpResult->result.message, flag);
}

void CellularCallHandler::SetColpResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto result = event->GetSharedObject<SsBaseResult>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }
    int32_t flag = SS_FROM_MMI_CODE;
    int32_t ret = ConfirmAndRemoveSsRequestCommand(result->index, flag);
    if (ret != TELEPHONY_SUCCESS) {
        return;
    }
    CellularCallSupplement supplement;
    supplement.EventSetColp(result->result, result->message, flag);
}

void CellularCallHandler::GetCallTransferResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto cFQueryList = event->GetSharedObject<CallForwardQueryInfoList>();
    if (cFQueryList == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] cFQueryList is null", slotId_);
        return;
    }
    SsRequestCommand ss;
    int32_t ret = GetSsRequestCommand(cFQueryList->result.index, ss);
    if (ret == TELEPHONY_SUCCESS) {
        cFQueryList->result.reason = ss.cfReason;
    }
    int32_t flag = SS_FROM_MMI_CODE;
    ret = ConfirmAndRemoveSsRequestCommand(cFQueryList->result.index, flag);
    if (ret != TELEPHONY_SUCCESS) {
        return;
    }
    CellularCallSupplement supplement;
    supplement.EventGetCallTransferInfo(*cFQueryList, cFQueryList->result.message, flag);
}

void CellularCallHandler::SetCallTransferInfoResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto result = event->GetSharedObject<SsBaseResult>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }
    int32_t flag = SS_FROM_MMI_CODE;
    int32_t ret = ConfirmAndRemoveSsRequestCommand(result->index, flag);
    if (ret != TELEPHONY_SUCCESS) {
        return;
    }
    CellularCallSupplement supplement;
    CallForwardingInfo info;
    auto callHiSysEvent = DelayedSingleton<CellularCallHiSysEvent>::GetInstance();
    if (callHiSysEvent == nullptr) {
        TELEPHONY_LOGE("CellularCallHiSysEvent is null.");
        return;
    }
    callHiSysEvent->GetCallForwardingInfo(info);
    if (result->result == TELEPHONY_SUCCESS) {
        CoreManagerInner::GetInstance().SetVoiceCallForwarding(info.slotId, info.enable, info.number);
    } else {
        result->result = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    supplement.EventSetCallTransferInfo(result->result, result->message, flag);
}

void CellularCallHandler::GetCallRestrictionResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto result = event->GetSharedObject<CallRestrictionResult>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }
    int32_t flag = SS_FROM_MMI_CODE;
    int32_t ret = ConfirmAndRemoveSsRequestCommand(result->result.index, flag);
    if (ret != TELEPHONY_SUCCESS) {
        return;
    }
    CellularCallSupplement supplement;
    supplement.EventGetCallRestriction(*result, result->result.message, flag);
}

void CellularCallHandler::SetCallRestrictionResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto result = event->GetSharedObject<SsBaseResult>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }
    int32_t flag = SS_FROM_MMI_CODE;
    int32_t ret = ConfirmAndRemoveSsRequestCommand(result->index, flag);
    if (ret != TELEPHONY_SUCCESS) {
        return;
    }
    CellularCallSupplement supplement;
    if (result->result != TELEPHONY_SUCCESS) {
        result->result = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    supplement.EventSetCallRestriction(result->result, result->message, flag);
}

void CellularCallHandler::SetBarringPasswordResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto result = event->GetSharedObject<SsBaseResult>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }
    int32_t flag = SS_FROM_MMI_CODE;
    int32_t ret = ConfirmAndRemoveSsRequestCommand(result->index, flag);
    if (ret != TELEPHONY_SUCCESS) {
        return;
    }
    CellularCallSupplement supplement;
    if (result->result != TELEPHONY_SUCCESS) {
        result->result = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    supplement.EventSetBarringPassword(result->result, result->message, flag);
}

void CellularCallHandler::SendUssdResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto result = event->GetSharedObject<RadioResponseInfo>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }
    CellularCallSupplement supplement;
    supplement.EventSendUssd(*result);
}

void CellularCallHandler::SsNotifyResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto result = event->GetSharedObject<SsNoticeInfo>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }
    CellularCallSupplement supplement;
    supplement.EventSsNotify(*result);
}

void CellularCallHandler::SendUnlockPinPukResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto result = event->GetSharedObject<PinPukResponse>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }
    CellularCallSupplement supplement;
    supplement.EventSetPinPuk(*result);
}

void CellularCallHandler::HandleOperatorConfigChanged(const AppExecFwk::InnerEvent::Pointer &event)
{
    CellularCallConfig config;
    config.HandleOperatorConfigChanged(slotId_);
}

void CellularCallHandler::UpdateRsrvccStateReport(const AppExecFwk::InnerEvent::Pointer &event)
{
    isInCsRedial_ = true;
    auto serviceInstance = DelayedSingleton<CellularCallService>::GetInstance();
    if (serviceInstance == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] serviceInstance is null", slotId_);
        return;
    }
    serviceInstance->SetCsControl(slotId_, nullptr);
}

void CellularCallHandler::RequestSsRequestCommandIndex(int32_t &index)
{
    if (indexCommand_ >= MAX_REQUEST_COUNT) {
        indexCommand_ = 0;
    } else {
        indexCommand_++;
    }
    index = indexCommand_;
}

void CellularCallHandler::SaveSsRequestCommand(const std::shared_ptr<SsRequestCommand> &utCommand, int32_t index)
{
    if (utCommand == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] utCommand is null", slotId_);
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    utCommandMap_.insert(std::make_pair(indexCommand_, utCommand));
}

int32_t CellularCallHandler::ConfirmAndRemoveSsRequestCommand(int32_t index, int32_t &flag)
{
    if (index == INVALID_INDEX) {
        // -1 mean this command index wasn't come from app, so don't need report result
        TELEPHONY_LOGI("[slot%{public}d] index is invalid, nothing need to do", slotId_);
        return TELEPHONY_ERROR;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto itor = utCommandMap_.find(index);
    if (itor == utCommandMap_.end()) {
        TELEPHONY_LOGE("[slot%{public}d] the index(%{public}d) in utCommandMap_ haven't been found", slotId_, index);
        return TELEPHONY_ERROR;
    }
    flag = itor->second->flag;
    utCommandMap_.erase(index);
    return TELEPHONY_SUCCESS;
}

int32_t CellularCallHandler::GetSsRequestCommand(int32_t index, SsRequestCommand &ss)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto itor = utCommandMap_.find(index);
    if (itor == utCommandMap_.end()) {
        TELEPHONY_LOGE("[slot%{public}d] the index in utCommandMap_ haven't been found", slotId_);
        return TELEPHONY_ERROR;
    }

    ss.cfAction = itor->second->cfAction;
    ss.cfReason = itor->second->cfReason;
    ss.number = itor->second->number;
    ss.enable = itor->second->enable;
    ss.clirAction = itor->second->clirAction;
    ss.facility = itor->second->facility;
    if (strcpy_s(ss.password, sizeof(ss.password), itor->second->password) != EOK) {
        TELEPHONY_LOGE("password strcpy_s fail.");
        return TELEPHONY_ERR_STRCPY_FAIL;
    }
    ss.classType = itor->second->classType;
    ss.action = itor->second->action;
    ss.flag = itor->second->flag;
    return TELEPHONY_SUCCESS;
}

void CellularCallHandler::CloseUnFinishedUssdResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto result = event->GetSharedObject<RadioResponseInfo>();
    if (result == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] result is null", slotId_);
        return;
    }
    CellularCallSupplement supplement;
    supplement.EventCloseUnFinishedUssd(*result);
}

void CellularCallHandler::OnRilAdapterHostDied(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto serviceInstance = DelayedSingleton<CellularCallService>::GetInstance();
    if (serviceInstance == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] serviceInstance is null", slotId_);
        return;
    }
    auto csControl = serviceInstance->GetCsControl(slotId_);
    if (csControl == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] cs_control is null", slotId_);
    } else if (csControl->ReportHangUpInfo(slotId_) != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("[slot%{public}d] fail to disconnect cs calls", slotId_);
    } else {
        serviceInstance->SetCsControl(slotId_, nullptr);
    }
    auto imsControl = serviceInstance->GetImsControl(slotId_);
    if (imsControl == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] ims_control is null", slotId_);
    } else if (imsControl->ReportHangUpInfo(slotId_) != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("[slot%{public}d] fail to disconnect ims calls", slotId_);
    } else {
        serviceInstance->SetImsControl(slotId_, nullptr);
    }
}

#ifdef CALL_MANAGER_AUTO_START_OPTIMIZE
void CellularCallHandler::StartCallManagerService()
{
    auto serviceInstance = DelayedSingleton<CellularCallService>::GetInstance();
    if (serviceInstance == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] serviceInstance is null", slotId_);
        return;
    }
    serviceInstance->StartCallManagerService();
}

void CellularCallHandler::RadioStateChangeProcess(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<Int32Parcel> object = event->GetSharedObject<Int32Parcel>();
    if (object == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] object is null", slotId_);
        return;
    }
    TELEPHONY_LOGI("[slot%{public}d] Radio changed with state: %{public}d", slotId_, object->data);
    if (object->data == CORE_SERVICE_POWER_ON) {
        StartCallManagerService();
    }
}

void CellularCallHandler::GetRadioStateProcess(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto object = event->GetUniqueObject<RadioStateInfo>();
    if (object == nullptr) {
        TELEPHONY_LOGE("object is null");
        return;
    }
    TELEPHONY_LOGI("GetRadioStateProcess [slot%{public}d], state=%{public}d", slotId_, object->state);
    if (object->state == CORE_SERVICE_POWER_ON) {
        StartCallManagerService();
    }
}
#endif
} // namespace Telephony
} // namespace OHOS

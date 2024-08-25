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

#ifndef CELLULAR_CALL_HANDLER_H
#define CELLULAR_CALL_HANDLER_H

#include <memory>
#include <mutex>

#include "cellular_call_config.h"
#include "cellular_call_data_struct.h"
#include "cellular_call_register.h"
#include "common_event.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "cs_control.h"
#include "ims_call_types.h"
#include "ims_control.h"
#include "satellite_control.h"
#include "tel_event_handler.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class CellularCallHandler : public TelEventHandler, public EventFwk::CommonEventSubscriber {
public:
    /**
     * CellularCallHandler constructor
     *
     * @param runner
     * @param subscriberInfo
     */
    explicit CellularCallHandler(const EventFwk::CommonEventSubscribeInfo &subscriberInfo);

    /**
     * ~CellularCallHandler destructor
     */
    ~CellularCallHandler() = default;

    /**
     * ProcessEvent.
     *
     * @param CellularCallRadioResponseEvent, Process Radio Response Event .
     */
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event) override;

    /**
     * Receive Operator Config Change event and process.
     *
     * @param CommonEventData, Process Operator Config Change .
     */
    void OnReceiveEvent(const EventFwk::CommonEventData &data) override;

    /**
     * Set Slot Id
     *
     * @param id
     */
    void SetSlotId(int32_t id);

    /**
     * Get Slot Id
     * @return id
     */
    int32_t GetSlotId();

    void RegisterImsCallCallbackHandler();

    void RegisterSatelliteCallCallbackHandler();

    void SimStateChangeReport(const AppExecFwk::InnerEvent::Pointer &event);

    void FactoryReset(const AppExecFwk::InnerEvent::Pointer &event);

    void SimRecordsLoadedReport(const AppExecFwk::InnerEvent::Pointer &event);

    void SimAccountLoadedReport(const AppExecFwk::InnerEvent::Pointer &event);

    void ResidentNetworkChangeReport(const AppExecFwk::InnerEvent::Pointer &event);

    void NetworkStateChangeReport(const AppExecFwk::InnerEvent::Pointer &event);

    void DialResponse(const AppExecFwk::InnerEvent::Pointer &event);

    void DialSatelliteResponse(const AppExecFwk::InnerEvent::Pointer &event);

    void CommonResultEventHandling(const AppExecFwk::InnerEvent::Pointer &event, CellularCallEventInfo &eventInfo);

    void CommonResultResponse(const AppExecFwk::InnerEvent::Pointer &event);

    void ExecutePostDial(const AppExecFwk::InnerEvent::Pointer &event);

    void SwapCallResponse(const AppExecFwk::InnerEvent::Pointer &event);

    void SendDtmfResponse(const AppExecFwk::InnerEvent::Pointer &event);

    void StartDtmfResponse(const AppExecFwk::InnerEvent::Pointer &event);

    void StopDtmfResponse(const AppExecFwk::InnerEvent::Pointer &event);

    void GetCsCallsDataResponse(const AppExecFwk::InnerEvent::Pointer &event);

    void GetImsCallsDataResponse(const AppExecFwk::InnerEvent::Pointer &event);

    void CsCallStatusInfoReport(const AppExecFwk::InnerEvent::Pointer &event);

    void ImsCallStatusInfoReport(const AppExecFwk::InnerEvent::Pointer &event);

    void SatelliteCallStatusInfoReport(const AppExecFwk::InnerEvent::Pointer &event);

    void ReportEccChanged(const AppExecFwk::InnerEvent::Pointer &event);

    void SetDomainPreferenceModeResponse(const AppExecFwk::InnerEvent::Pointer &event);

    void GetDomainPreferenceModeResponse(const AppExecFwk::InnerEvent::Pointer &event);

    void SetImsSwitchStatusResponse(const AppExecFwk::InnerEvent::Pointer &event);

    void GetImsSwitchStatusResponse(const AppExecFwk::InnerEvent::Pointer &event);

    void SetVoNRSwitchStatusResponse(const AppExecFwk::InnerEvent::Pointer &event);

    void UssdNotifyResponse(const AppExecFwk::InnerEvent::Pointer &event);

    void SsNotifyResponse(const AppExecFwk::InnerEvent::Pointer &event);

    void CallRingBackVoiceResponse(const AppExecFwk::InnerEvent::Pointer &event);

    void SetMuteResponse(const AppExecFwk::InnerEvent::Pointer &event);

    void GetMuteResponse(const AppExecFwk::InnerEvent::Pointer &event);

    void GetEmergencyCallListResponse(const AppExecFwk::InnerEvent::Pointer &event);

    void SetEmergencyCallListResponse(const AppExecFwk::InnerEvent::Pointer &event);

    void GetCallFailReasonResponse(const AppExecFwk::InnerEvent::Pointer &event);

    void UpdateSrvccStateReport(const AppExecFwk::InnerEvent::Pointer &event);

    void SrvccStateCompleted();

    void ReceiveUpdateCallMediaModeRequest(const AppExecFwk::InnerEvent::Pointer &event);

    void ReceiveUpdateCallMediaModeResponse(const AppExecFwk::InnerEvent::Pointer &event);

    void HandleCallSessionEventChanged(const AppExecFwk::InnerEvent::Pointer &event);

    void HandlePeerDimensionsChanged(const AppExecFwk::InnerEvent::Pointer &event);

    void HandleCallDataUsageChanged(const AppExecFwk::InnerEvent::Pointer &event);

    void HandleCameraCapabilitiesChanged(const AppExecFwk::InnerEvent::Pointer &event);

    void GetSatelliteCallsDataResponse(const AppExecFwk::InnerEvent::Pointer &event);

    /**
     * request the ut command index which will be used to report the result
     *
     * @param index
     */
    void RequestSsRequestCommandIndex(int32_t &index);

    /**
     * save the ut command which will be used to report the result
     *
     * @param SsRequestCommand
     * @param index
     */
    void SaveSsRequestCommand(const std::shared_ptr<SsRequestCommand> &utCommand, int32_t index);

    int32_t GetSsRequestCommand(int32_t index, SsRequestCommand &ss);

public:
    const uint32_t REGISTER_HANDLER_ID = 10003;
    int32_t srvccState_ = SrvccState::SRVCC_NONE;

private:
    int64_t CurrentTimeMillis();
    void GetCsCallData(const AppExecFwk::InnerEvent::Pointer &event);
    void GetImsCallData(const AppExecFwk::InnerEvent::Pointer &event);
    void GetSatelliteCallData(const AppExecFwk::InnerEvent::Pointer &event);
    void GetCsCallsDataRequest(const AppExecFwk::InnerEvent::Pointer &event);
    void GetImsCallsDataRequest(const AppExecFwk::InnerEvent::Pointer &event);
    void GetSatelliteCallsDataRequest(const AppExecFwk::InnerEvent::Pointer &event);
    void RegisterHandler(const AppExecFwk::InnerEvent::Pointer &event);
    void GetMMIResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void GetCallWaitingResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void SetCallWaitingResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void GetClirResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void SetClirResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void GetClipResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void SetClipResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void GetColrResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void SetColrResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void GetColpResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void SetColpResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void GetCallTransferResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void SetCallTransferInfoResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void GetCallRestrictionResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void SetCallRestrictionResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void SetBarringPasswordResponse(const AppExecFwk::InnerEvent::Pointer &event);
    int32_t ConfirmAndRemoveSsRequestCommand(int32_t index, int32_t &flag);
    void SendUssdResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void SendUnlockPinPukResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void CloseUnFinishedUssdResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void OnRilAdapterHostDied(const AppExecFwk::InnerEvent::Pointer &event);

    void InitBasicFuncMap();
    void InitConfigFuncMap();
    void InitSupplementFuncMap();
    void InitActiveReportFuncMap();
    void InitSatelliteCallFuncMap();

    void ReportCsCallsData(const CallInfoList &callInfoList);
    void ReportImsCallsData(const ImsCurrentCallList &imsCallInfoList);
    void ReportSatelliteCallsData(const SatelliteCurrentCallList &callInfoList);
    void HandleOperatorConfigChanged(const AppExecFwk::InnerEvent::Pointer &event);
    void UpdateRsrvccStateReport(const AppExecFwk::InnerEvent::Pointer &event);

#ifdef CALL_MANAGER_AUTO_START_OPTIMIZE
    /**
     * If radio state change get call manager service
     *
     * @param AppExecFwk::InnerEvent::Pointer
     */
    void RadioStateChangeProcess(const AppExecFwk::InnerEvent::Pointer &event);

    /**
     * If get radio state on, get call manager service
     *
     * @param AppExecFwk::InnerEvent::Pointer
     */
    void GetRadioStateProcess(const AppExecFwk::InnerEvent::Pointer &event);

    void StartCallManagerService();
#endif

private:
    void CellularCallIncomingStartTrace(const int32_t state);
    void CellularCallIncomingFinishTrace(const int32_t state);

private:
    int32_t slotId_ = DEFAULT_SIM_SLOT_ID;
    int64_t lastCallsDataFlag_ = 0L;
    using RequestFuncType = void (CellularCallHandler::*)(const AppExecFwk::InnerEvent::Pointer &event);
    std::map<uint32_t, RequestFuncType> requestFuncMap_;
    std::shared_ptr<CellularCallRegister> registerInstance_ = DelayedSingleton<CellularCallRegister>::GetInstance();
    bool isInCsRedial_ = false;
    int32_t indexCommand_ = 0;
    std::map<int32_t, std::shared_ptr<SsRequestCommand>> utCommandMap_;
    std::mutex mutex_;
};
} // namespace Telephony
} // namespace OHOS

#endif

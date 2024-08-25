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

#ifndef CELLULAR_CALL_REGISTER_H
#define CELLULAR_CALL_REGISTER_H

#include <map>
#include <mutex>

#include "cellular_call_connection_cs.h"
#include "i_call_status_callback.h"
#include "singleton.h"
#include "ims_call_interface.h"

namespace OHOS {
namespace Telephony {
class CellularCallRegister {
    DECLARE_DELAYED_SINGLETON(CellularCallRegister);

public:
    void ReportCallsInfo(const CallsReportInfo &callsReportInfo);

    void ReportSingleCallInfo(const CallReportInfo &info, TelCallState callState);

    void ReportEventResultInfo(const CellularCallEventInfo &info);

    void ReportGetWaitingResult(const CallWaitResponse &response);

    void ReportSetWaitingResult(int32_t result);

    void ReportGetRestrictionResult(const CallRestrictionResponse &response);

    void ReportSetRestrictionResult(int32_t result);

    void ReportGetTransferResult(const CallTransferResponse &response);

    void ReportSetBarringPasswordResult(int32_t result);

    void ReportSetTransferResult(int32_t result);

    void ReportGetClipResult(const ClipResponse &response);

    void ReportGetClirResult(const ClirResponse &response);

    void ReportSetClirResult(int32_t result);

    void ReportGetImsConfigResult(const GetImsConfigResponse &response);

    void ReportSetImsConfigResult(int32_t result);

    void ReportGetImsFeatureResult(const GetImsFeatureValueResponse &response);

    void ReportSetImsFeatureResult(int32_t result);

    void ReportCallRingBackResult(int32_t status);

    void ReportSetMuteResult(const MuteControlResponse &response);

    void ReportGetMuteResult(const MuteControlResponse &response);

    void ReportCallFailReason(const DisconnectedDetails &details);

    void ReportInviteToConferenceResult(int32_t result);

    void ReportGetCallDataResult(int32_t result);

    void ReportStartDtmfResult(int32_t result);

    void ReportStopDtmfResult(int32_t result);

    void ReportStartRttResult(int32_t result);

    void ReportStopRttResult(int32_t result);

    void ReportSendUssdResult(int32_t result);

    void ReportCloseUnFinishedUssdResult(int32_t result);

    int32_t RegisterCallManagerCallBack(const sptr<ICallStatusCallback> &callback);

    int32_t UnRegisterCallManagerCallBack();

    void ReportMmiCodeResult(const MmiCodeInfo &info);

    void ReportSetEmergencyCallListResponse(const SetEccListResponse &response);

    bool IsCallManagerCallBackRegistered();

    void ReportPostDialChar(char c);

    void ReportPostDialDelay(std::string str);

    void ReceiveUpdateCallMediaModeRequest(ImsCallModeReceiveInfo &callModeInfo);

    void ReceiveUpdateCallMediaModeResponse(ImsCallModeReceiveInfo &callModeInfo);

    void HandleCallSessionEventChanged(ImsCallSessionEventInfo &callSessionEventInfo);

    void HandlePeerDimensionsChanged(ImsCallPeerDimensionsInfo &callPeerDimensionsInfo);

    void HandleCallDataUsageChanged(ImsCallDataUsageInfo &callDataUsageInfo);

    void HandleCameraCapabilitiesChanged(CameraCapabilitiesInfo &cameraCapabilitiesInfo);

    ImsCallMode ConverToImsCallMode(ImsCallType callType);

private:
    sptr<ICallStatusCallback> callManagerCallBack_;
    std::mutex mutex_;
};
} // namespace Telephony
} // namespace OHOS

#endif // CELLULAR_CALL_REGISTER_H

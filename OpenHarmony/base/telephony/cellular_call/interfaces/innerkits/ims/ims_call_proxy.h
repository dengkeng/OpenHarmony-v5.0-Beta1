/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef TELEPHONY_IMS_CALL_PROXY_H
#define TELEPHONY_IMS_CALL_PROXY_H

#include "ims_call_interface.h"
#include "ims_call_ipc_interface_code.h"
#include "ims_feature.h"
#include "iremote_proxy.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class ImsCallProxy : public IRemoteProxy<ImsCallInterface> {
public:
    explicit ImsCallProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<ImsCallInterface>(impl) {}
    ~ImsCallProxy() = default;
    int32_t Dial(const ImsCallInfo &callInfo, CLIRMode mode) override;
    int32_t HangUp(const ImsCallInfo &callInfo) override;
    int32_t RejectWithReason(const ImsCallInfo &callInfo, const ImsRejectReason &reason) override;
    int32_t Answer(const ImsCallInfo &callInfo) override;
    int32_t HoldCall(int32_t slotId, int32_t callType) override;
    int32_t UnHoldCall(int32_t slotId, int32_t callType) override;
    int32_t SwitchCall(int32_t slotId, int32_t callType) override;
    int32_t CombineConference(int32_t slotId) override;
    int32_t InviteToConference(int32_t slotId, const std::vector<std::string> &numberList) override;
    int32_t KickOutFromConference(int32_t slotId, int32_t index) override;
    int32_t SendUpdateCallMediaModeRequest(const ImsCallInfo &callInfo, ImsCallType callType) override;
    int32_t SendUpdateCallMediaModeResponse(const ImsCallInfo &callInfo, ImsCallType callType) override;
    int32_t CancelCallUpgrade(int32_t slotId, int32_t callIndex) override;
    int32_t RequestCameraCapabilities(int32_t slotId, int32_t callIndex) override;
    int32_t GetImsCallsDataRequest(int32_t slotId, int64_t lastCallsDataFlag) override;
    int32_t GetLastCallFailReason(int32_t slotId) override;

    int32_t StartDtmf(int32_t slotId, char cDtmfCode, int32_t index) override;
    int32_t SendDtmf(int32_t slotId, char cDtmfCode, int32_t index) override;
    int32_t StopDtmf(int32_t slotId, int32_t index) override;
    int32_t StartRtt(int32_t slotId, const std::string &msg) override;
    int32_t StopRtt(int32_t slotId) override;

    int32_t SetDomainPreferenceMode(int32_t slotId, int32_t mode) override;
    int32_t GetDomainPreferenceMode(int32_t slotId) override;
    int32_t SetImsSwitchStatus(int32_t slotId, int32_t active) override;
    int32_t GetImsSwitchStatus(int32_t slotId) override;
    int32_t SetImsConfig(ImsConfigItem item, const std::string &value) override;
    int32_t SetImsConfig(ImsConfigItem item, int32_t value) override;
    int32_t GetImsConfig(ImsConfigItem item) override;
    int32_t SetImsFeatureValue(FeatureType type, int32_t value) override;
    int32_t GetImsFeatureValue(FeatureType type, int32_t &value) override;
    int32_t SetMute(int32_t slotId, int32_t mute) override;
    int32_t GetMute(int32_t slotId) override;

    int32_t ControlCamera(int32_t slotId, int32_t callIndex, const std::string &cameraId) override;
    int32_t SetPreviewWindow(
        int32_t slotId, int32_t callIndex, const std::string &surfaceID, sptr<Surface> surface) override;
    int32_t SetDisplayWindow(
        int32_t slotId, int32_t callIndex, const std::string &surfaceID, sptr<Surface> surface) override;
    int32_t SetCameraZoom(float zoomRatio) override;
    int32_t SetPausePicture(int32_t slotId, int32_t callIndex, const std::string &path) override;
    int32_t SetDeviceDirection(int32_t slotId, int32_t callIndex, int32_t rotation) override;

    int32_t SetClip(int32_t slotId, int32_t action, int32_t index) override;
    int32_t GetClip(int32_t slotId, int32_t index) override;
    int32_t SetClir(int32_t slotId, int32_t action, int32_t index) override;
    int32_t GetClir(int32_t slotId, int32_t index) override;
    int32_t SetCallTransfer(int32_t slotId, const CallTransferInfo &cfInfo, int32_t classType, int32_t index) override;
    int32_t CanSetCallTransferTime(int32_t slotId, bool &result) override;
    int32_t GetCallTransfer(int32_t slotId, int32_t reason, int32_t index) override;
    int32_t SetCallRestriction(
        int32_t slotId, const std::string &fac, int32_t mode, const std::string &pw, int32_t index) override;
    int32_t GetCallRestriction(int32_t slotId, const std::string &fac, int32_t index) override;
    int32_t SetCallWaiting(int32_t slotId, bool activate, int32_t classType, int32_t index) override;
    int32_t GetCallWaiting(int32_t slotId, int32_t index) override;
    int32_t SetColr(int32_t slotId, int32_t presentation, int32_t index) override;
    int32_t GetColr(int32_t slotId, int32_t index) override;
    int32_t SetColp(int32_t slotId, int32_t action, int32_t index) override;
    int32_t GetColp(int32_t slotId, int32_t index) override;

    int32_t RegisterImsCallCallback(const sptr<ImsCallCallbackInterface> &callback) override;
    int32_t UpdateImsCapabilities(int32_t slotId, const ImsCapabilityList &imsCapabilityList) override;
    int32_t GetUtImpuFromNetwork(int32_t slotId, std::string &impu) override;

private:
    int32_t WriteCommonInfo(int32_t slotId, std::string funcName, MessageParcel &in);
    int32_t WriteCommonInfo(int32_t slotId, std::string funcName, MessageParcel &in, int32_t callType);
    int32_t SendRequest(MessageParcel &in, int32_t eventId);
    int32_t SendRequest(int32_t slotId, MessageParcel &in, int32_t eventId);

private:
    static inline BrokerDelegator<ImsCallProxy> delegator_;
};
} // namespace Telephony
} // namespace OHOS

#endif // TELEPHONY_IMS_CALL_PROXY_H

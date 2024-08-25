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

#ifndef IMS_CALL_STUB_H
#define IMS_CALL_STUB_H
#include <unordered_map>

#include "ims_call_interface.h"
#include "ims_call_ipc_interface_code.h"
#include "iremote_stub.h"

namespace OHOS {
namespace Telephony {
class ImsCallStub : public IRemoteStub<ImsCallInterface> {
public:
    ImsCallStub();
    virtual ~ImsCallStub();
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);

private:
    using ImsCallFunc = int32_t (ImsCallStub::*)(MessageParcel &data, MessageParcel &reply);
    int32_t OnDial(MessageParcel &data, MessageParcel &reply);
    int32_t OnHangUp(MessageParcel &data, MessageParcel &reply);
    int32_t OnRejectWithReason(MessageParcel &data, MessageParcel &reply);
    int32_t OnAnswer(MessageParcel &data, MessageParcel &reply);
    int32_t OnHoldCall(MessageParcel &data, MessageParcel &reply);
    int32_t OnUnHoldCall(MessageParcel &data, MessageParcel &reply);
    int32_t OnSwitchCall(MessageParcel &data, MessageParcel &reply);
    int32_t OnCombineConference(MessageParcel &data, MessageParcel &reply);
    int32_t OnInviteToConference(MessageParcel &data, MessageParcel &reply);
    int32_t OnKickOutFromConference(MessageParcel &data, MessageParcel &reply);
    int32_t OnUpdateImsCallMode(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetImsCallsDataRequest(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetLastCallFailReason(MessageParcel &data, MessageParcel &reply);
    int32_t OnStartDtmf(MessageParcel &data, MessageParcel &reply);
    int32_t OnSendDtmf(MessageParcel &data, MessageParcel &reply);
    int32_t OnStopDtmf(MessageParcel &data, MessageParcel &reply);
    int32_t OnStartRtt(MessageParcel &data, MessageParcel &reply);
    int32_t OnStopRtt(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetDomainPreferenceMode(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetDomainPreferenceMode(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetImsSwitchStatus(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetImsSwitchStatus(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetImsConfigInt(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetImsConfigString(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetImsConfig(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetImsFeatureValue(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetImsFeatureValue(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetMute(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetMute(MessageParcel &data, MessageParcel &reply);
    int32_t OnCtrlCamera(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetPreviewWindow(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetDisplayWindow(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetCameraZoom(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetPauseImage(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetDeviceDirection(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetClip(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetClip(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetClir(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetClir(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetCallTransfer(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetCallTransfer(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetCallRestriction(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetCallRestriction(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetCallWaiting(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetCallWaiting(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetColr(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetColr(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetColp(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetColp(MessageParcel &data, MessageParcel &reply);
    int32_t OnRegisterImsCallCallback(MessageParcel &data, MessageParcel &reply);
    int32_t OnUpdateImsCapabilities(MessageParcel &data, MessageParcel &reply);
    void InitFuncMap();
    void InitDialFuncMap();
    void InitDtmfFuncMap();
    void InitConfigFuncMap();
    void InitVideoFuncMap();
    void InitSupplementFuncMap();

private:
    std::unordered_map<uint32_t, ImsCallFunc> memberFuncMap_;
};
} // namespace Telephony
} // namespace OHOS
#endif // IMS_CALL_STUB_H

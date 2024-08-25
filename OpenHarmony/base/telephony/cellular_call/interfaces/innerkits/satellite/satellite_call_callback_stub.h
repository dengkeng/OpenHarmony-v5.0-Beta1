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

#ifndef TELEPHONY_SATELLITE_CALL_CALLBACK_STUB_H
#define TELEPHONY_SATELLITE_CALL_CALLBACK_STUB_H

#include <map>

#include "cellular_call_data_struct.h"
#include "iremote_stub.h"
#include "satellite_call_callback_interface.h"
#include "satellite_call_callback_ipc_interface_code.h"

namespace OHOS {
namespace Telephony {
class SatelliteCallCallbackStub : public IRemoteStub<SatelliteCallCallbackInterface> {
public:
    SatelliteCallCallbackStub();
    virtual ~SatelliteCallCallbackStub();
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    /****************** call basic ******************/
    int32_t DialSatelliteResponse(int32_t slotId, const RadioResponseInfo &info) override;
    int32_t HangUpSatelliteResponse(int32_t slotId, const RadioResponseInfo &info) override;
    int32_t RejectSatelliteResponse(int32_t slotId, const RadioResponseInfo &info) override;
    int32_t AnswerSatelliteResponse(int32_t slotId, const RadioResponseInfo &info) override;
    int32_t CallStateChangeReport(int32_t slotId) override;
    int32_t GetSatelliteCallsDataResponse(int32_t slotId, const RadioResponseInfo &info) override;
    int32_t GetSatelliteCallsDataResponse(int32_t slotId, const SatelliteCurrentCallList &callList) override;

private:
    void InitFuncMap();
    void InitCallBasicFuncMap();

    /****************** call basic ******************/
    int32_t OnDialResponseInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnHangUpResponseInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnRejectResponseInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnAnswerResponseInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetSatelliteCallsDataResponseInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnCallStateChangeReportInner(MessageParcel &data, MessageParcel &reply);
    int32_t SendEvent(int32_t slotId, int32_t eventId, const RadioResponseInfo &info);

private:
    using RequestFuncType = int32_t (SatelliteCallCallbackStub::*)(MessageParcel &data, MessageParcel &reply);
    std::map<uint32_t, RequestFuncType> requestFuncMap_;
};
} // namespace Telephony
} // namespace OHOS

#endif // TELEPHONY_SATELLITE_CALL_CALLBACK_STUB_H

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

#ifndef TELEPHONY_SATELLITE_CALL_PROXY_H
#define TELEPHONY_SATELLITE_CALL_PROXY_H

#include "iremote_proxy.h"
#include "satellite_call_interface.h"
#include "satellite_call_ipc_interface_code.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class SatelliteCallProxy : public IRemoteProxy<SatelliteCallInterface> {
public:
    explicit SatelliteCallProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<SatelliteCallInterface>(impl) {}
    ~SatelliteCallProxy() = default;
    int32_t Dial(const SatelliteCallInfo &callInfo, CLIRMode mode) override;
    int32_t HangUp(int32_t slotId, int32_t index) override;
    int32_t Reject(int32_t slotId) override;
    int32_t Answer(int32_t slotId) override;
    int32_t GetSatelliteCallsDataRequest(int32_t slotId) override;
    int32_t RegisterSatelliteCallCallback(const sptr<SatelliteCallCallbackInterface> &callback) override;

private:
    int32_t WriteCommonInfo(int32_t slotId, std::string funcName, MessageParcel &in);
    int32_t WriteCommonInfo(int32_t slotId, std::string funcName, MessageParcel &in, int32_t callType);
    int32_t SendRequest(MessageParcel &in, int32_t eventId);
    int32_t SendRequest(int32_t slotId, MessageParcel &in, int32_t eventId);

private:
    static inline BrokerDelegator<SatelliteCallProxy> delegator_;
};
} // namespace Telephony
} // namespace OHOS

#endif // TELEPHONY_SATELLITE_CALL_PROXY_H

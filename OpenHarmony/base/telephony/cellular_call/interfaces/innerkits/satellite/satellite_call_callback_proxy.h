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

#ifndef TELEPHONY_SATELLITE_CALL_CALLBACK_PROXY_H
#define TELEPHONY_SATELLITE_CALL_CALLBACK_PROXY_H

#include "iremote_proxy.h"
#include "satellite_call_callback_interface.h"
#include "satellite_call_callback_ipc_interface_code.h"
#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {
class SatelliteCallCallbackProxy : public IRemoteProxy<SatelliteCallCallbackInterface> {
public:
    explicit SatelliteCallCallbackProxy(const sptr<IRemoteObject> &impl);
    virtual ~SatelliteCallCallbackProxy() = default;

    /****************** call basic ******************/
    int32_t DialSatelliteResponse(int32_t slotId, const RadioResponseInfo &info) override;
    int32_t HangUpSatelliteResponse(int32_t slotId, const RadioResponseInfo &info) override;
    int32_t RejectSatelliteResponse(int32_t slotId, const RadioResponseInfo &info) override;
    int32_t AnswerSatelliteResponse(int32_t slotId, const RadioResponseInfo &info) override;
    int32_t CallStateChangeReport(int32_t slotId) override;
    int32_t GetSatelliteCallsDataResponse(int32_t slotId, const RadioResponseInfo &info) override;
    int32_t GetSatelliteCallsDataResponse(int32_t slotId, const SatelliteCurrentCallList &callList) override;

private:
    int32_t SendResponseInfo(int32_t eventId, MessageParcel &in);
    int32_t WriteCommonInfo(int32_t slotId, const std::string &funcName, MessageParcel &in);
    int32_t WriteCommonInfo(
        int32_t slotId, const std::string &funcName, MessageParcel &in, const RadioResponseInfo &info);
    int32_t WriteSsBaseResultCommonInfo(
        int32_t slotId, const std::string &funcName, MessageParcel &in, const SsBaseResult &ssResult);

private:
    static inline BrokerDelegator<SatelliteCallCallbackProxy> delegator_;
};
} // namespace Telephony
} // namespace OHOS

#endif // TELEPHONY_SATELLITE_CALL_CALLBACK_PROXY_H
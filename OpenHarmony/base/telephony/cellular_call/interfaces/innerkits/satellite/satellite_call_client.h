
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

#ifndef TELEPHONY_SATELLITE_CALL_CLIENT_H
#define TELEPHONY_SATELLITE_CALL_CLIENT_H

#include "event_runner.h"
#include "i_satellite_service.h"
#include "iremote_stub.h"
#include "rwlock.h"
#include "satellite_call_interface.h"
#include "singleton.h"
#include "system_ability_status_change_stub.h"

namespace OHOS {
namespace Telephony {
class SatelliteCallClient {
    DECLARE_DELAYED_SINGLETON(SatelliteCallClient);

public:
    /**
     * @brief Get SatelliteCall Remote Object ptr
     *
     * @return sptr<SatelliteCallInterface>
     */
    sptr<SatelliteCallInterface> GetSatelliteCallProxy();

    /**
     * @brief Get the remote object ptr, initiate a listener and subscribe the system ability
     */
    void Init();

    /**
     * @brief Clear the listener and the remote ptr when destroy the SatelliteCallClient Object
     */
    void UnInit();

    /**
     * @brief Register SatelliteCallCallback Handler, put the handler and slot id into {handlerMap_}
     *
     * @param slotId Indicates the card slot index number,
     * @param handler Indicates the event handler ptr
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t RegisterSatelliteCallCallbackHandler(
        int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    /**
     * @brief Get the event handler ptr from {handlerMap_}
     *
     * @param slotId Indicates the card slot index number,
     * @return AppExecFwk::EventHandler
     */
    std::shared_ptr<AppExecFwk::EventHandler> GetHandler(int32_t slotId);

    /****************** call basic ******************/
    /**
     * @brief Satellite dial the call interface
     *
     * @param SatelliteCallInfo Indicates the call detail information, contains phone number, slot id,
     * video state, call index
     * @param CLIRMode Indicates the CLIR mode, like default, transfer, inhibition
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t Dial(const SatelliteCallInfo &callInfo, CLIRMode mode);

    /**
     * @brief Satellite HangUp the call interface
     *
     * @param slotId Indicates the call slot id,
     * @param index Indicates the call id,
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t HangUp(int32_t slotId, int32_t index);

    /**
     * @brief Satellite Reject the call interface
     *
     * @param slotId Indicates the call slot id,
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t Reject(int32_t slotId);

    /**
     * @brief Satellite Answer the call interface
     *
     * @param slotId Indicates the call slot id,
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t Answer(int32_t slotId);

    /**
     * @brief Get Satellite Calls Data Request
     *
     * @param slotId Indicates the card slot index number,
     * @param lastCallsDataFlag The Satellite call data id, is a number in milliseconds
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetSatelliteCallsDataRequest(int32_t slotId, int64_t lastCallsDataFlag);

    /**
     * @brief Get Satellite status
     *
     * @param slotId Indicates the card slot index number,
     * @return Returns true on satellite enable, others on false.
     */
    bool IsSatelliteEnabled(int32_t slotId);

private:
    /**
     * Is Connect ImsCall Remote Object
     *
     * @return bool
     */
    bool IsConnect() const;
    int32_t RegisterSatelliteCallCallback();
    int32_t ReConnectService();
    void Clean();

private:
    sptr<ISatelliteService> satelliteServiceProxy_ = nullptr;
    sptr<SatelliteCallInterface> satelliteCallProxy_ = nullptr;
    sptr<SatelliteCallCallbackInterface> satelliteCallCallback_ = nullptr;
    std::map<int32_t, std::shared_ptr<AppExecFwk::EventHandler>> handlerMap_;
    Utils::RWLock rwClientLock_;
};
} // namespace Telephony
} // namespace OHOS

#endif // TELEPHONY_SATELLITE_CALL_CLIENT_H
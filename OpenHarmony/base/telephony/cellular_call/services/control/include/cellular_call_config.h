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

#ifndef CELLULAR_CALL_CONFIG_H
#define CELLULAR_CALL_CONFIG_H

#include <map>
#include <mutex>

#include "config_request.h"
#include "global_params_data.h"
#include "operator_config_types.h"
#include "sim_state_type.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class CellularCallConfig {
public:
    /**
     * CellularCallConfig constructor
     *
     */
    CellularCallConfig();

    /**
     * Set Domain Preference Mode
     *
     * 3GPP TS 27.007 V17.3.0 (2021-09) 10.1.35	UE's voice domain preference E-UTRAN +CEVDP
     * 3GPP TS 24.167 V17.1.0 (2020-12) 5.27 /<X>/Voice_Domain_Preference_E_UTRAN
     *
     * @param mode
     * @param slotId
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetDomainPreferenceMode(int32_t slotId, int32_t mode);

    /**
     * Get Domain Preference Mode
     *
     * 3GPP TS 27.007 V17.3.0 (2021-09) 10.1.35	UE's voice domain preference E-UTRAN +CEVDP
     * 3GPP TS 24.167 V17.1.0 (2020-12) 5.27 /<X>/Voice_Domain_Preference_E_UTRAN
     *
     * @param slotId
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetDomainPreferenceMode(int32_t slotId);

    /**
     * Set Lte Ims Switch Status
     *
     * 3GPP TS 24.167 V17.1.0 (2020-12) 5.31 /<X>/Mobility_Management_IMS_Voice_Termination
     *
     * @param slotId
     * @param active
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetImsSwitchStatus(int32_t slotId, bool active);

    /**
     * Get Lte Ims Switch Status
     *
     * 3GPP TS 24.167 V17.1.0 (2020-12) 5.31 /<X>/Mobility_Management_IMS_Voice_Termination
     *
     * @param slotId
     * @param enabled
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetImsSwitchStatus(int32_t slotId, bool &enabled);

    /**
     * Set VoNR Switch Status
     *
     * @param slotId
     * @param state
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetVoNRSwitchStatus(int32_t slotId, int32_t state);

    /**
     * Get VoNR Switch Status
     *
     * @param slotId
     * @param state
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetVoNRSwitchStatus(int32_t slotId, int32_t &state);

    /**
     * Get Domain Preference Mode Response
     *
     * @param slotId
     * @param mode
     */
    void GetDomainPreferenceModeResponse(int32_t slotId, int32_t mode);

    /**
     * Get Lte Ims Switch Status Response
     *
     * @param slotId
     * @param active
     */
    void GetImsSwitchStatusResponse(int32_t slotId, int32_t active);

    /**
     * Get Preference Mode
     *
     * @param slotId
     * @return mode
     */
    int32_t GetPreferenceMode(int32_t slotId) const;

    /**
     * Set Ims Config
     *
     * @param ImsConfigItem
     * @param value
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetImsConfig(ImsConfigItem item, const std::string &value);

    /**
     * Set Ims Config
     *
     * @param ImsConfigItem
     * @param value
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetImsConfig(ImsConfigItem item, int32_t value);

    /**
     * Get Ims Config
     *
     * @param ImsConfigItem
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetImsConfig(ImsConfigItem item);

    /**
     * Set Ims Feature Value
     *
     * @param FeatureType
     * @param value
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetImsFeatureValue(FeatureType type, int32_t value);

    /**
     * Get Ims Feature Value
     *
     * @param FeatureType
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetImsFeatureValue(FeatureType type);

    /**
     * SetMute
     *
     * @param slotId
     * @param mute
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetMute(int32_t slotId, int32_t mute);

    /**
     * GetMute
     *
     * @param slotId
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetMute(int32_t slotId);

    /**
     * GetEmergencyCallList
     *
     * @param slotId
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetEmergencyCallList(int32_t slotId);

    /**
     * SetEmergencyCallList
     *
     * @param slotId
     * @param eccVec
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetEmergencyCallList(int32_t slotId, std::vector<EmergencyCall> &eccVec);

    /**
     * SetTempMode
     *
     * @param slotId
     */
    void SetTempMode(int32_t slotId);

    /**
     * Init mode and active
     */
    void InitModeActive();

    /**
     * Get Emergency Call List Response
     *
     * @param slotId
     * @param EmergencyInfoList
     */
    void UpdateEmergencyCallFromRadio(int32_t slotId, const EmergencyInfoList &eccList);

    /**
     * HandleSimStateChanged
     *
     * @param slotId
     */
    void HandleSimStateChanged(int32_t slotId);

    /**
     * HandleFactoryReset
     *
     * @param slotId
     */
    void HandleFactoryReset(int32_t slotId);

    /**
     * HandleSetLteImsSwitchResult
     *
     * @param slotId
     * @param result
     */
    void HandleSetLteImsSwitchResult(int32_t slotId, ErrType result);

    /**
     * HandleSetVoNRSwitchResult
     *
     * @param slotId
     * @param result
     */
    void HandleSetVoNRSwitchResult(int32_t slotId, ErrType result);

    /**
     * HandleSimRecordsLoaded
     *
     * @param slotId
     */
    void HandleSimRecordsLoaded(int32_t slotId);

    void HandleResidentNetworkChange(int32_t slotId, std::string plmn);

    void HandleNetworkStateChange(int32_t slotId);

    /**
     * HandleSimAccountLoaded
     *
     * @param slotId
     */
    void HandleSimAccountLoaded(int32_t slotId);

    /**
     * Handle when operator config change.
     *
     * @param slotId
     */
    void HandleOperatorConfigChanged(int32_t slotId);

    /**
     * Get Ecc Call List
     *
     * @param slotId
     * @return std::vector<EmergencyCall>
     */
    std::vector<EmergencyCall> GetEccCallList(int32_t slotId);

    std::string GetMcc(int32_t slotId_);

    /**
     * Change bool value to Ims switch value.
     *
     * @param value
     * @return std::int32_t
     */
    std::int32_t BooleanToImsSwitchValue(bool value);

    /**
     * The IF used to get the value of operator config
     * {@link OperatorConfig#KEY_IMS_SWITCH_ON_BY_DEFAULT_BOOL}
     *
     * @param slotId
     * @return bool
     */
    bool GetImsSwitchOnByDefaultConfig(int32_t slotId);

    /**
     * The IF used to get the value of operator config
     * {@link OperatorConfig#KEY_HIDE_IMS_SWITCH_BOOL}
     *
     * @param slotId
     * @return bool
     */
    bool GethideImsSwitchConfig(int32_t slotId);

    /**
     * The IF used to get the value of operator config
     * {@link OperatorConfig#KEY_VOLTE_SUPPORTED_BOOL}
     *
     * @param slotId
     * @return bool
     */
    bool GetvolteSupportedConfig(int32_t slotId);

    /**
     * The IF used to get the value of operator config
     * {@link OperatorConfig#KEY_NR_MODE_SUPPORTED_LIST_INT_ARRAY}
     *
     * @param slotId
     * @return std::vector<int32_t>
     */
    std::vector<int32_t> GetNrModeSupportedListConfig(int32_t slotId);

    /**
     * The IF used to get the value of operator config
     * {@link OperatorConfig#KEY_VOLTE_PROVISIONING_SUPPORTED_BOOL}
     *
     * @param slotId
     * @return bool
     */
    bool GetVolteProvisioningSupportedConfig(int32_t slotId);

    /**
     * The IF used to get the value of operator config
     * {@link OperatorConfig#KEY_SS_OVER_UT_SUPPORTED_BOOL}
     *
     * @param slotId
     * @return bool
     */
    bool GetSsOverUtSupportedConfig(int32_t slotId);

    /**
     * The IF used to get the value of operator config
     * {@link OperatorConfig#KEY_IMS_GBA_REQUIRED_BOOL}
     *
     * @param slotId
     * @return bool
     */
    bool GetImsGbaRequiredConfig(int32_t slotId);

    /**
     * The IF used to get the value of operator config
     * {@link OperatorConfig#KEY_UT_PROVISIONING_SUPPORTED_BOOL}
     *
     * @param slotId
     * @return bool
     */
    bool GetUtProvisioningSupportedConfig(int32_t slotId);

    /**
     * The IF used to get the value of operator config
     * {@link OperatorConfig#KEY_IMS_PREFER_FOR_EMERGENCY_BOOL}
     *
     * @param slotId
     * @return bool
     */
    bool GetImsPreferForEmergencyConfig(int32_t slotId);

    /**
     * The IF used to get the value of operator config
     * {@link OperatorConfig#KEY_CALL_WAITING_SERVICE_CLASS_INT}
     *
     * @param slotId
     * @return std::int32_t
     */
    std::int32_t GetCallWaitingServiceClassConfig(int32_t slotId);

    /**
     * The IF used to get the value of operator config
     * {@link OperatorConfig#KEY_IMS_CALL_DISCONNECT_REASONINFO_MAPPING_STRING_ARRAY}
     *
     * @param slotId
     * @return std::vector<std::string>
     */
    std::vector<std::string> GetImsCallDisconnectResoninfoMappingConfig(int32_t slotId);

    /**
     * The IF used to get the value of operator config
     * {@link OperatorConfig#KEY_FORCE_VOLTE_SWITCH_ON_BOOL}
     *
     * @param slotId
     * @return bool
     */
    bool GetForceVolteSwitchOnConfig(int32_t slotId);

    /**
     * Is Valid Slot Id
     *
     * @param slotId
     * @return bool
     */
    bool IsValidSlotId(int32_t slotId);

    void SetReadyToCall(int32_t slotId, bool isReadyToCall);

    bool IsReadyToCall(int32_t slotId);

private:
    static void InitDefaultOperatorConfig();
    EmergencyCall BuildDefaultEmergencyCall(const std::string &number, SimpresentType simType);
    EmergencyCall BuildEmergencyCall(int32_t slotId, const EmergencyInfo &from);
    void UniqueEccCallList(int32_t slotId, std::vector<EmergencyCall> &eccList);
    void MergeEccCallList(int32_t slotId);
    bool CheckAndUpdateSimState(int32_t slotId);
    int32_t ParseAndCacheOperatorConfigs(int32_t slotId, OperatorConfig &poc);
    void ParseBoolOperatorConfigs(
        int32_t slotId, std::map<int32_t, bool> &config, OperatorConfig &poc, std::string configName);
    void ResetImsSwitch(int32_t slotId);
    void UpdateImsCapabilities(int32_t slotId, bool needUpdateUtCapability);
    void UpdateImsUtCapabilities(int32_t slotId, bool isGbaValid, ImsCapabilityList &imsCapabilityList);
    void UpdateImsVoiceCapabilities(int32_t slotId, bool isGbaValid, ImsCapabilityList &imsCapabilityList);
    bool IsGbaValid(int32_t slotId);
    bool IsVolteProvisioned(int32_t slotId);
    bool IsVonrSupported(int32_t slotId, bool isGbaValid);
    bool IsUtProvisioned(int32_t slotId);
    bool IsNeedTurnOnIms(const ImsCapabilityList &imsCapabilityList);
    bool IsSimChanged(int32_t slotId, std::string iccid);
    bool ChangeImsSwitchWithOperatorConfig(int32_t slotId, bool active);
    int32_t SaveImsSwitch(int32_t slotId, int32_t imsSwitchValue);
    int32_t GetSwitchStatus(int32_t slotId);
    void saveImsSwitchStatusToLocalForPowerOn(int32_t slotId);
    void saveImsSwitchStatusToLocal(int32_t slotId, int32_t imsSwitchStatus);
    void SaveVoNRState(int32_t slotId, int32_t state);
    int32_t ObtainVoNRState(int32_t slotId);
    void UpdateEccNumberList(int32_t slotId);
    void GetEccListFromResult(const std::vector<EccNum> &eccVec,
        std::vector<std::string> &callListWithCard, std::vector<std::string> &callListNoCard);

private:
    static std::map<int32_t, int32_t> modeTempMap_;
    static std::map<int32_t, int32_t> modeMap_;
    static std::map<int32_t, std::vector<EmergencyCall>> eccListRadioMap_;
    static std::vector<EmergencyCall> eccList3gppHasSim_;
    static std::vector<EmergencyCall> eccList3gppNoSim_;
    static std::map<int32_t, std::vector<EmergencyCall>> allEccList_;
    static std::map<int32_t, int32_t> simState_;
    static std::map<int32_t, std::string> curPlmn_;
    static std::map<int32_t, RegServiceState> serviceState_;
    std::mutex mutex_;
    std::mutex simStateLock_;
    static std::mutex operatorMutex_;
    ConfigRequest configRequest_;
    static std::map<int32_t, bool> imsSwitchOnByDefault_;
    static std::map<int32_t, bool> hideImsSwitch_;
    static std::map<int32_t, bool> volteSupported_;
    static std::map<int32_t, std::vector<int32_t>> nrModeSupportedList_;
    static std::map<int32_t, bool> volteProvisioningSupported_;
    static std::map<int32_t, bool> ssOverUtSupported_;
    static std::map<int32_t, bool> imsGbaRequired_;
    static std::map<int32_t, bool> utProvisioningSupported_;
    static std::map<int32_t, bool> imsPreferForEmergency_;
    static std::map<int32_t, int32_t> callWaitingServiceClass_;
    static std::map<int32_t, std::vector<std::string>> imsCallDisconnectResoninfoMapping_;
    static std::map<int32_t, bool> forceVolteSwitchOn_;
    static std::map<int32_t, bool> readyToCall_;
    static std::map<int32_t, int32_t> vonrSwithStatus_;
    static bool isOperatorConfigInit_;
};
} // namespace Telephony
} // namespace OHOS
#endif // CELLULAR_CALL_CONFIG_H

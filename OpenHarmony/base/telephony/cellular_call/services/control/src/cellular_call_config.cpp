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

#include "cellular_call_config.h"

#include "cellular_call_data_struct.h"
#include "cellular_call_hisysevent.h"
#include "cellular_call_rdb_helper.h"
#include "cellular_call_register.h"
#include "cellular_call_service.h"
#include "core_manager_inner.h"
#include "core_service_client.h"
#include "module_service_utils.h"
#include "parameters.h"
#include "standardize_utils.h"
#include "string_ex.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
const int32_t SIM_PRESENT = 1;
const int32_t SIM_ABSENT = 0;
const int32_t IMS_SWITCH_STATUS_UNKNOWN = -1;
const int32_t IMS_SWITCH_STATUS_OFF = 0;
const int32_t IMS_SWITCH_STATUS_ON = 1;
const int32_t VONR_SWITCH_STATUS_UNKNOWN = -1;
const int32_t VONR_SWITCH_STATUS_OFF = 0;
const int32_t VONR_SWITCH_STATUS_ON = 1;
const int32_t SAVE_IMS_SWITCH_FAILED = 0;
const int32_t SAVE_IMS_SWITCH_SUCCESS_CHANGED = 1;
const int32_t SAVE_IMS_SWITCH_SUCCESS_NOT_CHANGED = 2;
const int32_t INVALID_SIM_ID = 0;
const int32_t IMS_GBA_BIT = 0x02;
const int32_t SYSTEM_PARAMETER_LENGTH = 0x02;
const int MCC_LEN = 3;
const std::string LAST_ICCID_KEY = "persist.telephony.last_iccid";
const std::string IMSSWITCH_STATE = "persist.telephony.imsswitch";
const std::string VONR_STATE = "persist.telephony.vonrswitch";

std::map<int32_t, int32_t> CellularCallConfig::modeMap_;
std::map<int32_t, int32_t> CellularCallConfig::modeTempMap_;
std::map<int32_t, bool> CellularCallConfig::imsSwitchOnByDefault_;
std::map<int32_t, bool> CellularCallConfig::hideImsSwitch_;
std::map<int32_t, bool> CellularCallConfig::volteSupported_;
std::map<int32_t, std::vector<int32_t>> CellularCallConfig::nrModeSupportedList_;
std::map<int32_t, bool> CellularCallConfig::volteProvisioningSupported_;
std::map<int32_t, bool> CellularCallConfig::ssOverUtSupported_;
std::map<int32_t, bool> CellularCallConfig::imsGbaRequired_;
std::map<int32_t, bool> CellularCallConfig::utProvisioningSupported_;
std::map<int32_t, bool> CellularCallConfig::imsPreferForEmergency_;
std::map<int32_t, int32_t> CellularCallConfig::callWaitingServiceClass_;
std::map<int32_t, std::vector<std::string>> CellularCallConfig::imsCallDisconnectResoninfoMapping_;
std::map<int32_t, bool> CellularCallConfig::forceVolteSwitchOn_;
std::map<int32_t, int32_t> CellularCallConfig::vonrSwithStatus_;
std::mutex mutex_;
std::mutex CellularCallConfig::operatorMutex_;
std::map<int32_t, std::vector<EmergencyCall>> CellularCallConfig::eccListRadioMap_;
std::vector<EmergencyCall> CellularCallConfig::eccList3gppHasSim_;
std::vector<EmergencyCall> CellularCallConfig::eccList3gppNoSim_;
std::map<int32_t, std::vector<EmergencyCall>> CellularCallConfig::allEccList_;
std::map<int32_t, int32_t> CellularCallConfig::simState_;
std::map<int32_t, std::string> CellularCallConfig::curPlmn_;
std::map<int32_t, RegServiceState> CellularCallConfig::serviceState_;
std::map<int32_t, bool> CellularCallConfig::readyToCall_;
bool CellularCallConfig::isOperatorConfigInit_ = false;

void CellularCallConfig::InitDefaultOperatorConfig()
{
    std::lock_guard<std::mutex> lock(operatorMutex_);
    for (int32_t i = DEFAULT_SIM_SLOT_ID; i < SIM_SLOT_COUNT; ++i) {
        CellularCallConfig::imsSwitchOnByDefault_.insert(std::pair<int, bool>(i, true));
        CellularCallConfig::hideImsSwitch_.insert(std::pair<int, bool>(i, false));
        CellularCallConfig::volteSupported_.insert(std::pair<int, bool>(i, false));
        CellularCallConfig::nrModeSupportedList_.insert(std::pair<int, std::vector<int32_t>>(
            i, std::vector<int32_t> { CARRIER_NR_AVAILABILITY_NSA, CARRIER_NR_AVAILABILITY_SA }));
        CellularCallConfig::volteProvisioningSupported_.insert(std::pair<int, bool>(i, false));
        CellularCallConfig::ssOverUtSupported_.insert(std::pair<int, bool>(i, false));
        CellularCallConfig::imsGbaRequired_.insert(std::pair<int, bool>(i, false));
        CellularCallConfig::utProvisioningSupported_.insert(std::pair<int, bool>(i, false));
        CellularCallConfig::imsPreferForEmergency_.insert(std::pair<int, bool>(i, true));
        CellularCallConfig::callWaitingServiceClass_.insert(
            std::pair<int, int32_t>(i, DEFAULT_CALL_WAITING_SERVICE_CLASS_CONFIG));
        CellularCallConfig::imsCallDisconnectResoninfoMapping_.insert(
            std::pair<int, std::vector<std::string>>(i, IMS_CALL_DISCONNECT_REASONINFO_MAPPING_CONFIG));
        CellularCallConfig::forceVolteSwitchOn_.insert(std::pair<int, bool>(i, false));
        CellularCallConfig::readyToCall_.insert(std::pair<int, bool>(i, true));
        CellularCallConfig::vonrSwithStatus_.insert(std::pair<int, int>(i, VONR_SWITCH_STATUS_UNKNOWN));
        CellularCallConfig::serviceState_.insert(std::pair<int, RegServiceState>(i,
            RegServiceState::REG_STATE_UNKNOWN));
    }
}

CellularCallConfig::CellularCallConfig()
{
    if (!isOperatorConfigInit_) {
        InitDefaultOperatorConfig();
        isOperatorConfigInit_ = true;
    }
}

int32_t CellularCallConfig::SetDomainPreferenceMode(int32_t slotId, int32_t mode)
{
    if (mode < DomainPreferenceMode::CS_VOICE_ONLY || mode > DomainPreferenceMode::IMS_PS_VOICE_ONLY) {
        TELEPHONY_LOGE("SetDomainPreferenceMode return, mode out of range!");
        return CALL_ERR_PARAMETER_OUT_OF_RANGE;
    }
    modeTempMap_[slotId] = mode;
    return configRequest_.SetDomainPreferenceModeRequest(slotId, mode);
}

int32_t CellularCallConfig::GetDomainPreferenceMode(int32_t slotId)
{
    return configRequest_.GetDomainPreferenceModeRequest(slotId);
}

int32_t CellularCallConfig::SetImsSwitchStatus(int32_t slotId, bool active)
{
    TELEPHONY_LOGI("entry, slotId:%{public}d, active:%{public}d", slotId, active);
    if (!volteSupported_[slotId]) {
        TELEPHONY_LOGE("Enable ims switch failed due to volte is not supported.");
        return CALL_ERR_VOLTE_NOT_SUPPORT;
    }
    if (active && !IsVolteProvisioned(slotId)) {
        TELEPHONY_LOGE("Enable ims switch failed due to volte provisioning disabled.");
        return CALL_ERR_VOLTE_PROVISIONING_DISABLED;
    }
    int32_t simId = CoreManagerInner::GetInstance().GetSimId(slotId);
    if (simId <= INVALID_SIM_ID) {
        TELEPHONY_LOGE("failed due to invalid sim id %{public}d", simId);
        return TELEPHONY_ERR_SLOTID_INVALID;
    }

    active = ChangeImsSwitchWithOperatorConfig(slotId, active);
    int32_t ret = SaveImsSwitch(slotId, BooleanToImsSwitchValue(active));
    if (ret == SAVE_IMS_SWITCH_FAILED) {
        return TELEPHONY_ERR_DATABASE_WRITE_FAIL;
    } else if (ret == SAVE_IMS_SWITCH_SUCCESS_NOT_CHANGED) {
        return TELEPHONY_SUCCESS;
    }

    SimState simState = SimState::SIM_STATE_UNKNOWN;
    CoreManagerInner::GetInstance().GetSimState(slotId, simState);
    TELEPHONY_LOGI("active: %{public}d simState : %{public}d", active, simState);
    if (simState == SimState::SIM_STATE_LOADED || simState == SimState::SIM_STATE_READY) {
        UpdateImsCapabilities(slotId, !active);
    }
    return TELEPHONY_SUCCESS;
}

int32_t CellularCallConfig::GetImsSwitchStatus(int32_t slotId, bool &enabled)
{
    TELEPHONY_LOGD("entry, slotId: %{public}d", slotId);
    auto itorHide = hideImsSwitch_.find(slotId);
    if (itorHide != hideImsSwitch_.end()) {
        if (itorHide->second) {
            auto itorSwitch = imsSwitchOnByDefault_.find(slotId);
            if (itorSwitch != imsSwitchOnByDefault_.end()) {
                enabled = imsSwitchOnByDefault_[slotId];
            }
        } else {
            int32_t imsSwitchStatus = GetSwitchStatus(slotId);
            enabled = imsSwitchStatus;
        }
    } else {
        TELEPHONY_LOGI("do not find hideImsSwitch");
        int32_t imsSwitchStatus = GetSwitchStatus(slotId);
        enabled = imsSwitchStatus;
    }
    return TELEPHONY_SUCCESS;
}

int32_t CellularCallConfig::SetVoNRSwitchStatus(int32_t slotId, int32_t state)
{
    TELEPHONY_LOGI(
        "CellularCallConfig::SetVoNRSwitchStatus entry, slotId: %{public}d, state: %{public}d", slotId, state);
    if (!IsVonrSupported(slotId, IsGbaValid(slotId))) {
        TELEPHONY_LOGE("Enable VoNR switch failed due to VoNR is not supported.");
        return TELEPHONY_ERR_FAIL;
    }
    SimState simState = SimState::SIM_STATE_UNKNOWN;
    CoreManagerInner::GetInstance().GetSimState(slotId, simState);
    if (simState == SimState::SIM_STATE_LOADED || simState == SimState::SIM_STATE_READY) {
        configRequest_.SetVoNRSwitchStatusRequest(slotId, state);
        vonrSwithStatus_[slotId] = state;
        return TELEPHONY_SUCCESS;
    }
    return TELEPHONY_ERR_NO_SIM_CARD;
}

int32_t CellularCallConfig::GetVoNRSwitchStatus(int32_t slotId, int32_t &state)
{
    if (!IsVonrSupported(slotId, IsGbaValid(slotId))) {
        TELEPHONY_LOGE("Enable VoNR switch failed due to VoNR is not supported.");
        state = VONR_SWITCH_STATUS_OFF;
        return TELEPHONY_SUCCESS;
    }
    state = ObtainVoNRState(slotId);
    return TELEPHONY_SUCCESS;
}

void CellularCallConfig::HandleSimStateChanged(int32_t slotId)
{
    TELEPHONY_LOGI("CellularCallConfig::HandleSimStateChanged entry, slotId: %{public}d", slotId);
    if (CheckAndUpdateSimState(slotId)) {
        UpdateEccNumberList(slotId);
    }
}

void CellularCallConfig::HandleFactoryReset(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE(" invalid slot id %{public}d", slotId);
        return;
    }
    bool hasSimCard = false;
    DelayedRefSingleton<CoreServiceClient>::GetInstance().HasSimCard(slotId, hasSimCard);
    if (!hasSimCard) {
        TELEPHONY_LOGE("return due to no sim card");
        return;
    }
    // Set VoLTE to default
    int32_t ret = SaveImsSwitch(slotId, BooleanToImsSwitchValue(imsSwitchOnByDefault_[slotId]));
    TELEPHONY_LOGI("Save ims switch ret: %{public}d", ret);
    UpdateImsCapabilities(slotId, true);
}

void CellularCallConfig::HandleSimRecordsLoaded(int32_t slotId)
{
    TELEPHONY_LOGI("CellularCallConfig::HandleSimRecordsLoaded entry, slotId: %{public}d", slotId);
    CheckAndUpdateSimState(slotId);
    UpdateEccNumberList(slotId);
}

void CellularCallConfig::HandleResidentNetworkChange(int32_t slotId, std::string plmn)
{
    TELEPHONY_LOGI("CellularCallConfig::HandleResidentNetworkChange entry, slotId: %{public}d", slotId);
    curPlmn_[slotId] = plmn;
    CheckAndUpdateSimState(slotId);
    UpdateEccNumberList(slotId);
}

void CellularCallConfig::HandleNetworkStateChange(int32_t slotId)
{
    TELEPHONY_LOGI("CellularCallConfig::HandleNetworkStateChange entry, slotId: %{public}d", slotId);
    ModuleServiceUtils moduleUtils;
    RegServiceState regState = moduleUtils.GetPsRegState(slotId);
    if (serviceState_[slotId] == regState) {
        TELEPHONY_LOGI("serviceState is not change, slotId: %{public}d", slotId);
        return;
    }
    serviceState_[slotId] = regState;
    CheckAndUpdateSimState(slotId);
    UpdateEccNumberList(slotId);
}

void CellularCallConfig::GetEccListFromResult(const std::vector<EccNum> &eccVec,
    std::vector<std::string> &callListWithCard, std::vector<std::string> &callListNoCard)
{
    if (!eccVec.empty()) {
        std::string eccWithCard = eccVec[0].ecc_withcard;
        callListWithCard = StandardizeUtils::Split(eccWithCard, ",");
        std::string eccNoCard = eccVec[0].ecc_nocard;
        callListNoCard = StandardizeUtils::Split(eccNoCard, ",");
    }
}

void CellularCallConfig::UpdateEccNumberList(int32_t slotId)
{
    std::u16string u16Hplmn = u"";
    CoreManagerInner::GetInstance().GetSimOperatorNumeric(slotId, u16Hplmn);
    std::string hplmn = Str16ToStr8(u16Hplmn);
    std::vector<std::string> callListWithCard;
    std::vector<std::string> callListNoCard;
    int32_t roamingState = CoreManagerInner::GetInstance().GetPsRoamingState(slotId);
    bool isRoaming = roamingState > static_cast<int32_t>(RoamingType::ROAMING_STATE_UNKNOWN) &&
        roamingState <= static_cast<int32_t>(RoamingType::ROAMING_STATE_INTERNATIONAL);
    ModuleServiceUtils moduleUtils;
    bool isNetworkInService = moduleUtils.GetPsRegState(slotId) == RegServiceState::REG_STATE_IN_SERVICE;
    bool isHomeNetRegister = !hplmn.empty() && isNetworkInService && !isRoaming;
    std::vector<EccNum> eccVec;
    bool isSimPresent = false;
    {
        std::lock_guard<std::mutex> lock(simStateLock_);
        isSimPresent = simState_[slotId] == SIM_PRESENT;
    }
    if (isHomeNetRegister && isSimPresent) {
        OperatorConfig operatorConfig;
        CoreManagerInner::GetInstance().GetOperatorConfigs(slotId, operatorConfig);
        callListWithCard = operatorConfig.stringArrayValue[KEY_EMERGENCY_CALL_STRING_ARRAY];
        if (callListWithCard.empty()) {
            DelayedSingleton<CellularCallRdbHelper>::GetInstance()->QueryEccList(hplmn, eccVec);
            GetEccListFromResult(eccVec, callListWithCard, callListNoCard);
        }
    } else {
        if (curPlmn_[slotId].empty()) {
            std::u16string u16Rplmn = CoreManagerInner::GetInstance().GetOperatorNumeric(slotId);
            std::string rplmn = Str16ToStr8(u16Rplmn);
            if (rplmn.empty()) {
                TELEPHONY_LOGE("rplmn is empty");
                return;
            }
            curPlmn_[slotId] = rplmn;
        }
        DelayedSingleton<CellularCallRdbHelper>::GetInstance()->QueryEccList(curPlmn_[slotId], eccVec);
        GetEccListFromResult(eccVec, callListWithCard, callListNoCard);
    }
    std::vector<EmergencyCall> eccInfoList;
    for (auto it : callListWithCard) {
        eccInfoList.push_back(BuildDefaultEmergencyCall(it, SimpresentType::TYPE_HAS_CARD));
    }
    for (auto it : callListNoCard) {
        eccInfoList.push_back(BuildDefaultEmergencyCall(it, SimpresentType::TYPE_NO_CARD));
    }
    SetEmergencyCallList(slotId, eccInfoList);
}

void CellularCallConfig::HandleSimAccountLoaded(int32_t slotId)
{
    TELEPHONY_LOGI("entry, slotId: %{public}d", slotId);
    saveImsSwitchStatusToLocalForPowerOn(slotId);
    ResetImsSwitch(slotId);
    UpdateImsCapabilities(slotId, true);
    CheckAndUpdateSimState(slotId);
    UpdateEccNumberList(slotId);
}

void CellularCallConfig::HandleOperatorConfigChanged(int32_t slotId)
{
    OperatorConfig operatorConfig;
    int32_t ret = CoreManagerInner::GetInstance().GetOperatorConfigs(slotId, operatorConfig);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("failed due to get operator config");
        return;
    }

    int32_t result = ParseAndCacheOperatorConfigs(slotId, operatorConfig);
    if (result != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("failed due to parse operator config");
        return;
    }
    ResetImsSwitch(slotId);
    UpdateImsCapabilities(slotId, true);
}

int32_t CellularCallConfig::ParseAndCacheOperatorConfigs(int32_t slotId, OperatorConfig &poc)
{
    TELEPHONY_LOGI("CellularCallConfig::ParseAndCacheOperatorConfigs start. slotId %{public}d", slotId);
    std::lock_guard<std::mutex> lock(operatorMutex_);
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE(" invalid slot id %{public}d", slotId);
        return TELEPHONY_ERROR;
    }

    ParseBoolOperatorConfigs(slotId, imsSwitchOnByDefault_, poc, KEY_IMS_SWITCH_ON_BY_DEFAULT_BOOL);
    ParseBoolOperatorConfigs(slotId, hideImsSwitch_, poc, KEY_HIDE_IMS_SWITCH_BOOL);
    ParseBoolOperatorConfigs(slotId, volteSupported_, poc, KEY_VOLTE_SUPPORTED_BOOL);
    ParseBoolOperatorConfigs(slotId, volteProvisioningSupported_, poc, KEY_VOLTE_PROVISIONING_SUPPORTED_BOOL);
    ParseBoolOperatorConfigs(slotId, ssOverUtSupported_, poc, KEY_SS_OVER_UT_SUPPORTED_BOOL);
    ParseBoolOperatorConfigs(slotId, imsGbaRequired_, poc, KEY_IMS_GBA_REQUIRED_BOOL);
    ParseBoolOperatorConfigs(slotId, utProvisioningSupported_, poc, KEY_UT_PROVISIONING_SUPPORTED_BOOL);
    ParseBoolOperatorConfigs(slotId, imsPreferForEmergency_, poc, KEY_IMS_PREFER_FOR_EMERGENCY_BOOL);
    ParseBoolOperatorConfigs(slotId, forceVolteSwitchOn_, poc, KEY_FORCE_VOLTE_SWITCH_ON_BOOL);

    if (poc.intArrayValue.count(KEY_NR_MODE_SUPPORTED_LIST_INT_ARRAY) > 0) {
        nrModeSupportedList_[slotId] = poc.intArrayValue[KEY_NR_MODE_SUPPORTED_LIST_INT_ARRAY];
    }
    if (poc.intValue.count(KEY_CALL_WAITING_SERVICE_CLASS_INT) > 0) {
        callWaitingServiceClass_[slotId] = poc.intValue[KEY_CALL_WAITING_SERVICE_CLASS_INT];
    }
    if (poc.stringArrayValue.count(KEY_IMS_CALL_DISCONNECT_REASONINFO_MAPPING_STRING_ARRAY) > 0) {
        imsCallDisconnectResoninfoMapping_[slotId] =
            poc.stringArrayValue[KEY_IMS_CALL_DISCONNECT_REASONINFO_MAPPING_STRING_ARRAY];
    }
    return TELEPHONY_SUCCESS;
}

void CellularCallConfig::ParseBoolOperatorConfigs(
    int32_t slotId, std::map<int32_t, bool> &config, OperatorConfig &poc, std::string configName)
{
    auto it = poc.boolValue.find(configName);
    if (it != poc.boolValue.end()) {
        config[slotId] = it->second;
    } else {
        TELEPHONY_LOGE("do't find operator config %{public}s", configName.c_str());
    }
}

void CellularCallConfig::ResetImsSwitch(int32_t slotId)
{
    bool hasSimCard = false;
    CoreManagerInner::GetInstance().HasSimCard(slotId, hasSimCard);
    if (!hasSimCard) {
        TELEPHONY_LOGE("return due to no sim card");
        return;
    }
    std::u16string iccId;
    CoreManagerInner::GetInstance().GetSimIccId(slotId, iccId);
    if (IsSimChanged(slotId, Str16ToStr8(iccId)) && forceVolteSwitchOn_[slotId]) {
        int32_t ret = CoreManagerInner::GetInstance().SaveImsSwitch(
            slotId, BooleanToImsSwitchValue(imsSwitchOnByDefault_[slotId]));
        if (ret != TELEPHONY_SUCCESS) {
            TELEPHONY_LOGE("SaveImsSwitch failed");
        } else {
            saveImsSwitchStatusToLocal(slotId, BooleanToImsSwitchValue(imsSwitchOnByDefault_[slotId]));
        }
    }
}

void CellularCallConfig::UpdateImsCapabilities(int32_t slotId, bool needUpdateUtCapability)
{
    bool isGbaValid = IsGbaValid(slotId);
    ImsCapabilityList imsCapabilityList;
    TELEPHONY_LOGI("UpdateImsCapabilities entry");
    UpdateImsVoiceCapabilities(slotId, isGbaValid, imsCapabilityList);
    if (needUpdateUtCapability) {
        UpdateImsUtCapabilities(slotId, isGbaValid, imsCapabilityList);
    }
    configRequest_.UpdateImsCapabilities(slotId, imsCapabilityList);
    configRequest_.SetImsSwitchStatusRequest(slotId, IsNeedTurnOnIms(imsCapabilityList));
}
bool CellularCallConfig::IsGbaValid(int32_t slotId)
{
    if (imsGbaRequired_[slotId]) {
        std::u16string simist = CoreManagerInner::GetInstance().GetSimIst(slotId);
        std::string simistStr = Str16ToStr8(simist);
        // If carrier requires that IMS is only available if GBA capable SIM is used,
        // then this function checks GBA bit in EF IST.
        // Format of EF IST is defined in 3GPP TS 31.103 (Section 4.2.7).
        if (!simistStr.empty() && simistStr.length() > 1) {
            bool result = (IMS_GBA_BIT & simistStr.at(1)) != 0;
            return result;
        }
    }
    return true;
}

void CellularCallConfig::UpdateImsVoiceCapabilities(
    int32_t slotId, bool isGbaValid, ImsCapabilityList &imsCapabilityList)
{
    int32_t vonrSwitch = VONR_SWITCH_STATUS_OFF;
    GetVoNRSwitchStatus(slotId, vonrSwitch);
    bool vonrSwitchEnabled = vonrSwitch == VONR_SWITCH_STATUS_ON;
    ImsCapability vonrCapability;
    vonrCapability.imsCapabilityType = ImsCapabilityType::CAPABILITY_TYPE_VOICE;
    vonrCapability.imsRadioTech = ImsRegTech::IMS_REG_TECH_NR;
    vonrCapability.enable = IsVonrSupported(slotId, isGbaValid) && vonrSwitchEnabled;
    imsCapabilityList.imsCapabilities.push_back(vonrCapability);

    bool imsSwitch = false;
    GetImsSwitchStatus(slotId, imsSwitch);
    bool isVolteProvisioned = IsVolteProvisioned(slotId);
    ImsCapability volteCapability;
    volteCapability.imsCapabilityType = ImsCapabilityType::CAPABILITY_TYPE_VOICE;
    volteCapability.imsRadioTech = ImsRegTech::IMS_REG_TECH_LTE;
    volteCapability.enable = vonrCapability.enable
        || (volteSupported_[slotId] && isGbaValid && imsSwitch && isVolteProvisioned);
    imsCapabilityList.imsCapabilities.push_back(volteCapability);
    TELEPHONY_LOGI("slotId = %{public}d, vonrCapability = %{public}d, volteSupported = %{public}d, "
        "isGbaValid = %{public}d, imsSwitch = %{public}d, isVolteProvisioned = %{public}d",
        slotId, vonrCapability.enable, volteSupported_[slotId], isGbaValid, imsSwitch, isVolteProvisioned);
}

void CellularCallConfig::UpdateImsUtCapabilities(int32_t slotId, bool isGbaValid, ImsCapabilityList &imsCapabilityList)
{
    ImsCapability utCapability;
    utCapability.imsCapabilityType = ImsCapabilityType::CAPABILITY_TYPE_UT;
    utCapability.imsRadioTech = ImsRegTech::IMS_REG_TECH_LTE;
    utCapability.enable = ssOverUtSupported_[slotId] && isGbaValid && IsUtProvisioned(slotId);
    imsCapabilityList.imsCapabilities.push_back(utCapability);
}

bool CellularCallConfig::IsVolteProvisioned(int32_t slotId)
{
    if (volteProvisioningSupported_[slotId]) {
        int32_t volteFeatureValue;
        int32_t result = configRequest_.GetImsFeatureValueRequest(FeatureType::TYPE_VOICE_OVER_LTE, volteFeatureValue);
        if (result != TELEPHONY_SUCCESS) {
            TELEPHONY_LOGE("get volte feature value failed");
            return false;
        }
        return volteFeatureValue == ImsFeatureIntResult::IMS_FEATURE_INT_VALUE_ENABLED;
    }
    return true;
}

bool CellularCallConfig::IsVonrSupported(int32_t slotId, bool isGbaValid)
{
    if (std::find(nrModeSupportedList_[slotId].begin(), nrModeSupportedList_[slotId].end(),
        CARRIER_NR_AVAILABILITY_SA) == nrModeSupportedList_[slotId].end()) {
        return false;
    }
    return isGbaValid;
}

bool CellularCallConfig::IsUtProvisioned(int32_t slotId)
{
    if (utProvisioningSupported_[slotId]) {
        int32_t utFeatureValue;
        int32_t result = configRequest_.GetImsFeatureValueRequest(FeatureType::TYPE_SS_OVER_UT, utFeatureValue);
        if (result != TELEPHONY_SUCCESS) {
            TELEPHONY_LOGE("get ut feature value failed");
            return false;
        }
        return utFeatureValue == ImsFeatureIntResult::IMS_FEATURE_INT_VALUE_ENABLED;
    }
    return true;
}

EmergencyCall CellularCallConfig::BuildEmergencyCall(int32_t slotId, const EmergencyInfo &from)
{
    EmergencyCall to = {};
    to.eccNum = from.eccNum;
    to.eccType = EccType(from.category);
    to.simpresent = SimpresentType(from.simpresent);
    to.mcc = from.mcc;
    to.abnormalService = AbnormalServiceType(from.abnormalService);
    return to;
}

bool CellularCallConfig::IsNeedTurnOnIms(const ImsCapabilityList &imsCapabilityList)
{
    for (auto imsCapabilitie : imsCapabilityList.imsCapabilities) {
        if (imsCapabilitie.imsCapabilityType == ImsCapabilityType::CAPABILITY_TYPE_VOICE
            || imsCapabilitie.imsCapabilityType == ImsCapabilityType::CAPABILITY_TYPE_VIDEO) {
            if (imsCapabilitie.enable) {
                return true;
            }
        }
    }
    return false;
}

bool CellularCallConfig::IsSimChanged(int32_t slotId, std::string iccid)
{
    const int32_t sysparaSize = SYSTEM_PARAMETER_LENGTH;
    char lastIccid[sysparaSize] = { 0 };
    std::string key = LAST_ICCID_KEY + std::to_string(slotId);
    GetParameter(key.c_str(), "", lastIccid, sysparaSize);

    if (iccid.compare(lastIccid) != 0) {
        SetParameter(key.c_str(), iccid.c_str());
        return true;
    }
    return false;
}

bool CellularCallConfig::ChangeImsSwitchWithOperatorConfig(int32_t slotId, bool active)
{
    auto itorHide = hideImsSwitch_.find(slotId);
    if (itorHide != hideImsSwitch_.end()) {
        if (itorHide->second) {
            auto itorSwitch = imsSwitchOnByDefault_.find(slotId);
            if (itorSwitch != imsSwitchOnByDefault_.end()) {
                active = imsSwitchOnByDefault_[slotId];
                return active;
            }
        }
    }
    TELEPHONY_LOGE("do not find hideImsSwitch or imsSwitchOnByDefault config");
    return active;
}

int32_t CellularCallConfig::SaveImsSwitch(int32_t slotId, int32_t imsSwitchValue)
{
    int32_t lastImsSwitchValue = IMS_SWITCH_STATUS_UNKNOWN;
    int32_t queryRet = CoreManagerInner::GetInstance().QueryImsSwitch(slotId, lastImsSwitchValue);
    if (queryRet != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("query ims switch failed");
        return SAVE_IMS_SWITCH_FAILED;
    }
    if (imsSwitchValue == lastImsSwitchValue) {
        TELEPHONY_LOGI("ims switch status do not change, imsSwitchValue: %{public}d", imsSwitchValue);
        return SAVE_IMS_SWITCH_SUCCESS_NOT_CHANGED;
    }
    int32_t saveRet = CoreManagerInner::GetInstance().SaveImsSwitch(slotId, imsSwitchValue);
    if (saveRet != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("save ims switch status to database failed!");
        return SAVE_IMS_SWITCH_FAILED;
    }
    saveImsSwitchStatusToLocal(slotId, imsSwitchValue);
    return SAVE_IMS_SWITCH_SUCCESS_CHANGED;
}

void CellularCallConfig::saveImsSwitchStatusToLocalForPowerOn(int32_t slotId)
{
    int32_t imsSwitchStatus = IMS_SWITCH_STATUS_UNKNOWN;
    int32_t ret = CoreManagerInner::GetInstance().QueryImsSwitch(slotId, imsSwitchStatus);
    if (ret != TELEPHONY_SUCCESS || imsSwitchStatus == IMS_SWITCH_STATUS_UNKNOWN) {
        TELEPHONY_LOGI("get ims switch state failed from database, return operator config default value");
        imsSwitchStatus = imsSwitchOnByDefault_[slotId] ? IMS_SWITCH_STATUS_ON : IMS_SWITCH_STATUS_OFF;
    }

    TELEPHONY_LOGI(
        "save slotId[%{public}d] imsSwitchStatus:%{public}d to local for Power on", slotId, imsSwitchStatus);
    std::string imsSwitchStateKey = IMSSWITCH_STATE + std::to_string(slotId);
    std::string imsSwitchState = std::to_string(imsSwitchStatus);
    SetParameter(imsSwitchStateKey.c_str(), imsSwitchState.c_str());
}

void CellularCallConfig::saveImsSwitchStatusToLocal(int32_t slotId, int32_t imsSwitchStatus)
{
    TELEPHONY_LOGI("save slotId[%{public}d] imsSwitchStatus:%{public}d to local", slotId, imsSwitchStatus);
    std::string imsSwitchStateKey = IMSSWITCH_STATE + std::to_string(slotId);
    std::string imsSwitchState = std::to_string(imsSwitchStatus);
    SetParameter(imsSwitchStateKey.c_str(), imsSwitchState.c_str());
}

void CellularCallConfig::SaveVoNRState(int32_t slotId, int32_t state)
{
    CellularCallHiSysEvent::WriteVoNRSwitchChangeEvent(state);
    TELEPHONY_LOGI("slotId: %{public}d, switchState: %{public}d", slotId, state);
    std::string vonrState = std::to_string(state);
    std::string vonrStateKey = VONR_STATE + std::to_string(slotId);
    SetParameter(vonrStateKey.c_str(), vonrState.c_str());
}

int32_t CellularCallConfig::ObtainVoNRState(int32_t slotId)
{
    std::string vonrStateKey = VONR_STATE + std::to_string(slotId);
    int32_t vonrState = GetIntParameter(vonrStateKey.c_str(), VONR_SWITCH_STATUS_ON);
    TELEPHONY_LOGI("slotId: %{public}d, switchState: %{public}d", slotId, vonrState);
    return vonrState;
}

void CellularCallConfig::HandleSetLteImsSwitchResult(int32_t slotId, ErrType result)
{
    TELEPHONY_LOGI("CellularCallConfig::HandleSetLteImsSwitchResult entry, slotId: %{public}d", slotId);
    if (result != ErrType::NONE) {
        TELEPHONY_LOGE("HandleSetLteImsSwitchResult set ims switch to modem failed!");
        // need to reset the Ims Switch parameter and notify APP to update UI.
    }
}

void CellularCallConfig::HandleSetVoNRSwitchResult(int32_t slotId, ErrType result)
{
    TELEPHONY_LOGD("CellularCallConfig::HandleSetVoNRSwitchResult entry, slotId: %{public}d", slotId);
    if (result != ErrType::NONE) {
        TELEPHONY_LOGE("HandleSetVoNRSwitchResult set vonr switch to modem failed!");
        return;
    }
    SaveVoNRState(slotId, vonrSwithStatus_[slotId]);
    ImsCapabilityList imsCapabilityList;
    UpdateImsVoiceCapabilities(slotId, IsGbaValid(slotId), imsCapabilityList);
    configRequest_.UpdateImsCapabilities(slotId, imsCapabilityList);
}

void CellularCallConfig::GetDomainPreferenceModeResponse(int32_t slotId, int32_t mode)
{
    modeMap_[slotId] = mode;
}

void CellularCallConfig::GetImsSwitchStatusResponse(int32_t slotId, int32_t active) {}

int32_t CellularCallConfig::GetPreferenceMode(int32_t slotId) const
{
    return modeMap_[slotId];
}

int32_t CellularCallConfig::GetSwitchStatus(int32_t slotId)
{
    std::string imsSwitchStateKey = IMSSWITCH_STATE + std::to_string(slotId);
    int32_t imsSwitchStatus = GetIntParameter(imsSwitchStateKey.c_str(), IMS_SWITCH_STATUS_UNKNOWN);
    if (imsSwitchStatus == IMS_SWITCH_STATUS_UNKNOWN) {
        TELEPHONY_LOGI("get ims switch state failed from local, try to get it from database");
        int32_t ret = CoreManagerInner::GetInstance().QueryImsSwitch(slotId, imsSwitchStatus);
        if (ret != TELEPHONY_SUCCESS || imsSwitchStatus == IMS_SWITCH_STATUS_UNKNOWN) {
            TELEPHONY_LOGI("get ims switch state failed from database, return operator config default value");
            imsSwitchStatus = imsSwitchOnByDefault_[slotId] ? IMS_SWITCH_STATUS_ON : IMS_SWITCH_STATUS_OFF;
        }
        // save DB or operator config default ims switch status to local
        saveImsSwitchStatusToLocal(slotId, imsSwitchStatus);
    }
    TELEPHONY_LOGD("slotId[%{public}d] GetSwitchStatus imsSwitchStatus:%{public}d", slotId, imsSwitchStatus);
    return imsSwitchStatus;
}

int32_t CellularCallConfig::SetImsConfig(ImsConfigItem item, const std::string &value)
{
    return configRequest_.SetImsConfigRequest(item, value);
}

int32_t CellularCallConfig::SetImsConfig(ImsConfigItem item, int32_t value)
{
    return configRequest_.SetImsConfigRequest(item, value);
}

int32_t CellularCallConfig::GetImsConfig(ImsConfigItem item)
{
    return configRequest_.GetImsConfigRequest(item);
}

int32_t CellularCallConfig::SetImsFeatureValue(FeatureType type, int32_t value)
{
    return configRequest_.SetImsFeatureValueRequest(type, value);
}

int32_t CellularCallConfig::GetImsFeatureValue(FeatureType type)
{
    int32_t imsFeatureValue;
    int32_t ret = configRequest_.GetImsFeatureValueRequest(type, imsFeatureValue);
    GetImsFeatureValueResponse response;
    response.result = ret;
    response.value = imsFeatureValue;
    DelayedSingleton<CellularCallRegister>::GetInstance()->ReportGetImsFeatureResult(response);
    return ret;
}

void CellularCallConfig::SetTempMode(int32_t slotId)
{
    modeMap_[slotId] = modeTempMap_[slotId];
}

void CellularCallConfig::InitModeActive()
{
    TELEPHONY_LOGI("InitModeActive");
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
    modeMap_[slotId] = DomainPreferenceMode::IMS_PS_VOICE_PREFERRED;
    std::lock_guard<std::mutex> lock(mutex_);
    eccListRadioMap_.clear();
    eccList3gppHasSim_.clear();
    eccList3gppNoSim_.clear();
    allEccList_.clear();
    eccList3gppHasSim_.push_back(BuildDefaultEmergencyCall("112", SimpresentType::TYPE_HAS_CARD));
    eccList3gppHasSim_.push_back(BuildDefaultEmergencyCall("911", SimpresentType::TYPE_HAS_CARD));
    eccList3gppNoSim_.push_back(BuildDefaultEmergencyCall("112", SimpresentType::TYPE_NO_CARD));
    eccList3gppNoSim_.push_back(BuildDefaultEmergencyCall("911", SimpresentType::TYPE_NO_CARD));
    eccList3gppNoSim_.push_back(BuildDefaultEmergencyCall("000", SimpresentType::TYPE_NO_CARD));
    eccList3gppNoSim_.push_back(BuildDefaultEmergencyCall("08", SimpresentType::TYPE_NO_CARD));
    eccList3gppNoSim_.push_back(BuildDefaultEmergencyCall("110", SimpresentType::TYPE_NO_CARD));
    eccList3gppNoSim_.push_back(BuildDefaultEmergencyCall("118", SimpresentType::TYPE_NO_CARD));
    eccList3gppNoSim_.push_back(BuildDefaultEmergencyCall("119", SimpresentType::TYPE_NO_CARD));
    eccList3gppNoSim_.push_back(BuildDefaultEmergencyCall("999", SimpresentType::TYPE_NO_CARD));
    TELEPHONY_LOGD("InitModeActive finish");
}

EmergencyCall CellularCallConfig::BuildDefaultEmergencyCall(const std::string &number, SimpresentType simType)
{
    TELEPHONY_LOGD("BuildDefaultEmergencyCall, eccNum:%{public}s", number.c_str());
    EmergencyCall emergencyCall;
    emergencyCall.eccNum = number;
    emergencyCall.eccType = EccType::TYPE_CATEGORY;
    emergencyCall.simpresent = simType;
    emergencyCall.mcc = "";
    emergencyCall.abnormalService = AbnormalServiceType::TYPE_ALL;
    std::string::size_type pos = number.find('+');
    if (pos != std::string::npos) {
        int32_t startOps = 0;
        std::string category = number.substr(startOps, pos);
        emergencyCall.eccType = static_cast<EccType>(std::atoi(category.c_str()));
        emergencyCall.eccNum = number.substr(pos, number.size());
    }
    return emergencyCall;
}

void CellularCallConfig::MergeEccCallList(int32_t slotId)
{
    std::map<int32_t, std::vector<EmergencyCall>> tempEccList;
    std::string mcc = GetMcc(slotId);
    for (auto ecc : eccListRadioMap_[slotId]) {
        ecc.mcc = mcc;
        tempEccList[slotId].push_back(ecc);
    }
    TELEPHONY_LOGD("MergeEccCallList merge radio slotId  %{public}d size  %{public}d", slotId,
        static_cast<int32_t>(eccListRadioMap_[slotId].size()));
    SimState simState = SimState::SIM_STATE_UNKNOWN;
    CoreManagerInner::GetInstance().GetSimState(slotId, simState);
    bool hasSim = simState == SimState::SIM_STATE_READY || simState == SimState::SIM_STATE_LOADED;
    if (hasSim) {
        if (!mcc.empty()) {
            for (auto ecc : eccList3gppHasSim_) {
                ecc.mcc = mcc;
                tempEccList[slotId].push_back(ecc);
            }
        }
    } else {
        for (auto ecc : eccList3gppNoSim_) {
            ecc.mcc = mcc;
            tempEccList[slotId].push_back(ecc);
        }
    }
    std::u16string u16Hplmn = u"";
    CoreManagerInner::GetInstance().GetSimOperatorNumeric(slotId, u16Hplmn);
    std::string hplmn = Str16ToStr8(u16Hplmn);
    int32_t roamingState = CoreManagerInner::GetInstance().GetPsRoamingState(slotId);
    bool isRoaming = roamingState > static_cast<int32_t>(RoamingType::ROAMING_STATE_UNKNOWN) &&
        roamingState <= static_cast<int32_t>(RoamingType::ROAMING_STATE_INTERNATIONAL);
    if (hasSim && !isRoaming && !hplmn.empty()) {
        std::vector<EccNum> eccVec;
        DelayedSingleton<CellularCallRdbHelper>::GetInstance()->QueryEccList(hplmn, eccVec);
        if (!eccVec.empty()) {
            std::string ecc = eccVec[0].ecc_fake;
            std::vector<std::string> callList = StandardizeUtils::Split(ecc, ",");
            for (auto it : callList) {
                EmergencyCall call = BuildDefaultEmergencyCall(it, SimpresentType::TYPE_HAS_CARD);
                call.mcc = mcc;
                tempEccList[slotId].push_back(call);
            }
        }
    }
    UniqueEccCallList(slotId, tempEccList[slotId]);
}

void CellularCallConfig::UniqueEccCallList(int32_t slotId, std::vector<EmergencyCall> &eccList)
{
    allEccList_[slotId].clear();
    for (auto call : eccList) {
        if (std::find(allEccList_[slotId].begin(), allEccList_[slotId].end(), call) ==
            allEccList_[slotId].end()) {
            allEccList_[slotId].push_back(call);
        }
    }
    for (auto call : allEccList_[slotId]) {
        TELEPHONY_LOGD("UniqueEccCallList end slotId %{public}d eccNum:%{public}s, mcc:%{public}s", slotId,
            call.eccNum.c_str(), call.mcc.c_str());
    }
}

std::string CellularCallConfig::GetMcc(int32_t slotId)
{
    std::u16string operatorNumeric;
    CoreManagerInner::GetInstance().GetSimOperatorNumeric(slotId, operatorNumeric);
    std::string imsi = Str16ToStr8(operatorNumeric);
    int len = static_cast<int>(imsi.length());
    std::string mcc = imsi;
    if (len >= MCC_LEN) {
        mcc = imsi.substr(0, MCC_LEN);
    }
    TELEPHONY_LOGD("getMcc slotd %{public}d mcc %{public}s end", slotId, mcc.c_str());
    return mcc;
}

int32_t CellularCallConfig::SetMute(int32_t slotId, int32_t mute)
{
    return configRequest_.SetMuteRequest(slotId, mute);
}

int32_t CellularCallConfig::GetMute(int32_t slotId)
{
    return configRequest_.GetMuteRequest(slotId);
}

int32_t CellularCallConfig::GetEmergencyCallList(int32_t slotId)
{
    return configRequest_.GetEmergencyCallListRequest(slotId);
}

int32_t CellularCallConfig::SetEmergencyCallList(int32_t slotId, std::vector<EmergencyCall> &eccVec)
{
    TELEPHONY_LOGD("SetEmergencyCallList start %{public}d", slotId);
    return configRequest_.SetEmergencyCallListRequest(slotId, eccVec);
}

bool CellularCallConfig::CheckAndUpdateSimState(int32_t slotId)
{
    SimState simState = SimState::SIM_STATE_UNKNOWN;
    CoreManagerInner::GetInstance().GetSimState(slotId, simState);
    int32_t simStateForEcc;
    switch (simState) {
        case SimState::SIM_STATE_READY:
        case SimState::SIM_STATE_LOADED: {
            simStateForEcc = SIM_PRESENT;
            break;
        }
        default: {
            simStateForEcc = SIM_ABSENT;
            break;
        }
    }
    std::lock_guard<std::mutex> lock(simStateLock_);
    bool result = (simState_[slotId] != simStateForEcc);
    simState_[slotId] = simStateForEcc;
    return result;
}

void CellularCallConfig::UpdateEmergencyCallFromRadio(int32_t slotId, const EmergencyInfoList &eccList)
{
    TELEPHONY_LOGD("UpdateEmergencyCallFromRadio %{publid}d size %{public}d", slotId, eccList.callSize);
    std::lock_guard<std::mutex> lock(mutex_);
    eccListRadioMap_[slotId].clear();
    for (auto ecc : eccList.calls) {
        TELEPHONY_LOGD("UpdateEmergencyCallFromRadio , data: eccNum %{public}s mcc %{public}s", ecc.eccNum.c_str(),
            ecc.mcc.c_str());
        eccListRadioMap_[slotId].push_back(BuildEmergencyCall(slotId, ecc));
    }
    MergeEccCallList(slotId);
}

std::vector<EmergencyCall> CellularCallConfig::GetEccCallList(int32_t slotId)
{
    TELEPHONY_LOGD("GetEccCallList  start %{publiic}d", slotId);
    std::lock_guard<std::mutex> lock(mutex_);
    TELEPHONY_LOGD("GetEccCallList size %{publiic}zu", allEccList_[slotId].size());
    for (auto ecc : allEccList_[slotId]) {
        TELEPHONY_LOGD("GetEccCallList, data: eccNum %{public}s mcc %{public}s", ecc.eccNum.c_str(), ecc.mcc.c_str());
    }
    return allEccList_[slotId];
}

int32_t CellularCallConfig::BooleanToImsSwitchValue(bool value)
{
    return value ? IMS_SWITCH_STATUS_ON : IMS_SWITCH_STATUS_OFF;
}

bool CellularCallConfig::GetImsSwitchOnByDefaultConfig(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("invalid slot id");
        return true;
    }
    return imsSwitchOnByDefault_[slotId];
}

bool CellularCallConfig::GethideImsSwitchConfig(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("invalid slot id");
        return false;
    }
    return hideImsSwitch_[slotId];
}

bool CellularCallConfig::GetvolteSupportedConfig(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("invalid slot id");
        return false;
    }
    return volteSupported_[slotId];
}

std::vector<int32_t> CellularCallConfig::GetNrModeSupportedListConfig(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("invalid slot id");
        return std::vector<int32_t> { CARRIER_NR_AVAILABILITY_NSA, CARRIER_NR_AVAILABILITY_SA };
    }
    return nrModeSupportedList_[slotId];
}

bool CellularCallConfig::GetVolteProvisioningSupportedConfig(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("invalid slot id");
        return false;
    }
    return volteProvisioningSupported_[slotId];
}

bool CellularCallConfig::GetSsOverUtSupportedConfig(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("invalid slot id");
        return false;
    }
    return ssOverUtSupported_[slotId];
}

bool CellularCallConfig::GetImsGbaRequiredConfig(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("invalid slot id");
        return false;
    }
    return imsGbaRequired_[slotId];
}

bool CellularCallConfig::GetUtProvisioningSupportedConfig(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("invalid slot id");
        return false;
    }
    return utProvisioningSupported_[slotId];
}

bool CellularCallConfig::GetImsPreferForEmergencyConfig(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("invalid slot id");
        return true;
    }
    return imsPreferForEmergency_[slotId];
}

std::int32_t CellularCallConfig::GetCallWaitingServiceClassConfig(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("invalid slot id");
        return 1;
    }
    return callWaitingServiceClass_[slotId];
}

std::vector<std::string> CellularCallConfig::GetImsCallDisconnectResoninfoMappingConfig(int32_t slotId)
{
    std::lock_guard<std::mutex> lock(operatorMutex_);
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("invalid slot id");
        return std::vector<std::string> {};
    }
    return imsCallDisconnectResoninfoMapping_[slotId];
}

bool CellularCallConfig::GetForceVolteSwitchOnConfig(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("invalid slot id");
        return false;
    }
    return forceVolteSwitchOn_[slotId];
}

bool CellularCallConfig::IsValidSlotId(int32_t slotId)
{
    int32_t count = SIM_SLOT_COUNT;
    if ((slotId >= DEFAULT_SIM_SLOT_ID) && (slotId < count)) {
        return true;
    }

    TELEPHONY_LOGE("SlotId is InValid = %{public}d", slotId);
    return false;
}

void CellularCallConfig::SetReadyToCall(int32_t slotId, bool isReadyToCall)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("invalid slot id");
        return;
    }
    readyToCall_[slotId] = isReadyToCall;
}

bool CellularCallConfig::IsReadyToCall(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("invalid slot id");
        return false;
    }
    return readyToCall_[slotId];
}
} // namespace Telephony
} // namespace OHOS

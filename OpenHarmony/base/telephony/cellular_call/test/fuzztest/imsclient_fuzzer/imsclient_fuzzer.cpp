/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "imsclient_fuzzer.h"

#include <cstddef>
#include <cstdint>
#define private public
#include "addcellularcalltoken_fuzzer.h"
#include "cellular_call_service.h"
#include "ims_call_client.h"
#include "ims_call_proxy.h"
#include "securec.h"
#include "surface_utils.h"
#include "system_ability_definition.h"

using namespace OHOS::Telephony;
namespace OHOS {
static bool g_isInited = false;
constexpr int32_t SERVICE_STATE_RUNNING = 1;
constexpr int32_t IMS_CONFIG_ITEM_NUM = 2;
enum {
    NUM_ONE = 1,
    NUM_TWO,
    NUM_THREE,
    NUM_FOUR,
    NUM_FIVE,
    NUM_SIX,
    NUM_SEVEN,
    NUM_EIGHT,
};

bool IsServiceInited()
{
    auto service = DelayedSingleton<CellularCallService>::GetInstance();
    if (service == nullptr) {
        return g_isInited;
    }
    if (service->GetServiceRunningState() != SERVICE_STATE_RUNNING) {
        service->OnStart();
    }
    if (!g_isInited && service->GetServiceRunningState() == SERVICE_STATE_RUNNING) {
        g_isInited = true;
    }
    return g_isInited;
}

void TestImsCallClientWithCallInfo(
    const uint8_t *data, size_t size, const std::shared_ptr<ImsCallClient> &imsCallClient)
{
    ImsCallInfo callInfo;
    if (memset_s(&callInfo, sizeof(struct ImsCallInfo), 0x00, sizeof(struct ImsCallInfo)) != EOK) {
        return;
    }
    size_t length = std::min(static_cast<size_t>(sizeof(callInfo.phoneNum) - 1), size);
    std::string number(reinterpret_cast<const char *>(data), length);
    int32_t mode = static_cast<int32_t>(size % NUM_TWO);
    int32_t slotId = static_cast<int32_t>(size % NUM_TWO);
    int32_t videoState = static_cast<int32_t>(size % NUM_THREE);
    int32_t index = static_cast<int32_t>(size % NUM_THREE);
    const char *cDtmfCode = number.c_str();
    if (strcpy_s(callInfo.phoneNum, sizeof(callInfo.phoneNum), number.c_str()) != EOK) {
        return;
    }
    callInfo.slotId = slotId;
    callInfo.videoState = videoState;
    callInfo.index = index;
    std::vector<std::string> numberList;
    numberList.push_back(number);
    imsCallClient->Dial(callInfo, static_cast<CLIRMode>(mode));
    imsCallClient->HangUp(callInfo);
    imsCallClient->Answer(callInfo);
    imsCallClient->Reject(callInfo);
    imsCallClient->RejectWithReason(callInfo, ImsRejectReason::USER_DECLINE);
    imsCallClient->InviteToConference(slotId, numberList);
    imsCallClient->KickOutFromConference(slotId, index);
    imsCallClient->StartDtmf(slotId, *cDtmfCode, index);
    imsCallClient->SendDtmf(slotId, *cDtmfCode, index);
    imsCallClient->StopDtmf(slotId, index);
    imsCallClient->StartRtt(slotId, number);
    imsCallClient->StopRtt(slotId);
    imsCallClient->SetDomainPreferenceMode(slotId, mode);
    imsCallClient->GetDomainPreferenceMode(slotId);
    imsCallClient->SetImsSwitchStatus(slotId, mode);
    imsCallClient->GetImsSwitchStatus(slotId);
    imsCallClient->SetMute(slotId, mode);
    imsCallClient->GetMute(slotId);
}

void TestImsCallClientWithSlotAndType(
    const uint8_t *data, size_t size, const std::shared_ptr<ImsCallClient> &imsCallClient)
{
    int32_t slotId = static_cast<int32_t>(size % NUM_TWO);
    int32_t index = static_cast<int32_t>(size % NUM_EIGHT);
    int32_t callType = static_cast<int32_t>(size % NUM_TWO);
    std::string info(reinterpret_cast<const char *>(data), size);
    int32_t mode = static_cast<int32_t>(size % NUM_SIX);
    imsCallClient->HoldCall(slotId, callType);
    imsCallClient->UnHoldCall(slotId, callType);
    imsCallClient->SwitchCall(slotId, callType);
    imsCallClient->CombineConference(slotId);
    imsCallClient->GetImsCallsDataRequest(slotId, callType);
    imsCallClient->GetLastCallFailReason(slotId);
    imsCallClient->ControlCamera(slotId, index, info);
    imsCallClient->SetPausePicture(slotId, index, info);
    int len = static_cast<int>(info.length());
    std::string subSurfaceId = info;
    if (len >= 1) {
        subSurfaceId = info.substr(0, 1);
    }
    if (subSurfaceId.empty() || subSurfaceId[0] < '0' || subSurfaceId[0] > '9') {
        subSurfaceId = "";
        imsCallClient->SetPreviewWindow(slotId, index, subSurfaceId, nullptr);
        imsCallClient->SetDisplayWindow(slotId, index, subSurfaceId, nullptr);
    } else {
        uint64_t tmpSurfaceId = std::stoull(subSurfaceId);
        auto surface = SurfaceUtils::GetInstance()->GetSurface(tmpSurfaceId);
        imsCallClient->SetPreviewWindow(slotId, index, subSurfaceId, surface);
        imsCallClient->SetDisplayWindow(slotId, index, subSurfaceId, surface);
    }
    imsCallClient->SetDeviceDirection(slotId, index, mode);
    imsCallClient->SetCameraZoom(mode);
    ImsCapabilityList imsCapabilityList;
    ImsCapability capbility;
    capbility.enable = mode;
    capbility.imsCapabilityType = static_cast<ImsCapabilityType>(callType);
    capbility.imsRadioTech = static_cast<ImsRegTech>(callType);
    imsCapabilityList.imsCapabilities.push_back(capbility);
    imsCallClient->UpdateImsCapabilities(slotId, imsCapabilityList);
}

void TestImsCallClientWithSettingFunction(
    const uint8_t *data, size_t size, const std::shared_ptr<ImsCallClient> &imsCallClient)
{
    CallTransferInfo transferInfo;
    if (memset_s(&transferInfo, sizeof(struct CallTransferInfo), 0x00, sizeof(struct CallTransferInfo)) != EOK) {
        return;
    }
    size_t length = std::min(static_cast<size_t>(sizeof(transferInfo.transferNum) - 1), size);
    std::string number(reinterpret_cast<const char *>(data), length);
    int32_t mode = static_cast<int32_t>(size % NUM_TWO);
    int32_t slotId = static_cast<int32_t>(size % NUM_TWO);
    int32_t index = static_cast<int32_t>(size % NUM_THREE);
    int32_t item = static_cast<int32_t>(size % IMS_CONFIG_ITEM_NUM);
    int32_t value = static_cast<int32_t>(size % NUM_FOUR);
    int32_t type = static_cast<int32_t>(size % NUM_FOUR);
    imsCallClient->SetImsConfig(static_cast<ImsConfigItem>(item), number);
    imsCallClient->SetImsConfig(static_cast<ImsConfigItem>(item), value);
    imsCallClient->GetImsConfig(static_cast<ImsConfigItem>(item));
    imsCallClient->SetImsFeatureValue(static_cast<FeatureType>(type), value);
    imsCallClient->GetImsFeatureValue(static_cast<FeatureType>(type), value);
    imsCallClient->SetClip(slotId, mode, index);
    imsCallClient->GetClip(slotId, index);
    imsCallClient->SetClir(slotId, mode, index);
    imsCallClient->GetClir(slotId, index);
    imsCallClient->SetCallWaiting(slotId, mode, type, index);
    imsCallClient->GetCallWaiting(slotId, index);
    imsCallClient->SetColr(slotId, mode, index);
    imsCallClient->GetColr(slotId, index);
    imsCallClient->SetColp(slotId, mode, index);
    imsCallClient->GetColp(slotId, index);
    if (strcpy_s(transferInfo.transferNum, sizeof(transferInfo.transferNum), number.c_str()) != EOK) {
        return;
    }
    transferInfo.settingType = static_cast<CallTransferSettingType>(type);
    transferInfo.type = static_cast<CallTransferType>(type);
    imsCallClient->SetCallTransfer(slotId, transferInfo, type, index);
    imsCallClient->GetCallTransfer(slotId, type, index);
    imsCallClient->SetCallRestriction(slotId, number, mode, number, index);
    imsCallClient->GetCallRestriction(slotId, number, index);
}

void TestImsCallClientWithCallMediaModeRequest(
    const uint8_t *data, size_t size, const std::shared_ptr<ImsCallClient> &imsCallClient)
{
    ImsCallInfo callInfo;
    if (memset_s(&callInfo, sizeof(struct ImsCallInfo), 0x00, sizeof(struct ImsCallInfo)) != EOK) {
        return;
    }
    size_t length = std::min(static_cast<size_t>(sizeof(callInfo.phoneNum) - 1), size);
    std::string number(reinterpret_cast<const char *>(data), length);
    callInfo.slotId = static_cast<int32_t>(size % NUM_TWO);
    callInfo.videoState = static_cast<int32_t>(size % NUM_TWO);
    callInfo.index = static_cast<int32_t>(size % NUM_EIGHT);
    if (strcpy_s(callInfo.phoneNum, sizeof(callInfo.phoneNum), number.c_str()) != EOK) {
        return;
    }
    ImsCallType callMode = static_cast<ImsCallType>(static_cast<int32_t>(size % NUM_SIX));
    imsCallClient->SendUpdateCallMediaModeRequest(callInfo, callMode);
}

void TestImsCallClientWithCallMediaModeResponse(
    const uint8_t *data, size_t size, const std::shared_ptr<ImsCallClient> &imsCallClient)
{
    ImsCallInfo callInfo;
    if (memset_s(&callInfo, sizeof(struct ImsCallInfo), 0x00, sizeof(struct ImsCallInfo)) != EOK) {
        return;
    }
    size_t length = std::min(static_cast<size_t>(sizeof(callInfo.phoneNum) - 1), size);
    std::string number(reinterpret_cast<const char *>(data), length);
    callInfo.slotId = static_cast<int32_t>(size % NUM_TWO);
    callInfo.videoState = static_cast<int32_t>(size % NUM_TWO);
    callInfo.index = static_cast<int32_t>(size % NUM_EIGHT);
    if (strcpy_s(callInfo.phoneNum, sizeof(callInfo.phoneNum), number.c_str()) != EOK) {
        return;
    }
    ImsCallType callMode = static_cast<ImsCallType>(static_cast<int32_t>(size % NUM_SIX));
    imsCallClient->SendUpdateCallMediaModeResponse(callInfo, callMode);
}

void TestImsCallClientWithCancelCallUpgrade(
    const uint8_t *data, size_t size, const std::shared_ptr<ImsCallClient> &imsCallClient)
{
    int32_t slotId = static_cast<int32_t>(size % NUM_TWO);
    int32_t index = static_cast<int32_t>(size % NUM_EIGHT);
    imsCallClient->CancelCallUpgrade(slotId, index);
}

void TestImsCallClientWithRequestCameraCapabilities(
    const uint8_t *data, size_t size, const std::shared_ptr<ImsCallClient> &imsCallClient)
{
    int32_t slotId = static_cast<int32_t>(size % NUM_TWO);
    int32_t index = static_cast<int32_t>(size % NUM_EIGHT);
    imsCallClient->RequestCameraCapabilities(slotId, index);
}

void TestImsCallProxyWithCallInfo(const uint8_t *data, size_t size, const sptr<ImsCallInterface> &proxy)
{
    ImsCallInfo callInfo;
    if (memset_s(&callInfo, sizeof(struct ImsCallInfo), 0x00, sizeof(struct ImsCallInfo)) != EOK) {
        return;
    }
    size_t length = std::min(static_cast<size_t>(sizeof(callInfo.phoneNum) - 1), size);
    std::string number(reinterpret_cast<const char *>(data), length);
    int32_t mode = static_cast<int32_t>(size % NUM_TWO);
    int32_t slotId = static_cast<int32_t>(size % NUM_TWO);
    int32_t videoState = static_cast<int32_t>(size % NUM_THREE);
    int32_t index = static_cast<int32_t>(size % NUM_THREE);
    const char *cDtmfCode = number.c_str();
    if (strcpy_s(callInfo.phoneNum, sizeof(callInfo.phoneNum), number.c_str()) != EOK) {
        return;
    }
    callInfo.slotId = slotId;
    callInfo.videoState = videoState;
    callInfo.index = index;
    std::vector<std::string> numberList;
    numberList.push_back(number);
    proxy->Dial(callInfo, static_cast<CLIRMode>(mode));
    proxy->HangUp(callInfo);
    proxy->Answer(callInfo);
    proxy->RejectWithReason(callInfo, ImsRejectReason::USER_DECLINE);
    proxy->InviteToConference(slotId, numberList);
    proxy->KickOutFromConference(slotId, index);
    proxy->StartDtmf(slotId, *cDtmfCode, index);
    proxy->SendDtmf(slotId, *cDtmfCode, index);
    proxy->StopDtmf(slotId, index);
    proxy->StartRtt(slotId, number);
    proxy->StopRtt(slotId);
    proxy->SetDomainPreferenceMode(slotId, mode);
    proxy->GetDomainPreferenceMode(slotId);
    proxy->SetImsSwitchStatus(slotId, mode);
    proxy->GetImsSwitchStatus(slotId);
    proxy->SetMute(slotId, mode);
    proxy->GetMute(slotId);
}

void TestImsCallProxyWithSlotAndType(const uint8_t *data, size_t size, const sptr<ImsCallInterface> &proxy)
{
    int32_t slotId = static_cast<int32_t>(size % NUM_TWO);
    int32_t index = static_cast<int32_t>(size % NUM_EIGHT);
    int32_t callType = static_cast<int32_t>(size % NUM_TWO);
    std::string info(reinterpret_cast<const char *>(data), size);
    int32_t mode = static_cast<int32_t>(size % NUM_SIX);
    proxy->HoldCall(slotId, callType);
    proxy->UnHoldCall(slotId, callType);
    proxy->SwitchCall(slotId, callType);
    proxy->CombineConference(slotId);
    proxy->GetImsCallsDataRequest(slotId, callType);
    proxy->GetLastCallFailReason(slotId);
    proxy->ControlCamera(slotId, index, info);
    proxy->SetPausePicture(slotId, index, info);
    int len = static_cast<int>(info.length());
    std::string subSurfaceId = info;
    if (len >= 1) {
        subSurfaceId = info.substr(0, 1);
    }
    if (subSurfaceId.empty() || subSurfaceId[0] < '0' || subSurfaceId[0] > '9') {
        subSurfaceId = "";
        proxy->SetPreviewWindow(slotId, index, subSurfaceId, nullptr);
        proxy->SetDisplayWindow(slotId, index, subSurfaceId, nullptr);
    } else {
        uint64_t tmpSurfaceId = std::stoull(subSurfaceId);
        auto surface = SurfaceUtils::GetInstance()->GetSurface(tmpSurfaceId);
        proxy->SetPreviewWindow(slotId, index, subSurfaceId, surface);
        proxy->SetDisplayWindow(slotId, index, subSurfaceId, surface);
    }
    proxy->SetDeviceDirection(slotId, index, mode);
    proxy->SetCameraZoom(mode);
    ImsCapabilityList imsCapabilityList;
    ImsCapability capbility;
    capbility.enable = mode;
    capbility.imsCapabilityType = static_cast<ImsCapabilityType>(callType);
    capbility.imsRadioTech = static_cast<ImsRegTech>(callType);
    imsCapabilityList.imsCapabilities.push_back(capbility);
    proxy->UpdateImsCapabilities(slotId, imsCapabilityList);
}

void TestImsCallProxyWithSettingFunction(const uint8_t *data, size_t size, const sptr<ImsCallInterface> &proxy)
{
    CallTransferInfo transferInfo;
    if (memset_s(&transferInfo, sizeof(struct CallTransferInfo), 0x00, sizeof(struct CallTransferInfo)) != EOK) {
        return;
    }
    size_t length = std::min(static_cast<size_t>(sizeof(transferInfo.transferNum) - 1), size);
    std::string number(reinterpret_cast<const char *>(data), length);
    int32_t mode = static_cast<int32_t>(size % NUM_TWO);
    int32_t slotId = static_cast<int32_t>(size % NUM_TWO);
    int32_t index = static_cast<int32_t>(size % NUM_THREE);
    int32_t item = static_cast<int32_t>(size % IMS_CONFIG_ITEM_NUM);
    int32_t value = static_cast<int32_t>(size % NUM_FOUR);
    int32_t type = static_cast<int32_t>(size % NUM_FOUR);
    proxy->SetImsConfig(static_cast<ImsConfigItem>(item), number);
    proxy->SetImsConfig(static_cast<ImsConfigItem>(item), value);
    proxy->GetImsConfig(static_cast<ImsConfigItem>(item));
    proxy->SetImsFeatureValue(static_cast<FeatureType>(type), value);
    proxy->GetImsFeatureValue(static_cast<FeatureType>(type), value);
    proxy->SetClip(slotId, mode, index);
    proxy->GetClip(slotId, index);
    proxy->SetClir(slotId, mode, index);
    proxy->GetClir(slotId, index);
    proxy->SetCallWaiting(slotId, mode, type, index);
    proxy->GetCallWaiting(slotId, index);
    proxy->SetColr(slotId, mode, index);
    proxy->GetColr(slotId, index);
    proxy->SetColp(slotId, mode, index);
    proxy->GetColp(slotId, index);
    if (strcpy_s(transferInfo.transferNum, sizeof(transferInfo.transferNum), number.c_str()) != EOK) {
        return;
    }
    transferInfo.settingType = static_cast<CallTransferSettingType>(type);
    transferInfo.type = static_cast<CallTransferType>(type);
    proxy->SetCallTransfer(slotId, transferInfo, type, index);
    proxy->GetCallTransfer(slotId, type, index);
    proxy->SetCallRestriction(slotId, number, mode, number, index);
    proxy->GetCallRestriction(slotId, number, index);
}

void TestImsCallProxyWithCallMediaModeRequest(const uint8_t *data, size_t size, const sptr<ImsCallInterface> &proxy)
{
    ImsCallInfo callInfo;
    if (memset_s(&callInfo, sizeof(struct ImsCallInfo), 0x00, sizeof(struct ImsCallInfo)) != EOK) {
        return;
    }
    size_t length = std::min(static_cast<size_t>(sizeof(callInfo.phoneNum) - 1), size);
    std::string number(reinterpret_cast<const char *>(data), length);
    callInfo.slotId = static_cast<int32_t>(size % NUM_TWO);
    callInfo.videoState = static_cast<int32_t>(size % NUM_TWO);
    callInfo.index = static_cast<int32_t>(size % NUM_EIGHT);
    if (strcpy_s(callInfo.phoneNum, sizeof(callInfo.phoneNum), number.c_str()) != EOK) {
        return;
    }
    ImsCallType callType = static_cast<ImsCallType>(static_cast<int32_t>(size % NUM_SIX));
    proxy->SendUpdateCallMediaModeRequest(callInfo, callType);
}

void TestImsCallProxyWithCallMediaModeResponse(const uint8_t *data, size_t size, const sptr<ImsCallInterface> &proxy)
{
    ImsCallInfo callInfo;
    if (memset_s(&callInfo, sizeof(struct ImsCallInfo), 0x00, sizeof(struct ImsCallInfo)) != EOK) {
        return;
    }
    size_t length = std::min(static_cast<size_t>(sizeof(callInfo.phoneNum) - 1), size);
    std::string number(reinterpret_cast<const char *>(data), length);
    callInfo.slotId = static_cast<int32_t>(size % NUM_TWO);
    callInfo.videoState = static_cast<int32_t>(size % NUM_TWO);
    callInfo.index = static_cast<int32_t>(size % NUM_EIGHT);
    if (strcpy_s(callInfo.phoneNum, sizeof(callInfo.phoneNum), number.c_str()) != EOK) {
        return;
    }
    ImsCallType callType = static_cast<ImsCallType>(static_cast<int32_t>(size % NUM_SIX));
    proxy->SendUpdateCallMediaModeResponse(callInfo, callType);
}

void TestImsCallProxyWithCancelCallUpgrade(const uint8_t *data, size_t size, const sptr<ImsCallInterface> &proxy)
{
    int32_t slotId = static_cast<int32_t>(size % NUM_TWO);
    int32_t index = static_cast<int32_t>(size % NUM_EIGHT);
    proxy->CancelCallUpgrade(slotId, index);
}

void TestImsCallProxyWithRequestCameraCapabilities(
    const uint8_t *data, size_t size, const sptr<ImsCallInterface> &proxy)
{
    int32_t slotId = static_cast<int32_t>(size % NUM_TWO);
    int32_t index = static_cast<int32_t>(size % NUM_EIGHT);
    proxy->RequestCameraCapabilities(slotId, index);
}

void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    auto imsCallClient = DelayedSingleton<ImsCallClient>::GetInstance();
    if (imsCallClient == nullptr) {
        return;
    }
    if (!IsServiceInited()) {
        return;
    }
    TestImsCallClientWithCallInfo(data, size, imsCallClient);
    TestImsCallClientWithSlotAndType(data, size, imsCallClient);
    TestImsCallClientWithSettingFunction(data, size, imsCallClient);
    TestImsCallClientWithCallMediaModeRequest(data, size, imsCallClient);
    TestImsCallClientWithCallMediaModeResponse(data, size, imsCallClient);
    TestImsCallClientWithCancelCallUpgrade(data, size, imsCallClient);
    TestImsCallClientWithRequestCameraCapabilities(data, size, imsCallClient);

    auto managerPtr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (managerPtr == nullptr) {
        return;
    }
    auto remoteObjectPtr = managerPtr->CheckSystemAbility(TELEPHONY_IMS_SYS_ABILITY_ID);
    if (remoteObjectPtr == nullptr) {
        return;
    }
    sptr<ImsCallInterface> proxy = iface_cast<ImsCallInterface>(remoteObjectPtr);
    if (proxy == nullptr) {
        return;
    }
    TestImsCallProxyWithCallInfo(data, size, proxy);
    TestImsCallProxyWithSlotAndType(data, size, proxy);
    TestImsCallProxyWithSettingFunction(data, size, proxy);
    TestImsCallProxyWithCallMediaModeRequest(data, size, proxy);
    TestImsCallProxyWithCallMediaModeResponse(data, size, proxy);
    TestImsCallProxyWithCancelCallUpgrade(data, size, proxy);
    TestImsCallProxyWithRequestCameraCapabilities(data, size, proxy);
    proxy.clear();
    proxy = nullptr;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::AddCellularCallTokenFuzzer token;
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}

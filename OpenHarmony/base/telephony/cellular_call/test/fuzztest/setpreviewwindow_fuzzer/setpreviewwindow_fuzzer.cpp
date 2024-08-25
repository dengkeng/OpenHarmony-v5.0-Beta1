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

#include "setpreviewwindow_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string_ex.h>
#define private public

#include "addcellularcalltoken_fuzzer.h"
#include "cellular_call_service.h"
#include "securec.h"
#include "surface_utils.h"
#include "system_ability_definition.h"

using namespace OHOS::Telephony;
namespace OHOS {
static bool g_isInited = false;
constexpr int32_t BOOL_NUM = 2;
constexpr int32_t VEDIO_STATE_NUM = 2;
constexpr int32_t OFFSET_SIZE = 11;
constexpr size_t MAX_NUMBER_LEN = 99;

bool IsServiceInited()
{
    if (!g_isInited) {
        DelayedSingleton<CellularCallService>::GetInstance()->OnStart();
    }
    if (!g_isInited && (static_cast<int32_t>(DelayedSingleton<CellularCallService>::GetInstance()->state_) ==
                           static_cast<int32_t>(ServiceRunningState::STATE_RUNNING))) {
        g_isInited = true;
    }
    return g_isInited;
}

void OnRemoteRequest(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    if (!dataMessageParcel.WriteInterfaceToken(CellularCallStub::GetDescriptor())) {
        return;
    }
    int32_t maxSize = static_cast<int32_t>(size) + OFFSET_SIZE;
    dataMessageParcel.WriteInt32(maxSize);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    uint32_t code = static_cast<uint32_t>(size);
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<CellularCallService>::GetInstance()->OnRemoteRequest(code, dataMessageParcel, reply, option);
}

void SetPreviewWindow(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t maxSize = static_cast<int32_t>(size);
    int32_t slotId = static_cast<int32_t>(size % BOOL_NUM);
    int32_t index = static_cast<int32_t>(size);
    std::string surfaceId(reinterpret_cast<const char *>(data), size);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(maxSize);
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteInt32(index);
    int len = static_cast<int>(surfaceId.length());
    std::string subSurfaceId = surfaceId;
    if (len >= 1) {
        subSurfaceId = surfaceId.substr(0, 1);
    }
    if (subSurfaceId.empty() || subSurfaceId[0] < '0' || subSurfaceId[0] > '9') {
        subSurfaceId = "";
        dataMessageParcel.WriteString(subSurfaceId);
    } else {
        dataMessageParcel.WriteString(subSurfaceId);
        uint64_t tmpSurfaceId = std::stoull(subSurfaceId);
        auto surface = SurfaceUtils::GetInstance()->GetSurface(tmpSurfaceId);
        if (surface != nullptr) {
            sptr<IBufferProducer> producer = surface->GetProducer();
            if (producer != nullptr) {
                dataMessageParcel.WriteRemoteObject(producer->AsObject());
            }
        }
    }
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CellularCallService>::GetInstance()->OnSetPreviewWindowInner(dataMessageParcel, reply);
}

void SetDisplayWindow(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t maxSize = static_cast<int32_t>(size);
    int32_t slotId = static_cast<int32_t>(size % BOOL_NUM);
    int32_t index = static_cast<int32_t>(size);
    std::string surfaceId(reinterpret_cast<const char *>(data), size);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(maxSize);
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteInt32(index);
    int len = static_cast<int>(surfaceId.length());
    std::string subSurfaceId = surfaceId;
    if (len >= 1) {
        subSurfaceId = surfaceId.substr(0, 1);
    }
    if (subSurfaceId.empty() || subSurfaceId[0] < '0' || subSurfaceId[0] > '9') {
        subSurfaceId = "";
        dataMessageParcel.WriteString(subSurfaceId);
    } else {
        dataMessageParcel.WriteString(subSurfaceId);
        uint64_t tmpSurfaceId = std::stoull(subSurfaceId);
        auto surface = SurfaceUtils::GetInstance()->GetSurface(tmpSurfaceId);
        if (surface != nullptr) {
            sptr<IBufferProducer> producer = surface->GetProducer();
            if (producer != nullptr) {
                dataMessageParcel.WriteRemoteObject(producer->AsObject());
            }
        }
    }
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CellularCallService>::GetInstance()->OnSetDisplayWindowInner(dataMessageParcel, reply);
}

void SetCameraZoom(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t maxSize = static_cast<int32_t>(size);
    float zoomRatio = static_cast<float>(size);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(maxSize);
    dataMessageParcel.WriteFloat(zoomRatio);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CellularCallService>::GetInstance()->OnSetCameraZoomInner(dataMessageParcel, reply);
}

void ControlCamera(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t maxSize = static_cast<int32_t>(size);
    int32_t slotId = static_cast<int32_t>(size % BOOL_NUM);
    int32_t index = static_cast<int32_t>(size);
    std::string cameraId(reinterpret_cast<const char *>(data), size);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(maxSize);
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteInt32(index);
    dataMessageParcel.WriteString(cameraId);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CellularCallService>::GetInstance()->OnControlCameraInner(dataMessageParcel, reply);
}

void SetPausePicture(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t maxSize = static_cast<int32_t>(size);
    int32_t slotId = static_cast<int32_t>(size % BOOL_NUM);
    int32_t index = static_cast<int32_t>(size);
    std::string path(reinterpret_cast<const char *>(data), size);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(maxSize);
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteInt32(index);
    dataMessageParcel.WriteString(path);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CellularCallService>::GetInstance()->OnSetPausePictureInner(dataMessageParcel, reply);
}

void SetDeviceDirection(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t maxSize = static_cast<int32_t>(size);
    int32_t slotId = static_cast<int32_t>(size % BOOL_NUM);
    int32_t index = static_cast<int32_t>(size);
    int32_t rotation = static_cast<int32_t>(size);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(maxSize);
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteInt32(index);
    dataMessageParcel.WriteInt32(rotation);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CellularCallService>::GetInstance()->OnSetDeviceDirectionInner(dataMessageParcel, reply);
}

void SendUpdateCallMediaModeRequest(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t maxSize = static_cast<int32_t>(size);
    CellularCallInfo callInfo;
    callInfo.callId = static_cast<int32_t>(size);
    callInfo.slotId = static_cast<int32_t>(size % BOOL_NUM);
    callInfo.accountId = static_cast<int32_t>(size % BOOL_NUM);
    callInfo.callType = static_cast<CallType>(static_cast<int32_t>(size));
    callInfo.videoState = static_cast<int32_t>(size % VEDIO_STATE_NUM);
    callInfo.index = static_cast<int32_t>(size);
    std::string telNum = "000000000";
    std::string tempNum(reinterpret_cast<const char *>(data), size);
    if (strlen(tempNum.c_str()) <= MAX_NUMBER_LEN) {
        telNum = tempNum;
    }
    size_t length = strlen(telNum.c_str()) + 1;
    if (strcpy_s(callInfo.phoneNum, length, telNum.c_str()) != EOK) {
        return;
    }
    int32_t mode = static_cast<int32_t>(size);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(maxSize);
    dataMessageParcel.WriteRawData(static_cast<const void *>(&callInfo), sizeof(CellularCallInfo));
    dataMessageParcel.WriteInt32(mode);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CellularCallService>::GetInstance()->OnSendUpdateCallMediaModeRequestInner(
        dataMessageParcel, reply);
}

void SendUpdateCallMediaModeResponse(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t maxSize = static_cast<int32_t>(size);
    CellularCallInfo callInfo;
    callInfo.callId = static_cast<int32_t>(size);
    callInfo.slotId = static_cast<int32_t>(size % BOOL_NUM);
    callInfo.accountId = static_cast<int32_t>(size % BOOL_NUM);
    callInfo.callType = static_cast<CallType>(static_cast<int32_t>(size));
    callInfo.videoState = static_cast<int32_t>(size % VEDIO_STATE_NUM);
    callInfo.index = static_cast<int32_t>(size);
    std::string telNum = "000000000";
    std::string tempNum(reinterpret_cast<const char *>(data), size);
    if (strlen(tempNum.c_str()) <= MAX_NUMBER_LEN) {
        telNum = tempNum;
    }
    size_t length = strlen(telNum.c_str()) + 1;
    if (strcpy_s(callInfo.phoneNum, length, telNum.c_str()) != EOK) {
        return;
    }
    int32_t mode = static_cast<int32_t>(size);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(maxSize);
    dataMessageParcel.WriteRawData(static_cast<const void *>(&callInfo), sizeof(CellularCallInfo));
    dataMessageParcel.WriteInt32(mode);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CellularCallService>::GetInstance()->OnSendUpdateCallMediaModeResponseInner(
        dataMessageParcel, reply);
}

void SetMute(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t mute = static_cast<int32_t>(size);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(mute);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CellularCallService>::GetInstance()->OnSetMuteInner(dataMessageParcel, reply);
}

void GetMute(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CellularCallService>::GetInstance()->OnGetMuteInner(dataMessageParcel, reply);
}

void StartDtmf(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t maxSize = static_cast<int32_t>(size);
    int32_t slotId = static_cast<int32_t>(size % BOOL_NUM);
    int32_t callId = static_cast<int32_t>(size);
    int32_t accountId = static_cast<int32_t>(size);
    int32_t videoState = static_cast<int32_t>(size % VEDIO_STATE_NUM);
    int32_t index = static_cast<int32_t>(size);
    char cDtmfCode = static_cast<char>(size);
    std::string telNum = "000000000";
    std::string tempNum(reinterpret_cast<const char *>(data), size);
    if (strlen(tempNum.c_str()) <= MAX_NUMBER_LEN) {
        telNum = tempNum;
    }
    size_t length = strlen(telNum.c_str()) + 1;
    CellularCallInfo callInfo;
    callInfo.slotId = slotId;
    callInfo.callId = callId;
    callInfo.accountId = accountId;
    callInfo.videoState = videoState;
    callInfo.index = index;
    if (strcpy_s(callInfo.phoneNum, length, telNum.c_str()) != EOK) {
        return;
    }
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(maxSize);
    dataMessageParcel.WriteInt8(cDtmfCode);
    dataMessageParcel.WriteRawData(static_cast<const void *>(&callInfo), sizeof(CellularCallInfo));
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CellularCallService>::GetInstance()->OnStartDtmfInner(dataMessageParcel, reply);
}

void CancelCallUpgrade(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t maxSize = static_cast<int32_t>(size);
    int32_t slotId = static_cast<int32_t>(size % BOOL_NUM);
    int32_t index = static_cast<int32_t>(size);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(maxSize);
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteInt32(index);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CellularCallService>::GetInstance()->OnCancelCallUpgradeInner(dataMessageParcel, reply);
}

void RequestCameraCapabilities(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t maxSize = static_cast<int32_t>(size);
    int32_t slotId = static_cast<int32_t>(size % BOOL_NUM);
    int32_t index = static_cast<int32_t>(size);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(maxSize);
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteInt32(index);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CellularCallService>::GetInstance()->OnRequestCameraCapabilitiesInner(dataMessageParcel, reply);
}

void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    OnRemoteRequest(data, size);
    SetPreviewWindow(data, size);
    SetDisplayWindow(data, size);
    SetCameraZoom(data, size);
    ControlCamera(data, size);
    SetPausePicture(data, size);
    SetDeviceDirection(data, size);
    SetMute(data, size);
    GetMute(data, size);
    StartDtmf(data, size);
    SendUpdateCallMediaModeRequest(data, size);
    SendUpdateCallMediaModeResponse(data, size);
    CancelCallUpgrade(data, size);
    RequestCameraCapabilities(data, size);
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

/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "session/container/include/zidl/session_stage_stub.h"
#include "session/container/include/zidl/session_stage_ipc_interface_code.h"

#include <ipc_types.h>
#include <transaction/rs_transaction.h>

#include "window_manager_hilog.h"

namespace OHOS::Rosen {
namespace {
constexpr HiviewDFX::HiLogLabel LABEL = {LOG_CORE, HILOG_DOMAIN_WINDOW, "SessionStageStub"};
}

const std::map<uint32_t, SessionStageStubFunc> SessionStageStub::stubFuncMap_{
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_SET_ACTIVE),
        &SessionStageStub::HandleSetActive),
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_NOTIFY_SIZE_CHANGE),
        &SessionStageStub::HandleUpdateRect),
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_NOTIFY_DENSITY_CHANGE),
        &SessionStageStub::HandleUpdateDensity),
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_HANDLE_BACK_EVENT),
        &SessionStageStub::HandleBackEventInner),
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_NOTIFY_DESTROY),
        &SessionStageStub::HandleNotifyDestroy),
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_NOTIFY_FOCUS_CHANGE),
        &SessionStageStub::HandleUpdateFocus),
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_NOTIFY_TRANSFER_COMPONENT_DATA),
        &SessionStageStub::HandleNotifyTransferComponentData),
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_NOTIFY_TRANSFER_COMPONENT_DATA_SYNC),
        &SessionStageStub::HandleNotifyTransferComponentDataSync),
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_NOTIFY_OCCUPIED_AREA_CHANGE_INFO),
        &SessionStageStub::HandleNotifyOccupiedAreaChange),
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_UPDATE_AVOID_AREA),
        &SessionStageStub::HandleUpdateAvoidArea),
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_NOTIFY_SCREEN_SHOT),
        &SessionStageStub::HandleNotifyScreenshot),
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_DUMP_SESSSION_ELEMENT_INFO),
        &SessionStageStub::HandleDumpSessionElementInfo),
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_NOTIFY_TOUCH_OUTSIDE),
        &SessionStageStub::HandleNotifyTouchOutside),
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_NOTIFY_WINDOW_MODE_CHANGE),
        &SessionStageStub::HandleUpdateWindowMode),
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_NOTIFY_FOREGROUND_INTERACTIVE_STATUS),
        &SessionStageStub::HandleNotifyForegroundInteractiveStatus),
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_NOTIFY_MAXIMIZE_MODE_CHANGE),
        &SessionStageStub::HandleUpdateMaximizeMode),
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_NOTIFY_CLOSE_EXIST_PIP_WINDOW),
        &SessionStageStub::HandleNotifyCloseExistPipWindow),
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_NOTIFY_SESSION_FOREGROUND),
        &SessionStageStub::HandleNotifySessionForeground),
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_NOTIFY_SESSION_BACKGROUND),
        &SessionStageStub::HandleNotifySessionBackground),
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_NOTIFY_TITLE_POSITION_CHANGE),
        &SessionStageStub::HandleUpdateTitleInTargetPos),
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_NOTIFY_DENSITY_FOLLOW_HOST),
        &SessionStageStub::HandleNotifyDensityFollowHost),
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_NOTIFY_WINDOW_VISIBILITY_CHANGE),
        &SessionStageStub::HandleNotifyWindowVisibilityChange),
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_NOTIFY_TRANSFORM_CHANGE),
        &SessionStageStub::HandleNotifyTransformChange),
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_NOTIFY_DIALOG_STATE_CHANGE),
        &SessionStageStub::HandleNotifyDialogStateChange),
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_SET_PIP_ACTION_EVENT),
        &SessionStageStub::HandleSetPipActionEvent),
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_NOTIFY_DISPLAYID_CHANGE),
        &SessionStageStub::HandleUpdateDisplayId),
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_NOTIFY_DISPLAY_MOVE),
        &SessionStageStub::HandleNotifyDisplayMove),
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_NOTIFY_SWITCH_FREEMULTIWINDOW),
        &SessionStageStub::HandleSwitchFreeMultiWindow),
    std::make_pair(static_cast<uint32_t>(SessionStageInterfaceCode::TRANS_ID_NOTIFY_KEYBOARD_INFO_CHANGE),
        &SessionStageStub::HandleNotifyKeyboardPanelInfoChange),
};

int SessionStageStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WLOGFD("Scene session stage on remote request!, code: %{public}u", code);
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        WLOGFE("Failed to check interface token!");
        return ERR_INVALID_STATE;
    }

    const auto func = stubFuncMap_.find(code);
    if (func == stubFuncMap_.end()) {
        WLOGFE("Failed to find function handler!");
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }

    return (this->*(func->second))(data, reply);
}

int SessionStageStub::HandleSetActive(MessageParcel& data, MessageParcel& reply)
{
    WLOGFD("SetActive!");
    bool active = data.ReadBool();
    WSError errCode = SetActive(active);
    reply.WriteUint32(static_cast<uint32_t>(errCode));
    return ERR_NONE;
}

int SessionStageStub::HandleUpdateRect(MessageParcel& data, MessageParcel& reply)
{
    WLOGFD("UpdateRect!");
    WSRect rect = { data.ReadInt32(), data.ReadInt32(), data.ReadUint32(), data.ReadUint32() };
    SizeChangeReason reason = static_cast<SizeChangeReason>(data.ReadUint32());
    bool hasRSTransaction = data.ReadBool();
    if (hasRSTransaction) {
        std::shared_ptr<RSTransaction> transaction(data.ReadParcelable<RSTransaction>());
        if (!transaction) {
            WLOGFE("transaction unMarsh failed");
            return -1;
        }
        WSError errCode = UpdateRect(rect, reason, transaction);
        reply.WriteUint32(static_cast<uint32_t>(errCode));
    } else {
        WSError errCode = UpdateRect(rect, reason);
        reply.WriteUint32(static_cast<uint32_t>(errCode));
    }
    return ERR_NONE;
}

int SessionStageStub::HandleUpdateDensity(MessageParcel& data, MessageParcel& reply)
{
    WLOGFD("UpdateDensity!");
    UpdateDensity();
    return ERR_NONE;
}

int SessionStageStub::HandleBackEventInner(MessageParcel& data, MessageParcel& reply)
{
    WLOGFD("HandleBackEventInner!");
    WSError errCode = HandleBackEvent();
    reply.WriteUint32(static_cast<uint32_t>(errCode));
    return ERR_NONE;
}

int SessionStageStub::HandleNotifyDestroy(MessageParcel& data, MessageParcel& reply)
{
    WLOGFD("Notify Destroy");
    WSError errCode = NotifyDestroy();
    reply.WriteUint32(static_cast<uint32_t>(errCode));
    return ERR_NONE;
}

int SessionStageStub::HandleNotifyCloseExistPipWindow(MessageParcel& data, MessageParcel& reply)
{
    TLOGD(WmsLogTag::WMS_PIP, "Notify Pip AlreadyExists");
    WSError errCode = NotifyCloseExistPipWindow();
    reply.WriteUint32(static_cast<uint32_t>(errCode));
    return ERR_NONE;
}

int SessionStageStub::HandleUpdateFocus(MessageParcel& data, MessageParcel& reply)
{
    WLOGFD("UpdateFocus!");
    bool isFocused = data.ReadBool();
    WSError errCode = UpdateFocus(isFocused);
    reply.WriteUint32(static_cast<uint32_t>(errCode));
    return ERR_NONE;
}

int SessionStageStub::HandleNotifyTransferComponentData(MessageParcel& data, MessageParcel& reply)
{
    WLOGFD("HandleNotifyTransferComponentData!");
    std::shared_ptr<AAFwk::WantParams> wantParams(data.ReadParcelable<AAFwk::WantParams>());
    if (wantParams == nullptr) {
        WLOGFE("wantParams is nullptr");
        return ERR_INVALID_VALUE;
    }
    WSError errCode = NotifyTransferComponentData(*wantParams);
    reply.WriteUint32(static_cast<uint32_t>(errCode));
    return ERR_NONE;
}

int SessionStageStub::HandleNotifyTransferComponentDataSync(MessageParcel& data, MessageParcel& reply)
{
    std::shared_ptr<AAFwk::WantParams> wantParams(data.ReadParcelable<AAFwk::WantParams>());
    if (wantParams == nullptr) {
        WLOGFE("wantParams is nullptr");
        return static_cast<int>(WSErrorCode::WS_ERROR_TRANSFER_DATA_FAILED);
    }
    AAFwk::WantParams reWantParams;
    WSErrorCode errCode = NotifyTransferComponentDataSync(*wantParams, reWantParams);
    if (errCode != WSErrorCode::WS_OK) {
        return static_cast<int>(errCode);
    }
    if (!reply.WriteParcelable(&reWantParams)) {
        WLOGFE("reWantParams write failed.");
        return static_cast<int>(WSErrorCode::WS_ERROR_TRANSFER_DATA_FAILED);
    }
    return static_cast<int>(WSErrorCode::WS_OK);
}

int SessionStageStub::HandleNotifyOccupiedAreaChange(MessageParcel& data, MessageParcel& reply)
{
    WLOGFD("HandleNotifyOccupiedAreaChangeInfo!");
    sptr<OccupiedAreaChangeInfo> info(data.ReadParcelable<OccupiedAreaChangeInfo>());
    if (info == nullptr) {
        WLOGFE("Occupied info is nullptr");
        return ERR_INVALID_VALUE;
    }
    NotifyOccupiedAreaChangeInfo(info);
    return ERR_NONE;
}

int SessionStageStub::HandleUpdateAvoidArea(MessageParcel& data, MessageParcel& reply)
{
    WLOGFD("HandleUpdateAvoidArea!");
    sptr<AvoidArea> avoidArea = data.ReadStrongParcelable<AvoidArea>();
    if (!avoidArea) {
        return ERR_INVALID_VALUE;
    }
    uint32_t type;
    if (!data.ReadUint32(type)) {
        return ERR_INVALID_VALUE;
    }
    UpdateAvoidArea(avoidArea, static_cast<AvoidAreaType>(type));
    return ERR_NONE;
}

int SessionStageStub::HandleNotifyScreenshot(MessageParcel& data, MessageParcel& reply)
{
    WLOGFD("Notify Screen shot!");
    NotifyScreenshot();
    return ERR_NONE;
}

int SessionStageStub::HandleDumpSessionElementInfo(MessageParcel& data, MessageParcel& reply)
{
    WLOGFD("HandleDumpSessionElementInfo!");
    std::vector<std::string> params;
    if (!data.ReadStringVector(&params)) {
        WLOGFE("Fail to read params");
        return -1;
    }
    DumpSessionElementInfo(params);
    return ERR_NONE;
}

int SessionStageStub::HandleNotifyTouchOutside(MessageParcel& data, MessageParcel& reply)
{
    WLOGFD("HandleNotifyTouchOutside!");
    NotifyTouchOutside();
    return ERR_NONE;
}

int SessionStageStub::HandleUpdateWindowMode(MessageParcel& data, MessageParcel& reply)
{
    WLOGFD("HandleUpdateWindowMode!");
    WindowMode mode = static_cast<WindowMode>(data.ReadUint32());
    WSError errCode = UpdateWindowMode(mode);
    reply.WriteInt32(static_cast<int32_t>(errCode));
    return ERR_NONE;
}

int SessionStageStub::HandleNotifyWindowVisibilityChange(MessageParcel& data, MessageParcel& reply)
{
    WLOGFD("HandleNotifyWindowVisibilityChange!");
    bool isVisible = data.ReadBool();
    WSError errCode = NotifyWindowVisibility(isVisible);
    reply.WriteInt32(static_cast<int32_t>(errCode));
    return ERR_NONE;
}

int SessionStageStub::HandleNotifyForegroundInteractiveStatus(MessageParcel& data, MessageParcel& reply)
{
    WLOGFD("NotifyForegroundInteractiveStatus!");
    bool interactive = data.ReadBool();
    NotifyForegroundInteractiveStatus(interactive);
    return ERR_NONE;
}

int SessionStageStub::HandleUpdateMaximizeMode(MessageParcel& data, MessageParcel& reply)
{
    WLOGFD("HandleUpdateMaximizeMode!");
    MaximizeMode mode = static_cast<MaximizeMode>(data.ReadUint32());
    WSError errCode = UpdateMaximizeMode(mode);
    reply.WriteInt32(static_cast<int32_t>(errCode));
    return ERR_NONE;
}

int SessionStageStub::HandleNotifySessionForeground(MessageParcel& data, MessageParcel& reply)
{
    WLOGFD("HandleNotifySessionForeground");
    uint32_t reason = data.ReadUint32();
    bool withAnimation = data.ReadBool();
    NotifySessionForeground(reason, withAnimation);
    return ERR_NONE;
}

int SessionStageStub::HandleNotifySessionBackground(MessageParcel& data, MessageParcel& reply)
{
    WLOGFD("HandleNotifySessionBackground");
    uint32_t reason = data.ReadUint32();
    bool withAnimation = data.ReadBool();
    bool isFromInnerkits = data.ReadBool();
    NotifySessionBackground(reason, withAnimation, isFromInnerkits);
    return ERR_NONE;
}

int SessionStageStub::HandleUpdateTitleInTargetPos(MessageParcel& data, MessageParcel& reply)
{
    WLOGFD("HandleUpdateTitleInTargetPos!");
    bool isShow = data.ReadBool();
    int32_t height = data.ReadInt32();
    WSError errCode = UpdateTitleInTargetPos(isShow, height);
    reply.WriteInt32(static_cast<int32_t>(errCode));
    return ERR_NONE;
}

int SessionStageStub::HandleNotifyTransformChange(MessageParcel& data, MessageParcel& reply)
{
    WLOGFD("HandleNotifyTransformChange!");
    Transform transform;
    transform.Unmarshalling(data);
    NotifyTransformChange(transform);
    return ERR_NONE;
}

int SessionStageStub::HandleNotifyDensityFollowHost(MessageParcel& data, MessageParcel& reply)
{
    TLOGD(WmsLogTag::WMS_UIEXT, "HandleNotifyDensityFollowHost");
    bool isFollowHost = data.ReadBool();
    float densityValue = data.ReadFloat();
    NotifyDensityFollowHost(isFollowHost, densityValue);
    return ERR_NONE;
}

int SessionStageStub::HandleNotifyDialogStateChange(MessageParcel& data, MessageParcel& reply)
{
    WLOGD("HandleNotifyDialogStateChange!");
    bool isForeground = data.ReadBool();
    NotifyDialogStateChange(isForeground);
    return ERR_NONE;
}

int SessionStageStub::HandleSetPipActionEvent(MessageParcel& data, MessageParcel& reply)
{
    TLOGD(WmsLogTag::WMS_PIP, "HandleSetPipActionEvent");
    std::string action = data.ReadString();
    if (action.empty()) {
        TLOGE(WmsLogTag::WMS_PIP, "SessionStageStub pip action event is nullptr");
        return ERR_INVALID_VALUE;
    }
    int32_t status;
    if (!data.ReadInt32(status)) {
        return ERR_INVALID_VALUE;
    }
    SetPipActionEvent(action, status);
    return ERR_NONE;
}

int SessionStageStub::HandleUpdateDisplayId(MessageParcel& data, MessageParcel& reply)
{
    WLOGD("UpdateDisplayId!");
    uint64_t displayId = data.ReadUint64();
    WSError errCode = UpdateDisplayId(displayId);
    reply.WriteInt32(static_cast<int32_t>(errCode));
    return ERR_NONE;
}

int SessionStageStub::HandleNotifyDisplayMove(MessageParcel& data, MessageParcel& reply)
{
    WLOGD("HandleNotifyDisplayMove!");
    DisplayId from = static_cast<DisplayId>(data.ReadUint64());
    DisplayId to = static_cast<DisplayId>(data.ReadUint64());
    NotifyDisplayMove(from, to);
    return ERR_NONE;
}

int SessionStageStub::HandleSwitchFreeMultiWindow(MessageParcel& data, MessageParcel& reply)
{
    TLOGD(WmsLogTag::WMS_LAYOUT, "HandleSwitchFreeMultiWindow!");
    bool enable = data.ReadBool();
    WSError errCode = SwitchFreeMultiWindow(enable);
    reply.WriteInt32(static_cast<int32_t>(errCode));

    return ERR_NONE;
}

int SessionStageStub::HandleNotifyKeyboardPanelInfoChange(MessageParcel& data, MessageParcel& reply)
{
    TLOGD(WmsLogTag::WMS_KEYBOARD, "HandleNotifyKeyboardPanelInfoChange!");
    sptr<KeyboardPanelInfo> keyboardPanelInfo = data.ReadParcelable<KeyboardPanelInfo>();
    if (keyboardPanelInfo == nullptr) {
        TLOGE(WmsLogTag::WMS_KEYBOARD, "keyboardPanelInfo is nullptr!");
        return ERR_INVALID_VALUE;
    }
    NotifyKeyboardPanelInfoChange(*keyboardPanelInfo);

    return ERR_NONE;
}
} // namespace OHOS::Rosen

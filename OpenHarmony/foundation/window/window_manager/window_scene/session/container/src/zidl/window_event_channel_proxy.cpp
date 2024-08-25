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

#include "session/container/include/zidl/window_event_channel_proxy.h"
#include "session/container/include/zidl/window_event_ipc_interface_code.h"

#include <axis_event.h>
#include <ipc_types.h>
#include <key_event.h>
#include <message_option.h>
#include <message_parcel.h>
#include <pointer_event.h>
#include <vector>

#include "parcel/accessibility_element_info_parcel.h"
#include "window_manager_hilog.h"

namespace OHOS::Rosen {
namespace {
constexpr HiviewDFX::HiLogLabel LABEL = {LOG_CORE, HILOG_DOMAIN_WINDOW, "WindowEventChannelProxy"};
constexpr int64_t MAX_COUNT = 210 * 9 * 9 * 100000000000;
}

WSError WindowEventChannelProxy::TransferKeyEvent(const std::shared_ptr<MMI::KeyEvent>& keyEvent)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WLOGFE("WriteInterfaceToken failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }

    if (!keyEvent->WriteToParcel(data)) {
        WLOGFE("Failed to write key event");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    bool isPreImeEvent = false;
    if (!data.WriteBool(isPreImeEvent)) {
        WLOGFE("Write bool failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    if (Remote()->SendRequest(static_cast<uint32_t>(WindowEventInterfaceCode::TRANS_ID_TRANSFER_KEY_EVENT),
        data, reply, option) != ERR_NONE) {
        WLOGFE("SendRequest failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    reply.ReadBool();
    int32_t ret = reply.ReadInt32();
    return static_cast<WSError>(ret);
}

WSError WindowEventChannelProxy::TransferPointerEvent(const std::shared_ptr<MMI::PointerEvent>& pointerEvent)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WLOGFE("WriteInterfaceToken failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }

    if (!pointerEvent->WriteToParcel(data)) {
        WLOGFE("Failed to write pointer event");
        return WSError::WS_ERROR_IPC_FAILED;
    }

    if (Remote()->SendRequest(static_cast<uint32_t>(WindowEventInterfaceCode::TRANS_ID_TRANSFER_POINTER_EVENT),
        data, reply, option) != ERR_NONE) {
        WLOGFE("SendRequest failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    int32_t ret = reply.ReadInt32();
    return static_cast<WSError>(ret);
}

WSError WindowEventChannelProxy::TransferBackpressedEventForConsumed(bool& isConsumed)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WLOGFE("WriteInterfaceToken failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }

    if (Remote()->SendRequest(static_cast<uint32_t>(WindowEventInterfaceCode::TRANS_ID_TRANSFER_BACKPRESSED_EVENT),
        data, reply, option) != ERR_NONE) {
        WLOGFE("SendRequest failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    isConsumed = reply.ReadBool();
    int32_t ret = reply.ReadInt32();
    return static_cast<WSError>(ret);
}

WSError WindowEventChannelProxy::TransferKeyEventForConsumed(
    const std::shared_ptr<MMI::KeyEvent>& keyEvent, bool& isConsumed, bool isPreImeEvent)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WLOGFE("WriteInterfaceToken failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }

    if (!keyEvent->WriteToParcel(data)) {
        WLOGFE("Failed to write key event");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    if (!data.WriteBool(isPreImeEvent)) {
        WLOGFE("Write bool failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    if (Remote()->SendRequest(static_cast<uint32_t>(WindowEventInterfaceCode::TRANS_ID_TRANSFER_KEY_EVENT),
        data, reply, option) != ERR_NONE) {
        WLOGFE("SendRequest failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    isConsumed = reply.ReadBool();
    int32_t ret = reply.ReadInt32();
    return static_cast<WSError>(ret);
}

WSError WindowEventChannelProxy::TransferKeyEventForConsumedAsync(
    const std::shared_ptr<MMI::KeyEvent>& keyEvent, bool isPreImeEvent, const sptr<IRemoteObject>& listener)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TLOGE(WmsLogTag::WMS_EVENT, "WriteInterfaceToken failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }

    if (!keyEvent->WriteToParcel(data)) {
        TLOGE(WmsLogTag::WMS_EVENT, "Failed to write key event");
        return WSError::WS_ERROR_IPC_FAILED;
    }

    if (!data.WriteBool(isPreImeEvent)) {
        TLOGE(WmsLogTag::WMS_EVENT, "Write isPreImeEvent failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }

    if (!data.WriteRemoteObject(listener)) {
        TLOGE(WmsLogTag::WMS_EVENT, "WriteRemoteObject listener failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }

    if (Remote()->SendRequest(static_cast<uint32_t>(WindowEventInterfaceCode::TRANS_ID_TRANSFER_KEY_EVENT_ASYNC),
        data, reply, option) != ERR_NONE) {
        TLOGE(WmsLogTag::WMS_EVENT, "SendRequest failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    int32_t ret = reply.ReadInt32();
    return static_cast<WSError>(ret);
}

WSError WindowEventChannelProxy::TransferFocusActiveEvent(bool isFocusActive)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WLOGFE("WriteInterfaceToken failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    if (!data.WriteBool(isFocusActive)) {
        WLOGFE("Write bool failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    if (Remote()->SendRequest(static_cast<uint32_t>(WindowEventInterfaceCode::TRANS_ID_TRANSFER_FOCUS_ACTIVE_EVENT),
        data, reply, option) != ERR_NONE) {
        WLOGFE("SendRequest failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    int32_t ret = reply.ReadInt32();
    return static_cast<WSError>(ret);
}

WSError WindowEventChannelProxy::TransferFocusState(bool focusState)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WLOGFE("WriteInterfaceToken failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    if (!data.WriteBool(focusState)) {
        WLOGFE("Write focusState failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    if (Remote()->SendRequest(static_cast<uint32_t>(WindowEventInterfaceCode::TRANS_ID_TRANSFER_FOCUS_STATE_EVENT),
        data, reply, option) != ERR_NONE) {
        WLOGFE("SendRequest failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    int32_t ret = reply.ReadInt32();
    return static_cast<WSError>(ret);
}

WSError GetElementInfos(MessageParcel& reply, std::list<Accessibility::AccessibilityElementInfo>& infos)
{
    int64_t count = 0;
    if (!reply.ReadInt64(count)) {
        WLOGFE("GetElementInfos failed to read count");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    if (count > MAX_COUNT) {
        WLOGFE("GetElementInfos count over size");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    infos.clear();
    for (int i = 0; i < count; i++) {
        sptr<Accessibility::AccessibilityElementInfoParcel> infoPtr =
            reply.ReadStrongParcelable<Accessibility::AccessibilityElementInfoParcel>();
        if (infoPtr != nullptr) {
            infos.push_back(*infoPtr);
        }
    }
    return WSError::WS_OK;
}

WSError WindowEventChannelProxy::TransferSearchElementInfo(int64_t elementId, int32_t mode, int64_t baseParent,
    std::list<Accessibility::AccessibilityElementInfo>& infos)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WLOGFE("WriteInterfaceToken failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    if (!data.WriteInt64(elementId)) {
        WLOGFE("Write elementId failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    if (!data.WriteInt32(mode)) {
        WLOGFE("Write mode failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    if (!data.WriteInt64(baseParent)) {
        WLOGFE("Write baseParent failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }

    if (Remote()->SendRequest(static_cast<uint32_t>(WindowEventInterfaceCode::TRANS_ID_TRANSFER_SEARCH_ELEMENT_INFO),
        data, reply, option) != ERR_NONE) {
        WLOGFE("SendRequest failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    return GetElementInfos(reply, infos);
}

WSError WindowEventChannelProxy::TransferSearchElementInfosByText(int64_t elementId, const std::string& text,
    int64_t baseParent, std::list<Accessibility::AccessibilityElementInfo>& infos)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WLOGFE("WriteInterfaceToken failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    if (!data.WriteInt64(elementId)) {
        WLOGFE("Write elementId failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    if (!data.WriteString(text)) {
        WLOGFE("Write text failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    if (!data.WriteInt64(baseParent)) {
        WLOGFE("Write baseParent failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }

    if (Remote()->SendRequest(
        static_cast<uint32_t>(WindowEventInterfaceCode::TRANS_ID_TRANSFER_SEARCH_ELEMENT_INFO_BY_TEXT), data, reply,
        option) != ERR_NONE) {
        WLOGFE("SendRequest failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    return GetElementInfos(reply, infos);
}

WSError GetElementInfo(MessageParcel& reply, Accessibility::AccessibilityElementInfo& info)
{
    sptr<Accessibility::AccessibilityElementInfoParcel> infoPtr =
        reply.ReadStrongParcelable<Accessibility::AccessibilityElementInfoParcel>();
    if (infoPtr != nullptr) {
        info = *infoPtr;
    }
    return WSError::WS_OK;
}

WSError WindowEventChannelProxy::TransferFindFocusedElementInfo(int64_t elementId, int32_t focusType,
    int64_t baseParent, Accessibility::AccessibilityElementInfo& info)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WLOGFE("WriteInterfaceToken failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    if (!data.WriteInt64(elementId)) {
        WLOGFE("Write elementId failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    if (!data.WriteInt32(focusType)) {
        WLOGFE("Write focusType failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    if (!data.WriteInt64(baseParent)) {
        WLOGFE("Write baseParent failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    if (Remote()->SendRequest(
        static_cast<uint32_t>(WindowEventInterfaceCode::TRANS_ID_TRANSFER_FIND_FOCUSED_ELEMENT_INFO), data, reply,
        option) != ERR_NONE) {
        WLOGFE("SendRequest failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    return GetElementInfo(reply, info);
}

WSError WindowEventChannelProxy::TransferFocusMoveSearch(int64_t elementId, int32_t direction, int64_t baseParent,
    Accessibility::AccessibilityElementInfo& info)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WLOGFE("WriteInterfaceToken failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    if (!data.WriteInt64(elementId)) {
        WLOGFE("Write elementId failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    if (!data.WriteInt32(direction)) {
        WLOGFE("Write direction failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    if (!data.WriteInt64(baseParent)) {
        WLOGFE("Write baseParent failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }

    if (Remote()->SendRequest(static_cast<uint32_t>(WindowEventInterfaceCode::TRANS_ID_TRANSFER_FOCUS_MOVE_SEARCH),
        data, reply, option) != ERR_NONE) {
        WLOGFE("SendRequest failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    return GetElementInfo(reply, info);
}

WSError WindowEventChannelProxy::TransferExecuteAction(int64_t elementId,
    const std::map<std::string, std::string>& actionArguments, int32_t action,
    int64_t baseParent)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WLOGFE("WriteInterfaceToken failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    if (!data.WriteInt64(elementId)) {
        WLOGFE("Write elementId failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    if (!data.WriteInt32(action)) {
        WLOGFE("Write action failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    std::vector<std::string> actionArgumentsKey {};
    std::vector<std::string> actionArgumentsValue {};
    for (auto iter = actionArguments.begin(); iter != actionArguments.end(); iter++) {
        actionArgumentsKey.push_back(iter->first);
        actionArgumentsValue.push_back(iter->second);
    }
    if (!data.WriteStringVector(actionArgumentsKey)) {
        WLOGFE("actionArgumentsKey write error");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    if (!data.WriteStringVector(actionArgumentsValue)) {
        WLOGFE("actionArgumentsValue write error");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    if (!data.WriteInt64(baseParent)) {
        WLOGFE("Write baseParent failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    if (Remote()->SendRequest(static_cast<uint32_t>(WindowEventInterfaceCode::TRANS_ID_TRANSFER_EXECUTE_ACTION),
        data, reply, option) != ERR_NONE) {
        WLOGFE("SendRequest failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    int32_t ret = reply.ReadInt32();
    return static_cast<WSError>(ret);
}

WSError WindowEventChannelProxy::TransferAccessibilityHoverEvent(float pointX, float pointY, int32_t sourceType,
    int32_t eventType, int64_t timeMs)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WLOGFE("WriteInterfaceToken failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    if (!data.WriteFloat(pointX) ||
        !data.WriteFloat(pointY) ||
        !data.WriteInt32(sourceType) ||
        !data.WriteInt32(eventType) ||
        !data.WriteInt64(timeMs)) {
        WLOGFE("Write TransferAccessibilityHoverEvent data failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    if (Remote()->SendRequest(
        static_cast<uint32_t>(WindowEventInterfaceCode::TRANS_ID_TRANSFER_ACCESSIBILITY_HOVER_EVENT),
        data, reply, option) != ERR_NONE) {
        WLOGFE("SendRequest failed");
        return WSError::WS_ERROR_IPC_FAILED;
    }
    int32_t ret = reply.ReadInt32();
    return static_cast<WSError>(ret);
}
} // namespace OHOS::Rosen

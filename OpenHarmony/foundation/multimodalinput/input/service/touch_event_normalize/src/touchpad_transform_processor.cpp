/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "touchpad_transform_processor.h"

#include <sstream>
#include <linux/input.h>

#include "event_log_helper.h"
#include "input_windows_manager.h"
#include "mmi_log.h"
#include "mouse_device_state.h"
#include "preferences.h"
#include "preferences_impl.h"
#include "preferences_errno.h"
#include "preferences_helper.h"
#include "preferences_xml_utils.h"
#include "dfx_hisysevent.h"
#include "multimodal_input_preferences_manager.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchPadTransformProcessor"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t MT_TOOL_NONE { -1 };
constexpr int32_t BTN_DOWN { 1 };
constexpr int32_t FINGER_COUNT_MAX { 5 };
constexpr int32_t FINGER_TAP_MIN { 3 };
constexpr int32_t FINGER_MOTION_MAX { 9 };
constexpr int32_t TP_SYSTEM_PINCH_FINGER_CNT { 2 };
const std::string TOUCHPAD_FILE_NAME = "touchpad_settings.xml";
} // namespace

TouchPadTransformProcessor::TouchPadTransformProcessor(int32_t deviceId)
    : deviceId_(deviceId)
{
    InitToolType();
}

int32_t TouchPadTransformProcessor::OnEventTouchPadDown(struct libinput_event *event)
{
    CALL_INFO_TRACE;
    CHKPR(event, RET_ERR);
    auto touchpad = libinput_event_get_touchpad_event(event);
    CHKPR(touchpad, RET_ERR);
    auto device = libinput_event_get_device(event);
    CHKPR(device, RET_ERR);

    uint64_t time = libinput_event_touchpad_get_time_usec(touchpad);
    auto pointIds = pointerEvent_->GetPointerIds();
    if (pointIds.empty()) {
        pointerEvent_->SetActionStartTime(time);
    }
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    PointerEvent::PointerItem item;
    int32_t longAxis = libinput_event_touchpad_get_touch_contact_long_axis(touchpad);
    int32_t shortAxis = libinput_event_touchpad_get_touch_contact_short_axis(touchpad);
    double pressure = libinput_event_touchpad_get_pressure(touchpad);
    int32_t seatSlot = libinput_event_touchpad_get_seat_slot(touchpad);
    double logicalX = libinput_event_touchpad_get_x(touchpad);
    double logicalY = libinput_event_touchpad_get_y(touchpad);
    double toolPhysicalX = libinput_event_touchpad_get_tool_x(touchpad);
    double toolPhysicalY = libinput_event_touchpad_get_tool_y(touchpad);
    double toolWidth = libinput_event_touchpad_get_tool_width(touchpad);
    double toolHeight = libinput_event_touchpad_get_tool_height(touchpad);
    int32_t toolType = GetTouchPadToolType(touchpad, device);
    if (toolType == PointerEvent::TOOL_TYPE_PALM) {
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    }

    item.SetLongAxis(longAxis);
    item.SetShortAxis(shortAxis);
    item.SetPressure(pressure);
    item.SetToolType(toolType);
    item.SetPointerId(seatSlot);
    item.SetDownTime(time);
    item.SetPressed(true);
    item.SetDisplayX(static_cast<int32_t>(logicalX));
    item.SetDisplayY(static_cast<int32_t>(logicalY));
    item.SetToolDisplayX(static_cast<int32_t>(toolPhysicalX));
    item.SetToolDisplayY(static_cast<int32_t>(toolPhysicalY));
    item.SetToolWidth(static_cast<int32_t>(toolWidth));
    item.SetToolHeight(static_cast<int32_t>(toolHeight));
    item.SetDeviceId(deviceId_);
    pointerEvent_->SetDeviceId(deviceId_);
    pointerEvent_->AddPointerItem(item);
    pointerEvent_->SetPointerId(seatSlot);

    return RET_OK;
}

int32_t TouchPadTransformProcessor::OnEventTouchPadMotion(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, RET_ERR);
    auto touchpad = libinput_event_get_touchpad_event(event);
    CHKPR(touchpad, RET_ERR);
    int32_t seatSlot = libinput_event_touchpad_get_seat_slot(touchpad);
    auto device = libinput_event_get_device(event);
    CHKPR(device, RET_ERR);

    uint64_t time = libinput_event_touchpad_get_time_usec(touchpad);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    PointerEvent::PointerItem item;
    if (!pointerEvent_->GetPointerItem(seatSlot, item)) {
        MMI_HILOGE("Can't find the pointer item data, seatSlot:%{public}d, errCode:%{public}d",
                   seatSlot, PARAM_INPUT_FAIL);
        return RET_ERR;
    }
    int32_t longAxis = libinput_event_touchpad_get_touch_contact_long_axis(touchpad);
    int32_t shortAxis = libinput_event_touchpad_get_touch_contact_short_axis(touchpad);
    double pressure = libinput_event_touchpad_get_pressure(touchpad);
    double logicalX = libinput_event_touchpad_get_x(touchpad);
    double logicalY = libinput_event_touchpad_get_y(touchpad);
    double toolPhysicalX = libinput_event_touchpad_get_tool_x(touchpad);
    double toolPhysicalY = libinput_event_touchpad_get_tool_y(touchpad);
    double toolWidth = libinput_event_touchpad_get_tool_width(touchpad);
    double toolHeight = libinput_event_touchpad_get_tool_height(touchpad);
    int32_t toolType = GetTouchPadToolType(touchpad, device);
    if (toolType == PointerEvent::TOOL_TYPE_PALM) {
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    }

    item.SetLongAxis(longAxis);
    item.SetShortAxis(shortAxis);
    item.SetPressure(pressure);
    item.SetDisplayX(static_cast<int32_t>(logicalX));
    item.SetDisplayY(static_cast<int32_t>(logicalY));
    item.SetToolDisplayX(static_cast<int32_t>(toolPhysicalX));
    item.SetToolDisplayY(static_cast<int32_t>(toolPhysicalY));
    item.SetToolWidth(static_cast<int32_t>(toolWidth));
    item.SetToolHeight(static_cast<int32_t>(toolHeight));
    pointerEvent_->UpdatePointerItem(seatSlot, item);
    pointerEvent_->SetPointerId(seatSlot);

    return RET_OK;
}

int32_t TouchPadTransformProcessor::OnEventTouchPadUp(struct libinput_event *event)
{
    CALL_INFO_TRACE;
    CHKPR(event, RET_ERR);
    auto touchpad = libinput_event_get_touchpad_event(event);
    CHKPR(touchpad, RET_ERR);
    int32_t seatSlot = libinput_event_touchpad_get_seat_slot(touchpad);

    uint64_t time = libinput_event_touchpad_get_time_usec(touchpad);
    pointerEvent_->SetActionTime(time);
    if (MULTI_FINGERTAP_HDR->GetMultiFingersState() == MulFingersTap::TRIPLETAP) {
        if (SetTouchPadMultiTapData() != RET_OK) {
            MMI_HILOGE("Set touchpad multiFingers tap failed");
            return RET_ERR;
        }
    } else {
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    }
    PointerEvent::PointerItem item;
    if (!pointerEvent_->GetPointerItem(seatSlot, item)) {
        MMI_HILOGE("Can't find the pointer item data, seatSlot:%{public}d, errCode:%{public}d",
                   seatSlot, PARAM_INPUT_FAIL);
        return RET_ERR;
    }
    item.SetPressed(false);
    pointerEvent_->UpdatePointerItem(seatSlot, item);
    pointerEvent_->SetPointerId(seatSlot);

    return RET_OK;
}

std::shared_ptr<PointerEvent> TouchPadTransformProcessor::OnEvent(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPP(event);
    if (pointerEvent_ == nullptr) {
        pointerEvent_ = PointerEvent::Create();
        CHKPP(pointerEvent_);
    }

    int32_t ret = RET_OK;
    int32_t type = libinput_event_get_type(event);
    switch (type) {
        case LIBINPUT_EVENT_TOUCHPAD_DOWN: {
            ret = OnEventTouchPadDown(event);
            break;
        }
        case LIBINPUT_EVENT_TOUCHPAD_UP: {
            ret = OnEventTouchPadUp(event);
            break;
        }
        case LIBINPUT_EVENT_TOUCHPAD_MOTION: {
            ret = OnEventTouchPadMotion(event);
            break;
        }
        case LIBINPUT_EVENT_GESTURE_SWIPE_BEGIN: {
            ret = OnEventTouchPadSwipeBegin(event);
            break;
        }
        case LIBINPUT_EVENT_GESTURE_SWIPE_UPDATE: {
            ret = OnEventTouchPadSwipeUpdate(event);
            break;
        }
        case LIBINPUT_EVENT_GESTURE_SWIPE_END: {
            ret = OnEventTouchPadSwipeEnd(event);
            break;
        }

        case LIBINPUT_EVENT_GESTURE_PINCH_BEGIN: {
            ret = OnEventTouchPadPinchBegin(event);
            break;
        }
        case LIBINPUT_EVENT_GESTURE_PINCH_UPDATE: {
            ret = OnEventTouchPadPinchUpdate(event);
            break;
        }
        case LIBINPUT_EVENT_GESTURE_PINCH_END: {
            ret = OnEventTouchPadPinchEnd(event);
            break;
        }
        default: {
            MMI_HILOGW("Touch pad action is not found");
            return nullptr;
        }
    }

    if (ret != RET_OK) {
        return nullptr;
    }

    pointerEvent_->UpdateId();
    MMI_HILOGD("Pointer event dispatcher of server:");
    EventLogHelper::PrintEventData(pointerEvent_, pointerEvent_->GetPointerAction(),
        pointerEvent_->GetPointerIds().size());
    auto device = InputDevMgr->GetInputDevice(pointerEvent_->GetDeviceId());
    CHKPP(device);
    MMI_HILOGI("InputTracking id:%{public}d event created by:%{public}s, type:%{public}d",
               pointerEvent_->GetId(), device->GetName().c_str(), type);
    return pointerEvent_;
}

int32_t TouchPadTransformProcessor::GetTouchPadToolType(
    struct libinput_event_touch *touchpad, struct libinput_device *device)
{
    int32_t toolType = libinput_event_touchpad_get_tool_type(touchpad);
    switch (toolType) {
        case MT_TOOL_NONE: {
            return GetTouchPadToolType(device);
        }
        case MT_TOOL_FINGER: {
            return PointerEvent::TOOL_TYPE_FINGER;
        }
        case MT_TOOL_PEN: {
            return PointerEvent::TOOL_TYPE_PEN;
        }
        case MT_TOOL_PALM: {
            MMI_HILOGD("ToolType is MT_TOOL_PALM");
            return PointerEvent::TOOL_TYPE_PALM;
        }
        default : {
            MMI_HILOGW("Unknown tool type, identified as finger, toolType:%{public}d", toolType);
            return PointerEvent::TOOL_TYPE_FINGER;
        }
    }
}

int32_t TouchPadTransformProcessor::GetTouchPadToolType(struct libinput_device *device)
{
    for (const auto &item : vecToolType_) {
        if (libinput_device_touchpad_btn_tool_type_down(device, item.first) == BTN_DOWN) {
            return item.second;
        }
    }
    MMI_HILOGD("Unknown Btn tool type, identified as finger");
    return PointerEvent::TOOL_TYPE_FINGER;
}

int32_t TouchPadTransformProcessor::SetTouchPadSwipeData(struct libinput_event *event, int32_t action)
{
    CALL_DEBUG_ENTER;

    bool tpSwipeSwitch = true;
    if (GetTouchpadSwipeSwitch(tpSwipeSwitch) != RET_OK) {
        MMI_HILOGD("Failed to get touchpad swipe switch flag, default is true.");
    }

    if (!tpSwipeSwitch) {
        MMI_HILOGD("Touchpad swipe switch is false.");
        return RET_ERR;
    }

    CHKPR(event, RET_ERR);
    struct libinput_event_gesture *gesture = libinput_event_get_gesture_event(event);
    CHKPR(gesture, RET_ERR);

    int64_t time = static_cast<int64_t>(libinput_event_gesture_get_time(gesture));
    pointerEvent_->SetActionTime(GetSysClockTime());
    pointerEvent_->SetActionStartTime(time);
    pointerEvent_->SetPointerAction(action);
    pointerEvent_->SetDeviceId(deviceId_);

    int32_t fingerCount = libinput_event_gesture_get_finger_count(gesture);
    if (fingerCount < 0 || fingerCount > FINGER_COUNT_MAX) {
        MMI_HILOGE("Finger count is invalid.");
        return RET_ERR;
    }
    pointerEvent_->SetFingerCount(fingerCount);

    if (fingerCount == 0) {
        MMI_HILOGD("There is no finger in swipe action %{public}d.", action);
        return RET_ERR;
    }

    int32_t sumX = 0;
    int32_t sumY = 0;
    for (int32_t i = 0; i < fingerCount; i++) {
        sumX += libinput_event_gesture_get_device_coords_x(gesture, i);
        sumY += libinput_event_gesture_get_device_coords_y(gesture, i);
    }

    PointerEvent::PointerItem pointerItem;
    pointerEvent_->GetPointerItem(defaultPointerId, pointerItem);
    pointerItem.SetPressed(MouseState->IsLeftBtnPressed());
    pointerItem.SetDownTime(time);
    pointerItem.SetDisplayX(sumX / fingerCount);
    pointerItem.SetDisplayY(sumY / fingerCount);
    pointerItem.SetDeviceId(deviceId_);
    pointerItem.SetPointerId(defaultPointerId);
    pointerEvent_->UpdatePointerItem(defaultPointerId, pointerItem);
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);

    if (action == PointerEvent::POINTER_ACTION_SWIPE_BEGIN) {
        MMI_HILOGE("Start report for POINTER_ACTION_SWIPE_BEGIN");
        DfxHisysevent::StatisticTouchpadGesture(pointerEvent_);
    }

    return RET_OK;
}

int32_t TouchPadTransformProcessor::OnEventTouchPadSwipeBegin(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    return SetTouchPadSwipeData(event, PointerEvent::POINTER_ACTION_SWIPE_BEGIN);
}

int32_t TouchPadTransformProcessor::OnEventTouchPadSwipeUpdate(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    return SetTouchPadSwipeData(event, PointerEvent::POINTER_ACTION_SWIPE_UPDATE);
}

int32_t TouchPadTransformProcessor::OnEventTouchPadSwipeEnd(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    return SetTouchPadSwipeData(event, PointerEvent::POINTER_ACTION_SWIPE_END);
}

int32_t TouchPadTransformProcessor::SetTouchPadMultiTapData()
{
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_TRIPTAP);
    auto state = MULTI_FINGERTAP_HDR->GetMultiFingersState();
    pointerEvent_->SetFingerCount(static_cast<int32_t>(state));
    return RET_OK;
}

int32_t TouchPadTransformProcessor::SetTouchPadPinchData(struct libinput_event *event, int32_t action)
{
    CALL_DEBUG_ENTER;

    bool tpPinchSwitch = true;
    if (GetTouchpadPinchSwitch(tpPinchSwitch) != RET_OK) {
        MMI_HILOGD("Failed to get touchpad pinch switch flag, default is true.");
    }

    CHKPR(event, RET_ERR);
    auto gesture = libinput_event_get_gesture_event(event);
    CHKPR(gesture, RET_ERR);
    int32_t fingerCount = libinput_event_gesture_get_finger_count(gesture);
    if (fingerCount <= 0 || fingerCount > FINGER_COUNT_MAX) {
        MMI_HILOGE("Finger count is invalid.");
        return RET_ERR;
    }

    if (!tpPinchSwitch && fingerCount == TP_SYSTEM_PINCH_FINGER_CNT) {
        MMI_HILOGD("Touchpad pinch switch is false.");
        return RET_ERR;
    }

    int64_t time = static_cast<int64_t>(libinput_event_gesture_get_time(gesture));
    double scale = libinput_event_gesture_get_scale(gesture);

    pointerEvent_->SetActionTime(GetSysClockTime());
    pointerEvent_->SetActionStartTime(time);

    SetPinchPointerItem(time);

    ProcessTouchPadPinchDataEvent(fingerCount, action, scale);

    return RET_OK;
}

void TouchPadTransformProcessor::SetPinchPointerItem(int64_t time)
{
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetDownTime(time);
    pointerItem.SetPressed(MouseState->IsLeftBtnPressed());
    pointerItem.SetPointerId(defaultPointerId);
    pointerItem.SetWindowX(0);
    pointerItem.SetWindowY(0);
    auto mouseInfo = WinMgr->GetMouseInfo();
    pointerItem.SetDisplayX(mouseInfo.physicalX);
    pointerItem.SetDisplayY(mouseInfo.physicalY);
    pointerEvent_->UpdatePointerItem(defaultPointerId, pointerItem);
}

void TouchPadTransformProcessor::ProcessTouchPadPinchDataEvent(int32_t fingerCount, int32_t action, double scale)
{
    pointerEvent_->ClearButtonPressed();
    std::vector<int32_t> pressedButtons;
    MouseState->GetPressedButtons(pressedButtons);
    for (const auto &item : pressedButtons) {
        pointerEvent_->SetButtonPressed(item);
    }

    pointerEvent_->SetFingerCount(fingerCount);
    pointerEvent_->SetDeviceId(deviceId_);
    auto mouseInfo = WinMgr->GetMouseInfo();
    pointerEvent_->SetTargetDisplayId(mouseInfo.displayId);
    pointerEvent_->SetTargetWindowId(-1);
    pointerEvent_->SetPointerId(defaultPointerId);
    pointerEvent_->SetPointerAction(action);
    pointerEvent_->SetAxisValue(PointerEvent::AXIS_TYPE_PINCH, scale);

    if (fingerCount == TP_SYSTEM_PINCH_FINGER_CNT) {
        pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
        pointerEvent_->SetAxisValue(PointerEvent::AXIS_TYPE_PINCH, scale);
    } else {
        pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
        pointerEvent_->SetAxisValue(PointerEvent::AXIS_TYPE_PINCH, scale);
    }

    if (pointerEvent_->GetFingerCount() == TP_SYSTEM_PINCH_FINGER_CNT) {
        WinMgr->UpdateTargetPointer(pointerEvent_);
    }

    // only three or four finger pinch need to statistic
    if (action == PointerEvent::POINTER_ACTION_AXIS_BEGIN && fingerCount > TP_SYSTEM_PINCH_FINGER_CNT) {
        DfxHisysevent::StatisticTouchpadGesture(pointerEvent_);
    }
}

int32_t TouchPadTransformProcessor::OnEventTouchPadPinchBegin(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    return SetTouchPadPinchData(event, PointerEvent::POINTER_ACTION_AXIS_BEGIN);
}

int32_t TouchPadTransformProcessor::OnEventTouchPadPinchUpdate(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    return SetTouchPadPinchData(event, PointerEvent::POINTER_ACTION_AXIS_UPDATE);
}

int32_t TouchPadTransformProcessor::OnEventTouchPadPinchEnd(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    return SetTouchPadPinchData(event, PointerEvent::POINTER_ACTION_AXIS_END);
}

void TouchPadTransformProcessor::InitToolType()
{
    vecToolType_.push_back(std::make_pair(BTN_TOOL_PEN, PointerEvent::TOOL_TYPE_PEN));
    vecToolType_.push_back(std::make_pair(BTN_TOOL_RUBBER, PointerEvent::TOOL_TYPE_RUBBER));
    vecToolType_.push_back(std::make_pair(BTN_TOOL_BRUSH, PointerEvent::TOOL_TYPE_BRUSH));
    vecToolType_.push_back(std::make_pair(BTN_TOOL_PENCIL, PointerEvent::TOOL_TYPE_PENCIL));
    vecToolType_.push_back(std::make_pair(BTN_TOOL_AIRBRUSH, PointerEvent::TOOL_TYPE_AIRBRUSH));
    vecToolType_.push_back(std::make_pair(BTN_TOOL_FINGER, PointerEvent::TOOL_TYPE_FINGER));
    vecToolType_.push_back(std::make_pair(BTN_TOOL_MOUSE, PointerEvent::TOOL_TYPE_MOUSE));
    vecToolType_.push_back(std::make_pair(BTN_TOOL_LENS, PointerEvent::TOOL_TYPE_LENS));
}

int32_t TouchPadTransformProcessor::SetTouchpadSwipeSwitch(bool switchFlag)
{
    std::string name = "touchpadSwipe";
    if (PutConfigDataToDatabase(name, switchFlag) != RET_OK) {
        MMI_HILOGE("Failed to set touchpad swpie switch flag to mem.");
        return RET_ERR;
    }

    DfxHisysevent::ReportTouchpadSettingState(DfxHisysevent::TOUCHPAD_SETTING_CODE::TOUCHPAD_SWIPE_SETTING,
        switchFlag);
    return RET_OK;
}

int32_t TouchPadTransformProcessor::GetTouchpadSwipeSwitch(bool &switchFlag)
{
    std::string name = "touchpadSwipe";
    if (GetConfigDataFromDatabase(name, switchFlag) != RET_OK) {
        MMI_HILOGE("Failed to get touchpad swpie switch flag from mem.");
        return RET_ERR;
    }

    return RET_OK;
}

int32_t TouchPadTransformProcessor::SetTouchpadPinchSwitch(bool switchFlag)
{
    std::string name = "touchpadPinch";
    if (PutConfigDataToDatabase(name, switchFlag) != RET_OK) {
        MMI_HILOGE("Failed to set touchpad pinch switch flag to mem.");
        return RET_ERR;
    }

    DfxHisysevent::ReportTouchpadSettingState(DfxHisysevent::TOUCHPAD_SETTING_CODE::TOUCHPAD_PINCH_SETTING,
        switchFlag);
    return RET_OK;
}

int32_t TouchPadTransformProcessor::GetTouchpadPinchSwitch(bool &switchFlag)
{
    std::string name = "touchpadPinch";
    if (GetConfigDataFromDatabase(name, switchFlag) != RET_OK) {
        MMI_HILOGE("Failed to get touchpad pinch switch flag from mem.");
        return RET_ERR;
    }

    return RET_OK;
}

int32_t TouchPadTransformProcessor::SetTouchpadRotateSwitch(bool rotateSwitch)
{
    std::string name = "touchpadRotate";
    if (PutConfigDataToDatabase(name, rotateSwitch) != RET_OK) {
        MMI_HILOGE("PutConfigDataToDatabase failed");
        return RET_ERR;
    }

    DfxHisysevent::ReportTouchpadSettingState(DfxHisysevent::TOUCHPAD_SETTING_CODE::TOUCHPAD_ROTATE_SETTING,
        rotateSwitch);
    return RET_OK;
}

int32_t TouchPadTransformProcessor::GetTouchpadRotateSwitch(bool &rotateSwitch)
{
    std::string name = "touchpadRotate";
    if (GetConfigDataFromDatabase(name, rotateSwitch) != RET_OK) {
        MMI_HILOGE("GetConfigDataFromDatabase failed");
        return RET_ERR;
    }

    return RET_OK;
}

int32_t TouchPadTransformProcessor::PutConfigDataToDatabase(std::string &key, bool value)
{
    return PREFERENCES_MGR->SetBoolValue(key, TOUCHPAD_FILE_NAME, value);
}

int32_t TouchPadTransformProcessor::GetConfigDataFromDatabase(std::string &key, bool &value)
{
    value = PREFERENCES_MGR->GetBoolValue(key, true);
    return RET_OK;
}

MultiFingersTapHandler::MultiFingersTapHandler() {}

MultiFingersTapHandler::~MultiFingersTapHandler() {}

int32_t MultiFingersTapHandler::HandleMulFingersTap(struct libinput_event_touch *event, int32_t type)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, RET_ERR);
    // if is not multifigners tap, return.
    if (tapTrends_ == TapTrends::NOMULTAP) {
        return RET_OK;
    }
    // calculator delta time, if is larger than threshold, return.
    auto time = libinput_event_touchpad_get_time_usec(event);
    uint64_t deltaTime = 0;
    if (tapTrends_ != TapTrends::BEGIN) {
        deltaTime = time - lastTime;
    } else {
        beginTime = time;
    }
    lastTime = time;
    if ((deltaTime > perTimeThreshold) || ((lastTime - beginTime) > totalTimeThreshold)) {
        MMI_HILOGD("Not multitap, single time interval or total time interval is out of range."
            "single: %{public}" PRId64 ", total: %{public}" PRId64, deltaTime, (lastTime - beginTime));
        SetMULTI_FINGERTAP_HDRDefault();
        return RET_OK;
    }
    if (type == LIBINPUT_EVENT_TOUCHPAD_DOWN) {
        // if trends is up, is not multifigners tap, return.
        if ((tapTrends_ == TapTrends::UPING) || !CanAddToPointerMaps(event)) {
            MMI_HILOGD("The trends is up, is not a multifigners tap event");
            SetMULTI_FINGERTAP_HDRDefault();
            return RET_OK;
        } else {
            downCnt++;
            tapTrends_ = TapTrends::DOWNING;
        }
    } else if ((type == LIBINPUT_EVENT_TOUCHPAD_UP) && !CanUnsetPointerItem(event)) {
        upCnt++;
        tapTrends_ = TapTrends::UPING;
    } else if (type == LIBINPUT_EVENT_TOUCHPAD_MOTION) {
        motionCnt++;
        if ((motionCnt >= FINGER_MOTION_MAX) || IsInvalidMulTapGesture(event)) {
            MMI_HILOGD("the motion is too much");
            SetMULTI_FINGERTAP_HDRDefault();
            return RET_OK;
        }
    }
    if ((upCnt == downCnt) && (upCnt >= FINGER_TAP_MIN) && (upCnt <= FINGER_COUNT_MAX)) {
        multiFingersState = static_cast<MulFingersTap>(upCnt);
        MMI_HILOGD("This is multifinger tap event, finger count: %{public}d", upCnt);
        return RET_OK;
    }
    return RET_OK;
}

void MultiFingersTapHandler::SetMULTI_FINGERTAP_HDRDefault(bool isAlldefault)
{
    downCnt = 0;
    upCnt = 0;
    motionCnt = 0;
    tapTrends_ = TapTrends::BEGIN;
    beginTime = 0;
    lastTime = 0;
    if (isAlldefault) {
        multiFingersState = MulFingersTap::NOTAP;
    }
    pointerMaps.clear();
}

bool MultiFingersTapHandler::ClearPointerItems(std::shared_ptr<PointerEvent> pointer)
{
    auto ids_ = pointer->GetPointerIds();
    for (const auto &id : ids_) {
        pointer->RemovePointerItem(id);
    }
    return true;
}

MulFingersTap MultiFingersTapHandler::GetMultiFingersState()
{
    return multiFingersState;
}

bool MultiFingersTapHandler::CanAddToPointerMaps(struct libinput_event_touch *event)
{
    int32_t seatSlot = libinput_event_touchpad_get_seat_slot(event);
    if (pointerMaps.find(seatSlot) != pointerMaps.end()) {
        return false;
    }
    auto currentX = libinput_event_touchpad_get_x(event);
    auto currentY = libinput_event_touchpad_get_y(event);
    pointerMaps[seatSlot] = {currentX, currentY};
    return true;
}

bool MultiFingersTapHandler::IsInvalidMulTapGesture(struct libinput_event_touch *event)
{
    int32_t seatSlot = libinput_event_touchpad_get_seat_slot(event);
    if (pointerMaps.find(seatSlot) == pointerMaps.end()) {
        return true;
    } else if (pointerMaps[seatSlot].first < 0 || pointerMaps[seatSlot].second < 0) {
        return true;
    }
    auto currentX = libinput_event_touchpad_get_x(event);
    auto currentY = libinput_event_touchpad_get_y(event);
    auto [ lastX, lastY ] = pointerMaps[seatSlot];
    auto deltaX = abs(currentX - lastX);
    auto deltaY = abs(currentY - lastY);
    auto distance = deltaX + deltaY;
    pointerMaps[seatSlot] = {currentX, currentY};
    return ((deltaX > distanceThreshold) || (deltaY > distanceThreshold) || (distance > distanceThreshold));
}

bool MultiFingersTapHandler::CanUnsetPointerItem(struct libinput_event_touch *event)
{
    int32_t seatSlot = libinput_event_touchpad_get_seat_slot(event);
    if (pointerMaps.find(seatSlot) != pointerMaps.end()) {
        return false;
    } else {
        pointerMaps[seatSlot] = {-1.0, -1.0};
        return true;
    }
}
} // namespace MMI
} // namespace OHOS

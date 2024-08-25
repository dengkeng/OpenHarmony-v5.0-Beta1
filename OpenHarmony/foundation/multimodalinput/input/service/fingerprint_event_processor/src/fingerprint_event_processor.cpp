/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "fingerprint_event_processor.h"

#include "event_log_helper.h"
#include "input_event_handler.h"
#include "pointer_event.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "FingerprintEventProcessor"

namespace OHOS {
namespace MMI {
#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
FingerprintEventProcessor::FingerprintEventProcessor()
{}

FingerprintEventProcessor::~FingerprintEventProcessor()
{}

bool FingerprintEventProcessor::IsFingerprintEvent(struct libinput_event* event)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, false);
    auto device = libinput_event_get_device(event);
    CHKPR(device, false);
    std::string name = libinput_device_get_name(device);
    if (name != FINGERPRINT_SOURCE_KEY && name != FINGERPRINT_SOURCE_POINT) {
        MMI_HILOGD("not FingerprintEvent");
        return false;
    }
    if (name == FINGERPRINT_SOURCE_KEY) {
        struct libinput_event_keyboard* keyBoard = libinput_event_get_keyboard_event(event);
        CHKPR(keyBoard, false);
        auto key = libinput_event_keyboard_get_key(keyBoard);
        if (key != FINGERPRINT_CODE_DOWN && key != FINGERPRINT_CODE_UP
            && key != FINGERPRINT_CODE_CLICK && key != FINGERPRINT_CODE_RETOUCH) {
            MMI_HILOGD("not FingerprintEvent event");
            return false;
        }
    }
    return true;
}

int32_t FingerprintEventProcessor::HandleFingerprintEvent(struct libinput_event* event)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, ERROR_NULL_POINTER);
    auto device = libinput_event_get_device(event);
    CHKPR(device, PARAM_INPUT_INVALID);
    std::string name = libinput_device_get_name(device);
    if (name == FINGERPRINT_SOURCE_KEY) {
        return AnalyseKeyEvent(event);
    } else if (name == FINGERPRINT_SOURCE_POINT) {
        return AnalysePointEvent(event);
    } else {
        MMI_HILOGI("input device failed, name is %{public}s", name.c_str());
        return PARAM_INPUT_INVALID;
    }
}

int32_t FingerprintEventProcessor::AnalyseKeyEvent(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    struct libinput_event_keyboard* keyEvent = libinput_event_get_keyboard_event(event);
    CHKPR(keyEvent, ERROR_NULL_POINTER);
    auto key = libinput_event_keyboard_get_key(keyEvent);
    enum libinput_key_state state = libinput_event_keyboard_get_key_state(keyEvent);
    if (state == LIBINPUT_KEY_STATE_PRESSED) {
        MMI_HILOGI("dont analyse the press status for %{public}d", key);
        return ERR_OK;
    }
    auto pointerEvent = PointerEvent::Create();
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    switch (key) {
        case FINGERPRINT_CODE_DOWN: {
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_FINGERPRINT_DOWN);
            break;
        }
        case FINGERPRINT_CODE_UP: {
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_FINGERPRINT_UP);
            break;
        }
        case FINGERPRINT_CODE_RETOUCH: {
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_FINGERPRINT_RETOUCH);
            break;
        }
        case FINGERPRINT_CODE_CLICK: {
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_FINGERPRINT_CLICK);
            break;
        }
        default:
            MMI_HILOGW("unknown key event : %{public}d", key);
            return UNKNOWN_EVENT;
    }
    int64_t time = GetSysClockTime();
    pointerEvent->SetActionTime(time);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_FINGERPRINT);
    pointerEvent->SetPointerId(0);
    EventLogHelper::PrintEventData(pointerEvent);
    MMI_HILOGD("fingerprint key:%{public}d", pointerEvent->GetPointerAction());
    InputHandler->GetMonitorHandler()->OnHandleEvent(pointerEvent);
    return RET_OK;
}

int32_t FingerprintEventProcessor::AnalysePointEvent(libinput_event * event)
{
    CALL_DEBUG_ENTER;
    struct libinput_event_pointer* rawPointerEvent = libinput_event_get_pointer_event(event);
    CHKPR(rawPointerEvent, ERROR_NULL_POINTER);
    double ux = libinput_event_pointer_get_dx_unaccelerated(rawPointerEvent);
    double uy = libinput_event_pointer_get_dy_unaccelerated(rawPointerEvent);
    auto pointerEvent = PointerEvent::Create();
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    int64_t time = GetSysClockTime();
    pointerEvent->SetActionTime(time);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_FINGERPRINT_SLIDE);
    pointerEvent->SetFingerprintDistanceX(ux);
    pointerEvent->SetFingerprintDistanceY(uy);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_FINGERPRINT);
    pointerEvent->SetPointerId(0);
    EventLogHelper::PrintEventData(pointerEvent);
    MMI_HILOGD("fingerprint ux:%{public}f, uy:%{public}f", ux, uy);
    InputHandler->GetMonitorHandler()->OnHandleEvent(pointerEvent);
    return RET_OK;
}


#endif // OHOS_BUILD_ENABLE_FINGERPRINT
} // namespace MMI
} // namespace OHOS

/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "key_command_handler.h"

#include "ability_manager_client.h"
#include "bytrace_adapter.h"
#include "cJSON.h"
#include "config_policy_utils.h"
#include "file_ex.h"
#include "setting_datashare.h"
#include "system_ability_definition.h"

#include "define_multimodal.h"
#include "dfx_hisysevent.h"
#include "display_event_monitor.h"
#include "error_multimodal.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "input_windows_manager.h"
#include "key_command_handler_util.h"
#include "mmi_log.h"
#include "multimodal_input_preferences_manager.h"
#include "nap_process.h"
#include "net_packet.h"
#include "proto.h"
#include "stylus_key_handler.h"
#include "timer_manager.h"
#include "util_ex.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyCommandHandler"

namespace OHOS {
namespace MMI {
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void KeyCommandHandler::HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    if (OnHandleEvent(keyEvent)) {
        MMI_HILOGD("The keyEvent start launch an ability, keyCode:%{public}d", keyEvent->GetKeyCode());
        BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::KEY_LAUNCH_EVENT);
        return;
    }
    CHKPV(nextHandler_);
    nextHandler_->HandleKeyEvent(keyEvent);
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#ifdef OHOS_BUILD_ENABLE_POINTER
void KeyCommandHandler::HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    if (OnHandleEvent(pointerEvent)) {
        MMI_HILOGD("The pointerEvent start launch an ability, pointAction:%{public}s",
            pointerEvent->DumpPointerAction());
    }
    CHKPV(nextHandler_);
    nextHandler_->HandlePointerEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_TOUCH
void KeyCommandHandler::HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    CHKPV(nextHandler_);
    OnHandleTouchEvent(pointerEvent);
    if (isKnuckleState_) {
        MMI_HILOGD("current pointer event is knuckle");
        return;
    }
    nextHandler_->HandleTouchEvent(pointerEvent);
}

void KeyCommandHandler::OnHandleTouchEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
#ifdef OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
    STYLUS_HANDLER->SetLastEventState(false);
#endif // OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
    if (!isParseConfig_) {
        if (!ParseConfig()) {
            MMI_HILOGE("Parse configFile failed");
            return;
        }
        isParseConfig_ = true;
    }
    if (!isTimeConfig_) {
        SetKnuckleDoubleTapIntervalTime(DOUBLE_CLICK_INTERVAL_TIME_DEFAULT);
        isTimeConfig_ = true;
    }
    if (!isDistanceConfig_) {
        distanceDefaultConfig_ = DOUBLE_CLICK_DISTANCE_DEFAULT_CONFIG * VPR_CONFIG;
        distanceLongConfig_ = DOUBLE_CLICK_DISTANCE_LONG_CONFIG * VPR_CONFIG;
        SetKnuckleDoubleTapDistance(distanceDefaultConfig_);
        isDistanceConfig_ = true;
    }

    switch (touchEvent->GetPointerAction()) {
        case PointerEvent::POINTER_ACTION_CANCEL:
        case PointerEvent::POINTER_ACTION_UP: {
            HandlePointerActionUpEvent(touchEvent);
            break;
        }
        case PointerEvent::POINTER_ACTION_MOVE: {
            HandlePointerActionMoveEvent(touchEvent);
            break;
        }
        case PointerEvent::POINTER_ACTION_DOWN: {
            HandlePointerActionDownEvent(touchEvent);
            break;
        }
        default:
            // Don't care about other actions
            MMI_HILOGD("other action not match.");
            break;
    }
}

void KeyCommandHandler::HandlePointerActionDownEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    auto id = touchEvent->GetPointerId();
    PointerEvent::PointerItem item;
    touchEvent->GetPointerItem(id, item);
    int32_t toolType = item.GetToolType();
    MMI_HILOGD("Pointer tool type:%{public}d", toolType);
    singleKnuckleGesture_.state = false;
    doubleKnuckleGesture_.state = false;
    switch (toolType) {
        case PointerEvent::TOOL_TYPE_FINGER: {
            isKnuckleState_ = false;
            HandleFingerGestureDownEvent(touchEvent);
            break;
        }
        case PointerEvent::TOOL_TYPE_KNUCKLE: {
            DfxHisysevent::ReportKnuckleClickEvent();
            HandleKnuckleGestureDownEvent(touchEvent);
            break;
        }
        default: {
            // other tool type are not processed
            isKnuckleState_ = false;
            MMI_HILOGD("Current touch event tool type:%{public}d", toolType);
            break;
        }
    }
}

void KeyCommandHandler::HandlePointerActionMoveEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    if (!twoFingerGesture_.active) {
        return;
    }
    if (twoFingerGesture_.timerId == -1) {
        MMI_HILOGD("Two finger gesture timer id is -1.");
        return;
    }
    auto id = touchEvent->GetPointerId();
    auto pos = std::find_if(std::begin(twoFingerGesture_.touches), std::end(twoFingerGesture_.touches),
        [id](const auto& item) { return item.id == id; });
    if (pos == std::end(twoFingerGesture_.touches)) {
        return;
    }
    PointerEvent::PointerItem item;
    touchEvent->GetPointerItem(id, item);
    auto dx = std::abs(pos->x - item.GetDisplayX());
    auto dy = std::abs(pos->y - item.GetDisplayY());
    auto moveDistance = sqrt(pow(dx, 2) + pow(dy, 2));
    if (moveDistance > ConvertVPToPX(TOUCH_MAX_THRESHOLD)) {
        StopTwoFingerGesture();
    }
}

void KeyCommandHandler::HandlePointerActionUpEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    auto id = touchEvent->GetPointerId();
    PointerEvent::PointerItem item;
    touchEvent->GetPointerItem(id, item);
    int32_t toolType = item.GetToolType();
    switch (toolType) {
        case PointerEvent::TOOL_TYPE_FINGER: {
            HandleFingerGestureUpEvent(touchEvent);
            break;
        }
        case PointerEvent::TOOL_TYPE_KNUCKLE: {
            HandleKnuckleGestureUpEvent(touchEvent);
            break;
        }
        default: {
            // other tool type are not processed
            MMI_HILOGW("Current touch event tool type:%{public}d", toolType);
            break;
        }
    }
}

void KeyCommandHandler::HandleFingerGestureDownEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    if (!twoFingerGesture_.active) {
        MMI_HILOGD("Two finger gesture is not active");
        return;
    }
    auto num = touchEvent->GetPointerIds().size();
    if (num == TwoFingerGesture::MAX_TOUCH_NUM) {
        StartTwoFingerGesture();
    } else {
        StopTwoFingerGesture();
    }
    if (num > 0 && num <= TwoFingerGesture::MAX_TOUCH_NUM) {
        auto id = touchEvent->GetPointerId();
        PointerEvent::PointerItem item;
        touchEvent->GetPointerItem(id, item);
        twoFingerGesture_.touches[num - 1].id = id;
        twoFingerGesture_.touches[num - 1].x = item.GetDisplayX();
        twoFingerGesture_.touches[num - 1].y = item.GetDisplayY();
        twoFingerGesture_.touches[num - 1].downTime = item.GetDownTime();
    }
}

void KeyCommandHandler::HandleFingerGestureUpEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    if (!twoFingerGesture_.active) {
        MMI_HILOGD("Two finger gesture is not active");
        return;
    }
    StopTwoFingerGesture();
}

void KeyCommandHandler::HandleKnuckleGestureDownEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);

    auto id = touchEvent->GetPointerId();
    PointerEvent::PointerItem item;
    touchEvent->GetPointerItem(id, item);
    if (item.GetToolType() != PointerEvent::TOOL_TYPE_KNUCKLE) {
        MMI_HILOGW("Touch event tool type:%{public}d not knuckle", item.GetToolType());
        return;
    }
    size_t size = touchEvent->GetPointerIds().size();
    if (size == SINGLE_KNUCKLE_SIZE) {
        SingleKnuckleGestureProcesser(touchEvent);
        isDoubleClick_ = false;
        knuckleCount_++;
    } else if (size == DOUBLE_KNUCKLE_SIZE) {
        DoubleKnuckleGestureProcesser(touchEvent);
        isDoubleClick_ = true;
    } else {
        MMI_HILOGW("Other kunckle size not process, size:%{public}zu", size);
    }
}

void KeyCommandHandler::HandleKnuckleGestureUpEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    size_t size = touchEvent->GetPointerIds().size();
    if ((size == SINGLE_KNUCKLE_SIZE) && (!isDoubleClick_)) {
        singleKnuckleGesture_.lastPointerUpTime = touchEvent->GetActionTime();
    } else if (size == DOUBLE_KNUCKLE_SIZE) {
        doubleKnuckleGesture_.lastPointerUpTime = touchEvent->GetActionTime();
    } else {
        MMI_HILOGW("Other kunckle size not process, size:%{public}zu", size);
    }
}

void KeyCommandHandler::SingleKnuckleGestureProcesser(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    singleKnuckleGesture_.state = false;
    KnuckleGestureProcessor(touchEvent, singleKnuckleGesture_);
}

void KeyCommandHandler::DoubleKnuckleGestureProcesser(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    doubleKnuckleGesture_.state = false;
    KnuckleGestureProcessor(touchEvent, doubleKnuckleGesture_);
}

void KeyCommandHandler::KnuckleGestureProcessor(const std::shared_ptr<PointerEvent> touchEvent,
    KnuckleGesture &knuckleGesture)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    isKnuckleState_ = true;
    if (knuckleGesture.lastPointerDownEvent == nullptr) {
        MMI_HILOGI("knuckle gesture first down Event");
        knuckleGesture.lastPointerDownEvent = touchEvent;
        UpdateKnuckleGestureInfo(touchEvent, knuckleGesture);
        return;
    }
    int64_t intervalTime = touchEvent->GetActionTime() - knuckleGesture.lastPointerUpTime;
    bool isTimeIntervalReady = intervalTime > 0 && intervalTime <= downToPrevUpTimeConfig_;
    float downToPrevDownDistance = AbsDiff(knuckleGesture, touchEvent);
    bool isDistanceReady = downToPrevDownDistance < downToPrevDownDistanceConfig_;
    knuckleGesture.downToPrevUpTime = intervalTime;
    knuckleGesture.doubleClickDistance = downToPrevDownDistance;
    UpdateKnuckleGestureInfo(touchEvent, knuckleGesture);
    if (isTimeIntervalReady && isDistanceReady) {
        MMI_HILOGI("knuckle gesture start launch ability");
        knuckleCount_ = 0;
        DfxHisysevent::ReportSingleKnuckleDoubleClickEvent(intervalTime);
        LaunchAbility(knuckleGesture.ability, 0);
        knuckleGesture.state = true;
        ReportKnuckleScreenCapture(touchEvent);
    } else {
        if (knuckleCount_ > KNUCKLE_KNOCKS) {
            knuckleCount_ = 0;
            MMI_HILOGW("time ready:%{public}d, distance ready:%{public}d", isTimeIntervalReady, isDistanceReady);
            if (!isTimeIntervalReady) {
                DfxHisysevent::ReportFailIfInvalidTime(touchEvent, intervalTime);
            }
            if (!isDistanceReady) {
                DfxHisysevent::ReportFailIfInvalidDistance(touchEvent, downToPrevDownDistance);
            }
        }
    }
    AdjustTimeIntervalConfigIfNeed(intervalTime);
    AdjustDistanceConfigIfNeed(downToPrevDownDistance);
}

void KeyCommandHandler::UpdateKnuckleGestureInfo(const std::shared_ptr<PointerEvent> touchEvent,
    KnuckleGesture &knuckleGesture)
{
    auto id = touchEvent->GetPointerId();
    PointerEvent::PointerItem item;
    touchEvent->GetPointerItem(id, item);
    knuckleGesture.lastDownPointer.x = item.GetDisplayX();
    knuckleGesture.lastDownPointer.y = item.GetDisplayY();
    knuckleGesture.lastDownPointer.id = touchEvent->GetId();
}

void KeyCommandHandler::AdjustTimeIntervalConfigIfNeed(int64_t intervalTime)
{
    CALL_DEBUG_ENTER;
    int64_t newTimeConfig;
    MMI_HILOGI("down to prev up interval time:%{public}" PRId64 ",config time:%{public}" PRId64"",
        intervalTime, downToPrevUpTimeConfig_);
    if (downToPrevUpTimeConfig_ == DOUBLE_CLICK_INTERVAL_TIME_DEFAULT) {
        if (intervalTime < DOUBLE_CLICK_INTERVAL_TIME_DEFAULT || intervalTime > DOUBLE_CLICK_INTERVAL_TIME_SLOW) {
            return;
        }
        newTimeConfig = DOUBLE_CLICK_INTERVAL_TIME_SLOW;
    } else if (downToPrevUpTimeConfig_ == DOUBLE_CLICK_INTERVAL_TIME_SLOW) {
        if (intervalTime > DOUBLE_CLICK_INTERVAL_TIME_DEFAULT) {
            return;
        }
        newTimeConfig = DOUBLE_CLICK_INTERVAL_TIME_DEFAULT;
    } else {
        return;
    }
    checkAdjustIntervalTimeCount_++;
    if (checkAdjustIntervalTimeCount_ < MAX_TIME_FOR_ADJUST_CONFIG) {
        return;
    }
    MMI_HILOGI("adjust new double click interval time:%{public}" PRId64 "", newTimeConfig);
    downToPrevUpTimeConfig_ = newTimeConfig;
    checkAdjustIntervalTimeCount_ = 0;
}

void KeyCommandHandler::AdjustDistanceConfigIfNeed(float distance)
{
    CALL_DEBUG_ENTER;
    float newDistanceConfig;
    MMI_HILOGI("down to prev down distance:%{public}f, config distance:%{public}f",
        distance, downToPrevDownDistanceConfig_);
    if (IsEqual(downToPrevDownDistanceConfig_, distanceDefaultConfig_)) {
        if (distance < distanceDefaultConfig_ || distance > distanceLongConfig_) {
            return;
        }
        newDistanceConfig = distanceLongConfig_;
    } else if (IsEqual(downToPrevDownDistanceConfig_, distanceLongConfig_)) {
        if (distance > distanceDefaultConfig_) {
            return;
        }
        newDistanceConfig = distanceDefaultConfig_;
    } else {
        return;
    }
    checkAdjustDistanceCount_++;
    if (checkAdjustDistanceCount_ < MAX_TIME_FOR_ADJUST_CONFIG) {
        return;
    }
    MMI_HILOGI("adjust new double click distance:%{public}f", newDistanceConfig);
    downToPrevDownDistanceConfig_ = newDistanceConfig;
    checkAdjustDistanceCount_ = 0;
}

void KeyCommandHandler::ReportKnuckleDoubleClickEvent(const std::shared_ptr<PointerEvent> touchEvent,
    KnuckleGesture &knuckleGesture)
{
    CHKPV(touchEvent);
    size_t size = touchEvent->GetPointerIds().size();
    if (size == SINGLE_KNUCKLE_SIZE) {
        DfxHisysevent::ReportSingleKnuckleDoubleClickEvent(knuckleGesture.downToPrevUpTime);
        return;
    }
    MMI_HILOGW("current touch event size:%{public}zu", size);
}

void KeyCommandHandler::ReportKnuckleScreenCapture(const std::shared_ptr<PointerEvent> touchEvent)
{
    CHKPV(touchEvent);
    size_t size = touchEvent->GetPointerIds().size();
    if (size == SINGLE_KNUCKLE_SIZE) {
        DfxHisysevent::ReportScreenCaptureGesture();
        return;
    }
    MMI_HILOGW("current touch event size:%{public}zu", size);
}

void KeyCommandHandler::StartTwoFingerGesture()
{
    CALL_DEBUG_ENTER;
    twoFingerGesture_.timerId = TimerMgr->AddTimer(twoFingerGesture_.abilityStartDelay, 1, [this]() {
        twoFingerGesture_.timerId = -1;
        if (!CheckTwoFingerGestureAction()) {
            return;
        }
        twoFingerGesture_.ability.params.emplace("displayX1", std::to_string(twoFingerGesture_.touches[0].x));
        twoFingerGesture_.ability.params.emplace("displayY1", std::to_string(twoFingerGesture_.touches[0].y));
        twoFingerGesture_.ability.params.emplace("displayX2", std::to_string(twoFingerGesture_.touches[1].x));
        twoFingerGesture_.ability.params.emplace("displayY2", std::to_string(twoFingerGesture_.touches[1].y));
        MMI_HILOGI("Start launch ability immediately");
        LaunchAbility(twoFingerGesture_.ability, twoFingerGesture_.abilityStartDelay);
    });
}

void KeyCommandHandler::StopTwoFingerGesture()
{
    CALL_DEBUG_ENTER;
    if (twoFingerGesture_.timerId != -1) {
        TimerMgr->RemoveTimer(twoFingerGesture_.timerId);
        twoFingerGesture_.timerId = -1;
    }
}

bool KeyCommandHandler::CheckTwoFingerGestureAction() const
{
    if (!twoFingerGesture_.active) {
        return false;
    }

    auto firstFinger = twoFingerGesture_.touches[0];
    auto secondFinger = twoFingerGesture_.touches[1];

    auto pressTimeInterval = fabs(firstFinger.downTime - secondFinger.downTime);
    if (pressTimeInterval > TWO_FINGERS_TIME_LIMIT) {
        return false;
    }

    auto devX = firstFinger.x - secondFinger.x;
    auto devY = firstFinger.y - secondFinger.y;
    auto distance = sqrt(pow(devX, 2) + pow(devY, 2));
    if (distance < ConvertVPToPX(TWO_FINGERS_DISTANCE_LIMIT)) {
        MMI_HILOGI("two fingers distance:%{public}f too small", distance);
        return false;
    }

    auto displayInfo = WinMgr->GetDefaultDisplayInfo();
    CHKPR(displayInfo, false);
    auto leftLimit = ConvertVPToPX(TOUCH_LIFT_LIMIT);
    auto rightLimit = displayInfo->width - ConvertVPToPX(TOUCH_RIGHT_LIMIT);
    auto topLimit = ConvertVPToPX(TOUCH_TOP_LIMIT);
    auto bottomLimit = displayInfo->height - ConvertVPToPX(TOUCH_BOTTOM_LIMIT);
    if (firstFinger.x <= leftLimit || firstFinger.x >= rightLimit ||
        firstFinger.y <= topLimit || firstFinger.y >= bottomLimit ||
        secondFinger.x <= leftLimit || secondFinger.x >= rightLimit ||
        secondFinger.y <= topLimit || secondFinger.y >= bottomLimit) {
        MMI_HILOGI("any finger out of region");
        return false;
    }

    return true;
}

int32_t KeyCommandHandler::ConvertVPToPX(int32_t vp) const
{
    if (vp <= 0) {
        return 0;
    }
    auto displayInfo = WinMgr->GetDefaultDisplayInfo();
    CHKPR(displayInfo, 0);
    int32_t dpi = displayInfo->dpi;
    if (dpi <= 0) {
        return 0;
    }
    const int32_t base = 160;
    return vp * (dpi / base);
}

#endif // OHOS_BUILD_ENABLE_TOUCH

bool KeyCommandHandler::ParseConfig()
{
#ifndef UNIT_TEST
    const char *testPathSuffix = "/etc/multimodalinput/ability_launch_config.json";
#else
    const char *testPathSuffix = "/data/test/test.json";
#endif // UNIT_TEST
    char buf[MAX_PATH_LEN] = { 0 };
    char *filePath = GetOneCfgFile(testPathSuffix, buf, MAX_PATH_LEN);
#ifndef UNIT_TEST
    std::string defaultConfig = "/system/etc/multimodalinput/ability_launch_config.json";
#else
    std::string defaultConfig = "/data/test/test.json";
#endif // UNIT_TEST
    if (filePath == nullptr || filePath[0] == '\0' || strlen(filePath) > MAX_PATH_LEN) {
        MMI_HILOGD("Can not get customization config file");
        return ParseJson(defaultConfig);
    }
    std::string customConfig = filePath;
    MMI_HILOGD("The configuration file path is :%{public}s", customConfig.c_str());
    return ParseJson(customConfig) || ParseJson(defaultConfig);
}

bool KeyCommandHandler::ParseExcludeConfig()
{
#ifndef UNIT_TEST
    const char *testPathSuffix = "/etc/multimodalinput/exclude_keys_config.json";
#else
    const char *testPathSuffix = "/data/test/exclude_keys_config.json";
#endif // UNIT_TEST
    char buf[MAX_PATH_LEN] = { 0 };
    char *filePath = GetOneCfgFile(testPathSuffix, buf, MAX_PATH_LEN);
#ifndef UNIT_TEST
    std::string defaultConfig = "/system/etc/multimodalinput/exclude_keys_config.json";
#else
    std::string defaultConfig = "/data/test/exclude_keys_config.json";
#endif // UNIT_TEST
    if (filePath == nullptr || filePath[0] == '\0' || strlen(filePath) > MAX_PATH_LEN) {
        MMI_HILOGD("Can not get customization exclude_keys_config.json file");
        return ParseExcludeJson(defaultConfig);
    }
    std::string customConfig = filePath;
    MMI_HILOGD("The exclude_keys_config.json file path is :%{public}s", customConfig.c_str());
    return ParseExcludeJson(customConfig) || ParseExcludeJson(defaultConfig);
}

void KeyCommandHandler::ParseRepeatKeyMaxCount()
{
    if (repeatKeys_.empty()) {
        maxCount_ = 0;
    }
    int32_t tempCount = 0;
    for (RepeatKey& item : repeatKeys_) {
        if (item.times > tempCount) {
            tempCount = item.times;
        }
    }
    maxCount_ = tempCount;
}

bool KeyCommandHandler::ParseJson(const std::string &configFile)
{
    CALL_DEBUG_ENTER;
    std::string jsonStr = ReadJsonFile(configFile);
    if (jsonStr.empty()) {
        MMI_HILOGE("Read configFile failed");
        return false;
    }
    JsonParser parser;
    parser.json_ = cJSON_Parse(jsonStr.c_str());
    if (!cJSON_IsObject(parser.json_)) {
        MMI_HILOGE("Parser.json_ is not object");
        return false;
    }

    bool isParseShortKeys = ParseShortcutKeys(parser, shortcutKeys_, businessIds_);
    bool isParseSequences = ParseSequences(parser, sequences_);
    bool isParseTwoFingerGesture = ParseTwoFingerGesture(parser, twoFingerGesture_);
    bool isParseSingleKnuckleGesture = IsParseKnuckleGesture(parser, SINGLE_KNUCKLE_ABILITY, singleKnuckleGesture_);
    bool isParseDoubleKnuckleGesture = IsParseKnuckleGesture(parser, DOUBLE_KNUCKLE_ABILITY, doubleKnuckleGesture_);
    bool isParseMultiFingersTap = ParseMultiFingersTap(parser, TOUCHPAD_TRIP_TAP_ABILITY, threeFingersTap_);
    bool isParseRepeatKeys = ParseRepeatKeys(parser, repeatKeys_);
    if (!isParseShortKeys && !isParseSequences && !isParseTwoFingerGesture && !isParseSingleKnuckleGesture &&
        !isParseDoubleKnuckleGesture && !isParseMultiFingersTap && !isParseRepeatKeys) {
        MMI_HILOGE("Parse configFile failed");
        return false;
    }

    Print();
    PrintSeq();
    return true;
}

bool KeyCommandHandler::ParseExcludeJson(const std::string &configFile)
{
    CALL_DEBUG_ENTER;
    std::string jsonStr = ReadJsonFile(configFile);
    if (jsonStr.empty()) {
        MMI_HILOGE("Read excludeKey configFile failed");
        return false;
    }
    JsonParser parser;
    parser.json_ = cJSON_Parse(jsonStr.c_str());
    if (!cJSON_IsObject(parser.json_)) {
        MMI_HILOGE("Parser.json_ of excludeKey is not object");
        return false;
    }
    bool isParseExcludeKeys = ParseExcludeKeys(parser, excludeKeys_);
    if (!isParseExcludeKeys) {
        MMI_HILOGE("Parse ExcludeKeys configFile failed");
        return false;
    }
    PrintExcludeKeys();
    return true;
}

void KeyCommandHandler::Print()
{
    MMI_HILOGI("shortcutKey count:%{public}zu", shortcutKeys_.size());
    int32_t row = 0;
    for (const auto &item : shortcutKeys_) {
        MMI_HILOGI("row:%{public}d", row++);
        auto &shortcutKey = item.second;
        for (const auto &prekey : shortcutKey.preKeys) {
            MMI_HILOGI("preKey:%{public}d", prekey);
        }
        MMI_HILOGI("finalKey:%{public}d, keyDownDuration:%{public}d, triggerType:%{public}d,"
                   " bundleName:%{public}s, abilityName:%{public}s", shortcutKey.finalKey,
                   shortcutKey.keyDownDuration, shortcutKey.triggerType,
                   shortcutKey.ability.bundleName.c_str(), shortcutKey.ability.abilityName.c_str());
    }
}

void KeyCommandHandler::PrintExcludeKeys()
{
    size_t keysSize = excludeKeys_.size();
    for (size_t i = 0; i < keysSize; i++) {
        MMI_HILOGD("keyCode:%{public}d, keyAction:%{public}d, delay:%{public}" PRId64,
                   excludeKeys_[i].keyCode, excludeKeys_[i].keyAction, excludeKeys_[i].delay);
    }
}

void KeyCommandHandler::PrintSeq()
{
    MMI_HILOGI("sequences count:%{public}zu", sequences_.size());
    int32_t row = 0;
    for (const auto &item : sequences_) {
        MMI_HILOGI("row:%{public}d", row++);
        for (const auto& sequenceKey : item.sequenceKeys) {
            MMI_HILOGI("keyCode:%{public}d, keyAction:%{public}d, delay:%{public}" PRId64,
                       sequenceKey.keyCode, sequenceKey.keyAction, sequenceKey.delay);
        }
        MMI_HILOGI("bundleName:%{public}s, abilityName:%{public}s",
                   item.ability.bundleName.c_str(), item.ability.abilityName.c_str());
    }
}

bool KeyCommandHandler::IsExcludeKey(const std::shared_ptr<KeyEvent> key)
{
    size_t keysSize = excludeKeys_.size();
    for (size_t i = 0; i < keysSize; i++) {
        if (key->GetKeyCode() == excludeKeys_[i].keyCode) {
            if (key->GetKeyAction() == excludeKeys_[i].keyAction) {
                return true;
            }
        }
    }
    return false;
}

bool KeyCommandHandler::IsEnableCombineKey(const std::shared_ptr<KeyEvent> key)
{
    CHKPF(key);
    if (enableCombineKey_) {
        return true;
    }

    if (!isParseExcludeConfig_) {
        if (!ParseExcludeConfig()) {
            MMI_HILOGE("Parse Exclude configFile failed");
            return false;
        }
        isParseExcludeConfig_ = true;
    }

    if (IsExcludeKey(key)) {
        auto items = key->GetKeyItems();
        if (items.size() != 1) {
            return enableCombineKey_;
        }
        return true;
    }
    if (key->GetKeyCode() == KeyEvent::KEYCODE_L) {
        for (const auto &item : key->GetKeyItems()) {
            int32_t keyCode = item.GetKeyCode();
            if (keyCode != KeyEvent::KEYCODE_L && keyCode != KeyEvent::KEYCODE_META_LEFT &&
                keyCode != KeyEvent::KEYCODE_META_RIGHT) {
                return enableCombineKey_;
            }
        }
        return true;
    }
    return enableCombineKey_;
}

int32_t KeyCommandHandler::EnableCombineKey(bool enable)
{
    enableCombineKey_ = enable;
    MMI_HILOGI("Enable combineKey is successful in keyCommand handler, enable:%{public}d", enable);
    return RET_OK;
}

void KeyCommandHandler::ParseStatusConfigObserver()
{
    CALL_DEBUG_ENTER;
    for (Sequence& item : sequences_) {
        if (item.statusConfig.empty()) {
            continue;
        }
        CreateStatusConfigObserver<Sequence>(item);
    }

    for (auto& item : shortcutKeys_) {
        ShortcutKey &shortcutKey = item.second;
        if (shortcutKey.statusConfig.empty()) {
            continue;
        }
        CreateStatusConfigObserver<ShortcutKey>(shortcutKey);
    }
}

template <class T>
void KeyCommandHandler::CreateStatusConfigObserver(T& item)
{
    CALL_DEBUG_ENTER;
    SettingObserver::UpdateFunc updateFunc = [&item](const std::string& key) {
        bool statusValue = true;
        auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
            .GetBoolValue(key, statusValue);
        if (ret != RET_OK) {
            MMI_HILOGE("Get value from setting date fail");
            return;
        }
        MMI_HILOGI("Config changed key:%{public}s value:%{public}d", key.c_str(), statusValue);
        item.statusConfigValue = statusValue;
    };
    sptr<SettingObserver> statusObserver = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .CreateObserver(item.statusConfig, updateFunc);
    ErrCode ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).RegisterObserver(statusObserver);
    if (ret != ERR_OK) {
        MMI_HILOGE("register setting observer failed, ret=%{public}d", ret);
        statusObserver = nullptr;
    }
    bool configVlaue = true;
    ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .GetBoolValue(item.statusConfig, configVlaue);
    if (ret != RET_OK) {
        MMI_HILOGE("Get value from setting date fail");
        return;
    }
    MMI_HILOGI("Get value success key:%{public}s value:%{public}d", item.statusConfig.c_str(), configVlaue);
    item.statusConfigValue = configVlaue;
}

std::shared_ptr<KeyEvent> KeyCommandHandler::CreateKeyEvent(int32_t keyCode, int32_t keyAction, bool isPressed)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPP(keyEvent);
    KeyEvent::KeyItem item;
    item.SetKeyCode(keyCode);
    item.SetPressed(isPressed);
    keyEvent->SetKeyCode(keyCode);
    keyEvent->SetKeyAction(keyAction);
    keyEvent->AddPressedKeyItems(item);
    return keyEvent;
}

bool KeyCommandHandler::PreHandleEvent(const std::shared_ptr<KeyEvent> key)
{
    CHKPF(key);
    MMI_HILOGD("KeyEvent occured. keyCode:%{public}d, keyAction:%{public}d",
               key->GetKeyCode(), key->GetKeyAction());
    if (!IsEnableCombineKey(key)) {
        MMI_HILOGI("Combine key is taken over in key command");
        return false;
    }
    if (!isParseConfig_) {
        if (!ParseConfig()) {
            MMI_HILOGE("Parse configFile failed");
            return false;
        }
        isParseConfig_ = true;
    }
    if (!isParseMaxCount_) {
        ParseRepeatKeyMaxCount();
        isParseMaxCount_ = true;
        if (repeatKeys_.size() > 0) {
            intervalTime_ = repeatKeys_[0].delay;
        }
    }
    if (!isParseStatusConfig_) {
        ParseStatusConfigObserver();
        isParseStatusConfig_ = true;
    }
    return true;
}

bool KeyCommandHandler::HandleEvent(const std::shared_ptr<KeyEvent> key)
{
    CALL_DEBUG_ENTER;
    CHKPF(key);
    if (!PreHandleEvent(key)) {
        return false;
    }

#ifdef OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
    if (STYLUS_HANDLER->HandleStylusKey(key)) {
        return true;
    }
#endif // OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER

    bool isHandled = HandleShortKeys(key);
    isHandled = HandleSequences(key) || isHandled;
    if (isHandled) {
        if (isKeyCancel_) {
            isHandleSequence_ = false;
            isKeyCancel_ = false;
        } else {
            isHandleSequence_ = true;
        }
        return true;
    }
    if (!isDownStart_) {
        HandleRepeatKeys(key);
        return false;
    } else {
        bool isRepeatKeyHandle = HandleRepeatKeys(key);
        if (isRepeatKeyHandle) {
            return true;
        }
    }
    count_ = 0;
    isDownStart_ = false;
    return false;
}

bool KeyCommandHandler::OnHandleEvent(const std::shared_ptr<KeyEvent> key)
{
    CALL_DEBUG_ENTER;
    CHKPF(key);

    bool handleEventStatus = HandleEvent(key);
    if (handleEventStatus) {
        return true;
    }

    if (!specialKeys_.empty() && specialKeys_.find(key->GetKeyCode()) != specialKeys_.end()) {
        HandleSpecialKeys(key->GetKeyCode(), key->GetAction());
        return true;
    }

    if (IsSpecialType(key->GetKeyCode(), SpecialType::SUBSCRIBER_BEFORE_DELAY)) {
        auto tmpKey = KeyEvent::Clone(key);
        int32_t timerId = TimerMgr->AddTimer(SPECIAL_KEY_DOWN_DELAY, 1, [this, tmpKey] () {
            MMI_HILOGD("Timer callback");
            auto it = specialTimers_.find(tmpKey->GetKeyCode());
            if (it != specialTimers_.end() && !it->second.empty()) {
                it->second.pop_front();
            }
            InputHandler->GetSubscriberHandler()->HandleKeyEvent(tmpKey);
        });
        if (timerId < 0) {
            MMI_HILOGE("Add timer failed");
            return false;
        }

        auto it = specialTimers_.find(key->GetKeyCode());
        if (it == specialTimers_.end()) {
            std::list<int32_t> timerIds;
            timerIds.push_back(timerId);
            auto it = specialTimers_.emplace(key->GetKeyCode(), timerIds);
            if (!it.second) {
                MMI_HILOGE("Keycode duplicated");
                return false;
            }
        } else {
            it->second.push_back(timerId);
        }
        MMI_HILOGD("Add timer success");
        return true;
    }
    return false;
}

bool KeyCommandHandler::OnHandleEvent(const std::shared_ptr<PointerEvent> pointer)
{
    CALL_DEBUG_ENTER;
    CHKPF(pointer);
#ifdef OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
    STYLUS_HANDLER->SetLastEventState(false);
#endif // OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
    if (!isParseConfig_) {
        if (!ParseConfig()) {
            MMI_HILOGE("Parse configFile failed");
            return false;
        }
        isParseConfig_ = true;
    }
    bool isHandled = HandleMulFingersTap(pointer);
    if (isHandled) {
        return true;
    }
    return false;
}

bool KeyCommandHandler::HandleRepeatKeys(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (repeatKeys_.empty()) {
        MMI_HILOGD("No sequences configuration data");
        return false;
    }

    if (count_ > maxCount_) {
        return false;
    }

    bool isLaunched = false;
    bool waitRepeatKey = false;

    for (RepeatKey& item : repeatKeys_) {
        if (HandleKeyUpCancel(item, keyEvent)) {
            return false;
        }
        if (HandleRepeatKeyCount(item, keyEvent)) {
            break;
        }
    }

    for (RepeatKey& item : repeatKeys_) {
        bool isRepeatKey = HandleRepeatKey(item, isLaunched, keyEvent);
        if (isRepeatKey) {
            waitRepeatKey = true;
        }
    }

    return isLaunched || waitRepeatKey;
}

bool KeyCommandHandler::HandleRepeatKey(const RepeatKey &item, bool &isLaunched,
    const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);

    if (keyEvent->GetKeyCode() != item.keyCode) {
        return false;
    }
    if (count_ == item.times) {
        bool statusValue = true;
        auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
            .GetBoolValue(item.statusConfig, statusValue);
        if (ret != RET_OK) {
            MMI_HILOGE("Get value from setting date fail");
            return false;
        }
        if (!statusValue) {
            return false;
        }
        LaunchAbility(item.ability);
        launchAbilityCount_ = count_;
        isLaunched = true;
        isDownStart_ = false;
        auto keyEventCancel = std::make_shared<KeyEvent>(*keyEvent);
        keyEventCancel->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
        InputHandler->GetSubscriberHandler()->HandleKeyEvent(keyEventCancel);
    }
    return true;
}

bool KeyCommandHandler::HandleKeyUpCancel(const RepeatKey &item, const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (keyEvent->GetKeyCode() == item.keyCode && keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_CANCEL) {
        isKeyCancel_ = true;
        isDownStart_ = false;
        return true;
    }
    return false;
}

bool KeyCommandHandler::HandleRepeatKeyCount(const RepeatKey &item, const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);

    if (keyEvent->GetKeyCode() == item.keyCode && keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_UP) {
        if (repeatKey_.keyCode != item.keyCode) {
            std::vector<int32_t> pressedKeys = keyEvent->GetPressedKeys();

            if (pressedKeys.size() == 0) {
                count_ = 1;
            } else {
                count_ = 0;
            }
            repeatKey_.keyCode = item.keyCode;
        } else {
            count_++;
        }

        upActionTime_ = keyEvent->GetActionTime();
        repeatTimerId_ = TimerMgr->AddTimer(intervalTime_ / SECONDS_SYSTEM, 1, [this] () {
            SendKeyEvent();
        });
        if (repeatTimerId_ < 0) {
            return false;
        }
        repeatKey_.keyCode = item.keyCode;
        return true;
    }

    if (keyEvent->GetKeyCode() == item.keyCode && keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_DOWN) {
        repeatKey_.keyCode = item.keyCode;
        isDownStart_ = true;

        downActionTime_ = keyEvent->GetActionTime();
        if ((downActionTime_ - upActionTime_) < intervalTime_) {
            if (repeatTimerId_ >= 0) {
                TimerMgr->RemoveTimer(repeatTimerId_);
            }
        }
        return true;
    }
    return false;
}

void KeyCommandHandler::SendKeyEvent()
{
    CALL_DEBUG_ENTER;
    if (!isHandleSequence_) {
        for (int32_t i = launchAbilityCount_; i < count_; i++) {
            int32_t keycode = repeatKey_.keyCode;
            if (IsSpecialType(keycode, SpecialType::KEY_DOWN_ACTION)) {
                HandleSpecialKeys(keycode, KeyEvent::KEY_ACTION_UP);
            }
            if (i != 0) {
                auto keyEventDown = CreateKeyEvent(keycode, KeyEvent::KEY_ACTION_DOWN, true);
                CHKPV(keyEventDown);
                InputHandler->GetSubscriberHandler()->HandleKeyEvent(keyEventDown);
            }

            auto keyEventUp = CreateKeyEvent(keycode, KeyEvent::KEY_ACTION_UP, false);
            CHKPV(keyEventUp);
            InputHandler->GetSubscriberHandler()->HandleKeyEvent(keyEventUp);
        }
    }
    count_ = 0;
    isDownStart_ = false;
    isHandleSequence_ = false;
    launchAbilityCount_ = 0;
}

bool KeyCommandHandler::HandleShortKeys(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (shortcutKeys_.empty()) {
        MMI_HILOGD("No shortkeys configuration data");
        return false;
    }
    if (IsKeyMatch(lastMatchedKey_, keyEvent)) {
        MMI_HILOGD("The same key is waiting timeout, skip");
        return true;
    }
    if (currentLaunchAbilityKey_.timerId >= 0 && IsKeyMatch(currentLaunchAbilityKey_, keyEvent)) {
        MMI_HILOGD("repeat, current key %{public}d has launched ability", currentLaunchAbilityKey_.finalKey);
        return true;
    }
    DfxHisysevent::GetComboStartTime();
    if (lastMatchedKey_.timerId >= 0) {
        MMI_HILOGD("Remove timer:%{public}d", lastMatchedKey_.timerId);
        TimerMgr->RemoveTimer(lastMatchedKey_.timerId);
    }
    ResetLastMatchedKey();
    bool result = false;
    for (auto &item : shortcutKeys_) {
        ShortcutKey &shortcutKey = item.second;
        if (!shortcutKey.statusConfigValue) {
            continue;
        }
        if (!IsKeyMatch(shortcutKey, keyEvent)) {
            MMI_HILOGD("Not key matched, next");
            continue;
        }
        int32_t delay = GetKeyDownDurationFromXml(shortcutKey.businessId);
        if (delay >= MIN_SHORT_KEY_DOWN_DURATION && delay <= MAX_SHORT_KEY_DOWN_DURATION) {
            MMI_HILOGD("User defined new short key down duration:%{public}d", delay);
            shortcutKey.keyDownDuration = delay;
        }
        shortcutKey.Print();
        if (shortcutKey.triggerType == KeyEvent::KEY_ACTION_DOWN) {
            result = HandleKeyDown(shortcutKey) || result;
        } else if (shortcutKey.triggerType == KeyEvent::KEY_ACTION_UP) {
            result = HandleKeyUp(keyEvent, shortcutKey) || result;
        } else {
            result = HandleKeyCancel(shortcutKey) || result;
        }
    }
    if (result) {
        return result;
    }
    return HandleConsumedKeyEvent(keyEvent);
}

bool KeyCommandHandler::HandleConsumedKeyEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (currentLaunchAbilityKey_.finalKey == keyEvent->GetKeyCode()
        && keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_UP) {
        MMI_HILOGI("Handle consumed key event, cancel opration");
        ResetCurrentLaunchAbilityKey();
        auto keyEventCancel = std::make_shared<KeyEvent>(*keyEvent);
        keyEventCancel->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
        auto inputEventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
        CHKPF(inputEventNormalizeHandler);
        inputEventNormalizeHandler->HandleKeyEvent(keyEventCancel);
        return true;
    }
    return false;
}

bool KeyCommandHandler::IsRepeatKeyEvent(const SequenceKey &sequenceKey)
{
    for (size_t i = keys_.size(); i > 0; --i) {
        if (keys_[i-1].keyCode == sequenceKey.keyCode) {
            if (keys_[i-1].keyAction == sequenceKey.keyAction) {
                MMI_HILOGI("Is repeat key, keyCode:%{public}d", sequenceKey.keyCode);
                return true;
            }
            MMI_HILOGI("Is not repeat key");
            return false;
        }
    }
    return false;
}

bool KeyCommandHandler::HandleSequences(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (matchedSequence_.timerId >= 0) {
        MMI_HILOGD("Remove matchedSequence timer:%{public}d", matchedSequence_.timerId);
        TimerMgr->RemoveTimer(matchedSequence_.timerId);
        matchedSequence_.timerId = -1;
    }
    if (sequences_.empty()) {
        MMI_HILOGD("No sequences configuration data");
        return false;
    }

    if (!AddSequenceKey(keyEvent)) {
        MMI_HILOGD("Add new sequence key failed");
        return false;
    }

    if (filterSequences_.empty()) {
        filterSequences_ = sequences_;
    }

    bool isLaunchAbility = false;
    for (auto iter = filterSequences_.begin(); iter != filterSequences_.end();) {
        if (!HandleSequence((*iter), isLaunchAbility)) {
            filterSequences_.erase(iter);
            continue;
        }
        ++iter;
    }

    if (filterSequences_.empty()) {
        MMI_HILOGW("no sequences matched");
        keys_.clear();
        return false;
    }

    if (isLaunchAbility) {
        for (const auto& item : keys_) {
            if (IsSpecialType(item.keyCode, SpecialType::KEY_DOWN_ACTION)) {
                HandleSpecialKeys(item.keyCode, item.keyAction);
            }
            InputHandler->GetSubscriberHandler()->RemoveSubscriberKeyUpTimer(item.keyCode);
            RemoveSubscribedTimer(item.keyCode);
        }
    }
    return isLaunchAbility;
}

bool KeyCommandHandler::AddSequenceKey(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    SequenceKey sequenceKey;
    sequenceKey.keyCode = keyEvent->GetKeyCode();
    sequenceKey.keyAction = keyEvent->GetKeyAction();
    sequenceKey.actionTime = keyEvent->GetActionTime();
    size_t size = keys_.size();
    if (size > 0) {
        if (keys_[size - 1].actionTime > sequenceKey.actionTime) {
            MMI_HILOGE("The current event time is greater than the last event time");
            ResetSequenceKeys();
            return false;
        }
        if ((sequenceKey.actionTime - keys_[size - 1].actionTime) > MAX_DELAY_TIME) {
            MMI_HILOGD("The delay time is greater than the maximum delay time");
            ResetSequenceKeys();
        } else {
            if (IsRepeatKeyEvent(sequenceKey)) {
                MMI_HILOGD("This is a repeat key event, don't add");
                return false;
            }
            keys_[size - 1].delay = sequenceKey.actionTime - keys_[size - 1].actionTime;
            InterruptTimers();
        }
    }
    if (size > MAX_SEQUENCEKEYS_NUM) {
        MMI_HILOGD("The save key size more than the max size");
        return false;
    }
    keys_.push_back(sequenceKey);
    return true;
}

bool KeyCommandHandler::HandleScreenLocked(Sequence& sequence, bool &isLaunchAbility)
{
    sequence.timerId = TimerMgr->AddTimer(LONG_ABILITY_START_DELAY, 1, [this, sequence] () {
        MMI_HILOGI("Timer callback");
        LaunchAbility(sequence);
    });
    if (sequence.timerId < 0) {
        MMI_HILOGE("Add Timer failed");
        return false;
    }
    MMI_HILOGI("Add timer success");
    matchedSequence_ = sequence;
    isLaunchAbility = true;
    return true;
}

bool KeyCommandHandler::HandleNormalSequence(Sequence& sequence, bool &isLaunchAbility)
{
    if (sequence.abilityStartDelay == 0) {
        MMI_HILOGI("Start launch ability immediately");
        LaunchAbility(sequence);
        isLaunchAbility = true;
        return true;
    }
    sequence.timerId = TimerMgr->AddTimer(sequence.abilityStartDelay, 1, [this, sequence] () {
        MMI_HILOGI("Timer callback");
        LaunchAbility(sequence);
    });
    if (sequence.timerId < 0) {
        MMI_HILOGE("Add Timer failed");
        return false;
    }
    MMI_HILOGI("Add timer success");
    isLaunchAbility = true;
    return true;
}

bool KeyCommandHandler::HandleSequence(Sequence &sequence, bool &isLaunchAbility)
{
    CALL_DEBUG_ENTER;
    size_t keysSize = keys_.size();
    size_t sequenceKeysSize = sequence.sequenceKeys.size();

    if (!sequence.statusConfigValue) {
        return false;
    }

    if (keysSize > sequenceKeysSize) {
        MMI_HILOGI("The save sequence not matching ability sequence");
        return false;
    }

    for (size_t i = 0; i < keysSize; ++i) {
        if (keys_[i] != sequence.sequenceKeys[i]) {
            MMI_HILOGI("The keyCode or keyAction not matching");
            return false;
        }
        int64_t delay = sequence.sequenceKeys[i].delay;
        if (((i + 1) != keysSize) && (delay != 0) && (keys_[i].delay >= delay)) {
            MMI_HILOGI("Delay is not matching");
            return false;
        }
    }

    if (keysSize == sequenceKeysSize) {
        std::string screenStatus = DISPLAY_MONITOR->GetScreenStatus();
        MMI_HILOGD("screenStatus: %{public}s", screenStatus.c_str());
        if (sequence.ability.bundleName == "com.ohos.screenshot" &&
            screenStatus == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF) {
            MMI_HILOGI("screen off, com.ohos.screenshot invalid");
            return false;
        }
        if (sequence.ability.bundleName == "com.ohos.screenshot" &&
            screenStatus == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED) {
            MMI_HILOGI("screen locked, com.ohos.screenshot delay 2000 milisecond");
            return HandleScreenLocked(sequence, isLaunchAbility);
        }
        return HandleNormalSequence(sequence, isLaunchAbility);
    }
    return true;
}

bool KeyCommandHandler::HandleMulFingersTap(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_TRIPTAP) {
        MMI_HILOGI("The touchpad trip tap will launch ability");
        LaunchAbility(threeFingersTap_.ability, 0);
        return true;
    }
    return false;
}

bool KeyCommandHandler::IsKeyMatch(const ShortcutKey &shortcutKey, const std::shared_ptr<KeyEvent> &key)
{
    CALL_DEBUG_ENTER;
    CHKPF(key);
    if ((key->GetKeyCode() != shortcutKey.finalKey) || (shortcutKey.triggerType != key->GetKeyAction())) {
        return false;
    }
    if ((shortcutKey.preKeys.size() + 1) != key->GetKeyItems().size()) {
        return false;
    }
    for (const auto &item : key->GetKeyItems()) {
        int32_t keyCode = item.GetKeyCode();
        if (SkipFinalKey(keyCode, key)) {
            continue;
        }
        if (shortcutKey.preKeys.find(keyCode) == shortcutKey.preKeys.end()) {
            return false;
        }
    }
    MMI_HILOGD("Leave, key matched");
    return true;
}

bool KeyCommandHandler::SkipFinalKey(const int32_t keyCode, const std::shared_ptr<KeyEvent> &key)
{
    CHKPF(key);
    return keyCode == key->GetKeyCode();
}

bool KeyCommandHandler::HandleKeyDown(ShortcutKey &shortcutKey)
{
    CALL_DEBUG_ENTER;
    if (shortcutKey.keyDownDuration == 0) {
        MMI_HILOGI("Start launch ability immediately");
        LaunchAbility(shortcutKey);
        return true;
    }
    shortcutKey.timerId = TimerMgr->AddTimer(shortcutKey.keyDownDuration, 1, [this, shortcutKey] () {
        MMI_HILOGI("Timer callback");
        currentLaunchAbilityKey_ = shortcutKey;
        LaunchAbility(shortcutKey);
    });
    if (shortcutKey.timerId < 0) {
        MMI_HILOGE("Add Timer failed");
        return false;
    }
    MMI_HILOGI("Add timer success");
    lastMatchedKey_ = shortcutKey;
    if (InputHandler->GetSubscriberHandler()->IsKeyEventSubscribed(shortcutKey.finalKey, shortcutKey.triggerType)) {
        MMI_HILOGI("current shortcutKey %{public}d is subSubcribed", shortcutKey.finalKey);
        return false;
    }
    return true;
}

int32_t KeyCommandHandler::GetKeyDownDurationFromXml(const std::string &businessId)
{
    CALL_DEBUG_ENTER;
    return PREFERENCES_MGR->GetShortKeyDuration(businessId);
}

bool KeyCommandHandler::HandleKeyUp(const std::shared_ptr<KeyEvent> &keyEvent, const ShortcutKey &shortcutKey)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (shortcutKey.keyDownDuration == 0) {
        MMI_HILOGI("Start launch ability immediately");
        LaunchAbility(shortcutKey);
        return true;
    }
    std::optional<KeyEvent::KeyItem> keyItem = keyEvent->GetKeyItem();
    if (!keyItem) {
        MMI_HILOGE("The keyItem is nullopt");
        return false;
    }
    auto upTime = keyEvent->GetActionTime();
    auto downTime = keyItem->GetDownTime();
    MMI_HILOGI("upTime:%{public}" PRId64 ",downTime:%{public}" PRId64 ",keyDownDuration:%{public}d",
        upTime, downTime, shortcutKey.keyDownDuration);
    if (upTime - downTime >= static_cast<int64_t>(shortcutKey.keyDownDuration) * 1000) {
        MMI_HILOGI("Skip, upTime - downTime >= duration");
        return false;
    }
    MMI_HILOGI("Start launch ability immediately");
    LaunchAbility(shortcutKey);
    return true;
}

bool KeyCommandHandler::HandleKeyCancel(ShortcutKey &shortcutKey)
{
    CALL_DEBUG_ENTER;
    if (shortcutKey.timerId < 0) {
        MMI_HILOGE("Skip, timerid less than 0");
    }
    auto timerId = shortcutKey.timerId;
    shortcutKey.timerId = -1;
    TimerMgr->RemoveTimer(timerId);
    MMI_HILOGI("timerId:%{public}d", timerId);
    return false;
}

void KeyCommandHandler::LaunchAbility(const Ability &ability, int64_t delay)
{
    CALL_DEBUG_ENTER;
    if (ability.bundleName.empty()) {
        MMI_HILOGW("BundleName is empty");
        return;
    }
    AAFwk::Want want;
    want.SetElementName(ability.deviceId, ability.bundleName, ability.abilityName);
    want.SetAction(ability.action);
    want.SetUri(ability.uri);
    want.SetType(ability.type);
    for (const auto &entity : ability.entities) {
        want.AddEntity(entity);
    }
    for (const auto &item : ability.params) {
        want.SetParam(item.first, item.second);
    }
    DfxHisysevent::CalcComboStartTimes(delay);
    DfxHisysevent::ReportComboStartTimes();
    MMI_HILOGI("Start launch ability, bundleName:%{public}s", ability.bundleName.c_str());
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
    if (err != ERR_OK) {
        MMI_HILOGE("LaunchAbility failed, bundleName:%{public}s, err:%{public}d", ability.bundleName.c_str(), err);
    }
    int32_t state = NapProcess::GetInstance()->GetNapClientPid();
    if (state == REMOVE_OBSERVER) {
        MMI_HILOGW("nap client status:%{public}d", state);
        return;
    }
    OHOS::MMI::NapProcess::NapStatusData napData;
    napData.pid = -1;
    napData.uid = -1;
    napData.bundleName = ability.bundleName;
    int32_t syncState = ACTIVE_EVENT;
    NapProcess::GetInstance()->AddMmiSubscribedEventData(napData, syncState);
    NapProcess::GetInstance()->NotifyBundleName(napData, syncState);
    MMI_HILOGI("End launch ability, bundleName:%{public}s", ability.bundleName.c_str());
}

void KeyCommandHandler::LaunchAbility(const Ability &ability)
{
    CALL_DEBUG_ENTER;
    AAFwk::Want want;
    want.SetElementName(ability.deviceId, ability.bundleName, ability.abilityName);
    want.SetAction(ability.action);
    want.SetUri(ability.uri);
    want.SetType(ability.uri);
    for (const auto &entity : ability.entities) {
        want.AddEntity(entity);
    }
    for (const auto &item : ability.params) {
        want.SetParam(item.first, item.second);
    }

    MMI_HILOGI("Start launch ability, bundleName:%{public}s", ability.bundleName.c_str());
    if (ability.abilityType == EXTENSION_ABILITY) {
        ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartExtensionAbility(want, nullptr);
        if (err != ERR_OK) {
            MMI_HILOGE("LaunchAbility failed, bundleName:%{public}s, err:%{public}d", ability.bundleName.c_str(), err);
        }
    } else {
        ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
        if (err != ERR_OK) {
            MMI_HILOGE("LaunchAbility failed, bundleName:%{public}s, err:%{public}d", ability.bundleName.c_str(), err);
        }
    }

    MMI_HILOGI("End launch ability, bundleName:%{public}s", ability.bundleName.c_str());
}

void KeyCommandHandler::LaunchAbility(const ShortcutKey &key)
{
    CALL_INFO_TRACE;
    LaunchAbility(key.ability, lastMatchedKey_.keyDownDuration);
    ResetLastMatchedKey();
}

void KeyCommandHandler::LaunchAbility(const Sequence &sequence)
{
    CALL_INFO_TRACE;
    LaunchAbility(sequence.ability, sequence.abilityStartDelay);
}

void ShortcutKey::Print() const
{
    for (const auto &prekey: preKeys) {
        MMI_HILOGI("Eventkey matched, preKey:%{public}d", prekey);
    }
    MMI_HILOGI("Eventkey matched, finalKey:%{public}d, bundleName:%{public}s",
        finalKey, ability.bundleName.c_str());
}

void KeyCommandHandler::RemoveSubscribedTimer(int32_t keyCode)
{
    CALL_DEBUG_ENTER;
    auto iter = specialTimers_.find(keyCode);
    if (iter != specialTimers_.end()) {
        for (auto& item : iter->second) {
            TimerMgr->RemoveTimer(item);
        }
        specialTimers_.erase(keyCode);
        MMI_HILOGI("Remove timer success");
    }
}

void KeyCommandHandler::HandleSpecialKeys(int32_t keyCode, int32_t keyAction)
{
    CALL_DEBUG_ENTER;
    auto iter = specialKeys_.find(keyCode);
    if (keyAction == KeyEvent::KEY_ACTION_UP) {
        if (iter != specialKeys_.end()) {
            specialKeys_.erase(iter);
            return;
        }
    }

    if (keyAction == KeyEvent::KEY_ACTION_DOWN) {
        if (iter == specialKeys_.end()) {
            auto it = specialKeys_.emplace(keyCode, keyAction);
            if (!it.second) {
                MMI_HILOGD("KeyCode duplicated");
                return;
            }
        }
    }
}

void KeyCommandHandler::InterruptTimers()
{
    for (Sequence& item : filterSequences_) {
        if (item.timerId >= 0) {
            MMI_HILOGD("The key sequence change, close the timer");
            TimerMgr->RemoveTimer(item.timerId);
            item.timerId = -1;
        }
    }
}

int32_t KeyCommandHandler::UpdateSettingsXml(const std::string &businessId, int32_t delay)
{
    CALL_DEBUG_ENTER;
    if (businessId.empty() || businessIds_.empty()) {
        MMI_HILOGE("businessId or businessIds_ is empty");
        return COMMON_PARAMETER_ERROR;
    }
    if (std::find(businessIds_.begin(), businessIds_.end(), businessId) == businessIds_.end()) {
        MMI_HILOGE("%{public}s not in the config file", businessId.c_str());
        return COMMON_PARAMETER_ERROR;
    }
    if (delay < MIN_SHORT_KEY_DOWN_DURATION || delay > MAX_SHORT_KEY_DOWN_DURATION) {
        MMI_HILOGE("delay is not in valid range.");
        return COMMON_PARAMETER_ERROR;
    }
    return PREFERENCES_MGR->SetShortKeyDuration(businessId, delay);
}

KnuckleGesture KeyCommandHandler::GetSingleKnuckleGesture()
{
    return singleKnuckleGesture_;
}
KnuckleGesture KeyCommandHandler::GetDoubleKnuckleGesture()
{
    return doubleKnuckleGesture_;
}
void KeyCommandHandler::SetKnuckleDoubleTapIntervalTime(int64_t interval)
{
    CALL_DEBUG_ENTER;
    if (interval < 0) {
        MMI_HILOGE("invalid interval time:%{public}" PRId64 "", interval);
        return;
    }
    downToPrevUpTimeConfig_ = interval;
}
void KeyCommandHandler::SetKnuckleDoubleTapDistance(float distance)
{
    CALL_DEBUG_ENTER;
    if (distance <= std::numeric_limits<float>::epsilon()) {
        MMI_HILOGE("invalid distance:%{public}f", distance);
        return;
    }
    downToPrevDownDistanceConfig_ = distance;
}
} // namespace MMI
} // namespace OHOS
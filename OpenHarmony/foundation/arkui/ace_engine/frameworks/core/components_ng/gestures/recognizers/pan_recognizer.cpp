/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "core/components_ng/gestures/recognizers/pan_recognizer.h"

#include "base/geometry/offset.h"
#include "base/log/log.h"
#include "base/log/log_wrapper.h"
#include "base/ressched/ressched_report.h"
#include "base/utils/utils.h"
#include "core/components_ng/gestures/base_gesture_event.h"
#include "core/components_ng/gestures/gesture_referee.h"
#include "core/components_ng/gestures/recognizers/gesture_recognizer.h"
#include "core/components_ng/gestures/recognizers/multi_fingers_recognizer.h"
#include "core/event/axis_event.h"
#include "core/pipeline_ng/pipeline_context.h"

namespace OHOS::Ace::NG {

namespace {

constexpr int32_t MAX_PAN_FINGERS = 10;
constexpr int32_t DEFAULT_PAN_FINGERS = 1;
constexpr int32_t AXIS_PAN_FINGERS = 1;

} // namespace

void PanRecognizer::ForceCleanRecognizer()
{
    MultiFingersRecognizer::ForceCleanRecognizer();
    OnResetStatus();
}

PanRecognizer::PanRecognizer(int32_t fingers, const PanDirection& direction, double distance)
    : MultiFingersRecognizer(fingers), direction_(direction), distance_(distance), mouseDistance_(distance),
      newFingers_(fingers_), newDistance_(distance_), newDirection_(direction_)
{
    panVelocity_.SetDirection(direction_.type);
    if (fingers_ > MAX_PAN_FINGERS || fingers_ < DEFAULT_PAN_FINGERS) {
        fingers_ = DEFAULT_PAN_FINGERS;
    }
}

RefPtr<Gesture> PanRecognizer::CreateGestureFromRecognizer() const
{
    return AceType::MakeRefPtr<PanGesture>(fingers_, direction_, distance_);
}

PanRecognizer::PanRecognizer(const RefPtr<PanGestureOption>& panGestureOption) : panGestureOption_(panGestureOption)
{
    auto context = PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(context);
    uint32_t directNum = panGestureOption->GetDirection().type;
    double distanceNumber = panGestureOption->GetDistance();
    int32_t fingersNumber = panGestureOption->GetFingers();

    distance_ = LessNotEqual(distanceNumber, 0.0) ? DEFAULT_PAN_DISTANCE.ConvertToPx() : distanceNumber;
    fingers_ = fingersNumber;
    if (fingers_ > MAX_PAN_FINGERS || fingers_ < DEFAULT_PAN_FINGERS) {
        fingers_ = DEFAULT_PAN_FINGERS;
    }

    if (directNum >= PanDirection::NONE && directNum <= PanDirection::ALL) {
        direction_.type = directNum;
    }

    newFingers_ = fingers_;
    newDistance_ = distance_;
    mouseDistance_ = distance_;
    newDirection_ = direction_;

    PanFingersFuncType changeFingers = [weak = AceType::WeakClaim(this)](int32_t fingers) {
        auto panRecognizer = weak.Upgrade();
        CHECK_NULL_VOID(panRecognizer);
        panRecognizer->ChangeFingers(fingers);
    };
    onChangeFingers_ = OnPanFingersFunc(changeFingers);
    panGestureOption_->SetOnPanFingersId(onChangeFingers_);

    PanDirectionFuncType changeDirection = [weak = AceType::WeakClaim(this)](const PanDirection& direction) {
        auto panRecognizer = weak.Upgrade();
        CHECK_NULL_VOID(panRecognizer);
        panRecognizer->ChangeDirection(direction);
    };
    onChangeDirection_ = OnPanDirectionFunc(changeDirection);
    panGestureOption_->SetOnPanDirectionId(onChangeDirection_);

    PanDistanceFuncType changeDistance = [weak = AceType::WeakClaim(this)](double distance) {
        auto panRecognizer = weak.Upgrade();
        CHECK_NULL_VOID(panRecognizer);
        panRecognizer->ChangeDistance(distance);
    };
    onChangeDistance_ = OnPanDistanceFunc(changeDistance);
    panGestureOption_->SetOnPanDistanceId(onChangeDistance_);
}

inline void ReportSlideOn()
{
#ifdef OHOS_PLATFORM
    ResSchedReport::GetInstance().ResSchedDataReport("slide_on");
#endif
}

inline void ReportSlideOff()
{
#ifdef OHOS_PLATFORM
    ResSchedReport::GetInstance().ResSchedDataReport("slide_off");
#endif
}

void PanRecognizer::OnAccepted()
{
    int64_t acceptTime = GetSysTimestamp();
    int64_t inputTime = acceptTime;
    if (firstInputTime_.has_value()) {
        inputTime = static_cast<int64_t>(firstInputTime_.value().time_since_epoch().count());
    }
    if (SystemProperties::GetTraceInputEventEnabled()) {
        ACE_SCOPED_TRACE("UserEvent InputTime:%lld AcceptTime:%lld InputType:PanGesture",
            static_cast<long long>(inputTime), static_cast<long long>(acceptTime));
    }

    auto node = GetAttachedNode().Upgrade();
    TAG_LOGI(AceLogTag::ACE_GESTURE, "Pan gesture has been accepted, node tag = %{public}s, id = %{public}s",
        node ? node->GetTag().c_str() : "null", node ? std::to_string(node->GetId()).c_str() : "invalid");
    refereeState_ = RefereeState::SUCCEED;
    ReportSlideOn();
    SendCallbackMsg(onActionStart_);
    SendCallbackMsg(onActionUpdate_);
}

void PanRecognizer::OnRejected()
{
    // fix griditem drag interrupted by click while pull moving
    if (refereeState_ != RefereeState::SUCCEED) {
        refereeState_ = RefereeState::FAIL;
    }
    firstInputTime_.reset();
}

void PanRecognizer::UpdateTouchPointInVelocityTracker(const TouchEvent& event, bool end)
{
    PointF windowPoint(event.x, event.y);
    NGGestureRecognizer::Transform(windowPoint, GetAttachedNode(), false,
        isPostEventResult_, event.postEventNodeId);

    TouchEvent transformEvent = event;
    transformEvent.x = windowPoint.GetX();
    transformEvent.y = windowPoint.GetY();
    panVelocity_.UpdateTouchPoint(event.id, transformEvent, end);
}

void PanRecognizer::UpdateAxisPointInVelocityTracker(const AxisEvent& event, bool end)
{
    auto pesudoTouchEvent = TouchEvent();
    pesudoTouchEvent.time = event.time;
    auto revertAxisValue = event.ConvertToSummationAxisValue(lastAxisEvent_);
    pesudoTouchEvent.x = revertAxisValue.first;
    pesudoTouchEvent.y = revertAxisValue.second;
    panVelocity_.UpdateTouchPoint(event.id, pesudoTouchEvent, end);
    lastAxisEvent_ = event;
    if (!end) {
        lastAxisEvent_.horizontalAxis = pesudoTouchEvent.x;
        lastAxisEvent_.verticalAxis = pesudoTouchEvent.y;
    }
}

void PanRecognizer::HandleTouchDownEvent(const TouchEvent& event)
{
    if (!firstInputTime_.has_value()) {
        firstInputTime_ = event.time;
    }

    TAG_LOGI(AceLogTag::ACE_GESTURE,
        "InputTracking id:%{public}d, pan recognizer receives %{public}d touch down event, begin to detect pan event",
        event.touchEventId, event.id);
    fingers_ = newFingers_;
    distance_ = newDistance_;
    direction_ = newDirection_;

    if (direction_.type == PanDirection::NONE) {
        auto node = GetAttachedNode().Upgrade();
        TAG_LOGI(AceLogTag::ACE_GESTURE, "Pan recognizer direction is none, node tag = %{public}s, id = %{public}s",
            node ? node->GetTag().c_str() : "null", node ? std::to_string(node->GetId()).c_str() : "invalid");
        Adjudicate(Claim(this), GestureDisposal::REJECT);
        return;
    }
    if (event.sourceType == SourceType::MOUSE && !isAllowMouse_) {
        Adjudicate(Claim(this), GestureDisposal::REJECT);
        return;
    }
    if (!IsInAttachedNode(event)) {
        Adjudicate(Claim(this), GestureDisposal::REJECT);
        return;
    }

    if (fingersId_.find(event.id) == fingersId_.end()) {
        fingersId_.insert(event.id);
    }

    deviceId_ = event.deviceId;
    deviceType_ = event.sourceType;
    lastTouchEvent_ = event;
    touchPoints_[event.id] = event;
    touchPointsDistance_[event.id] = Offset(0.0, 0.0);

    auto fingerNum = static_cast<int32_t>(touchPoints_.size());

    if (fingerNum >= fingers_) {
        if (refereeState_ == RefereeState::READY) {
            panVelocity_.Reset(event.id);
            UpdateTouchPointInVelocityTracker(event);
            refereeState_ = RefereeState::DETECTING;
        } else {
            TAG_LOGI(AceLogTag::ACE_GESTURE, "Pan gesture refereeState is not READY");
        }
    }
}

void PanRecognizer::HandleTouchDownEvent(const AxisEvent& event)
{
    if (!firstInputTime_.has_value()) {
        firstInputTime_ = event.time;
    }
    if (event.isRotationEvent) {
        return;
    }
    TAG_LOGI(AceLogTag::ACE_GESTURE,
        "InputTracking id:%{public}d, pan recognizer receives axis start event, begin to detect pan event",
        event.touchEventId);
    fingers_ = newFingers_;
    distance_ = newDistance_;
    direction_ = newDirection_;

    if (fingers_ != AXIS_PAN_FINGERS) {
        Adjudicate(Claim(this), GestureDisposal::REJECT);
        return;
    }

    if (direction_.type == PanDirection::NONE) {
        Adjudicate(Claim(this), GestureDisposal::REJECT);
        return;
    }

    touchPoints_[event.id] = TouchEvent();
    UpdateTouchPointWithAxisEvent(event);
    deviceId_ = event.deviceId;
    deviceType_ = event.sourceType;
    lastAxisEvent_ = event;

    panVelocity_.Reset(event.id);
    auto pesudoTouchEvent = TouchEvent();
    pesudoTouchEvent.time = event.time;
    auto revertAxisValue = event.ConvertToSummationAxisValue(lastAxisEvent_);
    pesudoTouchEvent.x = revertAxisValue.first;
    pesudoTouchEvent.y = revertAxisValue.second;
    panVelocity_.UpdateTouchPoint(event.id, pesudoTouchEvent, false);
    refereeState_ = RefereeState::DETECTING;
}

void PanRecognizer::HandleTouchUpEvent(const TouchEvent& event)
{
    TAG_LOGI(AceLogTag::ACE_GESTURE, "InputTracking id:%{public}d, pan recognizer receives %{public}d touch up event",
        event.touchEventId, event.id);
    if (currentFingers_ < fingers_) {
        return;
    }
    if (fingersId_.find(event.id) != fingersId_.end()) {
        fingersId_.erase(event.id);
    }
    globalPoint_ = Point(event.x, event.y);
    lastTouchEvent_ = event;
    time_ = event.time;

    if (static_cast<int32_t>(touchPoints_.size()) == fingers_) {
        UpdateTouchPointInVelocityTracker(event, true);
    } else if (static_cast<int32_t>(touchPoints_.size()) > fingers_) {
        panVelocity_.Reset(event.id);
        UpdateTouchPointInVelocityTracker(event, true);
    }

    if ((currentFingers_ <= fingers_) &&
        (refereeState_ != RefereeState::SUCCEED) && (refereeState_ != RefereeState::FAIL)) {
        Adjudicate(AceType::Claim(this), GestureDisposal::REJECT);
        if (isForDrag_ && onActionCancel_ && *onActionCancel_) {
            (*onActionCancel_)();
        }
        return;
    }

    if (refereeState_ == RefereeState::SUCCEED) {
        if (currentFingers_  == fingers_) {
            // last one to fire end.
            SendCallbackMsg(onActionEnd_);
            ReportSlideOff();
            averageDistance_.Reset();
            AddOverTimeTrace();
            refereeState_ = RefereeState::READY;
        }
    }

    if (refereeState_ == RefereeState::FAIL) {
        if (isForDrag_ && onActionCancel_ && *onActionCancel_) {
            (*onActionCancel_)();
        }
    }
    // Clear All fingers' velocity when fingersId is empty.
    if (fingersId_.empty()) {
        panVelocity_.ResetAll();
    }
}

void PanRecognizer::HandleTouchUpEvent(const AxisEvent& event)
{
    TAG_LOGI(AceLogTag::ACE_GESTURE, "InputTracking id:%{public}d, pan recognizer receives axis end event",
        event.touchEventId);
    // if axisEvent received rotateEvent, no need to active Pan recognizer.
    if (event.isRotationEvent) {
        return;
    }
    globalPoint_ = Point(event.x, event.y);

    UpdateAxisPointInVelocityTracker(event, true);
    lastAxisEvent_ = event;
    time_ = event.time;

    if ((refereeState_ != RefereeState::SUCCEED) && (refereeState_ != RefereeState::FAIL)) {
        Adjudicate(AceType::Claim(this), GestureDisposal::REJECT);
        return;
    }

    if (refereeState_ == RefereeState::SUCCEED) {
        // AxisEvent is single one.
        SendCallbackMsg(onActionEnd_);
        ReportSlideOff();
        AddOverTimeTrace();
    }
}

void PanRecognizer::HandleTouchMoveEvent(const TouchEvent& event)
{
    if (static_cast<int32_t>(touchPoints_.size()) < fingers_) {
        return;
    }

    globalPoint_ = Point(event.x, event.y);
    lastTouchEvent_ = event;
    PointF windowPoint(event.GetOffset().GetX(), event.GetOffset().GetY());
    PointF windowTouchPoint(touchPoints_[event.id].GetOffset().GetX(), touchPoints_[event.id].GetOffset().GetY());
    NGGestureRecognizer::Transform(windowPoint, GetAttachedNode(), false,
        isPostEventResult_, event.postEventNodeId);
    NGGestureRecognizer::Transform(windowTouchPoint, GetAttachedNode(), false,
        isPostEventResult_, event.postEventNodeId);
    delta_ =
        (Offset(windowPoint.GetX(), windowPoint.GetY()) - Offset(windowTouchPoint.GetX(), windowTouchPoint.GetY()));

    if (SystemProperties::GetDebugEnabled()) {
        LOGI("Delta is x %{public}f, y %{public}f ", delta_.GetX(), delta_.GetY());
    }
    mainDelta_ = GetMainAxisDelta();
    UpdateTouchPointInVelocityTracker(event.history.empty() ? event : event.history.back());
    averageDistance_ += delta_ / static_cast<double>(touchPoints_.size());
    touchPoints_[event.id] = event;
    touchPointsDistance_[event.id] += delta_;
    time_ = event.time;

    if (refereeState_ == RefereeState::DETECTING) {
        auto result = IsPanGestureAccept();
        if (result == GestureAcceptResult::ACCEPT) {
            if (HandlePanAccept()) {
                return;
            }
        } else if (result == GestureAcceptResult::REJECT) {
            Adjudicate(AceType::Claim(this), GestureDisposal::REJECT);
        }
    } else if (refereeState_ == RefereeState::SUCCEED) {
        if ((direction_.type & PanDirection::VERTICAL) == 0) {
            averageDistance_.SetY(0.0);
            for (auto& element : touchPointsDistance_) {
                element.second.SetY(0.0);
            }
        } else if ((direction_.type & PanDirection::HORIZONTAL) == 0) {
            averageDistance_.SetX(0.0);
            for (auto& element : touchPointsDistance_) {
                element.second.SetX(0.0);
            }
        }
        if (isFlushTouchEventsEnd_) {
            SendCallbackMsg(onActionUpdate_);
        }
    }
}

void PanRecognizer::OnFlushTouchEventsBegin()
{
    isFlushTouchEventsEnd_ = false;
}

void PanRecognizer::OnFlushTouchEventsEnd()
{
    isFlushTouchEventsEnd_ = true;
}

void PanRecognizer::HandleTouchMoveEvent(const AxisEvent& event)
{
    if (fingers_ != AXIS_PAN_FINGERS || event.isRotationEvent) {
        return;
    }

    auto pipeline = PipelineContext::GetCurrentContext();
    bool isShiftKeyPressed = false;
    bool hasDifferentDirectionGesture = false;
    if (pipeline) {
        isShiftKeyPressed =
            pipeline->IsKeyInPressed(KeyCode::KEY_SHIFT_LEFT) || pipeline->IsKeyInPressed(KeyCode::KEY_SHIFT_RIGHT);
        hasDifferentDirectionGesture = pipeline->HasDifferentDirectionGesture();
    }
    delta_ = event.ConvertToOffset(isShiftKeyPressed, hasDifferentDirectionGesture);
    if (event.sourceTool == SourceTool::MOUSE) {
        if ((direction_.type & PanDirection::HORIZONTAL) == 0) { // Direction is vertical
            delta_.SetX(0.0);
        } else if ((direction_.type & PanDirection::VERTICAL) == 0) { // Direction is horizontal
            delta_.SetY(0.0);
        }
    }

    globalPoint_ = Point(event.x, event.y);
    mainDelta_ = GetMainAxisDelta();
    averageDistance_ += delta_;

    UpdateAxisPointInVelocityTracker(event);
    lastAxisEvent_ = event;
    time_ = event.time;

    if (refereeState_ == RefereeState::DETECTING) {
        auto result = IsPanGestureAccept();
        if (result == GestureAcceptResult::ACCEPT) {
            if (HandlePanAccept()) {
                return;
            }
        } else if (result == GestureAcceptResult::REJECT) {
            Adjudicate(AceType::Claim(this), GestureDisposal::REJECT);
        }
    } else if (refereeState_ == RefereeState::SUCCEED) {
        if ((direction_.type & PanDirection::VERTICAL) == 0) {
            averageDistance_.SetY(0.0);
        } else if ((direction_.type & PanDirection::HORIZONTAL) == 0) {
            averageDistance_.SetX(0.0);
        }

        SendCallbackMsg(onActionUpdate_);
    }
}

bool PanRecognizer::HandlePanAccept()
{
    if (gestureInfo_ && gestureInfo_->GetType() == GestureTypeName::DRAG) {
        auto dragEventActuator = GetDragEventActuator();
        CHECK_NULL_RETURN(dragEventActuator, true);
        if (dragEventActuator->IsDragUserReject()) {
            Adjudicate(AceType::Claim(this), GestureDisposal::REJECT);
            return true;
        }
    }
    if (TriggerGestureJudgeCallback() == GestureJudgeResult::REJECT) {
        Adjudicate(AceType::Claim(this), GestureDisposal::REJECT);
        if (gestureInfo_ && gestureInfo_->GetType() == GestureTypeName::DRAG) {
            auto dragEventActuator = GetDragEventActuator();
            CHECK_NULL_RETURN(dragEventActuator, true);
            dragEventActuator->SetIsDragUserReject(true);
        }
        return true;
    }
    Adjudicate(AceType::Claim(this), GestureDisposal::ACCEPT);
    return false;
}

void PanRecognizer::HandleTouchCancelEvent(const TouchEvent& event)
{
    TAG_LOGI(AceLogTag::ACE_GESTURE,
        "InputTracking id:%{public}d, pan recognizer receives %{public}d touch cancel event", event.touchEventId,
        event.id);
    if ((refereeState_ != RefereeState::SUCCEED) && (refereeState_ != RefereeState::FAIL)) {
        Adjudicate(AceType::Claim(this), GestureDisposal::REJECT);
        return;
    }

    if (refereeState_ == RefereeState::SUCCEED && static_cast<int32_t>(touchPoints_.size()) == fingers_) {
        // AxisEvent is single one.
        SendCancelMsg();
        refereeState_ = RefereeState::READY;
    }
}

void PanRecognizer::HandleTouchCancelEvent(const AxisEvent& event)
{
    TAG_LOGI(AceLogTag::ACE_GESTURE, "InputTracking id:%{public}d, pan recognizer receives axis cancel event",
        event.touchEventId);
    if ((refereeState_ != RefereeState::SUCCEED) && (refereeState_ != RefereeState::FAIL)) {
        Adjudicate(AceType::Claim(this), GestureDisposal::REJECT);
        return;
    }

    if (refereeState_ == RefereeState::SUCCEED) {
        SendCancelMsg();
    }
}

bool PanRecognizer::CalculateTruthFingers(bool isDirectionUp) const
{
    float totalDistance = 0.0f;
    for (auto& element : touchPointsDistance_) {
        auto each_point_move = element.second.GetY();
        if (GreatNotEqual(each_point_move, 0.0) && isDirectionUp) {
            totalDistance += each_point_move;
        } else if (LessNotEqual(each_point_move, 0.0) && !isDirectionUp) {
            totalDistance -= each_point_move;
        }
    }
    auto judgeDistance = distance_;
    if (deviceType_ == SourceType::MOUSE) {
        judgeDistance = mouseDistance_;
    }
    return GreatNotEqual(totalDistance, judgeDistance) && static_cast<int32_t>(touchPointsDistance_.size()) >= fingers_;
}

PanRecognizer::GestureAcceptResult PanRecognizer::IsPanGestureAccept() const
{
    auto judgeDistance = distance_;
    if (deviceType_ == SourceType::MOUSE) { // use mouseDistance_
        judgeDistance = mouseDistance_;
    }

    if ((direction_.type & PanDirection::ALL) == PanDirection::ALL) {
        double offset = averageDistance_.GetDistance();
        if (fabs(offset) < judgeDistance) {
            return GestureAcceptResult::DETECTING;
        }
        return GestureAcceptResult::ACCEPT;
    }

    if (fabs(averageDistance_.GetX()) > fabs(averageDistance_.GetY())) {
        if ((direction_.type & PanDirection::HORIZONTAL) != 0) {
            double offset = averageDistance_.GetX();
            if (fabs(offset) < judgeDistance) {
                return GestureAcceptResult::DETECTING;
            }
            if ((direction_.type & PanDirection::LEFT) == 0 && offset < 0) {
                return GestureAcceptResult::REJECT;
            }
            if ((direction_.type & PanDirection::RIGHT) == 0 && offset > 0) {
                return GestureAcceptResult::REJECT;
            }
            return GestureAcceptResult::ACCEPT;
        }
        return GestureAcceptResult::DETECTING;
    }
    if ((direction_.type & PanDirection::VERTICAL) != 0) {
        double offset = averageDistance_.GetY();
        if (fabs(offset) < judgeDistance) {
            return GestureAcceptResult::DETECTING;
        }
        if (inputEventType_ == InputEventType::AXIS) {
            if ((direction_.type & PanDirection::UP) == 0 && offset < 0) {
                return GestureAcceptResult::REJECT;
            }
            if ((direction_.type & PanDirection::DOWN) == 0 && offset > 0) {
                return GestureAcceptResult::REJECT;
            }
        } else {
            if ((direction_.type & PanDirection::UP) == 0) {
                return CalculateTruthFingers(true) ? GestureAcceptResult::ACCEPT : GestureAcceptResult::REJECT;
            }
            if ((direction_.type & PanDirection::DOWN) == 0) {
                return CalculateTruthFingers(false) ? GestureAcceptResult::ACCEPT : GestureAcceptResult::REJECT;
            }
        }
        return GestureAcceptResult::ACCEPT;
    }
    return GestureAcceptResult::DETECTING;
}

Offset PanRecognizer::GetRawGlobalLocation(int32_t postEventNodeId)
{
    PointF localPoint(globalPoint_.GetX(), globalPoint_.GetY());
    if (!lastTouchEvent_.history.empty() && (gestureInfo_ && gestureInfo_->GetType() == GestureTypeName::BOXSELECT)) {
        auto lastPoint = lastTouchEvent_.history.back();
        PointF rawLastPoint(lastPoint.GetOffset().GetX(), lastPoint.GetOffset().GetY());
        NGGestureRecognizer::Transform(
            rawLastPoint, GetAttachedNode(), false, isPostEventResult_, postEventNodeId);
        return Offset(rawLastPoint.GetX(), rawLastPoint.GetY());
    }
    return Offset(localPoint.GetX(), localPoint.GetY());
}

void PanRecognizer::OnResetStatus()
{
    MultiFingersRecognizer::OnResetStatus();
    touchPoints_.clear();
    averageDistance_.Reset();
    touchPointsDistance_.clear();
}

void PanRecognizer::OnSucceedCancel()
{
    SendCancelMsg();
}

void PanRecognizer::SendCallbackMsg(const std::unique_ptr<GestureEventFunc>& callback)
{
    if (callback && *callback) {
        GestureEvent info;
        info.SetTimeStamp(time_);
        UpdateFingerListInfo();
        info.SetFingerList(fingerList_);
        info.SetOffsetX(averageDistance_.GetX());
        info.SetOffsetY(averageDistance_.GetY());
        TouchEvent touchPoint = {};
        if (!touchPoints_.empty()) {
            touchPoint = touchPoints_.begin()->second;
        }
        info.SetPointerId(touchPoint.id);
        PointF localPoint(globalPoint_.GetX(), globalPoint_.GetY());
        NGGestureRecognizer::Transform(localPoint, GetAttachedNode(), false,
            isPostEventResult_, touchPoint.postEventNodeId);
        info.SetRawGlobalLocation(GetRawGlobalLocation(touchPoint.postEventNodeId));
        info.SetGlobalPoint(globalPoint_).SetLocalLocation(Offset(localPoint.GetX(), localPoint.GetY()));
        info.SetDeviceId(deviceId_);
        info.SetSourceDevice(deviceType_);
        info.SetTargetDisplayId(touchPoint.targetDisplayId);
        info.SetDelta(delta_);
        info.SetMainDelta(mainDelta_ / static_cast<double>(touchPoints_.size()));
        info.SetVelocity(panVelocity_.GetVelocity());
        info.SetMainVelocity(panVelocity_.GetMainAxisVelocity());
        if (inputEventType_ == InputEventType::AXIS) {
            info.SetScreenLocation(lastAxisEvent_.GetScreenOffset());
            info.SetVerticalAxis(lastAxisEvent_.verticalAxis);
            info.SetHorizontalAxis(lastAxisEvent_.horizontalAxis);
            info.SetSourceTool(lastAxisEvent_.sourceTool);
        } else {
            info.SetScreenLocation(lastTouchEvent_.GetScreenOffset());
            info.SetSourceTool(lastTouchEvent_.sourceTool);
        }
        info.SetTarget(GetEventTarget().value_or(EventTarget()));
        info.SetInputEventType(inputEventType_);
        info.SetForce(lastTouchEvent_.force);
        if (lastTouchEvent_.tiltX.has_value()) {
            info.SetTiltX(lastTouchEvent_.tiltX.value());
        }
        if (lastTouchEvent_.tiltY.has_value()) {
            info.SetTiltY(lastTouchEvent_.tiltY.value());
        }
        info.SetPointerEvent(lastPointEvent_);
        // callback may be overwritten in its invoke so we copy it first
        auto callbackFunction = *callback;
        callbackFunction(info);
    }
}

GestureJudgeResult PanRecognizer::TriggerGestureJudgeCallback()
{
    auto targetComponent = GetTargetComponent();
    CHECK_NULL_RETURN(targetComponent, GestureJudgeResult::CONTINUE);
    auto callback = targetComponent->GetOnGestureJudgeBeginCallback();
    auto callbackNative = targetComponent->GetOnGestureJudgeNativeBeginCallback();
    if (!callback && !callbackNative && !sysJudge_) {
        return GestureJudgeResult::CONTINUE;
    }
    auto info = std::make_shared<PanGestureEvent>();
    info->SetTimeStamp(time_);
    UpdateFingerListInfo();
    info->SetFingerList(fingerList_);
    info->SetOffsetX(averageDistance_.GetX());
    info->SetOffsetY(averageDistance_.GetY());
    TouchEvent touchPoint = {};
    if (!touchPoints_.empty()) {
        touchPoint = touchPoints_.begin()->second;
    }
    info->SetSourceDevice(deviceType_);
    if (inputEventType_ == InputEventType::AXIS) {
        info->SetVelocity(Velocity());
        info->SetMainVelocity(0.0);
        info->SetSourceTool(lastAxisEvent_.sourceTool);
    } else {
        info->SetVelocity(panVelocity_.GetVelocity());
        info->SetMainVelocity(panVelocity_.GetMainAxisVelocity());
        info->SetSourceTool(lastTouchEvent_.sourceTool);
    }
    info->SetTarget(GetEventTarget().value_or(EventTarget()));
    info->SetForce(lastTouchEvent_.force);
    if (lastTouchEvent_.tiltX.has_value()) {
        info->SetTiltX(lastTouchEvent_.tiltX.value());
    }
    if (lastTouchEvent_.tiltY.has_value()) {
        info->SetTiltY(lastTouchEvent_.tiltY.value());
    }
    gestureInfo_->SetInputEventType(inputEventType_);
    if (callback && callback(gestureInfo_, info) == GestureJudgeResult::REJECT) {
        // If outer callback exits, prioritize checking outer callback. If outer
        // reject, return reject.
        return GestureJudgeResult::REJECT;
    } else if (callbackNative && callbackNative(gestureInfo_, info) == GestureJudgeResult::REJECT) {
        // If outer callback doesn't exit or accept, check inner callback. If inner
        // reject, return reject.
        return GestureJudgeResult::REJECT;
    } else if (sysJudge_ && sysJudge_(gestureInfo_, info) == GestureJudgeResult::REJECT) {
        return GestureJudgeResult::REJECT;
    }
    return GestureJudgeResult::CONTINUE;
}

bool PanRecognizer::ReconcileFrom(const RefPtr<NGGestureRecognizer>& recognizer)
{
    RefPtr<PanRecognizer> curr = AceType::DynamicCast<PanRecognizer>(recognizer);
    if (!curr) {
        ResetStatus();
        return false;
    }

    if (curr->fingers_ != fingers_ || curr->priorityMask_ != priorityMask_) {
        ResetStatus();
        return false;
    }

    direction_.type = curr->direction_.type;
    newDirection_.type = curr->newDirection_.type;
    distance_ = curr->distance_;
    newDistance_ = curr->newDistance_;
    mouseDistance_ = curr->mouseDistance_;

    onActionStart_ = std::move(curr->onActionStart_);
    onActionUpdate_ = std::move(curr->onActionUpdate_);
    onActionEnd_ = std::move(curr->onActionEnd_);
    onActionCancel_ = std::move(curr->onActionCancel_);

    return true;
}

Axis PanRecognizer::GetAxisDirection()
{
    auto hasHorizontal = direction_.type & PanDirection::HORIZONTAL;
    auto hasVertical = direction_.type & PanDirection::VERTICAL;
    if (direction_.type == PanDirection::ALL || (hasHorizontal && hasVertical)) {
        return Axis::FREE;
    }
    if (hasHorizontal) {
        return Axis::HORIZONTAL;
    }
    if (hasVertical) {
        return Axis::VERTICAL;
    }
    return Axis::NONE;
}

void PanRecognizer::SetDirection(const PanDirection& direction)
{
    ChangeDirection(direction);
    panVelocity_.SetDirection(direction_.type);
}

void PanRecognizer::ChangeFingers(int32_t fingers)
{
    if (fingers_ != fingers) {
        newFingers_ = fingers;
    }
}

void PanRecognizer::ChangeDirection(const PanDirection& direction)
{
    if (direction_.type != direction.type) {
        direction_.type = direction.type;
        newDirection_.type = direction.type;
    }
}

void PanRecognizer::ChangeDistance(double distance)
{
    if (distance_ != distance) {
        if (refereeState_ == RefereeState::READY || refereeState_ == RefereeState::DETECTING) {
            distance_ = distance;
        }
        newDistance_ = distance;
        mouseDistance_ = distance;
    }
}

double PanRecognizer::GetMainAxisDelta()
{
    switch (direction_.type) {
        case PanDirection::ALL:
            return delta_.GetDistance();
        case PanDirection::HORIZONTAL:
            return delta_.GetX();
        case PanDirection::VERTICAL:
            return delta_.GetY();
        default:
            return 0.0;
    }
}

RefPtr<GestureSnapshot> PanRecognizer::Dump() const
{
    RefPtr<GestureSnapshot> info = NGGestureRecognizer::Dump();
    std::stringstream oss;
    oss << "direction: " << direction_.type << ", "
        << "isForDrag: " << isForDrag_ << ", "
        << "distance: " << distance_ << ", "
        << "fingers: " << fingers_;
    info->customInfo = oss.str();
    return info;
}

RefPtr<DragEventActuator> PanRecognizer::GetDragEventActuator()
{
    auto targetComponent = GetTargetComponent();
    CHECK_NULL_RETURN(targetComponent, nullptr);
    auto uiNode = targetComponent->GetUINode().Upgrade();
    CHECK_NULL_RETURN(uiNode, nullptr);
    auto frameNode = AceType::DynamicCast<FrameNode>(uiNode);
    CHECK_NULL_RETURN(frameNode, nullptr);
    auto gestureEventHub = frameNode->GetOrCreateGestureEventHub();
    CHECK_NULL_RETURN(gestureEventHub, nullptr);
    return gestureEventHub->GetDragEventActuator();
}

int32_t PanRecognizer::PanVelocity::GetFastestTracker(std::function<double(VelocityTracker&)>&& func)
{
    int32_t maxId = -1;
    double maxV = 0.0;
    for (auto& [id, tracker] : trackerMap_) {
        double v = std::abs(func(tracker));
        if (v > maxV) {
            maxId = id;
            maxV = v;
        }
    }
    return maxId;
}

Velocity PanRecognizer::PanVelocity::GetVelocity()
{
    auto&& func = [](VelocityTracker& tracker) { return tracker.GetVelocity().GetVelocityValue(); };
    int32_t id = GetFastestTracker(func);
    return (id != -1) ? trackerMap_[id].GetVelocity() : Velocity();
}

double PanRecognizer::PanVelocity::GetMainAxisVelocity()
{
    auto&& func = [axis = axis_](VelocityTracker& tracker) {
        tracker.SetMainAxis(axis);
        return tracker.GetMainAxisVelocity();
    };
    int32_t id = GetFastestTracker(func);
    return (id != -1) ? trackerMap_[id].GetMainAxisVelocity() : 0.0;
}

void PanRecognizer::PanVelocity::UpdateTouchPoint(int32_t id, const TouchEvent& event, bool end)
{
    trackerMap_[id].UpdateTouchPoint(event, end);
}

void PanRecognizer::PanVelocity::Reset(int32_t id)
{
    trackerMap_.erase(id);
}

void PanRecognizer::PanVelocity::ResetAll()
{
    trackerMap_.clear();
}

void PanRecognizer::PanVelocity::SetDirection(int32_t directionType)
{
    auto axis = Axis::FREE;
    if ((directionType & PanDirection::VERTICAL) == 0) {
        axis = Axis::HORIZONTAL;
    } else if ((directionType & PanDirection::HORIZONTAL) == 0) {
        axis = Axis::VERTICAL;
    }
    axis_ = axis;
}

bool PanRecognizer::AboutToAddCurrentFingers(int32_t touchId)
{
    if (fingersId_.find(touchId) != fingersId_.end()) {
        auto node = GetAttachedNode().Upgrade();
        TAG_LOGI(AceLogTag::ACE_GESTURE,
            "Pan recognizer has already receive touchId: %{public}d event, node tag = %{public}s, id = %{public}s",
            touchId, node ? node->GetTag().c_str() : "null",
            node ? std::to_string(node->GetId()).c_str() : "invalid");
        return false;
    }
    currentFingers_++;
    return true;
}

bool PanRecognizer::AboutToMinusCurrentFingers(int32_t touchId)
{
    if (fingersId_.find(touchId) != fingersId_.end()) {
        return true;
    }
    auto node = GetAttachedNode().Upgrade();
    TAG_LOGI(AceLogTag::ACE_GESTURE,
        "Pan recognizer has already receive touchId: %{public}d up event, node tag = %{public}s, id = %{public}s",
        touchId, node ? node->GetTag().c_str() : "null",
        node ? std::to_string(node->GetId()).c_str() : "invalid");
    return false;
}

void PanRecognizer::AddOverTimeTrace()
{
    int64_t overTime = GetSysTimestamp();
    int64_t inputTime = overTime;
    if (firstInputTime_.has_value()) {
        inputTime = static_cast<int64_t>(firstInputTime_.value().time_since_epoch().count());
    }
    if (SystemProperties::GetTraceInputEventEnabled()) {
        ACE_SCOPED_TRACE("UserEvent InputTime:%lld OverTime:%lld InputType:PanGesture",
            static_cast<long long>(inputTime), static_cast<long long>(overTime));
    }
    firstInputTime_.reset();
}
} // namespace OHOS::Ace::NG

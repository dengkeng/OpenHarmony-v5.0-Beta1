/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "touch_drawing_manager.h"
#include "i_multimodal_input_connect.h"
#include "setting_datashare.h"
#include "text/font_mgr.h"
#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_CURSOR
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchDrawingManager"

namespace OHOS {
namespace MMI {
namespace {
const static Rosen::Drawing::Color LABELS_DEFAULT_COLOR = Rosen::Drawing::Color::ColorQuadSetARGB(192, 255, 255, 255);
const static Rosen::Drawing::Color LABELS_RED_COLOR = Rosen::Drawing::Color::ColorQuadSetARGB(192, 255, 0, 0);
const static Rosen::Drawing::Color TRACKER_COLOR = Rosen::Drawing::Color::ColorQuadSetARGB(255, 0, 96, 255);
const static Rosen::Drawing::Color POINTER_RED_COLOR = Rosen::Drawing::Color::ColorQuadSetARGB(255, 255, 0, 0);
const static Rosen::Drawing::Color CROSS_HAIR_COLOR = Rosen::Drawing::Color::ColorQuadSetARGB(255, 0, 0, 192);
constexpr int32_t DENSITY_BASELINE = 160;
constexpr int32_t INDEPENDENT_INNER_PIXELS = 20;
constexpr int32_t INDEPENDENT_OUTER_PIXELS = 21;
constexpr int32_t INDEPENDENT_WIDTH_PIXELS = 2;
constexpr int32_t MULTIPLE_FACTOR = 10;
constexpr int32_t CALCULATE_MIDDLE = 2;
constexpr int32_t DEFAULT_VALUE = -1;
constexpr int32_t RECT_COUNT = 6;
constexpr int32_t RECT_TOP = 118;
constexpr int32_t RECT_HEIGHT = 50;
constexpr int32_t TEXT_TOP = 40;
constexpr int32_t PEN_WIDTH = 1;
constexpr int32_t RECT_SPACEING = 1;
constexpr int32_t THREE_PRECISION = 3;
constexpr int32_t TWO_PRECISION = 2;
constexpr int32_t ONE_PRECISION = 1;
constexpr float TEXT_SIZE = 40.0f;
constexpr float TEXT_SCALE = 1.0f;
constexpr float TEXT_SKEW = 0.0f;
const std::string showCursorSwitchName = "settings.input.show_touch_hint";
const std::string pointerPositionSwitchName = "settings.developer.show_touch_track";
} // namespace

TouchDrawingManager::TouchDrawingManager()
{
    bubbleBrush_.SetColor(Rosen::Drawing::Color::COLOR_WHITE);
    bubbleBrush_.SetAntiAlias(true);
    float innerCircleTransparency = 0.6f;
    bubbleBrush_.SetAlphaF(innerCircleTransparency);

    bubblePen_.SetColor(Rosen::Drawing::Color::COLOR_BLACK);
    bubblePen_.SetAntiAlias(true);
    float outerCircleTransparency = 0.1f;
    bubblePen_.SetAlphaF(outerCircleTransparency);

    textBrush_.SetColor(Rosen::Drawing::Color::COLOR_BLACK);
    pathPen_.SetColor(TRACKER_COLOR);
    pointPen_.SetColor(POINTER_RED_COLOR);
    crosshairsPen_.SetColor(CROSS_HAIR_COLOR);
    linePen_.SetColor(POINTER_RED_COLOR);
}

TouchDrawingManager::~TouchDrawingManager() {}

void TouchDrawingManager::TouchDrawHandler(const std::shared_ptr<PointerEvent>& pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    pointerEvent_ = pointerEvent;
    CreateObserver();
    if (bubbleCanvasNode_ == nullptr) {
        bubbleCanvasNode_ = Rosen::RSCanvasNode::Create();
        InitCanvasNode(bubbleCanvasNode_);
    }
    if (trackerCanvasNode_ == nullptr) {
        trackerCanvasNode_ = Rosen::RSCanvasDrawingNode::Create();
        InitCanvasNode(trackerCanvasNode_);
    }
    if (crosshairCanvasNode_ == nullptr) {
        crosshairCanvasNode_ = Rosen::RSCanvasNode::Create();
        InitCanvasNode(crosshairCanvasNode_);
    }
    if (labelsCanvasNode_ == nullptr) {
        labelsCanvasNode_ = Rosen::RSCanvasNode::Create();
        InitCanvasNode(labelsCanvasNode_);
    }
    CreateTouchWindow();
    if (bubbleMode_.isShow) {
        DrawBubbleHandler();
    }
    if (pointerMode_.isShow) {
        UpdatePointerPosition();
        ClearTracker();
        DrawPointerPositionHandler();
    }
    Rosen::RSTransaction::FlushImplicitTransaction();
}

void TouchDrawingManager::UpdateDisplayInfo(const DisplayInfo& displayInfo)
{
    CALL_DEBUG_ENTER;
    displayInfo_ = displayInfo;
    bubble_.innerCircleRadius = displayInfo.dpi * INDEPENDENT_INNER_PIXELS / DENSITY_BASELINE / CALCULATE_MIDDLE;
    bubble_.outerCircleRadius = displayInfo.dpi * INDEPENDENT_OUTER_PIXELS / DENSITY_BASELINE / CALCULATE_MIDDLE;
    bubble_.outerCircleWidth = static_cast<float>(displayInfo.dpi * INDEPENDENT_WIDTH_PIXELS) / DENSITY_BASELINE;
    itemRectW_ = static_cast<double>(displayInfo_.width) / RECT_COUNT;
}

void TouchDrawingManager::GetOriginalTouchScreenCoordinates(Direction direction, int32_t width, int32_t height,
    int32_t &physicalX, int32_t &physicalY)
{
    switch (direction) {
        case DIRECTION0: {
            MMI_HILOGD("direction is DIRECTION0");
            break;
        }
        case DIRECTION90: {
            int32_t temp = physicalY;
            physicalY = width - physicalX;
            physicalX = temp;
            MMI_HILOGD("direction is DIRECTION90, Original touch screen physicalX:%{public}d, physicalY:%{public}d",
                physicalX, physicalY);
            break;
        }
        case DIRECTION180: {
            physicalX = width - physicalX;
            physicalY = height - physicalY;
            MMI_HILOGD("direction is DIRECTION180, Original touch screen physicalX:%{public}d, physicalY:%{public}d",
                physicalX, physicalY);
            break;
        }
        case DIRECTION270: {
            int32_t temp = physicalX;
            physicalX = height - physicalY;
            physicalY = temp;
            MMI_HILOGD("direction is DIRECTION270, Original touch screen physicalX:%{public}d, physicalY:%{public}d",
                physicalX, physicalY);
            break;
        }
        default: {
            MMI_HILOGW("direction is invalid, direction:%{public}d", direction);
            break;
        }
    }
}

void TouchDrawingManager::SetPointerPositionState(bool state)
{
    pointerMode_.isShow = state;
}

void TouchDrawingManager::UpdateLabels()
{
    if (pointerMode_.isShow) {
        DrawLabels();
    } else {
        ClearPointerPosition();
    }
    Rosen::RSTransaction::FlushImplicitTransaction();
}

void TouchDrawingManager::CreateObserver()
{
    CALL_DEBUG_ENTER;
    if (!hasBubbleObserver_) {
        bubbleMode_.SwitchName = showCursorSwitchName;
        CreateBubbleObserver(bubbleMode_);
        hasBubbleObserver_ = true;
    }
    if (!hasPointerObserver_) {
        pointerMode_.SwitchName = pointerPositionSwitchName;
        CreatePointerObserver(pointerMode_);
        SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).
            GetBoolValue(pointerPositionSwitchName, pointerMode_.isShow);
        hasPointerObserver_ = true;
    }
}

template <class T>
void TouchDrawingManager::CreateBubbleObserver(T &item)
{
    CALL_DEBUG_ENTER;
    SettingObserver::UpdateFunc updateFunc = [&item](const std::string& key) {
        auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
            .GetBoolValue(key, item.isShow);
        if (ret != RET_OK) {
            MMI_HILOGE("Get value from setting date fail");
            return;
        }
        MMI_HILOGI("key: %{public}s, statusValue: %{public}d", key.c_str(), item.isShow);
    };
    sptr<SettingObserver> statusObserver = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .CreateObserver(item.SwitchName, updateFunc);
    ErrCode ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).
        RegisterObserver(statusObserver);
    if (ret != ERR_OK) {
        MMI_HILOGE("register setting observer failed, ret=%{public}d", ret);
        statusObserver = nullptr;
    }
}

template <class T>
void TouchDrawingManager::CreatePointerObserver(T &item)
{
    CALL_DEBUG_ENTER;
    SettingObserver::UpdateFunc updateFunc = [&item](const std::string& key) {
        auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
            .GetBoolValue(key, item.isShow);
        if (ret != RET_OK) {
            MMI_HILOGE("Get value from setting date fail");
            return;
        }
        TOUCH_DRAWING_MGR->UpdateLabels();
        MMI_HILOGI("key: %{public}s, statusValue: %{public}d", key.c_str(), item.isShow);
    };
    sptr<SettingObserver> statusObserver = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .CreateObserver(item.SwitchName, updateFunc);
    ErrCode ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).RegisterObserver(statusObserver);
    if (ret != ERR_OK) {
        MMI_HILOGE("register setting observer failed, ret=%{public}d", ret);
        statusObserver = nullptr;
    }
}

template <class T>
std::string TouchDrawingManager::FormatNumber(T& number, int32_t precision)
{
    std::string temp(".000");
    auto str = std::to_string(number);
    if (str.find(".") == std::string::npos) {
        str += temp;
    }
    return str.substr(0, str.find(".") + precision + 1);
}

void TouchDrawingManager::InitCanvasNode(std::shared_ptr<Rosen::RSCanvasNode>& canvasNode)
{
    CALL_DEBUG_ENTER;
    CHKPV(canvasNode);
    canvasNode->SetBounds(0, 0, displayInfo_.width, displayInfo_.height);
    canvasNode->SetFrame(0, 0, displayInfo_.width, displayInfo_.height);
#ifndef USE_ROSEN_DRAWING
    canvasNode->SetBackgroundColor(SK_ColorTRANSPARENT);
#else
    canvasNode->SetBackgroundColor(Rosen::Drawing::Color::COLOR_TRANSPARENT);
#endif
    canvasNode->SetCornerRadius(1);
    canvasNode->SetPositionZ(Rosen::RSSurfaceNode::POINTER_WINDOW_POSITION_Z);
    canvasNode->SetRotation(0);
}

void TouchDrawingManager::CreateTouchWindow()
{
    CALL_DEBUG_ENTER;
    if (surfaceNode_ != nullptr) {
        MMI_HILOGI("surfaceNode is already.");
        return;
    }
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "touch window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    CHKPV(surfaceNode_);
    surfaceNode_->SetFrameGravity(Rosen::Gravity::RESIZE_ASPECT_FILL);
    surfaceNode_->SetPositionZ(Rosen::RSSurfaceNode::POINTER_WINDOW_POSITION_Z);
    surfaceNode_->SetBounds(0, 0, displayInfo_.width, displayInfo_.height);
    surfaceNode_->SetFrame(0, 0, displayInfo_.width, displayInfo_.height);
#ifndef USE_ROSEN_DRAWING
    surfaceNode_->SetBackgroundColor(SK_ColorTRANSPARENT);
#else
    surfaceNode_->SetBackgroundColor(Rosen::Drawing::Color::COLOR_TRANSPARENT);
#endif
    surfaceNode_->SetRotation(0);
    if (bubbleCanvasNode_ != nullptr) {
        MMI_HILOGD("add child bubble canvas node");
        surfaceNode_->AddChild(bubbleCanvasNode_, DEFAULT_VALUE);
    }
    if (trackerCanvasNode_ != nullptr) {
        MMI_HILOGD("add child pointer position canvas node");
        surfaceNode_->AddChild(trackerCanvasNode_, DEFAULT_VALUE);
    }
    if (crosshairCanvasNode_ != nullptr) {
        MMI_HILOGD("add child crosshair canvas node");
        surfaceNode_->AddChild(crosshairCanvasNode_, DEFAULT_VALUE);
    }
    if (labelsCanvasNode_ != nullptr) {
        MMI_HILOGD("add child labels canvas node");
        surfaceNode_->AddChild(labelsCanvasNode_, DEFAULT_VALUE);
    }
    surfaceNode_->AttachToDisplay(static_cast<uint64_t>(pointerEvent_->GetTargetDisplayId()));
}

void TouchDrawingManager::DrawBubbleHandler()
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent_);
    auto pointerAction = pointerEvent_->GetPointerAction();
    if (IsValidAction(pointerAction)) {
        DrawBubble();
    }
}

void TouchDrawingManager::DrawBubble()
{
    CHKPV(pointerEvent_);
    CHKPV(bubbleCanvasNode_);
    auto canvas = static_cast<RosenCanvas *>
        (bubbleCanvasNode_->BeginRecording(displayInfo_.width, displayInfo_.height));
    CHKPV(canvas);
    auto pointerIdList = pointerEvent_->GetPointerIds();
    for (auto pointerId : pointerIdList) {
        if ((pointerEvent_->GetPointerAction() == PointerEvent::POINTER_ACTION_UP ||
            pointerEvent_->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_UP) &&
            pointerEvent_->GetPointerId() == pointerId) {
            continue;
        }
        PointerEvent::PointerItem pointerItem;
        if (!pointerEvent_->GetPointerItem(pointerId, pointerItem)) {
            MMI_HILOGE("Can't find pointer item, pointer:%{public}d", pointerId);
            return;
        }
        int32_t physicalX = pointerItem.GetDisplayX();
        int32_t physicalY = pointerItem.GetDisplayY();
        if (displayInfo_.displayDirection == DIRECTION0) {
            GetOriginalTouchScreenCoordinates(displayInfo_.direction, displayInfo_.width,
                displayInfo_.height, physicalX, physicalY);
        }
        Rosen::Drawing::Point centerPt(physicalX, physicalY);
        bubblePen_.SetWidth(bubble_.outerCircleWidth);
        canvas->AttachPen(bubblePen_);
        canvas->DrawCircle(centerPt, bubble_.outerCircleRadius);
        canvas->DetachPen();

        canvas->AttachBrush(bubbleBrush_);
        canvas->DrawCircle(centerPt, bubble_.innerCircleRadius);
        canvas->DetachBrush();
    }
    bubbleCanvasNode_->FinishRecording();
}

void TouchDrawingManager::DrawPointerPositionHandler()
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent_);
    auto canvas = static_cast<RosenCanvas *>
        (crosshairCanvasNode_->BeginRecording(displayInfo_.width, displayInfo_.height));
    CHKPV(canvas);
    auto pointerIdList = pointerEvent_->GetPointerIds();
    for (auto pointerId : pointerIdList) {
        PointerEvent::PointerItem pointerItem;
        if (!pointerEvent_->GetPointerItem(pointerId, pointerItem)) {
            MMI_HILOGE("Can't find pointer item, pointer:%{public}d", pointerId);
            return;
        }
        int32_t displayX = pointerItem.GetDisplayX();
        int32_t displayY = pointerItem.GetDisplayY();
        DrawTracker(displayX, displayY, pointerId);
        if (pointerEvent_->GetPointerAction() != PointerEvent::POINTER_ACTION_UP) {
            DrawCrosshairs(canvas, displayX, displayY);
            UpdateLastPointerItem(pointerId, pointerItem);
        }
    }
    DrawLabels();
    crosshairCanvasNode_->FinishRecording();
}

void TouchDrawingManager::DrawTracker(int32_t x, int32_t y, int32_t pointerId)
{
    CALL_DEBUG_ENTER;
    Rosen::Drawing::Point centerPt(x, y);
    int32_t lastPhysicalX = 0;
    int32_t lastPhysicalY = 0;
    bool find = false;
    for (auto &item : lastPointerItem_) {
        if (item.GetPointerId() == pointerId) {
            lastPhysicalX = item.GetDisplayX();
            lastPhysicalY = item.GetDisplayY();
            find = true;
            break;
        }
    }
    CHKPV(trackerCanvasNode_);
    auto canvas = static_cast<RosenCanvas *>
        (trackerCanvasNode_->BeginRecording(displayInfo_.width, displayInfo_.height));
    if (find) {
        Rosen::Drawing::Point lastCenterPt(lastPhysicalX, lastPhysicalY);
        pathPen_.SetWidth(PEN_WIDTH);
        canvas->AttachPen(pathPen_);
        canvas->DrawLine(lastCenterPt, centerPt);
        canvas->DetachPen();
        pointPen_.SetWidth(INDEPENDENT_WIDTH_PIXELS);
        canvas->AttachPen(pointPen_);
        canvas->DrawPoint(lastCenterPt);
        canvas->DetachPen();
    }
    if (!isDownAction_ && !find) {
        int32_t futureX = x + xVelocity_ * MULTIPLE_FACTOR;
        int32_t futureY = y + yVelocity_ * MULTIPLE_FACTOR;
        Rosen::Drawing::Point futurePt(futureX, futureY);
        linePen_.SetWidth(PEN_WIDTH);
        canvas->AttachPen(linePen_);
        canvas->DrawLine(centerPt, futurePt);
        canvas->DetachPen();
    }
    trackerCanvasNode_->FinishRecording();
}

void TouchDrawingManager::DrawCrosshairs(RosenCanvas *canvas, int32_t x, int32_t y)
{
    CALL_DEBUG_ENTER;
    crosshairsPen_.SetWidth(PEN_WIDTH);
    canvas->AttachPen(crosshairsPen_);
    Rosen::Drawing::Point left(0, y);
    Rosen::Drawing::Point right(displayInfo_.width, y);
    canvas->DrawLine(left, right);
    Rosen::Drawing::Point top(x, 0);
    Rosen::Drawing::Point bottom(x, displayInfo_.height);
    canvas->DrawLine(top, bottom);
    canvas->DetachPen();
}

void TouchDrawingManager::DrawLabels()
{
    CALL_DEBUG_ENTER;
    CHKPV(labelsCanvasNode_);
    std::string viewP = "P: " + std::to_string(currentPointerCount_) + " / " + std::to_string(maxPointerCount_);
    std::string viewX = "X: " + FormatNumber(currentPhysicalX_, ONE_PRECISION);
    std::string viewY = "Y: " + FormatNumber(currentPhysicalY_, ONE_PRECISION);
    auto dx = currentPhysicalX_ - firstPointerItem_.GetDisplayX();
    auto dy = currentPhysicalY_ - firstPointerItem_.GetDisplayY();
    std::string viewDx = "dX: " + FormatNumber(dx, ONE_PRECISION);
    std::string viewDy = "dY: " + FormatNumber(dy, ONE_PRECISION);
    std::string viewXv = "Xv: " + FormatNumber(xVelocity_, THREE_PRECISION);
    std::string viewYv = "Yv: " + FormatNumber(yVelocity_, THREE_PRECISION);
    std::string viewPrs = "Prs: " + FormatNumber(pressure_, TWO_PRECISION);
    Rosen::Drawing::Rect rect;
    rect.left_ = 0;
    rect.right_ = itemRectW_ + rect.left_;
    rect.top_ = RECT_TOP;
    rect.bottom_ = RECT_TOP + RECT_HEIGHT;
    Rosen::Drawing::Color color = LABELS_DEFAULT_COLOR;
    auto canvas = static_cast<RosenCanvas *>
        (labelsCanvasNode_->BeginRecording(displayInfo_.width, displayInfo_.height));
    CHKPV(canvas);
    DrawRectItem(canvas, viewP, rect, color);
    if (isDownAction_ || !lastPointerItem_.empty()) {
        DrawRectItem(canvas, viewX, rect, color);
        DrawRectItem(canvas, viewY, rect, color);
    } else {
        color = dx == 0 ? LABELS_DEFAULT_COLOR : LABELS_RED_COLOR;
        DrawRectItem(canvas, viewDx, rect, color);
        color = dy == 0 ? LABELS_DEFAULT_COLOR : LABELS_RED_COLOR;
        DrawRectItem(canvas, viewDy, rect, color);
    }
    DrawRectItem(canvas, viewXv, rect, LABELS_DEFAULT_COLOR);
    DrawRectItem(canvas, viewYv, rect, LABELS_DEFAULT_COLOR);
    std::shared_ptr<Rosen::Drawing::TextBlob> textPrs = Rosen::Drawing::TextBlob::MakeFromString(viewPrs.c_str(),
        Rosen::Drawing::Font(nullptr, TEXT_SIZE, TEXT_SCALE, TEXT_SKEW), Rosen::Drawing::TextEncoding::UTF8);
    color = isFirstDraw_ ? LABELS_DEFAULT_COLOR : LABELS_RED_COLOR;
    DrawRectItem(canvas, viewPrs, rect, color);
    labelsCanvasNode_->FinishRecording();
    isFirstDraw_ = false;
}

void TouchDrawingManager::DrawRectItem(RosenCanvas* canvas, const std::string &text,
    Rosen::Drawing::Rect &rect, const Rosen::Drawing::Color &color)
{
    std::shared_ptr<Rosen::Drawing::TextBlob> textBlob = Rosen::Drawing::TextBlob::MakeFromString(text.c_str(),
        Rosen::Drawing::Font(nullptr, TEXT_SIZE, TEXT_SCALE, TEXT_SKEW), Rosen::Drawing::TextEncoding::UTF8);
    rectBrush_.SetColor(color);
    canvas->AttachBrush(rectBrush_);
    canvas->DrawRect(rect);
    canvas->DetachBrush();
    canvas->AttachBrush(textBrush_);
    canvas->DrawTextBlob(textBlob.get(), rect.left_, RECT_TOP + TEXT_TOP);
    canvas->DetachBrush();
    rect.left_ += itemRectW_ + RECT_SPACEING;
    rect.right_ += itemRectW_ + RECT_SPACEING;
}

void TouchDrawingManager::UpdatePointerPosition()
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent_);
    int32_t pointerAction = pointerEvent_->GetPointerAction();
    int32_t pointerId = pointerEvent_->GetPointerId();
    if (pointerAction == PointerEvent::POINTER_ACTION_DOWN) {
        if (lastPointerItem_.empty()) {
            ClearLabels();
        }
        maxPointerCount_ = ++currentPointerCount_;
    } else if (pointerAction == PointerEvent::POINTER_ACTION_UP) {
        isDownAction_ = false;
        isFirstDownAction_ = false;
        for (auto it = lastPointerItem_.begin(); it != lastPointerItem_.end(); it++) {
            if (it->GetPointerId() == pointerId) {
                lastPointerItem_.erase(it);
                --currentPointerCount_;
                break;
            }
        }
        if (!lastPointerItem_.empty() && (currentPointerId_ == pointerId)) {
            currentPointerId_ = lastPointerItem_.front().GetPointerId();
        }
    }
    if (isFirstDownAction_) {
        PointerEvent::PointerItem pointerItem;
        if (!pointerEvent_->GetPointerItem(pointerId, pointerItem)) {
            MMI_HILOGE("Can't find pointer item, pointer:%{public}d", pointerId);
            return;
        }
        firstPointerItem_ = pointerItem;
        isFirstDownAction_ = false;
    }
    UpdateVelocity();
    UpdateDisplayCoord();
}

void TouchDrawingManager::UpdateLastPointerItem(int32_t pointerId, PointerEvent::PointerItem &pointerItem)
{
    CALL_DEBUG_ENTER;
    if (!pointerItem.IsPressed()) {
        return;
    }
    for (auto &item : lastPointerItem_) {
        if (item.GetPointerId() == pointerId) {
            item = pointerItem;
            return;
        }
    }
    lastPointerItem_.emplace_back(pointerItem);
}

void TouchDrawingManager::UpdateVelocity()
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent_);
    auto pointerId = pointerEvent_->GetPointerId();
    int64_t actionTime = pointerEvent_->GetActionTime();
    if (pointerId == currentPointerId_) {
        if (!lastPointerItem_.empty()) {
            PointerEvent::PointerItem pointerItem;
            if (!pointerEvent_->GetPointerItem(pointerId, pointerItem)) {
                MMI_HILOGD("Can't find pointer item, pointer:%{public}d", pointerId);
                return;
            }
            int32_t physicalX = pointerItem.GetDisplayX();
            int32_t physicalY = pointerItem.GetDisplayY();
            double diffTime = static_cast<double>(actionTime - lastActionTime_) / 1000;
            if (MMI_EQ(diffTime, 0.0)) {
                xVelocity_ = 0.0;
                yVelocity_ = 0.0;
            } else {
                auto diffX = physicalX - lastPointerItem_.front().GetDisplayX();
                auto diffY = physicalY - lastPointerItem_.front().GetDisplayY();
                xVelocity_ = diffX / diffTime;
                yVelocity_ = diffY / diffTime;
            }
        }
        lastActionTime_ = actionTime;
    }
}

void TouchDrawingManager::UpdateDisplayCoord()
{
    CHKPV(pointerEvent_);
    PointerEvent::PointerItem pointerItem;
    if (!pointerEvent_->GetPointerItem(currentPointerId_, pointerItem)) {
        MMI_HILOGE("Can't find pointer item, pointer:%{public}d", currentPointerId_);
        return;
    }
    if (pointerItem.IsPressed()) {
        currentPhysicalX_ = pointerItem.GetDisplayX();
        currentPhysicalY_ = pointerItem.GetDisplayY();
        pressure_ = pointerItem.GetPressure();
    }
}

void TouchDrawingManager::ClearPointerPosition()
{
    CHKPV(labelsCanvasNode_);
    auto canvas = static_cast<RosenCanvas *>
        (labelsCanvasNode_->BeginRecording(displayInfo_.width, displayInfo_.height));
    CHKPV(canvas);
    canvas->Clear();
    labelsCanvasNode_->FinishRecording();
    isFirstDraw_ = true;
    pressure_ = 0.0;
}

void TouchDrawingManager::ClearTracker()
{
    CALL_DEBUG_ENTER;
    CHKPV(trackerCanvasNode_);
    if (lastPointerItem_.empty() && isDownAction_) {
        MMI_HILOGD("ClearTracker isDownAction_ and empty");
        auto canvasNode = static_cast<Rosen::RSCanvasDrawingNode*>(trackerCanvasNode_.get());
        canvasNode->ResetSurface();
    }
}

void TouchDrawingManager::ClearLabels()
{
    isFirstDownAction_ = true;
    isDownAction_ = true;
    maxPointerCount_ = 0;
    currentPointerCount_ = 0;
    currentPointerId_ = 0;
    xVelocity_ = 0.0;
    yVelocity_ = 0.0;
}

bool TouchDrawingManager::IsValidAction(const int32_t action)
{
    if (action == PointerEvent::POINTER_ACTION_DOWN || action == PointerEvent::POINTER_ACTION_PULL_DOWN ||
        action == PointerEvent::POINTER_ACTION_MOVE || action == PointerEvent::POINTER_ACTION_PULL_MOVE ||
        action == PointerEvent::POINTER_ACTION_UP || action == PointerEvent::POINTER_ACTION_PULL_UP) {
        return true;
    }
    return false;
}
} // namespace MMI
} // namespace OHOS

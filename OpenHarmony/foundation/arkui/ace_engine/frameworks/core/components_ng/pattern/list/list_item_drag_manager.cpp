/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "core/components_ng/pattern/list/list_item_drag_manager.h"

#include "core/pipeline_ng/pipeline_context.h"
#include "core/components/common/properties/shadow_config.h"
#include "core/components_ng/pattern/list/list_pattern.h"
#include "core/components_ng/syntax/lazy_for_each_node.h"

namespace OHOS::Ace::NG {
namespace {
static constexpr Dimension HOT_ZONE_HEIGHT_VP_DIM = 59.0_vp;
static constexpr Dimension HOT_ZONE_WIDTH_VP_DIM = 26.0_vp;
static constexpr int32_t DEFAULT_Z_INDEX = 100;
static constexpr float DEFAULT_SCALE = 1.05f;
}

RefPtr<FrameNode> ListItemDragManager::GetListFrameNode() const
{
    auto host = GetHost();
    CHECK_NULL_RETURN(host, nullptr);
    auto parent = host->GetParentFrameNode();
    CHECK_NULL_RETURN(parent, nullptr);
    if (parent->GetTag() == V2::LIST_ITEM_GROUP_ETS_TAG) {
        parent = parent->GetParentFrameNode();
        CHECK_NULL_RETURN(parent, nullptr);
    }
    if (parent->GetTag() == V2::LIST_ETS_TAG) {
        return parent;
    }
    return nullptr;
}

void ListItemDragManager::InitDragDropEvent()
{
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    auto listItemEventHub = host->GetEventHub<ListItemEventHub>();
    CHECK_NULL_VOID(listItemEventHub);
    auto gestureHub = listItemEventHub->GetOrCreateGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    auto actionStartTask = [weak = WeakClaim(this)](const GestureEvent& info) {
        auto manager = weak.Upgrade();
        CHECK_NULL_VOID(manager);
        manager->HandleOnItemDragStart(info);
    };

    auto actionUpdateTask = [weak = WeakClaim(this)](const GestureEvent& info) {
        auto manager = weak.Upgrade();
        CHECK_NULL_VOID(manager);
        manager->HandleOnItemDragUpdate(info);
    };

    auto actionEndTask = [weak = WeakClaim(this)](const GestureEvent& info) {
        auto manager = weak.Upgrade();
        CHECK_NULL_VOID(manager);
        manager->HandleOnItemDragEnd(info);
    };

    auto actionCancelTask = [weak = WeakClaim(this)]() {
        auto manager = weak.Upgrade();
        CHECK_NULL_VOID(manager);
        manager->HandleOnItemDragCancel();
    };

    auto actionLongPress = [weak = WeakClaim(this)](const GestureEvent& info) {
        auto manager = weak.Upgrade();
        CHECK_NULL_VOID(manager);
        manager->HandleOnItemLongPress(info);
    };

    auto dragEvent = MakeRefPtr<DragEvent>(
        std::move(actionStartTask), std::move(actionUpdateTask), std::move(actionEndTask), std::move(actionCancelTask));
    dragEvent->SetLongPressEventFunc(std::move(actionLongPress));
    gestureHub->SetDragEvent(dragEvent, { PanDirection::ALL }, DEFAULT_PAN_FINGER, DEFAULT_PAN_DISTANCE);
}

void ListItemDragManager::DeInitDragDropEvent()
{
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    auto listItemEventHub = host->GetEventHub<ListItemEventHub>();
    CHECK_NULL_VOID(listItemEventHub);
    auto gestureHub = listItemEventHub->GetOrCreateGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->RemoveDragEvent();
}

void ListItemDragManager::HandleOnItemDragStart(const GestureEvent& info)
{
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    auto geometry = host->GetGeometryNode();
    CHECK_NULL_VOID(geometry);
    dragOffset_ = geometry->GetMarginFrameOffset();

    auto parent = listNode_.Upgrade();
    CHECK_NULL_VOID(parent);
    auto pattern = parent->GetPattern<ListPattern>();
    CHECK_NULL_VOID(pattern);
    axis_ = pattern->GetAxis();
    lanes_ = pattern->GetLanes();

    auto forEach = forEachNode_.Upgrade();
    CHECK_NULL_VOID(forEach);
    totalCount_ = forEach->FrameCount();
    fromIndex_ = GetIndex();
}

void ListItemDragManager::HandleOnItemLongPress(const GestureEvent& info)
{
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    auto renderContext = host->GetRenderContext();
    CHECK_NULL_VOID(renderContext);
    if (renderContext->HasTransformScale()) {
        prevScale_ = renderContext->GetTransformScaleValue({ 1.0f, 1.0f });
    } else {
        renderContext->UpdateTransformScale({ 1.0f, 1.0f });
    }
    if (renderContext->HasBackShadow()) {
        prevShadow_ = renderContext->GetBackShadowValue(ShadowConfig::NoneShadow);
    } else {
        renderContext->UpdateBackShadow(ShadowConfig::NoneShadow);
    }
    prevZIndex_ = renderContext->GetZIndexValue(0);

    AnimationOption option;
    option.SetCurve(Curves::FRICTION);
    option.SetDuration(300); /* 300:animate duration */
    AnimationUtils::Animate(option, [weak = WeakClaim(this)]() {
            auto manager = weak.Upgrade();
            CHECK_NULL_VOID(manager);
            auto host = manager->GetHost();
            CHECK_NULL_VOID(host);
            auto renderContext = host->GetRenderContext();
            CHECK_NULL_VOID(renderContext);
            auto newScale = manager->prevScale_ * DEFAULT_SCALE;
            renderContext->UpdateTransformScale(newScale);
            renderContext->UpdateZIndex(DEFAULT_Z_INDEX);
            renderContext->UpdateBackShadow(ShadowConfig::DefaultShadowS);
        },
        option.GetOnFinishEvent()
    );
}

void ListItemDragManager::SetNearbyNodeScale(RefPtr<FrameNode> node, float scale)
{
    auto renderContext = node->GetRenderContext();
    CHECK_NULL_VOID(renderContext);
    auto it = prevScaleNode_.find(renderContext);
    VectorF prevScale = it != prevScaleNode_.end() ? it->second :
        renderContext->GetTransformScaleValue({ 1.0f, 1.0f });
    renderContext->UpdateTransformScale(prevScale * scale);
    scaleNode_.emplace(renderContext, prevScale);
}

void ListItemDragManager::ResetPrevScaleNode()
{
    for (auto& [weakNode, scale] : prevScaleNode_) {
        if (scaleNode_.find(weakNode) == scaleNode_.end()) {
            auto node = weakNode.Upgrade();
            if (node) {
                node->UpdateTransformScale(scale);
            }
        }
    }
    prevScaleNode_.swap(scaleNode_);
    scaleNode_.clear();
}

ListItemDragManager::ScaleResult ListItemDragManager::ScaleAxisNearItem(
    int32_t index, const RectF& rect, const OffsetF& delta, Axis axis)
{
    ScaleResult res = { false, 1.0f };
    auto forEach = forEachNode_.Upgrade();
    CHECK_NULL_RETURN(forEach, res);

    auto node = forEach->GetFrameNode(index);
    CHECK_NULL_RETURN(node, res);
    auto geometry = node->GetGeometryNode();
    CHECK_NULL_RETURN(geometry, res);
    auto nearRect = geometry->GetMarginFrameRect();
    if (axis != axis_) {
        float offset1 = nearRect.GetOffset().GetMainOffset(axis_);
        if (!NearEqual(offset1, rect.GetOffset().GetMainOffset(axis_))) {
            return res;
        }
    }
    float mainDelta = delta.GetMainOffset(axis);
    float c0 = rect.GetOffset().GetMainOffset(axis) + rect.GetSize().MainSize(axis) / 2;
    float c1 = nearRect.GetOffset().GetMainOffset(axis) + nearRect.GetSize().MainSize(axis) / 2;
    if (NearEqual(c0, c1)) {
        return res;
    }
    float sharped = Curves::SHARP->MoveInternal(std::abs(mainDelta / (c1 - c0)));
    float scale = 1 - sharped * 0.05f;
    SetNearbyNodeScale(node, scale);
    res.scale = scale;

    if (Positive(mainDelta)) {
        float th = (nearRect.GetOffset().GetMainOffset(axis) + nearRect.GetSize().MainSize(axis) -
            rect.GetOffset().GetMainOffset(axis) - rect.GetSize().MainSize(axis)) / 2;
        if (GreatNotEqual(mainDelta, th)) {
            res.needMove = true;
            return res;
        }
    }
    if (Negative(mainDelta)) {
        float th = (nearRect.GetOffset().GetMainOffset(axis) - rect.GetOffset().GetMainOffset(axis)) / 2;
        if (LessNotEqual(mainDelta, th)) {
            res.needMove = true;
            return res;
        }
    }
    return res;
}

void ListItemDragManager::ScaleDiagonalItem(int32_t index, const RectF& rect, const OffsetF& delta)
{
    auto forEach = forEachNode_.Upgrade();
    CHECK_NULL_VOID(forEach);

    auto node = forEach->GetFrameNode(index);
    CHECK_NULL_VOID(node);
    auto geometry = node->GetGeometryNode();
    CHECK_NULL_VOID(geometry);
    auto diagonalRect = geometry->GetMarginFrameRect();

    OffsetF c0 = rect.GetOffset() + OffsetF(rect.Width() / 2, rect.Height() / 2);
    OffsetF c1 = diagonalRect.GetOffset() + OffsetF(diagonalRect.Width() / 2, diagonalRect.Height() / 2);
    OffsetF c2 = c0 + delta;

    float d0 = c0.GetDistance(c1);
    if (NearZero(d0)) {
        return;
    }
    float d1 = c2.GetDistance(c1);

    float sharped = Curves::SHARP->MoveInternal(std::abs(1 - d1 / d0));
    float scale = 1 - sharped * 0.05f;
    SetNearbyNodeScale(node, scale);
}

int32_t ListItemDragManager::ScaleNearItem(int32_t index, const RectF& rect, const OffsetF& delta)
{
    int32_t nearIndex = index;
    float mainDelta = delta.GetMainOffset(axis_);
    if (Positive(mainDelta)) {
        nearIndex = index + lanes_;
    } else if (Negative(mainDelta)) {
        nearIndex = index - lanes_;
    }
    ScaleResult mainRes = { false, 1.0f };
    if (nearIndex != index) {
        mainRes = ScaleAxisNearItem(nearIndex, rect, delta, axis_);
    }

    int32_t crossNearIndex = index;
    float crossDelta = delta.GetCrossOffset(axis_);
    if (Positive(crossDelta)) {
        crossNearIndex = index + 1;
    } else if (Negative(crossDelta)) {
        crossNearIndex = index - 1;
    }
    ScaleResult crossRes = { false, 1.0f };
    if (crossNearIndex != index) {
        Axis crossAxis = axis_ == Axis::VERTICAL ? Axis::HORIZONTAL : Axis::VERTICAL;
        crossRes = ScaleAxisNearItem(crossNearIndex, rect, delta, crossAxis);
    }

    int32_t diagonalIndex = index;
    if (!NearEqual(mainRes.scale, 1.0f) && !NearEqual(crossRes.scale, 1.0f)) {
        diagonalIndex = Positive(crossDelta) ? nearIndex + 1 : nearIndex - 1;
        ScaleDiagonalItem(diagonalIndex, rect, delta);
    }

    ResetPrevScaleNode();
    if (mainRes.needMove && crossRes.needMove) {
        return diagonalIndex;
    } else if (mainRes.needMove) {
        return nearIndex;
    } else if (crossRes.needMove) {
        return crossNearIndex;
    }
    return index;
}

void ListItemDragManager::HandleAutoScroll(int32_t index, const PointF& point, const RectF& frameRect)
{
    auto parent = listNode_.Upgrade();
    CHECK_NULL_VOID(parent);
    auto listGeometry = parent->GetGeometryNode();
    CHECK_NULL_VOID(listGeometry);
    auto listSize = listGeometry->GetFrameSize();
    float hotZone = axis_ == Axis::VERTICAL ?
        HOT_ZONE_HEIGHT_VP_DIM.ConvertToPx() : HOT_ZONE_WIDTH_VP_DIM.ConvertToPx();
    float startOffset = frameRect.GetOffset().GetMainOffset(axis_);
    float endOffset = startOffset + frameRect.GetSize().MainSize(axis_);
    auto pattern = parent->GetPattern<ListPattern>();
    CHECK_NULL_VOID(pattern);
    bool reachStart = (index == 0 && startOffset > hotZone);
    bool rechEnd = (index == totalCount_ - 1) && endOffset < (listSize.MainSize(axis_) - hotZone);
    if (!reachStart && !rechEnd) {
        pattern->HandleMoveEventInComp(point);
        scrolling_ = true;
    } else if (scrolling_) {
        pattern->HandleLeaveHotzoneEvent();
        scrolling_ = false;
    }
}

void ListItemDragManager::SetPosition(const OffsetF& offset)
{
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    auto renderContext = host->GetRenderContext();
    CHECK_NULL_VOID(renderContext);
    renderContext->UpdatePosition({ Dimension(offset.GetX(), DimensionUnit::PX),
        Dimension(offset.GetY(), DimensionUnit::PX) });
}

void ListItemDragManager::HandleOnItemDragUpdate(const GestureEvent& info)
{
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    auto geometry = host->GetGeometryNode();
    CHECK_NULL_VOID(geometry);
    auto frameRect = geometry->GetMarginFrameRect();
    OffsetF gestureOffset(info.GetOffsetX(), info.GetOffsetY());
    OffsetF realOffset = gestureOffset + dragOffset_;
    if (lanes_ == 1) {
        realOffset.SetX(dragOffset_.GetX());
    }
    SetPosition(realOffset);

    int32_t from = GetIndex();
    PointF point(info.GetGlobalLocation().GetX(), info.GetGlobalLocation().GetY());
    HandleAutoScroll(from, point, frameRect);

    int32_t to = ScaleNearItem(from, frameRect, realOffset - frameRect.GetOffset());
    if (to == from) {
        return;
    }
    AnimationOption option;
    auto curve = AceType::MakeRefPtr<InterpolatingSpring>(0, 1, 400, 38); /* 400:stiffness, 38:damping */
    option.SetCurve(curve);
    option.SetDuration(30); /* 30:duration */
    AnimationUtils::Animate(option, [weak = forEachNode_, from, to]() {
            auto forEach = weak.Upgrade();
            CHECK_NULL_VOID(forEach);
            forEach->MoveData(from, to);
            auto pipeline = PipelineContext::GetCurrentContext();
            if (pipeline) {
                pipeline->FlushUITasks();
            }
        },
        option.GetOnFinishEvent()
    );
}

void ListItemDragManager::HandleDragEndAnimation()
{
    AnimationOption option;
    auto curve = AceType::MakeRefPtr<InterpolatingSpring>(0, 1, 400, 38); /* 400:stiffness, 38:damping */
    option.SetCurve(curve);
    option.SetDuration(30); /* 30:duration */
    AnimationUtils::Animate(option, [weak = WeakClaim(this)]() {
            auto manager = weak.Upgrade();
            CHECK_NULL_VOID(manager);
            manager->ResetPrevScaleNode();
            auto host = manager->GetHost();
            CHECK_NULL_VOID(host);
            auto renderContext = host->GetRenderContext();
            CHECK_NULL_VOID(renderContext);
            renderContext->UpdateZIndex(manager->prevZIndex_);
            renderContext->ResetPosition();
            renderContext->OnPositionUpdate(OffsetT<Dimension>());
        },
        option.GetOnFinishEvent()
    );

    option.SetCurve(Curves::FRICTION);
    option.SetDuration(300); /* animate duration:300ms */
    AnimationUtils::Animate(option, [weak = WeakClaim(this)]() {
            auto manager = weak.Upgrade();
            CHECK_NULL_VOID(manager);
            auto host = manager->GetHost();
            CHECK_NULL_VOID(host);
            auto renderContext = host->GetRenderContext();
            CHECK_NULL_VOID(renderContext);
            renderContext->UpdateBackShadow(manager->prevShadow_);
        },
        option.GetOnFinishEvent()
    );

    /* 14:init velocity, 170:stiffness, 17:damping */
    option.SetCurve(AceType::MakeRefPtr<InterpolatingSpring>(14, 1, 170, 17));
    option.SetDuration(30);  /* 30:duration */
    option.SetDelay(150); /* 150:animate delay */
    AnimationUtils::Animate(option, [weak = WeakClaim(this)]() {
            auto manager = weak.Upgrade();
            CHECK_NULL_VOID(manager);
            auto host = manager->GetHost();
            CHECK_NULL_VOID(host);
            auto renderContext = host->GetRenderContext();
            CHECK_NULL_VOID(renderContext);
            renderContext->UpdateTransformScale(manager->prevScale_);
        },
        option.GetOnFinishEvent()
    );
}

void ListItemDragManager::HandleOnItemDragEnd(const GestureEvent& info)
{
    if (scrolling_) {
        auto parent = listNode_.Upgrade();
        CHECK_NULL_VOID(parent);
        auto pattern = parent->GetPattern<ListPattern>();
        pattern->HandleLeaveHotzoneEvent();
        scrolling_ = false;
    }
    HandleDragEndAnimation();
    int32_t to = GetIndex();
    if (fromIndex_ != to) {
        auto forEach = forEachNode_.Upgrade();
        CHECK_NULL_VOID(forEach);
        forEach->FireOnMove(fromIndex_, to);
    }
}

void ListItemDragManager::HandleOnItemDragCancel()
{
    HandleDragEndAnimation();
}

int32_t ListItemDragManager::GetIndex() const
{
    auto forEach = forEachNode_.Upgrade();
    CHECK_NULL_RETURN(forEach, -1);
    return forEach->GetFrameNodeIndex(GetHost());
}
} // namespace OHOS::Ace::NG

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

#include "core/components_ng/manager/drag_drop/utils/drag_animation_helper.h"
#include "core/pipeline_ng/pipeline_context.h"
#include "core/components_ng/base/frame_node.h"
#include "core/components_ng/event/drag_event.h"
#include "core/components_ng/event/gesture_event_hub.h"
#include "core/animation/animation_pub.h"
#include "core/components_ng/render/animation_utils.h"
#include "core/components_ng/render/render_context.h"
#include "core/components_ng/pattern/menu/menu_theme.h"
#include "core/components_ng/pattern/overlay/overlay_manager.h"
#include "core/components_v2/inspector/inspector_constants.h"

namespace OHOS::Ace::NG {
namespace {
    constexpr int32_t BEFORE_LIFTING_TIME = 650;
    constexpr int32_t IMAGE_SHOW_TIME = 50;
    constexpr int32_t PIXELMAP_ANIMATION_DURATION = 300;
    constexpr int32_t BADGE_ANIMATION_DURATION = 200;
    constexpr float DEFAULT_ANIMATION_SCALE = 0.95f;
    constexpr float GATHER_SPRING_RESPONSE = 0.304f;
    constexpr float GATHER_SPRING_DAMPING_FRACTION = 0.97f;
    constexpr float GRID_MOVE_SCALE = 0.1f;
    constexpr float LIST_MOVE_SCALE = 0.1f;
    constexpr float EULER_NUMBER = 2.71828f;
    constexpr float GATHER_OFFSET_RADIUS = 0.1f;
    constexpr float PIXELMAP_DRAG_SCALE_MULTIPLE = 1.05f;
    constexpr float BADGE_FIRST_ANIMATION_SCALE = 1.2f;
    constexpr float BADGE_SECOND_ANIMATION_SCALE = 1.0f;
    constexpr Dimension BADGE_RELATIVE_OFFSET = 8.0_vp;
    constexpr Dimension BADGE_DEFAULT_SIZE = 24.0_vp;
    constexpr Dimension BADGE_TEXT_FONT_SIZE = 14.0_fp;
    const Color BADGE_TEXT_FONT_COLOR = Color::FromString("#ffffffff");
    const Color BADGE_BACKGROUND_COLOR = Color::FromString("#ff007dff");
    constexpr float DEFAULT_INTERPOLATING_SPRING_VELOCITY = 10.0f;
    constexpr float DEFAULT_INTERPOLATING_SPRING_MASS = 1.0f;
    constexpr float DEFAULT_INTERPOLATING_SPRING_STIFFNESS = 410.0f;
    constexpr float DEFAULT_INTERPOLATING_SPRING_DAMPING = 38.0f;
}

void DragAnimationHelper::CalcDistanceBeforeLifting(bool isGrid, float& maxDistance, float& minDistance,
    float& maxTranslation, OffsetF gatherNodeCenter, std::vector<GatherNodeChildInfo>& gatherNodeChildrenInfo)
{
    for (const auto& child : gatherNodeChildrenInfo) {
        auto imageNode = child.imageNode.Upgrade();
        CHECK_NULL_VOID(imageNode);
        auto width = child.width;
        auto height = child.height;
        OffsetF curPos = {child.offset.GetX() + child.halfWidth, child.offset.GetY() + child.halfHeight};
        float dis = sqrt(pow(gatherNodeCenter.GetX() - curPos.GetX(), 2) +
            pow(gatherNodeCenter.GetY() - curPos.GetY(), 2));
        maxDistance = std::max(maxDistance, dis);
        minDistance = minDistance < 0 ? dis : std::min(minDistance, dis);
        if (isGrid) {
            maxTranslation = maxTranslation < 0 ? std::min(width, height) :
                std::min(maxTranslation, std::min(width, height));
        } else {
            maxTranslation = maxTranslation < 0 ? height : std::min(maxTranslation, height);
        }
    }
    maxTranslation *= isGrid ? GRID_MOVE_SCALE : LIST_MOVE_SCALE;
}

OffsetF DragAnimationHelper::CalcOffsetToTarget(OffsetF curPos, OffsetF targetPos, float maxTranslation,
    float maxDistance, float minDistance)
{
    if (NearZero(maxDistance) || NearZero(minDistance) || maxTranslation < 0) {
        return {0.0f, 0.0f};
    }

    float xDis = targetPos.GetX() - curPos.GetX();
    float yDis = targetPos.GetY() - curPos.GetY();
    float dis = sqrt(pow(xDis, 2) + pow(yDis, 2));
    if (NearZero(dis)) {
        return {0.0f, 0.0f};
    }
    auto trans = maxTranslation * pow(EULER_NUMBER, -(dis - minDistance) /
        maxDistance * GATHER_OFFSET_RADIUS);
    float x = xDis * trans / dis;
    float y = yDis * trans / dis;
    return {x, y};
}

void DragAnimationHelper::PlayGatherNodeTranslateAnimation(const RefPtr<DragEventActuator>& actuator,
    const RefPtr<OverlayManager>& overlayManager)
{
    AnimationOption option;
    option.SetDuration(BEFORE_LIFTING_TIME);
    option.SetCurve(Curves::SHARP);
    CHECK_NULL_VOID(actuator);
    auto frameNode = actuator->GetFrameNode();
    auto gatherNodeCenter = frameNode->GetPaintRectCenter();
    auto gatherNodeChildrenInfo = overlayManager->GetGatherNodeChildrenInfo();

    bool isGrid = frameNode->GetTag() == V2::GRID_ITEM_ETS_TAG ? true : false;
    float maxDistance = 0.0f;
    float minDistance = -1.0f;
    float maxTranslation = -1.0f;
    CalcDistanceBeforeLifting(isGrid, maxDistance, minDistance, maxTranslation,
        gatherNodeCenter, gatherNodeChildrenInfo);
    AnimationUtils::Animate(
        option,
        [gatherNodeCenter, gatherNodeChildrenInfo, maxTranslation, maxDistance, minDistance]() mutable {
            for (const auto& child : gatherNodeChildrenInfo) {
                auto imageNode = child.imageNode.Upgrade();
                CHECK_NULL_VOID(imageNode);
                auto imageContext = imageNode->GetRenderContext();
                CHECK_NULL_VOID(imageContext);
                auto curPos = child.offset + OffsetF(child.halfWidth, child.halfHeight);
                auto offset = CalcOffsetToTarget(curPos, gatherNodeCenter, maxTranslation,
                    maxDistance, minDistance);
                imageContext->UpdatePosition(OffsetT<Dimension>(
                    Dimension(child.offset.GetX() + offset.GetX()),
                    Dimension(child.offset.GetY() + offset.GetY())));
            }
        },
        option.GetOnFinishEvent());
}

void DragAnimationHelper::PlayGatherNodeOpacityAnimation(const RefPtr<OverlayManager>& overlayManager)
{
    CHECK_NULL_VOID(overlayManager);
    auto gatherNodeChildrenInfo = overlayManager->GetGatherNodeChildrenInfo();
    for (const auto& child : gatherNodeChildrenInfo) {
        auto imageNode = child.imageNode.Upgrade();
        CHECK_NULL_VOID(imageNode);
        auto imageContext = imageNode->GetRenderContext();
        CHECK_NULL_VOID(imageContext);
        imageContext->UpdateOpacity(0.0f);
    }

    AnimationOption opacityOption;
    opacityOption.SetDuration(IMAGE_SHOW_TIME);
    opacityOption.SetCurve(AceType::MakeRefPtr<CubicCurve>(0.0f, 0.0f, 1.0f, 1.0f));

    AnimationUtils::Animate(
        opacityOption,
        [gatherNodeChildrenInfo]() mutable {
            for (const auto& child : gatherNodeChildrenInfo) {
                auto imageNode = child.imageNode.Upgrade();
                CHECK_NULL_VOID(imageNode);
                auto imageContext = imageNode->GetRenderContext();
                CHECK_NULL_VOID(imageContext);
                imageContext->UpdateOpacity(1.0f);
            }
        },
        opacityOption.GetOnFinishEvent());
}

void DragAnimationHelper::PlayGatherAnimationBeforeLifting(const RefPtr<DragEventActuator>& actuator)
{
    CHECK_NULL_VOID(actuator);
    if (!actuator->IsNeedGather()) {
        return;
    }
    auto pipeline = PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(pipeline);
    auto manager = pipeline->GetOverlayManager();
    CHECK_NULL_VOID(manager);
    auto frameNode = actuator->GetFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto gatherNode = actuator->GetGatherNode();
    actuator->SetGatherNode(nullptr);
    auto gatherNodeChildrenInfo = actuator->GetGatherNodeChildrenInfo();
    actuator->ClearGatherNodeChildrenInfo();
    DragEventActuator::MountGatherNode(manager, frameNode, gatherNode, gatherNodeChildrenInfo);
    pipeline->FlushSyncGeometryNodeTasks();
    auto dragDropManager = pipeline->GetDragDropManager();
    CHECK_NULL_VOID(dragDropManager);
    dragDropManager->SetIsTouchGatherAnimationPlaying(true);
    PlayGatherNodeOpacityAnimation(manager);
    PlayGatherNodeTranslateAnimation(actuator, manager);
}

void DragAnimationHelper::PlayNodeAnimationBeforeLifting(const RefPtr<FrameNode>& frameNode)
{
    CHECK_NULL_VOID(frameNode);
    auto previewOptions = frameNode->GetDragPreviewOption();
    if (!previewOptions.defaultAnimationBeforeLifting) {
        return;
    }
    AnimationOption option;
    option.SetDuration(BEFORE_LIFTING_TIME);
    auto springCurve = AceType::MakeRefPtr<InterpolatingSpring>(DEFAULT_INTERPOLATING_SPRING_VELOCITY,
        DEFAULT_INTERPOLATING_SPRING_MASS, DEFAULT_INTERPOLATING_SPRING_STIFFNESS,
        DEFAULT_INTERPOLATING_SPRING_DAMPING);
    option.SetCurve(springCurve);
    auto frameContext = frameNode->GetRenderContext();
    CHECK_NULL_VOID(frameContext);
    frameContext->UpdateTransformScale({ 1.0, 1.0 });

    AnimationUtils::Animate(
        option,
        [frameContext]() mutable {
            CHECK_NULL_VOID(frameContext);
            frameContext->UpdateTransformScale({ DEFAULT_ANIMATION_SCALE, DEFAULT_ANIMATION_SCALE });
        },
        option.GetOnFinishEvent());
}

void DragAnimationHelper::PlayNodeResetAnimation(const RefPtr<DragEventActuator>& actuator)
{
    CHECK_NULL_VOID(actuator);
    auto frameNode = actuator->GetFrameNode();
    CHECK_NULL_VOID(frameNode);
    bool defaultAnimationBeforeLifting = frameNode->GetDragPreviewOption().defaultAnimationBeforeLifting;
    if (!defaultAnimationBeforeLifting) {
        return;
    }
    auto frameContext = frameNode->GetRenderContext();
    CHECK_NULL_VOID(frameContext);
    auto layoutProperty = frameNode->GetLayoutProperty();
    if (layoutProperty) {
        layoutProperty->UpdateVisibility(VisibleType::VISIBLE);
    }
    AnimationOption option;
    option.SetDuration(PIXELMAP_ANIMATION_DURATION);
    const RefPtr<Curve> curve = AceType::MakeRefPtr<ResponsiveSpringMotion>(0.33f, 0.67f, 1.0f);
    option.SetCurve(curve);
    AnimationUtils::Animate(
        option,
        [frameContext]() mutable {
            frameContext->UpdateTransformScale({ 1.0, 1.0 });
        },
        option.GetOnFinishEvent());
}

void DragAnimationHelper::PlayGatherAnimation(const RefPtr<FrameNode>& frameNode,
    const RefPtr<OverlayManager>& overlayManager)
{
    CHECK_NULL_VOID(frameNode);
    auto gatherNodeCenter = frameNode->GetPaintRectCenter();
    CHECK_NULL_VOID(overlayManager);
    auto gatherNodeChildrenInfo = overlayManager->GetGatherNodeChildrenInfo();
    BorderRadiusProperty borderRadius;
    borderRadius.SetRadius(0.0_vp);
    borderRadius.multiValued = false;
    for (const auto& child : gatherNodeChildrenInfo) {
        auto imageNode = child.imageNode.Upgrade();
        CHECK_NULL_VOID(imageNode);
        auto imageContext = imageNode->GetRenderContext();
        CHECK_NULL_VOID(imageContext);
        imageContext->UpdateBorderRadius(borderRadius);
    }

    AnimationOption option;
    option.SetDuration(PIXELMAP_ANIMATION_DURATION);
    const RefPtr<Curve> curve = AceType::MakeRefPtr<ResponsiveSpringMotion>(GATHER_SPRING_RESPONSE,
        GATHER_SPRING_DAMPING_FRACTION, 0.0f);
    option.SetCurve(curve);

    option.SetOnFinishEvent([]() {
        auto pipelineContext = PipelineContext::GetMainPipelineContext();
        CHECK_NULL_VOID(pipelineContext);
        auto dragDropManager = pipelineContext->GetDragDropManager();
        CHECK_NULL_VOID(dragDropManager);
        dragDropManager->SetIsTouchGatherAnimationPlaying(false);
    });
    AnimationUtils::Animate(
        option,
        [overlayManager, gatherNodeCenter]() {
            DragDropManager::UpdateGatherNodeAttr(overlayManager, gatherNodeCenter, PIXELMAP_DRAG_SCALE_MULTIPLE);
        },
        option.GetOnFinishEvent());
}

void DragAnimationHelper::ShowBadgeAnimation(const RefPtr<FrameNode>& textNode)
{
    auto pipelineContext = PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(pipelineContext);
    auto dragDropManager = pipelineContext->GetDragDropManager();
    CHECK_NULL_VOID(dragDropManager);
    if (!dragDropManager->IsShowBadgeAnimation()) {
        return;
    }
    CHECK_NULL_VOID(textNode);
    auto textNodeContext = textNode->GetRenderContext();
    CHECK_NULL_VOID(textNodeContext);
    textNodeContext->UpdateTransformScale({ 0.0f, 0.0f });
    RefPtr<Curve> firstCubicCurve = AceType::MakeRefPtr<CubicCurve>(0.2f, 0.0f, 0.45f, 1.0f);
    CHECK_NULL_VOID(firstCubicCurve);
    AnimationOption textOption;
    textOption.SetDuration(BADGE_ANIMATION_DURATION);
    textOption.SetCurve(firstCubicCurve);
    textOption.SetDelay(BADGE_ANIMATION_DURATION);
    textOption.SetOnFinishEvent([textNodeContext]() {
        RefPtr<Curve> secondCubicCurve = AceType::MakeRefPtr<CubicCurve>(0.24f, 0.0f, 0.36f, 1.0f);
        CHECK_NULL_VOID(secondCubicCurve);
        AnimationOption animationOption;
        animationOption.SetDuration(BADGE_ANIMATION_DURATION);
        animationOption.SetCurve(secondCubicCurve);
        textNodeContext->UpdateTransformScale({ BADGE_FIRST_ANIMATION_SCALE, BADGE_FIRST_ANIMATION_SCALE });
        AnimationUtils::Animate(
            animationOption,
            [textNodeContext]() mutable {
                textNodeContext->UpdateTransformScale({ BADGE_SECOND_ANIMATION_SCALE, BADGE_SECOND_ANIMATION_SCALE });
            },
            animationOption.GetOnFinishEvent());
    });
    AnimationUtils::Animate(
        textOption,
        [textNodeContext]() mutable {
            textNodeContext->UpdateTransformScale({ BADGE_FIRST_ANIMATION_SCALE, BADGE_FIRST_ANIMATION_SCALE });
        },
        textOption.GetOnFinishEvent());

    dragDropManager->SetIsShowBadgeAnimation(false);
}

OffsetF DragAnimationHelper::CalcBadgeTextOffset(const RefPtr<MenuPattern>& menuPattern,
    const RefPtr<FrameNode>& imageNode, const RefPtr<PipelineBase>& context, int32_t badgeLength)
{
    CHECK_NULL_RETURN(imageNode, OffsetF());
    CHECK_NULL_RETURN(menuPattern, OffsetF());
    auto offset = imageNode->GetPaintRectOffset();
    auto width = imageNode->GetGeometryNode()->GetFrameSize().Width();
    auto scaleAfter = menuPattern->GetPreviewAfterAnimationScale();
    auto menuTheme = context->GetTheme<NG::MenuTheme>();
    CHECK_NULL_RETURN(menuTheme, OffsetF());
    auto previewAfterAnimationScale =
        LessNotEqual(scaleAfter, 0.0) ? menuTheme->GetPreviewAfterAnimationScale() : scaleAfter;
    double textOffsetX = offset.GetX() + width * previewAfterAnimationScale -
        BADGE_RELATIVE_OFFSET.ConvertToPx() - (BADGE_RELATIVE_OFFSET.ConvertToPx() * badgeLength);
    double textOffsetY = offset.GetY() - BADGE_RELATIVE_OFFSET.ConvertToPx();
    return OffsetF(textOffsetX, textOffsetY);
}

void DragAnimationHelper::CalcBadgeTextPosition(const RefPtr<MenuPattern>& menuPattern,
    const RefPtr<OverlayManager>& manager, const RefPtr<FrameNode>& imageNode, const RefPtr<FrameNode>& textNode)
{
    CHECK_NULL_VOID(manager);
    CHECK_NULL_VOID(textNode);
    auto pipelineContext = PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(pipelineContext);
    auto dragDropManager = pipelineContext->GetDragDropManager();
    CHECK_NULL_VOID(dragDropManager);
    auto badgeNumber = dragDropManager->GetBadgeNumber();
    auto childSize = badgeNumber > 0 ? badgeNumber : manager->GetGatherNodeChildrenInfo().size() + 1;
    auto badgeLength = std::to_string(childSize).size();
    UpdateBadgeLayoutAndRenderContext(textNode, badgeLength, childSize);
    auto textRenderContext = textNode->GetRenderContext();
    CHECK_NULL_VOID(textRenderContext);
    auto pipeline = PipelineBase::GetCurrentContext();
    CHECK_NULL_VOID(pipeline);
    auto offset = CalcBadgeTextOffset(menuPattern, imageNode, pipeline, badgeLength);
    textRenderContext->UpdatePosition(OffsetT<Dimension>(Dimension(offset.GetX()), Dimension(offset.GetY())));
    textNode->MarkDirtyNode(NG::PROPERTY_UPDATE_MEASURE);
    textNode->MarkModifyDone();
    textNode->SetLayoutDirtyMarked(true);
    textNode->SetActive(true);
    textNode->CreateLayoutTask();
    pipeline->FlushSyncGeometryNodeTasks();
}

void DragAnimationHelper::UpdateBadgeLayoutAndRenderContext(
    const RefPtr<FrameNode>& textNode, int32_t badgeLength, int32_t childSize)
{
    if (childSize <= 1) {
        return;
    }
    CHECK_NULL_VOID(textNode);
    auto textLayoutProperty = textNode->GetLayoutProperty<TextLayoutProperty>();
    CHECK_NULL_VOID(textLayoutProperty);
    textLayoutProperty->UpdateContent(std::to_string(childSize));
    textLayoutProperty->UpdateMaxLines(1);
    textLayoutProperty->UpdateFontWeight(FontWeight::MEDIUM);
    textLayoutProperty->UpdateTextColor(BADGE_TEXT_FONT_COLOR);
    textLayoutProperty->UpdateFontSize(BADGE_TEXT_FONT_SIZE);
    textLayoutProperty->UpdateTextAlign(TextAlign::CENTER);
    int64_t textWidth = BADGE_DEFAULT_SIZE.ConvertToPx() + (BADGE_RELATIVE_OFFSET.ConvertToPx() * (badgeLength - 1));
    auto textSize = CalcSize(NG::CalcLength(textWidth), NG::CalcLength(BADGE_DEFAULT_SIZE.ConvertToPx()));
    textLayoutProperty->UpdateUserDefinedIdealSize(textSize);

    auto textRenderContext = textNode->GetRenderContext();
    CHECK_NULL_VOID(textRenderContext);
    textRenderContext->SetVisible(true);
    textRenderContext->UpdateBackgroundColor(BADGE_BACKGROUND_COLOR);
    BorderRadiusProperty borderRadius;
    borderRadius.SetRadius(BADGE_DEFAULT_SIZE);
    textRenderContext->UpdateBorderRadius(borderRadius);
}
}
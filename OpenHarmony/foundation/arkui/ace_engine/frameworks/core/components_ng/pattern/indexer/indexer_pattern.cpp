/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "core/components_ng/pattern/indexer/indexer_pattern.h"

#include "base/geometry/dimension.h"
#include "base/geometry/ng/size_t.h"
#include "base/log/dump_log.h"
#include "base/memory/ace_type.h"
#include "base/memory/referenced.h"
#include "base/utils/utils.h"
#include "core/animation/animator.h"
#include "core/common/container.h"
#include "core/components/common/layout/constants.h"
#include "core/components/common/properties/color.h"
#include "core/components/common/properties/popup_param.h"
#include "core/components/common/properties/shadow_config.h"
#include "core/components/indexer/indexer_theme.h"
#include "core/components_ng/base/frame_node.h"
#include "core/components_ng/pattern/divider/divider_pattern.h"
#include "core/components_ng/pattern/indexer/indexer_theme.h"
#include "core/components_ng/pattern/linear_layout/linear_layout_pattern.h"
#include "core/components_ng/pattern/linear_layout/linear_layout_property.h"
#include "core/components_ng/pattern/list/list_event_hub.h"
#include "core/components_ng/pattern/list/list_item_layout_property.h"
#include "core/components_ng/pattern/list/list_item_pattern.h"
#include "core/components_ng/pattern/list/list_layout_property.h"
#include "core/components_ng/pattern/list/list_pattern.h"
#include "core/components_ng/pattern/stack/stack_pattern.h"
#include "core/components_ng/pattern/text/text_layout_property.h"
#include "core/components_ng/pattern/text/text_model.h"
#include "core/components_ng/pattern/text/text_pattern.h"
#include "core/components_ng/property/border_property.h"
#include "core/components_ng/property/calc_length.h"
#include "core/components_ng/property/measure_property.h"
#include "core/components_ng/property/measure_utils.h"
#include "core/components_ng/property/property.h"
#include "core/components_v2/inspector/inspector_constants.h"
#include "core/components_v2/list/list_properties.h"
#include "core/event/mouse_event.h"
#include "core/pipeline_ng/pipeline_context.h"

namespace OHOS::Ace::NG {
namespace {
constexpr int32_t TOTAL_NUMBER = 1000;
constexpr double PERCENT_100 = 100.0;
}
void IndexerPattern::OnModifyDone()
{
    Pattern::OnModifyDone();
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    auto layoutProperty = host->GetLayoutProperty<IndexerLayoutProperty>();
    CHECK_NULL_VOID(layoutProperty);

    auto itemCountChanged = false;
    bool autoCollapseModeChanged = true;
    if (!isNewHeightCalculated_) {
        auto autoCollapse = layoutProperty->GetAutoCollapse().value_or(false);
        autoCollapseModeChanged = autoCollapse != autoCollapse_;
        autoCollapse_ = autoCollapse;

        auto newArray = layoutProperty->GetArrayValue().value_or(std::vector<std::string>());
        bool arrayValueChanged = newArray.size() != fullArrayValue_.size() || newArray != fullArrayValue_;
        if (arrayValueChanged || autoCollapseModeChanged) {
            lastCollapsingMode_ = IndexerCollapsingMode::INVALID;
        }
        fullArrayValue_ = newArray;
    }

    if (fullArrayValue_.size() > 0) {
        if (autoCollapse_) {
            sharpItemCount_ = fullArrayValue_.at(0) == StringUtils::Str16ToStr8(INDEXER_STR_SHARP) ? 1 : 0;
            CollapseArrayValue();
        } else {
            sharpItemCount_ = 0;
            BuildFullArrayValue();
        }
        itemCountChanged = (itemCount_ != static_cast<int32_t>(arrayValue_.size()));
        itemCount_ = static_cast<int32_t>(arrayValue_.size());
    } else {
        sharpItemCount_ = 0;
        itemCountChanged = (itemCount_ != 0);
        itemCount_ = 0;
        arrayValue_.clear();
    }
    BuildArrayValueItems();

    bool removeBubble = false;
    auto usePopup = layoutProperty->GetUsingPopup().value_or(false);
    if (isPopup_ != usePopup) {
        isPopup_ = usePopup;
        removeBubble = !isPopup_;
    }

    // Remove bubble if auto-collapse mode switched on/off or if items count changed
    removeBubble |= autoCollapseModeChanged || itemCountChanged;
    if (removeBubble) {
        RemoveBubble();
    }

    auto propSelect = layoutProperty->GetSelected().value();
    if (propSelect < 0 || propSelect >= itemCount_) {
        propSelect = 0;
        layoutProperty->UpdateSelected(propSelect);
    }
    if (propSelect != selected_) {
        selected_ = propSelect;
        selectChanged_ = true;
        ResetStatus();
    } else if (!isNewHeightCalculated_) {
        selectChanged_ = false;
    }
    isNewHeightCalculated_ = false;
    auto itemSize =
        layoutProperty->GetItemSize().value_or(Dimension(INDEXER_ITEM_SIZE, DimensionUnit::VP)).ConvertToPx();
    auto indexerSizeChanged = (itemCountChanged || !NearEqual(itemSize, lastItemSize_));
    lastItemSize_ = itemSize;
    auto needMarkDirty = (layoutProperty->GetPropertyChangeFlag() == PROPERTY_UPDATE_NORMAL);
    ApplyIndexChanged(needMarkDirty, initialized_ && selectChanged_, false, indexerSizeChanged);
    auto gesture = host->GetOrCreateGestureEventHub();
    if (gesture) {
        InitPanEvent(gesture);
    }
    InitInputEvent();
    if (!touchListener_) {
        CHECK_NULL_VOID(gesture);
        auto touchCallback = [weak = WeakClaim(this)](const TouchEventInfo& info) {
            auto indexerPattern = weak.Upgrade();
            CHECK_NULL_VOID(indexerPattern);
            if (info.GetTouches().front().GetTouchType() == TouchType::DOWN) {
                indexerPattern->isTouch_ = true;
                indexerPattern->OnTouchDown(info);
            } else if (info.GetTouches().front().GetTouchType() == TouchType::UP) {
                indexerPattern->isTouch_ = false;
                indexerPattern->OnTouchUp(info);
            }
        };
        touchListener_ = MakeRefPtr<TouchEventImpl>(std::move(touchCallback));
        gesture->AddTouchEvent(touchListener_);
    }
    InitOnKeyEvent();
    SetAccessibilityAction();
}

bool IndexerPattern::OnDirtyLayoutWrapperSwap(const RefPtr<LayoutWrapper>& dirty, const DirtySwapConfig& config)
{
    if (config.skipMeasure && config.skipLayout) {
        return false;
    }
    auto layoutAlgorithmWrapper = DynamicCast<LayoutAlgorithmWrapper>(dirty->GetLayoutAlgorithm());
    CHECK_NULL_RETURN(layoutAlgorithmWrapper, false);
    auto indexerLayoutAlgorithm = DynamicCast<IndexerLayoutAlgorithm>(layoutAlgorithmWrapper->GetLayoutAlgorithm());
    CHECK_NULL_RETURN(indexerLayoutAlgorithm, false);
    itemSizeRender_ = indexerLayoutAlgorithm->GetItemSizeRender();
    auto height = indexerLayoutAlgorithm->GetActualHeight();
    if (actualIndexerHeight_ != height && autoCollapse_) {
        actualIndexerHeight_ = height;
        isNewHeightCalculated_ = true;
        auto hostNode = dirty->GetHostNode();
        StartCollapseDelayTask(hostNode, INDEXER_COLLAPSE_WAIT_DURATION);
    }
    return true;
}

void IndexerPattern::BuildArrayValueItems()
{
    int32_t indexerSize = static_cast<int32_t>(arrayValue_.size());
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    auto layoutProperty = host->GetLayoutProperty<IndexerLayoutProperty>();
    CHECK_NULL_VOID(layoutProperty);
    auto children = host->GetChildren();
    auto lastChildCount = static_cast<int32_t>(children.size());
    if (layoutProperty->GetIsPopupValue(false)) {
        lastChildCount -= 1;
    }
    if (indexerSize != lastChildCount) {
        host->Clean();
        layoutProperty->UpdateIsPopup(false);
        for (int32_t index = 0; index < indexerSize; index++) {
            auto indexerChildNode = FrameNode::CreateFrameNode(
                V2::TEXT_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<TextPattern>());
            CHECK_NULL_VOID(indexerChildNode);
            InitChildInputEvent(indexerChildNode, index);
            host->AddChild(indexerChildNode);
        }
    }
    std::vector<std::string> arrayValueStrs;
    for (auto indexerItem : arrayValue_) {
        arrayValueStrs.push_back(indexerItem.first);
    }
    layoutProperty->UpdateArrayValue(arrayValueStrs);
}

void IndexerPattern::BuildFullArrayValue()
{
    arrayValue_.clear();
    
    for (auto indexerLetter : fullArrayValue_) {
        arrayValue_.push_back(std::pair(indexerLetter, false));
    }
}

void IndexerPattern::CollapseArrayValue()
{
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    auto layoutProperty = host->GetLayoutProperty<IndexerLayoutProperty>();
    CHECK_NULL_VOID(layoutProperty);
    auto geometryNode = host->GetGeometryNode();
    CHECK_NULL_VOID(geometryNode);
    auto itemSize =
        layoutProperty->GetItemSize().value_or(Dimension(INDEXER_ITEM_SIZE, DimensionUnit::VP)).ConvertToVp();
    int32_t maxItemsCount = 0;
    auto height = Dimension(actualIndexerHeight_, DimensionUnit::PX).ConvertToVp();
    if (height > 0 && itemSize > 0) {
        maxItemsCount = static_cast<int32_t>(height / itemSize);
    }
    int32_t fullArraySize = static_cast<int32_t>(fullArrayValue_.size());
    if (maxItemsCount >= fullArraySize || fullArraySize - sharpItemCount_ <= INDEXER_NINE_CHARACTERS_CHECK) {
        if (lastCollapsingMode_ != IndexerCollapsingMode::NONE) {
            lastCollapsingMode_ = IndexerCollapsingMode::NONE;
            BuildFullArrayValue();
        }
    } else if (fullArraySize - sharpItemCount_ <= INDEXER_THIRTEEN_CHARACTERS_CHECK) {
        if (lastCollapsingMode_ != IndexerCollapsingMode::FIVE) {
            lastCollapsingMode_ = IndexerCollapsingMode::FIVE;
            ApplyFivePlusOneMode(fullArraySize);
        }
    } else {
        // 13 here is count of visible items in 7 + 1 mode (i.e. 7 characters 6 dots and # item if exists)
        if (maxItemsCount >= INDEXER_THIRTEEN_CHARACTERS_CHECK + sharpItemCount_) {
            if (lastCollapsingMode_ != IndexerCollapsingMode::SEVEN) {
                lastCollapsingMode_ = IndexerCollapsingMode::SEVEN;
                ApplySevenPlusOneMode(fullArraySize);
            }
        } else {
            if (lastCollapsingMode_ != IndexerCollapsingMode::FIVE) {
                lastCollapsingMode_ = IndexerCollapsingMode::FIVE;
                ApplyFivePlusOneMode(fullArraySize);
            }
        }
    }
}

void IndexerPattern::ApplySevenPlusOneMode(int32_t fullArraySize)
{
    // 7 + # mode
    // minimum items in one group (totally 6 groups) including
    // visible character in the group and excluding the first always visible item
    auto cmin = static_cast<int32_t>((fullArraySize - 1 - sharpItemCount_) / 6);
    auto gmax = (fullArraySize - 1 - sharpItemCount_) - cmin * 6; // number of groups with maximum items count
    auto cmax = cmin + 1; // maximum items in one group including visible character in the group
    auto gmin = 6 - gmax; // number of groups with minimum items count

    arrayValue_.clear();
    arrayValue_.push_back(std::pair(fullArrayValue_.at(0), false)); // push the first item
    if (sharpItemCount_ > 0) {
        arrayValue_.push_back(std::pair(fullArrayValue_.at(1), false)); // push the second item if the first is #
    }

    auto lastPushedIndex = sharpItemCount_;
    
    for (int32_t groupIndex = 0; groupIndex < gmin; groupIndex++) { // push groups of minimum items count
        int32_t firstIndex = lastPushedIndex + 1;
        int32_t lastIndex = firstIndex + cmin - 1;
        arrayValue_.push_back(std::pair(fullArrayValue_.at(firstIndex), true));
        arrayValue_.push_back(std::pair(fullArrayValue_.at(lastIndex), false));
        lastPushedIndex = lastIndex;
    }

    for (int32_t groupIndex = 0; groupIndex < gmax; groupIndex++) { // push groups of maximum items count
        int32_t firstIndex = lastPushedIndex + 1;
        int32_t lastIndex = firstIndex + cmax - 1;
        arrayValue_.push_back(std::pair(fullArrayValue_.at(firstIndex), true));
        arrayValue_.push_back(std::pair(fullArrayValue_.at(lastIndex), false));
        lastPushedIndex = lastIndex;
    }
}

void IndexerPattern::ApplyFivePlusOneMode(int32_t fullArraySize)
{
    // 5 + # mode
    // minimum items in one group (totally 4 groups) including
    // visible character in the group and excluding the first always visible item and # item if exists
    auto cmin = static_cast<int32_t>((fullArraySize - 1 - sharpItemCount_) / 4);
    auto gmax = (fullArraySize - 1 - sharpItemCount_) - cmin * 4; // number of groups with maximum items count
    auto cmax = cmin + 1; // maximum items in one group including visible character in the group
    auto gmin = 4 - gmax; // number of groups with minimum items count

    arrayValue_.clear();
    arrayValue_.push_back(std::pair(fullArrayValue_.at(0), false)); // push the first item
    if (sharpItemCount_ > 0) {
        arrayValue_.push_back(std::pair(fullArrayValue_.at(1), false)); // push the second item if the first is #
    }

    auto lastPushedIndex = sharpItemCount_;

    for (int32_t groupIndex = 0; groupIndex < gmin; groupIndex++) { // push groups of minimum items count
        int32_t firstIndex = lastPushedIndex + 1;
        int32_t lastIndex = firstIndex + cmin - 1;
        arrayValue_.push_back(std::pair(fullArrayValue_.at(firstIndex), true));
        arrayValue_.push_back(std::pair(fullArrayValue_.at(lastIndex), false));
        lastPushedIndex = lastIndex;
    }

    for (int32_t groupIndex = 0; groupIndex < gmax; groupIndex++) { // push groups of maximum items count
        int32_t firstIndex = lastPushedIndex + 1;
        int32_t lastIndex = firstIndex + cmax - 1;
        arrayValue_.push_back(std::pair(fullArrayValue_.at(firstIndex), true));
        arrayValue_.push_back(std::pair(fullArrayValue_.at(lastIndex), false));
        lastPushedIndex = lastIndex;
    }
}

void IndexerPattern::InitPanEvent(const RefPtr<GestureEventHub>& gestureHub)
{
    if (panEvent_) {
        return;
    }
    auto onActionStart = [weak = WeakClaim(this)](const GestureEvent& info) {
        auto pattern = weak.Upgrade();
        if (pattern) {
            if (info.GetInputEventType() == InputEventType::AXIS) {
                return;
            }
            pattern->MoveIndexByOffset(info.GetLocalLocation());
        }
    };

    auto onActionUpdate = [weak = WeakClaim(this)](const GestureEvent& info) {
        auto pattern = weak.Upgrade();
        CHECK_NULL_VOID(pattern);
        if (info.GetInputEventType() == InputEventType::AXIS) {
            if (GreatNotEqual(info.GetMainDelta(), 0.0)) {
                pattern->MoveIndexByStep(-1);
            } else if (LessNotEqual(info.GetMainDelta(), 0.0)) {
                pattern->MoveIndexByStep(1);
            }
        } else {
            pattern->MoveIndexByOffset(info.GetLocalLocation());
        }
    };

    auto onActionEnd = [weak = WeakClaim(this)](const GestureEvent& info) {};

    auto onActionCancel = [weak = WeakClaim(this)]() {};

    PanDirection panDirection;
    panDirection.type = PanDirection::VERTICAL;
    panEvent_ = MakeRefPtr<PanEvent>(
        std::move(onActionStart), std::move(onActionUpdate), std::move(onActionEnd), std::move(onActionCancel));
    gestureHub->AddPanEvent(panEvent_, panDirection, 1, 0.0_vp);
}

void IndexerPattern::OnHover(bool isHover)
{
    if (itemCount_ <= 0) {
        return;
    }
    if (isHover_ == isHover) {
        return;
    }
    isHover_ = isHover;
    isTouch_ = false;
    if (isHover_) {
        IndexerHoverInAnimation();
    } else {
        IndexerHoverOutAnimation();
    }
    ApplyIndexChanged(true, false);
}

void IndexerPattern::OnChildHover(int32_t index, bool isHover)
{
    childHoverIndex_ = isHover ? index : -1;
    ApplyIndexChanged(true, childHoverIndex_ >= 0 && childHoverIndex_ < itemCount_);
}

void IndexerPattern::OnPopupHover(bool isHover)
{
    isPopupHover_ = isHover;
    if (isHover) {
        delayTask_.Cancel();
        StartBubbleAppearAnimation();
    } else {
        StartDelayTask(INDEXER_BUBBLE_ENTER_DURATION + INDEXER_BUBBLE_WAIT_DURATION);
    }
}

void IndexerPattern::InitInputEvent()
{
    if (isInputEventRegisted_) {
        return;
    }
    isInputEventRegisted_ = true;
    InitCurrentInputEvent();
}

void IndexerPattern::InitCurrentInputEvent()
{
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    auto hoverCallback = [weak = WeakClaim(this)](bool isHovered) {
        auto pattern = weak.Upgrade();
        CHECK_NULL_VOID(pattern);
        pattern->OnHover(isHovered);
    };
    auto hoverEvent = MakeRefPtr<InputEvent>(hoverCallback);
    auto inputGesture = host->GetOrCreateInputEventHub();
    inputGesture->AddOnHoverEvent(hoverEvent);
}

void IndexerPattern::InitChildInputEvent(RefPtr<FrameNode>& itemNode, int32_t childIndex)
{
    CHECK_NULL_VOID(itemNode);
    auto childHoverCallback = [weak = WeakClaim(this), index = childIndex](bool isHovered) {
        auto pattern = weak.Upgrade();
        CHECK_NULL_VOID(pattern);
        pattern->OnChildHover(index, isHovered);
    };
    auto childOnHoverEvent = MakeRefPtr<InputEvent>(childHoverCallback);
    auto childInputEventHub = itemNode->GetOrCreateInputEventHub();
    childInputEventHub->AddOnHoverEvent(childOnHoverEvent);
}

void IndexerPattern::InitPopupInputEvent()
{
    CHECK_NULL_VOID(popupNode_);
    auto popupHoverCallback = [weak = WeakClaim(this)](bool isHovered) {
        auto pattern = weak.Upgrade();
        CHECK_NULL_VOID(pattern);
        pattern->OnPopupHover(isHovered);
    };
    auto popupOnHoverEvent = MakeRefPtr<InputEvent>(popupHoverCallback);
    auto popupInputEventHub = popupNode_->GetOrCreateInputEventHub();
    popupInputEventHub->AddOnHoverEvent(popupOnHoverEvent);
}

void IndexerPattern::OnTouchDown(const TouchEventInfo& info)
{
    if (itemCount_ <= 0) {
        return;
    }
    MoveIndexByOffset(info.GetTouches().front().GetLocalLocation());
}

void IndexerPattern::OnTouchUp(const TouchEventInfo& info)
{
    if (itemCount_ <= 0) {
        return;
    }
    childPressIndex_ = -1;
    if (isHover_) {
        IndexerPressOutAnimation();
    }
    ResetStatus();
    ApplyIndexChanged(true, true, true);
    OnSelect(true);
}

void IndexerPattern::MoveIndexByOffset(const Offset& offset)
{
    if (itemSizeRender_ <= 0) {
        return;
    }
    if (itemCount_ <= 0) {
        return;
    }
    auto nextSelectIndex = GetSelectChildIndex(offset);
    if (nextSelectIndex == childPressIndex_) {
        return;
    }
    childPressIndex_ = nextSelectIndex;
    selected_ = nextSelectIndex;
    lastSelected_ = nextSelectIndex;
    FireOnSelect(selected_, true);
    if (isHover_ && childPressIndex_ >= 0) {
        IndexerPressInAnimation();
    }
    childFocusIndex_ = -1;
    childHoverIndex_ = -1;
    ApplyIndexChanged(true, true);
}

int32_t IndexerPattern::GetSelectChildIndex(const Offset& offset)
{
    auto host = GetHost();
    CHECK_NULL_RETURN(host, -1);
    auto layoutProperty = host->GetLayoutProperty<IndexerLayoutProperty>();
    CHECK_NULL_RETURN(layoutProperty, -1);
    int32_t index = 0;
    for (auto child : host->GetChildren()) {
        auto childNode = DynamicCast<FrameNode>(child);
        CHECK_NULL_RETURN(childNode, -1);
        auto geometryNode = childNode->GetGeometryNode();
        CHECK_NULL_RETURN(geometryNode, -1);
        auto childOffset = geometryNode->GetFrameOffset();
        if (index == 0 && LessNotEqual(offset.GetY(), childOffset.GetY())) {
            return 0;
        }
        if (GreatOrEqual(offset.GetY(), childOffset.GetY()) &&
            LessNotEqual(offset.GetY(), childOffset.GetY() + itemSizeRender_)) {
            break;
        }
        index++;
    }
    return std::clamp(index, 0, itemCount_ - 1);
}

bool IndexerPattern::KeyIndexByStep(int32_t step)
{
    auto nextSected = GetSkipChildIndex(step);
    if (childFocusIndex_ == nextSected || nextSected == -1) {
        return false;
    }
    childFocusIndex_ = nextSected;
    auto refreshBubble = nextSected >= 0 && nextSected < itemCount_;
    if (refreshBubble) {
        selected_ = nextSected;
        lastSelected_ = nextSected;
    }
    childPressIndex_ = -1;
    childHoverIndex_ = -1;
    ApplyIndexChanged(true, refreshBubble);
    return nextSected >= 0;
}

int32_t IndexerPattern::GetSkipChildIndex(int32_t step)
{
    auto nextSelected = selected_ + step;
    if (nextSelected < 0 || nextSelected >= itemCount_) {
        return -1;
    }
    return nextSelected;
}

bool IndexerPattern::MoveIndexByStep(int32_t step)
{
    auto nextSected = GetSkipChildIndex(step);
    if (selected_ == nextSected || nextSected == -1) {
        return false;
    }
    selected_ = nextSected;
    ResetStatus();
    ApplyIndexChanged(true, true);
    return nextSected >= 0;
}

bool IndexerPattern::MoveIndexBySearch(const std::string& searchStr)
{
    auto nextSelectIndex = GetFocusChildIndex(searchStr);
    if (selected_ == nextSelectIndex || nextSelectIndex == -1) {
        return false;
    }
    selected_ = nextSelectIndex;
    childFocusIndex_ = nextSelectIndex;
    childHoverIndex_ = -1;
    childPressIndex_ = -1;
    ApplyIndexChanged(true, true);
    return nextSelectIndex >= 0;
}

int32_t IndexerPattern::GetFocusChildIndex(const std::string& searchStr)
{
    int32_t nextSelectIndex = -1;
    for (auto i = selected_ + 1; i < itemCount_; ++i) {
        const auto& indexValue = arrayValue_.at(i).first;
        if (searchStr.length() > indexValue.length()) {
            continue;
        }
        if (strcasecmp(indexValue.substr(0, searchStr.length()).c_str(), searchStr.c_str()) == 0) {
            nextSelectIndex = i;
            break;
        }
    }
    if (nextSelectIndex >= 0 && nextSelectIndex < itemCount_) {
        return nextSelectIndex;
    }
    for (auto i = 0; i < selected_; ++i) {
        const auto& indexValue = arrayValue_.at(i).first;
        if (searchStr.length() > indexValue.length()) {
            continue;
        }
        if (strcasecmp(indexValue.substr(0, searchStr.length()).c_str(), searchStr.c_str()) == 0) {
            nextSelectIndex = i;
            break;
        }
    }
    if (nextSelectIndex >= 0 && nextSelectIndex < itemCount_) {
        return nextSelectIndex;
    }
    return -1;
}

void IndexerPattern::ResetStatus()
{
    childHoverIndex_ = -1;
    childFocusIndex_ = -1;
    childPressIndex_ = -1;
    popupClickedIndex_ = -1;
}

void IndexerPattern::OnSelect(bool changed)
{
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    FireOnSelect(selected_, false);
    animateSelected_ = selected_;
    if (animateSelected_ >= 0) {
        auto selectedFrameNode = DynamicCast<FrameNode>(host->GetChildAtIndex(animateSelected_));
        CHECK_NULL_VOID(selectedFrameNode);
        ItemSelectedInAnimation(selectedFrameNode);
    }
    if (lastSelected_ >= 0 && lastSelected_ != animateSelected_) {
        auto lastFrameNode = DynamicCast<FrameNode>(host->GetChildAtIndex(lastSelected_));
        CHECK_NULL_VOID(lastFrameNode);
        ItemSelectedOutAnimation(lastFrameNode);
    }
    lastSelected_ = selected_;
}

void IndexerPattern::ApplyIndexChanged(
    bool isTextNodeInTree, bool selectChanged, bool fromTouchUp, bool indexerSizeChanged)
{
    initialized_ = true;
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    auto layoutProperty = host->GetLayoutProperty<IndexerLayoutProperty>();
    CHECK_NULL_VOID(layoutProperty);
    if (layoutProperty->GetAdaptiveWidthValue(false)) {
        host->MarkDirtyNode(PROPERTY_UPDATE_MEASURE_SELF_AND_PARENT);
    }
    auto paintProperty = host->GetPaintProperty<IndexerPaintProperty>();
    CHECK_NULL_VOID(paintProperty);
    auto pipeline = PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(pipeline);
    auto indexerTheme = pipeline->GetTheme<IndexerTheme>();
    CHECK_NULL_VOID(indexerTheme);
    int32_t index = 0;
    auto total = host->GetTotalChildCount();
    auto childrenNode = host->GetChildren();
    if (layoutProperty->GetIsPopupValue(false)) {
        total -= 1;
    }
    if (Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)) {
        auto indexerRenderContext = host->GetRenderContext();
        CHECK_NULL_VOID(indexerRenderContext);
        if (paintProperty->GetIndexerBorderRadius().has_value()) {
            auto indexerRadius = paintProperty->GetIndexerBorderRadiusValue();
            indexerRenderContext->UpdateBorderRadius({ indexerRadius, indexerRadius, indexerRadius, indexerRadius });
        } else {
            auto indexerRadius = Dimension(INDEXER_DEFAULT_RADIUS, DimensionUnit::VP);
            indexerRenderContext->UpdateBorderRadius({ indexerRadius, indexerRadius, indexerRadius, indexerRadius });
        }
    }
    for (int32_t i = 0; i < total; i++) {
        auto childNode = host->GetChildByIndex(i)->GetHostNode();
        UpdateChildBoundary(childNode);
        auto nodeLayoutProperty = childNode->GetLayoutProperty<TextLayoutProperty>();
        auto childRenderContext = childNode->GetRenderContext();
        childRenderContext->SetClipToBounds(true);
        auto nodeStr = autoCollapse_ && arrayValue_[index].second ?
            StringUtils::Str16ToStr8(INDEXER_STR_DOT) : arrayValue_[index].first;
        if (index == childHoverIndex_ || index == childPressIndex_) {
            if (Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)) {
                auto radiusSize = paintProperty->GetItemBorderRadius().has_value()
                                        ? paintProperty->GetItemBorderRadiusValue()
                                        : Dimension(INDEXER_ITEM_DEFAULT_RADIUS, DimensionUnit::VP);
                childRenderContext->UpdateBorderRadius({ radiusSize, radiusSize, radiusSize, radiusSize });
                childRenderContext->UpdateBackgroundColor(index == childHoverIndex_
                                                            ? indexerTheme->GetHoverBgAreaColor()
                                                            : indexerTheme->GetPressedBgAreaColor());
            } else {
                auto radiusSize = indexerTheme->GetHoverRadiusSize();
                childRenderContext->UpdateBorderRadius({ radiusSize, radiusSize, radiusSize, radiusSize });
                childRenderContext->UpdateBackgroundColor(indexerTheme->GetHoverBgAreaColor());
            }
        } else if (index == childFocusIndex_ || index == selected_) {
            nodeLayoutProperty->UpdateContent(nodeStr);
            nodeLayoutProperty->UpdateTextAlign(TextAlign::CENTER);
            nodeLayoutProperty->UpdateAlignment(Alignment::CENTER);
            if (index == childFocusIndex_) {
                auto borderWidth = indexerTheme->GetFocusBgOutlineSize();
                nodeLayoutProperty->UpdateBorderWidth({ borderWidth, borderWidth, borderWidth, borderWidth });
                auto borderColor = indexerTheme->GetFocusBgOutlineColor();
                childRenderContext->UpdateBorderColor({ borderColor, borderColor, borderColor, borderColor });
                childRenderContext->UpdateBackgroundColor(
                    paintProperty->GetSelectedBackgroundColor().value_or(indexerTheme->GetSeclectedBackgroundColor()));
            } else {
                Dimension borderWidth;
                nodeLayoutProperty->UpdateBorderWidth({ borderWidth, borderWidth, borderWidth, borderWidth });
                if (!fromTouchUp || animateSelected_ == lastSelected_) {
                    childRenderContext->UpdateBackgroundColor(paintProperty->GetSelectedBackgroundColor().value_or(
                        indexerTheme->GetSeclectedBackgroundColor()));
                }
                childRenderContext->ResetBlendBorderColor();
            }
            nodeLayoutProperty->UpdateTextColor(
                layoutProperty->GetSelectedColor().value_or(indexerTheme->GetSelectedTextColor()));
            if (Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)) {
                auto radius = paintProperty->GetItemBorderRadius().has_value()
                                    ? paintProperty->GetItemBorderRadiusValue()
                                    : Dimension(INDEXER_ITEM_DEFAULT_RADIUS, DimensionUnit::VP);
                childRenderContext->UpdateBorderRadius({ radius, radius, radius, radius });
            } else {
                auto radius = indexerTheme->GetHoverRadiusSize();
                childRenderContext->UpdateBorderRadius({ radius, radius, radius, radius });
            }
            auto selectedFont = layoutProperty->GetSelectedFont().value_or(indexerTheme->GetSelectTextStyle());
            nodeLayoutProperty->UpdateFontSize(selectedFont.GetFontSize());
            auto fontWeight = selectedFont.GetFontWeight();
            nodeLayoutProperty->UpdateFontWeight(fontWeight);
            nodeLayoutProperty->UpdateFontFamily(selectedFont.GetFontFamilies());
            nodeLayoutProperty->UpdateItalicFontStyle(selectedFont.GetFontStyle());
            childNode->MarkModifyDone();
            if (isTextNodeInTree) {
                childNode->MarkDirtyNode();
            }
            index++;
            AccessibilityEventType type = AccessibilityEventType::SELECTED;
            host->OnAccessibilityEvent(type);
            auto textAccessibilityProperty = childNode->GetAccessibilityProperty<TextAccessibilityProperty>();
            if (textAccessibilityProperty) textAccessibilityProperty->SetSelected(true);
            continue;
        } else {
            if (!fromTouchUp || animateSelected_ == lastSelected_ || index != lastSelected_) {
                childRenderContext->UpdateBackgroundColor(Color::TRANSPARENT);
            }
            if (Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)) {
                auto radiusDefaultSize = Dimension(INDEXER_ITEM_DEFAULT_RADIUS, DimensionUnit::VP);
                childRenderContext->UpdateBorderRadius({ radiusDefaultSize, radiusDefaultSize,
                    radiusDefaultSize, radiusDefaultSize });
            } else {
                Dimension radiusZeroSize;
                childRenderContext->UpdateBorderRadius(
                    { radiusZeroSize, radiusZeroSize, radiusZeroSize, radiusZeroSize });
            }
        }
        Dimension borderWidth;
        nodeLayoutProperty->UpdateContent(nodeStr);
        nodeLayoutProperty->UpdateTextAlign(TextAlign::CENTER);
        nodeLayoutProperty->UpdateAlignment(Alignment::CENTER);
        nodeLayoutProperty->UpdateBorderWidth({ borderWidth, borderWidth, borderWidth, borderWidth });
        childRenderContext->ResetBlendBorderColor();
        auto defaultFont = layoutProperty->GetFont().value_or(indexerTheme->GetDefaultTextStyle());
        nodeLayoutProperty->UpdateFontSize(defaultFont.GetFontSize());
        nodeLayoutProperty->UpdateFontWeight(defaultFont.GetFontWeight());
        nodeLayoutProperty->UpdateFontFamily(defaultFont.GetFontFamilies());
        nodeLayoutProperty->UpdateItalicFontStyle(defaultFont.GetFontStyle());
        nodeLayoutProperty->UpdateTextColor(layoutProperty->GetColor().value_or(indexerTheme->GetDefaultTextColor()));
        index++;
        auto textAccessibilityProperty = childNode->GetAccessibilityProperty<TextAccessibilityProperty>();
        if (textAccessibilityProperty) textAccessibilityProperty->SetSelected(false);
        childNode->MarkModifyDone();
        if (isTextNodeInTree) childNode->MarkDirtyNode();
    }
    if (selectChanged) {
        ShowBubble();
    }
}

void IndexerPattern::ShowBubble()
{
    if (!NeedShowBubble() || itemCount_ < 1) {
        return;
    }
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    auto layoutProperty = host->GetLayoutProperty<IndexerLayoutProperty>();
    CHECK_NULL_VOID(layoutProperty);
    if (!popupNode_) {
        popupNode_ = CreatePopupNode();
        AddPopupTouchListener(popupNode_);
        InitPopupInputEvent();
        UpdatePopupOpacity(0.0f);
    }
    if (!layoutProperty->GetIsPopupValue(false)) {
        popupNode_->MountToParent(host);
        layoutProperty->UpdateIsPopup(true);
    }
    UpdateBubbleView();
    delayTask_.Cancel();
    StartBubbleAppearAnimation();
    if (!isTouch_) {
        StartDelayTask(INDEXER_BUBBLE_ENTER_DURATION + INDEXER_BUBBLE_WAIT_DURATION);
    }
}

RefPtr<FrameNode> IndexerPattern::CreatePopupNode()
{
    auto columnNode = FrameNode::CreateFrameNode(V2::COLUMN_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
        AceType::MakeRefPtr<LinearLayoutPattern>(true));
    CHECK_NULL_RETURN(columnNode, nullptr);

    if (!autoCollapse_) {
        auto letterNode = FrameNode::CreateFrameNode(
            V2::TEXT_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<TextPattern>());
        CHECK_NULL_RETURN(letterNode, nullptr);
        auto letterStackNode = FrameNode::CreateFrameNode(
            V2::STACK_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StackPattern>());
        CHECK_NULL_RETURN(letterStackNode, nullptr);
        letterStackNode->AddChild(letterNode);
        columnNode->AddChild(letterStackNode);
    }
    auto listNode = FrameNode::CreateFrameNode(
        V2::LIST_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<ListPattern>());
    CHECK_NULL_RETURN(listNode, nullptr);
    auto listStackNode = FrameNode::CreateFrameNode(
        V2::STACK_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StackPattern>());
    CHECK_NULL_RETURN(listStackNode, nullptr);
    listStackNode->AddChild(listNode);
    columnNode->AddChild(listStackNode);
    return columnNode;
}

void IndexerPattern::UpdateBubbleView()
{
    CHECK_NULL_VOID(popupNode_);
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    auto columnLayoutProperty = popupNode_->GetLayoutProperty<LinearLayoutProperty>();
    CHECK_NULL_VOID(columnLayoutProperty);
    auto indexerEventHub = host->GetEventHub<IndexerEventHub>();
    auto popListData = indexerEventHub->GetOnRequestPopupData();
    auto actualIndex =
        autoCollapse_ && selected_ > 0
            ? std::find(fullArrayValue_.begin(), fullArrayValue_.end(), arrayValue_.at(selected_).first) -
                  fullArrayValue_.begin()
            : selected_;
    auto actualChildIndex =
        autoCollapse_ && childPressIndex_ > 0
            ? std::find(fullArrayValue_.begin(), fullArrayValue_.end(), arrayValue_.at(childPressIndex_).first) -
                  fullArrayValue_.begin()
            : childPressIndex_;
    auto currentListData =
        popListData ? popListData(actualChildIndex >= 0 ? actualChildIndex : actualIndex) : std::vector<std::string>();
    UpdateBubbleListView(currentListData);
    UpdateBubbleLetterView(!currentListData.empty(), currentListData);
    auto columnRenderContext = popupNode_->GetRenderContext();
    CHECK_NULL_VOID(columnRenderContext);
    if (Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)) {
        auto columnPadding = Dimension(BUBBLE_DIVIDER_SIZE, DimensionUnit::VP).ConvertToPx();
        columnLayoutProperty->UpdatePadding({ CalcLength(0), CalcLength(0), CalcLength(columnPadding), CalcLength(0) });
        auto paintProperty = host->GetPaintProperty<IndexerPaintProperty>();
        CHECK_NULL_VOID(paintProperty);
        if (paintProperty->GetPopupBorderRadius().has_value()) {
            auto radius = paintProperty->GetPopupBorderRadiusValue();
            columnRenderContext->UpdateBorderRadius({ radius, radius, radius, radius });
        } else {
            auto radius = Dimension(BUBBLE_RADIUS, DimensionUnit::VP);
            columnRenderContext->UpdateBorderRadius({ radius, radius, radius, radius });
        }
        columnRenderContext->UpdateBackShadow(Shadow::CreateShadow(ShadowStyle::OuterDefaultLG));
    } else {
        auto radius = Dimension(BUBBLE_BOX_RADIUS, DimensionUnit::VP);
        columnRenderContext->UpdateBorderRadius({ radius, radius, radius, radius });
        columnRenderContext->UpdateBackShadow(Shadow::CreateShadow(ShadowStyle::OuterDefaultMD));
    }
    UpdateBubbleBackgroundView();
    columnRenderContext->SetClipToBounds(true);
    popupNode_->MarkModifyDone();
    popupNode_->MarkDirtyNode();
}

void IndexerPattern::UpdateBubbleBackgroundView()
{
    if (Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)) {
        CHECK_NULL_VOID(popupNode_);
        auto host = GetHost();
        CHECK_NULL_VOID(host);
        auto paintProperty = host->GetPaintProperty<IndexerPaintProperty>();
        CHECK_NULL_VOID(paintProperty);
        auto pipeline = PipelineContext::GetCurrentContext();
        CHECK_NULL_VOID(pipeline);
        auto indexerTheme = pipeline->GetTheme<IndexerTheme>();
        BlurStyleOption styleOption;
        if (paintProperty->GetPopupBackgroundBlurStyle().has_value()) {
            styleOption = paintProperty->GetPopupBackgroundBlurStyle().value();
        } else {
            styleOption.blurStyle = BlurStyle::COMPONENT_REGULAR;
        }
        auto bubbleRenderContext = popupNode_->GetRenderContext();
        CHECK_NULL_VOID(bubbleRenderContext);
        bubbleRenderContext->UpdateBackBlurStyle(styleOption);
        bubbleRenderContext->UpdateBackgroundColor(
            paintProperty->GetPopupBackground().value_or(indexerTheme->GetPopupBackgroundColor()));
    }
}

void IndexerPattern::UpdateBubbleSize()
{
    CHECK_NULL_VOID(popupNode_);
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    auto columnLayoutProperty = popupNode_->GetLayoutProperty<LinearLayoutProperty>();
    CHECK_NULL_VOID(columnLayoutProperty);
    auto indexerEventHub = host->GetEventHub<IndexerEventHub>();
    auto popListData = indexerEventHub->GetOnRequestPopupData();
    auto actualIndex =
        autoCollapse_ && selected_ > 0
            ? std::find(fullArrayValue_.begin(), fullArrayValue_.end(), arrayValue_.at(selected_).first) -
                  fullArrayValue_.begin()
            : selected_;
    auto actualChildIndex =
        autoCollapse_ && childPressIndex_ > 0
            ? std::find(fullArrayValue_.begin(), fullArrayValue_.end(), arrayValue_.at(childPressIndex_).first) -
                  fullArrayValue_.begin()
            : childPressIndex_;
    auto currentListData =
        popListData ? popListData(actualChildIndex >= 0 ? actualChildIndex : actualIndex) : std::vector<std::string>();
    auto popupSize = autoCollapse_ ? currentListData.size() + 1 : currentListData.size();

    auto bubbleSize = Dimension(BUBBLE_BOX_SIZE, DimensionUnit::VP).ConvertToPx();
    auto columnCalcOffset = autoCollapse_ ? 0 : 1;
    if (Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)) {
        auto maxItemsSize = autoCollapse_ ? INDEXER_BUBBLE_MAXSIZE_COLLAPSED_API_TWELVE : INDEXER_BUBBLE_MAXSIZE;
        auto bubbleHeight = Dimension(BUBBLE_ITEM_SIZE, DimensionUnit::VP).ConvertToPx();
        auto bubbleDivider = Dimension(BUBBLE_DIVIDER_SIZE, DimensionUnit::VP).ConvertToPx();
        auto columnCalcSize = CalcSize();
        if (popupSize <= maxItemsSize) {
            columnCalcSize = CalcSize(CalcLength(bubbleSize),
                CalcLength((bubbleHeight + bubbleDivider) * (static_cast<int32_t>(popupSize) + columnCalcOffset) +
                           bubbleDivider));
        } else {
            columnCalcSize = CalcSize(CalcLength(bubbleSize),
                CalcLength(Dimension(
                    autoCollapse_ ? BUBBLE_COLLAPSE_COLUMN_MAX_SIZE : BUBBLE_COLUMN_MAX_SIZE, DimensionUnit::VP)
                                .ConvertToPx()));
        }
        columnLayoutProperty->UpdateUserDefinedIdealSize(columnCalcSize);
    } else {
        auto maxItemsSize = autoCollapse_ ? INDEXER_BUBBLE_MAXSIZE_COLLAPSED : INDEXER_BUBBLE_MAXSIZE;
        auto listActualSize = popupSize < maxItemsSize ? popupSize : maxItemsSize;
        auto columnCalcSize = CalcSize(
            CalcLength(bubbleSize),
            CalcLength(bubbleSize * (static_cast<int32_t>(listActualSize) + columnCalcOffset)));
        columnLayoutProperty->UpdateUserDefinedIdealSize(columnCalcSize);
    }
    popupNode_->MarkDirtyNode();
}

void IndexerPattern::UpdateBubbleLetterView(bool showDivider, std::vector<std::string>& currentListData)
{
    CHECK_NULL_VOID(popupNode_);
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    auto pipeline = PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(pipeline);
    auto indexerTheme = pipeline->GetTheme<IndexerTheme>();
    CHECK_NULL_VOID(indexerTheme);
    auto paintProperty = host->GetPaintProperty<IndexerPaintProperty>();
    CHECK_NULL_VOID(paintProperty);
    auto layoutProperty = host->GetLayoutProperty<IndexerLayoutProperty>();
    CHECK_NULL_VOID(layoutProperty);
    auto letterNode = GetLetterNode();
    CHECK_NULL_VOID(letterNode);
    UpdateBubbleLetterStackAndLetterTextView();
    auto letterLayoutProperty = letterNode->GetLayoutProperty<TextLayoutProperty>();
    CHECK_NULL_VOID(letterLayoutProperty);
    auto letterNodeRenderContext = letterNode->GetRenderContext();
    if (Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)) {
        auto bubbleSize = Dimension(BUBBLE_ITEM_SIZE, DimensionUnit::VP).ConvertToPx();
        letterLayoutProperty->UpdateUserDefinedIdealSize(CalcSize(CalcLength(bubbleSize), CalcLength(bubbleSize)));
        auto letterContext = letterNode->GetRenderContext();
        CHECK_NULL_VOID(letterContext);
        auto radius = paintProperty->GetPopupItemBorderRadius().has_value()
                            ? paintProperty->GetPopupItemBorderRadiusValue()
                            : Dimension(BUBBLE_ITEM_RADIUS, DimensionUnit::VP);
        letterContext->UpdateBorderRadius({ radius, radius, radius, radius });
        letterNodeRenderContext->UpdateBackgroundColor(paintProperty->GetPopupTitleBackground().value_or(
            currentListData.size() > 0 ? indexerTheme->GetPopupTitleBackground() : Color(POPUP_TITLE_BG_COLOR_SINGLE)));
    } else {
        auto bubbleSize = Dimension(BUBBLE_BOX_SIZE, DimensionUnit::VP).ConvertToPx();
        letterLayoutProperty->UpdateUserDefinedIdealSize(CalcSize(CalcLength(bubbleSize), CalcLength(bubbleSize)));
        letterNodeRenderContext->UpdateBackgroundColor(
            paintProperty->GetPopupBackground().value_or(indexerTheme->GetPopupBackgroundColor()));
        auto zeroWidth = Dimension();
        if (showDivider) {
            letterLayoutProperty->UpdateBorderWidth(
                { zeroWidth, zeroWidth, zeroWidth, Dimension(INDEXER_LIST_DIVIDER) });
            auto boderColor = BorderColorProperty();
            boderColor.bottomColor = indexerTheme->GetPopupSeparateColor();
            letterNodeRenderContext->UpdateBorderColor(boderColor);
        } else {
            letterLayoutProperty->UpdateBorderWidth({ zeroWidth, zeroWidth, zeroWidth, zeroWidth });
        }
    }
    letterNodeRenderContext->SetClipToBounds(true);
    letterNode->MarkModifyDone();
    letterNode->MarkDirtyNode();
}

void IndexerPattern::UpdateBubbleLetterStackAndLetterTextView()
{
    CHECK_NULL_VOID(popupNode_);
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    auto pipeline = PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(pipeline);
    auto indexerTheme = pipeline->GetTheme<IndexerTheme>();
    CHECK_NULL_VOID(indexerTheme);
    auto layoutProperty = host->GetLayoutProperty<IndexerLayoutProperty>();
    CHECK_NULL_VOID(layoutProperty);
    auto letterNode = GetLetterNode();
    CHECK_NULL_VOID(letterNode);
    auto letterLayoutProperty = letterNode->GetLayoutProperty<TextLayoutProperty>();
    CHECK_NULL_VOID(letterLayoutProperty);
    letterLayoutProperty->UpdateContent(arrayValue_[childPressIndex_ >= 0 ? childPressIndex_ : selected_].first);
    auto popupTextFont = layoutProperty->GetPopupFont().value_or(indexerTheme->GetPopupTextStyle());
    letterLayoutProperty->UpdateFontSize(popupTextFont.GetFontSize());
    letterLayoutProperty->UpdateFontWeight(popupTextFont.GetFontWeight());
    letterLayoutProperty->UpdateFontFamily(popupTextFont.GetFontFamilies());
    letterLayoutProperty->UpdateItalicFontStyle(popupTextFont.GetFontStyle());
    letterLayoutProperty->UpdateTextColor(layoutProperty->GetPopupColor().value_or(indexerTheme->GetPopupTextColor()));
    letterLayoutProperty->UpdateTextAlign(TextAlign::CENTER);
    letterLayoutProperty->UpdateAlignment(Alignment::CENTER);
    auto textPadding = Dimension(IndexerTheme::TEXT_PADDING_LEFT, DimensionUnit::VP).ConvertToPx();
    letterLayoutProperty->UpdatePadding(
        { CalcLength(textPadding), CalcLength(textPadding), CalcLength(0), CalcLength(0) });

    if (!autoCollapse_ && Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)) {
        auto letterStackNode = DynamicCast<FrameNode>(popupNode_->GetFirstChild());
        CHECK_NULL_VOID(letterStackNode);
        auto letterStackLayoutProperty = letterStackNode->GetLayoutProperty<StackLayoutProperty>();
        CHECK_NULL_VOID(letterStackLayoutProperty);
        auto letterStackWidth = Dimension(BUBBLE_BOX_SIZE, DimensionUnit::VP).ConvertToPx();
        auto letterStackHeight = Dimension(BUBBLE_ITEM_SIZE + BUBBLE_DIVIDER_SIZE, DimensionUnit::VP).ConvertToPx();
        letterStackLayoutProperty->UpdateUserDefinedIdealSize(
            CalcSize(CalcLength(letterStackWidth), CalcLength(letterStackHeight)));
        auto letterStackPadding = Dimension(BUBBLE_DIVIDER_SIZE, DimensionUnit::VP).ConvertToPx();
        letterStackLayoutProperty->UpdatePadding({ CalcLength(letterStackPadding), CalcLength(letterStackPadding),
            CalcLength(0), CalcLength(letterStackPadding) });
    }
}

RefPtr<FrameNode> IndexerPattern::GetLetterNode()
{
    CHECK_NULL_RETURN(popupNode_, nullptr);
    return autoCollapse_ ? GetAutoCollapseLetterNode()
                            : DynamicCast<FrameNode>(popupNode_->GetFirstChild()->GetFirstChild());
}

RefPtr<FrameNode> IndexerPattern::GetAutoCollapseLetterNode()
{
    CHECK_NULL_RETURN(popupNode_, nullptr);
    return DynamicCast<FrameNode>(popupNode_->GetLastChild()->GetFirstChild()->GetFirstChild()->GetFirstChild());
}

void IndexerPattern::UpdateBubbleListView(std::vector<std::string>& currentListData)
{
    CHECK_NULL_VOID(popupNode_);
    if (Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)) {
        CreateBubbleListView(currentListData);
    }
    auto listNode = DynamicCast<FrameNode>(popupNode_->GetLastChild()->GetFirstChild());
    CHECK_NULL_VOID(listNode);
    auto pipeline = PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(pipeline);
    auto indexerTheme = pipeline->GetTheme<IndexerTheme>();
    CHECK_NULL_VOID(indexerTheme);
    auto listPattern = DynamicCast<ListPattern>(listNode->GetPattern());
    listPattern->SetNeedLinked(false);
    auto listLayoutProperty = listNode->GetLayoutProperty<ListLayoutProperty>();
    CHECK_NULL_VOID(listLayoutProperty);
    UpdateBubbleListSize(currentListData);
    auto popupSize = autoCollapse_ ? currentListData.size() + 1 : currentListData.size();
    if (Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)) {
        auto maxItemsSize = autoCollapse_ ? INDEXER_BUBBLE_MAXSIZE_COLLAPSED_API_TWELVE : INDEXER_BUBBLE_MAXSIZE;
        auto listPadding = Dimension(BUBBLE_DIVIDER_SIZE, DimensionUnit::VP).ConvertToPx();
        listLayoutProperty->UpdatePadding(
            { CalcLength(listPadding), CalcLength(listPadding), CalcLength(0), CalcLength(0) });
        UpdatePopupListGradientView(popupSize, maxItemsSize);
    }
    if (!currentListData.empty() || autoCollapse_) {
        UpdateBubbleListItem(currentListData, listNode, indexerTheme);
    } else {
        listNode->Clean();
    }
    auto divider = V2::ItemDivider();
    if (Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)) {
        divider.strokeWidth = Dimension(BUBBLE_DIVIDER_SIZE, DimensionUnit::VP);
    } else {
        divider.strokeWidth = Dimension(INDEXER_LIST_DIVIDER, DimensionUnit::PX);
        divider.color = indexerTheme->GetPopupSeparateColor();
    }
    listLayoutProperty->UpdateDivider(divider);
    listLayoutProperty->UpdateListDirection(Axis::VERTICAL);
    auto listPaintProperty = listNode->GetPaintProperty<ScrollablePaintProperty>();
    CHECK_NULL_VOID(listPaintProperty);
    listPaintProperty->UpdateScrollBarMode(DisplayMode::OFF);
    auto listRenderContext = listNode->GetRenderContext();
    CHECK_NULL_VOID(listRenderContext);
    listRenderContext->SetClipToBounds(true);
    listNode->MarkModifyDone();
    listNode->MarkDirtyNode();
}

void IndexerPattern::UpdateBubbleListSize(std::vector<std::string>& currentListData)
{
    CHECK_NULL_VOID(popupNode_);
    currentPopupIndex_ = childPressIndex_ >= 0 ? childPressIndex_ : selected_;
    auto popupSize = autoCollapse_ ? currentListData.size() + 1 : currentListData.size();
    if (Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)) {
        auto maxItemsSize = autoCollapse_ ? INDEXER_BUBBLE_MAXSIZE_COLLAPSED_API_TWELVE : INDEXER_BUBBLE_MAXSIZE;
        auto listActualSize = popupSize < maxItemsSize ? popupSize : maxItemsSize;
        lastPopupIndex_ = currentPopupIndex_;
        lastPopupSize_ = listActualSize;
        auto stackNode = DynamicCast<FrameNode>(popupNode_->GetLastChild());
        CHECK_NULL_VOID(stackNode);
        auto stackLayoutProperty = stackNode->GetLayoutProperty<StackLayoutProperty>();
        CHECK_NULL_VOID(stackLayoutProperty);
        auto listCalcSize = CalcBubbleListSize(popupSize, maxItemsSize);
        stackLayoutProperty->UpdateUserDefinedIdealSize(listCalcSize);
        auto listNode =  DynamicCast<FrameNode>(stackNode->GetFirstChild());
        CHECK_NULL_VOID(listNode);
        auto listLayoutProperty = listNode->GetLayoutProperty<ListLayoutProperty>();
        CHECK_NULL_VOID(listLayoutProperty);
        listLayoutProperty->UpdateUserDefinedIdealSize(listCalcSize);
    } else {
        auto maxItemsSize = autoCollapse_ ? INDEXER_BUBBLE_MAXSIZE_COLLAPSED : INDEXER_BUBBLE_MAXSIZE;
        auto listActualSize = popupSize < maxItemsSize ? popupSize : maxItemsSize;
        if (listActualSize != lastPopupSize_ || lastPopupIndex_ != currentPopupIndex_) {
            lastPopupIndex_ = currentPopupIndex_;
            CreateBubbleListView(currentListData);
            lastPopupSize_ = listActualSize;
        }
        auto bubbleSize = Dimension(BUBBLE_BOX_SIZE, DimensionUnit::VP).ConvertToPx();
        auto listNode = DynamicCast<FrameNode>(popupNode_->GetLastChild()->GetFirstChild());
        CHECK_NULL_VOID(listNode);
        auto listLayoutProperty = listNode->GetLayoutProperty<ListLayoutProperty>();
        CHECK_NULL_VOID(listLayoutProperty);
        listLayoutProperty->UpdateUserDefinedIdealSize(
            CalcSize(CalcLength(bubbleSize), CalcLength(bubbleSize * listActualSize)));
    }
}

void IndexerPattern::CreateBubbleListView(std::vector<std::string>& currentListData)
{
    CHECK_NULL_VOID(popupNode_);
    auto listNode = Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)
                        ? FrameNode::CreateFrameNode(V2::LIST_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
                            AceType::MakeRefPtr<ListPattern>())
                        : DynamicCast<FrameNode>(popupNode_->GetLastChild()->GetFirstChild());
    CHECK_NULL_VOID(listNode);
    if (Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)) {
        auto stackNode = DynamicCast<FrameNode>(popupNode_->GetLastChild());
        CHECK_NULL_VOID(stackNode);
        stackNode->Clean();
    } else {
        listNode->Clean();
    }

    if (autoCollapse_) {
        auto letterNode = FrameNode::CreateFrameNode(
            V2::TEXT_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<TextPattern>());
        CHECK_NULL_VOID(letterNode);
        auto listItemNode =
            FrameNode::CreateFrameNode(V2::LIST_ITEM_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
                AceType::MakeRefPtr<ListItemPattern>(nullptr, V2::ListItemStyle::NONE));
        listItemNode->AddChild(letterNode);
        listNode->AddChild(listItemNode);
    }

    for (uint32_t i = 0; i < currentListData.size(); i++) {
        auto listItemNode =
            FrameNode::CreateFrameNode(V2::LIST_ITEM_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
                AceType::MakeRefPtr<ListItemPattern>(nullptr, V2::ListItemStyle::NONE));
        auto textNode = FrameNode::CreateFrameNode(
            V2::TEXT_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<TextPattern>());
        listItemNode->AddChild(textNode);
        AddListItemClickListener(listItemNode, i);
        listNode->AddChild(listItemNode);
    }
    if (Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)) {
        auto stackNode = DynamicCast<FrameNode>(popupNode_->GetLastChild());
        CHECK_NULL_VOID(stackNode);
        stackNode->AddChild(listNode);
    }
}

void IndexerPattern::UpdatePopupListGradientView(int32_t popupSize, int32_t maxItemsSize)
{
    CHECK_NULL_VOID(popupNode_);
    auto listNode = DynamicCast<FrameNode>(popupNode_->GetLastChild()->GetFirstChild());
    CHECK_NULL_VOID(listNode);
    if (popupSize > maxItemsSize) {
        DrawPopupListGradient(PopupListGradientStatus::BOTTOM);
        auto listEventHub = listNode->GetEventHub<ListEventHub>();
        CHECK_NULL_VOID(listEventHub);
        auto onScroll = [weak = WeakClaim(this)](Dimension offset, ScrollState state) {
            auto pattern = weak.Upgrade();
            CHECK_NULL_VOID(pattern);
            auto popupNode = pattern->popupNode_;
            CHECK_NULL_VOID(popupNode);
            auto listNode = DynamicCast<FrameNode>(popupNode->GetLastChild()->GetFirstChild());
            CHECK_NULL_VOID(listNode);
            auto listPattern = listNode->GetPattern<ListPattern>();
            CHECK_NULL_VOID(listPattern);
            if (listPattern->IsAtTop()) {
                pattern->DrawPopupListGradient(PopupListGradientStatus::BOTTOM);
                return;
            } else if (listPattern->IsAtBottom()) {
                pattern->DrawPopupListGradient(PopupListGradientStatus::TOP);
                return;
            } else {
                pattern->DrawPopupListGradient(PopupListGradientStatus::BOTH);
                return;
            }
        };
        listEventHub->SetOnScroll(onScroll);
    } else {
        DrawPopupListGradient(PopupListGradientStatus::NONE);
    }
}

void IndexerPattern::DrawPopupListGradient(PopupListGradientStatus gradientStatus)
{
    CHECK_NULL_VOID(popupNode_);
    auto stackNode = DynamicCast<FrameNode>(popupNode_->GetLastChild());
    CHECK_NULL_VOID(stackNode);
    auto listNode = DynamicCast<FrameNode>(stackNode->GetFirstChild());
    auto listRenderContext = listNode->GetRenderContext();
    CHECK_NULL_VOID(listRenderContext);
    auto stackRenderContext = stackNode->GetRenderContext();
    CHECK_NULL_VOID(stackRenderContext);
    auto listStackHeight = autoCollapse_ ? BUBBLE_COLLAPSE_COLUMN_MAX_SIZE : BUBBLE_COLUMN_MAX_SIZE;
    auto gradientPercent = static_cast<float>(GRADIENT_COVER_HEIGHT / listStackHeight) ;
    NG::Gradient coverGradient;
    coverGradient.CreateGradientWithType(NG::GradientType::LINEAR);
    switch (gradientStatus) {
        case PopupListGradientStatus::TOP:
            coverGradient.AddColor(CreatePercentGradientColor(0, Color::TRANSPARENT));
            coverGradient.AddColor(CreatePercentGradientColor(gradientPercent, Color::WHITE));
            coverGradient.AddColor(CreatePercentGradientColor(1, Color::WHITE));
            break;
        case PopupListGradientStatus::BOTTOM:
            coverGradient.AddColor(CreatePercentGradientColor(0, Color::WHITE));
            coverGradient.AddColor(CreatePercentGradientColor(1 - gradientPercent, Color::WHITE));
            coverGradient.AddColor(CreatePercentGradientColor(1, Color::TRANSPARENT));
            break;
        case PopupListGradientStatus::BOTH:
            coverGradient.AddColor(CreatePercentGradientColor(0, Color::TRANSPARENT));
            coverGradient.AddColor(CreatePercentGradientColor(gradientPercent, Color::WHITE));
            coverGradient.AddColor(CreatePercentGradientColor(1 - gradientPercent, Color::WHITE));
            coverGradient.AddColor(CreatePercentGradientColor(1, Color::TRANSPARENT));
            break;
        case PopupListGradientStatus::NONE:
        default:
            coverGradient.AddColor(CreatePercentGradientColor(0, Color::WHITE));
            coverGradient.AddColor(CreatePercentGradientColor(1, Color::WHITE));
            break;
    }
    listRenderContext->UpdateBackBlendMode(BlendMode::SRC_IN);
    listRenderContext->UpdateBackBlendApplyType(BlendApplyType::OFFSCREEN);
    stackRenderContext->UpdateLinearGradient(coverGradient);
    stackRenderContext->UpdateBackBlendMode(BlendMode::SRC_OVER);
    stackRenderContext->UpdateBackBlendApplyType(BlendApplyType::OFFSCREEN);
}

GradientColor IndexerPattern::CreatePercentGradientColor(float percent, Color color)
{
    NG::GradientColor gredient = GradientColor(color);
    gredient.SetDimension(CalcDimension(percent * PERCENT_100, DimensionUnit::PERCENT));
    return gredient;
}

CalcSize IndexerPattern::CalcBubbleListSize(int32_t popupSize, int32_t maxItemsSize)
{
    auto bubbleSize = Dimension(BUBBLE_BOX_SIZE, DimensionUnit::VP).ConvertToPx();
    auto bubbleHeight = Dimension(BUBBLE_ITEM_SIZE, DimensionUnit::VP).ConvertToPx();
    auto bubbleDivider = Dimension(BUBBLE_DIVIDER_SIZE, DimensionUnit::VP).ConvertToPx();
    auto listCalcSize = CalcSize();
    if (popupSize <= maxItemsSize) {
        listCalcSize = CalcSize(
            CalcLength(bubbleSize),
            CalcLength((bubbleHeight + bubbleDivider) * static_cast<int32_t>(popupSize) - bubbleDivider));
    } else {
        if (autoCollapse_) {
            listCalcSize = CalcSize(
                CalcLength(bubbleSize),
                CalcLength(Dimension(BUBBLE_COLLAPSE_LIST_MAX_SIZE, DimensionUnit::VP).ConvertToPx()));
        } else {
            listCalcSize = CalcSize(
                CalcLength(bubbleSize),
                CalcLength(Dimension(BUBBLE_LIST_MAX_SIZE, DimensionUnit::VP).ConvertToPx()));
        }
    }
    return listCalcSize;
}

void IndexerPattern::UpdateBubbleListItem(
    std::vector<std::string>& currentListData, const RefPtr<FrameNode>& listNode, RefPtr<IndexerTheme>& indexerTheme)
{
    CHECK_NULL_VOID(listNode);
    CHECK_NULL_VOID(indexerTheme);
    auto layoutProperty = GetLayoutProperty<IndexerLayoutProperty>();
    CHECK_NULL_VOID(layoutProperty);
    auto paintProperty = GetPaintProperty<IndexerPaintProperty>();
    CHECK_NULL_VOID(paintProperty);
    auto popupSelectedTextColor =
        paintProperty->GetPopupSelectedColor().value_or(indexerTheme->GetPopupSelectedTextColor());
    auto popupUnselectedTextColor =
        paintProperty->GetPopupUnselectedColor().value_or(indexerTheme->GetPopupUnselectedTextColor());
    auto popupItemTextFontSize =
        layoutProperty->GetFontSize().value_or(indexerTheme->GetPopupTextStyle().GetFontSize());
    auto popupItemTextFontWeight =
        layoutProperty->GetFontWeight().value_or(indexerTheme->GetPopupTextStyle().GetFontWeight());
    auto bubbleSize = Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)
                          ? Dimension(BUBBLE_ITEM_SIZE, DimensionUnit::VP).ConvertToPx()
                          : Dimension(BUBBLE_BOX_SIZE, DimensionUnit::VP).ConvertToPx();
    for (uint32_t i = 0; i < currentListData.size(); i++) {
        auto childIndexOffset = autoCollapse_ ? 1 : 0;
        auto listItemNode = DynamicCast<FrameNode>(listNode->GetChildAtIndex(i + childIndexOffset));
        CHECK_NULL_VOID(listItemNode);
        auto listItemProperty = listItemNode->GetLayoutProperty<ListItemLayoutProperty>();
        CHECK_NULL_VOID(listItemProperty);
        listItemProperty->UpdateUserDefinedIdealSize(CalcSize(CalcLength(bubbleSize), CalcLength(bubbleSize)));
        listItemProperty->UpdateAlignment(Alignment::CENTER);
        auto listItemContext = listItemNode->GetRenderContext();
        CHECK_NULL_VOID(listItemContext);
        auto textNode = DynamicCast<FrameNode>(listItemNode->GetFirstChild());
        CHECK_NULL_VOID(textNode);
        auto textLayoutProperty = textNode->GetLayoutProperty<TextLayoutProperty>();
        CHECK_NULL_VOID(textLayoutProperty);
        textLayoutProperty->UpdateContent(currentListData.at(i));
        textLayoutProperty->UpdateFontSize(popupItemTextFontSize);
        textLayoutProperty->UpdateFontWeight(popupItemTextFontWeight);
        if (autoCollapse_) textLayoutProperty->UpdateMaxLines(1);
        textLayoutProperty->UpdateTextOverflow(autoCollapse_ ? TextOverflow::ELLIPSIS : TextOverflow::NONE);
        textLayoutProperty->UpdateEllipsisMode(EllipsisMode::TAIL);
        textLayoutProperty->UpdateTextColor(i == popupClickedIndex_ ?
            popupSelectedTextColor : popupUnselectedTextColor);
        textLayoutProperty->UpdateTextAlign(TextAlign::CENTER);
        textLayoutProperty->UpdateAlignment(Alignment::CENTER);
        UpdateBubbleListItemContext(listNode, indexerTheme, i);
        UpdateBubbleListItemMarkModify(textNode, listItemNode);
    }
}

void IndexerPattern::UpdateBubbleListItemContext(
    const RefPtr<FrameNode>& listNode, RefPtr<IndexerTheme>& indexerTheme, uint32_t pos)
{
    CHECK_NULL_VOID(listNode);
    auto layoutProperty = GetLayoutProperty<IndexerLayoutProperty>();
    CHECK_NULL_VOID(layoutProperty);
    auto paintProperty = GetPaintProperty<IndexerPaintProperty>();
    CHECK_NULL_VOID(paintProperty);
    auto childIndexOffset = autoCollapse_ ? 1 : 0;
    auto listItemNode = DynamicCast<FrameNode>(listNode->GetChildAtIndex(pos + childIndexOffset));
    CHECK_NULL_VOID(listItemNode);
    auto listItemContext = listItemNode->GetRenderContext();
    CHECK_NULL_VOID(listItemContext);
    if (Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)) {
        auto popupItemRadius = paintProperty->GetPopupItemBorderRadius().has_value()
                                    ? paintProperty->GetPopupItemBorderRadiusValue()
                                    : Dimension(BUBBLE_ITEM_RADIUS, DimensionUnit::VP);
        listItemContext->UpdateBorderRadius({ popupItemRadius, popupItemRadius, popupItemRadius, popupItemRadius });
        auto popupItemBackground =
            paintProperty->GetPopupItemBackground().value_or(indexerTheme->GetPopupUnclickedBgAreaColor());
        listItemContext->UpdateBackgroundColor(
            pos == popupClickedIndex_ ? (indexerTheme->GetPopupClickedBgAreaColor()) : popupItemBackground);
    } else {
        auto popupItemBackground =
            paintProperty->GetPopupItemBackground().value_or(indexerTheme->GetPopupBackgroundColor());
        listItemContext->UpdateBackgroundColor(
            pos == popupClickedIndex_ ? Color(POPUP_LISTITEM_CLICKED_BG) : popupItemBackground);
    }
}

void IndexerPattern::UpdateBubbleListItemMarkModify(RefPtr<FrameNode>& textNode, RefPtr<FrameNode>& listItemNode)
{
    textNode->MarkModifyDone();
    textNode->MarkDirtyNode();
    listItemNode->MarkModifyDone();
    listItemNode->MarkDirtyNode();
}

void IndexerPattern::ChangeListItemsSelectedStyle(int32_t clickIndex)
{
    popupClickedIndex_ = clickIndex;
    auto host = GetHost();
    CHECK_NULL_VOID(popupNode_);
    auto pipeline = PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(pipeline);
    auto indexerTheme = pipeline->GetTheme<IndexerTheme>();
    CHECK_NULL_VOID(indexerTheme);
    auto paintProperty = host->GetPaintProperty<IndexerPaintProperty>();
    CHECK_NULL_VOID(paintProperty);
    auto popupSelectedTextColor =
        paintProperty->GetPopupSelectedColor().value_or(indexerTheme->GetPopupSelectedTextColor());
    auto popupUnselectedTextColor =
        paintProperty->GetPopupUnselectedColor().value_or(indexerTheme->GetPopupUnselectedTextColor());
    auto popupItemBackground =
        Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)
            ? paintProperty->GetPopupItemBackground().value_or(indexerTheme->GetPopupUnclickedBgAreaColor())
            : paintProperty->GetPopupItemBackground().value_or(indexerTheme->GetPopupBackgroundColor());
    auto listNode = popupNode_->GetLastChild()->GetFirstChild();
    auto currentIndex = 0;
    for (auto child : listNode->GetChildren()) {
        if (autoCollapse_ && listNode->GetChildIndex(child) == 0) continue;
        auto listItemNode = DynamicCast<FrameNode>(child);
        CHECK_NULL_VOID(listItemNode);
        auto listItemProperty = listItemNode->GetLayoutProperty<ListItemLayoutProperty>();
        CHECK_NULL_VOID(listItemProperty);
        auto listItemContext = listItemNode->GetRenderContext();
        CHECK_NULL_VOID(listItemContext);
        auto textNode = DynamicCast<FrameNode>(listItemNode->GetFirstChild());
        CHECK_NULL_VOID(textNode);
        auto textLayoutProperty = textNode->GetLayoutProperty<TextLayoutProperty>();
        CHECK_NULL_VOID(textLayoutProperty);
        if (currentIndex == clickIndex) {
            textLayoutProperty->UpdateTextColor(popupSelectedTextColor);
            listItemContext->UpdateBackgroundColor(
                Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)
                    ? indexerTheme->GetPopupClickedBgAreaColor()
                    : Color(POPUP_LISTITEM_CLICKED_BG));
        } else {
            textLayoutProperty->UpdateTextColor(popupUnselectedTextColor);
            listItemContext->UpdateBackgroundColor(popupItemBackground);
        }
        textNode->MarkModifyDone();
        textNode->MarkDirtyNode();
        listItemNode->MarkDirtyNode(PROPERTY_UPDATE_RENDER);
        currentIndex++;
    }
}

void IndexerPattern::AddPopupTouchListener(RefPtr<FrameNode> popupNode)
{
    CHECK_NULL_VOID(popupNode);
    auto gesture = popupNode->GetOrCreateGestureEventHub();
    CHECK_NULL_VOID(gesture);
    auto touchCallback = [weak = WeakClaim(this)](const TouchEventInfo& info) {
        auto indexerPattern = weak.Upgrade();
        CHECK_NULL_VOID(indexerPattern);
        auto touchType = info.GetTouches().front().GetTouchType();
        if (touchType == TouchType::DOWN) {
            indexerPattern->isTouch_ = true;
            indexerPattern->OnPopupTouchDown(info);
        } else if (touchType == TouchType::UP || touchType == TouchType::CANCEL) {
            indexerPattern->isTouch_ = false;
            if (!indexerPattern->isPopupHover_) {
                indexerPattern->StartDelayTask();
            }
        }
    };
    gesture->AddTouchEvent(MakeRefPtr<TouchEventImpl>(std::move(touchCallback)));
}

void IndexerPattern::AddListItemClickListener(RefPtr<FrameNode>& listItemNode, int32_t index)
{
    CHECK_NULL_VOID(listItemNode);
    auto gestureHub = listItemNode->GetOrCreateGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    auto touchCallback = [weak = WeakClaim(this), index](const TouchEventInfo& info) {
        auto indexerPattern = weak.Upgrade();
        CHECK_NULL_VOID(indexerPattern);
        if (info.GetTouches().front().GetTouchType() == TouchType::DOWN) {
            indexerPattern->OnListItemClick(index);
        } else if (info.GetTouches().front().GetTouchType() == TouchType::UP) {
            indexerPattern->ClearClickStatus();
        }
    };
    gestureHub->AddTouchEvent(MakeRefPtr<TouchEventImpl>(std::move(touchCallback)));
}

void IndexerPattern::OnListItemClick(int32_t index)
{
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    auto indexerEventHub = host->GetEventHub<IndexerEventHub>();
    CHECK_NULL_VOID(indexerEventHub);
    auto onPopupSelected = indexerEventHub->GetOnPopupSelected();
    if (onPopupSelected) {
        onPopupSelected(index);
    }
    ChangeListItemsSelectedStyle(index);
}

void IndexerPattern::ClearClickStatus()
{
    ChangeListItemsSelectedStyle(-1);
}

void IndexerPattern::OnPopupTouchDown(const TouchEventInfo& info)
{
    if (NeedShowPopupView()) {
        delayTask_.Cancel();
        StartBubbleAppearAnimation();
    }
}

bool IndexerPattern::NeedShowBubble()
{
    auto host = GetHost();
    CHECK_NULL_RETURN(host, false);
    auto layoutProperty = host->GetLayoutProperty<IndexerLayoutProperty>();
    CHECK_NULL_RETURN(layoutProperty, false);
    auto usePopup = layoutProperty->GetUsingPopup().value_or(false);
    return usePopup && IfSelectIndexValid();
}

bool IndexerPattern::IfSelectIndexValid()
{
    return (selected_ >= 0 && selected_ < static_cast<int32_t>(arrayValue_.size()));
}

void IndexerPattern::InitOnKeyEvent()
{
    if (isKeyEventRegisted_) {
        return;
    }
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    auto focusHub = host->GetFocusHub();
    CHECK_NULL_VOID(focusHub);
    auto onKeyEvent = [wp = WeakClaim(this)](const KeyEvent& event) -> bool {
        auto pattern = wp.Upgrade();
        CHECK_NULL_RETURN(pattern, false);
        return pattern->OnKeyEvent(event);
    };
    isKeyEventRegisted_ = true;
    focusHub->SetOnKeyEventInternal(std::move(onKeyEvent));
}

bool IndexerPattern::OnKeyEvent(const KeyEvent& event)
{
    if (event.action != KeyAction::DOWN) {
        return false;
    }
    if (event.code == KeyCode::KEY_DPAD_UP) {
        return KeyIndexByStep(-1);
    }
    if (event.code == KeyCode::KEY_DPAD_DOWN) {
        return KeyIndexByStep(1);
    }
    if (!event.IsCombinationKey() && (event.IsLetterKey() || event.IsNumberKey())) {
        return MoveIndexBySearch(event.ConvertCodeToString());
    }
    OnKeyEventDisapear();
    return false;
}

void IndexerPattern::OnKeyEventDisapear()
{
    ResetStatus();
    ApplyIndexChanged(true, false);
}

void IndexerPattern::ItemSelectedInAnimation(RefPtr<FrameNode>& itemNode)
{
    CHECK_NULL_VOID(itemNode);
    auto rendercontext = itemNode->GetRenderContext();
    CHECK_NULL_VOID(rendercontext);
    AnimationOption option;
    option.SetDuration(INDEXER_SELECT_DURATION);
    option.SetCurve(Curves::LINEAR);
    AnimationUtils::Animate(option, [rendercontext, id = Container::CurrentId(), weak = WeakClaim(this)]() {
        ContainerScope scope(id);
        auto pipeline = PipelineContext::GetCurrentContext();
        CHECK_NULL_VOID(pipeline);
        auto indexerTheme = pipeline->GetTheme<IndexerTheme>();
        CHECK_NULL_VOID(indexerTheme);
        auto pattern = weak.Upgrade();
        CHECK_NULL_VOID(pattern);
        auto host = pattern->GetHost();
        CHECK_NULL_VOID(host);
        auto paintProperty = host->GetPaintProperty<IndexerPaintProperty>();
        CHECK_NULL_VOID(paintProperty);
        rendercontext->UpdateBackgroundColor(
            paintProperty->GetSelectedBackgroundColor().value_or(indexerTheme->GetSeclectedBackgroundColor()));
    });
}

void IndexerPattern::ItemSelectedOutAnimation(RefPtr<FrameNode>& itemNode)
{
    CHECK_NULL_VOID(itemNode);
    auto rendercontext = itemNode->GetRenderContext();
    CHECK_NULL_VOID(rendercontext);
    AnimationOption option;
    option.SetDuration(INDEXER_SELECT_DURATION);
    option.SetCurve(Curves::LINEAR);
    AnimationUtils::Animate(option, [rendercontext, id = Container::CurrentId()]() {
        ContainerScope scope(id);
        auto pipeline = PipelineContext::GetCurrentContext();
        CHECK_NULL_VOID(pipeline);
        auto indexerTheme = pipeline->GetTheme<IndexerTheme>();
        CHECK_NULL_VOID(indexerTheme);
        rendercontext->UpdateBackgroundColor(Color::TRANSPARENT);
    });
}

void IndexerPattern::IndexerHoverInAnimation()
{
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    auto renderContext = host->GetRenderContext();
    CHECK_NULL_VOID(renderContext);
    AnimationOption option;
    option.SetDuration(INDEXER_HOVER_IN_DURATION);
    option.SetCurve(Curves::FRICTION);
    AnimationUtils::Animate(option, [renderContext, id = Container::CurrentId()]() {
        ContainerScope scope(id);
        auto pipeline = PipelineContext::GetCurrentContext();
        CHECK_NULL_VOID(pipeline);
        auto indexerTheme = pipeline->GetTheme<IndexerTheme>();
        CHECK_NULL_VOID(indexerTheme);
        renderContext->UpdateBackgroundColor(
            indexerTheme->GetSlipHoverBackgroundColor());
    });
}

void IndexerPattern::IndexerHoverOutAnimation()
{
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    auto renderContext = host->GetRenderContext();
    CHECK_NULL_VOID(renderContext);
    AnimationOption option;
    option.SetDuration(INDEXER_HOVER_OUT_DURATION);
    option.SetCurve(Curves::FRICTION);
    AnimationUtils::Animate(option, [renderContext, id = Container::CurrentId()]() {
        ContainerScope scope(id);
        auto pipeline = PipelineContext::GetCurrentContext();
        CHECK_NULL_VOID(pipeline);
        auto indexerTheme = pipeline->GetTheme<IndexerTheme>();
        CHECK_NULL_VOID(indexerTheme);
        renderContext->UpdateBackgroundColor(Color::TRANSPARENT);
    });
}

void IndexerPattern::IndexerPressInAnimation()
{
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    auto renderContext = host->GetRenderContext();
    CHECK_NULL_VOID(renderContext);
    AnimationOption option;
    option.SetDuration(INDEXER_PRESS_IN_DURATION);
    option.SetCurve(Curves::SHARP);
    AnimationUtils::Animate(option, [renderContext, id = Container::CurrentId()]() {
        ContainerScope scope(id);
        auto pipeline = PipelineContext::GetCurrentContext();
        CHECK_NULL_VOID(pipeline);
        auto indexerTheme = pipeline->GetTheme<IndexerTheme>();
        CHECK_NULL_VOID(indexerTheme);
        renderContext->UpdateBackgroundColor(Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)
                                                 ? indexerTheme->GetSlipPressedBackgroundColor()
                                                 : indexerTheme->GetSlipHoverBackgroundColor());
    });
}

void IndexerPattern::IndexerPressOutAnimation()
{
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    auto renderContext = host->GetRenderContext();
    CHECK_NULL_VOID(renderContext);
    AnimationOption option;
    option.SetDuration(INDEXER_PRESS_OUT_DURATION);
    option.SetCurve(Curves::SHARP);
    AnimationUtils::Animate(option, [renderContext, id = Container::CurrentId()]() {
        ContainerScope scope(id);
        auto pipeline = PipelineContext::GetCurrentContext();
        CHECK_NULL_VOID(pipeline);
        auto indexerTheme = pipeline->GetTheme<IndexerTheme>();
        CHECK_NULL_VOID(indexerTheme);
        renderContext->UpdateBackgroundColor(Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)
                                                 ? indexerTheme->GetSlipPressedBackgroundColor()
                                                 : indexerTheme->GetSlipHoverBackgroundColor());
    });
}

void IndexerPattern::StartBubbleAppearAnimation()
{
    animationId_ = GenerateAnimationId();
    UpdatePopupVisibility(VisibleType::VISIBLE);
    AnimationOption option;
    option.SetCurve(Curves::SHARP);
    option.SetDuration(INDEXER_BUBBLE_ENTER_DURATION);
    AnimationUtils::Animate(
        option,
        [id = Container::CurrentId(), weak = AceType::WeakClaim(this)]() {
            ContainerScope scope(id);
            auto pattern = weak.Upgrade();
            CHECK_NULL_VOID(pattern);
            pattern->UpdatePopupOpacity(1.0f);
            pattern->UpdateBubbleSize();
        });
}

void IndexerPattern::StartDelayTask(uint32_t duration)
{
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    auto context = host->GetContext();
    CHECK_NULL_VOID(context);
    CHECK_NULL_VOID(context->GetTaskExecutor());
    delayTask_.Reset([weak = AceType::WeakClaim(this)] {
        auto pattern = weak.Upgrade();
        CHECK_NULL_VOID(pattern);
        pattern->StartBubbleDisappearAnimation();
        });
    context->GetTaskExecutor()->PostDelayedTask(
        delayTask_, TaskExecutor::TaskType::UI, duration, "ArkUIAlphabetIndexerBubbleDisappear");
}

void IndexerPattern::StartCollapseDelayTask(RefPtr<FrameNode>& hostNode, uint32_t duration)
{
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    auto context = host->GetContext();
    CHECK_NULL_VOID(context);
    CHECK_NULL_VOID(context->GetTaskExecutor());
    delayCollapseTask_.Reset([hostNode] {
        hostNode->MarkModifyDone();
        hostNode->MarkDirtyNode();
        });
    context->GetTaskExecutor()->PostDelayedTask(
        delayCollapseTask_, TaskExecutor::TaskType::UI, duration, "ArkUIAlphabetIndexerCollapse");
}

void IndexerPattern::StartBubbleDisappearAnimation()
{
    AnimationOption option;
    option.SetCurve(Curves::SHARP);
    option.SetDuration(INDEXER_BUBBLE_EXIT_DURATION);
    AnimationUtils::Animate(
        option,
        [id = Container::CurrentId(), weak = AceType::WeakClaim(this)]() {
            ContainerScope scope(id);
            auto pattern = weak.Upgrade();
            CHECK_NULL_VOID(pattern);
            pattern->UpdatePopupOpacity(0.0f);
        },
        [id = Container::CurrentId(), weak = AceType::WeakClaim(this)]() {
            ContainerScope scope(id);
            auto pattern = weak.Upgrade();
            CHECK_NULL_VOID(pattern);
            CHECK_NULL_VOID(pattern->popupNode_);
            auto rendercontext = pattern->popupNode_->GetRenderContext();
            CHECK_NULL_VOID(rendercontext);
            if (NearZero(rendercontext->GetOpacityValue(0.0f))) {
                pattern->UpdatePopupVisibility(VisibleType::GONE);
            }
        });
}

void IndexerPattern::UpdatePopupOpacity(float ratio)
{
    CHECK_NULL_VOID(popupNode_);
    auto rendercontext = popupNode_->GetRenderContext();
    CHECK_NULL_VOID(rendercontext);
    rendercontext->UpdateOpacity(ratio);
}

void IndexerPattern::UpdatePopupVisibility(VisibleType visible)
{
    CHECK_NULL_VOID(popupNode_);
    auto layoutProperty = popupNode_->GetLayoutProperty<LinearLayoutProperty>();
    CHECK_NULL_VOID(layoutProperty);
    auto currentVisibility = layoutProperty->GetVisibility().value_or(VisibleType::VISIBLE);
    if (currentVisibility != visible) {
        layoutProperty->UpdateVisibility(visible);
        popupNode_->MarkDirtyNode(PROPERTY_UPDATE_LAYOUT);
    }
}

bool IndexerPattern::NeedShowPopupView()
{
    CHECK_NULL_RETURN(popupNode_, false);
    auto layoutProperty = popupNode_->GetLayoutProperty<LinearLayoutProperty>();
    CHECK_NULL_RETURN(layoutProperty, false);
    return layoutProperty->GetVisibility().value_or(VisibleType::VISIBLE) == VisibleType::VISIBLE;
}

int32_t IndexerPattern::GenerateAnimationId()
{
    return (++animationId_) % TOTAL_NUMBER;
}

void IndexerPattern::FireOnSelect(int32_t selectIndex, bool fromPress)
{
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    auto indexerEventHub = host->GetEventHub<IndexerEventHub>();
    CHECK_NULL_VOID(indexerEventHub);
    auto actualIndex = autoCollapse_ ?
            selected_ > 0 ?
                std::find(fullArrayValue_.begin(), fullArrayValue_.end(),
                    arrayValue_.at(selected_).first) - fullArrayValue_.begin() :
                selected_ :
        selectIndex;
    if (fromPress || lastIndexFromPress_ == fromPress || lastFireSelectIndex_ != selectIndex) {
        auto onChangeEvent = indexerEventHub->GetChangeEvent();
        if (onChangeEvent && (selected_ >= 0) && (selected_ < itemCount_)) {
            onChangeEvent(selected_);
        }
        auto onCreatChangeEvent = indexerEventHub->GetCreatChangeEvent();
        if (onCreatChangeEvent && (selected_ >= 0) && (selected_ < itemCount_)) {
            onCreatChangeEvent(selected_);
        }
        auto onSelected = indexerEventHub->GetOnSelected();
        if (onSelected && (selectIndex >= 0) && (selectIndex < itemCount_)) {
            onSelected(actualIndex); // fire onSelected with an item's index from original array
        }
    }
    lastFireSelectIndex_ = selectIndex;
    lastIndexFromPress_ = fromPress;
}

void IndexerPattern::SetAccessibilityAction()
{
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    auto childrenNode = host->GetChildren();
    for (auto& iter : childrenNode) {
        auto textNode = DynamicCast<NG::FrameNode>(iter);
        CHECK_NULL_VOID(textNode);
        auto accessibilityProperty = textNode->GetAccessibilityProperty<AccessibilityProperty>();
        CHECK_NULL_VOID(accessibilityProperty);
        accessibilityProperty->SetActionSelect(
            [weakPtr = WeakClaim(this), node = WeakClaim(RawPtr(textNode)), childrenNode]() {
                const auto& indexerPattern = weakPtr.Upgrade();
                CHECK_NULL_VOID(indexerPattern);
                const auto& frameNode = node.Upgrade();
                CHECK_NULL_VOID(frameNode);
                auto index = 0;
                auto nodeId = frameNode->GetAccessibilityId();
                for (auto& child : childrenNode) {
                    if (child->GetAccessibilityId() == nodeId) {
                        break;
                    }
                    index++;
                }
                indexerPattern->selected_ = index;
                indexerPattern->ResetStatus();
                indexerPattern->ApplyIndexChanged(true, true, true);
                indexerPattern->OnSelect(true);
            });

        accessibilityProperty->SetActionClearSelection(
            [weakPtr = WeakClaim(this), node = WeakClaim(RawPtr(textNode)), childrenNode] {
                const auto& indexerPattern = weakPtr.Upgrade();
                CHECK_NULL_VOID(indexerPattern);
                const auto& frameNode = node.Upgrade();
                CHECK_NULL_VOID(frameNode);
                auto index = 0;
                auto nodeId = frameNode->GetAccessibilityId();
                for (auto& child : childrenNode) {
                    if (child->GetAccessibilityId() == nodeId) {
                        break;
                    }
                    index++;
                }
                if (indexerPattern->selected_ != index) {
                    return;
                }
                indexerPattern->selected_ = 0;
                indexerPattern->ResetStatus();
                indexerPattern->ApplyIndexChanged(true, false);
                indexerPattern->OnSelect(false);
            });
    }
}

void IndexerPattern::RemoveBubble()
{
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    host->RemoveChild(popupNode_);
    auto layoutProperty = host->GetLayoutProperty<IndexerLayoutProperty>();
    CHECK_NULL_VOID(layoutProperty);
    layoutProperty->UpdateIsPopup(false);
    popupNode_ = nullptr;
    lastPopupIndex_ = -1;
}

bool IndexerPattern::IsMeasureBoundary() const
{
    auto host = GetHost();
    CHECK_NULL_RETURN(host, false);
    auto layoutProperty = host->GetLayoutProperty<IndexerLayoutProperty>();
    CHECK_NULL_RETURN(layoutProperty, false);
    return CheckMeasureSelfFlag(layoutProperty->GetPropertyChangeFlag());
}

void IndexerPattern::UpdateChildBoundary(RefPtr<FrameNode>& frameNode)
{
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    auto layoutProperty = host->GetLayoutProperty<IndexerLayoutProperty>();
    CHECK_NULL_VOID(layoutProperty);
    CHECK_NULL_VOID(frameNode);
    auto pattern = DynamicCast<TextPattern>(frameNode->GetPattern());
    CHECK_NULL_VOID(pattern);
    auto isMeasureBoundary = layoutProperty->GetPropertyChangeFlag() ==  PROPERTY_UPDATE_NORMAL;
    pattern->SetIsMeasureBoundary(isMeasureBoundary);
}

void IndexerPattern::DumpInfo()
{
    auto layoutProperty = GetLayoutProperty<IndexerLayoutProperty>();
    CHECK_NULL_VOID(layoutProperty);
    DumpLog::GetInstance().AddDesc(
        std::string("AlignStyle: ")
            .append(std::to_string(static_cast<int32_t>(layoutProperty->GetAlignStyleValue(AlignStyle::END)))));
    auto offset = layoutProperty->GetPopupHorizontalSpace();
    DumpLog::GetInstance().AddDesc(
        std::string("Offset: ").append(offset.has_value() ? offset.value().ToString() : "undefined"));
    DumpLog::GetInstance().AddDesc(
        std::string("PopupPositionX: ")
            .append(layoutProperty->GetPopupPositionXValue(Dimension(NG::BUBBLE_POSITION_X, DimensionUnit::VP))
                        .ToString()));
    DumpLog::GetInstance().AddDesc(
        std::string("PopupPositionY: ")
            .append(layoutProperty->GetPopupPositionYValue(Dimension(NG::BUBBLE_POSITION_Y, DimensionUnit::VP))
                        .ToString()));
}
} // namespace OHOS::Ace::NG

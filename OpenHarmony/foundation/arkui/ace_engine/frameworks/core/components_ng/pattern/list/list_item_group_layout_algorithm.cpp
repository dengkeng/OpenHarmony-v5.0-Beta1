/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "core/components_ng/pattern/list/list_item_group_layout_algorithm.h"

#include "base/utils/utils.h"
#include "core/components/common/layout/grid_system_manager.h"
#include "core/components_ng/pattern/list/list_item_group_layout_property.h"
#include "core/components_ng/pattern/list/list_item_group_pattern.h"
#include "core/components_ng/pattern/list/list_item_pattern.h"
#include "core/components_ng/pattern/list/list_lanes_layout_algorithm.h"
#include "core/components_ng/property/measure_utils.h"

namespace OHOS::Ace::NG {

namespace {
constexpr uint32_t GRID_COUNTS_4 = 4;
constexpr uint32_t GRID_COUNTS_6 = 6;
constexpr uint32_t GRID_COUNTS_8 = 8;
constexpr uint32_t GRID_COUNTS_12 = 12;

uint32_t GetMaxGridCounts(const RefPtr<GridColumnInfo>& columnInfo)
{
    CHECK_NULL_RETURN(columnInfo, GRID_COUNTS_8);
    auto currentColumns = columnInfo->GetParent()->GetColumns();
    auto maxGridCounts = GRID_COUNTS_8;
    switch (currentColumns) {
        case GRID_COUNTS_4:
            maxGridCounts = GRID_COUNTS_4;
            break;
        case GRID_COUNTS_8:
            maxGridCounts = GRID_COUNTS_6;
            break;
        case GRID_COUNTS_12:
            maxGridCounts = GRID_COUNTS_8;
            break;
        default:
            break;
    }
    return maxGridCounts;
}
} // namespace

void ListItemGroupLayoutAlgorithm::Measure(LayoutWrapper* layoutWrapper)
{
    CHECK_NULL_VOID(listLayoutProperty_);
    auto layoutProperty = AceType::DynamicCast<ListItemGroupLayoutProperty>(layoutWrapper->GetLayoutProperty());
    CHECK_NULL_VOID(layoutProperty);
    axis_ = listLayoutProperty_->GetListDirection().value_or(Axis::VERTICAL);
    const auto& padding = layoutProperty->CreatePaddingAndBorder();
    paddingBeforeContent_ = axis_ == Axis::HORIZONTAL ? padding.left.value_or(0) : padding.top.value_or(0);
    paddingAfterContent_ = axis_ == Axis::HORIZONTAL ? padding.right.value_or(0) : padding.bottom.value_or(0);
    auto contentConstraint = layoutProperty->GetContentLayoutConstraint().value();
    auto contentIdealSize = CreateIdealSize(
        contentConstraint, axis_, layoutProperty->GetMeasureType(MeasureType::MATCH_PARENT_CROSS_AXIS));

    auto mainPercentRefer = GetMainAxisSize(contentConstraint.percentReference, axis_);
    auto space = layoutProperty->GetSpace().value_or(Dimension(0));

    auto layoutConstraint = layoutProperty->GetLayoutConstraint().value();
    CalculateLanes(listLayoutProperty_, layoutConstraint, contentIdealSize.CrossSize(axis_), axis_);
    childLayoutConstraint_ = layoutProperty->CreateChildConstraint();
    isCardStyle_ = IsCardStyleForListItemGroup(layoutWrapper);
    if (isCardStyle_) {
        auto maxWidth = GetListItemGroupMaxWidth(contentConstraint.parentIdealSize, layoutProperty) -
                        layoutProperty->CreatePaddingAndBorder().Width();
        contentIdealSize.SetCrossSize(maxWidth, axis_);
    }
    UpdateListItemConstraint(contentIdealSize, childLayoutConstraint_);
    referencePos_ = UpdateReferencePos(layoutProperty, forwardLayout_, referencePos_);
    totalItemCount_ = layoutWrapper->GetTotalChildCount() - itemStartIndex_;
    totalMainSize_ = layoutWrapper->GetGeometryNode()->GetPaddingSize().MainSize(axis_);
    spaceWidth_ = ConvertToPx(space, layoutConstraint.scaleProperty, mainPercentRefer).value_or(0);
    if (Negative(spaceWidth_) || GreatOrEqual(spaceWidth_, endPos_ - startPos_)) {
        spaceWidth_ = 0.0f;
    }
    if (layoutProperty->GetDivider().has_value()) {
        auto divider = layoutProperty->GetDivider().value();
        std::optional<float> dividerSpace = divider.strokeWidth.ConvertToPx();
        if (GreatOrEqual(dividerSpace.value(), endPos_ - startPos_)) {
            dividerSpace.reset();
        }
        if (dividerSpace.has_value()) {
            spaceWidth_ = std::max(spaceWidth_, dividerSpace.value());
        }
    }
    MeasureHeaderFooter(layoutWrapper);
    totalMainSize_ = std::max(totalMainSize_, headerMainSize_ + footerMainSize_);
    if (childrenSize_) {
        posMap_->UpdateGroupPosMap(totalItemCount_, GetLanes(), spaceWidth_, childrenSize_,
            headerMainSize_, footerMainSize_);
        totalMainSize_ = posMap_->GetTotalHeight();
    }
    MeasureListItem(layoutWrapper, childLayoutConstraint_);
    childrenSize_ ? AdjustByPosMap() : AdjustItemPosition();

    auto crossSize = contentIdealSize.CrossSize(axis_);
    if (crossSize.has_value() && GreaterOrEqualToInfinity(crossSize.value())) {
        contentIdealSize.SetCrossSize(GetChildMaxCrossSize(layoutWrapper, axis_), axis_);
    }
    contentIdealSize.SetMainSize(totalMainSize_, axis_);
    AddPaddingToSize(padding, contentIdealSize);
    layoutWrapper->GetGeometryNode()->SetFrameSize(contentIdealSize.ConvertToSizeT());
    layoutWrapper->SetCacheCount(listLayoutProperty_->GetCachedCountValue(1) * lanes_);
}

float ListItemGroupLayoutAlgorithm::GetListItemGroupMaxWidth(
    const OptionalSizeF& parentIdealSize, RefPtr<LayoutProperty> layoutProperty)
{
    RefPtr<GridColumnInfo> columnInfo;
    columnInfo = GridSystemManager::GetInstance().GetInfoByType(GridColumnType::LIST_CARD);
    columnInfo->GetParent()->BuildColumnWidth();
    auto maxGridWidth = static_cast<float>(columnInfo->GetWidth(GetMaxGridCounts(columnInfo)));
    auto parentWidth = parentIdealSize.CrossSize(axis_).value() + layoutProperty->CreatePaddingAndBorder().Width();
    auto maxWidth = std::min(parentWidth, maxGridWidth);
    return maxWidth;
}

void ListItemGroupLayoutAlgorithm::Layout(LayoutWrapper* layoutWrapper)
{
    SetActiveChildRange(layoutWrapper);
    const auto& layoutProperty = layoutWrapper->GetLayoutProperty();
    CHECK_NULL_VOID(layoutProperty);
    auto size = layoutWrapper->GetGeometryNode()->GetFrameSize();
    auto padding = layoutWrapper->GetLayoutProperty()->CreatePaddingAndBorder();
    MinusPaddingToSize(padding, size);
    auto left = padding.left.value_or(0.0f);
    auto top = padding.top.value_or(0.0f);
    auto paddingOffset = OffsetF(left, top);
    float crossSize = GetCrossAxisSize(size, axis_);
    CHECK_NULL_VOID(listLayoutProperty_);
    itemAlign_ = listLayoutProperty_->GetListItemAlign().value_or(V2::ListItemAlign::START);

    if (headerIndex_ >= 0 || footerIndex_ >= 0) {
        LayoutHeaderFooter(layoutWrapper, paddingOffset, crossSize);
    }
    // layout items.
    LayoutListItem(layoutWrapper, paddingOffset, crossSize);
}

void ListItemGroupLayoutAlgorithm::SyncGeometry(RefPtr<LayoutWrapper>& wrapper)
{
    CHECK_NULL_VOID(wrapper);
    auto host = wrapper->GetHostNode();
    CHECK_NULL_VOID(host);
    host->ForceSyncGeometryNode();
}

bool ListItemGroupLayoutAlgorithm::CheckNeedMeasure(const RefPtr<LayoutWrapper>& layoutWrapper) const
{
    if (layoutWrapper->CheckNeedForceMeasureAndLayout()) {
        return true;
    }
    auto geometryNode = layoutWrapper->GetGeometryNode();
    CHECK_NULL_RETURN(geometryNode, true);
    auto constraint = geometryNode->GetParentLayoutConstraint();
    CHECK_NULL_RETURN(constraint, true);
    return constraint.value() != childLayoutConstraint_;
}

void ListItemGroupLayoutAlgorithm::MeasureHeaderFooter(LayoutWrapper* layoutWrapper)
{
    const auto& layoutProperty = layoutWrapper->GetLayoutProperty();
    auto headerFooterLayoutConstraint = layoutProperty->CreateChildConstraint();
    headerFooterLayoutConstraint.maxSize.SetMainSize(Infinity<float>(), axis_);
    if (headerIndex_ >= 0) {
        auto headerWrapper = layoutWrapper->GetOrCreateChildByIndex(headerIndex_);
        CHECK_NULL_VOID(headerWrapper);
        headerWrapper->Measure(headerFooterLayoutConstraint);
        headerMainSize_ = GetMainAxisSize(headerWrapper->GetGeometryNode()->GetMarginFrameSize(), axis_);
    }
    if (footerIndex_ >= 0) {
        auto footerWrapper = layoutWrapper->GetOrCreateChildByIndex(footerIndex_);
        CHECK_NULL_VOID(footerWrapper);
        footerWrapper->Measure(headerFooterLayoutConstraint);
        footerMainSize_ = GetMainAxisSize(footerWrapper->GetGeometryNode()->GetMarginFrameSize(), axis_);
    }
}

void ListItemGroupLayoutAlgorithm::SetActiveChildRange(LayoutWrapper* layoutWrapper)
{
    if (itemPosition_.empty()) {
        layoutWrapper->SetActiveChildRange(-1, -1);
        return;
    }
    auto start = itemStartIndex_ + itemPosition_.begin()->first;
    auto end = itemStartIndex_ + itemPosition_.rbegin()->first;
    layoutWrapper->SetActiveChildRange(start, end);
}

void ListItemGroupLayoutAlgorithm::UpdateListItemConstraint(const OptionalSizeF& selfIdealSize,
    LayoutConstraintF& contentConstraint)
{
    contentConstraint.parentIdealSize = selfIdealSize;
    contentConstraint.maxSize.SetMainSize(Infinity<float>(), axis_);
    auto crossSizeOptional = selfIdealSize.CrossSize(axis_);
    if (crossSizeOptional.has_value()) {
        float crossSize = crossSizeOptional.value();
        if (lanes_ > 1) {
            crossSize = (crossSize + laneGutter_) / lanes_ - laneGutter_;
            crossSize = crossSize <= 0 ? 1 : crossSize;
        }
        if (maxLaneLength_.has_value() && maxLaneLength_.value() < crossSize) {
            crossSize = maxLaneLength_.value();
        }
        contentConstraint.percentReference.SetCrossSize(crossSize, axis_);
        contentConstraint.parentIdealSize.SetCrossSize(crossSize, axis_);
        contentConstraint.maxSize.SetCrossSize(crossSize, axis_);
        if (minLaneLength_.has_value()) {
            contentConstraint.minSize.SetCrossSize(minLaneLength_.value(), axis_);
        }
    }
}

float ListItemGroupLayoutAlgorithm::GetChildMaxCrossSize(LayoutWrapper* layoutWrapper, Axis axis)
{
    float maxCrossSize = 0.0f;
    for (const auto& pos : itemPosition_) {
        auto wrapper = layoutWrapper->GetOrCreateChildByIndex(pos.first, false);
        if (!wrapper) {
            continue;
        }
        auto getGeometryNode = wrapper->GetGeometryNode();
        if (!getGeometryNode) {
            continue;
        }
        maxCrossSize = std::max(maxCrossSize, getGeometryNode->GetMarginFrameSize().CrossSize(axis));
    }
    return maxCrossSize;
}

float ListItemGroupLayoutAlgorithm::UpdateReferencePos(
    RefPtr<LayoutProperty> layoutProperty, bool forwardLayout, float referencePos)
{
    const auto& padding = layoutProperty->CreatePaddingAndBorder();
    const auto& margin = layoutProperty->CreateMargin();
    auto offsetBeforeContent = axis_ == Axis::HORIZONTAL ? padding.left.value_or(0) : padding.top.value_or(0);
    auto offsetAfterContent = axis_ == Axis::HORIZONTAL ? padding.right.value_or(0) : padding.bottom.value_or(0);
    offsetBeforeContent += axis_ == Axis::HORIZONTAL ? margin.left.value_or(0) : margin.top.value_or(0);
    offsetAfterContent += axis_ == Axis::HORIZONTAL ? margin.right.value_or(0) : margin.bottom.value_or(0);
    forwardLayout ? referencePos += offsetBeforeContent : referencePos -= offsetAfterContent;
    return referencePos;
}

bool ListItemGroupLayoutAlgorithm::NeedMeasureItem()
{
    if (forwardLayout_) {
        if (childrenSize_ && needAdjustRefPos_) {
            referencePos_ -= (totalMainSize_ - posMap_->GetPrevTotalHeight());
            refPos_ -= (totalMainSize_ - posMap_->GetPrevTotalHeight());
        }
        if (GreatNotEqual(headerMainSize_, endPos_ - referencePos_)) {
            return false;
        }
        if (LessNotEqual(totalMainSize_ - footerMainSize_, startPos_ - referencePos_)) {
            return false;
        }
    } else {
        if (childrenSize_ && needAdjustRefPos_) {
            referencePos_ += (totalMainSize_ - posMap_->GetPrevTotalHeight());
            refPos_ += (totalMainSize_ - posMap_->GetPrevTotalHeight());
        }
        if (GreatNotEqual(headerMainSize_, endPos_ - (referencePos_ - totalMainSize_))) {
            return false;
        }
        if (LessNotEqual(totalMainSize_ - footerMainSize_, startPos_ - (referencePos_ - totalMainSize_))) {
            return false;
        }
    }
    return true;
}

void ListItemGroupLayoutAlgorithm::LayoutListItemAll(LayoutWrapper* layoutWrapper,
    const LayoutConstraintF& layoutConstraint, float startPos)
{
    int32_t currentIndex = -1;
    float currentEndPos = startPos;
    float currentStartPos = 0.0f;
    while (currentIndex < totalItemCount_) {
        currentStartPos = currentEndPos;
        int32_t count = MeasureALineForward(layoutWrapper, layoutConstraint, currentIndex,
            currentStartPos, currentEndPos);
        if (count == 0) {
            break;
        }
        if (currentIndex < (totalItemCount_ - 1)) {
            currentEndPos += spaceWidth_;
        }
    }
}

void ListItemGroupLayoutAlgorithm::ClearItemPosition(LayoutWrapper* layoutWrapper)
{
    itemPosition_.clear();
}

void ListItemGroupLayoutAlgorithm::MeasureListItem(
    LayoutWrapper* layoutWrapper, const LayoutConstraintF& layoutConstraint)
{
    if (totalItemCount_ <= 0) {
        totalMainSize_ = headerMainSize_ + footerMainSize_;
        itemPosition_.clear();
        return;
    }
    int32_t startIndex = 0;
    int32_t endIndex = totalItemCount_ - 1;
    float startPos = headerMainSize_;
    float endPos = totalMainSize_ - footerMainSize_;
    prevStartPos_ = startPos_;
    prevEndPos_ = endPos_;
    if (needAllLayout_) {
        needAllLayout_ = false;
        itemPosition_.clear();
        LayoutListItemAll(layoutWrapper, layoutConstraint, startPos);
        return;
    }
    if (targetIndex_) {
        startPos_ = -Infinity<float>();
        endPos_ = Infinity<float>();
    }
    if (jumpIndex_.has_value()) {
        if (jumpIndex_.value() == LAST_ITEM) {
            jumpIndex_ = totalItemCount_ - 1;
        }
        auto jumpIndex = jumpIndex_.value();
        if (jumpIndex < 0 || jumpIndex >= totalItemCount_) {
            jumpIndex = 0;
        }
        if (scrollAlign_ == ScrollAlign::CENTER || scrollAlign_ == ScrollAlign::START ||
            scrollAlign_ == ScrollAlign::AUTO) {
            startIndex = jumpIndex;
        } else if (scrollAlign_ == ScrollAlign::END) {
            endIndex = jumpIndex;
        } else if (forwardLayout_) {
            startIndex = jumpIndex;
        } else {
            endIndex = jumpIndex;
        }
        itemPosition_.clear();
        jumpIndex_.reset();
    } else if (!itemPosition_.empty()) {
        if (itemPosition_.begin()->first > 0 || (forwardLayout_ && Negative(referencePos_))) {
            startPos = itemPosition_.begin()->second.startPos;
        }
        endPos = itemPosition_.rbegin()->second.endPos;
        startIndex = GetStartIndex();
        if (startIndex >= totalItemCount_) {
            startIndex = totalItemCount_ - 1;
            if (itemPosition_.begin()->first > 0) {
                startPos = ((startPos - headerMainSize_) / GetLanesFloor(itemPosition_.begin()->first)) *
                               GetLanesFloor(startIndex) + headerMainSize_;
            }
        }
        endIndex = std::min(GetEndIndex(), totalItemCount_ - 1);
        if (forwardLayout_) {
            ModifyReferencePos(GetLanesFloor(startIndex), startPos);
        } else {
            ModifyReferencePos(GetLanesCeil(endIndex), endPos);
        }
        itemPosition_.clear();
    } else if (!NeedMeasureItem()) {
        itemPosition_.clear();
        return;
    }
    if (scrollAlign_ == ScrollAlign::CENTER) {
        startIndex = GetLanesFloor(startIndex);
        MeasureCenter(layoutWrapper, layoutConstraint, startIndex);
    } else if (scrollAlign_ == ScrollAlign::START) {
        startIndex = GetLanesFloor(startIndex);
        MeasureStart(layoutWrapper, layoutConstraint, startIndex);
    } else if (scrollAlign_ == ScrollAlign::END) {
        endIndex = GetLanesCeil(endIndex);
        MeasureEnd(layoutWrapper, layoutConstraint, endIndex);
    } else if (jumpIndex_.has_value() && scrollAlign_ == ScrollAlign::AUTO) {
        startIndex = GetLanesFloor(startIndex);
        MeasureAuto(layoutWrapper, layoutConstraint, startIndex);
    } else if (forwardLayout_) {
        startIndex = GetLanesFloor(startIndex);
        MeasureForward(layoutWrapper, layoutConstraint, startIndex, startPos);
    } else {
        endIndex = GetLanesCeil(endIndex);
        MeasureBackward(layoutWrapper, layoutConstraint, endIndex, endPos);
    }
}

std::pair<float, float> ListItemGroupLayoutAlgorithm::GetItemGroupPosition(int32_t index)
{
    V2::StickyStyle sticky = listLayoutProperty_->GetStickyStyle().value_or(V2::StickyStyle::NONE);
    if (scrollAlign_ == ScrollAlign::CENTER) {
        float mainLen = 0;
        float center = (startPos_ + endPos_) / 2;  // 2:average
        auto pos = itemPosition_.find(index);
        if (pos != itemPosition_.end()) {
            mainLen = pos->second.endPos - pos->second.startPos;
            float refPos = (pos->second.endPos + pos->second.startPos) / 2 + paddingBeforeContent_; // 2:average
            float delta = center - refPos;
            return { delta, totalMainSize_ + paddingBeforeContent_ + paddingAfterContent_ + delta };
        }
    } else if (scrollAlign_ == ScrollAlign::START) {
        auto pos = itemPosition_.find(index);
        if (pos != itemPosition_.end()) {
            float top = startPos_ + contentStartOffset_;
            if (sticky == V2::StickyStyle::HEADER || sticky == V2::StickyStyle::BOTH) {
                top += headerMainSize_;
            }
            float refPos = pos->second.startPos + paddingBeforeContent_;
            float delta = top - refPos;
            return { delta, totalMainSize_ + paddingBeforeContent_ + paddingAfterContent_ + delta };
        }
    } else if (scrollAlign_ == ScrollAlign::END) {
        auto pos = itemPosition_.find(index);
        if (pos != itemPosition_.end()) {
            float bottom = endPos_ - contentEndOffset_;
            if (sticky == V2::StickyStyle::FOOTER || sticky == V2::StickyStyle::BOTH) {
                bottom -= footerMainSize_;
            }
            float refPos = pos->second.endPos + paddingBeforeContent_;
            float delta = bottom - refPos;
            return { delta, totalMainSize_ + paddingBeforeContent_ + paddingAfterContent_ + delta };
        }
    }
    return { 0.0f, 0.0f };
}

float ListItemGroupLayoutAlgorithm::GetItemHeight(int32_t index)
{
    auto it = itemPosition_.find(index);
    if (it != itemPosition_.end()) {
        return it->second.endPos - it->second.startPos;
    }
    return 0.0f;
}

int32_t ListItemGroupLayoutAlgorithm::MeasureALineAuto(LayoutWrapper* layoutWrapper,
    const LayoutConstraintF& layoutConstraint, int32_t currentIndex)
{
    auto wrapper = GetListItem(layoutWrapper, currentIndex);
    if (!wrapper) {
        return 0;
    }
    if (CheckNeedMeasure(wrapper)) {
        ACE_SCOPED_TRACE("ListLayoutAlgorithm::MeasureListItem:%d", currentIndex);
        wrapper->Measure(layoutConstraint);
    }
    float mainLen = GetMainAxisSize(wrapper->GetGeometryNode()->GetMarginFrameSize(), axis_);
    int32_t id = wrapper->GetHostNode()->GetId();
    itemPosition_[currentIndex] = { id, 0.0f, mainLen };
    return 1;
}

int32_t ListItemGroupLayoutAlgorithm::MeasureALineCenter(LayoutWrapper* layoutWrapper,
    const LayoutConstraintF& layoutConstraint, int32_t currentIndex)
{
    float mainLen = 0;
    int32_t cnt = 0;
    int32_t lanes = lanes_ > 1 ? lanes_ : 1;
    for (int32_t i = 0; i < lanes && currentIndex + cnt < totalItemCount_; i++) {
        auto wrapper = GetListItem(layoutWrapper, currentIndex + cnt);
        if (!wrapper) {
            break;
        }
        if (CheckNeedMeasure(wrapper)) {
            ACE_SCOPED_TRACE("ListLayoutAlgorithm::MeasureListItem:%d", currentIndex + cnt);
            wrapper->Measure(layoutConstraint);
        }
        mainLen = std::max(mainLen, GetMainAxisSize(wrapper->GetGeometryNode()->GetMarginFrameSize(), axis_));
        cnt++;
    }
    if (cnt > 0) {
        auto startPos = (startPos_ + endPos_ - mainLen) / 2; // 2:average
        auto endPos = startPos + mainLen; // 2:average
        for (int32_t i = 0; i < cnt; i++) {
            auto wrapper = GetListItem(layoutWrapper, currentIndex + i);
            int32_t id = wrapper->GetHostNode()->GetId();
            itemPosition_[currentIndex + i] = { id, startPos, endPos };
        }
    }
    return cnt;
}

int32_t ListItemGroupLayoutAlgorithm::MeasureALineForward(LayoutWrapper* layoutWrapper,
    const LayoutConstraintF& layoutConstraint, int32_t& currentIndex, float startPos, float& endPos)
{
    float mainLen = 0.0f;
    int32_t cnt = 0;
    int32_t lanes = lanes_ > 1 ? lanes_ : 1;
    for (int32_t i = 0; i < lanes && currentIndex + 1 <= totalItemCount_; i++) {
        auto wrapper = GetListItem(layoutWrapper, currentIndex + 1);
        if (!wrapper) {
            break;
        }
        cnt++;
        ++currentIndex;
        if (CheckNeedMeasure(wrapper)) {
            ACE_SCOPED_TRACE("ListLayoutAlgorithm::MeasureListItem:%d", currentIndex);
            wrapper->Measure(layoutConstraint);
        }
        mainLen = std::max(mainLen, GetMainAxisSize(wrapper->GetGeometryNode()->GetMarginFrameSize(), axis_));
    }
    if (cnt > 0) {
        endPos = startPos + mainLen;
        for (int32_t i = 0; i < cnt; i++) {
            auto wrapper = GetListItem(layoutWrapper, currentIndex - i);
            int32_t id = wrapper->GetHostNode()->GetId();
            itemPosition_[currentIndex - i] = { id, startPos, endPos };
        }
    }
    return cnt;
}

int32_t ListItemGroupLayoutAlgorithm::MeasureALineBackward(LayoutWrapper* layoutWrapper,
    const LayoutConstraintF& layoutConstraint, int32_t& currentIndex, float endPos, float& startPos)
{
    float mainLen = 0.0f;
    int32_t cnt = 0;
    int32_t lanes = lanes_ > 1 ? lanes_ : 1;
    for (int32_t i = 0; i < lanes && currentIndex - 1 >= 0; i++) {
        auto wrapper = GetListItem(layoutWrapper, currentIndex - 1);
        if (!wrapper) {
            break;
        }
        --currentIndex;
        cnt++;
        if (CheckNeedMeasure(wrapper)) {
            ACE_SCOPED_TRACE("ListLayoutAlgorithm::MeasureListItem:%d", currentIndex);
            wrapper->Measure(layoutConstraint);
        }
        mainLen = std::max(mainLen, GetMainAxisSize(wrapper->GetGeometryNode()->GetMarginFrameSize(), axis_));
        if (currentIndex % lanes == 0) {
            break;
        }
    }
    if (cnt > 0) {
        startPos = endPos - mainLen;
        for (int32_t i = 0; i < cnt; i++) {
            auto wrapper = GetListItem(layoutWrapper, currentIndex + i);
            int32_t id = wrapper->GetHostNode()->GetId();
            itemPosition_[currentIndex + i] = { id, startPos, endPos };
        }
    }
    return cnt;
}

void ListItemGroupLayoutAlgorithm::MeasureCenter(LayoutWrapper* layoutWrapper,
    const LayoutConstraintF& layoutConstraint, int32_t startIndex)
{
    MeasureALineCenter(layoutWrapper, layoutConstraint, startIndex);
    MeasureJumpToItemForward(layoutWrapper, layoutConstraint, GetEndIndex() + 1, GetEndPosition());
    MeasureJumpToItemBackward(layoutWrapper, layoutConstraint, GetStartIndex() - 1, GetStartPosition());

    totalMainSize_ = GetEndPosition() - GetStartPosition() + headerMainSize_ + footerMainSize_;
    float currentStartPos = headerMainSize_;
    int32_t i = 0;
    int32_t lanes = lanes_ > 1 ? lanes_ : 1;
    for (auto& pos : itemPosition_) {
        float len = pos.second.endPos - pos.second.startPos;
        pos.second.startPos = currentStartPos;
        pos.second.endPos = currentStartPos + len;
        i++;
        if (i % lanes == 0) {
            currentStartPos = pos.second.endPos + spaceWidth_;
        }
    }
}

void ListItemGroupLayoutAlgorithm::MeasureAuto(LayoutWrapper* layoutWrapper,
    const LayoutConstraintF& layoutConstraint, int32_t startIndex)
{
    if (MeasureALineAuto(layoutWrapper, layoutConstraint, startIndex) == 0) {
        return;
    }

    totalMainSize_ = GetEndPosition() - GetStartPosition() + headerMainSize_ + footerMainSize_;
}

void ListItemGroupLayoutAlgorithm::MeasureJumpToItemForward(LayoutWrapper* layoutWrapper,
    const LayoutConstraintF& layoutConstraint, int32_t startIndex, float startPos)
{
    float currentStartPos = startPos;
    float currentEndPos = startPos;
    int32_t currentIndex = startIndex - 1;
    while (LessOrEqual(currentEndPos, endPos_)) {
        currentStartPos = currentEndPos;
        int32_t count = MeasureALineForward(layoutWrapper, layoutConstraint, currentIndex,
            currentStartPos, currentEndPos);
        if (count == 0) {
            break;
        }
        if (currentIndex < (totalItemCount_ - 1)) {
            currentEndPos += spaceWidth_;
        }
    }
}

void ListItemGroupLayoutAlgorithm::MeasureJumpToItemBackward(LayoutWrapper* layoutWrapper,
    const LayoutConstraintF& layoutConstraint, int32_t endIndex, float endPos)
{
    float currentEndPos = endPos;
    float currentStartPos = endPos;
    int32_t currentIndex = endIndex + 1;
    while (GreatOrEqual(currentStartPos, startPos_)) {
        currentEndPos = currentStartPos;
        int32_t count = MeasureALineBackward(layoutWrapper, layoutConstraint, currentIndex,
            currentEndPos, currentStartPos);
        if (count == 0) {
            break;
        }
        if (currentIndex > 0) {
            currentStartPos -= spaceWidth_;
        }
    }
}

void ListItemGroupLayoutAlgorithm::MeasureStart(LayoutWrapper* layoutWrapper,
    const LayoutConstraintF& layoutConstraint, int32_t startIndex)
{
    V2::StickyStyle sticky = listLayoutProperty_->GetStickyStyle().value_or(V2::StickyStyle::NONE);
    float currentStartPos = startPos_ + contentStartOffset_;
    if (sticky == V2::StickyStyle::HEADER || sticky == V2::StickyStyle::BOTH) {
        currentStartPos += headerMainSize_;
    }

    MeasureJumpToItemForward(layoutWrapper, layoutConstraint, startIndex, currentStartPos);
    if (GreatNotEqual(currentStartPos, startPos_)) {
        MeasureJumpToItemBackward(layoutWrapper, layoutConstraint, startIndex - 1, currentStartPos);
    }

    totalMainSize_ = GetEndPosition() - GetStartPosition() + headerMainSize_ + footerMainSize_;
    currentStartPos = headerMainSize_;
    int32_t i = 0;
    int32_t lanes = lanes_ > 1 ? lanes_ : 1;
    for (auto& pos : itemPosition_) {
        float len = pos.second.endPos - pos.second.startPos;
        pos.second.startPos = currentStartPos;
        pos.second.endPos = currentStartPos + len;
        i++;
        if (i % lanes == 0) {
            currentStartPos = pos.second.endPos + spaceWidth_;
        }
    }
}

void ListItemGroupLayoutAlgorithm::MeasureEnd(LayoutWrapper* layoutWrapper,
    const LayoutConstraintF& layoutConstraint, int32_t endIndex)
{
    V2::StickyStyle sticky = listLayoutProperty_->GetStickyStyle().value_or(V2::StickyStyle::NONE);
    float currentEndPos = endPos_ - contentEndOffset_;
    if (sticky == V2::StickyStyle::FOOTER || sticky == V2::StickyStyle::BOTH) {
        currentEndPos -= footerMainSize_;
    }

    MeasureJumpToItemBackward(layoutWrapper, layoutConstraint, endIndex, currentEndPos);
    if (LessNotEqual(currentEndPos, endPos_)) {
        MeasureJumpToItemForward(layoutWrapper, layoutConstraint, endIndex + 1, currentEndPos);
    }

    totalMainSize_ = GetEndPosition() - GetStartPosition() + headerMainSize_ + footerMainSize_;
    float currentStartPos = headerMainSize_;
    int32_t i = 0;
    int32_t lanes = lanes_ > 1 ? lanes_ : 1;
    for (auto& pos : itemPosition_) {
        float len = pos.second.endPos - pos.second.startPos;
        pos.second.startPos = currentStartPos;
        pos.second.endPos = currentStartPos + len;
        i++;
        if (i % lanes == 0) {
            currentStartPos = pos.second.endPos + spaceWidth_;
        }
    }
}

void ListItemGroupLayoutAlgorithm::MeasureForward(LayoutWrapper* layoutWrapper,
    const LayoutConstraintF& layoutConstraint, int32_t startIndex, float startPos)
{
    float currentEndPos = childrenSize_ ? posMap_->GetPos(startIndex) : startPos;
    float currentStartPos = 0.0f;
    int32_t currentIndex = startIndex - 1;
    while (LessOrEqual(currentEndPos, endPos_ - referencePos_)) {
        currentStartPos = currentEndPos;
        int32_t count = MeasureALineForward(layoutWrapper, layoutConstraint, currentIndex,
            currentStartPos, currentEndPos);
        if (count == 0) {
            break;
        }
        if (currentIndex < (totalItemCount_ - 1)) {
            currentEndPos += spaceWidth_;
        }
        if (targetIndex_ && GreatOrEqual(startIndex, targetIndex_.value())) {
            startPos_ = prevStartPos_;
            endPos_ = prevEndPos_;
            targetIndex_.reset();
        }
    }

    currentStartPos = GetStartPosition();
    currentIndex = GetStartIndex();
    float th = std::max(startPos_ - referencePos_, headerMainSize_);
    while (currentIndex > 0  && GreatNotEqual(currentStartPos, th)) {
        currentEndPos = currentStartPos;
        int32_t count = MeasureALineBackward(layoutWrapper, layoutConstraint, currentIndex,
            currentEndPos, currentStartPos);
        if (count == 0) {
            break;
        }
        if (currentIndex > 0) {
            currentStartPos = currentStartPos - spaceWidth_;
        }
    }
}

void ListItemGroupLayoutAlgorithm::MeasureBackward(LayoutWrapper* layoutWrapper,
    const LayoutConstraintF& layoutConstraint, int32_t endIndex, float endPos)
{
    float currentStartPos = childrenSize_ ? posMap_->GetPos(endIndex) + posMap_->GetRowHeight(endIndex) : endPos;
    float currentEndPos = 0.0f;
    auto currentIndex = endIndex + 1;
    while (GreatOrEqual(currentStartPos, startPos_ - (referencePos_ - totalMainSize_))) {
        currentEndPos = currentStartPos;
        int32_t count = MeasureALineBackward(layoutWrapper, layoutConstraint, currentIndex,
            currentEndPos, currentStartPos);
        if (count == 0) {
            break;
        }
        if (currentIndex > 0) {
            currentStartPos = currentStartPos - spaceWidth_;
        }
        if (targetIndex_ && LessOrEqual(endIndex, targetIndex_.value())) {
            startPos_ = prevStartPos_;
            endPos_ = prevEndPos_;
            targetIndex_.reset();
        }
    }
    currentIndex = GetEndIndex();
    currentEndPos = GetEndPosition();
    while (childrenSize_ && LessOrEqual(currentEndPos, endPos_ - (referencePos_ - totalMainSize_))) {
        currentStartPos = currentEndPos;
        int32_t count = MeasureALineForward(layoutWrapper, layoutConstraint, currentIndex,
            currentStartPos, currentEndPos);
        if (count == 0) {
            break;
        }
        if (currentIndex < (totalItemCount_ - 1)) {
            currentEndPos += spaceWidth_;
        }
    }
}

void ListItemGroupLayoutAlgorithm::ModifyReferencePos(int32_t index, float pos)
{
    if (!childrenSize_ || !needAdjustRefPos_) {
        return;
    }
    if (forwardLayout_ && Negative(referencePos_)) {
        float offset = referencePos_ + pos;
        float newReferencePos = offset - posMap_->GetPos(index);
        refPos_ = refPos_ + newReferencePos - referencePos_;
        referencePos_ = newReferencePos;
    } else if (!forwardLayout_ && GreatNotEqual(referencePos_, prevContentMainSize_)) {
        float offset = referencePos_ - posMap_->GetPrevTotalHeight() + pos - prevContentMainSize_;
        float newReferencePos = offset + endPos_ - startPos_ + totalMainSize_ -
            (posMap_->GetPos(index) + posMap_->GetRowHeight(index));
        refPos_ = refPos_ + newReferencePos - referencePos_;
        referencePos_ = newReferencePos;
    }
}

void ListItemGroupLayoutAlgorithm::AdjustByPosMap()
{
    totalMainSize_ = posMap_->GetTotalHeight();
    if (itemPosition_.empty()) {
        return;
    }
    float startPos = itemPosition_.begin()->second.startPos;
    float offset = posMap_->GetGroupLayoutOffset(GetStartIndex(), startPos);
    for (auto& pos : itemPosition_) {
        pos.second.startPos += offset;
        pos.second.endPos += offset;
    }
}

void ListItemGroupLayoutAlgorithm::AdjustItemPosition()
{
    if (itemPosition_.empty()) {
        return;
    }
    float currentStartPos = GetStartPosition();
    if (currentStartPos < headerMainSize_) {
        auto delta = headerMainSize_ - currentStartPos;
        for (auto& pos : itemPosition_) {
            pos.second.startPos += delta;
            pos.second.endPos += delta;
        }
        totalMainSize_ = std::max(totalMainSize_ + delta, GetEndPosition() + footerMainSize_);
    } else if (GetStartIndex() == 0 && currentStartPos > headerMainSize_) {
        auto delta = currentStartPos - headerMainSize_;
        for (auto& pos : itemPosition_) {
            pos.second.startPos -= delta;
            pos.second.endPos -= delta;
        }
        totalMainSize_ -= delta;
    }
    if (GetEndIndex() == totalItemCount_ - 1) {
        totalMainSize_ = GetEndPosition() + footerMainSize_;
    } else {
        totalMainSize_ = std::max(totalMainSize_, GetEndPosition() + footerMainSize_);
    }
    const auto& start = *itemPosition_.begin();
    const auto& end = *itemPosition_.rbegin();
    if (layoutedItemInfo_.has_value()) {
        auto& itemInfo = layoutedItemInfo_.value();
        if (start.first <= itemInfo.startIndex || LessNotEqual(start.second.startPos, itemInfo.startPos)) {
            itemInfo.startIndex = start.first;
            itemInfo.startPos = start.second.startPos;
        }
        if (end.first >= itemInfo.endIndex || LessNotEqual(end.second.endPos, itemInfo.endPos)) {
            itemInfo.endIndex = end.first;
            itemInfo.endPos = end.second.endPos;
        }
    } else {
        layoutedItemInfo_ = { start.first, start.second.startPos, end.first, end.second.endPos };
    }
}

void ListItemGroupLayoutAlgorithm::CheckRecycle(
    const RefPtr<LayoutWrapper>& layoutWrapper, float startPos, float endPos, float referencePos, bool forwardLayout)
{
    referencePos = UpdateReferencePos(layoutWrapper->GetLayoutProperty(), forwardLayout, referencePos);
    // Mark inactive in wrapper.
    if (forwardLayout) {
        for (auto pos = itemPosition_.begin(); pos != itemPosition_.end();) {
            if (GreatOrEqual(pos->second.endPos, startPos - referencePos)) {
                break;
            }
            itemPosition_.erase(pos++);
        }
        return;
    }
    std::list<int32_t> removeIndexes;
    for (auto pos = itemPosition_.rbegin(); pos != itemPosition_.rend(); ++pos) {
        if (LessOrEqual(pos->second.startPos, endPos - (referencePos - totalMainSize_))) {
            break;
        }
        removeIndexes.emplace_back(pos->first);
    }
    for (const auto& index : removeIndexes) {
        itemPosition_.erase(index);
    }
}

void ListItemGroupLayoutAlgorithm::LayoutListItem(LayoutWrapper* layoutWrapper,
    const OffsetF& paddingOffset, float crossSize)
{
    // layout items.
    for (auto& pos : itemPosition_) {
        auto wrapper = GetListItem(layoutWrapper, pos.first);
        if (!wrapper) {
            continue;
        }

        auto offset = paddingOffset;
        int32_t laneIndex = pos.first % lanes_;
        float childCrossSize = GetCrossAxisSize(wrapper->GetGeometryNode()->GetMarginFrameSize(), axis_);
        float laneCrossOffset = CalculateLaneCrossOffset((crossSize + GetLaneGutter()) / lanes_, childCrossSize);
        if (axis_ == Axis::VERTICAL) {
            offset =
                offset + OffsetF(0, pos.second.startPos) + OffsetF(laneCrossOffset, 0) +
                OffsetF(((crossSize + laneGutter_) / lanes_) * laneIndex, 0);
        } else {
            offset =
                offset + OffsetF(pos.second.startPos, 0) + OffsetF(0, laneCrossOffset) +
                OffsetF(0, ((crossSize + laneGutter_) / lanes_) * laneIndex);
        }
        SetListItemIndex(layoutWrapper, wrapper, pos.first);
        wrapper->GetGeometryNode()->SetMarginFrameOffset(offset);
        if (wrapper->CheckNeedForceMeasureAndLayout()) {
            wrapper->Layout();
        } else {
            SyncGeometry(wrapper);
        }
    }
}

void ListItemGroupLayoutAlgorithm::UpdateZIndex(const RefPtr<LayoutWrapper>& layoutWrapper)
{
    auto host = layoutWrapper->GetHostNode();
    CHECK_NULL_VOID(host);
    auto renderContext = host->GetRenderContext();
    CHECK_NULL_VOID(renderContext);
    renderContext->UpdateZIndex(1);
}

void ListItemGroupLayoutAlgorithm::LayoutHeaderFooter(LayoutWrapper* layoutWrapper,
    const OffsetF& paddingOffset, float crossSize)
{
    OffsetF selfOffset = layoutWrapper->GetGeometryNode()->GetPaddingOffset();
    selfOffset = selfOffset - listLayoutProperty_->CreatePaddingAndBorder().Offset();
    float mainPos = GetMainAxisOffset(selfOffset, axis_);
    float headerMainSize = 0.0f;
    V2::StickyStyle sticky = listLayoutProperty_->GetStickyStyle().value_or(V2::StickyStyle::NONE);
    if (headerIndex_ >= 0) {
        auto wrapper = layoutWrapper->GetOrCreateChildByIndex(headerIndex_);
        CHECK_NULL_VOID(wrapper);
        UpdateZIndex(wrapper);
        headerMainSize = wrapper->GetGeometryNode()->GetFrameSize().MainSize(axis_);
        float headerPos = 0.0f;
        if ((sticky == V2::StickyStyle::BOTH || sticky == V2::StickyStyle::HEADER) && !itemPosition_.empty()) {
            contentStartOffset_ = std::max(contentStartOffset_, 0.0f);
            float stickyPos = contentStartOffset_ - mainPos;
            if (GetEndIndex() == totalItemCount_ - 1) {
                stickyPos = std::min(stickyPos, GetEndPosition() - headerMainSize);
            }
            headerPos = std::max(headerPos, stickyPos);
        }
        LayoutIndex(wrapper, paddingOffset, crossSize, headerPos);
        startHeaderPos_ = startHeaderPos_ > mainPos ? mainPos : startHeaderPos_;
    }

    if (footerIndex_ >= 0) {
        float endPos = totalMainSize_ - footerMainSize_;
        auto wrapper = layoutWrapper->GetOrCreateChildByIndex(footerIndex_);
        UpdateZIndex(wrapper);
        CHECK_NULL_VOID(wrapper);
        float const listMainSize = endPos_ - startPos_;
        if (Positive(listMainSize) && (sticky == V2::StickyStyle::BOTH || sticky == V2::StickyStyle::FOOTER)) {
            auto footerMainSize = wrapper->GetGeometryNode()->GetFrameSize().MainSize(axis_);
            float stickyPos = listMainSize - contentEndOffset_ - mainPos - footerMainSize;
            if (stickyPos < headerMainSize) {
                stickyPos = headerMainSize;
            }
            if (stickyPos < endPos) {
                endPos = stickyPos;
            }
        }
        LayoutIndex(wrapper, paddingOffset, crossSize, endPos);
        endFooterPos_ = mainPos + totalMainSize_ - footerMainSize_ - listMainSize;
    }
}

void ListItemGroupLayoutAlgorithm::LayoutIndex(const RefPtr<LayoutWrapper>& wrapper, const OffsetF& paddingOffset,
    float crossSize, float startPos)
{
    CHECK_NULL_VOID(wrapper);
    auto offset = paddingOffset;
    float childCrossSize = GetCrossAxisSize(wrapper->GetGeometryNode()->GetMarginFrameSize(), axis_);
    float laneCrossOffset = CalculateLaneCrossOffset(crossSize, childCrossSize);
    if (axis_ == Axis::VERTICAL) {
        offset = offset + OffsetF(laneCrossOffset, startPos);
    } else {
        offset = offset + OffsetF(startPos, laneCrossOffset);
    }
    wrapper->GetGeometryNode()->SetMarginFrameOffset(offset);
    wrapper->Layout();
}

float ListItemGroupLayoutAlgorithm::CalculateLaneCrossOffset(float crossSize, float childCrossSize)
{
    float delta = crossSize - GetLaneGutter() - childCrossSize;
    if (LessOrEqual(delta, 0.0f)) {
        return 0.0f;
    }
    switch (itemAlign_) {
        case OHOS::Ace::V2::ListItemAlign::START:
            return 0.0f;
        case OHOS::Ace::V2::ListItemAlign::CENTER:
            return delta / 2; /* 2:average */
        case OHOS::Ace::V2::ListItemAlign::END:
            return delta;
        default:
            return 0.0f;
    }
}

void ListItemGroupLayoutAlgorithm::CalculateLanes(const RefPtr<ListLayoutProperty>& layoutProperty,
    const LayoutConstraintF& layoutConstraint, std::optional<float> crossSizeOptional, Axis axis)
{
    int32_t lanes = layoutProperty->GetLanes().value_or(1);
    lanes = lanes > 1 ? lanes : 1;
    if (crossSizeOptional.has_value()) {
        if (layoutProperty->GetLaneMinLength().has_value()) {
            minLaneLength_ = ConvertToPx(layoutProperty->GetLaneMinLength().value(),
                layoutConstraint.scaleProperty, crossSizeOptional.value());
        }
        if (layoutProperty->GetLaneMaxLength().has_value()) {
            maxLaneLength_ = ConvertToPx(layoutProperty->GetLaneMaxLength().value(),
                layoutConstraint.scaleProperty, crossSizeOptional.value());
        }
        if (layoutProperty->GetLaneGutter().has_value()) {
            auto laneGutter = ConvertToPx(
                layoutProperty->GetLaneGutter().value(), layoutConstraint.scaleProperty, crossSizeOptional.value());
            laneGutter_ = laneGutter.value();
        }
    }
    lanes_ = ListLanesLayoutAlgorithm::CalculateLanesParam(
        minLaneLength_, maxLaneLength_, lanes, crossSizeOptional, laneGutter_);
}

void ListItemGroupLayoutAlgorithm::SetListItemIndex(const LayoutWrapper* groupLayoutWrapper,
    const RefPtr<LayoutWrapper>& itemLayoutWrapper, int32_t indexInGroup)
{
    auto host = itemLayoutWrapper->GetHostNode();
    CHECK_NULL_VOID(host);
    auto listItem = host->GetPattern<ListItemPattern>();
    CHECK_NULL_VOID(listItem);
    listItem->SetIndexInListItemGroup(indexInGroup);

    host = groupLayoutWrapper->GetHostNode();
    CHECK_NULL_VOID(host);
    auto listItemGroup = host->GetPattern<ListItemGroupPattern>();
    CHECK_NULL_VOID(listItemGroup);
    listItem->SetIndexInList(listItemGroup->GetIndexInList());
}

bool ListItemGroupLayoutAlgorithm::IsCardStyleForListItemGroup(const LayoutWrapper* groupLayoutWrapper)
{
    auto host = groupLayoutWrapper->GetHostNode();
    CHECK_NULL_RETURN(host, false);
    auto listItemGroup = host->GetPattern<ListItemGroupPattern>();
    CHECK_NULL_RETURN(listItemGroup, false);
    return listItemGroup->GetListItemGroupStyle() == V2::ListItemGroupStyle::CARD;
}
} // namespace OHOS::Ace::NG

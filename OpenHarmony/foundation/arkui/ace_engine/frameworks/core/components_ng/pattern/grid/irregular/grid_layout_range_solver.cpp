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

#include "core/components_ng/pattern/grid/irregular/grid_layout_range_solver.h"

#include "core/components_ng/pattern/grid/grid_layout_property.h"
#include "core/components_ng/pattern/grid/irregular/grid_layout_utils.h"

namespace OHOS::Ace::NG {
GridLayoutRangeSolver::GridLayoutRangeSolver(GridLayoutInfo* info, LayoutWrapper* wrapper)
    : info_(info), wrapper_(wrapper)
{
    auto props = AceType::DynamicCast<GridLayoutProperty>(wrapper_->GetLayoutProperty());
    opts_ = &props->GetLayoutOptions().value();
};

using Result = GridLayoutRangeSolver::StartingRowInfo;
Result GridLayoutRangeSolver::FindStartingRow(float mainGap)
{
    if (info_->gridMatrix_.empty() || info_->lineHeightMap_.empty()) {
        return { 0, 0, 0.0f };
    }
    // Negative offset implies scrolling down, so we can start from the previous startIndex_.
    // Otherwise, we have to restart from Row 0 because of irregular items.
    if (NonPositive(info_->currentOffset_)) {
        return SolveForward(mainGap, -info_->currentOffset_, info_->startMainLineIndex_);
    }
    return SolveBackward(mainGap, info_->currentOffset_, info_->startMainLineIndex_);
}

using RangeInfo = GridLayoutRangeSolver::RangeInfo;
RangeInfo GridLayoutRangeSolver::FindRangeOnJump(int32_t jumpIdx, int32_t jumpLineIdx, float mainGap)
{
    auto mainSize = wrapper_->GetGeometryNode()->GetContentSize().MainSize(info_->axis_);
    /*
    Notice that  finding the first line in ScrollAlign::END is the same as having the jumpLine matching the top of the
    viewport and applying a positive whole-page offset, so we can directly use SolveBackward. But for
    ScrollAlign::START, we have to change SolveForward a bit to find the ending row.
    */
    switch (info_->scrollAlign_) {
        case ScrollAlign::START: {
            auto [startRow, startIdx] = CheckMultiRow(jumpLineIdx);
            float offset = -info_->GetHeightInRange(startRow, jumpLineIdx, mainGap);
            auto [endLineIdx, endIdx] = SolveForwardForEndIdx(mainGap, mainSize, jumpLineIdx);
            return { startRow, startIdx, offset, endLineIdx, endIdx };
        }
        case ScrollAlign::CENTER: {
            // align by item center
            auto size = GridLayoutUtils::GetItemSize(info_, wrapper_, jumpIdx);
            auto [centerLine, offset] = info_->FindItemCenter(jumpLineIdx, size.rows, mainGap);
            float halfMainSize = mainSize / 2.0f;
            auto [endLineIdx, endIdx] = SolveForwardForEndIdx(mainGap, halfMainSize + offset, centerLine);
            auto res = SolveBackward(mainGap, halfMainSize - offset, centerLine);
            return { res.row, res.idx, res.pos, endLineIdx, endIdx };
        }
        case ScrollAlign::END: {
            auto res = SolveBackward(mainGap, mainSize - info_->lineHeightMap_.at(jumpLineIdx), jumpLineIdx);
            return { res.row, res.idx, res.pos, jumpLineIdx, info_->FindEndIdx(jumpLineIdx).itemIdx };
        }
        default:
            return {};
    }
}

Result GridLayoutRangeSolver::SolveForward(float mainGap, float targetLen, const int32_t idx)
{
    float len = -mainGap;
    auto it = info_->lineHeightMap_.find(idx);
    for (; it != info_->lineHeightMap_.end(); ++it) {
        if (GreatNotEqual(len + it->second + mainGap, targetLen)) {
            break;
        }
        len += it->second + mainGap;
    }
    if (it == info_->lineHeightMap_.end()) {
        len -= (--it)->second + mainGap;
    }
    auto [startRow, startIdx] = CheckMultiRow(it->first);
    for (int32_t i = it->first; i > startRow; --i) {
        --it;
        len -= it->second + mainGap;
    }
    return { startRow, startIdx, len - targetLen + mainGap };
}

std::pair<int32_t, float> GridLayoutRangeSolver::AddNextRows(float mainGap, int32_t idx)
{
    int32_t rowCnt = 1;

    const auto& irregulars = opts_->irregularIndexes;
    // consider irregular items occupying multiple rows
    const auto& row = info_->gridMatrix_.at(idx);
    for (int c = 0; c < info_->crossCount_; ++c) {
        auto it = row.find(c);
        if (it == row.end()) {
            continue;
        }
        const auto& itemIdx = it->second;
        if (itemIdx < 0) {
            continue;
        }
        if (itemIdx == 0 && (idx > 0 || c > 0)) {
            continue;
        }
        if (opts_->getSizeByIndex && irregulars.find(itemIdx) != irregulars.end()) {
            auto size = opts_->getSizeByIndex(itemIdx);
            rowCnt = std::max(rowCnt, info_->axis_ == Axis::VERTICAL ? size.rows : size.columns);
        }
    }

    float len = 0.0f;
    for (int i = 0; i < rowCnt; ++i) {
        len += info_->lineHeightMap_.at(idx + i) + mainGap;
    }

    return { rowCnt, len };
}

std::pair<int32_t, int32_t> GridLayoutRangeSolver::SolveForwardForEndIdx(float mainGap, float targetLen, int32_t line)
{
    if (Negative(targetLen)) {
        return { -1, -1 };
    }
    float len = 0.0f;
    auto it = info_->lineHeightMap_.find(line);
    if (it == info_->lineHeightMap_.end()) {
        return { -1, -1 };
    }

    for (; LessNotEqual(len, targetLen) && it != info_->lineHeightMap_.end(); ++it) {
        len += it->second + mainGap;
    }
    --it;
    return { it->first, info_->FindEndIdx(it->first).itemIdx };
}

Result GridLayoutRangeSolver::SolveBackward(float mainGap, float targetLen, int32_t idx)
{
    float len = mainGap;
    while (idx > 0 && LessNotEqual(len, targetLen)) {
        len += info_->lineHeightMap_.at(--idx) + mainGap;
    }

    auto [startLine, startItem] = CheckMultiRow(idx);
    float newOffset = targetLen - len + mainGap;
    newOffset -= info_->GetHeightInRange(startLine, idx, mainGap);
    return { startLine, startItem, newOffset };
}

std::pair<int32_t, int32_t> GridLayoutRangeSolver::CheckMultiRow(const int32_t idx)
{
    // check multi-row item that occupies Row [idx]
    const auto& mat = info_->gridMatrix_;
    const auto& row = mat.at(idx);
    if (row.empty()) {
        return { -1, -1 };
    }
    int32_t startLine = idx;
    int32_t startItem = row.begin()->second;
    for (int32_t c = 0; c < info_->crossCount_; ++c) {
        auto it = row.find(c);
        if (it == row.end()) {
            continue;
        }

        int32_t r = idx;
        if (it->second == 0) {
            // Item 0 always start at [0, 0]
            return { 0, 0 };
        }
        if (it->second < 0) {
            // traverse upwards to find the first row occupied by this item
            while (r > 0 && mat.at(r).at(c) < 0) {
                --r;
            }
            if (r < startLine) {
                startLine = r;
                startItem = -it->second;
            }
        }

        // skip the columns occupied by this item
        int32_t itemIdx = std::abs(it->second);
        if (opts_->irregularIndexes.find(itemIdx) != opts_->irregularIndexes.end()) {
            if (opts_->getSizeByIndex) {
                auto size = opts_->getSizeByIndex(itemIdx);
                c += (info_->axis_ == Axis::VERTICAL ? size.columns : size.rows) - 1;
            } else {
                // no getSizeByIndex implies itemWidth == crossCount
                break;
            }
        }
    }
    return { startLine, startItem };
}
} // namespace OHOS::Ace::NG

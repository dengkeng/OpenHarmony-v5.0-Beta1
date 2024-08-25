/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "grid_test_ng.h"
#include "test/mock/core/pipeline/mock_pipeline_context.h"
#include "test/mock/core/render/mock_render_context.h"
#include "test/mock/core/rosen/mock_canvas.h"

#include "core/components_ng/base/view_stack_processor.h"
#include "core/components_ng/pattern/grid/grid_item_model_ng.h"
#include "core/components_ng/pattern/grid/grid_item_pattern.h"
#include "core/components_ng/pattern/grid/grid_item_theme.h"
#include "core/components_ng/pattern/grid/grid_layout/grid_layout_algorithm.h"
#include "core/components_ng/pattern/grid/grid_scroll/grid_scroll_with_options_layout_algorithm.h"
#include "core/components_ng/pattern/grid/irregular/grid_irregular_layout_algorithm.h"
#include "core/components_ng/pattern/grid/irregular/grid_layout_utils.h"
#include "core/components_ng/pattern/text_field/text_field_manager.h"

namespace OHOS::Ace::NG {

namespace {} // namespace

class GridLayoutTestNg : public GridTestNg {
public:
    void UpdateLayoutInfo();
    void UpdateLayoutWrapper(RefPtr<FrameNode>& frameNode, float width = GRID_WIDTH, float height = GRID_HEIGHT);
};

void GridLayoutTestNg::UpdateLayoutInfo()
{
    GetInstance();
    FlushLayoutTask(frameNode_);
    pattern_->gridLayoutInfo_.lineHeightMap_[0] = ITEM_HEIGHT;
    pattern_->gridLayoutInfo_.gridMatrix_[0][0] = 0;
    pattern_->gridLayoutInfo_.gridMatrix_[0][1] = 1;
    pattern_->gridLayoutInfo_.gridMatrix_[1][0] = 0;
    pattern_->gridLayoutInfo_.gridMatrix_[1][1] = 1;
}

void GridLayoutTestNg::UpdateLayoutWrapper(RefPtr<FrameNode>& frameNode, float width, float height)
{
    LayoutConstraintF LayoutConstraint;
    LayoutConstraint.parentIdealSize = { GRID_WIDTH, GRID_HEIGHT };
    LayoutConstraint.percentReference = { GRID_WIDTH, GRID_HEIGHT };
    LayoutConstraint.selfIdealSize = { width, height };
    LayoutConstraint.maxSize = { width, GRID_HEIGHT };
    frameNode->Measure(LayoutConstraint);
    frameNode->Layout();
}

/**
 * @tc.name: GridPaintMethodTest001
 * @tc.desc: Test grid paint method GetForegroundDrawFunction function
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GridPaintMethodTest001, TestSize.Level1)
{
    Create([](GridModelNG model) {
        model.SetRowsTemplate("1fr 1fr");
        CreateFixedItem(10);
    });
    auto paintMethod = AceType::DynamicCast<GridPaintMethod>(pattern_->CreateNodePaintMethod());
    auto paintProperty = pattern_->CreatePaintProperty();
    PaintWrapper paintWrapper(frameNode_->GetRenderContext(), frameNode_->GetGeometryNode(), paintProperty);
    auto drawFunction = paintMethod->GetForegroundDrawFunction(&paintWrapper);
    Testing::MockCanvas rsCanvas;
    EXPECT_CALL(rsCanvas, DetachPen()).WillRepeatedly(ReturnRef(rsCanvas));
    EXPECT_CALL(rsCanvas, AttachBrush(_)).WillRepeatedly(ReturnRef(rsCanvas));
    EXPECT_CALL(rsCanvas, DrawRect(_)).WillRepeatedly(Return());
    drawFunction(rsCanvas);
    paintMethod = nullptr;
    drawFunction(rsCanvas);

    /**
     * @tc.steps: step1. When EdgeEffect::SPRING
     * @tc.expected: CreateNodePaintMethod would not trigger SetEdgeEffect
     */
    pattern_->SetEdgeEffect(EdgeEffect::SPRING);
    paintMethod = AceType::DynamicCast<GridPaintMethod>(pattern_->CreateNodePaintMethod());
    EXPECT_EQ(paintMethod->edgeEffect_.Upgrade(), nullptr);

    /**
     * @tc.steps: step2. When EdgeEffect::FADE
     * @tc.expected: CreateNodePaintMethod would trigger SetEdgeEffect
     */
    pattern_->SetEdgeEffect(EdgeEffect::FADE);
    paintMethod = AceType::DynamicCast<GridPaintMethod>(pattern_->CreateNodePaintMethod());
    EXPECT_NE(paintMethod->edgeEffect_.Upgrade(), nullptr);
}

/**
 * @tc.name: ScrollLayout001
 * @tc.desc: Test UpdateOffsetOnVirtualKeyboardHeightChange
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, ScrollLayout001, TestSize.Level1)
{
    auto textFieldManager = AceType::MakeRefPtr<TextFieldManagerNG>();
    MockPipelineContext::GetCurrent()->SetTextFieldManager(textFieldManager);
    auto textFieldPattern = AceType::MakeRefPtr<Pattern>();
    textFieldManager->SetOnFocusTextField(textFieldPattern);
    const Offset clickPosition = Offset(100.f, GRID_HEIGHT + ITEM_HEIGHT);
    textFieldManager->SetClickPosition(clickPosition);

    Create([](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr 1fr 1fr");
        model.SetMaxCount(2);
        CreateFixedItem(18);
    });
    const float smallerHeight = GRID_HEIGHT - ITEM_HEIGHT;
    RectF gridRect(0.f, 0.f, GRID_WIDTH, smallerHeight);
    auto mockRenderContext = AceType::DynamicCast<MockRenderContext>(frameNode_->renderContext_);
    mockRenderContext->rect_ = gridRect;

    /**
     * @tc.steps: step1. Change to smaller mainSize
     * @tc.expected: The mainSize is correct
     */
    auto gridFocus = frameNode_->GetOrCreateFocusHub();
    gridFocus->RequestFocusImmediately();
    // change grid height and trigger Measure
    UpdateLayoutWrapper(frameNode_, GRID_WIDTH, smallerHeight);
    float gridHeight = frameNode_->GetGeometryNode()->GetFrameSize().Height();
    EXPECT_FLOAT_EQ(gridHeight, smallerHeight);
}

/**
 * @tc.name: ScrollLayout002
 * @tc.desc: Test UpdateOffsetOnVirtualKeyboardHeightChange that currentOffset wuold not change
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, ScrollLayout002, TestSize.Level1)
{
    auto textFieldManager = AceType::MakeRefPtr<TextFieldManagerNG>();
    MockPipelineContext::GetCurrent()->SetTextFieldManager(textFieldManager);
    auto textFieldPattern = AceType::MakeRefPtr<Pattern>();
    textFieldManager->SetOnFocusTextField(textFieldPattern);
    const Offset clickPosition = Offset(100.f, 100.f);
    textFieldManager->SetClickPosition(clickPosition);

    Create([](GridModelNG model) {
        model.SetRowsTemplate("1fr 1fr 1fr 1fr");
        model.SetMaxCount(2);
        CreateFixedItem(18);
    });

    /**
     * @tc.steps: step1. While axis_ == Axis::HORIZONTAL
     * @tc.expected: currentOffset_ would not change
     */
    pattern_->gridLayoutInfo_.axis_ = Axis::HORIZONTAL;
    const float smallerHeight = GRID_HEIGHT - ITEM_HEIGHT;
    // change grid height and trigger Measure
    UpdateLayoutWrapper(frameNode_, GRID_WIDTH, smallerHeight);
    float currentOffset = pattern_->gridLayoutInfo_.currentOffset_;
    EXPECT_FLOAT_EQ(currentOffset, 0.f);

    /**
     * @tc.steps: step2. While Grid !IsCurrentFocus()
     * @tc.expected: currentOffset_ would not change
     */
    UpdateLayoutWrapper(frameNode_, GRID_WIDTH, GRID_HEIGHT); // reset Grid height
    pattern_->gridLayoutInfo_.axis_ = Axis::VERTICAL;
    // change grid height and trigger Measure
    UpdateLayoutWrapper(frameNode_, GRID_WIDTH, smallerHeight);
    currentOffset = pattern_->gridLayoutInfo_.currentOffset_;
    EXPECT_FLOAT_EQ(currentOffset, 0.f);

    /**
     * @tc.steps: step3. While clickPosition is in Grid
     * @tc.expected: currentOffset_ would not change
     */
    UpdateLayoutWrapper(frameNode_, GRID_WIDTH, GRID_HEIGHT); // reset Grid height
    pattern_->gridLayoutInfo_.axis_ = Axis::VERTICAL;
    // change grid height and trigger Measure
    UpdateLayoutWrapper(frameNode_, GRID_WIDTH, smallerHeight);
    currentOffset = pattern_->gridLayoutInfo_.currentOffset_;
    EXPECT_FLOAT_EQ(currentOffset, 0.f);
}

/**
 * @tc.name: AdaptiveLayout001
 * @tc.desc: Test property AdaptiveLayout
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, AdaptiveLayout001, TestSize.Level1)
{
    float itemWidth = 100.f;
    Create([itemWidth](GridModelNG model) {
        model.SetLayoutDirection(FlexDirection::ROW);
        model.SetEditable(true);
        model.SetCellLength(ITEM_HEIGHT);
        model.SetMinCount(4);
        model.SetMaxCount(2);
        CreateItem(10, itemWidth, ITEM_HEIGHT);
    });

    /**
     * @tc.steps: step1. While the before set minCount > maxCount
     * @tc.expected: would let minCount = 1, maxCount = Infinity;
     */
    int32_t colsNumber = 4; // 4 * 100(itemWidth) < 480(gridWidth)
    for (int32_t index = 0; index < 10; index++) {
        RectF childRect = GetChildRect(frameNode_, index);
        float offsetX = index % colsNumber * itemWidth;
        float offsetY = floor(index / colsNumber) * ITEM_HEIGHT;
        RectF expectRect = RectF(offsetX, offsetY, itemWidth, ITEM_HEIGHT);
        EXPECT_TRUE(IsEqual(childRect, expectRect)) << "index: " << index;
    }
}

/**
 * @tc.name: GridScrollTest001
 * @tc.desc: Test FireOnScrollBarUpdate Function.
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GridScrollTest001, TestSize.Level1)
{
    Create([](GridModelNG model) {
        ScrollBarUpdateFunc scrollFunc = [](int32_t index, Dimension offset) {
            std::optional<float> horizontalOffset = offset.ConvertToPx();
            std::optional<float> verticalOffset = offset.ConvertToPx();
            return std::make_pair(horizontalOffset, verticalOffset);
        };
        model.SetRowsTemplate("1fr 1fr");
        model.SetRowsGap(Dimension(5));
        model.SetOnScrollBarUpdate(std::move(scrollFunc));
        CreateBigItem(1, 1, 1, 2);
        CreateFixedItem(2);
    });
    Dimension offset(1.0);
    auto fireOnScroll = eventHub_->FireOnScrollBarUpdate(1.0, offset);
    EXPECT_FLOAT_EQ(fireOnScroll.first.value(), 1.0f);
    EXPECT_FLOAT_EQ(fireOnScroll.second.value(), 1.0f);
}

/**
 * @tc.name: GridScrollTest002
 * @tc.desc: Test CalculateLargeItemOffset Function.
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GridScrollTest002, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create girdItem and initialize related properties.
     */
    GridModelNG model;
    model.Create(nullptr, nullptr);
    ViewAbstract::SetWidth(CalcLength(GRID_WIDTH));
    ViewAbstract::SetHeight(CalcLength(GRID_HEIGHT));
    model.SetRowsTemplate("1fr 1fr");
    model.SetRowsGap(Dimension(5));
    UpdateLayoutInfo();
    auto gridScrollLayoutAlgorithm = AceType::MakeRefPtr<GridScrollLayoutAlgorithm>(pattern_->gridLayoutInfo_, 2, 0);
    ASSERT_NE(gridScrollLayoutAlgorithm, nullptr);
    auto ret = gridScrollLayoutAlgorithm->CalculateLargeItemOffset(OffsetF(100, 100), 0, 1, 0);
    EXPECT_EQ(ret.GetY(), 100.f - ITEM_HEIGHT);
    EXPECT_EQ(ret.GetX(), 100.f);
}

/**
 * @tc.name: GridScrollTest003
 * @tc.desc: Test CalculateLargeItemOffset Function.
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GridScrollTest003, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create girdItem and initialize related properties.
     */
    GridModelNG model;
    model.Create(nullptr, nullptr);
    ViewAbstract::SetWidth(CalcLength(GRID_WIDTH));
    ViewAbstract::SetHeight(CalcLength(GRID_HEIGHT));
    model.SetColumnsTemplate("1fr 1fr");
    model.SetRowsGap(Dimension(5));
    CreateFixedItem(10);
    UpdateLayoutInfo();
    auto gridScrollLayoutAlgorithm = AceType::MakeRefPtr<GridScrollLayoutAlgorithm>(pattern_->gridLayoutInfo_, 2, 0);
    ASSERT_NE(gridScrollLayoutAlgorithm, nullptr);
    auto ret = gridScrollLayoutAlgorithm->CalculateLargeItemOffset(OffsetF(0, 100), 1, 1, 0);
    EXPECT_EQ(ret.GetY(), 100.0f);
    EXPECT_EQ(ret.GetX(), 0.0f);
}

/**
 * @tc.name: GridScrollTest004
 * @tc.desc: Test CalculateLargeItemOffset Function.
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GridScrollTest004, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create girdItem and initialize related properties.
     */
    GridModelNG model;
    model.Create(nullptr, nullptr);
    ViewAbstract::SetWidth(CalcLength(GRID_WIDTH));
    ViewAbstract::SetHeight(CalcLength(GRID_HEIGHT));
    model.SetRowsTemplate("1fr 1fr");
    model.SetRowsGap(Dimension(5));
    UpdateLayoutInfo();
    auto gridScrollLayoutAlgorithm = AceType::MakeRefPtr<GridScrollLayoutAlgorithm>(pattern_->gridLayoutInfo_, 2, 0);
    auto ret1 = gridScrollLayoutAlgorithm->CalculateLargeItemOffset(OffsetF(0, 100), 1, 1, 0);
    EXPECT_EQ(ret1.GetY(), 100.0f);
    EXPECT_EQ(ret1.GetX(), 0.0f);
}

/**
 * @tc.name: GridScrollTest005
 * @tc.desc: Test AdjustRowColSpan Function.
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GridScrollTest005, TestSize.Level1)
{
    Create([](GridModelNG model) {
        model.SetRowsTemplate("1fr 1fr");
        GridItemModelNG itemModel;
        itemModel.Create(GridItemStyle::NONE);
        itemModel.SetRowStart(NULL_VALUE);
        itemModel.SetRowEnd(NULL_VALUE);
        itemModel.SetColumnStart(NULL_VALUE);
        itemModel.SetColumnEnd(NULL_VALUE);
        ViewStackProcessor::GetInstance()->Pop();
    });
    auto layoutProperty = GetChildLayoutProperty<GridItemLayoutProperty>(frameNode_, 0);
    EXPECT_EQ(layoutProperty->GetRowStart(), NULL_VALUE);
    EXPECT_EQ(layoutProperty->GetRowEnd(), NULL_VALUE);
    EXPECT_EQ(layoutProperty->GetColumnStart(), NULL_VALUE);
    EXPECT_EQ(layoutProperty->GetColumnEnd(), NULL_VALUE);
}

/**
 * @tc.name: GetTotalHeight001
 * @tc.desc: Test GetTotalHeight Function.
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GetTotalHeight001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create 10 gridItem
     */
    Create([](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr 1fr 1fr");
        CreateFixedItem(10);
    });
    EXPECT_EQ(pattern_->GetTotalHeight(), ITEM_HEIGHT * 3);

    /**
     * @tc.steps: step2. Create 20 gridItem
     */
    Create([](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr 1fr 1fr");
        CreateFixedItem(20);
    });
    EXPECT_EQ(pattern_->GetTotalHeight(), ITEM_HEIGHT * 5);
}

/**
 * @tc.name: GetAverageHeight001
 * @tc.desc: Test GetAverageHeight Function.
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GetAverageHeight001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create 10 gridItem
     */
    Create([](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr 1fr 1fr");
        CreateFixedItem(10);
    });
    EXPECT_EQ(pattern_->GetAverageHeight(), 60);

    /**
     * @tc.steps: step2. Create 20 gridItem
     */
    Create([](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr 1fr 1fr");
        CreateFixedItem(20);
    });
    EXPECT_EQ(pattern_->GetAverageHeight(), 50);
}

/**
 * @tc.name: GridItemDisableEventTest001
 * @tc.desc: GirdItem disable event test.
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GridItemDisableEventTest001, TestSize.Level1)
{
    Create([](GridModelNG model) { CreateFixedItem(10, GridItemStyle::PLAIN); });

    /**
     * @tc.steps: step2. Get girdItem frameNode and pattern, set callback function.
     * @tc.expected: Related function is called.
     */
    auto gridItemPattern = GetChildPattern<GridItemPattern>(frameNode_, 0);
    auto gridItemEventHub = GetChildEventHub<GridItemEventHub>(frameNode_, 0);
    EXPECT_FALSE(gridItemPattern->enableOpacity_.has_value());
    gridItemEventHub->SetEnabled(false);
    gridItemPattern->InitDisableStyle();
    gridItemEventHub->SetEnabled(true);
    gridItemPattern->InitDisableStyle();
    EXPECT_FALSE(gridItemPattern->enableOpacity_.has_value());
}

/**
 * @tc.name: GridItemGetInnerFocusPaintRectTest001
 * @tc.desc: GirdItem GetInnerFocusPaintRect test.
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GridItemGetInnerFocusPaintRectTest001, TestSize.Level1)
{
    Create([](GridModelNG model) { CreateFixedItem(10); });
    auto gridItemNode = GetChildFrameNode(frameNode_, 0);
    auto gridItemPattern = GetChildPattern<GridItemPattern>(frameNode_, 0);

    /**
     * @tc.steps: step1. Set paintRect when grid item does not have border radius.
     * @tc.expected: Focus border radius is equal to 4.0_vp.
     */
    RoundRect paintRect;
    gridItemPattern->GetInnerFocusPaintRect(paintRect);
    EdgeF radius = paintRect.GetCornerRadius(RoundRect::CornerPos::TOP_LEFT_POS);
    float expectRadius = GRIDITEM_FOCUS_INTERVAL.ConvertToPx();
    EXPECT_EQ(radius.x, expectRadius);
    EXPECT_EQ(radius.y, expectRadius);

    /**
     * @tc.steps: step2. Set paintRect when grid item has border radius.
     * @tc.expected: Focus border radius is equal to 11.0_vp.
     */
    auto renderContext = gridItemNode->GetRenderContext();
    renderContext->UpdateBorderRadius({ BORDER_RADIUS, BORDER_RADIUS, BORDER_RADIUS, BORDER_RADIUS });
    gridItemPattern->GetInnerFocusPaintRect(paintRect);
    radius = paintRect.GetCornerRadius(RoundRect::CornerPos::TOP_LEFT_POS);
    expectRadius = (GRIDITEM_FOCUS_INTERVAL + BORDER_RADIUS).ConvertToPx();
    EXPECT_EQ(radius.x, expectRadius);
    EXPECT_EQ(radius.y, expectRadius);
}

/**
 * @tc.name: GridScrollWithOptions001
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GridScrollWithOptions001, TestSize.Level1)
{
    GridLayoutOptions option;
    option.regularSize.rows = 1;
    option.regularSize.columns = 1;
    option.irregularIndexes = { 6, 1, 2, 3, 4, 5, 0 };
    auto onGetIrregularSizeByIndex = [](int32_t index) {
        GridItemSize gridItemSize;
        return gridItemSize;
    };
    option.getSizeByIndex = std::move(onGetIrregularSizeByIndex);
    Create([option](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr 1fr 1fr");
        model.SetLayoutOptions(option);
        CreateFixedItem(10);
    });

    auto layoutAlgorithmWrapper = AceType::DynamicCast<LayoutAlgorithmWrapper>(frameNode_->GetLayoutAlgorithm());
    auto layoutAlgorithm =
        AceType::DynamicCast<GridScrollWithOptionsLayoutAlgorithm>(layoutAlgorithmWrapper->GetLayoutAlgorithm());
    if (AceType::InstanceOf<GridIrregularLayoutAlgorithm>(layoutAlgorithmWrapper->GetLayoutAlgorithm())) {
        return;
    }
    layoutAlgorithm->GetTargetIndexInfoWithBenchMark(AccessibilityManager::RawPtr(frameNode_), false, 5);
    EXPECT_EQ(layoutAlgorithm->gridLayoutInfo_.startMainLineIndex_, 1);
}

/**
 * @tc.name: GridScrollWithOptions002
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GridScrollWithOptions002, TestSize.Level1)
{
    GridLayoutOptions option;
    option.regularSize.rows = 1;
    option.regularSize.columns = 1;
    option.irregularIndexes = { 6, 1, 2, 3, 4, 5, 0 };
    Create([option](GridModelNG model) {
        model.SetRowsTemplate("1fr 1fr 1fr 1fr");
        model.SetLayoutOptions(option);
        CreateFixedItem(10);
    });

    auto layoutAlgorithmWrapper = AceType::DynamicCast<LayoutAlgorithmWrapper>(frameNode_->GetLayoutAlgorithm());
    auto layoutAlgorithm =
        AceType::DynamicCast<GridScrollWithOptionsLayoutAlgorithm>(layoutAlgorithmWrapper->GetLayoutAlgorithm());
    if (AceType::InstanceOf<GridIrregularLayoutAlgorithm>(layoutAlgorithmWrapper->GetLayoutAlgorithm())) {
        return;
    }
    layoutAlgorithm->GetTargetIndexInfoWithBenchMark(AccessibilityManager::RawPtr(frameNode_), false, 5);
    EXPECT_EQ(layoutAlgorithm->gridLayoutInfo_.startMainLineIndex_, 5);
}

/**
 * @tc.name: GridScrollWithOptions003
 * @tc.desc: change grid columns after scroll
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GridScrollWithOptions003, TestSize.Level1)
{
    GridLayoutOptions option;
    option.regularSize.rows = 1;
    option.regularSize.columns = 1;
    option.irregularIndexes = { 6, 1, 2, 3, 4, 5 };
    auto onGetIrregularSizeByIndex = [](int32_t index) {
        GridItemSize gridItemSize { 1, 2 };
        return gridItemSize;
    };
    option.getSizeByIndex = std::move(onGetIrregularSizeByIndex);
    Create([option](GridModelNG model) {
        model.SetColumnsTemplate("1fr");
        model.SetLayoutOptions(option);
        CreateFixedItem(10);
    });
    pattern_->UpdateStartIndex(3);
    FlushLayoutTask(frameNode_);
    layoutProperty_->UpdateColumnsTemplate("1fr 1fr 1fr 1fr 1fr");
    frameNode_->MarkDirtyNode(PROPERTY_UPDATE_MEASURE);
    FlushLayoutTask(frameNode_);
    auto layoutAlgorithmWrapper = AceType::DynamicCast<LayoutAlgorithmWrapper>(frameNode_->GetLayoutAlgorithm());
    auto layoutAlgorithm =
        AceType::DynamicCast<GridScrollWithOptionsLayoutAlgorithm>(layoutAlgorithmWrapper->GetLayoutAlgorithm());
    if (AceType::InstanceOf<GridIrregularLayoutAlgorithm>(layoutAlgorithmWrapper->GetLayoutAlgorithm())) {
        return;
    }
    EXPECT_EQ(layoutAlgorithm->GetCrossStartAndSpanWithUserFunction(3, option, 1), std::make_pair(0, 2));
}

/**
 * @tc.name: GridScrollWithOptions004
 * @tc.desc: change grid columns after scroll, first line has empty position
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GridScrollWithOptions004, TestSize.Level1)
{
    GridLayoutOptions option;
    option.regularSize.rows = 1;
    option.regularSize.columns = 1;
    option.irregularIndexes = { 6, 1, 2, 3, 4, 5 };
    auto onGetIrregularSizeByIndex = [](int32_t index) {
        GridItemSize gridItemSize { 1, 2 };
        return gridItemSize;
    };
    option.getSizeByIndex = std::move(onGetIrregularSizeByIndex);
    Create([option](GridModelNG model) {
        model.SetColumnsTemplate("1fr");
        model.SetLayoutOptions(option);
        CreateFixedItem(10);
    });
    pattern_->UpdateStartIndex(3);
    FlushLayoutTask(frameNode_);
    layoutProperty_->UpdateColumnsTemplate("1fr 1fr 1fr 1fr 1fr 1fr");
    frameNode_->MarkDirtyNode(PROPERTY_UPDATE_MEASURE);
    FlushLayoutTask(frameNode_);
    auto layoutAlgorithmWrapper = AceType::DynamicCast<LayoutAlgorithmWrapper>(frameNode_->GetLayoutAlgorithm());
    auto layoutAlgorithm =
        AceType::DynamicCast<GridScrollWithOptionsLayoutAlgorithm>(layoutAlgorithmWrapper->GetLayoutAlgorithm());
    if (AceType::InstanceOf<GridIrregularLayoutAlgorithm>(layoutAlgorithmWrapper->GetLayoutAlgorithm())) {
        return;
    }
    EXPECT_EQ(layoutAlgorithm->GetCrossStartAndSpanWithUserFunction(3, option, 1), std::make_pair(0, 2));
    EXPECT_EQ(layoutAlgorithm->GetCrossStartAndSpanWithUserFunction(2, option, 1), std::make_pair(3, 2));
    EXPECT_EQ(layoutAlgorithm->GetCrossStartAndSpanWithUserFunction(1, option, 1), std::make_pair(1, 2));
}

/**
 * @tc.name: GridScrollWithOptions005
 * @tc.desc: second line full
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GridScrollWithOptions005, TestSize.Level1)
{
    GridLayoutOptions option;
    option.regularSize.rows = 1;
    option.regularSize.columns = 1;
    option.irregularIndexes = { 6, 1, 2, 3, 4, 5 };
    auto onGetIrregularSizeByIndex = [](int32_t index) {
        GridItemSize gridItemSize { 1, 2 };
        return gridItemSize;
    };
    option.getSizeByIndex = std::move(onGetIrregularSizeByIndex);
    Create([option](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr 1fr 1fr");
        model.SetLayoutOptions(option);
        CreateFixedItem(10);
    });
    auto layoutAlgorithmWrapper = AceType::DynamicCast<LayoutAlgorithmWrapper>(frameNode_->GetLayoutAlgorithm());
    auto layoutAlgorithm =
        AceType::DynamicCast<GridScrollWithOptionsLayoutAlgorithm>(layoutAlgorithmWrapper->GetLayoutAlgorithm());
    if (AceType::InstanceOf<GridIrregularLayoutAlgorithm>(layoutAlgorithmWrapper->GetLayoutAlgorithm())) {
        return;
    }
    EXPECT_EQ(layoutAlgorithm->GetCrossStartAndSpanWithUserFunction(3, option, 1), std::make_pair(2, 2));
    EXPECT_EQ(layoutAlgorithm->GetCrossStartAndSpanWithUserFunction(2, option, 1), std::make_pair(0, 2));
    EXPECT_EQ(layoutAlgorithm->GetCrossStartAndSpanWithUserFunction(1, option, 1), std::make_pair(1, 2));
}

/**
 * @tc.name: GridScrollWithOptions006
 * @tc.desc: first irregular item in new line
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GridScrollWithOptions006, TestSize.Level1)
{
    GridLayoutOptions option;
    option.regularSize.rows = 1;
    option.regularSize.columns = 1;
    option.irregularIndexes = { 6, 3, 4, 5 };
    auto onGetIrregularSizeByIndex = [](int32_t index) {
        GridItemSize gridItemSize { 1, 2 };
        return gridItemSize;
    };
    option.getSizeByIndex = std::move(onGetIrregularSizeByIndex);
    Create([option](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr 1fr 1fr");
        model.SetLayoutOptions(option);
        CreateFixedItem(10);
    });
    auto layoutAlgorithmWrapper = AceType::DynamicCast<LayoutAlgorithmWrapper>(frameNode_->GetLayoutAlgorithm());
    auto layoutAlgorithm =
        AceType::DynamicCast<GridScrollWithOptionsLayoutAlgorithm>(layoutAlgorithmWrapper->GetLayoutAlgorithm());
    if (AceType::InstanceOf<GridIrregularLayoutAlgorithm>(layoutAlgorithmWrapper->GetLayoutAlgorithm())) {
        return;
    }
    EXPECT_EQ(layoutAlgorithm->GetCrossStartAndSpanWithUserFunction(4, option, 1), std::make_pair(2, 2));
}

/**
 * @tc.name: SearchIrregularFocusableChildInScroll001
 * @tc.desc: Test the function when the gridItem cannot be focused
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, SearchIrregularFocusableChildInScroll001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create gridItems with irregular shape in scroll grid.
     */
    GridLayoutOptions option;
    option.regularSize.rows = 1;
    option.regularSize.columns = 1;
    option.irregularIndexes = { 6, 1, 2, 3, 4, 5, 0 };
    Create([option](GridModelNG model) {
        model.SetRowsTemplate("1fr 1fr 1fr 1fr");
        model.SetLayoutOptions(option);
        CreateFixedItem(10);
    });

    /**
     * @tc.steps: step2. Find target child with specified index parameters.
     * @tc.expected: Can not find the target focus child.
     */
    int32_t tarMainIndex = 1;
    int32_t tarCrossIndex = 1;
    auto IrregularFocusableChild = pattern_->SearchIrregularFocusableChild(tarMainIndex, tarCrossIndex);
    RefPtr<FocusHub> result = IrregularFocusableChild.Upgrade();
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: SearchIrregularFocusableChildInScroll002
 * @tc.desc: Test the function when the gridItem can be focused
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, SearchIrregularFocusableChildInScroll002, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create gridItems with irregular shape in scroll grid.
     */
    GridLayoutOptions option;
    option.regularSize.rows = 1;
    option.regularSize.columns = 1;
    option.irregularIndexes = { 6, 1, 2, 3, 4, 5, 0 };
    auto onGetIrregularSizeByIndex = [](int32_t index) {
        GridItemSize gridItemSize { 1, 2 };
        return gridItemSize;
    };
    option.getSizeByIndex = std::move(onGetIrregularSizeByIndex);
    Create([option](GridModelNG gridModelNG) {
        gridModelNG.SetRowsTemplate("1fr 1fr 1fr 1fr");
        gridModelNG.SetLayoutOptions(option);
        CreateFixedItem(10);
    });

    /**
     * @tc.steps: step2. Find target child with specified index parameters.
     * @tc.expected: Can not find the target focus child.
     */
    int32_t tarMainIndex = 1;
    int32_t tarCrossIndex = 1;
    auto IrregularFocusableChild = pattern_->SearchIrregularFocusableChild(tarMainIndex, tarCrossIndex);
    RefPtr<FocusHub> result = IrregularFocusableChild.Upgrade();
    EXPECT_EQ(result, nullptr);

    /**
     * @tc.steps: step3. Call the function when isLeftStep_ is true.
     * @tc.expected: Can find the target focus child.
     */
    pattern_->isLeftStep_ = true;
    IrregularFocusableChild = pattern_->SearchIrregularFocusableChild(tarMainIndex, tarCrossIndex);
    result = IrregularFocusableChild.Upgrade();
    EXPECT_NE(result, nullptr);
    pattern_->isLeftStep_ = false;

    /**
     * @tc.steps: step4. Call the function when isRightStep_ is true.
     * @tc.expected: Can find the target focus child.
     */
    tarCrossIndex = 0;
    pattern_->isRightStep_ = true;
    IrregularFocusableChild = pattern_->SearchIrregularFocusableChild(tarMainIndex, tarCrossIndex);
    result = IrregularFocusableChild.Upgrade();
    EXPECT_NE(result, nullptr);
    pattern_->isRightStep_ = false;

    /**
     * @tc.steps: step5. Call the function when isUpStep_ is true.
     * @tc.expected: Can find the target focus child.
     */
    pattern_->isUpStep_ = true;
    IrregularFocusableChild = pattern_->SearchIrregularFocusableChild(tarMainIndex, tarCrossIndex);
    result = IrregularFocusableChild.Upgrade();
    EXPECT_NE(result, nullptr);
    pattern_->isUpStep_ = false;

    /**
     * @tc.steps: step6. Call the function when isDownStep_ is true.
     * @tc.expected: Can find the target focus child.
     */
    pattern_->isDownStep_ = true;
    IrregularFocusableChild = pattern_->SearchIrregularFocusableChild(tarMainIndex, tarCrossIndex);
    result = IrregularFocusableChild.Upgrade();
    EXPECT_NE(result, nullptr);
    pattern_->isDownStep_ = false;

    /**
     * @tc.steps: step7. Call the function when isLeftEndStep_ is true.
     * @tc.expected: Can find the target focus child.
     */
    pattern_->isLeftEndStep_ = true;
    IrregularFocusableChild = pattern_->SearchIrregularFocusableChild(tarMainIndex, tarCrossIndex);
    result = IrregularFocusableChild.Upgrade();
    EXPECT_NE(result, nullptr);
    pattern_->isLeftEndStep_ = false;

    /**
     * @tc.steps: step8. Call the function when isRightEndStep_ is true.
     * @tc.expected: Can find the target focus child.
     */
    pattern_->isRightEndStep_ = true;
    IrregularFocusableChild = pattern_->SearchIrregularFocusableChild(tarMainIndex, tarCrossIndex);
    result = IrregularFocusableChild.Upgrade();
    EXPECT_NE(result, nullptr);
    pattern_->isRightEndStep_ = false;
}

/**
 * @tc.name: SearchIrregularFocusableChildInNormalGrid001
 * @tc.desc: Test ability of a fixed shape grid to obtain irregular shape focal item.
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, SearchIrregularFocusableChildInNormalGrid001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create gridItems with irregular shape in fixed shape grid.
     */
    Create([](GridModelNG model) {
        model.SetRowsTemplate("1fr 1fr 1fr 1fr");
        model.SetColumnsTemplate("1fr 1fr 1fr 1fr");
        CreateBigItem(1, 2, 1, 2);
        CreateFixedItem(10);
    });

    /**
     * @tc.steps: step2. Find target child with specified index parameters.
     * @tc.expected: Can find the target focus child.
     */
    int32_t tarMainIndex = 1;
    int32_t tarCrossIndex = 1;
    pattern_->isLeftStep_ = true;
    auto IrregularFocusableChild = pattern_->SearchIrregularFocusableChild(tarMainIndex, tarCrossIndex);
    RefPtr<FocusHub> result = IrregularFocusableChild.Upgrade();
    EXPECT_NE(result, nullptr);
    pattern_->isLeftStep_ = false;

    /**
     * @tc.steps: step3. Call the function when isRightStep_ is true.
     * @tc.expected: Can find the target focus child.
     */
    pattern_->isRightStep_ = true;
    IrregularFocusableChild = pattern_->SearchIrregularFocusableChild(tarMainIndex, tarCrossIndex);
    result = IrregularFocusableChild.Upgrade();
    EXPECT_NE(result, nullptr);
    pattern_->isRightStep_ = false;

    /**
     * @tc.steps: step4. Call the function when isUpStep_ is true.
     * @tc.expected: Can find the target focus child.
     */
    pattern_->isUpStep_ = true;
    IrregularFocusableChild = pattern_->SearchIrregularFocusableChild(tarMainIndex, tarCrossIndex);
    result = IrregularFocusableChild.Upgrade();
    EXPECT_NE(result, nullptr);
    pattern_->isUpStep_ = false;

    /**
     * @tc.steps: step5. Call the function when isDownStep_ is true.
     * @tc.expected: Can find the target focus child.
     */
    pattern_->isDownStep_ = true;
    IrregularFocusableChild = pattern_->SearchIrregularFocusableChild(tarMainIndex, tarCrossIndex);
    result = IrregularFocusableChild.Upgrade();
    EXPECT_NE(result, nullptr);
    pattern_->isDownStep_ = false;
}

/**
 * @tc.name: GridPattern_GetItemRect001
 * @tc.desc: Test the GetItemRect function of Grid.
 * @tc.type: FUNCgetitemre
 */
HWTEST_F(GridLayoutTestNg, GridPattern_GetItemRect001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Init Grid then slide Grid by Scroller.
     */
    GridLayoutOptions option;
    option.regularSize.rows = 1;
    option.regularSize.columns = 1;
    option.irregularIndexes = { 1, 3 };
    auto onGetIrregularSizeByIndex = [](int32_t index) {
        GridItemSize gridItemSize { 1, 2 };
        return gridItemSize;
    };
    option.getSizeByIndex = std::move(onGetIrregularSizeByIndex);
    Create([option](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr");
        model.SetLayoutOptions(option);
        CreateItem(10, -2, ITEM_HEIGHT);
    });
    pattern_->UpdateStartIndex(3, ScrollAlign::START);
    FlushLayoutTask(frameNode_);

    /**
     * @tc.steps: step2. Get invalid GridItem Rect.
     * @tc.expected: Return 0 when input invalid index.
     */
    EXPECT_TRUE(IsEqual(pattern_->GetItemRect(-1), Rect()));
    EXPECT_TRUE(IsEqual(pattern_->GetItemRect(2), Rect()));
    EXPECT_TRUE(IsEqual(pattern_->GetItemRect(10), Rect()));

    /**
     * @tc.steps: step3. Get valid GridItem Rect.
     * @tc.expected: Return actual Rect when input valid index.
     */
    EXPECT_TRUE(IsEqual(pattern_->GetItemRect(3), Rect(0, 0, GRID_WIDTH, ITEM_HEIGHT)));
    EXPECT_TRUE(IsEqual(pattern_->GetItemRect(4), Rect(0, ITEM_HEIGHT, GRID_WIDTH / 2, ITEM_HEIGHT)));
    EXPECT_TRUE(IsEqual(pattern_->GetItemRect(7), Rect(GRID_WIDTH / 2, ITEM_HEIGHT * 2, GRID_WIDTH / 2, ITEM_HEIGHT)));

    /**
     * @tc.steps: step4. Slide Grid by Scroller.
     */
    UpdateCurrentOffset(ITEM_HEIGHT + ITEM_HEIGHT / 2);
    FlushLayoutTask(frameNode_);

    /**
     * @tc.steps: step5. Get invalid GridItem Rect.
     * @tc.expected: Return 0 when input invalid index.
     */
    EXPECT_TRUE(IsEqual(pattern_->GetItemRect(-1), Rect()));
    EXPECT_TRUE(IsEqual(pattern_->GetItemRect(0), Rect()));
    EXPECT_TRUE(IsEqual(pattern_->GetItemRect(10), Rect()));

    /**
     * @tc.steps: step6. Get valid GridItem Rect.
     * @tc.expected: Return actual Rect when input valid index.
     */
    EXPECT_TRUE(IsEqual(pattern_->GetItemRect(1), Rect(0, -ITEM_HEIGHT / 2, GRID_WIDTH, ITEM_HEIGHT)));
    EXPECT_TRUE(IsEqual(pattern_->GetItemRect(2), Rect(0, ITEM_HEIGHT / 2, GRID_WIDTH / 2, ITEM_HEIGHT)));
    EXPECT_TRUE(IsEqual(pattern_->GetItemRect(3), Rect(0, ITEM_HEIGHT + ITEM_HEIGHT / 2, GRID_WIDTH, ITEM_HEIGHT)));
    EXPECT_TRUE(IsEqual(pattern_->GetItemRect(5),
        Rect(GRID_WIDTH / 2, ITEM_HEIGHT * 2 + ITEM_HEIGHT / 2, GRID_WIDTH / 2, ITEM_HEIGHT)));
}

/**
 * @tc.name: ChangeItemNumber001
 * @tc.desc: Test ChangeItemNumber
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, ChangeItemNumber001, TestSize.Level1)
{
    Create([](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr 1fr 1fr");
        CreateFixedItem(5);
    });

    /**
     * @tc.steps: step1. Add item
     * @tc.expected: The added item in the correct position
     */
    for (int32_t i = 0; i < 4; i++) {
        GridItemModelNG itemModel;
        itemModel.Create(GridItemStyle::NONE);
        ViewAbstract::SetHeight(CalcLength(Dimension(ITEM_HEIGHT)));
        RefPtr<UINode> currentNode = ViewStackProcessor::GetInstance()->Finish();
        auto currentFrameNode = AceType::DynamicCast<FrameNode>(currentNode);
        currentFrameNode->MountToParent(frameNode_);
    }
    frameNode_->MarkDirtyNode(PROPERTY_UPDATE_MEASURE);
    FlushLayoutTask(frameNode_);
    EXPECT_TRUE(IsEqual(GetChildOffset(frameNode_, 6), OffsetF(ITEM_WIDTH * 2, ITEM_HEIGHT)));
    EXPECT_TRUE(IsEqual(GetChildOffset(frameNode_, 8), OffsetF(0, ITEM_HEIGHT * 2)));
}

/**
 * @tc.name: ItemAboveViewport001
 * @tc.desc: Test GridLayoutInfo::ItemAboveViewport
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, ItemAboveViewport001, TestSize.Level1)
{
    GridLayoutInfo info;
    info.gridMatrix_ = {
        { 0, { { 0, 0 }, { 1, 1 } } },
        { 1, { { 0, 2 }, { 1, 3 } } },
        { 2, { { 0, 4 }, { 1, 5 } } },
    };
    info.lineHeightMap_ = { { 0, 200.0f }, { 1, 500.0f }, { 2, 300.0f } };
    info.crossCount_ = 2;

    info.startMainLineIndex_ = 0;
    info.endMainLineIndex_ = 2;
    info.startIndex_ = 0;
    info.endIndex_ = 5;

    info.currentOffset_ = 0.0f;
    EXPECT_FALSE(Negative(info.GetItemTopPos(0, 5.0f)));

    info.currentOffset_ = -50.0f;
    EXPECT_TRUE(Negative(info.GetItemTopPos(0, 5.0f)));

    info.currentOffset_ = -200.0f;
    EXPECT_TRUE(Negative(info.GetItemTopPos(0, 5.0f)));
    EXPECT_FALSE(Negative(info.GetItemTopPos(1, 5.0f)));

    // adding gap length
    info.currentOffset_ = -205.0f;
    EXPECT_TRUE(Negative(info.GetItemTopPos(0, 5.0f)));
    EXPECT_FALSE(Negative(info.GetItemTopPos(1, 5.0f)));

    EXPECT_TRUE(Negative(info.GetItemTopPos(1, 0.0f)));

    info.startMainLineIndex_ = 1;
    info.endMainLineIndex_ = 1;
    info.startIndex_ = 2;
    info.endIndex_ = 3;

    info.currentOffset_ = 0.0f;
    EXPECT_FALSE(Negative(info.GetItemTopPos(1, 5.0f)));

    info.currentOffset_ = -1.0f;
    EXPECT_TRUE(Negative(info.GetItemTopPos(1, 5.0f)));
}

/**
 * @tc.name: ItemBelowViewport001
 * @tc.desc: Test GridLayoutInfo::ItemBelowViewport
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, ItemBelowViewport001, TestSize.Level1)
{
    GridLayoutInfo info;
    info.gridMatrix_ = {
        { 0, { { 0, 0 }, { 1, 1 } } },
        { 1, { { 0, 2 }, { 1, 3 } } },
        { 2, { { 0, 4 }, { 1, -1 } } },
    };
    info.lineHeightMap_ = { { 0, 200.0f }, { 1, 500.0f }, { 2, 300.0f } };
    info.crossCount_ = 2;

    info.startMainLineIndex_ = 0;
    info.endMainLineIndex_ = 2;
    info.startIndex_ = 0;
    info.endIndex_ = 4;

    info.currentOffset_ = 0.0f;
    EXPECT_TRUE(GreatNotEqual(info.GetItemBottomPos(1, 2, 5.0f), 100.0f));
    EXPECT_TRUE(GreatNotEqual(info.GetItemBottomPos(1, 2, 5.0f), 700.0f));
    EXPECT_TRUE(GreatNotEqual(info.GetItemBottomPos(1, 2, 5.0f), 705.0f));
    EXPECT_TRUE(GreatNotEqual(info.GetItemBottomPos(1, 2, 5.0f), 710.0f));
    EXPECT_TRUE(GreatNotEqual(info.GetItemBottomPos(1, 2, 5.0f), 1005.0f));
    EXPECT_FALSE(GreatNotEqual(info.GetItemBottomPos(1, 2, 5.0f), 1010.0f));

    info.currentOffset_ = -50.0f;
    EXPECT_TRUE(GreatNotEqual(info.GetItemBottomPos(1, 2, 5.0f), 100.0f));
    EXPECT_TRUE(GreatNotEqual(info.GetItemBottomPos(1, 2, 5.0f), 700.0f));
    EXPECT_TRUE(GreatNotEqual(info.GetItemBottomPos(1, 2, 5.0f), 705.0f));
    EXPECT_TRUE(GreatNotEqual(info.GetItemBottomPos(1, 2, 5.0f), 710.0f));
    EXPECT_TRUE(GreatNotEqual(info.GetItemBottomPos(1, 2, 5.0f), 955.0f));
    EXPECT_FALSE(GreatNotEqual(info.GetItemBottomPos(1, 2, 5.0f), 960.0f));
    EXPECT_FALSE(GreatNotEqual(info.GetItemBottomPos(1, 2, 5.0f), 1005.0f));
    EXPECT_FALSE(GreatNotEqual(info.GetItemBottomPos(1, 2, 5.0f), 1010.0f));
}

/**
 * @tc.name: UpdateGridMatrix001
 * @tc.desc: Test UpdateGridMatrix
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, UpdateGridMatrix001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create 100 items
     * @tc.expected: The added item in the correct position
     */
    Create([](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr 1fr 1fr");
        CreateItem(100, ITEM_WIDTH, NULL_VALUE, GridItemStyle::NONE);
    });

    /**
     * @tc.steps: step2. Scroll To 99 item
     * @tc.expected: Scroll to the correct position,lineHeightMap_ size is 25
     */
    pattern_->ScrollToIndex(99, true, ScrollAlign::END);
    EXPECT_TRUE(IsEqual<int32_t>(pattern_->gridLayoutInfo_.lineHeightMap_.size(), 25));
}

/**
 * @tc.name: LayoutUtils::GetItemSize001
 * @tc.desc: Test LayoutUtils::GetItemSize
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GetItemSize001, TestSize.Level1)
{
    GridLayoutOptions option;
    option.irregularIndexes = {
        0, // [2 x 1]
        1, // [1 x 2]
        2  // [2 x 1]
    };
    auto onGetIrregularSizeByIndex = [](int32_t index) -> GridItemSize {
        if (index == 1) {
            return { .rows = 2, .columns = 1 };
        }
        return { .rows = 1, .columns = 2 };
    };

    option.getSizeByIndex = std::move(onGetIrregularSizeByIndex);
    Create([option](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr");
        model.SetLayoutOptions(option);
    });

    GridLayoutInfo info;
    auto* wrapper = AceType::RawPtr(frameNode_);

    info.crossCount_ = 2;
    EXPECT_EQ(GridLayoutUtils::GetItemSize(&info, wrapper, 0).rows, 1);
    EXPECT_EQ(GridLayoutUtils::GetItemSize(&info, wrapper, 0).columns, 2);
    EXPECT_EQ(GridLayoutUtils::GetItemSize(&info, wrapper, 1).rows, 2);
    EXPECT_EQ(GridLayoutUtils::GetItemSize(&info, wrapper, 1).columns, 1);
    EXPECT_EQ(GridLayoutUtils::GetItemSize(&info, wrapper, 2).rows, 1);
    EXPECT_EQ(GridLayoutUtils::GetItemSize(&info, wrapper, 2).columns, 2);

    info.axis_ = Axis::HORIZONTAL;
    // rows and columns should be flipped when horizontal
    EXPECT_EQ(GridLayoutUtils::GetItemSize(&info, wrapper, 0).rows, 2);
    EXPECT_EQ(GridLayoutUtils::GetItemSize(&info, wrapper, 0).columns, 1);
    EXPECT_EQ(GridLayoutUtils::GetItemSize(&info, wrapper, 1).rows, 1);
    EXPECT_EQ(GridLayoutUtils::GetItemSize(&info, wrapper, 1).columns, 2);
    EXPECT_EQ(GridLayoutUtils::GetItemSize(&info, wrapper, 2).rows, 2);
    EXPECT_EQ(GridLayoutUtils::GetItemSize(&info, wrapper, 2).columns, 1);
}

/**
 * @tc.name: LayoutUtils::GetItemSize002
 * @tc.desc: Test LayoutUtils::GetItemSize with null callback
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GetItemSize002, TestSize.Level1)
{
    GridLayoutOptions option;
    option.irregularIndexes = {
        0, // [2 x 1]
        1, // [1 x 2]
        2  // [2 x 1]
    };
    option.getSizeByIndex = nullptr;

    Create([option](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr");
        model.SetLayoutOptions(option);
        CreateItem(3, ITEM_WIDTH, NULL_VALUE, GridItemStyle::NONE);
    });

    GridLayoutInfo info;
    auto* wrapper = AceType::RawPtr(frameNode_);
    info.crossCount_ = 3;

    EXPECT_EQ(GridLayoutUtils::GetItemSize(&info, wrapper, 0).rows, 1);
    EXPECT_EQ(GridLayoutUtils::GetItemSize(&info, wrapper, 0).columns, 3);
    EXPECT_EQ(GridLayoutUtils::GetItemSize(&info, wrapper, 1).rows, 1);
    EXPECT_EQ(GridLayoutUtils::GetItemSize(&info, wrapper, 1).columns, 3);
    EXPECT_EQ(GridLayoutUtils::GetItemSize(&info, wrapper, 2).rows, 1);
    EXPECT_EQ(GridLayoutUtils::GetItemSize(&info, wrapper, 2).columns, 3);
}

/**
 * @tc.name: GridLayout001
 * @tc.desc: Test GridLayoutAlgorithm for coverage
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GridLayout001, TestSize.Level1)
{
    Create([](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr 1fr 1fr");
        model.SetRowsTemplate("1fr 1fr 1fr 1fr");
        CreateFixedItem(16);
    });

    /**
     * @tc.steps: step1. call InitGridCeils
     * @tc.expected: The GetLayoutProperty is !nullptr
     */
    auto pattern = frameNode_->GetPattern<GridPattern>();
    auto algorithm = AceType::MakeRefPtr<GridLayoutAlgorithm>(GridLayoutInfo {}, 4, 4);
    algorithm->InitGridCeils(AceType::RawPtr(frameNode_), { 0.0f, 0.0f });
    algorithm->crossCount_ = 5;
    algorithm->mainCount_ = 5;
    algorithm->InitGridCeils(AceType::RawPtr(frameNode_), { 0.0f, 0.0f });
    EXPECT_NE(pattern->GetLayoutProperty<GridLayoutProperty>(), nullptr);
}

/**
 * @tc.name: GridLayout002
 * @tc.desc: Test GridLayoutAlgorithm for coverage
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GridLayout002, TestSize.Level1)
{
    Create([](GridModelNG model) {
        model.SetColumnsTemplate("");
        model.SetRowsTemplate("");
        CreateFixedItem(16);
    });

    /**
     * @tc.steps: step1. Change to smaller mainSize
     * @tc.expected: The GetLayoutProperty is correct
     */
    auto pattern = frameNode_->GetPattern<GridPattern>();
    auto algorithm = AceType::MakeRefPtr<GridLayoutAlgorithm>(GridLayoutInfo {}, 4, 4);
    algorithm->InitGridCeils(AceType::RawPtr(frameNode_), { 0.0f, 0.0f });
    algorithm->crossCount_ = 5;
    algorithm->mainCount_ = 5;
    algorithm->InitGridCeils(AceType::RawPtr(frameNode_), { 0.0f, 0.0f });
    EXPECT_NE(pattern->GetLayoutProperty<GridLayoutProperty>(), nullptr);
}

/**
 * @tc.name: GridLayout003
 * @tc.desc: Test GridLayoutAlgorithm for coverage
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GridLayout003, TestSize.Level1)
{
    Create([](GridModelNG model) {
        std::string emptyString;
        model.SetColumnsTemplate(emptyString);
        model.SetRowsTemplate(emptyString);
        CreateFixedItem(16);
    });

    /**
     * @tc.steps: step1. Change to smaller mainSize
     * @tc.expected: The GetLayoutProperty is correct
     */
    auto pattern = frameNode_->GetPattern<GridPattern>();
    auto algorithm = AceType::MakeRefPtr<GridLayoutAlgorithm>(GridLayoutInfo {}, 4, 4);
    algorithm->gridLayoutInfo_.currentOffset_ = 0.0f;
    auto layoutProperty = pattern->CreateLayoutProperty();
    algorithm->InitGridCeils(AceType::RawPtr(frameNode_), { 0.0f, 0.0f });
    algorithm->crossCount_ = 5;
    algorithm->mainCount_ = 5;
    algorithm->InitGridCeils(AceType::RawPtr(frameNode_), { 0.0f, 0.0f });
    EXPECT_NE(layoutProperty, nullptr);
}

/**
 * @tc.name: GridLayout004
 * @tc.desc: Test GridLayoutAlgorithm for coverage
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GridLayout004, TestSize.Level1)
{
    Create([](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr");
        CreateFixedItem(10);
    });

    /**
     * @tc.steps: step1. isVertical_ is true
     * @tc.expected: The curRow and curCol is correct
     */
    int32_t curRow = 0;
    int32_t curCol = 0;
    auto pattern = frameNode_->GetPattern<GridPattern>();
    auto algorithm = AceType::MakeRefPtr<GridLayoutAlgorithm>(GridLayoutInfo {}, 2, 5);
    EXPECT_EQ(algorithm->crossCount_, 2);
    EXPECT_EQ(algorithm->mainCount_, 5);
    algorithm->GetNextGrid(curRow, curCol);
    EXPECT_EQ(curRow, 0);
    EXPECT_EQ(curCol, 1);
    EXPECT_TRUE(algorithm->isVertical_);
    algorithm->GetNextGrid(curRow, curCol);
    EXPECT_EQ(curRow, 1);
    EXPECT_EQ(curCol, 0);
    curRow = 1;
    curCol = 1;

    /**
     * @tc.steps: step2. isVertical_ is false
     * @tc.expected: The curRow and curCol is correct
     */
    algorithm->isVertical_ = false;
    algorithm->GetNextGrid(curRow, curCol);
    EXPECT_EQ(curRow, 2);
    EXPECT_EQ(curCol, 1);
    algorithm->GetNextGrid(curRow, curCol);
    EXPECT_EQ(curRow, 3);
    EXPECT_EQ(curCol, 1);
    curRow = 5;
    algorithm->GetNextGrid(curRow, curCol);
    EXPECT_EQ(curRow, 0);
    EXPECT_EQ(curCol, 2);
}

/**
 * @tc.name: GridLayout005
 * @tc.desc: Test GridLayoutAlgorithm for coverage
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GridLayout005, TestSize.Level1)
{
    GridLayoutOptions option;
    option.regularSize.rows = 1;
    option.regularSize.columns = 1;
    option.irregularIndexes = { 6, 1, 2, 3, 4, 5 };
    Create([option](GridModelNG model) {
        model.SetColumnsTemplate("1fr");
        model.SetLayoutOptions(option);
        CreateFixedItem(10);
    });

    /**
     * @tc.steps: step2.call GetItemRect
     * @tc.expected: The GetItemRect is crrect
     */
    GridItemRect retItemRect;
    auto pattern = frameNode_->GetPattern<GridPattern>();
    auto algorithm = AceType::MakeRefPtr<GridLayoutAlgorithm>(GridLayoutInfo {}, 2, 5);
    auto childLayoutProperty = GetChildLayoutProperty<GridItemLayoutProperty>(frameNode_, 0);
    ASSERT_NE(layoutProperty_, nullptr);
    ASSERT_NE(childLayoutProperty, nullptr);
    algorithm->GetItemRect(layoutProperty_, childLayoutProperty, 0);
    EXPECT_EQ(retItemRect.rowStart, -1);
    EXPECT_EQ(retItemRect.rowSpan, 1);
    EXPECT_EQ(retItemRect.columnStart, -1);
    EXPECT_EQ(retItemRect.columnSpan, 1);
}

/**
 * @tc.name: GridLayout006
 * @tc.desc: Test GridLayoutAlgorithm for coverage
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GridLayout006, TestSize.Level1)
{
    GridLayoutOptions option;
    option.regularSize.rows = 1;
    option.regularSize.columns = 1;
    option.irregularIndexes = { 6, 1, 2, 3, 4, 5 };
    option.getRectByIndex = [](int32_t index) {
        GridItemRect tmpItemRect;
        tmpItemRect.rowStart = 1;
        tmpItemRect.rowSpan = 20;
        tmpItemRect.columnStart = 1;
        tmpItemRect.columnSpan = 20;
        return tmpItemRect;
    };
    Create([option](GridModelNG model) {
        model.SetColumnsTemplate("1fr");
        model.SetLayoutOptions(option);
        CreateFixedItem(10);
    });
    pattern_->UpdateStartIndex(3);
    FlushLayoutTask(frameNode_);
    layoutProperty_->UpdateColumnsTemplate("1fr 1fr 1fr 1fr 1fr");

    /**
     * @tc.steps: step2.call GetItemRect
     * @tc.expected: The GetItemRect is crrect
     */
    GridItemRect retItemRect;
    auto pattern = frameNode_->GetPattern<GridPattern>();
    auto algorithm = AceType::MakeRefPtr<GridLayoutAlgorithm>(GridLayoutInfo {}, 2, 5);
    auto childLayoutProperty = GetChildLayoutProperty<GridItemLayoutProperty>(frameNode_, 0);
    ASSERT_NE(layoutProperty_, nullptr);
    ASSERT_NE(childLayoutProperty, nullptr);
    retItemRect = algorithm->GetItemRect(layoutProperty_, childLayoutProperty, 0);
    EXPECT_EQ(retItemRect.rowStart, 1);
    EXPECT_EQ(retItemRect.rowSpan, 20);
    EXPECT_EQ(retItemRect.columnStart, 1);
    EXPECT_EQ(retItemRect.columnSpan, 20);
}

/**
 * @tc.name: UpdateOverlayModifier001
 * @tc.desc: Test grid paint method UpdateOverlayModifier function
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, UpdateOverlayModifier001, TestSize.Level1)
{
    Create([](GridModelNG model) {
        model.SetRowsTemplate("1fr 1fr");
        CreateFixedItem(10);
    });

    /**
     * @tc.steps: step1. create paintMethod
     */
    auto paintMethod = AceType::DynamicCast<GridPaintMethod>(pattern_->CreateNodePaintMethod());
    auto paintProperty = pattern_->CreatePaintProperty();
    PaintWrapper paintWrapper(frameNode_->GetRenderContext(), frameNode_->GetGeometryNode(), paintProperty);
    paintMethod->UpdateOverlayModifier(nullptr);

    /**
     * @tc.steps: step2. call UpdateOverlayModifier
     * @tc.expected: scrollBar is nullptr
     */
    paintMethod->UpdateOverlayModifier(&paintWrapper);
    auto scrollBar = paintMethod->scrollBar_.Upgrade();
    EXPECT_EQ(scrollBar, nullptr);
}

/**
 * @tc.name: UpdateOverlayModifier002
 * @tc.desc: Test grid paint method UpdateOverlayModifier function
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, UpdateOverlayModifier002, TestSize.Level1)
{
    Create([](GridModelNG model) {
        model.SetRowsTemplate("1fr 1fr");
        CreateFixedItem(10);
    });

    /**
     * @tc.steps: step1. create scrollBar and paintMethod
     * @tc.expected: scrollBar is !nullptr
     */
    pattern_->scrollBar_ = AceType::MakeRefPtr<ScrollBar>(DisplayMode::AUTO);
    auto paintMethod = AceType::DynamicCast<GridPaintMethod>(pattern_->CreateNodePaintMethod());
    auto paintProperty = pattern_->CreatePaintProperty();
    PaintWrapper paintWrapper(frameNode_->GetRenderContext(), frameNode_->GetGeometryNode(), paintProperty);
    paintMethod->UpdateOverlayModifier(nullptr);
    auto scrollBar = paintMethod->scrollBar_.Upgrade();
    EXPECT_NE(scrollBar, nullptr);

    /**
     * @tc.steps: step2. call UpdateOverlayModifier
     * @tc.expected: AnimationTyp is correct
     */
    paintMethod->UpdateOverlayModifier(&paintWrapper);
    EXPECT_EQ(scrollBar->GetOpacityAnimationType(), OpacityAnimationType::NONE);
    EXPECT_EQ(scrollBar->GetHoverAnimationType(), HoverAnimationType::NONE);

    /**
     * @tc.steps: step3. call UpdateOverlayModifier when scrollBarOverlayModifier is seted
     * @tc.expected: AnimationTyp is correct
     */
    pattern_->CreateScrollBarOverlayModifier();
    EXPECT_EQ(pattern_->scrollBarOverlayModifier_, nullptr);
    paintMethod->SetScrollBarOverlayModifier(pattern_->GetScrollBarOverlayModifier());
    auto scrollBarOverlayModifier = paintMethod->scrollBarOverlayModifier_.Upgrade();
    EXPECT_EQ(scrollBarOverlayModifier, nullptr);
    paintMethod->UpdateOverlayModifier(&paintWrapper);
    EXPECT_EQ(scrollBar->GetOpacityAnimationType(), OpacityAnimationType::NONE);
    EXPECT_EQ(scrollBar->GetHoverAnimationType(), HoverAnimationType::NONE);
    scrollBar = nullptr;
}

/**
 * @tc.name: UpdateOverlayModifier003
 * @tc.desc: Test grid paint method UpdateOverlayModifier function
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, UpdateOverlayModifier003, TestSize.Level1)
{
    Create([](GridModelNG model) {
        model.SetRowsTemplate("1fr 1fr");
        CreateFixedItem(10);
    });

    /**
     * @tc.steps: step1. create scrollBar and paintMethod and ScrollBarOverlayModifier
     * @tc.expected: scrollBar is !nullptr
     */
    pattern_->scrollBar_ = AceType::MakeRefPtr<ScrollBar>(DisplayMode::AUTO);
    pattern_->scrollBar_->SetScrollable(true);
    auto paintMethod = AceType::DynamicCast<GridPaintMethod>(pattern_->CreateNodePaintMethod());
    auto paintProperty = pattern_->CreatePaintProperty();
    PaintWrapper paintWrapper(frameNode_->GetRenderContext(), frameNode_->GetGeometryNode(), paintProperty);
    EXPECT_TRUE(pattern_->scrollBar_->NeedPaint());
    pattern_->CreateScrollBarOverlayModifier();
    EXPECT_NE(pattern_->scrollBarOverlayModifier_, nullptr);
    paintMethod->SetScrollBarOverlayModifier(pattern_->GetScrollBarOverlayModifier());
    auto scrollBarOverlayModifier = paintMethod->scrollBarOverlayModifier_.Upgrade();
    EXPECT_NE(scrollBarOverlayModifier, nullptr);
    auto scrollBar = paintMethod->scrollBar_.Upgrade();
    EXPECT_NE(scrollBar, nullptr);

    /**
     * @tc.steps: step2. call UpdateOverlayModifier
     * @tc.expected: AnimationTyp is correct
     */
    paintMethod->UpdateOverlayModifier(&paintWrapper);
    EXPECT_EQ(scrollBar->GetOpacityAnimationType(), OpacityAnimationType::NONE);
    EXPECT_EQ(scrollBar->GetHoverAnimationType(), HoverAnimationType::NONE);

    /**
     * @tc.steps: step3. change PositionMode and call UpdateOverlayModifier
     * @tc.expected: AnimationTyp is correct
     */
    scrollBar->SetPositionMode(PositionMode::BOTTOM);
    paintMethod->UpdateOverlayModifier(&paintWrapper);
    scrollBar = paintMethod->scrollBar_.Upgrade();
    EXPECT_EQ(scrollBar->GetOpacityAnimationType(), OpacityAnimationType::NONE);
    EXPECT_EQ(scrollBar->GetHoverAnimationType(), HoverAnimationType::NONE);
    scrollBar = nullptr;
}

/**
 * @tc.name: PaintEdgeEffect001
 * @tc.desc: Test grid paint method PaintEdgeEffect function
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, PaintEdgeEffect001, TestSize.Level1)
{
    Create([](GridModelNG model) {
        model.SetRowsTemplate("1fr 1fr");
        CreateFixedItem(10);
    });

    /**
     * @tc.steps: step1. init scrollBar
     * @tc.expected: scrollBar is !nullptr
     */
    pattern_->scrollBar_ = AceType::MakeRefPtr<ScrollBar>(DisplayMode::AUTO);
    pattern_->scrollBar_->SetScrollable(true);
    auto paintMethod = AceType::DynamicCast<GridPaintMethod>(pattern_->CreateNodePaintMethod());
    auto paintProperty = pattern_->CreatePaintProperty();
    PaintWrapper paintWrapper(frameNode_->GetRenderContext(), frameNode_->GetGeometryNode(), paintProperty);
    EXPECT_TRUE(pattern_->scrollBar_->NeedPaint());
    pattern_->CreateScrollBarOverlayModifier();
    EXPECT_NE(pattern_->scrollBarOverlayModifier_, nullptr);
    paintMethod->SetScrollBarOverlayModifier(pattern_->GetScrollBarOverlayModifier());
    auto scrollBarOverlayModifier = paintMethod->scrollBarOverlayModifier_.Upgrade();
    EXPECT_NE(scrollBarOverlayModifier, nullptr);
    auto scrollBar = paintMethod->scrollBar_.Upgrade();
    EXPECT_NE(scrollBar, nullptr);

    /**
     * @tc.steps: step2. call PaintEdgeEffect
     * @tc.expected: edgeEffect_ is !nullptr
     */
    auto scrollEdgeEffect = AceType::MakeRefPtr<ScrollEdgeEffect>();
    paintMethod->SetEdgeEffect(scrollEdgeEffect);
    Testing::MockCanvas rsCanvas;
    EXPECT_CALL(rsCanvas, DetachPen()).WillRepeatedly(ReturnRef(rsCanvas));
    EXPECT_CALL(rsCanvas, AttachBrush(_)).WillRepeatedly(ReturnRef(rsCanvas));
    EXPECT_CALL(rsCanvas, DrawRect(_)).WillRepeatedly(Return());
    EXPECT_CALL(rsCanvas, DetachBrush()).WillRepeatedly(ReturnRef(rsCanvas));
    paintMethod->PaintEdgeEffect(nullptr, rsCanvas);
    paintMethod->PaintEdgeEffect(&paintWrapper, rsCanvas);
    EXPECT_NE(paintMethod->edgeEffect_.Upgrade(), nullptr);
}

/**
 * @tc.name: GridScrollTest006
 * @tc.desc: Test SetOnScrollBarUpdate Function.
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GridScrollTest006, TestSize.Level1)
{
    Create([](GridModelNG model) {
        ScrollBarUpdateFunc scrollFunc = [](int32_t index, Dimension offset) {
            std::optional<float> horizontalOffset = offset.ConvertToPx();
            std::optional<float> verticalOffset = offset.ConvertToPx();
            return std::make_pair(horizontalOffset, verticalOffset);
        };
        model.SetRowsTemplate("1fr 1fr");
        CreateFixedItem(2);
        model.SetGridHeight(Dimension(5));
        model.SetScrollBarMode(DisplayMode::AUTO);
        model.SetScrollBarColor("#FF0000");
        model.SetScrollBarWidth("10vp");
        model.SetIsRTL(TextDirection::LTR);

        NestedScrollOptions nestedOpt;
        model.SetNestedScroll(std::move(nestedOpt));
        ScrollToIndexFunc value;
        model.SetOnScrollToIndex(std::move(value));
    });
    auto paintProperty = frameNode_->GetPaintProperty<ScrollablePaintProperty>();
    EXPECT_EQ(paintProperty->GetBarStateString(), "BarState.Auto");

    auto pattern = frameNode_->GetPattern<GridPattern>();
    EXPECT_TRUE(pattern->isConfigScrollable_);
    auto eventHub = frameNode_->GetEventHub<GridEventHub>();
    EXPECT_FALSE(eventHub->onScrollToIndex_);
}

/**
 * @tc.name: GridSCroll001
 * @tc.desc: Test SetSelected Function.
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GridSCroll001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Create GridItemModelNG object
     */
    Create([](GridModelNG model) {
        model.SetRowsTemplate("1fr 1fr");
        GridItemModelNG itemModel;
        itemModel.Create(GridItemStyle::NONE);
        itemModel.SetRowStart(NULL_VALUE);
        itemModel.SetRowEnd(NULL_VALUE);
        itemModel.SetColumnStart(NULL_VALUE);
        itemModel.SetColumnEnd(NULL_VALUE);
        ViewStackProcessor::GetInstance()->Pop();

        /**
         * @tc.steps: step2. Test Create function
         */
        std::function<void(int32_t)> deepRenderFunc = [](int32_t innerNodeId) {};
        bool isLazy = true;
        itemModel.Create(std::move(deepRenderFunc), isLazy, GridItemStyle::PLAIN);

        /**
         * @tc.steps: step3. invoke SetSelected function
         */
        itemModel.SetSelected(true);
    });

    /**
     * @tc.expected: gridItemPattern->isSelected_ is true
     */
    auto gridItemPattern = frameNode_->GetPattern<GridItemPattern>();
    EXPECT_TRUE(gridItemPattern->isSelected_);
}

/**
 * @tc.name: SupplyAllData2ZeroIndex001
 * @tc.desc: Test GridScrollLayoutAlgorithm::SupplyAllData2ZeroIndex
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, SupplyAllData2ZeroIndex001, TestSize.Level1)
{
    Create([](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr 1fr");
        CreateFixedItem(30);
    });

    pattern_->ScrollToIndex(20, true, ScrollAlign::END);
    FlushLayoutTask(frameNode_);

    EXPECT_EQ(pattern_->GetGridLayoutInfo().gridMatrix_.size(), 4);
    EXPECT_EQ(pattern_->GetGridLayoutInfo().lineHeightMap_.size(), 4);
    EXPECT_EQ(pattern_->GetGridLayoutInfo().gridMatrix_.at(0).at(0), 0);
    EXPECT_EQ(pattern_->GetGridLayoutInfo().gridMatrix_.at(3).at(2), 11);
}

/**
 * @tc.name: SupplyAllData2ZeroIndex002
 * @tc.desc: Test GridScrollLayoutAlgorithm::SupplyAllData2ZeroIndex
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, SupplyAllData2ZeroIndex002, TestSize.Level1)
{
    Create([](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr 1fr");
        CreateFixedItem(30);
    });

    pattern_->ScrollToIndex(20, true, ScrollAlign::START);
    FlushLayoutTask(frameNode_);
    pattern_->ScrollToIndex(10, true, ScrollAlign::CENTER);
    FlushLayoutTask(frameNode_);

    EXPECT_EQ(pattern_->GetGridLayoutInfo().gridMatrix_.size(), 4);
    EXPECT_EQ(pattern_->GetGridLayoutInfo().lineHeightMap_.size(), 4);
    EXPECT_EQ(pattern_->GetGridLayoutInfo().gridMatrix_.at(0).at(0), 0);
    EXPECT_EQ(pattern_->GetGridLayoutInfo().gridMatrix_.at(3).at(2), 11);
}

/**
 * @tc.name: OnModifyDone001
 * @tc.desc: Test OnModifyDone
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, OnModifyDone001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Test OnModifyDone
     */
    Create([](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr 1fr 1fr");
        model.SetMultiSelectable(true);
        CreateFixedItem(10);
    });
    auto paintProperty = pattern_->GetPaintProperty<ScrollablePaintProperty>();
    EXPECT_TRUE(pattern_->multiSelectable_);
    EXPECT_TRUE(pattern_->isMouseEventInit_);
    EXPECT_TRUE(pattern_->GetScrollableEvent());
    EXPECT_TRUE(paintProperty->GetScrollBarProperty());
    EXPECT_TRUE(frameNode_->GetFocusHub());
    EXPECT_TRUE(pattern_->GetScrollableEvent()->GetScrollable());
    EXPECT_TRUE(pattern_->IsNeedInitClickEventRecorder());

    /**
     * @tc.steps: step2. Call OnModifyDone
     */
    pattern_->OnModifyDone();
    EXPECT_TRUE(pattern_->multiSelectable_);
    EXPECT_TRUE(pattern_->isMouseEventInit_);
    EXPECT_TRUE(pattern_->GetScrollableEvent());
    EXPECT_TRUE(paintProperty->GetScrollBarProperty());
    EXPECT_TRUE(frameNode_->GetFocusHub());
    EXPECT_TRUE(pattern_->GetScrollableEvent()->GetScrollable());
    EXPECT_TRUE(pattern_->IsNeedInitClickEventRecorder());

    /**
     * @tc.steps: step3. Change MultiSelectable and Call OnModifyDone
     */
    pattern_->SetMultiSelectable(false);
    pattern_->OnModifyDone();
    EXPECT_FALSE(pattern_->multiSelectable_);
    EXPECT_FALSE(pattern_->isMouseEventInit_);
}

/**
 * @tc.name: GetEndOffset001
 * @tc.desc: Test GetEndOffset
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GetEndOffset001, TestSize.Level1)
{
    Create([](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr 1fr 1fr");
        CreateFixedItem(10);
    });
    EXPECT_EQ(pattern_->GetEndOffset(), ITEM_HEIGHT);
}

/**
 * @tc.name: GetEndOffset002
 * @tc.desc: Test GetEndOffset
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GetEndOffset002, TestSize.Level1)
{
    Create([](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr 1fr 1fr");
        CreateFixedItem(10);
    });
    pattern_->SetEdgeEffect(EdgeEffect::SPRING, true);
    EXPECT_EQ(pattern_->GetEndOffset(), 0.f);
}

/**
 * @tc.name: GetEndOffset003
 * @tc.desc: Test GetEndOffset
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GetEndOffset003, TestSize.Level1)
{
    Create([](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr 1fr 1fr");
        CreateFixedItem(20);
    });
    pattern_->SetEdgeEffect(EdgeEffect::SPRING, true);
    EXPECT_EQ(pattern_->GetEndOffset(), 0.f);
}

/**
 * @tc.name: GetEndOffset004
 * @tc.desc: test EndOffset when content < viewport
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GetEndOffset004, TestSize.Level1)
{
    Create([](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr 1fr");
        model.SetLayoutOptions({ .irregularIndexes = { 1, 5 } });
        model.SetColumnsGap(Dimension { 5.0f });
        model.SetRowsGap(Dimension { 5.0f });
        CreateFixedHeightItems(6, 100.0f);
        model.SetEdgeEffect(EdgeEffect::SPRING, true);
        // make content smaller than viewport
        ViewAbstract::SetHeight(CalcLength(700.0f));
    });
    auto& info = pattern_->gridLayoutInfo_;
    pattern_->scrollableEvent_->scrollable_->isTouching_ = true;
    // line height + gap = 105
    for (int i = 0; i < 160; ++i) {
        UpdateCurrentOffset(-50.0f);
        EXPECT_EQ(pattern_->GetEndOffset(), info.startMainLineIndex_ * 105.0f);
    }
    EXPECT_LE(info.currentOffset_, -1000.0f);
    EXPECT_GE(info.startMainLineIndex_, 3);
}

/**
 * @tc.name: TestChildrenUpdate001
 * @tc.desc: Test updating existing children and adding children
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, TestChildrenUpdate001, TestSize.Level1)
{
    Create([](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr 1fr 1fr");
        CreateFixedHeightItems(2, 100.0f);
        model.SetLayoutOptions({});
        model.SetEdgeEffect(EdgeEffect::SPRING, true);
    });
    auto& info = pattern_->gridLayoutInfo_;
    pattern_->scrollableEvent_->scrollable_->isTouching_ = true;
    EXPECT_FALSE(pattern_->irregular_);
    for (int i = 0; i < 2; ++i) {
        frameNode_->ChildrenUpdatedFrom(i);
        frameNode_->MarkDirtyNode(PROPERTY_UPDATE_MEASURE);
        FlushLayoutTask(frameNode_);
        EXPECT_EQ(GetChildOffset(frameNode_, 0), OffsetF(0, 0));
        EXPECT_EQ(GetChildOffset(frameNode_, 1), OffsetF(GRID_WIDTH / 4.0f, 0));
        const decltype(info.gridMatrix_) cmp = { { 0, { { 0, 0 }, { 1, 1 } } } };
        EXPECT_EQ(info.gridMatrix_, cmp);
        EXPECT_EQ(info.lineHeightMap_.size(), 1);
    }

    AddFixedHeightItems(3, 100.0f);
    frameNode_->ChildrenUpdatedFrom(2);
    frameNode_->MarkDirtyNode(PROPERTY_UPDATE_MEASURE);
    FlushLayoutTask(frameNode_);
    const decltype(info.gridMatrix_) cmp2 = { { 0, { { 0, 0 }, { 1, 1 }, { 2, 2 }, { 3, 3 } } }, { 1, { { 0, 4 } } } };
    EXPECT_EQ(info.gridMatrix_, cmp2);
    EXPECT_EQ(info.lineHeightMap_.size(), 2);
    EXPECT_EQ(GetChildOffset(frameNode_, 4), OffsetF(0.0f, 100.0f));
}

/**
 * @tc.name: GetVisibleSelectedItems001
 * @tc.desc: Test GetVisibleSelectedItems
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GetVisibleSelectedItems001, TestSize.Level1)
{
    /**
     * @tc.cases: Set item(index:1) isSelected and call GetVisibleSelectedItems
     * @tc.expected: Has 1 item selected
     */
    Create([](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr 1fr 1fr");
        CreateFixedItem(20);
    });
    GetChildPattern<GridItemPattern>(frameNode_, 1)->SetSelected(true);
    EXPECT_EQ(pattern_->GetVisibleSelectedItems().size(), 1);
    EXPECT_FALSE(pattern_->irregular_);
}

/**
 * @tc.name: AdaptToChildMainSize001
 * @tc.desc: Test AdaptToChildMainSize
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, AdaptToChildMainSize001, TestSize.Level1)
{
    /**
     * @tc.cases: Set ColumnsTemplate, not set grid height
     */
    GridModelNG model;
    RefPtr<ScrollControllerBase> positionController = model.CreatePositionController();
    RefPtr<ScrollProxy> scrollBarProxy = model.CreateScrollBarProxy();
    model.Create(positionController, scrollBarProxy);
    ViewAbstract::SetWidth(CalcLength(GRID_WIDTH));
    model.SetColumnsTemplate("1fr 1fr 1fr 1fr");
    model.SetCellLength(ITEM_HEIGHT);
    model.SetMaxCount(4);
    CreateFixedItem(20);
    GetInstance();
    FlushLayoutTask(frameNode_);
    EXPECT_EQ(pattern_->GetGridLayoutInfo().lastMainSize_, 1000.f);
}

/**
 * @tc.name: AdaptToChildMainSize002
 * @tc.desc: Test AdaptToChildMainSize
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, AdaptToChildMainSize002, TestSize.Level1)
{
    /**
     * @tc.cases: Set RowsTemplate, not set grid width
     */
    GridModelNG model;
    RefPtr<ScrollControllerBase> positionController = model.CreatePositionController();
    RefPtr<ScrollProxy> scrollBarProxy = model.CreateScrollBarProxy();
    model.Create(positionController, scrollBarProxy);
    ViewAbstract::SetHeight(CalcLength(GRID_HEIGHT));
    model.SetRowsTemplate("1fr 1fr 1fr 1fr");
    model.SetCellLength(ITEM_WIDTH);
    model.SetMaxCount(4);
    CreateFixedItem(20);
    GetInstance();
    FlushLayoutTask(frameNode_);
    EXPECT_EQ(pattern_->GetGridLayoutInfo().lastMainSize_, 600.f);
}

/**
 * @tc.name: LayoutCachedItem001
 * @tc.desc: Test LayoutCachedItem
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, LayoutCachedItem001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Set CachedCount:1
     * @tc.expected: The item(index:16) below view is active, no item above view
     */
    Create([](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr 1fr 1fr");
        model.SetCachedCount(1);
        CreateFixedItem(40);
    });
    EXPECT_FALSE(GetChildFrameNode(frameNode_, 16)->IsActive()); // the fifth row
    EXPECT_FALSE(GetChildFrameNode(frameNode_, 20)->IsActive()); // the sixth row

    /**
     * @tc.steps: step2. Scroll down
     * @tc.expected: The item(index:0) above view is active, the item(index:20) below view is active
     */
    pattern_->UpdateCurrentOffset(-ITEM_HEIGHT, SCROLL_FROM_UPDATE);
    pattern_->ScrollToIndex(4, false, ScrollAlign::START);
    FlushLayoutTask(frameNode_);
    EXPECT_FALSE(GetChildFrameNode(frameNode_, 0)->IsActive());
    EXPECT_FALSE(GetChildFrameNode(frameNode_, 20)->IsActive());

    /**
     * @tc.steps: step3. Scroll down
     * @tc.expected: The item(index:4) above view is active, the item(index:24) below view is active
     */
    pattern_->ScrollToIndex(8, false, ScrollAlign::START);
    FlushLayoutTask(frameNode_);
    EXPECT_FALSE(GetChildFrameNode(frameNode_, 0)->IsActive());
    EXPECT_FALSE(GetChildFrameNode(frameNode_, 4)->IsActive());
    EXPECT_FALSE(GetChildFrameNode(frameNode_, 24)->IsActive()); // th seventh row

    /**
     * @tc.steps: step4. Scroll up
     * @tc.expected: The item(index:0) above view is active, the item(index:20) below view is active
     */
    pattern_->ScrollToIndex(4, false, ScrollAlign::START);
    FlushLayoutTask(frameNode_);
    EXPECT_FALSE(GetChildFrameNode(frameNode_, 0)->IsActive());
    EXPECT_FALSE(GetChildFrameNode(frameNode_, 20)->IsActive());
    EXPECT_FALSE(GetChildFrameNode(frameNode_, 24)->IsActive());

    /**
     * @tc.steps: step5. Scroll up
     * @tc.expected: The item(index:16) below view is active, no item above view
     */
    pattern_->ScrollToIndex(0, false, ScrollAlign::START);
    FlushLayoutTask(frameNode_);
    EXPECT_FALSE(GetChildFrameNode(frameNode_, 16)->IsActive());
    EXPECT_FALSE(GetChildFrameNode(frameNode_, 20)->IsActive());
}

/**
 * @tc.name: GridLayoutTest001
 * @tc.desc: Test Grid Measure with GrdiLayoutOptions
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GridLayoutTest001, TestSize.Level1)
{
    GridLayoutOptions option;
    option.regularSize = { 1, 1 };
    int32_t gridItems[4][4] = { { 0, 0, 1, 1 }, { 0, 1, 1, 1 }, { 0, 2, 1, 1 }, { 1, 0, 1, 1 } };

    auto onGetRectByIndex = [gridItems](int32_t index) {
        GridItemRect itemRect;
        itemRect.rowStart = gridItems[index][0];
        itemRect.columnStart = gridItems[index][1];
        itemRect.rowSpan = gridItems[index][2];
        itemRect.columnSpan = gridItems[index][3];
        return itemRect;
    };
    option.getRectByIndex = std::move(onGetRectByIndex);
    Create([option](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr 1fr");
        model.SetRowsTemplate("1fr 1fr 1fr");
        model.SetLayoutOptions(option);
        model.SetColumnsGap(Dimension(COL_GAP));
        model.SetRowsGap(Dimension(ROW_GAP));
        CreateFixedItem(4);
    });

    EXPECT_EQ(pattern_->GetGridLayoutInfo().startMainLineIndex_, 0);
    EXPECT_EQ(pattern_->GetGridLayoutInfo().endMainLineIndex_, 1);
    EXPECT_EQ(pattern_->GetGridLayoutInfo().startIndex_, 0);
    EXPECT_EQ(pattern_->GetGridLayoutInfo().endIndex_, 3);
}

/**
 * @tc.name: LayoutRTL001
 * @tc.desc: Test property ayout with Direction RTL
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, LayoutRTL001, TestSize.Level1)
{
    float itemWidth = 120.f;
    Create([itemWidth](GridModelNG model) {
        model.SetIsRTL(TextDirection::RTL);
        model.SetColumnsTemplate("1fr 1fr 1fr 1fr");
        model.SetRowsTemplate("1fr 1fr 1fr 1fr");
        CreateItem(12, itemWidth, ITEM_HEIGHT);
    });

    int32_t colsNumber = 4; // 4 * 120(itemWidth) = 480(gridWidth)
    for (int32_t index = 0; index < 10; index++) {
        RectF childRect = GetChildRect(frameNode_, index);
        float offsetX = GRID_WIDTH - index % colsNumber * itemWidth - itemWidth;
        float offsetY = floor(index / colsNumber) * ITEM_HEIGHT;
        RectF expectRect = RectF(offsetX, offsetY, itemWidth, ITEM_HEIGHT);
        EXPECT_TRUE(IsEqual(childRect, expectRect)) << "index: " << index;
    }
}

/**
 * @tc.name: AdaptiveLayoutRTL001
 * @tc.desc: Test property AdaptiveLayout with GridDirection Row and Direction RTL
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, AdaptiveLayoutRTL001, TestSize.Level1)
{
    float itemWidth = 100.f;
    Create([itemWidth](GridModelNG model) {
        model.SetLayoutDirection(FlexDirection::ROW);
        model.SetEditable(true);
        model.SetCellLength(ITEM_HEIGHT);
        model.SetMinCount(4);
        model.SetMaxCount(2);
        model.SetIsRTL(TextDirection::RTL);
        CreateItem(10, itemWidth, ITEM_HEIGHT);
    });

    /**
     * @tc.steps: step1. While the before set minCount > maxCount
     * @tc.expected: would let minCount = 1, maxCount = Infinity;
     */
    int32_t colsNumber = 4; // 4 * 100(itemWidth) < 480(gridWidth)
    for (int32_t index = 0; index < 10; index++) {
        RectF childRect = GetChildRect(frameNode_, index);
        float offsetX = GRID_WIDTH - index % colsNumber * itemWidth - itemWidth;
        float offsetY = floor(index / colsNumber) * ITEM_HEIGHT;
        RectF expectRect = RectF(offsetX, offsetY, itemWidth, ITEM_HEIGHT);
        EXPECT_TRUE(IsEqual(childRect, expectRect)) << "index: " << index;
    }
}

/**
 * @tc.name: AdaptiveLayoutRTL002
 * @tc.desc: Test property AdaptiveLayout with GridDirection Column and Direction RTL
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, AdaptiveLayoutRTL002, TestSize.Level1)
{
    float itemWidth = 100.f;
    Create([itemWidth](GridModelNG model) {
        model.SetLayoutDirection(FlexDirection::COLUMN);
        model.SetEditable(true);
        model.SetCellLength(ITEM_HEIGHT);
        model.SetMinCount(4);
        model.SetMaxCount(2);
        model.SetIsRTL(TextDirection::RTL);
        CreateItem(10, itemWidth, ITEM_HEIGHT);
    });

    /**
     * @tc.steps: step1. While the before set minCount > maxCount
     * @tc.expected: would let minCount = 1, maxCount = Infinity;
     */
    int32_t colsNumber = 4; // 4 * 100(itemWidth) < 480(gridWidth)
    int32_t rowsNumber = 4;
    for (int32_t index = 0; index < 8; index++) {
        RectF childRect = GetChildRect(frameNode_, index);
        float offsetX = GRID_WIDTH - floor(index / rowsNumber) * itemWidth * 2 - itemWidth;
        float offsetY = index % colsNumber * ITEM_HEIGHT;
        RectF expectRect = RectF(offsetX, offsetY, itemWidth, ITEM_HEIGHT);
        EXPECT_TRUE(IsEqual(childRect, expectRect)) << "index: " << index;
    }
}

/**
 * @tc.name: AdaptiveLayoutRTL003
 * @tc.desc: Test property AdaptiveLayout with GridDirection RowReverse and Direction RTL
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, AdaptiveLayoutRTL003, TestSize.Level1)
{
    float itemWidth = 100.f;
    Create([itemWidth](GridModelNG model) {
        model.SetLayoutDirection(FlexDirection::ROW_REVERSE);
        model.SetEditable(true);
        model.SetCellLength(ITEM_HEIGHT);
        model.SetMinCount(4);
        model.SetMaxCount(2);
        model.SetIsRTL(TextDirection::RTL);
        CreateItem(10, itemWidth, ITEM_HEIGHT);
    });

    /**
     * @tc.steps: step1. While the before set minCount > maxCount
     * @tc.expected: would let minCount = 1, maxCount = Infinity;
     */
    int32_t colsNumber = 4; // 4 * 100(itemWidth) < 480(gridWidth)
    for (int32_t index = 0; index < 10; index++) {
        RectF childRect = GetChildRect(frameNode_, index);
        float offsetX = index % colsNumber * itemWidth + (GRID_WIDTH - colsNumber * itemWidth);
        float offsetY = floor(index / colsNumber) * ITEM_HEIGHT;
        RectF expectRect = RectF(offsetX, offsetY, itemWidth, ITEM_HEIGHT);
        EXPECT_TRUE(IsEqual(childRect, expectRect)) << "index: " << index;
    }
}

/**
 * @tc.name: AdaptiveLayoutRTL004
 * @tc.desc: Test property AdaptiveLayout with GridDirection ColumnReverse and Direction RTL
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, AdaptiveLayoutRTL004, TestSize.Level1)
{
    float itemWidth = 100.f;
    Create([itemWidth](GridModelNG model) {
        model.SetLayoutDirection(FlexDirection::COLUMN_REVERSE);
        model.SetEditable(true);
        model.SetCellLength(ITEM_HEIGHT);
        model.SetMinCount(4);
        model.SetMaxCount(2);
        model.SetIsRTL(TextDirection::RTL);
        CreateItem(10, itemWidth, ITEM_HEIGHT);
    });

    /**
     * @tc.steps: step1. While the before set minCount > maxCount
     * @tc.expected: would let minCount = 1, maxCount = Infinity;
     */
    int32_t colsNumber = 4; // 4 * 100(itemWidth) < 480(gridWidth)
    int32_t rowsNumber = 4;
    for (int32_t index = 0; index < 8; index++) {
        RectF childRect = GetChildRect(frameNode_, index);
        float offsetX = GRID_WIDTH - floor(index / rowsNumber) * itemWidth * 2 - itemWidth;
        float offsetY = GRID_HEIGHT - index % colsNumber * ITEM_HEIGHT - ITEM_HEIGHT;
        RectF expectRect = RectF(offsetX, offsetY, itemWidth, ITEM_HEIGHT);
        EXPECT_TRUE(IsEqual(childRect, expectRect)) << "index: " << index;
    }
}

/**
 * @tc.name: ScrollLayoutRTL001
 * @tc.desc: Test Vertical Grid with Direction RTL
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, ScrollLayoutRTL001, TestSize.Level1)
{
    float itemWidth = 120.0f;
    Create([](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr 1fr 1fr");
        model.SetIsRTL(TextDirection::RTL);
        CreateFixedItem(18);
    });

    int32_t colsNumber = 4;
    for (int32_t index = 0; index < 8; index++) {
        RectF childRect = GetChildRect(frameNode_, index);
        float offsetX = GRID_WIDTH - index % colsNumber * itemWidth - itemWidth;
        float offsetY = floor(index / colsNumber) * ITEM_HEIGHT;
        RectF expectRect = RectF(offsetX, offsetY, itemWidth, ITEM_HEIGHT);
        EXPECT_TRUE(IsEqual(childRect, expectRect)) << "index: " << index;
    }
}

/**
 * @tc.name: ScrollLayoutRTL002
 * @tc.desc: Test Horizontal Grid with Direction RTL
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, ScrollLayoutRTL002, TestSize.Level1)
{
    float itemWidth = 120.0f;
    Create([](GridModelNG model) {
        model.SetRowsTemplate("1fr 1fr 1fr 1fr");
        model.SetIsRTL(TextDirection::RTL);
        CreateFixedItem(18);
    });

    int32_t rowsNumber = 4;
    for (int32_t index = 0; index < 8; index++) {
        RectF childRect = GetChildRect(frameNode_, index);
        float offsetX = GRID_WIDTH - floor(index / rowsNumber) * itemWidth - itemWidth;
        float offsetY = index % rowsNumber * ITEM_HEIGHT;
        RectF expectRect = RectF(offsetX, offsetY, itemWidth, ITEM_HEIGHT);
        EXPECT_TRUE(IsEqual(childRect, expectRect)) << "index: " << index;
    }
}

/**
 * @tc.name: AdaptToChildMainSize003
 * @tc.desc: Test Horizontal Grid with Infinity mainSize
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, AdaptToChildMainSize003, TestSize.Level1)
{
    Create([](GridModelNG model) {
        model.SetRowsTemplate("1fr 1fr 1fr 1fr");
        ViewAbstract::SetWidth(CalcLength(Infinity<int32_t>()));
        CreateFixedItem(8);
    });
    EXPECT_EQ(pattern_->GetGridLayoutInfo().lastMainSize_, ITEM_WIDTH * 2);
}

/**
 * @tc.name: AdaptToChildMainSize004
 * @tc.desc: Test Vertical Grid with Infinity mainSize
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, AdaptToChildMainSize004, TestSize.Level1)
{
    Create([](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr 1fr 1fr");
        ViewAbstract::SetHeight(CalcLength(Infinity<int32_t>()));
        CreateFixedItem(8);
    });
    EXPECT_EQ(pattern_->GetGridLayoutInfo().lastMainSize_, ITEM_HEIGHT * 2);
}

/**
 * @tc.name: AdaptToChildMainSize005
 * @tc.desc: Test Vertical Grid with maxcount and 0 itemHeight
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, AdaptToChildMainSize005, TestSize.Level1)
{
    Create([](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr 1fr 1fr");
        ViewAbstract::SetHeight(CalcLength(100));
        model.SetMaxCount(1);
        CreateItem(1, 0, 0);
    });
    EXPECT_EQ(pattern_->GetGridLayoutInfo().lastMainSize_, 100);
}

/*
 * @tc.name: GetResetMode001
 * @tc.desc: Test Reset Function when have bigItem
 * @tc.type: FUNC
 */
HWTEST_F(GridLayoutTestNg, GetResetMode001, TestSize.Level1)
{
    Create([](GridModelNG model) {
        model.SetColumnsTemplate("1fr 1fr 1fr 1fr");
        CreateFixedItem(40);
    });

    auto layoutAlgorithmWrapper = AceType::DynamicCast<LayoutAlgorithmWrapper>(frameNode_->GetLayoutAlgorithm());
    auto layoutAlgorithm =
        AceType::DynamicCast<GridScrollLayoutAlgorithm>(layoutAlgorithmWrapper->GetLayoutAlgorithm());
    EXPECT_EQ(layoutAlgorithm->GetResetMode(-1), std::make_pair(false, false));
    EXPECT_EQ(layoutAlgorithm->GetResetMode(1), std::make_pair(true, false));

    pattern_->ScrollToIndex(30, false, ScrollAlign::START);
    layoutAlgorithm->gridLayoutInfo_.startIndex_ = 30;
    frameNode_->childrenUpdatedFrom_ = 20;
    FlushLayoutTask(frameNode_);

    EXPECT_EQ(layoutAlgorithm->GetResetMode(0), std::make_pair(true, false));
    EXPECT_EQ(layoutAlgorithm->GetResetMode(10), std::make_pair(true, false));
    EXPECT_EQ(layoutAlgorithm->GetResetMode(25), std::make_pair(true, false));

    layoutAlgorithm->gridLayoutInfo_.hasBigItem_ = true;

    EXPECT_EQ(layoutAlgorithm->GetResetMode(0), std::make_pair(true, false));
    EXPECT_EQ(layoutAlgorithm->GetResetMode(10), std::make_pair(true, false));
    EXPECT_EQ(layoutAlgorithm->GetResetMode(25), std::make_pair(false, true));
}
} // namespace OHOS::Ace::NG

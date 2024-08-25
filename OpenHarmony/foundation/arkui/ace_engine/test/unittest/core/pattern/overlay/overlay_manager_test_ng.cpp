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
#include <mutex>
#include <optional>
#include <string>

#include "gtest/gtest.h"

#define private public
#define protected public
#include "test/mock/base/mock_task_executor.h"
#include "test/mock/core/common/mock_container.h"
#include "test/mock/core/common/mock_theme_manager.h"
#include "test/mock/core/pipeline/mock_pipeline_context.h"

#include "base/geometry/dimension.h"
#include "base/geometry/ng/offset_t.h"
#include "base/geometry/ng/rect_t.h"
#include "base/geometry/ng/size_t.h"
#include "base/memory/ace_type.h"
#include "base/utils/utils.h"
#include "base/window/foldable_window.h"
#include "core/components/common/properties/color.h"
#include "core/components/dialog/dialog_properties.h"
#include "core/components/dialog/dialog_theme.h"
#include "core/components/drag_bar/drag_bar_theme.h"
#include "core/components/picker/picker_data.h"
#include "core/components/picker/picker_theme.h"
#include "core/components/select/select_theme.h"
#include "core/components/toast/toast_theme.h"
#include "core/components_ng/base/view_abstract.h"
#include "core/components_ng/base/view_stack_processor.h"
#include "core/components_ng/pattern/bubble/bubble_event_hub.h"
#include "core/components_ng/pattern/bubble/bubble_pattern.h"
#include "core/components_ng/pattern/button/button_pattern.h"
#include "core/components_ng/pattern/dialog/dialog_event_hub.h"
#include "core/components_ng/pattern/dialog/dialog_pattern.h"
#include "core/components_ng/pattern/linear_layout/linear_layout_pattern.h"
#include "core/components_ng/pattern/menu/menu_pattern.h"
#include "core/components_ng/pattern/menu/menu_theme.h"
#include "core/components_ng/pattern/menu/menu_view.h"
#include "core/components_ng/pattern/menu/preview/menu_preview_pattern.h"
#include "core/components_ng/pattern/menu/wrapper/menu_wrapper_pattern.h"
#include "core/components_ng/pattern/overlay/modal_presentation_layout_algorithm.h"
#include "core/components_ng/pattern/overlay/modal_presentation_pattern.h"
#include "core/components_ng/pattern/overlay/overlay_manager.h"
#include "core/components_ng/pattern/overlay/sheet_drag_bar_paint_method.h"
#include "core/components_ng/pattern/overlay/sheet_drag_bar_pattern.h"
#include "core/components_ng/pattern/overlay/sheet_presentation_layout_algorithm.h"
#include "core/components_ng/pattern/overlay/sheet_presentation_pattern.h"
#include "core/components_ng/pattern/overlay/sheet_style.h"
#include "core/components_ng/pattern/overlay/sheet_theme.h"
#include "core/components_ng/pattern/overlay/sheet_view.h"
#include "core/components_ng/pattern/picker/picker_type_define.h"
#include "core/components_ng/pattern/root/root_pattern.h"
#include "core/components_ng/pattern/scroll/scroll_pattern.h"
#include "core/components_ng/pattern/stage/stage_pattern.h"
#include "core/components_ng/pattern/text/text_pattern.h"
#include "core/components_ng/pattern/text_field/text_field_manager.h"
#include "core/components_ng/pattern/toast/toast_layout_property.h"
#include "core/components_ng/pattern/toast/toast_pattern.h"
#include "core/components_v2/inspector/inspector_constants.h"
#include "core/pipeline_ng/pipeline_context.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS::Ace::NG {
namespace {
const NG::BorderWidthProperty BORDER_WIDTH_TEST = { 1.0_vp, 1.0_vp, 1.0_vp, 1.0_vp };
const NG::BorderStyleProperty BORDER_STYLE_TEST = {BorderStyle::SOLID,
    BorderStyle::SOLID, BorderStyle::SOLID, BorderStyle::SOLID};
const NG::BorderColorProperty BORDER_COLOR_TEST = { Color::BLUE,
    Color::BLUE, Color::BLUE, Color::BLUE };
const NG::BorderWidthProperty NEW_BORDER_WIDTH_TEST = { 10.0_vp, 15.0_vp, 5.0_vp, 10.0_vp };
const NG::BorderStyleProperty NEW_BORDER_STYLE_TEST = {BorderStyle::SOLID,
    BorderStyle::DASHED, BorderStyle::DOTTED, BorderStyle::NONE};
const NG::BorderColorProperty NEW_BORDER_COLOR_TEST = { Color::RED,
    Color::GREEN, Color::GRAY, Color::BLACK };
const std::string TEXT_TAG = "text";
const OffsetF MENU_OFFSET(10.0, 10.0);
const std::string MESSAGE = "hello world";
const std::string BOTTOMSTRING = "test";
constexpr int32_t DURATION = 2;
constexpr float MINUS_HEIGHT = -5.0f;
const std::string LONGEST_CONTENT = "新建文件夹";
const std::vector<std::string> FONT_FAMILY_VALUE = { "cursive" };
} // namespace

class OverlayManagerTestNg : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;
    static void SetUpTestCase();
    static void TearDownTestCase();
    std::function<RefPtr<UINode>()> builderFunc_;
    std::function<RefPtr<UINode>()> titleBuilderFunc_;

protected:
    static RefPtr<FrameNode> CreateBubbleNode(const TestProperty& testProperty);
    static RefPtr<FrameNode> CreateTargetNode();
    static void CreateSheetStyle(SheetStyle& sheetStyle);
    void CreateSheetBuilder();
    int32_t minPlatformVersion_ = 0;
};

void OverlayManagerTestNg::SetUp()
{
    minPlatformVersion_ = PipelineBase::GetCurrentContext()->GetMinPlatformVersion();
}

void OverlayManagerTestNg::TearDown()
{
    PipelineBase::GetCurrentContext()->SetMinPlatformVersion(minPlatformVersion_);
}

void OverlayManagerTestNg::SetUpTestCase()
{
    MockPipelineContext::SetUp();
    RefPtr<FrameNode> stageNode = AceType::MakeRefPtr<FrameNode>("STAGE", -1, AceType::MakeRefPtr<Pattern>());
    auto stageManager = AceType::MakeRefPtr<StageManager>(stageNode);
    MockPipelineContext::GetCurrent()->stageManager_ = stageManager;
    auto themeManager = AceType::MakeRefPtr<MockThemeManager>();
    MockContainer::SetUp();
    MockContainer::Current()->taskExecutor_ = AceType::MakeRefPtr<MockTaskExecutor>();
    MockContainer::Current()->pipelineContext_ = MockPipelineContext::GetCurrentContext();
    MockPipelineContext::GetCurrentContext()->SetMinPlatformVersion((int32_t)PlatformVersion::VERSION_ELEVEN);
    EXPECT_CALL(*themeManager, GetTheme(_)).WillRepeatedly([](ThemeType type) -> RefPtr<Theme> {
        if (type == DragBarTheme::TypeId()) {
            return AceType::MakeRefPtr<DragBarTheme>();
        } else if (type == IconTheme::TypeId()) {
            return AceType::MakeRefPtr<IconTheme>();
        } else if (type == DialogTheme::TypeId()) {
            return AceType::MakeRefPtr<DialogTheme>();
        } else if (type == PickerTheme::TypeId()) {
            return AceType::MakeRefPtr<PickerTheme>();
        } else if (type == SelectTheme::TypeId()) {
            return AceType::MakeRefPtr<SelectTheme>();
        } else if (type == MenuTheme::TypeId()) {
            return AceType::MakeRefPtr<MenuTheme>();
        } else if (type == ToastTheme::TypeId()) {
            return AceType::MakeRefPtr<ToastTheme>();
        } else if (type == SheetTheme::TypeId()) {
            return AceType::MakeRefPtr<SheetTheme>();
        } else {
            return nullptr;
        }
    });
    MockPipelineContext::GetCurrent()->SetThemeManager(themeManager);
}
void OverlayManagerTestNg::TearDownTestCase()
{
    MockPipelineContext::GetCurrent()->themeManager_ = nullptr;
    MockPipelineContext::TearDown();
}

RefPtr<FrameNode> OverlayManagerTestNg::CreateTargetNode()
{
    auto frameNode = FrameNode::GetOrCreateFrameNode(V2::BUTTON_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
        []() { return AceType::MakeRefPtr<ButtonPattern>(); });
    return frameNode;
}

void OverlayManagerTestNg::CreateSheetStyle(SheetStyle& sheetStyle)
{
    if (!sheetStyle.sheetMode.has_value()) {
        sheetStyle.sheetMode = SheetMode::MEDIUM;
    }
    if (!sheetStyle.showDragBar.has_value()) {
        sheetStyle.showDragBar = true;
    }
}

void OverlayManagerTestNg::CreateSheetBuilder()
{
    auto builderFunc = []() -> RefPtr<UINode> {
        auto frameNode =
            FrameNode::GetOrCreateFrameNode(V2::COLUMN_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
                []() { return AceType::MakeRefPtr<LinearLayoutPattern>(true); });
        auto childFrameNode = FrameNode::GetOrCreateFrameNode(V2::BUTTON_ETS_TAG,
            ElementRegister::GetInstance()->MakeUniqueId(), []() { return AceType::MakeRefPtr<ButtonPattern>(); });
        frameNode->AddChild(childFrameNode);
        return frameNode;
    };
    auto buildTitleNodeFunc = []() -> RefPtr<UINode> {
        auto frameNode =
            FrameNode::GetOrCreateFrameNode(V2::COLUMN_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
                []() { return AceType::MakeRefPtr<LinearLayoutPattern>(true); });
        auto childFrameNode = FrameNode::GetOrCreateFrameNode(V2::TEXT_ETS_TAG,
            ElementRegister::GetInstance()->MakeUniqueId(), []() { return AceType::MakeRefPtr<TextPattern>(); });
        frameNode->AddChild(childFrameNode);
        return frameNode;
    };
    builderFunc_ = builderFunc;
    titleBuilderFunc_ = buildTitleNodeFunc;
}


/**
 * @tc.name: DeleteModal001
 * @tc.desc: Test OverlayManager::DeleteModal
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, DeleteModal001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create target node and toast node.
     */
    auto targetNode = CreateTargetNode();
    auto targetId = targetNode->GetId();
    auto targetTag = targetNode->GetTag();
    auto toastId = ElementRegister::GetInstance()->MakeUniqueId();
    auto toastNode =
        FrameNode::CreateFrameNode(V2::TOAST_ETS_TAG, toastId, AceType::MakeRefPtr<BubblePattern>(targetId, targetTag));

    /**
     * @tc.steps: step2. create overlayManager and call ShowToast when rootElement is nullptr.
     * @tc.expected: toastMap_ is empty
     */
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    auto overlayManager = AceType::MakeRefPtr<OverlayManager>(rootNode);
    overlayManager->ShowToast(MESSAGE, DURATION, BOTTOMSTRING, true);
    EXPECT_FALSE(overlayManager->toastMap_.empty());

    auto builderFunc = []() -> RefPtr<UINode> {
        auto frameNode =
            FrameNode::GetOrCreateFrameNode(V2::COLUMN_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
                []() { return AceType::MakeRefPtr<LinearLayoutPattern>(true); });
        auto childFrameNode = FrameNode::GetOrCreateFrameNode(V2::BUTTON_ETS_TAG,
            ElementRegister::GetInstance()->MakeUniqueId(), []() { return AceType::MakeRefPtr<ButtonPattern>(); });
        frameNode->AddChild(childFrameNode);
        return frameNode;
    };

    auto buildTitleNodeFunc = []() -> RefPtr<UINode> {
        auto frameNode =
            FrameNode::GetOrCreateFrameNode(V2::COLUMN_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
                []() { return AceType::MakeRefPtr<LinearLayoutPattern>(true); });
        auto childFrameNode = FrameNode::GetOrCreateFrameNode(V2::TEXT_ETS_TAG,
            ElementRegister::GetInstance()->MakeUniqueId(), []() { return AceType::MakeRefPtr<TextPattern>(); });
        frameNode->AddChild(childFrameNode);
        return frameNode;
    };

    /**
     * @tc.steps: step3. create sheet node and run DeleteModal.
     */
    SheetStyle sheetStyle;
    CreateSheetStyle(sheetStyle);
    bool isShow = true;
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc), std::move(buildTitleNodeFunc), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    overlayManager->modalList_.emplace_back(nullptr);
    overlayManager->DeleteModal(targetId);
    EXPECT_EQ(overlayManager->modalList_.size(), 1);

    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc), std::move(buildTitleNodeFunc), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    overlayManager->modalList_.emplace_back(nullptr);
    overlayManager->DeleteModal(targetId + 1);
    EXPECT_EQ(overlayManager->modalList_.size(), 3);
}

/**
 * @tc.name: OnBindSheet001
 * @tc.desc: Test OverlayManager::OnBindSheet create sheet page.
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, OnBindSheet001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create target node.
     */
    auto targetNode = CreateTargetNode();
    ViewStackProcessor::GetInstance()->Push(targetNode);
    auto stageNode = FrameNode::CreateFrameNode(
        V2::STAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StagePattern>());
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    stageNode->MountToParent(rootNode);
    targetNode->MountToParent(stageNode);
    rootNode->MarkDirtyNode();

    /**
     * @tc.steps: step2. create builder func.
     */
    auto builderFunc = []() -> RefPtr<UINode> {
        auto frameNode =
            FrameNode::GetOrCreateFrameNode(V2::COLUMN_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
                []() { return AceType::MakeRefPtr<LinearLayoutPattern>(true); });
        auto childFrameNode = FrameNode::GetOrCreateFrameNode(V2::BUTTON_ETS_TAG,
            ElementRegister::GetInstance()->MakeUniqueId(), []() { return AceType::MakeRefPtr<ButtonPattern>(); });
        frameNode->AddChild(childFrameNode);
        return frameNode;
    };

    auto buildTitleNodeFunc = []() -> RefPtr<UINode> {
        auto frameNode =
            FrameNode::GetOrCreateFrameNode(V2::COLUMN_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
                []() { return AceType::MakeRefPtr<LinearLayoutPattern>(true); });
        auto childFrameNode = FrameNode::GetOrCreateFrameNode(V2::TEXT_ETS_TAG,
            ElementRegister::GetInstance()->MakeUniqueId(), []() { return AceType::MakeRefPtr<TextPattern>(); });
        frameNode->AddChild(childFrameNode);
        return frameNode;
    };

    /**
     * @tc.steps: step3. create sheet node and get sheet node, get pattern.
     * @tc.expected: related function is called.
     */
    SheetStyle sheetStyle;
    CreateSheetStyle(sheetStyle);
    bool isShow = true;
    auto overlayManager = AceType::MakeRefPtr<OverlayManager>(rootNode);
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc), std::move(buildTitleNodeFunc), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    auto topSheetNode = overlayManager->modalStack_.top().Upgrade();
    EXPECT_FALSE(topSheetNode == nullptr);
    auto topSheetPattern = topSheetNode->GetPattern<SheetPresentationPattern>();
    EXPECT_FALSE(topSheetPattern == nullptr);
    auto sheetLayoutProperty = topSheetNode->GetLayoutProperty<SheetPresentationProperty>();
    EXPECT_FALSE(sheetLayoutProperty == nullptr);
    auto sheetChildren = topSheetNode->GetChildren();
    auto oprationNode = sheetChildren.front();
    EXPECT_FALSE(oprationNode == nullptr);
    auto scrollNode = *(std::next(sheetChildren.begin(), 1));
    EXPECT_FALSE(scrollNode == nullptr);
    auto closeIconNode = topSheetNode->GetLastChild();
    EXPECT_FALSE(closeIconNode == nullptr);
    auto sheetDragBarNode = AceType::DynamicCast<FrameNode>(oprationNode->GetFirstChild());
    EXPECT_FALSE(sheetDragBarNode == nullptr);
    auto sheetDragBarPattern = sheetDragBarNode->GetPattern<SheetDragBarPattern>();
    EXPECT_FALSE(sheetDragBarPattern == nullptr);
    auto sheetDragBarPaintProperty = sheetDragBarNode->GetPaintProperty<SheetDragBarPaintProperty>();
    EXPECT_FALSE(sheetDragBarPaintProperty == nullptr);
    SheetStyle sheetStyle1;
    topSheetPattern->pageHeight_ = 10;

    // sheetStyle1.sheetMode is null.
    sheetStyle1.sheetMode = std::nullopt;
    overlayManager->sheetHeight_ = 0;
    sheetStyle1.height->unit_ = DimensionUnit::PERCENT;
    sheetStyle1.height->value_ = 2.0;
    overlayManager->ComputeSheetOffset(sheetStyle1, topSheetNode);
    EXPECT_TRUE(NearEqual(overlayManager->sheetHeight_, 2));

    overlayManager->sheetHeight_ = 0;
    sheetStyle1.height->unit_ = DimensionUnit::PERCENT;
    sheetStyle1.height->value_ = -2.0;
    overlayManager->ComputeSheetOffset(sheetStyle1, topSheetNode);
    EXPECT_TRUE(NearEqual(overlayManager->sheetHeight_, 2));

    overlayManager->sheetHeight_ = 0;
    sheetStyle1.height->unit_ = DimensionUnit::PERCENT;
    sheetStyle1.height->value_ = 0.1;
    overlayManager->ComputeSheetOffset(sheetStyle1, topSheetNode);
    EXPECT_TRUE(NearEqual(overlayManager->sheetHeight_, 1.0));

    overlayManager->sheetHeight_ = 0;
    sheetStyle1.height->unit_ = DimensionUnit::VP;
    sheetStyle1.height->value_ = 2;
    overlayManager->ComputeSheetOffset(sheetStyle1, topSheetNode);
    EXPECT_TRUE(NearEqual(overlayManager->sheetHeight_, 2));

    // sheetStyle1.sheetMode is not null.
    sheetStyle1.sheetMode = SheetMode(5);
    overlayManager->sheetHeight_ = 0;
    sheetStyle1.height->unit_ = DimensionUnit::PERCENT;
    sheetStyle1.height->value_ = 2.0;
    overlayManager->ComputeSheetOffset(sheetStyle1, topSheetNode);
    EXPECT_TRUE(NearEqual(overlayManager->sheetHeight_, 0));

    std::string title = "11";
    std::string subtitle = "22";
    sheetStyle1.sheetTitle = title;
    EXPECT_EQ(sheetStyle1.sheetTitle, title);
    sheetStyle1.sheetSubtitle = subtitle;
    EXPECT_EQ(sheetStyle1.sheetSubtitle, subtitle);
    std::stack<WeakPtr<FrameNode>> modalStack;
    overlayManager->modalStack_ = modalStack;
    EXPECT_FALSE(sheetDragBarPaintProperty == nullptr);
}

/**
 * @tc.name: RemoveAllModalInOverlay001
 * @tc.desc: Test OverlayManager::RemoveAllModalInOverlay.
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, RemoveAllModalInOverlay001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create target node.
     */
    auto targetNode = CreateTargetNode();
    auto stageNode = FrameNode::CreateFrameNode(
        V2::STAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StagePattern>());
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    stageNode->MountToParent(rootNode);
    targetNode->MountToParent(stageNode);
    rootNode->MarkDirtyNode();

    /**
     * @tc.steps: step2. create builder.
     */
    auto builderFunc = []() -> RefPtr<UINode> {
        auto frameNode =
            FrameNode::GetOrCreateFrameNode(V2::COLUMN_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
                []() { return AceType::MakeRefPtr<LinearLayoutPattern>(true); });
        auto childFrameNode = FrameNode::GetOrCreateFrameNode(V2::BUTTON_ETS_TAG,
            ElementRegister::GetInstance()->MakeUniqueId(), []() { return AceType::MakeRefPtr<ButtonPattern>(); });
        frameNode->AddChild(childFrameNode);
        return frameNode;
    };

    auto buildTitleNodeFunc = []() -> RefPtr<UINode> {
        auto frameNode =
            FrameNode::GetOrCreateFrameNode(V2::COLUMN_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
                []() { return AceType::MakeRefPtr<LinearLayoutPattern>(true); });
        auto childFrameNode = FrameNode::GetOrCreateFrameNode(V2::TEXT_ETS_TAG,
            ElementRegister::GetInstance()->MakeUniqueId(), []() { return AceType::MakeRefPtr<TextPattern>(); });
        frameNode->AddChild(childFrameNode);
        return frameNode;
    };

    /**
     * @tc.steps: step3. Run OnBindSheet to add something to modalStack and modalList.
     */
    SheetStyle sheetStyle;
    CreateSheetStyle(sheetStyle);
    bool isShow = true;
    auto overlayManager = AceType::MakeRefPtr<OverlayManager>(rootNode);
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc), std::move(buildTitleNodeFunc), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    auto sheetNode = overlayManager->modalStack_.top().Upgrade();
    EXPECT_EQ(sheetNode->GetTag(), V2::SHEET_PAGE_TAG);

    /**
     * @tc.steps: step4. run RemoveAllModalInOverlay func.
     */
    overlayManager->modalStack_.emplace(nullptr);
    overlayManager->modalList_.pop_back();
    EXPECT_TRUE(overlayManager->RemoveAllModalInOverlay());
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc), std::move(buildTitleNodeFunc), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    EXPECT_TRUE(overlayManager->RemoveAllModalInOverlay());

    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc), std::move(buildTitleNodeFunc), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    sheetNode = overlayManager->modalStack_.top().Upgrade();
    sheetNode->tag_ = V2::ROOT_ETS_TAG;
    EXPECT_TRUE(overlayManager->RemoveAllModalInOverlay());
}

/**
 * @tc.name: OnBindSheet002
 * @tc.desc: Test OverlayManager::OnBindSheet change sheetStyle dynamically.
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, OnBindSheet002, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create target node.
     */
    auto targetNode = CreateTargetNode();
    auto stageNode = FrameNode::CreateFrameNode(
        V2::STAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StagePattern>());
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    stageNode->MountToParent(rootNode);
    targetNode->MountToParent(stageNode);
    rootNode->MarkDirtyNode();

    /**
     * @tc.steps: step2. create builder.
     */
    auto builderFunc = []() -> RefPtr<UINode> {
        auto frameNode =
            FrameNode::GetOrCreateFrameNode(V2::COLUMN_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
                []() { return AceType::MakeRefPtr<LinearLayoutPattern>(true); });
        auto childFrameNode = FrameNode::GetOrCreateFrameNode(V2::BUTTON_ETS_TAG,
            ElementRegister::GetInstance()->MakeUniqueId(), []() { return AceType::MakeRefPtr<ButtonPattern>(); });
        frameNode->AddChild(childFrameNode);
        return frameNode;
    };

    auto buildTitleNodeFunc = []() -> RefPtr<UINode> {
        auto frameNode =
            FrameNode::GetOrCreateFrameNode(V2::COLUMN_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
                []() { return AceType::MakeRefPtr<LinearLayoutPattern>(true); });
        auto childFrameNode = FrameNode::GetOrCreateFrameNode(V2::TEXT_ETS_TAG,
            ElementRegister::GetInstance()->MakeUniqueId(), []() { return AceType::MakeRefPtr<TextPattern>(); });
        frameNode->AddChild(childFrameNode);
        return frameNode;
    };

    /**
     * @tc.steps: step3. create sheet node and get sheet node, get pattern.
     * @tc.expected: related function is called.
     */
    SheetStyle sheetStyle;
    CreateSheetStyle(sheetStyle);
    bool isShow = true;
    auto onWillAppear = []() {};
    auto onAppear = []() {};
    auto overlayManager = AceType::MakeRefPtr<OverlayManager>(rootNode);
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc), std::move(buildTitleNodeFunc), sheetStyle,
        onAppear, nullptr, nullptr, nullptr, onWillAppear, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr, targetNode);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    auto topSheetNode = overlayManager->modalStack_.top().Upgrade();
    EXPECT_FALSE(topSheetNode == nullptr);
    auto sheetNodeLayoutProperty = topSheetNode->GetLayoutProperty<SheetPresentationProperty>();
    auto style = sheetNodeLayoutProperty->GetSheetStyle();
    EXPECT_EQ(style->sheetMode.value(), SheetMode::MEDIUM);
    EXPECT_EQ(style->showDragBar.value(), true);

    /**
     * @tc.steps: step4. Change the sheetStyle.
     * @tc.expected: the sheetStyle is updated successfully
     */
    sheetStyle.sheetMode = SheetMode::AUTO;
    sheetStyle.showDragBar = false;
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc), std::move(buildTitleNodeFunc), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    auto sheetNode = overlayManager->modalStack_.top().Upgrade();
    EXPECT_FALSE(topSheetNode == nullptr);
    auto sheetPattern = sheetNode->GetPattern<SheetPresentationPattern>();
    sheetPattern->InitialLayoutProps();
    sheetStyle.sheetMode = SheetMode::MEDIUM;
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc), std::move(buildTitleNodeFunc), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    sheetNode = overlayManager->modalStack_.top().Upgrade();
    sheetPattern = sheetNode->GetPattern<SheetPresentationPattern>();
    sheetPattern->InitialLayoutProps();
    EXPECT_EQ(sheetPattern->GetTargetId(), topSheetNode->GetPattern<SheetPresentationPattern>()->GetTargetId());
    sheetNodeLayoutProperty = sheetNode->GetLayoutProperty<SheetPresentationProperty>();
    style = sheetNodeLayoutProperty->GetSheetStyle();
    EXPECT_EQ(style->sheetMode.value(), SheetMode::MEDIUM);
    EXPECT_EQ(style->showDragBar.value(), false);

    /**
     * @tc.steps: step4. Change the backgroundColor.
     * @tc.expected: the backgroundColor is updated successfully
     */
    sheetStyle.backgroundColor = Color::GREEN;
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc), std::move(buildTitleNodeFunc), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    sheetNode = overlayManager->modalStack_.top().Upgrade();
    EXPECT_FALSE(topSheetNode == nullptr);
    EXPECT_EQ(sheetNode->GetRenderContext()->GetBackgroundColorValue(), Color::GREEN);
    overlayManager->OnBindSheet(!isShow, nullptr, nullptr, nullptr, sheetStyle, nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
}

/**
 * @tc.name: DestroySheet003
 * @tc.desc: Test OverlayManager::DestroySheet func
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, DestroySheet003, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create target node.
     */
    auto targetNode = CreateTargetNode();
    auto targetId = targetNode->GetId();
    auto stageNode = FrameNode::CreateFrameNode(
        V2::STAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StagePattern>());
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    stageNode->MountToParent(rootNode);
    targetNode->MountToParent(stageNode);
    rootNode->MarkDirtyNode();

    /**
     * @tc.steps: step2. create builder.
     */
    auto builderFunc = []() -> RefPtr<UINode> {
        auto frameNode =
            FrameNode::GetOrCreateFrameNode(V2::COLUMN_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
                []() { return AceType::MakeRefPtr<LinearLayoutPattern>(true); });
        auto childFrameNode = FrameNode::GetOrCreateFrameNode(V2::BUTTON_ETS_TAG,
            ElementRegister::GetInstance()->MakeUniqueId(), []() { return AceType::MakeRefPtr<ButtonPattern>(); });
        frameNode->AddChild(childFrameNode);
        return frameNode;
    };

    auto buildTitleNodeFunc = []() -> RefPtr<UINode> {
        auto frameNode =
            FrameNode::GetOrCreateFrameNode(V2::COLUMN_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
                []() { return AceType::MakeRefPtr<LinearLayoutPattern>(true); });
        auto childFrameNode = FrameNode::GetOrCreateFrameNode(V2::TEXT_ETS_TAG,
            ElementRegister::GetInstance()->MakeUniqueId(), []() { return AceType::MakeRefPtr<TextPattern>(); });
        frameNode->AddChild(childFrameNode);
        return frameNode;
    };

    /**
     * @tc.steps: step3. create sheet node.
     * @tc.expected: Make sure the modalStack holds the sheetNode.
     */
    SheetStyle sheetStyle;
    CreateSheetStyle(sheetStyle);
    bool isShow = true;
    auto overlayManager = AceType::MakeRefPtr<OverlayManager>(rootNode);
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc), std::move(buildTitleNodeFunc), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    auto sheetNode = overlayManager->modalStack_.top().Upgrade();
    EXPECT_EQ(sheetNode->GetTag(), V2::SHEET_PAGE_TAG);

    /**
     * @tc.steps: step4. run destroySheet func
     */
    sheetNode->tag_ = V2::SHEET_MASK_TAG;
    EXPECT_NE(sheetNode->GetTag(), V2::SHEET_PAGE_TAG);
    overlayManager->DestroySheet(sheetNode, targetId);
    EXPECT_FALSE(overlayManager->modalStack_.empty());

    sheetNode->tag_ = V2::SHEET_PAGE_TAG;
    sheetNode->GetPattern<SheetPresentationPattern>()->targetId_ = targetId - 1;
    EXPECT_NE(sheetNode->GetPattern<SheetPresentationPattern>()->targetId_, targetId);
    overlayManager->DestroySheet(sheetNode, targetId);
    EXPECT_FALSE(overlayManager->modalStack_.empty());

    sheetNode->tag_ = V2::SHEET_PAGE_TAG;
    sheetNode->GetPattern<SheetPresentationPattern>()->targetId_ = targetId;
    overlayManager->DestroySheet(sheetNode, targetId);
    EXPECT_TRUE(overlayManager->modalStack_.empty());

    auto targetNodeSecond = CreateTargetNode();
    targetNodeSecond->MountToParent(stageNode);
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc), std::move(buildTitleNodeFunc), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        targetNodeSecond);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc), std::move(buildTitleNodeFunc), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    overlayManager->DestroySheet(sheetNode, targetId);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
}

/**
 * @tc.name: OnBindSheet003
 * @tc.desc: Test OverlayManager::OnBindSheet destroy sheet node.
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, OnBindSheet003, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create target node.
     */
    auto targetNode = CreateTargetNode();
    auto targetId = targetNode->GetId();
    auto stageNode = FrameNode::CreateFrameNode(
        V2::STAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StagePattern>());
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    stageNode->MountToParent(rootNode);
    targetNode->MountToParent(stageNode);
    rootNode->MarkDirtyNode();

    /**
     * @tc.steps: step2. create builder.
     */
    auto builderFunc = []() -> RefPtr<UINode> {
        auto frameNode =
            FrameNode::GetOrCreateFrameNode(V2::COLUMN_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
                []() { return AceType::MakeRefPtr<LinearLayoutPattern>(true); });
        auto childFrameNode = FrameNode::GetOrCreateFrameNode(V2::BUTTON_ETS_TAG,
            ElementRegister::GetInstance()->MakeUniqueId(), []() { return AceType::MakeRefPtr<ButtonPattern>(); });
        frameNode->AddChild(childFrameNode);
        return frameNode;
    };

    auto buildTitleNodeFunc = []() -> RefPtr<UINode> {
        auto frameNode =
            FrameNode::GetOrCreateFrameNode(V2::COLUMN_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
                []() { return AceType::MakeRefPtr<LinearLayoutPattern>(true); });
        auto childFrameNode = FrameNode::GetOrCreateFrameNode(V2::TEXT_ETS_TAG,
            ElementRegister::GetInstance()->MakeUniqueId(), []() { return AceType::MakeRefPtr<TextPattern>(); });
        frameNode->AddChild(childFrameNode);
        return frameNode;
    };

    /**
     * @tc.steps: step3. create sheet node.
     * @tc.expected: Make sure the modalStack holds the sheetNode.
     */
    SheetStyle sheetStyle;
    CreateSheetStyle(sheetStyle);
    bool isShow = true;
    auto overlayManager = AceType::MakeRefPtr<OverlayManager>(rootNode);
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc), std::move(buildTitleNodeFunc), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    auto sheetNode = overlayManager->modalStack_.top().Upgrade();
    EXPECT_EQ(sheetNode->GetTag(), V2::SHEET_PAGE_TAG);

    /**
     * @tc.steps: step4. destroy modal page.
     * @tc.expected: destroy modal successfully.
     */
    auto onWillDisappear = []() {};
    auto onDisappear = []() {};
    overlayManager->OnBindSheet(!isShow, nullptr, nullptr, nullptr, sheetStyle, nullptr, onDisappear, nullptr,
        nullptr, nullptr, onWillDisappear, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    overlayManager->modalList_.emplace_back(AceType::WeakClaim(AceType::RawPtr(stageNode)));
    overlayManager->DestroySheet(sheetNode, targetId);
    overlayManager->FindWindowScene(targetNode);
    overlayManager->DeleteModal(targetId);
    EXPECT_TRUE(overlayManager->modalStack_.empty());
}

/**
 * @tc.name: GetSheetMask001
 * @tc.desc: Test OverlayManager::GetSheetMask.
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, GetSheetMask001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create target node.
     */
    auto targetNode = CreateTargetNode();
    auto targetId = targetNode->GetId();
    auto stageNode = FrameNode::CreateFrameNode(
        V2::STAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StagePattern>());
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    stageNode->MountToParent(rootNode);
    targetNode->MountToParent(stageNode);
    rootNode->MarkDirtyNode();

    /**
     * @tc.steps: step2. create builder.
     */
    auto builderFunc = []() -> RefPtr<UINode> {
        auto frameNode =
            FrameNode::GetOrCreateFrameNode(V2::COLUMN_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
                []() { return AceType::MakeRefPtr<LinearLayoutPattern>(true); });
        auto childFrameNode = FrameNode::GetOrCreateFrameNode(V2::BUTTON_ETS_TAG,
            ElementRegister::GetInstance()->MakeUniqueId(), []() { return AceType::MakeRefPtr<ButtonPattern>(); });
        frameNode->AddChild(childFrameNode);
        return frameNode;
    };

    auto buildTitleNodeFunc = []() -> RefPtr<UINode> {
        auto frameNode =
            FrameNode::GetOrCreateFrameNode(V2::COLUMN_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
                []() { return AceType::MakeRefPtr<LinearLayoutPattern>(true); });
        auto childFrameNode = FrameNode::GetOrCreateFrameNode(V2::TEXT_ETS_TAG,
            ElementRegister::GetInstance()->MakeUniqueId(), []() { return AceType::MakeRefPtr<TextPattern>(); });
        frameNode->AddChild(childFrameNode);
        return frameNode;
    };

    /**
     * @tc.steps: step3. create sheet node.
     * @tc.expected: Make sure the modalStack holds the sheetNode.
     */
    SheetStyle sheetStyle;
    CreateSheetStyle(sheetStyle);
    bool isShow = true;
    auto overlayManager = AceType::MakeRefPtr<OverlayManager>(rootNode);
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc), std::move(buildTitleNodeFunc), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    auto sheetNode = overlayManager->modalStack_.top().Upgrade();
    EXPECT_EQ(sheetNode->GetTag(), V2::SHEET_PAGE_TAG);

    /**
     * @tc.steps: step4. Run GetSheetMask Func.
     * @tc.expected: if the color is set, Make sure the maskNode is exist and it's color is right.
     */
    auto maskNode = overlayManager->GetSheetMask(sheetNode);
    auto onWillDisappear = []() {};
    auto onDisappear = []() {};
    overlayManager->OnBindSheet(!isShow, nullptr, nullptr, nullptr, sheetStyle, nullptr, onDisappear, nullptr, nullptr,
    nullptr, onWillDisappear, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    sheetStyle.maskColor = Color::BLUE;
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc), std::move(buildTitleNodeFunc), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    sheetNode = overlayManager->modalStack_.top().Upgrade();
    EXPECT_FALSE(sheetNode == nullptr);
    EXPECT_EQ(sheetNode->GetTag(), V2::SHEET_PAGE_TAG);
    maskNode = overlayManager->GetSheetMask(sheetNode);
    EXPECT_FALSE(maskNode == nullptr);
    EXPECT_EQ(maskNode->GetTag(), V2::SHEET_MASK_TAG);
    EXPECT_EQ(maskNode->GetRenderContext()->GetBackgroundColorValue(), Color::BLUE);

    /**
     * @tc.steps: step5. destroy sheetNode.
     * @tc.expected: Make sure the maskNode is destroyed.
     */
    overlayManager->OnBindSheet(!isShow, nullptr, nullptr, nullptr, sheetStyle, nullptr, onDisappear, nullptr, nullptr,
        nullptr, onWillDisappear, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    overlayManager->modalList_.emplace_back(AceType::WeakClaim(AceType::RawPtr(stageNode)));
    overlayManager->DestroySheet(sheetNode, targetId);
    overlayManager->FindWindowScene(targetNode);
    overlayManager->DeleteModal(targetId);
    EXPECT_TRUE(overlayManager->modalStack_.empty());
}

/**
 * @tc.name: SheetPresentationPattern1
 * @tc.desc: Test SheetPresentationPattern create sheet page.
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, SheetPresentationPattern1, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create target node.
     */
    auto targetNode = CreateTargetNode();
    auto stageNode = FrameNode::CreateFrameNode(
        V2::STAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StagePattern>());
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    stageNode->MountToParent(rootNode);
    targetNode->MountToParent(stageNode);
    rootNode->MarkDirtyNode();
    /**
     * @tc.steps: step2. create builder.
     */
    auto builderFunc = []() -> RefPtr<UINode> {
        auto frameNode =
            FrameNode::GetOrCreateFrameNode(V2::COLUMN_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
                []() { return AceType::MakeRefPtr<LinearLayoutPattern>(true); });
        auto childFrameNode = FrameNode::GetOrCreateFrameNode(V2::BUTTON_ETS_TAG,
            ElementRegister::GetInstance()->MakeUniqueId(), []() { return AceType::MakeRefPtr<ButtonPattern>(); });
        frameNode->AddChild(childFrameNode);
        return frameNode;
    };

    auto buildTitleNodeFunc = []() -> RefPtr<UINode> {
        auto frameNode =
            FrameNode::GetOrCreateFrameNode(V2::COLUMN_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
                []() { return AceType::MakeRefPtr<LinearLayoutPattern>(true); });
        auto childFrameNode = FrameNode::GetOrCreateFrameNode(V2::TEXT_ETS_TAG,
            ElementRegister::GetInstance()->MakeUniqueId(), []() { return AceType::MakeRefPtr<TextPattern>(); });
        frameNode->AddChild(childFrameNode);
        return frameNode;
    };

    SheetStyle sheetStyle;
    CreateSheetStyle(sheetStyle);
    bool isShow = true;
    auto onWillAppear = []() {};
    auto onAppear = []() {};
    auto overlayManager = AceType::MakeRefPtr<OverlayManager>(rootNode);
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc), std::move(buildTitleNodeFunc), sheetStyle,
        onAppear, nullptr, nullptr, nullptr, onWillAppear, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr, targetNode);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    auto topSheetNode = overlayManager->modalStack_.top().Upgrade();
    EXPECT_FALSE(topSheetNode == nullptr);
    auto sheetNodeLayoutProperty = topSheetNode->GetLayoutProperty<SheetPresentationProperty>();
    auto style = sheetNodeLayoutProperty->GetSheetStyle();
    EXPECT_EQ(style->sheetMode.value(), SheetMode::MEDIUM);
    EXPECT_EQ(style->showDragBar.value(), true);

    sheetStyle.sheetMode = SheetMode::LARGE;
    sheetStyle.showDragBar = false;
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc), std::move(buildTitleNodeFunc), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    auto sheetNode = overlayManager->modalStack_.top().Upgrade();
    EXPECT_FALSE(topSheetNode == nullptr);
    auto geometryNode = sheetNode->GetGeometryNode();
    ASSERT_NE(geometryNode, nullptr);
    auto sheetPattern = sheetNode->GetPattern<SheetPresentationPattern>();
    EXPECT_EQ(sheetPattern->GetTargetId(), topSheetNode->GetPattern<SheetPresentationPattern>()->GetTargetId());
    sheetPattern->InitPanEvent();
    GestureEvent info;
    sheetPattern->HandleDragUpdate(info);
    sheetPattern->HandleDragEnd({});
    sheetNodeLayoutProperty = sheetNode->GetLayoutProperty<SheetPresentationProperty>();
    style = sheetNodeLayoutProperty->GetSheetStyle();
    auto sheetLayoutAlgorithm = sheetPattern->CreateLayoutAlgorithm();
    ASSERT_NE(sheetLayoutAlgorithm, nullptr);
    RefPtr<LayoutWrapperNode> layoutWrapper = AceType::MakeRefPtr<LayoutWrapperNode>(
        AceType::WeakClaim(AceType::RawPtr(sheetNode)), geometryNode->Clone(), sheetNodeLayoutProperty->Clone());
    EXPECT_FALSE(layoutWrapper == nullptr);
    layoutWrapper->SetLayoutAlgorithm(AccessibilityManager::MakeRefPtr<LayoutAlgorithmWrapper>(sheetLayoutAlgorithm));
    DirtySwapConfig dirtySwapConfig;
    EXPECT_TRUE(sheetPattern->OnDirtyLayoutWrapperSwap(layoutWrapper, dirtySwapConfig));
    sheetPattern->InitPanEvent();
    EXPECT_EQ(style->sheetMode.value(), SheetMode::LARGE);
    EXPECT_EQ(style->showDragBar.value(), false);
}

/**
 * @tc.name: OnBindSheet004
 * @tc.desc: Test OverlayManager::OnBindSheet create center sheet page.
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, OnBindSheet004, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create target node.
     */
    auto targetNode = CreateTargetNode();
    auto stageNode = FrameNode::CreateFrameNode(
        V2::STAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StagePattern>());
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    stageNode->MountToParent(rootNode);
    targetNode->MountToParent(stageNode);
    rootNode->MarkDirtyNode();

    /**
     * @tc.steps: step2. create sheetNode, get sheetPattern.
     */
    SheetStyle sheetStyle;
    bool isShow = true;
    CreateSheetBuilder();
    auto overlayManager = AceType::MakeRefPtr<OverlayManager>(rootNode);
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc_), std::move(titleBuilderFunc_), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,  nullptr, nullptr, targetNode);
    // assert
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    auto topSheetNode = overlayManager->modalStack_.top().Upgrade();
    ASSERT_NE(topSheetNode, nullptr);
    auto topSheetPattern = topSheetNode->GetPattern<SheetPresentationPattern>();
    ASSERT_NE(topSheetPattern, nullptr);

    /**
     * @tc.steps: step3. test sheetThemeType_ = popup, sheetStyle.sheetType = center.
     * @tc.expected: height = (setHeight + screenHeight) / 2.
     */
    topSheetPattern->sheetThemeType_ = "popup";
    auto layoutProperty = topSheetPattern->GetLayoutProperty<SheetPresentationProperty>();
    ASSERT_NE(layoutProperty, nullptr);
    layoutProperty->UpdateSheetStyle(sheetStyle);
    sheetStyle.sheetType = SheetType::SHEET_CENTER;
    topSheetPattern->pageHeight_ = 1000;
    auto setSheetSize = SizeF({ 500, 500 });
    topSheetNode->GetGeometryNode()->SetFrameSize(setSheetSize);
    overlayManager->sheetHeight_ = 0;
    overlayManager->ComputeSheetOffset(sheetStyle, topSheetNode);
    EXPECT_TRUE(NearEqual(overlayManager->sheetHeight_, 0));

    sheetStyle.sheetType = SheetType::SHEET_POPUP;
    layoutProperty->UpdateSheetStyle(sheetStyle);
    overlayManager->ComputeSheetOffset(sheetStyle, topSheetNode);
    EXPECT_TRUE(NearEqual(overlayManager->sheetHeight_, 0));
    sheetStyle.sheetType = SheetType::SHEET_BOTTOMLANDSPACE;
    layoutProperty->UpdateSheetStyle(sheetStyle);
    overlayManager->ComputeSheetOffset(sheetStyle, topSheetNode);
    EXPECT_TRUE(NearEqual(overlayManager->sheetHeight_, 0));
}

/**
 * @tc.name: OnBindSheet005
 * @tc.desc: Test OverlayManager::OnBindSheet create detent sheet page.
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, OnBindSheet005, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create target node.
     */
    auto targetNode = CreateTargetNode();
    auto stageNode = FrameNode::CreateFrameNode(
        V2::STAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StagePattern>());
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    stageNode->MountToParent(rootNode);
    targetNode->MountToParent(stageNode);
    rootNode->MarkDirtyNode();

    /**
     * @tc.steps: step2. create sheetNode, get sheetPattern.
     */
    SheetStyle sheetStyle;
    bool isShow = true;
    CreateSheetBuilder();
    auto overlayManager = AceType::MakeRefPtr<OverlayManager>(rootNode);
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc_), std::move(titleBuilderFunc_), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,  nullptr, nullptr, targetNode);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    auto topSheetNode = overlayManager->modalStack_.top().Upgrade();
    ASSERT_NE(topSheetNode, nullptr);
    auto topSheetPattern = topSheetNode->GetPattern<SheetPresentationPattern>();
    ASSERT_NE(topSheetPattern, nullptr);

    /**
     * @tc.steps: step3. test sheetThemeType_ = auto, sheetStyle.sheetType = bottom, set pageHeight = 1000.
     */
    topSheetPattern->sheetThemeType_ = "auto";
    sheetStyle.sheetType = SheetType::SHEET_BOTTOM;
    topSheetPattern->pageHeight_ = 1000;

    /**
     * @tc.steps: step4. test sheetStyle.detents.sheetMode has value, sheetMode = MEDIUM.
     * @tc.expected: height = pageHeight_*0.6 = 1000*0.6 = 600.
     */
    SheetHeight detent;
    detent.sheetMode = SheetMode::MEDIUM;
    sheetStyle.detents.emplace_back(detent);
    overlayManager->sheetHeight_ = 0;
    overlayManager->ComputeSheetOffset(sheetStyle, topSheetNode);
    EXPECT_FALSE(NearEqual(overlayManager->sheetHeight_, 500));
    sheetStyle.detents.clear();

    /**
     * @tc.steps: step5. test sheetStyle.detents.sheetMode has value, sheetMode = MEDIUM.
     * @tc.expected: height = pageHeight_-8 = 1000-8 = 992.
     */
    detent.sheetMode = SheetMode::LARGE;
    sheetStyle.detents.emplace_back(detent);
    overlayManager->sheetHeight_ = 0;
    overlayManager->ComputeSheetOffset(sheetStyle, topSheetNode);
    EXPECT_TRUE(NearEqual(overlayManager->sheetHeight_, 992));

    /**
     * @tc.steps: step6. test sheetStyle.detents.height has value, height unit is %.
     * @tc.expected: height = pageHeight*0.5 = 1000*0.5 = 500.
     */
    sheetStyle.detents.clear();
    detent.sheetMode = std::nullopt;
    Dimension detentHeight { 0.5, DimensionUnit::PERCENT };
    detent.height = detentHeight;
    sheetStyle.detents.emplace_back(detent);
    overlayManager->sheetHeight_ = 0;
    overlayManager->ComputeSheetOffset(sheetStyle, topSheetNode);
    EXPECT_TRUE(NearEqual(overlayManager->sheetHeight_, 500));

    /**
     * @tc.steps: step7. test sheetStyle.detents.height has value, height unit is vp.
     * @tc.expected: height = setHeight = 600.
     */
    sheetStyle.detents.clear();
    detent.height->unit_ = DimensionUnit::VP;
    detent.height->value_ = 600;
    sheetStyle.detents.emplace_back(detent);
    overlayManager->sheetHeight_ = 0;
    overlayManager->ComputeSheetOffset(sheetStyle, topSheetNode);
    EXPECT_TRUE(NearEqual(overlayManager->sheetHeight_, 600));

    /**
     * @tc.steps: step8. test sheetStyle.detents.height has value, height unit is vp, setHeight > maxHeight.
     * @tc.expected: height = setHeight = maxHeight = pageHeight-8 = 992.
     */
    sheetStyle.detents.clear();
    detent.height->unit_ = DimensionUnit::VP;
    detent.height->value_ = 1500;
    sheetStyle.detents.emplace_back(detent);
    overlayManager->sheetHeight_ = 0;
    overlayManager->ComputeSheetOffset(sheetStyle, topSheetNode);
    EXPECT_TRUE(NearEqual(overlayManager->sheetHeight_, 992));

    /**
     * @tc.steps: step9. test sheetStyle.detents.height has value, height unit is vp, setHeight < 0.
     * @tc.expected: height = setHeight = maxHeight = pageHeight-8 = 992.
     */
    sheetStyle.detents.clear();
    detent.height->unit_ = DimensionUnit::VP;
    detent.height->value_ = -100;
    sheetStyle.detents.emplace_back(detent);
    overlayManager->sheetHeight_ = 0;
    overlayManager->ComputeSheetOffset(sheetStyle, topSheetNode);
    EXPECT_TRUE(NearEqual(overlayManager->sheetHeight_, 992));
}

/**
 * @tc.name: OnBindSheet006
 * @tc.desc: Test OverlayManager::PlayBubbleStyleSheetTransition.
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, OnBindSheet006, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create target node.
     */
    auto targetNode = CreateTargetNode();
    auto stageNode = FrameNode::CreateFrameNode(
        V2::STAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StagePattern>());
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    stageNode->MountToParent(rootNode);
    targetNode->MountToParent(stageNode);
    rootNode->MarkDirtyNode();

    /**
     * @tc.steps: step2. create sheetNode, get sheetPattern.
     */
    SheetStyle sheetStyle;
    bool isShow = true;
    CreateSheetBuilder();
    auto overlayManager = AceType::MakeRefPtr<OverlayManager>(rootNode);
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc_), std::move(titleBuilderFunc_), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,  nullptr, nullptr, targetNode);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    auto topSheetNode = overlayManager->modalStack_.top().Upgrade();
    ASSERT_NE(topSheetNode, nullptr);
    auto topSheetPattern = topSheetNode->GetPattern<SheetPresentationPattern>();
    ASSERT_NE(topSheetPattern, nullptr);

    /**
     * @tc.steps: step3. test PlayBubbleStyleSheetTransition().
     */
    overlayManager->PlayBubbleStyleSheetTransition(topSheetNode, true);
    EXPECT_EQ(topSheetPattern->height_, overlayManager->sheetHeight_);
}

/**
 * @tc.name: HandleDragUpdate001
 * @tc.desc: Test SheetPresentationPattern::HandleDragUpdate().
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, HandleDragUpdate001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create target node.
     */
    auto targetNode = CreateTargetNode();
    auto stageNode = FrameNode::CreateFrameNode(
        V2::STAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StagePattern>());
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    stageNode->MountToParent(rootNode);
    targetNode->MountToParent(stageNode);
    rootNode->MarkDirtyNode();

    /**
     * @tc.steps: step2. create sheetNode, get sheetPattern.
     */
    SheetStyle sheetStyle;
    bool isShow = true;
    CreateSheetBuilder();
    auto overlayManager = AceType::MakeRefPtr<OverlayManager>(rootNode);
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc_), std::move(titleBuilderFunc_), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    auto topSheetNode = overlayManager->modalStack_.top().Upgrade();
    ASSERT_NE(topSheetNode, nullptr);
    auto topSheetPattern = topSheetNode->GetPattern<SheetPresentationPattern>();
    ASSERT_NE(topSheetPattern, nullptr);
    topSheetPattern->OnDirtyLayoutWrapperSwap(topSheetNode->CreateLayoutWrapper(), DirtySwapConfig());

    /**
     * @tc.steps: step3. Init height , sheetDetentHeight and currentOffset, set minDelta < 0.
     * @tc.expected: currentOffset is -5.
     */
    topSheetPattern->sheetDetentHeight_.emplace_back(20);
    topSheetPattern->sheetDetentHeight_.emplace_back(30);
    topSheetPattern->height_ = 20;
    topSheetPattern->pageHeight_ = 50;
    topSheetPattern->sheetMaxHeight_ = 30;
    topSheetPattern->OnCoordScrollStart();
    GestureEvent info;
    info.SetMainDelta(MINUS_HEIGHT);
    topSheetPattern->HandleDragUpdate(info);
    EXPECT_TRUE(NearEqual(topSheetPattern->currentOffset_, -5));

    /**
     * @tc.steps: step4. Init height , sheetDetentHeight and set currentOffset < 0,
     * @tc.expected: currentOffset = height_ - sheetMaxHeight_.
     */
    topSheetPattern->currentOffset_ = -5;
    topSheetPattern->HandleDragUpdate(info);
    EXPECT_TRUE(NearEqual(topSheetPattern->currentOffset_, -10));

    /**
     * @tc.steps: step5. Do OnCoordScrollUpdate when scrollOffset < 0 and showstate = true.
     * @tc.expected: return false
     */
    topSheetPattern->OnCoordScrollEnd(*topSheetPattern->sheetDetentHeight_.end());
    auto ret = topSheetPattern->OnCoordScrollUpdate(*topSheetPattern->sheetDetentHeight_.end());
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TestOnBindSheet
 * @tc.desc: Test SheetPresentationPattern::OnDirtyLayoutWrapperSwap() and root Rotates.
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, TestSheetAvoidSafeArea2, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create sheet node and parent node ,then sheet node mount to parent node and initialize
     * sheet pattern.
     */
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    auto sheetNode = FrameNode::CreateFrameNode(
        V2::SHEET_PAGE_TAG, 1, AceType::MakeRefPtr<SheetPresentationPattern>(-1, V2::BUTTON_ETS_TAG, nullptr));
    ASSERT_NE(sheetNode, nullptr);
    sheetNode->MountToParent(rootNode);
    auto dragBarNode = FrameNode::CreateFrameNode(
        "SheetDragBar", ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<SheetDragBarPattern>());
    ASSERT_NE(dragBarNode, nullptr);
    auto scroll = FrameNode::CreateFrameNode(
        V2::SCROLL_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<ScrollPattern>());
    ASSERT_NE(scroll, nullptr);
    dragBarNode->MountToParent(sheetNode);
    auto contentNode = FrameNode::CreateFrameNode(
        "SheetDragBar", ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<SheetDragBarPattern>());
    ASSERT_NE(contentNode, nullptr);
    contentNode->MountToParent(scroll);
    scroll->MountToParent(sheetNode);
    auto sheetPattern = sheetNode->GetPattern<SheetPresentationPattern>();
    auto renderContext = sheetNode->GetRenderContext();
    auto safeAreaManager = AceType::MakeRefPtr<SafeAreaManager>();
    auto geometryNode = sheetNode->GetGeometryNode();
    ASSERT_NE(geometryNode, nullptr);
    SheetStyle sheetStyle;
    CreateSheetStyle(sheetStyle);
    auto sheetLayoutProperty = sheetNode->GetLayoutProperty<SheetPresentationProperty>();
    ASSERT_NE(sheetLayoutProperty, nullptr);
    sheetLayoutProperty->UpdateSheetStyle(sheetStyle);
    geometryNode->SetFrameSize(SizeF(800, 2000));
    MockPipelineContext::GetCurrent()->safeAreaManager_ = safeAreaManager;
    MockPipelineContext::GetCurrent()->SetRootSize(800, 2000);
    sheetPattern->pageHeight_ = 2000;
    sheetPattern->sheetHeight_ = 2000;
    sheetPattern->height_ = 500;
    auto sheetLayoutAlgorithm = sheetPattern->CreateLayoutAlgorithm();
    AceType::DynamicCast<SheetPresentationLayoutAlgorithm>(sheetLayoutAlgorithm)->sheetMaxHeight_ = 500;
    ASSERT_NE(sheetLayoutAlgorithm, nullptr);
    auto layoutWrapper =
        AceType::MakeRefPtr<LayoutWrapperNode>(sheetNode, sheetNode->GetGeometryNode(), sheetNode->GetLayoutProperty());
    layoutWrapper->SetLayoutAlgorithm(AccessibilityManager::MakeRefPtr<LayoutAlgorithmWrapper>(sheetLayoutAlgorithm));
    /**
     * @tc.cases: case1. window rotates after layout.
     */
    sheetPattern->OnWindowSizeChanged(2000, 800, WindowSizeChangeReason::ROTATION);
    sheetPattern->OnDirtyLayoutWrapperSwap(layoutWrapper, DirtySwapConfig());
    EXPECT_EQ(static_cast<int>(renderContext->GetTransformTranslate()->y.ConvertToPx()),
        sheetPattern->pageHeight_ - sheetPattern->height_);
    /**
     * @tc.cases: case2. window rotates to vertical screen.
     */
    sheetPattern->OnWindowSizeChanged(800, 2000, WindowSizeChangeReason::RESIZE);
    sheetPattern->OnDirtyLayoutWrapperSwap(layoutWrapper, DirtySwapConfig());
    EXPECT_FALSE(sheetPattern->windowRotate_);
}

/**
 * @tc.type: FUNC
 * @tc.name: Test BindSheet
 * @tc.desc: Test SheetPresentationPattern::AvoidSafeArea() when sheetType is Center.
 */
HWTEST_F(OverlayManagerTestNg, TestSheetAvoidSafeArea3, TestSize.Level1)
{
    MockPipelineContext::GetCurrent()->SetMinPlatformVersion(static_cast<int32_t>(PlatformVersion::VERSION_ELEVEN));
    /**
     * @tc.steps: step1. create sheet node and initialize sheet pattern.
     */
    auto sheetNode = FrameNode::CreateFrameNode(
        V2::SHEET_PAGE_TAG, 1, AceType::MakeRefPtr<SheetPresentationPattern>(-1, V2::BUTTON_ETS_TAG, nullptr));
    auto dragBarNode = FrameNode::CreateFrameNode(
        "SheetDragBar", ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<SheetDragBarPattern>());
    auto scroll = FrameNode::CreateFrameNode(
        V2::SCROLL_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<ScrollPattern>());
    auto builderContent =
        FrameNode::CreateFrameNode(V2::COLUMN_ETS_TAG, 0, AceType::MakeRefPtr<LinearLayoutPattern>(false));
    builderContent->MountToParent(scroll);
    dragBarNode->MountToParent(sheetNode);
    scroll->MountToParent(sheetNode);
    sheetNode->GetFocusHub()->currentFocus_ = true;
    auto sheetPattern = sheetNode->GetPattern<SheetPresentationPattern>();
    sheetPattern->sheetType_ = SheetType::SHEET_CENTER;
    auto renderContext = sheetNode->GetRenderContext();
    auto safeAreaManager = AceType::MakeRefPtr<SafeAreaManager>();
    auto geometryNode = sheetNode->GetGeometryNode();
    ASSERT_NE(geometryNode, nullptr);
    geometryNode->SetFrameSize(SizeF(800, 1800));
    MockPipelineContext::GetCurrent()->safeAreaManager_ = safeAreaManager;
    MockPipelineContext::GetCurrent()->SetRootSize(800, 2000);
    auto textFieldManager = AceType::MakeRefPtr<TextFieldManagerNG>();
    textFieldManager->SetHeight(20);
    MockPipelineContext::GetCurrent()->SetTextFieldManager(textFieldManager);
    SafeAreaInsets::Inset upKeyboard { 0, 200 };
    sheetPattern->pageHeight_ = 2000;
    sheetPattern->sheetHeight_ = 1800;
    /**
     * @tc.steps: step2. keyboard up, and sheet will goes to correct position.
     * @tc.cases: case1. keyboard up, but sheet needs not up beacure hsafe is enough.
     */
    safeAreaManager->keyboardInset_ = upKeyboard;
    textFieldManager->SetClickPosition(Offset(500, 1000));
    sheetPattern->height_ = 1800;
    sheetPattern->AvoidSafeArea();
    EXPECT_EQ(sheetPattern->keyboardHeight_, 200);
    /**
     * @tc.cases: case2. keyboard up, sheet needs not to go up.
     */
    sheetPattern->keyboardHeight_ = 0;
    textFieldManager->SetClickPosition(Offset(500, 300));
    sheetPattern->AvoidSafeArea();
    EXPECT_EQ(static_cast<int>(renderContext->GetTransformTranslate()->y.ConvertToPx()), 2000 - sheetPattern->height_);
    /**
     * @tc.cases: case3. sheet offset = 1800, sheet goes up with h and not goes up to LARGE.
     */
    sheetPattern->keyboardHeight_ = 0;
    textFieldManager->SetClickPosition(Offset(500, 1900));
    sheetPattern->AvoidSafeArea();
    EXPECT_EQ(static_cast<int>(renderContext->GetTransformTranslate()->y.ConvertToPx()), 56);
    EXPECT_FALSE(sheetPattern->isScrolling_);
    /**
     * @tc.cases: case4. sheet offset = 1800, sheet goes up to LARGE and scrolling.
     */
    sheetPattern->keyboardHeight_ = 0;
    sheetPattern->height_ = 1950;
    textFieldManager->SetClickPosition(Offset(500, 1900));
    sheetPattern->AvoidSafeArea();
    EXPECT_EQ(static_cast<int>(renderContext->GetTransformTranslate()->y.ConvertToPx()), 8);
    EXPECT_EQ(sheetPattern->scrollHeight_, 102.0f);
    EXPECT_TRUE(sheetPattern->isScrolling_);
    /**
     * @tc.cases: case5. softkeyboard is down.
     */
    SafeAreaInsets::Inset downKeyboard { 0, 0 };
    safeAreaManager->keyboardInset_ = downKeyboard;
    sheetPattern->AvoidSafeArea();
    EXPECT_EQ(static_cast<int>(renderContext->GetTransformTranslate()->y.ConvertToPx()), 50);
    EXPECT_EQ(sheetPattern->keyboardHeight_, 0);
    EXPECT_FALSE(sheetPattern->isScrolling_);
}

/**
 * @tc.name: TestOnBindSheet
 * @tc.desc: Test Sheet avoids aiBar.
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, TestSheetAvoidaiBar, TestSize.Level1)
{
    MockPipelineContext::GetCurrent()->SetMinPlatformVersion(static_cast<int32_t>(PlatformVersion::VERSION_ELEVEN));
    auto operationColumn = FrameNode::CreateFrameNode(V2::COLUMN_ETS_TAG,
        ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<LinearLayoutPattern>(true));
    auto callback = [](const std::string&) {};
    NG::SheetStyle style;
    auto sheetNode = SheetView::CreateSheetPage(0, "", operationColumn, operationColumn, std::move(callback), style);
    ASSERT_NE(sheetNode, nullptr);
    auto sheetPattern = sheetNode->GetPattern<SheetPresentationPattern>();
    ASSERT_NE(sheetPattern, nullptr);
    auto scrollNode = AceType::DynamicCast<FrameNode>(sheetNode->GetChildAtIndex(1));
    ASSERT_NE(scrollNode, nullptr);
    auto scrollPattern = scrollNode->GetPattern<ScrollPattern>();
    ASSERT_NE(scrollPattern, nullptr);
    auto scrollLayoutProperty = scrollNode->GetLayoutProperty<ScrollLayoutProperty>();
    ASSERT_NE(scrollLayoutProperty, nullptr);
    sheetPattern->AvoidAiBar();
    EXPECT_EQ(scrollLayoutProperty->GetScrollContentEndOffsetValue(.0f), .0f);
    scrollPattern->scrollableDistance_ = 10.0f;
    sheetPattern->AvoidAiBar();
    EXPECT_EQ(scrollLayoutProperty->GetScrollContentEndOffsetValue(.0f),
        PipelineContext::GetCurrentContext()->GetSafeArea().bottom_.Length());
}

/**
 * @tc.name: SheetPresentationPattern2
 * @tc.desc: Test SheetPresentationPattern::CheckSheetHeightChange().
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, SheetPresentationPattern2, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create target node.
     */
    auto targetNode = CreateTargetNode();
    auto stageNode = FrameNode::CreateFrameNode(
        V2::STAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StagePattern>());
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    stageNode->MountToParent(rootNode);
    targetNode->MountToParent(stageNode);
    rootNode->MarkDirtyNode();

    /**
     * @tc.steps: step2. create sheetNode, get sheetPattern.
     */
    SheetStyle sheetStyle;
    bool isShow = true;
    CreateSheetBuilder();
    auto overlayManager = AceType::MakeRefPtr<OverlayManager>(rootNode);
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc_), std::move(titleBuilderFunc_), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    auto topSheetNode = overlayManager->modalStack_.top().Upgrade();
    ASSERT_NE(topSheetNode, nullptr);
    auto topSheetPattern = topSheetNode->GetPattern<SheetPresentationPattern>();
    ASSERT_NE(topSheetPattern, nullptr);

    /**
     * @tc.steps: step3. test CheckSheetHeightChange().
     */
    topSheetPattern->pageHeight_ = 1000;
    topSheetPattern->sheetMaxHeight_ = 1000;
    topSheetPattern->isFirstInit_ = true;
    topSheetPattern->InitialLayoutProps();
    EXPECT_FALSE(topSheetPattern->isFirstInit_);
    topSheetPattern->sheetType_ = SheetType::SHEET_POPUP;
    topSheetPattern->CheckSheetHeightChange();
    EXPECT_EQ(topSheetPattern->sheetType_, SheetType::SHEET_BOTTOM);
}

/**
 * @tc.name: SheetPresentationPattern3
 * @tc.desc: Test SheetPresentationPattern::InitSheetDetents().
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, SheetPresentationPattern3, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create target node.
     */
    auto targetNode = CreateTargetNode();
    auto stageNode = FrameNode::CreateFrameNode(
        V2::STAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StagePattern>());
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    stageNode->MountToParent(rootNode);
    targetNode->MountToParent(stageNode);
    rootNode->MarkDirtyNode();

    /**
     * @tc.steps: step2. create sheetNode, get sheetPattern.
     */
    SheetStyle sheetStyle;
    bool isShow = true;
    CreateSheetBuilder();
    auto overlayManager = AceType::MakeRefPtr<OverlayManager>(rootNode);
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc_), std::move(titleBuilderFunc_), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    auto topSheetNode = overlayManager->modalStack_.top().Upgrade();
    ASSERT_NE(topSheetNode, nullptr);
    auto topSheetPattern = topSheetNode->GetPattern<SheetPresentationPattern>();
    ASSERT_NE(topSheetPattern, nullptr);

    /**
     * @tc.steps: step3. test InitSheetDetents(), sheetType = BOTTOM.
     */
    topSheetPattern->pageHeight_ = 1000;
    topSheetPattern->sheetMaxHeight_ = 1000;
    topSheetPattern->sheetThemeType_ = "auto";
    auto sheetLayoutProperty = topSheetNode->GetLayoutProperty<SheetPresentationProperty>();
    EXPECT_FALSE(sheetLayoutProperty == nullptr);

    /**
     * @tc.steps: step4. test sheetMode has value.
     * @tc.expected: sheetStyle.detents = {600,992}.
     */
    SheetHeight detent;
    detent.sheetMode = SheetMode::MEDIUM;
    sheetStyle.detents.emplace_back(detent);
    detent.sheetMode = SheetMode::LARGE;
    sheetStyle.detents.emplace_back(detent);
    sheetLayoutProperty->UpdateSheetStyle(sheetStyle);
    topSheetPattern->InitSheetDetents();
    EXPECT_FALSE(NearEqual(topSheetPattern->sheetDetentHeight_.front(), 500));
    EXPECT_TRUE(NearEqual(topSheetPattern->sheetDetentHeight_.back(), 992));

    /**
     * @tc.steps: step5. test sheetStyle.height has value.
     */
    sheetStyle.detents.clear();
    SheetHeight detent1;
    Dimension detentHeight { 0.5, DimensionUnit::PERCENT };
    detent1.height = detentHeight;
    sheetStyle.detents.emplace_back(detent1);

    /**
     * @tc.steps: step6. set height > maxHeight.
     * @tc.expected: height = pageHeight_-8 = 992.
     */
    detent1.height->unit_ = DimensionUnit::VP;
    detent1.height->value_ = 1200;
    sheetStyle.detents.emplace_back(detent1);

    /**
     * @tc.steps: step6. set height < 0.
     * @tc.expected: height = pageHeight_-8 = 992.
     */
    detent1.height->unit_ = DimensionUnit::VP;
    detent1.height->value_ = -10;
    sheetStyle.detents.emplace_back(detent1);

    /**
     * @tc.steps: step7. InitSheetDetents(), sheetStyle.detents push{500,992,992}.
     * @tc.expected: sheetStyle.detents = {500,992}.
     */
    sheetLayoutProperty->UpdateSheetStyle(sheetStyle);
    topSheetPattern->InitSheetDetents();
    EXPECT_TRUE(NearEqual(topSheetPattern->sheetDetentHeight_.size(), 2));
    EXPECT_TRUE(NearEqual(topSheetPattern->sheetDetentHeight_.front(), 500));
    EXPECT_TRUE(NearEqual(topSheetPattern->sheetDetentHeight_.back(), 992));

    /**
     * @tc.steps: step8. test InitSheetDetents(), sheetType = CENTER.
     * @tc.expected: height = (centerHeight_+pageHeight_)/2 = 750.
     */
    sheetStyle.detents.clear();
    sheetLayoutProperty->UpdateSheetStyle(sheetStyle);
    topSheetPattern->sheetThemeType_ = "popup";
    topSheetPattern->centerHeight_ = 500;
    topSheetPattern->InitSheetDetents();
    EXPECT_TRUE(NearEqual(topSheetPattern->sheetDetentHeight_.front(), 0));
}

/**
 * @tc.name: SheetPresentationPattern4
 * @tc.desc: Test SheetPresentationPattern::InitialSingleGearHeight().
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, SheetPresentationPattern4, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create target node.
     */
    auto targetNode = CreateTargetNode();
    auto stageNode = FrameNode::CreateFrameNode(
        V2::STAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StagePattern>());
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    stageNode->MountToParent(rootNode);
    targetNode->MountToParent(stageNode);
    rootNode->MarkDirtyNode();

    /**
     * @tc.steps: step2. create sheetNode, get sheetPattern.
     */
    SheetStyle sheetStyle;
    bool isShow = true;
    CreateSheetBuilder();
    auto overlayManager = AceType::MakeRefPtr<OverlayManager>(rootNode);
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc_), std::move(titleBuilderFunc_), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    auto topSheetNode = overlayManager->modalStack_.top().Upgrade();
    ASSERT_NE(topSheetNode, nullptr);
    auto topSheetPattern = topSheetNode->GetPattern<SheetPresentationPattern>();
    ASSERT_NE(topSheetPattern, nullptr);

    /**
     * @tc.steps: step3. test InitialSingleGearHeight().
     */
    topSheetPattern->pageHeight_ = 1000;
    topSheetPattern->sheetMaxHeight_ = 1000;
    topSheetPattern->isFirstInit_ = true;

    /**
     * @tc.steps: step4. set sheetStyle.height = 0.5, unit is %.
     * @tc.expected: height = 1000*0.5 = 500.
     */
    Dimension singleHeight { 0.5, DimensionUnit::PERCENT };
    sheetStyle.height = singleHeight;
    EXPECT_TRUE(NearEqual(topSheetPattern->InitialSingleGearHeight(sheetStyle), 500));

    /**
     * @tc.steps: step5. set sheetStyle.height > maxHeight.
     * @tc.expected: height = 1000-8 = 992.
     */
    sheetStyle.height->unit_ = DimensionUnit::VP;
    sheetStyle.height->value_ = 1200;
    EXPECT_TRUE(NearEqual(topSheetPattern->InitialSingleGearHeight(sheetStyle), 992));

    /**
     * @tc.steps: step6. set sheetStyle.height < 0.
     * @tc.expected: height = 1000-8 = 992.
     */
    sheetStyle.height->unit_ = DimensionUnit::VP;
    sheetStyle.height->value_ = -10;
    EXPECT_TRUE(NearEqual(topSheetPattern->InitialSingleGearHeight(sheetStyle), 992));
}

/**
 * @tc.name: OnBindSheet007
 * @tc.desc: Test OverlayManager::DismissSheet().
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, OnBindSheet007, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create target node.
     */
    auto targetNode = CreateTargetNode();
    auto stageNode = FrameNode::CreateFrameNode(
        V2::STAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StagePattern>());
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    stageNode->MountToParent(rootNode);
    targetNode->MountToParent(stageNode);
    rootNode->MarkDirtyNode();

    /**
     * @tc.steps: step2. create sheetNode, get sheetPattern.
     */
    SheetStyle sheetStyle;
    bool isShow = true;
    CreateSheetBuilder();
    auto overlayManager = AceType::MakeRefPtr<OverlayManager>(rootNode);
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc_), std::move(titleBuilderFunc_), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    auto topSheetNode = overlayManager->modalStack_.top().Upgrade();
    ASSERT_NE(topSheetNode, nullptr);
    auto topSheetPattern = topSheetNode->GetPattern<SheetPresentationPattern>();
    ASSERT_NE(topSheetPattern, nullptr);

    /**
     * @tc.steps: step3. test DismissSheet().
     * @tc.expected: callback is false.
     */
    overlayManager->DismissSheet();
    EXPECT_FALSE(topSheetPattern->callback_);
}

/**
 * @tc.name: OnBindSheet008
 * @tc.desc: Test OverlayManager::OnBindSheet change sheetStyle width.
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, OnBindSheet008, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create target node.
     */
    auto targetNode = CreateTargetNode();
    auto stageNode = FrameNode::CreateFrameNode(
        V2::STAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StagePattern>());
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    stageNode->MountToParent(rootNode);
    targetNode->MountToParent(stageNode);
    rootNode->MarkDirtyNode();

    /**
     * @tc.steps: step2. create sheetNode, get sheetPattern.
     */
    SheetStyle sheetStyle;
    bool isShow = true;
    CreateSheetBuilder();
    auto overlayManager = AceType::MakeRefPtr<OverlayManager>(rootNode);
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc_), std::move(titleBuilderFunc_), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    auto sheetNode = overlayManager->modalStack_.top().Upgrade();
    ASSERT_NE(sheetNode, nullptr);
    auto sheetLayoutProperty = sheetNode->GetLayoutProperty<SheetPresentationProperty>();
    EXPECT_FALSE(sheetLayoutProperty == nullptr);
    auto style = sheetLayoutProperty->GetSheetStyle();
    EXPECT_EQ(style->width.has_value(), false);

    /**
     * @tc.steps: step3. Change the sheetStyle width.
     * @tc.expected: the sheetStyle width is updated successfully
     */
    Dimension width{ 300, DimensionUnit::VP };
    sheetStyle.width = width;
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc_), std::move(titleBuilderFunc_), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr, targetNode);
    sheetNode = overlayManager->modalStack_.top().Upgrade();
    sheetLayoutProperty = sheetNode->GetLayoutProperty<SheetPresentationProperty>();
    style = sheetLayoutProperty->GetSheetStyle();
    EXPECT_EQ(style->width.value(), width);

    Dimension widthNew{ 400, DimensionUnit::VP };
    sheetStyle.width = widthNew;
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc_), std::move(titleBuilderFunc_), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr, targetNode);
    sheetNode = overlayManager->modalStack_.top().Upgrade();
    sheetLayoutProperty = sheetNode->GetLayoutProperty<SheetPresentationProperty>();
    style = sheetLayoutProperty->GetSheetStyle();
    EXPECT_EQ(style->width.value(), widthNew);
}

/**
 * @tc.name: OnBindSheet009
 * @tc.desc: Test OverlayManager::OnBindSheet change sheetStyle border and shadow.
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, OnBindSheet009, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create target node.
     */
    auto targetNode = CreateTargetNode();
    auto stageNode = FrameNode::CreateFrameNode(
        V2::STAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StagePattern>());
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    stageNode->MountToParent(rootNode);
    targetNode->MountToParent(stageNode);
    rootNode->MarkDirtyNode();
    /**
     * @tc.steps: step2. create sheetNode, get sheetPattern.
     */
    SheetStyle sheetStyle;
    bool isShow = true;
    CreateSheetBuilder();
    auto overlayManager = AceType::MakeRefPtr<OverlayManager>(rootNode);
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc_), std::move(titleBuilderFunc_), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    auto sheetNode = overlayManager->modalStack_.top().Upgrade();
    ASSERT_NE(sheetNode, nullptr);
    auto renderContext = sheetNode->GetRenderContext();
    ASSERT_NE(renderContext, nullptr);
    EXPECT_EQ(renderContext->GetBorderWidth().has_value(), false);
    EXPECT_EQ(renderContext->GetBorderColor().has_value(), false);
    EXPECT_EQ(renderContext->GetBorderStyle().has_value(), false);
    EXPECT_EQ(renderContext->GetBackShadow().has_value(), false);
    /**
     * @tc.steps: step3. Change the sheetStyle border and shadow.
     * @tc.expected: the sheetStyle is updated successfully
     */
    Shadow shadow = ShadowConfig::DefaultShadowL;
    sheetStyle.borderWidth = BORDER_WIDTH_TEST;
    sheetStyle.borderColor = BORDER_COLOR_TEST;
    sheetStyle.borderStyle = BORDER_STYLE_TEST;
    sheetStyle.shadow = shadow;
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc_), std::move(titleBuilderFunc_), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    sheetNode = overlayManager->modalStack_.top().Upgrade();
    renderContext = sheetNode->GetRenderContext();
    EXPECT_EQ(renderContext->GetBorderWidth().value(), BORDER_WIDTH_TEST);
    EXPECT_EQ(renderContext->GetBorderColor().value(), BORDER_COLOR_TEST);
    EXPECT_EQ(renderContext->GetBorderStyle().value(), BORDER_STYLE_TEST);
    EXPECT_EQ(renderContext->GetBackShadow().value(), shadow);
    Shadow shadowNew = ShadowConfig::NoneShadow;
    sheetStyle.borderWidth = NEW_BORDER_WIDTH_TEST;
    sheetStyle.borderColor = NEW_BORDER_COLOR_TEST;
    sheetStyle.borderStyle = NEW_BORDER_STYLE_TEST;
    sheetStyle.shadow = shadowNew;
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc_), std::move(titleBuilderFunc_), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    sheetNode = overlayManager->modalStack_.top().Upgrade();
    renderContext = sheetNode->GetRenderContext();
    EXPECT_EQ(renderContext->GetBorderWidth().value(), NEW_BORDER_WIDTH_TEST);
    EXPECT_EQ(renderContext->GetBorderColor().value(), NEW_BORDER_COLOR_TEST);
    EXPECT_EQ(renderContext->GetBorderStyle().value(), NEW_BORDER_STYLE_TEST);
    EXPECT_EQ(renderContext->GetBackShadow().value(), shadowNew);
}

/**
 * @tc.name: SheetPresentationPattern5
 * @tc.desc: Test SheetPresentationPattern::BubbleStyleSheetTransition().
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, SheetPresentationPattern5, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create target node.
     */
    auto targetNode = CreateTargetNode();
    auto stageNode = FrameNode::CreateFrameNode(
        V2::STAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StagePattern>());
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    stageNode->MountToParent(rootNode);
    targetNode->MountToParent(stageNode);
    rootNode->MarkDirtyNode();

    /**
     * @tc.steps: step2. create sheetNode, get sheetPattern.
     */
    SheetStyle sheetStyle;
    bool isShow = true;
    CreateSheetBuilder();
    auto overlayManager = AceType::MakeRefPtr<OverlayManager>(rootNode);
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc_), std::move(titleBuilderFunc_), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    auto topSheetNode = overlayManager->modalStack_.top().Upgrade();
    ASSERT_NE(topSheetNode, nullptr);
    auto topSheetPattern = topSheetNode->GetPattern<SheetPresentationPattern>();
    ASSERT_NE(topSheetPattern, nullptr);

    /**
     * @tc.steps: step3. test SheetPresentationPattern::BubbleStyleSheetTransition().
     * @tc.expected: callback is false.
     */
    topSheetPattern->BubbleStyleSheetTransition(false);
    EXPECT_FALSE(topSheetPattern->callback_);
}

/**
 * @tc.name: SheetPresentationPattern6
 * @tc.desc: Test SheetPresentationPattern::ClipSheetNode().
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, SheetPresentationPattern6, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create target node.
     */
    auto targetNode = CreateTargetNode();
    auto stageNode = FrameNode::CreateFrameNode(
        V2::STAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StagePattern>());
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    stageNode->MountToParent(rootNode);
    targetNode->MountToParent(stageNode);
    rootNode->MarkDirtyNode();

    /**
     * @tc.steps: step2. create sheetNode, get sheetPattern.
     */
    SheetStyle sheetStyle;
    bool isShow = true;
    CreateSheetBuilder();
    auto overlayManager = AceType::MakeRefPtr<OverlayManager>(rootNode);
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc_), std::move(titleBuilderFunc_), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    auto topSheetNode = overlayManager->modalStack_.top().Upgrade();
    ASSERT_NE(topSheetNode, nullptr);
    auto topSheetPattern = topSheetNode->GetPattern<SheetPresentationPattern>();
    ASSERT_NE(topSheetPattern, nullptr);

    /**
     * @tc.steps: step3. test clip sheet node, set sheetSize.
     * @tc.expected: clipPath is as same as set.
     */
    auto sheetSize = SizeF(1000, 720);
    auto pipeline = PipelineContext::GetCurrentContext();
    auto sheetTheme = pipeline->GetTheme<SheetTheme>();
    auto sheetRadius = sheetTheme->GetSheetRadius();
    std::string substring = "720.000000 Z";

    /**
     * @tc.steps: step4. test clipPath.
     */
    auto popupPath = topSheetPattern->GetPopupStyleSheetClipPath(sheetSize, sheetRadius);
    EXPECT_EQ(popupPath.length(), 406);
    EXPECT_EQ(popupPath.substr(394, 12), substring);
    auto centerPath = topSheetPattern->GetCenterStyleSheetClipPath(sheetSize, sheetRadius);
    EXPECT_EQ(centerPath.length(), 297);
    EXPECT_EQ(centerPath.substr(285, 12), substring);
    auto bottomPath = topSheetPattern->GetBottomStyleSheetClipPath(sheetSize, sheetRadius);
    EXPECT_EQ(bottomPath.length(), 190);
    EXPECT_EQ(bottomPath.substr(178, 12), substring);
}

/**
 * @tc.name: SheetPresentationPattern7
 * @tc.desc: Test SheetPresentationPattern::UpdateInteractive().
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, SheetPresentationPattern7, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create target node.
     */
    auto targetNode = CreateTargetNode();
    auto stageNode = FrameNode::CreateFrameNode(
        V2::STAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StagePattern>());
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    stageNode->MountToParent(rootNode);
    targetNode->MountToParent(stageNode);
    rootNode->MarkDirtyNode();

    /**
     * @tc.steps: step2. create sheetNode, get sheetPattern.
     */
    SheetStyle sheetStyle;
    bool isShow = true;
    CreateSheetBuilder();
    auto overlayManager = AceType::MakeRefPtr<OverlayManager>(rootNode);
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc_), std::move(titleBuilderFunc_), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    auto topSheetNode = overlayManager->modalStack_.top().Upgrade();
    ASSERT_NE(topSheetNode, nullptr);
    auto topSheetPattern = topSheetNode->GetPattern<SheetPresentationPattern>();

    /**
     * @tc.steps: step3. test without setting enableOutsideInteractive.
     * @tc.expected: The backplanes are not interactive by default, maskNode should be visible.
     */
    topSheetPattern->UpdateInteractive();
    EXPECT_FALSE(sheetStyle.interactive);
    auto maskNode = overlayManager->GetSheetMask(topSheetNode);
    ASSERT_NE(maskNode, nullptr);
    auto maskLatoutProperty = maskNode->GetLayoutProperty();
    ASSERT_NE(maskLatoutProperty, nullptr);
    EXPECT_NE(maskLatoutProperty->GetVisibility(), VisibleType::INVISIBLE);

    /**
     * @tc.steps: step4. test set enableOutsideInteractive true.
     * @tc.expected: maskNode is invisible, the backplane can be interactive.
     */
    auto sheetLayoutProperty = topSheetNode->GetLayoutProperty<SheetPresentationProperty>();
    ASSERT_NE(sheetLayoutProperty, nullptr);
    sheetStyle.interactive = true;
    sheetLayoutProperty->UpdateSheetStyle(sheetStyle);
    topSheetPattern->UpdateInteractive();
    maskNode = overlayManager->GetSheetMask(topSheetNode);
    maskLatoutProperty = maskNode->GetLayoutProperty<LayoutProperty>();
    EXPECT_EQ(maskLatoutProperty->GetVisibility(), VisibleType::INVISIBLE);

    /**
     * @tc.steps: step5. test set enableOutsideInteractive false.
     * @tc.expected: maskNode is visible, the backplane can not be interactive.
     */
    sheetStyle.interactive = false;
    sheetLayoutProperty->UpdateSheetStyle(sheetStyle);
    topSheetPattern->UpdateInteractive();
    maskNode = overlayManager->GetSheetMask(topSheetNode);
    maskLatoutProperty = maskNode->GetLayoutProperty();
    EXPECT_NE(maskLatoutProperty->GetVisibility(), VisibleType::INVISIBLE);
}

/**
 * @tc.name: SheetPresentationPattern8
 * @tc.desc: Test SheetPresentationPattern::SheetInteractiveDismiss().
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, SheetPresentationPattern8, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create target node.
     */
    auto targetNode = CreateTargetNode();
    auto stageNode = FrameNode::CreateFrameNode(
        V2::STAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StagePattern>());
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    stageNode->MountToParent(rootNode);
    targetNode->MountToParent(stageNode);
    rootNode->MarkDirtyNode();

    /**
     * @tc.steps: step2. create sheetNode, get sheetPattern.
     */
    SheetStyle sheetStyle;
    bool isShow = true;
    CreateSheetBuilder();
    auto overlayManager = AceType::MakeRefPtr<OverlayManager>(rootNode);
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc_), std::move(titleBuilderFunc_), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    auto topSheetNode = overlayManager->modalStack_.top().Upgrade();
    ASSERT_NE(topSheetNode, nullptr);
    auto topSheetPattern = topSheetNode->GetPattern<SheetPresentationPattern>();

    /**
     * @tc.steps: step3. set shouldDismissFunc, sheetDetents.
     */
    topSheetPattern->sheetDetentHeight_.emplace_back(100);
    bool isDismiss = false;
    auto shouldDismissFunc = [&isDismiss]() -> void { isDismiss = true; };

    /**
     * @tc.steps: step4. Trigger a shutdown event, test when the velocity is illegal.
     * @tc.expected: shutdown faild, shouldDismissFunc is not called.
     */
    topSheetPattern->UpdateShouldDismiss(shouldDismissFunc);
    topSheetPattern->HandleDragEnd(-2000);
    EXPECT_FALSE(isDismiss);

    /**
     * @tc.steps: step5. Trigger a shutdown event.
     * @tc.expected: shouldDismissFunc is called, isDismiss = true.
     */
    topSheetPattern->HandleDragEnd(100);
    EXPECT_TRUE(isDismiss);

    /**
     * @tc.steps: step6. Trigger a shutdown event, test when the velocity reaches the threshold.
     * @tc.expected: shouldDismissFunc is called, isDismiss = true.
     */
    isDismiss = false;
    topSheetPattern->HandleDragEnd(2000);
    EXPECT_TRUE(isDismiss);
}

/**
 * @tc.name: SheetPresentationPattern9
 * @tc.desc: Test SheetPresentationPattern::SheetTransition().
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, SheetPresentationPattern9, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create target node.
     */
    auto targetNode = CreateTargetNode();
    auto stageNode = FrameNode::CreateFrameNode(
        V2::STAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StagePattern>());
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    stageNode->MountToParent(rootNode);
    targetNode->MountToParent(stageNode);
    rootNode->MarkDirtyNode();

    /**
     * @tc.steps: step2. create sheetNode, get sheetPattern.
     */
    SheetStyle sheetStyle;
    bool isShow = true;
    auto heightVal = 500.0f;
    auto onHeightDidChange = [&heightVal](float height) { heightVal = height; };
    CreateSheetBuilder();
    auto overlayManager = AceType::MakeRefPtr<OverlayManager>(rootNode);
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc_), std::move(titleBuilderFunc_), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, onHeightDidChange, nullptr, nullptr, nullptr,
        nullptr, targetNode);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    auto topSheetNode = overlayManager->modalStack_.top().Upgrade();
    auto topSheetPattern = topSheetNode->GetPattern<SheetPresentationPattern>();

    /**
     * @tc.steps: step3. set params of sheetTransition, enter ModifyFireSheetTransition.
     */
    topSheetPattern->SheetTransition(false);
    topSheetPattern->sheetType_ = SheetType::SHEET_BOTTOM;
    topSheetPattern->SheetTransition(true);

    /**
     * @tc.steps: step4. end of animation callback.
     * @tc.expected: sheetTransition is called, isAnimationProcess_ = false.
     */
    topSheetPattern->isAnimationBreak_ = false;
    topSheetPattern->ModifyFireSheetTransition();
    EXPECT_FALSE(topSheetPattern->isAnimationProcess_);

    /**
     * @tc.steps: step5. end of animation callback.
     * @tc.expected: sheetTransition is called, isAnimationBreak_ = false.
     */
    topSheetPattern->isAnimationBreak_ = true;
    topSheetPattern->ModifyFireSheetTransition();
    EXPECT_FALSE(topSheetPattern->isAnimationBreak_);

    /**
     * @tc.steps: step6. create property callback.
     * @tc.expected: property_ is not nullptr.
     */
    topSheetPattern->property_ = nullptr;
    topSheetPattern->CreatePropertyCallback();
    EXPECT_NE(topSheetPattern->property_, nullptr);
}

/**
 * @tc.name: SheetPresentationPattern10
 * @tc.desc: Test SheetPresentationPattern::FireOnHeightDidChange().
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, SheetPresentationPattern10, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create target node.
     */
    auto targetNode = CreateTargetNode();
    auto stageNode = FrameNode::CreateFrameNode(
        V2::STAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StagePattern>());
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    stageNode->MountToParent(rootNode);
    targetNode->MountToParent(stageNode);
    rootNode->MarkDirtyNode();

    /**
     * @tc.steps: step2. create sheetNode, get sheetPattern.
     */
    SheetStyle sheetStyle;
    bool isShow = true;
    auto heightVal = 500.0f;
    auto onHeightDidChange = [&heightVal](float height) { heightVal = height; };
    CreateSheetBuilder();
    auto overlayManager = AceType::MakeRefPtr<OverlayManager>(rootNode);
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc_), std::move(titleBuilderFunc_), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, onHeightDidChange, nullptr, nullptr, nullptr,
        nullptr, targetNode);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    auto topSheetNode = overlayManager->modalStack_.top().Upgrade();
    auto topSheetPattern = topSheetNode->GetPattern<SheetPresentationPattern>();
    
    /**
     * @tc.steps: step3. create property callback.
     * @tc.expected: topSheetNode->GetGeometryNode()->GetFrameSize().Height() 500.
     */
    topSheetPattern->sheetType_ = SheetType::SHEET_CENTER;
    topSheetNode->GetGeometryNode()->SetFrameSize(SizeF({ 500, 500 }));
    topSheetPattern->FireOnHeightDidChange(0);
    EXPECT_EQ(topSheetNode->GetGeometryNode()->GetFrameSize().Height(), 500);

    /**
     * @tc.steps: step4. create property callback.
     * @tc.expected: height_ equal 500.
     */
    topSheetPattern->sheetType_ = SheetType::SHEET_BOTTOM;
    topSheetPattern->SetCurrentHeight(500);
    topSheetPattern->currentOffset_ = 0;
    topSheetPattern->FireOnHeightDidChange(0);
    EXPECT_EQ(topSheetPattern->height_, 500);
}

/**
 * @tc.name: SheetPresentationPattern11
 * @tc.desc: Test SheetPresentationPattern::FireOnDetentsDidChange().
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, SheetPresentationPattern11, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create target node.
     */
    auto targetNode = CreateTargetNode();
    auto stageNode = FrameNode::CreateFrameNode(
        V2::STAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StagePattern>());
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    stageNode->MountToParent(rootNode);
    targetNode->MountToParent(stageNode);
    rootNode->MarkDirtyNode();

    /**
     * @tc.steps: step2. create sheetNode, get sheetPattern.
     */
    SheetStyle sheetStyle;
    sheetStyle.sheetType = SheetType::SHEET_BOTTOM;
    bool isShow = true;
    auto heightVal = 500.0f;
    auto onDetentsDidChange = [&heightVal](float height) { heightVal = height; };
    CreateSheetBuilder();
    auto overlayManager = AceType::MakeRefPtr<OverlayManager>(rootNode);
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc_), std::move(titleBuilderFunc_), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, onDetentsDidChange, nullptr,
        nullptr, nullptr, targetNode);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    auto topSheetNode = overlayManager->modalStack_.top().Upgrade();
    ASSERT_NE(topSheetNode, nullptr);
    auto topSheetPattern = topSheetNode->GetPattern<SheetPresentationPattern>();
    ASSERT_NE(topSheetPattern, nullptr);
    
    /**
     * @tc.steps: step3. test InitSheetDetents(), sheetType = BOTTOM.
     */
    topSheetPattern->pageHeight_ = 1000;
    topSheetPattern->sheetMaxHeight_ = 1000;
    topSheetPattern->sheetThemeType_ = "auto";
    sheetStyle.sheetType = SheetType::SHEET_BOTTOM;
    auto sheetLayoutProperty = topSheetNode->GetLayoutProperty<SheetPresentationProperty>();
    EXPECT_FALSE(sheetLayoutProperty == nullptr);

    /**
     * @tc.steps: step4. test sheetMode has value and sheetStyle.detents = {600,992}.
     * @tc.expected: Call FireOnDetentsDidChange.
     */
    SheetHeight detent;
    detent.sheetMode = SheetMode::MEDIUM;
    sheetStyle.detents.emplace_back(detent);
    topSheetPattern->FireOnDetentsDidChange(500);
    detent.sheetMode = SheetMode::LARGE;
    sheetStyle.detents.emplace_back(detent);
    topSheetPattern->FireOnDetentsDidChange(992);
    sheetLayoutProperty->UpdateSheetStyle(sheetStyle);
    topSheetPattern->InitSheetDetents();
    EXPECT_FALSE(NearEqual(topSheetPattern->sheetDetentHeight_.front(), 500));
    EXPECT_TRUE(NearEqual(topSheetPattern->sheetDetentHeight_.back(), 992));

    /**
     * @tc.steps: step5. test sheetStyle.height has value.
     * @tc.expected: Call FireOnDetentsDidChange.
     */
    sheetStyle.detents.clear();
    SheetHeight detent1;
    Dimension detentHeight { 0.5, DimensionUnit::PERCENT };
    detent1.height = detentHeight;
    sheetStyle.detents.emplace_back(detent1);
    topSheetPattern->FireOnDetentsDidChange(500);
}

/**
 * @tc.name: SheetPresentationPattern12
 * @tc.desc: Test SheetPresentationPattern::GetSheetType().
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, SheetPresentationPattern12, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create target node.
     */
    auto targetNode = CreateTargetNode();
    auto stageNode = FrameNode::CreateFrameNode(
        V2::STAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StagePattern>());
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    stageNode->MountToParent(rootNode);
    targetNode->MountToParent(stageNode);
    rootNode->MarkDirtyNode();

    /**
     * @tc.steps: step2. create sheetNode, get sheetPattern.
     */
    SheetStyle sheetStyle;
    bool isShow = true;
    CreateSheetBuilder();
    auto overlayManager = AceType::MakeRefPtr<OverlayManager>(rootNode);
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc_), std::move(titleBuilderFunc_), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, targetNode);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    auto topSheetNode = overlayManager->modalStack_.top().Upgrade();
    ASSERT_NE(topSheetNode, nullptr);
    auto topSheetPattern = topSheetNode->GetPattern<SheetPresentationPattern>();
    ASSERT_NE(topSheetPattern, nullptr);

     /**
     * @tc.steps: step3. create sheetNode, set width and mode floating.
     */
    MockPipelineContext::GetCurrent()->SetWindowModal(WindowModal::CONTAINER_MODAL);
    MockPipelineContext::GetCurrent()->windowManager_ = AceType::MakeRefPtr<WindowManager>();
    MockPipelineContext::GetCurrent()->windowManager_->SetWindowGetModeCallBack(
        []() -> WindowMode { return WindowMode::WINDOW_MODE_FLOATING; });

    RefPtr<PipelineBase> pipelineContext = NG::MockPipelineContext::pipeline_;
    auto windowGlobalRect = pipelineContext->GetDisplayWindowRectInfo();
    windowGlobalRect.SetSize(Size(200, 300));
    auto mode = topSheetPattern->GetSheetType();
    EXPECT_EQ(mode, SheetType::SHEET_BOTTOM);
}

/**
 * @tc.name: SheetPresentationPattern13
 * @tc.desc: Test SheetPresentationPattern::SheetInteractiveDismiss().
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, SheetPresentationPattern13, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create target node.
     */
    auto targetNode = CreateTargetNode();
    auto stageNode = FrameNode::CreateFrameNode(
        V2::STAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StagePattern>());
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    stageNode->MountToParent(rootNode);
    targetNode->MountToParent(stageNode);
    rootNode->MarkDirtyNode();

    /**
     * @tc.steps: step2. create sheetNode, get sheetPattern.
     */
    SheetStyle sheetStyle;
    bool isShow = true;
    CreateSheetBuilder();
    auto overlayManager = AceType::MakeRefPtr<OverlayManager>(rootNode);
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc_), std::move(titleBuilderFunc_), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    EXPECT_FALSE(overlayManager->modalStack_.empty());
    auto topSheetNode = overlayManager->modalStack_.top().Upgrade();
    ASSERT_NE(topSheetNode, nullptr);
    auto topSheetPattern = topSheetNode->GetPattern<SheetPresentationPattern>();

    /**
     * @tc.steps: step3. set onWillDismissFunc, sheetDetents.
     */
    topSheetPattern->sheetDetentHeight_.emplace_back(100);
    bool isDismiss = false;
    auto onWillDismissFunc = [&isDismiss](const int32_t) -> void { isDismiss = true; };
    bool isSpringBack = false;
    auto springBackFunc = [&isSpringBack]() -> void { isSpringBack = true; };

    /**
     * @tc.steps: step4. Trigger a shutdown event, test when the velocity is illegal.
     * @tc.expected: shutdown faild, onWillDismissFunc is not called.
     */
    topSheetPattern->UpdateOnWillDismiss(onWillDismissFunc);
    topSheetPattern->HandleDragEnd(-2000);
    EXPECT_FALSE(isDismiss);

    /**
     * @tc.steps: step5. Trigger a shutdown event.
     * @tc.expected: onWillDismissFunc is called, isDismiss = true, isSpringBack = true.
     */
    topSheetPattern->UpdateSheetSpringBack(springBackFunc);
    topSheetPattern->HandleDragEnd(100);
    EXPECT_TRUE(isDismiss);

    /**
     * @tc.steps: step6. Trigger a shutdown event, test when the velocity reaches the threshold.
     * @tc.expected: onWillDismissFunc is called, isDismiss = true, isSpringBack = false.
     */
    auto springBackFunc2 = [&isSpringBack]() -> void { isSpringBack = false; };
    topSheetPattern->UpdateSheetSpringBack(springBackFunc2);
    topSheetPattern->HandleDragEnd(2000);
    EXPECT_TRUE(isDismiss);
}

/**
 * @tc.name: TestSheetPage001
 * @tc.desc: Test CreateSheetPage.
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, TestSheetPage001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create sheet page.
     */
    auto builder = FrameNode::CreateFrameNode(V2::COLUMN_ETS_TAG,
        ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<LinearLayoutPattern>(true));
    auto callback = [](const std::string&) {};
    SheetStyle style;
    style.isTitleBuilder = true;
    auto sheetNode = SheetView::CreateSheetPage(0, "", builder, builder, std::move(callback), style);
    ASSERT_NE(sheetNode, nullptr);

    /**
     * @tc.steps: step2. set style.isTitleBuilder = true.
     * @tc.expected: create titleColumn and operationColumn.GetChildren().size() equal 2.
     */
    auto sheetLayoutProperty = sheetNode->GetLayoutProperty<SheetPresentationProperty>();
    ASSERT_NE(sheetLayoutProperty, nullptr);
    EXPECT_TRUE(sheetLayoutProperty->GetSheetStyle()->isTitleBuilder);
    auto operationColumn = sheetNode->GetFirstChild();
    ASSERT_NE(operationColumn, nullptr);
    EXPECT_EQ(operationColumn->GetChildren().size(), 2);
}
/**
 * @tc.name: TestSheetPage002
 * @tc.desc: Test CreateSheetPage.
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, TestSheetPage002, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create sheet page.
     */
    auto builder = FrameNode::CreateFrameNode(V2::COLUMN_ETS_TAG,
        ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<LinearLayoutPattern>(true));
    auto callback = [](const std::string&) {};
    SheetStyle style;
    style.isTitleBuilder = true;
    style.sheetTitle = MESSAGE;
    style.sheetSubtitle = MESSAGE;
    auto sheetNode = SheetView::CreateSheetPage(0, "", builder, builder, std::move(callback), style);
    ASSERT_NE(sheetNode, nullptr);

    /**
     * @tc.steps: step2. set style.isTitleBuilder = true、 sheetTitle and sheetSubtitle.
     * @tc.expected: create titleColumn and titleColumn.GetChildren().size() equal 3.
     */
    auto sheetLayoutProperty = sheetNode->GetLayoutProperty<SheetPresentationProperty>();
    ASSERT_NE(sheetLayoutProperty, nullptr);
    EXPECT_TRUE(sheetLayoutProperty->GetSheetStyle()->isTitleBuilder);
    auto operationColumn = sheetNode->GetFirstChild();
    ASSERT_NE(operationColumn, nullptr);
    EXPECT_EQ(operationColumn->GetChildren().size(), 2);
    auto titleColumn = operationColumn->GetLastChild();
    ASSERT_NE(titleColumn, nullptr);
    EXPECT_EQ(titleColumn->GetChildren().size(), 3);
}

/**
 * @tc.name: TestSheetPage003
 * @tc.desc: Test SheetPresentationLayoutAlgorithm::Measure.
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, TestSheetPage003, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create sheet page.
     */
    auto builder = FrameNode::CreateFrameNode(V2::COLUMN_ETS_TAG,
        ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<LinearLayoutPattern>(true));
    auto callback = [](const std::string&) {};
    SheetStyle style;
    style.isTitleBuilder = true;
    style.sheetTitle = MESSAGE;
    style.sheetSubtitle = MESSAGE;
    auto sheetNode = SheetView::CreateSheetPage(0, "", builder, builder, std::move(callback), style);
    ASSERT_NE(sheetNode, nullptr);

    /**
     * @tc.steps: step2. call Measure function.
     * @tc.expected: sheetHeight_ equal 320.
     */
    auto sheetPattern = sheetNode->GetPattern<SheetPresentationPattern>();
    ASSERT_NE(sheetPattern, nullptr);
    auto sheetLayoutAlgorithm =
        AceType::DynamicCast<SheetPresentationLayoutAlgorithm>(sheetPattern->CreateLayoutAlgorithm());
    ASSERT_NE(sheetLayoutAlgorithm, nullptr);
    sheetNode->layoutAlgorithm_ = AceType::MakeRefPtr<LayoutAlgorithmWrapper>(sheetLayoutAlgorithm);
    sheetNode->Measure(sheetNode->GetLayoutConstraint());
    EXPECT_EQ(sheetLayoutAlgorithm->sheetHeight_, 2000);

    sheetLayoutAlgorithm->sheetType_ = SHEET_CENTER;
    sheetLayoutAlgorithm->sheetStyle_.sheetMode = SheetMode::AUTO;
    auto layoutProperty = AceType::DynamicCast<SheetPresentationProperty>(sheetNode->GetLayoutProperty());
    CHECK_NULL_VOID(layoutProperty);
    layoutProperty->UpdateSheetStyle(sheetLayoutAlgorithm->sheetStyle_);
    auto maxSize = SizeF(10.0f, 10.0f);
    sheetLayoutAlgorithm->Measure(AceType::RawPtr(sheetNode));
    sheetLayoutAlgorithm->GetHeightByScreenSizeType(maxSize);
    sheetLayoutAlgorithm->sheetType_ = SHEET_POPUP;
    sheetLayoutAlgorithm->GetHeightByScreenSizeType(maxSize);
    EXPECT_EQ(sheetLayoutAlgorithm->sheetHeight_, 320);
}

/**
 * @tc.name: TestSheetPage004
 * @tc.desc: Test SheetPresentationLayoutAlgorithm::GetHeightBySheetStyle.
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, TestSheetPage004, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create sheet page.
     */
    auto builder = FrameNode::CreateFrameNode(V2::COLUMN_ETS_TAG,
        ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<LinearLayoutPattern>(true));
    auto callback = [](const std::string&) {};
    SheetStyle style;
    style.isTitleBuilder = true;
    style.sheetTitle = MESSAGE;
    style.sheetSubtitle = MESSAGE;
    auto sheetNode = SheetView::CreateSheetPage(0, "", builder, builder, std::move(callback), style);
    ASSERT_NE(sheetNode, nullptr);

    auto sheetPattern = sheetNode->GetPattern<SheetPresentationPattern>();
    ASSERT_NE(sheetPattern, nullptr);
    auto sheetLayoutAlgorithm =
        AceType::DynamicCast<SheetPresentationLayoutAlgorithm>(sheetPattern->CreateLayoutAlgorithm());
    ASSERT_NE(sheetLayoutAlgorithm, nullptr);

    /**
     * @tc.steps: step2. set sheetStyle_.height and sheetStyle_.width.
     * @tc.expected: height and width value are equal expected value.
     */
    sheetLayoutAlgorithm->GetHeightBySheetStyle();

    sheetLayoutAlgorithm->sheetStyle_.height = 2.5_pct;
    sheetLayoutAlgorithm->GetHeightBySheetStyle();
    sheetLayoutAlgorithm->sheetStyle_.height = 2.5_px;
    sheetLayoutAlgorithm->GetHeightBySheetStyle();
    sheetLayoutAlgorithm->sheetStyle_.height = 0.0_px;
    auto height = sheetLayoutAlgorithm->GetHeightBySheetStyle();
    EXPECT_EQ(height, SHEET_BIG_WINDOW_MIN_HEIGHT.ConvertToPx());
    sheetLayoutAlgorithm->sheetStyle_.height = -1.0_px;
    height = sheetLayoutAlgorithm->GetHeightBySheetStyle();
    EXPECT_EQ(height, SHEET_BIG_WINDOW_HEIGHT.ConvertToPx());

    sheetLayoutAlgorithm->sheetType_ = SHEET_CENTER;
    auto maxSize = SizeF(10.0f, 10.0f);
    auto width = sheetLayoutAlgorithm->GetWidthByScreenSizeType(maxSize);
    EXPECT_EQ(width, SHEET_LANDSCAPE_WIDTH.ConvertToPx());
    sheetLayoutAlgorithm->sheetType_ = SHEET_POPUP;
    width = sheetLayoutAlgorithm->GetWidthByScreenSizeType(maxSize);
    EXPECT_EQ(width, SHEET_POPUP_WIDTH.ConvertToPx());
}

/**
 * @tc.name: GetSheetType001
 * @tc.desc: Test SheetPresentationPattern::GetSheetType.
 * @tc.type: FUNC
 */
HWTEST_F(OverlayManagerTestNg, GetSheetType001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create target node.
     */
    auto targetNode = CreateTargetNode();
    auto stageNode = FrameNode::CreateFrameNode(
        V2::STAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<StagePattern>());
    auto rootNode = FrameNode::CreateFrameNode(V2::ROOT_ETS_TAG, 1, AceType::MakeRefPtr<RootPattern>());
    stageNode->MountToParent(rootNode);
    targetNode->MountToParent(stageNode);
    rootNode->MarkDirtyNode();

    /**
     * @tc.steps: step2. create builder.
     */
    CreateSheetBuilder();

    /**
     * @tc.steps: step3. create sheet node and get sheet node, get pattern.
     * @tc.expected: related function is called.
     */
    SheetStyle sheetStyle;
    CreateSheetStyle(sheetStyle);
    bool isShow = true;
    auto overlayManager = AceType::MakeRefPtr<OverlayManager>(rootNode);
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc_), std::move(titleBuilderFunc_), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);

    EXPECT_FALSE(overlayManager->modalStack_.empty());
    auto topSheetNode = overlayManager->modalStack_.top().Upgrade();
    EXPECT_FALSE(topSheetNode == nullptr);
    auto sheetNodeLayoutProperty = topSheetNode->GetLayoutProperty<SheetPresentationProperty>();
    auto style = sheetNodeLayoutProperty->GetSheetStyle();
    EXPECT_FALSE(style->sheetType.has_value());

    /**
     * @tc.steps: step4. Change the sheetType.
     * @tc.expected: the sheetType is updated successfully
     */
    sheetStyle.sheetType = SheetType::SHEET_BOTTOM;
    overlayManager->OnBindSheet(isShow, nullptr, std::move(builderFunc_), std::move(titleBuilderFunc_), sheetStyle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, targetNode);
    auto sheetNode = overlayManager->modalStack_.top().Upgrade();
    EXPECT_FALSE(sheetNode == nullptr);
    auto sheetPattern = sheetNode->GetPattern<SheetPresentationPattern>();
    EXPECT_EQ(sheetPattern->GetSheetType(), SheetType::SHEET_BOTTOM);
    sheetNodeLayoutProperty = sheetNode->GetLayoutProperty<SheetPresentationProperty>();
    style = sheetNodeLayoutProperty->GetSheetStyle();
    EXPECT_TRUE(style->sheetType.has_value());
    EXPECT_EQ(style->sheetType.value(), SheetType::SHEET_BOTTOM);
}
}
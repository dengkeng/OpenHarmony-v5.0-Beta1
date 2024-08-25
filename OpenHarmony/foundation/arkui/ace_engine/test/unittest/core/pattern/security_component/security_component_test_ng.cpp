/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <algorithm>
#include <cstddef>
#include <optional>
#include <utility>

#include "gtest/gtest.h"

#define protected public
#define private public
#include "base/geometry/dimension.h"
#include "base/memory/ace_type.h"
#include "base/memory/referenced.h"
#include "base/utils/system_properties.h"
#include "core/common/ace_engine.h"
#include "core/components/common/layout/constants.h"
#include "core/components/common/properties/color.h"
#include "core/components/common/properties/text_style.h"
#include "core/components_ng/base/view_stack_processor.h"
#include "core/components_ng/pattern/button/button_layout_property.h"
#include "core/components_ng/pattern/button/button_pattern.h"
#include "core/components_ng/pattern/image/image_pattern.h"
#include "core/components_ng/pattern/security_component/location_button/location_button_common.h"
#include "core/components_ng/pattern/security_component/location_button/location_button_model_ng.h"
#include "core/components_ng/pattern/security_component/paste_button/paste_button_common.h"
#include "core/components_ng/pattern/security_component/paste_button/paste_button_model_ng.h"
#include "core/components_ng/pattern/security_component/save_button/save_button_common.h"
#include "core/components_ng/pattern/security_component/save_button/save_button_model_ng.h"
#include "core/components_ng/pattern/security_component/security_component_handler.h"
#include "core/components_ng/pattern/security_component/security_component_pattern.h"
#include "core/components_ng/pattern/security_component/security_component_theme.h"
#include "core/components_ng/pattern/text/text_pattern.h"
#include "test/mock/core/common/mock_container.h"
#include "test/mock/core/common/mock_theme_manager.h"
#include "test/mock/core/pipeline/mock_pipeline_context.h"
#include "core/pipeline_ng/ui_task_scheduler.h"
#include "test/mock/base/mock_task_executor.h"
#undef protected
#undef private

using namespace testing;
using namespace testing::ext;

namespace OHOS::Ace::NG {
namespace {
const InspectorFilter filter;
constexpr float DEFAULT_ICON_SIZE = 16.0f;
constexpr float DEFAULT_FONT_SIZE = 16.0f;
constexpr float DEFAULT_ICON_MIN_SIZE = 12.0f;
constexpr float DEFAULT_FONT_MIN_SIZE = 12.0f;
constexpr float DEFAULT_PADDING = 10.0f;
constexpr float DEFAULT_BORDER_RADIUS = 1.0f;
constexpr float DEFAULT_BORDER_WIDTH = 1.0f;
constexpr float DEFAULT_PADDING_WITHOUT_BG = 4.0f;
constexpr float DEFAULT_BUTTON_SIZE = 20.0f;
constexpr float MIN_SIZE = 1.0f;
constexpr float ENLARGE_SIZE = 50.0f;
const std::string DEFAULT_TEXT = "Add Security Component Buttom";
constexpr int INDEX_ZERO = 0;
constexpr int INDEX_ONE = 1;
constexpr int INDEX_TWO = 2;
constexpr int INDEX_SIZE = 3;
constexpr int ICON_RESOURCE_TABLE = 2;
}

namespace {
    constexpr float MAX_ROTATE = 360.0f;
class TestNode : public UINode {
    DECLARE_ACE_TYPE(TestNode, UINode);

    public:
        static RefPtr<TestNode> CreateTestNode(int32_t nodeId)
        {
            auto node = MakeRefPtr<TestNode>(nodeId);
            return node;
        }

        bool IsAtomicNode() const override
        {
            return true;
        }

        explicit TestNode(int32_t nodeId) : UINode("TestNode", nodeId) {}
        ~TestNode() override = default;
    };
}

class SecurityComponentModelTestNg : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
protected:
    static RefPtr<FrameNode> CreateSecurityComponent(int32_t text, int32_t icon,
        int32_t backgroundType, std::string type);
    static void CreateSecurityComponentNotFinish(int32_t text, int32_t icon,
        int32_t backgroundType, std::string type);
    static RefPtr<LayoutWrapperNode> CreateLayoutWrapper(RefPtr<FrameNode>& node);
    static RefPtr<LayoutWrapperNode> CreateSecurityComponentLayoutWrapper(RefPtr<FrameNode>& node);
    static void CheckSecurityComponentDefaultProp(RefPtr<FrameNode>& node);
    static void InitDefaultTheme(RefPtr<SecurityComponentTheme>& theme);
    static void SetLocationUserDefinedPropty();
    static void SetPasteUserDefinedPropty();
    static void SetSaveUserDefinedPropty();
};

class MockSecurityComponentButtonLayoutAlgorithm : public BoxLayoutAlgorithm {
public:
    MockSecurityComponentButtonLayoutAlgorithm() = default;

    ~MockSecurityComponentButtonLayoutAlgorithm() override = default;

    void Measure(LayoutWrapper* layoutWrapper) override
    {
        SizeF frameSize(DEFAULT_BUTTON_SIZE, DEFAULT_BUTTON_SIZE);
        layoutWrapper->GetGeometryNode()->SetFrameSize(frameSize);
    }
};

void SecurityComponentModelTestNg::InitDefaultTheme(RefPtr<SecurityComponentTheme>& theme)
{
    theme->iconSize_ = Dimension(DEFAULT_ICON_SIZE);
    theme->fontSize_ = Dimension(DEFAULT_FONT_SIZE);
    theme->minIconSize_ = Dimension(DEFAULT_ICON_MIN_SIZE);
    theme->minFontSize_ = Dimension(DEFAULT_FONT_MIN_SIZE);
    theme->backgroundTopPadding_ = Dimension(DEFAULT_PADDING);
    theme->backgroundRightPadding_ = Dimension(DEFAULT_PADDING);
    theme->backgroundBottomPadding_ = Dimension(DEFAULT_PADDING);
    theme->backgroundLeftPadding_ = Dimension(DEFAULT_PADDING);
    theme->textIconSpace_ = Dimension(DEFAULT_PADDING);
    theme->borderRadius_ = Dimension(DEFAULT_BORDER_RADIUS);
    theme->borderWidth_ = Dimension(DEFAULT_BORDER_WIDTH);
    theme->paddingWithoutBg_ = Dimension(DEFAULT_PADDING_WITHOUT_BG);
    theme->iconColor_ = Color::WHITE;
    theme->fontColor_ = Color::WHITE;
    theme->backgroundColor_ = Color::BLUE;
    theme->iconColorNoBg_ = Color::BLUE;
    theme->fontColorNoBg_ = Color::BLACK;
    theme->borderColor_ = Color::RED;
}

void SecurityComponentModelTestNg::SetUpTestCase()
{
    MockPipelineContext::SetUp();
    MockContainer::SetUp();
    MockContainer::Current()->pipelineContext_ = PipelineBase::GetCurrentContext();
    auto themeManager = AceType::MakeRefPtr<MockThemeManager>();
    MockPipelineContext::GetCurrent()->SetThemeManager(themeManager);
    auto scTheme = AceType::MakeRefPtr<SecurityComponentTheme>();
    InitDefaultTheme(scTheme);
    EXPECT_CALL(*themeManager, GetTheme(_)).WillRepeatedly(Return(scTheme));
}

void SecurityComponentModelTestNg::TearDownTestCase()
{
    MockPipelineContext::TearDown();
    MockContainer::TearDown();
}

RefPtr<FrameNode> SecurityComponentModelTestNg::CreateSecurityComponent(int32_t text, int32_t icon,
    int32_t backgroundType, std::string type)
{
    if (type == V2::LOCATION_BUTTON_ETS_TAG) {
        LocationButtonModelNG locationSc;
        locationSc.Create(text, icon, backgroundType);
    } else if (type == V2::PASTE_BUTTON_ETS_TAG) {
        PasteButtonModelNG pasteSc;
        pasteSc.Create(text, icon, backgroundType);
    } else if (type == V2::SAVE_BUTTON_ETS_TAG) {
        SaveButtonModelNG saveSc;
        saveSc.Create(text, icon, backgroundType);
    }
    RefPtr<UINode> element = ViewStackProcessor::GetInstance()->Finish();
    return AceType::DynamicCast<FrameNode>(element);
}

void SecurityComponentModelTestNg::CreateSecurityComponentNotFinish(int32_t text, int32_t icon,
    int32_t backgroundType, std::string type)
{
    if (type == V2::LOCATION_BUTTON_ETS_TAG) {
        LocationButtonModelNG locationSc;
        locationSc.Create(text, icon, backgroundType);
    } else if (type == V2::PASTE_BUTTON_ETS_TAG) {
        PasteButtonModelNG pasteSc;
        pasteSc.Create(text, icon, backgroundType);
    } else if (type == V2::SAVE_BUTTON_ETS_TAG) {
        SaveButtonModelNG saveSc;
        saveSc.Create(text, icon, backgroundType);
    }
}

void SecurityComponentModelTestNg::SetLocationUserDefinedPropty()
{
    LocationButtonModelNG sc;
    sc.SetFontSize(Dimension(15.0)); // 15.0 vp
    sc.SetIconSize(Dimension(15.0)); // 15.0 vp
    sc.SetIconColor(Color::RED);
    sc.SetFontStyle(Ace::FontStyle::ITALIC);
    sc.SetFontWeight(FontWeight::BOLDER);
    std::vector<std::string> fontFamilies = { "testFont" };
    sc.SetFontFamily(fontFamilies);
    sc.SetFontColor(Color::GREEN);
    sc.SetBackgroundColor(Color::GRAY);
    sc.SetBackgroundBorderWidth(Dimension(15.0)); // 15.0 vp
    sc.SetBackgroundBorderColor(Color::GREEN);
    sc.SetBackgroundBorderStyle(BorderStyle::DOTTED);
    sc.SetBackgroundBorderRadius(Dimension(15.0)); // 15.0 vp
    sc.SetBackgroundPadding(Dimension(25.0)); // 25.0 vp
    sc.SetTextIconSpace(Dimension(25.0)); // 25.0 vp
    sc.SetTextIconLayoutDirection(SecurityComponentLayoutDirection::VERTICAL);
}

void SecurityComponentModelTestNg::SetPasteUserDefinedPropty()
{
    PasteButtonModelNG sc;
    sc.SetFontSize(Dimension(15.0)); // 15.0 vp
    sc.SetIconSize(Dimension(15.0)); // 15.0 vp
    sc.SetIconColor(Color::RED);
    sc.SetFontStyle(Ace::FontStyle::ITALIC);
    sc.SetFontWeight(FontWeight::BOLDER);
    std::vector<std::string> fontFamilies = { "testFont" };
    sc.SetFontFamily(fontFamilies);
    sc.SetFontColor(Color::GREEN);
    sc.SetBackgroundColor(Color::GRAY);
    sc.SetBackgroundBorderWidth(Dimension(15.0)); // 15.0 vp
    sc.SetBackgroundBorderColor(Color::GREEN);
    sc.SetBackgroundBorderStyle(BorderStyle::DOTTED);
    sc.SetBackgroundBorderRadius(Dimension(15.0)); // 15.0 vp
    sc.SetBackgroundPadding(Dimension(25.0)); // 25.0 vp
    sc.SetTextIconSpace(Dimension(25.0)); // 25.0 vp
    sc.SetTextIconLayoutDirection(SecurityComponentLayoutDirection::VERTICAL);
}

void SecurityComponentModelTestNg::SetSaveUserDefinedPropty()
{
    SaveButtonModelNG sc;
    sc.SetFontSize(Dimension(15.0)); // 15.0 vp
    sc.SetIconSize(Dimension(15.0)); // 15.0 vp
    sc.SetIconColor(Color::RED);
    sc.SetFontStyle(Ace::FontStyle::ITALIC);
    sc.SetFontWeight(FontWeight::BOLDER);
    std::vector<std::string> fontFamilies = { "testFont" };
    sc.SetFontFamily(fontFamilies);
    sc.SetFontColor(Color::GREEN);
    sc.SetBackgroundColor(Color::GRAY);
    sc.SetBackgroundBorderWidth(Dimension(15.0)); // 15.0 vp
    sc.SetBackgroundBorderColor(Color::GREEN);
    sc.SetBackgroundBorderStyle(BorderStyle::DOTTED);
    sc.SetBackgroundBorderRadius(Dimension(15.0)); // 15.0 vp
    sc.SetBackgroundPadding(Dimension(25.0)); // 25.0 vp
    sc.SetTextIconSpace(Dimension(25.0)); // 25.0 vp
    sc.SetTextIconLayoutDirection(SecurityComponentLayoutDirection::VERTICAL);
}

RefPtr<LayoutWrapperNode> SecurityComponentModelTestNg::CreateLayoutWrapper(RefPtr<FrameNode>& node)
{
    RefPtr<GeometryNode> geometryNode = AceType::MakeRefPtr<GeometryNode>();
    if (geometryNode == nullptr) {
        return nullptr;
    }
    return AceType::MakeRefPtr<LayoutWrapperNode>(node, geometryNode, node->GetLayoutProperty());
}

RefPtr<LayoutWrapperNode> SecurityComponentModelTestNg::CreateSecurityComponentLayoutWrapper(RefPtr<FrameNode>& node)
{
    auto layoutWrapper = CreateLayoutWrapper(node);
    auto buttonNode = GetSecCompChildNode(node, V2::BUTTON_ETS_TAG);
    CHECK_NULL_RETURN(buttonNode, nullptr);
    auto buttonWrapper = CreateLayoutWrapper(buttonNode);
    auto buttonAlgorithm = AceType::MakeRefPtr<MockSecurityComponentButtonLayoutAlgorithm>();
    CHECK_NULL_RETURN(buttonAlgorithm, nullptr);
    buttonWrapper->SetLayoutAlgorithm(AceType::MakeRefPtr<LayoutAlgorithmWrapper>(buttonAlgorithm));

    auto iconNode = GetSecCompChildNode(node, V2::IMAGE_ETS_TAG);
    CHECK_NULL_RETURN(iconNode, nullptr);
    auto iconWrapper = CreateLayoutWrapper(iconNode);
    auto iconPattern = iconNode->GetPattern<ImagePattern>();
    CHECK_NULL_RETURN(iconPattern, nullptr);
    auto iconAlgorithm = iconPattern->CreateLayoutAlgorithm();
    CHECK_NULL_RETURN(iconAlgorithm, nullptr);
    iconWrapper->SetLayoutAlgorithm(AceType::MakeRefPtr<LayoutAlgorithmWrapper>(iconAlgorithm));

    auto textNode = GetSecCompChildNode(node, V2::TEXT_ETS_TAG);
    CHECK_NULL_RETURN(textNode, nullptr);
    auto textWrapper = CreateLayoutWrapper(textNode);
    auto textPattern = textNode->GetPattern<TextPattern>();
    CHECK_NULL_RETURN(textPattern, nullptr);
    auto textAlgorithm = textPattern->CreateLayoutAlgorithm();
    CHECK_NULL_RETURN(textAlgorithm, nullptr);
    textWrapper->SetLayoutAlgorithm(AceType::MakeRefPtr<LayoutAlgorithmWrapper>(textAlgorithm));

    layoutWrapper->childrenMap_[INDEX_ZERO] = buttonWrapper;
    layoutWrapper->childrenMap_[INDEX_ONE] = iconWrapper;
    layoutWrapper->childrenMap_[INDEX_TWO] = textWrapper;
    layoutWrapper->currentChildCount_ = INDEX_SIZE;
    layoutWrapper->cachedList_.emplace_back(&*buttonWrapper);
    layoutWrapper->cachedList_.emplace_back(&*iconWrapper);
    layoutWrapper->cachedList_.emplace_back(&*textWrapper);
    return layoutWrapper;
}

void SecurityComponentModelTestNg::CheckSecurityComponentDefaultProp(RefPtr<FrameNode>& node)
{
    auto property = node->GetLayoutProperty<SecurityComponentLayoutProperty>();
    ASSERT_NE(property, nullptr);
    EXPECT_EQ(property->GetSecurityComponentDescription().value_or(1), 0);
    EXPECT_EQ(property->GetIconStyle().value_or(1), 0);
    EXPECT_EQ(property->GetBackgroundType().value_or(static_cast<int32_t>(ButtonType::NORMAL)),
        static_cast<int32_t>(ButtonType::CAPSULE));
    EXPECT_EQ(property->GetTextIconLayoutDirection().value_or(SecurityComponentLayoutDirection::VERTICAL),
        SecurityComponentLayoutDirection::HORIZONTAL);
}

/**
 * @tc.name: SecurityComponentLocationPropertyTest001
 * @tc.desc: Test default properties of security component.
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLocationPropertyTest001, TestSize.Level1)
{
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0, static_cast<int32_t>(ButtonType::CAPSULE),
        V2::LOCATION_BUTTON_ETS_TAG);
    ASSERT_NE(frameNode, nullptr);
    ASSERT_EQ(frameNode->GetTag(), V2::LOCATION_BUTTON_ETS_TAG);

    CheckSecurityComponentDefaultProp(frameNode);

    // text node property
    auto textNode = GetSecCompChildNode(frameNode, V2::TEXT_ETS_TAG);
    ASSERT_NE(textNode, nullptr);
    auto textProp = textNode->GetLayoutProperty<TextLayoutProperty>();
    ASSERT_NE(textProp, nullptr);
    EXPECT_EQ(textProp->GetMaxLines().value_or(0), static_cast<uint32_t>(1));
    EXPECT_EQ(textProp->GetFontSize().value_or(Dimension(0.0)).ConvertToVp(), DEFAULT_FONT_SIZE);
    EXPECT_EQ(textProp->GetItalicFontStyle().value_or(Ace::FontStyle::ITALIC), Ace::FontStyle::NORMAL);
    EXPECT_EQ(textProp->GetFontWeight().value_or(FontWeight::NORMAL), FontWeight::MEDIUM);
    std::vector<std::string> emptyVec;
    auto fontFamily = textProp->GetFontFamily().value_or(emptyVec);
    EXPECT_FALSE(fontFamily.empty());
    EXPECT_EQ(textProp->GetTextColor().value_or(Color()), Color::WHITE);

    // icon node property
    auto iconNode = GetSecCompChildNode(frameNode, V2::IMAGE_ETS_TAG);
    ASSERT_NE(iconNode, nullptr);
    auto iconProp = iconNode->GetLayoutProperty<ImageLayoutProperty>();
    ASSERT_NE(iconProp, nullptr);
    ImageSourceInfo iconSrc = iconProp->GetImageSourceInfo().value_or(ImageSourceInfo());
    EXPECT_EQ(iconSrc.GetFillColor().value_or(Color()), Color::WHITE);

    // button node property
    auto buttonNode = GetSecCompChildNode(frameNode, V2::BUTTON_ETS_TAG);
    ASSERT_NE(buttonNode, nullptr);
    auto buttonProp = buttonNode->GetLayoutProperty<ButtonLayoutProperty>();
    ASSERT_NE(buttonProp, nullptr);
    auto buttonRender = buttonNode->GetRenderContext();
    ASSERT_NE(buttonRender, nullptr);
    auto borderColor = buttonRender->GetBorderColor().value_or(BorderColorProperty());
    EXPECT_EQ(borderColor.leftColor.value_or(Color()), Color::RED);
    auto& widthProp = buttonProp->GetBorderWidthProperty();
    ASSERT_NE(widthProp, nullptr);
    EXPECT_EQ(widthProp->leftDimen.value_or(Dimension(0.0)).ConvertToVp(), DEFAULT_BORDER_WIDTH);
    auto borderStyle = buttonRender->GetBorderStyle().value_or(BorderStyleProperty());
    EXPECT_EQ(borderStyle.styleLeft.value_or(BorderStyle::SOLID), BorderStyle::NONE);

    EXPECT_EQ(buttonRender->GetBackgroundColor().value_or(Color()), Color::BLUE);
    EXPECT_EQ(buttonProp->GetType().value_or(ButtonType::NORMAL), ButtonType::CAPSULE);
}

/**
 * @tc.name: SecurityComponentLocationPropertyTest002
 * @tc.desc: Test default properties of security component without background
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLocationPropertyTest002, TestSize.Level1)
{
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0,
        BUTTON_TYPE_NULL, V2::LOCATION_BUTTON_ETS_TAG);
    ASSERT_NE(frameNode, nullptr);
    ASSERT_EQ(frameNode->GetTag(), V2::LOCATION_BUTTON_ETS_TAG);

    auto property = frameNode->GetLayoutProperty<SecurityComponentLayoutProperty>();
    ASSERT_NE(property, nullptr);
    EXPECT_EQ(property->GetBackgroundType().value_or(static_cast<int32_t>(ButtonType::NORMAL)),
        BUTTON_TYPE_NULL);
    EXPECT_EQ(property->GetBackgroundLeftPadding().value_or(Dimension(0.0)).ConvertToVp(), DEFAULT_PADDING_WITHOUT_BG);
    EXPECT_EQ(property->GetBackgroundRightPadding().value_or(Dimension(0.0)).ConvertToVp(),
        DEFAULT_PADDING_WITHOUT_BG);
    EXPECT_EQ(property->GetBackgroundTopPadding().value_or(Dimension(0.0)).ConvertToVp(), DEFAULT_PADDING_WITHOUT_BG);
    EXPECT_EQ(property->GetBackgroundBottomPadding().value_or(Dimension(0.0)).ConvertToVp(),
        DEFAULT_PADDING_WITHOUT_BG);

    auto textNode = GetSecCompChildNode(frameNode, V2::TEXT_ETS_TAG);
    ASSERT_NE(textNode, nullptr);
    auto textProp = textNode->GetLayoutProperty<TextLayoutProperty>();
    ASSERT_NE(textProp, nullptr);
    EXPECT_EQ(textProp->GetTextColor().value_or(Color()), Color::BLACK);

    auto iconNode = GetSecCompChildNode(frameNode, V2::IMAGE_ETS_TAG);
    ASSERT_NE(iconNode, nullptr);
    auto iconProp = iconNode->GetLayoutProperty<ImageLayoutProperty>();
    ASSERT_NE(iconProp, nullptr);
    ImageSourceInfo iconSrc = iconProp->GetImageSourceInfo().value_or(ImageSourceInfo());
    EXPECT_EQ(iconSrc.GetFillColor().value_or(Color()), Color::BLUE);

    auto buttonNode = GetSecCompChildNode(frameNode, V2::BUTTON_ETS_TAG);
    ASSERT_NE(buttonNode, nullptr);
    auto buttonProp = buttonNode->GetLayoutProperty<ButtonLayoutProperty>();
    ASSERT_NE(buttonProp, nullptr);
    auto buttonRender = buttonNode->GetRenderContext();
    ASSERT_NE(buttonRender, nullptr);
    EXPECT_EQ(buttonRender->GetBackgroundColor().value_or(Color()), Color::TRANSPARENT);
    EXPECT_EQ(buttonProp->GetType().value_or(ButtonType::CAPSULE), ButtonType::NORMAL);
}

/**
 * @tc.name: SecurityComponentLocationPropertyTest003
 * @tc.desc: Test default properties of security component without icon
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLocationPropertyTest003, TestSize.Level1)
{
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(1, -1,
        BUTTON_TYPE_NULL, V2::LOCATION_BUTTON_ETS_TAG);
    ASSERT_NE(frameNode, nullptr);
    ASSERT_EQ(frameNode->GetTag(), V2::LOCATION_BUTTON_ETS_TAG);

    auto property = frameNode->GetLayoutProperty<SecurityComponentLayoutProperty>();
    ASSERT_NE(property, nullptr);
    EXPECT_EQ(property->GetIconStyle().value_or(1), -1);
    EXPECT_EQ(property->GetTextIconSpace().value_or(Dimension(0.0)).ConvertToVp(), 0.0);

    auto iconNode = GetSecCompChildNode(frameNode, V2::IMAGE_ETS_TAG);
    ASSERT_EQ(iconNode, nullptr);
}

/**
 * @tc.name: SecurityComponentLocationPropertyTest004
 * @tc.desc: Test set security component property
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLocationPropertyTest004, TestSize.Level1)
{
    CreateSecurityComponentNotFinish(0, 0, static_cast<int32_t>(ButtonType::CAPSULE), V2::LOCATION_BUTTON_ETS_TAG);
    SetLocationUserDefinedPropty();
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    ASSERT_NE(frameNode, nullptr);
    frameNode->MarkModifyDone();
    auto property = frameNode->GetLayoutProperty<SecurityComponentLayoutProperty>();
    ASSERT_NE(property, nullptr);
    EXPECT_EQ(property->GetTextIconSpace().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetBackgroundLeftPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetBackgroundRightPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetBackgroundTopPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetBackgroundBottomPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetTextIconLayoutDirection().value_or(SecurityComponentLayoutDirection::HORIZONTAL),
        SecurityComponentLayoutDirection::VERTICAL);

    auto iconNode = GetCurSecCompChildNode(V2::IMAGE_ETS_TAG);
    ASSERT_NE(iconNode, nullptr);
    auto iconProp = iconNode->GetLayoutProperty<ImageLayoutProperty>();
    ASSERT_NE(iconProp, nullptr);
    ImageSourceInfo iconSrc = iconProp->GetImageSourceInfo().value_or(ImageSourceInfo());
    EXPECT_EQ(iconSrc.GetFillColor().value_or(Color()), Color::RED);
    auto textNode = GetCurSecCompChildNode(V2::TEXT_ETS_TAG);
    ASSERT_NE(textNode, nullptr);
    auto textProp = textNode->GetLayoutProperty<TextLayoutProperty>();
    ASSERT_NE(textProp, nullptr);
    EXPECT_EQ(textProp->GetFontSize().value_or(Dimension(0.0)).ConvertToVp(), 15.0); // 15.0 vp
    EXPECT_EQ(textProp->GetItalicFontStyle().value_or(Ace::FontStyle::NORMAL), Ace::FontStyle::ITALIC);
    EXPECT_EQ(textProp->GetFontWeight().value_or(FontWeight::MEDIUM), FontWeight::BOLDER);
    std::vector<std::string> emptyVec;
    auto fontFamily = textProp->GetFontFamily().value_or(emptyVec);
    ASSERT_FALSE(fontFamily.empty());
    EXPECT_EQ(fontFamily[0], "testFont");
    EXPECT_EQ(textProp->GetTextColor().value_or(Color()), Color::GREEN);

    auto buttonNode = GetCurSecCompChildNode(V2::BUTTON_ETS_TAG);
    ASSERT_NE(buttonNode, nullptr);
    auto buttonProp = buttonNode->GetLayoutProperty<ButtonLayoutProperty>();
    ASSERT_NE(buttonProp, nullptr);
    auto buttonRender = buttonNode->GetRenderContext();
    ASSERT_NE(buttonRender, nullptr);
    auto borderColor = buttonRender->GetBorderColor().value_or(BorderColorProperty());
    EXPECT_EQ(borderColor.leftColor.value_or(Color()), Color::GREEN);
    auto& widthProp = buttonProp->GetBorderWidthProperty();
    ASSERT_NE(widthProp, nullptr);
    EXPECT_EQ(widthProp->leftDimen.value_or(Dimension(0.0)).ConvertToVp(), 15.0); // 15.0 vp
    auto borderStyle = buttonRender->GetBorderStyle().value_or(BorderStyleProperty());
    EXPECT_EQ(borderStyle.styleLeft.value_or(BorderStyle::SOLID), BorderStyle::DOTTED);
    EXPECT_EQ(buttonRender->GetBackgroundColor().value_or(Color()), Color::GRAY);
}

/**
 * @tc.name: SecurityComponentLocationPropertyTest005
 * @tc.desc: Test set security component property
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLocationPropertyTest005, TestSize.Level1)
{
    CreateSecurityComponentNotFinish(0, 0, static_cast<int32_t>(ButtonType::CAPSULE), V2::LOCATION_BUTTON_ETS_TAG);
    SetLocationUserDefinedPropty();
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    ASSERT_NE(frameNode, nullptr);
    frameNode->MarkModifyDone();
    auto property = frameNode->GetLayoutProperty<SecurityComponentLayoutProperty>();
    ASSERT_NE(property, nullptr);
    EXPECT_EQ(property->GetTextIconSpace().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetBackgroundLeftPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetBackgroundRightPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetBackgroundTopPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetBackgroundBottomPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetTextIconLayoutDirection().value_or(SecurityComponentLayoutDirection::HORIZONTAL),
        SecurityComponentLayoutDirection::VERTICAL);

    auto iconNode = GetCurSecCompChildNode(V2::IMAGE_ETS_TAG);
    ASSERT_NE(iconNode, nullptr);
    auto iconProp = iconNode->GetLayoutProperty<ImageLayoutProperty>();
    ASSERT_NE(iconProp, nullptr);
    ImageSourceInfo iconSrc = iconProp->GetImageSourceInfo().value_or(ImageSourceInfo());
    EXPECT_EQ(iconSrc.GetFillColor().value_or(Color()), Color::RED);
    auto textNode = GetCurSecCompChildNode(V2::TEXT_ETS_TAG);
    ASSERT_NE(textNode, nullptr);
    auto textProp = textNode->GetLayoutProperty<TextLayoutProperty>();
    ASSERT_NE(textProp, nullptr);
    EXPECT_EQ(textProp->GetFontSize().value_or(Dimension(0.0)).ConvertToVp(), 15.0); // 15.0 vp
    EXPECT_EQ(textProp->GetItalicFontStyle().value_or(Ace::FontStyle::NORMAL), Ace::FontStyle::ITALIC);
    EXPECT_EQ(textProp->GetFontWeight().value_or(FontWeight::MEDIUM), FontWeight::BOLDER);
    std::vector<std::string> emptyVec;
    auto fontFamily = textProp->GetFontFamily().value_or(emptyVec);
    ASSERT_FALSE(fontFamily.empty());
    EXPECT_EQ(fontFamily[0], "testFont");
    EXPECT_EQ(textProp->GetTextColor().value_or(Color()), Color::GREEN);

    auto buttonNode = GetCurSecCompChildNode(V2::BUTTON_ETS_TAG);
    ASSERT_NE(buttonNode, nullptr);
    auto buttonProp = buttonNode->GetLayoutProperty<ButtonLayoutProperty>();
    ASSERT_NE(buttonProp, nullptr);
    auto buttonRender = buttonNode->GetRenderContext();
    ASSERT_NE(buttonRender, nullptr);
    auto borderColor = buttonRender->GetBorderColor().value_or(BorderColorProperty());
    EXPECT_EQ(borderColor.leftColor.value_or(Color()), Color::GREEN);
    auto& widthProp = buttonProp->GetBorderWidthProperty();
    ASSERT_NE(widthProp, nullptr);
    EXPECT_EQ(widthProp->leftDimen.value_or(Dimension(0.0)).ConvertToVp(), 15.0); // 15.0 vp
    auto borderStyle = buttonRender->GetBorderStyle().value_or(BorderStyleProperty());
    EXPECT_EQ(borderStyle.styleLeft.value_or(BorderStyle::SOLID), BorderStyle::DOTTED);
    EXPECT_EQ(buttonRender->GetBackgroundColor().value_or(Color()), Color::GRAY);
}

/**
 * @tc.name: SecurityComponentLocationPropertyTest006
 * @tc.desc: Test set security component property without background
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLocationPropertyTest006, TestSize.Level1)
{
    CreateSecurityComponentNotFinish(0, 0, BUTTON_TYPE_NULL, V2::LOCATION_BUTTON_ETS_TAG);
    LocationButtonModelNG locationSc;
    locationSc.SetBackgroundColor(Color::GRAY);
    locationSc.SetBackgroundBorderWidth(Dimension(15.0)); // 15.0 vp
    locationSc.SetBackgroundBorderColor(Color::GREEN);
    locationSc.SetBackgroundBorderStyle(BorderStyle::DOTTED);
    locationSc.SetBackgroundBorderRadius(Dimension(15.0)); // 15.0 vp
    locationSc.SetBackgroundPadding(Dimension(25.0)); // 25.0 vp

    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    ASSERT_NE(frameNode, nullptr);
    frameNode->MarkModifyDone();
    auto property = frameNode->GetLayoutProperty<SecurityComponentLayoutProperty>();
    ASSERT_NE(property, nullptr);
    EXPECT_NE(property->GetBackgroundLeftPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_NE(property->GetBackgroundRightPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_NE(property->GetBackgroundTopPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_NE(property->GetBackgroundBottomPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp

    auto buttonNode = GetCurSecCompChildNode(V2::BUTTON_ETS_TAG);
    ASSERT_NE(buttonNode, nullptr);
    auto buttonProp = buttonNode->GetLayoutProperty<ButtonLayoutProperty>();
    ASSERT_NE(buttonProp, nullptr);
    auto buttonRender = buttonNode->GetRenderContext();
    ASSERT_NE(buttonRender, nullptr);
    auto borderColor = buttonRender->GetBorderColor().value_or(BorderColorProperty());
    EXPECT_NE(borderColor.leftColor.value_or(Color()), Color::GREEN);
    auto& widthProp = buttonProp->GetBorderWidthProperty();
    ASSERT_EQ(widthProp, nullptr);
    auto borderStyle = buttonRender->GetBorderStyle().value_or(BorderStyleProperty());
    EXPECT_NE(borderStyle.styleLeft.value_or(BorderStyle::SOLID), BorderStyle::DOTTED);
}

/**
 * @tc.name: SecurityComponentLocationPropertyTest007
 * @tc.desc: Test set security component property without icon
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLocationPropertyTest007, TestSize.Level1)
{
    CreateSecurityComponentNotFinish(1, -1, static_cast<int32_t>(ButtonType::CAPSULE),
        V2::LOCATION_BUTTON_ETS_TAG);
    LocationButtonModelNG locationSc;
    locationSc.SetTextIconSpace(Dimension(15.0)); // 15.0vp

    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    ASSERT_NE(frameNode, nullptr);
    frameNode->MarkModifyDone();
    auto property = frameNode->GetLayoutProperty<SecurityComponentLayoutProperty>();
    ASSERT_NE(property, nullptr);
    EXPECT_EQ(property->GetTextIconSpace().value_or(Dimension(0.0)).ConvertToVp(), 0.0);
}

/**
 * @tc.name: SecurityComponentLocationPatternTest001
 * @tc.desc: Test default security component modifyDone
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLocationPatternTest001, TestSize.Level1)
{
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::LOCATION_BUTTON_ETS_TAG);
    ASSERT_NE(frameNode, nullptr);
    ASSERT_EQ(frameNode->GetTag(), V2::LOCATION_BUTTON_ETS_TAG);

    auto pattern = frameNode->GetPattern<SecurityComponentPattern>();
    ASSERT_NE(pattern, nullptr);
    pattern->OnModifyDone();
    EXPECT_TRUE(pattern->isAppearCallback_);
    EXPECT_NE(pattern->clickListener_, nullptr);

    auto secCompGesture = frameNode->GetOrCreateGestureEventHub();
    ASSERT_NE(secCompGesture, nullptr);
    EXPECT_EQ(secCompGesture->GetHitTestMode(), HitTestMode::HTMDEFAULT);

    // modifydone again
    pattern->OnModifyDone();
    EXPECT_TRUE(pattern->isAppearCallback_);
    EXPECT_NE(pattern->clickListener_, nullptr);
}

/**
 * @tc.name: SecurityComponentLocationPatternTest002
 * @tc.desc: Test event callback
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLocationPatternTest002, TestSize.Level1)
{
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::LOCATION_BUTTON_ETS_TAG);
    ASSERT_NE(frameNode, nullptr);
    ASSERT_EQ(frameNode->GetTag(), V2::LOCATION_BUTTON_ETS_TAG);

    auto pattern = frameNode->GetPattern<SecurityComponentPattern>();
    ASSERT_NE(pattern, nullptr);
    pattern->OnModifyDone();

    auto secCompGesture = frameNode->GetOrCreateGestureEventHub();
    ASSERT_NE(secCompGesture, nullptr);
    auto clickListener = secCompGesture->clickEventActuator_->clickEvents_.back();
    ASSERT_NE(clickListener, nullptr);
    ASSERT_NE(clickListener->callback_, nullptr);
    GestureEvent info;
    clickListener->callback_(info);

    auto eventHub = frameNode->GetEventHub<EventHub>();
    ASSERT_NE(eventHub, nullptr);
    ASSERT_NE(eventHub->onAppear_, nullptr);
    ASSERT_NE(eventHub->onDisappear_, nullptr);
    eventHub->onAppear_();
    eventHub->onDisappear_();
    ASSERT_EQ(pattern->scId_, -1);
}

/**
 * @tc.name: SecurityComponentLocationLayoutAlgoTest001
 * @tc.desc: Test default layout algo
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLocationLayoutAlgoTest001, TestSize.Level1)
{
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::LOCATION_BUTTON_ETS_TAG);
    ASSERT_NE(frameNode, nullptr);
    ASSERT_EQ(frameNode->GetTag(), V2::LOCATION_BUTTON_ETS_TAG);
    auto pattern = frameNode->GetPattern<SecurityComponentPattern>();
    ASSERT_NE(pattern, nullptr);
    pattern->OnModifyDone();

    auto property = frameNode->GetLayoutProperty<SecurityComponentLayoutProperty>();
    ASSERT_NE(property, nullptr);
    property->UpdateMarginSelfIdealSize(SizeF(MIN_SIZE, MIN_SIZE));
    property->UpdateContentConstraint();

    auto layoutAlgo = pattern->CreateLayoutAlgorithm();
    ASSERT_NE(layoutAlgo, nullptr);

    auto layoutWrapper = CreateSecurityComponentLayoutWrapper(frameNode);
    ASSERT_NE(layoutWrapper, nullptr);
    layoutAlgo->Measure(layoutWrapper.rawPtr_);
    layoutAlgo->Layout(layoutWrapper.rawPtr_);
    EXPECT_EQ(layoutWrapper->geometryNode_->GetFrameSize().Height(), DEFAULT_ICON_MIN_SIZE);
    EXPECT_EQ(layoutWrapper->geometryNode_->GetFrameSize().Width(), DEFAULT_ICON_MIN_SIZE);

    property->UpdateBackgroundType(static_cast<int32_t>(ButtonType::CAPSULE));
    property->UpdateTextIconLayoutDirection(SecurityComponentLayoutDirection::VERTICAL);
    pattern->OnModifyDone();

    layoutAlgo->Measure(layoutWrapper.rawPtr_);
    layoutAlgo->Layout(layoutWrapper.rawPtr_);
    EXPECT_EQ(layoutWrapper->geometryNode_->GetFrameSize().Height(), DEFAULT_ICON_MIN_SIZE);
    EXPECT_EQ(layoutWrapper->geometryNode_->GetFrameSize().Width(), DEFAULT_ICON_MIN_SIZE);

    property->UpdateBackgroundType(static_cast<int32_t>(ButtonType::CIRCLE));
    property->UpdateTextIconLayoutDirection(SecurityComponentLayoutDirection::VERTICAL);
    pattern->OnModifyDone();

    layoutAlgo->Measure(layoutWrapper.rawPtr_);
    layoutAlgo->Layout(layoutWrapper.rawPtr_);
    EXPECT_EQ(layoutWrapper->geometryNode_->GetFrameSize().Height(), DEFAULT_ICON_MIN_SIZE);
    EXPECT_EQ(layoutWrapper->geometryNode_->GetFrameSize().Width(), DEFAULT_ICON_MIN_SIZE);

    property->UpdateBackgroundType(static_cast<int32_t>(ButtonType::CAPSULE));
    property->UpdateTextIconLayoutDirection(SecurityComponentLayoutDirection::VERTICAL);
    pattern->OnModifyDone();

    property->UpdateMarginSelfIdealSize(SizeF(ENLARGE_SIZE, ENLARGE_SIZE));
    property->UpdateContentConstraint();
    layoutAlgo->Measure(layoutWrapper.rawPtr_);
    layoutAlgo->Layout(layoutWrapper.rawPtr_);
    EXPECT_EQ(layoutWrapper->geometryNode_->GetFrameSize().Height(), ENLARGE_SIZE);
    EXPECT_EQ(layoutWrapper->geometryNode_->GetFrameSize().Width(), ENLARGE_SIZE);
}

/**
 * @tc.name: SecurityComponentLocationAccessibilityPropertyTest001
 * @tc.desc: Test security component accessibility property
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLocationAccessibilityPropertyTest001, TestSize.Level1)
{
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::LOCATION_BUTTON_ETS_TAG);
    ASSERT_NE(frameNode, nullptr);
    ASSERT_EQ(frameNode->GetTag(), V2::LOCATION_BUTTON_ETS_TAG);
    auto pattern = frameNode->GetPattern<SecurityComponentPattern>();
    ASSERT_NE(pattern, nullptr);
    pattern->OnModifyDone();

    auto accessibility = pattern->CreateAccessibilityProperty();
    ASSERT_NE(accessibility, nullptr);
    accessibility->SetHost(frameNode);
}

/**
 * @tc.name: SecurityComponentSavePropertyTest001
 * @tc.desc: Test default properties of security component.
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentSavePropertyTest001, TestSize.Level1)
{
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0, static_cast<int32_t>(ButtonType::CAPSULE),
        V2::SAVE_BUTTON_ETS_TAG);
    ASSERT_NE(frameNode, nullptr);
    ASSERT_EQ(frameNode->GetTag(), V2::SAVE_BUTTON_ETS_TAG);

    CheckSecurityComponentDefaultProp(frameNode);

    // text node property
    auto textNode = GetSecCompChildNode(frameNode, V2::TEXT_ETS_TAG);
    ASSERT_NE(textNode, nullptr);
    auto textProp = textNode->GetLayoutProperty<TextLayoutProperty>();
    ASSERT_NE(textProp, nullptr);
    EXPECT_EQ(textProp->GetMaxLines().value_or(0), 1);
    EXPECT_EQ(textProp->GetFontSize().value_or(Dimension(0.0)).ConvertToVp(), DEFAULT_FONT_SIZE);
    EXPECT_EQ(textProp->GetItalicFontStyle().value_or(Ace::FontStyle::ITALIC), Ace::FontStyle::NORMAL);
    EXPECT_EQ(textProp->GetFontWeight().value_or(FontWeight::NORMAL), FontWeight::MEDIUM);
    std::vector<std::string> emptyVec;
    auto fontFamily = textProp->GetFontFamily().value_or(emptyVec);
    EXPECT_FALSE(fontFamily.empty());
    EXPECT_EQ(textProp->GetTextColor().value_or(Color()), Color::WHITE);

    // icon node property
    auto iconNode = GetSecCompChildNode(frameNode, V2::IMAGE_ETS_TAG);
    ASSERT_NE(iconNode, nullptr);
    auto iconProp = iconNode->GetLayoutProperty<ImageLayoutProperty>();
    ASSERT_NE(iconProp, nullptr);
    ImageSourceInfo iconSrc = iconProp->GetImageSourceInfo().value_or(ImageSourceInfo());
    EXPECT_EQ(iconSrc.GetFillColor().value_or(Color()), Color::WHITE);

    // button node property
    auto buttonNode = GetSecCompChildNode(frameNode, V2::BUTTON_ETS_TAG);
    ASSERT_NE(buttonNode, nullptr);
    auto buttonProp = buttonNode->GetLayoutProperty<ButtonLayoutProperty>();
    ASSERT_NE(buttonProp, nullptr);
    auto buttonRender = buttonNode->GetRenderContext();
    ASSERT_NE(buttonRender, nullptr);
    auto borderColor = buttonRender->GetBorderColor().value_or(BorderColorProperty());
    EXPECT_EQ(borderColor.leftColor.value_or(Color()), Color::RED);
    auto& widthProp = buttonProp->GetBorderWidthProperty();
    ASSERT_NE(widthProp, nullptr);
    EXPECT_EQ(widthProp->leftDimen.value_or(Dimension(0.0)).ConvertToVp(), DEFAULT_BORDER_WIDTH);
    auto borderStyle = buttonRender->GetBorderStyle().value_or(BorderStyleProperty());
    EXPECT_EQ(borderStyle.styleLeft.value_or(BorderStyle::SOLID), BorderStyle::NONE);

    EXPECT_EQ(buttonRender->GetBackgroundColor().value_or(Color()), Color::BLUE);
    EXPECT_EQ(buttonProp->GetType().value_or(ButtonType::NORMAL), ButtonType::CAPSULE);
}

/**
 * @tc.name: SecurityComponentSavePropertyTest002
 * @tc.desc: Test default properties of security component without background
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentSavePropertyTest002, TestSize.Level1)
{
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0,
        BUTTON_TYPE_NULL, V2::SAVE_BUTTON_ETS_TAG);
    ASSERT_NE(frameNode, nullptr);
    ASSERT_EQ(frameNode->GetTag(), V2::SAVE_BUTTON_ETS_TAG);
    frameNode->MarkModifyDone();

    auto property = frameNode->GetLayoutProperty<SecurityComponentLayoutProperty>();
    ASSERT_NE(property, nullptr);
    EXPECT_EQ(property->GetBackgroundType().value_or(static_cast<int32_t>(ButtonType::NORMAL)),
        BUTTON_TYPE_NULL);
    EXPECT_EQ(property->GetBackgroundLeftPadding().value_or(Dimension(0.0)).ConvertToVp(), DEFAULT_PADDING_WITHOUT_BG);
    EXPECT_EQ(property->GetBackgroundRightPadding().value_or(Dimension(0.0)).ConvertToVp(),
        DEFAULT_PADDING_WITHOUT_BG);
    EXPECT_EQ(property->GetBackgroundTopPadding().value_or(Dimension(0.0)).ConvertToVp(), DEFAULT_PADDING_WITHOUT_BG);
    EXPECT_EQ(property->GetBackgroundBottomPadding().value_or(Dimension(0.0)).ConvertToVp(),
        DEFAULT_PADDING_WITHOUT_BG);

    auto textNode = GetSecCompChildNode(frameNode, V2::TEXT_ETS_TAG);
    ASSERT_NE(textNode, nullptr);
    auto textProp = textNode->GetLayoutProperty<TextLayoutProperty>();
    ASSERT_NE(textProp, nullptr);
    EXPECT_EQ(textProp->GetTextColor().value_or(Color()), Color::BLACK);

    auto iconNode = GetSecCompChildNode(frameNode, V2::IMAGE_ETS_TAG);
    ASSERT_NE(iconNode, nullptr);
    auto iconProp = iconNode->GetLayoutProperty<ImageLayoutProperty>();
    ASSERT_NE(iconProp, nullptr);
    ImageSourceInfo iconSrc = iconProp->GetImageSourceInfo().value_or(ImageSourceInfo());
    EXPECT_EQ(iconSrc.GetFillColor().value_or(Color()), Color::BLUE);

    auto buttonNode = GetSecCompChildNode(frameNode, V2::BUTTON_ETS_TAG);
    ASSERT_NE(buttonNode, nullptr);
    auto buttonProp = buttonNode->GetLayoutProperty<ButtonLayoutProperty>();
    ASSERT_NE(buttonProp, nullptr);
    auto buttonRender = buttonNode->GetRenderContext();
    ASSERT_NE(buttonRender, nullptr);
    EXPECT_EQ(buttonRender->GetBackgroundColor().value_or(Color()), Color::TRANSPARENT);
    EXPECT_EQ(buttonProp->GetType().value_or(ButtonType::CAPSULE), ButtonType::NORMAL);
}

/**
 * @tc.name: SecurityComponentSavePropertyTest003
 * @tc.desc: Test default properties of security component without icon
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentSavePropertyTest003, TestSize.Level1)
{
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(1, -1,
        BUTTON_TYPE_NULL, V2::SAVE_BUTTON_ETS_TAG);
    ASSERT_NE(frameNode, nullptr);
    ASSERT_EQ(frameNode->GetTag(), V2::SAVE_BUTTON_ETS_TAG);

    auto property = frameNode->GetLayoutProperty<SecurityComponentLayoutProperty>();
    ASSERT_NE(property, nullptr);
    EXPECT_EQ(property->GetIconStyle().value_or(1), -1);
    EXPECT_EQ(property->GetTextIconSpace().value_or(Dimension(0.0)).ConvertToVp(), 0.0);

    auto iconNode = GetSecCompChildNode(frameNode, V2::IMAGE_ETS_TAG);
    ASSERT_EQ(iconNode, nullptr);
}

/**
 * @tc.name: SecurityComponentSavePropertyTest004
 * @tc.desc: Test set security component property
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentSavePropertyTest004, TestSize.Level1)
{
    CreateSecurityComponentNotFinish(0, 0, static_cast<int32_t>(ButtonType::CAPSULE), V2::SAVE_BUTTON_ETS_TAG);
    SetSaveUserDefinedPropty();
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    ASSERT_NE(frameNode, nullptr);
    auto property = frameNode->GetLayoutProperty<SecurityComponentLayoutProperty>();
    ASSERT_NE(property, nullptr);
    EXPECT_EQ(property->GetTextIconSpace().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetBackgroundLeftPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetBackgroundRightPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetBackgroundTopPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetBackgroundBottomPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetTextIconLayoutDirection().value_or(SecurityComponentLayoutDirection::HORIZONTAL),
        SecurityComponentLayoutDirection::VERTICAL);
    frameNode->MarkModifyDone();

    auto iconNode = GetCurSecCompChildNode(V2::IMAGE_ETS_TAG);
    ASSERT_NE(iconNode, nullptr);
    auto iconProp = iconNode->GetLayoutProperty<ImageLayoutProperty>();
    ASSERT_NE(iconProp, nullptr);
    ImageSourceInfo iconSrc = iconProp->GetImageSourceInfo().value_or(ImageSourceInfo());
    EXPECT_EQ(iconSrc.GetFillColor().value_or(Color()), Color::RED);
    auto textNode = GetCurSecCompChildNode(V2::TEXT_ETS_TAG);
    ASSERT_NE(textNode, nullptr);
    auto textProp = textNode->GetLayoutProperty<TextLayoutProperty>();
    ASSERT_NE(textProp, nullptr);
    EXPECT_EQ(textProp->GetFontSize().value_or(Dimension(0.0)).ConvertToVp(), 15.0); // 15.0 vp
    EXPECT_EQ(textProp->GetItalicFontStyle().value_or(Ace::FontStyle::NORMAL), Ace::FontStyle::ITALIC);
    EXPECT_EQ(textProp->GetFontWeight().value_or(FontWeight::MEDIUM), FontWeight::BOLDER);
    std::vector<std::string> emptyVec;
    auto fontFamily = textProp->GetFontFamily().value_or(emptyVec);
    ASSERT_FALSE(fontFamily.empty());
    EXPECT_EQ(fontFamily[0], "testFont");
    EXPECT_EQ(textProp->GetTextColor().value_or(Color()), Color::GREEN);

    auto buttonNode = GetCurSecCompChildNode(V2::BUTTON_ETS_TAG);
    ASSERT_NE(buttonNode, nullptr);
    auto buttonProp = buttonNode->GetLayoutProperty<ButtonLayoutProperty>();
    ASSERT_NE(buttonProp, nullptr);
    auto buttonRender = buttonNode->GetRenderContext();
    ASSERT_NE(buttonRender, nullptr);
    auto borderColor = buttonRender->GetBorderColor().value_or(BorderColorProperty());
    EXPECT_EQ(borderColor.leftColor.value_or(Color()), Color::GREEN);
    auto& widthProp = buttonProp->GetBorderWidthProperty();
    ASSERT_NE(widthProp, nullptr);
    EXPECT_EQ(widthProp->leftDimen.value_or(Dimension(0.0)).ConvertToVp(), 15.0); // 15.0 vp
    auto borderStyle = buttonRender->GetBorderStyle().value_or(BorderStyleProperty());
    EXPECT_EQ(borderStyle.styleLeft.value_or(BorderStyle::SOLID), BorderStyle::DOTTED);
    EXPECT_EQ(buttonRender->GetBackgroundColor().value_or(Color()), Color::GRAY);
}

/**
 * @tc.name: SecurityComponentSavePropertyTest005
 * @tc.desc: Test set security component property
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentSavePropertyTest005, TestSize.Level1)
{
    CreateSecurityComponentNotFinish(0, 0, static_cast<int32_t>(ButtonType::CAPSULE), V2::SAVE_BUTTON_ETS_TAG);
    SetSaveUserDefinedPropty();
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    ASSERT_NE(frameNode, nullptr);
    frameNode->MarkModifyDone();
    auto property = frameNode->GetLayoutProperty<SecurityComponentLayoutProperty>();
    ASSERT_NE(property, nullptr);
    EXPECT_EQ(property->GetTextIconSpace().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetBackgroundLeftPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetBackgroundRightPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetBackgroundTopPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetBackgroundBottomPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetTextIconLayoutDirection().value_or(SecurityComponentLayoutDirection::HORIZONTAL),
        SecurityComponentLayoutDirection::VERTICAL);

    auto iconNode = GetCurSecCompChildNode(V2::IMAGE_ETS_TAG);
    ASSERT_NE(iconNode, nullptr);
    auto iconProp = iconNode->GetLayoutProperty<ImageLayoutProperty>();
    ASSERT_NE(iconProp, nullptr);
    ImageSourceInfo iconSrc = iconProp->GetImageSourceInfo().value_or(ImageSourceInfo());
    EXPECT_EQ(iconSrc.GetFillColor().value_or(Color()), Color::RED);
    auto textNode = GetCurSecCompChildNode(V2::TEXT_ETS_TAG);
    ASSERT_NE(textNode, nullptr);
    auto textProp = textNode->GetLayoutProperty<TextLayoutProperty>();
    ASSERT_NE(textProp, nullptr);
    EXPECT_EQ(textProp->GetFontSize().value_or(Dimension(0.0)).ConvertToVp(), 15.0); // 15.0 vp
    EXPECT_EQ(textProp->GetItalicFontStyle().value_or(Ace::FontStyle::NORMAL), Ace::FontStyle::ITALIC);
    EXPECT_EQ(textProp->GetFontWeight().value_or(FontWeight::MEDIUM), FontWeight::BOLDER);
    std::vector<std::string> emptyVec;
    auto fontFamily = textProp->GetFontFamily().value_or(emptyVec);
    ASSERT_FALSE(fontFamily.empty());
    EXPECT_EQ(fontFamily[0], "testFont");
    EXPECT_EQ(textProp->GetTextColor().value_or(Color()), Color::GREEN);

    auto buttonNode = GetCurSecCompChildNode(V2::BUTTON_ETS_TAG);
    ASSERT_NE(buttonNode, nullptr);
    auto buttonProp = buttonNode->GetLayoutProperty<ButtonLayoutProperty>();
    ASSERT_NE(buttonProp, nullptr);
    auto buttonRender = buttonNode->GetRenderContext();
    ASSERT_NE(buttonRender, nullptr);
    auto borderColor = buttonRender->GetBorderColor().value_or(BorderColorProperty());
    EXPECT_EQ(borderColor.leftColor.value_or(Color()), Color::GREEN);
    auto& widthProp = buttonProp->GetBorderWidthProperty();
    ASSERT_NE(widthProp, nullptr);
    EXPECT_EQ(widthProp->leftDimen.value_or(Dimension(0.0)).ConvertToVp(), 15.0); // 15.0 vp
    auto borderStyle = buttonRender->GetBorderStyle().value_or(BorderStyleProperty());
    EXPECT_EQ(borderStyle.styleLeft.value_or(BorderStyle::SOLID), BorderStyle::DOTTED);
    EXPECT_EQ(buttonRender->GetBackgroundColor().value_or(Color()), Color::GRAY);
}

/**
 * @tc.name: SecurityComponentSavePropertyTest006
 * @tc.desc: Test set security component property without background
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentSavePropertyTest006, TestSize.Level1)
{
    CreateSecurityComponentNotFinish(0, 0, BUTTON_TYPE_NULL, V2::SAVE_BUTTON_ETS_TAG);
    SaveButtonModelNG saveSc;
    saveSc.SetBackgroundColor(Color::GRAY);
    saveSc.SetBackgroundBorderWidth(Dimension(15.0)); // 15.0 vp
    saveSc.SetBackgroundBorderColor(Color::GREEN);
    saveSc.SetBackgroundBorderStyle(BorderStyle::DOTTED);
    saveSc.SetBackgroundBorderRadius(Dimension(15.0)); // 15.0 vp
    saveSc.SetBackgroundPadding(Dimension(25.0)); // 25.0 vp

    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    ASSERT_NE(frameNode, nullptr);
    frameNode->MarkModifyDone();
    auto property = frameNode->GetLayoutProperty<SecurityComponentLayoutProperty>();
    ASSERT_NE(property, nullptr);
    EXPECT_NE(property->GetBackgroundLeftPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_NE(property->GetBackgroundRightPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_NE(property->GetBackgroundTopPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_NE(property->GetBackgroundBottomPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp

    auto buttonNode = GetCurSecCompChildNode(V2::BUTTON_ETS_TAG);
    ASSERT_NE(buttonNode, nullptr);
    auto buttonProp = buttonNode->GetLayoutProperty<ButtonLayoutProperty>();
    ASSERT_NE(buttonProp, nullptr);
    auto buttonRender = buttonNode->GetRenderContext();
    ASSERT_NE(buttonRender, nullptr);
    auto borderColor = buttonRender->GetBorderColor().value_or(BorderColorProperty());
    EXPECT_NE(borderColor.leftColor.value_or(Color()), Color::GREEN);
    auto& widthProp = buttonProp->GetBorderWidthProperty();
    ASSERT_EQ(widthProp, nullptr);
    auto borderStyle = buttonRender->GetBorderStyle().value_or(BorderStyleProperty());
    EXPECT_NE(borderStyle.styleLeft.value_or(BorderStyle::SOLID), BorderStyle::DOTTED);
}

/**
 * @tc.name: SecurityComponentSavePropertyTest007
 * @tc.desc: Test set security component property without icon
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentSavePropertyTest007, TestSize.Level1)
{
    CreateSecurityComponentNotFinish(1, -1, static_cast<int32_t>(ButtonType::CAPSULE),
        V2::SAVE_BUTTON_ETS_TAG);
    SaveButtonModelNG saveSc;
    saveSc.SetTextIconSpace(Dimension(15.0)); // 15.0vp

    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    ASSERT_NE(frameNode, nullptr);
    auto property = frameNode->GetLayoutProperty<SecurityComponentLayoutProperty>();
    ASSERT_NE(property, nullptr);
    EXPECT_EQ(property->GetTextIconSpace().value_or(Dimension(0.0)).ConvertToVp(), 0.0);
}

/**
 * @tc.name: SecurityComponentSavePatternTest001
 * @tc.desc: Test default security component modifyDone
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentSavePatternTest001, TestSize.Level1)
{
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::SAVE_BUTTON_ETS_TAG);
    ASSERT_NE(frameNode, nullptr);
    ASSERT_EQ(frameNode->GetTag(), V2::SAVE_BUTTON_ETS_TAG);

    auto pattern = frameNode->GetPattern<SecurityComponentPattern>();
    ASSERT_NE(pattern, nullptr);
    pattern->OnModifyDone();
    EXPECT_TRUE(pattern->isAppearCallback_);
    EXPECT_NE(pattern->clickListener_, nullptr);

    auto secCompGesture = frameNode->GetOrCreateGestureEventHub();
    ASSERT_NE(secCompGesture, nullptr);
    EXPECT_EQ(secCompGesture->GetHitTestMode(), HitTestMode::HTMDEFAULT);

    // modifydone again
    pattern->OnModifyDone();
    EXPECT_TRUE(pattern->isAppearCallback_);
    EXPECT_NE(pattern->clickListener_, nullptr);
}

/**
 * @tc.name: SecurityComponentSavePatternTest002
 * @tc.desc: Test event callback
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentSavePatternTest002, TestSize.Level1)
{
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::SAVE_BUTTON_ETS_TAG);
    ASSERT_NE(frameNode, nullptr);
    ASSERT_EQ(frameNode->GetTag(), V2::SAVE_BUTTON_ETS_TAG);

    auto pattern = frameNode->GetPattern<SecurityComponentPattern>();
    ASSERT_NE(pattern, nullptr);
    pattern->OnModifyDone();

    auto secCompGesture = frameNode->GetOrCreateGestureEventHub();
    ASSERT_NE(secCompGesture, nullptr);
    auto clickListener = secCompGesture->clickEventActuator_->clickEvents_.back();
    ASSERT_NE(clickListener, nullptr);
    ASSERT_NE(clickListener->callback_, nullptr);
    GestureEvent info;
    clickListener->callback_(info);

    auto eventHub = frameNode->GetEventHub<EventHub>();
    ASSERT_NE(eventHub, nullptr);
    ASSERT_NE(eventHub->onAppear_, nullptr);
    ASSERT_NE(eventHub->onDisappear_, nullptr);
    eventHub->onAppear_();
    eventHub->onDisappear_();
    ASSERT_EQ(pattern->scId_, -1);
}

/**
 * @tc.name: SecurityComponentSaveLayoutAlgoTest001
 * @tc.desc: Test default layout algo
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentSaveLayoutAlgoTest001, TestSize.Level1)
{
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::SAVE_BUTTON_ETS_TAG);
    ASSERT_NE(frameNode, nullptr);
    ASSERT_EQ(frameNode->GetTag(), V2::SAVE_BUTTON_ETS_TAG);
    auto pattern = frameNode->GetPattern<SecurityComponentPattern>();
    ASSERT_NE(pattern, nullptr);
    pattern->OnModifyDone();

    auto property = frameNode->GetLayoutProperty<SecurityComponentLayoutProperty>();
    ASSERT_NE(property, nullptr);
    property->UpdateMarginSelfIdealSize(SizeF(MIN_SIZE, MIN_SIZE));
    property->UpdateContentConstraint();

    auto layoutAlgo = pattern->CreateLayoutAlgorithm();
    ASSERT_NE(layoutAlgo, nullptr);

    auto layoutWrapper = CreateSecurityComponentLayoutWrapper(frameNode);
    ASSERT_NE(layoutWrapper, nullptr);
    layoutAlgo->Measure(layoutWrapper.rawPtr_);
    layoutAlgo->Layout(layoutWrapper.rawPtr_);
    EXPECT_EQ(layoutWrapper->geometryNode_->GetFrameSize().Height(), DEFAULT_ICON_MIN_SIZE);
    EXPECT_EQ(layoutWrapper->geometryNode_->GetFrameSize().Width(), DEFAULT_ICON_MIN_SIZE);

    property->UpdateBackgroundType(static_cast<int32_t>(ButtonType::CAPSULE));
    property->UpdateTextIconLayoutDirection(SecurityComponentLayoutDirection::VERTICAL);
    pattern->OnModifyDone();

    layoutAlgo->Measure(layoutWrapper.rawPtr_);
    layoutAlgo->Layout(layoutWrapper.rawPtr_);
    EXPECT_EQ(layoutWrapper->geometryNode_->GetFrameSize().Height(), DEFAULT_ICON_MIN_SIZE);
    EXPECT_EQ(layoutWrapper->geometryNode_->GetFrameSize().Width(), DEFAULT_ICON_MIN_SIZE);
}

/**
 * @tc.name: SecurityComponentSaveAccessibilityPropertyTest001
 * @tc.desc: Test security component accessibility property
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentSaveAccessibilityPropertyTest001, TestSize.Level1)
{
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::SAVE_BUTTON_ETS_TAG);
    ASSERT_NE(frameNode, nullptr);
    ASSERT_EQ(frameNode->GetTag(), V2::SAVE_BUTTON_ETS_TAG);
    auto pattern = frameNode->GetPattern<SecurityComponentPattern>();
    ASSERT_NE(pattern, nullptr);
    pattern->OnModifyDone();

    auto accessibility = pattern->CreateAccessibilityProperty();
    ASSERT_NE(accessibility, nullptr);
    accessibility->SetHost(frameNode);
}

/**
 * @tc.name: SecurityComponentPastePropertyTest001
 * @tc.desc: Test default properties of security component.
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentPastePropertyTest001, TestSize.Level1)
{
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0, static_cast<int32_t>(ButtonType::CAPSULE),
        V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(frameNode, nullptr);
    ASSERT_EQ(frameNode->GetTag(), V2::PASTE_BUTTON_ETS_TAG);

    CheckSecurityComponentDefaultProp(frameNode);

    // text node property
    auto textNode = GetSecCompChildNode(frameNode, V2::TEXT_ETS_TAG);
    ASSERT_NE(textNode, nullptr);
    auto textProp = textNode->GetLayoutProperty<TextLayoutProperty>();
    ASSERT_NE(textProp, nullptr);
    EXPECT_EQ(textProp->GetMaxLines().value_or(0), 1);
    EXPECT_EQ(textProp->GetFontSize().value_or(Dimension(0.0)).ConvertToVp(), DEFAULT_FONT_SIZE);
    EXPECT_EQ(textProp->GetItalicFontStyle().value_or(Ace::FontStyle::ITALIC), Ace::FontStyle::NORMAL);
    EXPECT_EQ(textProp->GetFontWeight().value_or(FontWeight::NORMAL), FontWeight::MEDIUM);
    std::vector<std::string> emptyVec;
    auto fontFamily = textProp->GetFontFamily().value_or(emptyVec);
    EXPECT_FALSE(fontFamily.empty());
    EXPECT_EQ(textProp->GetTextColor().value_or(Color()), Color::WHITE);

    // icon node property
    auto iconNode = GetSecCompChildNode(frameNode, V2::IMAGE_ETS_TAG);
    ASSERT_NE(iconNode, nullptr);
    auto iconProp = iconNode->GetLayoutProperty<ImageLayoutProperty>();
    ASSERT_NE(iconProp, nullptr);
    ImageSourceInfo iconSrc = iconProp->GetImageSourceInfo().value_or(ImageSourceInfo());
    EXPECT_EQ(iconSrc.GetFillColor().value_or(Color()), Color::WHITE);

    // button node property
    auto buttonNode = GetSecCompChildNode(frameNode, V2::BUTTON_ETS_TAG);
    ASSERT_NE(buttonNode, nullptr);
    auto buttonProp = buttonNode->GetLayoutProperty<ButtonLayoutProperty>();
    ASSERT_NE(buttonProp, nullptr);
    auto buttonRender = buttonNode->GetRenderContext();
    ASSERT_NE(buttonRender, nullptr);
    auto borderColor = buttonRender->GetBorderColor().value_or(BorderColorProperty());
    EXPECT_EQ(borderColor.leftColor.value_or(Color()), Color::RED);
    auto& widthProp = buttonProp->GetBorderWidthProperty();
    ASSERT_NE(widthProp, nullptr);
    EXPECT_EQ(widthProp->leftDimen.value_or(Dimension(0.0)).ConvertToVp(), DEFAULT_BORDER_WIDTH);
    auto borderStyle = buttonRender->GetBorderStyle().value_or(BorderStyleProperty());
    EXPECT_EQ(borderStyle.styleLeft.value_or(BorderStyle::SOLID), BorderStyle::NONE);

    EXPECT_EQ(buttonRender->GetBackgroundColor().value_or(Color()), Color::BLUE);
    EXPECT_EQ(buttonProp->GetType().value_or(ButtonType::NORMAL), ButtonType::CAPSULE);
}

/**
 * @tc.name: SecurityComponentPastePropertyTest002
 * @tc.desc: Test default properties of security component without background
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentPastePropertyTest002, TestSize.Level1)
{
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0,
        BUTTON_TYPE_NULL, V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(frameNode, nullptr);
    ASSERT_EQ(frameNode->GetTag(), V2::PASTE_BUTTON_ETS_TAG);

    auto property = frameNode->GetLayoutProperty<SecurityComponentLayoutProperty>();
    ASSERT_NE(property, nullptr);
    EXPECT_EQ(property->GetBackgroundType().value_or(static_cast<int32_t>(ButtonType::NORMAL)),
        BUTTON_TYPE_NULL);
    EXPECT_EQ(property->GetBackgroundLeftPadding().value_or(Dimension(0.0)).ConvertToVp(), DEFAULT_PADDING_WITHOUT_BG);
    EXPECT_EQ(property->GetBackgroundRightPadding().value_or(Dimension(0.0)).ConvertToVp(),
        DEFAULT_PADDING_WITHOUT_BG);
    EXPECT_EQ(property->GetBackgroundTopPadding().value_or(Dimension(0.0)).ConvertToVp(), DEFAULT_PADDING_WITHOUT_BG);
    EXPECT_EQ(property->GetBackgroundBottomPadding().value_or(Dimension(0.0)).ConvertToVp(),
        DEFAULT_PADDING_WITHOUT_BG);

    auto textNode = GetSecCompChildNode(frameNode, V2::TEXT_ETS_TAG);
    ASSERT_NE(textNode, nullptr);
    auto textProp = textNode->GetLayoutProperty<TextLayoutProperty>();
    ASSERT_NE(textProp, nullptr);
    EXPECT_EQ(textProp->GetTextColor().value_or(Color()), Color::BLACK);

    auto iconNode = GetSecCompChildNode(frameNode, V2::IMAGE_ETS_TAG);
    ASSERT_NE(iconNode, nullptr);
    auto iconProp = iconNode->GetLayoutProperty<ImageLayoutProperty>();
    ASSERT_NE(iconProp, nullptr);
    ImageSourceInfo iconSrc = iconProp->GetImageSourceInfo().value_or(ImageSourceInfo());
    EXPECT_EQ(iconSrc.GetFillColor().value_or(Color()), Color::BLUE);

    auto buttonNode = GetSecCompChildNode(frameNode, V2::BUTTON_ETS_TAG);
    ASSERT_NE(buttonNode, nullptr);
    auto buttonProp = buttonNode->GetLayoutProperty<ButtonLayoutProperty>();
    ASSERT_NE(buttonProp, nullptr);
    auto buttonRender = buttonNode->GetRenderContext();
    ASSERT_NE(buttonRender, nullptr);
    EXPECT_EQ(buttonRender->GetBackgroundColor().value_or(Color()), Color::TRANSPARENT);
    EXPECT_EQ(buttonProp->GetType().value_or(ButtonType::CAPSULE), ButtonType::NORMAL);
}

/**
 * @tc.name: SecurityComponentPastePropertyTest003
 * @tc.desc: Test default properties of security component without icon
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentPastePropertyTest003, TestSize.Level1)
{
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(1, -1,
        BUTTON_TYPE_NULL, V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(frameNode, nullptr);
    ASSERT_EQ(frameNode->GetTag(), V2::PASTE_BUTTON_ETS_TAG);

    auto property = frameNode->GetLayoutProperty<SecurityComponentLayoutProperty>();
    ASSERT_NE(property, nullptr);
    EXPECT_EQ(property->GetIconStyle().value_or(1), -1);
    EXPECT_EQ(property->GetTextIconSpace().value_or(Dimension(0.0)).ConvertToVp(), 0.0);

    auto iconNode = GetSecCompChildNode(frameNode, V2::IMAGE_ETS_TAG);
    ASSERT_EQ(iconNode, nullptr);
}

/**
 * @tc.name: SecurityComponentPastePropertyTest004
 * @tc.desc: Test set security component property
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentPastePropertyTest004, TestSize.Level1)
{
    CreateSecurityComponentNotFinish(0, 0, static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    SetPasteUserDefinedPropty();
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    ASSERT_NE(frameNode, nullptr);
    frameNode->MarkModifyDone();
    auto property = frameNode->GetLayoutProperty<SecurityComponentLayoutProperty>();
    ASSERT_NE(property, nullptr);
    EXPECT_EQ(property->GetTextIconSpace().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetBackgroundLeftPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetBackgroundRightPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetBackgroundTopPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetBackgroundBottomPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetTextIconLayoutDirection().value_or(SecurityComponentLayoutDirection::HORIZONTAL),
        SecurityComponentLayoutDirection::VERTICAL);

    auto iconNode = GetCurSecCompChildNode(V2::IMAGE_ETS_TAG);
    ASSERT_NE(iconNode, nullptr);
    auto iconProp = iconNode->GetLayoutProperty<ImageLayoutProperty>();
    ASSERT_NE(iconProp, nullptr);
    ImageSourceInfo iconSrc = iconProp->GetImageSourceInfo().value_or(ImageSourceInfo());
    EXPECT_EQ(iconSrc.GetFillColor().value_or(Color()), Color::RED);
    auto textNode = GetCurSecCompChildNode(V2::TEXT_ETS_TAG);
    ASSERT_NE(textNode, nullptr);
    auto textProp = textNode->GetLayoutProperty<TextLayoutProperty>();
    ASSERT_NE(textProp, nullptr);
    EXPECT_EQ(textProp->GetFontSize().value_or(Dimension(0.0)).ConvertToVp(), 15.0); // 15.0 vp
    EXPECT_EQ(textProp->GetItalicFontStyle().value_or(Ace::FontStyle::NORMAL), Ace::FontStyle::ITALIC);
    EXPECT_EQ(textProp->GetFontWeight().value_or(FontWeight::MEDIUM), FontWeight::BOLDER);
    std::vector<std::string> emptyVec;
    auto fontFamily = textProp->GetFontFamily().value_or(emptyVec);
    ASSERT_FALSE(fontFamily.empty());
    EXPECT_EQ(fontFamily[0], "testFont");
    EXPECT_EQ(textProp->GetTextColor().value_or(Color()), Color::GREEN);

    auto buttonNode = GetCurSecCompChildNode(V2::BUTTON_ETS_TAG);
    ASSERT_NE(buttonNode, nullptr);
    auto buttonProp = buttonNode->GetLayoutProperty<ButtonLayoutProperty>();
    ASSERT_NE(buttonProp, nullptr);
    auto buttonRender = buttonNode->GetRenderContext();
    ASSERT_NE(buttonRender, nullptr);
    auto borderColor = buttonRender->GetBorderColor().value_or(BorderColorProperty());
    EXPECT_EQ(borderColor.leftColor.value_or(Color()), Color::GREEN);
    auto& widthProp = buttonProp->GetBorderWidthProperty();
    ASSERT_NE(widthProp, nullptr);
    EXPECT_EQ(widthProp->leftDimen.value_or(Dimension(0.0)).ConvertToVp(), 15.0); // 15.0 vp
    auto borderStyle = buttonRender->GetBorderStyle().value_or(BorderStyleProperty());
    EXPECT_EQ(borderStyle.styleLeft.value_or(BorderStyle::SOLID), BorderStyle::DOTTED);
    EXPECT_EQ(buttonRender->GetBackgroundColor().value_or(Color()), Color::GRAY);
}

/**
 * @tc.name: SecurityComponentPastePropertyTest005
 * @tc.desc: Test set security component property
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentPastePropertyTest005, TestSize.Level1)
{
    CreateSecurityComponentNotFinish(0, 0, static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    SetPasteUserDefinedPropty();
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    ASSERT_NE(frameNode, nullptr);
    frameNode->MarkModifyDone();
    auto property = frameNode->GetLayoutProperty<SecurityComponentLayoutProperty>();
    ASSERT_NE(property, nullptr);
    EXPECT_EQ(property->GetTextIconSpace().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetBackgroundLeftPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetBackgroundRightPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetBackgroundTopPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetBackgroundBottomPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_EQ(property->GetTextIconLayoutDirection().value_or(SecurityComponentLayoutDirection::HORIZONTAL),
        SecurityComponentLayoutDirection::VERTICAL);

    auto iconNode = GetCurSecCompChildNode(V2::IMAGE_ETS_TAG);
    ASSERT_NE(iconNode, nullptr);
    auto iconProp = iconNode->GetLayoutProperty<ImageLayoutProperty>();
    ASSERT_NE(iconProp, nullptr);
    ImageSourceInfo iconSrc = iconProp->GetImageSourceInfo().value_or(ImageSourceInfo());
    EXPECT_EQ(iconSrc.GetFillColor().value_or(Color()), Color::RED);
    auto textNode = GetCurSecCompChildNode(V2::TEXT_ETS_TAG);
    ASSERT_NE(textNode, nullptr);
    auto textProp = textNode->GetLayoutProperty<TextLayoutProperty>();
    ASSERT_NE(textProp, nullptr);
    EXPECT_EQ(textProp->GetFontSize().value_or(Dimension(0.0)).ConvertToVp(), 15.0); // 15.0 vp
    EXPECT_EQ(textProp->GetItalicFontStyle().value_or(Ace::FontStyle::NORMAL), Ace::FontStyle::ITALIC);
    EXPECT_EQ(textProp->GetFontWeight().value_or(FontWeight::MEDIUM), FontWeight::BOLDER);
    std::vector<std::string> emptyVec;
    auto fontFamily = textProp->GetFontFamily().value_or(emptyVec);
    ASSERT_FALSE(fontFamily.empty());
    EXPECT_EQ(fontFamily[0], "testFont");
    EXPECT_EQ(textProp->GetTextColor().value_or(Color()), Color::GREEN);

    auto buttonNode = GetCurSecCompChildNode(V2::BUTTON_ETS_TAG);
    ASSERT_NE(buttonNode, nullptr);
    auto buttonProp = buttonNode->GetLayoutProperty<ButtonLayoutProperty>();
    ASSERT_NE(buttonProp, nullptr);
    auto buttonRender = buttonNode->GetRenderContext();
    ASSERT_NE(buttonRender, nullptr);
    auto borderColor = buttonRender->GetBorderColor().value_or(BorderColorProperty());
    EXPECT_EQ(borderColor.leftColor.value_or(Color()), Color::GREEN);
    auto& widthProp = buttonProp->GetBorderWidthProperty();
    ASSERT_NE(widthProp, nullptr);
    EXPECT_EQ(widthProp->leftDimen.value_or(Dimension(0.0)).ConvertToVp(), 15.0); // 15.0 vp
    auto borderStyle = buttonRender->GetBorderStyle().value_or(BorderStyleProperty());
    EXPECT_EQ(borderStyle.styleLeft.value_or(BorderStyle::SOLID), BorderStyle::DOTTED);
    EXPECT_EQ(buttonRender->GetBackgroundColor().value_or(Color()), Color::GRAY);
}

/**
 * @tc.name: SecurityComponentPastePropertyTest006
 * @tc.desc: Test set security component property without background
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentPastePropertyTest006, TestSize.Level1)
{
    CreateSecurityComponentNotFinish(0, 0, BUTTON_TYPE_NULL, V2::PASTE_BUTTON_ETS_TAG);
    PasteButtonModelNG pasteSc;
    pasteSc.SetBackgroundColor(Color::GRAY);
    pasteSc.SetBackgroundBorderWidth(Dimension(15.0)); // 15.0 vp
    pasteSc.SetBackgroundBorderColor(Color::GREEN);
    pasteSc.SetBackgroundBorderStyle(BorderStyle::DOTTED);
    pasteSc.SetBackgroundBorderRadius(Dimension(15.0)); // 15.0 vp
    pasteSc.SetBackgroundPadding(Dimension(25.0)); // 25.0 vp

    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    ASSERT_NE(frameNode, nullptr);
    auto property = frameNode->GetLayoutProperty<SecurityComponentLayoutProperty>();
    ASSERT_NE(property, nullptr);
    EXPECT_NE(property->GetBackgroundLeftPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_NE(property->GetBackgroundRightPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_NE(property->GetBackgroundTopPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp
    EXPECT_NE(property->GetBackgroundBottomPadding().value_or(Dimension(0.0)).ConvertToVp(), 25.0); // 25.0 vp

    auto buttonNode = GetCurSecCompChildNode(V2::BUTTON_ETS_TAG);
    ASSERT_NE(buttonNode, nullptr);
    auto buttonProp = buttonNode->GetLayoutProperty<ButtonLayoutProperty>();
    ASSERT_NE(buttonProp, nullptr);
    auto buttonRender = buttonNode->GetRenderContext();
    ASSERT_NE(buttonRender, nullptr);
    auto borderColor = buttonRender->GetBorderColor().value_or(BorderColorProperty());
    EXPECT_NE(borderColor.leftColor.value_or(Color()), Color::GREEN);
    auto& widthProp = buttonProp->GetBorderWidthProperty();
    ASSERT_EQ(widthProp, nullptr);
    auto borderStyle = buttonRender->GetBorderStyle().value_or(BorderStyleProperty());
    EXPECT_NE(borderStyle.styleLeft.value_or(BorderStyle::SOLID), BorderStyle::DOTTED);
}

/**
 * @tc.name: SecurityComponentPastePropertyTest007
 * @tc.desc: Test set security component property without icon
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentPastePropertyTest007, TestSize.Level1)
{
    CreateSecurityComponentNotFinish(1, -1, static_cast<int32_t>(ButtonType::CAPSULE),
        V2::PASTE_BUTTON_ETS_TAG);
    PasteButtonModelNG pasteSc;
    pasteSc.SetTextIconSpace(Dimension(15.0)); // 15.0vp

    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    ASSERT_NE(frameNode, nullptr);
    auto property = frameNode->GetLayoutProperty<SecurityComponentLayoutProperty>();
    ASSERT_NE(property, nullptr);
    EXPECT_EQ(property->GetTextIconSpace().value_or(Dimension(0.0)).ConvertToVp(), 0.0);
}

/**
 * @tc.name: SecurityComponentPastePatternTest001
 * @tc.desc: Test default security component modifyDone
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentPastePatternTest001, TestSize.Level1)
{
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(frameNode, nullptr);
    ASSERT_EQ(frameNode->GetTag(), V2::PASTE_BUTTON_ETS_TAG);

    auto pattern = frameNode->GetPattern<SecurityComponentPattern>();
    ASSERT_NE(pattern, nullptr);
    pattern->OnModifyDone();
    EXPECT_TRUE(pattern->isAppearCallback_);
    EXPECT_NE(pattern->clickListener_, nullptr);

    auto secCompGesture = frameNode->GetOrCreateGestureEventHub();
    ASSERT_NE(secCompGesture, nullptr);
    EXPECT_EQ(secCompGesture->GetHitTestMode(), HitTestMode::HTMDEFAULT);

    // modifydone again
    pattern->OnModifyDone();
    EXPECT_TRUE(pattern->isAppearCallback_);
    EXPECT_NE(pattern->clickListener_, nullptr);
}

/**
 * @tc.name: SecurityComponentPastePatternTest002
 * @tc.desc: Test event callback
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentPastePatternTest002, TestSize.Level1)
{
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(frameNode, nullptr);
    ASSERT_EQ(frameNode->GetTag(), V2::PASTE_BUTTON_ETS_TAG);

    auto pattern = frameNode->GetPattern<SecurityComponentPattern>();
    ASSERT_NE(pattern, nullptr);
    pattern->OnModifyDone();

    auto secCompGesture = frameNode->GetOrCreateGestureEventHub();
    ASSERT_NE(secCompGesture, nullptr);
    auto clickListener = secCompGesture->clickEventActuator_->clickEvents_.back();
    ASSERT_NE(clickListener, nullptr);
    ASSERT_NE(clickListener->callback_, nullptr);
    GestureEvent info;
    clickListener->callback_(info);

    auto eventHub = frameNode->GetEventHub<EventHub>();
    ASSERT_NE(eventHub, nullptr);
    ASSERT_NE(eventHub->onAppear_, nullptr);
    ASSERT_NE(eventHub->onDisappear_, nullptr);
    eventHub->onAppear_();
    eventHub->onDisappear_();
    ASSERT_EQ(pattern->scId_, -1);
}

/**
 * @tc.name: SecurityComponentPasteLayoutAlgoTest001
 * @tc.desc: Test default layout algo
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentPasteLayoutAlgoTest001, TestSize.Level1)
{
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(frameNode, nullptr);
    ASSERT_EQ(frameNode->GetTag(), V2::PASTE_BUTTON_ETS_TAG);
    auto pattern = frameNode->GetPattern<SecurityComponentPattern>();
    ASSERT_NE(pattern, nullptr);
    pattern->OnModifyDone();
    auto property = frameNode->GetLayoutProperty<SecurityComponentLayoutProperty>();
    ASSERT_NE(property, nullptr);
    property->UpdateMarginSelfIdealSize(SizeF(MIN_SIZE, MIN_SIZE));
    property->UpdateContentConstraint();

    auto layoutAlgo = pattern->CreateLayoutAlgorithm();
    ASSERT_NE(layoutAlgo, nullptr);

    auto layoutWrapper = CreateSecurityComponentLayoutWrapper(frameNode);
    ASSERT_NE(layoutWrapper, nullptr);
    layoutAlgo->Measure(layoutWrapper.rawPtr_);
    layoutAlgo->Layout(layoutWrapper.rawPtr_);
    EXPECT_EQ(layoutWrapper->geometryNode_->GetFrameSize().Height(), DEFAULT_ICON_MIN_SIZE);
    EXPECT_EQ(layoutWrapper->geometryNode_->GetFrameSize().Width(), DEFAULT_ICON_MIN_SIZE);
    property->UpdateBackgroundType(static_cast<int32_t>(ButtonType::CAPSULE));
    property->UpdateTextIconLayoutDirection(SecurityComponentLayoutDirection::VERTICAL);
    pattern->OnModifyDone();

    layoutAlgo->Measure(layoutWrapper.rawPtr_);
    layoutAlgo->Layout(layoutWrapper.rawPtr_);
    EXPECT_EQ(layoutWrapper->geometryNode_->GetFrameSize().Height(), DEFAULT_ICON_MIN_SIZE);
    EXPECT_EQ(layoutWrapper->geometryNode_->GetFrameSize().Width(), DEFAULT_ICON_MIN_SIZE);
}

/**
 * @tc.name: SecurityComponentPasteAccessibilityPropertyTest001
 * @tc.desc: Test security component accessibility property
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentPasteAccessibilityPropertyTest001, TestSize.Level1)
{
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(frameNode, nullptr);
    ASSERT_EQ(frameNode->GetTag(), V2::PASTE_BUTTON_ETS_TAG);
    auto pattern = frameNode->GetPattern<SecurityComponentPattern>();
    ASSERT_NE(pattern, nullptr);
    pattern->OnModifyDone();

    auto accessibility = pattern->CreateAccessibilityProperty();
    ASSERT_NE(accessibility, nullptr);
    accessibility->SetHost(frameNode);
}

/**
 * @tc.name: SecurityComponentGetIconResourceTest001
 * @tc.desc: Test set security component property with invalid icon
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentGetIconResourceTest001, TestSize.Level1)
{
    InternalResource::ResourceId id;
    EXPECT_FALSE(LocationButtonModelNG::GetInstance()->GetIconResource(-1, id));
    EXPECT_FALSE(LocationButtonModelNG::GetInstance()->GetIconResource(ICON_RESOURCE_TABLE + 1, id));
    EXPECT_FALSE(PasteButtonModelNG::GetInstance()->GetIconResource(-1, id));
    EXPECT_FALSE(PasteButtonModelNG::GetInstance()->GetIconResource(ICON_RESOURCE_TABLE + 1, id));
    EXPECT_FALSE(SaveButtonModelNG::GetInstance()->GetIconResource(-1, id));
    EXPECT_FALSE(SaveButtonModelNG::GetInstance()->GetIconResource(ICON_RESOURCE_TABLE + 1, id));
}

/**
 * @tc.name: SecurityComponentHandlerTest001
 * @tc.desc: Test security component handler
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentHandlerTest001, TestSize.Level1)
{
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    RefPtr<FrameNode> invalidFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), "test");
    int32_t scId;
    GestureEvent info;

    int32_t invalidId = -1;
    int32_t noExistId = 0;
    EXPECT_EQ(SecurityComponentHandler::RegisterSecurityComponent(invalidFrameNode, scId), -1);
    EXPECT_EQ(SecurityComponentHandler::UpdateSecurityComponent(invalidFrameNode, noExistId), -1);
    EXPECT_EQ(SecurityComponentHandler::UnregisterSecurityComponent(invalidId), -1);
    EXPECT_EQ(
        SecurityComponentHandler::ReportSecurityComponentClickEvent(invalidId, frameNode, info, [] (int32_t){}), -1);
    EXPECT_EQ(SecurityComponentHandler::ReportSecurityComponentClickEvent(
        noExistId, invalidFrameNode, info, [] (int32_t) {}), -1);

    KeyEvent key;
    EXPECT_EQ(SecurityComponentHandler::ReportSecurityComponentClickEvent(
        noExistId, invalidFrameNode, key, [] (int32_t) {}), -1);
    key.enhanceData = { 0 };
    EXPECT_EQ(SecurityComponentHandler::ReportSecurityComponentClickEvent(
        noExistId, invalidFrameNode, key, [] (int32_t) {}), -1);
}

/**
 * @tc.name: SecurityComponentHandlerTest002
 * @tc.desc: Test security component handler
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentHandlerTest002, TestSize.Level1)
{
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::SAVE_BUTTON_ETS_TAG);
    int32_t scId;
    GestureEvent info;

    int32_t noExistId = 0;
    ASSERT_EQ(SecurityComponentHandler::RegisterSecurityComponent(frameNode, scId), -1);
    ASSERT_EQ(SecurityComponentHandler::UpdateSecurityComponent(frameNode, noExistId), -1);
    ASSERT_EQ(SecurityComponentHandler::UnregisterSecurityComponent(noExistId), 0);
    ASSERT_EQ(SecurityComponentHandler::ReportSecurityComponentClickEvent(
        noExistId, frameNode, info, [] (int32_t) {}), -1);
}

/**
 * @tc.name: SecurityComponentHandlerTest003
 * @tc.desc: Test security component handler
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentHandlerTest003, TestSize.Level1)
{
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::LOCATION_BUTTON_ETS_TAG);
    int32_t scId;
    GestureEvent info;

    int32_t noExistId = 0;
    ASSERT_EQ(SecurityComponentHandler::RegisterSecurityComponent(frameNode, scId), -1);
    ASSERT_EQ(SecurityComponentHandler::UpdateSecurityComponent(frameNode, noExistId), -1);
    ASSERT_EQ(SecurityComponentHandler::UnregisterSecurityComponent(noExistId), 0);
    ASSERT_EQ(SecurityComponentHandler::ReportSecurityComponentClickEvent(
        noExistId, frameNode, info, [] (int32_t) {}), -1);
}

/**
 * @tc.name: SecurityComponentHandlerTest004
 * @tc.desc: Test security component handler
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentHandlerTest004, TestSize.Level1)
{
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    int32_t scId;
    GestureEvent info;

    int32_t noExistId = 0;
    ASSERT_EQ(SecurityComponentHandler::RegisterSecurityComponent(frameNode, scId), -1);
    ASSERT_EQ(SecurityComponentHandler::UpdateSecurityComponent(frameNode, noExistId), -1);
    ASSERT_EQ(SecurityComponentHandler::UnregisterSecurityComponent(noExistId), 0);
    ASSERT_EQ(SecurityComponentHandler::ReportSecurityComponentClickEvent(
        noExistId, frameNode, info, [] (int32_t) {}), -1);
}

/**
 * @tc.name: SecurityComponentCheckParentNodesEffectTest001
 * @tc.desc: Test security component CheckParentNodesEffect
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentCheckParentNodesEffectTest001, TestSize.Level1)
{
    RefPtr<FrameNode> parentFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(parentFrameNode, nullptr);
    RefPtr<FrameNode> childFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(childFrameNode, nullptr);
    parentFrameNode->AddChild(childFrameNode);

    // security component is not completely displayed
    ASSERT_FALSE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
    RefPtr<RenderContext> parentRenderContext = parentFrameNode->GetRenderContext();
    auto parentFrameRect = parentRenderContext->GetPaintRectWithTransform();
    RefPtr<RenderContext> childRenderContext = childFrameNode->GetRenderContext();
    auto childFrameRect = childRenderContext->GetPaintRectWithTransform();
    ASSERT_EQ(parentFrameRect.Width(), childFrameRect.Width());
    ASSERT_EQ(parentFrameRect.Height(), childFrameRect.Height());

    PixStretchEffectOption pixelStretchEffectOption;
    auto renderContext = parentFrameNode->GetRenderContext();
    ASSERT_NE(renderContext, nullptr);
    renderContext->UpdatePixelStretchEffect(pixelStretchEffectOption);
    ASSERT_TRUE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
}

/**
 * @tc.name: SecurityComponentCheckParentNodesEffectTest002
 * @tc.desc: Test security component CheckParentNodesEffect
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentCheckParentNodesEffectTest002, TestSize.Level1)
{
    RefPtr<FrameNode> parentFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(parentFrameNode, nullptr);
    RefPtr<FrameNode> childFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(childFrameNode, nullptr);
    parentFrameNode->AddChild(childFrameNode);

    auto renderContext = parentFrameNode->GetRenderContext();
    ASSERT_NE(renderContext, nullptr);
    renderContext->UpdateLightUpEffect(1);
    ASSERT_TRUE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
}

/**
 * @tc.name: SecurityComponentCheckParentNodesEffectTest003
 * @tc.desc: Test security component CheckParentNodesEffect
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentCheckParentNodesEffectTest003, TestSize.Level1)
{
    RefPtr<FrameNode> parentFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(parentFrameNode, nullptr);
    RefPtr<FrameNode> childFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(childFrameNode, nullptr);
    parentFrameNode->AddChild(childFrameNode);

    auto renderContext = parentFrameNode->GetRenderContext();
    ASSERT_NE(renderContext, nullptr);
    renderContext->UpdateSphericalEffect(0);
    ASSERT_FALSE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
    ASSERT_EQ(renderContext->GetSphericalEffect().value(), 0.0f);
    renderContext->UpdateSphericalEffect(1);
    ASSERT_TRUE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
}

/**
 * @tc.name: SecurityComponentCheckParentNodesEffectTest004
 * @tc.desc: Test security component CheckParentNodesEffect
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentCheckParentNodesEffectTest004, TestSize.Level1)
{
    RefPtr<FrameNode> parentFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(parentFrameNode, nullptr);
    RefPtr<FrameNode> childFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(childFrameNode, nullptr);
    parentFrameNode->AddChild(childFrameNode);

    auto renderContext = parentFrameNode->GetRenderContext();
    ASSERT_NE(renderContext, nullptr);
    renderContext->UpdateForegroundColor(Color::TRANSPARENT);
    ASSERT_FALSE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
    ASSERT_EQ(renderContext->GetForegroundColor().value(), Color::TRANSPARENT);
    renderContext->UpdateForegroundColor(Color::GRAY);
    ASSERT_TRUE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
}

/**
 * @tc.name: SecurityComponentCheckParentNodesEffectTest005
 * @tc.desc: Test security component CheckParentNodesEffect
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentCheckParentNodesEffectTest005, TestSize.Level1)
{
    RefPtr<FrameNode> parentFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(parentFrameNode, nullptr);
    RefPtr<FrameNode> childFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(childFrameNode, nullptr);
    parentFrameNode->AddChild(childFrameNode);

    auto renderContext = parentFrameNode->GetRenderContext();
    ASSERT_NE(renderContext, nullptr);
    RefPtr<BasicShape> basicShape;
    renderContext->UpdateClipMask(basicShape);
    ASSERT_TRUE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
}

/**
 * @tc.name: SecurityComponentCheckParentNodesEffectTest006
 * @tc.desc: Test security component CheckParentNodesEffect
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentCheckParentNodesEffectTest006, TestSize.Level1)
{
    RefPtr<FrameNode> parentFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(parentFrameNode, nullptr);
    RefPtr<FrameNode> childFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(childFrameNode, nullptr);
    parentFrameNode->AddChild(childFrameNode);

    auto renderContext = parentFrameNode->GetRenderContext();
    ASSERT_NE(renderContext, nullptr);
    renderContext->UpdateClipEdge(true);
    EXPECT_TRUE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));

    OffsetF invalidOffset(-100.0, -100.0);
    childFrameNode->geometryNode_->SetFrameOffset(invalidOffset);
    EXPECT_TRUE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
}

/**
 * @tc.name: SecurityComponentCheckParentNodesEffectTest007
 * @tc.desc: Test security component CheckParentNodesEffect
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentCheckParentNodesEffectTest007, TestSize.Level1)
{
    RefPtr<FrameNode> parentFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(parentFrameNode, nullptr);
    RefPtr<FrameNode> childFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(childFrameNode, nullptr);
    parentFrameNode->AddChild(childFrameNode);

    auto renderContext = parentFrameNode->GetRenderContext();
    ASSERT_NE(renderContext, nullptr);
    renderContext->UpdateFrontColorBlend(Color::TRANSPARENT);
    ASSERT_FALSE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
    ASSERT_EQ(renderContext->GetFrontColorBlend().value(), Color::TRANSPARENT);
    renderContext->UpdateFrontColorBlend(Color::GRAY);
    ASSERT_TRUE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
}

/**
 * @tc.name: SecurityComponentCheckParentNodesEffectTest008
 * @tc.desc: Test security component CheckParentNodesEffect
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentCheckParentNodesEffectTest008, TestSize.Level1)
{
    RefPtr<FrameNode> parentFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(parentFrameNode, nullptr);
    RefPtr<FrameNode> childFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(childFrameNode, nullptr);
    parentFrameNode->AddChild(childFrameNode);

    auto renderContext = parentFrameNode->GetRenderContext();
    ASSERT_NE(renderContext, nullptr);
    renderContext->UpdateFrontHueRotate(0);
    ASSERT_FALSE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
    ASSERT_EQ(renderContext->GetFrontHueRotate().value(), 0.0f);
    renderContext->UpdateFrontHueRotate(MAX_ROTATE);
    ASSERT_FALSE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
    ASSERT_EQ(renderContext->GetFrontHueRotate().value(), MAX_ROTATE);
    renderContext->UpdateFrontHueRotate(1);
    ASSERT_TRUE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
}

/**
 * @tc.name: SecurityComponentCheckParentNodesEffectTest009
 * @tc.desc: Test security component CheckParentNodesEffect
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentCheckParentNodesEffectTest009, TestSize.Level1)
{
    RefPtr<FrameNode> parentFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(parentFrameNode, nullptr);
    RefPtr<FrameNode> childFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(childFrameNode, nullptr);
    parentFrameNode->AddChild(childFrameNode);

    auto renderContext = parentFrameNode->GetRenderContext();
    ASSERT_NE(renderContext, nullptr);
    renderContext->UpdateFrontSepia(0.0_vp);
    ASSERT_FALSE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
    ASSERT_EQ(renderContext->GetFrontSepia().value().ConvertToVp(), 0.0f);
    renderContext->UpdateFrontSepia(1.0_vp);
    ASSERT_TRUE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
}

/**
 * @tc.name: SecurityComponentCheckParentNodesEffectTest010
 * @tc.desc: Test security component CheckParentNodesEffect
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentCheckParentNodesEffectTest010, TestSize.Level1)
{
    RefPtr<FrameNode> parentFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(parentFrameNode, nullptr);
    RefPtr<FrameNode> childFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(childFrameNode, nullptr);
    parentFrameNode->AddChild(childFrameNode);

    auto renderContext = parentFrameNode->GetRenderContext();
    ASSERT_NE(renderContext, nullptr);
    InvertVariant invert = 0.0f;
    renderContext->UpdateFrontInvert(invert);
    ASSERT_FALSE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
    ASSERT_EQ(renderContext->GetFrontInvert().value(), InvertVariant(0.0f));
    invert = 1.0f; // 1.0 means have frontinvert
    renderContext->UpdateFrontInvert(invert);
    ASSERT_TRUE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
}

/**
 * @tc.name: SecurityComponentCheckParentNodesEffectTest011
 * @tc.desc: Test security component CheckParentNodesEffect
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentCheckParentNodesEffectTest011, TestSize.Level1)
{
    RefPtr<FrameNode> parentFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(parentFrameNode, nullptr);
    RefPtr<FrameNode> childFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(childFrameNode, nullptr);
    parentFrameNode->AddChild(childFrameNode);

    auto renderContext = parentFrameNode->GetRenderContext();
    ASSERT_NE(renderContext, nullptr);
    renderContext->UpdateFrontContrast(1.0_vp);
    ASSERT_FALSE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
    ASSERT_EQ(renderContext->GetFrontContrast().value().ConvertToVp(), 1.0f);
    renderContext->UpdateFrontContrast(2.0_vp);
    ASSERT_TRUE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
}

/**
 * @tc.name: SecurityComponentCheckParentNodesEffectTest012
 * @tc.desc: Test security component CheckParentNodesEffect
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentCheckParentNodesEffectTest012, TestSize.Level1)
{
    RefPtr<FrameNode> parentFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(parentFrameNode, nullptr);
    RefPtr<FrameNode> childFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(childFrameNode, nullptr);
    parentFrameNode->AddChild(childFrameNode);

    auto renderContext = parentFrameNode->GetRenderContext();
    ASSERT_NE(renderContext, nullptr);
    renderContext->UpdateFrontSaturate(1.0_vp);
    ASSERT_FALSE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
    ASSERT_EQ(renderContext->GetFrontSaturate().value().ConvertToVp(), 1.0f);
    renderContext->UpdateFrontSaturate(2.0_vp);
    ASSERT_TRUE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
}

/**
 * @tc.name: SecurityComponentCheckParentNodesEffectTest013
 * @tc.desc: Test security component CheckParentNodesEffect
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentCheckParentNodesEffectTest013, TestSize.Level1)
{
    RefPtr<FrameNode> parentFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(parentFrameNode, nullptr);
    RefPtr<FrameNode> childFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(childFrameNode, nullptr);
    parentFrameNode->AddChild(childFrameNode);

    auto renderContext = parentFrameNode->GetRenderContext();
    ASSERT_NE(renderContext, nullptr);
    renderContext->UpdateFrontGrayScale(0.0_vp);
    ASSERT_FALSE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
    ASSERT_EQ(renderContext->GetFrontGrayScale().value().ConvertToVp(), 0.0f);
    renderContext->UpdateFrontGrayScale(1.0_vp);
    ASSERT_TRUE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
}

/**
 * @tc.name: SecurityComponentCheckParentNodesEffectTest014
 * @tc.desc: Test security component CheckParentNodesEffect
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentCheckParentNodesEffectTest014, TestSize.Level1)
{
    RefPtr<FrameNode> parentFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(parentFrameNode, nullptr);
    RefPtr<FrameNode> childFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(childFrameNode, nullptr);
    parentFrameNode->AddChild(childFrameNode);

    auto renderContext = parentFrameNode->GetRenderContext();
    ASSERT_NE(renderContext, nullptr);
    renderContext->UpdateFrontBlurRadius(0.0_px);
    ASSERT_FALSE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
}

/**
 * @tc.name: SecurityComponentCheckParentNodesEffectTest015
 * @tc.desc: Test security component CheckParentNodesEffect
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentCheckParentNodesEffectTest015, TestSize.Level1)
{
    RefPtr<FrameNode> parentFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(parentFrameNode, nullptr);
    RefPtr<FrameNode> childFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(childFrameNode, nullptr);
    parentFrameNode->AddChild(childFrameNode);

    auto property = parentFrameNode->GetLayoutProperty<SecurityComponentLayoutProperty>();
    ASSERT_NE(property, nullptr);
    property->UpdateVisibility(VisibleType::VISIBLE);
    ASSERT_FALSE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
    ASSERT_EQ(property->GetVisibility().value(), VisibleType::VISIBLE);
    property->UpdateVisibility(VisibleType::INVISIBLE);
    ASSERT_TRUE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
}

/**
 * @tc.name: SecurityComponentCheckParentNodesEffectTest016
 * @tc.desc: Test security component CheckParentNodesEffect
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentCheckParentNodesEffectTest016, TestSize.Level1)
{
    RefPtr<FrameNode> parentFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(parentFrameNode, nullptr);
    RefPtr<FrameNode> childFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(childFrameNode, nullptr);
    parentFrameNode->AddChild(childFrameNode);

    auto renderContext = parentFrameNode->GetRenderContext();
    ASSERT_NE(renderContext, nullptr);
    renderContext->UpdateFrontBrightness(1.0_vp);
    ASSERT_FALSE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
    ASSERT_EQ(renderContext->GetFrontBrightness().value().ConvertToVp(), 1.0f);
    renderContext->UpdateFrontBrightness(2.0_vp);
    ASSERT_TRUE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
}

/**
 * @tc.name: SecurityComponentCheckParentNodesEffectTest017
 * @tc.desc: Test security component CheckParentNodesEffect
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentCheckParentNodesEffectTest017, TestSize.Level1)
{
    RefPtr<FrameNode> parentFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(parentFrameNode, nullptr);
    RefPtr<FrameNode> childFrameNode = CreateSecurityComponent(0, 0,
        static_cast<int32_t>(ButtonType::CAPSULE), V2::PASTE_BUTTON_ETS_TAG);
    ASSERT_NE(childFrameNode, nullptr);
    parentFrameNode->AddChild(childFrameNode);

    auto renderContext = parentFrameNode->GetRenderContext();
    ASSERT_NE(renderContext, nullptr);
    renderContext->UpdateOpacity(1);
    EXPECT_FALSE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
    EXPECT_EQ(renderContext->GetOpacity().value(), 1.0f);
    renderContext->UpdateOpacity(2);
    EXPECT_TRUE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));

    parentFrameNode->tag_ = V2::MENU_WRAPPER_ETS_TAG;
    EXPECT_FALSE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));

    // parent is not FrameNode
    RefPtr<TestNode> unFrameNode = AceType::MakeRefPtr<TestNode>(0);
    unFrameNode->AddChild(childFrameNode);
    EXPECT_FALSE(SecurityComponentHandler::CheckParentNodesEffect(childFrameNode));
}

/**
 * @tc.name: SecurityComponentCalculateCurrentVisibleRatio001
 * @tc.desc: Test security component CalculateCurrentVisibleRatio
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentCalculateCurrentVisibleRatio001, TestSize.Level1)
{
    RectF invalidRect(-1.0, -1.0, -1.0, -1.0);
    RectF validRect(1.0, 1.0, 1.0, 1.0);
    EXPECT_EQ(SecurityComponentHandler::CalculateCurrentVisibleRatio(invalidRect, validRect), 0.0);
    EXPECT_EQ(SecurityComponentHandler::CalculateCurrentVisibleRatio(validRect, invalidRect), 0.0);
}

/**
 * @tc.name: SecurityComponentInitChildInfo001
 * @tc.desc: Test security component InitChildInfo
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentInitChildInfo001, TestSize.Level1)
{
    RefPtr<SecurityComponentPattern> pattern =
        AceType::MakeRefPtr<SecurityComponentPattern>();
    RefPtr<FrameNode> node = AceType::MakeRefPtr<FrameNode>(V2::LOCATION_BUTTON_ETS_TAG, 1, pattern, false);
    OHOS::Security::SecurityComponent::SecCompBase buttonInfo;
    EXPECT_FALSE(SecurityComponentHandler::InitChildInfo(buttonInfo, node));
}

/**
 * @tc.name: SecurityComponentInitButtonInfo001
 * @tc.desc: Test security component InitButtonInfo
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentInitButtonInfo001, TestSize.Level1)
{
    RefPtr<SecurityComponentPattern> pattern =
        AceType::MakeRefPtr<SecurityComponentPattern>();
    RefPtr<FrameNode> node = AceType::MakeRefPtr<FrameNode>(V2::MENU_WRAPPER_ETS_TAG, 1, pattern, false);
    std::string compInfo;
    Security::SecurityComponent::SecCompType type;
    EXPECT_FALSE(SecurityComponentHandler::InitButtonInfo(compInfo, node, type));
}

/**
 * @tc.name: PasteButtonModelNGCreateNode001
 * @tc.desc: Test paste button create Node
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, PasteButtonModelNGCreateNode001, TestSize.Level1)
{
    auto frameNode = PasteButtonModelNG::GetInstance()->CreateNode(0, 0, 0);
    ASSERT_NE(frameNode, nullptr);
}

/**
 * @tc.name: PasteButtonModelNGGetTextResource001
 * @tc.desc: Test paste button get text resource failed
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, PasteButtonModelNGGetTextResource001, TestSize.Level1)
{
    auto scTheme = MockPipelineContext::GetCurrent()->GetThemeManager();
    MockPipelineContext::GetCurrent()->SetThemeManager(nullptr);
    std::string text;
    EXPECT_FALSE(PasteButtonModelNG::GetInstance()->GetTextResource(0, text));
    MockPipelineContext::GetCurrent()->SetThemeManager(scTheme);
}

/**
 * @tc.name: LocationButtonModelNGGetTextResource001
 * @tc.desc: Test location button get text resource failed
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, LocationButtonModelNGGetTextResource001, TestSize.Level1)
{
    auto scTheme = MockPipelineContext::GetCurrent()->GetThemeManager();
    MockPipelineContext::GetCurrent()->SetThemeManager(nullptr);
    std::string text;
    EXPECT_FALSE(LocationButtonModelNG::GetInstance()->GetTextResource(0, text));
    MockPipelineContext::GetCurrent()->SetThemeManager(scTheme);
}

/**
 * @tc.name: SaveButtonModelNGGetTextResource001
 * @tc.desc: Test save button get text resource failed
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SaveButtonModelNGGetTextResource001, TestSize.Level1)
{
    auto scTheme = MockPipelineContext::GetCurrent()->GetThemeManager();
    MockPipelineContext::GetCurrent()->SetThemeManager(nullptr);
    std::string text;
    EXPECT_FALSE(SaveButtonModelNG::GetInstance()->GetTextResource(0, text));
    MockPipelineContext::GetCurrent()->SetThemeManager(scTheme);
}

/**
 * @tc.name: SecurityComponentProbeInitProbeTask001
 * @tc.desc: Test security component probe init task
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentProbeInitProbeTask001, TestSize.Level1)
{
    SecurityComponentProbe probe;
    std::string compInfo;
    // not init
    ASSERT_EQ(probe.GetComponentInfo(0, compInfo), -1);

    // init twice
    probe.InitProbeTask();
    probe.InitProbeTask();
    ASSERT_TRUE(probe.taskExec_.has_value());
    auto pipeline = PipelineBase::GetCurrentContext();
    ASSERT_NE(pipeline, nullptr);
    pipeline->taskExecutor_ = AceType::MakeRefPtr<MockTaskExecutor>();

    ASSERT_EQ(probe.GetComponentInfo(1001, compInfo), 0);
}

/**
 * @tc.name: SecurityComponentLayoutElementIconElement001
 * @tc.desc: Test security component icon element
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLayoutElementIconElement001, TestSize.Level1)
{
    IconLayoutElement icon;
    icon.isExist_ = false;
    icon.DoMeasure();
    ASSERT_EQ(icon.ShrinkWidth(0.0), 0.0);
    ASSERT_EQ(icon.ShrinkHeight(0.0), 0.0);

    icon.isExist_ = true;
    icon.isSetSize_ = true;
    ASSERT_EQ(icon.ShrinkWidth(0.0), 0.0);
    ASSERT_EQ(icon.ShrinkHeight(0.0), 0.0);

    icon.isSetSize_ = false;
    icon.minIconSize_ = 0.0;
    icon.width_ = 2.0;
    icon.height_ = 2.0;
    ASSERT_EQ(icon.ShrinkWidth(1.0), 0.0);
    ASSERT_EQ(icon.ShrinkHeight(1.0), 0.0);
}

/**
 * @tc.name: SecurityComponentLayoutElementTextElement001
 * @tc.desc: Test security component text element
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLayoutElementTextElement001, TestSize.Level1)
{
    TextLayoutElement text;
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0,
        BUTTON_TYPE_NULL, V2::LOCATION_BUTTON_ETS_TAG);
    ASSERT_NE(frameNode, nullptr);
    RefPtr<SecurityComponentLayoutProperty> property =
        AceType::MakeRefPtr<SecurityComponentLayoutProperty>();
    RefPtr<TextLayoutProperty> textProp = AceType::MakeRefPtr<TextLayoutProperty>();
    RefPtr<GeometryNode> geoNode = AceType::MakeRefPtr<GeometryNode>();
    RefPtr<LayoutWrapper> wrapper =
        AceType::MakeRefPtr<LayoutWrapperNode>(frameNode, geoNode, textProp);
    property->UpdateSecurityComponentDescription(-1);
    text.Init(property, wrapper);
    ASSERT_FALSE(text.isExist_);
    property->UpdateSecurityComponentDescription(0);
    property->UpdateFontSize(Dimension(2.0));
    text.Init(property, wrapper);
    ASSERT_TRUE(text.isExist_);
    ASSERT_TRUE(text.isSetSize_);

    RefPtr<TextLayoutProperty> textProperty =
        AceType::MakeRefPtr<TextLayoutProperty>();
    text.minTextSize_ = SizeF(1.0, 1.0);
    text.ChooseExactFontSize(textProperty, true);
    text.isExist_ = false;
    ASSERT_EQ(text.ShrinkWidth(0.0), 0.0);
    ASSERT_EQ(text.ShrinkHeight(0.0), 0.0);
    text.isExist_ = true;
    text.isSetSize_ = true;
    ASSERT_EQ(text.ShrinkWidth(0.0), 0.0);
    ASSERT_EQ(text.ShrinkHeight(0.0), 0.0);
}

/**
 * @tc.name: SecurityComponentPatternOnDirtyLayoutWrapperSwap001
 * @tc.desc: Test security component OnDirtyLayoutWrapperSwap
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentPatternOnDirtyLayoutWrapperSwap001, TestSize.Level1)
{
    SecurityComponentPattern pattern;
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0,
        BUTTON_TYPE_NULL, V2::LOCATION_BUTTON_ETS_TAG);
    ASSERT_NE(frameNode, nullptr);
    RefPtr<SecurityComponentLayoutProperty> prop = AceType::MakeRefPtr<SecurityComponentLayoutProperty>();
    RefPtr<GeometryNode> geoNode = AceType::MakeRefPtr<GeometryNode>();
    RefPtr<LayoutWrapperNode> wrapper =
        AceType::MakeRefPtr<LayoutWrapperNode>(frameNode, geoNode, prop);
    DirtySwapConfig config;
    config.skipMeasure = true;
    ASSERT_FALSE(pattern.OnDirtyLayoutWrapperSwap(wrapper, config));
    config.skipMeasure = false;
    wrapper->skipMeasureContent_ = true;
    ASSERT_FALSE(pattern.OnDirtyLayoutWrapperSwap(wrapper, config));

    RefPtr<LayoutAlgorithmWrapper> layoutWrapper =
        AceType::MakeRefPtr<LayoutAlgorithmWrapper>(AceType::MakeRefPtr<SecurityComponentLayoutAlgorithm>());
    wrapper->SetLayoutAlgorithm(layoutWrapper);
    config.skipMeasure = false;
    wrapper->skipMeasureContent_ = false;
    ASSERT_TRUE(pattern.OnDirtyLayoutWrapperSwap(wrapper, config));
}

/**
 * @tc.name: SecurityComponentPatternOnKeyEvent001
 * @tc.desc: Test security component OnKeyEvent
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentPatternOnKeyEvent001, TestSize.Level1)
{
    SecurityComponentPattern pattern;
    KeyEvent event;
    event.action = KeyAction::UP;
    ASSERT_FALSE(pattern.OnKeyEvent(event));

    event.action = KeyAction::DOWN;
    event.code = KeyCode::KEY_CALL;
    ASSERT_FALSE(pattern.OnKeyEvent(event));

    // frameNode is null
    event.code = KeyCode::KEY_SPACE;
    ASSERT_FALSE(pattern.OnKeyEvent(event));

    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0,
        BUTTON_TYPE_NULL, V2::LOCATION_BUTTON_ETS_TAG);
    ASSERT_NE(frameNode, nullptr);
    pattern.frameNode_ = frameNode;
    ASSERT_TRUE(pattern.OnKeyEvent(event));
}

/**
 * @tc.name: SecurityComponentPatternInitOnKeyEvent001
 * @tc.desc: Test security component InitOnKeyEvent
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentPatternInitOnKeyEvent001, TestSize.Level1)
{
    SecurityComponentPattern pattern;
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0,
        BUTTON_TYPE_NULL, V2::LOCATION_BUTTON_ETS_TAG);
    pattern.InitOnKeyEvent(frameNode);
    auto focusHub = frameNode->GetOrCreateFocusHub();
    KeyEvent event;
    focusHub->ProcessOnKeyEventInternal(event);
    ASSERT_TRUE(pattern.isSetOnKeyEvent);
}

/**
 * @tc.name: SecurityComponentPatternIsParentMenu001
 * @tc.desc: Test security component IsParentMenu
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentPatternIsParentMenu001, TestSize.Level1)
{
    RefPtr<SecurityComponentPattern> pattern = AceType::MakeRefPtr<SecurityComponentPattern>();
    auto menuNode = AceType::MakeRefPtr<FrameNode>(V2::MENU_WRAPPER_ETS_TAG, 1, pattern, false);
    auto locationButton = AceType::MakeRefPtr<FrameNode>(V2::LOCATION_BUTTON_ETS_TAG, 1, pattern, false);
    auto text = AceType::MakeRefPtr<FrameNode>(V2::TEXT_ETS_TAG, 1, pattern, false);

    locationButton->SetParent(text);
    ASSERT_FALSE(pattern->IsParentMenu(locationButton));

    text->SetParent(menuNode);
    ASSERT_TRUE(pattern->IsParentMenu(locationButton));
}

/**
 * @tc.name: SecurityComponentPatternOnTouch001
 * @tc.desc: Test security component OnTouch
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentPatternOnTouch001, TestSize.Level1)
{
    // DOWN
    TouchLocationInfo locationInfo(0);
    locationInfo.SetTouchType(TouchType::DOWN);
    Offset offset(1.0, 1.0);
    locationInfo.SetLocalLocation(offset);
    TouchEventInfo info("");
    info.AddTouchLocationInfo(std::move(locationInfo));
    SecurityComponentPattern pattern;
    pattern.OnTouch(info);
    ASSERT_NE(pattern.lastTouchOffset_, nullptr);

    // UP
    TouchLocationInfo locationInfo1(0);
    locationInfo1.SetTouchType(TouchType::UP);
    Offset offset1(1.0, 1.0);
    locationInfo1.SetLocalLocation(offset1);
    TouchEventInfo info1("");
    info1.AddTouchLocationInfo(std::move(locationInfo1));
    pattern.OnTouch(info1);
    ASSERT_EQ(pattern.lastTouchOffset_, nullptr);

    // OTHERS
    TouchLocationInfo locationInfo2(0);
    locationInfo2.SetTouchType(TouchType::PULL_DOWN);
    Offset offset2(1.0, 1.0);
    locationInfo2.SetLocalLocation(offset2);
    TouchEventInfo info2("");
    info2.AddTouchLocationInfo(std::move(locationInfo2));
    pattern.OnTouch(info2);
    ASSERT_EQ(pattern.lastTouchOffset_, nullptr);
}

/**
 * @tc.name: SecurityComponentPatternOnTouch002
 * @tc.desc: Test security component OnTouch
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentPatternOnTouch002, TestSize.Level1)
{
    // DOWN
    TouchLocationInfo locationInfo(0);
    locationInfo.SetTouchType(TouchType::DOWN);
    Offset offset(1.0, 1.0);
    locationInfo.SetLocalLocation(offset);
    TouchEventInfo info("");
    info.AddTouchLocationInfo(std::move(locationInfo));
    SecurityComponentPattern pattern;
    pattern.OnTouch(info);
    ASSERT_NE(pattern.lastTouchOffset_, nullptr);

    // UP other location
    TouchLocationInfo locationInfo1(0);
    locationInfo1.SetTouchType(TouchType::UP);
    Offset offset1(100.0, 100.0);
    locationInfo1.SetLocalLocation(offset1);
    TouchEventInfo info1("");
    info1.AddTouchLocationInfo(std::move(locationInfo1));
    pattern.OnTouch(info1);
    ASSERT_EQ(pattern.lastTouchOffset_, nullptr);
}

/**
 * @tc.name: SecurityComponentPatternInitOnTouchEvent001
 * @tc.desc: Test security component InitOnTouch
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentPatternInitOnTouchEvent001, TestSize.Level1)
{
    SecurityComponentPattern pattern;
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0,
        BUTTON_TYPE_NULL, V2::LOCATION_BUTTON_ETS_TAG);
    pattern.InitOnTouch(frameNode);
    auto gestureHub = frameNode->GetOrCreateGestureEventHub();

    TouchLocationInfo locationInfo(0);
    locationInfo.SetTouchType(TouchType::DOWN);
    Offset offset(1.0, 1.0);
    locationInfo.SetLocalLocation(offset);
    TouchEventInfo touch("");
    touch.AddTouchLocationInfo(std::move(locationInfo));
    ASSERT_TRUE(gestureHub->touchEventActuator_ != nullptr);
    ASSERT_TRUE(gestureHub->touchEventActuator_->touchEvents_.size() > 0);
    auto impl = gestureHub->touchEventActuator_->touchEvents_.front()->callback_;
    impl(touch);
    ASSERT_NE(pattern.onTouchListener_, nullptr);
}

/**
 * @tc.name: SecurityComponentPatternToJsonValue001
 * @tc.desc: Test security component without bg ToJsonValue
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentPatternToJsonValue001, TestSize.Level1)
{
    SecurityComponentPattern pattern;
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0,
        BUTTON_TYPE_NULL, V2::LOCATION_BUTTON_ETS_TAG);
    pattern.frameNode_ = frameNode;
    auto jsonNode = JsonUtil::Create(true);
    pattern.ToJsonValue(jsonNode, filter);
    ASSERT_EQ(jsonNode->GetString("type", ""), V2::LOCATION_BUTTON_ETS_TAG);
}

/**
 * @tc.name: SecurityComponentPatternToJsonValue002
 * @tc.desc: Test security component without text ToJsonValue
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentPatternToJsonValue002, TestSize.Level1)
{
    SecurityComponentPattern pattern;
    RefPtr<FrameNode> frameNode =
        CreateSecurityComponent(static_cast<int32_t>(SecurityComponentDescription::TEXT_NULL),
        0, 0, V2::LOCATION_BUTTON_ETS_TAG);
    pattern.frameNode_ = frameNode;
    auto jsonNode = JsonUtil::Create(true);
    pattern.ToJsonValue(jsonNode, filter);
    ASSERT_EQ(jsonNode->GetString("type", ""), V2::LOCATION_BUTTON_ETS_TAG);
}

/**
 * @tc.name: SecurityComponentPatternToJsonValue003
 * @tc.desc: Test security component without icon ToJsonValue
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentPatternToJsonValue003, TestSize.Level1)
{
    SecurityComponentPattern pattern;
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0,
        static_cast<int32_t>(SecurityComponentIconStyle::ICON_NULL),
        0, V2::LOCATION_BUTTON_ETS_TAG);
    pattern.frameNode_ = frameNode;
    auto jsonNode = JsonUtil::Create(true);
    pattern.ToJsonValue(jsonNode, filter);
    ASSERT_EQ(jsonNode->GetString("type", ""), V2::LOCATION_BUTTON_ETS_TAG);
}

/**
 * @tc.name: SecurityComponentLayoutAlgorithmGetChildWrapper001
 * @tc.desc: Test security component GetChildWrapper no exist child
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLayoutAlgorithmGetChildWrapper001, TestSize.Level1)
{
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0,
        0, V2::LOCATION_BUTTON_ETS_TAG);
    ASSERT_NE(frameNode, nullptr);
    auto buttonWrapper = CreateLayoutWrapper(frameNode);
    buttonWrapper->currentChildCount_ = 1;
    buttonWrapper->layoutWrapperBuilder_ = nullptr;
    auto buttonAlgorithm = AceType::MakeRefPtr<SecurityComponentLayoutAlgorithm>();
    ASSERT_NE(buttonAlgorithm, nullptr);
    ASSERT_EQ(buttonAlgorithm->GetChildWrapper(&*buttonWrapper, ""), nullptr);
}

/**
 * @tc.name: SecurityComponentLayoutAlgorithmUpdateChildPosition001
 * @tc.desc: Test security component UpdateChildPosition
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLayoutAlgorithmUpdateChildPosition001, TestSize.Level1)
{
    RefPtr<FrameNode> frameNode = CreateSecurityComponent(0, 0,
        0, V2::LOCATION_BUTTON_ETS_TAG);
    ASSERT_NE(frameNode, nullptr);
    auto layoutWrapper = CreateLayoutWrapper(frameNode);
    auto textNode = FrameNode::CreateFrameNode(
        V2::TEXT_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<TextPattern>());
    auto textGeometryNode = textNode->geometryNode_;
    auto textLayoutProperty = textNode->GetLayoutProperty<TextLayoutProperty>();
    auto textWrapper = AceType::MakeRefPtr<LayoutWrapperNode>(
        AceType::WeakClaim(AceType::RawPtr(textNode)), textGeometryNode, textLayoutProperty);
    layoutWrapper->childrenMap_[0] = textWrapper;
    layoutWrapper->currentChildCount_ = 1;

    auto buttonAlgorithm = AceType::MakeRefPtr<SecurityComponentLayoutAlgorithm>();
    ASSERT_NE(buttonAlgorithm, nullptr);
    OffsetF offset(1.0, 0.0);
    buttonAlgorithm->UpdateChildPosition(&*layoutWrapper, V2::TEXT_ETS_TAG, offset);

    ASSERT_EQ(textGeometryNode->GetMarginFrameOffset().GetX(), 1.0);
}

/**
 * @tc.name: SecurityComponentLayoutAlgorithmShrinkWidth001
 * @tc.desc: Test security component ShrinkWidth, shrink left and right padding
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLayoutAlgorithmShrinkWidth001, TestSize.Level1)
{
    auto buttonAlgorithm = AceType::MakeRefPtr<SecurityComponentLayoutAlgorithm>();
    ASSERT_NE(buttonAlgorithm, nullptr);
    buttonAlgorithm->left_ = PaddingLayoutElement();
    buttonAlgorithm->left_.Init(false, false, 4.0, 0.0); // left padding 4.0, minsize 0.0
    buttonAlgorithm->right_ = PaddingLayoutElement();
    buttonAlgorithm->right_.Init(false, false, 4.0, 0.0); // right_ padding 4.0, minsize 0.0
    // shrink 2.0px, left to 3.0, right to 3.0, total 6.0
    ASSERT_EQ(buttonAlgorithm->ShrinkWidth(2.0), 6.0);
    ASSERT_EQ(buttonAlgorithm->left_.width_, 3.0);
    ASSERT_EQ(buttonAlgorithm->right_.width_, 3.0);
}

/**
 * @tc.name: SecurityComponentLayoutAlgorithmShrinkWidth002
 * @tc.desc: Test security component ShrinkWidth, shrink middle padding
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLayoutAlgorithmShrinkWidth002, TestSize.Level1)
{
    auto buttonAlgorithm = AceType::MakeRefPtr<SecurityComponentLayoutAlgorithm>();
    ASSERT_NE(buttonAlgorithm, nullptr);
    buttonAlgorithm->left_ = PaddingLayoutElement();
    buttonAlgorithm->left_.Init(false, false, 4.0, 4.0); // left padding 4.0, minsize 4.0
    buttonAlgorithm->right_ = PaddingLayoutElement();
    buttonAlgorithm->right_.Init(false, false, 4.0, 4.0); // right_ padding 4.0, minsize 4.0
    buttonAlgorithm->middle_ = PaddingLayoutElement();
    buttonAlgorithm->middle_.Init(false, false, 4.0, 0.0); // middle_ padding 4.0, minsize 0.0
    // shrink 2.0px, left to 3.0, right to 3.0, total 6.0
    ASSERT_EQ(buttonAlgorithm->ShrinkWidth(2.0), 10.0);
    ASSERT_EQ(buttonAlgorithm->middle_.width_, 2.0);
}

/**
 * @tc.name: SecurityComponentLayoutAlgorithmShrinkWidth003
 * @tc.desc: Test security component ShrinkWidth, shrink text when isVertical_
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLayoutAlgorithmShrinkWidth003, TestSize.Level1)
{
    auto buttonAlgorithm = AceType::MakeRefPtr<SecurityComponentLayoutAlgorithm>();
    ASSERT_NE(buttonAlgorithm, nullptr);
    auto textNode = FrameNode::CreateFrameNode(
        V2::TEXT_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<TextPattern>());
    auto textGeometryNode = textNode->geometryNode_;
    auto textLayoutProperty = textNode->GetLayoutProperty<TextLayoutProperty>();
    auto textWrapperNode = AceType::MakeRefPtr<LayoutWrapperNode>(
        AceType::WeakClaim(AceType::RawPtr(textNode)), textGeometryNode, textLayoutProperty);
    auto secCompProperty = AceType::MakeRefPtr<SecurityComponentLayoutProperty>();
    secCompProperty->UpdateSecurityComponentDescription(1);

    buttonAlgorithm->text_ = TextLayoutElement();
    RefPtr<LayoutWrapper> textWrapper = textWrapperNode;
    buttonAlgorithm->text_.Init(secCompProperty, textWrapper);
    buttonAlgorithm->text_.width_ = 4.0; // set width 4.0
    buttonAlgorithm->isVertical_ = true;

    // shrink 2.0px, icon not exist, total 2.0
    ASSERT_EQ(buttonAlgorithm->ShrinkWidth(2.0), 2.0);
    ASSERT_EQ(buttonAlgorithm->text_.width_, 2.0);
}

/**
 * @tc.name: SecurityComponentLayoutAlgorithmShrinkWidth004
 * @tc.desc: Test security component ShrinkWidth, shrink icon when isVertical_
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLayoutAlgorithmShrinkWidth004, TestSize.Level1)
{
    auto buttonAlgorithm = AceType::MakeRefPtr<SecurityComponentLayoutAlgorithm>();
    ASSERT_NE(buttonAlgorithm, nullptr);
    auto imageIcon = FrameNode::CreateFrameNode(
        V2::IMAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<ImagePattern>());
    auto imageGeometryNode = imageIcon->geometryNode_;
    auto imageLayoutProperty = imageIcon->GetLayoutProperty<ImageLayoutProperty>();
    auto imageWrapperNode = AceType::MakeRefPtr<LayoutWrapperNode>(
        AceType::WeakClaim(AceType::RawPtr(imageIcon)), imageGeometryNode, imageLayoutProperty);
    auto secCompProperty = AceType::MakeRefPtr<SecurityComponentLayoutProperty>();
    secCompProperty->UpdateIconStyle(1);

    buttonAlgorithm->icon_ = IconLayoutElement();
    RefPtr<LayoutWrapper> iconWrapper = imageWrapperNode;
    buttonAlgorithm->icon_.Init(secCompProperty, iconWrapper);
    buttonAlgorithm->icon_.width_ = 16.0; // set width 4.0
    buttonAlgorithm->isVertical_ = true;

    EXPECT_EQ(buttonAlgorithm->ShrinkWidth(2.0), 14.0);
    EXPECT_EQ(buttonAlgorithm->icon_.width_, 14.0);
}

/**
 * @tc.name: SecurityComponentLayoutAlgorithmShrinkWidth005
 * @tc.desc: Test security component ShrinkWidth, shrink icon when not isVertical_
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLayoutAlgorithmShrinkWidth005, TestSize.Level1)
{
    auto buttonAlgorithm = AceType::MakeRefPtr<SecurityComponentLayoutAlgorithm>();
    ASSERT_NE(buttonAlgorithm, nullptr);
    auto imageIcon = FrameNode::CreateFrameNode(
        V2::IMAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<ImagePattern>());
    auto imageGeometryNode = imageIcon->geometryNode_;
    auto imageLayoutProperty = imageIcon->GetLayoutProperty<ImageLayoutProperty>();
    auto imageWrapperNode = AceType::MakeRefPtr<LayoutWrapperNode>(
        AceType::WeakClaim(AceType::RawPtr(imageIcon)), imageGeometryNode, imageLayoutProperty);
    auto secCompProperty = AceType::MakeRefPtr<SecurityComponentLayoutProperty>();
    secCompProperty->UpdateIconStyle(1);

    buttonAlgorithm->icon_ = IconLayoutElement();
    RefPtr<LayoutWrapper> iconWrapper = imageWrapperNode;
    buttonAlgorithm->icon_.Init(secCompProperty, iconWrapper);
    buttonAlgorithm->icon_.width_ = 16.0; // set width 4.0
    buttonAlgorithm->isVertical_ = false;
    buttonAlgorithm->text_.isSetSize_ = true;
    buttonAlgorithm->text_.width_ = 16.0; // set text 16.0
    // shrink 2.0px, icon will shrink only
    EXPECT_EQ(buttonAlgorithm->ShrinkWidth(2.0), 30);
    EXPECT_EQ(buttonAlgorithm->icon_.width_, 14.0);
}

/**
 * @tc.name: SecurityComponentLayoutAlgorithmEnlargeWidth001
 * @tc.desc: Test security component EnlargeWidth
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLayoutAlgorithmEnlargeWidth001, TestSize.Level1)
{
    auto buttonAlgorithm = AceType::MakeRefPtr<SecurityComponentLayoutAlgorithm>();
    ASSERT_NE(buttonAlgorithm, nullptr);
    buttonAlgorithm->middle_.isVertical_ = false;

    buttonAlgorithm->left_ = PaddingLayoutElement();
    buttonAlgorithm->left_.Init(false, true, 4.0, 0.0);
    buttonAlgorithm->right_ = PaddingLayoutElement();
    buttonAlgorithm->right_.Init(false, true, 4.0, 0.0);
    buttonAlgorithm->isVertical_ = true;
    EXPECT_EQ(buttonAlgorithm->EnlargeWidth(2.0), 8.0);

    buttonAlgorithm->left_.isSetSize_ = false;
    buttonAlgorithm->isVertical_ = false;
    EXPECT_EQ(buttonAlgorithm->EnlargeWidth(2.0), 10.0);
    EXPECT_EQ(buttonAlgorithm->middle_.width_, 0.0);

    buttonAlgorithm->left_.isSetSize_ = false;
    buttonAlgorithm->isVertical_ = true;
    EXPECT_EQ(buttonAlgorithm->EnlargeWidth(2.0), 12.0);
    EXPECT_EQ(buttonAlgorithm->middle_.width_, 0.0);

    buttonAlgorithm->left_.isSetSize_ = true;
    buttonAlgorithm->isVertical_ = false;
    EXPECT_EQ(buttonAlgorithm->EnlargeWidth(2.0), 14.0);
    EXPECT_EQ(buttonAlgorithm->middle_.width_, 2.0);
}

/**
 * @tc.name: SecurityComponentLayoutAlgorithmShrinkHeight001
 * @tc.desc: Test security component ShrinkHeight, shrink top and bottom padding
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLayoutAlgorithmShrinkHeight001, TestSize.Level1)
{
    auto buttonAlgorithm = AceType::MakeRefPtr<SecurityComponentLayoutAlgorithm>();
    ASSERT_NE(buttonAlgorithm, nullptr);
    buttonAlgorithm->top_ = PaddingLayoutElement();
    buttonAlgorithm->top_.Init(true, false, 4.0, 0.0); // top padding 4.0, minsize 0.0
    buttonAlgorithm->bottom_ = PaddingLayoutElement();
    buttonAlgorithm->bottom_.Init(true, false, 4.0, 0.0); // bottom padding 4.0, minsize 0.0
    // shrink 2.0px, left to 3.0, right to 3.0, total 6.0
    ASSERT_EQ(buttonAlgorithm->ShrinkHeight(2.0), 6.0);
    ASSERT_EQ(buttonAlgorithm->top_.height_, 3.0);
    ASSERT_EQ(buttonAlgorithm->bottom_.height_, 3.0);
}

/**
 * @tc.name: SecurityComponentLayoutAlgorithmShrinkHeight002
 * @tc.desc: Test security component ShrinkWidth, shrink middle padding
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLayoutAlgorithmShrinkHeight002, TestSize.Level1)
{
    auto buttonAlgorithm = AceType::MakeRefPtr<SecurityComponentLayoutAlgorithm>();
    ASSERT_NE(buttonAlgorithm, nullptr);
    buttonAlgorithm->isVertical_ = true;
    buttonAlgorithm->top_ = PaddingLayoutElement();
    buttonAlgorithm->top_.Init(true, false, 4.0, 4.0); // left padding 4.0, minsize 4.0
    buttonAlgorithm->bottom_ = PaddingLayoutElement();
    buttonAlgorithm->bottom_.Init(true, false, 4.0, 4.0); // right_ padding 4.0, minsize 4.0
    buttonAlgorithm->middle_ = PaddingLayoutElement();
    buttonAlgorithm->middle_.Init(true, false, 4.0, 0.0); // middle_ padding 4.0, minsize 0.0
    // shrink 2.0px, left to 3.0, right to 3.0, total 6.0
    ASSERT_EQ(buttonAlgorithm->ShrinkHeight(2.0), 10.0);
    ASSERT_EQ(buttonAlgorithm->middle_.height_, 2.0);
}

/**
 * @tc.name: SecurityComponentLayoutAlgorithmShrinkHeight003
 * @tc.desc: Test security component ShrinkWidth, shrink icon when isVertical_
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLayoutAlgorithmShrinkHeight003, TestSize.Level1)
{
    auto buttonAlgorithm = AceType::MakeRefPtr<SecurityComponentLayoutAlgorithm>();
    ASSERT_NE(buttonAlgorithm, nullptr);
    auto imageIcon = FrameNode::CreateFrameNode(
        V2::IMAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<ImagePattern>());
    auto imageGeometryNode = imageIcon->geometryNode_;
    auto imageLayoutProperty = imageIcon->GetLayoutProperty<ImageLayoutProperty>();
    auto imageWrapperNode = AceType::MakeRefPtr<LayoutWrapperNode>(
        AceType::WeakClaim(AceType::RawPtr(imageIcon)), imageGeometryNode, imageLayoutProperty);
    auto secCompProperty = AceType::MakeRefPtr<SecurityComponentLayoutProperty>();
    secCompProperty->UpdateIconStyle(1);

    buttonAlgorithm->icon_ = IconLayoutElement();
    RefPtr<LayoutWrapper> iconWrapper = imageWrapperNode;
    buttonAlgorithm->icon_.Init(secCompProperty, iconWrapper);
    buttonAlgorithm->icon_.height_ = 15.0; // set width 4.0
    buttonAlgorithm->text_.isSetSize_ = true;
    buttonAlgorithm->text_.height_ = 20.0; // set width 20.0
    buttonAlgorithm->isVertical_ = false;

    EXPECT_EQ(buttonAlgorithm->ShrinkHeight(4.0), 20.0); // text can not shrink
    EXPECT_EQ(buttonAlgorithm->icon_.height_, 15.0);
}

/**
 * @tc.name: SecurityComponentLayoutAlgorithmShrinkHeight004
 * @tc.desc: Test security component ShrinkWidth, shrink icon when not isVertical_
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLayoutAlgorithmShrinkHeight004, TestSize.Level1)
{
    auto buttonAlgorithm = AceType::MakeRefPtr<SecurityComponentLayoutAlgorithm>();
    ASSERT_NE(buttonAlgorithm, nullptr);
    auto imageIcon = FrameNode::CreateFrameNode(
        V2::IMAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<ImagePattern>());
    auto imageGeometryNode = imageIcon->geometryNode_;
    auto imageLayoutProperty = imageIcon->GetLayoutProperty<ImageLayoutProperty>();
    auto imageWrapperNode = AceType::MakeRefPtr<LayoutWrapperNode>(
        AceType::WeakClaim(AceType::RawPtr(imageIcon)), imageGeometryNode, imageLayoutProperty);
    auto secCompProperty = AceType::MakeRefPtr<SecurityComponentLayoutProperty>();
    secCompProperty->UpdateIconStyle(1);

    buttonAlgorithm->isVertical_ = true;
    buttonAlgorithm->icon_ = IconLayoutElement();
    RefPtr<LayoutWrapper> iconWrapper = imageWrapperNode;
    buttonAlgorithm->icon_.Init(secCompProperty, iconWrapper);
    buttonAlgorithm->icon_.height_ = 16.0; // set width 4.0
    buttonAlgorithm->isVertical_ = true;
    buttonAlgorithm->text_.isSetSize_ = true;
    buttonAlgorithm->text_.height_ = 16.0; // set text 16.0
    // shrink 2.0px, icon will shrink only
    EXPECT_EQ(buttonAlgorithm->ShrinkHeight(2.0), 30.0);
    EXPECT_EQ(buttonAlgorithm->icon_.height_, 14.0);
}

/**
 * @tc.name: SecurityComponentLayoutAlgorithmEnlargeHeight001
 * @tc.desc: Test security component EnlargeHeight
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLayoutAlgorithmEnlargeHeight001, TestSize.Level1)
{
    auto buttonAlgorithm = AceType::MakeRefPtr<SecurityComponentLayoutAlgorithm>();
    ASSERT_NE(buttonAlgorithm, nullptr);
    buttonAlgorithm->middle_.isVertical_ = true;

    buttonAlgorithm->top_ = PaddingLayoutElement();
    buttonAlgorithm->top_.Init(true, true, 4.0, 0.0);
    buttonAlgorithm->bottom_ = PaddingLayoutElement();
    buttonAlgorithm->bottom_.Init(true, true, 4.0, 0.0);
    buttonAlgorithm->isVertical_ = false;
    EXPECT_EQ(buttonAlgorithm->EnlargeHeight(2.0), 8.0);

    buttonAlgorithm->top_.isSetSize_ = false;
    buttonAlgorithm->isVertical_ = true;
    EXPECT_EQ(buttonAlgorithm->EnlargeHeight(2.0), 10.0);
    EXPECT_EQ(buttonAlgorithm->middle_.height_, 0.0);

    buttonAlgorithm->top_.isSetSize_ = false;
    buttonAlgorithm->isVertical_ = false;
    EXPECT_EQ(buttonAlgorithm->EnlargeHeight(2.0), 12.0);
    EXPECT_EQ(buttonAlgorithm->middle_.height_, 0.0);

    buttonAlgorithm->top_.isSetSize_ = true;
    buttonAlgorithm->isVertical_ = true;
    EXPECT_EQ(buttonAlgorithm->EnlargeHeight(2.0), 14.0);
    EXPECT_EQ(buttonAlgorithm->middle_.height_, 2.0);
}

/**
 * @tc.name: SecurityComponentLayoutAlgorithmAdapterWidth001
 * @tc.desc: Test security component AdaptWidth
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLayoutAlgorithmAdapterWidth001, TestSize.Level1)
{
    auto buttonAlgorithm = AceType::MakeRefPtr<SecurityComponentLayoutAlgorithm>();
    ASSERT_NE(buttonAlgorithm, nullptr);

    buttonAlgorithm->idealWidth_ = 0.0;
    buttonAlgorithm->top_ = PaddingLayoutElement();
    buttonAlgorithm->top_.Init(true, false, 4.0, 0.0);
    buttonAlgorithm->left_ = PaddingLayoutElement();
    buttonAlgorithm->left_.Init(false, false, 4.0, 0.0);
    buttonAlgorithm->componentWidth_ = 4.0;
    buttonAlgorithm->maxWidth_ = 2.0;
    buttonAlgorithm->AdaptWidth();
    EXPECT_EQ(buttonAlgorithm->componentWidth_, 2.0);

    buttonAlgorithm->maxWidth_ = 20.0;
    buttonAlgorithm->minWidth_ = 10.0;
    buttonAlgorithm->AdaptWidth();
    EXPECT_EQ(buttonAlgorithm->componentWidth_, 10.0);
}

/**
 * @tc.name: SecurityComponentLayoutAlgorithmAdaptHeight001
 * @tc.desc: Test security component AdaptHeight
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLayoutAlgorithmAdaptHeight001, TestSize.Level1)
{
    auto buttonAlgorithm = AceType::MakeRefPtr<SecurityComponentLayoutAlgorithm>();
    ASSERT_NE(buttonAlgorithm, nullptr);

    buttonAlgorithm->idealWidth_ = 0.0;
    buttonAlgorithm->top_ = PaddingLayoutElement();
    buttonAlgorithm->top_.Init(true, false, 4.0, 0.0);
    buttonAlgorithm->left_ = PaddingLayoutElement();
    buttonAlgorithm->left_.Init(false, false, 4.0, 0.0);
    buttonAlgorithm->componentHeight_ = 4.0;
    buttonAlgorithm->maxHeight_ = 2.0;
    buttonAlgorithm->AdaptHeight();
    EXPECT_EQ(buttonAlgorithm->componentHeight_, 2.0);

    buttonAlgorithm->maxHeight_ = 20.0;
    buttonAlgorithm->minHeight_ = 10.0;
    buttonAlgorithm->AdaptHeight();
    EXPECT_EQ(buttonAlgorithm->componentHeight_, 10.0);
}

/**
 * @tc.name: SecurityComponentLayoutAlgorithmUpdateVerticalOffset001
 * @tc.desc: Test security component UpdateVerticalOffset
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLayoutAlgorithmUpdateVerticalOffset001, TestSize.Level1)
{
    auto buttonAlgorithm = AceType::MakeRefPtr<SecurityComponentLayoutAlgorithm>();
    ASSERT_NE(buttonAlgorithm, nullptr);

    OffsetF offsetIcon(0.0, 0.0);
    OffsetF offsetText(0.0, 0.0);
    buttonAlgorithm->icon_.height_ = 2.0;
    buttonAlgorithm->middle_.height_ = 2.0;
    buttonAlgorithm->icon_.width_ = 2.0;
    buttonAlgorithm->text_.width_ = 1.0;
    buttonAlgorithm->UpdateVerticalOffset(offsetIcon, offsetText);
    EXPECT_EQ(offsetText.GetX(), 0.5); // (icon_.width_ - text_.width_) / 2
    EXPECT_EQ(offsetText.GetY(), 4.0); // icon_.height_ + middle_.height_

    OffsetF offsetIcon1(0.0, 0.0);
    OffsetF offsetText1(0.0, 0.0);
    buttonAlgorithm->text_.width_ = 3.0;
    buttonAlgorithm->UpdateVerticalOffset(offsetIcon1, offsetText1);
    EXPECT_EQ(offsetText1.GetX(), 0);
    EXPECT_EQ(offsetText1.GetY(), 4.0); // icon_.height_ + middle_.height_
    EXPECT_EQ(offsetIcon1.GetX(), 0.5); // (text_.width_ - icon_.width_) / 2
}

/**
 * @tc.name: SecurityComponentLayoutAlgorithmUpdateHorizontalOffset001
 * @tc.desc: Test security component UpdateHorizontalOffset
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLayoutAlgorithmUpdateHorizontalOffset001, TestSize.Level1)
{
    auto buttonAlgorithm = AceType::MakeRefPtr<SecurityComponentLayoutAlgorithm>();
    ASSERT_NE(buttonAlgorithm, nullptr);

    OffsetF offsetIcon(0.0, 0.0);
    OffsetF offsetText(0.0, 0.0);
    buttonAlgorithm->icon_.width_ = 2.0;
    buttonAlgorithm->middle_.width_ = 2.0;
    buttonAlgorithm->icon_.height_ = 2.0;
    buttonAlgorithm->text_.height_ = 1.0;
    buttonAlgorithm->UpdateHorizontalOffset(offsetIcon, offsetText);
    EXPECT_EQ(offsetText.GetX(), 4.0); // icon_.width_ + middle_.width_
    EXPECT_EQ(offsetText.GetY(), 0.5); // (icon_.height_ - text_.height_) / 2

    OffsetF offsetIcon1(0.0, 0.0);
    OffsetF offsetText1(0.0, 0.0);
    buttonAlgorithm->text_.height_ = 3.0;
    buttonAlgorithm->UpdateHorizontalOffset(offsetIcon1, offsetText1);
    EXPECT_EQ(offsetText1.GetX(), 4.0); // icon_.height_ + middle_.height_
    EXPECT_EQ(offsetText1.GetY(), 0);
    EXPECT_EQ(offsetIcon1.GetY(), 0.5); // (text_.width_ - icon_.width_) / 2
}

/**
 * @tc.name: LayoutAlgorithmUpdateCircleButtonConstraint001
 * @tc.desc: Test security component UpdateCircleButtonConstraint
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, LayoutAlgorithmUpdateCircleButtonConstraint001, TestSize.Level1)
{
    SecurityComponentLayoutAlgorithm buttonAlgorithm;
    buttonAlgorithm.UpdateCircleButtonConstraint();
    EXPECT_EQ(buttonAlgorithm.idealWidth_, 0.0);

    SecurityComponentLayoutAlgorithm buttonAlgorithm1;
    buttonAlgorithm1.idealWidth_ = 1.0;
    buttonAlgorithm1.UpdateCircleButtonConstraint();
    EXPECT_EQ(buttonAlgorithm1.idealWidth_, 1.0);

    SecurityComponentLayoutAlgorithm buttonAlgorithm2;
    buttonAlgorithm2.idealHeight_ = 2.0;
    buttonAlgorithm2.UpdateCircleButtonConstraint();
    EXPECT_EQ(buttonAlgorithm2.idealWidth_, 2.0);

    SecurityComponentLayoutAlgorithm buttonAlgorithm3;
    buttonAlgorithm3.componentWidth_ = 1.0;
    buttonAlgorithm3.minWidth_ = 2.0;
    buttonAlgorithm3.UpdateCircleButtonConstraint();
    EXPECT_EQ(buttonAlgorithm3.idealWidth_, 2.0);

    SecurityComponentLayoutAlgorithm buttonAlgorithm4;
    buttonAlgorithm4.componentHeight_ = 2.0;
    buttonAlgorithm4.minHeight_ = 3.0;
    buttonAlgorithm4.UpdateCircleButtonConstraint();
    EXPECT_EQ(buttonAlgorithm4.idealWidth_, 3.0);

    SecurityComponentLayoutAlgorithm buttonAlgorithm5;
    buttonAlgorithm5.componentWidth_ = 10.0;
    buttonAlgorithm5.maxWidth_ = 4.0;
    buttonAlgorithm5.UpdateCircleButtonConstraint();
    EXPECT_EQ(buttonAlgorithm5.idealWidth_, 4.0);

    SecurityComponentLayoutAlgorithm buttonAlgorithm6;
    buttonAlgorithm6.componentHeight_ = 10.0;
    buttonAlgorithm6.maxHeight_ = 4.0;
    buttonAlgorithm6.UpdateCircleButtonConstraint();
    EXPECT_EQ(buttonAlgorithm6.idealWidth_, 4.0);
}

/**
 * @tc.name: SecurityComponentLayoutAlgorithmFillBlank001
 * @tc.desc: Test security component FillBlank
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SecurityComponentModelTestNg, SecurityComponentLayoutAlgorithmFillBlank001, TestSize.Level1)
{
    SecurityComponentLayoutAlgorithm buttonAlgorithm;
    buttonAlgorithm.isNobg_ = true;
    buttonAlgorithm.FillBlank();
    EXPECT_EQ(buttonAlgorithm.componentWidth_, 0.0);

    SecurityComponentLayoutAlgorithm buttonAlgorithm1;
    buttonAlgorithm1.idealWidth_ = 2.0;
    buttonAlgorithm1.componentWidth_ = 0.0;
    buttonAlgorithm1.idealHeight_ = 2.0;
    buttonAlgorithm1.componentHeight_ = 0.0;
    buttonAlgorithm1.FillBlank();
    EXPECT_EQ(buttonAlgorithm1.left_.width_, 1.0);
    EXPECT_EQ(buttonAlgorithm1.right_.width_, 1.0);
    EXPECT_EQ(buttonAlgorithm1.top_.height_, 1.0);
    EXPECT_EQ(buttonAlgorithm1.bottom_.height_, 1.0);

    SecurityComponentLayoutAlgorithm buttonAlgorithm2;
    buttonAlgorithm2.minWidth_ = 2.0;
    buttonAlgorithm2.componentWidth_ = 0.0;
    buttonAlgorithm2.minHeight_ = 2.0;
    buttonAlgorithm2.componentHeight_ = 0.0;
    buttonAlgorithm2.FillBlank();
    EXPECT_EQ(buttonAlgorithm2.left_.width_, 1.0);
    EXPECT_EQ(buttonAlgorithm2.right_.width_, 1.0);
    EXPECT_EQ(buttonAlgorithm2.top_.height_, 1.0);
    EXPECT_EQ(buttonAlgorithm2.bottom_.height_, 1.0);
}
} // namespace OHOS::Ace::NG

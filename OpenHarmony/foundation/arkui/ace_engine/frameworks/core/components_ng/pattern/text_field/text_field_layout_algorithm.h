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

#ifndef FOUNDATION_ACE_FRAMEWORKS_CORE_COMPONENTS_NG_PATTERN_TEXT_FIELD_TEXT_FIELD_LAYOUT_ALGORITHM_H
#define FOUNDATION_ACE_FRAMEWORKS_CORE_COMPONENTS_NG_PATTERN_TEXT_FIELD_TEXT_FIELD_LAYOUT_ALGORITHM_H

#include <string>
#include <utility>

#include "base/geometry/ng/offset_t.h"
#include "base/memory/referenced.h"
#include "core/components/text_field/textfield_theme.h"
#include "core/components_ng/layout/layout_wrapper.h"
#include "core/components_ng/pattern/text/text_adapt_font_sizer.h"
#include "core/components_ng/pattern/text_field/text_field_layout_property.h"

namespace OHOS::Ace::NG {

struct InlineMeasureItem {
    float inlineScrollRectOffsetX = 0.0f;
    float inlineLastOffsetY = 0.0f;
    float inlineContentRectHeight = 0.0f;
    float inlineSizeHeight = 0.0f;
};

class TextFieldContentModifier;
class ACE_EXPORT TextFieldLayoutAlgorithm : public LayoutAlgorithm, public TextAdaptFontSizer {
    DECLARE_ACE_TYPE(TextFieldLayoutAlgorithm, LayoutAlgorithm, TextAdaptFontSizer);

public:
    TextFieldLayoutAlgorithm() = default;

    ~TextFieldLayoutAlgorithm() override = default;

    void OnReset() override
    {
        paragraph_->Reset();
    }

    RefPtr<Paragraph> GetParagraph() const override;
    void GetSuitableSize(SizeF& maxSize, LayoutWrapper* layoutWrapper) override;
    bool CreateParagraphAndLayout(const TextStyle& textStyle, const std::string& content,
        const LayoutConstraintF& contentConstraint, LayoutWrapper* layoutWrapper, bool needLayout = true) override;

    const RectF& GetTextRect() const
    {
        return textRect_;
    }

    const OffsetF& GetParentGlobalOffset() const
    {
        return parentGlobalOffset_;
    }

    float GetUnitWidth() const
    {
        return unitWidth_;
    }

    InlineMeasureItem GetInlineMeasureItem() const
    {
        return inlineMeasureItem_;
    }

    static TextDirection GetTextDirection(const std::string& content, TextDirection direction = TextDirection::AUTO);

    static void UpdateTextStyle(const RefPtr<FrameNode>& frameNode,
        const RefPtr<TextFieldLayoutProperty>& layoutProperty, const RefPtr<TextFieldTheme>& theme,
        TextStyle& textStyle, bool isDisabled);
    static void UpdatePlaceholderTextStyle(const RefPtr<FrameNode>& frameNode,
        const RefPtr<TextFieldLayoutProperty>& layoutProperty, const RefPtr<TextFieldTheme>& theme,
        TextStyle& textStyle, bool isDisabled);
    void CounterLayout(LayoutWrapper* layoutWrapper);
    float CounterNodeMeasure(float contentWidth, LayoutWrapper* layoutWrapper);
    void UpdateCounterTextMargin(LayoutWrapper* layoutWrapper);
    void UpdateCounterBorderStyle(uint32_t& textLength, uint32_t& maxLength, LayoutWrapper* layoutWrapper);
    void UpdateCounterNode(uint32_t textLength, uint32_t maxLength, const LayoutConstraintF& contentConstraint,
        LayoutWrapper* layoutWrapper);
    bool IsAdaptExceedLimit(const SizeF& maxSize) override;

protected:
    static void FontRegisterCallback(const RefPtr<FrameNode>& frameNode, const std::vector<std::string>& fontFamilies);
    void CreateParagraph(const TextStyle& textStyle, std::string content, bool needObscureText,
        int32_t nakedCharPosition, bool disableTextAlign = false);
    void CreateParagraph(const TextStyle& textStyle, const std::vector<std::string>& contents,
        const std::string& content, bool needObscureText, bool disableTextAlign = false);
    void CreateInlineParagraph(const TextStyle& textStyle, std::string content, bool needObscureText,
        int32_t nakedCharPosition, bool disableTextAlign = false);
    void SetPropertyToModifier(const TextStyle& textStyle, RefPtr<TextFieldContentModifier> modifier);

    float GetTextFieldDefaultHeight();

    void ConstructTextStyles(
        const RefPtr<FrameNode>& frameNode, TextStyle& textStyle, std::string& textContent, bool& showPlaceHolder);
    LayoutConstraintF CalculateContentMaxSizeWithCalculateConstraint(
        const LayoutConstraintF& contentConstraint, LayoutWrapper* layoutWrapper);

    int32_t ConvertTouchOffsetToCaretPosition(const Offset& localOffset);
    void UpdateUnitLayout(LayoutWrapper* layoutWrapper);
    ParagraphStyle GetParagraphStyle(const TextStyle& textStyle, const std::string& content) const;
    void GetInlineMeasureItem(
        const LayoutConstraintF& contentConstraint, LayoutWrapper* layoutWrapper, float& inlineIdealHeight);
    float ConstraintWithMinWidth(
        const LayoutConstraintF& contentConstraint, LayoutWrapper* layoutWrapper,
        RefPtr<Paragraph>& paragraph, float removeValue = 0.0f);
    SizeF GetConstraintSize(const LayoutConstraintF& contentConstraint, LayoutWrapper* layoutWrapper);
    std::optional<SizeF> InlineMeasureContent(const LayoutConstraintF& contentConstraint,
        LayoutWrapper* layoutWrapper);
    SizeF PlaceHolderMeasureContent(
        const LayoutConstraintF& contentConstraint, LayoutWrapper* layoutWrapper, float imageWidth = 0.0f);
    SizeF TextInputMeasureContent(const LayoutConstraintF& contentConstraint,
        LayoutWrapper* layoutWrapper, float imageWidth);
    SizeF TextAreaMeasureContent(const LayoutConstraintF& contentConstraint, LayoutWrapper* layoutWrapper);

    bool AddAdaptFontSizeAndAnimations(TextStyle& textStyle, const RefPtr<TextFieldLayoutProperty>& layoutProperty,
        const LayoutConstraintF& contentConstraint, LayoutWrapper* layoutWrapper);
    bool AdaptInlineFocusFontSize(TextStyle& textStyle, const std::string& content, const Dimension& stepUnit,
        const LayoutConstraintF& contentConstraint, LayoutWrapper* layoutWrapper) override;
    virtual bool CreateParagraphEx(const TextStyle& textStyle, const std::string& content,
        const LayoutConstraintF& contentConstraint, LayoutWrapper* layoutWrapper) = 0;

    RefPtr<Paragraph> paragraph_;
    RefPtr<Paragraph> inlineParagraph_;
    InlineMeasureItem inlineMeasureItem_;

    RectF textRect_;
    OffsetF parentGlobalOffset_;
    std::string textContent_;
    bool showPlaceHolder_ = false;
    float preferredHeight_ = 0.0f;
    TextDirection direction_ = TextDirection::AUTO;

    float unitWidth_ = 0.0f;
    bool autoWidth_ = false;
    Dimension textIndent_ = 0.0_px;
    float indent_ = 0.0f;
private:
    static void UpdateTextStyleMore(const RefPtr<FrameNode>& frameNode,
        const RefPtr<TextFieldLayoutProperty>& layoutProperty, const RefPtr<TextFieldTheme>& theme,
        TextStyle& textStyle, bool isDisabled);
    static void UpdatePlaceholderTextStyleMore(const RefPtr<FrameNode>& frameNode,
        const RefPtr<TextFieldLayoutProperty>& layoutProperty, const RefPtr<TextFieldTheme>& theme,
        TextStyle& placeholderTextStyle, bool isDisabled);
    void UpdateTextStyleTextOverflowAndWordBreak(TextStyle& textStyle, bool isTextArea,
        bool isInlineStyle, const RefPtr<TextFieldLayoutProperty>& textFieldLayoutProperty);
    float GetVisualTextWidth() const;
    void CalcInlineMeasureItem(LayoutWrapper* layoutWrapper);
    void ApplyIndent(double width);
    bool IsInlineFocusAdaptExceedLimit(const SizeF& maxSize);
    LayoutConstraintF BuildInfinityLayoutConstraint(const LayoutConstraintF& contentConstraint);
    ACE_DISALLOW_COPY_AND_MOVE(TextFieldLayoutAlgorithm);
};
} // namespace OHOS::Ace::NG

#endif // FOUNDATION_ACE_FRAMEWORKS_CORE_COMPONENTS_NG_PATTERN_TEXT_FIELD_TEXT_FIELD_LAYOUT_ALGORITHM_H

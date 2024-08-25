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

#include "core/components_ng/pattern/text_field/text_field_overlay_modifier.h"

#include "base/utils/utils.h"
#include "core/components_ng/base/modifier.h"
#include "core/components_ng/pattern/text_field/text_field_model.h"
#include "core/components_ng/pattern/text_field/text_field_pattern.h"
#include "core/components_ng/render/adapter/pixelmap_image.h"
#include "core/components_ng/render/drawing.h"
#include "core/components_ng/render/drawing_prop_convertor.h"
#include "core/components_ng/render/image_painter.h"

namespace OHOS::Ace::NG {
TextFieldOverlayModifier::TextFieldOverlayModifier(
    const WeakPtr<OHOS::Ace::NG::Pattern>& pattern, WeakPtr<ScrollEdgeEffect>&& edgeEffect)
    : pattern_(pattern), edgeEffect_(edgeEffect), magnifierPainter_(pattern)
{
    auto textFieldPattern = DynamicCast<TextFieldPattern>(pattern_.Upgrade());
    CHECK_NULL_VOID(textFieldPattern);
    auto theme = textFieldPattern->GetTheme();
    CHECK_NULL_VOID(theme);
    cursorColor_ = AceType::MakeRefPtr<AnimatablePropertyColor>(LinearColor(Color()));
    cursorWidth_ =
        AceType::MakeRefPtr<AnimatablePropertyFloat>(static_cast<float>(theme->GetCursorWidth().ConvertToPx()));
    selectedColor_ = AceType::MakeRefPtr<AnimatablePropertyColor>(LinearColor(Color()));
    cursorVisible_ = AceType::MakeRefPtr<PropertyBool>(false);
    showSelect_ = AceType::MakeRefPtr<PropertyBool>(false);
    contentSize_ = AceType::MakeRefPtr<PropertySizeF>(SizeF());
    contentOffset_ = AceType::MakeRefPtr<PropertyOffsetF>(OffsetF());
    cursorOffset_ = AceType::MakeRefPtr<PropertyOffsetF>(textFieldPattern->GetCaretOffset());
    frameSize_ = AceType::MakeRefPtr<PropertySizeF>(SizeF());
    currentOffset_ = AceType::MakeRefPtr<PropertyFloat>(0.0f);
    underlineWidth_ = AceType::MakeRefPtr<PropertyFloat>(0.0f);
    underlineColor_ = AceType::MakeRefPtr<PropertyColor>(Color());
    changeSelectedRects_ = AceType::MakeRefPtr<PropertyBool>(false);
    firstHandleOffset_ = AceType::MakeRefPtr<PropertyOffsetF>(OffsetF());
    secondHandleOffset_ = AceType::MakeRefPtr<PropertyOffsetF>(OffsetF());
    showPreviewText_ = AceType::MakeRefPtr<PropertyBool>(false);
    changePreviewTextRects_ = AceType::MakeRefPtr<PropertyBool>(false);
    previewTextDecorationColor_ = AceType::MakeRefPtr<PropertyColor>(Color());

    AttachProperty(cursorColor_);
    AttachProperty(cursorWidth_);
    AttachProperty(selectedColor_);
    AttachProperty(cursorVisible_);
    AttachProperty(showSelect_);
    AttachProperty(contentSize_);
    AttachProperty(contentOffset_);
    AttachProperty(cursorOffset_);
    AttachProperty(frameSize_);
    AttachProperty(currentOffset_);
    AttachProperty(underlineWidth_);
    AttachProperty(underlineColor_);
    AttachProperty(changeSelectedRects_);
    AttachProperty(firstHandleOffset_);
    AttachProperty(secondHandleOffset_);
    AttachProperty(showPreviewText_);
    AttachProperty(changePreviewTextRects_);
    AttachProperty(previewTextDecorationColor_);
}

void TextFieldOverlayModifier::SetFirstHandleOffset(const OffsetF& offset)
{
    firstHandleOffset_->Set(offset);
}

void TextFieldOverlayModifier::SetSecondHandleOffset(const OffsetF& offset)
{
    secondHandleOffset_->Set(offset);
}

void TextFieldOverlayModifier::onDraw(DrawingContext& context)
{
    auto& canvas = context.canvas;
    if (Container::GreatOrEqualAPIVersion(PlatformVersion::VERSION_ELEVEN)) {
        canvas.Save();
        RSRect clipRect;
        std::vector<RSPoint> clipRadius;
        GetFrameRectClip(clipRect, clipRadius);
        canvas.ClipRoundRect(clipRect, clipRadius, true);
    }
    PaintCursor(context);
    PaintSelection(context);
    if (Container::GreatOrEqualAPIVersion(PlatformVersion::VERSION_ELEVEN)) {
        canvas.Restore();
    }
    PaintScrollBar(context);
    PaintEdgeEffect(frameSize_->Get(), context.canvas);
    PaintUnderline(context.canvas);
    PaintPreviewTextDecoration(context);
    magnifierPainter_.PaintMagnifier(context.canvas);
}

void TextFieldOverlayModifier::GetFrameRectClip(RSRect& clipRect, std::vector<RSPoint>& clipRadius)
{
    auto textFieldPattern = DynamicCast<TextFieldPattern>(pattern_.Upgrade());
    CHECK_NULL_VOID(textFieldPattern);
    auto host = textFieldPattern->GetHost();
    CHECK_NULL_VOID(host);
    auto renderContext = host->GetRenderContext();
    CHECK_NULL_VOID(renderContext);
    auto textFrameRect = textFieldPattern->GetFrameRect();
    clipRect = RSRect(0.0f, 0.0f, textFrameRect.Width(), textFrameRect.Height());
    auto radius = renderContext->GetBorderRadius().value_or(BorderRadiusProperty());
    auto radiusTopLeft = RSPoint(static_cast<float>(radius.radiusTopLeft.value_or(0.0_vp).ConvertToPx()),
        static_cast<float>(radius.radiusTopLeft.value_or(0.0_vp).ConvertToPx()));
    clipRadius.emplace_back(radiusTopLeft);
    auto radiusTopRight = RSPoint(static_cast<float>(radius.radiusTopRight.value_or(0.0_vp).ConvertToPx()),
        static_cast<float>(radius.radiusTopRight.value_or(0.0_vp).ConvertToPx()));
    clipRadius.emplace_back(radiusTopRight);
    auto radiusBottomRight = RSPoint(static_cast<float>(radius.radiusBottomRight.value_or(0.0_vp).ConvertToPx()),
        static_cast<float>(radius.radiusBottomRight.value_or(0.0_vp).ConvertToPx()));
    clipRadius.emplace_back(radiusBottomRight);
    auto radiusBottomLeft = RSPoint(static_cast<float>(radius.radiusBottomLeft.value_or(0.0_vp).ConvertToPx()),
        static_cast<float>(radius.radiusBottomLeft.value_or(0.0_vp).ConvertToPx()));
    clipRadius.emplace_back(radiusBottomLeft);
}

void TextFieldOverlayModifier::PaintUnderline(RSCanvas& canvas) const
{
    auto textFieldPattern = DynamicCast<TextFieldPattern>(pattern_.Upgrade());
    CHECK_NULL_VOID(textFieldPattern);
    auto layoutProperty = textFieldPattern->GetLayoutProperty<TextFieldLayoutProperty>();
    CHECK_NULL_VOID(layoutProperty);
    if (!(layoutProperty->GetShowUnderlineValue(false) && textFieldPattern->IsUnspecifiedOrTextType())) {
        return;
    }
    if (textFieldPattern->IsNormalInlineState() && textFieldPattern->HasFocus()) {
        return;
    }
    auto contentRect = textFieldPattern->GetContentRect();
    auto textFrameRect = textFieldPattern->GetFrameRect();
    auto responseArea = textFieldPattern->GetResponseArea();
    Point leftPoint, rightPoint;
    if (layoutProperty->GetShowCounterValue(false)) {
        leftPoint.SetX(contentRect.Left());
        leftPoint.SetY(textFrameRect.Height());
        rightPoint.SetX(contentRect.Right());
        rightPoint.SetY(textFrameRect.Height());
    } else {
        auto responseAreaWidth = responseArea ? responseArea->GetAreaRect().Width() : 0.0f;
        leftPoint.SetX(contentRect.Left());
        leftPoint.SetY(textFrameRect.Height());
        rightPoint.SetX(contentRect.Right() + responseAreaWidth);
        rightPoint.SetY(textFrameRect.Height());
    }
    RSPen pen;
    pen.SetColor(ToRSColor(underlineColor_->Get()));
    pen.SetWidth(underlineWidth_->Get());
    pen.SetAntiAlias(true);
    canvas.AttachPen(pen);
    canvas.DrawLine(
        ToRSPoint(PointF(leftPoint.GetX(), leftPoint.GetY())), ToRSPoint(PointF(rightPoint.GetX(), rightPoint.GetY())));
    canvas.DetachPen();
}

void TextFieldOverlayModifier::PaintSelection(DrawingContext& context) const
{
    if (!showSelect_->Get() && !needPaintSelect_) {
        return;
    }
    auto& canvas = context.canvas;
    canvas.Save();
    auto textFieldPattern = DynamicCast<TextFieldPattern>(pattern_.Upgrade());
    CHECK_NULL_VOID(textFieldPattern);
    auto pipelineContext = PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(pipelineContext);
    auto themeManager = pipelineContext->GetThemeManager();
    CHECK_NULL_VOID(themeManager);
    auto theme = themeManager->GetTheme<TextFieldTheme>();
    RSBrush brush;
    brush.SetAntiAlias(true);
    brush.SetColor(ToRSColor(selectedColor_->Get()));
    canvas.AttachBrush(brush);
    auto paintOffset = textFieldPattern->GetContentRect().GetOffset();
    auto textBoxes = textFieldPattern->GetTextBoxes();
    auto textRect = textFieldPattern->GetTextRect();
    bool isTextArea = textFieldPattern->IsTextArea();
    float clipRectHeight = 0.0f;
    clipRectHeight = paintOffset.GetY() + contentSize_->Get().Height();
    RSRect clipInnerRect;
    auto defaultStyle = !textFieldPattern->IsNormalInlineState() || isTextArea;
    if (defaultStyle) {
        clipInnerRect = RSRect(paintOffset.GetX(), paintOffset.GetY(),
            paintOffset.GetX() + contentSize_->Get().Width() + textFieldPattern->GetInlinePadding(), clipRectHeight);
        canvas.ClipRect(clipInnerRect, RSClipOp::INTERSECT);
    } else {
        clipInnerRect = RSRect(paintOffset.GetX(), 0.0f, paintOffset.GetX() + contentSize_->Get().Width(),
            textFieldPattern->GetFrameRect().Height());
        canvas.ClipRect(clipInnerRect, RSClipOp::INTERSECT);
    }
    // for default style, selection height is equal to the content height
    for (const auto& textBox : textBoxes) {
        canvas.DrawRect(RSRect(textBox.Left() + (isTextArea ? contentOffset_->Get().GetX() : textRect.GetX()),
            defaultStyle
                ? (textBox.Top() + (isTextArea ? textRect.GetY() : contentOffset_->Get().GetY()))
                : 0.0f,
            textBox.Right() + (isTextArea ? contentOffset_->Get().GetX() : textRect.GetX()),
            defaultStyle
                ? (textBox.Bottom() + (isTextArea ? textRect.GetY() : contentOffset_->Get().GetY()))
                         : textFieldPattern->GetFrameRect().Height()));
    }
    canvas.DetachBrush();
    canvas.Restore();
}

void TextFieldOverlayModifier::PaintCursor(DrawingContext& context) const
{
    auto& canvas = context.canvas;
    auto textFieldPattern = DynamicCast<TextFieldPattern>(pattern_.Upgrade());
    CHECK_NULL_VOID(textFieldPattern);
    auto magnifierController = textFieldPattern->GetMagnifierController();
    CHECK_NULL_VOID(magnifierController);
    if (magnifierController->GetShowMagnifier()) {
        cursorVisible_->Set(true);
    }
    if (!cursorVisible_->Get() || textFieldPattern->IsSelected()) {
        return;
    }
    canvas.Save();
    RSBrush brush;
    brush.SetAntiAlias(true);
    brush.SetColor(ToRSColor(cursorColor_->Get()));
    canvas.AttachBrush(brush);
    auto paintOffset = contentOffset_->Get();
    float clipRectHeight = 0.0f;
    clipRectHeight = paintOffset.GetY() + contentSize_->Get().Height();
    RSRect clipInnerRect(paintOffset.GetX(), paintOffset.GetY(),
        // add extra clip space for cases such as auto width
        paintOffset.GetX() + contentSize_->Get().Width() +
            (LessOrEqual(contentSize_->Get().Width(), 0.0) ? cursorWidth_->Get() : 0.0f),
        clipRectHeight);
    canvas.ClipRect(clipInnerRect, RSClipOp::INTERSECT);
    auto caretRect = textFieldPattern->GetCaretRect();
    canvas.DrawRect(RSRect(caretRect.GetX(), caretRect.GetY(),
        caretRect.GetX() + (static_cast<float>(cursorWidth_->Get())), caretRect.GetY() + caretRect.Height()));
    canvas.DetachBrush();
    canvas.Restore();
}

void TextFieldOverlayModifier::PaintEdgeEffect(const SizeF& frameSize, RSCanvas& canvas)
{
    auto edgeEffect = edgeEffect_.Upgrade();
    CHECK_NULL_VOID(edgeEffect);
    edgeEffect->Paint(canvas, frameSize, { 0.0f, 0.0f });
}

void TextFieldOverlayModifier::PaintScrollBar(DrawingContext& context)
{
    auto textFieldPattern = DynamicCast<TextFieldPattern>(pattern_.Upgrade());
    CHECK_NULL_VOID(textFieldPattern);
    if (textFieldPattern->GetScrollBarVisible() && textFieldPattern->IsTextArea()) {
        ScrollBarOverlayModifier::onDraw(context);
    }
}

void TextFieldOverlayModifier::PaintPreviewTextDecoration(DrawingContext& context) const
{
    if (previewTextStyle != PreviewTextStyle::UNDERLINE ||
        (!showPreviewText_->Get() && !needPaintPreviewText)) {
        return;
    }

    auto& canvas = context.canvas;
    canvas.Save();
    auto textFieldPattern = DynamicCast<TextFieldPattern>(pattern_.Upgrade());
    CHECK_NULL_VOID(textFieldPattern);
    auto pipelineContext = PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(pipelineContext);
    auto themeManager = pipelineContext->GetThemeManager();
    CHECK_NULL_VOID(themeManager);
    auto theme = themeManager->GetTheme<TextFieldTheme>();

    auto textRect = textFieldPattern->GetTextRect();
    bool isTextArea = textFieldPattern->IsTextArea();

    float offsetX = isTextArea ? contentOffset_->Get().GetX() : textRect.GetX();
    float offsetY = isTextArea ? textRect.GetY() : contentOffset_->Get().GetY();
    auto previewTextRect = textFieldPattern->GetPreviewTextRects();
    if (previewTextRect.empty()) {
        return;
    }

    auto paintOffset = contentOffset_->Get();
    float clipRectHeight = paintOffset.GetY() + contentSize_->Get().Height();
    RSRect clipInnerRect;
    auto defaultStyle = !textFieldPattern->IsNormalInlineState() || isTextArea;
    if (defaultStyle) {
        clipInnerRect = RSRect(paintOffset.GetX(), paintOffset.GetY(),
            paintOffset.GetX() + contentSize_->Get().Width() + textFieldPattern->GetInlinePadding(), clipRectHeight);
        canvas.ClipRect(clipInnerRect, RSClipOp::INTERSECT);
    } else {
        clipInnerRect = RSRect(paintOffset.GetX(), 0.0f, paintOffset.GetX() + contentSize_->Get().Width(),
            textFieldPattern->GetFrameRect().Height());
        canvas.ClipRect(clipInnerRect, RSClipOp::INTERSECT);
    }

    RSPen pen;
    pen.SetColor(ToRSColor(previewTextDecorationColor_->Get()));
    pen.SetWidth(textFieldPattern->GetPreviewUnderlineWidth());
    pen.SetAntiAlias(true);
    canvas.AttachPen(pen);
    for (const auto& drawRect : previewTextRect) {
        Point leftPoint(drawRect.Left() + offsetX, drawRect.Bottom() + offsetY);
        Point rightPoint(drawRect.Right() + offsetX, drawRect.Bottom() + offsetY);
        canvas.DrawLine(ToRSPoint(PointF(leftPoint.GetX(), leftPoint.GetY())),
            ToRSPoint(PointF(rightPoint.GetX(), rightPoint.GetY())));
    }
    canvas.DetachPen();
}

void TextFieldOverlayModifier::SetCursorColor(Color& value)
{
    cursorColor_->Set(LinearColor(value));
}

void TextFieldOverlayModifier::SetCursorWidth(float value)
{
    cursorWidth_->Set(value);
}

void TextFieldOverlayModifier::SetSelectedBackGroundColor(Color& value)
{
    selectedColor_->Set(LinearColor(value));
}

void TextFieldOverlayModifier::SetCursorVisible(bool value)
{
    cursorVisible_->Set(value);
}

void TextFieldOverlayModifier::SetContentSize(SizeF& value)
{
    contentSize_->Set(value);
}

void TextFieldOverlayModifier::SetContentOffset(OffsetF& value)
{
    contentOffset_->Set(value);
}

void TextFieldOverlayModifier::SetCursorOffset(const OffsetF& value)
{
    cursorOffset_->Set(value);
}

void TextFieldOverlayModifier::SetInputStyle(InputStyle& value)
{
    inputStyle_ = value;
}

void TextFieldOverlayModifier::SetFrameSize(const SizeF& value)
{
    frameSize_->Set(value);
}

void TextFieldOverlayModifier::SetCurrentOffset(float value)
{
    currentOffset_->Set(value);
}

void TextFieldOverlayModifier::SetUnderlineWidth(float value)
{
    underlineWidth_->Set(value);
}

void TextFieldOverlayModifier::SetUnderlineColor(const Color& value)
{
    underlineColor_->Set(value);
}

void TextFieldOverlayModifier::SetScrollBar(const RefPtr<ScrollBar>& scrollBar)
{
    scrollBar_ = scrollBar;
}

void TextFieldOverlayModifier::SetChangeSelectedRects(bool value)
{
    if (value) {
        changeSelectedRects_->Set(!changeSelectedRects_->Get());
    }
    needPaintSelect_ = value;
}

void TextFieldOverlayModifier::SetShowSelect(bool value)
{
    showSelect_->Set(value);
}
void TextFieldOverlayModifier::SetShowPreviewTextDecoration(bool value)
{
    showPreviewText_->Set(value);
}
void TextFieldOverlayModifier::SetPreviewTextRects(bool value)
{
    if (value) {
        changePreviewTextRects_->Set(!changePreviewTextRects_->Get());
    }
    needPaintPreviewText = value;
}
void TextFieldOverlayModifier::SetPreviewTextDecorationColor(const Color& value)
{
    previewTextDecorationColor_->Set(value);
}
void TextFieldOverlayModifier::SetPreviewTextStyle(PreviewTextStyle style)
{
    previewTextStyle = style;
}
} // namespace OHOS::Ace::NG

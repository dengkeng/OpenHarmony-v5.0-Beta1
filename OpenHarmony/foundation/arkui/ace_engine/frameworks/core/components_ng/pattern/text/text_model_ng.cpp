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

#include "core/components_ng/pattern/text/text_model_ng.h"

#include "base/geometry/dimension.h"
#include "core/components/common/layout/constants.h"
#include "core/components/common/properties/alignment.h"
#include "core/components/common/properties/text_style.h"
#include "core/components_ng/base/frame_node.h"
#include "core/components_ng/base/view_abstract.h"
#include "core/components_ng/base/view_stack_processor.h"
#include "core/components_ng/pattern/text/span/span_string.h"
#include "core/components_ng/pattern/text/text_event_hub.h"
#include "core/components_ng/pattern/text/text_pattern.h"
#include "core/components_ng/pattern/text/text_styles.h"
#include "core/components_ng/pattern/text_field/text_field_event_hub.h"
#include "core/components_v2/inspector/inspector_constants.h"

namespace OHOS::Ace::NG {
void TextModelNG::Create(const std::string& content)
{
    auto* stack = ViewStackProcessor::GetInstance();
    auto nodeId = stack->ClaimNodeId();
    ACE_LAYOUT_SCOPED_TRACE("Create[%s][self:%d]", V2::TEXT_ETS_TAG, nodeId);
    auto frameNode =
        FrameNode::GetOrCreateFrameNode(V2::TEXT_ETS_TAG, nodeId, []() { return AceType::MakeRefPtr<TextPattern>(); });
    stack->Push(frameNode);

    ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, Content, content);
    // set draggable for framenode
    if (frameNode->IsFirstBuilding()) {
        auto pipeline = PipelineContext::GetCurrentContext();
        CHECK_NULL_VOID(pipeline);
        auto draggable = pipeline->GetDraggable<TextTheme>();
        frameNode->SetDraggable(draggable);
        auto gestureHub = frameNode->GetOrCreateGestureEventHub();
        CHECK_NULL_VOID(gestureHub);
        gestureHub->SetTextDraggable(true);
    }

    auto textPattern = frameNode->GetPattern<TextPattern>();
    textPattern->SetTextController(AceType::MakeRefPtr<TextController>());
    textPattern->GetTextController()->SetPattern(WeakPtr(textPattern));
    textPattern->ClearSelectionMenu();
}

void TextModelNG::Create(const RefPtr<SpanStringBase>& spanBase)
{
    TextModelNG::Create("");
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto textPattern = frameNode->GetPattern<TextPattern>();
    CHECK_NULL_VOID(textPattern);
    auto spanString = AceType::DynamicCast<SpanString>(spanBase);
    if (spanString) {
        auto spans = spanString->GetSpanItems();
        textPattern->SetSpanItemChildren(spans);
        textPattern->SetSpanStringMode(true);
    }
}

RefPtr<FrameNode> TextModelNG::CreateFrameNode(int32_t nodeId, const std::string& content)
{
    auto frameNode = FrameNode::CreateFrameNode(V2::TEXT_ETS_TAG, nodeId, AceType::MakeRefPtr<TextPattern>());

    CHECK_NULL_RETURN(frameNode, nullptr);
    auto layout = frameNode->GetLayoutProperty<TextLayoutProperty>();
    if (layout) {
        layout->UpdateContent(content);
    }
    // set draggable for framenode
    if (frameNode->IsFirstBuilding()) {
        auto pipeline = PipelineContext::GetCurrentContextSafely();
        CHECK_NULL_RETURN(pipeline, nullptr);
        auto draggable = pipeline->GetDraggable<TextTheme>();
        frameNode->SetDraggable(draggable);
        auto gestureHub = frameNode->GetOrCreateGestureEventHub();
        CHECK_NULL_RETURN(gestureHub, nullptr);
        gestureHub->SetTextDraggable(true);
    }

    auto textPattern = frameNode->GetPattern<TextPattern>();
    textPattern->SetTextController(AceType::MakeRefPtr<TextController>());
    textPattern->GetTextController()->SetPattern(WeakPtr(textPattern));
    textPattern->ClearSelectionMenu();
    return frameNode;
}

void TextModelNG::SetFont(const Font& value)
{
    if (value.fontSize.has_value()) {
        SetFontSize(value.fontSize.value());
    }
    if (value.fontWeight.has_value()) {
        SetFontWeight(value.fontWeight.value());
    }
    if (!value.fontFamilies.empty()) {
        SetFontFamily(value.fontFamilies);
    }
    if (value.fontStyle.has_value()) {
        SetItalicFontStyle(value.fontStyle.value());
    }
}

void TextModelNG::SetFontSize(const Dimension& value)
{
    if (!value.IsValid()) {
        ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, FontSize, Dimension());
        return;
    }
    ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, FontSize, value);
}

void TextModelNG::SetFontSize(FrameNode* frameNode, const Dimension& value)
{
    if (!value.IsValid()) {
        ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, FontSize, Dimension(), frameNode);
        return;
    }
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, FontSize, value, frameNode);
}

void TextModelNG::SetTextColor(const Color& value)
{
    ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, TextColor, value);
    ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, ForegroundColor, value);
    ACE_UPDATE_RENDER_CONTEXT(ForegroundColor, value);
    ACE_RESET_RENDER_CONTEXT(RenderContext, ForegroundColorStrategy);
    ACE_UPDATE_RENDER_CONTEXT(ForegroundColorFlag, true);
}

void TextModelNG::SetTextColor(FrameNode* frameNode, const Color& value)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, TextColor, value, frameNode);
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, ForegroundColor, value, frameNode);
    ACE_UPDATE_NODE_RENDER_CONTEXT(ForegroundColor, value, frameNode);
    ACE_RESET_NODE_RENDER_CONTEXT(RenderContext, ForegroundColorStrategy, frameNode);
    ACE_UPDATE_NODE_RENDER_CONTEXT(ForegroundColorFlag, true, frameNode);
}

void TextModelNG::SetTextShadow(const std::vector<Shadow>& value)
{
    ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, TextShadow, value);
}

void TextModelNG::SetItalicFontStyle(Ace::FontStyle value)
{
    ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, ItalicFontStyle, value);
}

void TextModelNG::SetItalicFontStyle(FrameNode* frameNode, Ace::FontStyle value)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, ItalicFontStyle, value, frameNode);
}

void TextModelNG::SetFontWeight(FrameNode* frameNode, Ace::FontWeight value)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, FontWeight, value, frameNode);
}

void TextModelNG::SetFontWeight(Ace::FontWeight value)
{
    ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, FontWeight, value);
}

void TextModelNG::SetFontFamily(const std::vector<std::string>& value)
{
    ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, FontFamily, value);
}

void TextModelNG::SetWordBreak(Ace::WordBreak value)
{
    ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, WordBreak, value);
}

void TextModelNG::SetLineBreakStrategy(Ace::LineBreakStrategy value)
{
    ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, LineBreakStrategy, value);
}

void TextModelNG::SetEllipsisMode(EllipsisMode value)
{
    ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, EllipsisMode, value);
}

void TextModelNG::SetTextAlign(Ace::TextAlign value)
{
    ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, TextAlign, value);
}

void TextModelNG::SetTextAlign(FrameNode* frameNode, Ace::TextAlign value)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, TextAlign, value, frameNode);
}

void TextModelNG::SetTextOverflow(Ace::TextOverflow value)
{
    ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, TextOverflow, value);
}

void TextModelNG::SetTextOverflow(FrameNode* frameNode, Ace::TextOverflow value)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, TextOverflow, value, frameNode);
}

void TextModelNG::SetMaxLines(uint32_t value)
{
    ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, MaxLines, value);
}

void TextModelNG::SetTextIndent(const Dimension& value)
{
    ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, TextIndent, value);
}

void TextModelNG::SetLineHeight(const Dimension& value)
{
    ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, LineHeight, value);
}

void TextModelNG::SetLineHeight(FrameNode* frameNode, const Dimension& value)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, LineHeight, value, frameNode);
}

void TextModelNG::SetLineSpacing(const Dimension& value)
{
    ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, LineSpacing, value);
}

void TextModelNG::SetLineSpacing(FrameNode* frameNode, const Dimension& value)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, LineSpacing, value, frameNode);
}

void TextModelNG::SetTextDecoration(Ace::TextDecoration value)
{
    ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, TextDecoration, value);
}

void TextModelNG::SetTextDecoration(FrameNode* frameNode, TextDecoration value)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, TextDecoration, value, frameNode);
}

void TextModelNG::SetTextDecorationColor(const Color& value)
{
    ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, TextDecorationColor, value);
}

void TextModelNG::SetTextDecorationColor(FrameNode* frameNode, const Color& value)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, TextDecorationColor, value, frameNode);
}

void TextModelNG::SetTextDecorationStyle(Ace::TextDecorationStyle value)
{
    ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, TextDecorationStyle, value);
}

void TextModelNG::SetTextDecorationStyle(FrameNode* frameNode, TextDecorationStyle value)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, TextDecorationStyle, value, frameNode);
}

void TextModelNG::SetBaselineOffset(const Dimension& value)
{
    ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, BaselineOffset, value);
}

void TextModelNG::SetTextCase(Ace::TextCase value)
{
    ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, TextCase, value);
}

void TextModelNG::SetLetterSpacing(const Dimension& value)
{
    ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, LetterSpacing, value);
}

void TextModelNG::SetAdaptMinFontSize(const Dimension& value)
{
    ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, AdaptMinFontSize, value);
}

void TextModelNG::SetAdaptMaxFontSize(const Dimension& value)
{
    ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, AdaptMaxFontSize, value);
}

void TextModelNG::SetHeightAdaptivePolicy(TextHeightAdaptivePolicy value)
{
    ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, HeightAdaptivePolicy, value);
}

void TextModelNG::SetTextDetectEnable(bool value)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto textPattern = frameNode->GetPattern<TextPattern>();
    CHECK_NULL_VOID(textPattern);
    textPattern->SetTextDetectEnable(value);
}

void TextModelNG::SetTextDetectConfig(const std::string& value, std::function<void(const std::string&)>&& onResult)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto textPattern = frameNode->GetPattern<TextPattern>();
    CHECK_NULL_VOID(textPattern);
    textPattern->SetTextDetectTypes(value);
    textPattern->SetOnResult(std::move(onResult));
}

void TextModelNG::SetOnClick(std::function<void(BaseEventInfo* info)>&& click)
{
    auto clickFunc = [func = std::move(click)](GestureEvent& info) { func(&info); };
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto textPattern = frameNode->GetPattern<TextPattern>();
    CHECK_NULL_VOID(textPattern);
    textPattern->SetOnClickEvent(std::move(clickFunc));
}

void TextModelNG::ClearOnClick()
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto textPattern = frameNode->GetPattern<TextPattern>();
    CHECK_NULL_VOID(textPattern);
    textPattern->SetOnClickEvent(nullptr);
}

void TextModelNG::SetRemoteMessage(std::function<void()>&& event) {}

void TextModelNG::SetCopyOption(CopyOptions copyOption)
{
    ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, CopyOption, copyOption);
}

void TextModelNG::SetDraggable(bool draggable)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    frameNode->SetDraggable(draggable);
}

void TextModelNG::SetMenuOptionItems(std::vector<MenuOptionsParam>&& menuOptionsItems)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto textPattern = frameNode->GetPattern<TextPattern>();
    textPattern->SetMenuOptionItems(std::move(menuOptionsItems));
}

void TextModelNG::SetOnCopy(std::function<void(const std::string&)>&& func)
{
    auto eventHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeEventHub<TextEventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetOnCopy(std::move(func));
}

void TextModelNG::SetTextSelection(int32_t startIndex, int32_t endIndex)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto textPattern = frameNode->GetPattern<TextPattern>();
    CHECK_NULL_VOID(textPattern);
    textPattern->SetTextSelection(startIndex, endIndex);
}

void TextModelNG::SetOnDragStart(NG::OnDragStartFunc&& onDragStart)
{
    auto dragStart = [dragStartFunc = std::move(onDragStart)](
                         const RefPtr<OHOS::Ace::DragEvent>& event, const std::string& extraParams) -> DragDropInfo {
        auto dragInfo = dragStartFunc(event, extraParams);
        DragDropInfo info;
        info.extraInfo = dragInfo.extraInfo;
        info.pixelMap = dragInfo.pixelMap;
        info.customNode = AceType::DynamicCast<UINode>(dragInfo.node);
        return info;
    };
    ViewAbstract::SetOnDragStart(std::move(dragStart));
}

void TextModelNG::SetOnDragEnter(NG::OnDragDropFunc&& onDragEnter)
{
    ViewAbstract::SetOnDragEnter(std::move(onDragEnter));
}

void TextModelNG::SetOnDragMove(NG::OnDragDropFunc&& onDragMove)
{
    ViewAbstract::SetOnDragMove(std::move(onDragMove));
}

void TextModelNG::SetOnDragLeave(NG::OnDragDropFunc&& onDragLeave)
{
    ViewAbstract::SetOnDragLeave(std::move(onDragLeave));
}

void TextModelNG::SetOnDrop(NG::OnDragDropFunc&& onDrop)
{
    ViewAbstract::SetOnDrop(std::move(onDrop));
}

void TextModelNG::InitText(FrameNode* frameNode, std::string& value)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, Content, value, frameNode);
}

void TextModelNG::InitTextController(FrameNode* frameNode, const RefPtr<SpanStringBase>& spanBase)
{
    auto textPattern = ViewStackProcessor::GetInstance()->GetMainFrameNodePattern<TextPattern>(frameNode);
    CHECK_NULL_VOID(textPattern);
    auto spanString = AceType::DynamicCast<SpanString>(spanBase);
    if (spanString) {
        auto spans = spanString->GetSpanItems();
        textPattern->SetSpanItemChildren(spans);
        textPattern->SetSpanStringMode(true);
    }
}

void TextModelNG::SetTextCase(FrameNode* frameNode, Ace::TextCase value)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, TextCase, value, frameNode);
}

void TextModelNG::SetMaxLines(FrameNode* frameNode, uint32_t value)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, MaxLines, value, frameNode);
}

void TextModelNG::SetAdaptMinFontSize(FrameNode* frameNode, const Dimension& value)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, AdaptMinFontSize, value, frameNode);
}

void TextModelNG::SetDraggable(FrameNode* frameNode, bool draggable)
{
    CHECK_NULL_VOID(frameNode);
    frameNode->SetDraggable(draggable);
}

void TextModelNG::SetAdaptMaxFontSize(FrameNode* frameNode, const Dimension& value)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, AdaptMaxFontSize, value, frameNode);
}

void TextModelNG::SetFontFamily(FrameNode* frameNode, const std::vector<std::string>& value)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, FontFamily, value, frameNode);
}

void TextModelNG::SetCopyOption(FrameNode* frameNode, CopyOptions copyOption)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, CopyOption, copyOption, frameNode);
}

void TextModelNG::SetTextShadow(FrameNode* frameNode, const std::vector<Shadow>& value)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, TextShadow, value, frameNode);
}

void TextModelNG::SetHeightAdaptivePolicy(FrameNode* frameNode, TextHeightAdaptivePolicy value)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, HeightAdaptivePolicy, value, frameNode);
}

void TextModelNG::SetTextIndent(FrameNode* frameNode, const Dimension& value)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, TextIndent, value, frameNode);
}

void TextModelNG::SetBaselineOffset(FrameNode* frameNode, const Dimension& value)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, BaselineOffset, value, frameNode);
}

void TextModelNG::SetFont(FrameNode* frameNode, const Font& value)
{
    if (value.fontSize.has_value()) {
        SetFontSize(frameNode, value.fontSize.value());
    }
    if (value.fontWeight.has_value()) {
        SetFontWeight(frameNode, value.fontWeight.value());
    }
    if (!value.fontFamilies.empty()) {
        SetFontFamily(frameNode, value.fontFamilies);
    }
    if (value.fontStyle.has_value()) {
        SetItalicFontStyle(frameNode, value.fontStyle.value());
    }
}

void TextModelNG::SetLetterSpacing(FrameNode* frameNode, const Dimension& value)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, LetterSpacing, value, frameNode);
}

void TextModelNG::SetWordBreak(FrameNode* frameNode, Ace::WordBreak value)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, WordBreak, value, frameNode);
}

void TextModelNG::SetLineBreakStrategy(FrameNode* frameNode, Ace::LineBreakStrategy value)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, LineBreakStrategy, value, frameNode);
}

void TextModelNG::SetEllipsisMode(FrameNode* frameNode, Ace::EllipsisMode value)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, EllipsisMode, value, frameNode);
}

void TextModelNG::SetTextDetectEnable(FrameNode* frameNode, bool value)
{
    auto textPattern = frameNode->GetPattern<TextPattern>();
    CHECK_NULL_VOID(textPattern);
    textPattern->SetTextDetectEnable(value);
}

void TextModelNG::BindSelectionMenu(TextSpanType& spanType, TextResponseType& responseType,
    std::function<void()>& buildFunc, SelectMenuParam& menuParam)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto pattern = frameNode->GetPattern<TextPattern>();
    if (pattern) {
        pattern->BindSelectionMenu(spanType, responseType, buildFunc, menuParam.onAppear, menuParam.onDisappear);
    }
}

void TextModelNG::SetOnTextSelectionChange(std::function<void(int32_t, int32_t)>&& func)
{
    auto eventHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeEventHub<TextEventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetOnSelectionChange(std::move(func));
}

RefPtr<TextControllerBase> TextModelNG::GetTextController()
{
    auto pattern = ViewStackProcessor::GetInstance()->GetMainFrameNodePattern<TextPattern>();
    CHECK_NULL_RETURN(pattern, nullptr);
    return pattern->GetTextController();
}

void TextModelNG::SetClipEdge(bool clip)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    frameNode->GetRenderContext()->SetClipToFrame(clip);
    frameNode->MarkDirtyNode(PROPERTY_UPDATE_RENDER);
}

void TextModelNG::SetFontFeature(const FONT_FEATURES_LIST& value)
{
    ACE_UPDATE_LAYOUT_PROPERTY(TextLayoutProperty, FontFeature, value);
}

void TextModelNG::SetFontFeature(FrameNode* frameNode, const FONT_FEATURES_LIST& value)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, FontFeature, value, frameNode);
}

void TextModelNG::SetMarqueeOptions(const TextMarqueeOptions& options)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    if (options.HasTextMarqueeStart()) {
        ACE_UPDATE_NODE_LAYOUT_PROPERTY(
            TextLayoutProperty, TextMarqueeStart, options.GetTextMarqueeStartValue(), frameNode);
    } else {
        ACE_RESET_NODE_LAYOUT_PROPERTY(TextLayoutProperty, TextMarqueeStart, frameNode);
    }
    if (options.HasTextMarqueeStep()) {
        ACE_UPDATE_NODE_LAYOUT_PROPERTY(
            TextLayoutProperty, TextMarqueeStep, options.GetTextMarqueeStepValue(), frameNode);
    } else {
        ACE_RESET_NODE_LAYOUT_PROPERTY(TextLayoutProperty, TextMarqueeStep, frameNode);
    }
    if (options.HasTextMarqueeLoop()) {
        ACE_UPDATE_NODE_LAYOUT_PROPERTY(
            TextLayoutProperty, TextMarqueeLoop, options.GetTextMarqueeLoopValue(), frameNode);
    } else {
        ACE_RESET_NODE_LAYOUT_PROPERTY(TextLayoutProperty, TextMarqueeLoop, frameNode);
    }
    if (options.HasTextMarqueeDirection()) {
        ACE_UPDATE_NODE_LAYOUT_PROPERTY(
            TextLayoutProperty, TextMarqueeDirection, options.GetTextMarqueeDirectionValue(), frameNode);
    } else {
        ACE_RESET_NODE_LAYOUT_PROPERTY(TextLayoutProperty, TextMarqueeDirection, frameNode);
    }
    if (options.HasTextMarqueeDelay()) {
        ACE_UPDATE_NODE_LAYOUT_PROPERTY(
            TextLayoutProperty, TextMarqueeDelay, options.GetTextMarqueeDelayValue(), frameNode);
    } else {
        ACE_RESET_NODE_LAYOUT_PROPERTY(TextLayoutProperty, TextMarqueeDelay, frameNode);
    }
    if (options.HasTextMarqueeFadeout()) {
        ACE_UPDATE_NODE_LAYOUT_PROPERTY(
            TextLayoutProperty, TextMarqueeFadeout, options.GetTextMarqueeFadeoutValue(), frameNode);
    } else {
        ACE_RESET_NODE_LAYOUT_PROPERTY(TextLayoutProperty, TextMarqueeFadeout, frameNode);
    }
    if (options.HasTextMarqueeStartPolicy()) {
        ACE_UPDATE_NODE_LAYOUT_PROPERTY(
            TextLayoutProperty, TextMarqueeStartPolicy, options.GetTextMarqueeStartPolicyValue(), frameNode);
    } else {
        ACE_RESET_NODE_LAYOUT_PROPERTY(TextLayoutProperty, TextMarqueeStartPolicy, frameNode);
    }
}

void TextModelNG::SetOnMarqueeStateChange(std::function<void(int32_t)>&& func)
{
    auto eventHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeEventHub<TextEventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetOnMarqueeStateChange(std::move(func));
}

std::string TextModelNG::GetContent(FrameNode* frameNode)
{
    CHECK_NULL_RETURN(frameNode, "");
    auto layoutProperty = frameNode->GetLayoutProperty<TextLayoutProperty>();
    CHECK_NULL_RETURN(layoutProperty, "");
    return layoutProperty->GetContent().value_or("");
}

float TextModelNG::GetLineHeight(FrameNode* frameNode)
{
    CHECK_NULL_RETURN(frameNode, 0.0f);
    auto layoutProperty = frameNode->GetLayoutProperty<TextLayoutProperty>();
    CHECK_NULL_RETURN(layoutProperty, 0.0f);
    Dimension defaultLineHeight(0);
    auto value = layoutProperty->GetLineHeight().value_or(defaultLineHeight);
    return static_cast<float>(value.Value());
}

float TextModelNG::GetLineSpacing(FrameNode* frameNode)
{
    CHECK_NULL_RETURN(frameNode, 0.0f);
    auto layoutProperty = frameNode->GetLayoutProperty<TextLayoutProperty>();
    CHECK_NULL_RETURN(layoutProperty, 0.0f);
    Dimension defaultLineSpacing(0);
    auto value = layoutProperty->GetLineSpacing().value_or(defaultLineSpacing);
    return static_cast<float>(value.Value());
}

TextDecoration TextModelNG::GetDecoration(FrameNode* frameNode)
{
    CHECK_NULL_RETURN(frameNode, TextDecoration::NONE);
    auto layoutProperty = frameNode->GetLayoutProperty<TextLayoutProperty>();
    CHECK_NULL_RETURN(layoutProperty, TextDecoration::NONE);
    return layoutProperty->GetTextDecoration().value_or(TextDecoration::NONE);
}

Color TextModelNG::GetTextDecorationColor(FrameNode* frameNode)
{
    CHECK_NULL_RETURN(frameNode, Color::BLACK);
    auto layoutProperty = frameNode->GetLayoutProperty<TextLayoutProperty>();
    CHECK_NULL_RETURN(layoutProperty, Color::BLACK);
    return layoutProperty->GetTextDecorationColor().value_or(Color::BLACK);
}

TextDecorationStyle TextModelNG::GetTextDecorationStyle(FrameNode* frameNode)
{
    CHECK_NULL_RETURN(frameNode, TextDecorationStyle::SOLID);
    auto layoutProperty = frameNode->GetLayoutProperty<TextLayoutProperty>();
    CHECK_NULL_RETURN(layoutProperty, TextDecorationStyle::SOLID);
    return layoutProperty->GetTextDecorationStyle().value_or(TextDecorationStyle::SOLID);
}

TextCase TextModelNG::GetTextCase(FrameNode* frameNode)
{
    CHECK_NULL_RETURN(frameNode, TextCase::NORMAL);
    auto layoutProperty = frameNode->GetLayoutProperty<TextLayoutProperty>();
    CHECK_NULL_RETURN(layoutProperty, TextCase::NORMAL);
    return layoutProperty->GetTextCase().value_or(TextCase::NORMAL);
}

Dimension TextModelNG::GetLetterSpacing(FrameNode* frameNode)
{
    Dimension defaultSpacing(0);
    CHECK_NULL_RETURN(frameNode, defaultSpacing);
    auto layoutProperty = frameNode->GetLayoutProperty<TextLayoutProperty>();
    CHECK_NULL_RETURN(layoutProperty, defaultSpacing);
    return layoutProperty->GetLetterSpacing().value_or(defaultSpacing);
}

uint32_t TextModelNG::GetMaxLines(FrameNode* frameNode)
{
    uint32_t defaultMaxLines = Infinity<uint32_t>();
    CHECK_NULL_RETURN(frameNode, defaultMaxLines);
    auto layoutProperty = frameNode->GetLayoutProperty<TextLayoutProperty>();
    CHECK_NULL_RETURN(layoutProperty, defaultMaxLines);
    auto& textLineStyle = layoutProperty->GetTextLineStyle();
    CHECK_NULL_RETURN(textLineStyle, defaultMaxLines);
    return textLineStyle->GetMaxLines().value_or(defaultMaxLines);
}

TextAlign TextModelNG::GetTextAlign(FrameNode* frameNode)
{
    CHECK_NULL_RETURN(frameNode, OHOS::Ace::TextAlign::START);
    auto layoutProperty = frameNode->GetLayoutProperty<TextLayoutProperty>();
    CHECK_NULL_RETURN(layoutProperty, OHOS::Ace::TextAlign::START);
    auto& textLineStyle = layoutProperty->GetTextLineStyle();
    CHECK_NULL_RETURN(textLineStyle, OHOS::Ace::TextAlign::START);
    return textLineStyle->GetTextAlign().value_or(TextAlign::START);
}

TextOverflow TextModelNG::GetTextOverflow(FrameNode* frameNode)
{
    CHECK_NULL_RETURN(frameNode, TextOverflow::CLIP);
    auto layoutProperty = frameNode->GetLayoutProperty<TextLayoutProperty>();
    CHECK_NULL_RETURN(layoutProperty, TextOverflow::CLIP);
    auto& textLineStyle = layoutProperty->GetTextLineStyle();
    CHECK_NULL_RETURN(textLineStyle, TextOverflow::CLIP);
    return textLineStyle->GetTextOverflow().value_or(TextOverflow::CLIP);
}

Dimension TextModelNG::GetTextIndent(FrameNode* frameNode)
{
    Dimension defaultTextIndent(0);
    CHECK_NULL_RETURN(frameNode, defaultTextIndent);
    auto layoutProperty = frameNode->GetLayoutProperty<TextLayoutProperty>();
    CHECK_NULL_RETURN(layoutProperty, defaultTextIndent);
    auto& textLineStyle = layoutProperty->GetTextLineStyle();
    CHECK_NULL_RETURN(textLineStyle, defaultTextIndent);
    return textLineStyle->GetTextIndent().value_or(defaultTextIndent);
}

std::vector<std::string> TextModelNG::GetFontFamily(FrameNode* frameNode)
{
    std::vector<std::string> value;
    ACE_GET_NODE_LAYOUT_PROPERTY_WITH_DEFAULT_VALUE(TextLayoutProperty, FontFamily, value, frameNode, value);
    return value;
}

CopyOptions TextModelNG::GetCopyOption(FrameNode* frameNode)
{
    CopyOptions value = CopyOptions::None;
    ACE_GET_NODE_LAYOUT_PROPERTY_WITH_DEFAULT_VALUE(TextLayoutProperty, CopyOption, value, frameNode, value);
    return value;
}

TextMarqueeOptions TextModelNG::GetMarqueeOptions(FrameNode* frameNode)
{
    TextMarqueeOptions options;
    CHECK_NULL_RETURN(frameNode, options);
    auto layoutProperty = frameNode->GetLayoutProperty<TextLayoutProperty>();
    CHECK_NULL_RETURN(layoutProperty, options);

    if (layoutProperty->HasTextMarqueeStart()) {
        options.UpdateTextMarqueeStart(layoutProperty->GetTextMarqueeStart().value());
    }
    if (layoutProperty->HasTextMarqueeStep()) {
        options.UpdateTextMarqueeStep(layoutProperty->GetTextMarqueeStep().value());
    }
    if (layoutProperty->HasTextMarqueeLoop()) {
        options.UpdateTextMarqueeLoop(layoutProperty->GetTextMarqueeLoop().value());
    }
    if (layoutProperty->HasTextMarqueeDirection()) {
        options.UpdateTextMarqueeDirection(layoutProperty->GetTextMarqueeDirection().value());
    }
    if (layoutProperty->HasTextMarqueeDelay()) {
        options.UpdateTextMarqueeDelay(layoutProperty->GetTextMarqueeDelay().value());
    }
    if (layoutProperty->HasTextMarqueeFadeout()) {
        options.UpdateTextMarqueeFadeout(layoutProperty->GetTextMarqueeFadeout().value());
    }
    if (layoutProperty->HasTextMarqueeStartPolicy()) {
        options.UpdateTextMarqueeStartPolicy(layoutProperty->GetTextMarqueeStartPolicy().value());
    }

    return options;
}

TextHeightAdaptivePolicy TextModelNG::GetHeightAdaptivePolicy(FrameNode* frameNode)
{
    TextHeightAdaptivePolicy value = TextHeightAdaptivePolicy::MAX_LINES_FIRST;
    ACE_GET_NODE_LAYOUT_PROPERTY_WITH_DEFAULT_VALUE(TextLayoutProperty, HeightAdaptivePolicy, value, frameNode, value);
    return value;
}

Dimension TextModelNG::GetAdaptMinFontSize(FrameNode* frameNode)
{
    Dimension value;
    ACE_GET_NODE_LAYOUT_PROPERTY_WITH_DEFAULT_VALUE(
        TextLayoutProperty, AdaptMinFontSize, value, frameNode, Dimension());
    return value;
}

Dimension TextModelNG::GetAdaptMaxFontSize(FrameNode* frameNode)
{
    Dimension value;
    ACE_GET_NODE_LAYOUT_PROPERTY_WITH_DEFAULT_VALUE(
        TextLayoutProperty, AdaptMaxFontSize, value, frameNode, Dimension());
    return value;
}

Font TextModelNG::GetFont(FrameNode* frameNode)
{
    Font value;
    value.fontSize = GetFontSize(frameNode);
    value.fontWeight = GetFontWeight(frameNode);
    value.fontFamilies = GetFontFamily(frameNode);
    value.fontStyle = GetItalicFontStyle(frameNode);
    return value;
}

Dimension TextModelNG::GetFontSize(FrameNode* frameNode)
{
    Dimension value;
    ACE_GET_NODE_LAYOUT_PROPERTY_WITH_DEFAULT_VALUE(TextLayoutProperty, FontSize, value, frameNode, Dimension());
    return value;
}

Ace::FontWeight TextModelNG::GetFontWeight(FrameNode* frameNode)
{
    Ace::FontWeight value = Ace::FontWeight::NORMAL;
    ACE_GET_NODE_LAYOUT_PROPERTY_WITH_DEFAULT_VALUE(TextLayoutProperty, FontWeight, value, frameNode, value);
    return value;
}

Ace::FontStyle TextModelNG::GetItalicFontStyle(FrameNode* frameNode)
{
    Ace::FontStyle value = Ace::FontStyle::NORMAL;
    ACE_GET_NODE_LAYOUT_PROPERTY_WITH_DEFAULT_VALUE(TextLayoutProperty, ItalicFontStyle, value, frameNode, value);
    return value;
}

Color TextModelNG::GetDefaultColor()
{
    auto context = PipelineContext::GetCurrentContextSafely();
    CHECK_NULL_RETURN(context, Color::BLACK);
    auto theme = context->GetTheme<TextTheme>();
    CHECK_NULL_RETURN(theme, Color::BLACK);
    return theme->GetTextStyle().GetTextColor();
}

Color TextModelNG::GetFontColor(FrameNode* frameNode)
{
    auto defaultColor = GetDefaultColor();
    CHECK_NULL_RETURN(frameNode, defaultColor);
    auto layoutProperty = frameNode->GetLayoutProperty<TextLayoutProperty>();
    CHECK_NULL_RETURN(layoutProperty, defaultColor);
    return layoutProperty->GetTextColor().value_or(defaultColor);
}

Dimension TextModelNG::GetTextBaselineOffset(FrameNode* frameNode)
{
    Dimension defaultOffset(0);
    CHECK_NULL_RETURN(frameNode, defaultOffset);
    auto layoutProperty = frameNode->GetLayoutProperty<TextLayoutProperty>();
    CHECK_NULL_RETURN(layoutProperty, defaultOffset);
    return layoutProperty->GetBaselineOffset().value_or(defaultOffset);
}

std::vector<Shadow> TextModelNG::GetTextShadow(FrameNode* frameNode)
{
    std::vector<Shadow> defaultShadow;
    CHECK_NULL_RETURN(frameNode, defaultShadow);
    auto layoutProperty = frameNode->GetLayoutProperty<TextLayoutProperty>();
    CHECK_NULL_RETURN(layoutProperty, defaultShadow);
    return layoutProperty->GetTextShadow().value_or(defaultShadow);
}

Ace::WordBreak TextModelNG::GetWordBreak(FrameNode* frameNode)
{
    Ace::WordBreak value = Ace::WordBreak::BREAK_WORD;
    ACE_GET_NODE_LAYOUT_PROPERTY_WITH_DEFAULT_VALUE(TextLayoutProperty, WordBreak, value, frameNode, value);
    return value;
}

EllipsisMode TextModelNG::GetEllipsisMode(FrameNode* frameNode)
{
    EllipsisMode value = EllipsisMode::TAIL;
    ACE_GET_NODE_LAYOUT_PROPERTY_WITH_DEFAULT_VALUE(TextLayoutProperty, EllipsisMode, value, frameNode, value);
    return value;
}

bool TextModelNG::GetTextDetectEnable(FrameNode* frameNode)
{
    auto textPattern = frameNode->GetPattern<TextPattern>();
    CHECK_NULL_RETURN(textPattern, false);
    return textPattern->GetTextDetectEnable();
}

void TextModelNG::SetTextDetectConfig(FrameNode* frameNode, const std::string& value)
{
    CHECK_NULL_VOID(frameNode);
    auto textPattern = frameNode->GetPattern<TextPattern>();
    CHECK_NULL_VOID(textPattern);
    textPattern->SetTextDetectTypes(value);
}

void TextModelNG::SetOnDetectResultUpdate(FrameNode* frameNode,  std::function<void(const std::string&)>&& onResult)
{
    CHECK_NULL_VOID(frameNode);
    auto textPattern = frameNode->GetPattern<TextPattern>();
    CHECK_NULL_VOID(textPattern);
    textPattern->SetOnResult(std::move(onResult));
}

std::string TextModelNG::GetTextDetectConfig(FrameNode* frameNode)
{
    CHECK_NULL_RETURN(frameNode, "");
    auto textPattern = frameNode->GetPattern<TextPattern>();
    CHECK_NULL_RETURN(textPattern, "");
    return textPattern->GetTextDetectTypes();
}

FONT_FEATURES_LIST TextModelNG::GetFontFeature(FrameNode* frameNode)
{
    FONT_FEATURES_LIST value;
    ACE_GET_NODE_LAYOUT_PROPERTY_WITH_DEFAULT_VALUE(TextLayoutProperty, FontFeature, value, frameNode, value);
    return value;
}

LineBreakStrategy TextModelNG::GetLineBreakStrategy(FrameNode* frameNode)
{
    LineBreakStrategy value = LineBreakStrategy::GREEDY;
    ACE_GET_NODE_LAYOUT_PROPERTY_WITH_DEFAULT_VALUE(TextLayoutProperty, LineBreakStrategy, value, frameNode, value);
    return value;
}

void TextModelNG::SetSelectedBackgroundColor(FrameNode* frameNode, const Color& value)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(TextLayoutProperty, SelectedBackgroundColor, value, frameNode);
}

Color TextModelNG::GetSelectedBackgroundColor(FrameNode* frameNode)
{
    auto context = PipelineContext::GetCurrentContextSafely();
    CHECK_NULL_RETURN(context, Color::BLACK);
    auto theme = context->GetTheme<TextTheme>();
    CHECK_NULL_RETURN(theme, Color::BLACK);
    Color value = theme->GetSelectedColor();
    ACE_GET_NODE_LAYOUT_PROPERTY_WITH_DEFAULT_VALUE(TextLayoutProperty, SelectedBackgroundColor, value, frameNode,
        value);
    return value;
}

void TextModelNG::ResetSelectedBackgroundColor(FrameNode* frameNode)
{
    CHECK_NULL_VOID(frameNode);
    auto textLayoutProperty = frameNode->GetLayoutProperty<TextLayoutProperty>();
    if (textLayoutProperty) {
        textLayoutProperty->ResetSelectedBackgroundColor();
    }
}
} // namespace OHOS::Ace::NG
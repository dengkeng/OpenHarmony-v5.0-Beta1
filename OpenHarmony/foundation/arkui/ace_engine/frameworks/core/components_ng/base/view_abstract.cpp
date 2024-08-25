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

#include "core/components_ng/base/view_abstract.h"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>

#include "base/geometry/dimension.h"
#include "base/geometry/matrix4.h"
#include "base/geometry/ng/offset_t.h"
#include "base/memory/ace_type.h"
#include "base/subwindow/subwindow.h"
#include "base/utils/system_properties.h"
#include "base/utils/utils.h"
#include "core/common/container.h"
#include "core/components/common/layout/constants.h"
#include "core/components/common/properties/shadow.h"
#include "core/components/theme/shadow_theme.h"
#include "core/components_ng/base/frame_node.h"
#include "core/components_ng/base/view_stack_processor.h"
#include "core/components_ng/layout/layout_property.h"
#include "core/components_ng/pattern/bubble/bubble_pattern.h"
#include "core/components_ng/pattern/bubble/bubble_view.h"
#include "core/components_ng/pattern/dialog/dialog_pattern.h"
#include "core/components_ng/pattern/menu/menu_pattern.h"
#include "core/components_ng/pattern/menu/menu_view.h"
#include "core/components_ng/pattern/menu/preview/menu_preview_pattern.h"
#include "core/components_ng/pattern/menu/wrapper/menu_wrapper_pattern.h"
#include "core/components_ng/pattern/option/option_paint_property.h"
#include "core/components_ng/pattern/text/span_node.h"
#include "core/components_ng/property/border_property.h"
#include "core/components_ng/property/calc_length.h"
#include "core/components_ng/property/measure_property.h"
#include "core/components_ng/property/property.h"
#include "core/components_ng/property/safe_area_insets.h"
#include "core/components_v2/inspector/inspector_constants.h"
#include "core/image/image_source_info.h"
#include "core/pipeline_ng/pipeline_context.h"
#include "core/pipeline_ng/ui_task_scheduler.h"

namespace OHOS::Ace::NG {

void ViewAbstract::SetWidth(const CalcLength &width)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_VOID(layoutProperty);
    // get previously user defined ideal height
    std::optional<CalcLength> height = std::nullopt;
    auto &&layoutConstraint = layoutProperty->GetCalcLayoutConstraint();
    if (layoutConstraint && layoutConstraint->selfIdealSize) {
        height = layoutConstraint->selfIdealSize->Height();
    }
    layoutProperty->UpdateUserDefinedIdealSize(CalcSize(width, height));
}

void ViewAbstract::SetHeight(const CalcLength &height)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_VOID(layoutProperty);
    // get previously user defined ideal width
    std::optional<CalcLength> width = std::nullopt;
    auto &&layoutConstraint = layoutProperty->GetCalcLayoutConstraint();
    if (layoutConstraint && layoutConstraint->selfIdealSize) {
        width = layoutConstraint->selfIdealSize->Width();
    }
    layoutProperty->UpdateUserDefinedIdealSize(CalcSize(width, height));
}

void ViewAbstract::SetClickEffectLevel(const ClickEffectLevel &level, float scaleValue)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ClickEffectInfo clickEffectInfo;
    clickEffectInfo.level = level;
    clickEffectInfo.scaleNumber = scaleValue;
    ACE_UPDATE_RENDER_CONTEXT(ClickEffectLevel, clickEffectInfo);
}

void ViewAbstract::ClearWidthOrHeight(bool isWidth)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_VOID(layoutProperty);
    layoutProperty->ClearUserDefinedIdealSize(isWidth, !isWidth);
}

void ViewAbstract::SetMinWidth(const CalcLength &width)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_VOID(layoutProperty);
    layoutProperty->UpdateCalcMinSize(CalcSize(width, std::nullopt));
}

void ViewAbstract::SetMinHeight(const CalcLength &height)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_VOID(layoutProperty);
    layoutProperty->UpdateCalcMinSize(CalcSize(std::nullopt, height));
}

void ViewAbstract::ResetMinSize(bool resetWidth)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_VOID(layoutProperty);
    layoutProperty->ResetCalcMinSize(resetWidth);
}

void ViewAbstract::SetMaxWidth(const CalcLength &width)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_VOID(layoutProperty);
    layoutProperty->UpdateCalcMaxSize(CalcSize(width, std::nullopt));
}

void ViewAbstract::SetMaxHeight(const CalcLength &height)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_VOID(layoutProperty);
    layoutProperty->UpdateCalcMaxSize(CalcSize(std::nullopt, height));
}

void ViewAbstract::ResetMaxSize(bool resetWidth)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_VOID(layoutProperty);
    layoutProperty->ResetCalcMaxSize(resetWidth);
}

void ViewAbstract::SetAspectRatio(float ratio)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_LAYOUT_PROPERTY(LayoutProperty, AspectRatio, ratio);
}

void ViewAbstract::ResetAspectRatio()
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_RESET_LAYOUT_PROPERTY(LayoutProperty, AspectRatio);
}

void ViewAbstract::SetBackgroundAlign(const Alignment &align)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(BackgroundAlign, align);
}

void ViewAbstract::SetBackgroundColor(const Color &color)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }

    Color updateColor = color;
    auto pipeline = PipelineContext::GetCurrentContext();
    if (pipeline != nullptr) {
        pipeline->CheckNeedUpdateBackgroundColor(updateColor);
    }

    ACE_UPDATE_RENDER_CONTEXT(BackgroundColor, updateColor);
}

void ViewAbstract::SetBackgroundColor(FrameNode *frameNode, const Color &color)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(BackgroundColor, color, frameNode);
}

void ViewAbstract::SetBackgroundImage(const ImageSourceInfo &src)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    auto pipeline = PipelineContext::GetCurrentContext();
    if (pipeline != nullptr) {
        bool disableSetImage = pipeline->CheckNeedDisableUpdateBackgroundImage();
        if (disableSetImage) {
            return;
        }
    }
    ACE_UPDATE_RENDER_CONTEXT(BackgroundImage, src);
}

void ViewAbstract::SetBackgroundImage(FrameNode *frameNode, const ImageSourceInfo &src)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(BackgroundImage, src, frameNode);
}

void ViewAbstract::SetBackgroundImageRepeat(const ImageRepeat &imageRepeat)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(BackgroundImageRepeat, imageRepeat);
}

void ViewAbstract::SetBackgroundImageRepeat(FrameNode *frameNode, const ImageRepeat &imageRepeat)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(BackgroundImageRepeat, imageRepeat, frameNode);
}

void ViewAbstract::SetBackgroundImageSize(const BackgroundImageSize &bgImgSize)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(BackgroundImageSize, bgImgSize);
}

void ViewAbstract::SetBackgroundImageSize(FrameNode *frameNode, const BackgroundImageSize &bgImgSize)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(BackgroundImageSize, bgImgSize, frameNode);
}

void ViewAbstract::SetBackgroundImagePosition(const BackgroundImagePosition &bgImgPosition)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(BackgroundImagePosition, bgImgPosition);
}

void ViewAbstract::SetBackgroundImagePosition(FrameNode *frameNode, const BackgroundImagePosition &bgImgPosition)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(BackgroundImagePosition, bgImgPosition, frameNode);
}

void ViewAbstract::SetBackgroundBlurStyle(const BlurStyleOption &bgBlurStyle)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto target = frameNode->GetRenderContext();
    if (target) {
        if (target->GetBackgroundEffect().has_value()) {
            target->UpdateBackgroundEffect(std::nullopt);
        }
        target->UpdateBackBlurStyle(bgBlurStyle);
        if (target->GetBackBlurRadius().has_value()) {
            target->UpdateBackBlurRadius(Dimension());
        }
    }
}

void ViewAbstract::SetForegroundEffect(float radius)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto target = frameNode->GetRenderContext();
    if (target) {
        target->UpdateForegroundEffect(radius);
    }
}

void ViewAbstract::SetMotionBlur(const MotionBlurOption &motionBlurOption)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(MotionBlur, motionBlurOption);
}

void ViewAbstract::SetBackgroundEffect(const EffectOption &effectOption)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto target = frameNode->GetRenderContext();
    if (target) {
        if (target->GetBackBlurRadius().has_value()) {
            target->UpdateBackBlurRadius(Dimension());
        }
        if (target->GetBackBlurStyle().has_value()) {
            target->UpdateBackBlurStyle(std::nullopt);
        }
        target->UpdateBackgroundEffect(effectOption);
    }
}

void ViewAbstract::SetForegroundBlurStyle(const BlurStyleOption &fgBlurStyle)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto target = frameNode->GetRenderContext();
    if (target) {
        target->UpdateFrontBlurStyle(fgBlurStyle);
        if (target->GetFrontBlurRadius().has_value()) {
            target->UpdateFrontBlurRadius(Dimension());
        }
    }
}

void ViewAbstract::SetSphericalEffect(double radio)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(SphericalEffect, radio);
}

void ViewAbstract::SetPixelStretchEffect(PixStretchEffectOption &option)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(PixelStretchEffect, option);
}

void ViewAbstract::SetLightUpEffect(double radio)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(LightUpEffect, radio);
}

void ViewAbstract::SetLayoutWeight(float value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_LAYOUT_PROPERTY(LayoutProperty, LayoutWeight, static_cast<float>(value));
}

void ViewAbstract::SetPixelRound(uint8_t value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_LAYOUT_PROPERTY(LayoutProperty, PixelRound, value);
}

void ViewAbstract::SetLayoutDirection(TextDirection value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_LAYOUT_PROPERTY(LayoutProperty, LayoutDirection, value);
}

void ViewAbstract::SetAlignRules(const std::map<AlignDirection, AlignRule> &alignRules)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_LAYOUT_PROPERTY(LayoutProperty, AlignRules, alignRules);
}

void ViewAbstract::SetChainStyle(const ChainInfo& chainInfo)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_LAYOUT_PROPERTY(LayoutProperty, ChainStyle, chainInfo);
}

void ViewAbstract::SetBias(const BiasPair& biasPair)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_LAYOUT_PROPERTY(LayoutProperty, Bias, biasPair);
}

void ViewAbstract::SetAlignSelf(FlexAlign value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_LAYOUT_PROPERTY(LayoutProperty, AlignSelf, value);
}

void ViewAbstract::SetFlexShrink(float value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_LAYOUT_PROPERTY(LayoutProperty, FlexShrink, value);
}

void ViewAbstract::ResetFlexShrink()
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_RESET_LAYOUT_PROPERTY(LayoutProperty, FlexShrink);
}

void ViewAbstract::SetFlexGrow(float value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_LAYOUT_PROPERTY(LayoutProperty, FlexGrow, value);
}

void ViewAbstract::SetFlexBasis(const Dimension &value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    if (LessNotEqual(value.Value(), 0.0f)) {
        ACE_UPDATE_LAYOUT_PROPERTY(LayoutProperty, FlexBasis, Dimension());
        return;
    }
    ACE_UPDATE_LAYOUT_PROPERTY(LayoutProperty, FlexBasis, value);
}

void ViewAbstract::SetDisplayIndex(int32_t value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_LAYOUT_PROPERTY(LayoutProperty, DisplayIndex, value);
}

void ViewAbstract::SetPadding(const CalcLength &value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    PaddingProperty padding;
    padding.SetEdges(value);
    ACE_UPDATE_LAYOUT_PROPERTY(LayoutProperty, Padding, padding);
}

void ViewAbstract::SetPadding(const PaddingProperty &value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_LAYOUT_PROPERTY(LayoutProperty, Padding, value);
}

void ViewAbstract::SetMargin(const CalcLength &value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    MarginProperty margin;
    margin.SetEdges(value);
    ACE_UPDATE_LAYOUT_PROPERTY(LayoutProperty, Margin, margin);
}

void ViewAbstract::SetMargin(const MarginProperty &value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_LAYOUT_PROPERTY(LayoutProperty, Margin, value);
}

void ViewAbstract::SetBorderRadius(const Dimension &value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    BorderRadiusProperty borderRadius;
    borderRadius.SetRadius(value);
    borderRadius.multiValued = false;
    ACE_UPDATE_RENDER_CONTEXT(BorderRadius, borderRadius);
}

void ViewAbstract::SetBorderRadius(const BorderRadiusProperty &value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(BorderRadius, value);
}

void ViewAbstract::SetBorderColor(const Color &value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    BorderColorProperty borderColor;
    borderColor.SetColor(value);
    ACE_UPDATE_RENDER_CONTEXT(BorderColor, borderColor);
}

void ViewAbstract::SetBorderColor(const BorderColorProperty &value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(BorderColor, value);
}

void ViewAbstract::SetBorderWidth(const Dimension &value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    BorderWidthProperty borderWidth;
    if (Negative(value.Value())) {
        borderWidth.SetBorderWidth(Dimension(0));
    } else {
        borderWidth.SetBorderWidth(value);
    }
    ACE_UPDATE_LAYOUT_PROPERTY(LayoutProperty, BorderWidth, borderWidth);
    ACE_UPDATE_RENDER_CONTEXT(BorderWidth, borderWidth);
}

void ViewAbstract::SetBorderWidth(const BorderWidthProperty &value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_LAYOUT_PROPERTY(LayoutProperty, BorderWidth, value);
    ACE_UPDATE_RENDER_CONTEXT(BorderWidth, value);
}

void ViewAbstract::SetBorderStyle(const BorderStyle &value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    BorderStyleProperty borderStyle;
    borderStyle.SetBorderStyle(value);
    ACE_UPDATE_RENDER_CONTEXT(BorderStyle, borderStyle);
}

void ViewAbstract::SetBorderStyle(FrameNode *frameNode, const BorderStyle &value)
{
    BorderStyleProperty borderStyle;
    borderStyle.SetBorderStyle(value);
    ACE_UPDATE_NODE_RENDER_CONTEXT(BorderStyle, borderStyle, frameNode);
}

void ViewAbstract::SetBorderStyle(const BorderStyleProperty &value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(BorderStyle, value);
}

void ViewAbstract::SetBorderStyle(FrameNode *frameNode, const BorderStyleProperty &value)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(BorderStyle, value, frameNode);
}

void ViewAbstract::SetOuterBorderRadius(const Dimension& value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    BorderRadiusProperty borderRadius;
    borderRadius.SetRadius(value);
    borderRadius.multiValued = false;
    ACE_UPDATE_RENDER_CONTEXT(OuterBorderRadius, borderRadius);
}

void ViewAbstract::SetOuterBorderRadius(FrameNode* frameNode, const Dimension& value)
{
    BorderRadiusProperty borderRadius;
    borderRadius.SetRadius(value);
    borderRadius.multiValued = false;
    ACE_UPDATE_NODE_RENDER_CONTEXT(OuterBorderRadius, borderRadius, frameNode);
}

void ViewAbstract::SetOuterBorderRadius(const BorderRadiusProperty& value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(OuterBorderRadius, value);
}

void ViewAbstract::SetOuterBorderRadius(FrameNode* frameNode, const BorderRadiusProperty& value)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(OuterBorderRadius, value, frameNode);
}

void ViewAbstract::SetOuterBorderColor(const Color& value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    BorderColorProperty borderColor;
    borderColor.SetColor(value);
    ACE_UPDATE_RENDER_CONTEXT(OuterBorderColor, borderColor);
}

void ViewAbstract::SetOuterBorderColor(FrameNode* frameNode, const Color& value)
{
    BorderColorProperty borderColor;
    borderColor.SetColor(value);
    ACE_UPDATE_NODE_RENDER_CONTEXT(OuterBorderColor, borderColor, frameNode);
}

void ViewAbstract::SetOuterBorderColor(const BorderColorProperty& value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(OuterBorderColor, value);
}

void ViewAbstract::SetOuterBorderColor(FrameNode* frameNode, const BorderColorProperty& value)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(OuterBorderColor, value, frameNode);
}

void ViewAbstract::SetOuterBorderWidth(const Dimension& value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    BorderWidthProperty borderWidth;
    if (Negative(value.Value())) {
        borderWidth.SetBorderWidth(Dimension(0));
    } else {
        borderWidth.SetBorderWidth(value);
    }
    ACE_UPDATE_RENDER_CONTEXT(OuterBorderWidth, borderWidth);
}

void ViewAbstract::SetOuterBorderWidth(FrameNode* frameNode, const Dimension& value)
{
    BorderWidthProperty borderWidth;
    if (Negative(value.Value())) {
        borderWidth.SetBorderWidth(Dimension(0));
    } else {
        borderWidth.SetBorderWidth(value);
    }
    ACE_UPDATE_NODE_RENDER_CONTEXT(OuterBorderWidth, borderWidth, frameNode);
}

void ViewAbstract::SetOuterBorderWidth(const BorderWidthProperty& value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(OuterBorderWidth, value);
}

void ViewAbstract::SetOuterBorderWidth(FrameNode* frameNode, const BorderWidthProperty& value)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(OuterBorderWidth, value, frameNode);
}

void ViewAbstract::SetOuterBorderStyle(const BorderStyleProperty& value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(OuterBorderStyle, value);
}

void ViewAbstract::SetOuterBorderStyle(FrameNode* frameNode, const BorderStyleProperty& value)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(OuterBorderStyle, value, frameNode);
}

void ViewAbstract::SetOuterBorderStyle(const BorderStyle& value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    BorderStyleProperty borderStyle;
    borderStyle.SetBorderStyle(value);
    ACE_UPDATE_RENDER_CONTEXT(OuterBorderStyle, borderStyle);
}

void ViewAbstract::SetOuterBorderStyle(FrameNode* frameNode, const BorderStyle& value)
{
    BorderStyleProperty borderStyle;
    borderStyle.SetBorderStyle(value);
    ACE_UPDATE_NODE_RENDER_CONTEXT(OuterBorderStyle, borderStyle, frameNode);
}

void ViewAbstract::DisableOnClick()
{
    auto gestureHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->ClearUserOnClick();
}

void ViewAbstract::DisableOnTouch()
{
    auto gestureHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->ClearUserOnTouch();
}

void ViewAbstract::DisableOnKeyEvent()
{
    auto focusHub = ViewStackProcessor::GetInstance()->GetOrCreateMainFrameNodeFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->ClearUserOnKey();
}

void ViewAbstract::DisableOnHover()
{
    auto eventHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeInputEventHub();
    CHECK_NULL_VOID(eventHub);
    eventHub->ClearUserOnHover();
}

void ViewAbstract::DisableOnMouse()
{
    auto eventHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeInputEventHub();
    CHECK_NULL_VOID(eventHub);
    eventHub->ClearUserOnMouse();
}

void ViewAbstract::DisableOnAppear()
{
    auto eventHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeEventHub<EventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->ClearUserOnAppear();
}

void ViewAbstract::DisableOnDisAppear()
{
    auto eventHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeEventHub<EventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->ClearUserOnDisAppear();
}

void ViewAbstract::DisableOnAttach()
{
    auto eventHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeEventHub<EventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->ClearOnAttach();
}

void ViewAbstract::DisableOnDetach()
{
    auto eventHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeEventHub<EventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->ClearOnDetach();
}

void ViewAbstract::DisableOnAreaChange()
{
    auto pipeline = PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(pipeline);
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    frameNode->ClearUserOnAreaChange();
}

void ViewAbstract::DisableOnFocus()
{
    auto focusHub = ViewStackProcessor::GetInstance()->GetOrCreateMainFrameNodeFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->ClearUserOnFocus();
}

void ViewAbstract::DisableOnBlur()
{
    auto focusHub = ViewStackProcessor::GetInstance()->GetOrCreateMainFrameNodeFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->ClearUserOnBlur();
}

void ViewAbstract::DisableOnClick(FrameNode* frameNode)
{
    auto gestureHub = frameNode->GetOrCreateGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->ClearUserOnClick();
}

void ViewAbstract::DisableOnTouch(FrameNode* frameNode)
{
    auto gestureHub = frameNode->GetOrCreateGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->ClearUserOnTouch();
}

void ViewAbstract::DisableOnKeyEvent(FrameNode* frameNode)
{
    auto focusHub = frameNode->GetOrCreateFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->ClearUserOnKey();
}

void ViewAbstract::DisableOnHover(FrameNode* frameNode)
{
    auto eventHub = frameNode->GetOrCreateInputEventHub();
    CHECK_NULL_VOID(eventHub);
    eventHub->ClearUserOnHover();
}

void ViewAbstract::DisableOnMouse(FrameNode* frameNode)
{
    auto eventHub = frameNode->GetOrCreateInputEventHub();
    CHECK_NULL_VOID(eventHub);
    eventHub->ClearUserOnMouse();
}

void ViewAbstract::DisableOnAppear(FrameNode* frameNode)
{
    auto eventHub = frameNode->GetEventHub<EventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->ClearUserOnAppear();
}

void ViewAbstract::DisableOnDisappear(FrameNode* frameNode)
{
    auto eventHub = frameNode->GetEventHub<EventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->ClearUserOnDisAppear();
}

void ViewAbstract::DisableOnAttach(FrameNode* frameNode)
{
    auto eventHub = frameNode->GetEventHub<EventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->ClearOnAttach();
}

void ViewAbstract::DisableOnDetach(FrameNode* frameNode)
{
    auto eventHub = frameNode->GetEventHub<EventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->ClearOnDetach();
}

void ViewAbstract::DisableOnFocus(FrameNode* frameNode)
{
    auto focusHub = frameNode->GetOrCreateFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->ClearUserOnFocus();
}

void ViewAbstract::DisableOnBlur(FrameNode* frameNode)
{
    auto focusHub = frameNode->GetOrCreateFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->ClearUserOnBlur();
}

void ViewAbstract::DisableOnAreaChange(FrameNode* frameNode)
{
    CHECK_NULL_VOID(frameNode);
    frameNode->ClearUserOnAreaChange();
}

void ViewAbstract::SetOnClick(GestureEventFunc &&clickEventFunc)
{
    auto gestureHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->SetUserOnClick(std::move(clickEventFunc));

    auto focusHub = NG::ViewStackProcessor::GetInstance()->GetOrCreateMainFrameNodeFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->SetFocusable(true, false);
}

void ViewAbstract::SetOnGestureJudgeBegin(GestureJudgeFunc &&gestureJudgeFunc)
{
    auto gestureHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->SetOnGestureJudgeBegin(std::move(gestureJudgeFunc));
}

void ViewAbstract::SetOnTouchIntercept(TouchInterceptFunc&& touchInterceptFunc)
{
    auto gestureHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->SetOnTouchIntercept(std::move(touchInterceptFunc));
}

void ViewAbstract::SetOnTouch(TouchEventFunc &&touchEventFunc)
{
    auto gestureHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->SetTouchEvent(std::move(touchEventFunc));
}

void ViewAbstract::SetOnMouse(OnMouseEventFunc &&onMouseEventFunc)
{
    auto eventHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeInputEventHub();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetMouseEvent(std::move(onMouseEventFunc));
}

void ViewAbstract::SetOnHover(OnHoverFunc &&onHoverEventFunc)
{
    auto eventHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeInputEventHub();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetHoverEvent(std::move(onHoverEventFunc));
}

void ViewAbstract::SetHoverEffect(HoverEffectType hoverEffect)
{
    auto eventHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeInputEventHub();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetHoverEffect(hoverEffect);
}

void ViewAbstract::SetHoverEffectAuto(HoverEffectType hoverEffect)
{
    auto eventHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeInputEventHub();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetHoverEffectAuto(hoverEffect);
}

void ViewAbstract::SetEnabled(bool enabled)
{
    auto eventHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeEventHub<EventHub>();
    if (eventHub) {
        eventHub->SetEnabled(enabled);
    }

    // The SetEnabled of focusHub must be after at eventHub
    auto focusHub = ViewStackProcessor::GetInstance()->GetOrCreateMainFrameNodeFocusHub();
    if (focusHub) {
        focusHub->SetEnabled(enabled);
    }
}

void ViewAbstract::SetFocusable(bool focusable)
{
    auto focusHub = ViewStackProcessor::GetInstance()->GetOrCreateMainFrameNodeFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->SetFocusable(focusable);
}

void ViewAbstract::SetOnFocus(OnFocusFunc &&onFocusCallback)
{
    auto focusHub = ViewStackProcessor::GetInstance()->GetOrCreateMainFrameNodeFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->SetOnFocusCallback(std::move(onFocusCallback));
}

void ViewAbstract::SetOnBlur(OnBlurFunc &&onBlurCallback)
{
    auto focusHub = ViewStackProcessor::GetInstance()->GetOrCreateMainFrameNodeFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->SetOnBlurCallback(std::move(onBlurCallback));
}

void ViewAbstract::SetOnKeyEvent(OnKeyCallbackFunc &&onKeyCallback)
{
    auto focusHub = ViewStackProcessor::GetInstance()->GetOrCreateMainFrameNodeFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->SetOnKeyCallback(std::move(onKeyCallback));
}

void ViewAbstract::SetTabIndex(int32_t index)
{
    auto focusHub = ViewStackProcessor::GetInstance()->GetOrCreateMainFrameNodeFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->SetTabIndex(index);
}

void ViewAbstract::SetFocusOnTouch(bool isSet)
{
    auto focusHub = ViewStackProcessor::GetInstance()->GetOrCreateMainFrameNodeFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->SetIsFocusOnTouch(isSet);
}

void ViewAbstract::SetFocusBoxStyle(const NG::FocusBoxStyle& style)
{
    auto focusHub = ViewStackProcessor::GetInstance()->GetOrCreateMainFrameNodeFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->GetFocusBox().SetStyle(style);
}

void ViewAbstract::SetDefaultFocus(bool isSet)
{
    auto focusHub = ViewStackProcessor::GetInstance()->GetOrCreateMainFrameNodeFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->SetIsDefaultFocus(isSet);
}

void ViewAbstract::SetGroupDefaultFocus(bool isSet)
{
    auto focusHub = ViewStackProcessor::GetInstance()->GetOrCreateMainFrameNodeFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->SetIsDefaultGroupFocus(isSet);
}

void ViewAbstract::SetOnAppear(std::function<void()> &&onAppear)
{
    auto eventHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeEventHub<EventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetOnAppear(std::move(onAppear));
}

void ViewAbstract::SetOnDisappear(std::function<void()> &&onDisappear)
{
    auto eventHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeEventHub<EventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetOnDisappear(std::move(onDisappear));
}

void ViewAbstract::SetOnAttach(std::function<void()> &&onAttach)
{
    auto eventHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeEventHub<EventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetOnAttach(std::move(onAttach));
}

void ViewAbstract::SetOnDetach(std::function<void()> &&onDetach)
{
    auto eventHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeEventHub<EventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetOnDetach(std::move(onDetach));
}

void ViewAbstract::SetOnAreaChanged(std::function<void(const RectF &oldRect, const OffsetF &oldOrigin,
    const RectF &rect, const OffsetF &origin)> &&onAreaChanged)
{
    auto pipeline = PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(pipeline);
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    frameNode->SetOnAreaChangeCallback(std::move(onAreaChanged));
    pipeline->AddOnAreaChangeNode(frameNode->GetId());
}

void ViewAbstract::SetOnSizeChanged(std::function<void(const RectF &oldRect, const RectF &rect)> &&onSizeChanged)
{
    auto pipeline = PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(pipeline);
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    frameNode->SetOnSizeChangeCallback(std::move(onSizeChanged));
}

void ViewAbstract::SetOnVisibleChange(std::function<void(bool, double)> &&onVisibleChange,
    const std::vector<double> &ratioList)
{
    auto pipeline = PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(pipeline);
    auto frameNode = AceType::Claim(ViewStackProcessor::GetInstance()->GetMainFrameNode());
    CHECK_NULL_VOID(frameNode);
    frameNode->CleanVisibleAreaUserCallback();
    pipeline->AddVisibleAreaChangeNode(frameNode, ratioList, onVisibleChange);
}

void ViewAbstract::SetResponseRegion(const std::vector<DimensionRect> &responseRegion)
{
    auto gestureHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->SetResponseRegion(responseRegion);
}

void ViewAbstract::SetMouseResponseRegion(const std::vector<DimensionRect> &mouseRegion)
{
    auto gestureHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->SetMouseResponseRegion(mouseRegion);
}

void ViewAbstract::SetTouchable(bool touchable)
{
    auto gestureHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->SetTouchable(touchable);
}

void ViewAbstract::SetMonopolizeEvents(bool monopolizeEvents)
{
    auto gestureHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->SetMonopolizeEvents(monopolizeEvents);
}

void ViewAbstract::SetHitTestMode(HitTestMode hitTestMode)
{
    auto gestureHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->SetHitTestMode(hitTestMode);
}

void ViewAbstract::SetOnTouchTestFunc(NG::OnChildTouchTestFunc&& onChildTouchTest)
{
    auto gestureHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->SetOnTouchTestFunc(std::move(onChildTouchTest));
}

void ViewAbstract::AddDragFrameNodeToManager()
{
    auto pipeline = PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(pipeline);
    auto dragDropManager = pipeline->GetDragDropManager();
    CHECK_NULL_VOID(dragDropManager);
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);

    dragDropManager->AddDragFrameNode(frameNode->GetId(), AceType::WeakClaim(frameNode));
}

void ViewAbstract::SetDraggable(bool draggable)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto gestureHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    if (draggable) {
        if (!frameNode->IsDraggable()) {
            gestureHub->InitDragDropEvent();
        }
    } else {
        gestureHub->RemoveDragEvent();
    }
    frameNode->SetCustomerDraggable(draggable);
}

void ViewAbstract::SetDragPreviewOptions(const DragPreviewOption& previewOption)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    frameNode->SetDragPreviewOptions(previewOption);
}

void ViewAbstract::SetOnDragStart(
    std::function<DragDropInfo(const RefPtr<OHOS::Ace::DragEvent> &, const std::string &)> &&onDragStart)
{
    auto gestureHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->InitDragDropEvent();

    auto eventHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeEventHub<EventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetOnDragStart(std::move(onDragStart));
}

void ViewAbstract::SetOnPreDrag(std::function<void(const PreDragStatus)> &&onPreDragFunc)
{
    auto eventHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeEventHub<EventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetOnPreDrag(std::move(onPreDragFunc));
}

void ViewAbstract::SetOnDragEnter(
    std::function<void(const RefPtr<OHOS::Ace::DragEvent> &, const std::string &)> &&onDragEnter)
{
    auto eventHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeEventHub<EventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetCustomerOnDragFunc(DragFuncType::DRAG_ENTER, std::move(onDragEnter));

    AddDragFrameNodeToManager();
}

void ViewAbstract::SetOnDragLeave(
    std::function<void(const RefPtr<OHOS::Ace::DragEvent> &, const std::string &)> &&onDragLeave)
{
    auto eventHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeEventHub<EventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetCustomerOnDragFunc(DragFuncType::DRAG_LEAVE, std::move(onDragLeave));

    AddDragFrameNodeToManager();
}

void ViewAbstract::SetOnDragMove(
    std::function<void(const RefPtr<OHOS::Ace::DragEvent> &, const std::string &)> &&onDragMove)
{
    auto eventHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeEventHub<EventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetCustomerOnDragFunc(DragFuncType::DRAG_MOVE, std::move(onDragMove));

    AddDragFrameNodeToManager();
}

void ViewAbstract::SetOnDrop(std::function<void(const RefPtr<OHOS::Ace::DragEvent> &, const std::string &)> &&onDrop)
{
    auto eventHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeEventHub<EventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetCustomerOnDragFunc(DragFuncType::DRAG_DROP, std::move(onDrop));

    AddDragFrameNodeToManager();
}

void ViewAbstract::SetOnDragEnd(std::function<void(const RefPtr<OHOS::Ace::DragEvent> &)> &&onDragEnd)
{
    auto eventHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeEventHub<EventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetCustomerOnDragFunc(DragFuncType::DRAG_END, std::move(onDragEnd));

    AddDragFrameNodeToManager();
}

void ViewAbstract::SetAlign(Alignment alignment)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_LAYOUT_PROPERTY(LayoutProperty, Alignment, alignment);
}

void ViewAbstract::SetAlign(FrameNode *frameNode, Alignment alignment)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(LayoutProperty, Alignment, alignment, frameNode);
}

void ViewAbstract::SetVisibility(VisibleType visible)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto layoutProperty = frameNode->GetLayoutProperty();
    if (layoutProperty) {
        layoutProperty->UpdateVisibility(visible, true);
    }

    auto focusHub = ViewStackProcessor::GetInstance()->GetOrCreateMainFrameNodeFocusHub();
    if (focusHub) {
        focusHub->SetShow(visible == VisibleType::VISIBLE);
    }
}

void ViewAbstract::SetGeometryTransition(const std::string &id, bool followWithoutTransition)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto layoutProperty = frameNode->GetLayoutProperty();
    if (layoutProperty) {
        layoutProperty->UpdateGeometryTransition(id, followWithoutTransition);
    }
}

void ViewAbstract::SetGeometryTransition(FrameNode *frameNode, const std::string &id, bool followWithoutTransition)
{
    CHECK_NULL_VOID(frameNode);
    auto layoutProperty = frameNode->GetLayoutProperty();
    if (layoutProperty) {
        layoutProperty->UpdateGeometryTransition(id, followWithoutTransition);
    }
}

const std::string ViewAbstract::GetGeometryTransition(FrameNode* frameNode, bool* followWithoutTransition)
{
    CHECK_NULL_RETURN(frameNode, "");
    auto layoutProperty = frameNode->GetLayoutProperty();
    if (layoutProperty) {
        auto geometryTransition = layoutProperty->GetGeometryTransition();
        if (geometryTransition) {
            *followWithoutTransition = geometryTransition->GetFollowWithoutTransition();
            return geometryTransition->GetId();
        }
    }
    return "";
}

void ViewAbstract::SetOpacity(double opacity)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(Opacity, opacity);
}
void ViewAbstract::SetAllowDrop(const std::set<std::string> &allowDrop)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    frameNode->SetAllowDrop(allowDrop);
}

void ViewAbstract::SetDrawModifier(const RefPtr<NG::DrawModifier>& drawModifier)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    frameNode->SetDrawModifier(drawModifier);
}

void* ViewAbstract::GetFrameNode()
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    return static_cast<void*>(frameNode);
}

void ViewAbstract::SetDragPreview(const NG::DragDropInfo& info)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    frameNode->SetDragPreview(info);
}

void ViewAbstract::SetPosition(const OffsetT<Dimension> &value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_RESET_RENDER_CONTEXT(RenderContext, PositionEdges);
    ACE_UPDATE_RENDER_CONTEXT(Position, value);
}

void ViewAbstract::SetPositionEdges(const EdgesParam& value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_RESET_RENDER_CONTEXT(RenderContext, Position);
    ACE_UPDATE_RENDER_CONTEXT(PositionEdges, value);
}

void ViewAbstract::SetOffset(const OffsetT<Dimension> &value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_RESET_RENDER_CONTEXT(RenderContext, OffsetEdges);
    ACE_UPDATE_RENDER_CONTEXT(Offset, value);
}

void ViewAbstract::SetOffsetEdges(const EdgesParam& value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_RESET_RENDER_CONTEXT(RenderContext, Offset);
    ACE_UPDATE_RENDER_CONTEXT(OffsetEdges, value);
}

void ViewAbstract::MarkAnchor(const OffsetT<Dimension> &value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(Anchor, value);
}

void ViewAbstract::ResetPosition()
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_RESET_RENDER_CONTEXT(RenderContext, Position);
    ACE_RESET_RENDER_CONTEXT(RenderContext, PositionEdges);
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto parentNode = frameNode->GetAncestorNodeOfFrame();
    CHECK_NULL_VOID(parentNode);

    // Row/Column/Flex measure and layout differently depending on whether the child nodes have position property.
    if (parentNode->GetTag() == V2::COLUMN_ETS_TAG || parentNode->GetTag() == V2::ROW_ETS_TAG ||
        parentNode->GetTag() == V2::FLEX_ETS_TAG) {
        frameNode->MarkDirtyNode(PROPERTY_UPDATE_MEASURE);
    } else {
        auto renderContext = frameNode->GetRenderContext();
        CHECK_NULL_VOID(renderContext);
        renderContext->RecalculatePosition();
    }
}

void ViewAbstract::SetZIndex(int32_t value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(ZIndex, value);
}

void ViewAbstract::SetScale(const NG::VectorF &value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(TransformScale, value);
}

void ViewAbstract::SetScale(FrameNode *frameNode, const NG::VectorF &value)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(TransformScale, value, frameNode);
}

void ViewAbstract::SetPivot(const DimensionOffset &value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(TransformCenter, value);
}

void ViewAbstract::SetPivot(FrameNode *frameNode, const DimensionOffset &value)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(TransformCenter, value, frameNode);
}

void ViewAbstract::SetTranslate(const NG::TranslateOptions &value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(TransformTranslate, value);
}

void ViewAbstract::SetTranslate(FrameNode *frameNode, const NG::TranslateOptions &value)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(TransformTranslate, value, frameNode);
}

void ViewAbstract::SetRotate(const NG::Vector5F &value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(TransformRotate, value);
}

void ViewAbstract::SetRotate(FrameNode *frameNode, const NG::Vector5F &value)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(TransformRotate, value, frameNode);
}

void ViewAbstract::SetTransformMatrix(const Matrix4 &matrix)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(TransformMatrix, matrix);
}

void ViewAbstract::BindPopup(const RefPtr<PopupParam> &param, const RefPtr<FrameNode> &targetNode,
    const RefPtr<UINode> &customNode)
{
    TAG_LOGD(AceLogTag::ACE_DIALOG, "bind popup enter");
    CHECK_NULL_VOID(targetNode);
    auto targetId = targetNode->GetId();
    auto targetTag = targetNode->GetTag();
    auto container = Container::Current();
    CHECK_NULL_VOID(container);
    auto pipelineContext = container->GetPipelineContext();
    CHECK_NULL_VOID(pipelineContext);
    auto context = AceType::DynamicCast<NG::PipelineContext>(pipelineContext);
    CHECK_NULL_VOID(context);
    auto overlayManager = context->GetOverlayManager();
    CHECK_NULL_VOID(overlayManager);
    auto popupInfo = overlayManager->GetPopupInfo(targetId);
    auto isShow = param->IsShow();
    auto isUseCustom = param->IsUseCustom();
    auto showInSubWindow = param->IsShowInSubWindow();
    // subwindow model needs to use subContainer to get popupInfo
    if (showInSubWindow) {
        auto subwindow = SubwindowManager::GetInstance()->GetSubwindow(Container::CurrentId());
        if (subwindow) {
            subwindow->GetPopupInfoNG(targetId, popupInfo);
        }
    }

    auto popupId = popupInfo.popupId;
    auto popupNode = popupInfo.popupNode;
    RefPtr<BubblePattern> popupPattern;
    if (popupNode) {
        popupPattern = popupNode->GetPattern<BubblePattern>();
    }

    if (popupInfo.isCurrentOnShow) {
        // Entering / Normal / Exiting
        bool popupShowing = popupPattern ? popupPattern->IsOnShow() : false;
        popupInfo.markNeedUpdate = popupShowing || !isShow;
    } else {
        // Invisable
        if (!isShow) {
            TAG_LOGW(AceLogTag::ACE_DIALOG, "get isShow failed");
            return;
        }
        popupInfo.markNeedUpdate = true;
    }

    // Create new popup.
    if (popupInfo.popupId == -1 || !popupNode) {
        if (!isUseCustom) {
            popupNode = BubbleView::CreateBubbleNode(targetTag, targetId, param);
        } else {
            CHECK_NULL_VOID(customNode);
            popupNode = BubbleView::CreateCustomBubbleNode(targetTag, targetId, customNode, param);
        }
        if (popupNode) {
            popupId = popupNode->GetId();
        }
        if (!showInSubWindow) {
            // erase popup when target node destroy
            auto destructor = [id = targetNode->GetId()]() {
                auto pipeline = NG::PipelineContext::GetCurrentContext();
                CHECK_NULL_VOID(pipeline);
                auto overlayManager = pipeline->GetOverlayManager();
                CHECK_NULL_VOID(overlayManager);
                overlayManager->ErasePopup(id);
                SubwindowManager::GetInstance()->HideSubWindowNG();
            };
            targetNode->PushDestroyCallback(destructor);
        } else {
            // erase popup in subwindow when target node destroy
            auto destructor = [id = targetNode->GetId(), containerId = Container::CurrentId()]() {
                auto subwindow = SubwindowManager::GetInstance()->GetSubwindow(containerId);
                CHECK_NULL_VOID(subwindow);
                auto overlayManager = subwindow->GetOverlayManager();
                CHECK_NULL_VOID(overlayManager);
                overlayManager->ErasePopup(id);
                SubwindowManager::GetInstance()->HideSubWindowNG();
            };
            targetNode->PushDestroyCallback(destructor);
        }
    } else {
        // use param to update PopupParm
        if (!isUseCustom) {
            BubbleView::UpdatePopupParam(popupId, param, targetNode);
            popupNode->MarkDirtyNode(PROPERTY_UPDATE_MEASURE);
        } else {
            BubbleView::UpdateCustomPopupParam(popupId, param);
            popupNode->MarkDirtyNode(PROPERTY_UPDATE_MEASURE);
        }
    }
    // update PopupInfo props
    popupInfo.popupId = popupId;
    popupInfo.popupNode = popupNode;
    popupInfo.isBlockEvent = param->IsBlockEvent();
    if (popupNode) {
        popupNode->MarkModifyDone();
        popupPattern = popupNode->GetPattern<BubblePattern>();
    }
    popupInfo.focusable = param->GetFocusable();
    popupInfo.target = AceType::WeakClaim(AceType::RawPtr(targetNode));
    popupInfo.targetSize = SizeF(param->GetTargetSize().Width(), param->GetTargetSize().Height());
    popupInfo.targetOffset = OffsetF(param->GetTargetOffset().GetX(), param->GetTargetOffset().GetY());
    if (showInSubWindow) {
        if (isShow) {
            SubwindowManager::GetInstance()->ShowPopupNG(targetId, popupInfo);
        } else {
            SubwindowManager::GetInstance()->HidePopupNG(targetId);
        }
        return;
    }
    if (!popupInfo.isCurrentOnShow) {
        targetNode->OnAccessibilityEvent(AccessibilityEventType::CHANGE,
            WindowsContentChangeTypes::CONTENT_CHANGE_TYPE_SUBTREE);
    }
    if (isShow) {
        if (popupInfo.isCurrentOnShow != isShow) {
            overlayManager->ShowPopup(targetId, popupInfo, param->GetOnWillDismiss(), param->GetInteractiveDismiss());
        }
    } else {
        overlayManager->HidePopup(targetId, popupInfo);
    }
}

void ViewAbstract::DismissPopup()
{
    auto context = PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(context);
    auto overlayManager = context->GetOverlayManager();
    CHECK_NULL_VOID(overlayManager);
    overlayManager->DismissPopup();
}

void ViewAbstract::DismissDialog()
{
    auto context = PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(context);
    auto overlayManager = context->GetOverlayManager();
    CHECK_NULL_VOID(overlayManager);
    auto rootNode = overlayManager->GetRootNode().Upgrade();
    CHECK_NULL_VOID(rootNode);
    RefPtr<FrameNode> overlay;
    if (overlayManager->GetDismissDialogId()) {
        overlay = overlayManager->GetDialog(overlayManager->GetDismissDialogId());
    } else {
        overlay = AceType::DynamicCast<FrameNode>(rootNode->GetLastChild());
    }
    CHECK_NULL_VOID(overlay);
    auto pattern = overlay->GetPattern();
    CHECK_NULL_VOID(pattern);
    auto dialogPattern = AceType::DynamicCast<DialogPattern>(pattern);
    if (dialogPattern) {
        overlayManager->RemoveDialog(overlay, false);
        if (overlayManager->isMaskNode(dialogPattern->GetHost()->GetId())) {
            overlayManager->PopModalDialog(dialogPattern->GetHost()->GetId());
        }
    }
}

void ViewAbstract::BindMenuWithItems(std::vector<OptionParam> &&params, const RefPtr<FrameNode> &targetNode,
    const NG::OffsetF &offset, const MenuParam &menuParam)
{
    TAG_LOGD(AceLogTag::ACE_DIALOG, "bind menu with items enter");
    CHECK_NULL_VOID(targetNode);

    if (params.empty()) {
        return;
    }
    auto menuNode =
        MenuView::Create(std::move(params), targetNode->GetId(), targetNode->GetTag(), MenuType::MENU, menuParam);
    auto menuWrapperPattern = menuNode->GetPattern<MenuWrapperPattern>();
    CHECK_NULL_VOID(menuWrapperPattern);
    menuWrapperPattern->RegisterMenuCallback(menuNode, menuParam);
    menuWrapperPattern->SetMenuTransitionEffect(menuNode, menuParam);
    auto pipeline = PipelineBase::GetCurrentContext();
    CHECK_NULL_VOID(pipeline);
    auto theme = pipeline->GetTheme<SelectTheme>();
    CHECK_NULL_VOID(theme);
    auto expandDisplay = theme->GetExpandDisplay();
    if (expandDisplay && menuParam.isShowInSubWindow && targetNode->GetTag() != V2::SELECT_ETS_TAG) {
        SubwindowManager::GetInstance()->ShowMenuNG(menuNode, menuParam, targetNode, offset);
        return;
    }
    auto pipelineContext = NG::PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(pipelineContext);
    auto overlayManager = pipelineContext->GetOverlayManager();
    CHECK_NULL_VOID(overlayManager);
    overlayManager->ShowMenu(targetNode->GetId(), offset, menuNode);
}

void ViewAbstract::BindMenuWithCustomNode(std::function<void()>&& buildFunc, const RefPtr<FrameNode>& targetNode,
    const NG::OffsetF& offset, MenuParam menuParam, std::function<void()>&& previewBuildFunc)
{
    if (!buildFunc || !targetNode) {
        return;
    }
#ifdef PREVIEW
    // unable to use the subWindow in the Previewer.
    menuParam.type = MenuType::MENU;
#endif
    TAG_LOGD(AceLogTag::ACE_DIALOG, "bind menu with custom node enter");
    auto pipeline = PipelineBase::GetCurrentContext();
    CHECK_NULL_VOID(pipeline);
    auto theme = pipeline->GetTheme<SelectTheme>();
    CHECK_NULL_VOID(theme);
    auto expandDisplay = theme->GetExpandDisplay();
    auto pipelineContext = NG::PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(pipelineContext);
    auto overlayManager = pipelineContext->GetOverlayManager();
    CHECK_NULL_VOID(overlayManager);
    if (menuParam.type == MenuType::CONTEXT_MENU) {
        SubwindowManager::GetInstance()->ShowMenuNG(
            std::move(buildFunc), std::move(previewBuildFunc), menuParam, targetNode, offset);
        return;
    }
    if (menuParam.type == MenuType::MENU && expandDisplay && menuParam.isShowInSubWindow &&
        targetNode->GetTag() != V2::SELECT_ETS_TAG) {
        bool isShown = SubwindowManager::GetInstance()->GetShown();
        if (!isShown) {
            SubwindowManager::GetInstance()->ShowMenuNG(
                std::move(buildFunc), std::move(previewBuildFunc), menuParam, targetNode, offset);
        } else {
            auto menuNode = overlayManager->GetMenuNode(targetNode->GetId());
            SubwindowManager::GetInstance()->HideMenuNG(menuNode, targetNode->GetId());
        }
        return;
    }
    NG::ScopedViewStackProcessor builderViewStackProcessor;
    buildFunc();
    auto customNode = NG::ViewStackProcessor::GetInstance()->Finish();
    RefPtr<NG::UINode> previewCustomNode;
    if (previewBuildFunc && menuParam.previewMode == MenuPreviewMode::CUSTOM) {
        previewBuildFunc();
        previewCustomNode = NG::ViewStackProcessor::GetInstance()->Finish();
    }
    auto menuNode =
        NG::MenuView::Create(customNode, targetNode->GetId(), targetNode->GetTag(), menuParam, true, previewCustomNode);
    auto menuWrapperPattern = menuNode->GetPattern<NG::MenuWrapperPattern>();
    CHECK_NULL_VOID(menuWrapperPattern);
    menuWrapperPattern->RegisterMenuCallback(menuNode, menuParam);
    menuWrapperPattern->SetMenuTransitionEffect(menuNode, menuParam);
    overlayManager->ShowMenu(targetNode->GetId(), offset, menuNode);
}

void ViewAbstract::SetBackdropBlur(const Dimension &radius, const BlurOption &blurOption)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto target = frameNode->GetRenderContext();
    if (target) {
        if (target->GetBackgroundEffect().has_value()) {
            target->UpdateBackgroundEffect(std::nullopt);
        }
        target->UpdateBackBlur(radius, blurOption);
        if (target->GetBackBlurStyle().has_value()) {
            target->UpdateBackBlurStyle(std::nullopt);
        }
    }
}

void ViewAbstract::SetBackdropBlur(FrameNode *frameNode, const Dimension &radius, const BlurOption &blurOption)
{
    CHECK_NULL_VOID(frameNode);
    auto target = frameNode->GetRenderContext();
    if (target) {
        if (target->GetBackgroundEffect().has_value()) {
            target->UpdateBackgroundEffect(std::nullopt);
        }
        target->UpdateBackBlur(radius, blurOption);
        if (target->GetBackBlurStyle().has_value()) {
            target->UpdateBackBlurStyle(std::nullopt);
        }
    }
}

void ViewAbstract::SetLinearGradientBlur(const NG::LinearGradientBlurPara& blurPara)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(LinearGradientBlur, blurPara);
}

void ViewAbstract::SetDynamicLightUp(float rate, float lightUpDegree)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(DynamicLightUpRate, rate);
    ACE_UPDATE_RENDER_CONTEXT(DynamicLightUpDegree, lightUpDegree);
}

void ViewAbstract::SetBgDynamicBrightness(const BrightnessOption& brightnessOption)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(BgDynamicBrightnessOption, brightnessOption);
}

void ViewAbstract::SetFgDynamicBrightness(const BrightnessOption& brightnessOption)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(FgDynamicBrightnessOption, brightnessOption);
}

void ViewAbstract::SetFrontBlur(const Dimension &radius, const BlurOption &blurOption)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto target = frameNode->GetRenderContext();
    if (target) {
        target->UpdateFrontBlur(radius, blurOption);
        if (target->GetFrontBlurStyle().has_value()) {
            target->UpdateFrontBlurStyle(std::nullopt);
        }
    }
}

void ViewAbstract::SetDynamicDim(float DimDegree)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(DynamicDimDegree, DimDegree);
}

void ViewAbstract::SetFrontBlur(FrameNode *frameNode, const Dimension &radius, const BlurOption &blurOption)
{
    CHECK_NULL_VOID(frameNode);
    auto target = frameNode->GetRenderContext();
    if (target) {
        target->UpdateFrontBlur(radius, blurOption);
        if (target->GetFrontBlurStyle().has_value()) {
            target->UpdateFrontBlurStyle(std::nullopt);
        }
    }
}

void ViewAbstract::SetBackShadow(const Shadow &shadow)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(BackShadow, shadow);
}

void ViewAbstract::SetBackShadow(FrameNode *frameNode, const Shadow &shadow)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(BackShadow, shadow, frameNode);
}

void ViewAbstract::SetBlendMode(BlendMode blendMode)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(BackBlendMode, blendMode);
}

void ViewAbstract::SetBlendApplyType(BlendApplyType blendApplyType)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(BackBlendApplyType, blendApplyType);
}

void ViewAbstract::SetLinearGradient(const NG::Gradient &gradient)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(LinearGradient, gradient);
}

void ViewAbstract::SetSweepGradient(const NG::Gradient &gradient)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(SweepGradient, gradient);
}

void ViewAbstract::SetRadialGradient(const NG::Gradient &gradient)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(RadialGradient, gradient);
}

void ViewAbstract::SetInspectorId(const std::string &inspectorId)
{
    auto& uiNode = ViewStackProcessor::GetInstance()->GetMainElementNode();
    if (uiNode) {
        uiNode->UpdateInspectorId(inspectorId);
    }
}

void ViewAbstract::SetAutoEventParam(const std::string& param)
{
    auto& uiNode = ViewStackProcessor::GetInstance()->GetMainElementNode();
    if (uiNode) {
        uiNode->UpdateAutoEventParam(param);
    }
}

void ViewAbstract::SetRestoreId(int32_t restoreId)
{
    auto& uiNode = ViewStackProcessor::GetInstance()->GetMainElementNode();
    if (uiNode) {
        uiNode->SetRestoreId(restoreId);
    }
}

void ViewAbstract::SetDebugLine(const std::string &line)
{
    auto& uiNode = ViewStackProcessor::GetInstance()->GetMainElementNode();
    if (uiNode) {
        uiNode->SetDebugLine(line);
    }
}

void ViewAbstract::SetGrid(std::optional<int32_t> span, std::optional<int32_t> offset, GridSizeType type)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_VOID(layoutProperty);
    // frame node is mounted to parent when pop from stack later, no grid-container is added here
    layoutProperty->UpdateGridProperty(span, offset, type);
}

void ViewAbstract::Pop()
{
    ViewStackProcessor::GetInstance()->Pop();
}

void ViewAbstract::SetTransition(const TransitionOptions &options)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(Transition, options);
}

void ViewAbstract::CleanTransition()
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto target = frameNode->GetRenderContext();
    if (target) {
        target->CleanTransition();
    }
}

void ViewAbstract::SetChainedTransition(const RefPtr<NG::ChainedTransitionEffect> &effect)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(ChainedTransition, effect);
}

void ViewAbstract::SetClipShape(const RefPtr<BasicShape> &basicShape)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto target = frameNode->GetRenderContext();
    if (target) {
        if (target->GetClipEdge().has_value()) {
            target->UpdateClipEdge(false);
        }
        target->UpdateClipShape(basicShape);
    }
}

void ViewAbstract::SetClipShape(FrameNode *frameNode, const RefPtr<BasicShape> &basicShape)
{
    CHECK_NULL_VOID(frameNode);
    auto target = frameNode->GetRenderContext();
    if (target) {
        if (target->GetClipEdge().has_value()) {
            target->UpdateClipEdge(false);
        }
        target->UpdateClipShape(basicShape);
    }
}

void ViewAbstract::SetClipEdge(bool isClip)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto target = frameNode->GetRenderContext();
    if (target) {
        if (target->GetClipShape().has_value()) {
            target->ResetClipShape();
            target->OnClipShapeUpdate(nullptr);
        }
        target->UpdateClipEdge(isClip);
    }
}

void ViewAbstract::SetClipEdge(FrameNode *frameNode, bool isClip)
{
    CHECK_NULL_VOID(frameNode);
    auto target = frameNode->GetRenderContext();
    if (target) {
        if (target->GetClipShape().has_value()) {
            target->ResetClipShape();
            target->OnClipShapeUpdate(nullptr);
        }
        target->UpdateClipEdge(isClip);
    }
}

void ViewAbstract::SetMask(const RefPtr<BasicShape> &basicShape)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto target = frameNode->GetRenderContext();
    if (target) {
        if (target->HasProgressMask()) {
            target->ResetProgressMask();
            target->OnProgressMaskUpdate(nullptr);
        }
        target->UpdateClipMask(basicShape);
    }
}

void ViewAbstract::SetProgressMask(const RefPtr<ProgressMaskProperty> &progress)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto target = frameNode->GetRenderContext();
    if (target) {
        if (target->HasClipMask()) {
            target->ResetClipMask();
            target->OnClipMaskUpdate(nullptr);
        }
        target->UpdateProgressMask(progress);
    }
}

void ViewAbstract::SetBrightness(const Dimension &brightness)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(FrontBrightness, brightness);
}

void ViewAbstract::SetBrightness(FrameNode *frameNode, const Dimension &brightness)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(FrontBrightness, brightness, frameNode);
}

void ViewAbstract::SetGrayScale(const Dimension &grayScale)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(FrontGrayScale, grayScale);
}

void ViewAbstract::SetGrayScale(FrameNode *frameNode, const Dimension &grayScale)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(FrontGrayScale, grayScale, frameNode);
}

void ViewAbstract::SetContrast(const Dimension &contrast)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(FrontContrast, contrast);
}

void ViewAbstract::SetContrast(FrameNode *frameNode, const Dimension &contrast)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(FrontContrast, contrast, frameNode);
}

void ViewAbstract::SetSaturate(const Dimension &saturate)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(FrontSaturate, saturate);
}

void ViewAbstract::SetSaturate(FrameNode *frameNode, const Dimension &saturate)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(FrontSaturate, saturate, frameNode);
}

void ViewAbstract::SetSepia(const Dimension &sepia)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(FrontSepia, sepia);
}

void ViewAbstract::SetSepia(FrameNode *frameNode, const Dimension &sepia)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(FrontSepia, sepia, frameNode);
}

void ViewAbstract::SetInvert(const InvertVariant &invert)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(FrontInvert, invert);
}

void ViewAbstract::SetInvert(FrameNode *frameNode, const InvertVariant &invert)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(FrontInvert, invert, frameNode);
}

void ViewAbstract::SetSystemBarEffect(bool systemBarEffect)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(SystemBarEffect, systemBarEffect);
}

void ViewAbstract::SetHueRotate(float hueRotate)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(FrontHueRotate, hueRotate);
}

void ViewAbstract::SetHueRotate(FrameNode *frameNode, float hueRotate)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(FrontHueRotate, hueRotate, frameNode);
}

void ViewAbstract::SetColorBlend(const Color &colorBlend)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(FrontColorBlend, colorBlend);
}

void ViewAbstract::SetColorBlend(FrameNode *frameNode, const Color &colorBlend)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(FrontColorBlend, colorBlend, frameNode);
}

void ViewAbstract::SetBorderImage(const RefPtr<BorderImage> &borderImage)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(BorderImage, borderImage);
}

void ViewAbstract::SetBorderImageSource(const std::string &bdImageSrc)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ImageSourceInfo imageSourceInfo(bdImageSrc);
    ACE_UPDATE_RENDER_CONTEXT(BorderImageSource, imageSourceInfo);
}

void ViewAbstract::SetHasBorderImageSlice(bool tag)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(HasBorderImageSlice, tag);
}

void ViewAbstract::SetHasBorderImageWidth(bool tag)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(HasBorderImageWidth, tag);
}

void ViewAbstract::SetHasBorderImageOutset(bool tag)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(HasBorderImageOutset, tag);
}

void ViewAbstract::SetHasBorderImageRepeat(bool tag)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(HasBorderImageRepeat, tag);
}

void ViewAbstract::SetBorderImageGradient(const Gradient &gradient)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(BorderImageGradient, gradient);
}

void ViewAbstract::SetVisualEffect(const OHOS::Rosen::VisualEffect* visualEffect)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(VisualEffect, visualEffect);
}

void ViewAbstract::SetBackgroundFilter(const OHOS::Rosen::Filter* backgroundFilter)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(BackgroundFilter, backgroundFilter);
}

void ViewAbstract::SetForegroundFilter(const OHOS::Rosen::Filter* foregroundFilter)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(ForegroundFilter, foregroundFilter);
}

void ViewAbstract::SetCompositingFilter(const OHOS::Rosen::Filter* compositingFilter)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(CompositingFilter, compositingFilter);
}

void ViewAbstract::SetOverlay(const OverlayOptions &overlay)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(OverlayText, overlay);
}

void ViewAbstract::SetOverlayBuilder(std::function<void()>&& buildFunc,
    const std::optional<Alignment>& align, const std::optional<Dimension>& offsetX,
    const std::optional<Dimension>& offsetY)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    if (buildFunc) {
        auto buildNodeFunc = [func = std::move(buildFunc)]() -> RefPtr<UINode> {
            ScopedViewStackProcessor builderViewStackProcessor;
            func();
            auto customNode = ViewStackProcessor::GetInstance()->Finish();
            return customNode;
        };
        auto overlayNode = AceType::DynamicCast<FrameNode>(buildNodeFunc());
        CHECK_NULL_VOID(overlayNode);
        frameNode->SetOverlayNode(overlayNode);
        overlayNode->SetParent(AceType::WeakClaim(frameNode));
        overlayNode->SetActive(true);
        overlayNode->MarkDirtyNode(PROPERTY_UPDATE_MEASURE);
        auto layoutProperty = AceType::DynamicCast<LayoutProperty>(overlayNode->GetLayoutProperty());
        CHECK_NULL_VOID(layoutProperty);
        layoutProperty->SetIsOverlayNode(true);
        layoutProperty->UpdateMeasureType(MeasureType::MATCH_PARENT);
        layoutProperty->UpdateAlignment(align.value_or(Alignment::TOP_LEFT));
        layoutProperty->SetOverlayOffset(offsetX, offsetY);
        auto renderContext = overlayNode->GetRenderContext();
        CHECK_NULL_VOID(renderContext);
        renderContext->UpdateZIndex(INT32_MAX);
        auto focusHub = overlayNode->GetOrCreateFocusHub();
        CHECK_NULL_VOID(focusHub);
        focusHub->SetFocusable(false);
    } else {
        frameNode->SetOverlayNode(nullptr);
    }
}

void ViewAbstract::SetMotionPath(const MotionPathOption &motionPath)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(MotionPath, motionPath);
}

void ViewAbstract::SetSharedTransition(const std::string &shareId,
    const std::shared_ptr<SharedTransitionOption> &option)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto target = frameNode->GetRenderContext();
    if (target) {
        target->SetSharedTransitionOptions(option);
        target->SetShareId(shareId);
    }
}

void ViewAbstract::SetMask(FrameNode* frameNode, const RefPtr<BasicShape>& basicShape)
{
    CHECK_NULL_VOID(frameNode);
    auto target = frameNode->GetRenderContext();
    if (target) {
        if (target->HasProgressMask()) {
            target->ResetProgressMask();
            target->OnProgressMaskUpdate(nullptr);
        }
        target->UpdateClipMask(basicShape);
    }
}

void ViewAbstract::SetProgressMask(FrameNode* frameNode, const RefPtr<ProgressMaskProperty>& progress)
{
    CHECK_NULL_VOID(frameNode);
    auto target = frameNode->GetRenderContext();
    if (target) {
        if (target->HasClipMask()) {
            target->ResetClipMask();
            target->OnClipMaskUpdate(nullptr);
        }
        target->UpdateProgressMask(progress);
    }
}

void ViewAbstract::SetUseEffect(bool useEffect)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(UseEffect, useEffect);
}

void ViewAbstract::SetFreeze(bool freeze)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(Freeze, freeze);
}

void ViewAbstract::SetUseShadowBatching(bool useShadowBatching)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(UseShadowBatching, useShadowBatching);
}

void ViewAbstract::SetForegroundColor(const Color &color)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto renderContext = frameNode->GetRenderContext();
    if (renderContext->GetForegroundColorStrategy().has_value()) {
        renderContext->UpdateForegroundColorStrategy(ForegroundColorStrategy::NONE);
        renderContext->ResetForegroundColorStrategy();
    }
    renderContext->UpdateForegroundColor(color);
    renderContext->UpdateForegroundColorFlag(true);
}

void ViewAbstract::SetForegroundColorStrategy(const ForegroundColorStrategy &strategy)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(ForegroundColorStrategy, strategy);
    ACE_RESET_RENDER_CONTEXT(RenderContext, ForegroundColor);
    ACE_UPDATE_RENDER_CONTEXT(ForegroundColorFlag, true);
}

void ViewAbstract::SetKeyboardShortcut(const std::string &value, const std::vector<ModifierKey> &keys,
    std::function<void()> &&onKeyboardShortcutAction)
{
    auto pipeline = PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(pipeline);
    auto eventManager = pipeline->GetEventManager();
    CHECK_NULL_VOID(eventManager);
    auto eventHub = ViewStackProcessor::GetInstance()->GetMainFrameNodeEventHub<EventHub>();
    CHECK_NULL_VOID(eventHub);
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    if (value.empty()) {
        eventHub->ClearSingleKeyboardShortcut();
        return;
    }
    auto key = eventManager->GetKeyboardShortcutKeys(keys);
    if ((key == 0 && value.length() == 1) || (key == 0 && keys.size() > 0 && value.length() > 1)) {
        return;
    }
    if (eventManager->IsSameKeyboardShortcutNode(value, key)) {
        return;
    }
    eventHub->SetKeyboardShortcut(value, key, std::move(onKeyboardShortcutAction));
    eventManager->AddKeyboardShortcutNode(AceType::WeakClaim(frameNode));
}

void ViewAbstract::CreateAnimatablePropertyFloat(const std::string &propertyName, float value,
    const std::function<void(float)> &onCallbackEvent)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    frameNode->CreateAnimatablePropertyFloat(propertyName, value, onCallbackEvent);
}

void ViewAbstract::UpdateAnimatablePropertyFloat(const std::string &propertyName, float value)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    frameNode->UpdateAnimatablePropertyFloat(propertyName, value);
}

void ViewAbstract::CreateAnimatableArithmeticProperty(const std::string &propertyName,
    RefPtr<CustomAnimatableArithmetic> &value,
    std::function<void(const RefPtr<CustomAnimatableArithmetic> &)> &onCallbackEvent)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    frameNode->CreateAnimatableArithmeticProperty(propertyName, value, onCallbackEvent);
}

void ViewAbstract::UpdateAnimatableArithmeticProperty(const std::string &propertyName,
    RefPtr<CustomAnimatableArithmetic> &value)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    frameNode->UpdateAnimatableArithmeticProperty(propertyName, value);
}

void ViewAbstract::SetObscured(const std::vector<ObscuredReasons> &reasons)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(Obscured, reasons);
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    frameNode->MarkDirtyNode(PROPERTY_UPDATE_RENDER);
}

void ViewAbstract::SetPrivacySensitive(bool flag)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    frameNode->SetPrivacySensitive(flag);
    frameNode->MarkDirtyNode(PROPERTY_UPDATE_MEASURE);
}

void ViewAbstract::UpdateSafeAreaExpandOpts(const SafeAreaExpandOpts &opts)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_LAYOUT_PROPERTY(LayoutProperty, SafeAreaExpandOpts, opts);
}

void ViewAbstract::SetRenderGroup(bool isRenderGroup)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(RenderGroup, isRenderGroup);
}

void ViewAbstract::SetRenderFit(RenderFit renderFit)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(RenderFit, renderFit);
}

void ViewAbstract::SetBorderRadius(FrameNode *frameNode, const BorderRadiusProperty &value)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(BorderRadius, value, frameNode);
}

void ViewAbstract::SetBorderRadius(FrameNode *frameNode, const Dimension &value)
{
    BorderRadiusProperty borderRadius;
    borderRadius.SetRadius(value);
    borderRadius.multiValued = false;
    ACE_UPDATE_NODE_RENDER_CONTEXT(BorderRadius, borderRadius, frameNode);
}

void ViewAbstract::SetBorderWidth(FrameNode *frameNode, const BorderWidthProperty &value)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(LayoutProperty, BorderWidth, value, frameNode);
    ACE_UPDATE_NODE_RENDER_CONTEXT(BorderWidth, value, frameNode);
}

void ViewAbstract::SetBorderWidth(FrameNode *frameNode, const Dimension &value)
{
    BorderWidthProperty borderWidth;
    if (Negative(value.Value())) {
        borderWidth.SetBorderWidth(Dimension(0));
        LOGW("border width is negative, reset to 0");
    } else {
        borderWidth.SetBorderWidth(value);
    }
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(LayoutProperty, BorderWidth, borderWidth, frameNode);
    ACE_UPDATE_NODE_RENDER_CONTEXT(BorderWidth, borderWidth, frameNode);
}

void ViewAbstract::SetBorderColor(FrameNode *frameNode, const BorderColorProperty &value)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(BorderColor, value, frameNode);
}

void ViewAbstract::SetBorderColor(FrameNode *frameNode, const Color &value)
{
    BorderColorProperty borderColor;
    borderColor.SetColor(value);
    ACE_UPDATE_NODE_RENDER_CONTEXT(BorderColor, borderColor, frameNode);
}

void ViewAbstract::SetWidth(FrameNode *frameNode, const CalcLength &width)
{
    CHECK_NULL_VOID(frameNode);
    auto layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_VOID(layoutProperty);
    // get previously user defined ideal height
    std::optional<CalcLength> height = std::nullopt;
    auto &&layoutConstraint = layoutProperty->GetCalcLayoutConstraint();
    if (layoutConstraint && layoutConstraint->selfIdealSize) {
        height = layoutConstraint->selfIdealSize->Height();
    }
    layoutProperty->UpdateUserDefinedIdealSize(CalcSize(width, height));
}

void ViewAbstract::SetHeight(FrameNode *frameNode, const CalcLength &height)
{
    CHECK_NULL_VOID(frameNode);
    auto layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_VOID(layoutProperty);
    std::optional<CalcLength> width = std::nullopt;
    auto &&layoutConstraint = layoutProperty->GetCalcLayoutConstraint();
    if (layoutConstraint && layoutConstraint->selfIdealSize) {
        width = layoutConstraint->selfIdealSize->Width();
    }
    layoutProperty->UpdateUserDefinedIdealSize(CalcSize(width, height));
}

void ViewAbstract::ClearWidthOrHeight(FrameNode *frameNode, bool isWidth)
{
    CHECK_NULL_VOID(frameNode);
    auto layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_VOID(layoutProperty);
    layoutProperty->ClearUserDefinedIdealSize(isWidth, !isWidth);
}

void ViewAbstract::SetPosition(FrameNode *frameNode, const OffsetT<Dimension> &value)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(Position, value, frameNode);
}

void ViewAbstract::SetPositionEdges(FrameNode* frameNode, const EdgesParam& value)
{
    ACE_RESET_RENDER_CONTEXT(RenderContext, Position);
    ACE_UPDATE_RENDER_CONTEXT(PositionEdges, value);
}

void ViewAbstract::ResetPosition(FrameNode* frameNode)
{
    ACE_RESET_NODE_RENDER_CONTEXT(RenderContext, Position, frameNode);
    ACE_RESET_NODE_RENDER_CONTEXT(RenderContext, PositionEdges, frameNode);
    CHECK_NULL_VOID(frameNode);
    auto parentNode = frameNode->GetAncestorNodeOfFrame();
    CHECK_NULL_VOID(parentNode);
    auto parentPattern = parentNode->GetPattern();

    if (parentNode->GetTag() == V2::COLUMN_ETS_TAG || parentNode->GetTag() == V2::ROW_ETS_TAG ||
        parentNode->GetTag() == V2::FLEX_ETS_TAG) {
        frameNode->MarkDirtyNode(PROPERTY_UPDATE_MEASURE);
    } else {
        auto renderContext = frameNode->GetRenderContext();
        CHECK_NULL_VOID(renderContext);
        renderContext->RecalculatePosition();
    }
}

void ViewAbstract::SetTransformMatrix(FrameNode *frameNode, const Matrix4 &matrix)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(TransformMatrix, matrix, frameNode);
}

void ViewAbstract::SetHitTestMode(FrameNode *frameNode, HitTestMode hitTestMode)
{
    CHECK_NULL_VOID(frameNode);
    auto gestureHub = frameNode->GetOrCreateGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->SetHitTestMode(hitTestMode);
}

void ViewAbstract::SetOpacity(FrameNode *frameNode, double opacity)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(Opacity, opacity, frameNode);
}

void ViewAbstract::SetZIndex(FrameNode *frameNode, int32_t value)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(ZIndex, value, frameNode);
}

void ViewAbstract::SetLinearGradient(FrameNode *frameNode, const NG::Gradient &gradient)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(LinearGradient, gradient, frameNode);
}

void ViewAbstract::SetSweepGradient(FrameNode* frameNode, const NG::Gradient& gradient)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(SweepGradient, gradient, frameNode);
}

void ViewAbstract::SetRadialGradient(FrameNode* frameNode, const NG::Gradient& gradient)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(RadialGradient, gradient, frameNode);
}

void ViewAbstract::SetOverlay(FrameNode* frameNode, const NG::OverlayOptions& overlay)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(OverlayText, overlay, frameNode);
}

void ViewAbstract::SetBorderImage(FrameNode* frameNode, const RefPtr<BorderImage>& borderImage)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(BorderImage, borderImage, frameNode);
}

void ViewAbstract::SetBorderImageSource(FrameNode* frameNode, const std::string& bdImageSrc)
{
    ImageSourceInfo imageSourceInfo(bdImageSrc);
    ACE_UPDATE_NODE_RENDER_CONTEXT(BorderImageSource, imageSourceInfo, frameNode);
}

void ViewAbstract::SetHasBorderImageSlice(FrameNode* frameNode, bool tag)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(HasBorderImageSlice, tag, frameNode);
}

void ViewAbstract::SetHasBorderImageWidth(FrameNode* frameNode, bool tag)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(HasBorderImageWidth, tag, frameNode);
}

void ViewAbstract::SetHasBorderImageOutset(FrameNode* frameNode, bool tag)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(HasBorderImageOutset, tag, frameNode);
}

void ViewAbstract::SetHasBorderImageRepeat(FrameNode* frameNode, bool tag)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(HasBorderImageRepeat, tag, frameNode);
}

void ViewAbstract::SetBorderImageGradient(FrameNode* frameNode, const NG::Gradient& gradient)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(BorderImageGradient, gradient, frameNode);
}

void ViewAbstract::SetForegroundBlurStyle(FrameNode* frameNode, const BlurStyleOption& fgBlurStyle)
{
    const auto target = frameNode->GetRenderContext();
    if (target) {
        target->UpdateFrontBlurStyle(fgBlurStyle);
        if (target->GetFrontBlurRadius().has_value()) {
            target->UpdateFrontBlurRadius(Dimension());
        }
    }
}

void ViewAbstract::SetLinearGradientBlur(FrameNode *frameNode, const NG::LinearGradientBlurPara& blurPara)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(LinearGradientBlur, blurPara, frameNode);
}

void ViewAbstract::SetBackgroundBlurStyle(FrameNode *frameNode, const BlurStyleOption &bgBlurStyle)
{
    auto target = frameNode->GetRenderContext();
    if (target) {
        if (target->GetBackgroundEffect().has_value()) {
            target->UpdateBackgroundEffect(std::nullopt);
        }
        target->UpdateBackBlurStyle(bgBlurStyle);
        if (target->GetBackBlurRadius().has_value()) {
            target->UpdateBackBlurRadius(Dimension());
        }
    }
}

void ViewAbstract::SetPixelStretchEffect(FrameNode* frameNode, PixStretchEffectOption& option)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(PixelStretchEffect, option, frameNode);
}

void ViewAbstract::SetLightUpEffect(FrameNode* frameNode, double radio)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(LightUpEffect, radio, frameNode);
}

void ViewAbstract::SetSphericalEffect(FrameNode* frameNode, double radio)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(SphericalEffect, radio, frameNode);
}

void ViewAbstract::SetRenderGroup(FrameNode* frameNode, bool isRenderGroup)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(RenderGroup, isRenderGroup, frameNode);
}

void ViewAbstract::SetRenderFit(FrameNode* frameNode, RenderFit renderFit)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(RenderFit, renderFit, frameNode);
}

void ViewAbstract::SetUseEffect(FrameNode* frameNode, bool useEffect)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(UseEffect, useEffect, frameNode);
}

void ViewAbstract::SetForegroundColor(FrameNode* frameNode, const Color& color)
{
    auto renderContext = frameNode->GetRenderContext();
    if (renderContext->GetForegroundColorStrategy().has_value()) {
        renderContext->UpdateForegroundColorStrategy(ForegroundColorStrategy::NONE);
        renderContext->ResetForegroundColorStrategy();
    }
    renderContext->UpdateForegroundColor(color);
    renderContext->UpdateForegroundColorFlag(true);
}

void ViewAbstract::SetForegroundColorStrategy(FrameNode* frameNode, const ForegroundColorStrategy& strategy)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(ForegroundColorStrategy, strategy, frameNode);
    ACE_RESET_NODE_RENDER_CONTEXT(RenderContext, ForegroundColor, frameNode);
    ACE_UPDATE_NODE_RENDER_CONTEXT(ForegroundColorFlag, true, frameNode);
}

void ViewAbstract::SetLightPosition(
    const CalcDimension& positionX, const CalcDimension& positionY, const CalcDimension& positionZ)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(LightPosition, TranslateOptions(positionX, positionY, positionZ));
}

void ViewAbstract::SetLightIntensity(const float value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(LightIntensity, value);
}

void ViewAbstract::SetLightColor(const Color& value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(LightColor, value);
}

void ViewAbstract::SetLightIlluminated(const uint32_t value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(LightIlluminated, value);
}

void ViewAbstract::SetIlluminatedBorderWidth(const Dimension& value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(IlluminatedBorderWidth, value);
}

void ViewAbstract::SetBloom(const float value)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(Bloom, value);
}

void ViewAbstract::SetMotionPath(FrameNode* frameNode, const MotionPathOption& motionPath)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(MotionPath, motionPath, frameNode);
}

void ViewAbstract::SetFocusOnTouch(FrameNode* frameNode, bool isSet)
{
    CHECK_NULL_VOID(frameNode);
    auto focusHub = frameNode->GetOrCreateFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->SetIsFocusOnTouch(isSet);
}

void ViewAbstract::SetGroupDefaultFocus(FrameNode* frameNode, bool isSet)
{
    CHECK_NULL_VOID(frameNode);
    auto focusHub = frameNode->GetOrCreateFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->SetIsDefaultGroupFocus(isSet);
}

void ViewAbstract::SetFocusable(FrameNode* frameNode, bool focusable)
{
    CHECK_NULL_VOID(frameNode);
    auto focusHub = frameNode->GetOrCreateFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->SetFocusable(focusable);
}

void ViewAbstract::SetTouchable(FrameNode* frameNode, bool touchable)
{
    CHECK_NULL_VOID(frameNode);
    auto gestureHub = frameNode->GetOrCreateGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->SetTouchable(touchable);
}

void ViewAbstract::SetDefaultFocus(FrameNode* frameNode, bool isSet)
{
    CHECK_NULL_VOID(frameNode);
    auto focusHub = frameNode->GetOrCreateFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->SetIsDefaultFocus(isSet);
}

void ViewAbstract::SetDisplayIndex(FrameNode* frameNode, int32_t value)
{
    CHECK_NULL_VOID(frameNode);
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(LayoutProperty, DisplayIndex, value, frameNode);
}

void ViewAbstract::SetOffset(FrameNode* frameNode, const OffsetT<Dimension>& value)
{
    CHECK_NULL_VOID(frameNode);
    ACE_UPDATE_NODE_RENDER_CONTEXT(Offset, value, frameNode);
}

void ViewAbstract::SetOffsetEdges(FrameNode* frameNode, const EdgesParam& value)
{
    ACE_RESET_RENDER_CONTEXT(RenderContext, Offset);
    ACE_UPDATE_RENDER_CONTEXT(OffsetEdges, value);
}

void ViewAbstract::MarkAnchor(FrameNode* frameNode, const OffsetT<Dimension>& value)
{
    CHECK_NULL_VOID(frameNode);
    ACE_UPDATE_NODE_RENDER_CONTEXT(Anchor, value, frameNode);
}

void ViewAbstract::SetVisibility(FrameNode* frameNode, VisibleType visible)
{
    CHECK_NULL_VOID(frameNode);
    auto layoutProperty = frameNode->GetLayoutProperty();
    if (layoutProperty) {
        layoutProperty->UpdateVisibility(visible, true);
    }

    auto focusHub = ViewStackProcessor::GetInstance()->GetOrCreateMainFrameNodeFocusHub();
    if (focusHub) {
        focusHub->SetShow(visible == VisibleType::VISIBLE);
    }
}

void ViewAbstract::SetPadding(FrameNode* frameNode, const CalcLength& value)
{
    CHECK_NULL_VOID(frameNode);
    PaddingProperty padding;
    padding.SetEdges(value);
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(LayoutProperty, Padding, padding, frameNode);
}

void ViewAbstract::SetPadding(FrameNode* frameNode, const PaddingProperty& value)
{
    CHECK_NULL_VOID(frameNode);
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(LayoutProperty, Padding, value, frameNode);
}

void ViewAbstract::SetMargin(FrameNode* frameNode, const CalcLength& value)
{
    CHECK_NULL_VOID(frameNode);
    MarginProperty margin;
    margin.SetEdges(value);
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(LayoutProperty, Margin, margin, frameNode);
}

void ViewAbstract::SetMargin(FrameNode* frameNode, const PaddingProperty& value)
{
    CHECK_NULL_VOID(frameNode);
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(LayoutProperty, Margin, value, frameNode);
}

void ViewAbstract::SetLayoutDirection(FrameNode* frameNode, TextDirection value)
{
    CHECK_NULL_VOID(frameNode);
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(LayoutProperty, LayoutDirection, value, frameNode);
}

void ViewAbstract::UpdateSafeAreaExpandOpts(FrameNode* frameNode, const SafeAreaExpandOpts& opts)
{
    CHECK_NULL_VOID(frameNode);
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(LayoutProperty, SafeAreaExpandOpts, opts, frameNode);
}

void ViewAbstract::SetAspectRatio(FrameNode* frameNode, float ratio)
{
    CHECK_NULL_VOID(frameNode);
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(LayoutProperty, AspectRatio, ratio, frameNode);
}

void ViewAbstract::SetAlignSelf(FrameNode* frameNode, FlexAlign value)
{
    CHECK_NULL_VOID(frameNode);
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(LayoutProperty, AlignSelf, value, frameNode);
}

void ViewAbstract::SetFlexBasis(FrameNode* frameNode, const Dimension& value)
{
    CHECK_NULL_VOID(frameNode);
    if (LessNotEqual(value.Value(), 0.0f)) {
        ACE_UPDATE_NODE_LAYOUT_PROPERTY(LayoutProperty, FlexBasis, Dimension(), frameNode);
        return;
    }
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(LayoutProperty, FlexBasis, value, frameNode);
}

void ViewAbstract::ResetFlexShrink(FrameNode* frameNode)
{
    CHECK_NULL_VOID(frameNode);
    ACE_RESET_NODE_LAYOUT_PROPERTY(LayoutProperty, FlexShrink, frameNode);
}

void ViewAbstract::SetFlexShrink(FrameNode* frameNode, float value)
{
    CHECK_NULL_VOID(frameNode);
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(LayoutProperty, FlexShrink, value, frameNode);
}

void ViewAbstract::SetFlexGrow(FrameNode* frameNode, float value)
{
    CHECK_NULL_VOID(frameNode);
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(LayoutProperty, FlexGrow, value, frameNode);
}

void ViewAbstract::SetLayoutWeight(FrameNode* frameNode, float value)
{
    CHECK_NULL_VOID(frameNode);
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(LayoutProperty, LayoutWeight, value, frameNode);
}

void ViewAbstract::ResetMaxSize(FrameNode* frameNode, bool resetWidth)
{
    CHECK_NULL_VOID(frameNode);
    auto layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_VOID(layoutProperty);
    layoutProperty->ResetCalcMaxSize(resetWidth);
}

void ViewAbstract::ResetMinSize(FrameNode* frameNode, bool resetWidth)
{
    CHECK_NULL_VOID(frameNode);
    auto layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_VOID(layoutProperty);
    layoutProperty->ResetCalcMinSize(resetWidth);
}

void ViewAbstract::SetMinWidth(FrameNode* frameNode, const CalcLength& minWidth)
{
    CHECK_NULL_VOID(frameNode);
    auto layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_VOID(layoutProperty);
    layoutProperty->UpdateCalcMinSize(CalcSize(minWidth, std::nullopt));
}

void ViewAbstract::SetMaxWidth(FrameNode* frameNode, const CalcLength& maxWidth)
{
    CHECK_NULL_VOID(frameNode);
    auto layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_VOID(layoutProperty);
    layoutProperty->UpdateCalcMaxSize(CalcSize(maxWidth, std::nullopt));
}

void ViewAbstract::SetMinHeight(FrameNode* frameNode, const CalcLength& minHeight)
{
    CHECK_NULL_VOID(frameNode);
    auto layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_VOID(layoutProperty);
    layoutProperty->UpdateCalcMinSize(CalcSize(std::nullopt, minHeight));
}

void ViewAbstract::SetMaxHeight(FrameNode* frameNode, const CalcLength& maxHeight)
{
    CHECK_NULL_VOID(frameNode);
    auto layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_VOID(layoutProperty);
    layoutProperty->UpdateCalcMaxSize(CalcSize(std::nullopt, maxHeight));
}

void ViewAbstract::SetAlignRules(FrameNode* frameNode, const std::map<AlignDirection, AlignRule>& alignRules)
{
    CHECK_NULL_VOID(frameNode);
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(LayoutProperty, AlignRules, alignRules, frameNode);
}

std::map<AlignDirection, AlignRule> ViewAbstract::GetAlignRules(FrameNode* frameNode)
{
    std::map<AlignDirection, AlignRule> alignRules;
    CHECK_NULL_RETURN(frameNode, alignRules);
    auto layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_RETURN(layoutProperty, alignRules);
    CHECK_NULL_RETURN(layoutProperty->GetFlexItemProperty(), alignRules);
    return layoutProperty->GetFlexItemProperty()->GetAlignRules().value_or(alignRules);
}

void ViewAbstract::ResetAlignRules(FrameNode* frameNode)
{
    CHECK_NULL_VOID(frameNode);
    auto layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_VOID(layoutProperty);
    CHECK_NULL_VOID(layoutProperty->GetFlexItemProperty());
    return layoutProperty->GetFlexItemProperty()->ResetAlignRules();
}

void ViewAbstract::SetChainStyle(FrameNode* frameNode, const ChainInfo& chainInfo)
{
    CHECK_NULL_VOID(frameNode);
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(LayoutProperty, ChainStyle, chainInfo, frameNode);
}

ChainInfo ViewAbstract::GetChainStyle(FrameNode* frameNode)
{
    ChainInfo chainInfo;
    CHECK_NULL_RETURN(frameNode, chainInfo);
    auto layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_RETURN(layoutProperty->GetFlexItemProperty(), chainInfo);
    layoutProperty->GetFlexItemProperty()->GetHorizontalChainStyle().value_or(chainInfo);
    if (chainInfo.direction.has_value()) {
        return chainInfo;
    }
    return layoutProperty->GetFlexItemProperty()->GetVerticalChainStyle().value_or(chainInfo);
}

void ViewAbstract::ResetChainStyle(FrameNode* frameNode)
{
    CHECK_NULL_VOID(frameNode);
    ChainInfo nullChainInfo;
    auto layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_VOID(layoutProperty->GetFlexItemProperty());
    layoutProperty->GetFlexItemProperty()->UpdateHorizontalChainStyle(nullChainInfo);
    layoutProperty->GetFlexItemProperty()->UpdateVerticalChainStyle(nullChainInfo);
}

void ViewAbstract::SetGrid(
    FrameNode* frameNode, std::optional<int32_t> span, std::optional<int32_t> offset, GridSizeType type)
{
    CHECK_NULL_VOID(frameNode);
    auto layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_VOID(layoutProperty);
    // frame node is mounted to parent when pop from stack later, no grid-container is added here
    layoutProperty->UpdateGridProperty(span, offset, type);
}

void ViewAbstract::ResetAspectRatio(FrameNode* frameNode)
{
    ACE_RESET_NODE_LAYOUT_PROPERTY(LayoutProperty, AspectRatio, frameNode);
}

void ViewAbstract::SetAllowDrop(FrameNode* frameNode, const std::set<std::string>& allowDrop)
{
    CHECK_NULL_VOID(frameNode);
    frameNode->SetAllowDrop(allowDrop);
}

void ViewAbstract::SetInspectorId(FrameNode* frameNode, const std::string& inspectorId)
{
    if (frameNode) {
        frameNode->UpdateInspectorId(inspectorId);
    }
}

void ViewAbstract::SetRestoreId(FrameNode* frameNode, int32_t restoreId)
{
    if (frameNode) {
        frameNode->SetRestoreId(restoreId);
    }
}

void ViewAbstract::SetTabIndex(FrameNode* frameNode, int32_t index)
{
    CHECK_NULL_VOID(frameNode);
    auto focusHub = frameNode->GetOrCreateFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->SetTabIndex(index);
}

void ViewAbstract::SetObscured(FrameNode* frameNode, const std::vector<ObscuredReasons>& reasons)
{
    CHECK_NULL_VOID(frameNode);
    ACE_UPDATE_NODE_RENDER_CONTEXT(Obscured, reasons, frameNode);
    frameNode->MarkDirtyNode(PROPERTY_UPDATE_RENDER);
}

void ViewAbstract::SetMotionBlur(FrameNode* frameNode, const MotionBlurOption &motionBlurOption)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(MotionBlur, motionBlurOption, frameNode);
}

void ViewAbstract::SetForegroundEffect(FrameNode* frameNode, float radius)
{
    CHECK_NULL_VOID(frameNode);
    auto target = frameNode->GetRenderContext();
    if (target) {
        target->UpdateForegroundEffect(radius);
    }
}

void ViewAbstract::SetBackgroundEffect(FrameNode* frameNode, const EffectOption &effectOption)
{
    CHECK_NULL_VOID(frameNode);
    auto target = frameNode->GetRenderContext();
    if (target) {
        if (target->GetBackBlurRadius().has_value()) {
            target->UpdateBackBlurRadius(Dimension());
        }
        if (target->GetBackBlurStyle().has_value()) {
            target->UpdateBackBlurStyle(std::nullopt);
        }
        target->UpdateBackgroundEffect(effectOption);
    }
}

void ViewAbstract::SetDynamicLightUp(FrameNode* frameNode, float rate, float lightUpDegree)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(DynamicLightUpRate, rate, frameNode);
    ACE_UPDATE_NODE_RENDER_CONTEXT(DynamicLightUpDegree, lightUpDegree, frameNode);
}

void ViewAbstract::SetBgDynamicBrightness(FrameNode* frameNode, const BrightnessOption& brightnessOption)
{
    CHECK_NULL_VOID(frameNode);
    ACE_UPDATE_NODE_RENDER_CONTEXT(BgDynamicBrightnessOption, brightnessOption, frameNode);
}

void ViewAbstract::SetFgDynamicBrightness(FrameNode* frameNode, const BrightnessOption& brightnessOption)
{
    CHECK_NULL_VOID(frameNode);
    ACE_UPDATE_NODE_RENDER_CONTEXT(FgDynamicBrightnessOption, brightnessOption, frameNode);
}

void ViewAbstract::SetDragPreviewOptions(FrameNode* frameNode, const DragPreviewOption& previewOption)
{
    CHECK_NULL_VOID(frameNode);
    frameNode->SetDragPreviewOptions(previewOption);
}

void ViewAbstract::SetResponseRegion(FrameNode* frameNode, const std::vector<DimensionRect>& responseRegion)
{
    CHECK_NULL_VOID(frameNode);
    auto gestureHub = frameNode->GetOrCreateGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->SetResponseRegion(responseRegion);
}

void ViewAbstract::SetMouseResponseRegion(FrameNode* frameNode, const std::vector<DimensionRect>& mouseResponseRegion)
{
    CHECK_NULL_VOID(frameNode);
    auto gestureHub = frameNode->GetOrCreateGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->SetMouseResponseRegion(mouseResponseRegion);
}

void ViewAbstract::SetSharedTransition(
    FrameNode* frameNode, const std::string& shareId, const std::shared_ptr<SharedTransitionOption>& option)
{
    const auto& target = frameNode->GetRenderContext();
    if (target) {
        target->SetSharedTransitionOptions(option);
        target->SetShareId(shareId);
    }
}

void ViewAbstract::SetTransition(FrameNode* frameNode, const TransitionOptions& options)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(Transition, options, frameNode);
}

void ViewAbstract::CleanTransition(FrameNode* frameNode)
{
    CHECK_NULL_VOID(frameNode);
    const auto& renderContext = frameNode->GetRenderContext();
    if (renderContext) {
        renderContext->CleanTransition();
    }
}

void ViewAbstract::SetChainedTransition(FrameNode* frameNode, const RefPtr<NG::ChainedTransitionEffect>& effect)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(ChainedTransition, effect, frameNode);
}

void ViewAbstract::SetEnabled(FrameNode* frameNode, bool enabled)
{
    CHECK_NULL_VOID(frameNode);
    auto eventHub = frameNode->GetEventHub<EventHub>();
    if (eventHub) {
        eventHub->SetEnabled(enabled);
    }
    auto focusHub = frameNode->GetOrCreateFocusHub();
    if (focusHub) {
        focusHub->SetEnabled(enabled);
    }
}

void ViewAbstract::SetUseShadowBatching(FrameNode* frameNode, bool useShadowBatching)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(UseShadowBatching, useShadowBatching, frameNode);
}

void ViewAbstract::SetBlendMode(FrameNode* frameNode, BlendMode blendMode)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(BackBlendMode, blendMode, frameNode);
}

void ViewAbstract::SetBlendApplyType(FrameNode* frameNode, BlendApplyType blendApplyType)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(BackBlendApplyType, blendApplyType, frameNode);
}

void ViewAbstract::SetMonopolizeEvents(FrameNode* frameNode, bool monopolizeEvents)
{
    CHECK_NULL_VOID(frameNode);
    auto gestureHub = frameNode->GetOrCreateGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->SetMonopolizeEvents(monopolizeEvents);
}

void ViewAbstract::SetDraggable(FrameNode* frameNode, bool draggable)
{
    CHECK_NULL_VOID(frameNode);
    auto gestureHub = frameNode->GetOrCreateGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    if (draggable) {
        if (!frameNode->IsDraggable()) {
            gestureHub->InitDragDropEvent();
        }
    } else {
        gestureHub->RemoveDragEvent();
    }
    frameNode->SetDraggable(draggable);
}

void ViewAbstract::SetHoverEffect(FrameNode* frameNode, HoverEffectType hoverEffect)
{
    CHECK_NULL_VOID(frameNode);
    auto eventHub = frameNode->GetOrCreateInputEventHub();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetHoverEffect(hoverEffect);
}

void ViewAbstract::SetClickEffectLevel(FrameNode* frameNode, const ClickEffectLevel& level, float scaleValue)
{
    ClickEffectInfo clickEffectInfo;
    clickEffectInfo.level = level;
    clickEffectInfo.scaleNumber = scaleValue;
    ACE_UPDATE_NODE_RENDER_CONTEXT(ClickEffectLevel, clickEffectInfo, frameNode);
}

void ViewAbstract::SetKeyboardShortcut(FrameNode* frameNode, const std::string& value,
    const std::vector<ModifierKey>& keys, std::function<void()>&& onKeyboardShortcutAction)
{
    auto pipeline = PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(pipeline);
    auto eventManager = pipeline->GetEventManager();
    CHECK_NULL_VOID(eventManager);
    auto eventHub = frameNode->GetEventHub<EventHub>();
    CHECK_NULL_VOID(eventHub);
    CHECK_NULL_VOID(frameNode);
    auto frameNodeRef = AceType::Claim<FrameNode>(frameNode);
    if (value.empty() || keys.empty()) {
        eventHub->ClearSingleKeyboardShortcut();
        return;
    }
    auto key = eventManager->GetKeyboardShortcutKeys(keys);
    if ((key == 0 && value.length() == 1) || (key == 0 && !keys.empty() && value.length() > 1)) {
        return;
    }
    if (eventManager->IsSameKeyboardShortcutNode(value, key)) {
        return;
    }
    eventHub->SetKeyboardShortcut(value, key, onKeyboardShortcutAction);
    eventManager->AddKeyboardShortcutNode(WeakPtr<NG::FrameNode>(frameNodeRef));
}

void ViewAbstract::SetOnAppear(FrameNode* frameNode, std::function<void()> &&onAppear)
{
    CHECK_NULL_VOID(frameNode);
    auto eventHub = frameNode->GetEventHub<EventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetOnAppear(std::move(onAppear));
}

void ViewAbstract::SetOnDisappear(FrameNode* frameNode, std::function<void()> &&onDisappear)
{
    CHECK_NULL_VOID(frameNode);
    auto eventHub = frameNode->GetEventHub<EventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetOnDisappear(std::move(onDisappear));
}

void ViewAbstract::SetOnAttach(FrameNode* frameNode, std::function<void()> &&onAttach)
{
    CHECK_NULL_VOID(frameNode);
    auto eventHub = frameNode->GetEventHub<EventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetOnAttach(std::move(onAttach));
}

void ViewAbstract::SetOnDetach(FrameNode* frameNode, std::function<void()> &&onDetach)
{
    CHECK_NULL_VOID(frameNode);
    auto eventHub = frameNode->GetEventHub<EventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetOnDetach(std::move(onDetach));
}

void ViewAbstract::SetOnAreaChanged(FrameNode* frameNode, std::function<void(const RectF &oldRect,
    const OffsetF &oldOrigin, const RectF &rect, const OffsetF &origin)> &&onAreaChanged)
{
    CHECK_NULL_VOID(frameNode);
    auto pipeline = PipelineContext::GetCurrentContextSafely();
    CHECK_NULL_VOID(pipeline);
    frameNode->SetOnAreaChangeCallback(std::move(onAreaChanged));
    pipeline->AddOnAreaChangeNode(frameNode->GetId());
}

void ViewAbstract::SetOnFocus(FrameNode* frameNode, OnFocusFunc &&onFocusCallback)
{
    CHECK_NULL_VOID(frameNode);
    auto focusHub = frameNode->GetOrCreateFocusHub();
    focusHub->SetOnFocusCallback(std::move(onFocusCallback));
}

void ViewAbstract::SetOnBlur(FrameNode* frameNode, OnBlurFunc &&onBlurCallback)
{
    CHECK_NULL_VOID(frameNode);
    auto focusHub = frameNode->GetOrCreateFocusHub();
    focusHub->SetOnBlurCallback(std::move(onBlurCallback));
}

void ViewAbstract::SetOnClick(FrameNode* frameNode, GestureEventFunc &&clickEventFunc)
{
    auto gestureHub = frameNode->GetOrCreateGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->SetUserOnClick(std::move(clickEventFunc));

    auto focusHub = frameNode->GetFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->SetFocusable(true, false);
}

void ViewAbstract::SetOnTouch(FrameNode* frameNode, TouchEventFunc &&touchEventFunc)
{
    auto gestureHub = frameNode->GetOrCreateGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->SetTouchEvent(std::move(touchEventFunc));
}

void ViewAbstract::SetOnMouse(FrameNode* frameNode, OnMouseEventFunc &&onMouseEventFunc)
{
    auto eventHub = frameNode->GetOrCreateInputEventHub();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetMouseEvent(std::move(onMouseEventFunc));
}

void ViewAbstract::SetOnHover(FrameNode* frameNode, OnHoverFunc &&onHoverEventFunc)
{
    auto eventHub = frameNode->GetOrCreateInputEventHub();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetHoverEvent(std::move(onHoverEventFunc));
}

void ViewAbstract::SetOnKeyEvent(FrameNode* frameNode, OnKeyCallbackFunc &&onKeyCallback)
{
    auto focusHub = frameNode->GetOrCreateFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->SetOnKeyCallback(std::move(onKeyCallback));
}

bool ViewAbstract::GetFocusable(FrameNode* frameNode)
{
    CHECK_NULL_RETURN(frameNode, false);
    auto focusHub = frameNode->GetOrCreateFocusHub();
    CHECK_NULL_RETURN(focusHub, false);
    return focusHub->IsFocusable();
}

bool ViewAbstract::GetDefaultFocus(FrameNode* frameNode)
{
    CHECK_NULL_RETURN(frameNode, false);
    auto focusHub = frameNode->GetOrCreateFocusHub();
    CHECK_NULL_RETURN(focusHub, false);
    return focusHub->IsDefaultFocus();
}

std::vector<DimensionRect> ViewAbstract::GetResponseRegion(FrameNode* frameNode)
{
    std::vector<DimensionRect> defaultRect;
    CHECK_NULL_RETURN(frameNode, defaultRect);
    auto gestureHub = frameNode->GetOrCreateGestureEventHub();
    CHECK_NULL_RETURN(gestureHub, defaultRect);
    return gestureHub->GetResponseRegion();
}

NG::OverlayOptions ViewAbstract::GetOverlay(FrameNode* frameNode)
{
    NG::OverlayOptions defaultOptions;
    const auto& target = frameNode->GetRenderContext();
    return target->GetOverlayTextValue(defaultOptions);
}

void ViewAbstract::SetNeedFocus(FrameNode* frameNode, bool value)
{
    CHECK_NULL_VOID(frameNode);
    auto focusHub = frameNode->GetOrCreateFocusHub();
    CHECK_NULL_VOID(focusHub);
    if (value) {
        focusHub->RequestFocus();
    } else {
        focusHub->LostFocusToViewRoot();
    }
}

bool ViewAbstract::GetNeedFocus(FrameNode* frameNode)
{
    CHECK_NULL_RETURN(frameNode, false);
    auto focusHub = frameNode->GetOrCreateFocusHub();
    CHECK_NULL_RETURN(focusHub, false);
    return focusHub->IsCurrentFocus();
}

double ViewAbstract::GetOpacity(FrameNode* frameNode)
{
    double opacity = 1.0f;
    const auto& target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, opacity);
    return target->GetOpacityValue(opacity);
}

BorderWidthProperty ViewAbstract::GetBorderWidth(FrameNode* frameNode)
{
    Dimension defaultDimension(0);
    BorderWidthProperty borderWidths = { defaultDimension, defaultDimension, defaultDimension, defaultDimension };
    const auto& target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, borderWidths);
    return target->GetBorderWidthValue(borderWidths);
}

BorderWidthProperty ViewAbstract::GetLayoutBorderWidth(FrameNode* frameNode)
{
    Dimension defaultDimen = Dimension(0, DimensionUnit::VP);
    BorderWidthProperty borderWidths;
    borderWidths.topDimen = std::optional<Dimension>(defaultDimen);
    borderWidths.rightDimen = std::optional<Dimension>(defaultDimen);
    borderWidths.bottomDimen = std::optional<Dimension>(defaultDimen);
    borderWidths.leftDimen = std::optional<Dimension>(defaultDimen);
    const auto& layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_RETURN(layoutProperty, borderWidths);
    const auto& property = layoutProperty->GetBorderWidthProperty();
    CHECK_NULL_RETURN(property, borderWidths);
    borderWidths.topDimen = std::optional<Dimension>(property->topDimen);
    borderWidths.rightDimen = std::optional<Dimension>(property->rightDimen);
    borderWidths.bottomDimen = std::optional<Dimension>(property->bottomDimen);
    borderWidths.leftDimen = std::optional<Dimension>(property->leftDimen);
    return borderWidths;
}

BorderRadiusProperty ViewAbstract::GetBorderRadius(FrameNode* frameNode)
{
    Dimension defaultDimension(0);
    BorderRadiusProperty borderRadius = { defaultDimension, defaultDimension, defaultDimension, defaultDimension };
    const auto& target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, borderRadius);
    return target->GetBorderRadiusValue(borderRadius);
}

BorderColorProperty ViewAbstract::GetBorderColor(FrameNode* frameNode)
{
    Color defaultColor(0xff000000);
    BorderColorProperty borderColors = { defaultColor, defaultColor, defaultColor, defaultColor };
    const auto& target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, borderColors);
    return target->GetBorderColorValue(borderColors);
}

BorderStyleProperty ViewAbstract::GetBorderStyle(FrameNode* frameNode)
{
    BorderStyle defaultStyle = BorderStyle::SOLID;
    BorderStyleProperty borderStyles = { defaultStyle, defaultStyle, defaultStyle, defaultStyle };
    const auto& target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, borderStyles);
    return target->GetBorderStyleValue(borderStyles);
}

int ViewAbstract::GetZIndex(FrameNode* frameNode)
{
    int zindex = 0;
    const auto& target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, zindex);
    return target->GetZIndexValue(zindex);
}

VisibleType ViewAbstract::GetVisibility(FrameNode* frameNode)
{
    VisibleType visibility = VisibleType::VISIBLE;
    ACE_GET_NODE_LAYOUT_PROPERTY_WITH_DEFAULT_VALUE(LayoutProperty, Visibility, visibility, frameNode, visibility);
    return visibility;
}

bool ViewAbstract::GetClip(FrameNode* frameNode)
{
    bool value = false;
    const auto& target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, value);
    return target->GetClipEdgeValue(value);
}

RefPtr<BasicShape> ViewAbstract::GetClipShape(FrameNode* frameNode)
{
    RefPtr<BasicShape> value = AceType::MakeRefPtr<BasicShape>();
    const auto& target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, value);
    return target->GetClipShapeValue(value);
}

Matrix4 ViewAbstract::GetTransform(FrameNode* frameNode)
{
    Matrix4 value;
    const auto& target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, value);
    return target->GetTransformMatrixValue(value);
}

HitTestMode ViewAbstract::GetHitTestBehavior(FrameNode* frameNode)
{
    auto gestureHub = frameNode->GetHitTestMode();
    return gestureHub;
}

OffsetT<Dimension> ViewAbstract::GetPosition(FrameNode* frameNode)
{
    Dimension PositionX(0, DimensionUnit::VP);
    Dimension PositionY(0, DimensionUnit::VP);
    OffsetT<Dimension> position(PositionX, PositionY);
    const auto& target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, position);
    return target->GetPositionValue(position);
}

std::optional<Shadow> ViewAbstract::GetShadow(FrameNode* frameNode)
{
    Shadow value;
    const auto& target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, value);
    return target->GetBackShadowValue(value);
}

NG::Gradient ViewAbstract::GetSweepGradient(FrameNode* frameNode)
{
    Gradient value;
    value.CreateGradientWithType(NG::GradientType::SWEEP);
    const auto& target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, value);
    return target->GetSweepGradientValue(value);
}

NG::Gradient ViewAbstract::GetRadialGradient(FrameNode* frameNode)
{
    Gradient value;
    value.CreateGradientWithType(NG::GradientType::RADIAL);
    const auto& target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, value);
    return target->GetRadialGradientValue(value);
}

RefPtr<BasicShape> ViewAbstract::GetMask(FrameNode* frameNode)
{
    RefPtr<BasicShape> value = AceType::MakeRefPtr<BasicShape>();
    const auto& target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, value);
    return target->GetClipMaskValue(value);
}

RefPtr<ProgressMaskProperty> ViewAbstract::GetMaskProgress(FrameNode* frameNode)
{
    RefPtr<ProgressMaskProperty> value = AceType::MakeRefPtr<ProgressMaskProperty>();
    const auto& target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, value);
    return target->GetProgressMaskValue(value);
}

BlendMode ViewAbstract::GetBlendMode(FrameNode* frameNode)
{
    BlendMode value = BlendMode::NONE;
    auto target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, value);
    return target->GetBackBlendModeValue(value);
}

TextDirection ViewAbstract::GetDirection(FrameNode* frameNode)
{
    TextDirection direction = TextDirection::AUTO;
    auto target = frameNode->GetLayoutProperty<LayoutProperty>();
    direction = target->GetLayoutDirection();
    return direction;
}

FlexAlign ViewAbstract::GetAlignSelf(FrameNode* frameNode)
{
    FlexAlign value = FlexAlign::AUTO;
    const auto& flexItemProperty = frameNode->GetLayoutProperty()->GetFlexItemProperty();
    CHECK_NULL_RETURN(flexItemProperty, value);
    auto getValue = flexItemProperty->GetAlignSelf();
    if (getValue.has_value()) {
        return getValue.value();
    }
    return value;
}

float ViewAbstract::GetFlexGrow(FrameNode* frameNode)
{
    float value = 0.0f;
    const auto& layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_RETURN(layoutProperty, value);
    const auto& property = layoutProperty->GetFlexItemProperty();
    CHECK_NULL_RETURN(property, value);
    auto getValue = property->GetFlexGrow();
    if (getValue.has_value()) {
        return getValue.value();
    }
    return value;
}

float ViewAbstract::GetFlexShrink(FrameNode* frameNode)
{
    float value = 0.0f;
    const auto& layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_RETURN(layoutProperty, value);
    const auto& property = layoutProperty->GetFlexItemProperty();
    CHECK_NULL_RETURN(property, value);
    auto getValue = property->GetFlexShrink();
    if (getValue.has_value()) {
        return getValue.value();
    }
    return value;
}

Dimension ViewAbstract::GetFlexBasis(FrameNode* frameNode)
{
    Dimension value;
    const auto& layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_RETURN(layoutProperty, value);
    const auto& property = layoutProperty->GetFlexItemProperty();
    CHECK_NULL_RETURN(property, value);
    auto getValue = property->GetFlexBasis();
    if (getValue.has_value()) {
        return getValue.value();
    }
    return value;
}

Dimension ViewAbstract::GetMinWidth(FrameNode* frameNode)
{
    Dimension value = Dimension(0.0f);
    const auto& layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_RETURN(layoutProperty, value);
    const auto& property = layoutProperty->GetCalcLayoutConstraint();
    CHECK_NULL_RETURN(property, value);
    auto size = property->minSize;
    if (size.has_value()) {
        auto width = size->Width();
        if (width.has_value()) {
            return width.value().GetDimension();
        }
    }
    return value;
}

Dimension ViewAbstract::GetMaxWidth(FrameNode* frameNode)
{
    Dimension value = Dimension(0.0f);
    const auto& layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_RETURN(layoutProperty, value);
    const auto& property = layoutProperty->GetCalcLayoutConstraint();
    CHECK_NULL_RETURN(property, value);
    auto size = property->maxSize;
    if (size.has_value()) {
        auto width = size->Width();
        if (width.has_value()) {
            return width.value().GetDimension();
        }
    }
    return value;
}

Dimension ViewAbstract::GetMinHeight(FrameNode* frameNode)
{
    Dimension value = Dimension(0.0f);
    const auto& layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_RETURN(layoutProperty, value);
    const auto& property = layoutProperty->GetCalcLayoutConstraint();
    CHECK_NULL_RETURN(property, value);
    auto size = property->minSize;
    if (size.has_value()) {
        auto height = size->Height();
        if (height.has_value()) {
            return height.value().GetDimension();
        }
    }
    return value;
}

Dimension ViewAbstract::GetMaxHeight(FrameNode* frameNode)
{
    Dimension value = Dimension(0.0f);
    const auto& layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_RETURN(layoutProperty, value);
    const auto& property = layoutProperty->GetCalcLayoutConstraint();
    CHECK_NULL_RETURN(property, value);
    auto size = property->maxSize;
    if (size.has_value()) {
        auto height = size->Height();
        if (height.has_value()) {
            return height.value().GetDimension();
        }
    }
    return value;
}

Dimension ViewAbstract::GetGrayScale(FrameNode* frameNode)
{
    Dimension value;
    auto target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, value);
    return target->GetFrontGrayScaleValue(value);
}

InvertVariant ViewAbstract::GetInvert(FrameNode* frameNode)
{
    InvertVariant value = 0.0f;
    auto target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, value);
    return target->GetFrontInvertValue(value);
}

Dimension ViewAbstract::GetSepia(FrameNode* frameNode)
{
    Dimension value;
    auto target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, value);
    return target->GetFrontSepiaValue(value);
}

Dimension ViewAbstract::GetContrast(FrameNode* frameNode)
{
    Dimension value(1.0f);
    auto target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, value);
    return target->GetFrontContrastValue(value);
}

Color ViewAbstract::GetForegroundColor(FrameNode* frameNode)
{
    Color value;
    auto target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, value);
    return target->GetForegroundColorValue(value);
}

NG::VectorF ViewAbstract::GetScale(FrameNode* frameNode)
{
    NG::VectorF defaultVector = { 1.0f, 1.0f };
    CHECK_NULL_RETURN(frameNode, defaultVector);
    auto renderContext = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(renderContext, defaultVector);
    return renderContext->GetTransformScale().value_or(defaultVector);
}

NG::Vector5F ViewAbstract::GetRotate(FrameNode* frameNode)
{
    NG::Vector5F defaultVector = { 0.0f, 0.0f, 0.0f, 0.0f, 0.0f };
    CHECK_NULL_RETURN(frameNode, defaultVector);
    auto renderContext = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(renderContext, defaultVector);
    return renderContext->GetTransformRotate().value_or(defaultVector);
}

Dimension ViewAbstract::GetBrightness(FrameNode* frameNode)
{
    Dimension defaultBrightness(1.0);
    CHECK_NULL_RETURN(frameNode, defaultBrightness);
    auto renderContext = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(renderContext, defaultBrightness);
    return renderContext->GetFrontBrightness().value_or(defaultBrightness);
}

Dimension ViewAbstract::GetSaturate(FrameNode* frameNode)
{
    Dimension defaultSaturate(1.0);
    CHECK_NULL_RETURN(frameNode, defaultSaturate);
    auto renderContext = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(renderContext, defaultSaturate);
    return renderContext->GetFrontSaturate().value_or(defaultSaturate);
}

BackgroundImagePosition ViewAbstract::GetBackgroundImagePosition(FrameNode* frameNode)
{
    BackgroundImagePosition defaultImagePosition;
    CHECK_NULL_RETURN(frameNode, defaultImagePosition);
    auto renderContext = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(renderContext, defaultImagePosition);
    return renderContext->GetBackgroundImagePosition().value_or(defaultImagePosition);
}

Dimension ViewAbstract::GetFrontBlur(FrameNode* frameNode)
{
    Dimension value;
    auto target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, value);
    auto& property = target->GetForeground();
    CHECK_NULL_RETURN(property, value);
    auto getValue = property->propBlurRadius;
    if (getValue.has_value()) {
        return getValue.value();
    }
    return value;
}

NG::Gradient ViewAbstract::GetLinearGradient(FrameNode *frameNode)
{
    NG::Gradient value;
    value.CreateGradientWithType(NG::GradientType::LINEAR);
    auto target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, value);
    return target->GetLinearGradientValue(value);
}

Alignment ViewAbstract::GetAlign(FrameNode *frameNode)
{
    Alignment value = Alignment::CENTER;
    const auto& layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_RETURN(layoutProperty, value);
    const auto& property = layoutProperty->GetPositionProperty();
    CHECK_NULL_RETURN(property, value);
    auto getValue = property->GetAlignment();
    if (getValue.has_value()) {
        return getValue.value();
    }
    return value;
}

Dimension ViewAbstract::GetWidth(FrameNode* frameNode)
{
    Dimension value = Dimension(-1.0f);
    const auto& layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_RETURN(layoutProperty, value);
    const auto& property = layoutProperty->GetCalcLayoutConstraint();
    CHECK_NULL_RETURN(property, value);
    auto size = property->selfIdealSize;
    if (size.has_value()) {
        auto width = size->Width();
        if (width.has_value()) {
            return width.value().GetDimension();
        }
    }
    return value;
}

Dimension ViewAbstract::GetHeight(FrameNode* frameNode)
{
    Dimension value = Dimension(-1.0f);
    const auto& layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_RETURN(layoutProperty, value);
    const auto& property = layoutProperty->GetCalcLayoutConstraint();
    CHECK_NULL_RETURN(property, value);
    auto size = property->selfIdealSize;
    if (size.has_value()) {
        auto height = size->Height();
        if (height.has_value()) {
            return height.value().GetDimension();
        }
    }
    return value;
}

Color ViewAbstract::GetBackgroundColor(FrameNode* frameNode)
{
    Color value;
    auto target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, value);
    return target->GetBackgroundColorValue(value);
}

std::string ViewAbstract::GetBackgroundImageSrc(FrameNode* frameNode)
{
    auto target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, "");
    if (target->GetBackgroundImage().has_value()) {
        return target->GetBackgroundImage()->GetSrc();
    }
    return "";
}

ImageRepeat ViewAbstract::GetBackgroundImageRepeat(FrameNode* frameNode)
{
    ImageRepeat value = ImageRepeat::NO_REPEAT;
    auto target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, value);
    if (target->GetBackgroundImageRepeat().has_value()) {
        return target->GetBackgroundImageRepeat().value();
    }
    return value;
}

PaddingProperty ViewAbstract::GetPadding(FrameNode* frameNode)
{
    CalcLength defaultDimen = CalcLength(0, DimensionUnit::VP);
    PaddingProperty paddings;
    paddings.top = std::optional<CalcLength>(defaultDimen);
    paddings.right = std::optional<CalcLength>(defaultDimen);
    paddings.bottom = std::optional<CalcLength>(defaultDimen);
    paddings.left = std::optional<CalcLength>(defaultDimen);
    const auto& layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_RETURN(layoutProperty, paddings);
    const auto& property = layoutProperty->GetPaddingProperty();
    CHECK_NULL_RETURN(property, paddings);
    paddings.top = std::optional<CalcLength>(property->top);
    paddings.right = std::optional<CalcLength>(property->right);
    paddings.bottom = std::optional<CalcLength>(property->bottom);
    paddings.left = std::optional<CalcLength>(property->left);
    return paddings;
}

std::optional<CalcSize> ViewAbstract::GetConfigSize(FrameNode* frameNode)
{
    auto value = std::optional<CalcSize>();
    const auto& layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_RETURN(layoutProperty, value);
    const auto& property = layoutProperty->GetCalcLayoutConstraint();
    CHECK_NULL_RETURN(property, value);
    auto size = property->selfIdealSize;
    if (size.has_value()) {
        value = size;
    }
    return value;
}

std::string ViewAbstract::GetKey(FrameNode* frameNode)
{
    std::string value;
    CHECK_NULL_RETURN(frameNode, value);
    return value = frameNode->GetInspectorIdValue();
}

bool ViewAbstract::GetEnabled(FrameNode* frameNode)
{
    auto eventHub = frameNode->GetEventHub<EventHub>();
    CHECK_NULL_RETURN(eventHub, false);
    return eventHub->IsEnabled();
}

MarginProperty ViewAbstract::GetMargin(FrameNode* frameNode)
{
    CalcLength defaultDimen = CalcLength(0, DimensionUnit::VP);
    MarginProperty margins;
    margins.top = std::optional<CalcLength>(defaultDimen);
    margins.right = std::optional<CalcLength>(defaultDimen);
    margins.bottom = std::optional<CalcLength>(defaultDimen);
    margins.left = std::optional<CalcLength>(defaultDimen);
    const auto& layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_RETURN(layoutProperty, margins);
    const auto& property = layoutProperty->GetMarginProperty();
    CHECK_NULL_RETURN(property, margins);
    margins.top = std::optional<CalcLength>(property->top);
    margins.right = std::optional<CalcLength>(property->right);
    margins.bottom = std::optional<CalcLength>(property->bottom);
    margins.left = std::optional<CalcLength>(property->left);
    return margins;
}

TranslateOptions ViewAbstract::GetTranslate(FrameNode* frameNode)
{
    TranslateOptions value(0.0f, 0.0f, 0.0f);
    auto target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, value);
    return target->GetTransformTranslateValue(value);
}

float ViewAbstract::GetAspectRatio(FrameNode* frameNode)
{
    float aspectRatio = 1.0f;
    const auto& layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_RETURN(layoutProperty, aspectRatio);
    aspectRatio = layoutProperty->GetAspectRatio();
    return aspectRatio;
}

void ViewAbstract::SetJSFrameNodeOnClick(FrameNode* frameNode, GestureEventFunc&& clickEventFunc)
{
    CHECK_NULL_VOID(frameNode);
    auto gestureHub = frameNode->GetOrCreateGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->SetJSFrameNodeOnClick(std::move(clickEventFunc));
}

void ViewAbstract::ClearJSFrameNodeOnClick(FrameNode* frameNode)
{
    CHECK_NULL_VOID(frameNode);
    auto gestureHub = frameNode->GetOrCreateGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->ClearJSFrameNodeOnClick();
}

void ViewAbstract::SetJSFrameNodeOnTouch(FrameNode* frameNode, TouchEventFunc&& touchEventFunc)
{
    CHECK_NULL_VOID(frameNode);
    auto gestureHub = frameNode->GetOrCreateGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->SetJSFrameNodeOnTouchEvent(std::move(touchEventFunc));
}

void ViewAbstract::ClearJSFrameNodeOnTouch(FrameNode* frameNode)
{
    CHECK_NULL_VOID(frameNode);
    auto gestureHub = frameNode->GetOrCreateGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->ClearJSFrameNodeOnTouch();
}

void ViewAbstract::SetJSFrameNodeOnAppear(FrameNode* frameNode, std::function<void()>&& onAppear)
{
    CHECK_NULL_VOID(frameNode);
    auto eventHub = frameNode->GetEventHub<NG::EventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetJSFrameNodeOnAppear(std::move(onAppear));
}

void ViewAbstract::ClearJSFrameNodeOnAppear(FrameNode* frameNode)
{
    CHECK_NULL_VOID(frameNode);
    auto eventHub = frameNode->GetEventHub<NG::EventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->ClearJSFrameNodeOnAppear();
}

void ViewAbstract::SetJSFrameNodeOnDisappear(FrameNode* frameNode, std::function<void()>&& onDisappear)
{
    CHECK_NULL_VOID(frameNode);
    auto eventHub = frameNode->GetEventHub<NG::EventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetJSFrameNodeOnDisappear(std::move(onDisappear));
}

void ViewAbstract::ClearJSFrameNodeOnDisappear(FrameNode* frameNode)
{
    CHECK_NULL_VOID(frameNode);
    auto eventHub = frameNode->GetEventHub<NG::EventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->ClearJSFrameNodeOnDisappear();
}

void ViewAbstract::SetJSFrameNodeOnKeyCallback(FrameNode* frameNode, OnKeyCallbackFunc&& onKeyCallback)
{
    CHECK_NULL_VOID(frameNode);
    auto focusHub = frameNode->GetOrCreateFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->SetJSFrameNodeOnKeyCallback(std::move(onKeyCallback));
}

void ViewAbstract::ClearJSFrameNodeOnKeyCallback(FrameNode* frameNode)
{
    CHECK_NULL_VOID(frameNode);
    auto focusHub = frameNode->GetOrCreateFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->ClearJSFrameNodeOnKeyCallback();
}

void ViewAbstract::SetJSFrameNodeOnFocusCallback(FrameNode* frameNode, OnFocusFunc&& onFocusCallback)
{
    CHECK_NULL_VOID(frameNode);
    auto focusHub = frameNode->GetOrCreateFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->SetJSFrameNodeOnFocusCallback(std::move(onFocusCallback));
}

void ViewAbstract::ClearJSFrameNodeOnFocusCallback(FrameNode* frameNode)
{
    CHECK_NULL_VOID(frameNode);
    auto focusHub = frameNode->GetOrCreateFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->ClearJSFrameNodeOnFocusCallback();
}

void ViewAbstract::SetJSFrameNodeOnBlurCallback(FrameNode* frameNode, OnBlurFunc&& onBlurCallback)
{
    CHECK_NULL_VOID(frameNode);
    auto focusHub = frameNode->GetOrCreateFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->SetJSFrameNodeOnBlurCallback(std::move(onBlurCallback));
}

void ViewAbstract::ClearJSFrameNodeOnBlurCallback(FrameNode* frameNode)
{
    CHECK_NULL_VOID(frameNode);
    auto focusHub = frameNode->GetOrCreateFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->ClearJSFrameNodeOnBlurCallback();
}

void ViewAbstract::SetJSFrameNodeOnHover(FrameNode* frameNode, OnHoverFunc&& onHoverEventFunc)
{
    CHECK_NULL_VOID(frameNode);
    auto eventHub = frameNode->GetOrCreateInputEventHub();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetJSFrameNodeOnHoverEvent(std::move(onHoverEventFunc));
}

void ViewAbstract::ClearJSFrameNodeOnHover(FrameNode* frameNode)
{
    CHECK_NULL_VOID(frameNode);
    auto eventHub = frameNode->GetOrCreateInputEventHub();
    CHECK_NULL_VOID(eventHub);
    eventHub->ClearJSFrameNodeOnHover();
}

void ViewAbstract::SetJSFrameNodeOnMouse(FrameNode* frameNode, OnMouseEventFunc&& onMouseEventFunc)
{
    CHECK_NULL_VOID(frameNode);
    auto eventHub = frameNode->GetOrCreateInputEventHub();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetJSFrameNodeOnMouseEvent(std::move(onMouseEventFunc));
}

void ViewAbstract::ClearJSFrameNodeOnMouse(FrameNode* frameNode)
{
    CHECK_NULL_VOID(frameNode);
    auto eventHub = frameNode->GetOrCreateInputEventHub();
    CHECK_NULL_VOID(eventHub);
    eventHub->ClearJSFrameNodeOnMouse();
}

BlendApplyType ViewAbstract::GetBlendApplyType(FrameNode* frameNode)
{
    BlendApplyType value = BlendApplyType::FAST;
    const auto& target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, value);
    return target->GetBackBlendApplyTypeValue(value);
}

void ViewAbstract::SetJSFrameNodeOnSizeChange(
    FrameNode* frameNode, std::function<void(const RectF& oldRect, const RectF& rect)>&& onSizeChanged)
{
    CHECK_NULL_VOID(frameNode);
    frameNode->SetJSFrameNodeOnSizeChangeCallback(std::move(onSizeChanged));
}

void ViewAbstract::ClearJSFrameNodeOnSizeChange(FrameNode* frameNode)
{
    CHECK_NULL_VOID(frameNode);
    auto eventHub = frameNode->GetEventHub<NG::EventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->ClearJSFrameNodeOnSizeChange();
}

void ViewAbstract::SetJSFrameNodeOnVisibleAreaApproximateChange(FrameNode* frameNode,
    const std::function<void(bool, double)>&& jsCallback, const std::vector<double>& ratioList,
    int32_t interval)
{
    auto pipeline = PipelineContext::GetCurrentContextSafely();
    CHECK_NULL_VOID(pipeline);
    CHECK_NULL_VOID(frameNode);
    frameNode->CleanVisibleAreaUserCallback(true);

    constexpr uint32_t minInterval = 100; // 100ms
    if (interval < 0 || interval < minInterval) {
        interval = minInterval;
    }
    VisibleCallbackInfo callback;
    callback.callback = std::move(jsCallback);
    callback.isCurrentVisible = false;
    callback.period = static_cast<uint32_t>(interval);
    pipeline->AddVisibleAreaChangeNode(frameNode->GetId());
    frameNode->SetVisibleAreaUserCallback(ratioList, callback);
}

void ViewAbstract::ClearJSFrameNodeOnVisibleAreaApproximateChange(FrameNode* frameNode)
{
    CHECK_NULL_VOID(frameNode);
    frameNode->CleanVisibleAreaUserCallback(true);
}

void ViewAbstract::SetOnGestureJudgeBegin(FrameNode* frameNode, GestureJudgeFunc&& gestureJudgeFunc)
{
    CHECK_NULL_VOID(frameNode);
    auto gestureHub = frameNode->GetOrCreateGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->SetOnGestureJudgeBegin(std::move(gestureJudgeFunc));
}

void ViewAbstract::SetOnSizeChanged(
    FrameNode* frameNode, std::function<void(const RectF& oldRect, const RectF& rect)>&& onSizeChanged)
{
    CHECK_NULL_VOID(frameNode);
    frameNode->SetOnSizeChangeCallback(std::move(onSizeChanged));
}

void ViewAbstract::SetDragEventStrictReportingEnabled(bool dragEventStrictReportingEnabled)
{
    auto pipeline = PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(pipeline);
    auto dragDropManager = pipeline->GetDragDropManager();
    CHECK_NULL_VOID(dragDropManager);
    dragDropManager->SetEventStrictReportingEnabled(dragEventStrictReportingEnabled);
}

void ViewAbstract::SetDisallowDropForcedly(bool isDisallowDropForcedly)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    frameNode->SetDisallowDropForcedly(isDisallowDropForcedly);
}

void ViewAbstract::SetBackgroundImageResizableSlice(const ImageResizableSlice& slice)
{
    if (!ViewStackProcessor::GetInstance()->IsCurrentVisualStateProcess()) {
        return;
    }
    ACE_UPDATE_RENDER_CONTEXT(BackgroundImageResizableSlice, slice);
}

void ViewAbstract::SetBackgroundImageResizableSlice(FrameNode* frameNode, const ImageResizableSlice& slice)
{
    ACE_UPDATE_NODE_RENDER_CONTEXT(BackgroundImageResizableSlice, slice, frameNode);
}

void ViewAbstract::SetOnTouchIntercept(FrameNode* frameNode, TouchInterceptFunc&& touchInterceptFunc)
{
    auto gestureHub = frameNode->GetOrCreateGestureEventHub();
    CHECK_NULL_VOID(gestureHub);
    gestureHub->SetOnTouchIntercept(std::move(touchInterceptFunc));
}

float ViewAbstract::GetLayoutWeight(FrameNode* frameNode)
{
    float layoutWeight = 0.0f;
    CHECK_NULL_RETURN(frameNode, layoutWeight);
    auto layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_RETURN(layoutProperty, layoutWeight);
    auto& magicItemProperty = layoutProperty->GetMagicItemProperty();
    if (magicItemProperty.HasLayoutWeight()) {
        return magicItemProperty.GetLayoutWeight().value_or(layoutWeight);
    }
    return layoutWeight;
}

void ViewAbstract::SetFocusScopeId(const std::string& focusScopeId, bool isGroup)
{
    auto focusHub = ViewStackProcessor::GetInstance()->GetOrCreateMainFrameNodeFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->SetFocusScopeId(focusScopeId, isGroup);
}

void ViewAbstract::SetFocusScopePriority(const std::string& focusScopeId, const uint32_t focusPriority)
{
    auto focusHub = ViewStackProcessor::GetInstance()->GetOrCreateMainFrameNodeFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->SetFocusScopePriority(focusScopeId, focusPriority);
}

int32_t ViewAbstract::GetDisplayIndex(FrameNode* frameNode)
{
    int32_t defaultDisplayIndex = 0;
    CHECK_NULL_RETURN(frameNode, defaultDisplayIndex);
    const auto& layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_RETURN(layoutProperty, defaultDisplayIndex);
    const auto& flexItemProperty = layoutProperty->GetFlexItemProperty();
    CHECK_NULL_RETURN(flexItemProperty, defaultDisplayIndex);
    return flexItemProperty->GetDisplayIndex().value_or(defaultDisplayIndex);
}

NG::BorderWidthProperty ViewAbstract::GetOuterBorderWidth(FrameNode* frameNode)
{
    BorderWidthProperty borderWidth;
    CHECK_NULL_RETURN(frameNode, borderWidth);
    auto context = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(context, borderWidth);
    auto outBorderWidth = context->GetOuterBorder()->GetOuterBorderWidth();
    CHECK_NULL_RETURN(outBorderWidth, borderWidth);
    return outBorderWidth.value_or(borderWidth);
}

void ViewAbstract::SetBias(FrameNode* frameNode, const BiasPair& biasPair)
{
    CHECK_NULL_VOID(frameNode);
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(LayoutProperty, Bias, biasPair, frameNode);
}

BiasPair ViewAbstract::GetBias(FrameNode* frameNode)
{
    BiasPair biasPair(-1.0f, -1.0f);
    CHECK_NULL_RETURN(frameNode, biasPair);
    auto layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_RETURN(layoutProperty, biasPair);
    CHECK_NULL_RETURN(layoutProperty->GetFlexItemProperty(), biasPair);
    return layoutProperty->GetFlexItemProperty()->GetBias().value_or(biasPair);
}

void ViewAbstract::ResetBias(FrameNode* frameNode)
{
    CHECK_NULL_VOID(frameNode);
    auto layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_VOID(layoutProperty);
    CHECK_NULL_VOID(layoutProperty->GetFlexItemProperty());
    layoutProperty->GetFlexItemProperty()->ResetBias();
}

RenderFit ViewAbstract::GetRenderFit(FrameNode* frameNode)
{
    RenderFit defalutRenderFit = RenderFit::TOP_LEFT;
    CHECK_NULL_RETURN(frameNode, defalutRenderFit);
    auto renderContext = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(renderContext, defalutRenderFit);
    return renderContext->GetRenderFit().value_or(defalutRenderFit);
}

BorderColorProperty ViewAbstract::GetOuterBorderColor(FrameNode* frameNode)
{
    Color defaultColor(0xff000000);
    BorderColorProperty borderColors = { defaultColor, defaultColor, defaultColor, defaultColor };
    CHECK_NULL_RETURN(frameNode, borderColors);
    const auto& target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, borderColors);
    return target->GetOuterBorderColorValue(borderColors);
}

bool ViewAbstract::GetRenderGroup(FrameNode* frameNode)
{
    CHECK_NULL_RETURN(frameNode, false);
    const auto& target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, false);
    return target->GetRenderGroupValue(false);
}

void ViewAbstract::SetOnVisibleChange(FrameNode* frameNode, std::function<void(bool, double)> &&onVisibleChange,
    const std::vector<double> &ratioList)
{
    auto pipeline = PipelineContext::GetCurrentContextSafely();
    CHECK_NULL_VOID(pipeline);
    CHECK_NULL_VOID(frameNode);
    frameNode->CleanVisibleAreaUserCallback();
    pipeline->AddVisibleAreaChangeNode(AceType::Claim<FrameNode>(frameNode), ratioList, onVisibleChange);
}

Color ViewAbstract::GetColorBlend(FrameNode* frameNode)
{
    Color defaultColor = Color::TRANSPARENT;
    CHECK_NULL_RETURN(frameNode, defaultColor);
    const auto& target = frameNode->GetRenderContext();
    CHECK_NULL_RETURN(target, defaultColor);
    return target->GetFrontColorBlendValue(defaultColor);
}

void ViewAbstract::ResetAreaChanged(FrameNode* frameNode)
{
    CHECK_NULL_VOID(frameNode);
    auto pipeline = PipelineContext::GetCurrentContextSafely();
    CHECK_NULL_VOID(pipeline);
    frameNode->ClearUserOnAreaChange();
    pipeline->RemoveOnAreaChangeNode(frameNode->GetId());
}

void ViewAbstract::ResetVisibleChange(FrameNode* frameNode)
{
    CHECK_NULL_VOID(frameNode);
    auto pipeline = PipelineContext::GetCurrentContextSafely();
    CHECK_NULL_VOID(pipeline);
    frameNode->CleanVisibleAreaUserCallback();
    pipeline->RemoveVisibleAreaChangeNode(frameNode->GetId());
}

void ViewAbstract::SetLayoutRect(FrameNode* frameNode, const NG::RectF& rect)
{
    CHECK_NULL_VOID(frameNode);
    frameNode->SetIsMeasureBoundary(true);
    const auto& layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_VOID(layoutProperty);
    layoutProperty->SetLayoutRect(rect);
}

void ViewAbstract::ResetLayoutRect(FrameNode* frameNode)
{
    CHECK_NULL_VOID(frameNode);
    frameNode->SetIsMeasureBoundary(false);
    const auto& layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_VOID(layoutProperty);
    layoutProperty->ResetLayoutRect();
}

NG::RectF ViewAbstract::GetLayoutRect(FrameNode* frameNode)
{
    CHECK_NULL_RETURN(frameNode, NG::RectF());
    const auto& layoutProperty = frameNode->GetLayoutProperty();
    CHECK_NULL_RETURN(layoutProperty, NG::RectF());
    return layoutProperty->GetLayoutRect().value_or(NG::RectF());
}

bool ViewAbstract::GetFocusOnTouch(FrameNode* frameNode)
{
    CHECK_NULL_RETURN(frameNode, false);
    auto focusHub = frameNode->GetFocusHub();
    CHECK_NULL_RETURN(focusHub, false);
    return focusHub->IsFocusOnTouch().value_or(false);
}
} // namespace OHOS::Ace::NG

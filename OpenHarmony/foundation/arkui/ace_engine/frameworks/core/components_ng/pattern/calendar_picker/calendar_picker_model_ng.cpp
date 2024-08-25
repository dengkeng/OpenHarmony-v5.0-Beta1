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

#include "core/components_ng/pattern/calendar_picker/calendar_picker_model_ng.h"

#include "base/i18n/localization.h"
#include "core/components/theme/icon_theme.h"
#include "core/components_ng/base/view_stack_processor.h"
#include "core/components_ng/pattern/button/button_pattern.h"
#include "core/components_ng/pattern/flex/flex_layout_pattern.h"
#include "core/components_ng/pattern/flex/flex_layout_property.h"
#include "core/components_ng/pattern/image/image_pattern.h"
#include "core/components_ng/pattern/text/text_pattern.h"
#include "core/components_ng/pattern/text_field/text_field_pattern.h"

namespace OHOS::Ace::NG {
constexpr int32_t YEAR_NODE_INDEX = 0;
constexpr int32_t MONTH_NODE_INDEX = 2;
constexpr int32_t DAY_NODE_INDEX = 4;
constexpr int32_t DATE_NODE_COUNT = 3;
constexpr int32_t ONE_DIGIT_BOUNDARY = 10;
constexpr float DEFAULT_HINT_RADIUS = 16.0f;
static int32_t yearNodeIndex_ = 0;
static int32_t monthNodeIndex_ = 2;
static int32_t dayNodeIndex_ = 4;
void CalendarPickerModelNG::Create(const CalendarSettingData& settingData)
{
    auto* stack = ViewStackProcessor::GetInstance();
    auto nodeId = stack->ClaimNodeId();
    ACE_LAYOUT_SCOPED_TRACE("Create[%s][self:%d]", V2::CALENDAR_PICKER_ETS_TAG, nodeId);
    auto pickerNode = CalendarPickerModelNG::CreateNode(nodeId, settingData);
    stack->Push(pickerNode);
}

RefPtr<FrameNode> CalendarPickerModelNG::CreateFrameNode(int32_t nodeId)
{
    NG::CalendarSettingData settingData;
    return CalendarPickerModelNG::CreateNode(nodeId, settingData);
}

void CalendarPickerModelNG::LayoutPicker(const RefPtr<CalendarPickerPattern>& pickerPattern,
    RefPtr<FrameNode>& pickerNode, const CalendarSettingData& settingData, const RefPtr<CalendarTheme>& theme)
{
    if (!pickerPattern->HasContentNode()) {
        auto contentNode =
            CalendarPickerModelNG::CreateCalendarNodeChild(pickerPattern->GetContentId(), settingData, theme);
        CHECK_NULL_VOID(contentNode);
        contentNode->MountToParent(pickerNode);
    } else {
        pickerPattern->SetDate(settingData.selectedDate.ToString(true));
    }
    auto flexNode = CalendarPickerModelNG::CreateButtonFlexChild(pickerPattern->GetButtonFlexId(), theme);
    CHECK_NULL_VOID(flexNode);
    flexNode->MountToParent(pickerNode);
    if (!pickerPattern->HasAddNode()) {
        auto addNode = CalendarPickerModelNG::CreateButtonChild(pickerPattern->GetAddId(), true, theme);
        CHECK_NULL_VOID(addNode);
        addNode->MountToParent(flexNode, 0, true);
    }
    if (!pickerPattern->HasSubNode()) {
        auto subNode = CalendarPickerModelNG::CreateButtonChild(pickerPattern->GetSubId(), false, theme);
        CHECK_NULL_VOID(subNode);
        subNode->MountToParent(flexNode, 1, true);
    }
}

RefPtr<FrameNode> CalendarPickerModelNG::CreateButtonChild(int32_t id, bool isAdd, const RefPtr<CalendarTheme>& theme)
{
    auto buttonNode =
        FrameNode::GetOrCreateFrameNode(V2::BUTTON_ETS_TAG, id, []() { return AceType::MakeRefPtr<ButtonPattern>(); });
    CHECK_NULL_RETURN(buttonNode, nullptr);
    auto buttonEventHub = buttonNode->GetEventHub<ButtonEventHub>();
    CHECK_NULL_RETURN(buttonEventHub, nullptr);
    buttonEventHub->SetStateEffect(true);

    auto buttonLayoutProperty = buttonNode->GetLayoutProperty<ButtonLayoutProperty>();
    CHECK_NULL_RETURN(buttonLayoutProperty, nullptr);
    buttonLayoutProperty->UpdateType(ButtonType::NORMAL);

    auto buttonPattern = buttonNode->GetPattern<ButtonPattern>();
    CHECK_NULL_RETURN(buttonPattern, nullptr);

    buttonNode->GetLayoutProperty()->UpdateUserDefinedIdealSize(
        CalcSize(CalcLength(theme->GetEntryButtonWidth()), std::nullopt));
    buttonNode->GetLayoutProperty()->UpdateLayoutWeight(1);
    BorderWidthProperty borderWidth;
    if (isAdd) {
        borderWidth.leftDimen = theme->GetEntryBorderWidth();
        borderWidth.bottomDimen = theme->GetEntryBorderWidth() / 2;
    } else {
        borderWidth.leftDimen = theme->GetEntryBorderWidth();
        borderWidth.topDimen = theme->GetEntryBorderWidth() / 2;
    }
    buttonNode->GetLayoutProperty()->UpdateBorderWidth(borderWidth);
    BorderColorProperty borderColor;
    borderColor.SetColor(theme->GetEntryBorderColor());
    buttonNode->GetRenderContext()->UpdateBorderColor(borderColor);
    buttonNode->MarkModifyDone();

    auto imageNode = CreateButtonImageChild(isAdd, theme);
    CHECK_NULL_RETURN(imageNode, nullptr);
    imageNode->MountToParent(buttonNode);
    return buttonNode;
}

RefPtr<FrameNode> CalendarPickerModelNG::CreateButtonImageChild(bool isAdd, const RefPtr<CalendarTheme>& theme)
{
    auto imageNode = FrameNode::CreateFrameNode(
        V2::IMAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<ImagePattern>());
    CHECK_NULL_RETURN(imageNode, nullptr);
    imageNode->GetLayoutProperty()->UpdateUserDefinedIdealSize(
        CalcSize(CalcLength(theme->GetEntryArrowWidth()), CalcLength(theme->GetEntryArrowHeight())));
    auto pipeline = PipelineBase::GetCurrentContext();
    CHECK_NULL_RETURN(pipeline, nullptr);
    auto iconTheme = pipeline->GetTheme<IconTheme>();
    std::string iconPath;
    ImageSourceInfo imageSourceInfo;
    if (isAdd) {
        imageSourceInfo.SetResourceId(InternalResource::ResourceId::IC_PUBLIC_ARROW_UP_SVG);
        iconPath = iconTheme->GetIconPath(InternalResource::ResourceId::IC_PUBLIC_ARROW_UP_SVG);
    } else {
        imageSourceInfo.SetResourceId(InternalResource::ResourceId::IC_PUBLIC_ARROW_DOWN_SVG);
        iconPath = iconTheme->GetIconPath(InternalResource::ResourceId::IC_PUBLIC_ARROW_DOWN_SVG);
    }
    imageSourceInfo.SetSrc(iconPath, theme->GetEntryArrowColor());
    imageNode->GetLayoutProperty<ImageLayoutProperty>()->UpdateImageSourceInfo(imageSourceInfo);
    imageNode->MarkModifyDone();
    return imageNode;
}

RefPtr<FrameNode> CalendarPickerModelNG::CreateButtonFlexChild(int32_t buttonFlexId, const RefPtr<CalendarTheme>& theme)
{
    auto flexNode = FrameNode::GetOrCreateFrameNode(
        V2::COLUMN_ETS_TAG, buttonFlexId, []() { return AceType::MakeRefPtr<LinearLayoutPattern>(true); });
    CHECK_NULL_RETURN(flexNode, nullptr);
    auto flexLayoutProperty = flexNode->GetLayoutProperty<LinearLayoutProperty>();
    CHECK_NULL_RETURN(flexLayoutProperty, nullptr);
    flexLayoutProperty->UpdateMainAxisAlign(FlexAlign::CENTER);
    flexLayoutProperty->UpdateMeasureType(MeasureType::MATCH_PARENT_CROSS_AXIS);
    return flexNode;
}

RefPtr<FrameNode> CalendarPickerModelNG::CreateCalendarNodeChild(
    int32_t contentId, const CalendarSettingData& settingData, const RefPtr<CalendarTheme>& theme)
{
    auto contentNode = FrameNode::GetOrCreateFrameNode(
        V2::ROW_ETS_TAG, contentId, []() { return AceType::MakeRefPtr<LinearLayoutPattern>(false); });
    CHECK_NULL_RETURN(contentNode, nullptr);

    auto linearLayoutProperty = contentNode->GetLayoutProperty<LinearLayoutProperty>();
    CHECK_NULL_RETURN(linearLayoutProperty, nullptr);

    linearLayoutProperty->UpdateMainAxisAlign(FlexAlign::CENTER);
    linearLayoutProperty->UpdateCrossAxisAlign(FlexAlign::CENTER);
    contentNode->GetRenderContext()->SetClipToFrame(true);
    linearLayoutProperty->UpdateMeasureType(MeasureType::MATCH_PARENT);
    BorderRadiusProperty borderRadius;
    borderRadius.radiusTopLeft = theme->GetEntryBorderRadius();
    borderRadius.radiusBottomLeft = theme->GetEntryBorderRadius();
    borderRadius.radiusTopRight = theme->GetEntryBorderRadius();
    borderRadius.radiusBottomLeft = theme->GetEntryBorderRadius();
    contentNode->GetRenderContext()->UpdateBorderRadius(borderRadius);
    PaddingProperty padding;
    padding.top = CalcLength(theme->GetEntryDateTopBottomMargin());
    padding.left = CalcLength(theme->GetEntryDateLeftRightMargin());
    padding.right = CalcLength(theme->GetEntryDateLeftRightMargin());
    padding.bottom = CalcLength(theme->GetEntryDateTopBottomMargin());
    linearLayoutProperty->UpdatePadding(padding);
	
    CreateDateNode(contentId, settingData);
    contentNode->MarkModifyDone();
    return contentNode;
}

void CalendarPickerModelNG::CreateDateNode(int32_t contentId, const CalendarSettingData& settingData)
{
    auto contentNode = FrameNode::GetOrCreateFrameNode(
        V2::ROW_ETS_TAG, contentId, []() { return AceType::MakeRefPtr<LinearLayoutPattern>(false); });
    CHECK_NULL_VOID(contentNode);
    PickerDate date = settingData.selectedDate;
    std::vector<std::string> outOrder;
    bool result = Localization::GetInstance()->GetDateColumnFormatOrder(outOrder);
    std::map<std::size_t, std::string> order;
    if (!result || outOrder.size() < DATE_NODE_COUNT) {
        yearNodeIndex_ = YEAR_NODE_INDEX;
        monthNodeIndex_ = MONTH_NODE_INDEX;
        dayNodeIndex_ = DAY_NODE_INDEX;
        auto num = 0;
        order[num++] = std::to_string(date.GetYear());
        order[num++] = (date.GetMonth() < ONE_DIGIT_BOUNDARY ? "0" : "") + std::to_string(date.GetMonth());
        order[num] = (date.GetDay() < ONE_DIGIT_BOUNDARY ? "0" : "") + std::to_string(date.GetDay());
    } else {
        int32_t index = 0;
        for (size_t i = 0; i < outOrder.size(); ++i) {
            if (outOrder[i] == "year") {
                yearNodeIndex_ = i + index;
                order[i] = std::to_string(date.GetYear());
            }
            if (outOrder[i] == "month") {
                monthNodeIndex_ = i + index;
                order[i] = (date.GetMonth() < ONE_DIGIT_BOUNDARY ? "0" : "") + std::to_string(date.GetMonth());
            }
            if (outOrder[i] == "day") {
                dayNodeIndex_ = i + index;
                order[i] = (date.GetDay() < ONE_DIGIT_BOUNDARY ? "0" : "") + std::to_string(date.GetDay());
            }
            index++;
        }
    }
    auto firstDateNode = CreateDateTextNode(order[0]);
    CHECK_NULL_VOID(firstDateNode);
    firstDateNode->MountToParent(contentNode);
    auto textNode1 = CreateDateTextNode("/");
    CHECK_NULL_VOID(textNode1);
    textNode1->MountToParent(contentNode);
    auto secondDateNode = CreateDateTextNode(order[1]);
    CHECK_NULL_VOID(secondDateNode);
    secondDateNode->MountToParent(contentNode);
    auto textNode2 = CreateDateTextNode("/");
    CHECK_NULL_VOID(textNode2);
    textNode2->MountToParent(contentNode);
    auto thirdDateNode = CreateDateTextNode(order[2]);
    CHECK_NULL_VOID(thirdDateNode);
    thirdDateNode->MountToParent(contentNode);
}

RefPtr<FrameNode> CalendarPickerModelNG::CreateDateTextNode(const std::string& textContent)
{
    auto pipeline = PipelineBase::GetCurrentContext();
    CHECK_NULL_RETURN(pipeline, nullptr);
    RefPtr<CalendarTheme> calendarTheme = pipeline->GetTheme<CalendarTheme>();
    CHECK_NULL_RETURN(calendarTheme, nullptr);
    auto textNode = FrameNode::CreateFrameNode(
        V2::TEXT_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<TextPattern>());
    CHECK_NULL_RETURN(textNode, nullptr);
    auto textLayoutProperty = textNode->GetLayoutProperty<TextLayoutProperty>();
    CHECK_NULL_RETURN(textLayoutProperty, nullptr);
    textLayoutProperty->UpdateContent(textContent);
    textLayoutProperty->UpdateMaxLines(1);
    textLayoutProperty->UpdateTextColor(calendarTheme->GetEntryFontColor());
    textLayoutProperty->UpdateFontSize(calendarTheme->GetEntryFontSize());
    textNode->MarkModifyDone();
    return textNode;
}

RefPtr<FrameNode> CalendarPickerModelNG::CreateNode(int32_t nodeId, const CalendarSettingData& settingData)
{
    auto pickerNode = FrameNode::GetOrCreateFrameNode(
        V2::CALENDAR_PICKER_ETS_TAG, nodeId, []() { return AceType::MakeRefPtr<CalendarPickerPattern>(); });
    auto pickerPattern = pickerNode->GetPattern<CalendarPickerPattern>();
    CHECK_NULL_RETURN(pickerPattern, pickerNode);
    auto pipelineContext = PipelineContext::GetCurrentContext();
    CHECK_NULL_RETURN(pipelineContext, pickerNode);
    RefPtr<CalendarTheme> theme = pipelineContext->GetTheme<CalendarTheme>();
    CHECK_NULL_RETURN(theme, pickerNode);
    pickerPattern->SetCalendarData(settingData);
    pickerNode->GetLayoutProperty()->UpdateUserDefinedIdealSize(
        CalcSize(std::nullopt, CalcLength(theme->GetEntryHeight())));
    BorderWidthProperty borderWidth;
    borderWidth.SetBorderWidth(theme->GetEntryBorderWidth());
    pickerNode->GetLayoutProperty()->UpdateBorderWidth(borderWidth);
    CHECK_NULL_RETURN(pickerNode->GetRenderContext(), pickerNode);
    BorderColorProperty borderColor;
    borderColor.SetColor(theme->GetEntryBorderColor());
    pickerNode->GetRenderContext()->UpdateBorderColor(borderColor);
    BorderRadiusProperty borderRadius;
    borderRadius.SetRadius(theme->GetEntryBorderRadius());
    pickerNode->GetRenderContext()->UpdateBorderRadius(borderRadius);
    pickerNode->GetRenderContext()->SetClipToFrame(true);
    pickerNode->GetRenderContext()->SetClipToBounds(true);
    pickerNode->GetRenderContext()->UpdateClipEdge(true);
    CHECK_NULL_RETURN(pickerNode->GetLayoutProperty<LinearLayoutProperty>(), pickerNode);
    pickerNode->GetLayoutProperty<LinearLayoutProperty>()->UpdateMainAxisAlign(FlexAlign::FLEX_START);
    pickerNode->GetLayoutProperty<LinearLayoutProperty>()->UpdateCrossAxisAlign(FlexAlign::CENTER);
    pickerNode->GetLayoutProperty<LinearLayoutProperty>()->UpdateMeasureType(MeasureType::MATCH_CONTENT);
    CalendarPickerModelNG::LayoutPicker(pickerPattern, pickerNode, settingData, theme);

    pickerNode->MarkModifyDone();
    return pickerNode;
}

void CalendarPickerModelNG::SetEdgeAlign(const CalendarEdgeAlign& alignType, const DimensionOffset& offset)
{
    ACE_UPDATE_LAYOUT_PROPERTY(CalendarPickerLayoutProperty, DialogAlignType, alignType);
    ACE_UPDATE_LAYOUT_PROPERTY(CalendarPickerLayoutProperty, DialogOffset, offset);
}

void CalendarPickerModelNG::SetTextStyle(const PickerTextStyle& textStyle)
{
    auto pipeline = PipelineBase::GetCurrentContext();
    CHECK_NULL_VOID(pipeline);
    RefPtr<CalendarTheme> calendarTheme = pipeline->GetTheme<CalendarTheme>();
    CHECK_NULL_VOID(calendarTheme);
    if (textStyle.fontSize.has_value() && textStyle.fontSize->IsValid()) {
        ACE_UPDATE_LAYOUT_PROPERTY(CalendarPickerLayoutProperty, FontSize, textStyle.fontSize.value());
    } else {
        ACE_UPDATE_LAYOUT_PROPERTY(CalendarPickerLayoutProperty, FontSize, calendarTheme->GetEntryFontSize());
    }
    ACE_UPDATE_LAYOUT_PROPERTY(
        CalendarPickerLayoutProperty, Color, textStyle.textColor.value_or(calendarTheme->GetEntryFontColor()));
    ACE_UPDATE_LAYOUT_PROPERTY(CalendarPickerLayoutProperty, Weight, textStyle.fontWeight.value_or(FontWeight::NORMAL));
}

void CalendarPickerModelNG::SetOnChange(SelectedChangeEvent&& onChange)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto eventHub = frameNode->GetEventHub<CalendarPickerEventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetOnChangeEvent(std::move(onChange));
}

void CalendarPickerModelNG::SetChangeEvent(SelectedChangeEvent&& onChange)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto eventHub = frameNode->GetEventHub<CalendarPickerEventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetChangeEvent(std::move(onChange));
}

void CalendarPickerModelNG::SetPadding(const PaddingProperty& padding)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto pickerPattern = frameNode->GetPattern<CalendarPickerPattern>();
    CHECK_NULL_VOID(pickerPattern);
    if (!pickerPattern->HasContentNode()) {
        return;
    }
    auto contentNode = AceType::DynamicCast<FrameNode>(frameNode->GetFirstChild());
    CHECK_NULL_VOID(contentNode);
    auto linearLayoutProperty = contentNode->GetLayoutProperty();
    CHECK_NULL_VOID(linearLayoutProperty);
    linearLayoutProperty->UpdatePadding(padding);
}

void CalendarPickerModelNG::SetTextStyle(FrameNode* frameNode, const PickerTextStyle& textStyle)
{
    auto pipeline = PipelineBase::GetCurrentContextSafely();
    CHECK_NULL_VOID(pipeline);
    RefPtr<CalendarTheme> calendarTheme = pipeline->GetTheme<CalendarTheme>();
    CHECK_NULL_VOID(calendarTheme);
    if (textStyle.fontSize.has_value() && textStyle.fontSize->IsValid()) {
        ACE_UPDATE_NODE_LAYOUT_PROPERTY(CalendarPickerLayoutProperty, FontSize, textStyle.fontSize.value(), frameNode);
    } else {
        ACE_UPDATE_NODE_LAYOUT_PROPERTY(
            CalendarPickerLayoutProperty, FontSize, calendarTheme->GetEntryFontSize(), frameNode);
    }
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(CalendarPickerLayoutProperty, Color,
        textStyle.textColor.value_or(calendarTheme->GetEntryFontColor()), frameNode);
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(
        CalendarPickerLayoutProperty, Weight, textStyle.fontWeight.value_or(FontWeight::NORMAL), frameNode);
}

RefPtr<CalendarTheme> GetCalendarTheme()
{
    auto pipeline = PipelineBase::GetCurrentContextSafely();
    CHECK_NULL_RETURN(pipeline, nullptr);
    return pipeline->GetTheme<CalendarTheme>();
}

PickerTextStyle CalendarPickerModelNG::GetTextStyle(FrameNode* frameNode)
{
    PickerTextStyle textStyle;
    CHECK_NULL_RETURN(frameNode, textStyle);
    auto calendarTheme = GetCalendarTheme();
    CHECK_NULL_RETURN(calendarTheme, textStyle);
    auto calendarPickerProperty = frameNode->GetLayoutProperty<CalendarPickerLayoutProperty>();
    CHECK_NULL_RETURN(calendarPickerProperty, textStyle);
    textStyle.textColor =
        calendarPickerProperty->HasColor() ? calendarPickerProperty->GetColor() : calendarTheme->GetEntryFontColor();
    textStyle.fontSize = calendarPickerProperty->HasFontSize() ? calendarPickerProperty->GetFontSize()
                                                               : calendarTheme->GetEntryFontSize();
    textStyle.fontWeight =
        calendarPickerProperty->HasWeight() ? calendarPickerProperty->GetWeight() : FontWeight::NORMAL;
    return textStyle;
}

CalendarEdgeAlign CalendarPickerModelNG::GetEdgeAlignType(FrameNode* frameNode)
{
    CHECK_NULL_RETURN(frameNode, CalendarEdgeAlign::EDGE_ALIGN_END);
    auto layoutProperty = frameNode->GetLayoutProperty<CalendarPickerLayoutProperty>();
    CHECK_NULL_RETURN(layoutProperty, CalendarEdgeAlign::EDGE_ALIGN_END);
    return layoutProperty->GetDialogAlignType().value_or(CalendarEdgeAlign::EDGE_ALIGN_END);
}

DimensionOffset CalendarPickerModelNG::GetEdgeOffset(FrameNode* frameNode)
{
    DimensionOffset offsetDimension(0.0_vp, 0.0_vp);
    CHECK_NULL_RETURN(frameNode, offsetDimension);
    auto layoutProperty = frameNode->GetLayoutProperty<CalendarPickerLayoutProperty>();
    CHECK_NULL_RETURN(layoutProperty, offsetDimension);
    return layoutProperty->GetDialogOffset().value_or(offsetDimension);
}

void CalendarPickerModelNG::SetEdgeAlign(
    FrameNode* frameNode, const CalendarEdgeAlign& alignType, const DimensionOffset& offset)
{
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(CalendarPickerLayoutProperty, DialogAlignType, alignType, frameNode);
    ACE_UPDATE_NODE_LAYOUT_PROPERTY(CalendarPickerLayoutProperty, DialogOffset, offset, frameNode);
}

void CalendarPickerModelNG::SetPadding(FrameNode* frameNode, const PaddingProperty& padding)
{
    CHECK_NULL_VOID(frameNode);
    auto pickerPattern = frameNode->GetPattern<CalendarPickerPattern>();
    CHECK_NULL_VOID(pickerPattern);
    if (!pickerPattern->HasContentNode()) {
        return;
    }
    auto contentNode = AceType::DynamicCast<FrameNode>(frameNode->GetFirstChild());
    CHECK_NULL_VOID(contentNode);
    auto linearLayoutProperty = contentNode->GetLayoutProperty();
    CHECK_NULL_VOID(linearLayoutProperty);
    linearLayoutProperty->UpdatePadding(padding);
}

void CalendarPickerModelNG::SetHintRadiusWithNode(FrameNode* frameNode, Dimension& radius)
{
    CHECK_NULL_VOID(frameNode);
    auto pickerPattern = frameNode->GetPattern<CalendarPickerPattern>();
    CHECK_NULL_VOID(pickerPattern);
    auto calendarDate = pickerPattern->GetCalendarData();
    calendarDate.dayRadius = radius;
    pickerPattern->SetCalendarData(calendarDate);
}

void CalendarPickerModelNG::SetSelectDateWithNode(FrameNode* frameNode, uint32_t year, uint32_t month, uint32_t day)
{
    CHECK_NULL_VOID(frameNode);
    auto pickerPattern = frameNode->GetPattern<CalendarPickerPattern>();
    CHECK_NULL_VOID(pickerPattern);
    auto calendarDate = pickerPattern->GetCalendarData();
    if (year > 0) {
        calendarDate.selectedDate.SetYear(year);
        auto yearNode = CalendarPickerModelNG::GetYearNode(frameNode);
        if (yearNode) {
            auto textLayoutProperty = yearNode->GetLayoutProperty<TextLayoutProperty>();
            if (textLayoutProperty) {
                textLayoutProperty->UpdateContent(std::to_string(year));
                yearNode->MarkModifyDone();
                yearNode->MarkDirtyNode();
            }
        }
    }
    if (month > 0) {
        calendarDate.selectedDate.SetMonth(month);
        auto monthNode = CalendarPickerModelNG::GetMonthNode(frameNode);
        if (monthNode) {
            auto textLayoutProperty = monthNode->GetLayoutProperty<TextLayoutProperty>();
            if (textLayoutProperty) {
                auto selectedMonthStr = (month < ONE_DIGIT_BOUNDARY  ? "0" : "") + std::to_string(month);
                textLayoutProperty->UpdateContent(selectedMonthStr);
                monthNode->MarkModifyDone();
                monthNode->MarkDirtyNode();
            }
        }
    }
    if (day > 0) {
        calendarDate.selectedDate.SetDay(day);
        auto dayNode = CalendarPickerModelNG::GetDayNode(frameNode);
        if (dayNode) {
            auto textLayoutProperty = dayNode->GetLayoutProperty<TextLayoutProperty>();
            if (textLayoutProperty) {
                auto selectedDayStr = (day < ONE_DIGIT_BOUNDARY  ? "0" : "") + std::to_string(day);
                textLayoutProperty->UpdateContent(selectedDayStr);
                dayNode->MarkModifyDone();
                dayNode->MarkDirtyNode();
            }
        }
    }
    pickerPattern->SetCalendarData(calendarDate);
}

RefPtr<FrameNode> CalendarPickerModelNG::GetYearNode(FrameNode* calendarPickerNode)
{
    CHECK_NULL_RETURN(calendarPickerNode, nullptr);
    auto feedbackNode = calendarPickerNode->GetFirstChild();
    CHECK_NULL_RETURN(feedbackNode, nullptr);
    return AceType::DynamicCast<FrameNode>(feedbackNode->GetChildAtIndex(yearNodeIndex_));
}

RefPtr<FrameNode> CalendarPickerModelNG::GetMonthNode(FrameNode* calendarPickerNode)
{
    CHECK_NULL_RETURN(calendarPickerNode, nullptr);
    auto feedbackNode = calendarPickerNode->GetFirstChild();
    CHECK_NULL_RETURN(feedbackNode, nullptr);
    return AceType::DynamicCast<FrameNode>(feedbackNode->GetChildAtIndex(monthNodeIndex_));
}

RefPtr<FrameNode> CalendarPickerModelNG::GetDayNode(FrameNode* calendarPickerNode)
{
    CHECK_NULL_RETURN(calendarPickerNode, nullptr);
    auto feedbackNode = calendarPickerNode->GetFirstChild();
    CHECK_NULL_RETURN(feedbackNode, nullptr);
    return AceType::DynamicCast<FrameNode>(feedbackNode->GetChildAtIndex(dayNodeIndex_));
}

Dimension CalendarPickerModelNG::GetHintRadius(FrameNode* frameNode)
{
    Dimension defaultRadius(DEFAULT_HINT_RADIUS);
    CHECK_NULL_RETURN(frameNode, defaultRadius);
    auto pickerPattern = frameNode->GetPattern<CalendarPickerPattern>();
    CHECK_NULL_RETURN(pickerPattern, defaultRadius);
    auto calendarDate = pickerPattern->GetCalendarData();
    return calendarDate.dayRadius.value_or(defaultRadius);
}

PickerDate CalendarPickerModelNG::GetSelectDateWithNode(FrameNode* frameNode)
{
    auto defaultSelectedDate = PickerDate::Current();
    CHECK_NULL_RETURN(frameNode, defaultSelectedDate);
    auto pickerPattern = frameNode->GetPattern<CalendarPickerPattern>();
    CHECK_NULL_RETURN(pickerPattern, defaultSelectedDate);
    return pickerPattern->GetCalendarData().selectedDate;
}

void CalendarPickerModelNG::SetOnChangeWithNode(FrameNode* frameNode, SelectedChangeEvent&& onChange)
{
    CHECK_NULL_VOID(frameNode);
    auto eventHub = frameNode->GetEventHub<CalendarPickerEventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetOnChangeEvent(std::move(onChange));
}
} // namespace OHOS::Ace::NG

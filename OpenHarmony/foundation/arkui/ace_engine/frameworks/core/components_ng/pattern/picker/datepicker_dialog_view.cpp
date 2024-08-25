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
#include "core/components_ng/pattern/picker/datepicker_dialog_view.h"

#include <utility>

#include "base/geometry/dimension.h"
#include "base/memory/ace_type.h"
#include "base/utils/utils.h"
#include "core/components/theme/icon_theme.h"
#include "core/components_ng/base/view_stack_processor.h"
#include "core/components_ng/pattern/button/button_pattern.h"
#include "core/components_ng/pattern/calendar/calendar_paint_property.h"
#include "core/components_ng/pattern/checkbox/checkbox_pattern.h"
#include "core/components_ng/pattern/dialog/dialog_view.h"
#include "core/components_ng/pattern/divider/divider_pattern.h"
#include "core/components_ng/pattern/image/image_pattern.h"
#include "core/components_ng/pattern/picker/datepicker_pattern.h"
#include "core/components_ng/pattern/picker/datepicker_row_layout_property.h"
#include "core/components_ng/pattern/stack/stack_pattern.h"
#include "core/components_ng/property/measure_property.h"
#include "core/components_v2/inspector/inspector_constants.h"
#include "core/pipeline/pipeline_base.h"

namespace OHOS::Ace::NG {
namespace {
const int32_t MARGIN_HALF = 2;
constexpr double MONTHDAYS_WIDTH_PERCENT_ONE = 0.4285;
constexpr double TIME_WIDTH_PERCENT_ONE = 0.5714;
constexpr double MONTHDAYS_WIDTH_PERCENT_TWO = 0.3636;
constexpr double TIME_WIDTH_PERCENT_TWO = 0.6363;
constexpr Dimension BUTTON_BOTTOM_TOP_MARGIN = 10.0_vp;
constexpr Dimension LUNARSWITCH_HEIGHT = 48.0_vp;
constexpr Dimension CHECKBOX_SIZE = 24.0_vp;
constexpr Dimension PICKER_DIALOG_MARGIN_FORM_EDGE = 24.0_vp;
constexpr Dimension TITLE_HEIGHT = 40.0_vp;
constexpr Dimension TITLE_BUTTON_HEIGHT = 32.0_vp;
constexpr Dimension TITLE_PADDING_HORIZONTAL = 16.0_vp;
constexpr Dimension PICKER_MARGIN_FROM_TITLE_AND_BUTTON = 8.0_vp;
constexpr int32_t HOVER_ANIMATION_DURATION = 250;
constexpr int32_t BUFFER_NODE_NUMBER = 2;
constexpr int32_t RATIO_SEVEN = 7;
constexpr int32_t RATIO_FOUR = 4;
constexpr int32_t RATIO_THREE = 3;
constexpr int32_t RATIO_TWO = 2;
constexpr uint8_t PIXEL_ROUND = 18;
constexpr size_t ACCEPT_BUTTON_INDEX = 0;
constexpr size_t CANCEL_BUTTON_INDEX = 1;
} // namespace
bool DatePickerDialogView::switchFlag_ = false;

RefPtr<FrameNode> DatePickerDialogView::Show(const DialogProperties& dialogProperties,
    const DatePickerSettingData& settingData, const std::vector<ButtonInfo>& buttonInfos,
    std::map<std::string, NG::DialogEvent> dialogEvent, std::map<std::string, NG::DialogGestureEvent> dialogCancelEvent)
{
    ACE_LAYOUT_SCOPED_TRACE("Create[DatePickerDialogView]");
    auto contentColumn = FrameNode::CreateFrameNode(V2::COLUMN_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
        AceType::MakeRefPtr<LinearLayoutPattern>(true));
    auto pickerStack = CreateStackNode();
    auto dateNode = CreateAndMountDateNode(settingData, pickerStack);
    auto pickerPattern = dateNode->GetPattern<DatePickerPattern>();
    CHECK_NULL_RETURN(pickerPattern, nullptr);
    pickerPattern->SetIsShowInDialog(true);
    auto buttonTitleNode = CreateAndMountButtonTitleNode(dateNode, contentColumn);
    CHECK_NULL_RETURN(buttonTitleNode, nullptr);

    std::function<void(bool)> lunarChangeEvent = CreateLunarChangeEvent(dateNode);
    RefPtr<FrameNode> acceptNode = dateNode;
    if (settingData.showTime) {
        switchFlag_ = false;
        auto pickerRow = FrameNode::CreateFrameNode(V2::ROW_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
            AceType::MakeRefPtr<LinearLayoutPattern>(false));
        CHECK_NULL_RETURN(pickerRow, nullptr);

        auto monthDaysNode = CreateAndMountMonthDaysNode(settingData, dateNode, pickerRow, std::move(lunarChangeEvent));
        CHECK_NULL_RETURN(monthDaysNode, nullptr);
        auto timeNode = CreateAndMountTimeNode(settingData, monthDaysNode, pickerRow);
        CHECK_NULL_RETURN(timeNode, nullptr);

        pickerRow->MountToParent(pickerStack);

        CreateTitleIconNode(buttonTitleNode);
        SetTitleMouseHoverEvent(buttonTitleNode);
        buttonTitleNode->MarkModifyDone();
        auto titleSwitchEvent = CreateAndSetDialogSwitchEvent(pickerStack, contentColumn);
        CreateAndAddTitleClickEvent(titleSwitchEvent, buttonTitleNode);
        acceptNode = monthDaysNode;
    }
    dateNode->MarkModifyDone();

    ViewStackProcessor::GetInstance()->Finish();
    auto stackLayoutProperty = pickerStack->GetLayoutProperty();
    CHECK_NULL_RETURN(stackLayoutProperty, nullptr);
    stackLayoutProperty->UpdateUserDefinedIdealSize(
        CalcSize(NG::CalcLength(Dimension(1, DimensionUnit::PERCENT)), std::nullopt));
    UpdateContentPadding(pickerStack);
    pickerStack->MountToParent(contentColumn);
    // build lunarswitch Node
    if (settingData.lunarswitch) {
        CreateLunarswitchNode(contentColumn, dateNode, std::move(lunarChangeEvent), settingData.isLunar);
    }
    auto dialogNode = DialogView::CreateDialogNode(dialogProperties, contentColumn);
    CHECK_NULL_RETURN(dialogNode, nullptr);

    // build dialog accept and cancel button
    BuildDialogAcceptAndCancelButton(
        buttonInfos, settingData, acceptNode, dateNode, dialogNode, contentColumn, dialogEvent, dialogCancelEvent);
    dialogNode->MarkDirtyNode(PROPERTY_UPDATE_MEASURE_SELF);
    return dialogNode;
}

void DatePickerDialogView::SetTimeNodeColumnWeight(
    const RefPtr<FrameNode>& timeNode, const DatePickerSettingData& settingData)
{
    auto timeLayoutProperty = timeNode->GetLayoutProperty();
    CHECK_NULL_VOID(timeLayoutProperty);
    if (Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)) {
        timeLayoutProperty->UpdateLayoutWeight(settingData.useMilitary ? RATIO_FOUR : RATIO_SEVEN);
        for (const auto& child : timeNode->GetChildren()) {
            auto frameNodeChild = AceType::DynamicCast<NG::FrameNode>(child);
            auto timeColumnLayoutProperty = frameNodeChild->GetLayoutProperty();
            timeColumnLayoutProperty->UpdateLayoutWeight(RATIO_TWO);
        }
        if (!settingData.useMilitary) {
            auto child = timeNode->GetFirstChild();
            auto frameNodeChild = AceType::DynamicCast<NG::FrameNode>(child);
            auto timeColumnLayoutProperty = frameNodeChild->GetLayoutProperty();
            timeColumnLayoutProperty->UpdateLayoutWeight(RATIO_THREE);
        }
    } else {
        timeLayoutProperty->UpdateUserDefinedIdealSize(
            CalcSize(NG::CalcLength(Dimension(settingData.useMilitary ? TIME_WIDTH_PERCENT_ONE : TIME_WIDTH_PERCENT_TWO,
                DimensionUnit::PERCENT)),
            std::nullopt));
    }
}

RefPtr<FrameNode> DatePickerDialogView::CreateLunarSwitchTextNode()
{
    auto pipeline = PipelineBase::GetCurrentContext();
    CHECK_NULL_RETURN(pipeline, nullptr);
    auto pickerTheme = pipeline->GetTheme<PickerTheme>();
    CHECK_NULL_RETURN(pickerTheme, nullptr);

    auto textNode = FrameNode::CreateFrameNode(
        V2::TEXT_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<TextPattern>());
    CHECK_NULL_RETURN(textNode, nullptr);
    auto textLayoutProperty = textNode->GetLayoutProperty<TextLayoutProperty>();
    CHECK_NULL_RETURN(textLayoutProperty, nullptr);
    textLayoutProperty->UpdateContent(Localization::GetInstance()->GetEntryLetters("datepicker.lunarSwitch"));
    textLayoutProperty->UpdateFontSize(pickerTheme->GetLunarSwitchTextSize());
    textLayoutProperty->UpdateTextColor(pickerTheme->GetLunarSwitchTextColor());
    textNode->MarkModifyDone();
    return textNode;
}

RefPtr<FrameNode> DatePickerDialogView::CreateStackNode()
{
    auto stackId = ElementRegister::GetInstance()->MakeUniqueId();
    return FrameNode::GetOrCreateFrameNode(
        V2::STACK_ETS_TAG, stackId, []() { return AceType::MakeRefPtr<StackPattern>(); });
}

RefPtr<FrameNode> DatePickerDialogView::CreateColumnNode()
{
    auto columnId = ElementRegister::GetInstance()->MakeUniqueId();
    return FrameNode::GetOrCreateFrameNode(
        V2::COLUMN_ETS_TAG, columnId, []() { return AceType::MakeRefPtr<LinearLayoutPattern>(true); });
}

RefPtr<FrameNode> DatePickerDialogView::CreateButtonNode()
{
    auto buttonId = ElementRegister::GetInstance()->MakeUniqueId();
    return FrameNode::GetOrCreateFrameNode(
        V2::BUTTON_ETS_TAG, buttonId, []() { return AceType::MakeRefPtr<ButtonPattern>(); });
}

RefPtr<FrameNode> DatePickerDialogView::CreateTitleButtonNode(const RefPtr<FrameNode>& dateNode)
{
    auto pipeline = PipelineContext::GetCurrentContext();
    CHECK_NULL_RETURN(pipeline, nullptr);
    auto dialogTheme = pipeline->GetTheme<DialogTheme>();
    auto pickerTheme = pipeline->GetTheme<PickerTheme>();
    auto pickerPattern = dateNode->GetPattern<DatePickerPattern>();
    CHECK_NULL_RETURN(pickerPattern, nullptr);
    auto titleRow = FrameNode::CreateFrameNode(V2::COLUMN_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
        AceType::MakeRefPtr<LinearLayoutPattern>(false));
    CHECK_NULL_RETURN(titleRow, nullptr);
    UpdateTitleRowLayoutProps(titleRow);

    auto buttonTitleNode = FrameNode::GetOrCreateFrameNode(
        V2::BUTTON_ETS_TAG, pickerPattern->GetButtonTitleId(), []() { return AceType::MakeRefPtr<ButtonPattern>(); });
    CHECK_NULL_RETURN(buttonTitleNode, nullptr);
    auto titleButtonRow = CreateTitleButtonRowNode();
    CHECK_NULL_RETURN(titleButtonRow, nullptr);
    auto textTitleNodeId = pickerPattern->GetTitleId();
    auto textTitleNode =
        FrameNode::CreateFrameNode(V2::TEXT_ETS_TAG, textTitleNodeId, AceType::MakeRefPtr<TextPattern>());
    CHECK_NULL_RETURN(textTitleNode, nullptr);
    auto textLayoutProperty = textTitleNode->GetLayoutProperty<TextLayoutProperty>();
    CHECK_NULL_RETURN(textLayoutProperty, nullptr);
    textLayoutProperty->UpdateContent("");
    textLayoutProperty->UpdateMeasureType(MeasureType::MATCH_PARENT_MAIN_AXIS);

    textLayoutProperty->UpdateTextColor(pickerTheme->GetTitleStyle().GetTextColor());
    textLayoutProperty->UpdateFontSize(pickerTheme->GetTitleStyle().GetFontSize());
    textLayoutProperty->UpdateFontWeight(pickerTheme->GetTitleStyle().GetFontWeight());
    textLayoutProperty->UpdateTextOverflow(pickerTheme->GetTitleStyle().GetTextOverflow());
    textLayoutProperty->UpdateMaxLines(pickerTheme->GetTitleStyle().GetMaxLines());
    auto buttonTitleRenderContext = buttonTitleNode->GetRenderContext();
    CHECK_NULL_RETURN(buttonTitleRenderContext, nullptr);
    buttonTitleRenderContext->UpdateBackgroundColor(Color::TRANSPARENT);
    MarginProperty margin;
    if (Container::LessThanAPITargetVersion(PlatformVersion::VERSION_TWELVE)) {
        margin.left = CalcLength(dialogTheme->GetDividerPadding().Left());
        margin.right = CalcLength(dialogTheme->GetDividerPadding().Right());
        margin.top = CalcLength(dialogTheme->GetDividerHeight() / MARGIN_HALF);
        margin.bottom = CalcLength(dialogTheme->GetDividerHeight() / MARGIN_HALF);
        buttonTitleNode->GetLayoutProperty()->UpdateMargin(margin);
    } else {
        buttonTitleNode->GetLayoutProperty()->UpdateUserDefinedIdealSize(CalcSize(
            CalcLength(Dimension(1.0, DimensionUnit::PERCENT)), CalcLength(TITLE_BUTTON_HEIGHT)));
    }
    textTitleNode->MountToParent(titleButtonRow);
    titleButtonRow->MountToParent(buttonTitleNode);
    buttonTitleNode->MountToParent(titleRow);
    titleRow->SetNeedCallChildrenUpdate(false);
    return titleRow;
}

void DatePickerDialogView::UpdateTitleRowLayoutProps(const RefPtr<FrameNode>& titleRow)
{
    auto layoutProps = titleRow->GetLayoutProperty<LinearLayoutProperty>();
    CHECK_NULL_VOID(layoutProps);
    layoutProps->UpdateMainAxisAlign(FlexAlign::CENTER);
    layoutProps->UpdateCrossAxisAlign(FlexAlign::CENTER);
    layoutProps->UpdateMeasureType(MeasureType::MATCH_PARENT_MAIN_AXIS);
}

RefPtr<FrameNode> DatePickerDialogView::CreateTitleButtonRowNode()
{
    auto titleButtonRow = FrameNode::CreateFrameNode(V2::COLUMN_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
        AceType::MakeRefPtr<LinearLayoutPattern>(false));
    CHECK_NULL_RETURN(titleButtonRow, nullptr);
    auto bottonRowlayoutProps = titleButtonRow->GetLayoutProperty<LinearLayoutProperty>();
    CHECK_NULL_RETURN(bottonRowlayoutProps, nullptr);
    bottonRowlayoutProps->UpdateMainAxisAlign(FlexAlign::CENTER);
    bottonRowlayoutProps->UpdateCrossAxisAlign(FlexAlign::CENTER);
    bottonRowlayoutProps->UpdateMeasureType(MeasureType::MATCH_CONTENT);
    return titleButtonRow;
}

void DatePickerDialogView::CreateTitleIconNode(const RefPtr<FrameNode>& titleNode)
{
    auto pipeline = PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(pipeline);
    auto iconTheme = pipeline->GetTheme<IconTheme>();
    CHECK_NULL_VOID(iconTheme);
    auto pickerTheme = pipeline->GetTheme<PickerTheme>();
    CHECK_NULL_VOID(pickerTheme);
    auto spinnerNode = FrameNode::CreateFrameNode(
        V2::IMAGE_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<ImagePattern>());
    CHECK_NULL_VOID(spinnerNode);
    ImageSourceInfo imageSourceInfo;
    auto iconPath = iconTheme->GetIconPath(InternalResource::ResourceId::SPINNER);
    imageSourceInfo.SetSrc(iconPath);
    imageSourceInfo.SetFillColor(pickerTheme->GetTitleStyle().GetTextColor());

    auto spinnerLayoutProperty = spinnerNode->GetLayoutProperty<ImageLayoutProperty>();
    CHECK_NULL_VOID(spinnerLayoutProperty);
    spinnerLayoutProperty->UpdateImageSourceInfo(imageSourceInfo);
    CalcSize idealSize = { CalcLength(pickerTheme->GetTitleStyle().GetFontSize()),
        CalcLength(pickerTheme->GetTitleStyle().GetFontSize()) };
    MeasureProperty layoutConstraint;
    layoutConstraint.selfIdealSize = idealSize;
    spinnerLayoutProperty->UpdateCalcLayoutProperty(layoutConstraint);
    spinnerNode->MarkModifyDone();
    auto buttonNode = AceType::DynamicCast<FrameNode>(titleNode->GetFirstChild());
    CHECK_NULL_VOID(buttonNode);
    auto buttonRowNode = AceType::DynamicCast<FrameNode>(buttonNode->GetFirstChild());
    CHECK_NULL_VOID(buttonRowNode);
    spinnerNode->MountToParent(buttonRowNode);
}

RefPtr<FrameNode> DatePickerDialogView::CreateDividerNode(const RefPtr<FrameNode>& dateNode)
{
    auto pipeline = PipelineContext::GetCurrentContext();
    CHECK_NULL_RETURN(pipeline, nullptr);
    auto dialogTheme = pipeline->GetTheme<DialogTheme>();
    auto pickerPattern = dateNode->GetPattern<DatePickerPattern>();
    CHECK_NULL_RETURN(pickerPattern, nullptr);
    auto dividerNode = FrameNode::GetOrCreateFrameNode(
        V2::DIVIDER_ETS_TAG, pickerPattern->GetDividerId(), []() { return AceType::MakeRefPtr<DividerPattern>(); });
    CHECK_NULL_RETURN(dividerNode, nullptr);

    auto dividerPaintProps = dividerNode->GetPaintProperty<DividerRenderProperty>();
    CHECK_NULL_RETURN(dividerPaintProps, nullptr);
    dividerPaintProps->UpdateDividerColor(dialogTheme->GetDividerColor());

    auto dividerLayoutProps = dividerNode->GetLayoutProperty<DividerLayoutProperty>();
    CHECK_NULL_RETURN(dividerLayoutProps, nullptr);
    dividerLayoutProps->UpdateVertical(true);
    dividerLayoutProps->UpdateUserDefinedIdealSize(
        CalcSize(CalcLength(dialogTheme->GetDividerWidth()), CalcLength(dialogTheme->GetDividerHeight())));

    return dividerNode;
}

RefPtr<FrameNode> DatePickerDialogView::CreateButtonNode(const RefPtr<FrameNode>& dateNode,
    const RefPtr<FrameNode>& datePickerNode, const std::vector<ButtonInfo>& buttonInfos,
    std::map<std::string, NG::DialogEvent> dialogEvent, std::map<std::string, NG::DialogGestureEvent> dialogCancelEvent)
{
    auto acceptEvent = dialogEvent["acceptId"];
    auto dateAcceptEvent = dialogEvent["dateAcceptId"];
    auto cancelEvent = dialogCancelEvent["cancelId"];
    auto contentRow = FrameNode::CreateFrameNode(V2::COLUMN_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
        AceType::MakeRefPtr<LinearLayoutPattern>(false));
    CHECK_NULL_RETURN(contentRow, nullptr);
    auto layoutProps = contentRow->GetLayoutProperty<LinearLayoutProperty>();
    CHECK_NULL_RETURN(layoutProps, nullptr);
    layoutProps->UpdateMainAxisAlign(FlexAlign::SPACE_AROUND);
    layoutProps->UpdateMeasureType(MeasureType::MATCH_PARENT_MAIN_AXIS);
    if (Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)) {
        MarginProperty margin;
        margin.top = CalcLength(PICKER_MARGIN_FROM_TITLE_AND_BUTTON);
        layoutProps->UpdateMargin(margin);
    }

    contentRow->SetNeedCallChildrenUpdate(false);
    SetDialogDateAcceptEvent(dateNode, std::move(dateAcceptEvent));

    auto buttonCancelNode = CreateCancelNode(cancelEvent, datePickerNode, buttonInfos);
    auto buttonConfirmNode = CreateConfirmNode(dateNode, datePickerNode, acceptEvent, buttonInfos);

    buttonCancelNode->MountToParent(contentRow);
    buttonConfirmNode->MountToParent(contentRow);

    auto datePickerPattern = dateNode->GetPattern<DatePickerPattern>();
    datePickerPattern->SetContentRowNode(contentRow);

    return contentRow;
}

RefPtr<FrameNode> DatePickerDialogView::CreateConfirmNode(const RefPtr<FrameNode>& dateNode,
    const RefPtr<FrameNode>& datePickerNode, DialogEvent& acceptEvent, const std::vector<ButtonInfo>& buttonInfos)
{
    auto pipeline = PipelineContext::GetCurrentContext();
    CHECK_NULL_RETURN(pipeline, nullptr);
    auto dialogTheme = pipeline->GetTheme<DialogTheme>();
    auto pickerTheme = pipeline->GetTheme<PickerTheme>();

    auto buttonConfirmNode = FrameNode::GetOrCreateFrameNode(V2::BUTTON_ETS_TAG,
        ElementRegister::GetInstance()->MakeUniqueId(), []() { return AceType::MakeRefPtr<ButtonPattern>(); });
    auto textConfirmNode = FrameNode::CreateFrameNode(
        V2::TEXT_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<TextPattern>());
    CHECK_NULL_RETURN(buttonConfirmNode, nullptr);
    CHECK_NULL_RETURN(textConfirmNode, nullptr);
    auto textLayoutProperty = textConfirmNode->GetLayoutProperty<TextLayoutProperty>();
    CHECK_NULL_RETURN(textLayoutProperty, nullptr);
    UpdateConfirmButtonTextLayoutProperty(textLayoutProperty, pickerTheme);
    auto datePickerPattern = datePickerNode->GetPattern<DatePickerPattern>();
    datePickerPattern->SetConfirmNode(buttonConfirmNode);
    auto buttonConfirmEventHub = buttonConfirmNode->GetEventHub<ButtonEventHub>();
    CHECK_NULL_RETURN(buttonConfirmEventHub, nullptr);
    buttonConfirmEventHub->SetStateEffect(true);

    auto buttonConfirmLayoutProperty = buttonConfirmNode->GetLayoutProperty<ButtonLayoutProperty>();
    CHECK_NULL_RETURN(buttonConfirmLayoutProperty, nullptr);
    UpdateButtonLayoutProperty(buttonConfirmLayoutProperty, pickerTheme);
    auto buttonConfirmRenderContext = buttonConfirmNode->GetRenderContext();
    buttonConfirmRenderContext->UpdateBackgroundColor(Color::TRANSPARENT);
    UpdateButtonStyles(buttonInfos, ACCEPT_BUTTON_INDEX, buttonConfirmLayoutProperty, buttonConfirmRenderContext);
    UpdateButtonDefaultFocus(buttonInfos, buttonConfirmNode, true);

    UpdateConfirmButtonMargin(buttonConfirmNode, dialogTheme);
    textConfirmNode->MountToParent(buttonConfirmNode);
    auto eventConfirmHub = buttonConfirmNode->GetOrCreateGestureEventHub();
    CHECK_NULL_RETURN(eventConfirmHub, nullptr);
    CHECK_NULL_RETURN(dateNode, nullptr);
    SetDialogAcceptEvent(dateNode, std::move(acceptEvent));
    auto clickCallback = [weak = WeakPtr<FrameNode>(dateNode)](const GestureEvent& /* info */) {
        auto dateNode = weak.Upgrade();
        CHECK_NULL_VOID(dateNode);
        auto pickerPattern = dateNode->GetPattern<DatePickerPattern>();
        CHECK_NULL_VOID(pickerPattern);
        auto datePickerEventHub = pickerPattern->GetEventHub<DatePickerEventHub>();
        CHECK_NULL_VOID(datePickerEventHub);
        datePickerEventHub->FireDialogAcceptEvent(pickerPattern->GetSelectedObject(true));
    };
    eventConfirmHub->AddClickEvent(AceType::MakeRefPtr<NG::ClickEvent>(clickCallback));
    buttonConfirmNode->MarkModifyDone();
    return buttonConfirmNode;
}

void DatePickerDialogView::UpdateConfirmButtonTextLayoutProperty(
    const RefPtr<TextLayoutProperty>& textLayoutProperty, const RefPtr<PickerTheme>& pickerTheme)
{
    CHECK_NULL_VOID(textLayoutProperty);
    textLayoutProperty->UpdateContent(Localization::GetInstance()->GetEntryLetters("common.ok"));
    textLayoutProperty->UpdateTextColor(pickerTheme->GetOptionStyle(true, false).GetTextColor());
    textLayoutProperty->UpdateFontSize(pickerTheme->GetOptionStyle(false, false).GetFontSize());
    textLayoutProperty->UpdateFontWeight(pickerTheme->GetOptionStyle(true, false).GetFontWeight());
}

void DatePickerDialogView::UpdateButtonLayoutProperty(
    const RefPtr<ButtonLayoutProperty>& buttonConfirmLayoutProperty, const RefPtr<PickerTheme>& pickerTheme)
{
    CHECK_NULL_VOID(buttonConfirmLayoutProperty);
    buttonConfirmLayoutProperty->UpdateLabel(Localization::GetInstance()->GetEntryLetters("common.ok"));
    buttonConfirmLayoutProperty->UpdateMeasureType(MeasureType::MATCH_PARENT_MAIN_AXIS);
    buttonConfirmLayoutProperty->UpdateType(ButtonType::CAPSULE);
    buttonConfirmLayoutProperty->UpdateFlexShrink(1.0);
    buttonConfirmLayoutProperty->UpdateUserDefinedIdealSize(
        CalcSize(CalcLength(pickerTheme->GetButtonWidth()), CalcLength(pickerTheme->GetButtonHeight())));
}

void DatePickerDialogView::UpdateConfirmButtonMargin(
    const RefPtr<FrameNode>& buttonConfirmNode, const RefPtr<DialogTheme>& dialogTheme)
{
    MarginProperty margin;
    margin.right = CalcLength(dialogTheme->GetDividerPadding().Right());
    margin.top = CalcLength(BUTTON_BOTTOM_TOP_MARGIN);
    margin.bottom = CalcLength(BUTTON_BOTTOM_TOP_MARGIN);
    buttonConfirmNode->GetLayoutProperty()->UpdateMargin(margin);
}

void DatePickerDialogView::UpdateButtonStyles(const std::vector<ButtonInfo>& buttonInfos, size_t index,
    const RefPtr<ButtonLayoutProperty>& buttonLayoutProperty, const RefPtr<RenderContext>& buttonRenderContext)
{
    if (index >= buttonInfos.size()) {
        return;
    }
    CHECK_NULL_VOID(buttonLayoutProperty);
    CHECK_NULL_VOID(buttonRenderContext);
    auto buttonTheme = PipelineBase::GetCurrentContext()->GetTheme<ButtonTheme>();
    CHECK_NULL_VOID(buttonTheme);
    if (buttonInfos[index].type.has_value()) {
        buttonLayoutProperty->UpdateType(buttonInfos[index].type.value());
    }
    UpdateButtonStyleAndRole(buttonInfos, index, buttonLayoutProperty, buttonRenderContext, buttonTheme);
    if (buttonInfos[index].fontSize.has_value()) {
        buttonLayoutProperty->UpdateFontSize(buttonInfos[index].fontSize.value());
    }
    if (buttonInfos[index].fontColor.has_value()) {
        buttonLayoutProperty->UpdateFontColor(buttonInfos[index].fontColor.value());
    }
    if (buttonInfos[index].fontWeight.has_value()) {
        buttonLayoutProperty->UpdateFontWeight(buttonInfos[index].fontWeight.value());
    }
    if (buttonInfos[index].fontStyle.has_value()) {
        buttonLayoutProperty->UpdateFontStyle(buttonInfos[index].fontStyle.value());
    }
    if (buttonInfos[index].fontFamily.has_value()) {
        buttonLayoutProperty->UpdateFontFamily(buttonInfos[index].fontFamily.value());
    }
    if (buttonInfos[index].borderRadius.has_value()) {
        buttonLayoutProperty->UpdateBorderRadius(buttonInfos[index].borderRadius.value());
    }
    if (buttonInfos[index].backgroundColor.has_value()) {
        buttonRenderContext->UpdateBackgroundColor(buttonInfos[index].backgroundColor.value());
    }
}

void DatePickerDialogView::UpdateButtonStyleAndRole(const std::vector<ButtonInfo>& buttonInfos, size_t index,
    const RefPtr<ButtonLayoutProperty>& buttonLayoutProperty, const RefPtr<RenderContext>& buttonRenderContext,
    const RefPtr<ButtonTheme>& buttonTheme)
{
    if (index >= buttonInfos.size()) {
        return;
    }
    CHECK_NULL_VOID(buttonLayoutProperty);
    CHECK_NULL_VOID(buttonRenderContext);
    CHECK_NULL_VOID(buttonTheme);
    if (buttonInfos[index].role.has_value()) {
        buttonLayoutProperty->UpdateButtonRole(buttonInfos[index].role.value());
        ButtonStyleMode buttonStyleMode;
        if (buttonInfos[index].buttonStyle.has_value()) {
            buttonStyleMode = buttonInfos[index].buttonStyle.value();
        } else {
            buttonStyleMode = buttonLayoutProperty->GetButtonStyle().value_or(ButtonStyleMode::EMPHASIZE);
        }
        auto bgColor = buttonTheme->GetBgColor(buttonStyleMode, buttonInfos[index].role.value());
        auto textColor = buttonTheme->GetTextColor(buttonStyleMode, buttonInfos[index].role.value());
        buttonRenderContext->UpdateBackgroundColor(bgColor);
        buttonLayoutProperty->UpdateFontColor(textColor);
    }
    if (buttonInfos[index].buttonStyle.has_value()) {
        buttonLayoutProperty->UpdateButtonStyle(buttonInfos[index].buttonStyle.value());
        ButtonRole buttonRole = buttonLayoutProperty->GetButtonRole().value_or(ButtonRole::NORMAL);
        auto bgColor = buttonTheme->GetBgColor(buttonInfos[index].buttonStyle.value(), buttonRole);
        auto textColor = buttonTheme->GetTextColor(buttonInfos[index].buttonStyle.value(), buttonRole);
        buttonRenderContext->UpdateBackgroundColor(bgColor);
        buttonLayoutProperty->UpdateFontColor(textColor);
    }
}

RefPtr<FrameNode> DatePickerDialogView::CreateDateNode(int32_t dateNodeId,
    std::map<std::string, PickerDate> datePickerProperty, const PickerTextProperties& properties, bool isLunar,
    bool showTime)
{
    ACE_LAYOUT_SCOPED_TRACE("Create[%s][self:%d]", V2::DATE_PICKER_ETS_TAG, dateNodeId);
    auto dateNode = FrameNode::GetOrCreateFrameNode(
        V2::DATE_PICKER_ETS_TAG, dateNodeId, []() { return AceType::MakeRefPtr<DatePickerPattern>(); });
    CHECK_NULL_RETURN(dateNode, nullptr);
    auto datePickerPattern = dateNode->GetPattern<DatePickerPattern>();
    CHECK_NULL_RETURN(datePickerPattern, nullptr);

    auto pipeline = PipelineBase::GetCurrentContext();
    CHECK_NULL_RETURN(pipeline, nullptr);
    auto dialogTheme = pipeline->GetTheme<DialogTheme>();
    CHECK_NULL_RETURN(dialogTheme, nullptr);
    datePickerPattern->SetBackgroundColor(dialogTheme->GetBackgroundColor());
    auto pickerTheme = pipeline->GetTheme<PickerTheme>();
    CHECK_NULL_RETURN(pickerTheme, nullptr);
    uint32_t showCount = pickerTheme->GetShowOptionCount() + BUFFER_NODE_NUMBER;
    datePickerPattern->SetShowCount(showCount);

    if (showTime) {
        CreateSingleDateNode(dateNode, showCount);
    } else {
        CreateNormalDateNode(dateNode, showCount);
    }

    PickerDate parseStartDate;
    PickerDate parseEndDate;
    PickerDate parseSelectedDate;
    SetShowLunar(dateNode, isLunar);
    SetDateTextProperties(dateNode, properties);
    auto iterStart = datePickerProperty.find("start");
    if (iterStart != datePickerProperty.end()) {
        parseStartDate = iterStart->second;
        SetStartDate(dateNode, parseStartDate);
    }
    auto iterEnd = datePickerProperty.find("end");
    if (iterEnd != datePickerProperty.end()) {
        parseEndDate = iterEnd->second;
        SetEndDate(dateNode, parseEndDate);
    }
    auto iterSelected = datePickerProperty.find("selected");
    if (iterSelected != datePickerProperty.end()) {
        parseSelectedDate = iterSelected->second;
        SetSelectedDate(dateNode, parseSelectedDate);
    }
    return dateNode;
}

RefPtr<FrameNode> DatePickerDialogView::CreateColumnNode(int32_t nodeId, uint32_t showCount, bool isDate)
{
    RefPtr<FrameNode> columnNode;
    if (isDate) {
        columnNode = FrameNode::GetOrCreateFrameNode(
            V2::COLUMN_ETS_TAG, nodeId, []() { return AceType::MakeRefPtr<DatePickerColumnPattern>(); });
    } else {
        columnNode = FrameNode::GetOrCreateFrameNode(
            V2::COLUMN_ETS_TAG, nodeId, []() { return AceType::MakeRefPtr<TimePickerColumnPattern>(); });
    }
    CHECK_NULL_RETURN(columnNode, nullptr);
    columnNode->Clean();
    for (uint32_t index = 0; index < showCount; index++) {
        auto textNode = FrameNode::CreateFrameNode(
            V2::TEXT_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<TextPattern>());
        CHECK_NULL_RETURN(textNode, nullptr);
        textNode->MountToParent(columnNode);
    }
    columnNode->MarkModifyDone();
    return columnNode;
}

void DatePickerDialogView::CreateNormalDateNode(const RefPtr<FrameNode>& dateNode, uint32_t showCount)
{
    auto datePickerPattern = dateNode->GetPattern<DatePickerPattern>();
    CHECK_NULL_VOID(datePickerPattern);
    datePickerPattern->SetShowMonthDaysFlag(false);

    auto yearColumnNode = CreateColumnNode(datePickerPattern->GetYearId(), showCount);
    auto monthColumnNode = CreateColumnNode(datePickerPattern->GetMonthId(), showCount);
    auto dayColumnNode = CreateColumnNode(datePickerPattern->GetDayId(), showCount);
    CHECK_NULL_VOID(yearColumnNode);
    CHECK_NULL_VOID(monthColumnNode);
    CHECK_NULL_VOID(dayColumnNode);
    datePickerPattern->SetColumn(yearColumnNode);
    datePickerPattern->SetColumn(monthColumnNode);
    datePickerPattern->SetColumn(dayColumnNode);

    if (Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)) {
        MountColumnNodeToPicker(yearColumnNode, dateNode, RATIO_THREE);
        MountColumnNodeToPicker(monthColumnNode, dateNode, RATIO_TWO);
        MountColumnNodeToPicker(dayColumnNode, dateNode, RATIO_TWO);
    } else {
        MountColumnNodeToPicker(yearColumnNode, dateNode);
        MountColumnNodeToPicker(monthColumnNode, dateNode);
        MountColumnNodeToPicker(dayColumnNode, dateNode);
    }
}

void DatePickerDialogView::CreateSingleDateNode(const RefPtr<FrameNode>& dateNode, uint32_t showCount)
{
    auto datePickerPattern = dateNode->GetPattern<DatePickerPattern>();
    CHECK_NULL_VOID(datePickerPattern);
    datePickerPattern->SetShowMonthDaysFlag(true);

    auto monthDaysColumnNode = CreateColumnNode(datePickerPattern->GetMonthDaysId(), showCount);
    auto yearColumnNode = CreateColumnNode(datePickerPattern->GetYearId(), showCount);
    CHECK_NULL_VOID(monthDaysColumnNode);
    CHECK_NULL_VOID(yearColumnNode);
    datePickerPattern->SetColumn(monthDaysColumnNode);
    datePickerPattern->SetColumn(yearColumnNode);

    if (Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)) {
        MountColumnNodeToPicker(monthDaysColumnNode, dateNode, RATIO_FOUR);
    } else {
        MountColumnNodeToPicker(monthDaysColumnNode, dateNode);
    }

    {
        auto stackYearNode = CreateStackNode();
        auto blendYearNode = CreateColumnNode();
        auto buttonYearNode = CreateButtonNode();
        buttonYearNode->MountToParent(stackYearNode);
        yearColumnNode->MountToParent(blendYearNode);
        blendYearNode->MountToParent(stackYearNode);
        auto layoutProperty = stackYearNode->GetLayoutProperty<LayoutProperty>();
        layoutProperty->UpdateAlignment(Alignment::CENTER);
        layoutProperty->UpdateVisibility(VisibleType::GONE);
        stackYearNode->MountToParent(dateNode);
        yearColumnNode->GetLayoutProperty<LayoutProperty>()->UpdatePixelRound(PIXEL_ROUND);
    }
}

RefPtr<FrameNode> DatePickerDialogView::CreateTimeNode(
    std::map<std::string, PickerTime> timePickerProperty, const PickerTextProperties& properties, bool useMilitaryTime)
{
    auto nodeId = ElementRegister::GetInstance()->MakeUniqueId();
    ACE_LAYOUT_SCOPED_TRACE("Create[%s][self:%d]", V2::TIME_PICKER_ETS_TAG, nodeId);
    auto timePickerNode = FrameNode::GetOrCreateFrameNode(
        V2::TIME_PICKER_ETS_TAG, nodeId, []() { return AceType::MakeRefPtr<TimePickerRowPattern>(); });
    CHECK_NULL_RETURN(timePickerNode, nullptr);
    auto timePickerRowPattern = timePickerNode->GetPattern<TimePickerRowPattern>();
    CHECK_NULL_RETURN(timePickerRowPattern, nullptr);

    auto pipeline = PipelineBase::GetCurrentContext();
    CHECK_NULL_RETURN(pipeline, nullptr);
    auto pickerTheme = pipeline->GetTheme<PickerTheme>();
    CHECK_NULL_RETURN(pickerTheme, nullptr);
    uint32_t showCount = pickerTheme->GetShowOptionCount() + BUFFER_NODE_NUMBER;
    timePickerRowPattern->SetShowCount(showCount);

    auto hasHourNode = timePickerRowPattern->HasHourNode();
    auto hasMinuteNode = timePickerRowPattern->HasMinuteNode();

    auto hourColumnNode = CreateColumnNode(timePickerRowPattern->GetHourId(), showCount, false);
    auto minuteColumnNode = CreateColumnNode(timePickerRowPattern->GetMinuteId(), showCount, false);
    CHECK_NULL_RETURN(hourColumnNode, nullptr);
    CHECK_NULL_RETURN(minuteColumnNode, nullptr);
    timePickerRowPattern->SetColumn(hourColumnNode);
    timePickerRowPattern->SetColumn(minuteColumnNode);

    if (!hasHourNode) {
        MountColumnNodeToPicker(hourColumnNode, timePickerNode);
    }
    if (!hasMinuteNode) {
        MountColumnNodeToPicker(minuteColumnNode, timePickerNode);
    }
    auto it = timePickerProperty.find("selected");
    if (it != timePickerProperty.end()) {
        auto selectedTime = it->second;
        timePickerRowPattern->SetSelectedTime(selectedTime);
    }
    timePickerRowPattern->SetHour24(useMilitaryTime);

    SetTimeTextProperties(timePickerNode, properties);
    return timePickerNode;
}

void DatePickerDialogView::MountColumnNodeToPicker(
    const RefPtr<FrameNode>& columnNode, const RefPtr<FrameNode>& pickerNode, uint32_t columnWeight)
{
    auto stackNode = CreateStackNode();
    auto blendNode = CreateColumnNode();
    auto buttonNode = CreateButtonNode();
    buttonNode->MountToParent(stackNode);
    columnNode->MountToParent(blendNode);
    blendNode->MountToParent(stackNode);
    auto layoutProperty = stackNode->GetLayoutProperty<LayoutProperty>();
    layoutProperty->UpdateAlignment(Alignment::CENTER);
    layoutProperty->UpdateLayoutWeight(columnWeight);
    stackNode->MountToParent(pickerNode);
    columnNode->GetLayoutProperty<LayoutProperty>()->UpdatePixelRound(PIXEL_ROUND);
}

RefPtr<FrameNode> DatePickerDialogView::CreateCancelNode(NG::DialogGestureEvent& cancelEvent,
    const RefPtr<FrameNode>& datePickerNode, const std::vector<ButtonInfo>& buttonInfos)
{
    auto pipeline = PipelineContext::GetCurrentContext();
    CHECK_NULL_RETURN(pipeline, nullptr);
    auto dialogTheme = pipeline->GetTheme<DialogTheme>();
    auto pickerTheme = pipeline->GetTheme<PickerTheme>();
    auto buttonCancelNode = FrameNode::GetOrCreateFrameNode(V2::BUTTON_ETS_TAG,
        ElementRegister::GetInstance()->MakeUniqueId(), []() { return AceType::MakeRefPtr<ButtonPattern>(); });
    CHECK_NULL_RETURN(buttonCancelNode, nullptr);
    auto textCancelNode = FrameNode::CreateFrameNode(
        V2::TEXT_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<TextPattern>());
    CHECK_NULL_RETURN(textCancelNode, nullptr);
    auto textCancelLayoutProperty = textCancelNode->GetLayoutProperty<TextLayoutProperty>();
    CHECK_NULL_RETURN(textCancelLayoutProperty, nullptr);
    textCancelLayoutProperty->UpdateContent(Localization::GetInstance()->GetEntryLetters("common.cancel"));
    textCancelLayoutProperty->UpdateTextColor(pickerTheme->GetOptionStyle(true, false).GetTextColor());
    textCancelLayoutProperty->UpdateFontSize(pickerTheme->GetOptionStyle(false, false).GetFontSize());
    textCancelLayoutProperty->UpdateFontWeight(pickerTheme->GetOptionStyle(true, false).GetFontWeight());
    auto datePickerPattern = datePickerNode->GetPattern<DatePickerPattern>();
    datePickerPattern->SetCancelNode(buttonCancelNode);
    textCancelNode->MountToParent(buttonCancelNode);
    auto eventCancelHub = buttonCancelNode->GetOrCreateGestureEventHub();
    CHECK_NULL_RETURN(eventCancelHub, nullptr);
    eventCancelHub->AddClickEvent(AceType::MakeRefPtr<NG::ClickEvent>(std::move(cancelEvent)));

    auto buttonCancelEventHub = buttonCancelNode->GetEventHub<ButtonEventHub>();
    CHECK_NULL_RETURN(buttonCancelEventHub, nullptr);
    buttonCancelEventHub->SetStateEffect(true);

    MarginProperty margin;
    margin.left = CalcLength(dialogTheme->GetDividerPadding().Left());
    margin.top = CalcLength(BUTTON_BOTTOM_TOP_MARGIN);
    margin.bottom = CalcLength(BUTTON_BOTTOM_TOP_MARGIN);
    buttonCancelNode->GetLayoutProperty()->UpdateMargin(margin);

    auto buttonCancelLayoutProperty = buttonCancelNode->GetLayoutProperty<ButtonLayoutProperty>();
    buttonCancelLayoutProperty->UpdateLabel(Localization::GetInstance()->GetEntryLetters("common.cancel"));
    buttonCancelLayoutProperty->UpdateMeasureType(MeasureType::MATCH_PARENT_MAIN_AXIS);
    buttonCancelLayoutProperty->UpdateType(ButtonType::CAPSULE);
    buttonCancelLayoutProperty->UpdateFlexShrink(1.0);
    buttonCancelLayoutProperty->UpdateUserDefinedIdealSize(
        CalcSize(CalcLength(pickerTheme->GetButtonWidth()), CalcLength(pickerTheme->GetButtonHeight())));

    auto buttonCancelRenderContext = buttonCancelNode->GetRenderContext();
    buttonCancelRenderContext->UpdateBackgroundColor(Color::TRANSPARENT);
    UpdateButtonStyles(buttonInfos, CANCEL_BUTTON_INDEX, buttonCancelLayoutProperty, buttonCancelRenderContext);
    UpdateButtonDefaultFocus(buttonInfos, buttonCancelNode, false);
    buttonCancelNode->MarkModifyDone();
    return buttonCancelNode;
}

void DatePickerDialogView::CreateLunarswitchNode(const RefPtr<FrameNode>& contentColumn,
    const RefPtr<FrameNode>& dateNode, std::function<void(const bool)>&& changeEvent, bool isLunar)
{
    auto pipeline = PipelineBase::GetCurrentContext();
    CHECK_NULL_VOID(pipeline);
    auto pickerTheme = pipeline->GetTheme<PickerTheme>();
    CHECK_NULL_VOID(pickerTheme);
    auto contentRow = FrameNode::CreateFrameNode(V2::ROW_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(),
        AceType::MakeRefPtr<LinearLayoutPattern>(false));
    CHECK_NULL_VOID(contentRow);
    auto layoutProps = contentRow->GetLayoutProperty<LinearLayoutProperty>();
    CHECK_NULL_VOID(layoutProps);
    if (Container::LessThanAPITargetVersion(PlatformVersion::VERSION_TWELVE)) {
        MarginProperty margin;
        margin.bottom = CalcLength(PICKER_MARGIN_FROM_TITLE_AND_BUTTON);
        layoutProps->UpdateMargin(margin);
    }
    layoutProps->UpdateUserDefinedIdealSize(
        CalcSize(CalcLength(Dimension(1.0, DimensionUnit::PERCENT)), CalcLength(LUNARSWITCH_HEIGHT)));

    auto checkbox = FrameNode::CreateFrameNode(
        V2::CHECK_BOX_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), AceType::MakeRefPtr<CheckBoxPattern>());
    CHECK_NULL_VOID(checkbox);
    auto eventHub = checkbox->GetEventHub<CheckBoxEventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetOnChange(std::move(changeEvent));
    auto checkboxPaintProps = checkbox->GetPaintProperty<CheckBoxPaintProperty>();
    CHECK_NULL_VOID(checkboxPaintProps);
    checkboxPaintProps->UpdateCheckBoxSelect(isLunar);
    auto checkboxLayoutProps = checkbox->GetLayoutProperty<LayoutProperty>();
    CHECK_NULL_VOID(checkboxLayoutProps);
    MarginProperty marginCheckbox;
    marginCheckbox.left = CalcLength(PICKER_DIALOG_MARGIN_FORM_EDGE);
    marginCheckbox.right = CalcLength(PICKER_MARGIN_FROM_TITLE_AND_BUTTON);
    checkboxLayoutProps->UpdateMargin(marginCheckbox);
    checkboxLayoutProps->UpdateUserDefinedIdealSize(CalcSize(CalcLength(CHECKBOX_SIZE), CalcLength(CHECKBOX_SIZE)));
    checkbox->MarkModifyDone();
    checkbox->MountToParent(contentRow);

    auto textNode = CreateLunarSwitchTextNode();
    CHECK_NULL_VOID(textNode);
    textNode->MountToParent(contentRow);
    auto datePickerPattern = dateNode->GetPattern<DatePickerPattern>();
    CHECK_NULL_VOID(datePickerPattern);
    datePickerPattern->SetLunarSwitchTextNode(textNode);

    contentRow->MountToParent(contentColumn);
}

void DatePickerDialogView::SetStartDate(const RefPtr<FrameNode>& frameNode, const PickerDate& value)
{
    auto datePickerPattern = frameNode->GetPattern<DatePickerPattern>();
    CHECK_NULL_VOID(datePickerPattern);
    datePickerPattern->SetStartDate(value);
    auto pickerProperty = frameNode->GetLayoutProperty<DataPickerRowLayoutProperty>();
    CHECK_NULL_VOID(pickerProperty);
    pickerProperty->UpdateStartDate(datePickerPattern->GetStartDateLunar());
}

void DatePickerDialogView::SetEndDate(const RefPtr<FrameNode>& frameNode, const PickerDate& value)
{
    auto datePickerPattern = frameNode->GetPattern<DatePickerPattern>();
    CHECK_NULL_VOID(datePickerPattern);
    datePickerPattern->SetEndDate(value);
    auto pickerProperty = frameNode->GetLayoutProperty<DataPickerRowLayoutProperty>();
    CHECK_NULL_VOID(pickerProperty);
    pickerProperty->UpdateEndDate(datePickerPattern->GetEndDateLunar());
}

void DatePickerDialogView::SetSelectedDate(const RefPtr<FrameNode>& frameNode, const PickerDate& value)
{
    auto datePickerPattern = frameNode->GetPattern<DatePickerPattern>();
    CHECK_NULL_VOID(datePickerPattern);
    datePickerPattern->SetSelectDate(value);
    auto pickerProperty = frameNode->GetLayoutProperty<DataPickerRowLayoutProperty>();
    CHECK_NULL_VOID(pickerProperty);
    pickerProperty->UpdateSelectedDate(datePickerPattern->GetSelectDate());
}

void DatePickerDialogView::SetShowLunar(const RefPtr<FrameNode>& frameNode, bool lunar)
{
    auto pickerProperty = frameNode->GetLayoutProperty<DataPickerRowLayoutProperty>();
    CHECK_NULL_VOID(pickerProperty);
    pickerProperty->UpdateLunar(lunar);
}

void DatePickerDialogView::SetDialogChange(const RefPtr<FrameNode>& frameNode, DialogEvent&& onChange)
{
    CHECK_NULL_VOID(frameNode);
    auto eventHub = frameNode->GetEventHub<DatePickerEventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetDialogChange(std::move(onChange));
}

void DatePickerDialogView::SetDialogDateChange(const RefPtr<FrameNode>& frameNode, DialogEvent&& onChange)
{
    CHECK_NULL_VOID(frameNode);
    auto eventHub = frameNode->GetEventHub<DatePickerEventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetDialogDateChange(std::move(onChange));
}

void DatePickerDialogView::SetDialogAcceptEvent(const RefPtr<FrameNode>& frameNode, DialogEvent&& onChange)
{
    CHECK_NULL_VOID(frameNode);
    auto eventHub = frameNode->GetEventHub<DatePickerEventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetDialogAcceptEvent(std::move(onChange));
}

void DatePickerDialogView::SetDialogDateAcceptEvent(const RefPtr<FrameNode>& frameNode, DialogEvent&& onChange)
{
    CHECK_NULL_VOID(frameNode);
    auto eventHub = frameNode->GetEventHub<DatePickerEventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetDialogDateAcceptEvent(std::move(onChange));
}

void DatePickerDialogView::SetDialogSwitchEvent(std::function<bool()> switchEvent)
{
    auto pipeline = PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(pipeline);
    auto overlayManger = pipeline->GetOverlayManager();
    CHECK_NULL_VOID(overlayManger);
    overlayManger->SetBackPressEvent(switchEvent);
}

void DatePickerDialogView::SetDateTextProperties(
    const RefPtr<FrameNode>& frameNode, const PickerTextProperties& properties)
{
    auto pipeline = PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(pipeline);
    auto pickerTheme = pipeline->GetTheme<PickerTheme>();
    CHECK_NULL_VOID(pickerTheme);
    auto selectedStyle = pickerTheme->GetOptionStyle(true, false);
    auto disappearStyle = pickerTheme->GetDisappearOptionStyle();
    auto normalStyle = pickerTheme->GetOptionStyle(false, false);
    auto pickerProperty = frameNode->GetLayoutProperty<DataPickerRowLayoutProperty>();
    CHECK_NULL_VOID(pickerProperty);

    if (properties.disappearTextStyle_.fontSize.has_value() && properties.disappearTextStyle_.fontSize->IsValid()) {
        pickerProperty->UpdateDisappearFontSize(properties.disappearTextStyle_.fontSize.value());
    } else {
        pickerProperty->UpdateDisappearFontSize(disappearStyle.GetFontSize());
    }
    pickerProperty->UpdateDisappearColor(
        properties.disappearTextStyle_.textColor.value_or(disappearStyle.GetTextColor()));
    pickerProperty->UpdateDisappearWeight(
        properties.disappearTextStyle_.fontWeight.value_or(disappearStyle.GetFontWeight()));
    pickerProperty->UpdateDisappearFontFamily(
        properties.disappearTextStyle_.fontFamily.value_or(disappearStyle.GetFontFamilies()));
    pickerProperty->UpdateDisappearFontStyle(
        properties.disappearTextStyle_.fontStyle.value_or(disappearStyle.GetFontStyle()));

    if (properties.normalTextStyle_.fontSize.has_value() && properties.normalTextStyle_.fontSize->IsValid()) {
        pickerProperty->UpdateFontSize(properties.normalTextStyle_.fontSize.value());
    } else {
        pickerProperty->UpdateFontSize(normalStyle.GetFontSize());
    }
    pickerProperty->UpdateColor(properties.normalTextStyle_.textColor.value_or(normalStyle.GetTextColor()));
    pickerProperty->UpdateWeight(properties.normalTextStyle_.fontWeight.value_or(normalStyle.GetFontWeight()));
    pickerProperty->UpdateFontFamily(properties.normalTextStyle_.fontFamily.value_or(normalStyle.GetFontFamilies()));
    pickerProperty->UpdateFontStyle(properties.normalTextStyle_.fontStyle.value_or(normalStyle.GetFontStyle()));

    if (properties.selectedTextStyle_.fontSize.has_value() && properties.selectedTextStyle_.fontSize->IsValid()) {
        pickerProperty->UpdateSelectedFontSize(properties.selectedTextStyle_.fontSize.value());
    } else {
        pickerProperty->UpdateSelectedFontSize(selectedStyle.GetFontSize());
    }
    pickerProperty->UpdateSelectedColor(properties.selectedTextStyle_.textColor.value_or(selectedStyle.GetTextColor()));
    pickerProperty->UpdateSelectedWeight(
        properties.selectedTextStyle_.fontWeight.value_or(selectedStyle.GetFontWeight()));
    pickerProperty->UpdateSelectedFontFamily(
        properties.selectedTextStyle_.fontFamily.value_or(selectedStyle.GetFontFamilies()));
    pickerProperty->UpdateSelectedFontStyle(
        properties.selectedTextStyle_.fontStyle.value_or(selectedStyle.GetFontStyle()));
}

void DatePickerDialogView::SetTimeTextProperties(
    const RefPtr<FrameNode>& frameNode, const PickerTextProperties& properties)
{
    auto pipeline = PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(pipeline);
    auto pickerTheme = pipeline->GetTheme<PickerTheme>();
    CHECK_NULL_VOID(pickerTheme);
    auto selectedStyle = pickerTheme->GetOptionStyle(true, false);
    auto disappearStyle = pickerTheme->GetDisappearOptionStyle();
    auto normalStyle = pickerTheme->GetOptionStyle(false, false);
    auto pickerProperty = frameNode->GetLayoutProperty<TimePickerLayoutProperty>();
    CHECK_NULL_VOID(pickerProperty);

    if (properties.disappearTextStyle_.fontSize.has_value() && properties.disappearTextStyle_.fontSize->IsValid()) {
        pickerProperty->UpdateDisappearFontSize(properties.disappearTextStyle_.fontSize.value());
    } else {
        pickerProperty->UpdateDisappearFontSize(disappearStyle.GetFontSize());
    }
    pickerProperty->UpdateDisappearColor(
        properties.disappearTextStyle_.textColor.value_or(disappearStyle.GetTextColor()));
    pickerProperty->UpdateDisappearWeight(
        properties.disappearTextStyle_.fontWeight.value_or(disappearStyle.GetFontWeight()));

    if (properties.normalTextStyle_.fontSize.has_value() && properties.normalTextStyle_.fontSize->IsValid()) {
        pickerProperty->UpdateFontSize(properties.normalTextStyle_.fontSize.value());
    } else {
        pickerProperty->UpdateFontSize(normalStyle.GetFontSize());
    }
    pickerProperty->UpdateColor(properties.normalTextStyle_.textColor.value_or(normalStyle.GetTextColor()));
    pickerProperty->UpdateWeight(properties.normalTextStyle_.fontWeight.value_or(normalStyle.GetFontWeight()));

    if (properties.selectedTextStyle_.fontSize.has_value() && properties.selectedTextStyle_.fontSize->IsValid()) {
        pickerProperty->UpdateSelectedFontSize(properties.selectedTextStyle_.fontSize.value());
    } else {
        pickerProperty->UpdateSelectedFontSize(selectedStyle.GetFontSize());
    }
    pickerProperty->UpdateSelectedColor(properties.selectedTextStyle_.textColor.value_or(selectedStyle.GetTextColor()));
    pickerProperty->UpdateSelectedWeight(
        properties.selectedTextStyle_.fontWeight.value_or(selectedStyle.GetFontWeight()));
}

void DatePickerDialogView::SetTitleMouseHoverEvent(const RefPtr<FrameNode>& titleRow)
{
    auto titleButtonNode = AceType::DynamicCast<FrameNode>(titleRow->GetFirstChild());
    CHECK_NULL_VOID(titleButtonNode);
    auto eventHub = titleButtonNode->GetEventHub<EventHub>();
    CHECK_NULL_VOID(eventHub);
    auto inputHub = eventHub->GetOrCreateInputEventHub();
    auto mouseTask = [weak = WeakPtr<FrameNode>(titleButtonNode)](bool isHover) {
        auto titleButtonNode = weak.Upgrade();
        CHECK_NULL_VOID(titleButtonNode);
        HandleMouseEvent(titleButtonNode, isHover);
    };
    auto mouseEvent = AceType::MakeRefPtr<InputEvent>(std::move(mouseTask));
    CHECK_NULL_VOID(mouseEvent);
    inputHub->AddOnHoverEvent(mouseEvent);
}

void DatePickerDialogView::HandleMouseEvent(const RefPtr<FrameNode>& titleButton, bool isHover)
{
    if (isHover) {
        auto pipeline = PipelineBase::GetCurrentContext();
        CHECK_NULL_VOID(pipeline);
        auto theme = pipeline->GetTheme<PickerTheme>();
        CHECK_NULL_VOID(theme);
        PlayHoverAnimation(titleButton, theme->GetHoverColor());
    } else {
        PlayHoverAnimation(titleButton, Color::TRANSPARENT);
    }
}

void DatePickerDialogView::PlayHoverAnimation(const RefPtr<FrameNode>& titleButton, const Color& color)
{
    AnimationOption option = AnimationOption();
    option.SetDuration(HOVER_ANIMATION_DURATION);
    option.SetCurve(Curves::FRICTION);
    option.SetFillMode(FillMode::FORWARDS);
    AnimationUtils::Animate(option, [weak = WeakPtr<FrameNode>(titleButton), color]() {
        auto titleButton = weak.Upgrade();
        auto buttonTitleNode = AceType::DynamicCast<FrameNode>(titleButton);
        CHECK_NULL_VOID(buttonTitleNode);
        auto buttonTitleRenderContext = buttonTitleNode->GetRenderContext();
        buttonTitleRenderContext->UpdateBackgroundColor(color);
        buttonTitleNode->MarkDirtyNode();
    });
}

RefPtr<FrameNode> DatePickerDialogView::CreateAndMountDateNode(
    const DatePickerSettingData& settingData, const RefPtr<FrameNode>& pickerStack)
{
    auto dateNodeId = ElementRegister::GetInstance()->MakeUniqueId();
    auto dateNode =
        CreateDateNode(dateNodeId, settingData.datePickerProperty, settingData.properties, settingData.isLunar, false);
    ViewStackProcessor::GetInstance()->Push(dateNode);
    dateNode->MountToParent(pickerStack);
    return dateNode;
}

RefPtr<FrameNode> DatePickerDialogView::CreateAndMountButtonTitleNode(
    const RefPtr<FrameNode>& dateNode, const RefPtr<FrameNode>& contentColumn)
{
    // create title node and bind title text id to date picker, then mark picker node modify done
    auto buttonTitleNode = CreateTitleButtonNode(dateNode);
    CHECK_NULL_RETURN(buttonTitleNode, nullptr);

    auto datePickerPattern = dateNode->GetPattern<DatePickerPattern>();
    datePickerPattern->SetbuttonTitleNode(buttonTitleNode);

    if (Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)) {
        auto layoutProps = buttonTitleNode->GetLayoutProperty<LinearLayoutProperty>();
        CHECK_NULL_RETURN(layoutProps, nullptr);
        PaddingProperty padding;
        padding.left = CalcLength(TITLE_PADDING_HORIZONTAL);
        padding.right = CalcLength(TITLE_PADDING_HORIZONTAL);
        layoutProps->UpdatePadding(padding);
        MarginProperty margin;
        margin.top = CalcLength(PICKER_MARGIN_FROM_TITLE_AND_BUTTON);
        margin.bottom = CalcLength(PICKER_MARGIN_FROM_TITLE_AND_BUTTON);
        layoutProps->UpdateMargin(margin);
        layoutProps->UpdateUserDefinedIdealSize(CalcSize(
            CalcLength(Dimension(1.0, DimensionUnit::PERCENT)), CalcLength(TITLE_HEIGHT)));
    }

    buttonTitleNode->MountToParent(contentColumn);
    return buttonTitleNode;
}

std::function<void(bool)> DatePickerDialogView::CreateLunarChangeEvent(const RefPtr<FrameNode>& dateNode)
{
    return [weak = AceType::WeakClaim(AceType::RawPtr(dateNode))](bool selected) {
        auto datePicker = weak.Upgrade();
        CHECK_NULL_VOID(datePicker);
        auto layoutProp = datePicker->GetLayoutProperty<DataPickerRowLayoutProperty>();
        CHECK_NULL_VOID(layoutProp);
        layoutProp->UpdateLunar(selected);
        datePicker->MarkModifyDone();
    };
}

RefPtr<FrameNode> DatePickerDialogView::CreateAndMountMonthDaysNode(const DatePickerSettingData& settingData,
    const RefPtr<FrameNode>& dateNode, const RefPtr<FrameNode>& pickerRow, std::function<void(bool)>&& lunarChangeEvent)
{
    auto layoutProperty = dateNode->GetLayoutProperty<LayoutProperty>();
    CHECK_NULL_RETURN(layoutProperty, nullptr);
    layoutProperty->UpdateVisibility(VisibleType::INVISIBLE);
    auto monthDaysNodeId = ElementRegister::GetInstance()->MakeUniqueId();
    auto monthDaysNode = CreateDateNode(
        monthDaysNodeId, settingData.datePickerProperty, settingData.properties, settingData.isLunar, true);
    lunarChangeEvent = [monthDaysNodeWeak = AceType::WeakClaim(AceType::RawPtr(monthDaysNode)),
                           dateNodeWeak = AceType::WeakClaim(AceType::RawPtr(dateNode))](bool selected) {
        auto monthDaysNode = monthDaysNodeWeak.Upgrade();
        auto dateNode = dateNodeWeak.Upgrade();
        CHECK_NULL_VOID(monthDaysNode);
        CHECK_NULL_VOID(dateNode);
        SetShowLunar(monthDaysNode, selected);
        SetShowLunar(dateNode, selected);
        monthDaysNode->MarkModifyDone();
        dateNode->MarkModifyDone();
    };
    auto monthDaysPickerPattern = monthDaysNode->GetPattern<DatePickerPattern>();
    CHECK_NULL_RETURN(monthDaysPickerPattern, nullptr);
    auto pickerPattern = dateNode->GetPattern<DatePickerPattern>();
    CHECK_NULL_RETURN(pickerPattern, nullptr);
    monthDaysPickerPattern->SetTitleId(pickerPattern->GetTitleId());
    monthDaysPickerPattern->SetShowTimeFlag(true);
    pickerPattern->SetShowTimeFlag(true);
    auto monthDaysLayoutProperty = monthDaysNode->GetLayoutProperty();
    CHECK_NULL_RETURN(monthDaysLayoutProperty, nullptr);
    if (Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)) {
        monthDaysLayoutProperty->UpdateLayoutWeight(settingData.useMilitary ? RATIO_THREE : RATIO_FOUR);
    } else {
        monthDaysLayoutProperty->UpdateUserDefinedIdealSize(
            CalcSize(NG::CalcLength(
                Dimension(settingData.useMilitary ? MONTHDAYS_WIDTH_PERCENT_ONE : MONTHDAYS_WIDTH_PERCENT_TWO,
                DimensionUnit::PERCENT)),
            std::nullopt));
    }
    monthDaysNode->MarkModifyDone();
    monthDaysNode->MountToParent(pickerRow);
    return monthDaysNode;
}

RefPtr<FrameNode> DatePickerDialogView::CreateAndMountTimeNode(const DatePickerSettingData& settingData,
    const RefPtr<FrameNode>& monthDaysNode, const RefPtr<FrameNode>& pickerRow)
{
    auto timeNode = CreateTimeNode(settingData.timePickerProperty, settingData.properties, settingData.useMilitary);
    auto timePickerEventHub = timeNode->GetEventHub<TimePickerEventHub>();
    CHECK_NULL_RETURN(timePickerEventHub, nullptr);
    auto timePickerRowPattern = timeNode->GetPattern<TimePickerRowPattern>();
    CHECK_NULL_RETURN(timePickerRowPattern, nullptr);
    auto timePickerLayout = timeNode->GetLayoutProperty<TimePickerLayoutProperty>();
    if (Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)) {
        ZeroPrefixType hourOptions = settingData.dateTimeOptions.hourType;
        ZeroPrefixType minuteOptions = settingData.dateTimeOptions.minuteType;
        if ((timePickerRowPattern->GetPrefixHour() != hourOptions) ||
            (timePickerRowPattern->GetPrefixMinute() != minuteOptions)) {
            timePickerRowPattern->SetDateTimeOptionUpdate(true);
        }
        timePickerRowPattern->SetPrefixHour(hourOptions);
        timePickerRowPattern->SetPrefixMinute(minuteOptions);
        timePickerLayout->UpdatePrefixHour(static_cast<int32_t>(hourOptions));
        timePickerLayout->UpdatePrefixMinute(static_cast<int32_t>(minuteOptions));
    }
    auto onChangeCallback = [weak = WeakPtr<FrameNode>(monthDaysNode)]() {
        auto monthDaysNode = weak.Upgrade();
        CHECK_NULL_VOID(monthDaysNode);
        auto pickerPattern = monthDaysNode->GetPattern<DatePickerPattern>();
        CHECK_NULL_VOID(pickerPattern);
        auto str = pickerPattern->GetSelectedObject(true);
        auto datePickerEventHub = pickerPattern->GetEventHub<DatePickerEventHub>();
        CHECK_NULL_VOID(datePickerEventHub);
        datePickerEventHub->FireDialogChangeEvent(str);
    };
    timePickerEventHub->SetOnChangeForDatePicker(std::move(onChangeCallback));
    timeNode->MarkModifyDone();
    SetTimeNodeColumnWeight(timeNode, settingData);
    timeNode->MountToParent(pickerRow);
    return timeNode;
}

std::function<void()> DatePickerDialogView::CreateAndSetDialogSwitchEvent(
    const RefPtr<FrameNode>& pickerStack, const RefPtr<FrameNode>& contentColumn)
{
    RefPtr<DateTimeAnimationController> animationController = AceType::MakeRefPtr<DateTimeAnimationController>();
    auto titleSwitchEvent = [weakContentColumn = AceType::WeakClaim(AceType::RawPtr(contentColumn)),
                                weakPickerStack = AceType::WeakClaim(AceType::RawPtr(pickerStack)),
                                animationController]() {
        auto contentColumn = weakContentColumn.Upgrade();
        CHECK_NULL_VOID(contentColumn);
        auto pickerStack = weakPickerStack.Upgrade();
        CHECK_NULL_VOID(pickerStack);
        // switch picker page.
        SwitchPickerPage(pickerStack, contentColumn, animationController);
    };
    auto switchEvent = [func = titleSwitchEvent]() {
        if (switchFlag_) {
            func();
            return true;
        }
        return false;
    };
    SetDialogSwitchEvent(switchEvent);
    return titleSwitchEvent;
}

void DatePickerDialogView::SwitchPickerPage(const RefPtr<FrameNode>& pickerStack,
    const RefPtr<FrameNode>& contentColumn, const RefPtr<DateTimeAnimationController>& animationController)
{
    auto pickerRow = pickerStack->GetLastChild();
    CHECK_NULL_VOID(pickerRow);
    auto dateNode = AceType::DynamicCast<FrameNode>(pickerStack->GetChildAtIndex(0));
    CHECK_NULL_VOID(dateNode);
    auto datePickerPattern = dateNode->GetPattern<DatePickerPattern>();
    CHECK_NULL_VOID(datePickerPattern);
    auto monthDaysNode = AceType::DynamicCast<FrameNode>(pickerRow->GetChildAtIndex(0));
    auto timeNode = AceType::DynamicCast<FrameNode>(pickerRow->GetChildAtIndex(1));
    CHECK_NULL_VOID(monthDaysNode);
    CHECK_NULL_VOID(timeNode);
    auto timePickerPattern = timeNode->GetPattern<TimePickerRowPattern>();
    CHECK_NULL_VOID(timePickerPattern);
    auto monthDaysPickerPattern = monthDaysNode->GetPattern<DatePickerPattern>();
    CHECK_NULL_VOID(monthDaysPickerPattern);

    PickerDate selectedDate =
        switchFlag_ ? datePickerPattern->GetCurrentDate() : monthDaysPickerPattern->GetCurrentDate();
    SetSelectedDate(switchFlag_ ? monthDaysNode : dateNode, selectedDate);
    if (switchFlag_) {
        datePickerPattern->SetFocusDisable();
        timePickerPattern->SetFocusEnable();
        monthDaysPickerPattern->SetFocusEnable();
        monthDaysNode->MarkModifyDone();
    } else {
        monthDaysPickerPattern->SetFocusDisable();
        timePickerPattern->SetFocusDisable();
        datePickerPattern->SetFocusEnable();
        dateNode->MarkModifyDone();
    }

    auto contentRow = AceType::DynamicCast<FrameNode>(contentColumn->GetLastChild());
    auto titleRow = AceType::DynamicCast<FrameNode>(contentColumn->GetChildAtIndex(0));
    CHECK_NULL_VOID(titleRow);
    auto titleButtonNode = AceType::DynamicCast<FrameNode>(titleRow->GetFirstChild());
    CHECK_NULL_VOID(titleButtonNode);
    auto titleButtonRowNode = AceType::DynamicCast<FrameNode>(titleButtonNode->GetFirstChild());
    CHECK_NULL_VOID(titleButtonRowNode);
    auto spinnerNode = AceType::DynamicCast<FrameNode>(titleButtonRowNode->GetLastChild());
    CHECK_NULL_VOID(spinnerNode);
    animationController->SetButtonIcon(spinnerNode);
    animationController->SetMonthDays(monthDaysNode);
    animationController->SetDatePicker(dateNode);
    animationController->SetTimePicker(timeNode);
    animationController->SetButtonRow(contentRow);
    switchFlag_ = !switchFlag_;

    animationController->Play(switchFlag_);
}

void DatePickerDialogView::CreateAndAddTitleClickEvent(
    std::function<void()>& titleSwitchEvent, const RefPtr<FrameNode>& buttonTitleNode)
{
    auto titleClickEvent = [func = std::move(titleSwitchEvent)](const GestureEvent& /* info */) { func(); };
    auto titleButtonNode = AceType::DynamicCast<FrameNode>(buttonTitleNode->GetFirstChild());
    CHECK_NULL_VOID(titleButtonNode);
    auto titleEventHub = titleButtonNode->GetOrCreateGestureEventHub();
    auto onClick = AceType::MakeRefPtr<NG::ClickEvent>(std::move(titleClickEvent));
    titleEventHub->AddClickEvent(onClick);
}

void DatePickerDialogView::BuildDialogAcceptAndCancelButton(const std::vector<ButtonInfo>& buttonInfos,
    const DatePickerSettingData& settingData, const RefPtr<FrameNode>& acceptNode, const RefPtr<FrameNode>& dateNode,
    const RefPtr<FrameNode>& dialogNode, const RefPtr<FrameNode>& contentColumn,
    std::map<std::string, NG::DialogEvent> dialogEvent, std::map<std::string, NG::DialogGestureEvent> dialogCancelEvent)
{
    auto changeEvent = dialogEvent["changeId"];
    auto dateChangeEvent = dialogEvent["dateChangeId"];
    if (settingData.showTime) {
        auto changeEventSame = changeEvent;
        auto dateChangeEventSame = dateChangeEvent;
        SetDialogChange(acceptNode, std::move(changeEventSame));
        SetDialogDateChange(acceptNode, std::move(dateChangeEventSame));
    }
    SetDialogChange(dateNode, std::move(changeEvent));
    SetDialogDateChange(dateNode, std::move(dateChangeEvent));
    auto contentRow = CreateButtonNode(acceptNode, dateNode, buttonInfos, dialogEvent, std::move(dialogCancelEvent));
    CHECK_NULL_VOID(contentRow);
    auto event = [weak = WeakPtr<FrameNode>(dialogNode)](const GestureEvent& /* info */) {
        auto dialogNode = weak.Upgrade();
        CHECK_NULL_VOID(dialogNode);
        auto pipeline = PipelineContext::GetCurrentContext();
        auto overlayManager = pipeline->GetOverlayManager();
        overlayManager->CloseDialog(dialogNode);
    };
    for (const auto& child : contentRow->GetChildren()) {
        auto firstChild = AceType::DynamicCast<FrameNode>(child);
        auto gesturHub = firstChild->GetOrCreateGestureEventHub();
        auto onClick = AceType::MakeRefPtr<NG::ClickEvent>(event);
        gesturHub->AddClickEvent(onClick);
    }
    contentRow->AddChild(CreateDividerNode(dateNode), 1);
    contentRow->MountToParent(contentColumn);
}

void DatePickerDialogView::UpdateContentPadding(const RefPtr<FrameNode>& contentColumn)
{
    if (Container::GreatOrEqualAPITargetVersion(PlatformVersion::VERSION_TWELVE)) {
        PaddingProperty contentPadding;
        contentPadding.left = CalcLength(PICKER_DIALOG_MARGIN_FORM_EDGE);
        contentPadding.right = CalcLength(PICKER_DIALOG_MARGIN_FORM_EDGE);
        contentColumn->GetLayoutProperty()->UpdatePadding(contentPadding);
    }
}

void DatePickerDialogView::UpdateButtonDefaultFocus(const std::vector<ButtonInfo>& buttonInfos,
    const RefPtr<FrameNode>& buttonNode, bool isConfirm)
{
    bool setDefaultFocus = false;
    if (buttonInfos.size() > CANCEL_BUTTON_INDEX) {
        if (buttonInfos[ACCEPT_BUTTON_INDEX].isPrimary && buttonInfos[CANCEL_BUTTON_INDEX].isPrimary) {
            return;
        }
        auto index = isConfirm ? ACCEPT_BUTTON_INDEX : CANCEL_BUTTON_INDEX;
        if (buttonInfos[index].isPrimary) {
            setDefaultFocus = true;
        }
    } else if (buttonInfos.size() == CANCEL_BUTTON_INDEX) {
        bool isAcceptButtonPrimary = (buttonInfos[0].isAcceptButton && isConfirm && buttonInfos[0].isPrimary);
        bool isCancelButtonPrimary = (!buttonInfos[0].isAcceptButton && !isConfirm && buttonInfos[0].isPrimary);
        if (isAcceptButtonPrimary || isCancelButtonPrimary) {
            setDefaultFocus = true;
        }
    }
    if (setDefaultFocus && buttonNode) {
        auto focusHub = buttonNode->GetOrCreateFocusHub();
        if (focusHub) {
            focusHub->SetIsDefaultFocus(true);
        }
    }
}
} // namespace OHOS::Ace::NG

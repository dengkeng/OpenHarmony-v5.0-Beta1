/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "core/components_ng/pattern/navigation/navigation_title_util.h"

#include <algorithm>

#include "base/i18n/localization.h"
#include "core/common/ace_application_info.h"
#include "core/common/container.h"
#include "core/components_ng/base/view_abstract.h"
#include "core/components_ng/pattern/bubble/bubble_pattern.h"
#include "core/components_ng/pattern/button/button_layout_property.h"
#include "core/components_ng/pattern/button/button_pattern.h"
#include "core/components_ng/pattern/grid/grid_pattern.h"
#include "core/components_ng/pattern/image/image_layout_property.h"
#include "core/components_ng/pattern/image/image_pattern.h"
#include "core/components_ng/pattern/menu/menu_view.h"
#include "core/components_ng/pattern/menu/wrapper/menu_wrapper_pattern.h"
#include "core/components_ng/pattern/navigation/bar_item_event_hub.h"
#include "core/components_ng/pattern/navigation/bar_item_pattern.h"
#include "core/components_ng/pattern/navigation/nav_bar_pattern.h"
#include "core/components_ng/pattern/navigation/title_bar_node.h"
#include "core/components_ng/pattern/navigation/title_bar_pattern.h"
#include "core/components_ng/pattern/navigation/tool_bar_node.h"
#include "core/components_ng/pattern/text/text_pattern.h"

namespace OHOS::Ace::NG {
RefPtr<FrameNode> NavigationTitleUtil::CreateMenuItems(const int32_t menuNodeId,
    const std::vector<NG::BarItem>& menuItems, RefPtr<TitleBarNode> titleBarNode, const bool isButtonEnabled)
{
    auto menuNode = FrameNode::GetOrCreateFrameNode(
        V2::NAVIGATION_MENU_ETS_TAG, menuNodeId, []() { return AceType::MakeRefPtr<LinearLayoutPattern>(false); });
    CHECK_NULL_RETURN(menuNode, nullptr);
    menuNode->Clean();
    menuNode->MarkDirtyNode(PROPERTY_UPDATE_MEASURE);
    auto rowProperty = menuNode->GetLayoutProperty<LinearLayoutProperty>();
    CHECK_NULL_RETURN(rowProperty, nullptr);
    rowProperty->UpdateMainAxisAlign(FlexAlign::SPACE_BETWEEN);
    auto theme = NavigationGetTheme();
    auto mostMenuItemCount = GetOrInitMaxMenuNums(theme, titleBarNode);
    bool needMoreButton = menuItems.size() > mostMenuItemCount ? true : false;

    uint32_t count = 0;
    std::vector<OptionParam> params;
    for (const auto& menuItem : menuItems) {
        ++count;
        if (needMoreButton && (count > mostMenuItemCount - 1)) {
            params.push_back({ menuItem.text.value_or(""), menuItem.icon.value_or(""),
                menuItem.isEnabled.value_or(true), menuItem.action, menuItem.iconSymbol.value_or(nullptr)});
        } else {
            auto menuItemNode = CreateMenuItemNode(theme, menuItem, isButtonEnabled);
            CHECK_NULL_RETURN(menuItemNode, nullptr);
            menuNode->AddChild(menuItemNode);
        }
    }

    // build more button
    if (needMoreButton) {
        auto barItemNode = CreateBarItemNode(isButtonEnabled);
        CHECK_NULL_RETURN(barItemNode, nullptr);
        auto menuItemNode = CreateMenuItemButton(theme);
        CHECK_NULL_RETURN(menuItemNode, nullptr);
        MenuParam menuParam;
        menuParam.isShowInSubWindow = false;
        menuParam.placement = Placement::BOTTOM_RIGHT;
        auto barMenuNode = MenuView::Create(
            std::move(params), menuItemNode->GetId(), menuItemNode->GetTag(), MenuType::NAVIGATION_MENU, menuParam);

        BuildMoreItemNodeAction(menuItemNode, barItemNode, barMenuNode, titleBarNode);
        auto iconNode = AceType::DynamicCast<FrameNode>(barItemNode->GetChildren().front());
        InitTitleBarButtonEvent(menuItemNode, iconNode, true);
        barItemNode->MountToParent(menuItemNode);
        barItemNode->MarkModifyDone();
        menuItemNode->MarkModifyDone();
        menuNode->AddChild(menuItemNode);
        titleBarNode->SetMoreMenuNode(barMenuNode);
    }
    return menuNode;
}

uint32_t NavigationTitleUtil::GetOrInitMaxMenuNums(RefPtr<NavigationBarTheme>& theme, RefPtr<TitleBarNode> titleBarNode)
{
    auto titleBarPattern = AceType::DynamicCast<TitleBarPattern>(titleBarNode->GetPattern());
    CHECK_NULL_RETURN(titleBarPattern, 0);
    auto navDesMaxNum = titleBarPattern->GetMaxMenuNum();
    auto mostMenuItemCount =
        navDesMaxNum < 0 ? theme->GetMostMenuItemCountInBar() : static_cast<uint32_t>(navDesMaxNum);
    mostMenuItemCount = SystemProperties::GetDeviceOrientation() == DeviceOrientation::LANDSCAPE ? MAX_MENU_NUM_LARGE
                                                                                                 : mostMenuItemCount;
    titleBarPattern->SetMaxMenuNum(mostMenuItemCount);
    return mostMenuItemCount;
}

void NavigationTitleUtil::BuildMoreItemNodeAction(const RefPtr<FrameNode>& buttonNode,
    const RefPtr<BarItemNode>& barItemNode, const RefPtr<FrameNode>& barMenuNode,
    const RefPtr<TitleBarNode>& titleBarNode)
{
    auto eventHub = barItemNode->GetEventHub<BarItemEventHub>();
    CHECK_NULL_VOID(eventHub);

    auto context = PipelineContext::GetCurrentContext();
    auto clickCallback = [weakContext = WeakPtr<PipelineContext>(context), id = barItemNode->GetId(),
                             weakMenu = WeakPtr<FrameNode>(barMenuNode),
                             weakBarItemNode = WeakPtr<BarItemNode>(barItemNode),
                             weakTitleBarNode = WeakPtr<TitleBarNode>(titleBarNode)]() {
        auto context = weakContext.Upgrade();
        CHECK_NULL_VOID(context);

        auto overlayManager = context->GetOverlayManager();
        CHECK_NULL_VOID(overlayManager);

        auto menu = weakMenu.Upgrade();
        CHECK_NULL_VOID(menu);

        auto menuNode = AceType::DynamicCast<FrameNode>(menu->GetChildAtIndex(0));
        CHECK_NULL_VOID(menuNode);

        overlayManager->ShowMenu(id, OffsetF(0.0f, 0.0f), menu);

        auto titleBarNode = weakTitleBarNode.Upgrade();
        CHECK_NULL_VOID(titleBarNode);
        titleBarNode->SetIsTitleMenuNodeShowing(true);
        auto hidMenuCallback = [weakTitleBarNode = WeakPtr<TitleBarNode>(titleBarNode)]() {
            auto titleBarNode = weakTitleBarNode.Upgrade();
            CHECK_NULL_VOID(titleBarNode);
            titleBarNode->SetIsTitleMenuNodeShowing(false);
        };
        auto menuWrapperPattern = menuNode->GetPattern<MenuWrapperPattern>();
        CHECK_NULL_VOID(menuWrapperPattern);
        menuWrapperPattern->RegisterMenuDisappearCallback(hidMenuCallback);
    };
    eventHub->SetItemAction(clickCallback);

    auto gestureEventHub = buttonNode->GetOrCreateGestureEventHub();
    CHECK_NULL_VOID(gestureEventHub);
    auto callback = [action = clickCallback](GestureEvent& info) {
        if (info.GetSourceDevice() == SourceType::KEYBOARD) {
            return;
        }
        action();
    };
    gestureEventHub->AddClickEvent(AceType::MakeRefPtr<ClickEvent>(callback));
}

RefPtr<FrameNode> NavigationTitleUtil::CreateMenuItemNode(
    RefPtr<NavigationBarTheme> theme, const BarItem& menuItem, bool isButtonEnabled)
{
    auto menuItemNode = CreateMenuItemButton(theme);
    CHECK_NULL_RETURN(menuItemNode, nullptr);

    int32_t barItemNodeId = ElementRegister::GetInstance()->MakeUniqueId();
    auto barItemNode = AceType::MakeRefPtr<BarItemNode>(V2::BAR_ITEM_ETS_TAG, barItemNodeId);
    barItemNode->InitializePatternAndContext();
    UpdateBarItemNodeWithItem(barItemNode, menuItem, isButtonEnabled);
    auto iconNode = AceType::DynamicCast<FrameNode>(barItemNode->GetChildren().front());
    InitTitleBarButtonEvent(menuItemNode, iconNode, false, menuItem, menuItem.isEnabled.value_or(true));
    auto barItemLayoutProperty = barItemNode->GetLayoutProperty();
    CHECK_NULL_RETURN(barItemLayoutProperty, nullptr);
    barItemLayoutProperty->UpdateMeasureType(MeasureType::MATCH_PARENT);

    barItemNode->MountToParent(menuItemNode);
    barItemNode->MarkModifyDone();
    menuItemNode->MarkModifyDone();
    return menuItemNode;
}

RefPtr<FrameNode> NavigationTitleUtil::CreateMenuItemButton(RefPtr<NavigationBarTheme> theme)
{
    auto buttonPattern = AceType::MakeRefPtr<NG::ButtonPattern>();
    CHECK_NULL_RETURN(buttonPattern, nullptr);
    buttonPattern->setComponentButtonType(ComponentButtonType::NAVIGATION);
    if (AceApplicationInfo::GetInstance().GreatOrEqualTargetAPIVersion(PlatformVersion::VERSION_TWELVE)) {
        buttonPattern->SetBlendColor(theme->GetBackgroundPressedColor(), theme->GetBackgroundHoverColor());
        buttonPattern->SetFocusBorderColor(theme->GetBackgroundFocusOutlineColor());
        buttonPattern->SetFocusBorderWidth(theme->GetBackgroundFocusOutlineWeight());
    } else {
        buttonPattern->SetFocusBorderColor(theme->GetToolBarItemFocusColor());
        buttonPattern->SetFocusBorderWidth(theme->GetToolBarItemFocusBorderWidth());
    }
    auto menuItemNode = FrameNode::CreateFrameNode(
        V2::MENU_ITEM_ETS_TAG, ElementRegister::GetInstance()->MakeUniqueId(), buttonPattern);
    CHECK_NULL_RETURN(menuItemNode, nullptr);
    auto menuItemLayoutProperty = menuItemNode->GetLayoutProperty<ButtonLayoutProperty>();
    CHECK_NULL_RETURN(menuItemLayoutProperty, nullptr);
    menuItemLayoutProperty->UpdateType(ButtonType::NORMAL);
    auto renderContext = menuItemNode->GetRenderContext();
    CHECK_NULL_RETURN(renderContext, nullptr);
    if (AceApplicationInfo::GetInstance().GreatOrEqualTargetAPIVersion(PlatformVersion::VERSION_TWELVE)) {
        auto iconBackgroundWidth = theme->GetIconBackgroundWidth();
        auto iconBackgroundHeight = theme->GetIconBackgroundHeight();
        menuItemLayoutProperty->UpdateUserDefinedIdealSize(
            CalcSize(CalcLength(iconBackgroundWidth), CalcLength(iconBackgroundHeight)));
        menuItemLayoutProperty->UpdateBorderRadius(BorderRadiusProperty(theme->GetCornerRadius()));
        renderContext->UpdateBackgroundColor(theme->GetCompBackgroundColor());
        PaddingProperty padding;
        padding.SetEdges(CalcLength(MENU_BUTTON_PADDING));
        menuItemLayoutProperty->UpdatePadding(padding);
        MarginProperty margin;
        margin.right = CalcLength(theme->GetCompPadding());
        menuItemLayoutProperty->UpdateMargin(margin);
    } else {
        menuItemLayoutProperty->UpdateUserDefinedIdealSize(
            CalcSize(CalcLength(BACK_BUTTON_SIZE), CalcLength(BACK_BUTTON_SIZE)));
        menuItemLayoutProperty->UpdateBorderRadius(BorderRadiusProperty(BUTTON_RADIUS_SIZE));
        renderContext->UpdateBackgroundColor(Color::TRANSPARENT);
        PaddingProperty padding;
        padding.SetEdges(CalcLength(BUTTON_PADDING));
        menuItemLayoutProperty->UpdatePadding(padding);
    }
    return menuItemNode;
}

RefPtr<FrameNode> NavigationTitleUtil::CreateBarItemTextNode(const std::string& text)
{
    int32_t nodeId = ElementRegister::GetInstance()->MakeUniqueId();
    auto textNode = FrameNode::CreateFrameNode(V2::TEXT_ETS_TAG, nodeId, AceType::MakeRefPtr<TextPattern>());
    auto textLayoutProperty = textNode->GetLayoutProperty<TextLayoutProperty>();
    CHECK_NULL_RETURN(textLayoutProperty, nullptr);
    textLayoutProperty->UpdateContent(text);
    textLayoutProperty->UpdateFontSize(TEXT_FONT_SIZE);
    textLayoutProperty->UpdateTextColor(TEXT_COLOR);
    textLayoutProperty->UpdateTextAlign(TextAlign::CENTER);
    return textNode;
}

RefPtr<FrameNode> NavigationTitleUtil::CreateBarItemIconNode(const BarItem& barItem, const bool isButtonEnabled)
{
    auto theme = NavigationGetTheme();
    CHECK_NULL_RETURN(theme, nullptr);

    Color iconColor = theme->GetMenuIconColor();
    double iconOpacity = theme->GetAlphaDisabled();
    auto iconWidth = theme->GetMenuIconSize();
    auto iconHeight = theme->GetMenuIconSize();
    if (AceApplicationInfo::GetInstance().GreatOrEqualTargetAPIVersion(PlatformVersion::VERSION_TWELVE)) {
        iconColor = theme->GetIconColor();
        iconOpacity = theme->GetIconDisableAlpha();
        iconWidth = theme->GetIconWidth();
        iconHeight = theme->GetIconHeight();
    }

    if (barItem.iconSymbol.has_value() && barItem.iconSymbol.value() != nullptr) {
        auto iconNode = FrameNode::GetOrCreateFrameNode(V2::SYMBOL_ETS_TAG,
            ElementRegister::GetInstance()->MakeUniqueId(), []() { return AceType::MakeRefPtr<TextPattern>(); });
        CHECK_NULL_RETURN(iconNode, nullptr);
        auto symbolProperty = iconNode->GetLayoutProperty<TextLayoutProperty>();
        symbolProperty->UpdateFontSize(iconWidth);
        if (isButtonEnabled) {
            symbolProperty->UpdateSymbolColorList({ iconColor });
        } else {
            symbolProperty->UpdateSymbolColorList({ iconColor.BlendOpacity(iconOpacity) });
        }
        barItem.iconSymbol.value()(AccessibilityManager::WeakClaim(AccessibilityManager::RawPtr(iconNode)));
        iconNode->MarkModifyDone();
        return iconNode;
    }
    int32_t nodeId = ElementRegister::GetInstance()->MakeUniqueId();
    ImageSourceInfo info(barItem.icon.value());
    auto iconNode = FrameNode::CreateFrameNode(V2::IMAGE_ETS_TAG, nodeId, AceType::MakeRefPtr<ImagePattern>());
    auto imageLayoutProperty = iconNode->GetLayoutProperty<ImageLayoutProperty>();
    CHECK_NULL_RETURN(imageLayoutProperty, nullptr);
    if (isButtonEnabled) {
        info.SetFillColor(iconColor);
    } else {
        info.SetFillColor(iconColor.BlendOpacity(iconOpacity));
    }
    imageLayoutProperty->UpdateImageSourceInfo(info);
    imageLayoutProperty->UpdateUserDefinedIdealSize(CalcSize(CalcLength(iconWidth), CalcLength(iconHeight)));
    iconNode->MarkModifyDone();
    return iconNode;
}

void NavigationTitleUtil::InitTitleBarButtonEvent(const RefPtr<FrameNode>& buttonNode,
    const RefPtr<FrameNode>& iconNode, bool isMoreButton, const BarItem menuItem, bool isButtonEnabled)
{
    auto eventHub = buttonNode->GetOrCreateInputEventHub();
    CHECK_NULL_VOID(eventHub);

    if (isMoreButton) {
        auto hoverTask = [weakTargetNode = WeakPtr<FrameNode>(buttonNode)](bool isHover) {
            auto targetNode = weakTargetNode.Upgrade();
            CHECK_NULL_VOID(targetNode);
            auto popupParam = AceType::MakeRefPtr<PopupParam>();
            popupParam->SetMessage(Localization::GetInstance()->GetEntryLetters("common.more"));
            popupParam->SetIsShow(isHover);
            popupParam->SetBlockEvent(false);
            ViewAbstract::BindPopup(popupParam, targetNode, nullptr);
        };
        eventHub->AddOnHoverEvent(AceType::MakeRefPtr<InputEvent>(std::move(hoverTask)));
        return;
    }

    if (menuItem.action || iconNode->GetTag() == V2::SYMBOL_ETS_TAG) {
        auto gestureEventHub = buttonNode->GetOrCreateGestureEventHub();
        CHECK_NULL_VOID(gestureEventHub);
        auto clickCallback = [action = menuItem.action, weakNode = WeakPtr<FrameNode>(iconNode)](GestureEvent& info) {
            if (info.GetSourceDevice() == SourceType::KEYBOARD) {
                return;
            }
            auto symbol = weakNode.Upgrade();
            if (symbol->GetTag() == V2::SYMBOL_ETS_TAG) {
                auto symbolProperty = symbol->GetLayoutProperty<TextLayoutProperty>();
                CHECK_NULL_VOID(symbolProperty);
                auto symbolEffectOptions = symbolProperty->GetSymbolEffectOptionsValue(SymbolEffectOptions());
                symbolEffectOptions.SetEffectType(SymbolEffectType::BOUNCE);
                symbolEffectOptions.SetIsTxtActive(true);
                symbolEffectOptions.SetIsTxtActiveSource(0);
                symbolProperty->UpdateSymbolEffectOptions(symbolEffectOptions);
                symbol->MarkDirtyNode(PROPERTY_UPDATE_MEASURE_SELF);
            }
            if (action) {
                action();
            }
        };
        gestureEventHub->AddClickEvent(AceType::MakeRefPtr<ClickEvent>(clickCallback));
    }

    auto buttonEvent = buttonNode->GetEventHub<ButtonEventHub>();
    CHECK_NULL_VOID(buttonEvent);
    buttonEvent->SetEnabled(isButtonEnabled);
}

void NavigationTitleUtil::UpdateBarItemNodeWithItem(
    const RefPtr<BarItemNode>& barItemNode, const BarItem& barItem, const bool isButtonEnabled)
{
    if (Container::LessThanAPIVersion(PlatformVersion::VERSION_TEN) && barItem.text.has_value() &&
        !barItem.text.value().empty()) {
        auto textNode = CreateBarItemTextNode(barItem.text.value());
        barItemNode->SetTextNode(textNode);
        barItemNode->AddChild(textNode);
    }
    if ((barItem.icon.has_value())
        || (barItem.iconSymbol.has_value() && barItem.iconSymbol.value() != nullptr)) {
        auto iconNode = CreateBarItemIconNode(barItem, isButtonEnabled);
        barItemNode->SetIconNode(iconNode);
        barItemNode->AddChild(iconNode);
    }
    if (barItem.action) {
        auto eventHub = barItemNode->GetEventHub<BarItemEventHub>();
        CHECK_NULL_VOID(eventHub);
        eventHub->SetItemAction(barItem.action);
    }
    auto barItemPattern = barItemNode->GetPattern<BarItemPattern>();
    barItemNode->MarkModifyDone();
}

void NavigationTitleUtil::BuildMoreIemNode(const RefPtr<BarItemNode>& barItemNode, const bool isButtonEnabled)
{
    auto theme = NavigationGetTheme();
    CHECK_NULL_VOID(theme);
    auto iconSize = theme->GetMenuIconSize();
    auto symbolNode = FrameNode::GetOrCreateFrameNode(V2::SYMBOL_ETS_TAG,
        ElementRegister::GetInstance()->MakeUniqueId(), []() { return AceType::MakeRefPtr<TextPattern>(); });
    CHECK_NULL_VOID(symbolNode);
    auto symbolProperty = symbolNode->GetLayoutProperty<TextLayoutProperty>();
    CHECK_NULL_VOID(symbolProperty);
    symbolProperty->UpdateSymbolSourceInfo(SymbolSourceInfo(theme->GetMoreSymbolId()));
    symbolProperty->UpdateFontSize(iconSize);
    if (isButtonEnabled) {
        symbolProperty->UpdateSymbolColorList({ theme->GetMenuIconColor() });
    } else {
        symbolProperty->UpdateSymbolColorList({ theme->GetMenuIconColor()
            .BlendOpacity(theme->GetAlphaDisabled()) });
    }
    symbolNode->MarkModifyDone();
    barItemNode->SetIsMoreItemNode(true);
    barItemNode->SetIconNode(symbolNode);
    barItemNode->AddChild(symbolNode);
    barItemNode->MarkModifyDone();
    return;
}

RefPtr<BarItemNode> NavigationTitleUtil::CreateBarItemNode(const bool isButtonEnabled)
{
    int32_t barItemNodeId = ElementRegister::GetInstance()->MakeUniqueId();
    auto barItemNode = AceType::MakeRefPtr<BarItemNode>(V2::BAR_ITEM_ETS_TAG, barItemNodeId);
    barItemNode->InitializePatternAndContext();
    auto barItemLayoutProperty = barItemNode->GetLayoutProperty();
    CHECK_NULL_RETURN(barItemLayoutProperty, nullptr);
    barItemLayoutProperty->UpdateMeasureType(MeasureType::MATCH_PARENT);
    BuildMoreIemNode(barItemNode, isButtonEnabled);
    return barItemNode;
}
} // namespace OHOS::Ace::NG

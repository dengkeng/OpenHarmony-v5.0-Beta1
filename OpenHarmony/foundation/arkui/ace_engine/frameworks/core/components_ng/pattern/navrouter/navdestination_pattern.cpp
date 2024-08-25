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

#include "core/components_ng/pattern/navrouter/navdestination_pattern.h"

#include <atomic>

#include "core/common/container.h"
#include "base/log/dump_log.h"
#include "core/components/theme/app_theme.h"
#include "core/components_ng/pattern/navigation/title_bar_layout_property.h"
#include "core/components_ng/pattern/navigation/title_bar_node.h"
#include "core/components_ng/pattern/navigation/navigation_pattern.h"
#include "core/components_ng/pattern/text/text_layout_property.h"

namespace OHOS::Ace::NG {
namespace {
    // titlebar ZINDEX
    constexpr static int32_t DEFAULT_TITLEBAR_ZINDEX = 2;
    std::atomic<uint64_t> navDestinationPatternNextAutoGenId = 0;
}

NavDestinationPattern::NavDestinationPattern(const RefPtr<ShallowBuilder>& shallowBuilder)
    : shallowBuilder_(shallowBuilder)
{
    navDestinationId_ = navDestinationPatternNextAutoGenId.fetch_add(1);
}

NavDestinationPattern::NavDestinationPattern()
{
    navDestinationId_ = navDestinationPatternNextAutoGenId.fetch_add(1);
}

NavDestinationPattern::~NavDestinationPattern()
{
    customNode_ = nullptr;
}

void NavDestinationPattern::OnActive()
{
    Pattern::OnActive();
    auto hostNode = AceType::DynamicCast<NavDestinationGroupNode>(GetHost());
    CHECK_NULL_VOID(hostNode);
    auto navDestinationContext = hostNode->GetRenderContext();
    CHECK_NULL_VOID(navDestinationContext);
    auto navDestinationLayoutProperty = hostNode->GetLayoutProperty<NavDestinationLayoutProperty>();
    CHECK_NULL_VOID(navDestinationLayoutProperty);
    auto titleBarNode = AceType::DynamicCast<TitleBarNode>(hostNode->GetTitleBarNode());
    CHECK_NULL_VOID(titleBarNode);
    auto titleBarLayoutProperty = titleBarNode->GetLayoutProperty<TitleBarLayoutProperty>();
    CHECK_NULL_VOID(titleBarLayoutProperty);
    if (navDestinationLayoutProperty->GetHideTitleBar().value_or(false)) {
        titleBarLayoutProperty->UpdateVisibility(VisibleType::GONE);
    } else {
        titleBarLayoutProperty->UpdateVisibility(VisibleType::VISIBLE);
    }
    titleBarNode->MarkModifyDone();
}

void NavDestinationPattern::OnModifyDone()
{
    Pattern::OnModifyDone();
    auto hostNode = AceType::DynamicCast<NavDestinationGroupNode>(GetHost());
    CHECK_NULL_VOID(hostNode);
    auto titleBarNode = AceType::DynamicCast<TitleBarNode>(hostNode->GetTitleBarNode());
    CHECK_NULL_VOID(titleBarNode);
    auto titleBarRenderContext = titleBarNode->GetRenderContext();
    CHECK_NULL_VOID(titleBarRenderContext);
    // set the titlebar to float on the top
    titleBarRenderContext->UpdateZIndex(DEFAULT_TITLEBAR_ZINDEX);
    auto&& opts = hostNode->GetLayoutProperty()->GetSafeAreaExpandOpts();
    auto navDestinationContentNode = AceType::DynamicCast<FrameNode>(hostNode->GetContentNode());
    if (opts && opts->Expansive() && navDestinationContentNode) {
        TAG_LOGI(AceLogTag::ACE_NAVIGATION,
            "Navdestination SafArea expand as %{public}s", opts->ToString().c_str());
            navDestinationContentNode->GetLayoutProperty()->UpdateSafeAreaExpandOpts(*opts);
            navDestinationContentNode->MarkModifyDone();
    }

    UpdateNameIfNeeded(hostNode);
    UpdateBackgroundColorIfNeeded(hostNode);
    UpdateTitlebarVisibility(hostNode);
}

void NavDestinationPattern::OnLanguageConfigurationUpdate()
{
    if (isRightToLeft_ == AceApplicationInfo::GetInstance().IsRightToLeft()) {
        return;
    }
    isRightToLeft_ = AceApplicationInfo::GetInstance().IsRightToLeft();
    auto hostNode = AceType::DynamicCast<NavDestinationGroupNode>(GetHost());
    CHECK_NULL_VOID(hostNode);
    auto titleBarNode = AceType::DynamicCast<TitleBarNode>(hostNode->GetTitleBarNode());
    CHECK_NULL_VOID(titleBarNode);
    titleBarNode->MarkDirtyNode(PROPERTY_UPDATE_LAYOUT);
}

void NavDestinationPattern::UpdateNameIfNeeded(RefPtr<NavDestinationGroupNode>& hostNode)
{
    if (!name_.empty()) {
        return;
    }

    if (hostNode->GetInspectorId().has_value()) {
        name_ = hostNode->GetInspectorIdValue();
    } else {
        name_ = std::to_string(GetHost()->GetId());
    }
    auto pathInfo = GetNavPathInfo();
    if (pathInfo) {
        pathInfo->SetName(name_);
    }
}

void NavDestinationPattern::UpdateBackgroundColorIfNeeded(RefPtr<NavDestinationGroupNode>& hostNode)
{
    auto renderContext = hostNode->GetRenderContext();
    CHECK_NULL_VOID(renderContext);
    if (IsUserDefinedBgColor()) {
        TAG_LOGI(AceLogTag::ACE_NAVIGATION, "User defined Background color: %{public}s",
            renderContext->GetBackgroundColor()->ColorToString().c_str());
        return;
    }
    if (hostNode->GetNavDestinationMode() == NavDestinationMode::DIALOG) {
        renderContext->UpdateBackgroundColor(Color::TRANSPARENT);
        TAG_LOGI(AceLogTag::ACE_NAVIGATION, "Set dialog background color: %{public}s",
            renderContext->GetBackgroundColor()->ColorToString().c_str());
        return;
    }
    auto pipelineContext = PipelineContext::GetCurrentContext();
    if (!pipelineContext) {
        return;
    }
    auto theme = pipelineContext->GetTheme<AppTheme>();
    if (!theme) {
        return;
    }
    renderContext->UpdateBackgroundColor(theme->GetBackgroundColor());
    TAG_LOGI(AceLogTag::ACE_NAVIGATION, "Default background color: %{public}s",
        renderContext->GetBackgroundColor()->ColorToString().c_str());
}

void NavDestinationPattern::UpdateTitlebarVisibility(RefPtr<NavDestinationGroupNode>& hostNode)
{
    auto navDestinationLayoutProperty = hostNode->GetLayoutProperty<NavDestinationLayoutProperty>();
    CHECK_NULL_VOID(navDestinationLayoutProperty);
    auto titleBarNode = AceType::DynamicCast<TitleBarNode>(hostNode->GetTitleBarNode());
    CHECK_NULL_VOID(titleBarNode);
    auto titleBarLayoutProperty = titleBarNode->GetLayoutProperty<TitleBarLayoutProperty>();
    CHECK_NULL_VOID(titleBarLayoutProperty);

    if (navDestinationLayoutProperty->HasNoPixMap()) {
        if (navDestinationLayoutProperty->HasImageSource()) {
            titleBarLayoutProperty->UpdateImageSource(navDestinationLayoutProperty->GetImageSourceValue());
        }
        if (navDestinationLayoutProperty->HasPixelMap()) {
            titleBarLayoutProperty->UpdatePixelMap(navDestinationLayoutProperty->GetPixelMapValue());
        }
        titleBarLayoutProperty->UpdateNoPixMap(navDestinationLayoutProperty->GetNoPixMapValue());
    }

    if (navDestinationLayoutProperty->GetHideTitleBar().value_or(false)) {
        titleBarLayoutProperty->UpdateVisibility(VisibleType::GONE);
        titleBarNode->SetJSViewActive(false);
    } else {
        titleBarLayoutProperty->UpdateVisibility(VisibleType::VISIBLE);
        titleBarNode->SetJSViewActive(true);
        auto&& opts = navDestinationLayoutProperty->GetSafeAreaExpandOpts();
        if (opts && opts->Expansive()) {
            titleBarLayoutProperty->UpdateSafeAreaExpandOpts(*opts);
        }
    }

    auto navDesIndex = hostNode->GetIndex();
    if (navDesIndex == 0) {
        navDestinationLayoutProperty->UpdatePropertyChangeFlag(PROPERTY_UPDATE_MEASURE);
        titleBarLayoutProperty->UpdatePropertyChangeFlag(PROPERTY_UPDATE_MEASURE);
    }
    titleBarNode->MarkModifyDone();
    titleBarNode->MarkDirtyNode(PROPERTY_UPDATE_MEASURE_SELF_AND_CHILD);
}

bool NavDestinationPattern::GetBackButtonState()
{
    auto hostNode = AceType::DynamicCast<NavDestinationGroupNode>(GetHost());
    CHECK_NULL_RETURN(hostNode, false);
    auto navDestinationLayoutProperty = hostNode->GetLayoutProperty<NavDestinationLayoutProperty>();
    CHECK_NULL_RETURN(navDestinationLayoutProperty, false);
    if (navDestinationLayoutProperty->GetHideTitleBarValue(false)) {
        return false;
    }
    // get navigation node
    auto parent = AceType::DynamicCast<FrameNode>(hostNode->GetParent());
    RefPtr<NavigationGroupNode> navigationNode;
    while (parent && !parent->IsRootNode()) {
        navigationNode = AceType::DynamicCast<NavigationGroupNode>(parent);
        if (navigationNode) {
            break;
        }
        parent = AceType::DynamicCast<FrameNode>(parent->GetParent());
    }
    if (!navigationNode) {
        TAG_LOGW(AceLogTag::ACE_NAVIGATION, "can't find navigation node");
        return false;
    }
    auto navigationLayoutProperty = navigationNode->GetLayoutProperty<NavigationLayoutProperty>();
    CHECK_NULL_RETURN(navigationLayoutProperty, false);
    auto pattern = navigationNode->GetPattern<NavigationPattern>();
    auto stack = pattern->GetNavigationStack();
    auto index = stack->FindIndex(name_, customNode_, true);
    bool showBackButton = true;
    auto titleBarNode = AceType::DynamicCast<TitleBarNode>(hostNode->GetTitleBarNode());
    if (index == 0 && (pattern->GetNavigationMode() == NavigationMode::SPLIT ||
        navigationLayoutProperty->GetHideNavBarValue(false))) {
        showBackButton = false;
    }
    auto isCustomTitle = hostNode->GetPrevTitleIsCustomValue(false);
    if (isCustomTitle) {
        return showBackButton;
    }
    auto titleNode = AceType::DynamicCast<FrameNode>(titleBarNode->GetTitle());
    CHECK_NULL_RETURN(titleNode, showBackButton);
    auto theme = NavigationGetTheme();
    CHECK_NULL_RETURN(theme, showBackButton);
    auto textLayoutProperty = titleNode->GetLayoutProperty<TextLayoutProperty>();
    auto currentFontSize = textLayoutProperty->GetAdaptMaxFontSizeValue(Dimension(0.0, DimensionUnit::FP));
    auto targetFontSize = showBackButton ? theme->GetTitleFontSizeMin() : theme->GetTitleFontSize();
    if (targetFontSize == currentFontSize) {
        return showBackButton;
    }
    textLayoutProperty->UpdateAdaptMaxFontSize(targetFontSize);
    textLayoutProperty->UpdatePropertyChangeFlag(PROPERTY_UPDATE_MEASURE);
    return showBackButton;
}

void NavDestinationPattern::OnAttachToFrameNode()
{
    auto host = GetHost();
    CHECK_NULL_VOID(host);
    if (Container::GreatOrEqualAPIVersion(PlatformVersion::VERSION_ELEVEN)) {
        SafeAreaExpandOpts opts = { .type = SAFE_AREA_TYPE_SYSTEM | SAFE_AREA_TYPE_CUTOUT,
            .edges = SAFE_AREA_EDGE_ALL };
        host->GetLayoutProperty()->UpdateSafeAreaExpandOpts(opts);
    }
    isRightToLeft_ = AceApplicationInfo::GetInstance().IsRightToLeft();
}

void NavDestinationPattern::DumpInfo()
{
    DumpLog::GetInstance().AddDesc(std::string("name: ").append(name_));
}
} // namespace OHOS::Ace::NG

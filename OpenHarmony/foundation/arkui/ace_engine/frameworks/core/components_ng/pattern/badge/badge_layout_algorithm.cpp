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

#include "core/components_ng/pattern/badge/badge_layout_algorithm.h"

#include "base/geometry/dimension.h"
#include "base/utils/utils.h"
#include "core/common/ace_application_info.h"
#include "core/common/container.h"
#include "core/components/badge/badge_theme.h"
#include "core/components/common/layout/constants.h"
#include "core/components_ng/base/frame_node.h"
#include "core/components_ng/layout/layout_algorithm.h"
#include "core/components_ng/pattern/badge/badge_layout_property.h"
#include "core/components_ng/pattern/text/text_layout_property.h"
#include "core/components_ng/property/layout_constraint.h"
#include "core/components_ng/property/measure_utils.h"
#include "core/pipeline/pipeline_base.h"

namespace OHOS::Ace::NG {
namespace {
constexpr float PERCENT_HALF = 0.5f;
} // namespace

void BadgeLayoutAlgorithm::Measure(LayoutWrapper* layoutWrapper)
{
    auto host = layoutWrapper->GetHostNode();
    CHECK_NULL_VOID(host);
    auto children = host->GetChildren();
    if (children.empty()) {
        return;
    }
    auto childrenSize = children.size();
    auto layoutProperty = AceType::DynamicCast<BadgeLayoutProperty>(layoutWrapper->GetLayoutProperty());
    CHECK_NULL_VOID(layoutProperty);
    auto childLayoutConstraint = layoutProperty->CreateChildConstraint();

    auto textFirstLayoutConstraint = childLayoutConstraint;
    textFirstLayoutConstraint.maxSize = { Infinity<float>(), Infinity<float>() };

    auto textWrapper = layoutWrapper->GetOrCreateChildByIndex(childrenSize - 1);
    CHECK_NULL_VOID(textWrapper);
    auto textLayoutProperty = AceType::DynamicCast<TextLayoutProperty>(textWrapper->GetLayoutProperty());
    CHECK_NULL_VOID(textLayoutProperty);
    auto textGeometryNode = textWrapper->GetGeometryNode();
    CHECK_NULL_VOID(textGeometryNode);

    auto pipeline = PipelineBase::GetCurrentContext();
    CHECK_NULL_VOID(pipeline);
    auto badgeTheme = pipeline->GetTheme<BadgeTheme>();
    CHECK_NULL_VOID(badgeTheme);

    auto badgeFontSize = layoutProperty->GetBadgeFontSize();
    if (badgeFontSize.has_value() && GreatOrEqual(badgeFontSize.value().ConvertToPx(), 0)) {
        hasFontSize_ = true;
        textLayoutProperty->UpdateFontSize(badgeFontSize.value());
    } else {
        hasFontSize_ = false;
        auto badgeThemeFontSize = badgeTheme->GetBadgeFontSize();
        textLayoutProperty->UpdateFontSize(badgeThemeFontSize);
    }
    if (textWrapper) {
        textWrapper->Measure(textFirstLayoutConstraint);
    }

    auto badgeCircleSize = badgeTheme->GetBadgeCircleSize();
    auto badgeValue = layoutProperty->GetBadgeValue();
    if (badgeValue.has_value() && badgeValue.value().empty()) {
        badgeCircleSize = badgeTheme->GetLittleBadgeCircleSize();
    }
    auto circleSize = layoutProperty->GetBadgeCircleSize();
    auto badgeCircleDiameter = circleSize.has_value() ? (circleSize->IsValid() ? circleSize->ConvertToPx() : 0)
                                                      : badgeCircleSize.ConvertToPx();

    auto badgeWidth = 0.0;
    auto badgeHeight = badgeCircleDiameter;
    auto countLimit = layoutProperty->GetBadgeMaxCountValue();
    auto badgeCircleRadius = badgeCircleDiameter / 2;

    std::string textData;
    if (textLayoutProperty->HasContent()) {
        textData = textLayoutProperty->GetContentValue();
    }

    auto messageCount = textData.size();
    auto textSize = textGeometryNode->GetContentSize();
    if (!textData.empty() || messageCount > 0) {
        if ((textData.size() <= 1 && !textData.empty()) ||
            ((messageCount < 10 && messageCount <= countLimit) && textData.empty())) {
            if (hasFontSize_) {
                badgeCircleDiameter = std::max(static_cast<double>(textSize.Height()), badgeCircleDiameter);
                badgeHeight = std::max(badgeCircleDiameter, badgeHeight);
            }
            badgeCircleRadius = badgeCircleDiameter / 2;
            badgeWidth = badgeCircleDiameter;
        } else if (textData.size() > 1 || messageCount > countLimit) {
            if (hasFontSize_) {
                badgeCircleDiameter = std::max(static_cast<double>(textSize.Height()), badgeCircleDiameter);
                badgeHeight = std::max(badgeCircleDiameter, badgeHeight);
            }
            badgeWidth = textSize.Width() + badgeTheme->GetNumericalBadgePadding().ConvertToPx() * 2;
            badgeWidth = badgeCircleDiameter > badgeWidth ? badgeCircleDiameter : badgeWidth;
            badgeCircleRadius = badgeCircleDiameter / 2;
        }
    }
    if (LessOrEqual(circleSize->ConvertToPx(), 0)) {
        badgeWidth = 0;
        badgeHeight = 0;
    }
    textLayoutProperty->UpdateMarginSelfIdealSize(SizeF(badgeWidth, badgeHeight));
    auto textLayoutConstraint = textFirstLayoutConstraint;
    textLayoutConstraint.selfIdealSize = OptionalSize<float>(badgeWidth, badgeHeight);

    textWrapper->Measure(textLayoutConstraint);
    auto childWrapper = layoutWrapper->GetOrCreateChildByIndex(childrenSize - 2);
    CHECK_NULL_VOID(childWrapper);
    childWrapper->Measure(childLayoutConstraint);

    PerformMeasureSelf(layoutWrapper);
}

static OffsetF GetTextDataOffset(const RefPtr<BadgeLayoutProperty> layoutProperty, float badgeCircleDiameter,
                                 float badgeCircleRadius, const RefPtr<GeometryNode>& geometryNode, bool textIsSpace)
{
    auto offset = geometryNode->GetFrameOffset();
    auto parentSize = geometryNode->GetFrameSize();
    auto width = parentSize.Width();
    auto height = parentSize.Height();
    auto badgePosition = layoutProperty->GetBadgePosition();
    auto layoutDirection = layoutProperty->GetNonAutoLayoutDirection();
    OffsetF textOffset;
    if (badgePosition == BadgePosition::RIGHT_TOP) {
        if (layoutDirection == TextDirection::RTL) {
            textOffset = OffsetF(offset.GetX(), offset.GetY());
        } else {
            textOffset = OffsetF(offset.GetX() + width - badgeCircleDiameter, offset.GetY());
        }
        if (!textIsSpace) {
            textOffset += OffsetF(Dimension(2.0_vp).ConvertToPx(), -Dimension(2.0_vp).ConvertToPx());
        }
    } else if (badgePosition == BadgePosition::RIGHT) {
        if (layoutDirection == TextDirection::RTL) {
            textOffset = OffsetF(offset.GetX(), offset.GetY() + height * PERCENT_HALF - badgeCircleRadius);
        } else {
            textOffset = OffsetF(
                offset.GetX() + width - badgeCircleDiameter, offset.GetY() + height * PERCENT_HALF - badgeCircleRadius);
        }
    } else if (badgePosition == BadgePosition::LEFT) {
        if (layoutDirection == TextDirection::RTL) {
            textOffset = OffsetF(
                offset.GetX() + width - badgeCircleDiameter, offset.GetY() + height * PERCENT_HALF - badgeCircleRadius);
        } else {
            textOffset = OffsetF(offset.GetX(), offset.GetY() + height * PERCENT_HALF - badgeCircleRadius);
        }
    } else {
        textOffset = OffsetF(offset.GetX(), offset.GetY());
    }
    return textOffset;
}

static void LayoutIsPositionXy(const RefPtr<BadgeLayoutProperty> layoutProperty,
                               const RefPtr<GeometryNode>&geometryNode, OffsetF& textOffset)
{
    auto offset = geometryNode->GetFrameOffset();
    auto badgePositionX = layoutProperty->GetBadgePositionX();
    auto badgePositionY = layoutProperty->GetBadgePositionY();
    textOffset =
        OffsetF(offset.GetX() + badgePositionX->ConvertToPx(), offset.GetY() + badgePositionY->ConvertToPx());
}

void BadgeLayoutAlgorithm::Layout(LayoutWrapper* layoutWrapper)
{
    CHECK_NULL_VOID(layoutWrapper);
    auto host = layoutWrapper->GetHostNode();
    CHECK_NULL_VOID(host);
    auto children = host->GetChildren();
    if (children.empty()) {
        return;
    }
    auto childrenSize = children.size();

    auto geometryNode = layoutWrapper->GetGeometryNode();
    CHECK_NULL_VOID(geometryNode);

    auto layoutProperty = DynamicCast<BadgeLayoutProperty>(layoutWrapper->GetLayoutProperty());
    CHECK_NULL_VOID(layoutProperty);

    auto pipeline = PipelineBase::GetCurrentContext();
    CHECK_NULL_VOID(pipeline);
    auto badgeTheme = pipeline->GetTheme<BadgeTheme>();
    CHECK_NULL_VOID(badgeTheme);
    auto badgeCircleSize = badgeTheme->GetBadgeCircleSize();
    auto circleSize = layoutProperty->GetBadgeCircleSize();
    auto badgeCircleDiameter = circleSize.has_value() ? (circleSize->IsValid() ? circleSize->ConvertToPx() : 0)
                                                      : badgeCircleSize.ConvertToPx();

    auto badgeWidth = 0.0;
    auto badgeCircleRadius = badgeCircleDiameter / 2;
    auto countLimit =
        layoutProperty->HasBadgeMaxCount() ? layoutProperty->GetBadgeMaxCountValue() : badgeTheme->GetMaxCount();

    auto textWrapper = layoutWrapper->GetOrCreateChildByIndex(childrenSize - 1);
    CHECK_NULL_VOID(textWrapper);
    auto textLayoutProperty = DynamicCast<TextLayoutProperty>(textWrapper->GetLayoutProperty());
    CHECK_NULL_VOID(textLayoutProperty);
    auto textGeometryNode = textWrapper->GetGeometryNode();
    CHECK_NULL_VOID(textGeometryNode);

    std::string textData;
    if (textLayoutProperty->HasContent()) {
        textData = textLayoutProperty->GetContentValue();
    }

    auto messageCount = textData.size();
    auto textSize = textGeometryNode->GetContentSize();

    if (!textData.empty() || messageCount > 0) {
        if ((textData.size() <= 1 && !textData.empty()) ||
            ((messageCount < 10 && messageCount <= countLimit) && textData.empty())) {
            if (hasFontSize_) {
                badgeCircleDiameter = std::max(static_cast<double>(textSize.Height()), badgeCircleDiameter);
            }
            badgeCircleRadius = badgeCircleDiameter / 2;
            badgeWidth = badgeCircleDiameter;
        } else if (textData.size() > 1 || messageCount > countLimit) {
            if (hasFontSize_) {
                badgeCircleDiameter = std::max(static_cast<double>(textSize.Height()), badgeCircleDiameter);
            }
            badgeWidth = textSize.Width() + badgeTheme->GetNumericalBadgePadding().ConvertToPx() * 2;
            badgeWidth = badgeCircleDiameter > badgeWidth ? badgeCircleDiameter : badgeWidth;
            badgeCircleRadius = badgeCircleDiameter / 2;
        }
    }

    BorderRadiusProperty radius;
    auto borderWidth = layoutProperty->GetBadgeBorderWidthValue(badgeTheme->GetBadgeBorderWidth());
    OffsetF borderOffset(borderWidth.ConvertToPx(), borderWidth.ConvertToPx());
    radius.SetRadius(Dimension(badgeCircleRadius + borderWidth.ConvertToPx()));
    auto textFrameNode = textWrapper->GetHostNode();
    CHECK_NULL_VOID(textFrameNode);
    auto textRenderContext = textFrameNode->GetRenderContext();
    CHECK_NULL_VOID(textRenderContext);
    textRenderContext->UpdateBorderRadius(radius);

    textLayoutProperty->UpdateAlignment(Alignment::CENTER);

    OffsetF textOffset;
    if (!layoutProperty->GetIsPositionXy().value()) {
        textOffset = GetTextDataOffset(layoutProperty, badgeCircleDiameter, badgeCircleRadius,
            geometryNode, textData == " ");
    } else {
        LayoutIsPositionXy(layoutProperty, geometryNode, textOffset);
    }
    if (Container::GreatOrEqualAPIVersion(PlatformVersion::VERSION_TEN)) {
        textGeometryNode->SetMarginFrameOffset(textOffset - geometryNode->GetFrameOffset());
    } else {
        textGeometryNode->SetMarginFrameOffset(textOffset - geometryNode->GetFrameOffset() - borderOffset);
    }
    auto textFrameSize = textGeometryNode->GetFrameSize();
    if (GreatNotEqual(circleSize->ConvertToPx(), 0) && Container::LessThanAPIVersion(PlatformVersion::VERSION_TEN)) {
        textFrameSize += SizeF(borderWidth.ConvertToPx() * 2, borderWidth.ConvertToPx() * 2);
    }
    textGeometryNode->SetFrameSize(textFrameSize);
    textWrapper->Layout();

    auto childWrapper = layoutWrapper->GetOrCreateChildByIndex(childrenSize - 2);
    CHECK_NULL_VOID(childWrapper);
    auto childGeometryNode = childWrapper->GetGeometryNode();
    CHECK_NULL_VOID(childGeometryNode);
    // the child node needs to use its own margin
    auto layoutDirection = layoutWrapper->GetLayoutProperty()->GetNonAutoLayoutDirection();
    if (layoutDirection == TextDirection::RTL) {
        auto parentSize = geometryNode->GetFrameSize();
        auto width = parentSize.Width();
        auto childSize = childGeometryNode->GetFrameSize();
        auto childOffset = childGeometryNode->GetFrameOffset();
        childGeometryNode->SetMarginFrameOffset(OffsetF(
            childOffset.GetX() + width - childSize.Width(), childOffset.GetY()));
    } else {
        childGeometryNode->SetMarginFrameOffset(OffsetF());
    }
    childWrapper->Layout();
}

void BadgeLayoutAlgorithm::PerformMeasureSelf(LayoutWrapper* layoutWrapper)
{
    const auto& layoutConstraint = layoutWrapper->GetLayoutProperty()->GetLayoutConstraint();
    const auto& minSize = layoutConstraint->minSize;
    const auto& maxSize = layoutConstraint->maxSize;
    const auto& padding = layoutWrapper->GetLayoutProperty()->CreatePaddingAndBorder();
    OptionalSizeF frameSize;
    do {
        // Use idea size first if it is valid.
        frameSize.UpdateSizeWithCheck(layoutConstraint->selfIdealSize);
        if (frameSize.IsValid()) {
            break;
        }
        // use the last child size.
        auto host = layoutWrapper->GetHostNode();
        CHECK_NULL_VOID(host);
        auto children = host->GetChildren();
        auto childrenSize = children.size();
        auto childFrame =
            layoutWrapper->GetOrCreateChildByIndex(childrenSize - 2)->GetGeometryNode()->GetMarginFrameSize();
        AddPaddingToSize(padding, childFrame);
        frameSize.UpdateIllegalSizeWithCheck(childFrame);
        frameSize.Constrain(minSize, maxSize);
        frameSize.UpdateIllegalSizeWithCheck(SizeF { 0.0f, 0.0f });
    } while (false);

    layoutWrapper->GetGeometryNode()->SetFrameSize(frameSize.ConvertToSizeT());
}

} // namespace OHOS::Ace::NG

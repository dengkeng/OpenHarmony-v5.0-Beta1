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

#include "core/components_ng/pattern/picker/datepicker_paint_method.h"

#include "base/geometry/rect.h"
#include "base/utils/utils.h"
#include "core/components/common/properties/color.h"
#include "core/components/picker/picker_theme.h"
#include "core/components_ng/pattern/picker/datepicker_pattern.h"
#include "core/components_ng/pattern/picker/datepicker_row_layout_property.h"
#include "core/pipeline_ng/pipeline_context.h"


namespace OHOS::Ace::NG {

namespace {
constexpr float DIVIDER_LINE_WIDTH = 1.0f;
constexpr uint8_t ENABLED_ALPHA = 255;
constexpr uint8_t DISABLED_ALPHA = 102;
} // namespace

CanvasDrawFunction DatePickerPaintMethod::GetForegroundDrawFunction(PaintWrapper* paintWrapper)
{
    auto pipeline = PipelineBase::GetCurrentContext();
    CHECK_NULL_RETURN(pipeline, nullptr);
    auto theme = pipeline->GetTheme<PickerTheme>();
    CHECK_NULL_RETURN(theme, nullptr);
    auto dividerColor = theme->GetDividerColor();

    auto dividerSpacing = pipeline->NormalizeToPx(theme->GetDividerSpacing());
    const auto& geometryNode = paintWrapper->GetGeometryNode();
    CHECK_NULL_RETURN(geometryNode, nullptr);
    auto frameRect = geometryNode->GetFrameRect();

    auto renderContext = paintWrapper->GetRenderContext();
    CHECK_NULL_RETURN(renderContext, nullptr);
    auto pickerNode = renderContext->GetHost();
    CHECK_NULL_RETURN(pickerNode, nullptr);
    auto layoutProperty = pickerNode->GetLayoutProperty<DataPickerRowLayoutProperty>();
    CHECK_NULL_RETURN(layoutProperty, nullptr);

    return [weak = WeakClaim(this), dividerLineWidth = DIVIDER_LINE_WIDTH, layoutProperty, frameRect, dividerSpacing,
               dividerColor, enabled = enabled_, pattern = pattern_](RSCanvas& canvas) {
        PaddingPropertyF padding = layoutProperty->CreatePaddingAndBorder();
        RectF contentRect = { padding.left.value_or(0), padding.top.value_or(0),
            frameRect.Width() - padding.Width(), frameRect.Height() - padding.Height() };
        if (contentRect.Height() >= dividerSpacing) {
            DividerPainter dividerPainter(dividerLineWidth, contentRect.Width(), false, dividerColor, LineCap::SQUARE);
            double upperLine = (contentRect.Height() - dividerSpacing) / 2.0 + contentRect.GetY();
            double downLine = (contentRect.Height() + dividerSpacing) / 2.0 + contentRect.GetY();

            OffsetF offset = OffsetF(contentRect.GetX(), upperLine);
            dividerPainter.DrawLine(canvas, offset);
            OffsetF offsetY = OffsetF(contentRect.GetX(), downLine);
            dividerPainter.DrawLine(canvas, offsetY);
        }

        auto picker = weak.Upgrade();
        CHECK_NULL_VOID(picker);
        if (!enabled) {
            picker->PaintDisable(canvas, frameRect.Width(), frameRect.Height());
        }
    };
}

void DatePickerPaintMethod::PaintDisable(RSCanvas& canvas, double X, double Y)
{
    double centerY = Y;
    double centerX = X;
    RSRect rRect(0, 0, centerX, centerY);
    RSPath path;
    path.AddRoundRect(rRect, 0, 0, RSPathDirection::CW_DIRECTION);
    RSPen pen;
    RSBrush brush;
    brush.SetColor(float(DISABLED_ALPHA) / ENABLED_ALPHA);
    pen.SetColor(float(DISABLED_ALPHA) / ENABLED_ALPHA);
    canvas.AttachBrush(brush);
    canvas.AttachPen(pen);
    canvas.DrawPath(path);
    canvas.DetachPen();
    canvas.DetachBrush();
}
} // namespace OHOS::Ace::NG

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

#include "property/rs_property_drawable_frame_geometry.h"

#include "pipeline/rs_paint_filter_canvas.h"
#include "pipeline/rs_render_node.h"
#include "platform/common/rs_log.h"
#include "property/rs_properties.h"
#include "property/rs_properties_painter.h"

#include "src/image/SkImage_Base.h"

namespace OHOS::Rosen {
void RSFrameGeometryDrawable::Draw(const RSRenderContent& content, RSPaintFilterCanvas& canvas) const
{
    canvas.Translate(content.GetRenderProperties().GetFrameOffsetX(), content.GetRenderProperties().GetFrameOffsetY());
}
RSPropertyDrawable::DrawablePtr RSFrameGeometryDrawable::Generate(const RSRenderContent& content)
{
    return std::make_unique<RSFrameGeometryDrawable>();
}

void RSColorFilterDrawable::Draw(const RSRenderContent& content, RSPaintFilterCanvas& canvas) const
{
    auto drSurface = canvas.GetSurface();
    if (drSurface == nullptr) {
        ROSEN_LOGE("RSColorFilterDrawable::Draw drSurface is null");
        return;
    }
    auto clipBounds = canvas.GetDeviceClipBounds();
    auto imageSnapshot = drSurface->GetImageSnapshot(clipBounds);
    if (imageSnapshot == nullptr) {
        ROSEN_LOGD("RSColorFilterDrawable::Draw image is null");
        return;
    }
    imageSnapshot->HintCacheGpuResource();
    Drawing::AutoCanvasRestore acr(canvas, true);
    canvas.ResetMatrix();
    static Drawing::SamplingOptions options(Drawing::FilterMode::NEAREST, Drawing::MipmapMode::NONE);
    canvas.AttachBrush(brush_);
    Drawing::Rect clipBoundsRect = {clipBounds.GetLeft(), clipBounds.GetTop(),
        clipBounds.GetRight(), clipBounds.GetBottom()};
    canvas.DrawImageRect(*imageSnapshot, clipBoundsRect, options);
    canvas.DetachBrush();
}

RSPropertyDrawable::DrawablePtr RSColorFilterDrawable::Generate(const RSRenderContent& content)
{
    auto& colorFilter = content.GetRenderProperties().GetColorFilter();
    if (colorFilter == nullptr) {
        return nullptr;
    }
    Drawing::Brush brush;
    brush.SetAntiAlias(true);
    Drawing::Filter filter;
    filter.SetColorFilter(colorFilter);
    brush.SetFilter(filter);
    return std::make_unique<RSColorFilterDrawable>(std::move(brush));
}

bool RSColorFilterDrawable::Update(const RSRenderContent& content)
{
    auto& colorFilter = content.GetRenderProperties().GetColorFilter();
    if (colorFilter == nullptr) {
        return false;
    }
    Drawing::Filter filter;
    filter.SetColorFilter(colorFilter);
    brush_.SetFilter(filter);
    return true;
}

RSPropertyDrawable::DrawablePtr RSClipFrameDrawable::Generate(const RSRenderContent& content)
{
    // PLANNING: cache frame rect, and update when frame rect changed
    return content.GetRenderProperties().GetClipToFrame() ? std::make_unique<RSClipFrameDrawable>() : nullptr;
}

void RSClipFrameDrawable::Draw(const RSRenderContent& content, RSPaintFilterCanvas& canvas) const
{
    canvas.ClipRect(RSPropertiesPainter::Rect2DrawingRect(content.GetRenderProperties().GetFrameRect()),
        Drawing::ClipOp::INTERSECT, false);
}
} // namespace OHOS::Rosen

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

#include "drawable/rs_effect_render_node_drawable.h"

#include "pipeline/rs_effect_render_node.h"
#include "pipeline/rs_uni_render_thread.h"
#include "platform/common/rs_log.h"

namespace OHOS::Rosen::DrawableV2 {
RSEffectRenderNodeDrawable::Registrar RSEffectRenderNodeDrawable::instance_;

RSEffectRenderNodeDrawable::RSEffectRenderNodeDrawable(std::shared_ptr<const RSRenderNode>&& node)
    : RSRenderNodeDrawable(std::move(node))
{}

RSRenderNodeDrawable::Ptr RSEffectRenderNodeDrawable::OnGenerate(std::shared_ptr<const RSRenderNode> node)
{
    return new RSEffectRenderNodeDrawable(std::move(node));
}

void RSEffectRenderNodeDrawable::OnDraw(Drawing::Canvas& canvas)
{
    if (!ShouldPaint()) {
        return;
    }

    RS_LOGD("RSEffectRenderNodeDrawable::OnDraw node: %{public}" PRIu64, nodeId_);
    const auto& params = GetRenderParams();
    auto paintFilterCanvas = static_cast<RSPaintFilterCanvas*>(&canvas);
    RSAutoCanvasRestore acr(paintFilterCanvas, RSPaintFilterCanvas::SaveType::kCanvasAndAlpha);

    params->ApplyAlphaAndMatrixToCanvas(*paintFilterCanvas);
    auto uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams().get();
    if ((!uniParam || uniParam->IsOpDropped()) && GetOpDropped()
        && QuickReject(canvas, params->GetLocalDrawRect())) {
        return;
    }
    RSRenderNodeDrawable::OnDraw(canvas);
}

void RSEffectRenderNodeDrawable::OnCapture(Drawing::Canvas& canvas)
{
    if (!ShouldPaint()) {
        return;
    }

    RS_LOGD("RSEffectRenderNodeDrawable::OnCapture node: %{public}" PRIu64, nodeId_);
    const auto& params = GetRenderParams();
    auto paintFilterCanvas = static_cast<RSPaintFilterCanvas*>(&canvas);
    RSAutoCanvasRestore acr(paintFilterCanvas, RSPaintFilterCanvas::SaveType::kCanvasAndAlpha);
    params->ApplyAlphaAndMatrixToCanvas(*paintFilterCanvas);
    RSRenderNodeDrawable::OnCapture(canvas);
}
} // namespace OHOS::Rosen::DrawableV2

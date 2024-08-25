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

#include "core/components_ng/pattern/custom_paint/canvas_modifier.h"
#include "core/components_ng/render/adapter/rosen_render_context.h"
#include "core/components_ng/render/drawing.h"

#ifdef ENABLE_ROSEN_BACKEND
#include "pipeline/rs_recording_canvas.h"
#include "pipeline/rs_paint_filter_canvas.h"
#endif

namespace OHOS::Ace::NG {
CanvasModifier::CanvasModifier()
{
    needRender_ = AceType::MakeRefPtr<PropertyBool>(true);
    AttachProperty(needRender_);
}

void CanvasModifier::onDraw(DrawingContext& drawingContext)
{
    ACE_SCOPED_TRACE("CanvasModifier::onDraw");
#ifndef USE_ROSEN_DRAWING
    auto skCanvas = drawingContext.canvas.GetImpl<Rosen::Drawing::SkiaCanvas>()->ExportSkCanvas();

    auto recordingCanvas = static_cast<OHOS::Rosen::RSRecordingCanvas*>(skCanvas);
    if (!recordingCanvas || !rsRecordingCanvas_) {
        return;
    }

    auto drawCmdList = rsRecordingCanvas_->GetDrawCmdList();
    if (!drawCmdList) {
        return;
    }

    auto rsDrawCmdList = recordingCanvas->GetDrawCmdList();
    CHECK_NULL_VOID(rsDrawCmdList);
    recordingCanvasDrawSize_.SetWidth(rsDrawCmdList->GetWidth());
    recordingCanvasDrawSize_.SetHeight(rsDrawCmdList->GetHeight());
    drawCmdSize_.SetWidth(drawCmdList->GetWidth());
    drawCmdSize_.SetHeight(drawCmdList->GetHeight());
    rsDrawCmdList->SetWidth(drawCmdList->GetWidth());
    rsDrawCmdList->SetHeight(drawCmdList->GetHeight());

    if (needResetSurface_) {
        CHECK_NULL_VOID(renderContext_.Upgrade());
        renderContext_.Upgrade()->ResetSurface();
        needResetSurface_ = false;
    }

    if (drawCmdList->GetSize() == 0) {
        return;
    }
    auto canvas = std::make_shared<OHOS::Rosen::RSPaintFilterCanvas>(recordingCanvas);
    CHECK_NULL_VOID(canvas);
    canvas->SetRecordingState(true);
    drawCmdList->Playback(*canvas);
    rsRecordingCanvas_->Clear();
#else
    if (!rsRecordingCanvas_) {
        return;
    }

    auto& recordingCanvas = drawingContext.canvas;
    auto drawCmdList = rsRecordingCanvas_->GetDrawCmdList();
    if (!drawCmdList) {
        return;
    }

    auto rsDrawCmdList = static_cast<RSRecordingCanvas&>(recordingCanvas).GetDrawCmdList();
    CHECK_NULL_VOID(rsDrawCmdList);
    recordingCanvasDrawSize_.SetWidth(rsDrawCmdList->GetWidth());
    recordingCanvasDrawSize_.SetHeight(rsDrawCmdList->GetHeight());
    drawCmdSize_.SetWidth(drawCmdList->GetWidth());
    drawCmdSize_.SetHeight(drawCmdList->GetHeight());
    rsDrawCmdList->SetWidth(drawCmdList->GetWidth());
    rsDrawCmdList->SetHeight(drawCmdList->GetHeight());

    if (needResetSurface_) {
        CHECK_NULL_VOID(renderContext_.Upgrade());
        renderContext_.Upgrade()->ResetSurface();
        needResetSurface_ = false;
    }

    TAG_LOGD(AceLogTag::ACE_CANVAS, "Playback %{public}zu drawing commands.", drawCmdList->GetOpItemSize());
    if (drawCmdList->IsEmpty()) {
        return;
    }
    drawCmdList->Playback(recordingCanvas);
    rsRecordingCanvas_->Clear();
#endif
}

std::string CanvasModifier::GetDumpInfo()
{
    return std::string("recordingCanvas size: ")
        .append(recordingCanvasDrawSize_.ToString())
        .append(", rsRecordingCanvas size: ")
        .append(drawCmdSize_.ToString());
}
} // namespace OHOS::Ace::NG

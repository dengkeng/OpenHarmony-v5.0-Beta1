/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef KNUCKLE_DYNAMIC_DRAWING_MANAGER_H
#define KNUCKLE_DYNAMIC_DRAWING_MANAGER_H

#include "ui/rs_canvas_drawing_node.h"
#include "ui/rs_surface_node.h"
#include "transaction/rs_transaction.h"

#include "draw/canvas.h"
#include "include/core/SkPath.h"
#include "include/core/SkPaint.h"
#include "knuckle_glow_trace_system.h"
#include "pointer_event.h"
#include "window_info.h"

namespace OHOS {
namespace MMI {
class KnuckleDynamicDrawingManager {
public:
    KnuckleDynamicDrawingManager();
    ~KnuckleDynamicDrawingManager();
    void KnuckleDynamicDrawHandler(std::shared_ptr<PointerEvent> pointerEvent);
    void UpdateDisplayInfo(const DisplayInfo& displayInfo);

private:
    void StartTouchDraw(std::shared_ptr<PointerEvent> pointerEvent);
    void CreateTouchWindow(const int32_t displayId);
    void CreateCanvasNode();
    int32_t DrawGraphic(std::shared_ptr<PointerEvent> pointerEvent);

    bool CheckPointerAction(std::shared_ptr<PointerEvent> pointerEvent);
    void ProcessUpAndCancelEvent(std::shared_ptr<PointerEvent> pointerEvent);
    void ProcessDownEvent(std::shared_ptr<PointerEvent> pointerEvent);
    void ProcessMoveEvent(std::shared_ptr<PointerEvent> pointerEvent);
    void InitPointerPathPaint();
    void UpdateTrackColors();
    std::shared_ptr<OHOS::Media::PixelMap> DecodeImageToPixelMap(const std::string &imagePath);
    std::shared_ptr<Rosen::Drawing::Bitmap> PixelMapToBitmap(
    std::shared_ptr<Media::PixelMap>& pixelMap);
    Rosen::Drawing::AlphaType AlphaTypeToAlphaType(Media::AlphaType alphaType);
    Rosen::Drawing::ColorType PixelFormatToColorType(Media::PixelFormat pixelFormat);
    bool IsSingleKnuckle(std::shared_ptr<PointerEvent> touchEvent);

private:
    std::shared_ptr<Rosen::RSSurfaceNode> surfaceNode_ { nullptr };
    std::shared_ptr<Rosen::RSCanvasDrawingNode> canvasNode_ { nullptr };
    DisplayInfo displayInfo_ {};
    uint64_t screenId_ { 0 };
    Rosen::Drawing::Brush brush_;
    Rosen::Drawing::Pen pen_;
    std::vector<Rosen::Drawing::Point> traceControlPoints_;

    int32_t pointCounter_ { 0 };
    bool isDrawing_ { false };
    std::shared_ptr<KnuckleGlowTraceSystem> glowTraceSystem_;
    Rosen::Drawing::Path pointerPath_;
    SkPaint pointerPathPaint_;
    int64_t lastUpdateTimeMillis_ { 0 };

    std::shared_ptr<OHOS::Media::PixelMap> pixelMap_ { nullptr };
    bool isStop_ { false };
};
} // namespace MMI
} // namespace OHOS
#endif // KNUCKLE_DYNAMIC_DRAWING_MANAGER_H

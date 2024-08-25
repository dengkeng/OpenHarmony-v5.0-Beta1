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
#include "skbug_8955.h"

#include <native_drawing/drawing_brush.h>
#include <native_drawing/drawing_font.h>
#include <native_drawing/drawing_pen.h>
#include <native_drawing/drawing_text_blob.h>

#include "test_common.h"

#include "common/log_common.h"

enum {
    K_W = 100,
    K_H = 100,
};

SkBug8955::SkBug8955()
{
    // dm file gm/skbug_8955.cpp
    bitmapWidth_ = K_W;
    bitmapHeight_ = K_H;
    fileName_ = "skbug_8955";
}

void SkBug8955::OnTestFunction(OH_Drawing_Canvas* canvas)
{
    OH_Drawing_Brush* brush = OH_Drawing_BrushCreate();
    OH_Drawing_Font* font = OH_Drawing_FontCreate();
    float fSize = 50.f;
    OH_Drawing_FontSetTextSize(font, fSize);
    auto blob = OH_Drawing_TextBlobCreateFromText("+", 1, font, TEXT_ENCODING_UTF8); // 1 为字符串长度
    OH_Drawing_CanvasSave(canvas);
    OH_Drawing_CanvasScale(canvas, 0, 0);
    OH_Drawing_CanvasAttachBrush(canvas, brush);
    float x = 30.f;
    float y = 60.f;
    OH_Drawing_CanvasDrawTextBlob(canvas, blob, x, y);
    OH_Drawing_CanvasRestore(canvas);
    OH_Drawing_CanvasDrawTextBlob(canvas, blob, x, y);

    OH_Drawing_CanvasDetachBrush(canvas);
    OH_Drawing_FontDestroy(font);
    OH_Drawing_BrushDestroy(brush);
    OH_Drawing_TextBlobDestroy(blob);
}

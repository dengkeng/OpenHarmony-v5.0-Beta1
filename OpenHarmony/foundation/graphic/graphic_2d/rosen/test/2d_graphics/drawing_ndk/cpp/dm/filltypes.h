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

#ifndef FILLTYPES_H
#define FILLTYPES_H
#include <bits/alltypes.h>
#include <native_drawing/drawing_canvas.h>
#include <native_drawing/drawing_path.h>
#include <native_drawing/drawing_rect.h>

#include "../test_base.h"

class FillType : public TestBase {
    typedef struct {
        int x;
        int y;
        OH_Drawing_PathFillType ft;
        float scale;
    } DATA_PARAM;

public:
    FillType();
    ~FillType() override {};

protected:
    void OnTestFunction(OH_Drawing_Canvas* canvas) override;
    void showPath(OH_Drawing_Canvas* canvas, DATA_PARAM param, OH_Drawing_Brush* brush);
    void showFour(OH_Drawing_Canvas* canvas, float scale, OH_Drawing_Brush* brush);
    OH_Drawing_Path* path = nullptr;
};
#endif // FILLTYPES_H
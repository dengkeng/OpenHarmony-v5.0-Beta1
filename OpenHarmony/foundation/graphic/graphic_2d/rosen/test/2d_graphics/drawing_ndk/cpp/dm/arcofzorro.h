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
#ifndef ARCOFZORRO_H
#define ARCOFZORRO_H
#include "../test_base.h"
#include <bits/alltypes.h>
#include <native_drawing/drawing_rect.h>
#include <native_drawing/drawing_canvas.h>

class ArcOfZorro : public TestBase {
public:
    ArcOfZorro();
    ~ArcOfZorro() override;

protected:
    void OnTestFunction(OH_Drawing_Canvas *canvas) override;
    float x = 10;
    float y = 10;
    float w = 200;
    float h = 200;
    int xOffset = 0;
    int yOffset = 0;
    int direction = 0;
};
#endif // ARCOFZORRO_H
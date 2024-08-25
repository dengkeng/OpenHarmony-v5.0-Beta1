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

#include "knuckle_divergent_point.h"

#include <random>

#include "include/core/SkColorFilter.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KnuckleDivergentPoint"

namespace OHOS {
namespace MMI {
namespace {
constexpr double PI = 3.14159265358979323846f;
constexpr double MOVE_SPEED = 10.0f;
constexpr double BASIC_GRAVITY_Y = 0.5f;
constexpr int32_t BASIC_LIFESPAN = 15;
constexpr float DOUBLE = 2.0f;
} // namespace

KnuckleDivergentPoint::KnuckleDivergentPoint(const OHOS::Rosen::Drawing::Bitmap &bitmap)
    : traceShadow_(bitmap)
{
    CALL_DEBUG_ENTER;
}

KnuckleDivergentPoint::~KnuckleDivergentPoint() {};

void KnuckleDivergentPoint::Update()
{
    CALL_DEBUG_ENTER;
    if (IsEnded()) {
        return;
    }
    lifespan_--;
    pointX_ += moveVelocityX_;
    pointY_ += moveVelocityY_;
    moveVelocityY_ += BASIC_GRAVITY_Y;
}

void KnuckleDivergentPoint::Clear()
{
    CALL_DEBUG_ENTER;
    lifespan_ = DEFAULT_LIFESPAN;
}

void KnuckleDivergentPoint::Draw(Rosen::Drawing::RecordingCanvas* canvas)
{
    CALL_DEBUG_ENTER;
    CHKPV(canvas);
    if (IsEnded() || pointX_ <= 0 || pointY_ <= 0) {
        return;
    }

    OHOS::Rosen::Drawing::Brush brush;
    canvas->AttachBrush(brush);
    canvas->DrawBitmap(traceShadow_, pointX_, pointY_);
    canvas->DetachBrush();
}

void KnuckleDivergentPoint::Reset(double pointX, double pointY)
{
    CALL_DEBUG_ENTER;
    pointX_ = pointX;
    pointY_ = pointY;
    lifespan_ = BASIC_LIFESPAN;
    std::random_device rd;
    std::default_random_engine e(rd());
    std::uniform_real_distribution<double> u(0.0, 1.0);
    double baseVelocity = u(e) * DOUBLE * PI;

    moveVelocityX_ = std::cos(baseVelocity) * MOVE_SPEED;
    moveVelocityY_ = std::sin(baseVelocity) * MOVE_SPEED;
}

bool KnuckleDivergentPoint::IsEnded() const
{
    CALL_DEBUG_ENTER;
    return lifespan_ < 0;
}
} // namespace MMI
} // namespace OHOS

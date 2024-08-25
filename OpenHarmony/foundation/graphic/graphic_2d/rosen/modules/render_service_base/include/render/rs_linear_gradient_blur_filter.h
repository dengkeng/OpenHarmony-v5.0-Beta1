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
#ifndef RENDER_SERVICE_CLIENT_CORE_RENDER_RS_LINEAR_GRADIENT_BLUR_FILTER_H
#define RENDER_SERVICE_CLIENT_CORE_RENDER_RS_LINEAR_GRADIENT_BLUR_FILTER_H

#include "render/rs_skia_filter.h"
#include "render/rs_gradient_blur_para.h"
#include "pipeline/rs_paint_filter_canvas.h"

#include "effect/runtime_effect.h"
#include "effect/runtime_shader_builder.h"

namespace OHOS {
namespace Rosen {
class RSB_EXPORT RSLinearGradientBlurFilter : public RSDrawingFilterOriginal {
public:
    RSLinearGradientBlurFilter(const std::shared_ptr<RSLinearGradientBlurPara>& para, const float geoWidth,
        const float geoHeight);
    RSLinearGradientBlurFilter(const RSLinearGradientBlurFilter&) = delete;
    RSLinearGradientBlurFilter operator=(const RSLinearGradientBlurFilter&) = delete;
    ~RSLinearGradientBlurFilter() override;

    void PostProcess(Drawing::Canvas& canvas) override {};
    std::string GetDescription() override;
    std::string GetDetailedDescription() override;
    void DrawImageRect(Drawing::Canvas& canvas, const std::shared_ptr<Drawing::Image>& image,
        const Drawing::Rect& src, const Drawing::Rect& dst) const override;
    void PreProcess(std::shared_ptr<Drawing::Image> image) override {};
    std::shared_ptr<RSDrawingFilterOriginal> Compose(
        const std::shared_ptr<RSDrawingFilterOriginal>& other) const override
    {
        return nullptr;
    }
    void SetGeometry(Drawing::Canvas& canvas, float geoWidth, float geoHeight) override
    {
        auto dst = canvas.GetDeviceClipBounds();
        tranX_ = dst.GetLeft();
        tranY_ = dst.GetTop();
        mat_ = canvas.GetTotalMatrix();
        geoWidth_ = std::ceil(geoWidth);
        geoHeight_ = std::ceil(geoHeight);
    }
    void IsOffscreenCanvas(bool isOffscreenCanvas) override
    {
        isOffscreenCanvas_ = isOffscreenCanvas;
    }

private:
    static void TransformGradientBlurDirection(uint8_t& direction, const uint8_t directionBias);
    static void ComputeScale(float width, float height, bool useMaskAlgorithm);
    static void MakeHorizontalMeanBlurEffect();
    static void MakeVerticalMeanBlurEffect();
    static void DrawImageRectByDDGRGpuApiType(Drawing::Canvas& canvas, uint8_t directionBias,
        Drawing::RectF& clipIPadding, const std::shared_ptr<Drawing::Image>& image,
        std::shared_ptr<RSLinearGradientBlurPara> para);

    friend class RSMarshallingHelper;
    std::shared_ptr<RSLinearGradientBlurPara> linearGradientBlurPara_ = nullptr;
    inline static float imageScale_ = 1.f;
    inline static float geoWidth_ = 0.f;
    inline static float geoHeight_ = 0.f;
    inline static float tranX_ = 0.f;
    inline static float tranY_ = 0.f;
    inline static bool isOffscreenCanvas_ = true;

    static uint8_t CalcDirectionBias(const Drawing::Matrix& mat);
    static bool GetGradientDirectionPoints(
        Drawing::Point (&pts)[2], const Drawing::Rect& clipBounds, GradientDirection direction);
    static std::shared_ptr<Drawing::ShaderEffect> MakeAlphaGradientShader(const Drawing::Rect& clipBounds,
        const std::shared_ptr<RSLinearGradientBlurPara>& para, uint8_t directionBias);
    static void DrawMaskLinearGradientBlur(const std::shared_ptr<Drawing::Image>& image, Drawing::Canvas& canvas,
        std::shared_ptr<RSDrawingFilterOriginal>& blurFilter,
        std::shared_ptr<Drawing::ShaderEffect> alphaGradientShader, const Drawing::Rect& dst);
    static std::shared_ptr<Drawing::ShaderEffect> MakeMaskLinearGradientBlurShader(
        std::shared_ptr<Drawing::ShaderEffect> srcImageShader, std::shared_ptr<Drawing::ShaderEffect> gradientShader);
    static void DrawMeanLinearGradientBlur(const std::shared_ptr<Drawing::Image>& image, Drawing::Canvas& canvas,
        float radius, std::shared_ptr<Drawing::ShaderEffect> alphaGradientShader, const Drawing::Rect& dst);

    static std::shared_ptr<Drawing::RuntimeEffect> horizontalMeanBlurShaderEffect_;
    static std::shared_ptr<Drawing::RuntimeEffect> verticalMeanBlurShaderEffect_;
    static std::shared_ptr<Drawing::RuntimeEffect> maskBlurShaderEffect_;
    inline static Drawing::Matrix mat_;
};
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_CLIENT_CORE_RENDER_RS_LINEAR_GRADIENT_BLUR_FILTER_H
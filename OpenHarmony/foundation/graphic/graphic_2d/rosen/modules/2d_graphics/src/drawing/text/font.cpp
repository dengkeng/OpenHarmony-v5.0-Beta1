/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "text/font.h"

#include "impl_factory.h"
#include "impl_interface/font_impl.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
Font::Font() : fontImpl_(ImplFactory::CreateFontImpl()) {}

Font::Font(std::shared_ptr<Typeface> typeface, scalar size, scalar scaleX, scalar skewX)
    : fontImpl_(ImplFactory::CreateFontImpl(typeface, size, scaleX, skewX)) {}

void Font::SetEdging(FontEdging edging)
{
    fontImpl_->SetEdging(edging);
}

void Font::SetBaselineSnap(bool baselineSnap)
{
    fontImpl_->SetBaselineSnap(baselineSnap);
}

void Font::SetForceAutoHinting(bool isForceAutoHinting)
{
    fontImpl_->SetForceAutoHinting(isForceAutoHinting);
}

void Font::SetSubpixel(bool isSubpixel)
{
    fontImpl_->SetSubpixel(isSubpixel);
}

void Font::SetHinting(FontHinting hintingLevel)
{
    fontImpl_->SetHinting(hintingLevel);
}

void Font::SetEmbeddedBitmaps(bool embeddedBitmaps)
{
    fontImpl_->SetEmbeddedBitmaps(embeddedBitmaps);
}

void Font::SetTypeface(std::shared_ptr<Typeface> typeface)
{
    fontImpl_->SetTypeface(typeface);
}

void Font::SetSize(scalar textSize)
{
    fontImpl_->SetSize(textSize);
}

void Font::SetEmbolden(bool isEmbolden)
{
    fontImpl_->SetEmbolden(isEmbolden);
}

void Font::SetScaleX(scalar scaleX)
{
    fontImpl_->SetScaleX(scaleX);
}

void Font::SetSkewX(scalar skewX)
{
    fontImpl_->SetSkewX(skewX);
}

void Font::SetLinearMetrics(bool isLinearMetrics)
{
    fontImpl_->SetLinearMetrics(isLinearMetrics);
}

scalar Font::GetMetrics(FontMetrics* metrics) const
{
    return fontImpl_->GetMetrics(metrics);
}

void Font::GetWidths(const uint16_t glyphs[], int count, scalar widths[]) const
{
    fontImpl_->GetWidths(glyphs, count, widths);
}

void Font::GetWidths(const uint16_t glyphs[], int count, scalar widths[], Rect bounds[]) const
{
    fontImpl_->GetWidths(glyphs, count, widths, bounds);
}

scalar Font::GetSize() const
{
    return fontImpl_->GetSize();
}

std::shared_ptr<Typeface> Font::GetTypeface()
{
    return fontImpl_->GetTypeface();
}

FontEdging Font::GetEdging() const
{
    return fontImpl_->GetEdging();
}

FontHinting Font::GetHinting() const
{
    return fontImpl_->GetHinting();
}

bool Font::IsEmbeddedBitmaps() const
{
    return fontImpl_->IsEmbeddedBitmaps();
}

scalar Font::GetScaleX() const
{
    return fontImpl_->GetScaleX();
}

scalar Font::GetSkewX() const
{
    return fontImpl_->GetSkewX();
}

bool Font::IsBaselineSnap() const
{
    return fontImpl_->IsBaselineSnap();
}

bool Font::IsForceAutoHinting() const
{
    return fontImpl_->IsForceAutoHinting();
}

bool Font::IsSubpixel() const
{
    return fontImpl_->IsSubpixel();
}

bool Font::IsLinearMetrics() const
{
    return fontImpl_->IsLinearMetrics();
}

bool Font::IsEmbolden() const
{
    return fontImpl_->IsEmbolden();
}

uint16_t Font::UnicharToGlyph(int32_t uni) const
{
    return fontImpl_->UnicharToGlyph(uni);
}

int Font::TextToGlyphs(const void* text, size_t byteLength, TextEncoding encoding,
    uint16_t glyphs[], int maxGlyphCount) const
{
    return fontImpl_->TextToGlyphs(text, byteLength, encoding, glyphs, maxGlyphCount);
}

scalar Font::MeasureText(const void* text, size_t byteLength, TextEncoding encoding, Rect* bounds)
{
    return fontImpl_->MeasureText(text, byteLength, encoding, bounds);
}

int Font::CountText(const void* text, size_t byteLength, TextEncoding encoding) const
{
    return fontImpl_->CountText(text, byteLength, encoding);
}
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS

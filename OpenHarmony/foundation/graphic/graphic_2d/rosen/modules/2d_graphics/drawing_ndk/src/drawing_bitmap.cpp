/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "drawing_bitmap.h"

#include "drawing_canvas_utils.h"

#include "draw/color.h"
#include "image/bitmap.h"

using namespace OHOS;
using namespace Rosen;
using namespace Drawing;

static Bitmap* CastToBitmap(OH_Drawing_Bitmap* cBitmap)
{
    return reinterpret_cast<Bitmap*>(cBitmap);
}

static ColorType CColorFormatCastToColorType(OH_Drawing_ColorFormat cColorFormat)
{
    ColorType colorType = COLORTYPE_UNKNOWN;
    switch (cColorFormat) {
        case COLOR_FORMAT_UNKNOWN:
            colorType = COLORTYPE_UNKNOWN;
            break;
        case COLOR_FORMAT_ALPHA_8:
            colorType = COLORTYPE_ALPHA_8;
            break;
        case COLOR_FORMAT_RGB_565:
            colorType = COLORTYPE_RGB_565;
            break;
        case COLOR_FORMAT_ARGB_4444:
            colorType = COLORTYPE_ARGB_4444;
            break;
        case COLOR_FORMAT_RGBA_8888:
            colorType = COLORTYPE_RGBA_8888;
            break;
        case COLOR_FORMAT_BGRA_8888:
            colorType = COLORTYPE_BGRA_8888;
            break;
        default:
            break;
    }
    return colorType;
}

static OH_Drawing_ColorFormat ColorFormatCastToCColorType(ColorType colorType)
{
    OH_Drawing_ColorFormat cColorFormat = COLOR_FORMAT_UNKNOWN;
    switch (colorType) {
        case COLORTYPE_UNKNOWN:
            cColorFormat = COLOR_FORMAT_UNKNOWN;
            break;
        case COLORTYPE_ALPHA_8:
            cColorFormat = COLOR_FORMAT_ALPHA_8;
            break;
        case COLORTYPE_RGB_565:
            cColorFormat = COLOR_FORMAT_RGB_565;
            break;
        case COLORTYPE_ARGB_4444:
            cColorFormat = COLOR_FORMAT_ARGB_4444;
            break;
        case COLORTYPE_RGBA_8888:
            cColorFormat = COLOR_FORMAT_RGBA_8888;
            break;
        case COLORTYPE_BGRA_8888:
            cColorFormat = COLOR_FORMAT_BGRA_8888;
            break;
        default:
            break;
    }
    return cColorFormat;
}

static AlphaType CAlphaFormatCastToAlphaType(OH_Drawing_AlphaFormat cAlphaFormat)
{
    AlphaType alphaType = ALPHATYPE_UNKNOWN;

    switch (cAlphaFormat) {
        case ALPHA_FORMAT_UNKNOWN:
            alphaType = ALPHATYPE_UNKNOWN;
            break;
        case ALPHA_FORMAT_OPAQUE:
            alphaType = ALPHATYPE_OPAQUE;
            break;
        case ALPHA_FORMAT_PREMUL:
            alphaType = ALPHATYPE_PREMUL;
            break;
        case ALPHA_FORMAT_UNPREMUL:
            alphaType = ALPHATYPE_UNPREMUL;
            break;
        default:
            break;
    }
    return alphaType;
}

static OH_Drawing_AlphaFormat AlphaFormatCastToCAlphaType(AlphaType alphaType)
{
    OH_Drawing_AlphaFormat alphaFormat = ALPHA_FORMAT_UNKNOWN;
    switch (alphaType) {
        case ALPHATYPE_UNKNOWN:
            alphaFormat = ALPHA_FORMAT_UNKNOWN;
            break;
        case ALPHATYPE_OPAQUE:
            alphaFormat = ALPHA_FORMAT_OPAQUE;
            break;
        case ALPHATYPE_PREMUL:
            alphaFormat = ALPHA_FORMAT_PREMUL;
            break;
        case ALPHATYPE_UNPREMUL:
            alphaFormat = ALPHA_FORMAT_UNPREMUL;
            break;
        default:
            break;
    }
    return alphaFormat;
}

OH_Drawing_Bitmap* OH_Drawing_BitmapCreate()
{
    return (OH_Drawing_Bitmap*)new Bitmap;
}

void OH_Drawing_BitmapDestroy(OH_Drawing_Bitmap* cBitmap)
{
    delete CastToBitmap(cBitmap);
}

OH_Drawing_Bitmap* OH_Drawing_BitmapCreateFromPixels(OH_Drawing_Image_Info* cImageInfo, void* pixels, uint32_t rowBytes)
{
    if (cImageInfo == nullptr || pixels == nullptr || rowBytes == 0) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return nullptr;
    }

    ImageInfo imageInfo(cImageInfo->width, cImageInfo->height,
        static_cast<ColorType>(cImageInfo->colorType), static_cast<AlphaType>(cImageInfo->alphaType));

    Bitmap* bitmap = new Bitmap;
    bool ret = bitmap->InstallPixels(imageInfo, pixels, rowBytes);
    if (!ret) {
        delete bitmap;
        return nullptr;
    }
    return (OH_Drawing_Bitmap*)bitmap;
}

void OH_Drawing_BitmapBuild(OH_Drawing_Bitmap* cBitmap, const uint32_t width, const uint32_t height,
    const OH_Drawing_BitmapFormat* cBitmapFormat)
{
    Bitmap* bitmap = CastToBitmap(cBitmap);
    if (bitmap == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    ColorType colorType = CColorFormatCastToColorType(cBitmapFormat->colorFormat);
    AlphaType alphaType = CAlphaFormatCastToAlphaType(cBitmapFormat->alphaFormat);

    BitmapFormat format { colorType, alphaType };
    bitmap->Build(width, height, format);
}

uint32_t OH_Drawing_BitmapGetWidth(OH_Drawing_Bitmap* cBitmap)
{
    Bitmap* bitmap = CastToBitmap(cBitmap);
    if (bitmap == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return 0;
    }
    return bitmap->GetWidth();
}

uint32_t OH_Drawing_BitmapGetHeight(OH_Drawing_Bitmap* cBitmap)
{
    Bitmap* bitmap = CastToBitmap(cBitmap);
    if (bitmap == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return 0;
    }
    return bitmap->GetHeight();
}

OH_Drawing_ColorFormat OH_Drawing_BitmapGetColorFormat(OH_Drawing_Bitmap* cBitmap)
{
    Bitmap* bitmap = CastToBitmap(cBitmap);
    if (bitmap == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return COLOR_FORMAT_UNKNOWN;
    }
    return ColorFormatCastToCColorType(bitmap->GetColorType());
}

OH_Drawing_AlphaFormat OH_Drawing_BitmapGetAlphaFormat(OH_Drawing_Bitmap* cBitmap)
{
    Bitmap* bitmap = CastToBitmap(cBitmap);
    if (bitmap == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return ALPHA_FORMAT_UNKNOWN;
    }
    return AlphaFormatCastToCAlphaType(bitmap->GetAlphaType());
}
void* OH_Drawing_BitmapGetPixels(OH_Drawing_Bitmap* cBitmap)
{
    Bitmap* bitmap = CastToBitmap(cBitmap);
    if (bitmap == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return nullptr;
    }
    return bitmap->GetPixels();
}

void OH_Drawing_BitmapGetImageInfo(OH_Drawing_Bitmap* cBitmap, OH_Drawing_Image_Info* cImageInfo)
{
    if (cBitmap == nullptr || cImageInfo == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    ImageInfo imageInfo = CastToBitmap(cBitmap)->GetImageInfo();

    cImageInfo->width = imageInfo.GetWidth();
    cImageInfo->height = imageInfo.GetHeight();
    cImageInfo->colorType = static_cast<OH_Drawing_ColorFormat>(imageInfo.GetColorType());
    cImageInfo->alphaType = static_cast<OH_Drawing_AlphaFormat>(imageInfo.GetAlphaType());
}

bool OH_Drawing_BitmapReadPixels(OH_Drawing_Bitmap* cBitmap, const OH_Drawing_Image_Info* dstInfo,
    void* dstPixels, size_t dstRowBytes, int32_t srcX, int32_t srcY)
{
    if (cBitmap == nullptr || dstInfo == nullptr || dstPixels == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return false;
    }

    ImageInfo imageInfo(dstInfo->width, dstInfo->height,
        static_cast<ColorType>(dstInfo->colorType), static_cast<AlphaType>(dstInfo->alphaType));

    return CastToBitmap(cBitmap)->ReadPixels(imageInfo, dstPixels, dstRowBytes, srcX, srcY);
}
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

#ifndef TEXT_BLOB_H
#define TEXT_BLOB_H

#include <cstdint>
#include <memory>

#include "draw/path.h"
#include "impl_interface/text_blob_impl.h"
#include "text/font.h"
#include "text/font_types.h"
#include "text/rs_xform.h"
#include "utils/data.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
class DRAWING_API TextBlob {
public:
    explicit TextBlob(std::shared_ptr<TextBlobImpl> textBlobImpl) noexcept;
    virtual ~TextBlob() = default;

    static std::shared_ptr<TextBlob> MakeFromText(const void* text, size_t byteLength,
        const Font& font, TextEncoding encoding = TextEncoding::UTF8);
    static std::shared_ptr<TextBlob> MakeFromPosText(const void* text, size_t byteLength,
        const Point pos[], const Font& font, TextEncoding encoding = TextEncoding::UTF8);
    static std::shared_ptr<TextBlob> MakeFromString(const char* str,
        const Font& font, TextEncoding encoding = TextEncoding::UTF8);
    static std::shared_ptr<TextBlob> MakeFromRSXform(const void* text, size_t byteLength,
        const RSXform xform[], const Font& font, TextEncoding encoding = TextEncoding::UTF8);

    /**
     * @brief   Serialize TextBlob.
     * @param ctx  Serialize context.
     * @return  A shared point to serialized data.
     */
    std::shared_ptr<Data> Serialize(void* ctx) const;

    /**
     * @brief       Deserialize TextBlob.
     * @param data  Serialized data.
     * @param size  Data size.
     * @param ctx   Deserialize context.
     * @return      A shared point to deserialized data.
     */
    static std::shared_ptr<TextBlob> Deserialize(const void* data, size_t size, void* ctx);
    static void GetDrawingGlyphIDforTextBlob(const TextBlob* blob, std::vector<uint16_t>& glyphIds);
    static Path GetDrawingPathforTextBlob(uint16_t glyphId, const TextBlob* blob);
    static void GetDrawingPointsForTextBlob(const TextBlob* blob, std::vector<Point>& points);

    template<typename T>
    T* GetImpl() const
    {
        if (textBlobImpl_) {
            return textBlobImpl_->DowncastingTo<T>();
        }
        return nullptr;
    }

    std::shared_ptr<Rect> Bounds() const;

    uint32_t UniqueID() const;

    class Context {
    public:
        explicit Context(std::shared_ptr<Typeface> typeface, bool isCustomTypeface) noexcept
            : typeface_(typeface), isCustomTypeface_(isCustomTypeface) {}

        std::shared_ptr<Typeface>& GetTypeface()
        {
            return typeface_;
        }

        void SetTypeface(std::shared_ptr<Typeface> typeface)
        {
            typeface_ = typeface;
        }

        bool IsCustomTypeface()
        {
            return isCustomTypeface_;
        }

        void SetIsCustomTypeface(bool isCustomTypeface)
        {
            isCustomTypeface_ = isCustomTypeface;
        }
    private:
        std::shared_ptr<Typeface> typeface_ = nullptr;
        bool isCustomTypeface_ = false;
    };

private:
    std::shared_ptr<TextBlobImpl> textBlobImpl_;
};
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS
#endif
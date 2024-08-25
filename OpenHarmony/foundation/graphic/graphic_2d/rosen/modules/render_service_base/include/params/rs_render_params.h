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

#ifndef RENDER_SERVICE_BASE_PARAMS_RS_RENDER_PARAMS_H
#define RENDER_SERVICE_BASE_PARAMS_RS_RENDER_PARAMS_H

#include "common/rs_common_def.h"
#include "common/rs_rect.h"
#include "property/rs_properties.h"
#include "utils/matrix.h"

namespace OHOS::Rosen {
#define RENDER_BASIC_PARAM_TO_STRING(basicType) (std::string(#basicType "[") + std::to_string(basicType) + "] ")
#define RENDER_RECT_PARAM_TO_STRING(rect) (std::string(#rect "[") + (rect).ToString() + "] ")
#define RENDER_PARAM_TO_STRING(param) (std::string(#param "[") + (param).ToString() + "] ")

struct DirtyRegionInfoForDFX {
    RectI oldDirty;
    RectI oldDirtyInSurface;
    bool operator==(const DirtyRegionInfoForDFX& rhs) const
    {
        return oldDirty == rhs.oldDirty && oldDirtyInSurface == rhs.oldDirtyInSurface;
    }
};

class RSB_EXPORT RSRenderParams {
public:
    RSRenderParams(NodeId id) : id_(id) {}
    virtual ~RSRenderParams() = default;

    void SetAlpha(float alpha);
    float GetAlpha() const;

    void SetAlphaOffScreen(bool alphaOffScreen);
    bool GetAlphaOffScreen() const;

    void SetMatrix(const Drawing::Matrix& matrix);
    const Drawing::Matrix& GetMatrix() const;

    void ApplyAlphaAndMatrixToCanvas(RSPaintFilterCanvas& canvas) const;

    void SetBoundsRect(const Drawing::RectF& boundsRect);
    const Drawing::Rect& GetBounds() const;

    void SetFrameRect(const Drawing::RectF& frameRect);
    const Drawing::Rect& GetFrameRect() const;

    // return to add some dirtynode does not mark pending
    bool SetLocalDrawRect(const RectF& localDrawRect);
    const RectF& GetLocalDrawRect() const;
    virtual bool IsNeedProcess() const { return false; };

    void SetHasSandBox(bool hasSandBox);
    bool HasSandBox() const;

    bool GetShouldPaint() const;
    void SetShouldPaint(bool shouldPaint);
    void SetContentEmpty(bool empty);

    bool NeedSync() const;
    void SetNeedSync(bool needSync);

    const std::shared_ptr<RSFilter>& GetForegroundFilterCache() const;
    void SetForegroundFilterCache(const std::shared_ptr<RSFilter>& foregroundFilterCache);

    inline NodeId GetId() const
    {
        return id_;
    }

    Gravity GetFrameGravity() const
    {
        return frameGravity_;
    }

    void SetFrameGravity(Gravity gravity);

    inline bool IsSecurityLayer() const
    {
        return isSecurityLayer_;
    }

    inline bool IsSkipLayer() const
    {
        return isSkipLayer_;
    }

    inline bool IsLayerDirty() const
    {
        return dirtyType_.test(RSRenderParamsDirtyType::LAYER_INFO_DIRTY);
    }

    void SetChildHasVisibleFilter(bool val);
    bool ChildHasVisibleFilter() const;
    void SetChildHasVisibleEffect(bool val);
    bool ChildHasVisibleEffect() const;

    void SetCacheSize(Vector2f size);
    Vector2f GetCacheSize() const;

    void SetDrawingCacheChanged(bool isChanged, bool lastFrameSynced);
    bool GetDrawingCacheChanged() const;

    void SetDrawingCacheType(RSDrawingCacheType cacheType);
    RSDrawingCacheType GetDrawingCacheType() const;

    void OpincUpdateRootFlag(bool suggestFlag);
    bool OpincGetRootFlag() const;
    void OpincSetCacheChangeFlag(bool state);
    bool OpincGetCacheChangeState();
    bool OpincGetCachedMark();
    void OpincSetCachedMark(bool mark);

    void SetDrawingCacheIncludeProperty(bool includeProperty);
    bool GetDrawingCacheIncludeProperty() const;

    void SetShadowRect(Drawing::Rect rect);
    Drawing::Rect GetShadowRect() const;

    void SetDirtyRegionInfoForDFX(DirtyRegionInfoForDFX dirtyRegionInfo);
    DirtyRegionInfoForDFX GetDirtyRegionInfoForDFX() const;

    // One-time trigger, needs to be manually reset false in main/RT thread after each sync operation
    void OnCanvasDrawingSurfaceChange(const std::unique_ptr<RSRenderParams>& target);
    bool GetCanvasDrawingSurfaceChanged() const;
    void SetCanvasDrawingSurfaceChanged(bool changeFlag);

    // disable copy and move
    RSRenderParams(const RSRenderParams&) = delete;
    RSRenderParams(RSRenderParams&&) = delete;
    RSRenderParams& operator=(const RSRenderParams&) = delete;
    RSRenderParams& operator=(RSRenderParams&&) = delete;

    virtual void OnSync(const std::unique_ptr<RSRenderParams>& target);

    // dfx
    virtual std::string ToString() const;

    static void SetParentSurfaceMatrix(const Drawing::Matrix& parentSurfaceMatrix);
    static const Drawing::Matrix& GetParentSurfaceMatrix();

protected:
    bool needSync_ = false;
    std::bitset<RSRenderParamsDirtyType::MAX_DIRTY_TYPE> dirtyType_;

private:
    NodeId id_;
    Drawing::Matrix matrix_;
    Drawing::RectF boundsRect_;
    Drawing::RectF frameRect_;
    float alpha_ = 1.0f;
    // this rect should map display coordination
    RectF localDrawRect_;
    Vector2f cacheSize_;
    Gravity frameGravity_ = Gravity::CENTER;

    bool childHasVisibleEffect_ = false;
    bool childHasVisibleFilter_ = false;
    bool hasSandBox_ = false;
    bool isDrawingCacheChanged_ = false;
    bool drawingCacheIncludeProperty_ = false;
    bool isSecurityLayer_ = false;
    bool isSkipLayer_ = false;
    bool shouldPaint_ = false;
    bool contentEmpty_  = false;
    bool canvasDrawingNodeSurfaceChanged_ = false;
    bool alphaOffScreen_ = false;
    Drawing::Rect shadowRect_;
    RSDrawingCacheType drawingCacheType_ = RSDrawingCacheType::DISABLED_CACHE;
    DirtyRegionInfoForDFX dirtyRegionInfoForDFX_;
    std::shared_ptr<RSFilter> foregroundFilterCache_ = nullptr;
    bool isOpincRootFlag_ = false;
    bool isOpincStateChanged_ = false;
    bool isOpincMarkCached_ = false;
};
} // namespace OHOS::Rosen
#endif // RENDER_SERVICE_BASE_PARAMS_RS_RENDER_PARAMS_H

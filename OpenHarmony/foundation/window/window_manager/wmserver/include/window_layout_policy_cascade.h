/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_ROSEN_WINDOW_LAYOUT_POLICY_CASCADE_H
#define OHOS_ROSEN_WINDOW_LAYOUT_POLICY_CASCADE_H

#include <map>
#include <refbase.h>
#include <set>

#include "window_layout_policy.h"
#include "window_node.h"
#include "wm_common.h"

namespace OHOS {
namespace Rosen {
class WindowLayoutPolicyCascade : public WindowLayoutPolicy {
public:
    WindowLayoutPolicyCascade() = delete;
    WindowLayoutPolicyCascade(DisplayGroupWindowTree& displayGroupWindowTree);
    ~WindowLayoutPolicyCascade() = default;
    void Launch() override;
    void Reorder() override;
    Rect GetDividerRect(DisplayId displayId) const override;
    void SetSplitDividerWindowRects(std::map<DisplayId, Rect> dividerWindowRects) override;
    void PerformWindowLayout(const sptr<WindowNode>& node, WindowUpdateType updateType) override;
    void GetMaximizeRect(const sptr<WindowNode>& node, Rect& maxRect) override;

private:
    /*
     * methods for calculate cascadeRect and splitRect
     */
    void InitAllRects();
    void InitSplitRects(DisplayId displayId);
    void SetSplitRectByDivider(const Rect& divRect, DisplayId displayId);
    void SetInitialDividerRect(const sptr<WindowNode>& node, DisplayId displayId);
    void InitCascadeRect(DisplayId displayId);
    void SetDefaultCascadeRect(const sptr<WindowNode>& node);
    Rect StepCascadeRect(Rect rect, DisplayId displayId) const;
    Rect GetCurCascadeRect(const sptr<WindowNode>& node) const;

    // methods for limit divider position by display and split ratio
    void UpdateDividerPosition(const sptr<WindowNode>& node) const;
    void LimitDividerInDisplayRegion(Rect& rect, DisplayId displayId) const;
    void LimitDividerPositionBySplitRatio(DisplayId displayId, Rect& winRect) const;

    /*
     * methods for calculate window rect
     */
    void LayoutDivider(const sptr<WindowNode>& node, WindowUpdateType type);
    void LayoutSplitNodes(DisplayId displayId, WindowUpdateType type, bool layoutByDivider = false);
    void UpdateLayoutRect(const sptr<WindowNode>& node) override;
    void ComputeDecoratedRequestRect(const sptr<WindowNode>& node) const;
    void ApplyWindowRectConstraints(const sptr<WindowNode>& node, Rect& winRect) const;
    void ComputeRectByAspectRatio(const sptr<WindowNode>& node) const;
    bool CheckAspectRatioBySizeLimits(const sptr<WindowNode>& node, WindowSizeLimits& newLimits) const;

    /*
     * methods for floating window limitSize and position
     */
    DockWindowShowState GetDockWindowShowState(DisplayId displayId, Rect& dockWinRect) const;
    void LimitFloatingWindowSize(const sptr<WindowNode>& node, Rect& winRect) const;
    void LimitMainFloatingWindowPosition(const sptr<WindowNode>& node, Rect& winRect) const;
    void UpdateFloatingWindowSizeForStretchableWindow(const sptr<WindowNode>& node,
        const Rect& displayRect, Rect& winRect) const;
    void UpdateFloatingWindowSizeBySizeLimits(const sptr<WindowNode>& node,
        const Rect& displayRect, Rect& winRect) const;
    void LimitWindowPositionWhenInitRectOrMove(const sptr<WindowNode>& node, Rect& winRect) const;
    void LimitWindowPositionWhenDrag(const sptr<WindowNode>& node, Rect& winRect) const;
    void FixWindowSizeByRatioIfDragBeyondLimitRegion(const sptr<WindowNode>& node, Rect& winRect) const;
    void FixWindowRectWhenDrag(const sptr<WindowNode>& node, const Rect& oriWinRect, Rect& winRect) const;

    /*
     * Layout preprocess:
     * 1) Set default cascade rect if rect is empty
     * 2) Get aspect ratio form persistent storage
     * 3) Fix rect within display region
     */
    void LayoutPreProcess(const sptr<WindowNode>& node, WindowUpdateType updateType);

    struct CascadeRects {
        Rect primaryRect_;
        Rect secondaryRect_;
        Rect dividerRect_;
        Rect defaultCascadeRect_;
    };
    mutable std::map<DisplayId, CascadeRects> cascadeRectsMap_;
    std::map<DisplayId, Rect> restoringDividerWindowRects_;
};
}
}
#endif // OHOS_ROSEN_WINDOW_LAYOUT_POLICY_CASCADE_H

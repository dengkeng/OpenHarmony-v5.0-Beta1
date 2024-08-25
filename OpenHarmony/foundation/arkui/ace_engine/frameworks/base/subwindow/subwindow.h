/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_ACE_FRAMEWORKS_BASE_SUBWINDOW_SUBWINDOW_H
#define FOUNDATION_ACE_FRAMEWORKS_BASE_SUBWINDOW_SUBWINDOW_H

#include <set>

#include "base/geometry/ng/rect_t.h"
#include "base/memory/ace_type.h"
#include "base/memory/referenced.h"
#include "core/components/dialog/dialog_properties.h"
#include "core/components_ng/base/frame_node.h"
#include "core/components_ng/pattern/overlay/overlay_manager.h"
#include "core/components_ng/property/menu_property.h"
#include "core/pipeline/base/component.h"

namespace OHOS::Ace {

class ACE_EXPORT Subwindow : public AceType {
    DECLARE_ACE_TYPE(Subwindow, AceType)

public:
    static RefPtr<Subwindow> CreateSubwindow(int32_t instanceId);

    virtual void InitContainer() = 0;
    virtual void ResizeWindow() = 0;
    virtual NG::RectF GetRect() = 0;
    virtual void ShowMenu(const RefPtr<Component>& newComponent) = 0;
    virtual void ShowMenuNG(const RefPtr<NG::FrameNode> menuNode, const NG::MenuParam& menuParam,
        const RefPtr<NG::FrameNode>& targetNode, const NG::OffsetF& offset) = 0;
    virtual void ShowMenuNG(std::function<void()>&& buildFunc, std::function<void()>&& previewBuildFunc,
        const NG::MenuParam& menuParam, const RefPtr<NG::FrameNode>& targetNode, const NG::OffsetF& offset) = 0;
    virtual bool ShowPreviewNG() = 0;
    virtual void HidePreviewNG() = 0;
    virtual void HideMenuNG(const RefPtr<NG::FrameNode>& menu, int32_t targetId) = 0;
    virtual void HideMenuNG(bool showPreviewAnimation = true, bool startDrag = false) = 0;
    virtual void UpdateHideMenuOffsetNG(const NG::OffsetF& offset = NG::OffsetF(0.0f, 0.0f)) = 0;
    virtual void ShowPopup(const RefPtr<Component>& newComponent, bool disableTouchEvent = true) = 0;
    virtual void ShowPopupNG(int32_t targetId, const NG::PopupInfo& popupInfo) = 0;
    virtual void HidePopupNG(int32_t targetId) = 0;
    virtual void GetPopupInfoNG(int32_t targetId, NG::PopupInfo& popupInfo) = 0;
    virtual bool CancelPopup(const std::string& id) = 0;
    virtual void CloseMenu() = 0;
    virtual void ClearMenu() {};
    virtual void ClearMenuNG(int32_t targetId = -1, bool inWindow = true, bool showAnimation = false) = 0;
    virtual void ClearPopupNG() = 0;
    virtual RefPtr<NG::FrameNode> ShowDialogNG(
        const DialogProperties& dialogProps, std::function<void()>&& buildFunc) = 0;
    virtual RefPtr<NG::FrameNode> ShowDialogNGWithNode(
        const DialogProperties& dialogProps, const RefPtr<NG::UINode>& customNode) = 0;
    virtual void CloseDialogNG(const RefPtr<NG::FrameNode>& dialogNode) = 0;
    virtual void OpenCustomDialogNG(const DialogProperties& dialogProps, std::function<void(int32_t)>&& callback) = 0;
    virtual void CloseCustomDialogNG(int32_t dialogId) = 0;
    virtual void CloseCustomDialogNG(const WeakPtr<NG::UINode>& node, std::function<void(int32_t)>&& callback) = 0;
    virtual void UpdateCustomDialogNG(const WeakPtr<NG::UINode>& node, const DialogProperties& dialogProps,
        std::function<void(int32_t)>&& callback) = 0;
    virtual void HideSubWindowNG() = 0;
    virtual int32_t GetChildContainerId() const = 0;
    virtual bool GetShown() = 0;
    virtual void MarkDirtyDialogSafeArea() = 0;

    // Add interface for hot regions
    virtual void SetHotAreas(const std::vector<Rect>& rects, int32_t nodeId) {};
    virtual void DeleteHotAreas(int32_t nodeId) {};

    // Add interface to provide the size and offset of the parent window
    virtual Rect GetParentWindowRect() const = 0;
    virtual Rect GetUIExtensionHostWindowRect() const = 0;
    virtual bool CheckHostWindowStatus() const = 0;

    int32_t GetSubwindowId() const
    {
        return subwindowId_;
    }

    void SetSubwindowId(int32_t id)
    {
        subwindowId_ = id;
    }

    int32_t GetUIExtensionHostWindowId() const
    {
        return uiExtensionHostWindowId_;
    }

    void SetUIExtensionHostWindowId(int32_t id)
    {
        uiExtensionHostWindowId_ = id;
    }

    void SetAboveApps(bool isAboveApps)
    {
        isAboveApps_ = isAboveApps;
    }

    bool GetAboveApps() const
    {
        return isAboveApps_;
    }

    virtual void ClearToast() = 0;
    virtual void ShowToast(const std::string& message, int32_t duration, const std::string& bottom,
        const NG::ToastShowMode& showMode, int32_t alignment, std::optional<DimensionOffset> offset) = 0;
    virtual void ShowDialog(const std::string& title, const std::string& message,
        const std::vector<ButtonInfo>& buttons, bool autoCancel, std::function<void(int32_t, int32_t)>&& callback,
        const std::set<std::string>& callbacks) = 0;
    virtual void ShowDialog(const PromptDialogAttr& dialogAttr, const std::vector<ButtonInfo>& buttons,
        std::function<void(int32_t, int32_t)>&& callback, const std::set<std::string>& callbacks) = 0;
    virtual void ShowActionMenu(const std::string& title, const std::vector<ButtonInfo>& button,
        std::function<void(int32_t, int32_t)>&& callback) = 0;
    virtual void CloseDialog(int32_t instanceId) = 0;
    virtual void OpenCustomDialog(const PromptDialogAttr& dialogAttr, std::function<void(int32_t)>&& callback) = 0;
    virtual void CloseCustomDialog(const int32_t dialogId) = 0;
    virtual void CloseCustomDialog(const WeakPtr<NG::UINode>& node, std::function<void(int32_t)> &&callback) = 0;
    virtual const RefPtr<NG::OverlayManager> GetOverlayManager() = 0;
    virtual bool IsFocused() = 0;
    virtual void RequestFocus() = 0;
    virtual void ResizeWindowForFoldStatus() = 0;
    virtual void ResizeWindowForFoldStatus(int32_t parentContainerId) = 0;

private:
    int32_t subwindowId_ = 0;
    int32_t uiExtensionHostWindowId_ = 0;
    bool isAboveApps_ = false;
};

} // namespace OHOS::Ace

#endif // FOUNDATION_ACE_FRAMEWORKS_BASE_SUBWINDOW_SUBWINDOW_H

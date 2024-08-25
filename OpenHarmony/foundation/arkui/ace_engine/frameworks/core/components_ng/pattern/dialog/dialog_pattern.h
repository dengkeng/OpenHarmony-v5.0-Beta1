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

#ifndef FOUNDATION_ACE_FRAMEWORKS_CORE_COMPONENTS_NG_PATTERNS_DIALOG_DIALOG_PATTERN_H
#define FOUNDATION_ACE_FRAMEWORKS_CORE_COMPONENTS_NG_PATTERNS_DIALOG_DIALOG_PATTERN_H

#include <cstdint>

#include "base/geometry/ng/offset_t.h"
#include "base/geometry/ng/size_t.h"
#include "base/memory/ace_type.h"
#include "base/memory/referenced.h"
#include "core/components/dialog/dialog_properties.h"
#include "core/components/dialog/dialog_theme.h"
#include "core/components_ng/manager/focus/focus_view.h"
#include "core/components_ng/pattern/dialog//dialog_event_hub.h"
#include "core/components_ng/pattern/dialog/dialog_accessibility_property.h"
#include "core/components_ng/pattern/dialog/dialog_layout_algorithm.h"
#include "core/components_ng/pattern/dialog/dialog_layout_property.h"
#include "core/components_ng/pattern/overlay/popup_base_pattern.h"

namespace OHOS::Ace::NG {
class InspectorFilter;

enum class DialogContentNode {
    TITLE = 0,
    SUBTITLE,
    MESSAGE,
    SHEET,
};
enum class DialogDismissReason {
    DIALOG_PRESS_BACK = 0,
    DIALOG_TOUCH_OUTSIDE,
    DIALOG_CLOSE_BUTTON,
};
class DialogPattern : public PopupBasePattern, public FocusView {
    DECLARE_ACE_TYPE(DialogPattern, PopupBasePattern, FocusView);

public:
    DialogPattern(const RefPtr<DialogTheme>& dialogTheme, const RefPtr<UINode>& customNode)
        : dialogTheme_(dialogTheme), customNode_(customNode)
    {}
    ~DialogPattern() override = default;

    bool IsAtomicNode() const override
    {
        return false;
    }

    void SetOnWillDismiss(const std::function<void(const int32_t& info)>& onWillDismiss)
    {
        onWillDismiss_ = onWillDismiss;
    }

    bool ShouldDismiss() const
    {
        if (onWillDismiss_) {
            return true;
        }
        return false;
    }

    void CallOnWillDismiss(const int32_t reason)
    {
        if (onWillDismiss_) {
            onWillDismiss_(reason);
        }
    }

    RefPtr<LayoutProperty> CreateLayoutProperty() override
    {
        return AceType::MakeRefPtr<DialogLayoutProperty>();
    }

    RefPtr<LayoutAlgorithm> CreateLayoutAlgorithm() override
    {
        return AceType::MakeRefPtr<DialogLayoutAlgorithm>();
    }

    RefPtr<EventHub> CreateEventHub() override
    {
        return MakeRefPtr<DialogEventHub>();
    }

    RefPtr<AccessibilityProperty> CreateAccessibilityProperty() override
    {
        return MakeRefPtr<DialogAccessibilityProperty>();
    }

    FocusPattern GetFocusPattern() const override
    {
        return { FocusType::SCOPE, true };
    }

    std::list<int32_t> GetRouteOfFirstScope() override
    {
        return { 0, 0 };
    }

    void BuildChild(const DialogProperties& dialogProperties);

    void ToJsonValue(std::unique_ptr<JsonValue>& json, const InspectorFilter& filter) const override;

    const std::string& GetTitle()
    {
        return title_;
    }

    const std::string& GetSubtitle()
    {
        return subtitle_;
    }

    const std::string& GetMessage()
    {
        return message_;
    }

    RefPtr<UINode> GetCustomNode()
    {
        return customNode_.Upgrade();
    }

    void SetOpenAnimation(const std::optional<AnimationOption>& openAnimation)
    {
        openAnimation_ = openAnimation;
    }
    std::optional<AnimationOption> GetOpenAnimation() const
    {
        return openAnimation_;
    }

    void SetCloseAnimation(const std::optional<AnimationOption>& closeAnimation)
    {
        closeAnimation_ = closeAnimation;
    }
    std::optional<AnimationOption> GetCloseAnimation() const
    {
        return closeAnimation_;
    }

    void SetDialogProperties(const DialogProperties& param)
    {
        dialogProperties_ = param;
        InitHostWindowRect();
    }

    const DialogProperties& GetDialogProperties() const
    {
        return dialogProperties_;
    }

    void OnColorConfigurationUpdate() override;

    void OnLanguageConfigurationUpdate() override;

    void DumpInfo() override;

    bool AvoidBottom() const override
    {
        return false;
    }

    void RegisterDialogDidAppearCallback(std::function<void()>&& onDidAppear)
    {
        onDidAppearCallback_ = std::move(onDidAppear);
    }

    void RegisterDialogDidDisappearCallback(std::function<void()>&& onDidDisappear)
    {
        onDidDisappearCallback_ = std::move(onDidDisappear);
    }

    void RegisterDialogWillAppearCallback(std::function<void()>&& onWillAppear)
    {
        onWillAppearCallback_ = std::move(onWillAppear);
    }

    void RegisterDialogWillDisappearCallback(std::function<void()>&& onWillDisappear)
    {
        onWillDisappearCallback_ = std::move(onWillDisappear);
    }

    void CallDialogDidAppearCallback()
    {
        if (onDidAppearCallback_) {
            onDidAppearCallback_();
        }
    }

    void CallDialogDidDisappearCallback()
    {
        if (onDidDisappearCallback_) {
            onDidDisappearCallback_();
        }
    }

    void CallDialogWillAppearCallback()
    {
        if (onWillAppearCallback_) {
            onWillAppearCallback_();
        }
    }

    void CallDialogWillDisappearCallback()
    {
        if (onWillDisappearCallback_) {
            onWillDisappearCallback_();
        }
    }

    bool IsUIExtensionSubWindow() const
    {
        return isUIExtensionSubWindow_;
    }

    RectF GetHostWindowRect() const
    {
        return hostWindowRect_;
    }

private:
    bool AvoidKeyboard() const override
    {
        return false;
    }
    void OnModifyDone() override;

    void OnAttachToFrameNode() override;
    void OnDetachFromFrameNode(FrameNode* frameNode) override;
    void OnWindowSizeChanged(int32_t width, int32_t height, WindowSizeChangeReason type) override;
    void InitHostWindowRect();
    void InitClickEvent(const RefPtr<GestureEventHub>& gestureHub);
    void HandleClick(const GestureEvent& info);
    void RegisterOnKeyEvent(const RefPtr<FocusHub>& focusHub);
    bool OnKeyEvent(const KeyEvent& event);
    void InitFocusEvent(const RefPtr<FocusHub>& focusHub);
    void HandleBlurEvent();
    void HandleFocusEvent();

    void PopDialog(int32_t buttonIdx);

    // set render context properties of content frame
    void UpdateContentRenderContext(const RefPtr<FrameNode>& contentNode, const DialogProperties& props);
    void UpdateBgBlurStyle(const RefPtr<RenderContext>& contentRenderContext, const DialogProperties& props);
    RefPtr<FrameNode> BuildMainTitle(const DialogProperties& dialogProperties);
    void CreateTitleRowNode(const DialogProperties& dialogProperties, PaddingProperty& titlePadding);
    RefPtr<FrameNode> BuildSubTitle(const DialogProperties& dialogProperties);
    void ParseButtonFontColorAndBgColor(
        const ButtonInfo& params, std::string& textColor, std::optional<Color>& bgColor);
    void SetButtonEnabled(const RefPtr<FrameNode>& buttonNode, bool enabled);
    // update wrapperNode background style
    void UpdateWrapperBackgroundStyle(const RefPtr<FrameNode>& host, const RefPtr<DialogTheme>& dialogTheme);
    RefPtr<FrameNode> BuildTitle(const DialogProperties& dialogProperties);
    RefPtr<FrameNode> BuildContent(const DialogProperties& dialogProperties);
    RefPtr<FrameNode> CreateDialogScroll(const DialogProperties& dialogProps);

    void UpdateDialogButtonProperty(RefPtr<FrameNode>& buttonNode, int32_t index, bool isVertical, int32_t length);
    RefPtr<FrameNode> BuildButtons(const std::vector<ButtonInfo>& buttons, const DialogButtonDirection& direction);
    void AddButtonAndDivider(
        const std::vector<ButtonInfo>& buttons, const RefPtr<NG::FrameNode>& container, bool isVertical);
    RefPtr<FrameNode> CreateDivider(
        const Dimension& dividerLength, const Dimension& dividerWidth, const Color& color, const Dimension& space);
    RefPtr<FrameNode> CreateButton(
        const ButtonInfo& params, int32_t index, bool isCancel = false, bool isVertical = false, int32_t length = 0);
    RefPtr<FrameNode> CreateButtonText(const std::string& text, const std::string& colorStr);
    // to close dialog when button is clicked
    void BindCloseCallBack(const RefPtr<GestureEventHub>& hub, int32_t buttonIdx);
    // build ActionSheet items
    RefPtr<FrameNode> BuildSheet(const std::vector<ActionSheetInfo>& sheets);
    RefPtr<FrameNode> BuildSheetItem(const ActionSheetInfo& item);
    RefPtr<FrameNode> BuildSheetInfoTitle(const std::string& title);
    RefPtr<FrameNode> BuildSheetInfoIcon(const std::string& icon);
    // build actionMenu
    RefPtr<FrameNode> BuildMenu(const std::vector<ButtonInfo>& buttons, bool hasTitle);
    void RecordEvent(int32_t btnIndex) const;
    void ParseBorderRadius(BorderRadiusProperty& raidus);
    void UpdateSheetIconAndText();
    void UpdateButtonsProperty();
    void UpdateNodeContent(const RefPtr<FrameNode>& node, std::string& text);
    void DumpBoolProperty();
    void DumpObjectProperty();
    RefPtr<DialogTheme> dialogTheme_;
    WeakPtr<UINode> customNode_;
    RefPtr<ClickEvent> onClick_;

    std::optional<AnimationOption> openAnimation_;
    std::optional<AnimationOption> closeAnimation_;

    // XTS inspector values
    std::string message_;
    std::string title_;
    std::string subtitle_;
    std::function<void(const int32_t& info)> onWillDismiss_;

    DialogProperties dialogProperties_;
    WeakPtr<FrameNode> menuNode_;
    bool isFirstDefaultFocus_ = true;
    RefPtr<FrameNode> buttonContainer_;
    RefPtr<RenderContext> contentRenderContext_;

    ACE_DISALLOW_COPY_AND_MOVE(DialogPattern);

    std::function<void()> onDidAppearCallback_ = nullptr;
    std::function<void()> onDidDisappearCallback_ = nullptr;
    std::function<void()> onWillAppearCallback_ = nullptr;
    std::function<void()> onWillDisappearCallback_ = nullptr;
    std::unordered_map<DialogContentNode, RefPtr<FrameNode>> contentNodeMap_;
    bool isUIExtensionSubWindow_ = false;
    RectF hostWindowRect_;
};
} // namespace OHOS::Ace::NG

#endif // FOUNDATION_ACE_FRAMEWORKS_CORE_COMPONENTS_NG_PATTERNS_DIALOG_DIALOG_PATTERN_H

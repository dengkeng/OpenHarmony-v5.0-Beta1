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

#ifndef FOUNDATION_ACE_FRAMEWORKS_CORE_COMPONENTS_NG_PATTERNS_SEARCH_SEARCH_MODEL_H
#define FOUNDATION_ACE_FRAMEWORKS_CORE_COMPONENTS_NG_PATTERNS_SEARCH_SEARCH_MODEL_H

#include <mutex>

#include "core/components_ng/pattern/search/search_event_hub.h"
#include "core/components_ng/pattern/text_field/text_field_controller.h"

namespace OHOS::Ace {

class SearchModel {
public:
    static SearchModel* GetInstance();
    virtual ~SearchModel() = default;

    virtual RefPtr<TextFieldControllerBase> Create(const std::optional<std::string>& value,
        const std::optional<std::string>& placeholder, const std::optional<std::string>& icon);
    virtual void RequestKeyboardOnFocus(bool needToRequest) = 0;
    virtual void SetSearchButton(const std::string& text);
    virtual void SetCaretWidth(const Dimension& value);
    virtual void SetCaretColor(const Color& color);
    virtual void SetSearchIconSize(const Dimension& value);
    virtual void SetSearchIconColor(const Color& color);
    virtual void SetSearchSrcPath(const std::string& src, const std::string& bundleName, const std::string& moduleName);
    virtual void SetRightIconSrcPath(const std::string& src);
    virtual void SetCancelButtonStyle(CancelButtonStyle cancelButtonStyle);
    virtual void SetCancelIconSize(const Dimension& value);
    virtual void SetCancelIconColor(const Color& color);
    virtual void SetSearchButtonFontSize(const Dimension& value);
    virtual void SetSearchButtonFontColor(const Color& color);
    virtual void SetPlaceholderColor(const Color& color);
    virtual void SetPlaceholderFont(const Font& font);
    virtual void SetTextFont(const Font& font);
    virtual void SetTextColor(const Color& color);
    virtual void SetTextAlign(const TextAlign& textAlign);
    virtual void SetCopyOption(const CopyOptions& copyOptions);
    virtual void SetMenuOptionItems(std::vector<NG::MenuOptionsParam>&& menuOptionsItems) = 0;
    virtual void SetFocusable(bool focusable) {};
    virtual void SetFocusNode(bool isFocusNode) {};
    virtual void SetHeight(const Dimension& height);
    virtual void SetBackBorder() {};
    virtual void SetOnSubmit(std::function<void(const std::string&)>&& onSubmit);
    virtual void SetOnChange(std::function<void(const std::string&)>&& onChange);
    virtual void SetOnTextSelectionChange(std::function<void(int32_t, int32_t)>&& func) = 0;
    virtual void SetOnScroll(std::function<void(float, float)>&& func) = 0;
    virtual void SetOnCopy(std::function<void(const std::string&)>&& func);
    virtual void SetOnCut(std::function<void(const std::string&)>&& func);
    virtual void SetOnPaste(std::function<void(const std::string&)>&& func);
    virtual void SetOnPasteWithEvent(std::function<void(const std::string&, NG::TextCommonEvent&)>&& func);
    virtual void SetOnChangeEvent(std::function<void(const std::string&)>&& onChangeEvent);
    virtual void SetSelectionMenuHidden(bool selectionMenuHidden) = 0;
    virtual void SetCustomKeyboard(const std::function<void ()> &&buildFunc, bool supportAvoidance = false);
    virtual void SetSearchEnterKeyType(TextInputAction value);
    virtual void SetMaxLength(uint32_t value);
    virtual void ResetMaxLength();
    virtual void SetType(TextInputType value);
    virtual void SetLetterSpacing(const Dimension& value) {};
    virtual void SetLineHeight(const Dimension& value) {};
    virtual void SetAdaptMinFontSize(const Dimension& value) {};
    virtual void SetAdaptMaxFontSize(const Dimension& value) {};
    virtual void SetTextDecoration(Ace::TextDecoration value) {};
    virtual void SetTextDecorationColor(const Color& value) {};
    virtual void SetTextDecorationStyle(Ace::TextDecorationStyle value) {};
    virtual void SetFontFeature(const std::list<std::pair<std::string, int32_t>>& value) = 0;
    virtual void UpdateInspectorId(const std::string& key) {};
    virtual void SetDragPreviewOptions(const NG::DragPreviewOption option) {};
    virtual void SetSelectedBackgroundColor(const Color& value) {};

    virtual void SetInputFilter(const std::string& value, const std::function<void(const std::string&)>& onError) {};
    virtual void SetOnEditChanged(std::function<void(bool)>&& func) {};
    virtual void SetTextIndent(const Dimension& value) {};
private:
    static std::unique_ptr<SearchModel> instance_;
    static std::mutex mutex_;
};

} // namespace OHOS::Ace

#endif // FOUNDATION_ACE_FRAMEWORKS_CORE_COMPONENTS_NG_PATTERNS_SEARCH_SEARCH_MODEL_H

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

#ifndef VIEW_PROXY_H
#define VIEW_PROXY_H

#include <memory>
#include <string>
#include <type_traits>
#include "component/component_factory.h"
#include "components/ui_view.h"
#include "log/log.h"

namespace Updater {
class ViewProxy final {
public:
    ViewProxy() = default;
    ViewProxy(std::unique_ptr<ComponentInterface> view, const std::string &message)
        : view_(std::move(view)), errMsg_(message) { }
    explicit ViewProxy(std::unique_ptr<ComponentInterface> view) : view_(std::move(view)) { }
    ~ViewProxy() = default;
    OHOS::UIView *operator->() const
    {
        static OHOS::UIView dummy;
        if (view_ != nullptr) {
            return view_->GetOhosView();
        }
        return &dummy;
    }
    template<typename T = OHOS::UIView>
    T *As() const
    {
        std::string errMsg {};
        return As<T>(errMsg);
    }
    template<typename T, std::enable_if_t<IS_UPDATER_COMPONENT<T>>* = nullptr>
    T *As(std::string &errMsg) const
    {
        static T dummy;
        if (view_ == nullptr) {
            errMsg = errMsg_ + " view is null";
            return &dummy;
        }
        if (std::string(dummy.GetComponentType()) != view_->GetComponentType()) {
            errMsg = errMsg_ + " view's real type not matched";
            LOG(ERROR) << errMsg;
            return &dummy;
        }
        return static_cast<T *>(view_.get());
    }
    template<typename T = OHOS::UIView, std::enable_if_t<!IS_UPDATER_COMPONENT<T>>* = nullptr>
    T *As(std::string &errMsg) const
    {
        static T dummy;
        static_assert(std::is_base_of_v<OHOS::UIView, T>,
            "template argument should be a derived class of OHOS::UIView");
        if (view_ == nullptr) {
            errMsg = errMsg_ + " view is null";
            return &dummy;
        }
        OHOS::UIView *ohosView = view_->GetOhosView();
        if constexpr (std::is_same_v<OHOS::UIView, T>) {
            return ohosView;
        }
        if (dummy.GetViewType() != ohosView->GetViewType()) {
            errMsg = errMsg_ + " view's real type not matched";
            LOG(ERROR) << errMsg;
            return &dummy;
        }
        return static_cast<T *>(ohosView);
    }
private:
    std::unique_ptr<ComponentInterface> view_ {nullptr};
    std::string errMsg_ {};
};
} // namespace Updater
#endif

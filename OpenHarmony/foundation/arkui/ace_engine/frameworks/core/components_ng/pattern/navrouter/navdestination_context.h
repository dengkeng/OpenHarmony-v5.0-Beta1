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

#ifndef FOUNDATION_ACE_FRAMEWORKS_CORE_COMPONENTS_NG_PATTERNS_NAVROUTER_NAVDESTINATION_CONTEXT_H
#define FOUNDATION_ACE_FRAMEWORKS_CORE_COMPONENTS_NG_PATTERNS_NAVROUTER_NAVDESTINATION_CONTEXT_H

#include <string>

#include "base/memory/ace_type.h"
#include "core/components_ng/pattern/navigation/navigation_stack.h"

namespace OHOS::Ace::NG {
class NavigationStack;
class NavPathInfo : public virtual AceType {
    DECLARE_ACE_TYPE(NavPathInfo, AceType)
public:
    NavPathInfo() = default;
    explicit NavPathInfo(const std::string& name) : name_(name) {}
    virtual ~NavPathInfo() = default;

    void SetName(const std::string& name)
    {
        name_ = name;
    }

    std::string GetName() const
    {
        return name_;
    }

    virtual napi_value GetParamObj() const
    {
        return nullptr;
    }

protected:
    std::string name_;
};

class NavDestinationContext : public virtual AceType {
    DECLARE_ACE_TYPE(NavDestinationContext, AceType)
public:
    NavDestinationContext() = default;
    virtual ~NavDestinationContext() = default;

    void SetNavPathInfo(RefPtr<NavPathInfo> info)
    {
        pathInfo_ = info;
    }

    RefPtr<NavPathInfo> GetNavPathInfo() const
    {
        return pathInfo_;
    }

    void SetNavigationStack(WeakPtr<NavigationStack> stack)
    {
        navigationStack_ = stack;
    }

    WeakPtr<NavigationStack> GetNavigationStack() const
    {
        return navigationStack_;
    }

    int32_t GetIndex() const
    {
        return index_;
    }

    void SetIndex(int32_t index)
    {
        index_ = index;
    }

    int32_t GetPreIndex() const
    {
        return preIndex_;
    }

    void SetPreIndex(int32_t index)
    {
        preIndex_ = index;
    }

    uint64_t GetNavDestinationId() const
    {
        return navDestinationId_;
    }

    void SetNavDestinationId(uint64_t id)
    {
        navDestinationId_ = id;
    }

    void SetIsEmpty(bool isEmpty)
    {
        isEmpty_ = isEmpty;
    }

    bool GetIsEmpty() const
    {
        return isEmpty_;
    }

protected:
    int32_t index_ = -1;
    int32_t preIndex_ = -1;
    uint64_t navDestinationId_ = 0;
    bool isEmpty_ = false;
    RefPtr<NavPathInfo> pathInfo_;
    WeakPtr<NavigationStack> navigationStack_;
};
} // namespace OHOS::Ace::NG

#endif // FOUNDATION_ACE_FRAMEWORKS_CORE_COMPONENTS_NG_PATTERNS_NAVROUTER_NAVDESTINATION_CONTEXT_H

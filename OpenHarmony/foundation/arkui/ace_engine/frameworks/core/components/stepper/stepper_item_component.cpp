/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "core/components/stepper/stepper_item_component.h"

#include "core/components/stepper/render_stepper_item.h"
#include "core/components/stepper/stepper_item_element.h"

namespace OHOS::Ace {

RefPtr<Element> StepperItemComponent::CreateElement()
{
    return AceType::MakeRefPtr<StepperItemElement>();
}

RefPtr<RenderNode> StepperItemComponent::CreateRenderNode()
{
    return RenderStepperItem::Create();
}

RefPtr<StepperItemComponent> StepperItemComponent::GetStepperItem(const RefPtr<Component>& component)
{
    // find stepperItem from composed component
    RefPtr<Component> item = component;
    while (item) {
        auto itemComponent = AceType::DynamicCast<StepperItemComponent>(item);
        if (itemComponent) {
            return itemComponent;
        }
        auto parent = AceType::DynamicCast<SingleChild>(item);
        if (!parent) {
            return nullptr;
        }
        item = parent->GetChild();
    }
    return nullptr;
}

} // namespace OHOS::Ace

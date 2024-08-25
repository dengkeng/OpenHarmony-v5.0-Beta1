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

#ifndef FOUNDATION_ACE_FRAMEWORKS_CORE_COMMON_DYNAMIC_COMPONENT_RENDERER_H
#define FOUNDATION_ACE_FRAMEWORKS_CORE_COMMON_DYNAMIC_COMPONENT_RENDERER_H

#include "interfaces/inner_api/ace/ui_content.h"

#include "base/memory/ace_type.h"
#include "core/components_ng/base/frame_node.h"

namespace OHOS::Ace::NG {

class DynamicComponentRenderer : public virtual AceType {
    DECLARE_ACE_TYPE(DynamicComponentRenderer, AceType);

public:
    DynamicComponentRenderer() = default;
    virtual ~DynamicComponentRenderer() = default;

    static RefPtr<DynamicComponentRenderer> Create(const RefPtr<FrameNode>& host, const std::string& hapPath,
        const std::string& abcPath, const std::string& entryPoint, void* runtime);

    virtual void CreateContent() = 0;
    virtual void DestroyContent() = 0;

    virtual void UpdateViewportConfig(const ViewportConfig& config, Rosen::WindowSizeChangeReason reason,
        const std::shared_ptr<Rosen::RSTransaction>& rsTransaction) = 0;

    virtual void TransferPointerEvent(const std::shared_ptr<MMI::PointerEvent>& pointerEvent) = 0;
    virtual void TransferKeyEvent(const std::shared_ptr<MMI::KeyEvent>& keyEvent) = 0;

private:
    ACE_DISALLOW_COPY_AND_MOVE(DynamicComponentRenderer);
};
} // namespace OHOS::Ace::NG
#endif // FOUNDATION_ACE_FRAMEWORKS_CORE_COMMON_DYNAMIC_COMPONENT_RENDERER_H

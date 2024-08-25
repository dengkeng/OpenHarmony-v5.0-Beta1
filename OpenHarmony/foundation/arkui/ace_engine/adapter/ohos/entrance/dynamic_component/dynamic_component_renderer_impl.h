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

#ifndef FOUNDATION_ACE_ADAPTER_OHOS_ENTRANCE_DYNAMIC_COMPONENT_DYNAMIC_COMPONENT_RENDERER_H
#define FOUNDATION_ACE_ADAPTER_OHOS_ENTRANCE_DYNAMIC_COMPONENT_DYNAMIC_COMPONENT_RENDERER_H

#include <cstdint>

#include "interfaces/inner_api/ace/ui_content.h"

#include "base/memory/ace_type.h"
#include "base/thread/task_executor.h"
#include "core/common/dynamic_component_renderer.h"
#include "core/components_ng/base/frame_node.h"

namespace OHOS::Ace::NG {

class DynamicComponentRendererImpl : public DynamicComponentRenderer {
    DECLARE_ACE_TYPE(DynamicComponentRendererImpl, DynamicComponentRenderer);

public:
    DynamicComponentRendererImpl(const RefPtr<FrameNode>& host, const std::string& hapPath, const std::string& abcPath,
        const std::string& entryPoint, void* runtime);
    ~DynamicComponentRendererImpl() override = default;

    void CreateContent() override;
    void DestroyContent() override;

    void UpdateViewportConfig(const ViewportConfig& config, Rosen::WindowSizeChangeReason reason,
        const std::shared_ptr<Rosen::RSTransaction>& rsTransaction) override;

    void TransferPointerEvent(const std::shared_ptr<MMI::PointerEvent>& pointerEvent) override;
    void TransferKeyEvent(const std::shared_ptr<MMI::KeyEvent>& keyEvent) override;

private:
    RefPtr<TaskExecutor> GetTaskExecutor();
    RefPtr<TaskExecutor> GetHostTaskExecutor();

    void AttachRenderContext();
    void RegisterSizeChangedCallback();

    bool contentReady_ = false;
    std::function<void()> contentReadyCallback_;
    mutable std::mutex contentReadyMutex_;

    std::string hapPath_;
    std::string abcPath_;
    std::string entryPoint_;
    std::shared_ptr<UIContent> uiContent_;
    NativeEngine* runtime_ = nullptr;
    WeakPtr<FrameNode> host_;
    int32_t hostInstanceId_ = -1;

    SizeF contentSize_;

    ACE_DISALLOW_COPY_AND_MOVE(DynamicComponentRendererImpl);
};
} // namespace OHOS::Ace::NG
#endif // FOUNDATION_ACE_ADAPTER_OHOS_ENTRANCE_DYNAMIC_COMPONENT_DYNAMIC_COMPONENT_RENDERER_H

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

#include "core/components_ng/pattern/overlay/modal_presentation_layout_algorithm.h"

#include "core/components_ng/layout/box_layout_algorithm.h"
#include "core/pipeline_ng/pipeline_context.h"

namespace OHOS::Ace::NG {
void ModalPresentationLayoutAlgorithm::Measure(LayoutWrapper* layoutWrapper)
{
    CHECK_NULL_VOID(layoutWrapper);
    BoxLayoutAlgorithm::PerformMeasureSelf(layoutWrapper);
    auto pipeline = PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(pipeline);
    auto layoutProp = layoutWrapper->GetLayoutProperty();
    auto modalFrameSize = layoutWrapper->GetGeometryNode()->GetFrameSize();
    auto childConstraint = layoutProp->CreateChildConstraint();
    auto inset = pipeline->GetSafeArea();
    childConstraint.maxSize = SizeF(modalFrameSize.Width(), modalFrameSize.Height() - inset.bottom_.Length());
    childConstraint.percentReference = SizeF(modalFrameSize.Width(), modalFrameSize.Height() - inset.bottom_.Length());
    for (auto&& child : layoutWrapper->GetAllChildrenWithBuild()) {
        child->Measure(childConstraint);
    }
}

void ModalPresentationLayoutAlgorithm::Layout(LayoutWrapper* layoutWrapper)
{
    CHECK_NULL_VOID(layoutWrapper);
    BoxLayoutAlgorithm::PerformLayout(layoutWrapper);
    for (auto&& child : layoutWrapper->GetAllChildrenWithBuild()) {
        child->Layout();
    }
}

} // namespace OHOS::Ace::NG
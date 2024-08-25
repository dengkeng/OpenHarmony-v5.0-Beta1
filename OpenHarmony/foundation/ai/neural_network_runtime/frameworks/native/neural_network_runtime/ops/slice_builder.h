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

#ifndef NEURAL_NETWORK_RUNTIME_SLICE_BUILDER_H
#define NEURAL_NETWORK_RUNTIME_SLICE_BUILDER_H

#include "ops_builder.h"
#include "ops_registry.h"

namespace OHOS {
namespace NeuralNetworkRuntime {
namespace Ops {
class SliceBuilder : public OpsBuilder {
public:
    typedef OH_NN_ReturnCode (SliceBuilder::*FuncPtr)(const std::shared_ptr<NNTensor>&);

    SliceBuilder();
    ~SliceBuilder() override;
    OH_NN_ReturnCode Build(const std::vector<uint32_t>& paramsIndex,
                           const std::vector<uint32_t>& inputsIndex,
                           const std::vector<uint32_t>& outputsIndex,
                           const std::vector<std::shared_ptr<NNTensor>>& allTensors) override;

    LiteGraphTensorPtr GetPrimitive() override;

private:
    OH_NN_ReturnCode SetAxes(const std::shared_ptr<NNTensor>& tensor);

private:
    std::vector<int64_t> m_axes;
    std::unordered_map<OH_NN_TensorType, FuncPtr> m_paramMap = {
        {OH_NN_SLICE_AXES, &SliceBuilder::SetAxes}
    };
};
} // namespace Ops
} // namespace NeuralNetworkRuntime
} // namespace OHOS

#endif // NEURAL_NETWORK_RUNTIME_SLICE_BUILDER_H
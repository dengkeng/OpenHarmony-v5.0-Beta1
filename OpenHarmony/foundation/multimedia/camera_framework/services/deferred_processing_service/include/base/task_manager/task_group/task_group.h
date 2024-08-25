/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_DEFERRED_PROCESSING_SERVICE_TASK_GROUP_H
#define OHOS_DEFERRED_PROCESSING_SERVICE_TASK_GROUP_H

#include "base_task_group.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class TaskGroup : public BaseTaskGroup {
public:
    TaskGroup(const std::string& name, TaskFunc func, bool serial, const ThreadPool* threadPool);
    ~TaskGroup() override = default;
};
} //namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_DEFERRED_PROCESSING_SERVICE_TASK_GROUP_H

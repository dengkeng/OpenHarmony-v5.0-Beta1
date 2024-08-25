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

#include "ohos_adapter/cpptoc/ark_background_task_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

bool ark_background_task_adapter_request_background_running(bool running, int32_t bgMode)
{
    // Execute
    return ArkBackgroundTaskAdapter::RequestBackgroundRunning(running, bgMode);
}

ArkBackgroundTaskAdapterCppToC::ArkBackgroundTaskAdapterCppToC() {}

ArkBackgroundTaskAdapterCppToC::~ArkBackgroundTaskAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkBackgroundTaskAdapterCppToC, ArkBackgroundTaskAdapter,
    ark_background_task_adapter_t>::kBridgeType = ARK_BACKGROUND_TASK_ADAPTER;

} // namespace OHOS::ArkWeb

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

ARK_WEB_EXPORT bool ark_background_task_adapter_request_background_running_static(bool running, int32_t bgMode)
{
    ARK_WEB_CPPTOC_DV_LOG();

    return OHOS::ArkWeb::ark_background_task_adapter_request_background_running(running, bgMode);
}

#ifdef __cplusplus
}
#endif // __cplusplus

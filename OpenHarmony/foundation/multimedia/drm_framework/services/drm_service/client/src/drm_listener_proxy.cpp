/*
 * Copyright (c) 2023  Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cinttypes>
#include "drm_log.h"
#include "drm_listener_proxy.h"

namespace OHOS {
namespace DrmStandard {
DrmListenerProxy::DrmListenerProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IDrmListener>(impl)
{
    DRM_DEBUG_LOG("0x%{public}06" PRIXPTR " DrmListenerProxy Instances create",
        (POINTER_MASK & reinterpret_cast<uintptr_t>(this)));
}
DrmListenerProxy::~DrmListenerProxy()
{
    DRM_DEBUG_LOG("0x%{public}06" PRIXPTR " DrmListenerProxy Instances destroy",
        (POINTER_MASK & reinterpret_cast<uintptr_t>(this)));
}
} // namespace DrmStandard
} // namespace OHOS
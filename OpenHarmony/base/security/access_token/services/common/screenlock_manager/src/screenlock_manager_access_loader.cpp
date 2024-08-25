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
#include "screenlock_manager_access_loader.h"
#include "screenlock_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool ScreenLockManagerAccessLoader::IsScreenLocked()
{
    return ScreenLock::ScreenLockManager::GetInstance()->IsScreenLocked();
}

extern "C" {
void* Create()
{
    return reinterpret_cast<void*>(new ScreenLockManagerAccessLoader);
}

void Destroy(void* loaderPtr)
{
    ScreenLockManagerAccessLoaderInterface* loader =
        reinterpret_cast<ScreenLockManagerAccessLoaderInterface*>(loaderPtr);
    if (loader != nullptr) {
        delete loader;
    }
}
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

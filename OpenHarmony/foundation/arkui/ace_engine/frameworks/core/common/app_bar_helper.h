/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_ACE_FRAMEWORKS_CORE_COMMON_APP_BAR_HELPER_H
#define FOUNDATION_ACE_FRAMEWORKS_CORE_COMMON_APP_BAR_HELPER_H

#include <map>
#include <string>

#include "core/components_ng/base/frame_node.h"

namespace OHOS::Ace {

class ACE_EXPORT AppBarHelper final {
public:
    static RefPtr<NG::FrameNode> CreateUIExtensionNode(const std::string& bundleName,
        const std::string& abilityName, const std::map<std::string, std::string>& params,
        std::function<void(int32_t)>&& onRelease,
        std::function<void(int32_t, const std::string&, const std::string&)>&& onError);

    static std::string QueryAppGalleryBundleName();
};

} // namespace OHOS::Ace
#endif // FOUNDATION_ACE_FRAMEWORKS_CORE_COMMON_APP_BAR_HELPER_H

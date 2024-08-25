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

#include "base/utils/system_properties.h"
#include "core/components/common/painter/rosen_scroll_fade_painter.h"
#include "core/components/scroll/scroll_fade_painter.h"

namespace OHOS::Ace {

RefPtr<ScrollFadePainter> ScrollFadePainter::CreatePainter()
{
    if (SystemProperties::GetRosenBackendEnabled()) {
#ifdef ENABLE_ROSEN_BACKEND
        return AceType::MakeRefPtr<RosenScrollFadePainter>();
#else
        return nullptr;
#endif
    } else {
        return nullptr;
    }
}
} // namespace OHOS::Ace

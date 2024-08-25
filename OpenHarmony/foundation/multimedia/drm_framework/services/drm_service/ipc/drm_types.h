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

#ifndef OHOS_DRM_TYPES_H
#define OHOS_DRM_TYPES_H

#include <stdint.h>

namespace OHOS {
namespace DrmStandard {
enum MediaKeySessionKeyStatus {
    MEDIA_KEY_SESSION_KEY_STATUS_USABLE = 0,
    MEDIA_KEY_SESSION_KEY_STATUS_EXPIRED = 1,
    MEDIA_KEY_SESSION_KEY_STATUS_OUTPUT_NOT_ALLOWED = 2,
    MEDIA_KEY_SESSION_KEY_STATUS_PENDING = 3,
    MEDIA_KEY_SESSION_KEY_STATUS_INTERNAL_ERROR = 4,
    MEDIA_KEY_SESSION_KEY_STATUS_USABLE_IN_FUTURE = 5,
};

typedef enum DrmEventType : int32_t {
    DRM_EVENT_PROVISION_REQUIRED = 0,
    DRM_EVENT_KEY_NEEDED,
    DRM_EVENT_KEY_EXPIRED,
    DRM_EVENT_VENDOR_DEFINED,
    DRM_EVENT_EXPIRATION_UPDATED,
    DRM_EVENT_KEY_CHANGED,
    DRM_EVENT_KEYSESSION_LOST,
} DrmEventType;
} // DrmStandard
} // OHOS

#endif // OHOS_DRM_TYPES_H
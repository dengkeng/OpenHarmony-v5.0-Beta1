/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef OHOS_DRM_ENUM_NAPI_H
#define OHOS_DRM_ENUM_NAPI_H

#include "key_session_napi.h"
#include "media_key_system_napi.h"
#include "drm_log.h"
#include "drm_error_code.h"

namespace OHOS {
namespace DrmStandard {
class DrmEnumNapi {
public:
    DrmEnumNapi() = default;
    ~DrmEnumNapi() = default;
    static napi_value Init(napi_env env, napi_value exports);

private:
    static napi_value JsEnumIntInit(napi_env env, napi_value exports);
    static napi_value JsEnumStringInit(napi_env env, napi_value exports);
};
} // namespace DrmStandard
} // namespace OHOS
#endif // OHOS_DRM_ENUM_NAPI_H_
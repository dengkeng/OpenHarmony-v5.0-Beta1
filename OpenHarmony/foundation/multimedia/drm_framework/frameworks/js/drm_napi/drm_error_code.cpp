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

#include "drm_error_code.h"

namespace OHOS {
namespace DrmStandard {
napi_status NapiDrmError::ThrowError(napi_env env, const char *napiMessage, int32_t napiCode)
{
    napi_value message = nullptr;
    napi_value code = nullptr;
    napi_value result = nullptr;
    napi_create_string_utf8(env, napiMessage, NAPI_AUTO_LENGTH, &message);
    napi_create_error(env, nullptr, message, &result);
    napi_create_int32(env, napiCode, &code);
    napi_set_named_property(env, result, "code", code);
    napi_throw(env, result);
    return napi_ok;
}

void NapiDrmError::ThrowError(napi_env env, int32_t code)
{
    std::string messageValue = GetMessageByCode(code);
    napi_throw_error(env, (std::to_string(code)).c_str(), messageValue.c_str());
}

std::string NapiDrmError::GetMessageByCode(int32_t &code)
{
    std::string errMessage;
    switch (code) {
        case DRM_INVALID_PARAM:
            errMessage = DRM_INVALID_PARAM_INFO;
            break;
        case DRM_SERVICE_FATAL_ERROR:
            errMessage = DRM_SERVICE_FATAL_ERRO_INFO;
            break;
        case DRM_UNKNOWN_ERROR:
            errMessage = DRM_UNKNOWN_ERROR_INFO;
            break;
        case DRM_MAX_SYSTEM_NUM_REACHED:
            errMessage = DRM_MAX_SYSTEM_NUM_REACHED_INFO;
            break;
        case DRM_MAX_SESSION_NUM_REACHED:
            errMessage = DRM_MAX_SESSION_NUM_REACHED_INFO;
            break;
        default:
            errMessage = DRM_UNKNOWN_ERROR_INFO;
            code = DRM_UNKNOWN_ERROR;
            break;
    }
    return errMessage;
}
} // namespace DrmStandard
} // namespace OHOS
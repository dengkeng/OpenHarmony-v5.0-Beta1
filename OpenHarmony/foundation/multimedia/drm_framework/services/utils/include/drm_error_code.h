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

#ifndef DRM_ERROR_CODE_H
#define DRM_ERROR_CODE_H
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace DrmStandard {
class NapiDrmError {
public:
    static napi_status ThrowError(napi_env env, const char *napiMessage, int32_t napiCode);
    static void ThrowError(napi_env env, int32_t code);
    static std::string GetMessageByCode(int32_t &code);
};

const int32_t DRM_ERROR = -1;
const int32_t DRM_OK = 0;
const int32_t DRM_ALLOC_ERROR = 1;
const int32_t DRM_INVALID_ARG = 2;
const int32_t DRM_INVALID_STATE = 3;
const int32_t DRM_OPERATION_NOT_ALLOWED = 5;
const int32_t DRM_HOST_ERROR = 6;
const int32_t DRM_SERVICE_ERROR = 7;
const int32_t DRM_MEMORY_ERROR = 8;
const int32_t DRM_UNKNOWN_ERROR = 24700101;
const int32_t DRM_MAX_SYSTEM_NUM_REACHED = 24700103;
const int32_t DRM_MAX_SESSION_NUM_REACHED = 24700104;
const int32_t DRM_SERVICE_FATAL_ERROR = 24700201;
const int32_t DRM_INVALID_PARAM = 401;

const std::string DRM_INVALID_PARAM_INFO = "input parameter value error";
const std::string DRM_SERVICE_FATAL_ERRO_INFO = "service error";
const std::string DRM_UNKNOWN_ERROR_INFO = "unknow error";
const std::string DRM_MAX_SYSTEM_NUM_REACHED_INFO = "mediaKeySystem number limited";
const std::string DRM_MAX_SESSION_NUM_REACHED_INFO = "mediaKeySession number limited";
} // namespace DrmStandard
} // namespace OHOS
#endif // DRM_ERROR_CODE_H
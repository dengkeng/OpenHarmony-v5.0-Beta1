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
#ifndef NAPI_PARAM_UTILS_H
#define NAPI_PARAM_UTILS_H

#include <cstdint>
#include <map>
#include <list>
#include <string>
#include <mutex>
#include <vector>
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_base_context.h"
#include "drm_log.h"
#include "drm_error_code.h"
#include "i_keysession_service.h"

namespace OHOS {
namespace DrmStandard {
/* Constants for array index */
const int32_t PARAM0 = 0;
const int32_t PARAM1 = 1;
const int32_t PARAM2 = 2;
const int32_t PARAM3 = 3;

/* Constants for array size */
const int32_t ARGS_ZERO = 0;
const int32_t ARGS_ONE = 1;
const int32_t ARGS_TWO = 2;
const int32_t ARGS_THREE = 3;
const int32_t ARGS_FOUR = 4;

const int32_t KEY_SYSTEM_MAX_NUMBER = 64;
const int32_t KEY_SESSION_MAX_NUMBER = 64;

enum NapiMediaKeyRequestType {
    MEDIA_KEY_REQUEST_TYPE_UNKNOWN = 0,
    MEDIA_KEY_REQUEST_TYPE_INITIAL,
    MEDIA_KEY_REQUEST_TYPE_RENEWAL,
    MEDIA_KEY_REQUEST_TYPE_RELEASE,
    MEDIA_KEY_REQUEST_TYPE_NONE,
    MEDIA_KEY_REQUEST_TYPE_UPDATE,
};

struct NapiProvisionRequest {
    std::vector<uint8_t> data;
    std::string defaultURL;
};

struct DrmEventParame {
    int32_t extra;
    std::vector<uint8_t> data;
};

struct DrmKeysChangeEventParame {
    std::map<std::vector<uint8_t>, MediaKeySessionKeyStatus> statusTable;
    bool hasNewGoodLicense;
};

template<typename T>
class ObjectRefMap {
public:
    static std::mutex allObjLock;
    static std::map<T*, uint32_t> refMap;
    static void Insert(T *obj);
    static void Erase(T *obj);
    static T *IncreaseRef(T *obj);
    static void DecreaseRef(T *obj);

    ObjectRefMap(T *obj);
    ~ObjectRefMap();
    T *GetPtr();

private:
    T *obj_ = nullptr;
};

template <typename T>
std::mutex ObjectRefMap<T>::allObjLock;

template <typename T>
std::map<T *, uint32_t> ObjectRefMap<T>::refMap;

template <typename T>
void ObjectRefMap<T>::Insert(T *obj)
{
    std::lock_guard<std::mutex> lock(allObjLock);
    refMap[obj] = 1;
}

template <typename T>
void ObjectRefMap<T>::Erase(T *obj)
{
    std::lock_guard<std::mutex> lock(allObjLock);
    auto it = refMap.find(obj);
    if (it != refMap.end()) {
        refMap.erase(it);
    }
}

template <typename T>
T *ObjectRefMap<T>::IncreaseRef(T *obj)
{
    std::lock_guard<std::mutex> lock(allObjLock);
    if (refMap.count(obj)) {
        refMap[obj]++;
        return obj;
    } else {
        return nullptr;
    }
}

template <typename T>
void ObjectRefMap<T>::DecreaseRef(T *obj)
{
    std::lock_guard<std::mutex> lock(allObjLock);
    if (refMap.count(obj) && --refMap[obj] == 0) {
        refMap.erase(obj);
        delete obj;
        obj = nullptr;
    }
}

template <typename T>
ObjectRefMap<T>::ObjectRefMap(T *obj)
{
    if (obj != nullptr) {
        obj_ = ObjectRefMap::IncreaseRef(obj);
    }
}

template <typename T>
ObjectRefMap<T>::~ObjectRefMap()
{
    if (obj_ != nullptr) {
        ObjectRefMap::DecreaseRef(obj_);
    }
}

template <typename T>
T *ObjectRefMap<T>::GetPtr()
{
    return obj_;
}

#define DRM_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar)           \
    do {                                                               \
        void *data;                                                    \
        napi_get_cb_info(env, info, &(argc), argv, &(thisVar), &data); \
    } while (0)

#define DRM_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar)             \
    do {                                                                           \
        void *data;                                                                \
        status = napi_get_cb_info(env, info, nullptr, nullptr, &(thisVar), &data); \
    } while (0)

#define DRM_NAPI_CHECK_AND_RETURN_VOID_LOG(cond, fmt, ...) \
    do {                                              \
        if (!(cond)) {                                \
            DRM_ERR_LOG(fmt, ##__VA_ARGS__);          \
            return;                                   \
        }                                             \
    } while (0)

#define DRM_NAPI_CHECK_AND_CLOSE_RETURN_VOID_LOG(cond, fmt, ...) \
    do {                                              \
        if (!(cond)) {                                \
            DRM_ERR_LOG(fmt, ##__VA_ARGS__);          \
            napi_close_handle_scope(env, scope);      \
            return;                                   \
        }                                             \
    } while (0)

#define DRM_NAPI_CHECK_AND_RETURN_LOG(cond, status, fmt, ...) \
    do {                                              \
        if (!(cond)) {                                \
            DRM_ERR_LOG(fmt, ##__VA_ARGS__);          \
            return status;                                   \
        }                                             \
    } while (0)


/* check condition related to argc/argv, return and logging. */
#define NAPI_CHECK_ARGS_RETURN_VOID(context, condition, message, code)               \
    do {                                                               \
        if (!(condition)) {                                            \
            (context)->status = napi_invalid_arg;                         \
            (context)->errMessage = std::string(message);                      \
            (context)->errCode = code;                      \
            DRM_ERR_LOG("test (" #condition ") failed: " message);           \
            return;                                                    \
        }                                                              \
    } while (0)

#define NAPI_CHECK_STATUS_RETURN_VOID(context, message, code)                        \
    do {                                                               \
        if ((context)->status != napi_ok) {                               \
            (context)->errMessage = std::string(message);                      \
            (context)->errCode = code;                      \
            DRM_ERR_LOG("test (context->status == napi_ok) failed: " message);  \
            return;                                                    \
        }                                                              \
    } while (0)

class NapiParamUtils {
public:
    static napi_status GetValueInt32(const napi_env &env, int32_t &value, napi_value in);
    static napi_status SetValueInt32(const napi_env &env, const int32_t &value, napi_value &result);
    static napi_status GetValueInt32(const napi_env &env, const std::string &fieldStr, int32_t &value, napi_value in);
    static napi_status SetValueInt32(const napi_env &env, const std::string &fieldStr,
        const int32_t value, napi_value &result);

    static std::string GetStringArgument(napi_env env, napi_value value);
    static napi_status SetValueString(const napi_env &env, const std::string &stringValue, napi_value &result);
    static napi_status SetValueString(const napi_env &env, const std::string &fieldStr, const std::string &stringValue,
        napi_value &result);

    static napi_value GetUndefinedValue(napi_env env);

    static napi_status SetValueUint8Array(const napi_env &env, const std::vector<uint8_t> &value,
        napi_value &result);
    static napi_status SetValueUint8Array(const napi_env &env, const std::string &fieldStr,
        const std::vector<uint8_t> &value, napi_value &result);
    static napi_status GetValueUint8Array(const napi_env &env, std::vector<uint8_t> &value,
        napi_value in);
    static napi_status SetValueBoolean(const napi_env &env, const bool boolValue, napi_value &result);
    static napi_status SetValueMap(const napi_env &env,
    std::map<std::vector<uint8_t>, MediaKeySessionKeyStatus> statusTable, napi_value &result);

    static napi_status GetValueOptionsData(const napi_env &env, std::map<std::string, std::string> &valueMap,
        napi_value in);
    static napi_status SetProvisionRequest(const napi_env &env, const NapiProvisionRequest &provisionRequest,
        napi_value &result);
    static napi_status SetMediaKeyRequest(const napi_env &env,
        const IMediaKeySessionService::MediaKeyRequest &mediaKeyRequest, napi_value &result);
    static napi_status SetDrmEventInfo(const napi_env &env, DrmEventParame &eventParame,
        napi_value &result);
    static napi_status SetDrmKeysChangeEventInfo(const napi_env &env, DrmKeysChangeEventParame &eventParame,
        napi_value &statusTable, napi_value &hasNewGoodLicense);
};
} // namespace DrmStandard
} // namespace OHOS
#endif // NAPI_PARAM_UTILS_H

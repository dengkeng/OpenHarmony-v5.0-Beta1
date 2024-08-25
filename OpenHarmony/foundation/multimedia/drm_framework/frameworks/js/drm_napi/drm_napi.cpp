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

#include "ipc_skeleton.h"
#include "napi_param_utils.h"
#include "drm_napi.h"

namespace OHOS {
namespace DrmStandard {
thread_local napi_ref DrmNapi::sConstructor_ = nullptr;

DrmNapi::DrmNapi() : env_(nullptr), wrapper_(nullptr)
{
    DRM_DEBUG_LOG("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

DrmNapi::~DrmNapi()
{
    DRM_DEBUG_LOG("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
}

napi_value DrmNapi::Init(napi_env env, napi_value exports)
{
    DRM_INFO_LOG("DrmNapi Init enter.");
    napi_property_descriptor drmproperty[] = {
        DECLARE_NAPI_FUNCTION("getMediaKeySystemTest", CreateMediaKeySystemInstance),
    };
    DRM_DEBUG_LOG("DrmNapi enter properties");
    napi_property_descriptor drm_static_properties[] = {
        DECLARE_NAPI_STATIC_FUNCTION("createMediaKeySystem", CreateMediaKeySystemInstance),
        DECLARE_NAPI_STATIC_FUNCTION("isMediaKeySystemSupported", IsMediaKeySystemSupported),
        DECLARE_NAPI_STATIC_FUNCTION("getMediaKeySystems", GetMediaKeySystemName),
        DECLARE_NAPI_STATIC_FUNCTION("getMediaKeySystemUuid", GetMediaKeySystemUuid)
    };
    DRM_DEBUG_LOG("DrmNapi enter napi_define_class");
    napi_value constructor = nullptr;
    napi_status status = napi_define_class(env, DRM_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH, DrmNapiConstructor, nullptr,
        sizeof(drmproperty) / sizeof(drmproperty[0]), drmproperty, &constructor);

    DRM_CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to define DrmNapi class");

    status = napi_create_reference(env, constructor, 1, &sConstructor_);
    DRM_CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to create reference of DrmNapi constructor");
    status = napi_set_named_property(env, exports, DRM_NAPI_CLASS_NAME, constructor);
    DRM_CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to set DrmNapi constructor");

    status = napi_define_properties(env, exports, sizeof(drm_static_properties) / sizeof(drm_static_properties[0]),
        drm_static_properties);
    DRM_CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to define static DrmNapi function");

    DRM_INFO_LOG("DrmNapi Init success");
    return exports;
}

napi_value DrmNapi::DrmNapiConstructor(napi_env env, napi_callback_info info)
{
    DRM_INFO_LOG("DrmNapi DrmNapiConstructor enter.");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    DRM_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<DrmNapi> obj = std::make_unique<DrmNapi>();
        if (obj != nullptr) {
            obj->env_ = env;
            status = napi_wrap(env, thisVar, reinterpret_cast<void *>(obj.get()), DrmNapi::DrmNapiDestructor, nullptr,
                nullptr);
            if (status == napi_ok) {
                obj.release();
                DRM_INFO_LOG("DrmNapi DrmNapiConstructor exit.");
                return thisVar;
            } else {
                DRM_ERR_LOG("DrmNapiDestructor Failure wrapping js to native napi");
            }
        }
    }
    DRM_ERR_LOG("DrmNapiDestructor call Failed!");
    DRM_INFO_LOG("DrmNapi DrmNapiConstructor exit.");
    return result;
}

void DrmNapi::DrmNapiDestructor(napi_env env, void *nativeObject, void *finalize)
{
    DRM_INFO_LOG("DrmNapi DrmNapiDestructor enter.");
    DrmNapi *drmNapi = reinterpret_cast<DrmNapi *>(nativeObject);
    if (drmNapi != nullptr) {
        drmNapi->~DrmNapi();
    }
    DRM_INFO_LOG("DrmNapi DrmNapiDestructor exit.");
}

napi_value DrmNapi::IsMediaKeySystemSupported(napi_env env, napi_callback_info info)
{
    DRM_INFO_LOG("DrmNapi IsMediaKeySystemSupported enter.");
    napi_value result = nullptr;
    result = MediaKeySystemNapi::IsMediaKeySystemSupported(env, info);
    DRM_INFO_LOG("DrmNapi IsMediaKeySystemSupported exit.");
    return result;
}

napi_value DrmNapi::GetMediaKeySystemName(napi_env env, napi_callback_info info)
{
    DRM_INFO_LOG("DrmNapi GetMediaKeySystemName enter.");
    napi_value result = nullptr;
    result = MediaKeySystemNapi::GetMediaKeySystemName(env, info);
    DRM_INFO_LOG("DrmNapi GetMediaKeySystemName exit.");
    return result;
}

napi_value DrmNapi::GetMediaKeySystemUuid(napi_env env, napi_callback_info info)
{
    DRM_INFO_LOG("DrmNapi GetMediaKeySystemUuid enter.");
    napi_value result = nullptr;
    result = MediaKeySystemNapi::GetMediaKeySystemUuid(env, info);
    DRM_INFO_LOG("DrmNapi GetMediaKeySystemUuid exit.");
    return result;
}
napi_value DrmNapi::CreateMediaKeySystemInstance(napi_env env, napi_callback_info info)
{
    DRM_INFO_LOG("DrmNapi CreateMediaKeySystemInstance enter.");
    napi_value result = nullptr;
    result = MediaKeySystemNapi::CreateMediaKeySystemInstance(env, info);
    DRM_INFO_LOG("DrmNapi CreateMediaKeySystemInstance exit.");
    return result;
}
} // namespace OHOS
} // namespace DrmStandard

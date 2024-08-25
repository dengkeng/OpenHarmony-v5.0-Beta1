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
#ifndef OHOS_DRM_KEY_SESSION_H
#define OHOS_DRM_KEY_SESSION_H

#include <map>
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "drm_log.h"
#include "drm_error_code.h"
#include "key_session_callback_napi.h"
#include "key_session_impl.h"
#include "napi_param_utils.h"
#include "drm_error_code.h"
#include "napi_async_work.h"

namespace OHOS {
namespace DrmStandard {
static const char KEY_SESSION_NAPI_CLASS_NAME[] = "MediaKeySession";

struct MediaKeySessionAsyncContext : public ContextBase {
    int32_t intValue;
    std::vector<uint8_t> response;
    std::vector<uint8_t> licenseId;
    std::vector<uint8_t> releaseRequest;
    std::vector<uint8_t> releaseLicenseId;
    std::vector<uint8_t> restoreLicenseId;
    std::vector<uint8_t> releaseResponse;
    std::vector<uint8_t> releaseResponseLicenseId;
    IMediaKeySessionService::MediaKeyRequestInfo mediaKeyRequestInfo;
    IMediaKeySessionService::MediaKeyRequest mediaKeyRequest;
};

class MediaKeySessionNapi {
public:
    MediaKeySessionNapi();
    ~MediaKeySessionNapi();
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateMediaKeySession(napi_env env, sptr<MediaKeySessionImpl> keySessionImpl);
    static napi_value GenerateMediaKeyRequest(napi_env env, napi_callback_info info);
    static napi_value ProcessMediaKeyResponse(napi_env env, napi_callback_info info);
    static napi_value GenerateOfflineReleaseRequest(napi_env env, napi_callback_info info);
    static napi_value ProcessOfflineReleaseResponse(napi_env env, napi_callback_info info);
    static napi_value CheckMediaKeyStatus(napi_env env, napi_callback_info info);
    static napi_value RestoreOfflineMediaKeys(napi_env env, napi_callback_info info);
    static napi_value ClearMediaKeys(napi_env env, napi_callback_info info);
    static napi_value GetContentProtectionLevel(napi_env env, napi_callback_info info);
    static napi_value GetDecryptModule(napi_env env, napi_callback_info info);
    static napi_value AddEventListener(napi_env env, napi_callback_info info);
    static napi_value DeleteEventListener(napi_env env, napi_callback_info info);
    static napi_value RequireSecureDecoderModule(napi_env env, napi_callback_info info);
    static napi_value SetEventCallback(napi_env env, napi_callback_info info);
    static napi_value UnsetEventCallback(napi_env env, napi_callback_info info);
    static bool SetMediaKeySessionNativeProperty(napi_env env, napi_value obj, const std::string &name,
        sptr<MediaKeySessionImpl> keySessionImpl);
    void SetEventCallbackReference(const std::string eventType, std::shared_ptr<AutoRef> callbackPair);
    void ClearEventCallbackReference(const std::string eventType);
    static napi_value Destroy(napi_env env, napi_callback_info info);
    static bool CheckMediaKeySessionStatus(MediaKeySessionNapi *napi,
        std::shared_ptr<MediaKeySessionAsyncContext> context);
    static bool CheckContextStatus(std::shared_ptr<MediaKeySessionAsyncContext> context);

private:
    static napi_value MediaKeySessionNapiConstructor(napi_env env, napi_callback_info info);
    static void MediaKeySessionNapiDestructor(napi_env env, void *nativeObject, void *finalize);

    napi_env env_;
    napi_ref wrapper_;
    static thread_local napi_ref sConstructor_;
    std::mutex mutex_;
    static thread_local sptr<MediaKeySessionImpl> sMediaKeySessionImpl_;
    sptr<MediaKeySessionImpl> keySessionImpl_;
    sptr<MediaKeySessionCallbackNapi> keySessionCallbackNapi_;
};
} // DrmStandard
} // OHOS


#endif // OHOS_DRM_KEY_SESSION_H_
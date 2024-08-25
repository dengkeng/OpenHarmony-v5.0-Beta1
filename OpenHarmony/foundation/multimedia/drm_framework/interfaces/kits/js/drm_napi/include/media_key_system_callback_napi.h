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
#ifndef OHOS_DRM_MEDIA_KEYSYSTEM_CALLBACK_NAPI_H
#define OHOS_DRM_MEDIA_KEYSYSTEM_CALLBACK_NAPI_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "common_napi.h"
#include "media_key_system_impl.h"
#include "napi_param_utils.h"
#include "napi_async_work.h"

namespace OHOS {
namespace DrmStandard {
class MediaKeySystemCallbackNapi : public MediaKeySystemImplCallback {
public:
    explicit MediaKeySystemCallbackNapi(napi_env env);
    virtual ~MediaKeySystemCallbackNapi();
    void SetCallbackReference(const std::string eventType, std::shared_ptr<AutoRef> callbackPair);
    void ClearCallbackReference(const std::string eventType);
    void SendEvent(const std::string &event, int32_t extra, const std::vector<uint8_t> &data) override;

private:
    struct MediaKeySystemJsCallback {
        std::shared_ptr<AutoRef> callback = nullptr;
        std::string callbackName = "unknown";
        DrmEventParame eventParame;
    };

    static void WorkCallbackStateChangeDone(uv_work_t *work, int status);
    static void WorkCallbackInterruptDone(uv_work_t *work, int status);
    void OnJsCallbackInterrupt(std::unique_ptr<MediaKeySystemJsCallback> &jsCb);
    void OnJsCallbackStateChange(std::unique_ptr<MediaKeySystemJsCallback> &jsCb);
    napi_env env_ = nullptr;
    std::mutex mutex_;
    std::map<std::string, std::shared_ptr<AutoRef>> callbackMap_;
};
} // namespace DrmStandard
} // namespace OHOS

#endif // OHOS_DRM_MEDIA_KEYSYSTEM_CALLBACK_NAPI_H_
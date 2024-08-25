/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_JS_AUTO_FILL_MANAGER_H
#define OHOS_ABILITY_RUNTIME_JS_AUTO_FILL_MANAGER_H

#include <map>

#include "js_auto_fill_manager.h"
#include "js_auto_save_request_callback.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "native_engine/native_value.h"

namespace OHOS {
namespace AbilityRuntime {
class JsAutoFillManager {
public:
    JsAutoFillManager() = default;
    ~JsAutoFillManager() = default;
    static void Finalizer(napi_env env, void *data, void *hint);
    static napi_value RequestAutoSave(napi_env env, napi_callback_info info);

private:
    napi_value OnRequestAutoSave(napi_env env, NapiCallbackInfo &info);
    void OnRequestAutoSaveInner(napi_env env, int32_t instanceId,
        const std::shared_ptr<JsAutoSaveRequestCallback> &saveRequestCallback);
    std::shared_ptr<JsAutoSaveRequestCallback> GetCallbackByInstanceId(int32_t instanceId);
    void OnRequestAutoSaveDone(int32_t instanceId);

    std::mutex mutexLock_;
    std::map<int32_t, std::weak_ptr<JsAutoSaveRequestCallback>> saveRequestObject_;
};
napi_value JsAutoFillManagerInit(napi_env env, napi_value exportObj);
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_JS_AUTO_FILL_MANAGER_H
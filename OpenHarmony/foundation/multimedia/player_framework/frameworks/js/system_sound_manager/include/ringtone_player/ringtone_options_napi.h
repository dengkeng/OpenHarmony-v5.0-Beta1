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

#ifndef RINGTONE_OPTIONS_NAPI_H
#define RINGTONE_OPTIONS_NAPI_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Media {
static const std::string RINGTONE_OPTIONS_NAPI_CLASS_NAME = "RingtoneOptions";

class RingtoneOptionsNapi {
public:
    RingtoneOptionsNapi();
    ~RingtoneOptionsNapi();

    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateRingtoneOptionsWrapper(napi_env env, float volume, bool loop);

private:
    static void Destructor(napi_env env, void *nativeObject, void *finalize_hint);
    static napi_value Construct(napi_env env, napi_callback_info info);
    static napi_value GetVolume(napi_env env, napi_callback_info info);
    static napi_value SetVolume(napi_env env, napi_callback_info info);
    static napi_value GetLoop(napi_env env, napi_callback_info info);
    static napi_value SetLoop(napi_env env, napi_callback_info info);

    static thread_local napi_ref sConstructor_;

    static float sVolume_;
    static bool sLoop_;

    float volume_;
    bool loop_;
    napi_env env_;
};
} // namespace Media
} // namespace OHOS
#endif // RINGTONE_OPTIONS_NAPI_H
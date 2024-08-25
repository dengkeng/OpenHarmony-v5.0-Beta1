/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_JS_TRANSITION_CONTROLLER_H
#define OHOS_JS_TRANSITION_CONTROLLER_H

#include "native_engine/native_engine.h"
#include "native_engine/native_value.h"
#include "window.h"

namespace OHOS {
namespace Rosen {
class JsTransitionController : public IAnimationTransitionController {
public:
    JsTransitionController(napi_env env, std::shared_ptr<NativeReference> jsWin, sptr<Window> window);
    ~JsTransitionController();
    void AnimationForShown() override;
    void AnimationForHidden() override;
    void SetJsController(std::shared_ptr<NativeReference> jsVal);
};
}
}
#endif // OHOS_JS_TRANSITION_CONTROLLER_H